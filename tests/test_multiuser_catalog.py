"""Actual HTTP catalog discovery, authorization, cache identity and revocation."""

import asyncio
import os
from pathlib import Path
import secrets
import shutil
import tempfile

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest

from multiuser.broker import Brokers, CatalogUnavailable, catalog_models
from multiuser.settings import Settings


def test_catalog_discards_untrusted_metadata_and_malformed_or_secret_ids():
    secret = secrets.token_urlsafe(24)
    assert catalog_models({'data': [{'id': 'valid', 'api_key': secret}, {'id': 'valid'},
        {'id': secret}, {'id': 'bad\nname'}, {'id': None}]}, secret) == [
        {'id': 'valid', 'object': 'model', 'owned_by': 'assigned-provider'}]
    for payload in [{}, {'data': []}, {'data': 'bad'}, {'data': [{'id': None}]}, {'data': [{}] * 4097}]:
        with pytest.raises(CatalogUnavailable):
            catalog_models(payload)


@pytest.mark.asyncio
async def test_provider_catalog_http_is_account_scoped_single_flight_and_revocable():
    root = Path(tempfile.mkdtemp(prefix='hmu-catalog-', dir='/tmp'))
    settings = Settings(root=root, gateway_uid=os.getuid())
    store = settings.store(); store.initialize()
    service = Brokers(settings)
    servers, clients = [], []
    states = {}
    try:
        for name in ('alpha', 'bravo'):
            state = {'secret': secrets.token_urlsafe(24), 'catalog_requests': 0, 'hold': None, 'fail': False,
                     'started': asyncio.Event(), 'posted_models': []}
            states[name] = state
            async def models(request, name=name, state=state):
                assert request.headers['Authorization'] == 'Bearer ' + state['secret']
                state['catalog_requests'] += 1
                state['started'].set()
                if state['hold']:
                    await state['hold'].wait()
                if state['fail']:
                    return web.json_response({'error': state['secret']}, status=503)
                return web.json_response({'data': [{'id': 'base'}, {'id': name + '-extra'}]})
            async def completion(request, state=state, name=name):
                assert request.headers['Authorization'] == 'Bearer ' + state['secret']
                payload = await request.json()
                state['posted_models'].append(payload['model'])
                return web.json_response({'model': payload['model'], 'owner': payload['user'], 'provider': name})
            app = web.Application()
            app.router.add_get('/v1/models', models)
            app.router.add_post('/v1/chat/completions', completion)
            server = TestServer(app); await server.start_server(); servers.append(server)
            state['id'] = store.put_provider(name, str(server.make_url('/v1')), state['secret'])
        password = secrets.token_urlsafe(24)
        store.create_user('administrator', password, role='admin', bootstrap=True)
        template = store.put_template('Common profile', {'provider_id': states['alpha']['id'],
            'model': 'base', 'model_catalog': 'provider'})
        alice = store.create_user('alice', password, template_id=template)
        bob = store.create_user('bobby', password, template_id=template, provider_id=states['bravo']['id'])
        for user in (alice, bob):
            settings.broker_socket(user['id']).parent.mkdir(parents=True)
            await service.bind(user['id'])
            clients.append(aiohttp.ClientSession(connector=aiohttp.UnixConnector(path=str(settings.broker_socket(user['id'])))))
        await service.start()
        a, b = clients
        async def catalog(client):
            async with client.get('http://broker/v1/models') as response:
                return response.status, await response.json()
        first, second = await asyncio.gather(catalog(a), catalog(b))
        assert {m['id'] for m in first[1]['data']} == {'base', 'alpha-extra'}
        assert {m['id'] for m in second[1]['data']} == {'base', 'bravo-extra'}
        await asyncio.gather(*(catalog(a) for _ in range(12)))
        assert states['alpha']['catalog_requests'] == 1
        for client, model, expected in [(a, 'alpha-extra', 200), (b, 'alpha-extra', 403), (a, 'invented', 403)]:
            async with client.post('http://broker/v1/chat/completions', json={'model': model, 'messages': []},
                                   headers={'X-User-Id': bob['id']}) as response:
                assert response.status == expected
                value = await response.json()
                if expected == 200:
                    assert value['owner'] == alice['id']
        states['alpha']['secret'] = secrets.token_urlsafe(24)
        store.put_provider('alpha', str(servers[0].make_url('/v1')), states['alpha']['secret'], provider_id=states['alpha']['id'])
        assert (await catalog(a))[0] == 200
        assert states['alpha']['catalog_requests'] == 2
        service.catalog_cache.clear()
        states['alpha']['started'].clear(); states['alpha']['hold'] = asyncio.Event()
        pending = asyncio.create_task(catalog(a))
        await asyncio.wait_for(states['alpha']['started'].wait(), timeout=5)
        store.update_user(alice['id'], provider_id=states['bravo']['id'], assign_provider=True)
        states['alpha']['hold'].set()
        assert (await pending)[0] == 403
        assert {m['id'] for m in (await catalog(a))[1]['data']} == {'base', 'bravo-extra'}
        alpha_route = 'http://broker/providers/' + states['alpha']['id'] + '/v1'
        bravo_route = 'http://broker/providers/' + states['bravo']['id'] + '/v1'
        async with a.get(alpha_route + '/models') as response:
            assert response.status == 403
        document = store.template(template)['document']
        document['connections'] = [{'provider_id': state['id'], 'name': name, 'model': 'base'} for name, state in states.items()]
        store.put_template('Common profile', document, template_id=template)
        for route, name in [(alpha_route, 'alpha'), (bravo_route, 'bravo')]:
            async with a.get(route + '/models') as response:
                assert response.status == 200
                assert {m['id'] for m in (await response.json())['data']} == {'base', name + '-extra'}
            async with a.post(route + '/chat/completions', json={'model': 'base', 'messages': []},
                    headers={'X-User-Id': bob['id']}) as response:
                assert response.status == 200
                value = await response.json()
                assert value['provider'] == name and value['owner'] == alice['id']
        before = {name: state['catalog_requests'] for name, state in states.items()}
        for route in (alpha_route, bravo_route, alpha_route, bravo_route):
            async with a.get(route + '/models') as response:
                assert response.status == 200
        assert before == {name: state['catalog_requests'] for name, state in states.items()}
        private_provider = store.put_provider('B private provider', str(servers[0].make_url('/v1')), states['alpha']['secret'])
        store.update_user(bob['id'], provider_id=private_provider, assign_provider=True)
        async with a.get('http://broker/providers/' + private_provider + '/v1/models',
                         headers={'X-User-Id': bob['id'], 'X-Forwarded-User': 'bobby'}) as response:
            assert response.status == 403
        async with a.get('http://broker/providers/' + 'f' * 32 + '/v1/models') as response:
            assert response.status == 403
        service.catalog_cache.clear()
        states['alpha']['started'].clear(); states['alpha']['hold'] = asyncio.Event()
        pending = asyncio.create_task(a.get(alpha_route + '/models'))
        await asyncio.wait_for(states['alpha']['started'].wait(), timeout=5)
        document['connections'] = [entry for entry in document['connections'] if entry['provider_id'] != states['alpha']['id']]
        store.put_template('Common profile', document, template_id=template)
        states['alpha']['hold'].set()
        removed = await pending
        assert removed.status == 403
        await removed.read(); removed.release()
        service.catalog_cache.clear(); states['bravo']['fail'] = True
        status, failure = await catalog(a)
        assert status == 502 and states['bravo']['secret'] not in str(failure)
    finally:
        for state in states.values():
            if state['hold']:
                state['hold'].set()
        for client in clients:
            await client.close()
        await service.close()
        for server in servers:
            await server.close()
        shutil.rmtree(root)
