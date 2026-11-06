"""Actual HTTP/SSE gateway tests; OS/container acceptance is a separate gate."""

import asyncio
from dataclasses import replace
import os
from pathlib import Path
import secrets
import shutil
import tempfile

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest
import pytest_asyncio

from multiuser.gateway import Gateway, create_app
from multiuser.settings import Settings
from multiuser.store import PolicyError


@pytest_asyncio.fixture
async def gateway(unused_tcp_port):
    root = Path(tempfile.mkdtemp(prefix='hmu-http-', dir='/tmp'))
    settings = Settings(root=root, public_url=f'http://127.0.0.1:{unused_tcp_port}', port=unused_tcp_port,
                        gateway_uid=os.getuid())
    store = settings.store()
    store.initialize()
    password = secrets.token_urlsafe(24)
    admin = store.create_user('administrator', password, role='admin', bootstrap=True)
    alice = store.create_user('alice', password)
    bob = store.create_user('bobby', password)
    received = {}
    runners = []
    for user in (admin, alice, bob):
        uid = user['id']
        relay = settings.relay_socket(uid)
        relay.parent.mkdir(parents=True)
        backend = web.Application()
        async def handler(request, owner=uid):
            received.setdefault(owner, []).append({'headers': dict(request.headers), 'path': request.path})
            if request.path == '/api/stream':
                response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
                await response.prepare(request)
                try:
                    for _ in range(100):
                        await response.write(('data: ' + owner + '\n\n').encode())
                        await asyncio.sleep(0.05)
                except ConnectionError:
                    pass
                return response
            if request.path in ('/api/raw-code', '/api/alternate-script-mime'):
                return web.Response(text='untrusted-worker-code', content_type=(
                    'application/ecmascript' if request.path.endswith('alternate-script-mime') else 'application/javascript'),
                                    headers={'Service-Worker-Allowed': '/', 'Set-Cookie': 'hmu_session=attacker; Path=/'})
            if request.path == '/api/echo':
                assert request.content_length is not None
                assert request.headers.get('Transfer-Encoding') is None
                return web.json_response({'owner': owner, 'body': await request.json()})
            return web.json_response({'owner': owner, 'sessions': [{'id': 'private-' + owner}]})
        backend.router.add_route('*', '/{path:.*}', handler)
        runner = web.AppRunner(backend, access_log=None)
        await runner.setup()
        await web.UnixSite(runner, str(relay)).start()
        runners.append(runner)
        store.set_runtime(uid, 'fixture', 'ready')
    server = TestServer(create_app(settings), host='127.0.0.1', port=unused_tcp_port)
    await server.start_server()
    clients = []
    async def login(name):
        client = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))
        clients.append(client)
        async with client.post(str(server.make_url('/api/auth/login')),
                               json={'username': name, 'password': password},
                               headers={'Origin': settings.origin}) as response:
            assert response.status == 200
            value = await response.json()
            cookie = response.headers['Set-Cookie']
            assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
        client.headers['X-Hermes-CSRF-Token'] = value['user']['csrf_token']
        return client, value['user']['csrf_token']
    yield settings, store, server, login, (admin, alice, bob), received
    for client in clients:
        await client.close()
    await server.close()
    for runner in runners:
        await runner.cleanup()
    shutil.rmtree(root)


@pytest.mark.asyncio
async def test_server_session_selects_backend_despite_identity_profile_and_id_spoofing(gateway):
    settings, _store, server, login, users, received = gateway
    alice, _csrf = await login('alice')
    bob, _ = await login('bobby')
    a, b = users[1]['id'], users[2]['id']
    headers = {'X-User-Id': b, 'X-Forwarded-User': 'bobby', 'X-Forwarded-For': '8.8.8.8',
               'Cookie': f'hmu_session={alice.cookie_jar.filter_cookies(server.make_url("/"))["hmu_session"].value}; hermes_profile=bobby'}
    async with alice.get(server.make_url('/api/sessions?user_id=' + b + '&profile=bobby'), headers=headers) as response:
        value = await response.json()
        assert response.status == 200 and value['owner'] == a
        assert value['sessions'][0]['id'] != 'private-' + b
    async with bob.get(server.make_url('/api/sessions')) as response:
        assert (await response.json())['owner'] == b
    forwarded = received[a][-1]['headers']
    assert 'X-User-Id' not in forwarded and 'X-Forwarded-User' not in forwarded
    assert 'hmu_session' not in forwarded.get('Cookie', '')
    assert 'X-Hermes-CSRF-Token' not in forwarded
    assert settings.origin not in forwarded.get('Origin', '')


@pytest.mark.asyncio
async def test_admin_api_and_csrf_are_backend_enforced(gateway):
    settings, _store, server, login, users, _received = gateway
    alice, csrf = await login('alice')
    for route in ['users', 'providers', 'templates']:
        async with alice.get(server.make_url('/multiuser/api/' + route), headers={'X-Admin': '1'}) as response:
            assert response.status == 403
    async with alice.post(server.make_url('/api/echo'), json={'payload': 'x'}, headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': ''}) as response:
        assert response.status == 403
    for origin in ['https://evil.example', 'null']:
        async with alice.post(server.make_url('/api/echo'), json={}, headers={'Origin': origin, 'X-Hermes-CSRF-Token': csrf}) as response:
            assert response.status == 403
    async with alice.post(server.make_url('/api/echo'), json={'payload': 'x' * 70000},
                          headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': csrf}) as response:
        value = await response.json()
        assert response.status == 200 and value['owner'] == users[1]['id']
        assert len(value['body']['payload']) == 70000
    async with alice.post(server.make_url('/api/providers/custom'), json={},
                          headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': csrf}) as response:
        assert response.status == 403
    async with alice.get(server.make_url('/api/chat/cancel?stream_id=guess'),
                         headers={'Sec-Fetch-Site': 'same-site', 'X-Hermes-CSRF-Token': ''}) as response:
        assert response.status == 403


@pytest.mark.asyncio
async def test_admin_changes_revoke_sessions_and_provider_secrets_are_write_only(gateway):
    settings, _store, server, login, users, _received = gateway
    admin, admin_csrf = await login('administrator')
    alice, _ = await login('alice')
    secret = secrets.token_urlsafe(24)
    headers = {'Origin': settings.origin, 'X-Hermes-CSRF-Token': admin_csrf}
    async with admin.post(server.make_url('/multiuser/api/providers'), json={
        'name': 'Fixture model', 'base_url': 'http://127.0.0.1:9876/v1', 'secret': secret}, headers=headers) as response:
        assert response.status == 200
        assert secret not in await response.text()
    async with admin.get(server.make_url('/multiuser/api/providers')) as response:
        assert secret not in await response.text()
    async with admin.post(server.make_url('/multiuser/api/users/' + users[1]['id']),
                          json={'enabled': False}, headers=headers) as response:
        assert response.status == 200
    async with alice.get(server.make_url('/api/sessions')) as response:
        assert response.status == 401
    async with admin.post(server.make_url('/multiuser/api/users/' + users[0]['id']),
                          json={'enabled': False}, headers=headers) as response:
        assert response.status == 400


@pytest.mark.asyncio
async def test_streaming_revalidates_session_without_affecting_another_user(gateway):
    settings, _store, server, login, users, _received = gateway
    alice, csrf = await login('alice')
    bob, _ = await login('bobby')
    stream_a = await alice.get(server.make_url('/api/stream'))
    stream_b = await bob.get(server.make_url('/api/stream'))
    assert users[1]['id'].encode() in await stream_a.content.readuntil(b'\n\n')
    assert users[2]['id'].encode() in await stream_b.content.readuntil(b'\n\n')
    async with alice.post(server.make_url('/api/auth/logout'), json={},
                          headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': csrf}) as response:
        assert response.status == 200
    remainder = await asyncio.wait_for(stream_a.content.read(), 2)
    assert users[2]['id'].encode() not in remainder
    assert users[2]['id'].encode() in await asyncio.wait_for(stream_b.content.readuntil(b'\n\n'), 2)
    stream_a.close()
    stream_b.close()


@pytest.mark.asyncio
async def test_frontend_cannot_be_poisoned_by_runtime_or_untrusted_code(gateway):
    settings, _store, server, login, users, _received = gateway
    alice, _ = await login('alice')
    token = alice.cookie_jar.filter_cookies(server.make_url('/'))['hmu_session'].value
    async with alice.get(server.make_url('/static/panels.js')) as response:
        assert response.status == 200
        assert 'untrusted-worker-code' not in await response.text()
    async with alice.get(server.make_url('/api/raw-code')) as response:
        assert response.content_type == 'application/octet-stream'
        assert 'Service-Worker-Allowed' not in response.headers
        assert 'Set-Cookie' not in response.headers
    async with alice.get(server.make_url('/api/alternate-script-mime')) as response:
        assert response.content_type == 'application/octet-stream'
    async with alice.get(server.make_url('/api/raw-code'), headers={'Service-Worker': 'script'}) as response:
        assert response.status == 403
    assert alice.cookie_jar.filter_cookies(server.make_url('/'))['hmu_session'].value == token
    async with alice.get(server.make_url('/sw.js')) as response:
        assert 'unregister' in await response.text()
    async with alice.get(server.make_url('/')) as response:
        html = await response.text()
        assert 'multiuser/static/client.js' in html
        assert '<base href="/">' in html
        assert '__CSRF_TOKEN_JSON__' not in html
    async with alice.get(server.make_url('/api/settings')) as response:
        settings = await response.json()
        assert settings['webui_version'] in html
        assert settings['auth_enabled'] is True and settings['password_auth_enabled'] is True
    async with aiohttp.ClientSession() as anonymous:
        async with anonymous.get(server.make_url('/'), allow_redirects=False) as response:
            assert response.status == 302 and response.headers['Location'] == '/login'
        async with anonymous.get(server.make_url('/api/sessions')) as response:
            assert response.status == 401


def test_only_loopback_trials_can_use_insecure_cookies():
    # Root stays short enough for Unix sockets; origin policy is independent.
    settings = Settings(root=Path('/tmp/hmu-policy'), gateway_uid=os.getuid())
    assert Gateway(settings).cookie_name == '__Host-hmu_session'
    for url in ['http://public.example', 'https://user:password@host.example', 'https://host.example/path']:
        with pytest.raises(PolicyError):
            replace(settings, public_url=url).validate()
