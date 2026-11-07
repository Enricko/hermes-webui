"""Native capability switching keeps account authority and runtime identity."""

import asyncio
import secrets

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest

from multiuser.broker import Brokers
from multiuser.runtime_profiles import profile_name, read_plan, selected_profile
from multiuser.settings import Settings
from multiuser.store import PolicyError
from multiuser.templates import worker_config


def test_native_cookie_is_only_a_granted_in_account_selector(monkeypatch, tmp_path):
    a, b = 'a'*32, 'b'*32
    user = {'id':'c'*32, 'auth_version':4, 'template_id':a, 'template_ids':[a,b]}
    plan = {'anchor':a, 'auth_version':4, 'profiles':{a:'default', b:profile_name(b)}}
    monkeypatch.setattr('multiuser.runtime_profiles.operator_plan', lambda *_: plan)
    settings = Settings(root=tmp_path)
    assert read_plan(settings, user) == plan
    assert selected_profile(user, plan) == (a, 'default')
    assert selected_profile(user, plan, profile_name(b)) == (b, profile_name(b))
    for cookie in [profile_name('f'*32), 'assigned%252d'+'f'*32, '../../another-user', '/root', '%00default']:
        with pytest.raises(PolicyError):
            selected_profile(user, plan, cookie)
    assert read_plan(settings, {**user, 'auth_version':5}) is None
    assert read_plan(settings, {**user, 'template_ids':[a]}) is None
    removed_root = {**plan, 'profiles':{b:profile_name(b)}}
    assert selected_profile({**user, 'template_id':b}, removed_root, 'default') == (b, profile_name(b))


def test_profile_configs_bind_all_model_routes_to_their_own_capability():
    tid, pid = 'a'*32, 'b'*32
    cfg = worker_config({'provider_id':pid, 'model':'base', 'skill_bundle_id':'c'*32,
        'connections':[{'provider_id':pid,'name':'Router','model':'base'}]},
        profile_id=tid, skills_path='/shared/profile-skills/'+tid)
    expected = 'http://127.0.0.1:8000/profiles/'+tid+'/providers/'+pid+'/v1'
    assert cfg['model']['base_url'] == expected
    assert {p['base_url'] for p in cfg['custom_providers']} == {expected}
    assert cfg['skills']['external_dirs'] == ['/shared/profile-skills/'+tid]
    assert 'tenant-broker' == cfg['model']['api_key']


@pytest.mark.asyncio
async def test_broker_uses_profile_bound_policy_and_denies_guesses_and_revocation(tmp_path):
    settings = Settings(root=tmp_path)
    store = settings.store(); store.initialize()
    password = secrets.token_urlsafe(24)
    store.create_user('administrator', password, role='admin', bootstrap=True)
    seen = []
    async def completion(request):
        seen.append(await request.json())
        return web.json_response({'ok':True})
    provider_app = web.Application(); provider_app.router.add_post('/v1/chat/completions', completion)
    async with TestServer(provider_app) as provider_server:
        pid = store.put_provider('Router', str(provider_server.make_url('/v1')), 'synthetic-private-key')
        first = store.put_template('A', {'provider_id':pid,'model':'base','parameters':{'temperature':0.2,'max_tokens':500}})
        second = store.put_template('B', {'provider_id':pid,'model':'base','parameters':{'temperature':0.8,'max_tokens':100}})
        alice = store.create_user('alice', password, template_ids=[first,second], provider_ids=[pid], template_id=first)
        bob = store.create_user('bobby', password, template_id=first)
        service = Brokers(settings)
        await service.start()
        service.limits = {user['id']:asyncio.Semaphore(4) for user in (alice,bob)}
        try:
            app = web.Application()
            async def route(request):
                owner = alice['id'] if request.match_info['owner'] == 'alice' else bob['id']
                # Separate listeners in production bind UID before parsing a route.
                cloned = request.clone(rel_url='/' + request.match_info['rest'])
                return await service.model(owner, cloned)
            app.router.add_route('*', '/{owner}/{rest:.*}', route)
            async with TestServer(app) as server, aiohttp.ClientSession() as client:
                async def post(owner, tid, tokens=50):
                    url = server.make_url(f'/{owner}/profiles/{tid}/providers/{pid}/v1/chat/completions')
                    async with client.post(url, json={'model':'base','messages':[],'max_tokens':tokens},
                                           headers={'X-User-Id':alice['id']}) as response:
                        return response.status, await response.text()
                assert (await post('alice', second))[0] == 200
                assert seen[-1]['temperature'] == 0.8 and seen[-1]['user'] == alice['id']
                assert (await post('alice', first, 200))[0] == 200
                assert seen[-1]['temperature'] == 0.2
                for owner, tid, tokens in [('alice',second,101),('bobby',second,50),('alice','f'*32,50)]:
                    status, body = await post(owner, tid, tokens)
                    assert status == 403 and 'synthetic-private-key' not in body
                store.update_user(alice['id'], template_ids=[first], provider_ids=[pid])
                assert (await post('alice', second))[0] == 403
        finally:
            await service.close()
