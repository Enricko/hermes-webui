"""Actual HTTP/SSE gateway tests; OS/container acceptance is a separate gate."""

import asyncio
import contextlib
from dataclasses import replace
import json
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
            if request.path == '/api/profiles':
                # A worker cannot supply account identity or an assigned catalog.
                return web.json_response({'active':'default', 'profiles':[
                    {'name':'default', 'is_default':True, 'total_skills':3, 'enabled_skills':3},
                    {'name':'private-work', 'is_default':False}] + received.get('_extra_native_profiles', []),
                    'account_profiles':[{'id':'f'*32, 'name':'Forged worker profile'}],
                    'account_profile_id':'f'*32})
            if request.path == '/api/profile/switch':
                name = (await request.json())['name']
                response = web.json_response({'active':name, 'is_default':name == 'default'})
                response.set_cookie('hermes_profile', name, path='/')
                return response
            return web.json_response({'owner': owner, 'sessions': [{'id': 'private-' + owner}]},
                                     headers={'Cache-Control': 'public, max-age=31536000'})
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
            received.setdefault('_login_headers', {})[name] = dict(response.headers)
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
    for route in ['users', 'providers', 'templates', 'hermes-profiles']:
        async with alice.get(server.make_url('/multiuser/api/' + route), headers={'X-Admin': '1'}) as response:
            assert response.status == 403
    admin_client, admin_csrf = await login('administrator')
    async with admin_client.get(server.make_url('/multiuser/api/hermes-profiles')) as response:
        assert response.status == 200 and (await response.json()) == {'profiles': []}
    async with admin_client.post(server.make_url('/multiuser/api/hermes-profiles'),
        json={'hermes_home': '/root/.hermes', 'source_id': 'f' * 32},
        headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': admin_csrf}) as response:
        assert response.status == 403
    async with alice.post(server.make_url('/multiuser/api/users/' + users[1]['id']),
                          json={'provider_id': 'f' * 32},
                          headers={'Origin': settings.origin, 'X-Hermes-CSRF-Token': csrf}) as response:
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
async def test_independent_grants_self_selection_and_old_stream_generation_are_enforced(gateway):
    settings, store, server, login, users, _received = gateway
    pa = store.put_provider('Provider A', 'http://127.0.0.1:1/v1', 'fixture-key-a')
    pb = store.put_provider('Provider B', 'http://127.0.0.1:2/v1', 'fixture-key-b')
    ta = store.put_template('Profile A', {'provider_id':pa, 'model':'a'})
    tb = store.put_template('Profile B', {'provider_id':pb, 'model':'b'})
    admin, csrf = await login('administrator')
    for account, profiles, providers in [(users[1], [ta, tb], [pa]), (users[2], [ta], [pa, pb])]:
        async with admin.post(server.make_url('/multiuser/api/users/' + account['id']), json={
            'template_ids': profiles, 'provider_ids': providers, 'template_id':ta},
            headers={'Origin':settings.origin, 'X-Hermes-CSRF-Token':csrf}) as response:
            assert response.status == 200
    alice, a_csrf = await login('alice'); bob, _ = await login('bobby')
    async with alice.get(server.make_url('/multiuser/api/me')) as response:
        me = await response.json()
        assert {p['id'] for p in me['choices']['profiles']} == {ta, tb}
        assert [p['id'] for p in me['choices']['providers']] == [pa]
        assert 'fixture-key' not in json.dumps(me)
    headers = {'Origin':settings.origin, 'X-Hermes-CSRF-Token':a_csrf}
    for body in [{'template_id':tb, 'provider_id':pb}, {'template_id':'f'*32, 'provider_id':pa},
                 {'template_id':ta, 'provider_id':pa, 'user_id':users[2]['id']},
                 {'template_id':ta, 'provider_id':pa, 'provider_ids':[pa,pb]}]:
        async with alice.post(server.make_url('/multiuser/api/selection'), json=body, headers=headers) as response:
            assert response.status == 400
    stream_a = await alice.get(server.make_url('/api/stream'))
    stream_b = await bob.get(server.make_url('/api/stream'))
    await stream_a.content.readuntil(b'\n\n'); await stream_b.content.readuntil(b'\n\n')
    async with alice.post(server.make_url('/multiuser/api/selection'), json={'template_id':tb, 'provider_id':pa}, headers=headers) as response:
        assert response.status == 200 and (await response.json())['changed']
    await asyncio.wait_for(stream_a.content.read(), 2)
    assert users[2]['id'].encode() in await asyncio.wait_for(stream_b.content.readuntil(b'\n\n'), 2)
    async with alice.get(server.make_url('/multiuser/api/me')) as response:
        assert response.status == 200
        me = await response.json()
        assert me['profile']['id'] == tb and me['provider']['id'] == pa
    async with alice.get(server.make_url('/api/sessions')) as response:
        assert response.status == 503  # No admission of the previous active runtime.
    assert store.user(users[2]['id'])['template_id'] == ta
    stream_a.close(); stream_b.close()


@pytest.mark.asyncio
async def test_prepared_profile_switch_preserves_runtime_sessions_and_old_streams(gateway, monkeypatch):
    settings, store, server, login, users, received = gateway
    provider = store.put_provider('Router', 'http://127.0.0.1:1/v1', 'synthetic-key')
    a = store.put_template('A', {'provider_id':provider,'model':'base'})
    b = store.put_template('B', {'provider_id':provider,'model':'base'})
    for user, tids in [(users[1],[a,b]),(users[2],[a])]:
        store.update_user(user['id'], template_ids=tids, provider_ids=[provider], template_id=a, assign_template=True)
    def plan(_settings, user):
        return {'anchor':a, 'auth_version':user['auth_version'], 'profiles':{
            tid:('default' if tid == a else 'assigned-'+tid) for tid in user['template_ids']}}
    monkeypatch.setattr('multiuser.gateway.read_plan', plan)
    received['_extra_native_profiles'] = [{'name':'assigned-'+b,'is_default':False}]
    alice, csrf = await login('alice'); bob, _ = await login('bobby')
    other, _ = await login('alice')
    before = store.user(users[1]['id']); runtime = store.runtime(users[1]['id'])
    headers = {'Origin':settings.origin, 'X-Hermes-CSRF-Token':csrf}
    stream = await alice.get(server.make_url('/api/stream'))
    await stream.content.readuntil(b'\n\n')
    async with alice.post(server.make_url('/multiuser/api/selection'), json={'template_id':b,'provider_id':provider,'native':True}, headers=headers) as response:
        assert response.status == 200 and (await response.json()) == {'changed':True,'native_profile':'assigned-'+b}
    async with alice.post(server.make_url('/api/profile/switch'), json={'name':'assigned-'+b}, headers=headers) as response:
        assert response.status == 200 and (await response.json())['active'] == 'assigned-'+b
    assert received[users[1]['id']][-1]['headers']['Cookie'] == 'hermes_profile=default'
    async with alice.get(server.make_url('/multiuser/api/me')) as response:
        assert (await response.json())['profile']['id'] == b
    assert store.user(users[1]['id']) == before and store.runtime(users[1]['id']) == runtime
    async with other.get(server.make_url('/api/sessions')) as response:
        assert response.status == 200
    assert users[1]['id'].encode() in await asyncio.wait_for(stream.content.readuntil(b'\n\n'), 2)
    stream.close()
    for client, bad_cookie in [(bob,'assigned-'+b), (alice,'assigned%252d'+'f'*32)]:
        jar = aiohttp.CookieJar(unsafe=True)
        jar.update_cookies(client.cookie_jar.filter_cookies(server.make_url('/')), response_url=server.make_url('/'))
        jar.update_cookies({'hermes_profile':bad_cookie}, response_url=server.make_url('/'))
        async with aiohttp.ClientSession(cookie_jar=jar) as forged:
            async with forged.get(server.make_url('/api/profiles')) as response:
                assert response.status in (400,403)
    async with bob.get(server.make_url('/api/sessions?profile=assigned-'+b)) as response:
        assert response.status == 403
    raw_client, b_csrf = await login('bobby')
    async with raw_client.post(server.make_url('/api/profile/switch'), data=json.dumps({'name':'assigned-'+b}),
                            headers={'Origin':settings.origin, 'X-Hermes-CSRF-Token':b_csrf, 'Content-Type':'text/plain'}) as response:
        assert response.status == 403
    async with alice.post(server.make_url('/api/profile/delete'), json={'name':'assigned-'+b}, headers=headers) as response:
        assert response.status == 403
    document = store.template(b)['document']
    store.put_template('B', document, template_id=b, enabled=False)
    async with alice.get(server.make_url('/api/sessions')) as response:
        assert response.status == 403  # Disabled before its old mapping/mounts are replaced.
    async with other.get(server.make_url('/api/profiles')) as response:
        data = await response.json()
        assert response.status == 200
        assert 'assigned-'+b not in [row['name'] for row in data['profiles']]
    store.update_user(users[1]['id'], template_ids=[a], provider_ids=[provider])
    async with alice.get(server.make_url('/api/sessions')) as response:
        assert response.status == 401


@pytest.mark.asyncio
async def test_native_profile_menu_uses_server_grants_and_keeps_filesystem_names_separate(gateway):
    settings, store, server, login, users, _received = gateway
    provider = store.put_provider('Selected provider', 'http://127.0.0.1:1/v1', 'synthetic-menu-key')
    first = store.put_template('Profile A', {'provider_id':provider, 'model':'a', 'soul':'Shared A instructions'})
    second = store.put_template('Profile B', {'provider_id':provider, 'model':'b', 'soul':'Shared B instructions'})
    store.put_template('Unassigned profile', {'provider_id':provider, 'model':'secret-name'})
    store.update_user(users[1]['id'], template_ids=[first, second], provider_ids=[provider],
                      template_id=first, assign_template=True)
    store.update_user(users[2]['id'], template_ids=[first], provider_ids=[provider],
                      template_id=first, assign_template=True)
    for name, expected in [('alice', {first, second}), ('bobby', {first})]:
        client, _ = await login(name)
        async with client.get(server.make_url('/api/profiles?user_id=' + users[2]['id']),
            headers={'X-User-Id':users[2]['id'], 'X-Forwarded-User':'bobby'}) as response:
            assert response.status == 200
            data = await response.json()
            assert {p['id'] for p in data['account_profiles']} == expected
            assert data['account_profile_id'] == first and data['account_provider_id'] == provider
            assert [p['name'] for p in data['profiles']] == ['default', 'private-work']
            assert data['profiles'][0]['total_skills'] == 3
            assert 'Forged worker profile' not in json.dumps(data)
            assert 'synthetic-menu-key' not in json.dumps(data)
            assert 'Shared A instructions' not in json.dumps(data)
            assert response.headers['Cache-Control'] == 'no-store'
        async with client.get(server.make_url('/multiuser/api/me')) as response:
            assert {p['id'] for p in (await response.json())['choices']['profiles']} == expected


@pytest.mark.asyncio
async def test_reselecting_assigned_base_resets_personal_profile_cookie_without_restarting(gateway):
    settings, store, server, login, users, _ = gateway
    provider = store.put_provider('Provider', 'http://127.0.0.1:1/v1', '')
    profile = store.put_template('Profile', {'provider_id':provider, 'model':'a'})
    store.update_user(users[1]['id'], template_ids=[profile], provider_ids=[provider], template_id=profile, assign_template=True)
    client, csrf = await login('alice')
    before = store.runtime(users[1]['id'])
    async with client.post(server.make_url('/multiuser/api/selection'), json={'template_id':profile, 'provider_id':provider},
        headers={'Origin':settings.origin, 'X-Hermes-CSRF-Token':csrf}) as response:
        assert response.status == 200 and (await response.json())['changed'] is False
        assert 'hermes_profile=' in response.headers['Set-Cookie'] and 'Max-Age=0' in response.headers['Set-Cookie']
    assert store.runtime(users[1]['id']) == before


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
        for asset in ('client.js', 'style.css'):
            assert f'/multiuser/static/{asset}?v={settings["webui_version"]}' in html
        assert settings['auth_enabled'] is True and settings['password_auth_enabled'] is True
    async with aiohttp.ClientSession() as anonymous:
        async with anonymous.get(server.make_url('/'), allow_redirects=False) as response:
            assert response.status == 302 and response.headers['Location'] == '/login'
        async with anonymous.get(server.make_url('/api/sessions')) as response:
            assert response.status == 401


@pytest.mark.asyncio
async def test_pending_runtime_does_not_boot_chat_until_ready(gateway):
    _settings, store, server, login, users, received = gateway
    alice, _ = await login('alice')
    uid = users[1]['id']
    store.set_runtime(uid, '', 'waiting_for_broker')
    async with alice.get(server.make_url('/')) as response:
        html = await response.text()
        assert response.status == 200 and '/multiuser/static/waiting.js' in html
        assert 'static/boot.js' not in html and '__ACCOUNT_CONTROLS__' not in html
        assert '/multiuser/static/client.js' not in html
    assert uid not in received  # no backend settings/files initialization
    async with alice.get(server.make_url('/multiuser/api/me')) as response:
        assert (await response.json())['runtime']['state'] == 'waiting_for_broker'
    store.set_runtime(uid, 'ready-now', 'ready')
    async with alice.get(server.make_url('/')) as response:
        html = await response.text()
        assert 'static/boot.js' in html and 'multiuser/static/client.js' in html


@pytest.mark.asyncio
async def test_unassigned_admin_keeps_account_management_available(gateway):
    _settings, store, server, login, users, _received = gateway
    admin, _ = await login('administrator')
    store.set_runtime(users[0]['id'], '', 'unassigned')
    async with admin.get(server.make_url('/multiuser/admin')) as response:
        html = await response.text()
        assert '/multiuser/static/client.js' in html and 'static/boot.js' not in html
    async with admin.get(server.make_url('/multiuser/api/users')) as response:
        assert response.status == 200


@pytest.mark.asyncio
async def test_health_reports_stopped_account_discovery(gateway):
    _settings, _store, server, _login, _users, _received = gateway
    service = next(value for value in server.app.values() if isinstance(value, Gateway))
    async with aiohttp.ClientSession() as client:
        async with client.get(server.make_url('/health')) as response:
            assert response.status == 200
            assert (await response.json())['account_discovery'] == 'running'
        service.brokers.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await service.brokers.task
        async with client.get(server.make_url('/health')) as response:
            assert response.status == 503
            assert (await response.json())['account_discovery'] == 'stopped'


@pytest.mark.asyncio
async def test_identity_controls_remain_available_when_assigned_provider_is_disabled(gateway):
    settings, store, server, login, users, _received = gateway
    provider = store.put_provider('Unavailable provider', 'http://127.0.0.1:1/v1', 'private-provider-key')
    template = store.put_template('Existing profile', {'provider_id': provider, 'model': 'approved'})
    store.update_user(users[1]['id'], template_id=template, assign_template=True)
    alice, _csrf = await login('alice')
    store.put_provider('Unavailable provider', 'http://127.0.0.1:1/v1', provider_id=provider, enabled=False)
    async with alice.get(server.make_url('/multiuser/api/me')) as response:
        text = await response.text()
        assert response.status == 200 and 'private-provider-key' not in text
        value = await response.json()
        assert value['profile']['id'] == template and value['provider']['id'] == provider


@pytest.mark.asyncio
async def test_private_worker_data_is_never_http_cached_even_if_worker_requests_it(gateway):
    settings, _store, server, login, users, received = gateway
    alice, csrf = await login('alice')
    assert received['_login_headers']['alice']['Clear-Site-Data'] == '"storage"'
    for path in ['/api/sessions', '/api/file/raw?path=private.txt', '/api/settings']:
        async with alice.get(server.make_url(path)) as response:
            assert response.status == 200
            assert response.headers['Cache-Control'] == 'no-store'
            assert (await response.json())['owner'] == users[1]['id']
    async with alice.post(server.make_url('/api/auth/logout'), json={}, headers={'Origin': settings.origin,
                          'X-Hermes-CSRF-Token': csrf}) as response:
        assert response.status == 200
        assert response.headers['Clear-Site-Data'] == '"cache", "storage"'


@pytest.mark.asyncio
async def test_trusted_assets_support_compression_validation_and_version_caching(gateway):
    _settings, _store, server, login, _users, _received = gateway
    alice, _ = await login('alice')
    async with alice.get(server.make_url('/static/ui.js'), headers={'Accept-Encoding': 'gzip'}) as response:
        raw = await response.read()
        assert response.status == 200 and response.headers.get('Content-Encoding') == 'gzip'
        assert int(response.headers['Content-Length']) < len(raw)
        assert response.headers['Vary'] == 'Accept-Encoding'
        etag = response.headers['ETag']
    async with alice.get(server.make_url('/static/ui.js'), headers={
            'Accept-Encoding': 'gzip', 'If-None-Match': etag}) as response:
        assert response.status == 304 and not await response.read()
    service = next(value for value in server.app.values() if isinstance(value, Gateway))
    async with alice.get(server.make_url('/static/ui.js?v=' + service.version)) as response:
        assert 'immutable' in response.headers['Cache-Control']
    async with alice.get(server.make_url('/static/ui.js?v=unknown')) as response:
        assert response.headers['Cache-Control'] == 'no-cache'
    for asset in ('client.js', 'style.css'):
        async with alice.get(server.make_url('/multiuser/static/' + asset + '?v=' + service.version)) as response:
            assert 'immutable' in response.headers['Cache-Control']
    async with alice.get(server.make_url('/static/ui.js'), headers={'Accept-Encoding': 'gzip;q=0'}) as response:
        assert 'Content-Encoding' not in response.headers


def test_only_loopback_trials_can_use_insecure_cookies():
    # Root stays short enough for Unix sockets; origin policy is independent.
    settings = Settings(root=Path('/tmp/hmu-policy'), gateway_uid=os.getuid())
    assert Gateway(settings).cookie_name == '__Host-hmu_session'
    for url in ['http://public.example', 'https://user:password@host.example', 'https://host.example/path']:
        with pytest.raises(PolicyError):
            replace(settings, public_url=url).validate()
