"""Opt-in acceptance against real namespaces, Agent execution, HTTP and storage."""

import asyncio
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import zipfile

import aiohttp
import pytest
import pytest_asyncio

pytestmark = [pytest.mark.asyncio(loop_scope='module'), pytest.mark.skipif(
    os.getenv('HERMES_MULTIUSER_DOCKER_TEST') != '1', reason='Explicit real-Docker acceptance gate; run with HERMES_MULTIUSER_DOCKER_TEST=1')]


@pytest_asyncio.fixture(scope='module', loop_scope='module')
async def lab():
    images = Path(os.environ['HERMES_MULTIUSER_TEST_IMAGES'])
    evidence = Path(os.environ.get('HERMES_MULTIUSER_EVIDENCE', '/tmp/hermes-multiuser-acceptance'))
    spec = importlib.util.spec_from_file_location('hmu_lab', Path(__file__).with_name('multiuser_lab.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    instance = module.Lab(images, evidence)
    try:
        await instance.start()
        yield instance
    finally:
        await instance.close()


async def test_distinct_credentials_roles_and_native_agent_chat(lab):
    assert len(set(lab.passwords.values())) == 3
    async with aiohttp.ClientSession() as client:
        async with client.post(lab.origin + '/api/auth/login', json={
            'username': 'bobby', 'password': lab.passwords['alice']}, headers={'Origin': lab.origin}) as response:
            assert response.status == 401
    for path in ['/multiuser/api/users', '/multiuser/api/providers', '/multiuser/api/templates']:
        status, _ = await lab.api('alice', path, headers={'X-Admin': '1'})
        assert status == 403
    sid = await lab.session('alice')
    stream = await lab.start_chat('alice', sid, 'Hello isolated Hermes')
    events = await lab.events('alice', stream)
    assert any(event == 'token' and 'private Hermes runtime' in item.get('text', '') for event, item in events), events
    assert any(event == 'done' for event, _ in events)
    status, profiles = await lab.api('alice', '/api/profiles')
    assert status == 200
    current = next(p for p in profiles['profiles'] if p['is_active'])
    assert current['total_skills'] == 2 and current['provider_managed'] is True
    status, catalog = await lab.api('alice', '/api/models/live')
    assert status == 200 and {m['id'] for m in catalog['models']} >= {'fixture-model', 'fixture-extra'}
    status, started = await lab.api('alice', '/api/chat/start', {'session_id': sid, 'message': 'Try another provider model',
        'model': 'fixture-extra', 'model_provider': 'custom', 'profile': 'default', 'workspace': '/workspace'})
    assert status == 200
    assert any(event == 'done' for event, _ in await lab.events('alice', started['stream_id']))
    assert lab.model.requests[-1]['model'] == 'fixture-extra'
    lab.results['local_auth_roles_and_real_agent_chat'] = True
    lab.results['shared_profile_skill_count_and_nondefault_provider_model'] = True


async def test_private_api_ids_profiles_files_download_and_archive_containment(lab):
    a, b = await asyncio.gather(lab.session('alice'), lab.session('bobby'))
    marker_a, marker_b = secrets.token_hex(20), secrets.token_hex(20)
    for name, marker in [('alice', marker_a), ('bobby', marker_b)]:
        await lab.execute(name, 'from pathlib import Path;import sys;Path("/workspace/private.txt").write_bytes(sys.stdin.buffer.read())', stdin=marker.encode())
    status, data = await lab.api('alice', '/api/file?session_id=' + a + '&path=private.txt')
    assert status == 200 and marker_a in str(data)
    for path in ['/api/session?session_id=' + b, '/api/session/export?session_id=' + b,
                 '/api/file?session_id=' + b + '&path=private.txt', '/api/file/raw?session_id=' + b + '&path=private.txt']:
        status, data = await lab.api('alice', path, headers={'X-User-Id': lab.users['bobby']['id']})
        assert status in (400, 403, 404) and marker_b not in str(data)
    for path in ['../../etc/passwd', '/etc/passwd', str(lab.settings.user_dir(lab.users['bobby']['id']) / 'workspace/private.txt')]:
        status, data = await lab.api('alice', '/api/file?session_id=' + a + '&path=' + path)
        assert status in (400, 403, 404) and marker_b not in str(data)
    await lab.execute('alice', 'from pathlib import Path;Path("/workspace/outside-link").symlink_to("/etc/passwd")')
    status, _ = await lab.api('alice', '/api/file?session_id=' + a + '&path=outside-link')
    assert status in (400, 403, 404)
    before = await lab.execute('alice', 'from pathlib import Path;import hashlib;print(hashlib.sha256(Path("/state/hermes/config.yaml").read_bytes()).hexdigest())')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as output:
        output.writestr('../../state/hermes/config.yaml', 'overwritten')
    form = aiohttp.FormData()
    form.add_field('session_id', a)
    form.add_field('path', '')
    form.add_field('file', archive.getvalue(), filename='escape.zip', content_type='application/zip')
    client = await lab.login('alice')
    async with client.post(lab.origin + '/api/workspace/upload', data=form) as response:
        data = await response.json()
        assert response.status == 200 and data['extracted'] is False and data.get('extract_error')
    after = await lab.execute('alice', 'from pathlib import Path;import hashlib;print(hashlib.sha256(Path("/state/hermes/config.yaml").read_bytes()).hexdigest())')
    assert before == after
    status, data = await lab.api('alice', '/api/sessions?all_profiles=true&profile=bobby', headers={'Cookie':
        'hermes_profile=bobby', 'X-Forwarded-User': 'bobby'})
    assert marker_b not in str(data)
    lab.results['private_resource_and_archive_boundaries'] = True


async def test_actual_terminal_file_tools_cannot_reach_other_storage_or_host(lab):
    host_canary = Path('/tmp/hmu-host-canary-' + secrets.token_hex(8))
    marker = secrets.token_hex(24)
    host_canary.write_text(marker)
    host_canary.chmod(0o600)
    try:
        b_path = str(lab.settings.user_dir(lab.users['bobby']['id']) / 'workspace/private.txt')
        code = ('from tools.file_tools import read_file_tool,write_file_tool;from tools.terminal_tool import terminal_tool;'
                'import sys,json;paths=json.loads(sys.stdin.read());'
                'print(json.dumps({"read":[read_file_tool(p) for p in paths],'
                '"write":[write_file_tool(p,"probe") for p in paths],'
                '"own_read":read_file_tool("/workspace/private.txt"),'
                '"own_write":write_file_tool("/workspace/tool-owned.txt","owned-file-tool"),'
                '"terminal":terminal_tool("printf owned-terminal-tool; cat "+paths[0],task_id="same-task")}))')
        result = await lab.execute('alice', code, stdin=json.dumps([str(host_canary), b_path]).encode())
        assert marker not in result
        assert 'owned-terminal-tool' in result
        own = await lab.execute('alice', 'from pathlib import Path;print(Path("/workspace/private.txt").read_text())')
        assert own.strip() in result
        assert 'owned-file-tool' in await lab.execute('alice', 'from pathlib import Path;print(Path("/workspace/tool-owned.txt").read_text())')
        assert host_canary.read_text() == marker
        assert 'probe' not in await lab.execute('bobby', 'from pathlib import Path;print(Path("/workspace/private.txt").read_text())')
        code = ('import os,json,socket,hashlib;'
                'r={"uid":os.getuid(),"env_hashes":[hashlib.sha256(v.encode()).hexdigest() for v in os.environ.values()]};'
                'r["docker_socket"]=os.path.exists("/var/run/docker.sock");'
                'r["host_control"]=os.path.exists(' + repr(str(lab.settings.database)) + ');'
                '\ntry:\n socket.create_connection(("1.1.1.1",443),timeout=1);r["direct_network"]=True\n'
                'except OSError:r["direct_network"]=False\nprint(json.dumps(r))')
        result = json.loads(await lab.execute('alice', code))
        assert result['uid'] == lab.settings.worker_uid
        assert not result['docker_socket'] and not result['host_control'] and not result['direct_network']
        assert hashlib.sha256(lab.provider_secret.encode()).hexdigest() not in result['env_hashes']
        lab.results['actual_terminal_file_network_and_secret_isolation'] = True
    finally:
        host_canary.unlink(missing_ok=True)


async def test_shared_converter_runs_concurrently_via_real_agent_and_is_read_only(lab):
    for name, color in [('alice', 'red'), ('bobby', 'blue')]:
        await lab.execute(name, 'from PIL import Image;from pathlib import Path;'
            'Path("/workspace/same.jpg").unlink(missing_ok=True);'
            'Image.new("RGB",(20,20),' + repr(color) + ').save("/workspace/same.png")')
    async def convert(name):
        sid = await lab.session(name)
        stream = await lab.start_chat(name, sid, 'CONVERT_SHARED: use the shared converter for same.png into same.jpg')
        events = await lab.events(name, stream)
        assert any(event == 'done' for event, _ in events)
        assert any('terminal' in json.dumps(item) for event, item in events if event.startswith('tool'))
        return json.loads(await lab.execute(name, 'from PIL import Image;from pathlib import Path;import json,os;'
            'p=Path("/shared/tools/png_to_jpg.py");'
            'print(json.dumps({"pixel":Image.open("/workspace/same.jpg").getpixel((0,0)),"inode":p.stat().st_ino,"source":p.read_text()}))'))
    a, b = await asyncio.gather(convert('alice'), convert('bobby'))
    assert a['pixel'][0] > 200 and a['pixel'][2] < 30
    assert b['pixel'][2] > 200 and b['pixel'][0] < 30
    assert a['inode'] == b['inode'] and a['source'] == b['source']
    denied = await lab.execute('alice', 'from pathlib import Path;import json;'
        '\ntry:Path("/shared/tools/png_to_jpg.py").write_text("changed");r=False\nexcept OSError:r=True\n'
        '\ntry:Path("/shared/tools/png_to_jpg.py").unlink();u=False\nexcept OSError:u=True\nprint(json.dumps([r,u]))')
    assert json.loads(denied) == [True, True]
    lab.results['same_tool_same_filenames_concurrent_real_agent_execution'] = True
    lab.results['shared_source_read_only_and_same_inode'] = True


async def test_stream_and_cancel_are_owned_by_authenticated_runtime(lab):
    sid = await lab.session('bobby')
    stream = await lab.start_chat('bobby', sid, 'BLOCK_FOR_CANCEL')
    for _ in range(60):
        if lab.model.waiting.get(lab.users['bobby']['id'], asyncio.Event()).is_set():
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError('Actual Agent did not start its inference stream')
    status, _ = await lab.api('alice', '/api/chat/stream?stream_id=' + stream)
    assert status in (400, 403, 404)
    status, value = await lab.api('alice', '/api/chat/cancel?stream_id=' + stream)
    # Upstream cancel is idempotent: an unknown local stream returns 200/false.
    assert status == 200 and value['cancelled'] is False
    bob_before = lab.runtime('bobby')['runtime_id']
    status, value = await lab.api('bobby', '/api/chat/cancel?stream_id=' + stream)
    assert status == 200 and value['cancelled'] is True
    lab.model.release[lab.users['bobby']['id']].set()
    assert lab.runtime('bobby')['runtime_id'] == bob_before
    lab.results['stream_cancel_ownership'] = True


async def test_same_existing_profile_with_distinct_providers_and_read_only_shared_skills(lab):
    from aiohttp import web
    second_secret = secrets.token_urlsafe(32)
    second = type(lab.model)(second_secret)
    runner = web.AppRunner(second.app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    lab.runners.append(runner)
    port = site._server.sockets[0].getsockname()[1]
    provider = lab.store.put_provider('B account provider', f'http://127.0.0.1:{port}/v1', second_secret)
    status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users['bobby']['id'], {'provider_id': provider})
    assert status == 200
    await lab.ready(['bobby'])
    await lab.login('bobby', fresh=True)
    try:
        before_a, before_b = len(lab.model.requests), len(second.requests)
        sessions = await asyncio.gather(lab.session('alice'), lab.session('bobby'))
        streams = await asyncio.gather(*(lab.start_chat(name, sid, 'Use the existing common profile')
            for name, sid in zip(('alice', 'bobby'), sessions, strict=True)))
        events = await asyncio.gather(*(lab.events(name, stream) for name, stream in zip(('alice', 'bobby'), streams, strict=True)))
        assert all(any(event == 'done' for event, _ in owned) for owned in events)
        assert len(lab.model.requests) > before_a and len(second.requests) > before_b
        assert second.requests[-1]['user_id'] == lab.users['bobby']['id']
        assert lab.model.requests[-1]['user_id'] == lab.users['alice']['id']
        probes = []
        for name in ('alice', 'bobby'):
            status, me = await lab.api(name, '/multiuser/api/me')
            assert status == 200 and me['profile']['id'] == lab.template
            status, skills = await lab.api(name, '/api/skills')
            assert status == 200 and 'reviewed-base' in json.dumps(skills)
            code = ('from pathlib import Path;import json;'
                    'p=Path("/shared/skills/reviewed-base/SKILL.md");'
                    'r={"hash":__import__("hashlib").sha256(p.read_bytes()).hexdigest(),"inode":p.stat().st_ino};'
                    '\ntry:p.write_text("changed");r["writable"]=True\nexcept OSError:r["writable"]=False\n'
                    'print(json.dumps(r))')
            probes.append(json.loads(await lab.execute(name, code)))
        assert probes[0] == probes[1] and probes[0]['writable'] is False
        assert lab.store.user(lab.users['alice']['id'])['template_id'] == lab.store.user(lab.users['bobby']['id'])['template_id']
        lab.results['one_existing_profile_distinct_providers_shared_readonly_skills'] = True
    finally:
        status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users['bobby']['id'], {'provider_id': None})
        assert status == 200
        await lab.ready(['bobby'])
        await lab.login('bobby', fresh=True)


async def test_private_state_survives_restart_and_disable_stops_only_its_jobs(lab):
    await lab.execute('alice', 'from pathlib import Path;Path("/state/hermes/memories").mkdir(exist_ok=True);'
        'Path("/state/hermes/memories/MEMORY.md").write_text("alice-private-memory");'
        'Path("/workspace/persistent.txt").write_text("alice-private-file")')
    sid = await lab.session('alice')
    stream = await lab.start_chat('alice', sid, 'Conversation before restart')
    assert any(event == 'done' for event, _ in await lab.events('alice', stream))
    await lab.operator('stop-runtime', '--user', lab.users['alice']['id'])
    await lab.ready(['alice'])
    status, data = await lab.api('alice', '/api/session?session_id=' + sid)
    assert status == 200 and 'Conversation before restart' in json.dumps(data)
    files = await lab.execute('alice', 'from pathlib import Path;print(Path("/state/hermes/memories/MEMORY.md").read_text());print(Path("/workspace/persistent.txt").read_text())')
    assert 'alice-private-memory' in files and 'alice-private-file' in files
    heartbeat = 'from pathlib import Path;import time;\nwhile True: Path("/workspace/heartbeat").write_text(str(time.time()));time.sleep(.1)'
    code = ('import subprocess,sys,json;'
            'p=subprocess.Popen([sys.executable,"-c",' + repr(heartbeat) + '],'
            'start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print(json.dumps({"pid":p.pid}))')
    await asyncio.gather(lab.execute('alice', code), lab.execute('bobby', code))
    old_b = lab.runtime('bobby')['runtime_id']
    status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users['alice']['id'], {'enabled': False})
    assert status == 200
    status, _ = await lab.api('alice', '/api/sessions')
    assert status == 401
    await lab.operator('reconcile')
    assert lab.store.runtime(lab.users['alice']['id'])['state'] == 'disabled'
    assert lab.runtime('bobby')['runtime_id'] == old_b
    first = await lab.execute('bobby', 'from pathlib import Path;print(Path("/workspace/heartbeat").read_text())')
    await asyncio.sleep(0.3)
    second = await lab.execute('bobby', 'from pathlib import Path;print(Path("/workspace/heartbeat").read_text())')
    assert float(second) > float(first)
    status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users['alice']['id'], {'enabled': True})
    assert status == 200
    await lab.ready(['alice'])
    await lab.login('alice', fresh=True)
    lab.results['conversation_memory_workspace_persistence'] = True
    lab.results['disable_revokes_sessions_and_stops_only_owned_processes'] = True
