"""Real Docker lab. Only the external model API is deterministic test data."""

import asyncio
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sys
import tempfile

import yaml

import aiohttp
from aiohttp import web

from multiuser.gateway import create_app
from multiuser.settings import Settings

REPO = Path(__file__).resolve().parent.parent


class Lab:
    def __init__(self, images, evidence):
        self.images = Path(images)
        self.evidence = Path(evidence)
        self.root = Path(tempfile.mkdtemp(prefix='hmu-e2e-', dir='/tmp'))
        self.users = {}
        self.passwords = {name: secrets.token_urlsafe(24) for name in ('administrator', 'alice', 'bobby')}
        self.clients = {}
        self.runners = []
        self.results = {}
        self.event_evidence = []

    async def operator(self, *arguments, stdin=None):
        command = ['sudo', '-n']
        # sudo deliberately strips loader variables. This optional prefix is
        # selected by the trusted test operator, never a browser or Agent.
        if os.environ.get('LD_LIBRARY_PATH'):
            command += ['env', 'LD_LIBRARY_PATH=' + os.environ['LD_LIBRARY_PATH']]
        process = await asyncio.create_subprocess_exec(*command, sys.executable, '-m', 'multiuser.manage',
            '--root', str(self.root), *arguments, cwd=REPO,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await process.communicate(stdin)
        if process.returncode:
            raise AssertionError('Trusted test provisioning failed: ' + err.decode(errors='replace')[-1000:])
        return json.loads(out)

    async def start(self):
        self.evidence.mkdir(parents=True, exist_ok=True)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.origin = f'http://127.0.0.1:{port}'
        await self.operator('init', '--public-url', self.origin, '--port', str(port),
                            '--gateway-uid', str(os.getuid()), '--images', str(self.images))
        self.settings = Settings.load(self.root)
        self.store = self.settings.store()
        self.users['administrator'] = await self.operator('bootstrap-admin', '--username', 'administrator', '--password-stdin',
            stdin=(self.passwords['administrator'] + '\n').encode())
        spec = importlib.util.spec_from_file_location('hmu_model_fixture', REPO / 'tests/fixtures/multiuser_provider.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.provider_secret = secrets.token_urlsafe(32)
        self.model = module.ModelFixture(self.provider_secret)
        model_runner = web.AppRunner(self.model.app(), access_log=None)
        await model_runner.setup()
        model_site = web.TCPSite(model_runner, '127.0.0.1', 0)
        await model_site.start()
        self.runners.append(model_runner)
        model_port = model_site._server.sockets[0].getsockname()[1]
        gateway_runner = web.AppRunner(create_app(self.settings), access_log=None)
        await gateway_runner.setup()
        await web.TCPSite(gateway_runner, '127.0.0.1', port).start()
        self.runners.append(gateway_runner)
        status, value = await self.api('administrator', '/multiuser/api/providers', {
            'name': 'Deterministic acceptance model', 'base_url': f'http://127.0.0.1:{model_port}/v1', 'secret': self.provider_secret})
        assert status == 200
        self.provider = value['id']
        self.named_models = {'Router One': self.model}
        self.connections = [{'provider_id': self.provider, 'name': 'Router One', 'model': 'fixture-model'}]
        for name in ('Router Two', 'Router Three'):
            secret = secrets.token_urlsafe(32)
            model = module.ModelFixture(secret)
            runner = web.AppRunner(model.app(), access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            self.runners.append(runner)
            self.named_models[name] = model
            provider_port = site._server.sockets[0].getsockname()[1]
            status, result = await self.api('administrator', '/multiuser/api/providers', {
                'name': name, 'base_url': f'http://127.0.0.1:{provider_port}/v1', 'secret': secret})
            assert status == 200
            self.connections.append({'provider_id': result['id'], 'name': name, 'model': 'fixture-model'})
        status, value = await self.api('administrator', '/multiuser/api/tools', {
            'name': 'PNG to JPEG', 'filename': 'png_to_jpg.py',
            'description': 'Use python /shared/tools/png_to_jpg.py --input /workspace/same.png --output /workspace/same.jpg --tmp-dir /tmp. Use private workspace job paths; do not recreate the converter.',
            'content': (REPO / 'multiuser/shared_tools/png_to_jpg.py').read_text()})
        assert status == 200
        self.tool = value['id']
        self.template_document = {'provider_id': self.provider, 'model': 'fixture-model', 'models': ['fixture-model'],
            'model_catalog': 'provider',
            'connections': self.connections,
            'parameters': {'context_length': 128000, 'max_tokens': 4096}, 'agent': {'max_iterations': 20},
            'soul': 'You are Hermes. Use the provided read-only shared tools before implementing a converter.',
            'tools': [self.tool], 'skills': {}, 'egress_hosts': []}
        status, value = await self.api('administrator', '/multiuser/api/templates', {'name': 'Acceptance base', 'document': self.template_document})
        assert status == 200
        self.template = value['id']
        self.profile_source = Path(tempfile.mkdtemp(prefix='hmu-profile-fixture-', dir='/tmp'))
        (self.profile_source / 'skills/reviewed-base').mkdir(parents=True)
        (self.profile_source / 'config.yaml').write_text('model:\n  default: fixture-model\n')
        (self.profile_source / 'SOUL.md').write_text(self.template_document['soul'])
        (self.profile_source / 'skills/reviewed-base/SKILL.md').write_text(
            '---\nname: reviewed-base\ndescription: Existing shared profile skill\n---\nUse the existing shared converter before recreating it.\n')
        await self.operator('reuse-profile', '--source', str(self.profile_source), '--template', self.template,
                            '--backup', str(self.evidence / 'profile-reuse-backup'))
        # Exercise portable discovery against installed main/named profiles,
        # while explicitly adopting the already-used capability identity.
        configured = []
        for connection in self.connections:
            provider = self.store.provider(connection['provider_id'])
            configured.append({'name': connection['name'], 'model': connection['model'],
                               'base_url': provider['base_url'], 'api_key': provider['secret']})
        source_config = {'model': {'default': 'fixture-model', 'provider': 'custom',
            'base_url': self.store.provider(self.provider)['base_url'], 'api_key': self.provider_secret},
            'custom_providers': configured, 'agent': {'max_turns': 20}}
        (self.profile_source / 'config.yaml').write_text(yaml.safe_dump(source_config))
        named = self.profile_source / 'profiles' / 'writer'; named.mkdir(parents=True)
        (named / 'config.yaml').write_text(yaml.safe_dump(source_config))
        (named / 'SOUL.md').write_text('Original named writer profile')
        (named / 'state.db').write_text('original private conversations must never be imported')
        (named / 'USER.md').write_text('original private user information')
        discovered = await self.operator('connect-hermes', '--hermes-home', str(self.profile_source),
            '--name', 'Installed Hermes', '--backup-root', str(self.evidence / 'discovery-backups'),
            '--adopt-template', 'default=' + self.template)
        assert all(p['status'] == 'ready' for p in discovered['profiles']), discovered
        assert discovered['profiles'][0]['template_id'] == self.template
        self.discovered_template = discovered['profiles'][1]['template_id']
        assert (await self.operator('sync-profiles'))['profiles'] == discovered['profiles']
        self.template_document = self.store.template(self.template)['document']
        for name in ('alice', 'bobby'):
            status, value = await self.api('administrator', '/multiuser/api/users', {'username': name,
                'password': self.passwords[name], 'role': 'user', 'template_id': self.template})
            assert status == 201
            self.users[name] = value['user']
        status, _ = await self.api('administrator', '/multiuser/api/users/' + self.users['administrator']['id'], {'template_id': self.template})
        assert status == 200
        await self.login('administrator', fresh=True)
        await self.ready()

    async def login(self, name, *, fresh=False):
        if fresh and name in self.clients:
            await self.clients.pop(name).close()
        if name not in self.clients:
            client = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True),
                timeout=aiohttp.ClientTimeout(total=90), headers={'Origin': self.origin})
            async with client.post(self.origin + '/api/auth/login', json={'username': name, 'password': self.passwords[name]}) as response:
                value = await response.json()
                assert response.status == 200
                client.headers['X-Hermes-CSRF-Token'] = value['user']['csrf_token']
            self.clients[name] = client
        return self.clients[name]

    async def api(self, name, path, body=None, *, method=None, headers=None):
        client = await self.login(name)
        async with client.request(method or ('POST' if body is not None else 'GET'), self.origin + path,
                                  json=body, headers=headers) as response:
            raw = await response.read()
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = raw.decode(errors='replace')
            return response.status, value

    async def ready(self, names=None):
        names = names or list(self.users)
        for _ in range(40):
            await self.operator('reconcile')
            states = [self.store.runtime(self.users[name]['id']) for name in names]
            if all(row and row['state'] == 'ready' for row in states):
                return
            if any(row and row['state'] in ('error', 'template_conflict') for row in states):
                raise AssertionError('Runtime admission failed: ' + str([(row['state'], row['error']) for row in states if row]))
            await asyncio.sleep(0.5)
        raise AssertionError('Disposable workers did not become ready')

    def runtime(self, name):
        return self.store.runtime(self.users[name]['id'])

    async def execute(self, name, code, *, stdin=b''):
        # docker exec does not inherit the entrypoint process's private runtime
        # variables. Use the same home/config for real file/terminal tool probes.
        process = await asyncio.create_subprocess_exec('docker', 'exec', '--interactive',
            '--env', 'HOME=/state/hermes', '--env', 'HERMES_HOME=/state/hermes',
            '--env', 'HERMES_BASE_HOME=/state/hermes', '--env', 'HERMES_CONFIG_PATH=/state/hermes/config.yaml',
            '--env', 'TMPDIR=/tmp', self.runtime(name)['runtime_id'],
            'python', '-c', code, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await process.communicate(stdin)
        if process.returncode:
            raise AssertionError('Worker probe failed: ' + err.decode(errors='replace')[-1200:])
        return out.decode()

    async def session(self, name):
        status, data = await self.api(name, '/api/session/new', {'workspace': '/workspace', 'model': 'fixture-model'})
        assert status == 200, data
        return data['session']['session_id']

    async def start_chat(self, name, sid, text):
        status, data = await self.api(name, '/api/chat/start', {'session_id': sid, 'message': text,
            'model': 'fixture-model', 'model_provider': 'custom', 'profile': 'default', 'workspace': '/workspace'})
        assert status == 200, data
        return data['stream_id']

    async def events(self, name, stream_id):
        client = await self.login(name)
        result = []
        async with client.get(self.origin + '/api/chat/stream?stream_id=' + stream_id) as response:
            assert response.status == 200
            event = None
            async for line in response.content:
                text = line.decode().strip()
                if text.startswith('event: '):
                    event = text[7:]
                elif text.startswith('data: '):
                    value = json.loads(text[6:])
                    result.append((event, value))
                    if event == 'stream_end':
                        break
        self.event_evidence.append(result)
        return result

    async def close(self):
        if hasattr(self, 'model'):
            for event in self.model.release.values():
                event.set()
        for client in self.clients.values():
            await client.close()
        with contextlib.suppress(Exception):
            await self.operator('stop-all-runtimes')
        for runner in reversed(self.runners):
            await runner.cleanup()
        self.evidence.mkdir(parents=True, exist_ok=True)
        (self.evidence / 'docker-events.json').write_text(json.dumps(self.event_evidence, indent=2) + '\n')
        (self.evidence / 'docker-acceptance.json').write_text(json.dumps({
            'results': self.results, 'root': str(self.root), 'images': json.loads(self.images.read_text()),
            'model_requests_bound_to': sorted({r['user_id'] for r in getattr(self, 'model', type('', (), {'requests': []})).requests}),
            'worker_implementation': 'actual upstream WebUI and actual Hermes Agent',
            'external_model': 'deterministic OpenAI protocol fixture'}, indent=2) + '\n')
        # This is the unique empty installation the fixture created; no existing
        # user directories, volumes, services or networks are removed.
        cleanup = ("from pathlib import Path;import json,shutil,sys;"
                   "p=Path(sys.argv[1]);assert p.parent==Path('/tmp') and p.name.startswith('hmu-e2e-');"
                   "c=json.loads((p/'settings.json').read_text());assert c['root']==str(p) and c['public_url'].startswith('http://127.0.0.1:');shutil.rmtree(p)")
        process = await asyncio.create_subprocess_exec('sudo', '-n', sys.executable, '-c', cleanup, str(self.root))
        await process.wait()
        if hasattr(self, 'profile_source'):
            shutil.rmtree(self.profile_source)
