"""Synthetic provider integration, real SQLite and adversarial private files."""
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from api.access_policy import AccessContext, AccessDenied, PolicyStore
from api.member_chat import MemberChat, ConversationBusy
from api.provider_broker import ProviderFailure, infer


@pytest.fixture
def provider():
    received = []
    entered, release = threading.Event(), threading.Event()
    settings = {"wait": False, "error": False}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            received.append((self.path, dict(self.headers), body))
            entered.set()
            if settings["wait"]:
                assert release.wait(10)
            response = ({"content": [{"type": "text", "text": "synthetic reply"}]} if self.path.endswith('/messages')
                        else {"choices": [{"message": {"content": "synthetic reply"}}]})
            if settings['error']:
                response = {'error':'synthetic-provider-key must never be reflected'}
            payload = json.dumps(response).encode()
            self.send_response(401 if settings["error"] else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}/v1', received, settings, entered, release
    release.set()
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def service(tmp_path, provider):
    endpoint, *_ = provider
    policy = PolicyStore.initialize(tmp_path / 'policy.sqlite', 'admin')
    for user in ('alice', 'bob'):
        policy.put_account('admin', user)
    for kind, identifier, binding in [
        ('profile', 'shared', {'system_prompt': 'Administrator profile instructions'}),
        ('workspace', 'private', {}),
        ('skill', 'writing', {'content': 'Administrator writing skill'}),
        ('connection', 'provider', {'protocol': 'openai', 'base_url': endpoint, 'account_id': 'synthetic-account'}),
    ]:
        policy.put_resource('admin', identifier, kind=kind, label=identifier, binding=binding)
    for user in ('alice', 'bob'):
        policy.replace_grants('admin', user, {'shared': [], 'private': [], 'writing': [], 'provider': ['allowed']})
    service = MemberChat(policy, tmp_path / 'private-state')
    service.vault.put('provider', 'synthetic-provider-key', {'protocol': 'openai', 'base_url': endpoint, 'account_id': 'synthetic-account'})
    return service


def context(user='alice'):
    return AccessContext(user, 'shared', 'private', 'provider', 'allowed', ('writing',))


def test_two_users_have_private_conversations_and_files(service, provider):
    conversation = service.create(context())
    assert service.chat('alice', conversation['id'], 'Hello')['reply'] == 'synthetic reply'
    assert len(service.read('alice', conversation['id'])['messages']) == 2
    assert service.conversations('bob') == []
    with pytest.raises(AccessDenied):
        service.read('bob', conversation['id'])
    with pytest.raises(AccessDenied):
        service.chat('bob', conversation['id'], 'foreign input')
    service.write_file(context(), 'private.txt', b'alice private sentinel')
    assert service.list_files(context('bob')) == []
    with pytest.raises(FileNotFoundError):
        service.read_file(context('bob'), 'private.txt')
    assert service.read_file(context(), 'private.txt') == b'alice private sentinel'
    _, received, *_ = provider
    body = received[0][2]
    assert body['messages'][0]['content'] == 'Administrator profile instructions\n\nAdministrator writing skill'
    assert 'tools' not in body and 'tool_choice' not in body
    assert 'synthetic-provider-key' not in json.dumps(body)


@pytest.mark.parametrize('field,value', [('model', 'other'), ('connection_id', 'other'), ('profile_id', 'other'), ('skills', ('other',))])
def test_forged_selection_never_reaches_provider(service, provider, field, value):
    with pytest.raises(AccessDenied):
        service.create(replace(context(), **{field: value}))
    assert provider[1] == []


def test_native_anthropic_messages(service, provider):
    binding = {'protocol': 'anthropic', 'base_url': provider[0], 'account_id': 'anthropic-account'}
    service.policy.put_resource('admin', 'provider', kind='connection', label='native', binding=binding)
    service.vault.put('provider', 'synthetic-anthropic-key', binding)
    reply, _ = infer(service.policy, service.vault, context(), [{'role': 'user', 'content': 'Hello'}])
    assert reply == 'synthetic reply'
    path, headers, body = provider[1][0]
    assert path == '/v1/messages'
    assert headers['X-Api-Key'] == 'synthetic-anthropic-key'
    assert body['system'].startswith('Administrator profile instructions')
    assert body['model'] == 'allowed' and 'tools' not in body


def test_relink_does_not_reuse_old_credentials(service, provider):
    binding = {'protocol': 'openai', 'base_url': provider[0], 'account_id': 'different-account'}
    service.policy.put_resource('admin', 'provider', kind='connection', label='new account', binding=binding)
    with pytest.raises(ProviderFailure):
        infer(service.policy, service.vault, context(), [{'role': 'user', 'content': 'hello'}])
    assert provider[1] == []


def test_revoke_during_provider_request_suppresses_output_and_persistence(service, provider):
    _, _, settings, entered, release = provider
    settings['wait'] = True
    conversation = service.create(context())
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(service.chat, 'alice', conversation['id'], 'private request')
        assert entered.wait(5)
        service.policy.replace_grants('admin', 'alice', {})
        release.set()
        with pytest.raises(AccessDenied):
            running.result(timeout=10)
    with service.policy._transaction() as db:
        assert db.execute('SELECT COUNT(*) FROM member_messages').fetchone()[0] == 0
        assert db.execute('SELECT busy FROM member_conversations').fetchone()[0] is None


def test_concurrent_send_cannot_duplicate_turn(service, provider):
    _, _, settings, entered, release = provider
    settings['wait'] = True
    conversation = service.create(context())
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(service.chat, 'alice', conversation['id'], 'first')
        assert entered.wait(5)
        with pytest.raises(ConversationBusy):
            service.chat('alice', conversation['id'], 'second')
        release.set()
        running.result(timeout=10)
    assert len(service.read('alice', conversation['id'])['messages']) == 2
    assert len(provider[1]) == 1


@pytest.mark.parametrize('path', ['../bob/secret', '/etc/passwd', 'a/../../secret', 'a\\secret', '.', 'a//b'])
def test_private_file_traversal_denied(service, path):
    with pytest.raises(ValueError):
        service.write_file(context(), path, b'forbidden')


def test_symlink_escape_is_not_followed_and_upload_replaces_leaf_link(service, tmp_path):
    service.write_file(context(), 'normal.txt', b'normal')
    root = service.root / 'files' / 'alice' / 'private'
    secret = tmp_path / 'host-secret'
    secret.write_text('host sentinel')
    (root / 'escape').symlink_to(tmp_path, target_is_directory=True)
    (root / 'linked.txt').symlink_to(secret)
    with pytest.raises(OSError):
        service.read_file(context(), 'escape/host-secret')
    with pytest.raises(OSError):
        service.read_file(context(), 'linked.txt')
    service.write_file(context(), 'linked.txt', b'own file')
    assert secret.read_text() == 'host sentinel'
    assert service.read_file(context(), 'linked.txt') == b'own file'


def test_nested_folders_and_revoked_workspace(service):
    service.write_file(context(), 'folder', b'', directory=True)
    service.write_file(context(), 'folder/file.txt', b'nested')
    assert service.read_file(context(), 'folder/file.txt') == b'nested'
    service.policy.replace_grants('admin', 'alice', {})
    with pytest.raises(AccessDenied):
        service.list_files(context())


def test_vault_requires_private_permissions(service):
    service.vault.path.chmod(0o644)
    from api.access_policy import PolicyUnavailable
    with pytest.raises(PolicyUnavailable):
        service.vault.get('provider', {})


def test_credentials_are_not_returned_in_errors(service, provider):
    provider[2]['error'] = True
    with pytest.raises(ProviderFailure) as failure:
        infer(service.policy, service.vault, context(), [{'role': 'user', 'content': 'hello'}])
    assert 'synthetic-provider-key' not in str(failure.value)
    assert service.vault.path.stat().st_mode & 0o077 == 0
