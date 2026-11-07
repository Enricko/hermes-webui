"""Control-plane invariants with private disposable databases; no Agent imports."""

import concurrent.futures
import secrets

import pytest

from multiuser.store import LoginDenied, PolicyError, RateLimited, Store
from multiuser.templates import validate_template, worker_config


@pytest.fixture
def accounts(tmp_path):
    store = Store(tmp_path / 'control' / 'accounts.sqlite', session_ttl=60)
    store.initialize()
    password = secrets.token_urlsafe(24)
    admin = store.create_user('administrator', password, role='admin', bootstrap=True)
    return store, password, admin


def test_passwords_are_argon2id_and_never_in_account_responses(accounts):
    store, password, admin = accounts
    assert password not in repr(store.users())
    assert 'password_hash' not in store.user(admin['id'])
    with store.connection() as db:
        encoded = db.execute('SELECT password_hash FROM users').fetchone()[0]
    assert encoded.startswith('$argon2id$')
    assert password not in encoded


def test_session_expiry_logout_and_account_changes_revoke_sessions(accounts):
    store, password, _admin = accounts
    user = store.create_user('alice', password)
    token, principal = store.login('alice', password, '127.0.0.1', now=100)
    assert principal.user_id == user['id']
    assert store.session(token, now=159) is not None
    assert store.session(token, now=160) is None
    token, principal = store.login('alice', password, '127.0.0.1')
    store.logout(principal)
    assert store.session(token) is None
    for change in ({'password': secrets.token_urlsafe(24)}, {'enabled': False}):
        current_password = password
        if 'enabled' in change:
            store.update_user(user['id'], password=password)
        token, _principal = store.login('alice', current_password, '127.0.0.1')
        store.update_user(user['id'], **change)
        assert store.session(token) is None
    with pytest.raises(LoginDenied):
        store.login('alice', password, '127.0.0.1')


def test_role_change_revokes_an_existing_admin_session(accounts):
    store, password, admin = accounts
    store.create_user('second-admin', password, role='admin')
    token, _principal = store.login('administrator', password, '127.0.0.1')
    store.update_user(admin['id'], role='user')
    assert store.session(token) is None


def test_last_admin_cannot_be_removed_even_by_concurrent_updates(accounts):
    store, password, first = accounts
    second = store.create_user('second-admin', password, role='admin')
    def demote(user):
        try:
            store.update_user(user['id'], role='user')
            return True
        except PolicyError:
            return False
    with concurrent.futures.ThreadPoolExecutor() as pool:
        results = list(pool.map(demote, [first, second]))
    assert results.count(True) == 1
    assert sum(u['role'] == 'admin' and u['enabled'] for u in store.users()) == 1


def test_invalid_and_disabled_logins_are_generic_and_rate_limited(accounts):
    store, password, _admin = accounts
    user = store.create_user('alice', password)
    store.update_user(user['id'], enabled=False)
    for name in ['unknown-person', 'alice']:
        for _attempt in range(store.login_limit):
            with pytest.raises(LoginDenied, match='Invalid username or password'):
                store.login(name, password, 'peer')
        with pytest.raises(RateLimited):
            store.login(name, password, 'a-new-peer')


def test_user_ids_are_not_usernames_and_bootstrap_is_one_time(accounts):
    store, password, admin = accounts
    assert len(admin['id']) == 32 and admin['id'] != admin['username']
    with pytest.raises(PolicyError):
        store.create_user('new-bootstrap', password, role='admin', bootstrap=True)
    for name in ['../bob', '/root', 'a b', 'ab', 'alice\nadmin', 'a' * 49]:
        with pytest.raises(PolicyError):
            store.create_user(name, password)


def test_template_cannot_smuggle_state_credentials_or_path_traversal(accounts):
    store, _password, _admin = accounts
    provider = store.put_provider('Local fixture', 'http://127.0.0.1:9999/v1', 'provider-secret')
    base = {'provider_id': provider, 'model': 'test-model', 'soul': 'Shared identity'}
    for field in ['memory', 'conversation', 'user_id', 'env', 'api_key', 'mcp_servers']:
        with pytest.raises(PolicyError):
            validate_template({**base, field: 'private-state'})
    for name in ['../USER.md', '/root/.env', 'category/../../secret', 'x/.env', 'x/USER.md']:
        with pytest.raises(PolicyError):
            validate_template({**base, 'skills': {name: 'private'}})
    configuration = worker_config({**base, 'parameters': {'temperature': 0.5, 'max_tokens': 1024}})
    assert 'provider-secret' not in repr(configuration)
    assert configuration['terminal']['cwd'] == '/workspace'
    assert configuration['model']['base_url'] == 'http://127.0.0.1:8000/v1'
    assert configuration['agent']['max_tokens'] == 1024
    assert worker_config({**base, 'agent': {'max_iterations': 20}})['agent']['max_turns'] == 20


def test_same_profile_can_route_accounts_to_different_server_assigned_providers(accounts):
    from multiuser.broker import entitlement
    store, password, _admin = accounts
    first = store.put_provider('First provider', 'http://127.0.0.1:1/v1', 'first-secret')
    second = store.put_provider('Second provider', 'http://127.0.0.1:2/v1', 'second-secret')
    profile = store.put_template('Existing common profile', {'provider_id': first, 'model': 'approved',
        'soul': 'Existing identity', 'skills': {'shared/SKILL.md': 'Existing skill'}})
    alice = store.create_user('alice', password, template_id=profile)
    bob = store.create_user('bobby', password, template_id=profile, provider_id=second)
    a, b = entitlement(store, alice['id']), entitlement(store, bob['id'])
    assert a[0]['template_id'] == b[0]['template_id'] == profile
    assert a[2]['secret'] == 'first-secret' and b[2]['secret'] == 'second-secret'
    assert a[1]['soul'] == b[1]['soul'] and a[1]['skills'] == b[1]['skills']
    assert store.template(profile)['document']['provider_id'] == first
    token, _ = store.login('bobby', password, 'local')
    store.update_user(bob['id'], provider_id=None, assign_provider=True)
    assert store.session(token) is None
    assert entitlement(store, bob['id'])[2]['id'] == first
    for invalid in ['../../outside', 'f' * 32]:
        with pytest.raises(PolicyError):
            store.update_user(alice['id'], provider_id=invalid, assign_provider=True)
    store.put_provider('Second provider', 'http://127.0.0.1:2/v1', provider_id=second, enabled=False)
    with pytest.raises(PolicyError):
        store.create_user('charlie', password, template_id=profile, provider_id=second)


def test_version_one_upgrade_preserves_accounts_sessions_and_profile(accounts, tmp_path):
    import sqlite3
    from multiuser.manage import upgrade
    from multiuser.settings import Settings
    store, password, admin = accounts
    token, _ = store.login('administrator', password, 'local')
    with store.connection() as db:
        db.execute('ALTER TABLE users DROP COLUMN provider_id')
        db.execute('PRAGMA user_version=1')
    backup = tmp_path.with_name(tmp_path.name + '-upgrade-backup')
    settings = Settings(root=store.path.parent.parent)
    assert upgrade(settings, backup)['schema_version'] == 3
    assert store.session(token).user_id == admin['id']
    assert store.user(admin['id'])['provider_id'] is None
    with sqlite3.connect(backup / 'accounts-before.sqlite') as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM users').fetchone()[0] == 1
    assert backup.stat().st_mode & 0o777 == 0o700
    assert (backup / 'accounts-before.sqlite').stat().st_mode & 0o777 == 0o600
