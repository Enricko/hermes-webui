import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from api import account_admin, user_roles
from api.access_policy import AccessDenied, PolicyStore


@pytest.fixture
def accounts(tmp_path, monkeypatch):
    path = tmp_path / 'users.json'
    monkeypatch.setattr(user_roles, 'users_file', lambda: path)
    monkeypatch.setattr(user_roles, '_cache', None)
    path.write_text(json.dumps({'users': {'admin': {'id': 'admin-id', 'role': 'admin', 'password': user_roles.hash_password('synthetic-password')}}}))
    policy = PolicyStore.initialize(tmp_path / 'policy.sqlite', 'admin-id')
    return path, policy, tmp_path / 'private-users'


def test_admin_creates_account_and_private_workspace_without_exposing_password(accounts):
    path, policy, root = accounts
    result = account_admin.edit_account('admin-id', username='alice', role='user', enabled=True,
                                        password='synthetic-alice-password', create=True, state_root=root, policy=policy)
    assert user_roles.authenticate('alice', 'synthetic-alice-password')
    record = json.loads(path.read_text())['users']['alice']
    assert (root / result['id'] / 'alice').is_dir()
    assert result['workspace'] == '/alice'
    assert (root / result['id']).stat().st_mode & 0o077 == 0
    assert record['password'] != 'synthetic-alice-password'
    assert 'password' not in json.dumps(account_admin.public_accounts('admin-id'))
    assert result['id'] in [account['id'] for account in policy.snapshot('admin-id')['accounts']]


def test_password_reset_disable_and_reenable_preserve_id_but_revoke_login(accounts):
    _, policy, root = accounts
    first = account_admin.edit_account('admin-id', username='alice', role='user', enabled=True,
                                       password='synthetic-alice-password', create=True, state_root=root, policy=policy)
    rec = user_roles.load_users()['alice']
    info = {'username': 'alice', 'bound_profile': rec['profile'], 'account_binding': user_roles.session_binding(rec)}
    account_admin.edit_account('admin-id', username='alice', role='user', enabled=False, policy=policy)
    assert not user_roles.resolve_session_account(info)[0]
    account_admin.edit_account('admin-id', username='alice', role='user', enabled=True, password='new-synthetic-password', policy=policy)
    assert not user_roles.resolve_session_account(info)[0]
    assert user_roles.load_users()['alice']['id'] == first['id']


def test_user_cannot_create_or_promote_accounts(accounts):
    _, policy, root = accounts
    with pytest.raises(AccessDenied):
        account_admin.edit_account('unknown', username='attacker', role='admin', enabled=True,
                                   password='synthetic-password', create=True, state_root=root, policy=policy)


def test_last_administrator_cannot_disable_self(accounts):
    with pytest.raises(AccessDenied):
        account_admin.edit_account('admin-id', username='admin', role='admin', enabled=False, policy=accounts[1])
    assert user_roles.load_users()['admin']['role'] == 'admin'


def test_concurrent_account_creates_do_not_lose_updates(accounts):
    _, policy, root = accounts
    def create(username):
        return account_admin.edit_account('admin-id', username=username, role='user', enabled=True,
                                          password='synthetic-password', create=True, state_root=root, policy=policy)
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert len(list(executor.map(create, ['alice', 'bob']))) == 2
    assert set(user_roles.load_users()) == {'admin', 'alice', 'bob'}


@pytest.mark.parametrize('password', ['', 'short', 'a' * 1025, 42])
def test_invalid_new_password_is_rejected(accounts, password):
    with pytest.raises(ValueError):
        account_admin.edit_account('admin-id', username='alice', role='user', enabled=True,
                                   password=password, create=True, state_root=accounts[2])
