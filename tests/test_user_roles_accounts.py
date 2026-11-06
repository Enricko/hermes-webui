"""Account lifecycle regressions; every store and workspace is disposable."""
import json
from types import SimpleNamespace
from urllib.parse import urlparse
import pytest

from api import user_roles as roles


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "users.json"
    monkeypatch.setattr(roles, "users_file", lambda: path)
    monkeypatch.delenv("HERMES_WEBUI_USERS_FILE", raising=False)
    monkeypatch.setattr(roles, "_cache", None)
    roles.clear_request_restriction()
    yield path
    roles.clear_request_restriction()


@pytest.fixture(scope="module")
def password_hash():
    return roles.hash_password("synthetic-password-only")


def save(path, password_hash, **updates):
    rec = {"id": "alice-id", "password": password_hash, "role": "user",
           "profile": "alice", "workspaces": [str(path.parent / "workspace")]}
    rec.update(updates)
    path.write_text(json.dumps({"users": {"alice": rec}}))
    return rec


def session():
    account = roles.load_users()["alice"]
    return {"username": "alice", "bound_profile": "alice",
            "account_binding": roles.session_binding(account)}


def test_deleted_store_keeps_auth_required(store, password_hash):
    save(store, password_hash)
    assert roles.has_accounts()
    store.unlink()
    assert roles.has_accounts()
    assert roles.load_users() == {}


@pytest.mark.parametrize("content", ['{"users": {}}', '{', '[]', '{"users":null}'])
def test_empty_or_corrupt_store_keeps_auth_required(store, content):
    store.write_text(content)
    assert roles.has_accounts()
    assert roles.load_users() == {}


def test_explicit_missing_store_requires_auth(store, monkeypatch):
    monkeypatch.setenv("HERMES_WEBUI_USERS_FILE", str(store))
    assert roles.has_accounts()


def test_no_accounts_preserves_single_user_mode(store):
    assert not roles.has_accounts()


@pytest.mark.parametrize("change", [
    {"password": "pbkdf2_sha256$changed"}, {"id": "new-id"},
    {"role": "admin"}, {"profile": "other"}, {"disabled": True},
    {"auth_generation": 1},
])
def test_account_changes_revoke_existing_login(store, password_hash, change):
    save(store, password_hash)
    info = session()
    assert roles.resolve_session_account(info)[0]
    save(store, password_hash, **change)
    assert not roles.resolve_session_account(info)[0]


def test_old_unbound_login_is_rejected(store, password_hash):
    save(store, password_hash)
    assert not roles.resolve_session_account({"username": "alice", "bound_profile": "alice"})[0]


def test_grant_change_is_live_without_restoring_old_workspace(store, password_hash):
    save(store, password_hash)
    info = session()
    replacement = store.parent / "replacement"
    save(store, password_hash, workspaces=[str(replacement)])
    valid, restriction = roles.resolve_session_account(info)
    assert valid
    roles.set_request_restriction(restriction)
    assert roles.workspace_allowed(replacement)
    assert not roles.workspace_allowed(store.parent / "workspace")


@pytest.mark.parametrize("roots", ["/tmp", {}, ["relative"], ["~nonexistent-hermes-test-user"]])
def test_malformed_workspace_denies_record(store, password_hash, roots):
    save(store, password_hash, workspaces=roots)
    assert roles.load_users() == {}


def test_cache_is_scoped_to_store_path(store, password_hash, monkeypatch):
    save(store, password_hash)
    assert roles.load_users()
    other = store.parent / "other.json"
    other.write_text('{"users": {}}')
    monkeypatch.setattr(roles, "users_file", lambda: other)
    assert roles.load_users() == {}


def test_symlink_outside_workspace_is_denied(store, password_hash):
    save(store, password_hash)
    root = store.parent / "workspace"
    root.mkdir()
    (root / "escape").symlink_to(store.parent, target_is_directory=True)
    _, restriction = roles.resolve_session_account(session())
    roles.set_request_restriction(restriction)
    assert roles.workspace_allowed(root / "normal")
    assert not roles.workspace_allowed(root / "escape" / "users.json")


@pytest.mark.parametrize("stored", [
    "pbkdf2_sha256$-1$00$00", "pbkdf2_sha256$9999999999$00$00",
    "pbkdf2_sha256$600000$not-hex$00", "malformed", None,
])
def test_malformed_hash_is_denied(stored):
    assert not roles._verify_hash("password", stored)


def test_valid_password_and_disabled_account(store, password_hash):
    save(store, password_hash)
    assert roles.authenticate("ALICE", "synthetic-password-only")
    assert roles.authenticate("alice", "wrong") is None
    save(store, password_hash, disabled=True)
    assert roles.authenticate("alice", "synthetic-password-only") is None


@pytest.mark.parametrize("auth_type", [None, "trusted", "oidc", "passkey"])
def test_accountless_auth_cannot_bypass_account_mode(store, password_hash, monkeypatch, auth_type):
    from api import auth

    save(store, password_hash)
    monkeypatch.setattr(auth, "parse_cookie", lambda _: "synthetic-cookie")
    monkeypatch.setattr(auth, "verify_session", lambda _: True)
    monkeypatch.setattr(auth, "get_session_info", lambda _: {"auth_type": auth_type})
    invalidated = []
    monkeypatch.setattr(auth, "invalidate_session", invalidated.append)
    handler = SimpleNamespace()
    assert auth.ensure_trusted_auth_session(handler) is None
    assert invalidated == ["synthetic-cookie"]


@pytest.mark.parametrize("path", [
    "/api/chat/start", "/api/chat", "/api/file", "/api/terminal/start",
    "/api/sessions", "/api/cron", "/api/admin/access", "/api/providers",
])
def test_members_cannot_fall_back_to_privileged_host_execution(store, password_hash, path):
    save(store, password_hash)
    _, restriction = roles.resolve_session_account(session())
    roles.set_request_restriction(restriction)
    assert roles.request_denied(SimpleNamespace(command="POST"), urlparse(path))


def test_member_can_read_own_policy_catalog(store, password_hash):
    save(store, password_hash)
    _, restriction = roles.resolve_session_account(session())
    roles.set_request_restriction(restriction)
    assert roles.request_denied(SimpleNamespace(command="GET"), urlparse("/api/access/me")) is None
