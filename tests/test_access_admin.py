import io
import json
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from api import access_admin, auth, user_roles
from api.access_policy import PolicyStore


class Handler:
    def __init__(self, command="GET"):
        self.command = command
        self.headers = {}
        self.request = SimpleNamespace()
        self.client_address = ("127.0.0.1", 1234)
        self.wfile = io.BytesIO()
        self.status = None
    def send_response(self, status):
        self.status = status
    def send_header(self, *args):
        pass
    def end_headers(self):
        pass


@pytest.fixture
def policy(tmp_path, monkeypatch):
    store = PolicyStore.initialize(tmp_path / "policy.sqlite", "admin-id")
    store.put_account("admin-id", "alice-id")
    store.put_resource("admin-id", "private-resource", kind="profile", label="Alice profile", binding={"target": "private"})
    store.replace_grants("admin-id", "alice-id", {"private-resource": []})
    monkeypatch.setattr(access_admin, "configured_store", lambda: store)
    monkeypatch.setattr(user_roles, "resolve_session_account", lambda _: (True, None))
    monkeypatch.setattr(user_roles, "load_users", lambda: {
        "admin": {"id": "admin-id", "role": "admin"}, "alice": {"id": "alice-id", "role": "user"}})
    return store


def login(monkeypatch, username="admin", auth_type="local"):
    monkeypatch.setattr(auth, "ensure_trusted_auth_session", lambda _: {"username": username, "auth_type": auth_type})


def test_admin_can_register_and_assign_resources(policy, monkeypatch):
    login(monkeypatch)
    handler = Handler("POST")
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"), {
        "action": "resource", "id": "skill", "kind": "skill", "label": "Coding", "binding": {"template": "coding"}})
    assert handler.status == 200
    assert any(r["id"] == "skill" for r in policy.snapshot("admin-id")["resources"])


@pytest.mark.parametrize("auth_type", [None, "trusted", "passkey", "oidc"])
def test_accountless_auth_cannot_read_admin_catalog(policy, monkeypatch, auth_type):
    login(monkeypatch, auth_type=auth_type)
    handler = Handler()
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"))
    assert handler.status == 403


def test_member_catalog_excludes_bindings_and_other_users(policy, monkeypatch):
    login(monkeypatch, "alice")
    handler = Handler()
    access_admin.handle_access_admin(handler, urlparse("/api/access/me"))
    assert handler.status == 200
    response = json.loads(handler.wfile.getvalue())
    assert response["account_id"] == "alice-id"
    assert response["runtime_ready"] is False
    assert len(response["resources"]) == 1
    assert "binding" not in response["resources"][0]


def test_member_cannot_write_admin_policy(policy, monkeypatch):
    login(monkeypatch, "alice")
    handler = Handler("POST")
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"), {"action": "account", "username": "alice"})
    assert handler.status == 403


def test_missing_policy_is_service_unavailable(policy, monkeypatch):
    login(monkeypatch)
    monkeypatch.setattr(access_admin, "configured_store", lambda: PolicyStore(policy.path.parent / "missing.sqlite"))
    handler = Handler()
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"))
    assert handler.status == 503
