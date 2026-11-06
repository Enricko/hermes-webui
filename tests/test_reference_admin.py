"""Administrator API, CLI and UI wiring for read-only folder references (M5)."""
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

import pytest

from api import access_admin, user_roles
from api.access_policy import PolicyStore
# Reuse the admin API fixture (admin-id + alice-id) and the fake HTTP handler.
from tests.test_access_admin import Handler, login, policy  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def store(request, monkeypatch):
    store = request.getfixturevalue("policy")
    store.put_account("admin-id", "bob-id")
    store.put_account("admin-id", "carol-id")
    monkeypatch.setattr(user_roles, "load_users", lambda: {
        "admin": {"id": "admin-id", "role": "admin"}, "alice": {"id": "alice-id", "role": "user"},
        "bob": {"id": "bob-id", "role": "user"}, "carol": {"id": "carol-id", "role": "user"}})
    return store


def post(monkeypatch, body, username="admin"):
    login(monkeypatch, username)
    handler = Handler("POST")
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"), body)
    return handler.status, json.loads(handler.wfile.getvalue())


def get(monkeypatch, path, username="admin"):
    login(monkeypatch, username)
    handler = Handler()
    access_admin.handle_access_admin(handler, urlparse(path))
    return handler.status, json.loads(handler.wfile.getvalue())


def test_admin_sets_references_with_grants_and_member_sees_only_names(store, monkeypatch):
    before = store.snapshot("admin-id")["revision"]
    status, body = post(monkeypatch, {"action": "grants", "account_id": "alice-id",
                                      "grants": {"private-resource": []}, "references": ["bob-id"]})
    assert status == 200 and body["revision"] == before + 1
    status, snapshot = get(monkeypatch, "/api/admin/access")
    assert status == 200 and snapshot["references"] == [{"account_id": "alice-id", "target_id": "bob-id"}]
    status, me = get(monkeypatch, "/api/access/me", "alice")
    assert status == 200 and me["references"] == [{"id": "bob-id", "username": "bob"}]
    status, other = get(monkeypatch, "/api/access/me", "bob")
    assert status == 200 and other["references"] == []


def test_grants_without_references_keep_existing_references(store, monkeypatch):
    store.replace_references("admin-id", "alice-id", ["bob-id"])
    status, _ = post(monkeypatch, {"action": "grants", "account_id": "alice-id", "grants": {"private-resource": []}})
    assert status == 200 and store.reference_targets("alice-id") == ["bob-id"]
    status, _ = post(monkeypatch, {"action": "grants", "account_id": "alice-id",
                                   "grants": {"private-resource": []}, "references": []})
    assert status == 200 and store.reference_targets("alice-id") == []


@pytest.mark.parametrize("references,expected", [
    (["alice-id"], 400), (["unknown-id"], 403), (["../bob-id"], 400), ("bob-id", 400), ([None], 400),
])
def test_invalid_reference_requests_are_refused_without_change(store, monkeypatch, references, expected):
    store.replace_references("admin-id", "alice-id", ["bob-id"])
    before = store.snapshot("admin-id")
    status, _ = post(monkeypatch, {"action": "grants", "account_id": "alice-id",
                                   "grants": {}, "references": references})
    assert status == expected
    assert store.snapshot("admin-id") == before


def test_disabled_target_is_refused(store, monkeypatch):
    store.put_account("admin-id", "carol-id", enabled=False)
    status, _ = post(monkeypatch, {"action": "grants", "account_id": "alice-id",
                                   "grants": {"private-resource": []}, "references": ["carol-id"]})
    assert status == 403 and store.reference_targets("alice-id") == []


def test_member_cannot_grant_itself_references(store, monkeypatch):
    status, _ = post(monkeypatch, {"action": "grants", "account_id": "alice-id",
                                   "grants": {"private-resource": []}, "references": ["bob-id"]}, "alice")
    assert status == 403 and store.reference_targets("alice-id") == []


def test_cli_replaces_references_by_username(tmp_path):
    users = tmp_path / "users.json"
    synthetic_hash = user_roles.hash_password("synthetic-only-password")
    users.write_text(json.dumps({"users": {name: {"id": f"{name}-id", "role": "admin" if name == "admin" else "user",
                                                  "password": synthetic_hash, "profile": name,
                                                  "workspaces": [str(tmp_path / name)]}
                                           for name in ("admin", "alice", "bob")}}))
    policy_path = tmp_path / "policy.sqlite"
    script = ROOT / "scripts" / "webui_access.py"
    environment = {**os.environ, "HERMES_WEBUI_USERS_FILE": str(users)}
    def run(*args, check=True):
        result = subprocess.run([sys.executable, str(script), "--policy", str(policy_path), "--admin", "admin", *args],
                                env=environment, capture_output=True, text=True, timeout=20)
        assert (result.returncode == 0) is check, result.stderr
        assert synthetic_hash not in result.stdout
        return result.stdout
    run("init")
    run("account", "alice")
    run("account", "bob")
    run("references", "alice", "bob")
    assert PolicyStore(policy_path).reference_targets("alice-id") == ["bob-id"]
    assert json.loads(run("show"))["references"] == [{"account_id": "alice-id", "target_id": "bob-id"}]
    run("references", "alice", "alice", check=False)
    run("references", "alice", "nobody", check=False)
    assert PolicyStore(policy_path).reference_targets("alice-id") == ["bob-id"]
    run("references", "alice")
    assert PolicyStore(policy_path).reference_targets("alice-id") == []


def test_admin_ui_sends_references_separately_from_resource_grants():
    source = (ROOT / "static" / "access-admin.js").read_text()
    assert "Folder references (read-only)" in source
    assert "querySelectorAll('input[data-resource-id]:checked')" in source
    assert "querySelectorAll('input[data-reference-id]:checked')" in source
    assert "action: 'grants', account_id: selected.id, grants, references" in source
