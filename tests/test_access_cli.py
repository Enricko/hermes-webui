"""Exercise operator commands with synthetic stores, never production homes."""
import json
import os
from pathlib import Path
import subprocess
import sys

from api import user_roles
from api.access_policy import AccessContext, PolicyStore
from scripts import webui_users


def test_account_disable_enable_and_removal_keep_auth_closed(tmp_path, monkeypatch):
    store = tmp_path / "users.json"
    monkeypatch.setattr(user_roles, "users_file", lambda: store)
    record = {"id": "fixed-account-id", "role": "admin", "password": user_roles.hash_password("synthetic-password")}
    store.write_text(json.dumps({"users": {"admin": record}}))
    old = user_roles.load_users()["admin"]
    info = {"username": "admin", "bound_profile": None, "account_binding": user_roles.session_binding(old)}
    assert user_roles.resolve_session_account(info)[0]
    for command in ("disable", "enable"):
        monkeypatch.setattr(sys, "argv", ["webui_users", "--file", str(store), command, "admin"])
        webui_users.main()
        assert not user_roles.resolve_session_account(info)[0]
    latest = user_roles.load_users()["admin"]
    assert latest["id"] == "fixed-account-id"
    assert latest["auth_generation"] == 2
    monkeypatch.setattr(sys, "argv", ["webui_users", "--file", str(store), "remove", "admin"])
    webui_users.main()
    assert user_roles.load_users() == {}
    assert store.with_name("users.json.required").exists()
    assert user_roles.has_accounts()


def test_policy_cli_initialization_registration_and_grants(tmp_path):
    users = tmp_path / "users.json"
    synthetic_hash = user_roles.hash_password("synthetic-only-password")
    users.write_text(json.dumps({"users": {
        "admin": {"id": "admin-id", "role": "admin", "password": synthetic_hash},
        "alice": {"id": "alice-id", "role": "user", "password": synthetic_hash,
                  "profile": "alice", "workspaces": [str(tmp_path / "workspace")]},
    }}))
    policy = tmp_path / "policy.sqlite"
    script = Path(__file__).resolve().parents[1] / "scripts" / "webui_access.py"
    environment = {**os.environ, "HERMES_WEBUI_USERS_FILE": str(users)}
    def run(*args):
        result = subprocess.run([sys.executable, str(script), "--policy", str(policy), "--admin", "admin", *args],
                                env=environment, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert synthetic_hash not in result.stdout
        return result.stdout
    run("init")
    run("account", "alice")
    for kind, resource_id in (("profile", "shared"), ("workspace", "workspace"), ("connection", "provider")):
        source = tmp_path / f"{kind}.json"
        source.write_text(json.dumps({"id": resource_id, "kind": kind, "label": resource_id, "binding": {}}))
        run("resource", str(source))
    grants = tmp_path / "grants.json"
    grants.write_text(json.dumps({"shared": [], "workspace": [], "provider": ["approved-model"]}))
    run("grants", "alice", str(grants))
    assert json.loads(run("show"))["revision"] > 1
    admission = PolicyStore(policy).authorize(AccessContext("alice-id", "shared", "workspace", "provider", "approved-model"))
    assert admission.profile_instance_id
