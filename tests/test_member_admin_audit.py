"""Administrator read-only view of member conversations, with audit (M1).

Real login store and real SQLite policy; every account, message and credential
string is synthetic and disposable. No provider is ever contacted: inference is
replaced by a function that fails the test if reached.
"""
from contextlib import closing
import json
import os
import sqlite3
from urllib.parse import urlparse

import pytest

from api import access_admin, account_admin, member_chat, member_routes, user_roles
from api.access_policy import AccessContext, AccessDenied, PolicyUnavailable
from api.member_chat import MemberChat
# Reuse the disposable login store/policy fixture and the fake HTTP handler.
from tests.test_account_admin import accounts  # noqa: F401
from tests.test_access_admin import Handler, login

LIST = "/api/member/admin/conversations"
READ = "/api/member/admin/conversation"
DENIED = (403, {"error": "Access is not granted to this account"})
UNKNOWN_ID = "0" * 32


@pytest.fixture
def env(request, tmp_path, monkeypatch):
    # Logins are never authenticated here; the lowest accepted cost keeps setup fast.
    monkeypatch.setattr(user_roles, "_ITERATIONS", 100_000)
    _, policy, root = request.getfixturevalue("accounts")
    ids = {"admin": "admin-id"}
    for name, role in (("alice", "user"), ("bob", "user"), ("admin2", "admin")):
        ids[name] = account_admin.edit_account("admin-id", username=name, role=role, enabled=True,
                                               password="synthetic-password-" + name, create=True,
                                               state_root=root, policy=policy)["id"]
    for kind, identifier, binding in [("profile", "shared", {"system_prompt": "synthetic"}),
                                      ("workspace", "private", {}),
                                      ("connection", "provider", {"protocol": "openai", "account_id": "synthetic",
                                                                  "base_url": "http://127.0.0.1:9/v1"})]:
        policy.put_resource("admin-id", identifier, kind=kind, label=identifier, binding=binding)
    for name in ("alice", "bob", "admin"):
        policy.replace_grants("admin-id", ids[name], {"shared": [], "private": [], "provider": ["allowed"]})
    service = MemberChat(policy, tmp_path / "member-data")
    conversations = {}
    for name in ("alice", "bob", "admin"):
        created = service.create(AccessContext(ids[name], "shared", "private", "provider", "allowed"))
        conversations[name] = created["id"]
        with policy._transaction(write=True) as db:
            db.executemany("INSERT INTO member_messages VALUES (?,?,?,?)", [
                (created["id"], 0, "user", f"{name}-question-sentinel"),
                (created["id"], 1, "assistant", f"{name}-answer-sentinel")])
            db.execute("UPDATE member_conversations SET title=? WHERE id=?", (f"{name}-title-sentinel", created["id"]))

    def never_infer(*args, **kwargs):
        raise AssertionError("provider must not be contacted")

    monkeypatch.setattr(member_chat, "infer", never_infer)
    monkeypatch.setenv("HERMES_WEBUI_MEMBER_CHAT", "1")
    monkeypatch.setenv("HERMES_WEBUI_MEMBER_DATA_DIR", str(tmp_path / "member-data"))
    monkeypatch.setattr(access_admin, "configured_store", lambda: policy)
    monkeypatch.setattr(user_roles, "resolve_session_account", lambda _: (True, None))
    return policy, ids, conversations, root


def call(monkeypatch, username, path, command="GET", body=None, auth_type="local"):
    login(monkeypatch, username, auth_type)
    handler = Handler(command)
    member_routes.handle_member(handler, urlparse(path), body)
    return handler.status, json.loads(handler.wfile.getvalue() or b"null")


def audit_rows(policy):
    with policy._transaction() as db:
        return [dict(row) for row in db.execute("SELECT * FROM member_admin_audit ORDER BY id")]


def state(policy):
    with policy._transaction() as db:
        return ([tuple(row) for row in db.execute("SELECT * FROM member_conversations ORDER BY id")],
                [tuple(row) for row in db.execute("SELECT * FROM member_messages ORDER BY conversation, ordinal")])


def test_ordinary_user_cannot_list_or_read_others_conversations(env, monkeypatch):
    policy, ids, conversations, _ = env
    before = state(policy)
    status, own = call(monkeypatch, "bob", "/api/member/conversations")
    assert status == 200 and [row["id"] for row in own["conversations"]] == [conversations["bob"]]
    responses = [own]
    for foreign in (conversations["alice"], conversations["admin"]):
        assert call(monkeypatch, "bob", f"/api/member/conversation?id={foreign}") == DENIED
        assert call(monkeypatch, "bob", f"{READ}?id={foreign}") == DENIED
        for path, body in [("/api/member/chat", {"conversation_id": foreign, "message": "foreign input"}),
                           (READ, {"id": foreign, "action": "delete"}),
                           (LIST, {"action": "rename", "id": foreign, "title": "x"})]:
            assert call(monkeypatch, "bob", path, "POST", body) == DENIED
    status, listing = call(monkeypatch, "bob", LIST)
    assert (status, listing) == DENIED
    responses.append(listing)
    encoded = json.dumps(responses)
    for secret in ("alice-question-sentinel", "alice-title-sentinel", conversations["alice"], ids["alice"],
                   "admin-question-sentinel", conversations["admin"]):
        assert secret not in encoded
    assert state(policy) == before
    assert audit_rows(policy) == []


def test_admin_lists_metadata_without_content(env, monkeypatch):
    policy, ids, conversations, _ = env
    status, body = call(monkeypatch, "admin", LIST)
    assert status == 200 and body["read_only"] is True
    rows = {row["id"]: row for row in body["conversations"]}
    assert set(rows) == set(conversations.values())
    for name in ("alice", "bob"):
        row = rows[conversations[name]]
        assert row == {"id": conversations[name], "owner_id": ids[name], "owner_username": name,
                       "created": row["created"], "own": False}
    own = rows[conversations["admin"]]
    assert own["own"] is True and own["title"] == "admin-title-sentinel"
    encoded = json.dumps(body)
    for name in ("alice", "bob"):
        for secret in (f"{name}-question-sentinel", f"{name}-answer-sentinel", f"{name}-title-sentinel"):
            assert secret not in encoded
    assert "messages" not in encoded and "context" not in encoded
    # Listing is metadata only and is not an audited content read.
    assert audit_rows(policy) == []


def test_admin_reads_foreign_content_read_only_with_one_audit_row_per_read(env, monkeypatch):
    policy, ids, conversations, _ = env
    before = state(policy)
    status, body = call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")
    assert status == 200
    assert body["read_only"] is True and body["own"] is False
    assert body["owner_id"] == ids["alice"] and body["owner_username"] == "alice"
    assert body["messages"] == [{"role": "user", "content": "alice-question-sentinel"},
                                {"role": "assistant", "content": "alice-answer-sentinel"}]
    rows = audit_rows(policy)
    assert len(rows) == 1
    assert {k: rows[0][k] for k in ("admin_account_id", "owner_account_id", "conversation_id", "action")} == {
        "admin_account_id": "admin-id", "owner_account_id": ids["alice"],
        "conversation_id": conversations["alice"], "action": "read"}
    assert set(rows[0]) == {"id", "admin_account_id", "owner_account_id", "conversation_id", "action", "created"}
    assert "sentinel" not in json.dumps(rows)
    assert call(monkeypatch, "admin2", f"{READ}?id={conversations['alice']}")[0] == 200
    rows = audit_rows(policy)
    assert len(rows) == 2 and rows[1]["admin_account_id"] == ids["admin2"]
    assert state(policy) == before


def test_admin_own_conversation_is_not_audited(env, monkeypatch):
    policy, _, conversations, _ = env
    status, body = call(monkeypatch, "admin", f"{READ}?id={conversations['admin']}")
    assert status == 200 and body["own"] is True and body["read_only"] is False
    assert body["messages"][0]["content"] == "admin-question-sentinel"
    status, owner_view = call(monkeypatch, "admin", f"/api/member/conversation?id={conversations['admin']}")
    assert status == 200 and owner_view["admin_views"] == 0
    assert audit_rows(policy) == []


def test_admin_cannot_write_send_or_use_owner_routes_on_foreign_conversations(env, monkeypatch):
    policy, _, conversations, _ = env
    before = state(policy)
    foreign = conversations["alice"]
    assert call(monkeypatch, "admin", f"/api/member/conversation?id={foreign}") == DENIED
    assert call(monkeypatch, "admin", "/api/member/chat", "POST",
                {"conversation_id": foreign, "message": "admin continues"}) == DENIED
    for path in (LIST, READ, f"{READ}?id={foreign}", "/api/member/admin/delete"):
        for action in ("send", "rename", "delete", "continue"):
            body = {"action": action, "id": foreign, "conversation_id": foreign, "message": "x", "title": "x"}
            assert call(monkeypatch, "admin", path, "POST", body) == DENIED
    # No rename/delete operation exists on the owner route for anyone.
    for action in ("rename", "delete"):
        status, _ = call(monkeypatch, "admin", f"/api/member/conversation?id={foreign}", "POST",
                         {"action": action, "id": foreign, "title": "x"})
        assert status == 404
    assert state(policy) == before
    assert audit_rows(policy) == []


def test_audit_write_failure_denies_read(env, monkeypatch):
    policy, _, conversations, _ = env
    with policy._transaction(write=True) as db:
        db.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON member_admin_audit "
                   "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
    status, body = call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")
    assert status == 503 and "sentinel" not in json.dumps(body)
    assert audit_rows(policy) == []
    with policy._transaction(write=True) as db:
        db.execute("DROP TRIGGER refuse_audit")
    assert call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")[0] == 200
    assert len(audit_rows(policy)) == 1


def test_missing_audit_table_denies_read_without_returning_content(env):
    policy, ids, conversations, root = env
    service = MemberChat(policy, root.parent / "member-data")
    with policy._transaction(write=True) as db:
        db.execute("DROP TABLE member_admin_audit")
    with pytest.raises(PolicyUnavailable):
        service.admin_read("admin-id", conversations["alice"])
    # Owner transparency cannot be computed either: fail closed, not "0 views".
    with pytest.raises(PolicyUnavailable):
        service.read(ids["alice"], conversations["alice"])


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes")
def test_read_only_policy_database_denies_admin_read(env, monkeypatch):
    policy, _, conversations, _ = env
    policy.path.chmod(0o400)
    try:
        status, body = call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")
    finally:
        policy.path.chmod(0o600)
    assert status == 503 and "sentinel" not in json.dumps(body)
    assert audit_rows(policy) == []


def test_owner_read_reports_admin_view_count_and_time_only(env, monkeypatch):
    policy, ids, conversations, _ = env
    status, before = call(monkeypatch, "alice", f"/api/member/conversation?id={conversations['alice']}")
    assert status == 200 and before["admin_views"] == 0 and before["last_admin_view"] is None
    call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")
    call(monkeypatch, "admin2", f"{READ}?id={conversations['alice']}")
    status, after = call(monkeypatch, "alice", f"/api/member/conversation?id={conversations['alice']}")
    assert status == 200 and after["admin_views"] == 2
    assert after["last_admin_view"] == max(row["created"] for row in audit_rows(policy))
    encoded = json.dumps(after)
    assert "admin-id" not in encoded and ids["admin2"] not in encoded and "admin2" not in encoded
    status, other = call(monkeypatch, "bob", f"/api/member/conversation?id={conversations['bob']}")
    assert status == 200 and other["admin_views"] == 0


@pytest.mark.parametrize("revoke", ["disable-both-stores", "disable-policy-only", "demote-policy-only",
                                    "demote-login-only"])
def test_disabled_or_demoted_admin_loses_access_on_next_request(env, monkeypatch, revoke):
    policy, ids, conversations, root = env
    assert call(monkeypatch, "admin2", f"{READ}?id={conversations['alice']}")[0] == 200
    assert call(monkeypatch, "admin2", LIST)[0] == 200
    if revoke == "disable-both-stores":
        account_admin.edit_account("admin-id", username="admin2", role="admin", enabled=False, policy=policy)
    elif revoke == "disable-policy-only":
        policy.put_account("admin-id", ids["admin2"], role="admin", enabled=False)
    elif revoke == "demote-policy-only":
        policy.put_account("admin-id", ids["admin2"], role="user", enabled=True)
    else:
        account_admin.edit_account("admin-id", username="admin2", role="user", enabled=True,
                                   state_root=root, policy=None)
    assert call(monkeypatch, "admin2", f"{READ}?id={conversations['alice']}") == DENIED
    assert call(monkeypatch, "admin2", LIST) == DENIED
    assert len(audit_rows(policy)) == 1


@pytest.mark.parametrize("disable", ["both-stores", "policy-only", "login-only"])
def test_admin_cannot_read_or_list_conversations_of_disabled_owner(env, monkeypatch, disable):
    policy, ids, conversations, root = env
    if disable == "both-stores":
        account_admin.edit_account("admin-id", username="alice", role="user", enabled=False, policy=policy)
    elif disable == "policy-only":
        policy.put_account("admin-id", ids["alice"], role="user", enabled=False)
    else:
        account_admin.edit_account("admin-id", username="alice", role="user", enabled=False,
                                   state_root=root, policy=None)
    # Sealed: same generic error as an unknown ID, nothing listed, nothing audited.
    assert call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}") == DENIED
    status, listing = call(monkeypatch, "admin", LIST)
    assert status == 200
    assert conversations["alice"] not in json.dumps(listing)
    assert conversations["bob"] in json.dumps(listing)
    assert audit_rows(policy) == []
    # Other owners and the administrator's own conversation are unaffected.
    assert call(monkeypatch, "admin", f"{READ}?id={conversations['bob']}")[0] == 200
    assert call(monkeypatch, "admin", f"{READ}?id={conversations['admin']}")[0] == 200
    # Re-enabling in both authorities makes the conversation readable again (and audited).
    account_admin.edit_account("admin-id", username="alice", role="user", enabled=True,
                               state_root=root, policy=policy)
    policy.put_account("admin-id", ids["alice"], role="user", enabled=True)
    status, body = call(monkeypatch, "admin", f"{READ}?id={conversations['alice']}")
    assert status == 200 and body["read_only"] is True
    assert [row["owner_account_id"] for row in audit_rows(policy)] == [ids["bob"], ids["alice"]]


def test_unknown_malformed_and_foreign_ids_share_one_generic_error(env, monkeypatch):
    policy, ids, conversations, _ = env
    with policy._transaction(write=True) as db:
        # Ownership integrity: a row whose stored context names another account.
        context = {"account_id": ids["alice"], "profile_id": "shared", "workspace_id": "private",
                   "connection_id": "provider", "model": "allowed", "skills": [], "tools": []}
        db.execute("INSERT INTO member_conversations VALUES (?,?,?,?,?,NULL,NULL)",
                   ("f" * 32, ids["bob"], json.dumps(context), "inconsistent", 0.0))
    probes = [conversations["alice"], UNKNOWN_ID, "f" * 32, "short", "", "../" + conversations["alice"]]
    for probe in probes:
        assert call(monkeypatch, "bob", f"/api/member/conversation?id={probe}") == DENIED
        assert call(monkeypatch, "bob", f"{READ}?id={probe}") == DENIED
    for probe in probes[1:]:
        assert call(monkeypatch, "admin", f"{READ}?id={probe}") == DENIED
    assert call(monkeypatch, "admin", "/api/member/admin/unknown") == DENIED
    assert "f" * 32 not in json.dumps(call(monkeypatch, "admin", LIST)[1])
    assert audit_rows(policy) == []


@pytest.mark.parametrize("auth_type", [None, "trusted", "passkey", "oidc"])
def test_admin_routes_require_account_login(env, monkeypatch, auth_type):
    _, _, conversations, _ = env
    for path in (LIST, f"{READ}?id={conversations['alice']}"):
        assert call(monkeypatch, "admin", path, auth_type=auth_type) == DENIED


def test_service_layer_refuses_non_admin_and_records_nothing(env):
    policy, ids, conversations, root = env
    service = MemberChat(policy, root.parent / "member-data")
    for account in (ids["alice"], ids["bob"], "no-such-account"):
        with pytest.raises(AccessDenied):
            service.admin_conversations(account)
        with pytest.raises(AccessDenied):
            service.admin_read(account, conversations["admin"])
    assert audit_rows(policy) == []
    # The schema itself refuses self-audit rows and unknown actions.
    with closing(sqlite3.connect(policy.path)) as db:
        for admin, action in (("admin-id", "read"), (ids["admin2"], "write")):
            with pytest.raises(sqlite3.IntegrityError):
                db.execute("INSERT INTO member_admin_audit(admin_account_id,owner_account_id,conversation_id,"
                           "action,created) VALUES (?,'admin-id',?,?,0)", (admin, conversations["admin"], action))
