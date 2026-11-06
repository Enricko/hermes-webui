"""Read-only member API for administrator-granted folder references (M5).

Real login store, real private folders and real SQLite policy; every account,
file and credential-shaped string is synthetic and disposable.
"""
import base64
import json
from pathlib import Path
from urllib.parse import quote, urlparse

import pytest

from api import access_admin, account_admin, member_routes, user_roles
from api.access_policy import AccessContext
from api.member_chat import MemberChat
# Reuse the disposable login store/policy fixture and the fake HTTP handler.
from tests.test_account_admin import accounts  # noqa: F401
from tests.test_access_admin import Handler, login

ROUTES = ("/api/member/references", "/api/member/reference/files", "/api/member/reference/file")


@pytest.fixture
def env(request, tmp_path, monkeypatch):
    # Logins are never authenticated here; the lowest accepted cost keeps setup fast.
    monkeypatch.setattr(user_roles, "_ITERATIONS", 100_000)
    _, policy, root = request.getfixturevalue("accounts")
    ids = {}
    for name in ("alice", "bob", "carol"):
        ids[name] = account_admin.edit_account("admin-id", username=name, role="user", enabled=True,
                                               password="synthetic-password-" + name, create=True,
                                               state_root=root, policy=policy)["id"]
    for kind, identifier, binding in [("profile", "shared", {"system_prompt": "synthetic"}),
                                      ("workspace", "private", {}),
                                      ("connection", "provider", {"protocol": "openai", "account_id": "synthetic",
                                                                  "base_url": "http://127.0.0.1:9/v1"})]:
        policy.put_resource("admin-id", identifier, kind=kind, label=identifier, binding=binding)
    for name in ("alice", "bob"):
        policy.replace_grants("admin-id", ids[name], {"shared": [], "private": [], "provider": ["allowed"]})
    bob_root = root / ids["bob"] / "bob"
    (bob_root / "notes").mkdir()
    (bob_root / "notes" / "plan.txt").write_text("bob shared plan")
    (bob_root / "readme.md").write_text("bob readme")
    (bob_root / ".env").write_text("SYNTHETIC_TOKEN=hidden-env-sentinel")
    (bob_root / "id_rsa").write_text("hidden-key-sentinel")
    (bob_root / "server.key").write_text("hidden-key-sentinel")
    (bob_root / "big.bin").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host-secret.txt").write_text("host-secret-sentinel")
    (bob_root / "escape").symlink_to(outside, target_is_directory=True)
    (bob_root / "link.txt").symlink_to(outside / "host-secret.txt")
    (bob_root / "alias.md").symlink_to(bob_root / "readme.md")
    (root / ids["carol"] / "carol" / "carol.txt").write_text("carol private")
    policy.replace_references("admin-id", ids["alice"], [ids["bob"]])
    monkeypatch.setenv("HERMES_WEBUI_MEMBER_CHAT", "1")
    monkeypatch.setenv("HERMES_WEBUI_MEMBER_DATA_DIR", str(tmp_path / "member-data"))
    monkeypatch.setattr(access_admin, "configured_store", lambda: policy)
    monkeypatch.setattr(user_roles, "resolve_session_account", lambda _: (True, None))
    return policy, ids, bob_root, tmp_path


def call(monkeypatch, username, path, owner=None, rel=None, command="GET", body=None, auth_type="local"):
    login(monkeypatch, username, auth_type)
    query = "&".join(f"{key}={quote(value, safe='')}" for key, value in (("owner", owner), ("path", rel)) if value is not None)
    handler = Handler(command)
    member_routes.handle_member(handler, urlparse(path + ("?" + query if query else "")), body)
    return handler.status, json.loads(handler.wfile.getvalue() or b"null")


def tree(root):
    return sorted((str(p.relative_to(root)), p.is_symlink() or p.is_dir() or p.read_bytes()) for p in Path(root).rglob("*"))


def test_granted_reference_lists_and_reads_target_folder(env, monkeypatch):
    _, ids, _, tmp_path = env
    status, body = call(monkeypatch, "alice", "/api/member/references")
    assert status == 200 and body == {"references": [{"id": ids["bob"], "username": "bob"}]}
    status, catalog = call(monkeypatch, "alice", "/api/member/catalog")
    assert status == 200 and catalog["references"] == [{"id": ids["bob"], "username": "bob"}]
    status, listing = call(monkeypatch, "alice", ROUTES[1], ids["bob"])
    assert status == 200 and listing["read_only"] is True and listing["truncated"] is False
    assert [row["name"] for row in listing["files"]] == ["notes", "big.bin", "readme.md"]
    status, nested = call(monkeypatch, "alice", ROUTES[1], ids["bob"], "notes")
    assert status == 200 and [row["name"] for row in nested["files"]] == ["plan.txt"]
    status, read = call(monkeypatch, "alice", ROUTES[2], ids["bob"], "notes/plan.txt")
    assert status == 200 and read["read_only"] is True
    assert base64.b64decode(read["content"]) == b"bob shared plan" and read["size"] == 15
    for response in (listing, nested, read, catalog):
        assert str(tmp_path) not in json.dumps(response)


def test_file_size_limit_and_directories_are_not_files(env, monkeypatch):
    _, ids, *_ = env
    assert call(monkeypatch, "alice", ROUTES[2], ids["bob"], "big.bin")[0] == 400
    assert call(monkeypatch, "alice", ROUTES[2], ids["bob"], "notes")[0] == 400
    assert call(monkeypatch, "alice", ROUTES[2], ids["bob"], "")[0] == 400


def test_no_grant_and_unknown_owner_are_indistinguishable(env, monkeypatch):
    _, ids, *_ = env
    denied = []
    for user, owner in [("carol", ids["bob"]), ("bob", ids["alice"]), ("alice", ids["carol"]),
                        ("alice", ids["alice"]), ("alice", "no-such-account"), ("alice", "admin-id"),
                        ("alice", "../" + ids["bob"]), ("alice", "")]:
        for route in ROUTES[1:]:
            denied.append(call(monkeypatch, user, route, owner, "readme.md" if route == ROUTES[2] else None))
    assert all(response == (403, {"error": "Access is not granted to this account"}) for response in denied)
    assert call(monkeypatch, "carol", ROUTES[0]) == (200, {"references": []})


def test_revoke_takes_effect_on_the_very_next_request(env, monkeypatch):
    policy, ids, *_ = env
    assert call(monkeypatch, "alice", ROUTES[2], ids["bob"], "readme.md")[0] == 200
    policy.replace_references("admin-id", ids["alice"], [])
    assert call(monkeypatch, "alice", ROUTES[2], ids["bob"], "readme.md")[0] == 403
    assert call(monkeypatch, "alice", ROUTES[1], ids["bob"])[0] == 403
    assert call(monkeypatch, "alice", ROUTES[0]) == (200, {"references": []})


def test_disabling_target_login_denies_reference(env, monkeypatch):
    policy, ids, *_ = env
    account_admin.edit_account("admin-id", username="bob", role="user", enabled=False, policy=policy)
    assert call(monkeypatch, "alice", ROUTES[1], ids["bob"])[0] == 403
    assert call(monkeypatch, "alice", ROUTES[0]) == (200, {"references": []})


@pytest.mark.parametrize("command", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("route", ROUTES)
def test_write_attempts_are_refused_without_side_effects(env, monkeypatch, command, route):
    _, ids, bob_root, _ = env
    before = tree(bob_root)
    payload = base64.b64encode(b"overwrite attempt").decode()
    for action in ("write", "mkdir", "delete", "rename", "upload"):
        body = {"action": action, "owner": ids["bob"], "path": "readme.md", "content": payload, "to": "moved.md"}
        status, response = call(monkeypatch, "alice", route, ids["bob"], "readme.md", command=command, body=body)
        assert status == 405 and response == {"error": "Reference folders are read only"}
    assert tree(bob_root) == before


def test_member_file_api_cannot_reach_reference_folder(env, monkeypatch):
    _, ids, bob_root, _ = env
    before = tree(bob_root)
    context = {"profile_id": "shared", "workspace_id": "private", "connection_id": "provider", "model": "allowed"}
    for path in ("../../../private-users/" + ids["bob"] + "/bob/readme.md", str(bob_root / "readme.md")):
        for action in ("write", "mkdir", "read", "list"):
            body = {"action": action, "context": context, "path": path, "content": base64.b64encode(b"x").decode()}
            assert call(monkeypatch, "alice", "/api/member/files", command="POST", body=body)[0] == 400
    assert tree(bob_root) == before


@pytest.mark.parametrize("rel", ["../", "..", "../carol", "notes/../../x", "/etc/passwd", "notes\\plan.txt",
                                 "a//b", ".", "notes/./plan.txt", "readme.md\0.txt", "x" * 2049])
def test_path_traversal_is_rejected(env, monkeypatch, rel):
    _, ids, _, tmp_path = env
    for route in ROUTES[1:]:
        status, body = call(monkeypatch, "alice", route, ids["bob"], rel)
        assert status == 400 and str(tmp_path) not in json.dumps(body)


@pytest.mark.parametrize("rel", ["escape", "escape/host-secret.txt", "link.txt", "alias.md",
                                 ".env", "id_rsa", "server.key", "notes/.hidden"])
def test_symlinks_and_hidden_secrets_are_refused(env, monkeypatch, rel):
    _, ids, *_ = env
    for route in ROUTES[1:]:
        status, body = call(monkeypatch, "alice", route, ids["bob"], rel)
        assert status == 400
        assert "sentinel" not in json.dumps(body)


def test_target_conversations_and_member_data_are_never_exposed(env, monkeypatch):
    policy, ids, bob_root, tmp_path = env
    bob_context = AccessContext(ids["bob"], "shared", "private", "provider", "allowed")
    service = MemberChat(policy, tmp_path / "member-data")
    conversation = service.create(bob_context)
    with policy._transaction(write=True) as db:
        db.execute("INSERT INTO member_messages VALUES (?,?,?,?)",
                   (conversation["id"], 0, "user", "bob-conversation-sentinel"))
    service.write_file(bob_context, "member-upload.txt", b"bob-member-data-sentinel")
    seen = [call(monkeypatch, "alice", route)[1] for route in ("/api/member/references", "/api/member/catalog")]
    pending = [""]
    while pending:
        folder = pending.pop()
        status, listing = call(monkeypatch, "alice", ROUTES[1], ids["bob"], folder)
        assert status == 200
        seen.append(listing)
        for row in listing["files"]:
            rel = f"{folder}/{row['name']}" if folder else row["name"]
            if row["directory"]:
                pending.append(rel)
            elif row["size"] <= 2 * 1024 * 1024:
                status, read = call(monkeypatch, "alice", ROUTES[2], ids["bob"], rel)
                assert status == 200
                seen.append({**read, "content": base64.b64decode(read["content"]).decode()})
    encoded = json.dumps(seen)
    for secret in ("bob-conversation-sentinel", conversation["id"], "bob-member-data-sentinel",
                   "hidden-env-sentinel", "hidden-key-sentinel", "host-secret-sentinel", "carol private",
                   "password", "pbkdf2", str(tmp_path)):
        assert secret not in encoded
    # The grantee's own conversation list never contains the target's rows.
    assert call(monkeypatch, "alice", "/api/member/conversations")[1] == {"conversations": []}
    # The private conversation is still only readable by its owner.
    assert call(monkeypatch, "alice", f"/api/member/conversation?id={conversation['id']}")[0] == 403


@pytest.mark.parametrize("auth_type", [None, "trusted", "passkey", "oidc"])
def test_reference_routes_require_account_login(env, monkeypatch, auth_type):
    _, ids, *_ = env
    for route in ROUTES:
        assert call(monkeypatch, "alice", route, ids["bob"], auth_type=auth_type)[0] == 403
