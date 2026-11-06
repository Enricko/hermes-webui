"""M4: a profile grant carries that profile's shared skills and SOUL.

Synthetic Hermes homes under tmp_path only; the real Hermes home is never read.
"""
import hashlib
import io
import json
import os
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from api import access_admin, auth, user_roles
from api.access_policy import AccessContext, AccessDenied, PolicyStore

SOUL = "SYNTHETIC-SOUL-TEXT-7f3a: answer tersely and cite files."
SECRET = "SYNTHETIC-SECRET-VALUE-9b1c"
SECRET_NAMES = {".env", "auth.json", "id_rsa", "credentials.json", "server.key"}


def write_skill(home, rel, name=None, body="Do the thing."):
    directory = home / "skills" / rel
    directory.mkdir(parents=True, exist_ok=True)
    front = f"---\nname: {name}\ndescription: synthetic\n---\n" if name else ""
    (directory / "SKILL.md").write_text(front + body, encoding="utf-8")
    return directory


def make_home(root, name, *, soul=SOUL, skills=("alpha", "beta")):
    home = root / "hermes" / name
    home.mkdir(parents=True)
    if soul is not None:
        (home / "SOUL.md").write_text(soul, encoding="utf-8")
    for skill in skills:
        write_skill(home, f"category/{skill}", skill)
    for secret in (".env", "auth.json"):
        (home / secret).write_text(f"KEY={SECRET}\n", encoding="utf-8")
    (home / "memories").mkdir()
    (home / "memories" / "MEMORY.md").write_text(SECRET, encoding="utf-8")
    return home


@pytest.fixture
def env(tmp_path):
    store = PolicyStore.initialize(tmp_path / "policy" / "policy.sqlite", "admin")
    for user in ("alice", "bob"):
        store.put_account("admin", user)
    store.put_resource("admin", "ws", kind="workspace", label="ws", binding={})
    store.put_resource("admin", "conn", kind="connection", label="conn", binding={})
    homes = {"writer": make_home(tmp_path, "writer"),
             "coder": make_home(tmp_path, "coder", soul="Coder soul", skills=("gamma",))}

    def refresh(names=("coder", "writer")):
        rows = store.import_profiles("admin", list(names), homes={n: str(homes[n]) for n in names})
        return {row["name"]: row["id"] for row in rows}

    ids = refresh()
    return SimpleNamespace(store=store, homes=homes, ids=ids, refresh=refresh, tmp=tmp_path)


def grant(store, user, *resources):
    store.replace_grants("admin", user, {**{r: [] for r in resources}, "ws": [], "conn": ["m"]})


def ctx(user, profile):
    return AccessContext(user, profile, "ws", "conn", "m")


def revision(store):
    return store.snapshot("admin")["revision"]


def test_granted_profile_yields_its_skills_and_soul_digest(env):
    writer = env.ids["writer"]
    grant(env.store, "alice", writer)
    skills = env.store.effective_skills("alice", writer)
    assert [s["name"] for s in skills] == ["alpha", "beta"]
    assert {s["source"] for s in skills} == {"profile"}
    assert all(len(s["sha256"]) == 64 and not os.path.isabs(s["path"]) for s in skills)
    soul = env.store.effective_soul("alice", writer)
    assert soul.text == SOUL
    assert soul.sha256 == hashlib.sha256(SOUL.encode()).hexdigest() and soul.size == len(SOUL.encode())
    assert soul.revision == revision(env.store)
    assert env.store.account_snapshot("alice")["profiles"] == [{
        "id": writer, "label": "writer", "skills": ["alpha", "beta"],
        "soul": {"sha256": soul.sha256, "bytes": soul.size}}]
    # Another profile's content is not reachable through this grant.
    with pytest.raises(AccessDenied):
        env.store.effective_soul("alice", env.ids["coder"])
    with pytest.raises(AccessDenied):
        env.store.effective_skills("alice", env.ids["coder"])


def test_no_grant_yields_nothing(env):
    assert env.store.account_snapshot("bob")["profiles"] == []
    for profile in env.ids.values():
        with pytest.raises(AccessDenied):
            env.store.effective_skills("bob", profile)
        with pytest.raises(AccessDenied):
            env.store.effective_soul("bob", profile)


def test_revoke_removes_skills_and_soul_at_next_call(env):
    writer = env.ids["writer"]
    grant(env.store, "alice", writer)
    admission = env.store.authorize(ctx("alice", writer))
    assert env.store.effective_soul("alice", writer).text == SOUL
    before = revision(env.store)
    grant(env.store, "alice")
    assert revision(env.store) > before
    assert env.store.account_snapshot("alice")["profiles"] == []
    with pytest.raises(AccessDenied):
        env.store.effective_soul("alice", writer)
    with pytest.raises(AccessDenied):
        env.store.effective_skills("alice", writer)
    with pytest.raises(AccessDenied):
        env.store.revalidate(admission)


def test_explicit_skill_resource_merges_without_duplicates(env):
    writer = env.ids["writer"]
    env.store.put_resource("admin", "extra-alpha", kind="skill", label="alpha", binding={"content": "dup"})
    env.store.put_resource("admin", "extra-delta", kind="skill", label="delta", binding={"content": "extra"})
    grant(env.store, "alice", writer, "extra-alpha", "extra-delta")
    skills = env.store.effective_skills("alice", writer)
    assert [s["name"] for s in skills] == ["alpha", "beta", "delta"]
    by_name = {s["name"]: s for s in skills}
    assert by_name["alpha"]["source"] == "profile"
    assert by_name["delta"] == {"name": "delta", "source": "skill", "resource_id": "extra-delta"}
    assert env.store.account_snapshot("alice")["profiles"][0]["skills"] == ["alpha", "beta", "delta"]
    # Explicit extras still authorize through the existing skill selection.
    assert env.store.authorize(AccessContext("alice", writer, "ws", "conn", "m", ("extra-delta",)))


def test_two_accounts_share_content_with_distinct_private_instances(env):
    writer = env.ids["writer"]
    for user in ("alice", "bob"):
        grant(env.store, user, writer)
    assert env.store.effective_skills("alice", writer) == env.store.effective_skills("bob", writer)
    alice_soul, bob_soul = (env.store.effective_soul(u, writer) for u in ("alice", "bob"))
    assert (alice_soul.sha256, alice_soul.text) == (bob_soul.sha256, bob_soul.text)
    assert env.store.account_snapshot("alice")["profiles"] == env.store.account_snapshot("bob")["profiles"]
    alice, bob = (env.store.authorize(ctx(u, writer)) for u in ("alice", "bob"))
    assert alice.profile_instance_id != bob.profile_instance_id
    instances = {(r["account_id"], r["profile_id"]): r["id"] for r in env.store.snapshot("admin")["instances"]}
    assert instances[("alice", writer)] == alice.profile_instance_id
    assert instances[("bob", writer)] == bob.profile_instance_id


def _login(monkeypatch, store, username):
    monkeypatch.setattr(access_admin, "configured_store", lambda: store)
    monkeypatch.setattr(user_roles, "resolve_session_account", lambda _: (True, None))
    monkeypatch.setattr(user_roles, "load_users", lambda: {
        "admin": {"id": "admin", "role": "admin"}, "alice": {"id": "alice", "role": "user"}})
    monkeypatch.setattr(auth, "ensure_trusted_auth_session", lambda _: {"username": username, "auth_type": "local"})


class _Handler:
    def __init__(self, command="GET"):
        self.command, self.headers, self.request = command, {}, SimpleNamespace()
        self.client_address, self.wfile, self.status = ("127.0.0.1", 1), io.BytesIO(), None

    def send_response(self, status):
        self.status = status

    def send_header(self, *args):
        pass

    def end_headers(self):
        pass


def test_soul_text_and_host_paths_never_appear_in_summaries(env, monkeypatch):
    writer = env.ids["writer"]
    grant(env.store, "alice", writer)
    _login(monkeypatch, env.store, "alice")
    handler = _Handler()
    access_admin.handle_access_admin(handler, urlparse("/api/access/me"))
    assert handler.status == 200
    api_body = handler.wfile.getvalue().decode()
    assert json.loads(api_body)["profiles"][0]["skills"] == ["alpha", "beta"]
    serialized = [api_body, json.dumps(env.store.account_snapshot("alice")),
                  json.dumps(env.store.snapshot("admin"))]
    for text in serialized:
        assert SOUL not in text and "SYNTHETIC-SOUL" not in text
        assert SECRET not in text and str(env.tmp) not in text
    assert SOUL not in repr(env.store.effective_soul("alice", writer))


def test_changed_soul_or_skills_on_refresh_bumps_revision(env):
    writer = env.ids["writer"]
    grant(env.store, "alice", writer)
    admission = env.store.authorize(ctx("alice", writer))
    first = env.store.effective_soul("alice", writer)
    before = revision(env.store)
    env.refresh()
    assert revision(env.store) == before  # unchanged content is a no-op
    (env.homes["writer"] / "SOUL.md").write_text("A revised synthetic soul.", encoding="utf-8")
    env.refresh()
    after_soul = revision(env.store)
    assert after_soul > before
    with pytest.raises(AccessDenied):
        env.store.revalidate(admission)
    updated = env.store.effective_soul("alice", writer)
    assert updated.text == "A revised synthetic soul." and updated.sha256 != first.sha256
    assert env.store.account_snapshot("alice")["profiles"][0]["soul"]["sha256"] == updated.sha256
    alpha = {s["name"]: s["sha256"] for s in env.store.effective_skills("alice", writer)}["alpha"]
    (env.homes["writer"] / "skills" / "category" / "alpha" / "notes.md").write_text("more", encoding="utf-8")
    env.refresh()
    assert revision(env.store) > after_soul
    assert {s["name"]: s["sha256"] for s in env.store.effective_skills("alice", writer)}["alpha"] != alpha
    write_skill(env.homes["writer"], "other/epsilon", "epsilon")
    env.refresh()
    assert env.store.account_snapshot("alice")["profiles"][0]["skills"] == ["alpha", "beta", "epsilon"]
    # A deleted SOUL.md is no longer delivered.
    (env.homes["writer"] / "SOUL.md").unlink()
    env.refresh()
    assert env.store.effective_soul("alice", writer) is None
    assert env.store.account_snapshot("alice")["profiles"][0]["soul"] is None


def test_removed_profile_no_longer_authorizes(env):
    writer = env.ids["writer"]
    grant(env.store, "alice", writer)
    admission = env.store.authorize(ctx("alice", writer))
    before = revision(env.store)
    env.refresh(("coder",))
    assert revision(env.store) > before
    with pytest.raises(AccessDenied):
        env.store.authorize(ctx("alice", writer))
    with pytest.raises(AccessDenied):
        env.store.revalidate(admission)
    with pytest.raises(AccessDenied):
        env.store.effective_soul("alice", writer)
    with pytest.raises(AccessDenied):
        env.store.effective_skills("alice", writer)
    assert env.store.account_snapshot("alice")["profiles"] == []
    with pytest.raises(AccessDenied):
        grant(env.store, "alice", writer)
    restored = env.refresh()
    assert restored["writer"] == writer
    assert env.store.authorize(ctx("alice", writer)).profile_instance_id == admission.profile_instance_id
    assert env.store.effective_soul("alice", writer).text == SOUL


def test_secret_files_are_never_read_or_listed(env, monkeypatch):
    home = env.homes["writer"]
    skill = home / "skills" / "category" / "alpha"
    for name in SECRET_NAMES:
        (skill / name).write_text(SECRET, encoding="utf-8")
    (skill / ".git").mkdir()
    (skill / ".git" / "config").write_text(SECRET, encoding="utf-8")
    outside = env.tmp / "outside"
    write_skill(outside, "linked", "linked", body=SECRET)
    (home / "skills" / "linked").symlink_to(outside / "skills" / "linked")
    attempted, live_fds, scanned = [], {}, []
    real_open, real_scandir = os.open, os.scandir

    def recording_open(path, flags, mode=0o777, *, dir_fd=None):
        attempted.append(os.fspath(path))  # every attempt, even a refused one
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        live_fds[fd] = os.fspath(path)  # fd numbers are reused; latest wins
        return fd

    def recording_scandir(path="."):
        scanned.append(live_fds.get(path, path))
        return real_scandir(path)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", recording_open)
        patch.setattr(os, "scandir", recording_scandir)
        env.refresh()
    names = {os.path.basename(path) for path in attempted}
    assert names & (SECRET_NAMES | {"config", "MEMORY.md"}) == set()
    assert "SOUL.md" in names and "SKILL.md" in names and scanned
    assert str(home) not in scanned  # the profile home itself is never listed
    grant(env.store, "alice", env.ids["writer"])
    assert [s["name"] for s in env.store.effective_skills("alice", env.ids["writer"])] == ["alpha", "beta"]
    dumped = json.dumps(env.store.snapshot("admin")) + json.dumps(env.store.account_snapshot("alice"))
    assert SECRET not in dumped and all(name not in dumped for name in SECRET_NAMES)


def test_symlinked_soul_is_not_followed(env):
    home = env.homes["writer"]
    (home / "SOUL.md").unlink()
    (home / "SOUL.md").symlink_to(home / ".env")
    env.refresh()
    grant(env.store, "alice", env.ids["writer"])
    assert env.store.effective_soul("alice", env.ids["writer"]) is None


def test_non_admin_import_reads_no_files_and_homes_must_be_absolute(env, monkeypatch):
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", lambda *a, **k: calls.append(a) or pytest.fail("filesystem read"))
        with pytest.raises(AccessDenied):
            env.store.import_profiles("alice", ["writer"], homes={"writer": str(env.homes["writer"])})
    assert calls == []
    with pytest.raises(ValueError):
        env.store.import_profiles("admin", ["writer"], homes={"writer": "relative/home"})
    with pytest.raises(ValueError):
        env.store.import_profiles("admin", ["writer"], homes={"other": str(env.homes["writer"])})


def test_admin_import_route_records_server_discovered_homes(env, monkeypatch):
    from api import profiles
    _login(monkeypatch, env.store, "admin")
    monkeypatch.setattr(profiles, "list_profiles_api", lambda: [
        {"name": "writer", "path": str(env.homes["writer"])}, {"name": "coder", "path": "relative"}])
    handler = _Handler("POST")
    access_admin.handle_access_admin(handler, urlparse("/api/admin/access"), {
        "action": "import_profiles", "homes": {"coder": str(env.homes["writer"])}})
    assert handler.status == 200
    grant(env.store, "alice", env.ids["writer"], env.ids["coder"])
    summary = {p["label"]: p for p in env.store.account_snapshot("alice")["profiles"]}
    assert summary["writer"]["soul"]["bytes"] == len(SOUL.encode())
    # A non-absolute discovered path and a body-supplied home are both ignored.
    assert summary["coder"]["skills"] == [] and summary["coder"]["soul"] is None
