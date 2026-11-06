"""Read-only folder reference grants in the SQLite policy authority (M5)."""
import json
import sqlite3

import pytest

from api import user_roles
from api.access_policy import AccessDenied, PolicyStore
# Reuse the disposable policy (admin, alice, bob + grants) and selection helper.
from tests.test_access_policy import context, policy  # noqa: F401


@pytest.fixture
def store(request, monkeypatch):
    store = request.getfixturevalue("policy")
    store.put_account("admin", "carol")
    # Display names come from the login store; IDs here equal the usernames.
    monkeypatch.setattr(user_roles, "load_users", lambda: {
        name: {"id": name, "role": "admin" if name == "admin" else "user"} for name in ("admin", "alice", "bob", "carol")})
    return store


def revision(store):
    return store.snapshot("admin")["revision"]


def test_grant_and_revoke_bump_revision_and_invalidate_admissions(store):
    admission = store.authorize(context())
    before = revision(store)
    store.replace_references("admin", "alice", ["bob"])
    assert revision(store) == before + 1
    with pytest.raises(AccessDenied):
        store.revalidate(admission)
    assert store.reference_targets("alice") == ["bob"]
    assert store.authorize_reference("alice", "bob") == revision(store)
    store.replace_references("admin", "alice", [])
    assert revision(store) == before + 2
    assert store.reference_targets("alice") == []
    with pytest.raises(AccessDenied):
        store.authorize_reference("alice", "bob")


def test_references_are_one_directional_and_private_by_default(store):
    assert store.reference_targets("alice") == []
    store.replace_references("admin", "alice", ["bob"])
    assert store.reference_targets("bob") == []
    with pytest.raises(AccessDenied):
        store.authorize_reference("bob", "alice")
    with pytest.raises(AccessDenied):
        store.authorize_reference("carol", "bob")


def test_self_reference_is_rejected_and_rolls_back(store):
    store.replace_references("admin", "alice", ["bob"])
    before = revision(store)
    with pytest.raises(ValueError):
        store.replace_references("admin", "alice", ["carol", "alice"])
    assert store.reference_targets("alice") == ["bob"]
    assert revision(store) == before


@pytest.mark.parametrize("target", ["unknown-account", "../bob", "", None, 42])
def test_unknown_or_malformed_target_is_rejected(store, target):
    before = revision(store)
    with pytest.raises((AccessDenied, ValueError)):
        store.replace_references("admin", "alice", [target])
    assert store.reference_targets("alice") == [] and revision(store) == before


@pytest.mark.parametrize("targets", ["bob", {"bob": []}, ["bob"] * 513])
def test_reference_list_shape_is_validated(store, targets):
    with pytest.raises(ValueError):
        store.replace_references("admin", "alice", targets)


def test_disabled_target_is_rejected_and_existing_grant_stops_authorizing(store):
    store.replace_references("admin", "alice", ["bob"])
    store.put_account("admin", "carol", enabled=False)
    with pytest.raises(AccessDenied):
        store.replace_references("admin", "alice", ["bob", "carol"])
    assert store.reference_targets("alice") == ["bob"]
    store.put_account("admin", "bob", enabled=False)
    assert store.reference_targets("alice") == []
    with pytest.raises(AccessDenied):
        store.authorize_reference("alice", "bob")


def test_disabled_grantee_cannot_use_or_receive_references(store):
    store.replace_references("admin", "alice", ["bob"])
    store.put_account("admin", "alice", enabled=False)
    with pytest.raises(AccessDenied):
        store.authorize_reference("alice", "bob")
    with pytest.raises(AccessDenied):
        store.replace_references("admin", "alice", ["bob"])


@pytest.mark.parametrize("target", ["unknown-account", "carol", "alice", "../bob", "", None, "x" * 129])
def test_authorize_reference_denies_uniformly(store, target):
    store.replace_references("admin", "alice", ["bob"])
    with pytest.raises(AccessDenied) as denied:
        store.authorize_reference("alice", target)
    assert str(denied.value) == "Reference folder is not granted to this account"


def test_only_admin_can_change_references(store):
    with pytest.raises(AccessDenied):
        store.replace_references("alice", "alice", ["bob"])
    with pytest.raises(AccessDenied):
        store.replace_grants("alice", "alice", {}, references=["bob"])
    with pytest.raises(AccessDenied):
        store.replace_references("unknown", "alice", ["bob"])
    assert store.reference_targets("alice") == []


def test_replace_grants_carries_references_atomically(store):
    grants = {"shared": [], "alice-ws": [], "account-one": ["allowed-model"], "coding": []}
    store.replace_grants("admin", "alice", grants, references=["bob"])
    assert store.reference_targets("alice") == ["bob"]
    # Omitted references are left unchanged.
    store.replace_grants("admin", "alice", grants)
    assert store.reference_targets("alice") == ["bob"]
    before = store.authorize(context())
    with pytest.raises(ValueError):
        store.replace_grants("admin", "alice", {"shared": []}, references=["alice"])
    assert store.authorize(context()).revision == before.revision
    assert store.reference_targets("alice") == ["bob"]
    store.replace_grants("admin", "alice", grants, references=[])
    assert store.reference_targets("alice") == []


def test_snapshots_expose_ids_and_usernames_only(store, monkeypatch):
    store.replace_references("admin", "alice", ["bob", "carol"])
    rows = store.snapshot("admin")["references"]
    assert rows == [{"account_id": "alice", "target_id": "bob"}, {"account_id": "alice", "target_id": "carol"}]
    member = store.account_snapshot("alice")
    assert member["references"] == [{"id": "bob", "username": "bob"}, {"id": "carol", "username": "carol"}]
    assert store.account_snapshot("bob")["references"] == []
    # A target without an enabled login is omitted: both authorities must agree.
    monkeypatch.setattr(user_roles, "load_users", lambda: {"bob": {"id": "bob", "role": "user"}})
    assert store.account_snapshot("alice")["references"] == [{"id": "bob", "username": "bob"}]
    encoded = json.dumps(member)
    assert "binding" not in encoded and "/" not in encoded


def test_member_snapshot_is_read_only_and_needs_enabled_account(store):
    with pytest.raises(AccessDenied):
        store.reference_targets("unknown")
    store.put_account("admin", "alice", enabled=False)
    with pytest.raises(AccessDenied):
        store.account_snapshot("alice")


def test_database_created_before_reference_table_still_opens(store):
    with sqlite3.connect(store.path) as db:
        db.execute("DROP TABLE reference_grants")
    old = PolicyStore(store.path)
    assert old.authorize(context()).profile_instance_id
    assert old.reference_targets("alice") == []
    assert old.account_snapshot("alice")["references"] == []
    assert old.snapshot("admin")["references"] == []
    with pytest.raises(AccessDenied):
        old.authorize_reference("alice", "bob")
    before = revision(old)
    old.replace_references("admin", "alice", ["bob"])
    assert old.reference_targets("alice") == ["bob"] and revision(old) == before + 1
    with pytest.raises(FileExistsError):
        PolicyStore.initialize(store.path, "replacement-admin")


def test_schema_refuses_self_reference_even_on_direct_insert(store):
    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(store.path) as db:
            db.execute("INSERT INTO reference_grants VALUES ('alice','alice')")
