"""Live grant, ownership and revocation tests against disposable SQLite policy."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from api.access_policy import AccessContext, AccessDenied, PolicyStore, PolicyUnavailable


@pytest.fixture
def policy(tmp_path):
    store = PolicyStore.initialize(tmp_path / "policy.sqlite", "admin")
    for user in ("alice", "bob"):
        store.put_account("admin", user)
    for kind, names in {"profile": ["shared", "other"], "workspace": ["alice-ws", "bob-ws"],
                        "connection": ["account-one", "account-two"], "skill": ["coding", "finance"]}.items():
        for name in names:
            store.put_resource("admin", name, kind=kind, label=name,
                               binding={"target": name, "endpoint": "https://same-provider.example"})
    for user, connection in (("alice", "account-one"), ("bob", "account-two")):
        store.replace_grants("admin", user, {"shared": [], f"{user}-ws": [],
                                              connection: ["allowed-model"], "coding": []})
    return store


def context(user="alice"):
    return AccessContext(user, "shared", f"{user}-ws",
                         "account-one" if user == "alice" else "account-two",
                         "allowed-model", ("coding",))


def test_shared_template_has_distinct_private_instances(policy):
    alice = policy.authorize(context())
    bob = policy.authorize(context("bob"))
    assert alice.profile_instance_id != bob.profile_instance_id
    assert policy.authorize(context()).profile_instance_id == alice.profile_instance_id


@pytest.mark.parametrize("changes", [
    {"profile_id": "other"}, {"workspace_id": "bob-ws"},
    {"connection_id": "account-two"}, {"model": "ungranted"},
    {"skills": ("finance",)}, {"account_id": "unknown"},
    {"profile_id": "alice-ws"},
])
def test_foreign_selection_denied_before_admission(policy, changes):
    with pytest.raises(AccessDenied):
        policy.authorize(replace(context(), **changes))


@pytest.mark.parametrize("kind", ["session", "run", "attachment", "project", "draft", "cron", "journal"])
def test_private_objects_cannot_be_read_or_overwritten_by_other_user(policy, kind):
    policy.register_object(context(), kind=kind, object_id="private-object")
    policy.authorize_object(context(), kind=kind, object_id="private-object")
    with pytest.raises(AccessDenied):
        policy.authorize_object(context("bob"), kind=kind, object_id="private-object")
    with pytest.raises(AccessDenied):
        policy.register_object(context("bob"), kind=kind, object_id="private-object")


def test_disabled_account_and_revoked_workspace_block_private_object(policy):
    policy.register_object(context(), kind="session", object_id="session-id")
    policy.replace_grants("admin", "alice", {"shared": [], "account-one": ["allowed-model"], "coding": []})
    with pytest.raises(AccessDenied):
        policy.authorize_object(context(), kind="session", object_id="session-id")
    policy.put_account("admin", "bob", enabled=False)
    with pytest.raises(AccessDenied):
        policy.authorize(context("bob"))


def test_resource_at_same_provider_does_not_share_connection_authority(policy):
    with pytest.raises(AccessDenied):
        policy.authorize(replace(context(), connection_id="account-two"))


def test_failed_grant_replacement_rolls_back(policy):
    before = policy.authorize(context())
    with pytest.raises(AccessDenied):
        policy.replace_grants("admin", "alice", {"missing": []})
    assert policy.authorize(context()) == before


def test_cannot_revoke_last_admin(policy):
    with pytest.raises(AccessDenied):
        policy.put_account("admin", "admin", enabled=False)
    assert policy.snapshot("admin")


@pytest.mark.parametrize("operation", ["account", "resource", "grants", "snapshot"])
def test_user_cannot_administer_policy(policy, operation):
    with pytest.raises(AccessDenied):
        if operation == "account":
            policy.put_account("alice", "alice", role="admin")
        elif operation == "resource":
            policy.put_resource("alice", "new", kind="workspace", label="new", binding={})
        elif operation == "grants":
            policy.replace_grants("alice", "alice", {"account-two": ["allowed-model"]})
        else:
            policy.snapshot("alice")


def test_multiple_profiles_and_workspaces_are_explicit(policy):
    policy.replace_grants("admin", "alice", {"shared": [], "other": [], "alice-ws": [], "bob-ws": [],
                                              "account-one": ["allowed-model"], "coding": []})
    first = policy.authorize(context())
    second = policy.authorize(replace(context(), profile_id="other", workspace_id="bob-ws"))
    assert first.profile_instance_id != second.profile_instance_id
    policy.put_resource("admin", "future", kind="profile", label="future", binding={})
    with pytest.raises(AccessDenied):
        policy.authorize(replace(context(), profile_id="future"))


def test_relink_invalidates_preexisting_admission(policy):
    admission = policy.authorize(context())
    policy.put_resource("admin", "account-one", kind="connection", label="one", binding={"account": "different"})
    with pytest.raises(AccessDenied):
        policy.revalidate(admission)
    assert policy.authorize(context()).connection_generation > admission.connection_generation


def test_revoke_then_regrant_cannot_resurrect_old_admission(policy):
    admission = policy.authorize(context())
    policy.replace_grants("admin", "alice", {})
    policy.replace_grants("admin", "alice", {"shared": [], "alice-ws": [],
                                              "account-one": ["allowed-model"], "coding": []})
    with pytest.raises(AccessDenied):
        policy.revalidate(admission)
    assert policy.authorize(context()).profile_instance_id == admission.profile_instance_id


@pytest.mark.parametrize("revoke_first", [True, False])
def test_admission_revocation_ordering(policy, revoke_first):
    admitted = threading.Event()
    revoked = threading.Event()
    def admit():
        if revoke_first:
            assert revoked.wait(5)
            with pytest.raises(AccessDenied):
                policy.authorize(context())
        else:
            result = policy.authorize(context())
            admitted.set()
            assert revoked.wait(5)
            with pytest.raises(AccessDenied):
                policy.revalidate(result)
    def revoke():
        if not revoke_first:
            assert admitted.wait(5)
        policy.replace_grants("admin", "alice", {})
        revoked.set()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(admit), executor.submit(revoke)]
        for future in futures:
            future.result(timeout=10)


def test_missing_and_corrupt_policy_never_create_empty_authority(tmp_path):
    path = tmp_path / "missing.sqlite"
    store = PolicyStore(path)
    with pytest.raises(PolicyUnavailable):
        store.authorize(context())
    assert not path.exists()
    path.write_text("invalid")
    with pytest.raises(PolicyUnavailable):
        store.authorize(context())
    with pytest.raises(FileExistsError):
        PolicyStore.initialize(path, "replacement-admin")


@pytest.mark.parametrize("binding", [{"api_key": "synthetic"}, {"nested": [{"refresh_token": "synthetic"}]}])
def test_policy_metadata_rejects_credentials(policy, binding):
    with pytest.raises(ValueError):
        policy.put_resource("admin", "secret", kind="connection", label="secret", binding=binding)


def test_empty_model_allowlist_is_denial_not_all_models(policy):
    with pytest.raises(ValueError):
        policy.replace_grants("admin", "alice", {"account-one": []})
    assert policy.authorize(context())
