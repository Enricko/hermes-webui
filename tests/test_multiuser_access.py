"""Independent profile/provider grants and activation authority, using real SQLite."""

import secrets

import pytest

from multiuser.broker import entitlement
from multiuser.store import PolicyError, Store
from multiuser.templates import worker_config


@pytest.fixture
def access(tmp_path):
    store = Store(tmp_path / 'accounts.sqlite'); store.initialize()
    password = secrets.token_urlsafe(24)
    store.create_user('administrator', password, role='admin', bootstrap=True)
    pa = store.put_provider('Provider A', 'http://127.0.0.1:1/v1', 'synthetic-provider-a')
    pb = store.put_provider('Provider B', 'http://127.0.0.1:2/v1', 'synthetic-provider-b')
    pc = store.put_provider('Not assigned', 'http://127.0.0.1:3/v1', 'synthetic-provider-c')
    ta = store.put_template('Profile A', {'provider_id':pa, 'model':'model-a', 'soul':'Instructions A'})
    tb = store.put_template('Profile B', {'provider_id':pb, 'model':'model-b', 'soul':'Instructions B'})
    tc = store.put_template('Not assigned', {'provider_id':pc, 'model':'model-c'})
    alice = store.create_user('alice', password, template_ids=[ta, tb], provider_ids=[pa], template_id=ta)
    bob = store.create_user('bobby', password, template_ids=[ta], provider_ids=[pa, pb], template_id=ta, provider_id=pb)
    return store, password, (pa, pb, pc), (ta, tb, tc), alice, bob


def test_profiles_and_providers_are_independent_and_broker_enforced(access):
    store, password, (pa, pb, pc), (ta, tb, tc), alice, bob = access
    assert alice['template_ids'] == [ta, tb] and alice['provider_ids'] == [pa]
    assert bob['template_ids'] == [ta] and bob['provider_ids'] == [pa, pb]
    _, a, provider_a = entitlement(store, alice['id'])
    _, b, provider_b = entitlement(store, bob['id'])
    assert a['soul'] == b['soul'] == 'Instructions A'
    assert provider_a['id'] == pa and provider_b['id'] == pb
    assert b['model'] == 'model-b'
    assert {p['provider_id'] for p in a['connections']} == {pa}
    assert {p['provider_id'] for p in b['connections']} == {pa, pb}
    assert 'synthetic-provider' not in repr(worker_config(b))
    for uid, forbidden in [(alice['id'], pb), (alice['id'], pc), (bob['id'], pc)]:
        with pytest.raises(PolicyError, match='not assigned'):
            entitlement(store, uid, forbidden)
    token, principal = store.login('alice', password, 'fixture')
    assert store.select_access(principal, tb, pa)
    assert store.session(token).template_id == tb
    _, changed, actual = entitlement(store, alice['id'])
    assert changed['soul'] == 'Instructions B' and changed['model'] == 'model-a' and actual['id'] == pa
    _, bob_principal = store.login('bobby', password, 'fixture')
    with pytest.raises(PolicyError, match='Profile is not assigned'):
        store.select_access(bob_principal, tb, pa)
    assert store.user(bob['id'])['template_id'] == ta


def test_activation_preserves_own_session_expires_other_sessions_and_never_restores_revoked_access(access):
    store, password, (pa, pb, _pc), (ta, tb, _tc), alice, bob = access
    token, principal = store.login('alice', password, 'first')
    other_token, _ = store.login('alice', password, 'second')
    bob_token, _ = store.login('bobby', password, 'bob')
    store.set_runtime(alice['id'], 'before', 'ready')
    assert store.select_access(principal, tb, pa)
    renewed = store.session(token)
    assert renewed and renewed.expires == principal.expires and renewed.auth_version > principal.auth_version
    assert store.session(other_token) is None and store.session(bob_token) is not None
    assert store.runtime(alice['id'])['state'] == 'switching'
    assert not store.select_access(renewed, tb, pa)
    store.update_user(alice['id'], template_ids=[ta], provider_ids=[pa], template_id=ta, assign_template=True)
    with pytest.raises(PolicyError, match='Session expired'):
        store.select_access(renewed, tb, pa)
    assert store.user(alice['id'])['template_ids'] == [ta]
    assert store.session(token) is None


def test_grant_updates_validate_atomically_and_preserve_other_users(access):
    store, _password, (pa, pb, _pc), (ta, tb, _tc), alice, bob = access
    before = store.users()
    for changes in [dict(template_ids=[ta, 'f'*32]), dict(provider_ids=['f'*32]),
                    dict(template_ids=[ta, ta]), dict(provider_ids=[]),
                    dict(provider_ids=[pa], provider_id=pb, assign_provider=True),
                    dict(template_ids=[tb], template_id=ta, assign_template=True)]:
        with pytest.raises(PolicyError):
            store.update_user(alice['id'], **changes)
        assert store.users() == before
    with pytest.raises(PolicyError):
        store.create_user('invalid-user', secrets.token_urlsafe(24), template_ids=[ta], provider_ids=[])
    assert store.users() == before
    updated = store.update_user(alice['id'], template_ids=[tb], provider_ids=[pa, pb])
    assert updated['template_id'] == tb
    assert store.user(bob['id']) == bob


def test_legacy_assignments_remain_inherited_until_explicitly_saved(access):
    store, password, (pa, pb, _pc), (ta, tb, _tc), _alice, _bob = access
    legacy = store.create_user('legacy-user', password, template_id=ta, provider_id=pb)
    assert not legacy['access_managed'] and set(legacy['provider_ids']) == {pa, pb}
    explicit = store.update_user(legacy['id'], template_ids=[ta, tb], provider_ids=[pa])
    assert explicit['access_managed'] and explicit['provider_id'] is None
    store.update_user(legacy['id'], provider_id=pb, assign_provider=True)
    assert store.user(legacy['id'])['provider_ids'] == [pa, pb]
    store.update_user(legacy['id'], template_id=tb, assign_template=True)
    legacy = store.user(legacy['id'])
    assert not legacy['access_managed'] and legacy['template_ids'] == [tb]
