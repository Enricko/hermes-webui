"""Broker policy and three-way seeding adversarial cases, using disposable state."""

import asyncio
import copy
import os
from types import SimpleNamespace

import pytest

from multiuser.broker import model_payload, public_addresses
from multiuser.provision import Provisioner, private_read, private_write
from multiuser.settings import Settings
from multiuser.store import PolicyError
from multiuser.templates import validate_template


@pytest.fixture
def document():
    return validate_template({'provider_id': 'a' * 32, 'model': 'approved',
        'parameters': {'max_tokens': 2048, 'temperature': 0.7}, 'soul': 'Shared base'})


def test_broker_owns_identity_disables_stored_state_and_bounds_response(document):
    payload = {'model': 'approved', 'user': 'another-user', 'store': True, 'messages': [], 'temperature': 0.1}
    result = model_payload(payload, document, 'owner')
    assert result['user'] == 'owner' and result['store'] is False
    assert result['max_tokens'] == 2048
    assert result['temperature'] == 0.7
    assert payload['user'] == 'another-user'  # no caller mutation
    for mutation in [{'model': 'unapproved'}, {'max_tokens': 2049}, {'max_tokens': True},
                     {'previous_response_id': 'guess'}, {'messages': [{'audio': {'id': 'guess'}}]},
                     {'messages': [{'content': [{'type': 'item_reference', 'id': 'guess'}]}]},
                     {'tools': [{'type': 'file_search', 'vector_store_ids': ['guess']}]},
                     {'tools': {'function': 'bad'}}, {'messages': [{'file_id': 'guess'}]}]:
        with pytest.raises(PolicyError):
            model_payload({**payload, **mutation}, document, 'owner')
    for route in ['/v1/messages', '/v1/responses']:
        with pytest.raises(PolicyError):
            model_payload({**payload, 'metadata': ['malformed']}, document, 'owner', route)


@pytest.mark.asyncio
async def test_egress_denies_local_metadata_mixed_dns_and_unapproved_hosts(monkeypatch):
    async def answers(host, port, **_):
        addresses = {'public.example': ['8.8.8.8'], 'mixed.example': ['8.8.8.8', '127.0.0.1'],
                     'metadata.example': ['169.254.169.254'], 'private.example': ['10.0.0.1'],
                     'v6.example': ['::1']}[host]
        return [(2, 1, 6, '', (address, port)) for address in addresses]
    monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', answers)
    assert await public_addresses('public.example', 443, ['*.example']) == ['8.8.8.8']
    for host, port, patterns in [('public.example', 22, ['*']), ('unapproved.example', 443, []),
            ('mixed.example', 443, ['*']), ('metadata.example', 80, ['*']),
            ('private.example', 443, ['*']), ('v6.example', 443, ['*'])]:
        with pytest.raises(PolicyError):
            await public_addresses(host, port, patterns)


def test_private_seed_refuses_symlinks_fifos_and_parent_escape(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    target = outside / 'keep.txt'
    target.write_text('untouched')
    (home / 'link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        private_write(home, 'link/keep.txt', b'changed', os.getuid())
    (home / 'file').symlink_to(target)
    with pytest.raises(OSError):
        private_read(home, 'file')
    os.mkfifo(home / 'pipe')
    with pytest.raises(PolicyError):
        private_read(home, 'pipe')
    assert target.read_text() == 'untouched'


def test_template_updates_preserve_edits_deletions_memory_and_learned_skills(tmp_path, document):
    uid = 'b' * 32
    settings = Settings(root=tmp_path, worker_uid=os.getuid())
    home = settings.user_dir(uid) / 'hermes'
    home.mkdir(parents=True)
    (settings.runtime_dir(uid) / 'tools').mkdir(parents=True)
    operator = Provisioner.__new__(Provisioner)
    operator.settings = settings
    operator.store = None  # this template selects no published tools
    template = {'document': document}
    assert operator.seed(uid, template) == []
    (home / 'SOUL.md').write_text('Private identity')
    (home / 'config.yaml').unlink()
    (home / 'memory.md').write_text('Private memory')
    (home / 'skills/personal').mkdir()
    (home / 'skills/personal/SKILL.md').write_text('Private learned skill')
    assert operator.seed(uid, template) == []
    assert not (home / 'config.yaml').exists()
    updated = copy.deepcopy(template)
    updated['document']['soul'] = 'Updated shared base'
    assert operator.seed(uid, updated) == ['SOUL.md']
    assert operator.seed(uid, updated, keep_private=True) == ['SOUL.md']
    assert operator.seed(uid, updated) == []
    assert (home / 'SOUL.md').read_text() == 'Private identity'
    assert (home / 'memory.md').read_text() == 'Private memory'
    assert (home / 'skills/personal/SKILL.md').read_text() == 'Private learned skill'


def test_migration_snapshots_privately_but_imports_only_selected_capabilities(tmp_path):
    import tarfile
    import yaml
    from multiuser.manage import migrate
    settings = Settings(root=tmp_path / 'installation')
    store = settings.store()
    store.initialize()
    provider = store.put_provider('Explicit destination', 'http://127.0.0.1:9/v1', 'new-provider-secret')
    source = tmp_path / 'legacy'
    source.mkdir()
    (source / 'config.yaml').write_text(yaml.safe_dump({'model': {'default': 'approved', 'temperature': 0.2,
        'api_key': 'old-private-provider-secret'}, 'agent': {'max_iterations': 20}, 'memory': 'private-memory-provider'}))
    (source / 'SOUL.md').write_text('Reviewed shared instructions')
    for name in ['USER.md', '.env', 'auth.json', 'state.db', 'MEMORY.md']:
        (source / name).write_text('legacy-private-canary-' + name)
    (source / 'skills/team').mkdir(parents=True)
    (source / 'skills/team/SKILL.md').write_text('Reviewed shared skill')
    backup = tmp_path / 'private-backup'
    args = SimpleNamespace(source=source, backup=backup, provider_id=provider, model=None,
        allowed_model=[], parameters=True, soul=True, skill=['team/SKILL.md'], name='Reviewed legacy capabilities')
    report = migrate(settings, args)
    assert backup.stat().st_mode & 0o777 == 0o700
    assert (backup / 'single-user-before.tar').stat().st_mode & 0o777 == 0o600
    with tarfile.open(backup / 'single-user-before.tar') as archive:
        assert 'hermes/state.db' in archive.getnames()
    document = store.template(report['template_id'])['document']
    assert document['soul'] == 'Reviewed shared instructions'
    assert document['skills'] == {'team/SKILL.md': 'Reviewed shared skill'}
    assert document['parameters']['temperature'] == 0.2
    assert 'private' not in repr(document)
    assert report['personal_state_imported'] is False
    assert (source / 'state.db').read_text() == 'legacy-private-canary-state.db'


def test_persisted_capabilities_are_revalidated_before_trusted_filesystem_use(tmp_path):
    import json
    from multiuser.store import Store
    store = Store(tmp_path / 'control/accounts.sqlite')
    store.initialize()
    tid = store.put_tool('Reviewed tool', 'Use this script', 'safe.py', 'print("safe")')
    with store.connection(write=True) as db:
        db.execute('UPDATE tools SET filename=? WHERE id=?', ('../../root-target', tid))
    with pytest.raises(PolicyError):
        store.tool(tid)
    provider = store.put_provider('Explicit endpoint', 'http://127.0.0.1:9/v1', '')
    template = store.put_template('Base', {'provider_id': provider, 'model': 'approved'})
    with store.connection(write=True) as db:
        db.execute('UPDATE templates SET document=? WHERE id=?', (json.dumps({
            'provider_id': provider, 'model': 'approved', 'skills': {'../../escape': 'bad'}}), template))
    with pytest.raises(PolicyError):
        store.template(template)


def test_shared_skill_snapshot_preserves_resources_but_excludes_secrets_state_and_symlinks(tmp_path):
    from multiuser.profile import secret_values, snapshot_skills
    source = tmp_path / 'source'
    (source / 'existing/scripts').mkdir(parents=True)
    (source / 'existing/SKILL.md').write_text('Use scripts/tool.py before writing a new tool')
    (source / 'existing/scripts/tool.py').write_text('print("existing implementation")')
    for name in ['.env', 'auth.json', 'USER.md', 'private.log']:
        (source / name).write_text('private state')
    (source / '.env').write_text("export SECRET_API_KEY='private-api-key-canary'\n")
    (source / 'existing/private.md').write_text('The credential is private-api-key-canary')
    (source / 'outside').symlink_to(tmp_path, target_is_directory=True)
    (source / 'existing/link.md').symlink_to(source / 'existing/SKILL.md')
    destination = tmp_path / 'snapshot'
    known = secret_values(source, {})
    assert b'private-api-key-canary' in known
    assert 'SECRET_API_KEY' not in os.environ
    copied, skipped = snapshot_skills(source, destination, known)
    assert set(copied) == {'existing/SKILL.md', 'existing/scripts/tool.py'}
    assert len(skipped) == 7
    assert (destination / 'existing/SKILL.md').read_bytes() == (source / 'existing/SKILL.md').read_bytes()
    assert not (destination / 'existing/scripts/tool.py').stat().st_mode & 0o222
    assert not (destination / 'existing/SKILL.md').stat().st_mode & 0o222
    assert not (destination / 'outside').exists()
