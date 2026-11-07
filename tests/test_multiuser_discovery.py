"""Portable discovery uses source capabilities, stable IDs and explicit authority."""

import json
import os

import pytest
import yaml

from multiuser.discovery import connect, detect_home, discover, read_file, sync
from multiuser.settings import Settings
from multiuser.store import PolicyError


def source(path, model='original-model', key='private-source-key-123456789', *, providers=True):
    path.mkdir(parents=True, exist_ok=True)
    config = {'model': {'provider': 'custom', 'base_url': 'http://127.0.0.1:1234/v1',
                       'api_key': '${ROUTER_KEY}', 'default': model}, 'agent': {'max_turns': 80}}
    if providers:
        config['custom_providers'] = [{'name': 'Another router', 'base_url': 'http://127.0.0.1:5678/v1',
                                      'key_env': 'SECOND_KEY', 'model': model}]
    (path / 'config.yaml').write_text(yaml.safe_dump(config))
    (path / '.env').write_text(f'ROUTER_KEY={key}\nSECOND_KEY=second-source-secret-123456789\n')
    (path / 'SOUL.md').write_text('Original reusable instructions')
    (path / 'state.db').write_bytes(b'private conversation fixture')
    (path / 'USER.md').write_text('private user information')
    (path / 'skills' / 'base').mkdir(parents=True, exist_ok=True)
    (path / 'skills' / 'base' / 'SKILL.md').write_text('---\nname: base\ndescription: Original base skill\n---\nUse existing tools.')
    (path / 'skills' / 'base' / 'USER.md').write_text('private must not be copied')
    return config


@pytest.fixture
def installation(tmp_path, monkeypatch):
    monkeypatch.setattr('multiuser.provision.require_operator', lambda _settings: None)
    # Unit tests run unprivileged. The separate real-Docker gate exercises the
    # root-owned bundle policy and actual worker mounts without this stub.
    monkeypatch.setattr('multiuser.profile.bundle_path', lambda cfg, bid: cfg.root / 'shared/profiles' / bid / 'skills')
    settings = Settings(root=tmp_path / 'installation')
    settings.store().initialize()
    (settings.root / 'shared').mkdir()
    (settings.root / 'settings.json').write_text('{}')
    home = tmp_path / 'original-hermes'
    source(home)
    source(home / 'profiles' / 'writer', model='writer-model', key='writer-private-key-123456789')
    return settings, home, tmp_path / 'backups'


def test_discovery_is_read_only_dynamic_and_ignores_process_credentials(installation, monkeypatch):
    settings, home, backups = installation
    monkeypatch.setenv('ROUTER_KEY', 'wrong-process-secret')
    monkeypatch.setenv('HERMES_HOME', str(home / 'profiles' / 'writer'))
    monkeypatch.delenv('HERMES_BASE_HOME', raising=False)
    assert detect_home() == home
    before = (home / '.env').read_bytes()
    report = discover(home)
    assert [p['key'] for p in report['profiles']] == ['default', 'writer']
    assert not settings.store().templates()
    assert not backups.exists()
    result = connect(settings, home, 'Installed Hermes', backups)
    assert len(result['profiles']) == 2 and all(p['status'] == 'ready' for p in result['profiles'])
    assert (home / '.env').read_bytes() == before
    templates = settings.store().templates()
    assert len(templates) == 2
    first, second = [settings.store().template(p['template_id']) for p in result['profiles']]
    assert first['document']['model'] == 'original-model' and second['document']['model'] == 'writer-model'
    assert settings.store().provider(first['document']['provider_id'])['secret'] == 'private-source-key-123456789'
    assert first['document']['provider_id'] != second['document']['provider_id']
    assert os.environ['ROUTER_KEY'] == 'wrong-process-secret'
    assert 'private-source-key' not in json.dumps(result)
    assert 'original-hermes' not in json.dumps(settings.store().discovered_profiles())
    for template in templates:
        assert 'private user information' not in repr(template)
        bundle = settings.root / 'shared/profiles' / template['document']['skill_bundle_id'] / 'skills'
        assert (bundle / 'base/SKILL.md').is_file()
        assert not (bundle / 'base/USER.md').exists()
    assert not (settings.root / 'users').exists()
    assert list(backups.glob('*/accounts-before.sqlite'))


def test_sync_is_idempotent_adds_new_profiles_and_preserves_ids_and_admin_edits(installation):
    settings, home, backups = installation
    first = connect(settings, home, 'Installed', backups)
    tids = [p['template_id'] for p in first['profiles']]
    versions = [t['version'] for t in settings.store().templates()]
    second = sync(settings)
    assert [p['template_id'] for p in second['profiles']] == tids
    assert [t['version'] for t in settings.store().templates()] == versions
    assert len(list(backups.iterdir())) == 2
    (home / 'SOUL.md').write_text('Updated instructions from Hermes')
    sync(settings)
    assert settings.store().template(tids[0])['document']['soul'] == 'Updated instructions from Hermes'
    assert settings.store().template(tids[0])['version'] == 2
    source(home / 'profiles/research', model='research-model')
    assert len(sync(settings)['profiles']) == 3
    template = settings.store().template(tids[0]); template['document']['soul'] = 'Admin override'
    settings.store().put_template(template['name'], template['document'], template_id=tids[0])
    assert sync(settings)['profiles'][0]['status'] == 'conflict'
    assert settings.store().template(tids[0])['document']['soul'] == 'Admin override'
    (home / 'profiles/writer').rename(home / 'writer-removed')
    sync(settings)
    assert next(p for p in settings.store().discovered_profiles() if p['profile_key'] == 'writer')['status'] == 'missing'
    assert settings.store().template(tids[1])


def test_unsupported_profile_visible_without_copying_oauth_and_symlinks_fail_closed(installation):
    settings, home, backups = installation
    other = home / 'profiles/oauth-only'; other.mkdir()
    (other / 'config.yaml').write_text('model:\n  provider: anthropic\n  default: native-model\n')
    (other / 'auth.json').write_text('{"token":"personal-oauth-token"}')
    (home / 'profiles/linked').symlink_to(other, target_is_directory=True)
    profiles = connect(settings, home, 'Installed', backups)['profiles']
    assert [p['profile'] for p in profiles] == ['Installed / default', 'Installed / oauth-only', 'Installed / writer']
    assert profiles[1]['status'] == 'needs-provider' and profiles[1]['template_id'] is None
    with pytest.raises(PolicyError):
        connect(settings, home, 'Installed', home / 'backup')
    secret = home / 'secret'; secret.write_text('not a skill')
    (home / 'linked').symlink_to(secret)
    with pytest.raises(OSError):
        read_file(home, 'linked')
    with pytest.raises(PolicyError):
        read_file(home, '../secret')
    assert (other / 'auth.json').read_text() == '{"token":"personal-oauth-token"}'


def test_explicit_adoption_keeps_existing_template_provider_and_endpoint(installation):
    settings, home, backups = installation
    store = settings.store()
    pid = store.put_provider('Existing provider', 'http://127.0.0.1:9876/v1', 'private-source-key-123456789')
    tid = store.put_template('Existing main', {'provider_id': pid, 'model': 'original-model'})
    result = connect(settings, home, 'Installed', backups, {'default': tid})
    assert result['profiles'][0]['template_id'] == tid
    assert store.template(tid)['document']['provider_id'] == pid
    assert store.provider(pid)['base_url'] == 'http://127.0.0.1:9876/v1'
    assert len(store.templates()) == 2


def test_provider_mapping_and_keyless_local_profiles(installation):
    from multiuser.discovery import provider_entries
    entries, warnings = provider_entries({'model': {'provider': 'openrouter', 'default': 'model'},
        'providers': {'backup': {'base_url': 'http://127.0.0.1:77/v1', 'model': 'backup'}}},
        {'OPENROUTER_API_KEY': 'source-openrouter-key'})
    assert entries[0]['base_url'] == 'https://openrouter.ai/api/v1'
    assert entries[1]['secret'] == '' and not warnings
    entries, _ = provider_entries({'model': {'provider': 'custom:original', 'default': 'model'},
        'custom_providers': {'Original': {'base_url': 'http://localhost:88/v1', 'key_env': 'LOCAL'}}}, {'LOCAL': 'local-secret'})
    assert entries[0]['secret'] == entries[1]['secret'] == 'local-secret'


def test_native_mapping_identity_uses_key_and_legacy_winner_and_disabled_records():
    from multiuser.discovery import provider_entries
    entries, _ = provider_entries({'model': {'provider': 'custom:stable-id', 'default': 'model'},
        'providers': {'custom:stable-id': {'name': 'Editable label', 'base_url': 'http://localhost:88/v1', 'api_key': 'native-key'},
                      'disabled': {'base_url': 'http://localhost:99/v1', 'enabled': False}}}, {})
    assert len(entries) == 2 and entries[0]['secret'] == 'native-key'
    assert entries[1]['key'] == 'custom:stable-id'
    entries, _ = provider_entries({'model': {'provider': 'custom:router', 'default': 'model'},
        'custom_providers': [{'name': 'Router', 'base_url': 'http://localhost:88/v1', 'api_key': 'legacy-key'}],
        'providers': {'custom:router': {'base_url': 'http://localhost:99/v1', 'api_key': 'native-key'}}}, {})
    assert len(entries) == 2 and entries[0]['secret'] == entries[1]['secret'] == 'legacy-key'


def test_provider_edits_and_explicit_sync_resolution_preserve_authority(installation):
    from multiuser.discovery import resolve
    settings, home, backups = installation
    connected = connect(settings, home, 'Installed', backups)
    first = connected['profiles'][0]
    template = settings.store().template(first['template_id'])
    pid = template['document']['provider_id']
    settings.store().put_provider('Admin provider', 'http://localhost:444/v1', 'admin-private-key', provider_id=pid)
    assert sync(settings)['profiles'][0]['status'] == 'conflict'
    sid = settings.store().discovered_profiles()[0]['source_id']
    assert resolve(settings, sid, 'default', keep_admin=True)['profiles'][0]['status'] == 'customized'
    (home / 'SOUL.md').write_text('Source edit while frozen')
    assert sync(settings)['profiles'][0]['status'] == 'customized'
    assert settings.store().template(first['template_id'])['document']['soul'] != 'Source edit while frozen'
    assert resolve(settings, sid, 'default', keep_admin=False)['profiles'][0]['status'] == 'ready'
    assert settings.store().template(first['template_id'])['document']['soul'] == 'Source edit while frozen'


def test_missing_source_does_not_hide_another_registered_installation(installation):
    settings, home, backups = installation
    connect(settings, home, 'First', backups)
    second = home.parent / 'another-hermes'; source(second, key='different-main-key-123456789')
    connect(settings, second, 'Second', backups)
    home.rename(home.with_name('original-moved'))
    result = sync(settings)
    assert result['profiles'][0]['status'] == 'missing'
    assert result['profiles'][1]['status'] == 'ready'
    catalog = settings.store().discovered_profiles()
    assert {p['status'] for p in catalog if p['name'].startswith('First')} == {'missing'}
    assert len(settings.store().templates()) == 3


def test_skill_publication_is_atomic_on_destination_filesystem(installation, monkeypatch):
    from pathlib import Path
    settings, home, backups = installation
    rename = os.rename
    published = []
    def destination_rename(source_path, destination_path):
        src, dst = Path(source_path), Path(destination_path)
        assert src.parent == dst.parent == settings.root / 'shared/profiles'
        assert src.name.startswith('.publish-')
        assert (src / 'skills/base/SKILL.md').is_file()
        published.append(dst)
        return rename(src, dst)
    monkeypatch.setattr(os, 'rename', destination_rename)
    assert all(p['status'] == 'ready' for p in connect(settings, home, 'Installed', backups)['profiles'])
    assert published
    assert not list((settings.root / 'shared/profiles').glob('.publish-*'))
