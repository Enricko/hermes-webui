"""Private provider imports and worker configurations never transfer credentials."""

import copy
import os

import pytest
import yaml

from multiuser.connections import source_connections
from multiuser.store import PolicyError
from multiuser.templates import validate_template, worker_config


def test_existing_connections_resolve_only_source_credentials_without_process_mutation(tmp_path, monkeypatch):
    monkeypatch.setenv('PROVIDER_KEY', 'another-users-credential')
    (tmp_path / '.env').write_text('export PROVIDER_KEY="source-profile-credential"\n')
    (tmp_path / 'config.yaml').write_text(yaml.safe_dump({'custom_providers': [
        {'name': 'Original Router', 'base_url': 'http://127.0.0.1:1/v1', 'key_env': 'PROVIDER_KEY', 'model': 'base'}]}))
    entries = source_connections(tmp_path, ['Original Router'])
    assert entries[0]['secret'] == 'source-profile-credential'
    assert os.environ['PROVIDER_KEY'] == 'another-users-credential'
    with pytest.raises(PolicyError):
        source_connections(tmp_path, ['Unknown Router'])
    (tmp_path / '.env').unlink()
    with pytest.raises(PolicyError):
        source_connections(tmp_path, ['Original Router'])


def test_named_connections_are_opaque_internal_routes_and_duplicate_names_fail_closed():
    document = {'provider_id': 'a' * 32, 'model': 'base', 'model_catalog': 'provider',
        'connections': [{'provider_id': 'a' * 32, 'name': 'Main Router', 'model': 'base'},
                        {'provider_id': 'b' * 32, 'name': 'Second Router', 'model': 'same-model'}]}
    config = worker_config(document)
    assert len(config['custom_providers']) == 3
    assert config['custom_providers'][0]['name'] == 'Account primary'
    assert config['model']['provider'] == 'custom:account-primary'
    assert config['custom_providers'][0]['base_url'] == config['model']['base_url']
    for provider in config['custom_providers'][1:]:
        assert provider['base_url'].startswith('http://127.0.0.1:8000/providers/')
        assert provider['api_key'] == 'tenant-broker'
        assert provider['discover_models'] is True
    for mutation in [dict(document['connections'][0], name='Main-Router', provider_id='c' * 32),
                     dict(document['connections'][1], base_url='http://attacker'),
                     dict(document['connections'][1], api_key='private'),
                     dict(document['connections'][1], provider_id='../escape')]:
        invalid = copy.deepcopy(document)
        invalid['connections'].append(mutation)
        with pytest.raises(PolicyError):
            validate_template(invalid)


def test_provider_import_is_backed_up_atomic_and_keeps_secrets_out_of_runtime(tmp_path, monkeypatch):
    import io
    import json
    import secrets
    import urllib.request
    from multiuser.connections import import_connections
    from multiuser.settings import Settings
    monkeypatch.setattr('multiuser.provision.require_operator', lambda _settings: None)
    settings = Settings(root=tmp_path / 'installation')
    store = settings.store(); store.initialize()
    store.create_user('administrator', secrets.token_urlsafe(24), role='admin', bootstrap=True)
    existing = store.put_provider('Legacy main', 'http://127.0.0.1:1/v1', 'old-private-key')
    template = store.put_template('Original profile', {'provider_id': existing, 'model': 'base'})
    source = tmp_path / 'legacy'; source.mkdir()
    (source / '.env').write_text('FIRST_KEY=source-first-private-key\nSECOND_KEY=source-second-private-key\n')
    original = {'custom_providers': [
        {'name': 'First Router', 'base_url': 'http://127.0.0.1:99/v1', 'key_env': 'FIRST_KEY', 'model': 'base'},
        {'name': 'Second Router', 'base_url': 'http://127.0.0.1:2/v1', 'key_env': 'SECOND_KEY', 'model': 'retired-default'}]}
    (source / 'config.yaml').write_text(yaml.safe_dump(original))
    source_before = (source / '.env').read_bytes()
    mode = {'fail': True}
    requested = []
    class Opener:
        def open(self, request, timeout):
            requested.append(request.full_url)
            if ':2/' in request.full_url and mode['fail']:
                return io.BytesIO(b'{"error":"source-second-private-key"}')
            return io.BytesIO(json.dumps({'data': [{'id': 'base'}, {'id': 'additional'}]}).encode())
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *_: Opener())
    names = ['First Router', 'Second Router']
    with pytest.raises(PolicyError, match='catalog could not be verified'):
        import_connections(settings, source, names, template, tmp_path / 'failed-backup', {'First Router': existing})
    assert len(store.providers()) == 1
    assert store.provider(existing)['secret'] == 'old-private-key'
    assert store.template(template)['document']['connections'] == []
    mode['fail'] = False
    backup = tmp_path / 'backup'
    report = import_connections(settings, source, names, template, backup, {'First Router': existing})
    assert len(store.providers()) == 2 and len(report['connections']) == 2
    assert report['connections'][1]['source_default_available'] is False
    assert report['connections'][1]['model'] == 'base'
    assert 'http://127.0.0.1:99/v1/models' not in requested
    assert store.provider(existing)['secret'] == 'source-first-private-key'
    runtime = worker_config(store.template(template)['document'])
    assert 'source-first-private-key' not in repr(runtime) and 'source-second-private-key' not in repr(runtime)
    assert (source / '.env').read_bytes() == source_before
    assert backup.stat().st_mode & 0o777 == 0o700
    assert (backup / 'accounts-before.sqlite').stat().st_mode & 0o777 == 0o600
    assert (backup / 'provider-source-before.tar').stat().st_mode & 0o777 == 0o600
