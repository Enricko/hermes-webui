"""Explicit root-only import of selected existing provider connections."""

import json
import shlex
import sqlite3
import tarfile
import urllib.error
import urllib.request
import uuid

import yaml

from multiuser.broker import CatalogUnavailable, catalog_models
from multiuser.store import PolicyError, identifier


def source_connections(source, names):
    for name in ('config.yaml', '.env'):
        if (source / name).is_symlink():
            raise PolicyError('Provider source files cannot be symlinks')
    config = yaml.safe_load((source / 'config.yaml').read_text()) or {}
    env = {}
    if (source / '.env').is_file():
        for line in (source / '.env').read_text().splitlines():
            key, separator, value = line.partition('=')
            if not separator or key.lstrip().startswith('#'):
                continue
            try:
                words = shlex.split(value, comments=True)
            except ValueError:
                continue
            if words:
                env[key.strip().removeprefix('export ')] = ' '.join(words)
    connections = []
    for name in names:
        matches = [p for p in config.get('custom_providers', []) if isinstance(p, dict) and p.get('name') == name]
        if len(matches) != 1:
            raise PolicyError('Select an unambiguous existing custom provider name')
        entry = matches[0]
        secret = entry.get('api_key') or env.get(entry.get('key_env', ''), '')
        if isinstance(secret, str) and secret.startswith('${') and secret.endswith('}'):
            secret = env.get(secret[2:-1], '')
        if not isinstance(secret, str) or not secret:
            raise PolicyError('The selected provider credential must resolve in its source profile')
        connections.append({'name': name, 'base_url': entry.get('base_url'), 'secret': secret, 'model': entry.get('model')})
    return connections


def import_connections(settings, source, names, template_id, backup, reuse):
    from multiuser.provision import require_operator
    from multiuser.templates import validate_template
    require_operator(settings)
    if source.is_symlink() or not source.is_dir() or not names or len(names) != len(set(names)):
        raise PolicyError('Select existing providers from one regular Hermes home')
    source = source.resolve(strict=True)
    backup = backup.absolute()
    if backup.exists() or backup.is_relative_to(source) or backup.is_relative_to(settings.root):
        raise PolicyError('Use a new private backup directory outside both data roots')
    entries = source_connections(source, names)
    store = settings.store()
    template = store.template(template_id)
    # Validate metadata before changing any provider records or reading URLs.
    for entry in entries:
        validate_template({**template['document'], 'connections': [{'provider_id': 'a' * 32,
            'name': entry['name'], 'model': entry['model']}]})
    backup.mkdir(parents=True, mode=0o700)
    with store.connection() as connection, sqlite3.connect(backup / 'accounts-before.sqlite') as destination:
        connection.backup(destination)
    (backup / 'accounts-before.sqlite').chmod(0o600)
    with tarfile.open(backup / 'provider-source-before.tar', 'w', dereference=False) as archive:
        for name in ('config.yaml', '.env'):
            if (source / name).is_file():
                archive.add(source / name, arcname=name)
    (backup / 'provider-source-before.tar').chmod(0o600)
    known = {provider['name']: provider for provider in store.providers()}
    verified = []
    for entry in entries:
        existing = store.provider(identifier(reuse[entry['name']])) if entry['name'] in reuse else known.get(entry['name'])
        endpoint = existing['base_url'] if existing else entry['base_url']
        from urllib.parse import urlsplit
        parsed = urlsplit(str(endpoint or ''))
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyError('Provider endpoint must be an explicit HTTP(S) URL without credentials')
        request = urllib.request.Request(endpoint.rstrip('/') + '/models', headers={
            'Authorization': 'Bearer ' + entry['secret'], 'User-Agent': 'Hermes-WebUI/1.0'})
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args, **_kwargs):
                    return None
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=12) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise CatalogUnavailable()
                models = catalog_models(json.loads(raw), entry['secret'])
        except (urllib.error.URLError, ValueError, CatalogUnavailable) as exc:
            raise PolicyError('Selected provider catalog could not be verified: ' + entry['name']) from exc
        ids = [model['id'] for model in models]
        verified.append({**entry, 'base_url': endpoint, 'id': existing['id'] if existing else uuid.uuid4().hex,
            'model': entry['model'] if entry['model'] in ids else ids[0],
            'source_default_available': entry['model'] in ids, 'model_count': len(ids)})
    assigned = list(template['document']['connections'])
    report = []
    for entry in verified:
        pid = entry['id']
        assigned = [old for old in assigned if old['provider_id'] != pid and old['name'] != entry['name']]
        assigned.append({'provider_id': pid, 'name': entry['name'], 'model': entry['model']})
        report.append({'provider_id': pid, 'name': entry['name'], 'model': entry['model'],
            'model_count': entry['model_count'], 'source_default_available': entry['source_default_available']})
    document = template['document']
    document.update(connections=assigned, model_catalog='provider')
    document = validate_template(document)
    # Publish credentials and their authorization together, or neither. A
    # concurrent profile edit must never be overwritten by a stale import.
    with store.connection(write=True) as db:
        for entry in verified:
            db.execute('''INSERT INTO providers(id,name,base_url,secret,enabled) VALUES(?,?,?,?,1)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,base_url=excluded.base_url,
                secret=excluded.secret,enabled=1''', (entry['id'], entry['name'], entry['base_url'].rstrip('/'), entry['secret']))
        for pid in [document['provider_id'], *(entry['provider_id'] for entry in assigned)]:
            if not db.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (pid,)).fetchone():
                raise PolicyError('A selected provider became unavailable during import')
        changed = db.execute('UPDATE templates SET document=?,version=version+1 WHERE id=? AND version=?',
                             (json.dumps(document), template_id, template['version']))
        if changed.rowcount != 1:
            raise PolicyError('The shared profile changed during provider import; retry after review')
        store._event(db, 'profile.providers_imported', template_id)
    result = {'template_id': template_id, 'connections': report, 'backup': str(backup),
              'credentials_in_worker': False, 'original_source_modified': False}
    (backup / 'provider-import.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
