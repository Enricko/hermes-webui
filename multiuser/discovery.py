"""Operator-owned discovery of installed Hermes capabilities, never tenant state.

The root-only registry is the filesystem authority. The gateway receives only a
sanitized catalog in SQLite, and cannot request imports or supply source paths.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
import uuid

import yaml

from multiuser.profile import TOKEN, secret_values, snapshot_skills
from multiuser.store import PolicyError, identifier
from multiuser.templates import AGENT_FIELDS, PARAMETERS, validate_template

# Stateless OpenAI-compatible defaults only. Native/OAuth providers remain
# visible as needs-provider; auth.json and process environment are never read.
COMPATIBLE = {
    'openai': ('https://api.openai.com/v1', 'OPENAI_API_KEY'),
    'openrouter': ('https://openrouter.ai/api/v1', 'OPENROUTER_API_KEY'),
    'groq': ('https://api.groq.com/openai/v1', 'GROQ_API_KEY'),
    'deepseek': ('https://api.deepseek.com/v1', 'DEEPSEEK_API_KEY'),
    'together': ('https://api.together.xyz/v1', 'TOGETHER_API_KEY'),
    'fireworks': ('https://api.fireworks.ai/inference/v1', 'FIREWORKS_API_KEY'),
    'xai': ('https://api.x.ai/v1', 'XAI_API_KEY'),
    'nvidia': ('https://integrate.api.nvidia.com/v1', 'NVIDIA_API_KEY'),
}
PROFILE_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def regular_directory(path):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path or not path.is_dir():
        raise PolicyError('Hermes sources must be existing directories without symlink components')
    return path


def read_file(root, relative, limit=2 * 1024 * 1024, *, optional=False):
    """Bounded openat traversal: never follow any component, even during a race."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = Path(relative).parts
        if not parts or any(p in ('..', '.', '/') for p in parts):
            raise PolicyError('Invalid source resource')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        try:
            item = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            if optional:
                return b''
            raise
        with os.fdopen(item, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise PolicyError('Source resource must be a bounded regular file')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise PolicyError('Source resource exceeds its size limit')
            return data
    finally:
        os.close(fd)


def detect_home(explicit=None):
    if explicit is not None:
        return regular_directory(explicit)
    value = os.environ.get('HERMES_BASE_HOME') or os.environ.get('HERMES_HOME')
    if value:
        home = regular_directory(value)
        # A CLI launched while a named profile is active still discovers its
        # installation, not a second unrelated default profile.
        if home.parent.name == 'profiles' and (home.parent.parent / 'config.yaml').is_file():
            home = regular_directory(home.parent.parent)
        return home
    owner = os.environ.get('SUDO_USER') or pwd.getpwuid(os.getuid()).pw_name
    return regular_directory(Path(pwd.getpwnam(owner).pw_dir) / '.hermes')


def profile_paths(home):
    paths = [('default', home)]
    parent = home / 'profiles'
    if parent.exists():
        regular_directory(parent)
        for child in sorted(parent.iterdir()):
            if child.name != 'default' and PROFILE_KEY.fullmatch(child.name) and not child.is_symlink() and child.is_dir():
                paths.append((child.name, child))
    return [(key, path) for key, path in paths if (path / 'config.yaml').exists()]


def configuration(path):
    raw = read_file(path, 'config.yaml')
    value = yaml.safe_load(raw) or {}
    if not isinstance(value, dict):
        raise PolicyError('Hermes config must be a mapping')
    env = {}
    for line in read_file(path, '.env', optional=True).decode().splitlines():
        key, separator, value_raw = line.partition('=')
        if separator and not key.lstrip().startswith('#'):
            try:
                words = shlex.split(value_raw, comments=True)
            except ValueError:
                continue
            if words:
                env[key.strip().removeprefix('export ')] = ' '.join(words)
    return value, env


def endpoint(value):
    parsed = urlsplit(str(value or ''))
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PolicyError('A compatible HTTP(S) provider endpoint is required')
    return str(value).rstrip('/')


def provider_entries(config, env):
    """Return supported configured connections with profile-local credentials."""
    raw_model = config.get('model') or {}
    model = raw_model if isinstance(raw_model, dict) else {'default': raw_model}
    default = model.get('default')
    if not isinstance(default, str) or not default:
        raise PolicyError('Choose a model in Hermes before connecting this profile')
    entries = []
    records = config.get('custom_providers') or []
    if isinstance(records, dict):
        records = [dict(record, name=name) for name, record in records.items() if isinstance(record, dict)]
    if not isinstance(records, list):
        raise PolicyError('Unsupported custom provider configuration')
    configured = config.get('providers') or {}
    slug = lambda name: re.sub(r'[^a-z0-9._-]+', '-', str(name).lower().removeprefix('custom:')).strip('-')
    if isinstance(configured, dict):
        legacy_names = {slug(p.get('name')) for p in records if isinstance(p, dict)}
        records = records + [dict(record, name=record.get('name', name.removeprefix('custom:')), _identity=slug(name))
                             for name, record in configured.items() if isinstance(record, dict) and
                             record.get('base_url') and record.get('enabled', True) and slug(name) not in legacy_names]
    selected = str(model.get('provider', 'custom'))
    selected_record = next((p for p in records if isinstance(p, dict) and
                            p.get('_identity', slug(p.get('name'))) == slug(selected)), {})
    builtin = configured.get(selected, {}) if isinstance(configured, dict) else {}
    builtin = builtin if isinstance(builtin, dict) else {}
    primary = {**builtin, **selected_record, **model}
    if selected in COMPATIBLE:
        url, key_env = COMPATIBLE[selected]
        primary.setdefault('base_url', url); primary.setdefault('key_env', key_env)
    elif selected not in ('custom', 'openai-compatible') and not selected.startswith('custom:'):
        raise PolicyError('This profile needs a stateless OpenAI-compatible provider; OAuth/native tokens are not shared')

    def entry(record, name, key, fallback_model):
        url = endpoint(record.get('base_url'))
        secret = record.get('api_key')
        if isinstance(secret, str) and secret.startswith('${') and secret.endswith('}'):
            secret = env.get(secret[2:-1], '')
        if not secret:
            secret = env.get(record.get('key_env', ''), '')
        if not secret:
            secret = env.get('OPENAI_API_KEY', '') if selected == 'custom' and key == 'primary' else ''
        local = urlsplit(url).hostname in ('127.0.0.1', 'localhost', '::1')
        if not isinstance(secret, str) or (not secret and not local):
            raise PolicyError('Provider API key must resolve in this profile config or .env; OAuth is never copied')
        if '\r' in secret or '\n' in secret or len(secret) > 16384:
            raise PolicyError('Invalid provider credential')
        return {'key': key, 'name': name, 'base_url': url, 'secret': secret,
                'model': record.get('model') or fallback_model}

    entries.append(entry(primary, 'Primary', 'primary', default))
    warnings = []
    for record in records:
        if not isinstance(record, dict):
            continue
        name = record.get('name', '')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}', name) or slug(name) == 'account-primary':
            warnings.append('A connection has an unsupported or reserved name'); continue
        try:
            if record.get('enabled', True) is False:
                continue
            candidate = entry(record, name, 'custom:' + record.get('_identity', slug(name)), default)
        except PolicyError:
            warnings.append('A connection needs an explicit compatible endpoint and profile-local API key'); continue
        if any(p['key'] == candidate['key'] for p in entries):
            raise PolicyError('Duplicate provider connection names')
        entries.append(candidate)
    return entries, warnings


def discover(explicit=None):
    home = detect_home(explicit)
    result = []
    for key, path in profile_paths(home):
        try:
            config, env = configuration(path)
            entries, warnings = provider_entries(config, env)
            result.append({'key': key, 'status': 'available', 'model': entries[0]['model'],
                           'connections': [p['name'] for p in entries[1:]], 'warnings': warnings})
        except (PolicyError, OSError, ValueError, yaml.YAMLError):
            result.append({'key': key, 'status': 'needs-provider',
                           'message': 'Review this profile configuration and its compatible API-key provider in Hermes'})
    return {'profiles': result, 'personal_state_imported': False}


def private_json(path, value):
    temp = path.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, indent=2); out.write('\n'); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def registry(settings):
    path = settings.root / 'profile-sources.json'
    if not path.exists():
        return {'version': 1, 'sources': []}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PolicyError('The profile source registry must be a private root-owned regular file')
    value = json.loads(read_file(settings.root, path.name))
    if value.get('version') != 1 or not isinstance(value.get('sources'), list):
        raise PolicyError('Unsupported source registry')
    return value


@contextlib.contextmanager
def sync_lock(settings):
    from multiuser.provision import require_operator
    require_operator(settings)
    fd = os.open(settings.root / 'profile-sync.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise PolicyError('Invalid trusted profile synchronization lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def connect(settings, explicit, name, backup_root, adopt=None):
    home = detect_home(explicit)
    if home.is_relative_to(settings.root) or settings.root.is_relative_to(home):
        raise PolicyError('Existing Hermes home and multi-user state must be separate')
    if not isinstance(name, str) or not 1 <= len(name) <= 32 or any(ord(c) < 32 for c in name):
        raise PolicyError('Use a source label of 1–32 characters')
    backup_root = Path(backup_root).absolute()
    if backup_root.resolve() != backup_root or backup_root.is_relative_to(home) or backup_root.is_relative_to(settings.root):
        raise PolicyError('Backups must be outside both data roots without symlink components')
    adopt = adopt or {}
    known = dict(profile_paths(home))
    for key, tid in adopt.items():
        if key not in known:
            raise PolicyError('Adoption must identify a discovered profile')
        settings.store().template(identifier(tid))
    with sync_lock(settings):
        value = registry(settings)
        previous = next((s for s in value['sources'] if s['home'] == str(home)), None)
        if previous:
            if adopt:
                raise PolicyError('Adoption is only allowed during first registration')
        else:
            if any(s['name'] == name for s in value['sources']):
                raise PolicyError('Choose a distinct label for each registered Hermes installation')
            adopted = {p['template_id'] for s in value['sources'] for p in s['profiles'].values()}
            if adopted.intersection(adopt.values()):
                raise PolicyError('An adopted template can have only one source authority')
            backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            info = backup_root.stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise PolicyError('The backup root must be private and root-owned')
            value['sources'].append({'id': uuid.uuid4().hex, 'home': str(home), 'name': name,
                'backup_root': str(backup_root), 'adopt': adopt, 'profiles': {}})
            private_json(settings.root / 'profile-sources.json', value)
    return sync(settings)


def capability_document(config, soul, prior=None):
    # Preserve operator choices for fields the installed profile doesn't set.
    document = dict(prior or {})
    model = config.get('model') or {}
    model = model if isinstance(model, dict) else {'default': model}
    document.update(model=model.get('default'), models=[model.get('default')], model_catalog='provider',
                    soul=soul.decode('utf-8'), skills={})
    document['parameters'] = {**document.get('parameters', {}), **{k: v for k, v in model.items() if k in PARAMETERS}}
    document['parameters'].setdefault('context_length', 128000)
    document['agent'] = {**document.get('agent', {}), **{k: v for k, v in (config.get('agent') or {}).items() if k in AGENT_FIELDS}}
    if config.get('max_turns') and 'max_turns' not in document['agent']:
        document['agent']['max_turns'] = config['max_turns']
    document.pop('skill_bundle_id', None)
    return document


def stage_capabilities(settings, home, path, config, staging):
    secrets = secret_values(path, config)
    soul = read_file(path, 'SOUL.md', 65536, optional=True)
    instructions = (config.get('agent') or {}).get('system_message', '')
    if not isinstance(instructions, str):
        raise PolicyError('Unsupported profile instructions')
    for content in (soul, instructions.encode()):
        if TOKEN.search(content) or any(s in content for s in secrets):
            raise PolicyError('Review embedded credentials before sharing profile instructions')
    directories = [path / 'skills']
    extra = (config.get('skills') or {}).get('external_dirs', [])
    for entry in extra if isinstance(extra, list) else []:
        if not isinstance(entry, str):
            continue
        candidate = Path(entry).expanduser() if entry.startswith('~/') else Path(entry)
        if not candidate.is_absolute():
            candidate = path / candidate
        # Registration authorizes this Hermes home only, not arbitrary folders.
        if candidate.is_relative_to(home) and candidate not in directories:
            directories.append(candidate)
    hashes = {}
    for index, directory in enumerate(directories):
        if not directory.exists():
            continue
        regular_directory(directory)
        destination = staging / str(index)
        try:
            copied, _ = snapshot_skills(directory, destination, secrets)
        except PolicyError as exc:
            if 'no reusable skills' in str(exc):
                continue
            raise
        # Profile-local skills win over shared external skill names.
        for relative, content_hash in copied.items():
            if relative in hashes:
                continue
            target = staging / 'skills' / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(destination / relative, target)
            target.chmod((destination / relative).stat().st_mode & 0o777)
            hashes[relative] = content_hash
    if not hashes:
        return soul, None
    bundle = digest(hashes)[:32]
    parent = settings.root / 'shared' / 'profiles'
    parent.mkdir(mode=0o755, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise PolicyError('Invalid shared profile directory')
    parent.chmod(0o755)
    final = parent / bundle
    if not final.exists():
        final.mkdir(mode=0o755)
        os.rename(staging / 'skills', final / 'skills')
        (final / 'manifest.json').write_text(json.dumps(hashes, sort_keys=True))
        final.chmod(0o755)
        for directory, _dirs, _files in os.walk(final / 'skills'):
            Path(directory).chmod(0o755)
    else:
        from multiuser.profile import bundle_path
        bundle_path(settings, bundle)
    return soul, bundle


def backup(settings, source):
    parent = regular_directory(source['backup_root'])
    if parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o077:
        raise PolicyError('Invalid private backup directory')
    destination = parent / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(mode=0o700)
    with settings.store().connection() as db, sqlite3.connect(destination / 'accounts-before.sqlite') as out:
        db.backup(out)
    (destination / 'accounts-before.sqlite').chmod(0o600)
    shutil.copyfile(settings.root / 'profile-sources.json', destination / 'profile-sources-before.json')
    (destination / 'profile-sources-before.json').chmod(0o600)
    return destination


def sync(settings):
    with sync_lock(settings):
        value = registry(settings)
        store = settings.store()
        report = []
        for source in value['sources']:
            try:
                home = regular_directory(source['home'])
                found = dict(profile_paths(home))
            except (PolicyError, OSError):
                with store.connection(write=True) as db:
                    db.execute('UPDATE discovered_profiles SET status=?,message=?,updated=? WHERE source_id=?',
                        ('missing', 'Registered Hermes source is unavailable; private data was preserved', time.time(), source['id']))
                report.append({'source_id': source['id'], 'status': 'missing'})
                continue
            for key, path in found.items():
                previous = source['profiles'].get(key, {})
                tid = previous.get('template_id') or source.get('adopt', {}).get(key)
                name = f"{source['name']} / {key}"
                template_name = name if len(name) <= 80 else name[:70] + ' ' + digest([source['id'], key])[:8]
                status, message = 'ready', 'Ready to assign; personal data remains separate'
                try:
                    if previous.get('frozen'):
                        raise PolicyError('customized')
                    config, env = configuration(path)
                    entries, warnings = provider_entries(config, env)
                    prior = store.template(tid) if tid else None
                    if previous and (not prior or digest(prior['document']) != previous['document_hash']):
                        raise PolicyError('conflict')
                    with tempfile.TemporaryDirectory(prefix='hermes-profile-') as temp:
                        soul, bundle = stage_capabilities(settings, home, path, config, Path(temp))
                    document = capability_document(config, soul, prior['document'] if prior else None)
                    if bundle:
                        document['skill_bundle_id'] = bundle
                    bindings, providers = {}, []
                    for entry in entries:
                        pid = previous.get('bindings', {}).get(entry['key'])
                        current = store.provider(pid) if pid else None
                        if current and previous.get('provider_hashes', {}).get(pid) != digest(current):
                            raise PolicyError('conflict')
                        # Explicit adoption reuses existing provider identities
                        # only when credential equality proves the connection.
                        if not pid and prior:
                            choices = [prior['document']['provider_id']] + [p['provider_id'] for p in prior['document']['connections']]
                            for choice in dict.fromkeys(choices):
                                candidate = store.provider(choice)
                                if candidate['secret'] == entry['secret'] and (entry['secret'] or candidate['base_url'] == entry['base_url']):
                                    pid, current = choice, candidate; break
                        if pid and any(p['id'] == pid and (p['secret'] != entry['secret'] or
                            p['base_url'] != (current['base_url'] if current else entry['base_url'])) for p in providers):
                            # Connections that used to share a key may diverge.
                            # Never overwrite one with another connection's key.
                            pid, current = None, None
                        pid = pid or uuid.uuid4().hex
                        bindings[entry['key']] = pid
                        selected_model = entry['model']
                        if previous.get('source_models', {}).get(entry['key']) == entry['model']:
                            selected_model = previous.get('selected_models', {}).get(entry['key'], selected_model)
                        elif prior and not previous and entry['key'] != 'primary':
                            # Adoption retains an operator's already-verified
                            # connection default (e.g. a retired source model).
                            selected_model = next((p['model'] for p in prior['document']['connections'] if p['provider_id'] == pid), selected_model)
                        provider_name = f"{source['name']}/{key}: {entry['name']}"
                        if len(provider_name) > 80:
                            provider_name = provider_name[:70] + ' ' + digest([source['id'], key, entry['key']])[:8]
                        providers.append({'id': pid, 'name': current['name'] if current else provider_name,
                            # A one-time adopted endpoint may be an intentional
                            # local alias. Keep it while the source URL is unchanged.
                            'base_url': current['base_url'] if current and (not previous or previous.get('source_urls', {}).get(entry['key']) == entry['base_url']) else entry['base_url'],
                            'secret': entry['secret'], 'model': selected_model, 'display': entry['name']})
                    document['provider_id'] = providers[0]['id']
                    document['connections'] = []
                    for provider in providers[1:]:
                        if provider['id'] not in {p['provider_id'] for p in document['connections']}:
                            document['connections'].append({'provider_id': provider['id'], 'name': provider['display'], 'model': provider['model']})
                    document = validate_template(document)
                    # A keyed digest stays root-private; fingerprints of keys
                    # are never returned to the browser or command output.
                    fingerprint = digest({'document': document, 'providers': providers})
                    changed = fingerprint != previous.get('fingerprint')
                    if changed:
                        destination = backup(settings, source)
                        with tarfile.open(destination / ('source-' + key + '.tar'), 'w', dereference=False) as archive:
                            for filename in ('config.yaml', '.env', 'SOUL.md'):
                                if (path / filename).is_file() and not (path / filename).is_symlink():
                                    archive.add(path / filename, arcname=filename)
                        (destination / ('source-' + key + '.tar')).chmod(0o600)
                        tid = tid or uuid.uuid4().hex
                        with store.connection(write=True) as db:
                            current = db.execute('SELECT document FROM templates WHERE id=?', (tid,)).fetchone()
                            if prior and (not current or digest(json.loads(current['document'])) != digest(prior['document'])):
                                raise PolicyError('conflict')
                            for provider in providers:
                                db.execute('INSERT INTO providers VALUES(?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET '
                                           'base_url=excluded.base_url,secret=excluded.secret',
                                           (provider['id'], provider['name'], provider['base_url'], provider['secret']))
                            if not prior or digest(prior['document']) != digest(document):
                                db.execute('INSERT INTO templates(id,name,document) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET '
                                           'document=excluded.document,version=templates.version+1',
                                           (tid, prior['name'] if prior else template_name, json.dumps(document)))
                            store._event(db, 'profile.discovered', tid)
                        source['profiles'][key] = {'template_id': tid, 'bindings': bindings, 'fingerprint': fingerprint,
                            'document_hash': digest(document),
                            'provider_hashes': {p['id']: digest(store.provider(p['id'])) for p in providers},
                            'source_urls': {entry['key']: entry['base_url'] for entry in entries},
                            'source_models': {entry['key']: entry['model'] for entry in entries},
                            'selected_models': {entry['key']: p['model'] for entry, p in zip(entries, providers, strict=True)}}
                        # Persist immediately so a later profile failure cannot
                        # turn a completed publication into duplicate IDs.
                        private_json(settings.root / 'profile-sources.json', value)
                    if warnings:
                        message = 'Ready; some connections need compatible provider configuration in Hermes'
                except (PolicyError, OSError, ValueError, yaml.YAMLError) as exc:
                    status = str(exc) if isinstance(exc, PolicyError) and str(exc) in ('conflict', 'customized') else 'needs-provider'
                    message = {'conflict': 'Admin edits preserved; resolve explicitly with the operator before syncing',
                               'customized': 'Admin-managed profile; automatic source updates are paused'}.get(status,
                               'Review model, credentials and reusable capabilities in the source Hermes profile')
                with store.connection(write=True) as db:
                    db.execute('INSERT INTO discovered_profiles VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id,profile_key) DO UPDATE SET '
                               'template_id=excluded.template_id,status=excluded.status,message=excluded.message,updated=excluded.updated',
                               (source['id'], key, name, tid, status, message, time.time()))
                report.append({'profile': name, 'template_id': tid, 'status': status, 'message': message})
            for key in source['profiles']:
                if key not in found:
                    with store.connection(write=True) as db:
                        db.execute('UPDATE discovered_profiles SET status=?,message=?,updated=? WHERE source_id=? AND profile_key=?',
                            ('missing', 'Source profile is missing; existing accounts and private data were preserved', time.time(), source['id'], key))
        return {'profiles': report, 'personal_state_imported': False}


def resolve(settings, source_id, key, *, keep_admin):
    """Explicit operator choice; neither option ever overwrites tenant files."""
    identifier(source_id)
    with sync_lock(settings):
        value = registry(settings)
        source = next((s for s in value['sources'] if s['id'] == source_id), None)
        if not source or key not in source['profiles']:
            raise PolicyError('Registered source profile not found')
        previous = source['profiles'][key]
        destination = backup(settings, source)
        template = settings.store().template(previous['template_id'])
        previous.update(frozen=keep_admin, document_hash=digest(template['document']), fingerprint='')
        previous['provider_hashes'] = {pid: digest(settings.store().provider(pid)) for pid in set(previous['bindings'].values())}
        private_json(settings.root / 'profile-sources.json', value)
    result = sync(settings)
    result['backup'] = str(destination)
    return result
