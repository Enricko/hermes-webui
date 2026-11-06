"""Trusted, explicit reuse of an existing capability profile; never personal state."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tarfile
import uuid

import yaml

from multiuser.store import PolicyError, identifier
from multiuser.templates import AGENT_FIELDS, PARAMETERS, SECRET_WORDS

TOKEN = re.compile(rb'(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})')
EXCLUDED = {'__pycache__', 'node_modules', 'cache', 'logs', 'memories', 'sessions', 'backups', 'auth.json', 'USER.md'}
EXTENSIONS = {'', '.md', '.txt', '.py', '.sh', '.js', '.mjs', '.json', '.yaml', '.yml', '.html',
              '.css', '.svg', '.conf', '.go', '.jpg', '.jpeg', '.png', '.woff', '.woff2'}


def bundle_path(settings, bundle_id):
    root = settings.root / 'shared'
    for part in ('profiles', identifier(bundle_id), 'skills'):
        root = root / part
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PolicyError('Shared profile skills must be an immutable operator-owned directory')
    return root


def secret_values(source, config):
    values = []
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if SECRET_WORDS.search(str(key)) and isinstance(item, str) and len(item) >= 16 and not item.startswith('${'):
                    values.append(item.encode())
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(config)
    env = source / '.env'
    if env.is_file() and not env.is_symlink():
        # Extract literal credential candidates for scanning only. Never load,
        # expand or execute the source environment in the control-plane process.
        for line in env.read_text().splitlines():
            key, separator, raw = line.partition('=')
            if not separator or key.lstrip().startswith('#') or not SECRET_WORDS.search(key):
                continue
            try:
                candidates = (raw.strip(), ' '.join(shlex.split(raw, comments=True)))
            except ValueError:
                candidates = (raw.strip().strip('\"\''),)
            values.extend(value.encode() for value in candidates if len(value) >= 16)
    return values


def snapshot_skills(source, destination, secrets=()):
    """Open source entries without following links; publish only reviewed skill resources."""
    destination.mkdir(parents=True, mode=0o755)
    copied, skipped = {}, []
    for directory, dirs, names, descriptor in os.fwalk(source, follow_symlinks=False):
        relative = Path(directory).relative_to(source)
        included = []
        for name in sorted(dirs):
            if name.startswith('.') or name in EXCLUDED or SECRET_WORDS.search(name) or (Path(directory) / name).is_symlink():
                skipped.append(str(relative / name) + '/')
            else:
                included.append(name)
        dirs[:] = included
        for name in sorted(names):
            path = relative / name
            if name.startswith('.') or name in EXCLUDED or SECRET_WORDS.search(name) or path.suffix not in EXTENSIONS:
                skipped.append(str(path)); continue
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            except OSError:
                skipped.append(str(path)); continue
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                    skipped.append(str(path)); continue
                content = stream.read()
            if TOKEN.search(content) or any(secret in content for secret in secrets):
                skipped.append(str(path)); continue
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(content)
            target.chmod(0o555 if info.st_mode & 0o111 else 0o444)
            copied[str(path)] = hashlib.sha256(content).hexdigest()
    if not any(Path(name).name == 'SKILL.md' for name in copied):
        raise PolicyError('The selected source contains no reusable skills')
    for directory, _dirs, _names in os.walk(destination):
        Path(directory).chmod(0o755)
    return copied, skipped


def reuse_profile(settings, source, template_id, backup):
    from multiuser.provision import require_operator
    require_operator(settings)
    if source.is_symlink() or not source.is_dir():
        raise PolicyError('Select an existing regular Hermes home directory')
    source = source.resolve(strict=True)
    backup = backup.absolute()
    if (backup.exists() or backup.is_relative_to(source) or backup.is_relative_to(settings.root)
            or source.is_relative_to(settings.root)):
        raise PolicyError('Use a new private backup outside both source and installation')
    for name in ('config.yaml', 'SOUL.md', 'skills'):
        if (source / name).is_symlink():
            raise PolicyError('Profile capability roots cannot be symlinks')
    template = settings.store().template(template_id)
    config = yaml.safe_load((source / 'config.yaml').read_text()) or {}
    secrets = secret_values(source, config)
    soul = (source / 'SOUL.md').read_bytes()
    if TOKEN.search(soul) or any(secret in soul for secret in secrets):
        raise PolicyError('Review embedded credentials in SOUL before sharing it')
    backup.mkdir(parents=True, mode=0o700)
    with tarfile.open(backup / 'capabilities-before.tar', 'w', dereference=False) as archive:
        for name in ('config.yaml', 'SOUL.md', 'skills'):
            archive.add(source / name, arcname=name)
    (backup / 'capabilities-before.tar').chmod(0o600)
    (backup / 'template-before.json').write_text(json.dumps(template, indent=2) + '\n')
    (backup / 'template-before.json').chmod(0o600)
    bundle = uuid.uuid4().hex
    parent = settings.root / 'shared' / 'profiles'
    parent.mkdir(exist_ok=True, mode=0o755)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PolicyError('Invalid shared profile directory')
    (parent / bundle).mkdir(mode=0o755)
    destination = parent / bundle / 'skills'
    copied, skipped = snapshot_skills(source / 'skills', destination, secrets)
    (destination.parent / 'manifest.json').write_text(json.dumps(copied, sort_keys=True) + '\n')
    document = template['document']
    document['skill_bundle_id'] = bundle
    document['soul'] = soul.decode('utf-8')
    model = config.get('model') or {}
    if isinstance(model, dict):
        if model.get('default') != document['model']:
            raise PolicyError('Select a compatible provider/model before reusing this profile')
        document['parameters'].update({k: v for k, v in model.items() if k in PARAMETERS})
    document['agent'].update({k: v for k, v in (config.get('agent') or {}).items() if k in AGENT_FIELDS})
    # Preserve selected explicit instructions; the existing seed mechanism
    # appends them to SOUL once, and does not export them as a provider secret.
    settings.store().put_template(template['name'], document, template_id=template_id)
    report = {'template_id': template_id, 'skill_bundle_id': bundle, 'skill_files': len(copied),
              'skills': sum(Path(name).name == 'SKILL.md' for name in copied), 'skipped_resources': skipped,
              'soul_sha256': hashlib.sha256(soul).hexdigest(), 'personal_state_imported': False,
              'provider_credentials_imported': False, 'backup': str(backup)}
    (backup / 'profile-reuse.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
