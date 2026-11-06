"""Explicit multi-user installation/account CLI. Passwords never enter argv or logs."""

from __future__ import annotations

import argparse
from dataclasses import replace
import getpass
import json
import os
from pathlib import Path
import sys
import tarfile

from multiuser.settings import Settings
from multiuser.store import PolicyError


def password(args):
    if args.password_stdin:
        return sys.stdin.readline().rstrip('\r\n')
    first = getpass.getpass('Password: ')
    second = getpass.getpass('Confirm password: ')
    if first != second:
        raise PolicyError('Passwords do not match')
    return first


def find_user(store, value):
    matches = [u for u in store.users() if value in (u['id'], u['username'])]
    if len(matches) != 1:
        raise PolicyError('Account not found')
    return matches[0]


def migrate(settings, args):
    """Snapshot first; only explicit capabilities can enter the new template."""
    import yaml
    from multiuser.templates import AGENT_FIELDS, PARAMETERS, relative_file
    source = args.source.resolve(strict=True)
    backup = args.backup.absolute()
    if backup.exists() or backup.is_relative_to(source) or backup.is_relative_to(settings.root):
        raise PolicyError('Use a new private backup directory outside both source and multi-user state')
    if not source.is_dir():
        raise PolicyError('Single-user source must be a Hermes home directory')
    backup.mkdir(parents=True, mode=0o700)
    with tarfile.open(backup / 'single-user-before.tar', 'w', dereference=False) as archive:
        archive.add(source, arcname='hermes')
    (backup / 'single-user-before.tar').chmod(0o600)
    config_path = source / 'config.yaml'
    if config_path.is_symlink():
        raise PolicyError('Source configuration must not be a symlink')
    config = yaml.safe_load(config_path.read_text()) or {}
    model = config.get('model', {})
    default = args.model or (model.get('default') if isinstance(model, dict) else model)
    if not default:
        raise PolicyError('Select an explicit model')
    document = {'provider_id': args.provider_id, 'model': default, 'models': args.allowed_model or [default]}
    if args.parameters:
        document['parameters'] = {k: v for k, v in model.items() if k in PARAMETERS} if isinstance(model, dict) else {}
        document['agent'] = {k: v for k, v in (config.get('agent') or {}).items() if k in AGENT_FIELDS - {'system_message'}}
    if args.soul:
        soul = source / 'SOUL.md'
        if soul.is_symlink():
            raise PolicyError('SOUL must be a regular explicitly selected file')
        document['soul'] = soul.read_text()
    skills = {}
    for relative in args.skill:
        name = relative_file(relative)
        path = source / 'skills' / name
        if path.is_symlink() or not path.resolve().is_relative_to(source / 'skills'):
            raise PolicyError('Selected skill cannot escape the source skills directory')
        skills[name] = path.read_text()
    document['skills'] = skills
    tid = settings.store().put_template(args.name, document)
    report = {'template_id': tid, 'model': default, 'parameters_selected': args.parameters,
              'soul_selected': args.soul, 'selected_skill_files': list(skills),
              'personal_state_imported': False, 'backup': str(backup)}
    (backup / 'migration-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/srv/hermes'))
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='Create an intentionally enabled, empty installation')
    init.add_argument('--public-url', required=True)
    init.add_argument('--port', type=int, default=8799)
    init.add_argument('--gateway-uid', type=int, default=10000)
    init.add_argument('--worker-uid', type=int, default=10001)
    init.add_argument('--relay-uid', type=int, default=10002)
    init.add_argument('--images', type=Path)
    images = sub.add_parser('set-images')
    images.add_argument('--images', type=Path, required=True)
    for command in ['bootstrap-admin', 'create-user']:
        item = sub.add_parser(command)
        item.add_argument('--username', required=True)
        item.add_argument('--password-stdin', action='store_true')
        item.add_argument('--template')
        if command == 'create-user':
            item.add_argument('--role', choices=['admin', 'user'], default='user')
    sub.add_parser('list-users')
    for command in ['disable-user', 'enable-user', 'reset-password', 'set-role', 'assign-template']:
        item = sub.add_parser(command)
        item.add_argument('--user', required=True, help='Stable ID or username (operator CLI only)')
        if command == 'reset-password':
            item.add_argument('--password-stdin', action='store_true')
        if command == 'set-role':
            item.add_argument('--role', choices=['admin', 'user'], required=True)
        if command == 'assign-template':
            item.add_argument('--template', required=True)
    provider = sub.add_parser('put-provider')
    provider.add_argument('--id')
    provider.add_argument('--name', required=True)
    provider.add_argument('--base-url', required=True)
    provider.add_argument('--secret-stdin', action='store_true')
    sub.add_parser('list-providers')
    template = sub.add_parser('put-template')
    template.add_argument('--id')
    template.add_argument('--name', required=True)
    template.add_argument('--file', type=Path, required=True)
    sub.add_parser('list-templates')
    tool = sub.add_parser('publish-tool')
    tool.add_argument('--id')
    tool.add_argument('--name', required=True)
    tool.add_argument('--description', required=True)
    tool.add_argument('--source', type=Path, required=True)
    sub.add_parser('list-tools')
    reconcile = sub.add_parser('reconcile')
    reconcile.add_argument('--watch', action='store_true')
    stop = sub.add_parser('stop-runtime')
    stop.add_argument('--user', required=True)
    sub.add_parser('stop-all-runtimes', help='Stop only this installation; preserve every data directory')
    resolve = sub.add_parser('resolve-template', help='Preserve private edits and accept the new template baseline')
    resolve.add_argument('--user', required=True)
    resolve.add_argument('--keep-private', action='store_true', required=True)
    migration = sub.add_parser('migrate-single-user')
    migration.add_argument('--source', type=Path, required=True)
    migration.add_argument('--backup', type=Path, required=True)
    migration.add_argument('--name', required=True)
    migration.add_argument('--provider-id', required=True)
    migration.add_argument('--model')
    migration.add_argument('--allowed-model', action='append', default=[])
    migration.add_argument('--parameters', action='store_true')
    migration.add_argument('--soul', action='store_true')
    migration.add_argument('--skill', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            from multiuser.provision import initialize
            values = json.loads(args.images.read_text()) if args.images else {}
            settings = Settings(root=args.root.absolute(), public_url=args.public_url.rstrip('/'), port=args.port,
                                gateway_uid=args.gateway_uid, worker_uid=args.worker_uid, relay_uid=args.relay_uid,
                                runtime_image=values.get('worker_image', ''), relay_image=values.get('relay_image', ''))
            initialize(settings)
            result = {'root': str(settings.root), 'initialized': True, 'single_user_data_imported': False}
        else:
            settings = Settings.load(args.root)
            if os.geteuid() not in (0, settings.gateway_uid):
                raise PolicyError('Use the dedicated trusted gateway account or a root operator')
            store = settings.store()
            if args.command == 'set-images':
                if os.geteuid() != 0:
                    raise PolicyError('Only the trusted root operator can select runtime images')
                values = json.loads(args.images.read_text())
                settings = replace(settings, runtime_image=values['worker_image'], relay_image=values['relay_image'])
                settings.validate(images=True).save()
                os.chown(settings.root / 'settings.json', 0, settings.gateway_uid)
                result = {'images_updated': True}
            elif args.command in ('bootstrap-admin', 'create-user'):
                result = store.create_user(args.username, password(args), role='admin' if args.command == 'bootstrap-admin' else args.role,
                                           template_id=args.template, bootstrap=args.command == 'bootstrap-admin')
            elif args.command == 'list-users':
                result = store.users()
            elif args.command in ('disable-user', 'enable-user', 'reset-password', 'set-role', 'assign-template'):
                user = find_user(store, args.user)
                changes = {}
                if args.command in ('disable-user', 'enable-user'):
                    changes['enabled'] = args.command == 'enable-user'
                elif args.command == 'reset-password':
                    changes['password'] = password(args)
                elif args.command == 'set-role':
                    changes['role'] = args.role
                else:
                    changes.update(template_id=args.template, assign_template=True)
                result = store.update_user(user['id'], **changes)
            elif args.command == 'put-provider':
                secret = sys.stdin.readline().rstrip('\r\n') if args.secret_stdin else getpass.getpass('Provider API key (empty for a private local endpoint): ')
                result = {'id': store.put_provider(args.name, args.base_url, secret, provider_id=args.id)}
            elif args.command == 'list-providers':
                result = store.providers()
            elif args.command == 'put-template':
                result = {'id': store.put_template(args.name, json.loads(args.file.read_text()), template_id=args.id)}
            elif args.command == 'list-templates':
                result = store.templates()
            elif args.command == 'publish-tool':
                source = args.source.absolute()
                if source.is_symlink() or not source.is_file() or source.suffix not in ('.py', '.sh', '.js'):
                    raise PolicyError('Publish an explicitly reviewed regular script (.py, .sh or .js), not a symlink')
                result = {'id': store.put_tool(args.name, args.description, source.name, source.read_text(), tool_id=args.id)}
            elif args.command == 'list-tools':
                result = store.tools()
            elif args.command in ('reconcile', 'stop-runtime', 'stop-all-runtimes', 'resolve-template'):
                from multiuser.provision import Provisioner
                provisioner = Provisioner(settings)
                if args.command == 'resolve-template':
                    user = find_user(store, args.user)
                    if not user['template_id']:
                        raise PolicyError('Assign a template first')
                    provisioner.stop(user['id'])
                    provisioner.prepare_directories(user['id'])
                    kept = provisioner.seed(user['id'], store.template(user['template_id']), keep_private=True)
                    print(json.dumps({'private_files_preserved': kept}))
                    return 0
                elif args.command == 'stop-runtime':
                    provisioner.stop(find_user(store, args.user)['id'])
                elif args.command == 'stop-all-runtimes':
                    for user in store.users():
                        provisioner.stop(user['id'])
                elif args.watch:
                    provisioner.watch()
                else:
                    provisioner.reconcile()
                result = {'reconciled': True}
            elif args.command == 'migrate-single-user':
                result = migrate(settings, args)
            else:
                raise PolicyError('Unsupported command')
        print(json.dumps(result, indent=2))
    except (PolicyError, ValueError, OSError) as exc:
        print('Refused: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
