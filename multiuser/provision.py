"""Trusted host-only provisioning. This module is never invoked by an Agent/API."""

from __future__ import annotations

import contextlib
from decimal import Decimal
import fcntl
import hashlib
import http.client
import json
import os
import socket
import stat
import subprocess
import time

from multiuser.settings import Settings
from multiuser.store import PolicyError, identifier
from multiuser.templates import relative_file, worker_config


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__('localhost', timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def require_operator(settings: Settings):
    if os.geteuid() != 0:
        raise PolicyError("Provisioning requires a trusted root operator; the gateway has no Docker access")
    path = settings.root / 'settings.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PolicyError("Provisioning settings must be root-owned and not group/world writable")
    if settings.root.lstat().st_uid != 0 or settings.root.lstat().st_mode & 0o022:
        raise PolicyError("Installation root must be root-owned and not group/world writable")
    settings.validate(images=True)


def initialize(settings):
    if os.geteuid() != 0:
        raise PolicyError("Initialize with a trusted root operator")
    settings.validate()
    if settings.root.exists() and any(settings.root.iterdir()):
        raise PolicyError("Initialization requires a new empty directory; existing single-user state is never adopted")
    settings.root.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.chown(settings.root, 0, settings.gateway_uid)
    settings.root.chmod(0o750)
    for name, uid, gid, mode in [
        ('control', 0, settings.gateway_uid, 0o2770),
        ('users', 0, 0, 0o700), ('runtimes', 0, settings.gateway_uid, 0o750),
        ('shared', 0, 0, 0o700),
    ]:
        path = settings.root / name
        path.mkdir()
        os.chown(path, uid, gid)
        path.chmod(mode)
    settings.save()
    os.chown(settings.root / 'settings.json', 0, settings.gateway_uid)
    settings.store().initialize()
    os.chown(settings.database, settings.gateway_uid, settings.gateway_uid)
    # A dedicated control-plane group and setgid directory also make WAL/SHM
    # files accessible when the root reconciler and gateway overlap.
    settings.database.chmod(0o660)


def directory(path, uid, gid, mode):
    if path.is_symlink():
        raise PolicyError("Provisioning directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise PolicyError("Provisioning path must be a directory")
    os.chown(path, uid, gid)
    path.chmod(mode)


@contextlib.contextmanager
def private_parent(root, relative):
    """Every user-controlled component is opened with O_NOFOLLOW, including races."""
    parts = relative_file(relative).split('/')
    descriptors = [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in parts[:-1]:
            parent = descriptors[-1]
            try:
                os.mkdir(part, 0o700, dir_fd=parent)
                os.chown(part, os.stat(root).st_uid, os.stat(root).st_gid, dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                pass
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
        yield descriptors[-1], parts[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def private_read(root, relative):
    try:
        with private_parent(root, relative) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
                    raise PolicyError("Template destination must be a regular file")
                return stream.read()
    except FileNotFoundError:
        return None


def private_write(root, relative, data, uid):
    with private_parent(root, relative) as (parent, name):
        temp = '.mu-' + os.urandom(12).hex()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), uid, uid)
            # Replacing a malicious symlink replaces the link itself; never its
            # target. Parent descriptors cannot be retargeted by a rename race.
            os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass


class Provisioner:
    def __init__(self, settings):
        require_operator(settings)
        self.settings = settings
        self.store = settings.store()
        self.prefix = 'hmu-' + hashlib.sha256(str(settings.root).encode()).hexdigest()[:10] + '-'
        security = self.docker('info', '--format', '{{json .SecurityOptions}}').stdout
        if 'seccomp,profile=builtin' not in security:
            raise PolicyError("A Docker daemon with the default seccomp profile is required")

    def docker(self, *args, check=True):
        # No shell interpolation, alternate Docker context, or user-supplied flags.
        result = subprocess.run(['docker', '--host', 'unix://' + self.settings.docker_socket, *args],
                                capture_output=True, text=True, timeout=90, check=False)
        if check and result.returncode:
            # Daemon errors can include host paths; keep browser-facing errors generic.
            raise PolicyError('Docker provisioning failed (' + str(result.returncode) + ')')
        return result

    def inspect(self, name):
        result = self.docker('inspect', name, check=False)
        return json.loads(result.stdout)[0] if result.returncode == 0 else None

    def names(self, uid):
        identifier(uid)
        return self.prefix + uid + '-relay', self.prefix + uid + '-worker'

    def stop(self, uid):
        relay, worker = self.names(uid)
        for name in [worker, relay]:
            actual = self.inspect(name)
            if actual:
                if actual.get('Config', {}).get('Labels', {}).get('hermes.mu.installation') != self.prefix or actual['Config']['Labels'].get('hermes.mu.user') != uid:
                    raise PolicyError("Refusing to remove a container outside this installation/account")
                self.docker('stop', '--time', '30', name, check=False)
                self.docker('rm', name)

    def prepare_directories(self, uid):
        s = self.settings
        root = s.user_dir(uid)
        directory(root, 0, 0, 0o700)
        for name in ['hermes', 'workspace', 'tmp', 'outputs']:
            directory(root / name, s.worker_uid, s.worker_uid, 0o700)
        runtime = s.runtime_dir(uid)
        directory(runtime, 0, s.gateway_uid, 0o750)
        directory(runtime / 'relay', s.relay_uid, s.gateway_uid, 0o750)
        directory(runtime / 'broker', s.gateway_uid, s.gateway_uid, 0o750)
        directory(runtime / 'tools', 0, 0, 0o755)

    def seed(self, uid, template, *, keep_private=False):
        import yaml
        s = self.settings
        home = s.user_dir(uid) / 'hermes'
        manifest = s.runtime_dir(uid) / 'seed-manifest.json'
        previous = json.loads(manifest.read_text()) if manifest.exists() else {}
        document = template['document']
        instructions = document['agent'].get('system_message', '')
        soul = document['soul'] + ('\n\n' + instructions if instructions else '')
        files = {'config.yaml': yaml.safe_dump(worker_config(document), sort_keys=False).encode(),
                 'SOUL.md': soul.encode()}
        for name, content in document['skills'].items():
            files['skills/' + relative_file(name)] = content.encode()
        catalog = []
        filenames = set()
        for tid in document['tools']:
            tool = self.store.tool(tid)
            filename = tool['filename']
            if filename in filenames:
                raise PolicyError("A template cannot select two tools with the same filename")
            filenames.add(filename)
            source = s.root / 'shared' / tool['id'] / str(tool['version'])
            directory(source, 0, 0, 0o755)
            script = source / filename
            content = tool['content'].encode()
            if script.exists() and script.read_bytes() != content:
                raise PolicyError("Published tool versions are immutable")
            if not script.exists():
                script.write_bytes(content)
                script.chmod(0o444)
            dest = s.runtime_dir(uid) / 'tools' / filename
            if dest.exists():
                dest.unlink()
            os.link(script, dest)
            catalog.append(f"- `/shared/tools/{filename}`: {tool['description']}")
        for path in (s.runtime_dir(uid) / 'tools').iterdir():
            if path.name not in filenames:
                path.unlink()
        instruction = ("# Shared tools\n\nUse the existing tools below before reimplementing a converter.\n"
                       "Source under /shared/tools is read-only. Put every input/output in /workspace\n"
                       "and every job's temporary files under /tmp; never write next to a script.\n\n" +
                       ('\n'.join(catalog) or 'No shared tools have been assigned.') + '\n')
        files['skills/shared-tools/SKILL.md'] = instruction.encode()
        updated = dict(previous)
        conflicts = []
        for relative, content in files.items():
            existing = private_read(home, relative)
            existing_hash = hashlib.sha256(existing).hexdigest() if existing is not None else None
            desired_hash = hashlib.sha256(content).hexdigest()
            if relative in previous and desired_hash == previous[relative]:
                # No template change: private edits/deletions survive account
                # restarts and password changes without becoming conflicts.
                continue
            if existing is not None and existing_hash != previous.get(relative):
                # User edits are authoritative; changing a capability template
                # cannot overwrite private instructions, config or learned skills.
                if existing != content:
                    conflicts.append(relative)
                    if keep_private:
                        # Explicit operator resolution: advance the template
                        # baseline while preserving the user's current bytes.
                        updated[relative] = desired_hash
                continue
            private_write(home, relative, content, s.worker_uid)
            updated[relative] = desired_hash
        manifest.write_text(json.dumps(updated, indent=2) + '\n')
        manifest.chmod(0o600)
        return conflicts

    def generation(self, user, template):
        versions = [(tid, self.store.tool(tid)['version']) for tid in template['document']['tools']]
        value = [user['auth_version'], template['id'], template['version'], versions,
                 self.settings.runtime_image, self.settings.relay_image,
                 self.settings.gateway_uid, self.settings.worker_uid, self.settings.relay_uid,
                 self.settings.worker_memory, self.settings.worker_cpus]
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def common(self, uid, generation, memory, cpus):
        return ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--pids-limit', '256', '--memory', memory, '--cpus', cpus, '--init', '--ipc', 'private', '--cgroupns', 'private',
                '--label', 'hermes.mu.installation=' + self.prefix,
                '--label', 'hermes.mu.user=' + uid, '--label', 'hermes.mu.generation=' + generation,
                '--log-opt', 'max-size=10m', '--log-opt', 'max-file=2']

    @staticmethod
    def mount(source, destination, *, readonly=False):
        return ['--mount', 'type=bind,src=' + str(source) + ',dst=' + destination + (',readonly' if readonly else '')]

    def start(self, uid, generation):
        s = self.settings
        relay_name, worker_name = self.names(uid)
        relay = self.common(uid, generation, '128m', '0.25') + [
            '--name', relay_name, '--network', 'none', '--user', f'{s.relay_uid}:{s.gateway_uid}']
        relay += self.mount(s.runtime_dir(uid) / 'relay', '/relay')
        relay += self.mount(s.runtime_dir(uid) / 'broker', '/broker', readonly=True)
        relay += [s.relay_image]
        self.docker('create', *relay)
        actual_relay = self.inspect(relay_name)
        self.admit_relay(uid, generation, actual_relay, running=False)
        self.docker('start', relay_name)
        actual_relay = self.inspect(relay_name)
        self.admit_relay(uid, generation, actual_relay)
        worker = self.common(uid, generation, s.worker_memory, s.worker_cpus) + [
            '--name', worker_name, '--network', 'container:' + actual_relay['Id'],
            '--user', f'{s.worker_uid}:{s.worker_uid}', '--shm-size', '128m']
        user = s.user_dir(uid)
        for source, destination in [('hermes', '/state/hermes'), ('workspace', '/workspace'),
                                    ('tmp', '/tmp'), ('outputs', '/outputs')]:
            worker += self.mount(user / source, destination)
        worker += self.mount(s.runtime_dir(uid) / 'tools', '/shared/tools', readonly=True)
        self.docker('create', *worker, s.runtime_image)
        self.admit_worker(uid, generation, self.inspect(worker_name), actual_relay, running=False)
        self.docker('start', worker_name)

    def base_admission(self, uid, generation, actual, image, user, *, running=True):
        if actual is None or (running and not actual['State']['Running']) or (not running and actual['State']['Status'] != 'created'):
            raise PolicyError("Runtime container is not running")
        host = actual['HostConfig']
        labels = actual['Config'].get('Labels', {})
        required = {"hermes.mu.installation": self.prefix, "hermes.mu.user": uid,
                    "hermes.mu.generation": generation}
        if any(labels.get(k) != v for k, v in required.items()) or actual['Image'] != image:
            raise PolicyError("Runtime provenance mismatch")
        if actual['Config']['User'] != user or not host['ReadonlyRootfs'] or host['Privileged']:
            raise PolicyError("Runtime must be non-root, unprivileged and read-only")
        if host.get('CapAdd') or not any(str(v).lower() == 'all' for v in host.get('CapDrop', [])):
            raise PolicyError("Runtime capability restrictions are missing")
        if not any(v.startswith('no-new-privileges') for v in host.get('SecurityOpt', [])):
            raise PolicyError("Runtime privilege escalation protection is missing")
        if any('unconfined' in value for value in host.get('SecurityOpt', [])):
            raise PolicyError("Unconfined runtime security profiles are forbidden")
        if host.get('PidMode') or host.get('IpcMode') != 'private' or host.get('CgroupnsMode') != 'private' or not host.get('Init'):
            raise PolicyError("Runtime process isolation is missing")
        if host.get('PortBindings') or host.get('Devices') or host.get('VolumesFrom'):
            raise PolicyError("Unexpected runtime ports, devices or inherited mounts")
        memory = self.settings.worker_memory if image == self.settings.runtime_image else '128m'
        cpus = self.settings.worker_cpus if image == self.settings.runtime_image else '0.25'
        expected_memory = int(memory[:-1]) * (1024 ** (3 if memory[-1] == 'g' else 2))
        if (host.get('PidsLimit') != 256 or host.get('Memory') != expected_memory or
                host.get('NanoCpus') != int(Decimal(cpus) * 10**9) or host.get('DeviceRequests')):
            raise PolicyError("Runtime resource bounds are missing")

    def mounts_admission(self, actual, expected):
        found = {m['Destination']: (m['Source'], bool(m['RW'])) for m in actual['Mounts']}
        if found != expected or any(m['Type'] != 'bind' for m in actual['Mounts']):
            raise PolicyError("Unexpected runtime mount; refusing admission")

    def admit_relay(self, uid, generation, actual, *, running=True):
        s = self.settings
        self.base_admission(uid, generation, actual, s.relay_image, f'{s.relay_uid}:{s.gateway_uid}', running=running)
        if actual['HostConfig']['NetworkMode'] != 'none':
            raise PolicyError("Relay must have only loopback networking")
        self.mounts_admission(actual, {'/relay': (str(s.runtime_dir(uid) / 'relay'), True),
                                      '/broker': (str(s.runtime_dir(uid) / 'broker'), False)})

    def admit_worker(self, uid, generation, actual, relay, *, running=True):
        s = self.settings
        self.base_admission(uid, generation, actual, s.runtime_image, f'{s.worker_uid}:{s.worker_uid}', running=running)
        if actual['HostConfig']['NetworkMode'] != 'container:' + relay['Id']:
            raise PolicyError("Worker must use only its own relay's loopback namespace")
        expected = {dst: (str(s.user_dir(uid) / src), True) for src, dst in [
            ('hermes', '/state/hermes'), ('workspace', '/workspace'), ('tmp', '/tmp'), ('outputs', '/outputs')]}
        expected['/shared/tools'] = (str(s.runtime_dir(uid) / 'tools'), False)
        self.mounts_admission(actual, expected)

    def reconcile_user(self, user):
        uid = user['id']
        if not user['enabled'] or user['template_id'] is None:
            self.stop(uid)
            self.store.set_runtime(uid, '', 'disabled' if not user['enabled'] else 'unassigned')
            return
        template = self.store.template(user['template_id'])
        self.store.provider(template['document']['provider_id'])
        generation = self.generation(user, template)
        relay_name, worker_name = self.names(uid)
        relay, worker = self.inspect(relay_name), self.inspect(worker_name)
        current = self.store.runtime(uid)
        if relay and worker and current and current['generation'] == generation:
            self.admit_relay(uid, generation, relay)
            self.admit_worker(uid, generation, worker, relay)
        else:
            self.stop(uid)
            self.prepare_directories(uid)
            conflicts = self.seed(uid, template)
            if conflicts:
                self.store.set_runtime(uid, generation, 'template_conflict', error='Private edits preserved: ' + ', '.join(conflicts))
                return
            if not self.settings.broker_socket(uid).is_socket():
                self.store.set_runtime(uid, generation, 'waiting_for_broker')
                return
            self.start(uid, generation)
            relay, worker = self.inspect(relay_name), self.inspect(worker_name)
            self.admit_relay(uid, generation, relay)
            self.admit_worker(uid, generation, worker, relay)
        client = UnixHTTP(self.settings.relay_socket(uid))
        try:
            client.request('GET', '/api/onboarding/status')
            response = client.getresponse()
            body = json.loads(response.read())
            if response.status != 200 or not body.get('system', {}).get('imports_ok'):
                raise PolicyError("Worker did not prove actual Agent imports")
        except (OSError, http.client.HTTPException):
            self.store.set_runtime(uid, generation, 'starting', worker['Id'], relay['Id'])
            return
        finally:
            client.close()
        self.store.set_runtime(uid, generation, 'ready', worker['Id'], relay['Id'])

    def reconcile(self):
        lock = self.settings.root / 'provision.lock'
        with lock.open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PolicyError("Another trusted reconciler is active") from exc
            for user in self.store.users():
                try:
                    self.reconcile_user(user)
                except Exception as exc:
                    # Unknown/tampered runtime state must never remain admitted.
                    self.stop(user['id'])
                    self.store.set_runtime(user['id'], '', 'error', error=type(exc).__name__ + ': runtime refused')

    def watch(self):
        while True:
            self.reconcile()
            time.sleep(1)
