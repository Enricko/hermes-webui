"""Operator-owned deployment settings, never accepted from a browser or Agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from multiuser.store import PolicyError, Store, identifier


@dataclass(frozen=True)
class Settings:
    root: Path
    public_url: str = 'https://hermes.example.com'
    bind_host: str = '127.0.0.1'
    port: int = 8799
    gateway_uid: int = 10000
    worker_uid: int = 10001
    relay_uid: int = 10002
    runtime_image: str = ''
    relay_image: str = ''
    docker_socket: str = '/var/run/docker.sock'
    session_ttl: int = 28800
    worker_memory: str = '2g'
    worker_cpus: str = '1'
    max_upload_bytes: int = 20 * 1024 * 1024

    def validate(self, *, images=False):
        if not self.root.is_absolute() or self.root.resolve() != self.root or self.root in (Path('/'), Path('/tmp'), Path('/srv'), Path('/home'), Path('/root')):
            raise PolicyError("Use a dedicated, absolute, non-symlink data directory")
        if len(os.fsencode(self.root / 'runtimes' / ('a' * 32) / 'broker' / 'provider.sock')) > 103:
            raise PolicyError("Data root is too long for Unix sockets; use e.g. /srv/hermes")
        parsed = urlsplit(self.public_url)
        local = parsed.hostname in ('127.0.0.1', 'localhost', '::1')
        if parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username or parsed.password or not parsed.hostname:
            raise PolicyError("Public URL must be an origin, without credentials or path")
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and local and self.bind_host in ('127.0.0.1', '::1')):
            raise PolicyError("HTTPS is required, except for a loopback-only local trial")
        if self.bind_host not in ('127.0.0.1', '::1'):
            raise PolicyError("Bind to loopback and use an explicitly configured TLS reverse proxy")
        if not 1 <= self.port <= 65535 or not 60 <= self.session_ttl <= 86400:
            raise PolicyError("Invalid port or session expiry")
        ids = [self.gateway_uid, self.worker_uid, self.relay_uid]
        if any(not isinstance(uid, int) or uid <= 0 for uid in ids) or len(set(ids)) != 3:
            raise PolicyError("Gateway, worker and relay require distinct non-root UIDs")
        if self.docker_socket != '/var/run/docker.sock':
            raise PolicyError("Provisioning uses only the explicit local Docker socket")
        if not re.fullmatch(r'[1-9][0-9]*(?:[mg])', self.worker_memory) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', self.worker_cpus) or not 0.1 <= float(self.worker_cpus) <= 32:
            raise PolicyError("Invalid runtime resource limits")
        if not 1024 <= self.max_upload_bytes <= 100 * 1024 * 1024:
            raise PolicyError("Upload limit must be between 1 KiB and 100 MiB")
        if images and any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in (self.runtime_image, self.relay_image)):
            raise PolicyError("Resolve both runtime images to immutable sha256 image IDs before provisioning")
        return self

    @property
    def origin(self):
        return self.public_url.rstrip('/')

    @property
    def secure(self):
        return urlsplit(self.public_url).scheme == 'https'

    @property
    def database(self):
        return self.root / 'control' / 'accounts.sqlite'

    def store(self):
        return Store(self.database, session_ttl=self.session_ttl)

    def runtime_dir(self, uid):
        return self.root / 'runtimes' / identifier(uid)

    def user_dir(self, uid):
        return self.root / 'users' / identifier(uid)

    def relay_socket(self, uid):
        return self.runtime_dir(uid) / 'relay' / 'webui.sock'

    def broker_socket(self, uid):
        return self.runtime_dir(uid) / 'broker' / 'provider.sock'

    @classmethod
    def load(cls, root):
        root = Path(root).absolute()
        path = root / 'settings.json'
        if path.is_symlink() or not path.is_file():
            raise PolicyError("Initialize an explicit multi-user installation first")
        value = json.loads(path.read_text())
        if value.pop('root', None) != str(root):
            raise PolicyError("Data root does not match its installation settings")
        return cls(root=root, **value).validate()

    def save(self):
        self.validate()
        value = asdict(self)
        value['root'] = str(self.root)
        target = self.root / 'settings.json'
        if target.is_symlink():
            raise PolicyError("Settings must not be a symlink")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = target.with_suffix('.json.tmp')
        temp.write_text(json.dumps(value, indent=2) + '\n')
        temp.chmod(0o640)
        os.replace(temp, target)
