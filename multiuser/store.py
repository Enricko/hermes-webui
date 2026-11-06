"""Private control-plane state. No Agent imports, process environment, or cwd mutation."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

USER_NAME = re.compile(r"[a-z][a-z0-9_.-]{2,47}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")
TOOL_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")
HASHER = PasswordHasher()
# A missing account does the same password work as an existing one.
_DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))


class PolicyError(ValueError):
    """A request is invalid or would violate a control-plane invariant."""


class LoginDenied(PolicyError):
    """Intentionally gives no account existence or password information."""


class RateLimited(LoginDenied):
    """The shared, persistent attempt budget has been consumed."""


def identifier(value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise PolicyError("Invalid identifier")
    return value


def username(value: str) -> str:
    if not isinstance(value, str):
        raise PolicyError("Username must be text")
    value = value.strip().lower()
    if not USER_NAME.fullmatch(value):
        raise PolicyError("Username must contain 3–48 ASCII letters, digits, dots, dashes or underscores")
    return value


def password_hash(value: str) -> str:
    if not isinstance(value, str) or not 12 <= len(value) <= 1024:
        raise PolicyError("Password must contain 12–1024 characters")
    return HASHER.hash(value)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Session:
    token_hash: str
    user_id: str
    username: str
    role: str
    csrf: str
    expires: float
    auth_version: int
    template_id: str | None

    def public(self) -> dict:
        return {"id": self.user_id, "username": self.username, "role": self.role,
                "csrf_token": self.csrf, "expires_at": self.expires,
                "template_id": self.template_id}


class Store:
    def __init__(self, path: Path, *, session_ttl: int = 28800,
                 login_limit: int = 8, login_window: int = 300):
        self.path = Path(path)
        self.session_ttl = session_ttl
        self.login_limit = login_limit
        self.login_window = login_window
        if sqlite3.sqlite_version_info < (3, 51, 3):
            raise PolicyError('The account control plane requires SQLite >=3.51.3 (upstream WAL fix)')
        if not 60 <= session_ttl <= 86400:
            raise PolicyError("Session expiry must be between 60 seconds and one day")

    @contextlib.contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def initialize(self):
        if self.path.is_symlink():
            raise PolicyError("Control database must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise PolicyError("Unsupported control database schema")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS providers (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    base_url TEXT NOT NULL, secret TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS tools (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL, filename TEXT NOT NULL,
                    content TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS templates (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    document TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')),
                    enabled INTEGER NOT NULL DEFAULT 1,
                    auth_version INTEGER NOT NULL DEFAULT 1,
                    template_id TEXT REFERENCES templates(id), created REAL NOT NULL,
                    provider_id TEXT REFERENCES providers(id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    csrf TEXT NOT NULL, expires REAL NOT NULL, auth_version INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS session_user ON sessions(user_id);
                CREATE TABLE IF NOT EXISTS attempts (
                    bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtimes (
                    user_id TEXT PRIMARY KEY REFERENCES users(id),
                    generation TEXT NOT NULL, state TEXT NOT NULL,
                    runtime_id TEXT, relay_id TEXT, error TEXT NOT NULL DEFAULT '', updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, created REAL NOT NULL, actor TEXT,
                    action TEXT NOT NULL, subject TEXT NOT NULL
                );
            """)
            if 'provider_id' not in {row['name'] for row in db.execute('PRAGMA table_info(users)')}:
                db.execute('ALTER TABLE users ADD COLUMN provider_id TEXT REFERENCES providers(id)')
            db.execute('PRAGMA user_version=2')
        self.path.chmod(0o600)

    @staticmethod
    def _event(db, action, subject, actor=None):
        db.execute("INSERT INTO audit(created,actor,action,subject) VALUES(?,?,?,?)",
                   (time.time(), actor, action, subject))

    def create_user(self, name, password, *, role="user", template_id=None, provider_id=None,
                    bootstrap=False, actor=None):
        name = username(name)
        if role not in ("admin", "user"):
            raise PolicyError("Invalid role")
        if template_id is not None:
            identifier(template_id)
        if provider_id is not None:
            identifier(provider_id)
        encoded = password_hash(password)
        uid = uuid.uuid4().hex
        with self.connection(write=True) as db:
            if bootstrap and (role != "admin" or db.execute("SELECT COUNT(*) FROM users").fetchone()[0]):
                raise PolicyError("Bootstrap is allowed only for the first administrator")
            if not bootstrap and not db.execute("SELECT 1 FROM users WHERE enabled=1 AND role='admin'").fetchone():
                raise PolicyError("Bootstrap an administrator first")
            if provider_id is not None and not db.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (provider_id,)).fetchone():
                raise PolicyError('Select an enabled provider')
            try:
                db.execute("INSERT INTO users(id,username,password_hash,role,template_id,created,provider_id) VALUES(?,?,?,?,?,?,?)",
                           (uid, name, encoded, role, template_id, time.time(), provider_id))
            except sqlite3.IntegrityError as exc:
                raise PolicyError("Username or template is invalid/unavailable") from exc
            self._event(db, "user.created", uid, actor)
        return self.user(uid)

    def user(self, uid):
        identifier(uid)
        with self.connection() as db:
            row = db.execute("SELECT id,username,role,enabled,auth_version,template_id,provider_id,created FROM users WHERE id=?", (uid,)).fetchone()
        if row is None:
            raise PolicyError("Account not found")
        return dict(row)

    def users(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT id,username,role,enabled,auth_version,template_id,provider_id,created FROM users ORDER BY username")]

    def update_user(self, uid, *, role=None, enabled=None, password=None,
                    template_id=None, assign_template=False, provider_id=None, assign_provider=False, actor=None):
        identifier(uid)
        if role is not None and role not in ("admin", "user"):
            raise PolicyError("Invalid role")
        if enabled is not None and not isinstance(enabled, bool):
            raise PolicyError("Enabled must be boolean")
        if assign_template and template_id is not None:
            identifier(template_id)
        if assign_provider and provider_id is not None:
            identifier(provider_id)
        encoded = password_hash(password) if password is not None else None
        with self.connection(write=True) as db:
            old = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if old is None:
                raise PolicyError("Account not found")
            new_role = role if role is not None else old["role"]
            new_enabled = int(enabled) if enabled is not None else old["enabled"]
            if old["role"] == "admin" and old["enabled"] and (new_role != "admin" or not new_enabled):
                count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0]
                if count <= 1:
                    raise PolicyError("The last enabled administrator cannot be removed")
            new_template = template_id if assign_template else old["template_id"]
            new_provider = provider_id if assign_provider else old['provider_id']
            if assign_provider and new_provider is not None and not db.execute(
                    'SELECT 1 FROM providers WHERE id=? AND enabled=1', (new_provider,)).fetchone():
                raise PolicyError('Select an enabled provider')
            try:
                db.execute("UPDATE users SET role=?,enabled=?,password_hash=?,template_id=?,provider_id=?,auth_version=auth_version+1 WHERE id=?",
                           (new_role, new_enabled, encoded or old["password_hash"], new_template, new_provider, uid))
            except sqlite3.IntegrityError as exc:
                raise PolicyError("Template not found") from exc
            db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            self._event(db, "user.updated_and_sessions_revoked", uid, actor)
        return self.user(uid)

    def _consume_attempt(self, name, peer, now):
        buckets = ["name:" + token_hash(name), "peer:" + token_hash(peer)]
        with self.connection(write=True) as db:
            db.execute("DELETE FROM attempts WHERE reset<=?", (now,))
            for bucket in buckets:
                row = db.execute("SELECT count,reset FROM attempts WHERE bucket=?", (bucket,)).fetchone()
                # IP budget permits independent users behind one reverse proxy,
                # while account budgets remain independent of forwarded headers.
                limit = self.login_limit * (10 if bucket.startswith("peer:") else 1)
                if row and row["count"] >= limit:
                    raise RateLimited("Too many login attempts; try again later")
            for bucket in buckets:
                db.execute("INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1",
                           (bucket, now + self.login_window))
        return buckets

    def login(self, name, password, peer, *, now=None):
        now = time.time() if now is None else now
        # Invalid names consume a budget too; never echo credentials.
        name = str(name).strip().lower()[:128]
        buckets = self._consume_attempt(name, str(peer)[:128], now)
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
        candidate = row["password_hash"] if row else _DUMMY_HASH
        try:
            verified = isinstance(password, str) and len(password) <= 1024 and HASHER.verify(candidate, password)
        except (VerificationError, InvalidHashError):
            verified = False
        if not verified or row is None or not row["enabled"]:
            raise LoginDenied("Invalid username or password")
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.connection(write=True) as db:
            current = db.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
            if not current["enabled"] or current["auth_version"] != row["auth_version"]:
                raise LoginDenied("Invalid username or password")
            if HASHER.check_needs_rehash(candidate):
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (HASHER.hash(password), row["id"]))
            db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)",
                       (token_hash(token), row["id"], csrf, now + self.session_ttl, row["auth_version"]))
            # Clear only the account bucket; an IP cannot reset its spray budget
            # by occasionally authenticating to an account it controls.
            db.execute("DELETE FROM attempts WHERE bucket=?", (buckets[0],))
            self._event(db, "session.created", row["id"], row["id"])
        return token, self.session(token, now=now)

    def session(self, token, *, now=None):
        if not isinstance(token, str) or len(token) > 128:
            return None
        return self.session_by_hash(token_hash(token), now=now)

    def session_by_hash(self, digest, *, now=None):
        now = time.time() if now is None else now
        with self.connection() as db:
            row = db.execute("""SELECT s.token_hash,s.csrf,s.expires,s.auth_version,u.id,u.username,u.role,u.template_id
                FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?
                AND s.expires>? AND u.enabled=1 AND s.auth_version=u.auth_version""", (digest, now)).fetchone()
        if row is None:
            return None
        return Session(row["token_hash"], row["id"], row["username"], row["role"], row["csrf"],
                       row["expires"], row["auth_version"], row["template_id"])

    def logout(self, session):
        with self.connection(write=True) as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (session.token_hash,))
            self._event(db, "session.revoked", session.user_id, session.user_id)

    def put_provider(self, name, base_url, secret=None, *, provider_id=None, enabled=True):
        from urllib.parse import urlsplit
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyError("Provider requires an explicit HTTP(S) base URL without embedded credentials")
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise PolicyError("Invalid provider name")
        if secret is not None and (not isinstance(secret, str) or len(secret) > 16384):
            raise PolicyError("Provider secret must be text of at most 16 KiB")
        pid = identifier(provider_id) if provider_id else uuid.uuid4().hex
        with self.connection(write=True) as db:
            old = db.execute("SELECT secret FROM providers WHERE id=?", (pid,)).fetchone()
            if secret is None and old is None:
                raise PolicyError("A provider secret must be supplied explicitly (empty is allowed for a private local endpoint)")
            db.execute("""INSERT INTO providers VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,base_url=excluded.base_url,secret=excluded.secret,enabled=excluded.enabled""",
                       (pid, name, base_url.rstrip('/'), old["secret"] if secret is None else secret, int(enabled)))
        return pid

    def providers(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT id,name,base_url,enabled FROM providers ORDER BY name")]

    def provider(self, pid):
        identifier(pid)
        with self.connection() as db:
            row = db.execute("SELECT * FROM providers WHERE id=? AND enabled=1", (pid,)).fetchone()
        if row is None:
            raise PolicyError("Provider is unavailable")
        return dict(row)

    def put_template(self, name, document, *, template_id=None, enabled=True):
        from multiuser.templates import validate_template
        document = validate_template(document)
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise PolicyError("Invalid template name")
        tid = identifier(template_id) if template_id else uuid.uuid4().hex
        with self.connection(write=True) as db:
            if not db.execute("SELECT 1 FROM providers WHERE id=? AND enabled=1", (document["provider_id"],)).fetchone():
                raise PolicyError("Select an enabled provider")
            for tool in document["tools"]:
                if not db.execute("SELECT 1 FROM tools WHERE id=? AND enabled=1", (tool,)).fetchone():
                    raise PolicyError("Selected tool is unavailable")
            db.execute("""INSERT INTO templates(id,name,document,enabled) VALUES(?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,document=excluded.document,
                version=templates.version+1,enabled=excluded.enabled""",
                       (tid, name, json.dumps(document), int(enabled)))
        return tid

    def templates(self):
        with self.connection() as db:
            return [{**dict(r), "document": json.loads(r["document"])} for r in db.execute("SELECT * FROM templates ORDER BY name")]

    def template(self, tid):
        from multiuser.templates import validate_template
        identifier(tid)
        with self.connection() as db:
            row = db.execute("SELECT * FROM templates WHERE id=? AND enabled=1", (tid,)).fetchone()
        if row is None:
            raise PolicyError("Template is unavailable")
        return {**dict(row), "document": validate_template(json.loads(row["document"]))}

    def effective_template(self, user):
        """One shared capability profile, with a server-owned provider per account."""
        template = self.template(user['template_id'])
        if user.get('provider_id') is not None:
            template['document']['provider_id'] = identifier(user['provider_id'])
        self.provider(template['document']['provider_id'])
        return template

    def put_tool(self, name, description, filename, content, *, tool_id=None, enabled=True):
        if not isinstance(name, str) or not 1 <= len(name) <= 80 or not TOOL_NAME.fullmatch(filename):
            raise PolicyError("Invalid tool name or filename")
        if not isinstance(content, str) or not 1 <= len(content.encode()) <= 1024 * 1024:
            raise PolicyError("Tool source must contain 1 byte to 1 MiB of text")
        if not isinstance(description, str) or not 1 <= len(description) <= 4000:
            raise PolicyError("Tool description is required (maximum 4000 characters)")
        tid = identifier(tool_id) if tool_id else uuid.uuid4().hex
        with self.connection(write=True) as db:
            db.execute("""INSERT INTO tools(id,name,description,filename,content,enabled) VALUES(?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,
                filename=excluded.filename,content=excluded.content,version=tools.version+1,enabled=excluded.enabled""",
                       (tid, name, description, filename, content, int(enabled)))
        return tid

    def tools(self, *, source=False):
        fields = '*' if source else 'id,name,description,filename,version,enabled'
        with self.connection() as db:
            return [dict(r) for r in db.execute(f"SELECT {fields} FROM tools ORDER BY name")]

    def tool(self, tid):
        identifier(tid)
        with self.connection() as db:
            row = db.execute("SELECT * FROM tools WHERE id=? AND enabled=1", (tid,)).fetchone()
        if row is None:
            raise PolicyError("Tool is unavailable")
        # Revalidate at the trusted filesystem boundary, even for persisted
        # records. The gateway cannot turn database edits into root paths.
        if (not isinstance(row['filename'], str) or not TOOL_NAME.fullmatch(row['filename']) or
                not isinstance(row['version'], int) or row['version'] < 1 or
                not isinstance(row['content'], str) or not 1 <= len(row['content'].encode()) <= 1024 * 1024):
            raise PolicyError('Published tool record violates filesystem policy')
        return dict(row)

    def set_runtime(self, uid, generation, state, runtime_id=None, relay_id=None, error=""):
        identifier(uid)
        with self.connection(write=True) as db:
            db.execute("""INSERT INTO runtimes VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                generation=excluded.generation,state=excluded.state,runtime_id=excluded.runtime_id,
                relay_id=excluded.relay_id,error=excluded.error,updated=excluded.updated""",
                       (uid, generation, state, runtime_id, relay_id, error[:200], time.time()))

    def runtime(self, uid):
        identifier(uid)
        with self.connection() as db:
            row = db.execute("SELECT * FROM runtimes WHERE user_id=?", (uid,)).fetchone()
        return dict(row) if row else None
