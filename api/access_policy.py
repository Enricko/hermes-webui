"""Transactional authority for multi-user grants and private object ownership.

No agent imports, credentials, environment mutation or worker execution belong
here. Callers must supply authenticated immutable account IDs. Runtime admission
is deliberately separate from policy authorization: a grant never proves that
an execution boundary is contained.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import re
import secrets
import sqlite3
from pathlib import Path


class AccessDenied(PermissionError):
    """Unknown, disabled, revoked or mismatched authority."""


class PolicyUnavailable(RuntimeError):
    """A configured policy database cannot be read or validated."""


_ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
_KINDS = {"profile", "workspace", "connection", "skill"}


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid immutable identifier")
    return value


@dataclass(frozen=True)
class AccessContext:
    account_id: str
    profile_id: str
    workspace_id: str
    connection_id: str
    model: str
    skills: tuple[str, ...] = ()


@dataclass(frozen=True)
class Admission:
    context: AccessContext
    revision: int
    profile_instance_id: str
    connection_generation: int


class PolicyStore:
    """One SQLite authority; account/grant mutation and revocation are atomic.

    Opening a missing database never creates an empty permissive policy. Only
    ``initialize`` creates the schema; operators retain the database on removal
    of the last account. All reads reload live policy rather than cache grants.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()

    @classmethod
    def initialize(cls, path: str | Path, admin_id: str) -> PolicyStore:
        admin_id = _id(admin_id)
        store = cls(path)
        store.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Refuse replacing an existing authority, including a broken database.
        with store.path.open("xb"):
            pass
        store.path.chmod(0o600)
        with sqlite3.connect(store.path) as db:
            db.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    schema_version INTEGER NOT NULL, revision INTEGER NOT NULL);
                INSERT INTO metadata VALUES (1,1,1);
                CREATE TABLE accounts (id TEXT PRIMARY KEY, role TEXT NOT NULL
                    CHECK(role IN ('admin','user')), enabled INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE resources (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    label TEXT NOT NULL, binding TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE grants (account_id TEXT NOT NULL REFERENCES accounts(id),
                    resource_id TEXT NOT NULL REFERENCES resources(id), models TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY(account_id,resource_id));
                CREATE TABLE instances (account_id TEXT NOT NULL REFERENCES accounts(id),
                    profile_id TEXT NOT NULL REFERENCES resources(id), id TEXT UNIQUE NOT NULL,
                    PRIMARY KEY(account_id,profile_id));
                CREATE TABLE objects (kind TEXT NOT NULL, id TEXT NOT NULL,
                    owner TEXT NOT NULL REFERENCES accounts(id), profile_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL, PRIMARY KEY(kind,id));
            """)
            db.execute("INSERT INTO accounts(id,role) VALUES (?, 'admin')", (admin_id,))
        return store

    @contextmanager
    def _transaction(self, *, write=False):
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            version = db.execute("SELECT schema_version FROM metadata WHERE singleton=1").fetchone()
            if version is None or version[0] != 1:
                raise PolicyUnavailable("Unsupported policy schema")
            yield db
            db.commit()
        except sqlite3.Error as exc:
            raise PolicyUnavailable("Policy authority unavailable") from exc
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _account(db, account_id, *, admin=False):
        row = db.execute("SELECT * FROM accounts WHERE id=?", (_id(account_id),)).fetchone()
        if row is None or not row["enabled"] or (admin and row["role"] != "admin"):
            raise AccessDenied("Account is unavailable or lacks administrator authority")
        return row

    @staticmethod
    def _bump(db):
        db.execute("UPDATE metadata SET revision=revision+1 WHERE singleton=1")

    def put_account(self, actor: str, account_id: str, *, role="user", enabled=True):
        if role not in {"admin", "user"} or not isinstance(enabled, bool):
            raise ValueError("Invalid account role or status")
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            db.execute("INSERT INTO accounts VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "role=excluded.role, enabled=excluded.enabled", (_id(account_id), role, int(enabled)))
            if not db.execute("SELECT 1 FROM accounts WHERE role='admin' AND enabled=1").fetchone():
                raise AccessDenied("Cannot remove the last enabled administrator")
            self._bump(db)

    def put_resource(self, actor: str, resource_id: str, *, kind: str, label: str, binding: dict):
        """Register trusted metadata, never a worker-supplied endpoint or path.

        Binding changes advance generation; refreshing credentials elsewhere
        leaves this account/endpoint identity unchanged. Resource kind is fixed.
        """
        if kind not in _KINDS or not isinstance(binding, dict) or not isinstance(label, str):
            raise ValueError("Invalid resource")
        forbidden = {"password", "api_key", "access_token", "refresh_token", "secret"}
        def contains_secret(value):
            if isinstance(value, dict):
                return any(str(k).lower() in forbidden or contains_secret(v) for k, v in value.items())
            return isinstance(value, list) and any(contains_secret(v) for v in value)
        if contains_secret(binding):
            raise ValueError("Store credentials in the trusted broker, not policy metadata")
        encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            old = db.execute("SELECT * FROM resources WHERE id=?", (_id(resource_id),)).fetchone()
            if old and old["kind"] != kind:
                raise AccessDenied("Resource identity cannot change kind")
            generation = 1 if old is None else old["generation"] + int(old["binding"] != encoded)
            db.execute("INSERT INTO resources VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "label=excluded.label,binding=excluded.binding,generation=excluded.generation",
                       (resource_id, kind, label, encoded, generation))
            self._bump(db)

    def replace_grants(self, actor: str, account_id: str, grants: dict[str, list[str]]):
        """Explicit grants only. A future resource is never implicitly admitted.

        Connections require nonempty model allowlists. Profile instances are
        private per account even if their template is shared, and survive a
        revoke/regrant without being reassigned to another account.
        """
        if not isinstance(grants, dict):
            raise ValueError("Grants must be an object")
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            self._account(db, account_id)
            db.execute("DELETE FROM grants WHERE account_id=?", (account_id,))
            for resource_id, models in grants.items():
                resource = db.execute("SELECT kind FROM resources WHERE id=?", (_id(resource_id),)).fetchone()
                if resource is None:
                    raise AccessDenied("Unknown resource")
                if not isinstance(models, list) or any(not isinstance(m, str) or not m.strip() for m in models):
                    raise ValueError("Models must be explicit nonempty strings")
                if resource[0] == "connection" and not models:
                    raise ValueError("Connection grant requires allowed models")
                if resource[0] != "connection" and models:
                    raise ValueError("Only connections have model grants")
                db.execute("INSERT INTO grants VALUES (?,?,?)",
                           (account_id, resource_id, json.dumps(sorted(set(models)))))
                if resource[0] == "profile":
                    db.execute("INSERT OR IGNORE INTO instances VALUES (?,?,?)",
                               (account_id, resource_id, secrets.token_hex(16)))
            self._bump(db)

    def _authorize(self, db, context):
        self._account(db, context.account_id)
        generation = None
        selections = [("profile", context.profile_id), ("workspace", context.workspace_id),
                      ("connection", context.connection_id)] + [("skill", s) for s in context.skills]
        for kind, resource_id in selections:
            row = db.execute("SELECT r.kind,r.generation,g.models FROM resources r JOIN grants g "
                             "ON r.id=g.resource_id WHERE g.account_id=? AND r.id=?",
                             (context.account_id, _id(resource_id))).fetchone()
            if row is None or row["kind"] != kind:
                raise AccessDenied("Selection is not granted to this account")
            if kind == "connection":
                if context.model not in json.loads(row["models"]):
                    raise AccessDenied("Model is not granted on this connection")
                generation = row["generation"]
        instance = db.execute("SELECT id FROM instances WHERE account_id=? AND profile_id=?",
                              (context.account_id, context.profile_id)).fetchone()
        if instance is None:
            raise AccessDenied("Private profile instance unavailable")
        revision = db.execute("SELECT revision FROM metadata WHERE singleton=1").fetchone()[0]
        return Admission(context, revision, instance[0], generation)

    def authorize(self, context: AccessContext) -> Admission:
        with self._transaction() as db:
            return self._authorize(db, context)

    def revalidate(self, admission: Admission) -> Admission:
        current = self.authorize(admission.context)
        if current.revision != admission.revision or current.connection_generation != admission.connection_generation:
            raise AccessDenied("Access policy or connection account binding changed")
        return current

    def register_object(self, context: AccessContext, *, kind: str, object_id: str):
        with self._transaction(write=True) as db:
            self._authorize(db, context)
            existing = db.execute("SELECT * FROM objects WHERE kind=? AND id=?",
                                  (_id(kind), _id(object_id))).fetchone()
            identity = (context.account_id, context.profile_id, context.workspace_id)
            if existing:
                if (existing["owner"], existing["profile_id"], existing["workspace_id"]) != identity:
                    raise AccessDenied("Private object identity already belongs to another context")
                return
            db.execute("INSERT INTO objects VALUES (?,?,?,?,?)", (kind, object_id, *identity))

    def authorize_object(self, context: AccessContext, *, kind: str, object_id: str):
        with self._transaction() as db:
            self._authorize(db, context)
            row = db.execute("SELECT * FROM objects WHERE kind=? AND id=?", (_id(kind), _id(object_id))).fetchone()
            if row is None or (row["owner"], row["profile_id"], row["workspace_id"]) != (
                context.account_id, context.profile_id, context.workspace_id
            ):
                raise AccessDenied("Private object is unavailable")

    def snapshot(self, actor: str) -> dict:
        """Administrator view contains policy metadata and no credentials."""
        with self._transaction() as db:
            self._account(db, actor, admin=True)
            return {"revision": db.execute("SELECT revision FROM metadata").fetchone()[0],
                    **{table: [dict(row) for row in db.execute(f"SELECT * FROM {table}")]
                       for table in ("accounts", "resources", "grants", "instances")}}

    def account_snapshot(self, account_id: str) -> dict:
        """Member catalog exposes only granted IDs/labels, never trusted bindings."""
        with self._transaction() as db:
            self._account(db, account_id)
            rows = db.execute("SELECT r.id,r.kind,r.label,g.models FROM resources r JOIN grants g "
                              "ON r.id=g.resource_id WHERE g.account_id=? ORDER BY r.kind,r.id", (account_id,))
            return {"account_id": account_id, "runtime_ready": False,
                    "resources": [{**dict(row), "models": json.loads(row["models"])} for row in rows]}
