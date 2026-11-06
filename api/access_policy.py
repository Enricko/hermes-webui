"""Transactional authority for multi-user grants and private object ownership.

No agent imports, credentials, environment mutation or worker execution belong
here. Callers must supply authenticated immutable account IDs. Runtime admission
is deliberately separate from policy authorization: a grant never proves that
an execution boundary is contained.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from pathlib import Path


class AccessDenied(PermissionError):
    """Unknown, disabled, revoked or mismatched authority."""


class PolicyUnavailable(RuntimeError):
    """A configured policy database cannot be read or validated."""


_ID = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
_KINDS = {"profile", "workspace", "connection", "skill", "tool"}
_MAX_REFERENCES = 512
# Read-only folder references between accounts. Optional relation: databases
# created before it existed still open; absence of the table means no grants.
_REFERENCE_TABLE = ("CREATE TABLE IF NOT EXISTS reference_grants ("
                    "account_id TEXT NOT NULL REFERENCES accounts(id), "
                    "target_id TEXT NOT NULL REFERENCES accounts(id), "
                    "PRIMARY KEY(account_id,target_id), CHECK(account_id <> target_id))")
# Shared profile content: a profile grant carries that profile's skills and
# SOUL. Digests live in the resource binding; the SOUL text lives only in this
# private relation, never in a binding, snapshot or member response. Optional
# relation like reference_grants: absence means no SOUL has been recorded.
_PROFILE_SOUL_TABLE = ("CREATE TABLE IF NOT EXISTS profile_souls ("
                       "profile_id TEXT PRIMARY KEY REFERENCES resources(id), "
                       "sha256 TEXT NOT NULL, size INTEGER NOT NULL, text TEXT NOT NULL)")
_SKILL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Never opened, hashed or recorded below skills/. Hidden names (.env, .git,
# .ssh, ...) are skipped separately; the profile home itself is never listed.
_SECRET_FILE = re.compile(r"(?i)^(auth\.json|.*credentials?(\..*)?|.*\.(key|pem|p12|pfx|kdbx)"
                          r"|id_(rsa|dsa|ecdsa|ed25519)(\..*)?)$")
_MAX_SOUL_BYTES = 256 * 1024
_MAX_SKILLS = 512
_MAX_SKILL_TREE_FILES = 10_000
_MAX_SKILL_TREE_BYTES = 64 * 1024 * 1024
_MAX_SKILL_DEPTH = 8


def _id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid immutable identifier")
    return value


def _open_at(name: str, dir_fd: int, *, directory=False) -> int | None:
    """Open one entry of ``dir_fd`` without following a symlink at any step.

    Returns None for symlinks, missing entries and the wrong file type so an
    entry swapped during a scan is skipped rather than followed.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        mode = 0
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        os.close(fd)
        return None
    return fd


def _frontmatter_name(head: bytes) -> str | None:
    text = head.decode("utf-8", "replace")
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    for line in (text[3:end] if end != -1 else "").splitlines():
        if line.startswith("name:"):
            return line[5:].strip().strip("'\"") or None
    return None


def _scan_skills(home_fd: int) -> list[dict]:
    """Name, relative path and content digest of each skill below ``skills/``.

    A skill is a directory holding a regular ``SKILL.md``; its name is the
    frontmatter ``name`` or the directory name. Symlinks, hidden entries and
    secret-looking files are never opened. First name in path order wins.
    """
    root = _open_at("skills", home_fd, directory=True)
    if root is None:
        return []
    files: list[tuple[str, int, str, bytes]] = []
    total = 0

    def walk(dir_fd, prefix, depth):
        nonlocal total
        with os.scandir(dir_fd) as entries:
            listed = sorted((e.name, e.is_dir(follow_symlinks=False), e.is_file(follow_symlinks=False))
                            for e in entries if not e.is_symlink())
        for name, is_dir, is_file in listed:
            if name.startswith(".") or _SECRET_FILE.fullmatch(name):
                continue
            rel = f"{prefix}{name}"
            if is_dir and depth < _MAX_SKILL_DEPTH:
                child = _open_at(name, dir_fd, directory=True)
                if child is not None:
                    try:
                        walk(child, rel + "/", depth + 1)
                    finally:
                        os.close(child)
            elif is_file:
                fd = _open_at(name, dir_fd)
                if fd is None:
                    continue
                digest, size, head = hashlib.sha256(), 0, b""
                with os.fdopen(fd, "rb") as handle:
                    while chunk := handle.read(65536):
                        if name == "SKILL.md" and len(head) < 4096:
                            head += chunk[:4096 - len(head)]
                        size += len(chunk)
                        total += len(chunk)
                        if total > _MAX_SKILL_TREE_BYTES:
                            raise ValueError("Profile skills tree is too large to import")
                        digest.update(chunk)
                files.append((rel, size, digest.hexdigest(), head))
                if len(files) > _MAX_SKILL_TREE_FILES:
                    raise ValueError("Profile skills tree has too many files to import")

    try:
        walk(root, "", 0)
    finally:
        os.close(root)
    files.sort()
    skills, seen = [], set()
    for rel, _size, _digest, head in files:
        directory, _, base = rel.rpartition("/")
        if base != "SKILL.md" or not directory:
            continue
        name = _frontmatter_name(head)
        if not (name and _SKILL_NAME.fullmatch(name)):
            name = directory.rpartition("/")[2]
        if not _SKILL_NAME.fullmatch(name) or name in seen:
            continue
        seen.add(name)
        digest = hashlib.sha256()
        for member, size, file_digest, _head in files:
            if member.startswith(directory + "/"):
                digest.update(f"{member[len(directory) + 1:]}\0{size}\0{file_digest}\n"
                              .encode("utf-8", "surrogateescape"))
        skills.append({"name": name, "path": directory, "sha256": digest.hexdigest()})
    if len(skills) > _MAX_SKILLS:
        raise ValueError("Profile has too many skills to import")
    return sorted(skills, key=lambda skill: skill["name"])


def _read_soul(home_fd: int) -> dict | None:
    fd = _open_at("SOUL.md", home_fd)
    if fd is None:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(_MAX_SOUL_BYTES + 1)
    if len(data) > _MAX_SOUL_BYTES:
        raise ValueError("SOUL.md is too large to import")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("SOUL.md must be UTF-8") from None
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "text": text}


def _scan_profile(home: Path) -> dict:
    """Read only ``home/SOUL.md`` and the ``home/skills`` tree.

    The home directory is never listed, so ``.env``, ``auth.json``, memories
    and sessions beside them are neither read nor discovered.
    """
    try:
        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return {"skills": [], "soul": None}
    try:
        return {"skills": _scan_skills(home_fd), "soul": _read_soul(home_fd)}
    finally:
        os.close(home_fd)


def _profile_manifest(binding: dict) -> tuple[list[dict], dict | None]:
    """Validated skills and SOUL digest of an imported Hermes profile binding."""
    if binding.get("source") != "hermes-profile":
        return [], None
    raw = binding.get("skills")
    skills = [skill for skill in (raw if isinstance(raw, list) else [])
              if isinstance(skill, dict) and isinstance(skill.get("name"), str)
              and _SKILL_NAME.fullmatch(skill["name"]) and isinstance(skill.get("sha256"), str)
              and _SHA256.fullmatch(skill["sha256"])]
    soul = binding.get("soul")
    if not (isinstance(soul, dict) and isinstance(soul.get("sha256"), str) and _SHA256.fullmatch(soul["sha256"])
            and isinstance(soul.get("bytes"), int) and not isinstance(soul["bytes"], bool)):
        soul = None
    return skills, soul


def _merged_skills(profile_skills: list[dict], extras: list[tuple[str, str]]) -> list[dict]:
    """Profile skills plus explicitly granted skill resources, unique by name.

    A profile skill wins over an explicit resource with the same name.
    """
    merged = {skill["name"]: {"name": skill["name"], "source": "profile", "sha256": skill["sha256"],
                              "path": skill.get("path")} for skill in profile_skills}
    for resource_id, label in extras:
        merged.setdefault(label, {"name": label, "source": "skill", "resource_id": resource_id})
    return [merged[name] for name in sorted(merged)]


def _login_usernames() -> dict[str, str]:
    """Immutable ID -> enabled login name, for display only (never authority)."""
    from api.user_roles import load_users
    return {record["id"]: name for name, record in load_users().items()
            if isinstance(record, dict) and record.get("id")}


@dataclass(frozen=True)
class AccessContext:
    account_id: str
    profile_id: str
    workspace_id: str
    connection_id: str
    model: str
    skills: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class Admission:
    context: AccessContext
    revision: int
    profile_instance_id: str
    connection_generation: int


@dataclass(frozen=True)
class ProfileSoul:
    """Trusted SOUL for a worker; the text is kept out of repr and logs."""
    profile_id: str
    sha256: str
    size: int
    revision: int
    text: str = field(repr=False)


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
            db.execute(_REFERENCE_TABLE)
            db.execute(_PROFILE_SOUL_TABLE)
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

    @staticmethod
    def _has_table(db, name):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

    @staticmethod
    def _has_reference_table(db):
        return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reference_grants'").fetchone() is not None

    def _reference_targets(self, db, account_id):
        """Granted targets that are still enabled. Live read, never cached."""
        if not self._has_reference_table(db):
            return []
        return [row[0] for row in db.execute(
            "SELECT r.target_id FROM reference_grants r JOIN accounts a ON a.id=r.target_id "
            "WHERE r.account_id=? AND a.enabled=1 AND r.target_id<>r.account_id ORDER BY r.target_id",
            (account_id,))]

    @staticmethod
    def _replace_references(db, account_id, targets):
        if not isinstance(targets, list) or len(targets) > _MAX_REFERENCES:
            raise ValueError("References must be a list of account IDs")
        targets = {_id(target) for target in targets}
        if account_id in targets:
            raise ValueError("An account cannot reference its own folder")
        db.execute(_REFERENCE_TABLE)
        db.execute("DELETE FROM reference_grants WHERE account_id=?", (account_id,))
        for target in sorted(targets):
            row = db.execute("SELECT enabled FROM accounts WHERE id=?", (target,)).fetchone()
            if row is None or not row["enabled"]:
                raise AccessDenied("Reference account is unknown or disabled")
            db.execute("INSERT INTO reference_grants VALUES (?,?)", (account_id, target))

    def _granted_profile(self, db, account_id, profile_id):
        """Live profile grant, as ``_authorize`` requires it: granted, still
        available and holding this account's private instance."""
        self._account(db, account_id)
        row = db.execute("SELECT r.binding FROM resources r JOIN grants g ON r.id=g.resource_id "
                         "JOIN instances i ON i.account_id=g.account_id AND i.profile_id=r.id "
                         "WHERE g.account_id=? AND r.id=? AND r.kind='profile'",
                         (account_id, _id(profile_id))).fetchone()
        if row is None:
            raise AccessDenied("Profile is not granted to this account")
        binding = json.loads(row["binding"])
        if binding.get("available") is False:
            raise AccessDenied("Resource is no longer available")
        return binding

    @staticmethod
    def _granted_extra_skills(db, account_id):
        """Explicit ``skill`` grants as (resource ID, name = label)."""
        return [(row["id"], row["label"]) for row in db.execute(
            "SELECT r.id,r.label,r.binding FROM resources r JOIN grants g ON r.id=g.resource_id "
            "WHERE g.account_id=? AND r.kind='skill' ORDER BY r.id", (account_id,))
            if json.loads(row["binding"]).get("available") is not False]

    def _profile_summaries(self, db, account_id):
        """Member-safe view: skill names and SOUL digest/size, no text or paths."""
        extras = self._granted_extra_skills(db, account_id)
        summaries = []
        for row in db.execute("SELECT r.id,r.label,r.binding FROM resources r JOIN grants g ON r.id=g.resource_id "
                              "JOIN instances i ON i.account_id=g.account_id AND i.profile_id=r.id "
                              "WHERE g.account_id=? AND r.kind='profile' ORDER BY r.id", (account_id,)):
            binding = json.loads(row["binding"])
            if binding.get("available") is False:
                continue
            skills, soul = _profile_manifest(binding)
            summaries.append({"id": row["id"], "label": row["label"],
                              "skills": [skill["name"] for skill in _merged_skills(skills, extras)],
                              "soul": None if soul is None else {"sha256": soul["sha256"], "bytes": soul["bytes"]}})
        return summaries

    @staticmethod
    def _private_workspace_ids(db):
        return [row['id'] for row in db.execute("SELECT id,binding FROM resources WHERE kind='workspace'")
                if (binding := json.loads(row['binding'])).get('scope') == 'login-username'
                and binding.get('available') is not False]

    def put_account(self, actor: str, account_id: str, *, role="user", enabled=True):
        if role not in {"admin", "user"} or not isinstance(enabled, bool):
            raise ValueError("Invalid account role or status")
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            db.execute("INSERT INTO accounts VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "role=excluded.role, enabled=excluded.enabled", (_id(account_id), role, int(enabled)))
            if not db.execute("SELECT 1 FROM accounts WHERE role='admin' AND enabled=1").fetchone():
                raise AccessDenied("Cannot remove the last enabled administrator")
            if enabled:
                for workspace in self._private_workspace_ids(db):
                    db.execute("INSERT OR IGNORE INTO grants VALUES (?,?,'[]')",(account_id,workspace))
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

    def replace_grants(self, actor: str, account_id: str, grants: dict[str, list[str]],
                       references: list[str] | None = None):
        """Explicit grants only. A future resource is never implicitly admitted.

        Connections require nonempty model allowlists. Profile instances are
        private per account even if their template is shared, and survive a
        revoke/regrant without being reassigned to another account.
        ``references`` (optional) replaces read-only folder references in the
        same transaction; ``None`` leaves them unchanged.
        """
        if not isinstance(grants, dict):
            raise ValueError("Grants must be an object")
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            self._account(db, account_id)
            grants = dict(grants)
            for workspace in self._private_workspace_ids(db):
                grants[workspace] = []
            db.execute("DELETE FROM grants WHERE account_id=?", (account_id,))
            for resource_id, models in grants.items():
                resource = db.execute("SELECT kind,binding FROM resources WHERE id=?", (_id(resource_id),)).fetchone()
                if resource is None:
                    raise AccessDenied("Unknown resource")
                if json.loads(resource['binding']).get('available') is False:
                    raise AccessDenied("Resource is no longer available")
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
            if references is not None:
                self._replace_references(db, account_id, references)
            self._bump(db)

    def replace_references(self, actor: str, account_id: str, targets: list[str]):
        """Administrator grants ``account_id`` read-only access to each target's
        private folder. Nothing else of a target (conversations, grants,
        credentials) becomes visible. Self, unknown and disabled targets are
        refused; every change advances the policy revision.
        """
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            self._account(db, account_id)
            self._replace_references(db, account_id, targets)
            self._bump(db)

    def reference_targets(self, account_id: str) -> list[str]:
        """Live list of target account IDs this account may read, read only."""
        with self._transaction() as db:
            self._account(db, account_id)
            return self._reference_targets(db, account_id)

    def authorize_reference(self, account_id: str, target_id: str) -> int:
        """Return the current revision if the live policy grants the reference.

        Unknown, malformed, disabled and ungranted targets all raise the same
        AccessDenied so callers cannot probe which accounts exist.
        """
        with self._transaction() as db:
            self._account(db, account_id)
            if (not isinstance(target_id, str) or not _ID.fullmatch(target_id)
                    or target_id not in self._reference_targets(db, account_id)):
                raise AccessDenied("Reference folder is not granted to this account")
            return db.execute("SELECT revision FROM metadata WHERE singleton=1").fetchone()[0]

    def _authorize(self, db, context):
        self._account(db, context.account_id)
        generation = None
        selections = [("profile", context.profile_id), ("workspace", context.workspace_id),
                      ("connection", context.connection_id)] + [("skill", s) for s in context.skills] + [("tool", t) for t in context.tools]
        for kind, resource_id in selections:
            row = db.execute("SELECT r.kind,r.generation,r.binding,g.models FROM resources r JOIN grants g "
                             "ON r.id=g.resource_id WHERE g.account_id=? AND r.id=?",
                             (context.account_id, _id(resource_id))).fetchone()
            if row is None or row["kind"] != kind:
                raise AccessDenied("Selection is not granted to this account")
            if json.loads(row['binding']).get('available') is False:
                raise AccessDenied("Resource is no longer available")
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
            references = ([dict(row) for row in db.execute(
                "SELECT account_id,target_id FROM reference_grants ORDER BY account_id,target_id")]
                if self._has_reference_table(db) else [])
            return {"revision": db.execute("SELECT revision FROM metadata").fetchone()[0],
                    **{table: [dict(row) for row in db.execute(f"SELECT * FROM {table}")]
                       for table in ("accounts", "resources", "grants", "instances")},
                    "references": references}

    def account_snapshot(self, account_id: str) -> dict:
        """Member catalog exposes only granted IDs/labels, never trusted bindings.

        Reference targets carry only ID and login name; a target without an
        enabled login is omitted (both authorities must agree). ``profiles``
        lists each granted, available profile with its effective skill names
        and SOUL digest/size; SOUL text and host paths are never included.
        """
        with self._transaction() as db:
            self._account(db, account_id)
            rows = db.execute("SELECT r.id,r.kind,r.label,g.models FROM resources r JOIN grants g "
                              "ON r.id=g.resource_id WHERE g.account_id=? ORDER BY r.kind,r.id", (account_id,))
            resources = [{**dict(row), "models": json.loads(row["models"])} for row in rows]
            targets = self._reference_targets(db, account_id)
            profiles = self._profile_summaries(db, account_id)
        names = _login_usernames() if targets else {}
        return {"account_id": account_id, "runtime_ready": False, "resources": resources,
                "references": [{"id": target, "username": names[target]} for target in targets if target in names],
                "profiles": profiles}

    def effective_skills(self, account_id: str, profile_id: str) -> list[dict]:
        """Trusted call sites only: skills an account gets with a granted profile.

        The profile's own skills (name, relative ``path`` under its skills
        directory, ``sha256``) merged with explicitly granted ``skill``
        resources (name, ``resource_id``), unique by name. Re-checks the live
        grant on every call; a revoked or removed profile raises AccessDenied.
        """
        with self._transaction() as db:
            binding = self._granted_profile(db, account_id, profile_id)
            return _merged_skills(_profile_manifest(binding)[0], self._granted_extra_skills(db, account_id))

    def effective_soul(self, account_id: str, profile_id: str) -> ProfileSoul | None:
        """Trusted call sites only: SOUL text of a granted profile, or None.

        Re-checks the live grant on every call. The stored text must match the
        digest recorded at import, otherwise the policy fails closed.
        """
        with self._transaction() as db:
            soul = _profile_manifest(self._granted_profile(db, account_id, profile_id))[1]
            if soul is None:
                return None
            row = (db.execute("SELECT sha256,size,text FROM profile_souls WHERE profile_id=?",
                              (profile_id,)).fetchone()
                   if self._has_table(db, "profile_souls") else None)
            if (row is None or row["sha256"] != soul["sha256"] or row["size"] != soul["bytes"]
                    or hashlib.sha256(row["text"].encode("utf-8")).hexdigest() != soul["sha256"]):
                raise PolicyUnavailable("Profile SOUL record is inconsistent")
            revision = db.execute("SELECT revision FROM metadata WHERE singleton=1").fetchone()[0]
            return ProfileSoul(profile_id, soul["sha256"], soul["bytes"], revision, row["text"])

    def context_resources(self, context: AccessContext) -> tuple[Admission, dict]:
        """Trusted call-site data only; never serialize these bindings to a member."""
        with self._transaction() as db:
            admission = self._authorize(db, context)
            ids = (context.profile_id, context.workspace_id, context.connection_id, *context.skills, *context.tools)
            return admission, {resource_id: json.loads(db.execute(
                "SELECT binding FROM resources WHERE id=?", (resource_id,)).fetchone()[0]) for resource_id in ids}

    def import_profiles(self, actor: str, names: list[str], homes: dict[str, str | Path] | None = None) -> list[dict]:
        """Register real Hermes templates with persistent IDs and no credentials.

        Import never clones homes or grants access. Removed templates become
        unavailable while their instance/ownership records remain intact, and
        lose their recorded skills/SOUL. ``homes`` maps a name to its absolute
        Hermes home and must come from the trusted server, never a request.
        Only that home's ``SOUL.md`` and ``skills/`` tree are read: skill
        names/digests and the SOUL digest/size go into the binding, the SOUL
        text into the private ``profile_souls`` relation. A name without a
        home records none. Changed content advances the resource generation
        and the policy revision, invalidating earlier admissions.
        """
        from api.user_roles import _PROFILE_RE
        if not isinstance(names, list) or any(not isinstance(name, str) or not _PROFILE_RE.fullmatch(name) for name in names):
            raise ValueError('Invalid Hermes profile names')
        homes = {} if homes is None else homes
        if not isinstance(homes, dict) or any(
                name not in names or not isinstance(home, (str, Path)) or not Path(home).is_absolute()
                for name, home in homes.items()):
            raise ValueError('Invalid Hermes profile homes')
        with self._transaction() as db:
            # Authority first: a non-administrator triggers no filesystem read.
            self._account(db, actor, admin=True)
        # Scan outside the write transaction; nothing is stored if a scan fails.
        contents = {name: _scan_profile(Path(home)) for name, home in sorted(homes.items())}
        with self._transaction(write=True) as db:
            self._account(db, actor, admin=True)
            db.execute(_PROFILE_SOUL_TABLE)
            known = {}
            for row in db.execute("SELECT * FROM resources WHERE kind='profile'"):
                binding = json.loads(row['binding'])
                if binding.get('source') == 'hermes-profile':
                    known[binding['profile_name']] = row
            changed = False
            result = []
            for name in sorted(set(names) | set(known)):
                available = name in names
                old = known.get(name)
                content = contents.get(name) if available else None
                soul = content['soul'] if content else None
                binding = json.dumps({'source':'hermes-profile','profile_name':name,'available':available,
                                      'skills':content['skills'] if content else [],
                                      'soul':{'sha256':soul['sha256'],'bytes':soul['bytes']} if soul else None},
                                     sort_keys=True,separators=(',',':'))
                identifier = old['id'] if old else 'profile-' + secrets.token_hex(16)
                if old is None:
                    db.execute("INSERT INTO resources VALUES (?,?,?,?,1)",(identifier,'profile',name,binding))
                    changed = True
                elif old['binding'] != binding:
                    db.execute("UPDATE resources SET binding=?,generation=generation+1 WHERE id=?",(binding,identifier))
                    changed = True
                if soul:
                    db.execute("INSERT INTO profile_souls VALUES (?,?,?,?) ON CONFLICT(profile_id) DO UPDATE SET "
                               "sha256=excluded.sha256,size=excluded.size,text=excluded.text",
                               (identifier, soul['sha256'], soul['bytes'], soul['text']))
                else:
                    db.execute("DELETE FROM profile_souls WHERE profile_id=?", (identifier,))
                if available:
                    result.append({'id':identifier,'name':name})
            if changed:
                self._bump(db)
            return result
