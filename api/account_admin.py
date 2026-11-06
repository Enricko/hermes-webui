"""Local username/password account administration with serialized atomic writes.

Passwords are write-only. Account IDs never change on rename-free edits; a
deleted/recreated username receives a fresh identity. Workspaces are allocated
under trusted state, never a path supplied by a member or browser.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading

from api import user_roles
from api.access_policy import AccessDenied

_LOCK = threading.RLock()


@contextmanager
def account_transaction(*, write=True):
    path = user_roles.users_file()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with _LOCK, path.with_name(path.name + ".lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            if lock.tell() == 0:
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            data = json.loads(path.read_text()) if path.exists() else {"users": {}}
            if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
                raise ValueError("Account store is invalid")
            yield data
            if not write:
                return
            fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".accounts-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    json.dump(data, output, indent=2)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, 0o600)
                path.with_name(path.name + ".required").touch(mode=0o600, exist_ok=True)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def _admin(users, actor_id):
    for name, record in users.items():
        if record.get("id") == actor_id:
            normalized = user_roles._normalize_record(name, record)
            if normalized and normalized["role"] == "admin":
                return
    raise AccessDenied("Active administrator required")


def workspace_alias(username: str) -> str:
    normalized = user_roles.normalize_username(username)
    if not user_roles._USERNAME_RE.fullmatch(normalized):
        raise ValueError('Invalid login username')
    return '/' + normalized


def public_accounts(actor_id: str) -> list[dict]:
    # Read under the same inter-process lock as edits. The transaction does not
    # expose raw records, password hashes, trusted paths or credentials.
    with account_transaction(write=False) as data:
        _admin(data["users"], actor_id)
        return [{"username": name, "id": record.get("id"), "role": record.get("role"),
                 "enabled": not record.get("disabled", False), "workspace":workspace_alias(name)}
                for name, record in sorted(data["users"].items())]


def edit_account(actor_id: str, *, username: str, role: str, enabled: bool,
                 password: str | None = None, create=False, state_root: Path | None = None, policy=None) -> dict:
    username = user_roles.normalize_username(username)
    if not user_roles._USERNAME_RE.fullmatch(username) or role not in user_roles.ROLES or not isinstance(enabled, bool):
        raise ValueError("Invalid username, role or account status")
    if password is not None and (not isinstance(password, str) or len(password) < 12 or len(password) > 1024):
        raise ValueError("Password must contain 12–1024 characters")
    with account_transaction() as data:
        users = data["users"]
        _admin(users, actor_id)
        previous = users.get(username)
        if create and previous is not None:
            raise ValueError("Username is already in use")
        if not create and previous is None:
            raise ValueError("Account does not exist")
        if previous is None and password is None:
            raise ValueError("New accounts require a password")
        record = dict(previous or {})
        record.setdefault("id", secrets.token_hex(16))
        if not previous or (role == "user" and (not record.get("profile") or not record.get("workspaces"))):
            if state_root is None:
                state_root = user_roles.users_file().parent / 'accounts'
            root = Path(state_root) / record["id"]
            root.mkdir(parents=True, mode=0o700, exist_ok=bool(previous))
            workspace = root / username
            workspace.mkdir(mode=0o700, exist_ok=bool(previous))
            record.update(profile="u-" + record["id"], workspaces=[str(workspace.absolute())])
        record.update(role=role, disabled=not enabled)
        record['workspace_alias'] = workspace_alias(username)
        if password is not None:
            record["password"] = user_roles.hash_password(password)
        if previous and any(record.get(k) != previous.get(k) for k in ("role", "disabled", "password")):
            record["auth_generation"] = int(previous.get("auth_generation", 0)) + 1
        users[username] = record
        if not any(r.get("role") == "admin" and not r.get("disabled", False) for r in users.values()):
            raise AccessDenied("Cannot disable or demote the last administrator")
        if policy is not None:
            # A failed policy transaction aborts the JSON edit. If the final
            # atomic JSON write fails after SQLite commits, the two stores
            # must both authorize subsequent access: inconsistency denies it.
            policy.put_account(actor_id, record["id"], role=role, enabled=enabled)
        return {"id": record["id"], "username": username, "role": role, "enabled": enabled,
                "workspace":workspace_alias(username)}
