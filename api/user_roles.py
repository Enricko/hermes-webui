"""Per-account logins with roles for the built-in login page.

LOCAL PATCH (not upstream hermes-webui). Accounts live in
``<STATE_DIR>/users.json`` (override with ``HERMES_WEBUI_USERS_FILE``)::

    {"users": {
        "admin1": {"password": "pbkdf2_sha256$...", "role": "admin"},
        "alice": {"password": "pbkdf2_sha256$...", "role": "user",
                   "profile": "team-alice",
                   "workspaces": ["/srv/workspaces/alice"]}
    }}

role ``admin``  -> unrestricted, same as the legacy single password.
role ``user``   -> legacy Agent execution is denied pending isolated admission;
                   the separate opt-in member API offers tool-free chat/files.

Account mode requires a local account on every login path. Accountless legacy
password, passkey, OIDC and header sessions cannot bypass account policy.
Manage accounts with ``scripts/webui_users.py``.

Folder/profile checks do not contain agent tools running with service OS
permissions. See docs/architecture/multi-user-implementation.md for release gates.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

AUTH_TYPE = "local"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLES = (ROLE_ADMIN, ROLE_USER)

_SCHEME = "pbkdf2_sha256"
_ITERATIONS = 600_000
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ── Storage ──────────────────────────────────────────────────────────────────

def users_file() -> Path:
    override = os.getenv("HERMES_WEBUI_USERS_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    from api.config import STATE_DIR

    return Path(STATE_DIR) / "users.json"


def accounts_configured() -> bool:
    """Remember account mode durably; an empty/broken store must not disable auth.

    The marker is administrator-owned, outside user workspaces. Explicitly
    selecting a store also enables account mode before the first account exists.
    """
    path = users_file()
    marker = path.with_name(path.name + ".required")
    if os.getenv("HERMES_WEBUI_USERS_FILE", "").strip():
        return True
    try:
        if marker.exists():
            return True
        if path.exists():
            marker.touch(mode=0o600, exist_ok=True)
            return True
        return False
    except OSError:
        # An inaccessible configured store is never anonymous mode.
        return True


def normalize_username(name) -> str:
    return str(name or "").strip().lower()


def _normalize_record(name, rec) -> dict | None:
    username = normalize_username(name)
    if not _USERNAME_RE.fullmatch(username) or not isinstance(rec, dict):
        logger.warning("users.json: ignoring invalid account %r", name)
        return None
    role = str(rec.get("role") or "").strip().lower()
    password = str(rec.get("password") or "")
    if role not in ROLES or not password.startswith(_SCHEME + "$"):
        logger.warning("users.json: ignoring account %r (bad role or password hash)", username)
        return None
    if rec.get("disabled", False) is not False:
        return None
    out = {"username": username, "role": role, "password": password,
           "id": str(rec.get("id") or ""), "disabled": False,
           "auth_generation": rec.get("auth_generation", 0)}
    if role == ROLE_USER:
        profile = str(rec.get("profile") or "").strip()
        if not (profile == "default" or _PROFILE_RE.fullmatch(profile)):
            logger.warning("users.json: ignoring user %r (missing/invalid profile)", username)
            return None
        roots = []
        raw_roots = rec.get("workspaces")
        if not isinstance(raw_roots, list):
            return None
        for raw in raw_roots:
            try:
                p = Path(str(raw)).expanduser()
                if p.is_absolute():
                    roots.append(p.resolve())
            except (OSError, RuntimeError, ValueError):
                return None
        if not roots:
            logger.warning("users.json: ignoring user %r (no workspaces)", username)
            return None
        out["profile"] = profile
        out["workspaces"] = roots
    return out


_cache_lock = threading.Lock()
_cache: tuple[tuple, dict] | None = None


def load_users() -> dict[str, dict]:
    """Return {username: record}; re-read whenever the file changes."""
    global _cache
    path = users_file()
    try:
        st = path.stat()
    except FileNotFoundError:
        return {}
    except OSError:
        logger.warning("users.json: cannot stat %s", path)
        return {}
    sig = (str(path.absolute()), st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
    with _cache_lock:
        if _cache is not None and _cache[0] == sig:
            return _cache[1]
    users: dict[str, dict] = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("users.json: unreadable or invalid JSON at %s", path)
    else:
        raw = data.get("users") if isinstance(data, dict) else None
        if isinstance(raw, dict):
            for name, rec in raw.items():
                norm = _normalize_record(name, rec)
                if norm:
                    users[norm["username"]] = norm
    with _cache_lock:
        _cache = (sig, users)
    return users


def has_accounts() -> bool:
    return accounts_configured()


# ── Passwords ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_SCHEME}${_ITERATIONS}${salt.hex()}${dk.hex()}"


def _verify_hash(password: str, stored: str) -> bool:
    if not isinstance(stored, str):
        return False
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != _SCHEME:
            return False
        iterations = int(iters)
        salt = bytes.fromhex(salt_hex)
        if not 100_000 <= iterations <= 2_000_000 or len(salt) != 16 or len(hash_hex) != 64:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH: str | None = None


def authenticate(username, password) -> dict | None:
    """Return the account record when username/password match, else None."""
    global _DUMMY_HASH
    rec = load_users().get(normalize_username(username))
    if rec is None:
        # Spend the same PBKDF2 time so unknown usernames are not distinguishable.
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password(secrets.token_hex(8))
        _verify_hash(str(password or ""), _DUMMY_HASH)
        return None
    if not _verify_hash(str(password or ""), rec["password"]):
        return None
    return rec


def bound_profile_for(rec: dict) -> str | None:
    return rec["profile"] if rec["role"] == ROLE_USER else None


def session_binding(rec: dict) -> str:
    """Bind login authority to identity, password and role, never to a username alone.

    This digest stays in the server-side session store and is not a cookie or
    an API field. Legacy records are invalidated on their first password reset;
    the account CLI assigns immutable IDs for new and updated records.
    """
    fields = [rec.get(k) for k in ("id", "username", "password", "role", "profile", "auth_generation")]
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


# ── Per-request restriction context ──────────────────────────────────────────

@dataclass(frozen=True)
class Restriction:
    username: str
    profile: str
    workspaces: tuple[Path, ...]


_tls = threading.local()


def set_request_restriction(restriction: Restriction | None) -> None:
    _tls.restriction = restriction


def clear_request_restriction() -> None:
    _tls.restriction = None


def current_restriction() -> Restriction | None:
    return getattr(_tls, "restriction", None)


def is_restricted() -> bool:
    return current_restriction() is not None


def resolve_session_account(info: dict) -> tuple[bool, Restriction | None]:
    """Validate a ``local`` login session against the current users.json.

    Returns (valid, restriction). A session becomes invalid as soon as the
    account is removed or its role/profile changes, so edits take effect on
    the next request without waiting for the cookie to expire.
    """
    rec = load_users().get(normalize_username(info.get("username")))
    if rec is None:
        return False, None
    binding = info.get("account_binding")
    if not isinstance(binding, str) or not hmac.compare_digest(binding, session_binding(rec)):
        return False, None
    expected = bound_profile_for(rec)
    actual = str(info.get("bound_profile") or "").strip() or None
    if expected != actual:
        return False, None
    if rec["role"] != ROLE_USER:
        return True, None
    return True, Restriction(rec["username"], rec["profile"], tuple(rec["workspaces"]))


# ── Path checks ──────────────────────────────────────────────────────────────

def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolved(path) -> Path | None:
    try:
        return Path(str(path)).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def workspace_allowed(path) -> bool:
    r = current_restriction()
    if r is None:
        return True
    p = _resolved(path)
    return p is not None and any(_within(p, root) for root in r.workspaces)


def filter_workspace_rows(rows: list) -> list:
    """Keep only saved workspaces the restricted account may use."""
    r = current_restriction()
    if r is None:
        return rows
    kept = [w for w in rows if isinstance(w, dict) and workspace_allowed(w.get("path"))]
    if not kept:
        root = r.workspaces[0]
        kept = [{"path": str(root), "name": root.name or str(root)}]
    return kept


_SECRET_FILE_NAMES = {".env", "config.yaml", "auth.json", "webui.env", "users.json", "settings.json"}


def _is_secret_file(path: Path) -> bool:
    name = path.name
    return name in _SECRET_FILE_NAMES or name.startswith(".env") or ".db" in name


def media_path_allowed(raw_path: str, handler) -> bool:
    """For /api/media: restricted accounts only get their own files."""
    r = current_restriction()
    if r is None:
        return True
    target = _resolved(raw_path)
    if target is None or _is_secret_file(target):
        return False
    if any(_within(target, root) for root in r.workspaces):
        return True
    try:
        from api.profiles import get_hermes_home_for_profile

        home = Path(get_hermes_home_for_profile(r.profile)).resolve()
        if _within(target, home):
            return True
    except Exception:
        logger.debug("media check: cannot resolve profile home", exc_info=True)
    try:
        from api.upload import _attachment_root

        att = _attachment_root()
        if _within(target, att):
            parts = target.relative_to(att).parts
            if len(parts) >= 2:
                from api.routes import _session_id_visible_to_request_profile

                return bool(_session_id_visible_to_request_profile(handler, parts[0], emit_error=False))
    except Exception:
        logger.debug("media check: attachment lookup failed", exc_info=True)
    return False


# ── Endpoint policy for role "user" ──────────────────────────────────────────

_USER_DENIED_PREFIXES = (
    "/api/admin/",
    "/api/updates/",
    "/api/onboarding/",
    "/api/terminal/",
    "/api/escape/",
    "/api/extensions/install",
    "/api/extensions/uninstall",
    "/api/extensions/toggle",
    "/api/extensions/sidecar-proxy-consent",
    "/api/auth/passkey/register",
    "/api/auth/passkey/delete",
)
_USER_DENIED_EXACT = frozenset({
    "/api/shutdown",
    "/api/health/restart",
    "/api/logs",
    "/api/insights",
    "/api/project-os/dashboard",
    "/api/profile/create",
    "/api/profile/delete",
    "/api/providers/delete",
    "/api/file/open-vscode",
    "/api/file/reveal",
    "/api/gateway/start",
    "/api/gateway/stop",
    "/api/gateway/restart",
    "/api/sessions/cleanup",
    "/api/sessions/cleanup_zero_message",
    "/api/approval/inject_test",
    "/api/clarify/inject_test",
    "/api/skills/save",
    "/api/skills/delete",
})
# Readable by the UI, but changing them is admin-only (global or host-level).
_USER_DENIED_WRITES = frozenset({
    "/api/settings",
    "/api/providers",
    "/api/providers/self-hosted",
    "/api/dashboard/config",
    "/api/mcp/servers",
    "/api/plugins",
})


def request_denied(handler, parsed) -> str | None:
    """Return an error message when a restricted account may not make this request."""
    if current_restriction() is None:
        return None
    path = getattr(parsed, "path", "") or ""
    # A profile cookie/path allowlist does not contain terminal, Python or MCP
    # tools. Until the isolated-worker bridge is wired and verified, never
    # admit a member to the shared process's agent/state/file execution paths.
    # There is deliberately no environment-variable escape hatch for this gate.
    if path.startswith("/api/") and not path.startswith("/api/member/") and path not in {
        "/api/auth/status", "/api/auth/logout", "/api/access/me"
    }:
        return "Isolated multi-user runtime is not available yet"
    method = str(getattr(handler, "command", "GET") or "GET").upper()
    if path in _USER_DENIED_EXACT or path.startswith(_USER_DENIED_PREFIXES):
        return "Not available for this account"
    if method not in ("GET", "HEAD") and path in _USER_DENIED_WRITES:
        return "Not available for this account"
    if path == "/api/media":
        raw = parse_qs(getattr(parsed, "query", "") or "").get("path", [""])[0].strip()
        if raw and not media_path_allowed(raw, handler):
            return "File not available for this account"
    return None
