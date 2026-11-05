"""Stdlib-only helpers for the hermetic multi-user verification launcher (F02).

Shared by ``scripts/test_multiuser.py``, which loads this file by validated
path, and by the multi-user pytest conftest. This module never imports product
code and never reads operator state.

Evidence limits:

* ``verify_hermetic_environment`` checks observable properties of the current
  (or a supplied) environment: where the disposable paths point, who owns the
  state root, and which variables are present. A label such as
  ``HERMES_MU_STATE_ROOT`` is only a starting point; it is never treated as
  proof on its own.
* ``NetworkGuard`` intercepts Python-level socket calls in the current
  interpreter only. Subprocesses, native extensions that call ``_socket`` or
  libc directly, and OS-level networking are outside it. It is not an OS
  network sandbox and is never reported as one.
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import socketserver
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

__all__ = [
    "AGENT_CHECKOUT_VAR",
    "AGENT_MODE_VAR",
    "DestinationRefused",
    "FixtureError",
    "FixtureTeardownError",
    "HermeticEnvironmentError",
    "LoopbackUpstream",
    "NetworkGuard",
    "OPERATOR_HOME_VAR",
    "RecordedRequest",
    "REPO_ROOT_VAR",
    "STATE_ROOT_VAR",
    "SYNTHETIC_PREFIX",
    "TIER_VAR",
    "active_guard",
    "assert_hermetic_environment",
    "disposable_layout",
    "is_secret_like_name",
    "is_within",
    "operator_home",
    "synthetic_credential",
    "validate_destination",
    "verify_hermetic_environment",
]

STATE_ROOT_VAR = "HERMES_MU_STATE_ROOT"
TIER_VAR = "HERMES_MU_TIER"
AGENT_MODE_VAR = "HERMES_MU_AGENT_MODE"
AGENT_CHECKOUT_VAR = "HERMES_MU_AGENT_CHECKOUT"
REPO_ROOT_VAR = "HERMES_MU_REPO_ROOT"
# Windows only: the child's USERPROFILE is disposable, so the launcher passes
# the operator home explicitly for denial checks. POSIX uses the passwd entry.
OPERATOR_HOME_VAR = "HERMES_MU_OPERATOR_HOME"
SYNTHETIC_PREFIX = "mu-synthetic-"

# Every variable the launcher points at a disposable path inside the state root.
DISPOSABLE_PATH_VARS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
    "HERMES_HOME",
    "HERMES_BASE_HOME",
    "HERMES_CONFIG_PATH",
    "HERMES_WEBUI_STATE_DIR",
    "HERMES_WEBUI_DEFAULT_WORKSPACE",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "GH_CONFIG_DIR",
    "GNUPGHOME",
    "DOCKER_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "NETRC",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "KUBECONFIG",
    "NPM_CONFIG_USERCONFIG",
    "PYTHONPYCACHEPREFIX",
    "LOCALAPPDATA",
    "APPDATA",
)
# Variables that must carry exactly the same path as another disposable one.
ALIAS_VARS = {
    "USERPROFILE": "HOME",
    "TMP": "TMPDIR",
    "TEMP": "TMPDIR",
    # Isolated single-profile layout: the base home is the active home.
    "HERMES_BASE_HOME": "HERMES_HOME",
}
# Disposable directories that must not overlap one another.
PRIMARY_DIR_VARS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
    "HERMES_HOME",
    "HERMES_WEBUI_STATE_DIR",
    "HERMES_WEBUI_DEFAULT_WORKSPACE",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "GH_CONFIG_DIR",
    "GNUPGHOME",
    "DOCKER_CONFIG",
    "PYTHONPYCACHEPREFIX",
    "LOCALAPPDATA",
    "APPDATA",
)
# The complete set of variables a launcher-built child environment may hold.
LAUNCHER_ENV_VARS = frozenset(
    DISPOSABLE_PATH_VARS
    + tuple(ALIAS_VARS)
    + (
        "PATH",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "PIP_CONFIG_FILE",
        "PIP_NO_INPUT",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "NO_PROXY",
        "no_proxy",
        "HERMES_WEBUI_HOST",
        "HERMES_DISABLE_LAZY_INSTALLS",
        "HERMES_WEBUI_AGENT_DIR",
        "HERMES_WEBUI_PYTHON",
        "HERMES_WEBUI_TEST_PYTHON",
        "PLAYWRIGHT_BROWSERS_PATH",
        "PYTHONPATH",
        "HERMES_MU_IMPORT_MANIFEST",
        "HERMES_MU_IMPORT_MANIFEST_SHA256",
        STATE_ROOT_VAR,
        TIER_VAR,
        AGENT_MODE_VAR,
        AGENT_CHECKOUT_VAR,
        REPO_ROOT_VAR,
        OPERATOR_HOME_VAR,
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "NO_COLOR",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    )
)
# Variables the shell, pytest or the OS add after the launcher builds the env.
TOLERATED_RUNTIME_VARS = frozenset(
    {
        "PWD",
        "OLDPWD",
        "SHLVL",
        "_",
        "PYTEST_VERSION",
        "PYTEST_CURRENT_TEST",
        "COLUMNS",
        "LINES",
        "__CF_USER_TEXT_ENCODING",
        "__CFBundleIdentifier",
    }
)
POSIX_SYSTEM_PATH_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")

_SECRET_NAME_RE = re.compile(
    r"KEY|TOKEN|SECRET|PASSW(?:OR)?D|PASSPHRASE|AUTH|CREDENTIAL|COOKIE|SESSION|"
    r"PRIVATE|BEARER|SIGNING|(?:^|_)PAT(?:_|$)",
    re.IGNORECASE,
)
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


class HermeticEnvironmentError(RuntimeError):
    """The environment does not have the properties the launcher guarantees."""


class FixtureError(RuntimeError):
    """A synthetic fixture could not be started or was misused."""


class FixtureTeardownError(FixtureError):
    """A synthetic fixture did not stop within its bounded teardown."""


class DestinationRefused(PermissionError):
    """A network destination is not an exact fixture-owned loopback endpoint."""


def is_secret_like_name(name: str) -> bool:
    """True when an environment variable name looks like it carries a secret."""
    return bool(_SECRET_NAME_RE.search(name or ""))


def synthetic_credential(label: str = "credential") -> str:
    """Return a fresh random credential that is visibly synthetic."""
    if not _LABEL_RE.match(label or ""):
        raise ValueError("label must be 1-48 chars of lowercase letters, digits or '-'")
    return f"{SYNTHETIC_PREFIX}{label}-{secrets.token_hex(16)}"


def operator_home() -> str:
    """Return the operator's real home directory, independent of ``$HOME``."""
    if os.name == "posix":
        import pwd

        return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    explicit = os.environ.get(OPERATOR_HOME_VAR, "").strip()
    if explicit:
        return os.path.realpath(explicit)
    return os.path.realpath(os.path.expanduser("~"))


def is_within(path: str, root: str) -> bool:
    """Lexical containment of normalized absolute paths (``path`` may equal ``root``)."""
    path = os.path.normcase(os.path.normpath(path))
    root = os.path.normcase(os.path.normpath(root))
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def disposable_layout(state_root: str) -> dict:
    """Map each disposable variable to its path under ``state_root``.

    Directories are created by the launcher; file paths (git config, netrc,
    AWS, kube, npm) are left absent except the empty global git config.
    """
    r = state_root
    j = os.path.join
    hermes_home = j(r, "hermes")
    return {
        "HOME": j(r, "home"),
        "XDG_CONFIG_HOME": j(r, "xdg", "config"),
        "XDG_DATA_HOME": j(r, "xdg", "data"),
        "XDG_CACHE_HOME": j(r, "xdg", "cache"),
        "XDG_STATE_HOME": j(r, "xdg", "state"),
        "TMPDIR": j(r, "tmp"),
        "HERMES_HOME": hermes_home,
        "HERMES_BASE_HOME": hermes_home,
        "HERMES_CONFIG_PATH": j(hermes_home, "config.yaml"),
        "HERMES_WEBUI_STATE_DIR": j(r, "webui-state"),
        "HERMES_WEBUI_DEFAULT_WORKSPACE": j(r, "workspace"),
        "CODEX_HOME": j(r, "cli", "codex"),
        "CLAUDE_CONFIG_DIR": j(r, "cli", "claude"),
        "GH_CONFIG_DIR": j(r, "cli", "gh"),
        "GNUPGHOME": j(r, "cli", "gnupg"),
        "DOCKER_CONFIG": j(r, "cli", "docker"),
        "GIT_CONFIG_GLOBAL": j(r, "cli", "gitconfig"),
        "NETRC": j(r, "cli", "netrc"),
        "AWS_CONFIG_FILE": j(r, "cli", "aws-config"),
        "AWS_SHARED_CREDENTIALS_FILE": j(r, "cli", "aws-credentials"),
        "KUBECONFIG": j(r, "cli", "kubeconfig"),
        "NPM_CONFIG_USERCONFIG": j(r, "cli", "npmrc"),
        "PYTHONPYCACHEPREFIX": j(r, "pycache"),
        "LOCALAPPDATA": j(r, "appdata", "local"),
        "APPDATA": j(r, "appdata", "roaming"),
        "USERPROFILE": j(r, "home"),
        "TMP": j(r, "tmp"),
        "TEMP": j(r, "tmp"),
    }


def _has_symlink_component(path: str) -> bool:
    """True when ``path`` (or its existing prefix) passes through a link."""
    return os.path.normcase(os.path.realpath(path)) != os.path.normcase(os.path.normpath(path))


def verify_hermetic_environment(environ=None) -> list:
    """Return a list of problems; an empty list means the checks passed.

    With ``environ=None`` the current process environment is checked and the
    interpreter's user-site state is checked as well.
    """
    env = dict(os.environ if environ is None else environ)
    problems = []
    root = env.get(STATE_ROOT_VAR, "")
    if not root or not os.path.isabs(root):
        return [f"{STATE_ROOT_VAR} is missing or not absolute"]
    try:
        st = os.lstat(root)
    except OSError as exc:
        return [f"state root is not accessible: {exc.__class__.__name__}"]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        problems.append("state root is not a real directory")
    if _has_symlink_component(root):
        problems.append("state root path passes through a symbolic link")
    if os.name == "posix":
        if st.st_uid != os.getuid():
            problems.append("state root is not owned by the current user")
        if st.st_mode & 0o077:
            problems.append("state root is accessible to group or other users")
    home = operator_home()
    if is_within(root, home) or is_within(home, root):
        problems.append("state root overlaps the operator home")

    values = {}
    for var in DISPOSABLE_PATH_VARS:
        value = env.get(var, "")
        if not value or not os.path.isabs(value):
            problems.append(f"{var} is missing or not absolute")
            continue
        if not is_within(value, root) or os.path.normpath(value) == os.path.normpath(root):
            problems.append(f"{var} is not inside the disposable state root")
        if _has_symlink_component(value):
            problems.append(f"{var} passes through a symbolic link")
        values[var] = os.path.normcase(os.path.normpath(value))
    for alias, target in ALIAS_VARS.items():
        value = env.get(alias)
        if value is None and alias not in DISPOSABLE_PATH_VARS:
            problems.append(f"{alias} is missing")
        elif value is not None and os.path.normcase(os.path.normpath(value)) != values.get(target):
            problems.append(f"{alias} does not match {target}")
    distinct = {var: v for var, v in values.items() if var not in ALIAS_VARS}
    if len(set(distinct.values())) != len(distinct):
        problems.append("disposable paths are not pairwise distinct")
    primaries = [values[v] for v in PRIMARY_DIR_VARS if v in values]
    for i, first in enumerate(primaries):
        for second in primaries[i + 1:]:
            if is_within(first, second) or is_within(second, first):
                problems.append("disposable directories overlap one another")
                break
    if "HERMES_CONFIG_PATH" in values and "HERMES_HOME" in values:
        if not is_within(values["HERMES_CONFIG_PATH"], values["HERMES_HOME"]):
            problems.append("HERMES_CONFIG_PATH is not inside HERMES_HOME")

    unexpected = sorted(set(env) - LAUNCHER_ENV_VARS - TOLERATED_RUNTIME_VARS)
    if unexpected:
        problems.append("unexpected environment variables: " + ", ".join(unexpected))
    for name, value in env.items():
        # Disposable path variables were checked above to point inside the root.
        if name in DISPOSABLE_PATH_VARS:
            continue
        if is_secret_like_name(name) and not str(value).startswith(SYNTHETIC_PREFIX):
            problems.append(f"{name} carries a non-synthetic secret-like value")
        if "MULTIUSER" in name.upper() or "MULTI_USER" in name.upper():
            problems.append(f"{name} would configure product multi-user mode")
    if env.get("PYTHONNOUSERSITE") != "1":
        problems.append("PYTHONNOUSERSITE is not 1")
    # The only PYTHONPATH a launcher child gets is its own import-guard directory.
    if "PYTHONPATH" in env and env["PYTHONPATH"] != os.path.join(root, "launcher", "importguard"):
        problems.append("PYTHONPATH is not the launcher import-guard directory")
    manifest = env.get("HERMES_MU_IMPORT_MANIFEST")
    if manifest is not None and (not is_within(manifest, root) or "PYTHONPATH" not in env):
        problems.append("the import manifest is not a launcher-owned file in the state root")
    if env.get("HERMES_WEBUI_HOST", "127.0.0.1") != "127.0.0.1":
        problems.append("HERMES_WEBUI_HOST is not 127.0.0.1")

    mode = env.get(AGENT_MODE_VAR, "")
    agent_dir = env.get("HERMES_WEBUI_AGENT_DIR", "")
    if mode == "none":
        if AGENT_CHECKOUT_VAR in env:
            problems.append(f"{AGENT_CHECKOUT_VAR} is set without an explicit Agent")
        if not agent_dir or not is_within(agent_dir, root) or os.path.lexists(agent_dir):
            problems.append("HERMES_WEBUI_AGENT_DIR is not an absent path in the state root")
    elif mode == "explicit":
        checkout = env.get(AGENT_CHECKOUT_VAR, "")
        if not checkout or os.path.normpath(agent_dir) != os.path.normpath(checkout):
            problems.append("HERMES_WEBUI_AGENT_DIR does not match the explicit checkout")
        elif _has_symlink_component(checkout) or is_within(checkout, root):
            problems.append("explicit Agent checkout is not a canonical external path")
        elif not os.path.isfile(os.path.join(checkout, "run_agent.py")):
            problems.append("explicit Agent checkout has no run_agent.py")
    else:
        problems.append(f"{AGENT_MODE_VAR} is neither 'none' nor 'explicit'")

    repo = env.get(REPO_ROOT_VAR, "")
    if not repo or _has_symlink_component(repo) or not os.path.isfile(
        os.path.join(repo, "scripts", "test_multiuser.py")
    ):
        problems.append(f"{REPO_ROOT_VAR} is not the canonical launcher checkout")
    if os.name == "posix":
        allowed_path = set(POSIX_SYSTEM_PATH_DIRS)
        if repo:
            allowed_path.add(os.path.join(repo, ".venv", "bin"))
        for entry in env.get("PATH", "").split(os.pathsep):
            if entry not in allowed_path:
                problems.append("PATH contains a directory outside the launcher allowlist")
                break
            if os.path.lexists(os.path.join(entry, "hermes")):
                problems.append("PATH exposes an installed 'hermes' launcher")
                break
    if environ is None and not sys.flags.no_user_site:
        problems.append("the interpreter has user site-packages enabled")
    return problems


def assert_hermetic_environment(environ=None) -> None:
    problems = verify_hermetic_environment(environ)
    if problems:
        raise HermeticEnvironmentError("; ".join(problems))


# ── Exact loopback destinations ──────────────────────────────────────────────


def _literal_ip(host):
    """Return an ``ipaddress`` object for a literal host, or None for a name."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str) or not host:
        return None
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _endpoint_of(target):
    endpoint = getattr(target, "endpoint", target)
    if not isinstance(endpoint, tuple) or len(endpoint) < 2:
        raise FixtureError("an allowed destination must be a LoopbackUpstream or (host, port)")
    ip = _literal_ip(endpoint[0])
    if ip is None or not ip.is_loopback:
        raise FixtureError("only literal loopback endpoints can be allowed")
    port = int(endpoint[1])
    if not 0 < port < 65536:
        raise FixtureError("allowed endpoint port is out of range")
    return (ip.compressed, port)


def validate_destination(url: str, owned=()) -> None:
    """Refuse ``url`` unless it targets an exact fixture-owned loopback endpoint."""
    allowed = {_endpoint_of(item) for item in owned}
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise DestinationRefused(f"unparseable destination: {exc}") from None
    if parts.scheme not in {"http", "https", "ws", "wss"}:
        raise DestinationRefused("destination scheme is not http(s) or ws(s)")
    if parts.username is not None or parts.password is not None:
        raise DestinationRefused("destination carries embedded credentials")
    ip = _literal_ip(parts.hostname or "")
    if ip is None:
        raise DestinationRefused("destination host is a name, not a literal loopback address")
    if not ip.is_loopback:
        raise DestinationRefused("destination is not loopback")
    if port is None:
        port = 443 if parts.scheme in {"https", "wss"} else 80
    if (ip.compressed, port) not in allowed:
        raise DestinationRefused("destination is not a fixture-owned endpoint")


_GUARD_LOCK = threading.Lock()
_ACTIVE_GUARD = None
_SOCKET_METHODS = ("connect", "connect_ex", "sendto", "sendmsg")


def active_guard():
    """The NetworkGuard installed in this process, or None.

    Launcher ``--script`` runs install a deny-by-default guard before the script
    starts; a script registers the fixtures it owns with ``active_guard().allow``.
    """
    return _ACTIVE_GUARD
_MODULE_FUNCTIONS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo")


class NetworkGuard:
    """Python-level guard that only permits exact fixture-owned endpoints.

    Allowed: connections to literal loopback (host, port) pairs registered with
    ``allow`` and, for AF_UNIX, socket paths under ``allow_unix_under``.
    Refused: host names (including ``localhost``), any non-loopback address
    (public, RFC1918, link-local/metadata, IPv6), unowned loopback ports such as
    an operator service, abstract or foreign UNIX sockets, other families, and
    reverse lookups. Refusals raise ``DestinationRefused`` before any packet is
    sent and are recorded in ``refused``.

    Not an OS sandbox: subprocesses and native code are not intercepted.
    """

    def __init__(self, allowed=(), *, allow_unix_under=()):
        self._allowed = set()
        self._unix_roots = tuple(os.path.realpath(p) for p in allow_unix_under)
        self._saved_methods = None
        self._saved_functions = None
        self.refused = []
        for item in allowed:
            self.allow(item)

    @property
    def allowed(self):
        return frozenset(self._allowed)

    def allow(self, target):
        self._allowed.add(_endpoint_of(target))
        return target

    def _refuse(self, operation, detail):
        self.refused.append((operation, detail))
        raise DestinationRefused(f"{operation} refused by multi-user test guard: {detail}")

    def _check_address(self, family, address, operation):
        if family in (socket.AF_INET, getattr(socket, "AF_INET6", None)):
            if not isinstance(address, tuple) or len(address) < 2:
                self._refuse(operation, "malformed inet address")
            ip = _literal_ip(address[0])
            if ip is None:
                self._refuse(operation, f"host name {address[0]!r}")
            if not ip.is_loopback:
                self._refuse(operation, f"non-loopback address {ip.compressed}")
            if (ip.compressed, int(address[1])) not in self._allowed:
                self._refuse(operation, f"unowned loopback endpoint {ip.compressed}:{address[1]}")
            return
        if family == getattr(socket, "AF_UNIX", None):
            raw = address
            if isinstance(raw, (bytes, bytearray)):
                raw = bytes(raw).decode("utf-8", "surrogateescape")
            if not isinstance(raw, str) or not raw or raw.startswith("\0"):
                self._refuse(operation, "abstract or malformed unix socket")
            real = os.path.realpath(raw)
            if not any(is_within(real, base) for base in self._unix_roots):
                self._refuse(operation, "unix socket outside the allowed fixture roots")
            return
        self._refuse(operation, f"socket family {family!r}")

    def install(self):
        global _ACTIVE_GUARD
        with _GUARD_LOCK:
            if _ACTIVE_GUARD is self:
                return self
            if _ACTIVE_GUARD is not None:
                raise FixtureError("another NetworkGuard is already installed in this process")
            guard = self
            cls = socket.socket
            self._saved_methods = {
                name: (name in cls.__dict__, cls.__dict__.get(name), getattr(cls, name))
                for name in _SOCKET_METHODS
                if hasattr(cls, name)
            }
            self._saved_functions = {
                name: getattr(socket, name) for name in _MODULE_FUNCTIONS if hasattr(socket, name)
            }
            orig = {name: saved[2] for name, saved in self._saved_methods.items()}
            fns = self._saved_functions

            def connect(sock, address):
                guard._check_address(sock.family, address, "connect")
                return orig["connect"](sock, address)

            def connect_ex(sock, address):
                guard._check_address(sock.family, address, "connect")
                return orig["connect_ex"](sock, address)

            def sendto(sock, data, *args):
                if args:
                    guard._check_address(sock.family, args[-1], "sendto")
                return orig["sendto"](sock, data, *args)

            def sendmsg(sock, buffers, *args):
                if len(args) >= 3 and args[2] is not None:
                    guard._check_address(sock.family, args[2], "sendmsg")
                return orig["sendmsg"](sock, buffers, *args)

            def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                if host is not None and _literal_ip(host) is None:
                    guard._refuse("getaddrinfo", f"host name {host!r}")
                return fns["getaddrinfo"](
                    host, port, family, type, proto, flags | socket.AI_NUMERICHOST
                )

            def gethostbyname(name):
                if _literal_ip(name) is None:
                    guard._refuse("gethostbyname", f"host name {name!r}")
                return fns["gethostbyname"](name)

            def gethostbyname_ex(name):
                if _literal_ip(name) is None:
                    guard._refuse("gethostbyname_ex", f"host name {name!r}")
                return fns["gethostbyname_ex"](name)

            def gethostbyaddr(address):
                guard._refuse("gethostbyaddr", f"reverse lookup of {address!r}")

            def getnameinfo(sockaddr, flags):
                return fns["getnameinfo"](
                    sockaddr, flags | socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
                )

            wrappers = {
                "connect": connect,
                "connect_ex": connect_ex,
                "sendto": sendto,
                "sendmsg": sendmsg,
            }
            for name in self._saved_methods:
                setattr(cls, name, wrappers[name])
            replacements = {
                "getaddrinfo": getaddrinfo,
                "gethostbyname": gethostbyname,
                "gethostbyname_ex": gethostbyname_ex,
                "gethostbyaddr": gethostbyaddr,
                "getnameinfo": getnameinfo,
            }
            for name in self._saved_functions:
                setattr(socket, name, replacements[name])
            _ACTIVE_GUARD = self
        return self

    def uninstall(self):
        global _ACTIVE_GUARD
        with _GUARD_LOCK:
            if _ACTIVE_GUARD is not self:
                return
            cls = socket.socket
            for name, (had, original, _bound) in self._saved_methods.items():
                if had:
                    setattr(cls, name, original)
                else:
                    delattr(cls, name)
            for name, original in self._saved_functions.items():
                setattr(socket, name, original)
            self._saved_methods = self._saved_functions = None
            _ACTIVE_GUARD = None

    def __enter__(self):
        return self.install()

    def __exit__(self, *exc):
        self.uninstall()
        return False


# ── Synthetic loopback upstream ──────────────────────────────────────────────


class RecordedRequest:
    __slots__ = ("method", "path", "headers", "body")

    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    def __repr__(self):
        return f"RecordedRequest({self.method!r}, {self.path!r}, {len(self.body)} bytes)"


def _default_handler(request):
    body = json.dumps({"ok": True, "fixture": "synthetic", "path": request.path}).encode()
    return 200, {"Content-Type": "application/json"}, body


class _LoopbackHTTPServer(http.server.HTTPServer):
    """One tracked thread per request, so teardown can close and await every one."""

    allow_reuse_address = False

    def __init__(self, address, handler_cls, family):
        self.address_family = family
        self.active = {}
        self.active_lock = threading.Lock()
        super().__init__(address, handler_cls)

    def server_bind(self):
        # HTTPServer.server_bind resolves the FQDN (a DNS lookup); skip it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address):
        thread = threading.Thread(
            target=self._serve_request, args=(request, client_address),
            name="mu-upstream-request", daemon=True,
        )
        with self.active_lock:
            self.active[thread] = request
        thread.start()

    def _serve_request(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            pass  # a closed or reset fixture connection; the client sees the failure
        finally:
            self.shutdown_request(request)
            with self.active_lock:
                self.active.pop(threading.current_thread(), None)

    def close_requests(self):
        """Shut down every open request connection, waking handlers blocked on I/O."""
        with self.active_lock:
            requests = list(self.active.values())
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass

    def handler_threads(self):
        with self.active_lock:
            return list(self.active)


_MAX_BODY = 10 * 1024 * 1024


class LoopbackUpstream:
    """Synthetic HTTP upstream bound to a literal loopback address.

    The listener stays bound from ``start`` until ``close``; the port is chosen
    by the OS, so an existing service is never displaced or killed. ``handler``
    receives a ``RecordedRequest`` and returns ``(status, headers, body)``.

    Request reads time out after ``request_timeout`` seconds. ``close`` sets
    ``closing`` (cooperative handlers can wait on it), stops the listener,
    shuts down every open request connection and waits for every request
    handler; a handler that is still running is reported through
    ``FixtureTeardownError`` and kept in ``stuck_handlers``.
    """

    def __init__(self, handler=None, *, host="127.0.0.1", ready_timeout=5.0, request_timeout=5.0):
        ip = _literal_ip(host)
        if ip is None or not ip.is_loopback or host not in ("127.0.0.1", "::1"):
            raise FixtureError("LoopbackUpstream binds only to 127.0.0.1 or ::1")
        self.host = host
        self._family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        self._handler = handler or _default_handler
        self._ready_timeout = float(ready_timeout)
        self._request_timeout = float(request_timeout)
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self._closed = False
        self.closing = threading.Event()
        self.stuck_handlers = []
        self.port = None
        self.requests = []

    @property
    def endpoint(self):
        if self.port is None:
            raise FixtureError("LoopbackUpstream is not started")
        return (self.host, self.port)

    @property
    def url(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.endpoint[1]}"

    def _make_handler_class(self):
        upstream = self

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = upstream._request_timeout

            def _handle(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                body = self.rfile.read(min(max(length, 0), _MAX_BODY)) if length else b""
                request = RecordedRequest(self.command, self.path, dict(self.headers.items()), body)
                with upstream._lock:
                    upstream.requests.append(request)
                try:
                    status, headers, payload = upstream._handler(request)
                except Exception:
                    status, headers, payload = 500, {"Content-Type": "text/plain"}, b"fixture handler error"
                payload = payload if isinstance(payload, bytes) else str(payload).encode()
                self.send_response(int(status))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

            def log_message(self, *args):
                pass

        return Handler

    def start(self):
        with self._lock:
            if self._closed:
                raise FixtureError("LoopbackUpstream cannot be restarted after close")
            if self._server is not None:
                return self
            server = _LoopbackHTTPServer((self.host, 0), self._make_handler_class(), self._family)
            ready = threading.Event()

            def serve():
                ready.set()
                server.serve_forever(poll_interval=0.05)

            thread = threading.Thread(target=serve, name="mu-loopback-upstream", daemon=True)
            self._server, self._thread = server, thread
            self.port = server.server_address[1]
        try:
            self._start_serve_thread(thread)
        except BaseException:
            # Roll back the bound listener so a partial start leaks nothing.
            with self._lock:
                self._server = self._thread = None
                self._closed = True
            server.server_close()
            raise FixtureError("LoopbackUpstream serve thread could not start") from None
        if not ready.wait(self._ready_timeout):
            try:
                self.close()
            finally:
                raise FixtureError("LoopbackUpstream did not become ready")
        return self

    def _start_serve_thread(self, thread):
        thread.start()

    def close(self, timeout=5.0):
        """Stop the listener and every request handler within ``timeout`` seconds."""
        with self._lock:
            server, thread = self._server, self._thread
            self._server = self._thread = None
            self._closed = True
        if server is None:
            return
        self.closing.set()
        deadline = time.monotonic() + float(timeout)
        stuck = []
        if thread is not None and thread.is_alive():
            stopper = threading.Thread(target=server.shutdown, name="mu-upstream-stop", daemon=True)
            stopper.start()
            stopper.join(max(deadline - time.monotonic(), 0))
            thread.join(max(deadline - time.monotonic(), 0))
            if thread.is_alive():
                stuck.append(thread)
        server.server_close()
        server.close_requests()
        for handler in server.handler_threads():
            handler.join(max(deadline - time.monotonic(), 0))
        stuck.extend(t for t in server.handler_threads() if t.is_alive())
        if stuck:
            self.stuck_handlers = stuck
            raise FixtureTeardownError(
                f"LoopbackUpstream left {len(stuck)} thread(s) running after close"
            )

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
        return False
