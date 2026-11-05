#!/usr/bin/env python3
"""Hermetic multi-user verification launcher (F02).

Strong entry form (initial interpreter startup hooks disabled):

    python3 -I -S scripts/test_multiuser.py --self-test
    python3 -I -S scripts/test_multiuser.py --no-agent -- -q tests/multiuser/test_f02.py
    python3 -I -S scripts/test_multiuser.py --agent-checkout PATH -- <pytest args>
    python3 -I -S scripts/test_multiuser.py --no-agent --script tests/<script>.py [-- <args>]
    python3 -I -S scripts/test_multiuser.py --tier containment --host-os linux --backend docker -- ...
    python3 -I -S scripts/test_multiuser.py --tier remote --deployment-manifest PATH -- ...

Plain ``python3 scripts/test_multiuser.py`` works too. Its result is labelled
``initial-interpreter-unverified``: hooks that ran before ``main`` (.pth files,
sitecustomize) cannot be undone by this launcher.

Every run prints one final stdout line, ``MULTIUSER_RESULT {json}``, and exits:
0 PASS, 1 FAIL, 2 REFUSED (unsafe input or usage), 3 NOT_RUN (a mandatory
prerequisite is unavailable). NOT_RUN is never a pass.

What the launcher does, before any product import:

* refuses unsafe paths, links (anywhere in collected test trees and explicit
  Agent checkouts), pytest options, pytest.ini keys and option combinations;
* statically checks the repo ``.venv`` and its base interpreter, which must be
  a verified distribution build, for startup hooks, import-path extensions and
  editable or Agent sources, without executing them;
* denies implicit installed-Agent discovery and checkout ``.env`` files
  (metadata only, never read);
* allocates a private disposable state root and a freshly built allowlisted
  child environment; nothing is copied wholesale from the parent;
* provisions a missing ``.venv`` only through ``scripts/test.sh --prepare-only``
  (which exits before any post-install Python starts), re-audits it, and runs
  pytest only through ``scripts/test.sh --execute-only`` with ``--confcutdir``
  pinned to ``tests/multiuser`` and a private generated ini; PASS comes from
  the JUnit counts;
* runs ``--script`` only from reviewed F02-aware locations, from an immutable
  snapshot, under a deny-by-default Python ``NetworkGuard``.

Scopes F02 cannot make safe report NOT_RUN: explicit-Agent runs (no synthetic
credential compartment isolates OS keychains), browser transport, containment
and remote tiers. Python-level guards are not OS network containment.
This launcher stays stdlib-only and imports no product module.
"""
from __future__ import annotations

import argparse
import configparser
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import xml.etree.ElementTree as ET

SCHEMA = "hermes-webui/multiuser-launcher/1"
RESULT_PREFIX = "MULTIUSER_RESULT "
EXIT_CODES = {"PASS": 0, "FAIL": 1, "REFUSED": 2, "NOT_RUN": 3}
TIERS = ("unit", "native", "browser", "containment", "remote")
HOST_OS_PLATFORMS = {"linux": "linux", "macos": "darwin", "windows": "win32"}
BACKENDS = ("docker", "docker-desktop")
SUPPORTED_PYTHON = ((3, 11), (3, 12), (3, 13))
DEFAULT_CHILD_TIMEOUT = 3600
INTERRUPT_GRACE_SECONDS = 10.0
TERMINATE_GRACE_SECONDS = 5.0
SCRIPT_NOT_RUN_EXIT = 77
RUNNER_NOT_PREPARED_EXIT = 78  # scripts/test.sh --execute-only refused to provision
PYTEST_PLUGINS = ("pytest_timeout", "pytest_asyncio.plugin")
# Modules scripts/test.sh checks before it would install anything (plus pip,
# whose absence makes it rebuild). Static presence decides whether to prepare.
RUNNER_MODULES = (
    "cryptography", "mcp", "pytest", "pytest_asyncio", "pytest_shard",
    "pytest_timeout", "ruff", "yaml", "pip",
)
INSTALLED_AGENT_ROOTS = (
    "/usr/local/lib/hermes-agent",
    "/opt/hermes-agent",
    "/usr/local/hermes-agent",
    "/usr/local/share/hermes-agent",
)
SITE_AGENT_NAMES = ("run_agent.py", "run_agent", "hermes_cli", "cron", "hermes", "hermes_agent")
# Directories inside an explicit Agent checkout that the link walk skips.
CHECKOUT_WALK_SKIP = frozenset({".git", "venv", ".venv", "__pycache__", "node_modules"})
# --script admission: reviewed F02-aware locations only (repo-relative, POSIX).
ADMITTED_SCRIPT_PATTERNS = (
    re.compile(r"^tests/multiuser/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.py$"),
    re.compile(r"^tests/browser_multiuser_[a-z0-9_]+\.py$"),
)
# Base interpreters accepted as verified distribution builds (resolved paths).
_DISTRIBUTION_EXE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"^/opt/homebrew/Cellar/python@3\.(1[1-3])/[^/]+/Frameworks/Python\.framework/"
        r"Versions/3\.\1/bin/python3\.\1$",
        r"^/usr/local/Cellar/python@3\.(1[1-3])/[^/]+/Frameworks/Python\.framework/"
        r"Versions/3\.\1/bin/python3\.\1$",
        r"^/Library/Frameworks/Python\.framework/Versions/3\.(1[1-3])/bin/python3\.\1$",
        r"^/usr/bin/python3\.(1[1-3])$",
        r"^/usr/local/bin/python3\.(1[1-3])$",
        r"^/opt/hostedtoolcache/Python/3\.(1[1-3])\.\d+/(?:x64|arm64)/bin/python3\.\1$",
    )
)
_NATIVE_EXECUTABLE_MAGIC = (
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
)
WELL_KNOWN_PYTHON_DIRS = (
    "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
    "/Library/Frameworks/Python.framework/Versions/Current/bin",
)
_MARKER_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\([^()\n]*\))?\s*:[^\n]*$")
PASSTHROUGH_VARS = ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "NO_COLOR")
WINDOWS_PASSTHROUGH_VARS = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
_PASSTHROUGH_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{0,64}$")
_MIN_LEAK_VALUE_LEN = 8

# Interpreter-distribution startup hooks reviewed line by line, keyed by SHA-256.
# Anything else named sitecustomize/usercustomize is NOT_RUN until reviewed.
REVIEWED_INTERPRETER_HOOKS = {
    "7767e083377ba3a97a42bd199dac51f5ea3a71669f2dbebec011bd696f79ebb4": (
        "Homebrew python@3.13 sitecustomize (/opt/homebrew): sys.path and prefix "
        "normalization only; no network, credential or file reads"
    ),
}
# Executable .pth files from project test dependencies, keyed by (name, SHA-256).
REVIEWED_PTH_FILES = {}

CLAIMS = {
    "agent_source_pin": False,
    "native_clients": False,
    "browser_privacy": False,
    "os_containment": False,
    "external_provider": False,
}


class Outcome(Exception):
    """A terminal launcher decision with a stable reason code."""

    def __init__(self, status, code, detail):
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail


def refused(code, detail):
    return Outcome("REFUSED", code, detail)


def not_run(code, detail):
    return Outcome("NOT_RUN", code, detail)


def failed(code, detail):
    return Outcome("FAIL", code, detail)


class _Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


class _SignalState:
    """``run`` raises on a signal; ``spawn`` and ``teardown`` only record it.

    ``spawn`` covers process creation until ownership of the child is
    published, so a signal can never strand an unowned process group.
    """

    phase = "run"
    received = None


def _signal_handler(signum, _frame):
    _SignalState.received = signum
    if _SignalState.phase == "run":
        raise _Interrupted(signum)


# ── Result ───────────────────────────────────────────────────────────────────


class Result:
    def __init__(self):
        self.status = None
        self.tier = None
        self.mode = None
        self.agent = "none"
        self.reasons = []
        self.checks = []
        self.child_exit_code = None
        self.tests = None
        self.state = {"allocated": False, "root_removed": None}
        self.entry = {
            "isolated": bool(sys.flags.isolated),
            "no_site": bool(sys.flags.no_site),
            "startup_guarantee": (
                "launcher-isolated"
                if sys.flags.isolated and sys.flags.no_site
                else "initial-interpreter-unverified"
            ),
            "python": ".".join(str(part) for part in sys.version_info[:3]),
        }

    def check(self, name, status, detail=""):
        self.checks.append({"name": name, "status": status, "detail": detail})

    def reason(self, code, detail):
        self.reasons.append({"code": code, "detail": detail})

    def settle(self, status, code=None, detail=""):
        """Record an outcome; the most severe status wins (FAIL > REFUSED > NOT_RUN > PASS)."""
        rank = {"PASS": 0, "NOT_RUN": 1, "REFUSED": 2, "FAIL": 3}
        if self.status is None or rank[status] > rank[self.status]:
            self.status = status
        if code:
            self.reason(code, detail)

    def to_dict(self):
        status = self.status or "FAIL"
        return {
            "schema": SCHEMA,
            "status": status,
            "exit_code": EXIT_CODES[status],
            "tier": self.tier,
            "mode": self.mode,
            "agent": self.agent,
            "entry": self.entry,
            "reasons": self.reasons,
            "checks": self.checks,
            "child_exit_code": self.child_exit_code,
            "tests": self.tests,
            "state": self.state,
            "containment": {
                "python_network_guard": "helper-only",
                "os_network_sandbox": "not_provided",
            },
            "claims": dict(CLAIMS),
        }


# ── Paths ────────────────────────────────────────────────────────────────────


def _is_within(path, root):
    path = os.path.normcase(os.path.normpath(path))
    root = os.path.normcase(os.path.normpath(root))
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _is_link_like(st):
    if stat.S_ISLNK(st.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and getattr(st, "st_file_attributes", 0) & reparse)


def _walk_components(root, target):
    """lstat every component from ``root`` (exclusive) down to ``target``.

    Raises REFUSED unsafe_symlink for any link or junction and REFUSED
    path_missing when a component does not exist. Returns the final lstat.
    """
    rel = os.path.relpath(target, root)
    current = root
    st = os.lstat(root)
    if rel == os.curdir:
        return st
    for part in rel.split(os.sep):
        current = os.path.join(current, part)
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            raise refused("path_missing", f"{target} does not exist") from None
        except OSError as exc:
            raise refused("path_missing", f"{target} is not accessible: {exc.__class__.__name__}") from None
        if _is_link_like(st):
            raise refused("unsafe_symlink", f"{current} is a symbolic link or junction")
    return st


def _resolve_in_repo(raw, repo_root):
    if "\0" in raw:
        raise refused("usage", "path contains a NUL byte")
    candidate = raw if os.path.isabs(raw) else os.path.join(repo_root, raw)
    return os.path.normpath(candidate)


def _read_validated_file(path, expected, label, limit=8 * 1024 * 1024):
    """Read ``path`` through one no-follow descriptor that matches the validated lstat."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise refused("unsafe_symlink", f"{label} could not be opened without following links") from None
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise refused("unsafe_symlink", f"{label} changed during validation")
        if opened.st_size > limit:
            raise refused("script_invalid", f"{label} is larger than {limit} bytes")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def ensure_tree_without_links(root, skip=frozenset(), refuse=None):
    """Refuse links or junctions below ``root`` (never followed).

    ``refuse(entry)`` limits refusal to matching links; by default every link
    is refused. Directories are never entered through a link.
    """
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise refused("path_missing", f"{directory} cannot be listed: {exc.__class__.__name__}") from None
        for entry in entries:
            if entry.name in skip:
                continue
            st = entry.stat(follow_symlinks=False)
            if _is_link_like(st):
                if refuse is None or refuse(entry):
                    raise refused("unsafe_symlink", f"{entry.path} is a symbolic link or junction")
                continue
            if stat.S_ISDIR(st.st_mode):
                pending.append(entry.path)


def _collectable_link(entry):
    """Links pytest could follow while collecting: directories, conftests, packages, tests.

    Other linked files are left to the import guard, which refuses importing
    anything through a link.
    """
    name = entry.name
    try:
        if entry.is_dir(follow_symlinks=True):
            return True
    except OSError:
        return True
    return name in ("conftest.py", "__init__.py") or (
        name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
    )


def ensure_collection_safe(repo_root, path):
    """Refuse links pytest could import for ``path``: package and conftest chains and the tree."""
    st = _walk_components(repo_root, path)
    top = path if stat.S_ISDIR(st.st_mode) else os.path.dirname(path)
    rel = os.path.relpath(top, repo_root)
    current = repo_root
    for part in rel.split(os.sep):
        current = os.path.join(current, part)
        for name in ("__init__.py", "conftest.py"):
            candidate = os.path.join(current, name)
            if os.path.lexists(candidate) and _is_link_like(os.lstat(candidate)):
                raise refused("unsafe_symlink", f"{candidate} is a symbolic link or junction")
    if stat.S_ISDIR(st.st_mode):
        ensure_tree_without_links(path, skip=frozenset({"__pycache__"}), refuse=_collectable_link)


def script_admitted(path, repo_root):
    rel = os.path.relpath(path, repo_root).replace(os.sep, "/")
    return any(pattern.match(rel) for pattern in ADMITTED_SCRIPT_PATTERNS)


def validate_repo_script(raw, repo_root):
    """Validate ``--script`` and return (path, snapshot_bytes)."""
    path = _resolve_in_repo(raw, repo_root)
    if not _is_within(path, repo_root) or os.path.normpath(path) == os.path.normpath(repo_root):
        raise refused("path_outside_checkout", f"script {raw!r} is outside the checkout")
    parts = os.path.relpath(path, repo_root).split(os.sep)
    if parts[0] in (".venv", ".git"):
        raise refused("path_outside_checkout", f"script {raw!r} is inside {parts[0]}")
    st = _walk_components(repo_root, path)
    if not stat.S_ISREG(st.st_mode) or not path.endswith(".py"):
        raise refused("script_invalid", f"script {raw!r} is not a regular .py file")
    return path, _read_validated_file(path, st, f"script {raw!r}")


def validate_test_path(arg, repo_root):
    path_part = arg.split("::", 1)[0]
    if not path_part:
        raise refused("pytest_arg_disallowed", f"positional {arg!r} has no path")
    path = _resolve_in_repo(path_part, repo_root)
    tests_root = os.path.join(repo_root, "tests", "multiuser")
    if not _is_within(path, repo_root):
        raise refused("path_outside_checkout", f"test path {path_part!r} is outside the checkout")
    if not _is_within(path, tests_root):
        raise refused("pytest_arg_disallowed", f"test path {path_part!r} is outside tests/multiuser")
    ensure_collection_safe(repo_root, path)


_NOARG_PYTEST_FLAGS = frozenset(
    {
        "-q", "--quiet", "-qq", "-v", "--verbose", "-vv", "-vvv", "-x", "--exitfirst",
        "-s", "-l", "--showlocals", "--strict-markers", "--no-header", "--no-summary",
    }
)
_CHOICE_PYTEST_FLAGS = {
    "--tb": frozenset({"auto", "long", "short", "line", "native", "no"}),
    "--color": frozenset({"yes", "no", "auto"}),
    "--capture": frozenset({"no", "sys", "fd", "tee-sys"}),
}
_NUMERIC_PYTEST_FLAGS = {
    "--maxfail": re.compile(r"^\d{1,6}$"),
    "--durations": re.compile(r"^\d{1,6}$"),
    "--timeout": re.compile(r"^\d{1,6}(\.\d{1,3})?$"),
}
_REPORT_CHARS_RE = re.compile(r"^-r[fEsxXpPaAwN]{1,12}$")


def validate_pytest_args(args, repo_root):
    """Return pytest args after the fail-closed allowlist; default scope is tests/multiuser."""
    out = []
    positional = 0
    i = 0
    while i < len(args):
        arg = args[i]
        if "\0" in arg:
            raise refused("pytest_arg_disallowed", "argument contains a NUL byte")
        if arg in _NOARG_PYTEST_FLAGS or _REPORT_CHARS_RE.match(arg):
            out.append(arg)
        elif arg in ("-k", "-m"):
            if i + 1 >= len(args):
                raise refused("pytest_arg_disallowed", f"{arg} needs a value")
            out.extend((arg, args[i + 1]))
            i += 1
        elif arg[:2] in ("-k", "-m") and len(arg) > 2 and not arg.startswith("--"):
            out.append(arg)
        elif arg.startswith("--") and "=" in arg:
            name, value = arg.split("=", 1)
            if name in _CHOICE_PYTEST_FLAGS and value in _CHOICE_PYTEST_FLAGS[name]:
                out.append(arg)
            elif name in _NUMERIC_PYTEST_FLAGS and _NUMERIC_PYTEST_FLAGS[name].match(value):
                out.append(arg)
            else:
                raise refused("pytest_arg_disallowed", f"pytest option {name} is not allowed")
        elif arg.startswith("-"):
            raise refused("pytest_arg_disallowed", f"pytest option {arg.split('=', 1)[0]} is not allowed")
        else:
            validate_test_path(arg, repo_root)
            out.append(arg)
            positional += 1
        i += 1
    if not positional:
        tests_root = os.path.join(repo_root, "tests", "multiuser")
        ensure_collection_safe(repo_root, tests_root)
        out.append(os.path.join("tests", "multiuser"))
    return out


def installed_agent_roots(operator_home, parent_env):
    """Operator and system locations an installed Agent occupies (never an explicit source)."""
    roots = [
        os.path.join(operator_home, ".hermes"),
        os.path.join(operator_home, "hermes-agent"),
        os.path.join(operator_home, ".local", "share", "hermes-agent"),
    ]
    xdg_data = parent_env.get("XDG_DATA_HOME", "")
    if os.path.isabs(xdg_data):
        roots.append(os.path.join(xdg_data, "hermes-agent"))
    for name in ("LOCALAPPDATA", "APPDATA"):
        value = parent_env.get(name, "")
        if os.path.isabs(value):
            roots.append(os.path.join(value, "hermes"))
    roots.extend(INSTALLED_AGENT_ROOTS)
    return roots


def validate_agent_checkout(raw, repo_root, operator_home, parent_env=None):
    """Validate an explicit Agent checkout and return (path, (dev, ino))."""
    if "\0" in raw:
        raise refused("usage", "agent checkout contains a NUL byte")
    path = os.path.normpath(os.path.abspath(raw))
    installed = installed_agent_roots(operator_home, os.environ if parent_env is None else parent_env)
    if any(_is_within(path, root) for root in installed):
        raise refused("installed_agent_location", f"{path} is an installed or operator Agent location")
    if os.path.normcase(path) == os.path.normcase(
        os.path.join(os.path.dirname(repo_root), "hermes-agent")
    ):
        raise refused("implicit_discovery_location", f"{path} is the implicit sibling discovery location")
    if _is_within(path, repo_root) or _is_within(repo_root, path):
        raise refused("agent_checkout_invalid", f"{path} overlaps the WebUI checkout")
    if not os.path.lexists(path):
        raise refused("path_missing", f"agent checkout {path} does not exist")
    canonical = os.path.realpath(path)
    if os.path.normcase(canonical) != os.path.normcase(path):
        raise refused("unsafe_symlink", f"agent checkout passes through a link; pass {canonical}")
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise refused("agent_checkout_invalid", f"{path} is not a directory")
    entry = os.path.join(path, "run_agent.py")
    try:
        entry_st = os.lstat(entry)
    except OSError:
        raise refused("agent_checkout_invalid", f"{path} has no run_agent.py") from None
    if not stat.S_ISREG(entry_st.st_mode):
        raise refused("agent_checkout_invalid", f"{entry} is not a regular file")
    ensure_tree_without_links(path, skip=CHECKOUT_WALK_SKIP)
    return path, (st.st_dev, st.st_ino)


_DIR_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_private_dir_chain(base, target):
    """Open ``target`` below ``base`` one component at a time, never following links.

    Each directory below ``base`` must be owned by the current user and not
    writable by group or others. Returns a descriptor for ``target``.
    """
    fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        rel = os.path.relpath(target, base)
        if rel != os.curdir:
            for part in rel.split(os.sep):
                try:
                    child = os.open(part, _DIR_OPEN_FLAGS, dir_fd=fd)
                except OSError as exc:
                    reason = errno.errorcode.get(exc.errno, str(exc.errno))
                    raise refused("report_path_disallowed", f"{part!r} is not a real directory ({reason})") from None
                os.close(fd)
                fd = child
                st = os.fstat(fd)
                if st.st_uid != os.getuid() or st.st_mode & 0o022:
                    raise refused("report_path_disallowed", f"{part!r} is not private to the current user")
        return fd
    except BaseException:
        os.close(fd)
        raise


class ReportTarget:
    """A new report file under the trusted per-user temp base, written via an anchored parent.

    Existing files are never opened or truncated; the parent directory is
    held by descriptor from validation to write, and the write is refused if
    the parent path no longer names that same directory.
    """

    def __init__(self, raw, operator_home):
        if "\0" in raw:
            raise refused("usage", "--report contains a NUL byte")
        if os.name != "posix":
            raise refused("unsupported_platform", "--report needs descriptor-anchored writes")
        base = trusted_temp_base(operator_home)
        path = os.path.abspath(raw)
        self.name = os.path.basename(path)
        if self.name in ("", os.curdir, os.pardir):
            raise refused("report_path_disallowed", "--report must name a file")
        parent = os.path.realpath(os.path.dirname(path))
        if not _is_within(parent, base):
            raise refused("report_path_disallowed", f"--report must be inside the per-user temp area {base}")
        self._fd = _open_private_dir_chain(base, parent)
        try:
            os.stat(self.name, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            self.close()
            raise refused("report_path_disallowed", "--report names an existing file; it is never overwritten")
        self.parent = parent
        self.path = os.path.join(parent, self.name)

    def write(self, text):
        anchor = os.fstat(self._fd)
        try:
            current = os.lstat(self.parent)
        except OSError:
            current = None
        if current is None or _is_link_like(current) or (
            (current.st_dev, current.st_ino) != (anchor.st_dev, anchor.st_ino)
        ):
            raise OSError(errno.ESTALE, "the report directory was replaced after validation; nothing was written")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.name, flags, 0o600, dir_fd=self._fd)
        try:
            os.write(fd, text.encode())
        finally:
            os.close(fd)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def validate_manifest(raw):
    if "\0" in raw:
        raise refused("usage", "deployment manifest contains a NUL byte")
    path = os.path.abspath(raw)
    try:
        st = os.lstat(path)
    except OSError:
        raise not_run("deployment_manifest_required", "deployment manifest does not exist") from None
    if _is_link_like(st):
        raise refused("unsafe_symlink", "deployment manifest is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise refused("path_missing", "deployment manifest is not a regular file")
    return path


def dotenv_hits(*roots):
    """List ``.env`` entries in each root and its ancestors (lexists only; never read)."""
    hits = []
    for root in roots:
        current = os.path.normpath(root)
        while True:
            candidate = os.path.join(current, ".env")
            if os.path.lexists(candidate) and candidate not in hits:
                hits.append(candidate)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
    return hits


def implicit_agent_hits(repo_root, path_dirs):
    """Installed-Agent locations the product's startup discovery could pick up."""
    parent = os.path.dirname(repo_root)
    hits = [p for p in (os.path.join(parent, "hermes-agent"),) + INSTALLED_AGENT_ROOTS if os.path.lexists(p)]
    markers = ("run_agent.py", os.path.join("cron", "jobs.py"), "hermes_cli")
    if any(os.path.lexists(os.path.join(parent, marker)) for marker in markers):
        hits.append(parent)
    for directory in path_dirs:
        for name in ("hermes", "hermes.exe", "hermes.cmd"):
            candidate = os.path.join(directory, name)
            if os.path.lexists(candidate):
                hits.append(candidate)
    return hits


# ── Interpreter and .venv provenance (static; nothing is executed) ──────────


class BaseInterpreter:
    def __init__(self, exe, real, prefix, version, stdlib):
        self.exe = exe
        self.real = real
        self.prefix = prefix
        self.version = version
        self.stdlib = stdlib

    @property
    def site_packages(self):
        return os.path.realpath(os.path.join(self.stdlib, "site-packages"))


class Venv:
    def __init__(self, root, python, version, site_dirs, base):
        self.root = root
        self.python = python
        self.version = version
        self.site_dirs = site_dirs
        self.base = base


def _sha256(path, limit=4 * 1024 * 1024):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        total = 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise not_run("venv_provenance_unknown", f"{path} is too large to review")
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _version_text(version):
    return f"{version[0]}.{version[1]}"


def inspect_base_interpreter(exe, operator_home):
    """Locate a base interpreter's version and stdlib from its files alone."""
    if not os.path.isabs(exe):
        raise not_run("unsupported_python", f"interpreter path {exe!r} is not absolute")
    real = os.path.realpath(exe)
    try:
        st = os.stat(real)
    except OSError:
        raise not_run("unsupported_python", f"interpreter {exe} does not exist") from None
    if not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
        raise not_run("unsupported_python", f"interpreter {exe} is not an executable file")
    if _is_within(real, operator_home):
        raise not_run("unsupported_python", f"interpreter {exe} lives inside the operator home")
    prefix = os.path.dirname(os.path.dirname(real))
    named = re.match(r"^python(\d+)\.(\d+)$", os.path.basename(real))
    candidates = [(int(named.group(1)), int(named.group(2)))] if named else list(SUPPORTED_PYTHON)
    found = []
    for version in candidates:
        stdlib = os.path.join(prefix, "lib", f"python{_version_text(version)}")
        if os.path.isfile(os.path.join(stdlib, "os.py")):
            found.append((version, stdlib))
    if len(found) != 1:
        raise not_run("unsupported_python", f"cannot statically identify the stdlib of {exe}")
    version, stdlib = found[0]
    if version not in SUPPORTED_PYTHON:
        raise not_run("unsupported_python", f"{exe} is Python {_version_text(version)}, not 3.11-3.13")
    verify_distribution(real, stdlib, version)
    return BaseInterpreter(exe, real, prefix, version, stdlib)


def verify_distribution(real, stdlib, version):
    """Require a native interpreter binary at a known distribution location.

    A name plus an adjacent ``os.py`` proves nothing, so the resolved path
    must match a reviewed distribution layout for the same version, the file
    must start with ELF or Mach-O magic, and the binary and stdlib must be
    owned by root or the current user and not writable by group or others.
    Nothing is executed.
    """
    matched = None
    for pattern in _DISTRIBUTION_EXE_PATTERNS:
        match = pattern.match(real)
        if match:
            matched = match
            break
    if matched is None or matched.group(1) != str(version[1]):
        raise not_run("venv_provenance_unknown", f"{real} is not a verified Python distribution build")
    try:
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise not_run("venv_provenance_unknown", f"{real} cannot be opened without following links") from None
    try:
        magic = os.read(fd, 4)
    finally:
        os.close(fd)
    if magic not in _NATIVE_EXECUTABLE_MAGIC:
        raise not_run("venv_provenance_unknown", f"{real} is not a native executable")
    for path in (real, stdlib):
        st = os.stat(path)
        if st.st_uid not in (0, os.getuid()) or st.st_mode & 0o022:
            raise not_run("venv_provenance_unknown", f"{path} is writable by other users")


def scan_interpreter_hooks(base, result=None):
    """Refuse unreviewed sitecustomize/usercustomize in the base stdlib search path."""
    problems = []
    zipped = os.path.join(base.prefix, "lib", f"python{base.version[0]}{base.version[1]}.zip")
    if os.path.lexists(zipped):
        problems.append(f"{zipped} may carry startup hooks")
    for directory in (base.stdlib, os.path.join(base.stdlib, "lib-dynload")):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            low = name.lower()
            if not low.startswith(("sitecustomize", "usercustomize")):
                continue
            path = os.path.join(directory, name)
            if name == "sitecustomize.py" and not _is_link_like(os.lstat(path)):
                digest = _sha256(path)
                if digest in REVIEWED_INTERPRETER_HOOKS:
                    if result is not None:
                        result.check(
                            "interpreter_hook_reviewed",
                            "PASS",
                            f"{path}: {REVIEWED_INTERPRETER_HOOKS[digest]}",
                        )
                    continue
                problems.append(f"{path} is an unreviewed startup hook (sha256 {digest})")
            else:
                problems.append(f"{path} is an unreviewed startup hook")
    if problems:
        raise not_run("venv_provenance_unknown", "; ".join(problems))


def scan_site_packages(site_dir):
    """Refuse site-packages content that runs code at startup or exposes an Agent.

    ``.pth`` path entries are refused outright, even inside the venv: an added
    directory could carry its own sitecustomize or Agent sources unaudited.
    """
    problems = []
    agent_hits = []
    try:
        entries = sorted(os.listdir(site_dir))
    except OSError:
        raise not_run("venv_provenance_unknown", f"{site_dir} cannot be listed") from None
    for name in entries:
        low = name.lower()
        path = os.path.join(site_dir, name)
        if name in SITE_AGENT_NAMES:
            agent_hits.append(path)
            continue
        if low.startswith(("sitecustomize", "usercustomize")):
            problems.append(f"{path} is a startup hook")
        elif low.endswith(".egg-link") or low.startswith("__editable__"):
            problems.append(f"{path} is an editable install")
        elif low.endswith(".pth"):
            st = os.lstat(path)
            if _is_link_like(st) or not stat.S_ISREG(st.st_mode) or st.st_size > 256 * 1024:
                problems.append(f"{path} is not a small regular .pth file")
                continue
            with open(path, "rb") as handle:
                raw = handle.read()
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeDecodeError:
                problems.append(f"{path} is not UTF-8")
                continue
            executable = False
            for line in lines:
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                if text.startswith(("import ", "import\t")):
                    executable = True
                    continue
                problems.append(f"{path} extends the import path ({text[:80]!r})")
                break
            if executable:
                digest = hashlib.sha256(raw).hexdigest()
                if REVIEWED_PTH_FILES.get(name) != digest:
                    problems.append(f"{path} runs code at startup (sha256 {digest})")
    if agent_hits:
        raise not_run("implicit_agent_discoverable", "site-packages exposes Agent sources: " + ", ".join(agent_hits))
    if problems:
        raise not_run("venv_provenance_unknown", "; ".join(problems))


def _read_pyvenv_cfg(path):
    try:
        st = os.lstat(path)
    except OSError:
        raise not_run("venv_provenance_unknown", "pyvenv.cfg is missing") from None
    if _is_link_like(st) or not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024:
        raise not_run("venv_provenance_unknown", "pyvenv.cfg is not a small regular file")
    values = {}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip().lower()] = value.strip()
    return values


def inspect_venv(repo_root, operator_home, result=None):
    """Statically validate the repo .venv; raise NOT_RUN for anything unknown."""
    root = os.path.join(repo_root, ".venv")
    try:
        st = os.lstat(root)
    except OSError:
        raise not_run("venv_unavailable", "repo .venv does not exist") from None
    if _is_link_like(st):
        raise not_run("venv_provenance_unknown", "repo .venv is a symbolic link")
    if not stat.S_ISDIR(st.st_mode):
        raise not_run("venv_provenance_unknown", "repo .venv is not a directory")
    if os.name == "posix" and (st.st_uid != os.getuid() or st.st_mode & 0o022):
        raise not_run("venv_provenance_unknown", "repo .venv is not private to the current user")
    cfg = _read_pyvenv_cfg(os.path.join(root, "pyvenv.cfg"))
    if cfg.get("include-system-site-packages", "").lower() != "false":
        raise not_run("venv_provenance_unknown", "repo .venv includes system site-packages")
    match = re.match(r"^(\d+)\.(\d+)", cfg.get("version", "") or cfg.get("version_info", ""))
    if not match:
        raise not_run("venv_provenance_unknown", "pyvenv.cfg has no version")
    version = (int(match.group(1)), int(match.group(2)))
    if version not in SUPPORTED_PYTHON:
        raise not_run("unsupported_python", f"repo .venv is Python {_version_text(version)}, not 3.11-3.13")
    home = cfg.get("home", "")
    if not os.path.isabs(home):
        raise not_run("venv_provenance_unknown", "pyvenv.cfg home is not absolute")
    python = os.path.join(root, "bin", "python")
    if not os.path.lexists(python):
        raise not_run("venv_provenance_unknown", "repo .venv has no bin/python")
    target = os.path.realpath(python)
    base_exe = None
    for name in (f"python{_version_text(version)}", "python3", "python"):
        candidate = os.path.join(home, name)
        if os.path.lexists(candidate) and os.path.realpath(candidate) == target:
            base_exe = candidate
            break
    if base_exe is None:
        raise not_run("venv_provenance_unknown", "repo .venv python does not resolve into pyvenv.cfg home")
    base = inspect_base_interpreter(base_exe, operator_home)
    if base.version != version:
        raise not_run("venv_provenance_unknown", "repo .venv version does not match its base interpreter")
    scan_interpreter_hooks(base, result)
    real_root = os.path.realpath(root)
    site_dirs = []
    for libdir in ("lib", "lib64"):
        site = os.path.join(root, libdir, f"python{_version_text(version)}", "site-packages")
        if not os.path.lexists(os.path.join(root, libdir)):
            continue
        real_site = os.path.realpath(site)
        if not _is_within(real_site, real_root):
            raise not_run("venv_provenance_unknown", f"{site} resolves outside the .venv")
        if os.path.isdir(real_site) and real_site not in site_dirs:
            site_dirs.append(real_site)
    if not site_dirs:
        raise not_run("venv_provenance_unknown", "repo .venv has no site-packages")
    for site in site_dirs:
        scan_site_packages(site)
    for name in ("hermes", "hermes.exe"):
        if os.path.lexists(os.path.join(root, "bin", name)):
            raise not_run("implicit_agent_discoverable", "repo .venv exposes a 'hermes' launcher")
    return Venv(root, python, version, site_dirs, base)


def missing_runner_modules(venv):
    """Modules scripts/test.sh needs that no audited site-packages dir provides."""
    missing = []
    for module in RUNNER_MODULES:
        present = False
        for site in venv.site_dirs:
            if os.path.isfile(os.path.join(site, module, "__init__.py")) or os.path.isfile(
                os.path.join(site, module + ".py")
            ):
                present = True
                break
        if not present:
            missing.append(module)
    return missing


def select_base_python(parent_env, operator_home):
    """Pick a verified 3.11-3.13 distribution interpreter for a first .venv, statically."""
    explicit = parent_env.get("HERMES_WEBUI_TEST_PYTHON", "").strip()
    if explicit:
        return inspect_base_interpreter(explicit, operator_home)
    directories = [d for d in parent_env.get("PATH", "").split(os.pathsep) if d and os.path.isabs(d)]
    directories.extend(d for d in WELL_KNOWN_PYTHON_DIRS if d not in directories)
    for name in ("python3.13", "python3.12", "python3.11", "python3"):
        for directory in directories:
            candidate = os.path.join(directory, name)
            if not os.path.isfile(candidate):
                continue
            try:
                return inspect_base_interpreter(candidate, operator_home)
            except Outcome:
                continue
    raise not_run("unsupported_python", "no verified Python 3.11-3.13 distribution build was found")


def browser_runtime_ready(venv):
    for site in venv.site_dirs:
        browsers = os.path.join(site, "playwright", "driver", "package", ".local-browsers")
        if os.path.isdir(browsers) and os.listdir(browsers):
            return True
    return False


# ── Disposable state ─────────────────────────────────────────────────────────


def trusted_temp_base(operator_home):
    """A temp base the launcher trusts; inherited TMPDIR is never used."""
    candidates = []
    if sys.platform == "darwin":
        try:
            candidates.append(os.confstr(65537))  # _CS_DARWIN_USER_TEMP_DIR
        except (ValueError, OSError):
            pass
        candidates.append("/private/tmp")
    elif os.name == "posix":
        candidates.append("/tmp")
    else:
        candidates.append(tempfile.gettempdir())
    for candidate in candidates:
        if not candidate:
            continue
        real = os.path.realpath(candidate)
        try:
            st = os.stat(real)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        if os.name == "posix":
            shared = st.st_mode & 0o022
            if st.st_uid == os.getuid():
                if shared and not st.st_mode & stat.S_ISVTX:
                    continue
            elif st.st_uid != 0 or (shared and not st.st_mode & stat.S_ISVTX):
                continue
        if _is_within(real, operator_home):
            raise refused("real_home_path", f"trusted temp base {real} is inside the operator home")
        return real
    raise refused("unsupported_platform", "no trusted temporary directory is available")


def _open_dir_entry(name, dir_fd):
    """Open a child directory without following links, unlocking a 000 directory once."""
    try:
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
    except PermissionError as denied:
        try:
            os.chmod(name, 0o700, dir_fd=dir_fd, follow_symlinks=False)
        except (NotImplementedError, OSError):
            raise denied from None
        return os.open(name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)


def _clear_directory_fd(dir_fd):
    """Delete everything inside the directory ``dir_fd`` refers to, never following links."""
    st = os.fstat(dir_fd)
    if st.st_uid == os.getuid() and st.st_mode & 0o700 != 0o700:
        os.fchmod(dir_fd, stat.S_IMODE(st.st_mode) | 0o700)  # read-only launcher dirs, or a child's chmod
    scan_fd = os.open(os.curdir, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
    try:
        with os.scandir(scan_fd) as iterator:
            names = [entry.name for entry in iterator]
    finally:
        os.close(scan_fd)
    for name in names:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            child = _open_dir_entry(name, dir_fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    raise OSError(errno.ESTALE, f"{name} changed during cleanup")
                _clear_directory_fd(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=dir_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)


class StateRoot:
    """A private 0700 directory, anchored by descriptor and removed on every exit.

    On POSIX, cleanup walks the allocation-time descriptor, so replacing or
    moving the path cannot redirect deletion to other content; the final rmdir
    goes through the parent descriptor and is confirmed against the anchor.
    """

    def __init__(self, base):
        self._fd = self._parent_fd = None
        self._ident = None
        self._before_unlink = None  # self-test barrier between identity check and rmdir
        try:
            if os.name == "posix":
                self._parent_fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            self.path = tempfile.mkdtemp(prefix="hermes-mu-", dir=base)
            self.name = os.path.basename(self.path)
            if os.name == "posix":
                self._fd = os.open(self.name, _DIR_OPEN_FLAGS, dir_fd=self._parent_fd)
                st = os.fstat(self._fd)
                lst = os.stat(self.name, dir_fd=self._parent_fd, follow_symlinks=False)
            else:
                st = lst = os.lstat(self.path)
            if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino) or not stat.S_ISDIR(lst.st_mode):
                raise refused("unsafe_symlink", "state root changed while it was allocated")
            if os.name == "posix" and (lst.st_uid != os.getuid() or lst.st_mode & 0o077):
                raise refused("unsafe_symlink", "state root is not private")
            self._ident = (st.st_dev, st.st_ino)
        except BaseException:
            self._close()
            raise

    def _close(self):
        for attr in ("_fd", "_parent_fd"):
            fd = getattr(self, attr)
            if fd is not None:
                os.close(fd)
                setattr(self, attr, None)

    def intact(self):
        try:
            st = os.lstat(self.path)
        except OSError:
            return False
        return not _is_link_like(st) and (st.st_dev, st.st_ino) == self._ident

    def remove(self):
        """Remove the allocated directory; anything else at its path is left untouched."""
        try:
            if os.name != "posix":
                return self._remove_by_path()
            try:
                _clear_directory_fd(self._fd)
            except OSError as exc:
                raise failed("teardown_failed", f"state root contents could not be removed: {exc}") from None
            if self._before_unlink is not None:
                self._before_unlink()
            try:
                entry = os.stat(self.name, dir_fd=self._parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                raise failed(
                    "teardown_failed",
                    "state root was moved away; its contents were cleared through the anchored descriptor",
                ) from None
            if _is_link_like(entry) or (entry.st_dev, entry.st_ino) != self._ident:
                raise failed(
                    "teardown_failed",
                    "state root was replaced; the replacement was left untouched and the original cleared",
                )
            try:
                os.rmdir(self.name, dir_fd=self._parent_fd)
            except OSError as exc:
                raise failed("teardown_failed", f"state root could not be removed: {exc}") from None
            # An unlinked directory refuses new entries; if this succeeds, the
            # rmdir above removed a swapped-in empty directory, not the anchor.
            try:
                os.mkdir(".mu-unlink-probe", dir_fd=self._fd)
            except FileNotFoundError:
                return True
            except OSError as exc:
                raise failed("teardown_failed", f"state root removal could not be confirmed: {exc}") from None
            os.rmdir(".mu-unlink-probe", dir_fd=self._fd)
            raise failed("teardown_failed", "the removed entry was not the anchored state root")
        finally:
            self._close()

    def _remove_by_path(self):
        if not os.path.lexists(self.path):
            return True
        if not self.intact():
            raise failed("teardown_failed", "state root was replaced; it was not deleted")
        shutil.rmtree(self.path)
        return not os.path.lexists(self.path)


def create_layout(state_root, helper):
    layout = helper.disposable_layout(state_root)
    files = {"HERMES_CONFIG_PATH", "GIT_CONFIG_GLOBAL", "NETRC", "AWS_CONFIG_FILE",
             "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG", "NPM_CONFIG_USERCONFIG"}
    for var, path in layout.items():
        target = os.path.dirname(path) if var in files else path
        os.makedirs(target, mode=0o700, exist_ok=True)
    fd = os.open(layout["GIT_CONFIG_GLOBAL"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.makedirs(os.path.join(state_root, "launcher"), mode=0o700, exist_ok=True)
    return layout


def child_path_dirs(repo_root):
    if os.name != "posix":
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        return [os.path.join(system_root, "System32"), system_root]
    dirs = [os.path.join(repo_root, ".venv", "bin")]
    dirs.extend(d for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin") if os.path.isdir(d))
    return dirs


def build_child_env(parent_env, layout, *, helper, state_root, repo_root, tier, agent_checkout,
                    venv_python, path_dirs, extra=None):
    """Build the child environment from scratch; only allowlisted values pass through."""
    env = dict(layout)
    env.update(
        {
            "PATH": os.pathsep.join(path_dirs),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "HERMES_WEBUI_HOST": "127.0.0.1",
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
            "HERMES_WEBUI_PYTHON": venv_python,
            helper.STATE_ROOT_VAR: state_root,
            helper.TIER_VAR: tier,
            helper.REPO_ROOT_VAR: repo_root,
        }
    )
    if agent_checkout:
        env["HERMES_WEBUI_AGENT_DIR"] = agent_checkout
        env[helper.AGENT_MODE_VAR] = "explicit"
        env[helper.AGENT_CHECKOUT_VAR] = agent_checkout
    else:
        env["HERMES_WEBUI_AGENT_DIR"] = os.path.join(state_root, "agent-absent")
        env[helper.AGENT_MODE_VAR] = "none"
    if os.name != "posix":
        env[helper.OPERATOR_HOME_VAR] = helper.operator_home()
    passthrough = PASSTHROUGH_VARS + (WINDOWS_PASSTHROUGH_VARS if os.name != "posix" else ())
    for name in passthrough:
        value = parent_env.get(name)
        if value is not None and (name in WINDOWS_PASSTHROUGH_VARS or _PASSTHROUGH_VALUE_RE.match(value)):
            env[name] = value
    env.update(extra or {})
    return env


def find_secret_leaks(parent_env, child_env, helper, repo_root=None):
    """Names (never values) of parent secret-like variables whose value reached the child.

    A value that is the checkout path or one of its ancestors is not counted:
    the checkout path legitimately appears in the child environment.
    """
    leaks = []
    for name, value in parent_env.items():
        if not helper.is_secret_like_name(name) or len(value) < _MIN_LEAK_VALUE_LEN:
            continue
        if repo_root and os.path.isabs(value) and _is_within(repo_root, value):
            continue
        for child_name, child_value in child_env.items():
            if value in child_value:
                leaks.append(f"{name}->{child_name}")
    return leaks


def checked_child_env(parent_env, child_env, helper):
    leaks = find_secret_leaks(parent_env, child_env, helper, child_env.get(helper.REPO_ROOT_VAR))
    if leaks:
        raise refused("secret_leak", "parent secret-like values reached the child: " + ", ".join(leaks))
    problems = helper.verify_hermetic_environment(child_env)
    if problems:
        raise failed("launcher_error", "child environment failed verification: " + "; ".join(problems))
    return child_env


# ── Child processes ──────────────────────────────────────────────────────────


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(proc, signum, wait):
    """Signal the owned process group and wait until it is gone or ``wait`` elapses."""
    if os.name != "posix":
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(wait)
        except subprocess.TimeoutExpired:
            pass
        return proc.poll() is not None
    pgid = proc.pid
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        proc.poll()
        return True
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        proc.poll()
        if not _group_alive(pgid):
            return True
        time.sleep(0.05)
    proc.poll()
    return not _group_alive(pgid)


def terminate_group(proc, first_signal=None, grace=INTERRUPT_GRACE_SECONDS):
    """SIGINT (optional) → SIGTERM → SIGKILL the owned group; True when it is gone."""
    steps = []
    if first_signal is not None:
        steps.append((first_signal, grace))
    steps.append((signal.SIGTERM, TERMINATE_GRACE_SECONDS))
    steps.append((getattr(signal, "SIGKILL", signal.SIGTERM), TERMINATE_GRACE_SECONDS))
    for signum, wait in steps:
        if _signal_group(proc, signum, wait):
            break
    try:
        proc.wait(TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    return os.name != "posix" or not _group_alive(proc.pid)


def run_child(cmd, *, env, cwd, timeout, result=None, label="child", after_spawn=None):
    """Run ``cmd`` in its own process group with inherited stdio and bounded waits.

    A signal that arrives while the child is being created is deferred until
    the child is owned here, and the owned group is terminated on every exit.
    ``after_spawn`` is a self-test seam called at the ownership boundary.
    """
    kwargs = {"env": env, "cwd": cwd, "stdin": subprocess.DEVNULL, "close_fds": True}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    _SignalState.phase = "spawn"
    try:
        proc = subprocess.Popen(cmd, **kwargs)
    finally:
        _SignalState.phase = "run"
    outcome = code = None
    gone = True
    try:
        _SignalState.phase = "spawn"
        try:
            if after_spawn is not None:
                after_spawn(proc)
        finally:
            _SignalState.phase = "run"
        if _SignalState.received is not None:
            raise _Interrupted(_SignalState.received)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = failed("child_timeout", f"{label} exceeded {timeout}s")
                break
            try:
                code = proc.wait(timeout=min(remaining, 0.5))
                break
            except subprocess.TimeoutExpired:
                continue
    except _Interrupted as exc:
        outcome = failed("interrupted", f"signal {exc.signum} received")
    finally:
        _SignalState.phase = "teardown"
        try:
            leftover = proc.poll() is None or (os.name == "posix" and _group_alive(proc.pid))
            if leftover:
                interrupted = outcome is not None and outcome.code == "interrupted"
                gone = terminate_group(proc, first_signal=signal.SIGINT if interrupted else None)
                if result is not None and outcome is None:
                    result.check("leftover_descendants_terminated", "PASS" if gone else "FAIL", label)
        finally:
            _SignalState.phase = "run"
    if outcome is not None:
        outcome.detail += f"; owned group terminated={gone}"
        raise outcome
    if not gone:
        raise failed("launcher_error", f"{label} left processes that could not be terminated")
    return code


def parse_junit(path):
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if _is_link_like(st) or not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024 * 1024:
        return None
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if root.tag not in ("testsuite", "testsuites") or not suites:
        return None
    totals = {"total": 0, "failed": 0, "errors": 0, "skipped": 0}
    try:
        for suite in suites:
            totals["total"] += int(suite.get("tests", "0"))
            totals["failed"] += int(suite.get("failures", "0"))
            totals["errors"] += int(suite.get("errors", "0"))
            totals["skipped"] += int(suite.get("skipped", "0"))
    except ValueError:
        return None
    totals["passed"] = totals["total"] - totals["failed"] - totals["errors"] - totals["skipped"]
    return totals


def judge_pytest(exit_code, counts):
    """PASS only for executed, non-skipped, all-green JUnit evidence."""
    if exit_code == 5:
        return failed("no_tests_collected", "pytest collected no tests")
    if exit_code != 0:
        return failed("child_failed", f"pytest exited {exit_code}")
    if counts is None:
        return failed("junit_unparseable", "pytest exited 0 without a parseable JUnit report")
    if counts["total"] == 0:
        return failed("no_tests_collected", "the JUnit report has no tests")
    if counts["failed"] or counts["errors"]:
        return failed("child_failed", "the JUnit report has failures despite exit 0")
    if counts["skipped"]:
        return not_run("tests_skipped", f"{counts['skipped']} of {counts['total']} tests were skipped")
    return None


# ── Selection ────────────────────────────────────────────────────────────────


class Selection:
    def __init__(self, tier, mode, agent_mode):
        self.tier = tier
        self.mode = mode
        self.agent_mode = agent_mode


def resolve_selection(args, passthrough):
    """Validate option combinations and return the tier/mode; no filesystem access."""
    if args.self_test:
        others = [args.no_agent, args.agent_checkout, args.script, args.tier, args.host_os,
                  args.backend, args.deployment_manifest]
        if any(others) or passthrough:
            raise refused("conflicting_options", "--self-test takes no tier, source or pytest options")
        return Selection("self-test", "self-test", "none")
    if args.no_agent and args.agent_checkout:
        raise refused("conflicting_options", "--no-agent and --agent-checkout are mutually exclusive")
    tier = args.tier
    if tier is None:
        if args.script:
            tier = "browser"
        elif args.agent_checkout:
            tier = "native"
        elif args.no_agent:
            tier = "unit"
        else:
            raise refused("usage", "choose --self-test, --no-agent, --agent-checkout or --tier")
    if (args.host_os or args.backend) and tier != "containment":
        raise refused("conflicting_options", "--host-os/--backend apply only to --tier containment")
    if args.deployment_manifest and tier != "remote":
        raise refused("conflicting_options", "--deployment-manifest applies only to --tier remote")
    if tier == "unit" and args.agent_checkout:
        raise refused("conflicting_options", "the unit tier never uses an Agent checkout")
    if tier == "native" and args.no_agent:
        raise refused("conflicting_options", "the native tier needs an explicit Agent checkout")
    if tier == "browser" and not args.script:
        raise refused("usage", "the browser tier runs a repo-owned --script")
    if tier in ("containment", "remote") and args.script:
        raise refused("conflicting_options", f"the {tier} tier runs pytest, not --script")
    if tier == "containment" and not (args.host_os and args.backend):
        raise refused("usage", "the containment tier needs --host-os and --backend")
    mode = "script" if args.script else "pytest"
    return Selection(tier, mode, "explicit" if args.agent_checkout else "none")


def tier_prerequisites(selection, args):
    """Raise NOT_RUN for tier prerequisites that F02 cannot satisfy or verify."""
    if selection.tier == "containment":
        expected = HOST_OS_PLATFORMS[args.host_os]
        if not sys.platform.startswith(expected):
            raise not_run("host_os_mismatch", f"--host-os {args.host_os} does not match {sys.platform}")
        raise not_run(
            "containment_backend_unverified",
            f"no disposable {args.backend} engine attestation is available; the operator's "
            "existing container service is never used",
        )
    if selection.tier == "remote":
        if not args.deployment_manifest:
            raise not_run("deployment_manifest_required", "the remote tier needs --deployment-manifest")
        validate_manifest(args.deployment_manifest)
        raise not_run("remote_attestation_unavailable", "no verified remote supervisor attestation is available")
    if selection.tier == "native" and not args.agent_checkout:
        raise not_run("agent_checkout_required", "the native tier needs --agent-checkout")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise refused("usage", message)


def build_parser():
    parser = _Parser(prog="test_multiuser.py", allow_abbrev=False,
                     description="Hermetic multi-user verification launcher.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-agent", action="store_true")
    parser.add_argument("--agent-checkout", metavar="PATH")
    parser.add_argument("--script", metavar="REPO_PATH")
    parser.add_argument("--tier", choices=TIERS)
    parser.add_argument("--host-os", choices=tuple(HOST_OS_PLATFORMS))
    parser.add_argument("--backend", choices=BACKENDS)
    parser.add_argument("--deployment-manifest", metavar="PATH")
    parser.add_argument("--report", metavar="PATH")
    parser.add_argument("--child-timeout", type=int, default=DEFAULT_CHILD_TIMEOUT, metavar="SECONDS")
    return parser


def load_helper(repo_root):
    """Load the stdlib helper from one validated read (works under -I -S).

    Returns ``(module, source_bytes)``; the same bytes are snapshotted for
    script runs, so every process uses the version that was validated here.
    """
    path = os.path.join(repo_root, "scripts", "multiuser_test_fixtures.py")
    st = _walk_components(repo_root, path)
    if not stat.S_ISREG(st.st_mode):
        raise refused("path_missing", "scripts/multiuser_test_fixtures.py is not a regular file")
    source = _read_validated_file(path, st, "scripts/multiuser_test_fixtures.py")
    module = types.ModuleType("_hermes_mu_fixtures")
    module.__file__ = path
    sys.modules[module.__name__] = module
    exec(compile(source, path, "exec"), module.__dict__)
    return module, source


# ── Import binding ───────────────────────────────────────────────────────────

IMPORT_GUARD_MODULE = "mu_import_guard"
IMPORT_MANIFEST_VAR = "HERMES_MU_IMPORT_MANIFEST"
IMPORT_MANIFEST_SHA_VAR = "HERMES_MU_IMPORT_MANIFEST_SHA256"
_MANIFEST_SKIP = frozenset({"node_modules", "__pycache__"})

# Written into the state root and loaded first (pytest ``-p``; script runner
# import) in every child, before any checkout module can be imported.
_IMPORT_GUARD_SOURCE = '''"""Launcher-owned import guard: checkout sources load only as approved bytes."""
import errno
import hashlib
import json
import os
from importlib import machinery

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _load_manifest():
    fd = os.open(os.environ["HERMES_MU_IMPORT_MANIFEST"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read()
    if hashlib.sha256(raw).hexdigest() != os.environ["HERMES_MU_IMPORT_MANIFEST_SHA256"]:
        raise ImportError("the import manifest does not match the launcher-approved digest")
    return json.loads(raw)


_DATA = _load_manifest()
_ROOT = _DATA["root"]
_VENV = os.path.join(_ROOT, ".venv")
_FILES = _DATA["files"]
_ROOT_FD = os.open(_ROOT, _DIR_FLAGS)
_st = os.fstat(_ROOT_FD)
if (_st.st_dev, _st.st_ino) != (_DATA["root_dev"], _DATA["root_ino"]):
    raise ImportError("the checkout root changed after launcher preflight")
try:
    os.stat(".env", dir_fd=_ROOT_FD, follow_symlinks=False)
except FileNotFoundError:
    pass
else:
    raise ImportError("a checkout .env appeared after launcher preflight")


def _within(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _relative(path):
    path = os.path.abspath(os.fspath(path))
    if not _within(path, _ROOT) or _within(path, _VENV):
        return None
    return os.path.relpath(path, _ROOT)


def _read_anchored(rel):
    parts = rel.split(os.sep)
    fd = os.open(os.curdir, _DIR_FLAGS, dir_fd=_ROOT_FD)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(file_fd, "rb") as handle:
        return handle.read()


_source_get_data = machinery.SourceFileLoader.get_data
_sourceless_get_data = machinery.SourcelessFileLoader.get_data
_extension_create = machinery.ExtensionFileLoader.create_module


def _bound_get_data(self, path):
    rel = _relative(path)
    if rel is None:
        return _source_get_data(self, path)
    if not rel.endswith(".py"):
        raise FileNotFoundError(errno.ENOENT, "checkout bytecode is never used", path)
    expected = _FILES.get(rel.replace(os.sep, "/"))
    if expected is None:
        raise ImportError(f"{rel} is not a launcher-approved checkout source")
    try:
        data = _read_anchored(rel)
    except OSError as exc:
        raise ImportError(f"{rel} cannot be read through the anchored checkout: {exc}") from None
    if hashlib.sha256(data).hexdigest() != expected:
        raise ImportError(f"{rel} changed after launcher preflight")
    return data


def _refused_sourceless(self, path):
    if _relative(path) is not None:
        raise ImportError(f"{path}: sourceless modules inside the checkout are refused")
    return _sourceless_get_data(self, path)


def _refused_extension(self, spec):
    if _relative(getattr(self, "path", "")) is not None:
        raise ImportError(f"{self.path}: extension modules inside the checkout are refused")
    return _extension_create(self, spec)


machinery.SourceFileLoader.get_data = _bound_get_data
machinery.SourcelessFileLoader.get_data = _refused_sourceless
machinery.ExtensionFileLoader.create_module = _refused_extension
'''


def build_import_manifest(repo_root):
    """SHA-256 of every regular checkout ``.py``, read by a descriptor-anchored walk.

    Links are never entered or recorded, so nothing reached through one is
    importable; dot-directories (``.venv``, ``.git``) are outside the manifest.
    """
    root_fd = os.open(repo_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    files = {}

    def walk(dir_fd, prefix):
        scan_fd = os.open(os.curdir, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
        try:
            with os.scandir(scan_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
        finally:
            os.close(scan_fd)
        for name in names:
            if name.startswith(".") or name in _MANIFEST_SKIP:
                continue
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        raise refused("unsafe_symlink", f"{prefix}{name} changed during the source walk")
                    walk(child, f"{prefix}{name}/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode) and name.endswith(".py"):
                fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
                with os.fdopen(fd, "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        raise refused("unsafe_symlink", f"{prefix}{name} changed during the source walk")
                    files[prefix + name] = hashlib.sha256(handle.read()).hexdigest()

    try:
        root_st = os.fstat(root_fd)
        walk(root_fd, "")
    finally:
        os.close(root_fd)
    return {"root": repo_root, "root_dev": root_st.st_dev, "root_ino": root_st.st_ino, "files": files}


def check_import_shadowing(repo_root, venv):
    """Refuse checkout top-level modules that would shadow stdlib/venv modules.

    ``python -m pytest`` and the runner's interpreter search the checkout
    before stdlib and site-packages while starting up, before the import guard
    is installed, so a same-named checkout module would load unbound.
    """
    shadowable = set(getattr(sys, "stdlib_module_names", ())) | {IMPORT_GUARD_MODULE, "multiuser_test_fixtures"}
    for site in venv.site_dirs:
        for name in os.listdir(site):
            stem = name[:-3] if name.endswith(".py") else name
            if stem.isidentifier():
                shadowable.add(stem)
    for name in os.listdir(repo_root):
        path = os.path.join(repo_root, name)
        stem = name[:-3] if name.endswith(".py") else name
        # A directory without __init__.py is only a namespace portion and
        # loses to a regular package later on sys.path.
        importable = name.endswith(".py") or os.path.isfile(os.path.join(path, "__init__.py"))
        if importable and stem in shadowable:
            raise refused("import_shadowing", f"checkout top-level {name!r} shadows a stdlib or venv module")


def write_import_guard(state_root, manifest):
    """Write the guard module and manifest read-only; return the env entries that bind them."""
    launcher_dir = os.path.join(state_root, "launcher")
    guard_dir = os.path.join(launcher_dir, "importguard")
    os.makedirs(guard_dir, mode=0o700)
    _write_new_file(os.path.join(guard_dir, IMPORT_GUARD_MODULE + ".py"), _IMPORT_GUARD_SOURCE.encode())
    os.chmod(guard_dir, 0o500)
    raw = json.dumps(manifest, sort_keys=True).encode()
    manifest_path = os.path.join(launcher_dir, "import-manifest.json")
    _write_new_file(manifest_path, raw)
    return {
        "PYTHONPATH": guard_dir,
        IMPORT_MANIFEST_VAR: manifest_path,
        IMPORT_MANIFEST_SHA_VAR: hashlib.sha256(raw).hexdigest(),
    }


def _write_new_file(path, data, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


# ── Pytest configuration ─────────────────────────────────────────────────────


def validated_pytest_markers(repo_root):
    """Read the checkout pytest.ini statically; only ``[pytest] markers`` are allowed."""
    ini = os.path.join(repo_root, "pytest.ini")
    if not os.path.lexists(ini):
        return []
    st = os.lstat(ini)
    if _is_link_like(st) or not stat.S_ISREG(st.st_mode):
        raise refused("unsafe_symlink", "pytest.ini is not a regular file")
    try:
        text = _read_validated_file(ini, st, "pytest.ini", limit=64 * 1024).decode("utf-8")
        parser = configparser.ConfigParser(interpolation=None, strict=True, default_section="\x00none")
        parser.read_string(text)
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise refused("pytest_config_disallowed", f"pytest.ini cannot be parsed safely: {exc.__class__.__name__}") from None
    extra_sections = [name for name in parser.sections() if name != "pytest"]
    if extra_sections:
        raise refused("pytest_config_disallowed", "pytest.ini has unreviewed sections: " + ", ".join(extra_sections))
    if not parser.has_section("pytest"):
        return []
    keys = set(parser["pytest"].keys()) - {"markers"}
    if keys:
        raise refused("pytest_config_disallowed", "pytest.ini sets unreviewed options: " + ", ".join(sorted(keys)))
    markers = [line.strip() for line in parser["pytest"].get("markers", "").splitlines() if line.strip()]
    for line in markers:
        if not _MARKER_LINE_RE.match(line):
            raise refused("pytest_config_disallowed", f"pytest.ini marker line is not a plain marker: {line[:80]!r}")
    return markers


def write_private_ini(state_root, markers):
    path = os.path.join(state_root, "launcher", "pytest.ini")
    text = "[pytest]\n"
    if markers:
        text += "markers =\n" + "".join(f"    {line}\n" for line in markers)
    _write_new_file(path, text.encode())
    return path


# ── Real runs ────────────────────────────────────────────────────────────────

# Runs under ``python -P`` (no checkout on sys.path): the import guard loads
# first, then the snapshot helper installs a deny-by-default NetworkGuard, then
# the immutable script snapshot executes with only its snapshot dir on sys.path.
_SCRIPT_RUNNER = (
    "import os, sys\n"
    "import mu_import_guard\n"
    "_snapdir, _name = sys.argv[1], sys.argv[2]\n"
    "sys.path.insert(0, _snapdir)\n"
    "import multiuser_test_fixtures as _mu\n"
    "_mu.NetworkGuard(allow_unix_under=[os.environ['HERMES_MU_STATE_ROOT']]).install()\n"
    "_script = os.path.join(_snapdir, _name)\n"
    "with open(_script, 'rb') as _f:\n"
    "    _code = compile(_f.read(), _script, 'exec')\n"
    "sys.argv = [_script] + sys.argv[3:]\n"
    "exec(_code, {'__name__': '__main__', '__file__': _script, '__spec__': None})\n"
)


def write_script_snapshot(state_root, script_path, snapshot, helper_source):
    snapdir = os.path.join(state_root, "launcher", "script")
    os.makedirs(snapdir, mode=0o700)
    name = os.path.basename(script_path)
    _write_new_file(os.path.join(snapdir, name), snapshot)
    _write_new_file(os.path.join(snapdir, "multiuser_test_fixtures.py"), helper_source)
    os.chmod(snapdir, 0o500)
    return snapdir, name


def _pytest_base_args(repo_root, confcutdir, ini):
    args = ["-p", IMPORT_GUARD_MODULE, "-p", "no:cacheprovider"]
    for plugin in PYTEST_PLUGINS:
        args.extend(("-p", plugin))
    args.extend((f"--rootdir={repo_root}", "-c", ini, f"--confcutdir={confcutdir}", "--assert=plain"))
    return args


def checkout_unchanged(path, ident):
    """True while ``path`` is still the explicit checkout directory validated earlier."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return not _is_link_like(st) and (st.st_dev, st.st_ino) == ident


def run_selected(selection, args, passthrough, result, repo_root, helper, helper_source):
    parent_env = dict(os.environ)
    home = helper.operator_home()
    test_sh = os.path.join(repo_root, "scripts", "test.sh")
    sh_st = _walk_components(repo_root, test_sh)
    if not stat.S_ISREG(sh_st.st_mode):
        raise refused("path_missing", "scripts/test.sh is not a regular file")

    pytest_args = script_path = snapshot = markers = None
    if selection.mode == "pytest":
        pytest_args = validate_pytest_args(passthrough, repo_root)
        markers = validated_pytest_markers(repo_root)
    else:
        if any("\0" in arg for arg in passthrough):
            raise refused("usage", "script argument contains a NUL byte")
        script_path, snapshot = validate_repo_script(args.script, repo_root)
        if os.path.basename(script_path) in (IMPORT_GUARD_MODULE + ".py", "multiuser_test_fixtures.py"):
            raise refused("script_invalid", "the script name collides with a launcher snapshot module")
    if os.name != "posix":
        raise not_run("platform_route_unverified", "pytest/script runs need a verified Windows shell route")
    tier_prerequisites(selection, args)

    agent_path = agent_ident = None
    if args.agent_checkout:
        agent_path, agent_ident = validate_agent_checkout(args.agent_checkout, repo_root, home, parent_env)
        result.agent = "explicit"
    if script_path is not None and not script_admitted(script_path, repo_root):
        raise not_run("script_unreviewed", "only reviewed F02-aware scripts (tests/multiuser/**, "
                      "tests/browser_multiuser_*.py) run under the launcher")
    hits = dotenv_hits(*[p for p in (repo_root, agent_path) if p])
    if hits:
        raise not_run("checkout_dotenv_present", "a .env would be loaded: " + ", ".join(hits))
    path_dirs = child_path_dirs(repo_root)
    agent_hits = implicit_agent_hits(repo_root, path_dirs)
    if agent_hits:
        raise not_run("implicit_agent_discoverable", "installed Agent discoverable at: " + ", ".join(agent_hits))

    prepare_base = None
    missing = []
    try:
        venv = inspect_venv(repo_root, home, result)
        missing = missing_runner_modules(venv)
    except Outcome as exc:
        if exc.code != "venv_unavailable":
            raise
        if selection.tier == "browser":
            raise not_run("browser_runtime_unavailable", "repo .venv does not exist, so Playwright is absent") from None
        venv = None
        prepare_base = select_base_python(parent_env, home)
        scan_interpreter_hooks(prepare_base, result)
        scan_site_packages(prepare_base.site_packages)
    if selection.tier == "browser":
        if not browser_runtime_ready(venv):
            raise not_run("browser_runtime_unavailable", "repo .venv has no project-local Playwright browsers")
        raise not_run("browser_transport_unverified",
                      "the browser runs as an unguarded subprocess with its own credential stores; "
                      "no verified browser transport or credential compartment exists")
    if agent_path is not None:
        raise not_run("credential_compartment_unverified",
                      "explicit Agent code can reach OS credential stores (such as the macOS login "
                      "Keychain) that HOME isolation does not cover; no synthetic credential "
                      "compartment is available")
    if venv is not None:
        check_import_shadowing(repo_root, venv)
    result.check("preflight", "PASS", "paths, sources, config, dotenv, discovery and interpreter provenance checked")

    base = trusted_temp_base(home)
    root = StateRoot(base)
    result.state["allocated"] = True
    try:
        layout = create_layout(root.path, helper)
        venv_python = os.path.join(repo_root, ".venv", "bin", "python")
        common = {
            "helper": helper, "state_root": root.path, "repo_root": repo_root,
            "tier": selection.tier, "agent_checkout": agent_path,
            "venv_python": venv_python, "path_dirs": path_dirs,
        }
        if venv is None or missing:
            extra = {"HERMES_WEBUI_TEST_PYTHON": prepare_base.exe} if venv is None else None
            env = checked_child_env(parent_env, build_child_env(parent_env, layout, extra=extra, **common), helper)
            sys.stderr.write("test_multiuser: provisioning repo .venv through scripts/test.sh --prepare-only\n")
            code = run_child(["/bin/bash", test_sh, "--prepare-only"], env=env, cwd=repo_root,
                             timeout=args.child_timeout, result=result, label="prepare")
            if code != 0:
                raise failed("prepare_failed", f"scripts/test.sh --prepare-only exited {code}")
            venv = inspect_venv(repo_root, home, result)
            missing = missing_runner_modules(venv)
            if missing:
                raise not_run("venv_dependencies_missing", "still missing after prepare: " + ", ".join(missing))
            check_import_shadowing(repo_root, venv)
            result.check("venv_prepared", "PASS", "scripts/test.sh --prepare-only, then a static re-audit")
        bound = write_import_guard(root.path, build_import_manifest(repo_root))
        env = checked_child_env(parent_env, build_child_env(parent_env, layout, extra=bound, **common), helper)
        result.check("child_environment", "PASS", "allowlisted, disposable, import-bound and verified before spawn")
        sys.stderr.write(
            f"test_multiuser: tier={selection.tier} mode={selection.mode} state={root.path} (disposable)\n"
        )
        if selection.mode == "pytest":
            ini = write_private_ini(root.path, markers)
            junit = os.path.join(root.path, "launcher", "junit.xml")
            cmd = ["/bin/bash", test_sh, "--execute-only"] + _pytest_base_args(
                repo_root, os.path.join(repo_root, "tests", "multiuser"), ini
            ) + [f"--junitxml={junit}", "-o", "junit_family=xunit2"] + pytest_args
            code = run_child(cmd, env=env, cwd=repo_root, timeout=args.child_timeout, result=result,
                             label="pytest")
            result.child_exit_code = code
            if code == RUNNER_NOT_PREPARED_EXIT:
                verdict = not_run("venv_dependencies_missing", "scripts/test.sh --execute-only refused to provision")
            else:
                counts = parse_junit(junit)
                result.tests = counts
                verdict = judge_pytest(code, counts)
        else:
            snapdir, name = write_script_snapshot(root.path, script_path, snapshot, helper_source)
            cmd = [venv_python, "-P", "-c", _SCRIPT_RUNNER, snapdir, name] + list(passthrough)
            code = run_child(cmd, env=env, cwd=repo_root, timeout=args.child_timeout, result=result,
                             label="script")
            result.child_exit_code = code
            if code == 0:
                verdict = None
            elif code == SCRIPT_NOT_RUN_EXIT:
                verdict = not_run("script_not_run", f"script exited {SCRIPT_NOT_RUN_EXIT} (prerequisite unavailable)")
            else:
                verdict = failed("child_failed", f"script exited {code}")
        # Reachable once a credential compartment lifts the explicit-Agent gate above.
        if agent_path is not None and not checkout_unchanged(agent_path, agent_ident):
            raise failed("source_replaced", "the explicit Agent checkout was replaced during the run")
        if verdict is not None:
            raise verdict
        result.settle("PASS")
    finally:
        _SignalState.phase = "teardown"
        try:
            result.state["root_removed"] = root.remove()
        except Outcome as exc:
            result.state["root_removed"] = False
            result.settle(exc.status, exc.code, exc.detail)
        except OSError as exc:
            result.state["root_removed"] = False
            result.settle("FAIL", "teardown_failed", f"state root removal failed: {exc.__class__.__name__}")


# ── Self-test ────────────────────────────────────────────────────────────────

_PROBE = (
    "import importlib.util, json, os, sys\n"
    "spec = importlib.util.spec_from_file_location('_mu_probe_helper', sys.argv[1])\n"
    "helper = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(helper)\n"
    "print(json.dumps({'env': dict(os.environ), 'cwd': os.getcwd(),\n"
    "                  'problems': helper.verify_hermetic_environment()}))\n"
)


class _SelfTest:
    def __init__(self, result, repo_root, helper, scratch):
        self.result = result
        self.repo_root = repo_root
        self.helper = helper
        self.scratch = scratch
        self.home = helper.operator_home()
        self.marker = os.path.join(scratch, "EXECUTED-MARKER")

    def run(self, name, fn):
        try:
            detail = fn() or ""
        except AssertionError as exc:
            self.result.check(name, "FAIL", str(exc) or "assertion failed")
        except _NotApplicable as exc:
            self.result.check(name, "NOT_RUN", str(exc))
        except Exception as exc:  # a self-test bug or environment failure is a FAIL, never a pass
            self.result.check(name, "FAIL", f"{exc.__class__.__name__}: {exc}")
        else:
            self.result.check(name, "PASS", detail)

    def expect(self, fn, status, code):
        try:
            fn()
        except Outcome as exc:
            assert (exc.status, exc.code) == (status, code), (
                f"expected {status} {code}, got {exc.status} {exc.code}: {exc.detail}"
            )
            return
        raise AssertionError(f"expected {status} {code}, got acceptance")

    def write(self, path, text="", mode=0o600):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, mode)
        return path

    def marker_writer(self):
        return f"open({self.marker!r}, 'w').write('executed')\n"

    def symlink(self, source, link):
        try:
            os.symlink(source, link)
        except OSError as exc:
            if os.name == "posix":
                raise
            raise _NotApplicable(f"symbolic links are unavailable: {exc.__class__.__name__}") from None

    def fake_repo(self, name):
        repo = os.path.join(self.scratch, name, "repo")
        self.write(os.path.join(repo, "scripts", "test.sh"), "#!/bin/sh\n" + f"touch {self.marker}\n", 0o700)
        self.write(os.path.join(repo, "tests", "multiuser", "test_ok.py"), "def test_ok():\n    pass\n")
        self.write(os.path.join(repo, "tests", "test_root.py"), "def test_root():\n    pass\n")
        self.write(os.path.join(repo, "tests", "ok_script.py"), "print('ok')\n")
        return repo

    def poison_parent(self):
        self.sentinels = {
            "OPENAI_API_KEY": self.helper.synthetic_credential("openai-sentinel"),
            "ANTHROPIC_API_KEY": self.helper.synthetic_credential("anthropic-sentinel"),
            "GITHUB_TOKEN": self.helper.synthetic_credential("github-sentinel"),
            "HERMES_WEBUI_PASSWORD": self.helper.synthetic_credential("password-sentinel"),
        }
        parent = dict(self.sentinels)
        parent.update(
            {
                "HOME": "/nonexistent/operator-home",
                "HERMES_HOME": "/nonexistent/operator-home/.hermes",
                "CODEX_HOME": "/nonexistent/operator-home/.codex",
                "PYTHONPATH": "/nonexistent/poison",
                "PYTHONSTARTUP": "/nonexistent/poison.py",
                "BASH_ENV": "/nonexistent/poison.sh",
                "SSH_AUTH_SOCK": "/nonexistent/agent.sock",
                "HTTPS_PROXY": "http://10.0.0.1:3128",
                "PYTEST_ADDOPTS": "-p poison",
                "HERMES_WEBUI_MULTIUSER": "1",
                "HERMES_WEBUI_PORT": "8787",
                "TEST_PORT": "8787",
                "DOCKER_HOST": "unix:///var/run/docker.sock",
                "OPENAI_BASE_URL": "https://api.example.invalid/v1",
                "PATH": os.environ.get("PATH", ""),
                "LANG": "en_US.UTF-8",
            }
        )
        return parent

    def build_env(self, root, parent):
        layout = create_layout(root, self.helper)
        env = build_child_env(
            parent, layout, helper=self.helper, state_root=root, repo_root=self.repo_root, tier="unit",
            agent_checkout=None, venv_python=os.path.join(self.repo_root, ".venv", "bin", "python"),
            path_dirs=child_path_dirs(self.repo_root),
        )
        return layout, env

    # Individual checks ---------------------------------------------------

    def check_state_root(self):
        st = os.lstat(self.scratch_root.path)
        assert not _is_link_like(st) and stat.S_ISDIR(st.st_mode), "state root is not a real directory"
        if os.name == "posix":
            assert st.st_uid == os.getuid() and not st.st_mode & 0o077, "state root is not private"
        assert not _is_within(self.scratch_root.path, self.home), "state root is inside the operator home"
        assert os.path.realpath(self.scratch_root.path) == self.scratch_root.path, "state root is not canonical"
        return f"private 0700 root under trusted base {os.path.dirname(self.scratch_root.path)}"

    def check_env_scrubbed(self):
        root = os.path.join(self.scratch, "env-root")
        os.makedirs(root, mode=0o700)
        parent = self.poison_parent()
        layout, env = self.build_env(root, parent)
        for name, value in parent.items():
            if name in ("PATH", "LANG"):
                continue
            if name in layout:
                assert env[name] == layout[name] != value, f"{name} kept the parent value"
            else:
                assert name not in env, f"{name} was inherited"
        for name, value in self.sentinels.items():
            assert not any(value in v for v in env.values()), f"{name} value reached the child"
        assert env["HOME"] == layout["HOME"] and env["HOME"] != parent["HOME"], "HOME is not disposable"
        assert find_secret_leaks(parent, env, self.helper) == [], "leak check reported a false leak"
        problems = self.helper.verify_hermetic_environment(env)
        assert not problems, "; ".join(problems)
        return "poisoned parent variables absent; disposable layout verified"

    def check_child_observes_env(self):
        root = os.path.join(self.scratch, "probe-root")
        os.makedirs(root, mode=0o700)
        parent = self.poison_parent()
        _layout, env = self.build_env(root, parent)
        helper_path = os.path.join(self.repo_root, "scripts", "multiuser_test_fixtures.py")
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _PROBE, helper_path],
            env=env, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
        )
        assert proc.returncode == 0, f"probe exited {proc.returncode}: {proc.stderr[-400:]!r}"
        report = json.loads(proc.stdout.decode())
        child = report["env"]
        for name, value in self.sentinels.items():
            assert name not in child and not any(value in v for v in child.values()), f"{name} reached the probe"
        assert child.get("HOME") == env["HOME"], "probe HOME differs from the disposable HOME"
        assert child.get("HERMES_WEBUI_HOST") == "127.0.0.1", "probe is not loopback-bound"
        assert not any("MULTIUSER" in k.upper() for k in child), "product multi-user mode variable present"
        assert not report["problems"], "; ".join(report["problems"])
        return "a spawned child saw only the allowlisted environment"

    def check_leak_refused(self):
        parent = {"OPENAI_API_KEY": self.helper.synthetic_credential("leak"), "LANG": "C"}
        child = {"LANG": "x" + parent["OPENAI_API_KEY"]}
        self.expect(lambda: checked_child_env(parent, child, self.helper), "REFUSED", "secret_leak")
        return "a parent secret value copied into a child value is refused"

    def check_script_paths(self):
        repo = self.fake_repo("script-paths")
        outside = self.write(os.path.join(self.scratch, "script-paths", "outside.py"), self.marker_writer())
        tests = os.path.join(repo, "tests")
        self.symlink(outside, os.path.join(tests, "link_script.py"))
        os.makedirs(os.path.join(self.scratch, "script-paths", "outside-dir"))
        self.write(os.path.join(self.scratch, "script-paths", "outside-dir", "x.py"), self.marker_writer())
        self.symlink(os.path.join(self.scratch, "script-paths", "outside-dir"), os.path.join(tests, "linkdir"))
        cases = [
            ("../outside.py", "path_outside_checkout"),
            (outside, "path_outside_checkout"),
            ("tests/link_script.py", "unsafe_symlink"),
            ("tests/linkdir/x.py", "unsafe_symlink"),
            ("tests/missing.py", "path_missing"),
            (".venv/bin/x.py", "path_outside_checkout"),
            ("scripts/test.sh", "script_invalid"),
        ]
        for raw, code in cases:
            self.expect(lambda raw=raw: validate_repo_script(raw, repo), "REFUSED", code)
        path, snapshot = validate_repo_script("tests/ok_script.py", repo)
        assert snapshot == b"print('ok')\n" and path == os.path.join(repo, "tests", "ok_script.py")
        assert not os.path.lexists(self.marker), "a refused script was executed"
        return f"{len(cases)} unsafe script paths refused; repo script snapshotted"

    def check_pytest_args(self):
        repo = self.fake_repo("pytest-args")
        self.write(os.path.join(self.scratch, "pytest-args", "outside_test.py"), self.marker_writer())
        self.symlink(
            os.path.join(self.scratch, "pytest-args", "outside_test.py"),
            os.path.join(repo, "tests", "multiuser", "test_link.py"),
        )
        bad = [
            (["-c", "x.ini"], "pytest_arg_disallowed"),
            (["-o", "addopts=-p x"], "pytest_arg_disallowed"),
            (["-p", "poison"], "pytest_arg_disallowed"),
            (["--pyargs", "api"], "pytest_arg_disallowed"),
            (["--confcutdir=/"], "pytest_arg_disallowed"),
            (["--rootdir=/"], "pytest_arg_disallowed"),
            (["--collect-only"], "pytest_arg_disallowed"),
            (["--co"], "pytest_arg_disallowed"),
            (["-W", "error::api.config.Warning"], "pytest_arg_disallowed"),
            (["--tb=evil"], "pytest_arg_disallowed"),
            (["tests/test_root.py"], "pytest_arg_disallowed"),
            (["../outside_test.py"], "path_outside_checkout"),
            (["tests/multiuser/test_link.py"], "unsafe_symlink"),
            (["tests/multiuser/test_missing.py"], "path_missing"),
            # The default directory scope collects tests/multiuser/test_link.py through its link.
            (["-q"], "unsafe_symlink"),
        ]
        for args, code in bad:
            self.expect(lambda args=args: validate_pytest_args(args, repo), "REFUSED", code)
        good = validate_pytest_args(
            ["-q", "tests/multiuser/test_ok.py::test_ok", "-k", "ok and not slow", "--timeout=30", "-rA"], repo
        )
        assert good[-1] == "-rA" and "tests/multiuser/test_ok.py::test_ok" in good
        chain = self.fake_repo("pytest-chain")
        self.symlink(
            os.path.join(self.scratch, "pytest-args", "outside_test.py"),
            os.path.join(chain, "tests", "multiuser", "conftest.py"),
        )
        self.expect(lambda: validate_pytest_args(["tests/multiuser/test_ok.py"], chain), "REFUSED", "unsafe_symlink")
        clean = self.fake_repo("pytest-clean")
        # A linked non-collectable helper is left to the import guard, which refuses links.
        self.symlink(
            os.path.join(self.scratch, "pytest-args", "outside_test.py"),
            os.path.join(clean, "tests", "multiuser", "linked_helper.py"),
        )
        assert validate_pytest_args(["-q"], clean) == ["-q", os.path.join("tests", "multiuser")]
        assert not os.path.lexists(self.marker)
        return f"{len(bad) + 1} unsafe pytest arguments or collected links refused; default scope is tests/multiuser"

    def check_pytest_config(self):
        cases = {
            "addopts": ("[pytest]\naddopts = -p poison\n", "pytest_config_disallowed"),
            "pythonpath": ("[pytest]\npythonpath = /elsewhere\n", "pytest_config_disallowed"),
            "filterwarnings": ("[pytest]\nfilterwarnings = error::api.config.Warning\n", "pytest_config_disallowed"),
            "section": ("[pytest]\nmarkers =\n    a: b\n[tool:pytest]\naddopts = -x\n", "pytest_config_disallowed"),
            "marker": ("[pytest]\nmarkers =\n    not a marker line\n", "pytest_config_disallowed"),
            "duplicate": ("[pytest]\nmarkers = a: b\nmarkers = c: d\n", "pytest_config_disallowed"),
        }
        for name, (text, code) in cases.items():
            repo = self.fake_repo(f"ini-{name}")
            self.write(os.path.join(repo, "pytest.ini"), text)
            self.expect(lambda repo=repo: validated_pytest_markers(repo), "REFUSED", code)
        linked = self.fake_repo("ini-linked")
        target = self.write(os.path.join(self.scratch, "ini-linked", "real.ini"), "[pytest]\n")
        self.symlink(target, os.path.join(linked, "pytest.ini"))
        self.expect(lambda: validated_pytest_markers(linked), "REFUSED", "unsafe_symlink")
        ok = self.fake_repo("ini-ok")
        self.write(os.path.join(ok, "pytest.ini"), "[pytest]\nmarkers =\n    integration: live\n    slow(n): long\n")
        markers = validated_pytest_markers(ok)
        assert markers == ["integration: live", "slow(n): long"], markers
        assert validated_pytest_markers(self.fake_repo("ini-absent")) == []
        state = os.path.join(self.scratch, "ini-state")
        os.makedirs(os.path.join(state, "launcher"))
        with open(write_private_ini(state, markers), encoding="utf-8") as handle:
            text = handle.read()
        assert text == "[pytest]\nmarkers =\n    integration: live\n    slow(n): long\n", text
        return f"{len(cases) + 1} unsafe pytest.ini variants refused; private ini carries markers only"

    def check_script_admission(self):
        repo = self.repo_root
        admitted = ["tests/multiuser/fixtures/probe.py", "tests/multiuser/x.py", "tests/browser_multiuser_roles.py"]
        rejected = ["tests/browser_smoke.py", "scripts/x.py", "tests/test_x.py", "tests/browser_multiuser_.py"]
        for rel in admitted:
            assert script_admitted(os.path.join(repo, rel), repo), f"{rel} should be admitted"
        for rel in rejected:
            assert not script_admitted(os.path.join(repo, rel), repo), f"{rel} should not be admitted"
        return "only reviewed F02-aware script locations are admitted"

    def check_agent_checkout(self):
        repo = self.fake_repo("agent")
        base = os.path.dirname(repo)
        good = os.path.join(base, "agent-ok")
        self.write(os.path.join(good, "run_agent.py"), self.marker_writer())
        self.symlink(good, os.path.join(base, "agent-link"))
        os.makedirs(os.path.join(base, "agent-empty"))
        sibling = os.path.join(base, "hermes-agent")
        self.write(os.path.join(sibling, "run_agent.py"), self.marker_writer())
        self.write(os.path.join(repo, "nested-agent", "run_agent.py"), self.marker_writer())
        xdg = os.path.join(base, "xdg-data")
        self.write(os.path.join(xdg, "hermes-agent", "run_agent.py"), self.marker_writer())
        inner_link = os.path.join(base, "agent-inner-link")
        self.write(os.path.join(inner_link, "run_agent.py"), self.marker_writer())
        self.symlink(os.path.join(good, "run_agent.py"), os.path.join(inner_link, "tools.py"))
        parent_env = {"XDG_DATA_HOME": xdg}
        cases = [
            (os.path.join(self.home, ".hermes", "hermes-agent"), "installed_agent_location"),
            (os.path.join(self.home, ".local", "share", "hermes-agent"), "installed_agent_location"),
            (os.path.join(xdg, "hermes-agent"), "installed_agent_location"),
            ("/usr/local/lib/hermes-agent", "installed_agent_location"),
            (sibling, "implicit_discovery_location"),
            (os.path.join(repo, "nested-agent"), "agent_checkout_invalid"),
            (os.path.join(base, "agent-missing"), "path_missing"),
            (os.path.join(base, "agent-link"), "unsafe_symlink"),
            (os.path.join(base, "agent-empty"), "agent_checkout_invalid"),
            (inner_link, "unsafe_symlink"),
        ]
        for raw, code in cases:
            self.expect(
                lambda raw=raw: validate_agent_checkout(raw, repo, self.home, parent_env), "REFUSED", code
            )
        path, ident = validate_agent_checkout(good, repo, self.home, parent_env)
        assert path == good and ident[1] == os.lstat(good).st_ino
        assert checkout_unchanged(good, ident)
        os.rename(good, good + "-moved")
        os.makedirs(good)
        assert not checkout_unchanged(good, ident), "a replaced checkout was not detected"
        assert not os.path.lexists(self.marker), "an Agent checkout was executed during validation"
        return f"{len(cases)} unsafe Agent sources refused; explicit synthetic checkout accepted unexecuted"

    def check_tiers(self):
        parser = build_parser()
        manifest = self.write(os.path.join(self.scratch, "tiers", "manifest.json"), "{}")
        matching = [name for name, plat in HOST_OS_PLATFORMS.items() if sys.platform.startswith(plat)]
        here = matching[0] if matching else None
        other = next(name for name in HOST_OS_PLATFORMS if name != here)
        cases = [
            (["--tier", "containment", "--host-os", other, "--backend", "docker"], "NOT_RUN", "host_os_mismatch"),
            (["--tier", "remote"], "NOT_RUN", "deployment_manifest_required"),
            (["--tier", "remote", "--deployment-manifest", manifest], "NOT_RUN", "remote_attestation_unavailable"),
            (["--tier", "native"], "NOT_RUN", "agent_checkout_required"),
            (["--no-agent", "--agent-checkout", "/x"], "REFUSED", "conflicting_options"),
            (["--tier", "unit", "--agent-checkout", "/x"], "REFUSED", "conflicting_options"),
            (["--tier", "native", "--no-agent"], "REFUSED", "conflicting_options"),
            (["--tier", "browser", "--no-agent"], "REFUSED", "usage"),
            (["--no-agent", "--host-os", "linux"], "REFUSED", "conflicting_options"),
            (["--tier", "containment", "--host-os", "linux"], "REFUSED", "usage"),
            (["--self-test", "--no-agent"], "REFUSED", "conflicting_options"),
            ([], "REFUSED", "usage"),
            (["--tier", "bogus"], "REFUSED", "usage"),
        ]
        if here is not None:
            cases.append(
                (["--tier", "containment", "--host-os", here, "--backend", "docker"], "NOT_RUN",
                 "containment_backend_unverified")
            )

        def decide(argv):
            parsed = parser.parse_args(argv)
            selection = resolve_selection(parsed, [])
            tier_prerequisites(selection, parsed)

        for argv, status, code in cases:
            self.expect(lambda argv=argv: decide(argv), status, code)
        return f"{len(cases)} tier/option combinations map to NOT_RUN or REFUSED"

    def fake_base(self, name, version="3.13", hook=None):
        base = os.path.join(self.scratch, name, "base")
        exe = self.write(os.path.join(base, "bin", f"python{version}"), "#!/bin/sh\n" + f"touch {self.marker}\n", 0o700)
        self.write(os.path.join(base, "lib", f"python{version}", "os.py"), "")
        os.makedirs(os.path.join(base, "lib", f"python{version}", "lib-dynload"))
        if hook is not None:
            self.write(os.path.join(base, "lib", f"python{version}", "sitecustomize.py"), hook)
        return exe

    def trusted_base(self):
        """A verified distribution interpreter on this host (inspected, never executed)."""
        try:
            return inspect_venv(self.repo_root, self.home).base
        except Outcome:
            pass
        env = {"PATH": os.pathsep.join(WELL_KNOWN_PYTHON_DIRS)}
        try:
            return select_base_python(env, self.home)
        except Outcome as exc:
            raise _NotApplicable(f"no verified distribution interpreter on this host: {exc.detail}") from None

    def fake_venv(self, name, base, *, version=None, include="false"):
        """A synthetic repo .venv whose home and bin/python point at ``base``'s executable."""
        repo = self.fake_repo(name)
        exe = base if isinstance(base, str) else base.exe
        version = version or (_version_text(base.version) if not isinstance(base, str) else "3.13")
        venv = os.path.join(repo, ".venv")
        self.write(
            os.path.join(venv, "pyvenv.cfg"),
            f"home = {os.path.dirname(exe)}\ninclude-system-site-packages = {include}\nversion = {version}.0\n",
        )
        os.makedirs(os.path.join(venv, "bin"))
        self.symlink(exe, os.path.join(venv, "bin", "python"))
        site = os.path.join(venv, "lib", f"python{version}", "site-packages")
        os.makedirs(site)
        return repo, site

    def check_venv_provenance(self):
        if os.name != "posix":
            raise _NotApplicable("POSIX venv layout only")
        fake = self.fake_base("venv-fake-base")
        repo, _site = self.fake_venv("venv-fake", fake)
        self.expect(lambda: inspect_venv(repo, self.home), "NOT_RUN", "venv_provenance_unknown")
        self.expect(lambda: select_base_python({"HERMES_WEBUI_TEST_PYTHON": fake}, self.home),
                    "NOT_RUN", "venv_provenance_unknown")
        hooked = self.fake_base("venv-hook-base", hook=self.marker_writer())
        fake_interpreter = BaseInterpreter(
            hooked, hooked, os.path.dirname(os.path.dirname(hooked)), (3, 13),
            os.path.join(os.path.dirname(os.path.dirname(hooked)), "lib", "python3.13"),
        )
        self.expect(lambda: scan_interpreter_hooks(fake_interpreter), "NOT_RUN", "venv_provenance_unknown")
        base = self.trusted_base()
        repo, _site = self.fake_venv("venv-clean", base)
        venv = inspect_venv(repo, self.home)
        assert venv.version == base.version
        assert missing_runner_modules(venv) == list(RUNNER_MODULES), "an empty venv must need preparing"
        cases = []
        repo, site = self.fake_venv("venv-pth", base)
        self.write(os.path.join(site, "evil.pth"), "import os; " + self.marker_writer())
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-sitecustomize", base)
        self.write(os.path.join(site, "sitecustomize.py"), self.marker_writer())
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-path-pth", base)
        self.write(os.path.join(site, "outside.pth"), os.path.join(self.scratch, "elsewhere") + "\n")
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-inner-pth", base)
        extra = os.path.join(repo, ".venv", "extra")
        self.write(os.path.join(extra, "sitecustomize.py"), self.marker_writer())
        self.write(os.path.join(extra, "run_agent.py"), self.marker_writer())
        self.write(os.path.join(site, "inner.pth"), extra + "\n")
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-egg-link", base)
        self.write(os.path.join(site, "pkg.egg-link"), "/elsewhere\n")
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-agent", base)
        self.write(os.path.join(site, "run_agent.py"), self.marker_writer())
        cases.append((repo, "implicit_agent_discoverable"))
        repo, _site = self.fake_venv("venv-system-site", base, include="true")
        cases.append((repo, "venv_provenance_unknown"))
        repo, _site = self.fake_venv("venv-old", base, version="3.10")
        cases.append((repo, "unsupported_python"))
        linked = self.fake_repo("venv-linked")
        clean_repo, _site = self.fake_venv("venv-link-target", base)
        self.symlink(os.path.join(clean_repo, ".venv"), os.path.join(linked, ".venv"))
        cases.append((linked, "venv_provenance_unknown"))
        for repo, code in cases:
            self.expect(lambda repo=repo: inspect_venv(repo, self.home), "NOT_RUN", code)
        assert not os.path.lexists(self.marker), "a startup hook or interpreter was executed"
        return (f"fake base and base hook NOT_RUN; clean venv on {base.real} accepted; "
                f"{len(cases)} hostile venvs NOT_RUN without execution")

    def check_import_shadowing(self):
        repo = self.fake_repo("shadow")
        site = os.path.join(self.scratch, "shadow", "site")
        self.write(os.path.join(site, "pytest", "__init__.py"), "")
        venv = Venv(None, None, (3, 13), [site], None)
        check_import_shadowing(repo, venv)
        self.write(os.path.join(repo, "pytest", "__init__.py"), self.marker_writer())
        self.expect(lambda: check_import_shadowing(repo, venv), "REFUSED", "import_shadowing")
        other = self.fake_repo("shadow-stdlib")
        self.write(os.path.join(other, "mu_import_guard.py"), self.marker_writer())
        self.expect(lambda: check_import_shadowing(other, venv), "REFUSED", "import_shadowing")
        assert not os.path.lexists(self.marker)
        return "checkout modules that would shadow startup imports are refused"

    def check_discovery_and_dotenv(self):
        repo = self.fake_repo("discovery")
        sibling = os.path.join(os.path.dirname(repo), "hermes-agent")
        assert sibling not in implicit_agent_hits(repo, [])
        os.makedirs(sibling)
        assert sibling in implicit_agent_hits(repo, []), "sibling Agent checkout not detected"
        bindir = os.path.join(self.scratch, "discovery", "bin")
        self.write(os.path.join(bindir, "hermes"), "#!/bin/sh\n", 0o700)
        assert any(h.endswith("hermes") for h in implicit_agent_hits(self.fake_repo("discovery2"), [bindir]))
        dot_repo = self.fake_repo("dotenv")
        dotenv = self.write(os.path.join(dot_repo, ".env"), "OPENAI_API_KEY=" + self.sentinels["OPENAI_API_KEY"])
        os.chmod(dotenv, 0)
        assert dotenv in dotenv_hits(dot_repo), ".env not detected"
        os.chmod(dotenv, 0o600)
        return "sibling/PATH Agent discovery and an unreadable .env detected from metadata alone"

    def check_loopback_fixture(self):
        import urllib.error
        import urllib.request

        no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with self.helper.LoopbackUpstream() as upstream:
            with self.helper.NetworkGuard([upstream]):
                with no_proxy.open(upstream.url + "/v1/models", timeout=5) as response:
                    assert response.status == 200
            assert [r.path for r in upstream.requests] == ["/v1/models"]
            endpoint = upstream.endpoint
        probe = socket_module().socket(socket_module().AF_INET, socket_module().SOCK_STREAM)
        try:
            probe.settimeout(1)
            assert probe.connect_ex(endpoint) != 0, "the upstream port still accepts after close"
        finally:
            probe.close()
        try:
            with self.helper.LoopbackUpstream() as upstream:
                held = upstream.endpoint
                raise RuntimeError("synthetic failure inside the fixture")
        except RuntimeError:
            pass
        probe = socket_module().socket(socket_module().AF_INET, socket_module().SOCK_STREAM)
        try:
            probe.settimeout(1)
            assert probe.connect_ex(held) != 0, "the upstream survived an exception"
        finally:
            probe.close()
        for host in ("0.0.0.0", "10.0.0.1", "localhost"):
            try:
                self.helper.LoopbackUpstream(host=host)
            except self.helper.FixtureError:
                continue
            raise AssertionError(f"LoopbackUpstream accepted host {host}")
        return "upstream bound, served, recorded, and released on success and on exception"

    def check_network_guard(self):
        import urllib.error
        import urllib.request

        sock = socket_module()
        helper = self.helper
        redirect_target = "http://10.1.2.3/collect"

        def redirecting(request):
            if request.path == "/redirect":
                return 302, {"Location": redirect_target}, b""
            return 200, {}, b"ok"

        unowned = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        unowned.bind(("127.0.0.1", 0))
        unowned.listen(1)
        unowned.settimeout(0.3)
        try:
            with helper.LoopbackUpstream(redirecting) as upstream:
                with helper.NetworkGuard([upstream]) as guard:
                    blocked = [
                        ("10.0.0.1", 80),
                        ("192.168.1.1", 443),
                        ("169.254.169.254", 80),
                        ("8.8.8.8", 53),
                        ("localhost", upstream.port),
                        ("127.0.0.1", unowned.getsockname()[1]),
                    ]
                    for address in blocked:
                        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                        try:
                            s.connect(address)
                        except helper.DestinationRefused:
                            pass
                        else:
                            raise AssertionError(f"connect to {address} was allowed")
                        finally:
                            s.close()
                    if sock.has_ipv6:
                        for address in (("::1", upstream.port), ("2001:4860:4860::8888", 443)):
                            try:
                                s = sock.socket(sock.AF_INET6, sock.SOCK_STREAM)
                            except OSError:
                                break  # IPv6 sockets are disabled on this host
                            try:
                                s.connect(address)
                            except helper.DestinationRefused:
                                pass
                            else:
                                raise AssertionError(f"connect to {address} was allowed")
                            finally:
                                s.close()
                    udp = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
                    try:
                        udp.sendto(b"x", ("127.0.0.1", 53))
                        raise AssertionError("UDP to an unowned port was allowed")
                    except helper.DestinationRefused:
                        pass
                    finally:
                        udp.close()
                    for call in (
                        lambda: sock.getaddrinfo("example.invalid", 443),
                        lambda: sock.gethostbyname("example.invalid"),
                        lambda: sock.gethostbyaddr("127.0.0.1"),
                        lambda: sock.create_connection(("localhost", upstream.port), timeout=1),
                    ):
                        try:
                            call()
                        except helper.DestinationRefused:
                            continue
                        raise AssertionError("a name lookup or reverse lookup was allowed")
                    if hasattr(sock, "AF_UNIX"):
                        u = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
                        try:
                            u.connect("/var/run/docker.sock")
                            raise AssertionError("connect to a foreign unix socket was allowed")
                        except helper.DestinationRefused:
                            pass
                        finally:
                            u.close()
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    try:
                        opener.open(upstream.url + "/redirect", timeout=5)
                        raise AssertionError("a redirect to a non-owned destination was followed")
                    except urllib.error.URLError as exc:
                        assert isinstance(exc.reason, helper.DestinationRefused), repr(exc.reason)
                    proxied = urllib.request.build_opener(
                        urllib.request.ProxyHandler({"http": "http://10.9.9.9:3128"})
                    )
                    try:
                        proxied.open(upstream.url + "/", timeout=5)
                        raise AssertionError("an unowned proxy was used")
                    except urllib.error.URLError as exc:
                        assert isinstance(exc.reason, helper.DestinationRefused), repr(exc.reason)
                    refused_count = len(guard.refused)
            try:
                unowned.accept()[0].close()
                raise AssertionError("the unowned local listener received a connection")
            except OSError:
                pass
        finally:
            unowned.close()
        assert "connect" not in sock.socket.__dict__, "socket.connect was not restored"
        assert sock.getaddrinfo is helper_original_getaddrinfo, "getaddrinfo was not restored"
        return f"{refused_count} non-owned destinations refused before any connection; guard restored"

    def check_validate_destination(self):
        helper = self.helper
        with helper.LoopbackUpstream() as upstream:
            helper.validate_destination(upstream.url + "/v1", [upstream])
            for url in (
                f"http://localhost:{upstream.port}/",
                f"http://127.0.0.1:{upstream.port + 1 if upstream.port < 65535 else 1}/",
                "https://api.openai.com/v1",
                f"http://user:pw@127.0.0.1:{upstream.port}/",
                f"ftp://127.0.0.1:{upstream.port}/",
                "http://169.254.169.254/latest/meta-data",
                "http://[::1]:1/",
            ):
                try:
                    helper.validate_destination(url, [upstream])
                except helper.DestinationRefused:
                    continue
                raise AssertionError(f"destination {url} was accepted")
        return "only the exact owned endpoint validates"

    def check_loopback_teardown(self):
        import threading

        sock = socket_module()
        helper = self.helper
        gate = threading.Event()

        def blocking(request):
            gate.wait(30)
            return 200, {}, b"late"

        upstream = helper.LoopbackUpstream(blocking).start()
        client = sock.create_connection(upstream.endpoint, timeout=5)
        try:
            client.sendall(b"GET /block HTTP/1.0\r\n\r\n")
            deadline = time.monotonic() + 5
            while not upstream.requests and time.monotonic() < deadline:
                time.sleep(0.02)
            started = time.monotonic()
            try:
                upstream.close(timeout=0.5)
            except helper.FixtureTeardownError:
                pass
            else:
                raise AssertionError("close() reported success while a handler was still running")
            assert time.monotonic() - started < 5, "close() was not bounded"
            stuck = list(upstream.stuck_handlers)
            assert stuck and all(t.is_alive() for t in stuck), "the stuck handler was not reported"
        finally:
            gate.set()
            client.close()
        for thread in stuck:
            thread.join(5)
        assert not any(t.is_alive() for t in stuck), "released handlers did not exit"

        slow = helper.LoopbackUpstream(request_timeout=30).start()
        partial = sock.create_connection(slow.endpoint, timeout=5)
        try:
            partial.sendall(b"GET /partial HTTP/1.1\r\nHost: x")
            time.sleep(0.2)
            slow.close(timeout=5)
        finally:
            partial.close()
        assert not slow.stuck_handlers, "a handler blocked on a client read survived close()"

        quick = helper.LoopbackUpstream(request_timeout=0.3).start()
        idle = sock.create_connection(quick.endpoint, timeout=5)
        try:
            time.sleep(0.8)
            quick.close(timeout=2)
        finally:
            idle.close()

        class FailingStart(helper.LoopbackUpstream):
            def _start_serve_thread(self, thread):
                raise RuntimeError("synthetic thread start failure")

        failing = FailingStart()
        try:
            failing.start()
        except helper.FixtureError:
            pass
        else:
            raise AssertionError("a failed serve-thread start was not reported")
        probe = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        try:
            probe.settimeout(1)
            assert probe.connect_ex(("127.0.0.1", failing.port)) != 0, "a partial start leaked its listener"
        finally:
            probe.close()
        return "stuck handlers raise FixtureTeardownError; blocked reads and idle clients are closed; partial start rolls back"

    def check_import_binding(self):
        if os.name != "posix":
            raise _NotApplicable("descriptor-anchored import binding is POSIX-only")
        repo = self.fake_repo("binding")
        self.write(os.path.join(repo, "pkg", "__init__.py"), "")
        self.write(os.path.join(repo, "pkg", "mod.py"), "VALUE = 'approved'\n")
        self.write(os.path.join(repo, "pkg", "swap.py"), "VALUE = 'approved'\n")
        outside = self.write(os.path.join(self.scratch, "binding", "foreign.py"), self.marker_writer())
        state = os.path.join(self.scratch, "binding", "state")
        os.makedirs(os.path.join(state, "launcher"), mode=0o700)
        manifest = build_import_manifest(repo)
        bound = write_import_guard(state, manifest)

        def child(code, extra_env=None):
            env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
                   "PYTHONPYCACHEPREFIX": os.path.join(state, "pycache")}
            env.update(bound)
            env.update(extra_env or {})
            script = (
                "import sys\nimport mu_import_guard\n"
                f"sys.path.insert(0, {repo!r})\n" + code
            )
            return subprocess.run([sys.executable, "-S", "-c", script], env=env, cwd=state,
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=60)

        ok = child("import pkg.mod\nprint(pkg.mod.VALUE)\n")
        assert ok.returncode == 0 and ok.stdout.strip() == b"approved", ok.stderr[-400:]
        self.write(os.path.join(repo, "pkg", "swap.py"), self.marker_writer())
        self.write(os.path.join(repo, "pkg", "new.py"), self.marker_writer())
        self.symlink(outside, os.path.join(repo, "pkg", "linked.py"))
        self.write(os.path.join(repo, "pkg", "compiled.pyc"), "")
        for module in ("pkg.swap", "pkg.new", "pkg.linked", "pkg.compiled"):
            refused_run = child(f"import {module}\n")
            assert refused_run.returncode != 0 and b"ImportError" in refused_run.stderr, (
                f"{module} imported: {refused_run.stderr[-300:]!r}"
            )
        os.rename(os.path.join(repo, "pkg"), os.path.join(repo, "pkg-approved"))
        os.makedirs(os.path.join(self.scratch, "binding", "foreign-pkg"))
        self.write(os.path.join(self.scratch, "binding", "foreign-pkg", "__init__.py"), self.marker_writer())
        self.write(os.path.join(self.scratch, "binding", "foreign-pkg", "mod.py"), self.marker_writer())
        self.symlink(os.path.join(self.scratch, "binding", "foreign-pkg"), os.path.join(repo, "pkg"))
        parent_swap = child("import pkg.mod\n")
        assert parent_swap.returncode != 0 and b"ImportError" in parent_swap.stderr, parent_swap.stderr[-300:]
        tampered = child("pass\n", {"HERMES_MU_IMPORT_MANIFEST_SHA256": "0" * 64})
        assert tampered.returncode != 0, "a manifest digest mismatch did not stop the guard"
        assert not os.path.lexists(self.marker), "a replaced, new, linked or foreign module executed"
        return "approved bytes import; replaced, new, linked, sourceless and parent-swapped modules refused"

    def check_signal_spawn_boundary(self):
        if os.name != "posix":
            raise _NotApplicable("process-group signal checks are POSIX-only")
        if signal.getsignal(signal.SIGINT) is not _signal_handler:
            raise _NotApplicable("the launcher signal handler is not installed")
        hang = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(120)'])\n"
            "time.sleep(120)\n"
        )
        pids = {}

        def interrupt(proc):
            pids["pgid"] = proc.pid
            os.kill(os.getpid(), signal.SIGINT)

        try:
            run_child([sys.executable, "-I", "-S", "-c", hang], env={"PATH": "/usr/bin:/bin"},
                      cwd=self.scratch, timeout=60, after_spawn=interrupt)
        except Outcome as exc:
            assert exc.code == "interrupted" and "terminated=True" in exc.detail, exc.detail
        else:
            raise AssertionError("a signal at the spawn boundary was lost")
        finally:
            _SignalState.received = None
        assert not _group_alive(pids["pgid"]), "the owned group survived a spawn-boundary signal"
        return "a SIGINT at the ownership boundary is deferred, then terminates the owned group"

    def check_child_lifecycle(self):
        if os.name != "posix":
            raise _NotApplicable("process-group lifecycle checks are POSIX-only")
        env = {"PATH": "/usr/bin:/bin"}
        code = run_child([sys.executable, "-I", "-S", "-c", "raise SystemExit(7)"], env=env,
                         cwd=self.scratch, timeout=30)
        assert code == 7, f"child exit code {code} was not propagated"
        hang = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(120)'])\n"
            "time.sleep(120)\n"
        )
        started = time.monotonic()
        try:
            run_child([sys.executable, "-I", "-S", "-c", hang], env=env, cwd=self.scratch, timeout=1)
        except Outcome as exc:
            assert exc.code == "child_timeout" and "terminated=True" in exc.detail, exc.detail
        else:
            raise AssertionError("a hung child was not timed out")
        assert time.monotonic() - started < 30, "timeout handling was unbounded"
        return "exit codes propagate; a hung child and its descendant were terminated"

    def check_teardown(self):
        base = os.path.dirname(self.scratch_root.path)
        root = StateRoot(base)
        try:
            self.write(os.path.join(root.path, "home", "file"), "x")
            locked = os.path.join(root.path, "launcher", "locked")
            self.write(os.path.join(locked, "inner", "f"), "x")
            os.chmod(os.path.join(locked, "inner"), 0)
            os.chmod(locked, 0o500)
            raise RuntimeError("synthetic failure")
        except RuntimeError:
            pass
        finally:
            assert root.remove() is True
        assert not os.path.lexists(root.path), "state root survived a failure"
        if os.name != "posix":
            raise _NotApplicable("descriptor-anchored teardown is POSIX-only")

        def swap(root, payload):
            moved = root.path + "-moved"
            os.rename(root.path, moved)
            os.makedirs(root.path, mode=0o700)
            if payload:
                self.write(os.path.join(root.path, "replacement-sentinel"), "keep")
            return moved

        outcomes = []
        for when, payload in (("before", True), ("barrier", True), ("barrier", False), ("moved", None)):
            root = StateRoot(base)
            self.write(os.path.join(root.path, "home", "ours"), "x")
            moved = None
            try:
                if when == "before":
                    moved = swap(root, payload)
                elif when == "moved":
                    moved = root.path + "-moved"
                    os.rename(root.path, moved)
                else:
                    holder = {}

                    def barrier(root=root, payload=payload, holder=holder):
                        holder["moved"] = swap(root, payload)

                    root._before_unlink = barrier
                self.expect(root.remove, "FAIL", "teardown_failed")
                moved = moved or holder.get("moved")
                assert os.listdir(moved) == [], f"{when}: the anchored original was not cleared"
                if payload is not None:
                    present = os.path.exists(os.path.join(root.path, "replacement-sentinel"))
                    assert present == payload and os.path.isdir(root.path), f"{when}: replacement was touched"
                else:
                    assert not os.path.lexists(root.path)
                outcomes.append(when if payload is not False else "barrier-empty")
            finally:
                for path in (root.path, moved):
                    if path:
                        shutil.rmtree(path, ignore_errors=True)
        return "failure teardown clears locked dirs; " + ", ".join(outcomes) + " swaps FAIL without touching replacements"

    def check_report_target(self):
        if os.name != "posix":
            raise _NotApplicable("descriptor-anchored report writes are POSIX-only")
        work = os.path.join(self.scratch, "reports")
        os.makedirs(work, mode=0o700)
        target = ReportTarget(os.path.join(work, "new.json"), self.home)
        target.write("{}\n")
        target.close()
        st = os.lstat(os.path.join(work, "new.json"))
        assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
        auth = self.write(os.path.join(work, "fake-operator-state", "auth.json"), "SYNTHETIC-AUTH")
        self.expect(lambda: ReportTarget(auth, self.home), "REFUSED", "report_path_disallowed")
        with open(auth, encoding="utf-8") as handle:
            assert handle.read() == "SYNTHETIC-AUTH", "an existing file was modified"
        self.symlink(auth, os.path.join(work, "link.json"))
        self.expect(lambda: ReportTarget(os.path.join(work, "link.json"), self.home), "REFUSED",
                    "report_path_disallowed")
        self.expect(lambda: ReportTarget(os.path.join(self.repo_root, "report.json"), self.home), "REFUSED",
                    "report_path_disallowed")
        shared = os.path.join(work, "shared")
        os.makedirs(shared)
        os.chmod(shared, 0o777)
        self.expect(lambda: ReportTarget(os.path.join(shared, "r.json"), self.home), "REFUSED",
                    "report_path_disallowed")
        foreign = os.path.join(work, "foreign")
        os.makedirs(foreign, mode=0o700)
        self.write(os.path.join(foreign, "foreign-sentinel"), "keep")
        for replacement in ("directory", "symlink"):
            anchored = os.path.join(work, f"anchored-{replacement}")
            os.makedirs(anchored, mode=0o700)
            target = ReportTarget(os.path.join(anchored, "r.json"), self.home)
            os.rename(anchored, anchored + "-moved")
            if replacement == "directory":
                os.makedirs(anchored, mode=0o700)
            else:
                self.symlink(foreign, anchored)
            try:
                target.write("{}\n")
            except OSError:
                pass
            else:
                raise AssertionError(f"a report was written after its parent was replaced by a {replacement}")
            finally:
                target.close()
            assert os.listdir(anchored + "-moved") == [], "the report reached the original parent"
            assert sorted(os.listdir(foreign)) == ["foreign-sentinel"], "the report reached a foreign directory"
            if replacement == "directory":
                assert os.listdir(anchored) == []
        return "new private reports only; existing, linked, foreign and shared paths refused; replaced parents refused"

    def check_no_product_import(self):
        loaded = sorted(
            name for name in sys.modules
            if name in ("api", "bootstrap", "server") or name.startswith("api.")
        )
        assert not loaded, "product modules imported: " + ", ".join(loaded)
        return "no product module is imported by the launcher"


class _NotApplicable(Exception):
    pass


def socket_module():
    import socket

    return socket


helper_original_getaddrinfo = None


def run_self_test(result, repo_root, helper):
    global helper_original_getaddrinfo
    helper_original_getaddrinfo = socket_module().getaddrinfo
    environ_before = dict(os.environ)
    home = helper.operator_home()
    root = StateRoot(trusted_temp_base(home))
    result.state["allocated"] = True
    try:
        scratch = os.path.join(root.path, "selftest")
        os.makedirs(scratch, mode=0o700)
        suite = _SelfTest(result, repo_root, helper, scratch)
        suite.scratch_root = root
        suite.sentinels = {}
        suite.poison_parent()
        for name in (
            "state_root", "env_scrubbed", "child_observes_env", "leak_refused", "script_paths",
            "script_admission", "pytest_args", "pytest_config", "agent_checkout", "tiers",
            "venv_provenance", "import_shadowing", "discovery_and_dotenv", "import_binding",
            "loopback_fixture", "loopback_teardown", "network_guard", "validate_destination",
            "child_lifecycle", "signal_spawn_boundary", "teardown", "report_target", "no_product_import",
        ):
            suite.run(name, getattr(suite, f"check_{name}"))
        if dict(os.environ) != environ_before:
            result.check("parent_env_unchanged", "FAIL", "the launcher changed its own environment")
        else:
            result.check("parent_env_unchanged", "PASS", "launcher environment unchanged")
    finally:
        _SignalState.phase = "teardown"
        try:
            result.state["root_removed"] = root.remove()
        except Outcome as exc:
            result.state["root_removed"] = False
            result.settle(exc.status, exc.code, exc.detail)
    statuses = {check["status"] for check in result.checks}
    if "FAIL" in statuses or not result.state["root_removed"]:
        failures = [c["name"] for c in result.checks if c["status"] == "FAIL"]
        result.settle("FAIL", "self_test_failed", "failed checks: " + ", ".join(failures or ["teardown"]))
    elif "NOT_RUN" in statuses:
        skipped = [c["name"] for c in result.checks if c["status"] == "NOT_RUN"]
        result.settle("NOT_RUN", "self_test_incomplete", "not run on this platform: " + ", ".join(skipped))
    else:
        result.settle("PASS")


# ── Entry point ──────────────────────────────────────────────────────────────


def _emit(result, report):
    payload = result.to_dict()
    text = json.dumps(payload, sort_keys=True)
    if report is not None:
        try:
            report.write(text + "\n")
        except OSError as exc:
            result.settle("FAIL", "report_write_failed", f"report not written: {exc.__class__.__name__}")
            payload = result.to_dict()
            text = json.dumps(payload, sort_keys=True)
        finally:
            report.close()
    for reason in payload["reasons"]:
        sys.stderr.write(f"test_multiuser: {payload['status']} {reason['code']}: {reason['detail']}\n")
    sys.stdout.write(RESULT_PREFIX + text + "\n")
    sys.stdout.flush()
    return payload["exit_code"]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    result = Result()
    report = None
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, _signal_handler)
    _SignalState.phase = "run"
    _SignalState.received = None
    try:
        if "--" in argv:
            split = argv.index("--")
            launcher_argv, passthrough = argv[:split], argv[split + 1:]
        else:
            launcher_argv, passthrough = argv, []
        args = build_parser().parse_args(launcher_argv)
        if os.name not in ("posix", "nt"):
            raise refused("unsupported_platform", f"platform {os.name!r} has unknown path semantics")
        repo_root = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
        helper, helper_source = load_helper(repo_root)
        if args.report:
            report = ReportTarget(args.report, helper.operator_home())
        if not 0 < args.child_timeout <= 86400:
            raise refused("usage", "--child-timeout must be between 1 and 86400 seconds")
        selection = resolve_selection(args, passthrough)
        result.tier, result.mode = selection.tier, selection.mode
        result.agent = selection.agent_mode
        if selection.mode == "self-test":
            run_self_test(result, repo_root, helper)
        else:
            run_selected(selection, args, passthrough, result, repo_root, helper, helper_source)
    except Outcome as exc:
        result.settle(exc.status, exc.code, exc.detail)
    except _Interrupted as exc:
        result.settle("FAIL", "interrupted", f"signal {exc.signum} received before a child was running")
    except Exception as exc:  # never let an unexpected error look like a pass
        result.settle("FAIL", "launcher_error", f"{exc.__class__.__name__}: {exc}")
    finally:
        _SignalState.phase = "teardown"
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if _SignalState.received is not None and result.status == "PASS":
        result.settle("FAIL", "interrupted", f"signal {_SignalState.received} received")
    return _emit(result, report)


if __name__ == "__main__":
    sys.exit(main())
