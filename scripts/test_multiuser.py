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

* refuses unsafe paths, links, pytest options and option combinations;
* statically checks the repo ``.venv`` and base interpreter for startup hooks
  and editable or Agent sources, without executing them;
* denies implicit installed-Agent discovery and checkout ``.env`` files
  (metadata only, never read);
* allocates a private disposable state root and a freshly built allowlisted
  child environment; nothing is copied wholesale from the parent;
* runs pytest only through ``./scripts/test.sh`` with ``--confcutdir`` pinned
  to ``tests/multiuser``, and derives PASS from the JUnit counts.

Python-level fixture guards (see ``multiuser_test_fixtures.NetworkGuard``) are
not OS network containment; containment and remote tiers stay NOT_RUN here.
This launcher stays stdlib-only and imports no product module.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
PYTEST_PLUGINS = ("pytest_timeout", "pytest_asyncio.plugin")
INSTALLED_AGENT_ROOTS = (
    "/usr/local/lib/hermes-agent",
    "/opt/hermes-agent",
    "/usr/local/hermes-agent",
    "/usr/local/share/hermes-agent",
)
SITE_AGENT_NAMES = ("run_agent.py", "run_agent", "hermes_cli", "cron", "hermes", "hermes_agent")
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise refused("unsafe_symlink", f"script {raw!r} changed during validation")
        if opened.st_size > 8 * 1024 * 1024:
            raise refused("script_invalid", f"script {raw!r} is larger than 8 MiB")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return path, b"".join(chunks)


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
    _walk_components(repo_root, path)


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
        _walk_components(repo_root, tests_root)
        out.append(os.path.join("tests", "multiuser"))
    return out


def validate_agent_checkout(raw, repo_root, operator_home):
    """Validate an explicit Agent checkout and return (path, (dev, ino))."""
    if "\0" in raw:
        raise refused("usage", "agent checkout contains a NUL byte")
    path = os.path.normpath(os.path.abspath(raw))
    installed = [os.path.join(operator_home, ".hermes"), os.path.join(operator_home, "hermes-agent")]
    installed.extend(INSTALLED_AGENT_ROOTS)
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
    return path, (st.st_dev, st.st_ino)


def validate_output_file(raw, label):
    """Return an absolute path for a file the launcher writes (final component never followed)."""
    if "\0" in raw:
        raise refused("usage", f"{label} contains a NUL byte")
    path = os.path.abspath(raw)
    parent = os.path.realpath(os.path.dirname(path))
    if not os.path.isdir(parent):
        raise refused("path_missing", f"{label} directory does not exist")
    path = os.path.join(parent, os.path.basename(path))
    if os.path.lexists(path):
        st = os.lstat(path)
        if _is_link_like(st) or not stat.S_ISREG(st.st_mode):
            raise refused("unsafe_symlink", f"{label} exists and is not a regular file")
    return path


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
    return BaseInterpreter(exe, real, prefix, version, stdlib)


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


def scan_site_packages(site_dir, allowed_root):
    """Refuse site-packages content that runs code at startup or exposes an Agent."""
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
                entry = text if os.path.isabs(text) else os.path.join(site_dir, text)
                if not _is_within(os.path.realpath(entry), allowed_root):
                    problems.append(f"{path} adds a path outside {allowed_root}")
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
        scan_site_packages(site, real_root)
    for name in ("hermes", "hermes.exe"):
        if os.path.lexists(os.path.join(root, "bin", name)):
            raise not_run("implicit_agent_discoverable", "repo .venv exposes a 'hermes' launcher")
    return Venv(root, python, version, site_dirs, base)


def select_base_python(parent_env, operator_home):
    """Pick a supported base interpreter for a first .venv bootstrap, statically."""
    explicit = parent_env.get("HERMES_WEBUI_TEST_PYTHON", "").strip()
    if explicit:
        return inspect_base_interpreter(explicit, operator_home)
    for name in ("python3.13", "python3.12", "python3.11", "python3"):
        for directory in parent_env.get("PATH", "").split(os.pathsep):
            if not directory or not os.path.isabs(directory):
                continue
            candidate = os.path.join(directory, name)
            if not os.path.isfile(candidate):
                continue
            try:
                return inspect_base_interpreter(candidate, operator_home)
            except Outcome:
                continue
    raise not_run("unsupported_python", "no statically identifiable Python 3.11-3.13 outside the operator home")


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


class StateRoot:
    """A private 0700 directory, anchored by descriptor and removed on every exit."""

    def __init__(self, base):
        self.path = tempfile.mkdtemp(prefix="hermes-mu-", dir=base)
        self._fd = None
        self._ident = None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            if os.name == "posix":
                self._fd = os.open(self.path, flags)
                st = os.fstat(self._fd)
            else:
                st = os.stat(self.path)
            lst = os.lstat(self.path)
            if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino) or not stat.S_ISDIR(lst.st_mode):
                raise refused("unsafe_symlink", "state root changed while it was allocated")
            if os.name == "posix" and (lst.st_uid != os.getuid() or lst.st_mode & 0o077):
                raise refused("unsafe_symlink", "state root is not private")
            self._ident = (st.st_dev, st.st_ino)
        except BaseException:
            self._close_fd()
            raise

    def _close_fd(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def intact(self):
        try:
            st = os.lstat(self.path)
        except OSError:
            return False
        return not _is_link_like(st) and (st.st_dev, st.st_ino) == self._ident

    def remove(self):
        """Delete the root only while it is still the allocated directory."""
        try:
            if not os.path.lexists(self.path):
                return True
            if not self.intact():
                raise failed("teardown_failed", "state root was replaced; it was not deleted")
            shutil.rmtree(self.path)
            return not os.path.lexists(self.path)
        finally:
            self._close_fd()


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


def run_child(cmd, *, env, cwd, timeout, result=None, label="child"):
    """Run ``cmd`` in its own process group with inherited stdio and bounded waits."""
    kwargs = {"env": env, "cwd": cwd, "stdin": subprocess.DEVNULL, "close_fds": True}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(cmd, **kwargs)
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                gone = terminate_group(proc)
                raise failed("child_timeout", f"{label} exceeded {timeout}s; owned group terminated={gone}")
            try:
                code = proc.wait(timeout=min(remaining, 0.5))
                break
            except subprocess.TimeoutExpired:
                continue
    except _Interrupted as exc:
        _SignalState.phase = "teardown"
        gone = terminate_group(proc, first_signal=signal.SIGINT)
        raise failed("interrupted", f"signal {exc.signum} received; owned group terminated={gone}") from None
    if os.name == "posix" and _group_alive(proc.pid):
        gone = terminate_group(proc)
        if result is not None:
            result.check("leftover_descendants_terminated", "PASS" if gone else "FAIL", label)
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
    """Load the stdlib helper by validated path (works under -I -S)."""
    path = os.path.join(repo_root, "scripts", "multiuser_test_fixtures.py")
    st = _walk_components(repo_root, path)
    if not stat.S_ISREG(st.st_mode):
        raise refused("path_missing", "scripts/multiuser_test_fixtures.py is not a regular file")
    spec = importlib.util.spec_from_file_location("_hermes_mu_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ── Real runs ────────────────────────────────────────────────────────────────

_SCRIPT_RUNNER = (
    "import os, sys\n"
    "_path, _snapshot = sys.argv[1], sys.argv[2]\n"
    "with open(_snapshot, 'rb') as _f:\n"
    "    _code = compile(_f.read(), _path, 'exec')\n"
    "sys.argv = [_path] + sys.argv[3:]\n"
    "sys.path[0] = os.path.dirname(_path)\n"
    "exec(_code, {'__name__': '__main__', '__file__': _path, '__spec__': None})\n"
)


def _pytest_base_args(repo_root, confcutdir, ini):
    args = ["-p", "no:cacheprovider"]
    for plugin in PYTEST_PLUGINS:
        args.extend(("-p", plugin))
    args.extend((f"--rootdir={repo_root}", "-c", ini, f"--confcutdir={confcutdir}"))
    return args


def _pytest_ini(repo_root, state_root):
    ini = os.path.join(repo_root, "pytest.ini")
    if os.path.lexists(ini):
        st = os.lstat(ini)
        if _is_link_like(st) or not stat.S_ISREG(st.st_mode):
            raise refused("unsafe_symlink", "pytest.ini is not a regular file")
        return ini
    generated = os.path.join(state_root, "launcher", "pytest.ini")
    with open(generated, "w", encoding="utf-8") as handle:
        handle.write("[pytest]\n")
    return generated


def run_selected(selection, args, passthrough, result, repo_root, helper):
    parent_env = dict(os.environ)
    home = helper.operator_home()
    test_sh = os.path.join(repo_root, "scripts", "test.sh")
    sh_st = _walk_components(repo_root, test_sh)
    if not stat.S_ISREG(sh_st.st_mode):
        raise refused("path_missing", "scripts/test.sh is not a regular file")

    pytest_args = script_path = snapshot = None
    if selection.mode == "pytest":
        pytest_args = validate_pytest_args(passthrough, repo_root)
    else:
        if any("\0" in arg for arg in passthrough):
            raise refused("usage", "script argument contains a NUL byte")
        script_path, snapshot = validate_repo_script(args.script, repo_root)
    if os.name != "posix":
        raise not_run("platform_route_unverified", "pytest/script runs need a verified Windows shell route")
    tier_prerequisites(selection, args)

    agent_path = agent_ident = None
    if args.agent_checkout:
        agent_path, agent_ident = validate_agent_checkout(args.agent_checkout, repo_root, home)
        result.agent = "explicit"
    hits = dotenv_hits(*[p for p in (repo_root, agent_path) if p])
    if hits:
        raise not_run("checkout_dotenv_present", "a .env would be loaded: " + ", ".join(hits))
    path_dirs = child_path_dirs(repo_root)
    agent_hits = implicit_agent_hits(repo_root, path_dirs)
    if agent_hits:
        raise not_run("implicit_agent_discoverable", "installed Agent discoverable at: " + ", ".join(agent_hits))

    bootstrap_base = None
    try:
        venv = inspect_venv(repo_root, home, result)
    except Outcome as exc:
        if exc.code != "venv_unavailable":
            raise
        if selection.tier == "browser":
            raise not_run("browser_runtime_unavailable", "repo .venv does not exist, so Playwright is absent") from None
        venv = None
        bootstrap_base = select_base_python(parent_env, home)
        scan_interpreter_hooks(bootstrap_base, result)
        scan_site_packages(bootstrap_base.site_packages, bootstrap_base.prefix)
    if venv is not None and selection.tier == "browser" and not browser_runtime_ready(venv):
        raise not_run("browser_runtime_unavailable", "repo .venv has no project-local Playwright browsers")
    result.check("preflight", "PASS", "paths, sources, dotenv, discovery and interpreter provenance checked")

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
        ini = _pytest_ini(repo_root, root.path)
        if venv is None:
            empty = os.path.join(root.path, "launcher", "no-conftest")
            os.makedirs(empty, mode=0o700)
            env = checked_child_env(parent_env, build_child_env(
                parent_env, layout, extra={"HERMES_WEBUI_TEST_PYTHON": bootstrap_base.exe}, **common
            ), helper)
            cmd = ["/bin/bash", test_sh] + _pytest_base_args(repo_root, empty, ini) + ["--version"]
            sys.stderr.write("test_multiuser: bootstrapping repo .venv through scripts/test.sh\n")
            code = run_child(cmd, env=env, cwd=repo_root, timeout=args.child_timeout, result=result,
                             label="bootstrap")
            if code != 0:
                raise failed("bootstrap_failed", f"scripts/test.sh bootstrap exited {code}")
            venv = inspect_venv(repo_root, home, result)
            if selection.tier == "browser" and not browser_runtime_ready(venv):
                raise not_run("browser_runtime_unavailable", "repo .venv has no project-local Playwright browsers")
            result.check("bootstrap", "PASS", "repo .venv created hermetically and re-validated")
        extra = {"PLAYWRIGHT_BROWSERS_PATH": "0"} if selection.tier == "browser" else None
        env = checked_child_env(parent_env, build_child_env(parent_env, layout, extra=extra, **common), helper)
        result.check("child_environment", "PASS", "allowlisted, disposable and verified before spawn")
        sys.stderr.write(
            f"test_multiuser: tier={selection.tier} mode={selection.mode} state={root.path} (disposable)\n"
        )
        if selection.mode == "pytest":
            junit = os.path.join(root.path, "launcher", "junit.xml")
            cmd = ["/bin/bash", test_sh] + _pytest_base_args(
                repo_root, os.path.join(repo_root, "tests", "multiuser"), ini
            ) + [f"--junitxml={junit}", "-o", "junit_family=xunit2"] + pytest_args
            code = run_child(cmd, env=env, cwd=repo_root, timeout=args.child_timeout, result=result,
                             label="pytest")
            result.child_exit_code = code
            counts = parse_junit(junit)
            result.tests = counts
            verdict = judge_pytest(code, counts)
        else:
            snap = os.path.join(root.path, "launcher", "script_snapshot.py")
            fd = os.open(snap, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            try:
                os.write(fd, snapshot)
            finally:
                os.close(fd)
            cmd = [venv_python, "-c", _SCRIPT_RUNNER, script_path, snap] + list(passthrough)
            code = run_child(cmd, env=env, cwd=repo_root, timeout=args.child_timeout, result=result,
                             label="script")
            result.child_exit_code = code
            if code == 0:
                verdict = None
            elif code == SCRIPT_NOT_RUN_EXIT:
                verdict = not_run("script_not_run", f"script exited {SCRIPT_NOT_RUN_EXIT} (prerequisite unavailable)")
            else:
                verdict = failed("child_failed", f"script exited {code}")
        if agent_path is not None:
            try:
                st = os.lstat(agent_path)
                same = not _is_link_like(st) and (st.st_dev, st.st_ino) == agent_ident
            except OSError:
                same = False
            if not same:
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
        ]
        for args, code in bad:
            self.expect(lambda args=args: validate_pytest_args(args, repo), "REFUSED", code)
        good = validate_pytest_args(
            ["-q", "tests/multiuser/test_ok.py::test_ok", "-k", "ok and not slow", "--timeout=30", "-rA"], repo
        )
        assert good[-1] == "-rA" and "tests/multiuser/test_ok.py::test_ok" in good
        assert validate_pytest_args(["-q"], repo) == ["-q", os.path.join("tests", "multiuser")]
        assert not os.path.lexists(self.marker)
        return f"{len(bad)} unsafe pytest arguments refused; default scope is tests/multiuser"

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
        cases = [
            (os.path.join(self.home, ".hermes", "hermes-agent"), "installed_agent_location"),
            ("/usr/local/lib/hermes-agent", "installed_agent_location"),
            (sibling, "implicit_discovery_location"),
            (os.path.join(repo, "nested-agent"), "agent_checkout_invalid"),
            (os.path.join(base, "agent-missing"), "path_missing"),
            (os.path.join(base, "agent-link"), "unsafe_symlink"),
            (os.path.join(base, "agent-empty"), "agent_checkout_invalid"),
        ]
        for raw, code in cases:
            self.expect(lambda raw=raw: validate_agent_checkout(raw, repo, self.home), "REFUSED", code)
        path, ident = validate_agent_checkout(good, repo, self.home)
        assert path == good and ident[1] == os.lstat(good).st_ino
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

    def fake_venv(self, name, *, version="3.13", include="false", base_hook=None):
        repo = self.fake_repo(name)
        exe = self.fake_base(name, version, base_hook)
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
        repo, _site = self.fake_venv("venv-clean")
        venv = inspect_venv(repo, self.home)
        assert venv.version == (3, 13)
        cases = []
        repo, site = self.fake_venv("venv-pth")
        self.write(os.path.join(site, "evil.pth"), "import os; " + self.marker_writer())
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-sitecustomize")
        self.write(os.path.join(site, "sitecustomize.py"), self.marker_writer())
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-path-pth")
        self.write(os.path.join(site, "outside.pth"), os.path.join(self.scratch, "elsewhere") + "\n")
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-egg-link")
        self.write(os.path.join(site, "pkg.egg-link"), "/elsewhere\n")
        cases.append((repo, "venv_provenance_unknown"))
        repo, site = self.fake_venv("venv-agent")
        self.write(os.path.join(site, "run_agent.py"), self.marker_writer())
        cases.append((repo, "implicit_agent_discoverable"))
        repo, _site = self.fake_venv("venv-system-site", include="true")
        cases.append((repo, "venv_provenance_unknown"))
        repo, _site = self.fake_venv("venv-base-hook", base_hook=self.marker_writer())
        cases.append((repo, "venv_provenance_unknown"))
        repo, _site = self.fake_venv("venv-old", version="3.10")
        cases.append((repo, "unsupported_python"))
        linked = self.fake_repo("venv-linked")
        clean_repo, _site = self.fake_venv("venv-link-target")
        self.symlink(os.path.join(clean_repo, ".venv"), os.path.join(linked, ".venv"))
        cases.append((linked, "venv_provenance_unknown"))
        for repo, code in cases:
            self.expect(lambda repo=repo: inspect_venv(repo, self.home), "NOT_RUN", code)
        assert not os.path.lexists(self.marker), "a startup hook or interpreter was executed"
        return f"clean synthetic venv accepted; {len(cases)} hostile venvs NOT_RUN without execution"

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
            raise RuntimeError("synthetic failure")
        except RuntimeError:
            pass
        finally:
            assert root.remove() is True
        assert not os.path.lexists(root.path), "state root survived a failure"
        swapped = StateRoot(base)
        moved = swapped.path + "-moved"
        os.rename(swapped.path, moved)
        os.makedirs(swapped.path, mode=0o700)
        keep = self.write(os.path.join(swapped.path, "external-sentinel"), "keep")
        try:
            self.expect(swapped.remove, "FAIL", "teardown_failed")
            assert os.path.exists(keep), "a replaced state root was deleted"
        finally:
            shutil.rmtree(swapped.path, ignore_errors=True)
            shutil.rmtree(moved, ignore_errors=True)
        return "state root removed after failure; a replaced root is left untouched"

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
            "pytest_args", "agent_checkout", "tiers", "venv_provenance", "discovery_and_dotenv",
            "loopback_fixture", "network_guard", "validate_destination", "child_lifecycle",
            "teardown", "no_product_import",
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


def _emit(result, report_path):
    payload = result.to_dict()
    text = json.dumps(payload, sort_keys=True)
    if report_path:
        try:
            fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(fd, (text + "\n").encode())
            finally:
                os.close(fd)
        except OSError as exc:
            result.settle("FAIL", "report_write_failed", f"report not written: {exc.__class__.__name__}")
            payload = result.to_dict()
            text = json.dumps(payload, sort_keys=True)
    for reason in payload["reasons"]:
        sys.stderr.write(f"test_multiuser: {payload['status']} {reason['code']}: {reason['detail']}\n")
    sys.stdout.write(RESULT_PREFIX + text + "\n")
    sys.stdout.flush()
    return payload["exit_code"]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    result = Result()
    report_path = None
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
        if args.report:
            report_path = validate_output_file(args.report, "--report")
        if not 0 < args.child_timeout <= 86400:
            raise refused("usage", "--child-timeout must be between 1 and 86400 seconds")
        selection = resolve_selection(args, passthrough)
        result.tier, result.mode = selection.tier, selection.mode
        result.agent = selection.agent_mode
        if os.name not in ("posix", "nt"):
            raise refused("unsupported_platform", f"platform {os.name!r} has unknown path semantics")
        repo_root = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
        helper = load_helper(repo_root)
        if selection.mode == "self-test":
            run_self_test(result, repo_root, helper)
        else:
            run_selected(selection, args, passthrough, result, repo_root, helper)
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
    return _emit(result, report_path)


if __name__ == "__main__":
    sys.exit(main())
