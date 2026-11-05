"""Independent behavior checks for the F02 disposable-unit controller.

These tests are intended to run only inside an independently admitted unit.
The fake Docker CLI cases exercise controller boundaries and ordering; they are
simulations and do not establish OS-level containment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import shlex
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = REPO_ROOT / "scripts" / "multiuser_unit.sh"
WORKER = REPO_ROOT / "scripts" / "test_multiuser.py"
FAKE_DOCKER_TEMPLATE = (
    Path(__file__).parent / "fixtures" / "fake_unit_docker.sh"
)
FAKE_ENGINE_TEMPLATE = (
    Path(__file__).parent / "fixtures" / "fake_unit_docker.py"
)
CONTROLLER_PREFIX = "MULTIUSER_UNIT_RESULT "
WORKER_PREFIX = "MULTIUSER_RESULT "
BASE_IMAGE = "python:3.13-slim@sha256:" + "a" * 64
FAKE_ENGINE_ID = "mu-synthetic-engine-id"
FAKE_UNIT_CONTAINER_ID = "d" * 64
FAKE_PREP_CONTAINER_ID = "e" * 64
SYNTHETIC_SENTINELS = {
    "docker_host": "tcp://mu-synthetic-invalid.invalid:2375",
    "docker_context": "mu-synthetic-context",
    "http_proxy": "http://mu-synthetic-proxy.invalid:8080",
    "aws_secret": "mu-synthetic-aws-key-not-real",
    "ssh_auth_sock": "/tmp/mu-synthetic-agent.sock",
}
ADMISSION_MISMATCHES = [
    ("wrong-image", "image"),
    ("wrong-user", "user"),
    ("wrong-workdir", "workdir"),
    ("wrong-command", "cmd"),
    ("entrypoint", "entrypoint"),
    ("env", "env"),
    ("volumes", "volumes"),
    ("writable-root", "read_only_rootfs"),
    ("host-network", "network"),
    ("privileged", "privileged"),
    ("missing-cap-drop", "cap_drop"),
    ("cap-add", "cap_add"),
    ("no-new-privileges", "no_new_privileges"),
    ("host-pid", "pid_mode"),
    ("non-private-ipc", "ipc_mode"),
    ("host-uts", "uts_mode"),
    ("host-userns", "userns_mode"),
    ("host-cgroupns", "cgroupns_mode"),
    ("binds", "binds"),
    ("host-mounts", "host_mounts"),
    ("top-mounts", "mounts"),
    ("devices", "devices"),
    ("device-requests", "device_requests"),
    ("volumes-from", "volumes_from"),
    ("links", "links"),
    ("extra-hosts", "extra_hosts"),
    ("tmpfs", "tmpfs"),
    ("pids-limit", "pids_limit"),
    ("memory", "memory"),
    ("cpus", "cpus"),
    ("restart", "restart"),
    ("auto-remove", "auto_remove"),
    ("init", "init"),
    ("log-driver", "log_driver"),
]


def _result(stdout: str, prefix: str) -> dict:
    lines = stdout.splitlines()
    matches = [line for line in lines if line.startswith(prefix)]
    assert len(matches) == 1, f"expected one {prefix.strip()} record, got {len(matches)}"
    assert next((line for line in reversed(lines) if line.strip()), "") == matches[0], (
        "the machine result must be the final non-empty stdout line"
    )
    return json.loads(matches[0][len(prefix) :])


def _socket_path(tmp_path: Path) -> Path:
    path = tmp_path / "engine.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
    finally:
        listener.close()
    return path


def _fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    assert FAKE_DOCKER_TEMPLATE.is_file(), (
        f"missing fake Docker fixture: {FAKE_DOCKER_TEMPLATE}"
    )
    log = tmp_path / "fake-docker.log"
    script = tmp_path / "docker-fake"
    template = FAKE_DOCKER_TEMPLATE.read_text(encoding="utf-8")
    script.write_text(
        template.replace("__MU_CALL_LOG__", shlex.quote(str(log))),
        encoding="utf-8",
    )
    script.chmod(0o700)
    return script, log


def _fake_engine(
    tmp_path: Path,
    scenario: str,
    *,
    state_root: Path | None = None,
    engine_id: str = FAKE_ENGINE_ID,
) -> tuple[Path, Path]:
    assert FAKE_ENGINE_TEMPLATE.is_file(), (
        f"missing synthetic engine fixture: {FAKE_ENGINE_TEMPLATE}"
    )
    root = state_root if state_root is not None else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    script = root / "docker-engine-simulation"
    template = FAKE_ENGINE_TEMPLATE.read_text(encoding="utf-8")
    rendered = template.replace("__MU_ROOT__", repr(str(root)))
    rendered = rendered.replace("__MU_SCENARIO__", repr(scenario))
    rendered = rendered.replace("__MU_ENGINE_ID__", repr(engine_id))
    rendered = rendered.replace("__MU_JQ_MARKER__", repr(str(root / "jq-fail.marker")))
    script.write_text(f"#!{sys.executable}\n" + rendered, encoding="utf-8")
    script.chmod(0o700)
    return script, root / "fake-calls.jsonl"


def _fake_jq_failure_wrapper(
    tmp_path: Path, marker: Path, blocked_path: Path
) -> Path:
    wrapper = tmp_path / "jq-failure-wrapper"
    wrapper.write_text(
        "#!/bin/sh\n"
        "last=\n"
        "for arg do last=$arg; done\n"
        f"if [ -f {shlex.quote(str(marker))} ] && [ \"$last\" = {shlex.quote(str(blocked_path))} ]; then exit 1; fi\n"
        "exec /usr/bin/jq \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return wrapper


def _logged_calls(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _wait_for_file(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"synthetic barrier was not reached: {path.name}")


def _assert_process_group_child_gone(pid_path: Path, timeout: float = 6.0) -> None:
    assert pid_path.is_file(), "the fake client did not publish its child PID"
    pid = int(pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        time.sleep(0.02)
    raise AssertionError(f"fake client descendant {pid} survived bounded cancellation")


def _assert_cap_plus_one_stream_file(evidence: Path, cap: int, label: str) -> None:
    matches = [
        path for path in evidence.rglob("*")
        if path.is_file() and path.stat().st_size == cap + 1
    ]
    assert matches, f"{label} did not retain the documented cap+1 overflow marker"


def _synthetic_checkout(tmp_path: Path) -> tuple[Path, Path, str]:
    """Create a real, inert Git checkout entirely below tmp_path for the CLI."""
    repo = tmp_path / "controller-checkout"
    scripts = repo / "scripts"
    tests = repo / "tests" / "multiuser"
    fixtures = tests / "fixtures"
    scripts.mkdir(parents=True)
    fixtures.mkdir(parents=True)
    (repo / ".gitattributes").write_text(
        "requirements.txt diff=mu-synthetic filter=mu-synthetic\n",
        encoding="utf-8",
    )
    tracked = (
        "scripts/multiuser_unit.sh",
        "scripts/multiuser_unit.Dockerfile",
        "scripts/test.sh",
        "scripts/test_multiuser.py",
        "requirements.txt",
        "requirements-dev.txt",
        ".gitattributes",
        "tests/multiuser/test_f02_unit.py",
        "tests/multiuser/fixtures/fake_unit_docker.py",
    )
    for relative in tracked:
        source = REPO_ROOT / relative
        assert source.is_file(), f"missing source required by synthetic checkout: {source}"
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(source.stat().st_mode & 0o777)

    git_home = tmp_path / "git-home"
    git_home.mkdir(mode=0o700)
    git_templates = tmp_path / "git-templates"
    git_templates.mkdir(mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(git_home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TEMPLATE_DIR": str(git_templates),
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repo), *args],
            cwd=tmp_path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    initialized = subprocess.run(
        ["/usr/bin/git", "init", "-b", "main", str(repo)],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert initialized.returncode == 0, initialized.stderr
    for key, value in (
        ("user.name", "F02 synthetic test"),
        ("user.email", "f02-synthetic@example.invalid"),
        ("core.hooksPath", str(tmp_path / "no-hooks")),
        ("commit.gpgsign", "false"),
        ("credential.helper", ""),
    ):
        configured = git("config", "--local", key, value)
        assert configured.returncode == 0, configured.stderr
    added = git("add", "--all")
    assert added.returncode == 0, added.stderr
    committed = git("commit", "--no-gpg-sign", "-m", "synthetic F02 controller checkout")
    assert committed.returncode == 0, committed.stderr
    revision = git("rev-parse", "HEAD")
    assert revision.returncode == 0, revision.stderr
    commit = revision.stdout.strip()
    assert len(commit) == 40 and all(char in "0123456789abcdef" for char in commit)
    return repo, repo / "scripts" / "multiuser_unit.sh", commit


def _git_environment(tmp_path: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path / "git-home"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TEMPLATE_DIR": str(tmp_path / "git-templates"),
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(repo: Path, tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        cwd=tmp_path,
        env=_git_environment(tmp_path),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )


def _git_bytes(
    repo: Path, tmp_path: Path, *args: str, input_bytes: bytes
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        cwd=tmp_path,
        env=_git_environment(tmp_path),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )


def _malformed_candidate(
    repo: Path, tmp_path: Path, kind: str, base_commit: str
) -> str:
    if kind == "gitlink":
        mode, object_id, path = b"160000", base_commit, b"submodule"
    else:
        target = b"../safe\n" if kind == "newline-symlink-target" else b"synthetic\n"
        blob = _git_bytes(repo, tmp_path, "hash-object", "-w", "--stdin", input_bytes=target)
        assert blob.returncode == 0, blob.stderr.decode(errors="replace")
        mode = b"120000" if kind == "newline-symlink-target" else b"100644"
        object_id = blob.stdout.decode().strip()
        paths = {
            "newline-path": b"bad\nname",
            "parent-path": b"../escape",
            "absolute-path": b"/absolute",
            "double-slash-path": b"bad//name",
        }
        path = paths.get(kind, b"unsafe-link")
    tree_data = mode + b" " + path + b"\0" + bytes.fromhex(object_id)
    tree = _git_bytes(
        repo,
        tmp_path,
        "hash-object",
        "-w",
        "-t",
        "tree",
        "--literally",
        "--stdin",
        input_bytes=tree_data,
    )
    assert tree.returncode == 0, tree.stderr.decode(errors="replace")
    committed = _git(
        repo,
        tmp_path,
        "commit-tree",
        tree.stdout.decode().strip(),
        "-m",
        "synthetic malformed source tree",
    )
    assert committed.returncode == 0, committed.stderr
    candidate = committed.stdout.strip()
    assert len(candidate) == 40 and all(char in "0123456789abcdef" for char in candidate)
    return candidate


def _build_runtime_evidence(
    tmp_path: Path,
    controller_path: Path,
    *,
    engine_id: str = FAKE_ENGINE_ID,
) -> tuple[Path, dict, list[dict]]:
    docker_bin, call_log = _fake_engine(
        tmp_path,
        "build-success",
        state_root=tmp_path / "build-engine-state",
        engine_id=engine_id,
    )
    build_evidence = tmp_path / "build-evidence"
    result = _run_controller(
        tmp_path,
        docker_bin,
        build_evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 0, controller
    assert controller["status"] == "PASS", controller
    return build_evidence / "result.json", controller, _logged_calls(call_log)


def _run_simulated_request(
    tmp_path: Path,
    *,
    controller_path: Path,
    commit: str,
    runtime_evidence: Path,
    image_id: str,
    scenario: str,
    engine_id: str = FAKE_ENGINE_ID,
    jq_bin: Path | None = None,
    worker_args: tuple[str, ...] = (
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
    ),
) -> tuple[subprocess.CompletedProcess[str], dict, list[dict]]:
    docker_bin, call_log = _fake_engine(
        tmp_path,
        scenario,
        state_root=tmp_path / f"run-engine-state-{scenario}",
        engine_id=engine_id,
    )
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "run",
        "--runtime-evidence",
        str(runtime_evidence),
        "--image-id",
        image_id,
        "--candidate",
        commit,
        "--timeout",
        "1" if scenario in {"timeout", "attach-timeout"} else "10",
        "--",
        *worker_args,
        controller_path=controller_path,
        jq_bin=jq_bin,
    )
    return result, _result(result.stdout, CONTROLLER_PREFIX), _logged_calls(call_log)


def _mutated_evidence(
    tmp_path: Path, source: Path, name: str, mutate: Callable[[dict], None]
) -> Path:
    directory = tmp_path / f"{name}-evidence-parent"
    directory.mkdir(mode=0o700)
    payload = json.loads(source.read_text(encoding="utf-8"))
    mutate(payload)
    target = directory / "result.json"
    target.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    target.chmod(0o600)
    return target


def _assert_previous_lease_preserved(
    evidence: Path, fake_root: Path
) -> dict:
    previous = fake_root / "lease-before-obstruction.bin"
    lease = evidence / "lease.json"
    assert previous.is_file()
    assert lease.read_bytes() == previous.read_bytes()
    payload = json.loads(lease.read_text(encoding="utf-8"))
    assert payload["schema"] == "hermes-webui/multiuser-unit-lease/1"
    assert isinstance(payload["containers"], list)
    assert isinstance(payload["images"], list)
    return payload


def _controller_command(
    tmp_path: Path,
    docker_bin: Path,
    evidence: Path,
    *command: str,
    dry_run: bool = False,
    controller_path: Path | None = None,
    engine_socket: Path | None = None,
    jq_bin: Path | None = None,
) -> list[str]:
    if controller_path is None:
        _, controller_path, _ = _synthetic_checkout(tmp_path)
    socket_path = engine_socket if engine_socket is not None else _socket_path(tmp_path)
    args = [
        "/usr/bin/env",
        "-i",
        "/bin/bash",
        "-p",
        str(controller_path),
        "--engine-socket",
        str(socket_path),
        "--evidence-dir",
        str(evidence),
        "--docker-bin",
        str(docker_bin),
        "--jq-bin",
        str(jq_bin if jq_bin is not None else Path("/usr/bin/jq")),
    ]
    if dry_run:
        args.append("--dry-run")
    args.extend(command)
    return args


def _run_controller(
    tmp_path: Path,
    docker_bin: Path,
    evidence: Path,
    *command: str,
    env: dict[str, str] | None = None,
    dry_run: bool = False,
    controller_path: Path | None = None,
    engine_socket: Path | None = None,
    jq_bin: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    argv = _controller_command(
        tmp_path,
        docker_bin,
        evidence,
        *command,
        dry_run=dry_run,
        controller_path=controller_path,
        engine_socket=engine_socket,
        jq_bin=jq_bin,
    )
    child_env = env if env is not None else {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path / "caller-home"),
    }
    return subprocess.run(
        argv,
        cwd=tmp_path,
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def test_worker_without_unit_admission_is_not_run_before_argparse(tmp_path: Path) -> None:
    assert WORKER.is_file(), f"missing F02 worker: {WORKER}"
    state_path = tmp_path / "must-not-be-allocated"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path / "worker-home"),
        "HERMES_MU_UNIT_STATE": str(state_path),
    }
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(WORKER), "--help"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    worker = _result(result.stdout, WORKER_PREFIX)
    assert result.returncode == 3
    assert worker["status"] == "NOT_RUN"
    assert any(
        reason["code"] == "unit_admission_required" for reason in worker["reasons"]
    )
    assert "usage:" not in result.stdout.lower()
    assert not state_path.exists(), "unadmitted worker allocated state before refusing"


def test_admitted_worker_self_test_executes_and_reports_real_checks(
    tmp_path: Path,
) -> None:
    """I2 acceptance: exercise the actual worker with the outer unit context.

    The supplied unit identity is advisory worker context only. The enclosing
    independently admitted unit, not this subprocess result, is the authority
    for OS isolation. This required positive intentionally fails if I2 does not
    propagate the outer context into pytest's environment.
    """
    unit_names = (
        "HERMES_MU_UNIT_ID",
        "HERMES_MU_UNIT_NONCE",
        "HERMES_MU_UNIT_SRC",
        "HERMES_MU_UNIT_STATE",
    )
    missing = [name for name in unit_names if not os.environ.get(name)]
    assert not missing, f"admitted worker context was not propagated: {missing}"
    child_env = {name: os.environ[name] for name in unit_names}
    child_env.update(
        {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ["HERMES_MU_UNIT_STATE"],
        }
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(WORKER), "--self-test"],
        cwd=REPO_ROOT,
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    worker = _result(result.stdout, WORKER_PREFIX)
    assert result.returncode == 0
    assert worker["status"] == "PASS"
    assert worker["exit_code"] == 0
    assert worker["tier"] == "self-test"
    assert worker["mode"] == "self-test"
    assert worker["unit"]["id"] == os.environ["HERMES_MU_UNIT_ID"]
    assert worker["unit"]["nonce"] == os.environ["HERMES_MU_UNIT_NONCE"]
    assert worker["tests"] is None
    checks = worker["checks"]
    assert checks, "self-test PASS must include performed checks"
    assert all(check["status"] == "PASS" for check in checks), checks
    assert worker["reasons"] == []
    assert set(worker["claims"].values()) == {False}


def test_controller_dry_run_is_not_run_and_never_calls_docker(tmp_path: Path) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    evidence = tmp_path / "build-evidence"
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        dry_run=True,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 3
    assert controller["status"] == "NOT_RUN"
    assert controller["dry_run"] is True
    assert any(reason["code"] == "dry_run" for reason in controller["reasons"])
    assert controller["engine"] is None
    assert set(controller["claims"].values()) == {False}
    assert any(line.startswith("MULTIUSER_UNIT_PLAN ") for line in result.stdout.splitlines())
    assert not call_log.exists(), "dry-run contacted the synthetic Docker CLI"


def test_direct_entry_rejects_hostile_shell_startup_without_running_it(
    tmp_path: Path,
) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    marker = tmp_path / "shell-startup-marker"
    bash_env = tmp_path / "synthetic-bash-env"
    bash_env.write_text(f"printf 'BASH_ENV ran\\n' >> {shlex.quote(str(marker))}\n", encoding="utf-8")
    bash_env.chmod(0o600)
    evidence = tmp_path / "must-not-be-created"
    socket_path = _socket_path(tmp_path)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path / "hostile-home"),
        "BASH_ENV": str(bash_env),
        "BASH_FUNC_git%%": f"() {{ printf 'function ran\\n' >> {shlex.quote(str(marker))}; }}",
    }
    result = subprocess.run(
        [
            str(controller_path),
            "--engine-socket",
            str(socket_path),
            "--evidence-dir",
            str(evidence),
            "--docker-bin",
            str(docker_bin),
            "--jq-bin",
            "/usr/bin/jq",
            "--dry-run",
            "build",
            "--base-image",
            BASE_IMAGE,
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    outcome = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert outcome["status"] == "REFUSED"
    assert outcome["command"] is None
    assert any(reason["code"] == "unsupported_entry" for reason in outcome["reasons"])
    assert not marker.exists(), "inherited shell startup or function code ran"
    assert not evidence.exists(), "startup refusal allocated controller state"
    assert not call_log.exists(), "startup refusal reached the Docker CLI"


def test_unpinned_base_image_is_refused_before_engine_contact(tmp_path: Path) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    evidence = tmp_path / "unpinned-build-evidence"
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        "python:3.13-slim",
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "base_image_unpinned" for reason in controller["reasons"]
    )
    assert not call_log.exists(), "unpinned image request reached the Docker CLI"


def test_fake_controller_build_simulation_binds_recipe_and_freeze_evidence(
    tmp_path: Path,
) -> None:
    """The fake engine covers control flow only; it cannot attest a Docker build."""
    docker_bin, call_log = _fake_engine(tmp_path, "build-success")
    evidence = tmp_path / "synthetic-build-evidence"
    _repo, controller_path, recipe_commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    build = next(argv for argv in calls if argv[:1] == ["build"])
    assert result.returncode == 0
    assert controller["status"] == "PASS"
    assert controller["recipe"]["commit"] == recipe_commit
    assert controller["recipe"]["base_image"] == BASE_IMAGE
    assert controller["recipe"]["unit_image_id"] == "sha256:" + "1" * 64
    assert controller["recipe"]["freeze_sha256"]
    assert controller["recipe"]["tree"]
    assert controller["recipe"]["unit_layers"]
    assert controller["recipe"]["runtime_config"]["User"] == "10001:10001"
    assert set(controller["recipe"]["inputs"]) == {
        "requirements.txt",
        "requirements-dev.txt",
        "scripts/test.sh",
        "scripts/multiuser_unit.Dockerfile",
    }
    assert controller["protocol_simulation"] is True
    result_file = evidence / "result.json"
    result_stat = result_file.stat()
    assert result_stat.st_uid == os.getuid()
    assert result_stat.st_mode & 0o777 == 0o600
    assert evidence.stat().st_mode & 0o777 == 0o700
    assert build[build.index("--build-arg") + 1] == f"MU_BASE_IMAGE={BASE_IMAGE}"
    assert controller["cleanup"]["verified"] is True
    assert controller["cleanup"]["container_removed"] is True
    assert controller["claims"] and set(controller["claims"].values()) == {False}


def test_run_requires_runtime_evidence_before_contacting_engine(tmp_path: Path) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, "expected-venv-link")
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / "missing-runtime-evidence-option",
        "run",
        "--image-id",
        "sha256:" + "1" * 64,
        "--candidate",
        commit,
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(reason["code"] == "usage" for reason in controller["reasons"])
    assert not call_log.exists(), "run without prior build evidence contacted the engine"


def test_missing_runtime_evidence_file_is_refused_before_engine_contact(
    tmp_path: Path,
) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, "expected-venv-link")
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    missing = tmp_path / "no-such-build-evidence" / "result.json"
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / "missing-evidence-run",
        "run",
        "--runtime-evidence",
        str(missing),
        "--image-id",
        "sha256:" + "1" * 64,
        "--candidate",
        commit,
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_refused"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "missing build evidence reached the engine"


def test_build_refuses_recipe_worktree_drift_before_engine_contact(tmp_path: Path) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, "build-success")
    repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    requirements = repo / "requirements.txt"
    requirements.write_bytes(requirements.read_bytes() + b"# synthetic uncommitted drift\n")
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / "dirty-recipe-evidence",
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(reason["code"] == "recipe_dirty" for reason in controller["reasons"])
    assert not call_log.exists(), "dirty recipe reached the engine"


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        (
            "recipe-digest",
            lambda payload: payload["recipe"]["inputs"].__setitem__(
                "requirements.txt", "0" * 64
            ),
        ),
        (
            "recipe-dev-digest",
            lambda payload: payload["recipe"]["inputs"].__setitem__(
                "requirements-dev.txt", "0" * 64
            ),
        ),
        (
            "test-runner-digest",
            lambda payload: payload["recipe"]["inputs"].__setitem__(
                "scripts/test.sh", "0" * 64
            ),
        ),
        (
            "unit-dockerfile-digest",
            lambda payload: payload["recipe"]["inputs"].__setitem__(
                "scripts/multiuser_unit.Dockerfile", "0" * 64
            ),
        ),
        (
            "recipe-commit",
            lambda payload: payload["recipe"].__setitem__("commit", "0" * 40),
        ),
        (
            "recipe-tree",
            lambda payload: payload["recipe"].__setitem__("tree", "0" * 40),
        ),
        (
            "unit-image-id",
            lambda payload: payload["recipe"].__setitem__(
                "unit_image_id", "sha256:" + "9" * 64
            ),
        ),
    ],
)
def test_mutated_runtime_evidence_is_refused_before_resource_creation(
    tmp_path: Path, name: str, mutate: Callable[[dict], None]
) -> None:
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    altered = _mutated_evidence(tmp_path, runtime_evidence, name, mutate)
    result, controller, records = _run_simulated_request(
        tmp_path,
        controller_path=controller_path,
        commit=commit,
        runtime_evidence=altered,
        image_id=build_result["recipe"]["unit_image_id"],
        scenario=f"mutated-{name}",
    )
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_invalid"
        for reason in controller["reasons"]
    )
    assert not any(argv[:1] == ["create"] for argv in calls)


def test_linked_runtime_evidence_is_refused_before_engine_contact(tmp_path: Path) -> None:
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    link_parent = tmp_path / "linked-runtime-evidence"
    link_parent.mkdir(mode=0o700)
    linked = link_parent / "result.json"
    linked.symlink_to(runtime_evidence)
    docker_bin, call_log = _fake_engine(
        tmp_path,
        "expected-venv-link",
        state_root=tmp_path / "linked-evidence-engine",
    )
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / "linked-evidence-run",
        "run",
        "--runtime-evidence",
        str(linked),
        "--image-id",
        build_result["recipe"]["unit_image_id"],
        "--candidate",
        commit,
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_refused"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "linked evidence reached the engine"


@pytest.mark.parametrize("unsafe_part", ["file-mode", "parent-mode"])
def test_runtime_evidence_requires_private_owned_metadata(
    tmp_path: Path, unsafe_part: str
) -> None:
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    parent = tmp_path / f"unsafe-evidence-{unsafe_part}"
    parent.mkdir(mode=0o700)
    candidate_evidence = parent / "result.json"
    shutil.copyfile(runtime_evidence, candidate_evidence)
    candidate_evidence.chmod(0o600)
    if unsafe_part == "file-mode":
        candidate_evidence.chmod(0o644)
    else:
        parent.chmod(0o755)
    docker_bin, call_log = _fake_engine(
        tmp_path,
        f"unsafe-evidence-{unsafe_part}",
        state_root=tmp_path / f"unsafe-evidence-engine-{unsafe_part}",
    )
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / f"unsafe-evidence-run-{unsafe_part}",
        "run",
        "--runtime-evidence",
        str(candidate_evidence),
        "--image-id",
        build_result["recipe"]["unit_image_id"],
        "--candidate",
        commit,
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_refused"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "unsafe build metadata reached the engine"


def test_runtime_evidence_engine_binding_precedes_all_resource_creation(
    tmp_path: Path,
) -> None:
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    result, controller, records = _run_simulated_request(
        tmp_path,
        controller_path=controller_path,
        commit=commit,
        runtime_evidence=runtime_evidence,
        image_id=build_result["recipe"]["unit_image_id"],
        scenario="engine-mismatch",
        engine_id="mu-synthetic-other-engine",
    )
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_mismatch"
        for reason in controller["reasons"]
    )
    assert not any(argv[:1] == ["create"] for argv in calls)


def test_runtime_evidence_image_id_must_match_explicit_run_image(
    tmp_path: Path,
) -> None:
    _repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, _build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    docker_bin, call_log = _fake_engine(
        tmp_path,
        "expected-venv-link",
        state_root=tmp_path / "wrong-runtime-image-engine",
    )
    result = _run_controller(
        tmp_path,
        docker_bin,
        tmp_path / "wrong-runtime-image-run",
        "run",
        "--runtime-evidence",
        str(runtime_evidence),
        "--image-id",
        "sha256:" + "9" * 64,
        "--candidate",
        commit,
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "runtime_evidence_invalid"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "mismatched image evidence reached the engine"


@pytest.mark.parametrize(
    "kind",
    [
        "gitlink",
        "newline-path",
        "parent-path",
        "absolute-path",
        "double-slash-path",
        "newline-symlink-target",
    ],
)
def test_unsafe_git_tree_entries_are_refused_before_container_creation(
    tmp_path: Path, kind: str
) -> None:
    repo, controller_path, base_commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_calls = _build_runtime_evidence(
        tmp_path, controller_path
    )
    candidate = _malformed_candidate(repo, tmp_path, kind, base_commit)
    result, controller, records = _run_simulated_request(
        tmp_path,
        controller_path=controller_path,
        commit=candidate,
        runtime_evidence=runtime_evidence,
        image_id=build_result["recipe"]["unit_image_id"],
        scenario=f"unsafe-tree-{kind}",
    )
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(reason["code"] == "candidate_invalid" for reason in controller["reasons"])
    assert not any(argv[:1] == ["create"] for argv in calls)


def test_fake_controller_build_failure_never_becomes_a_pass(tmp_path: Path) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, "build-fail")
    evidence = tmp_path / "synthetic-build-failure-evidence"
    _repo, controller_path, _recipe_commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "build_failed" for reason in controller["reasons"])
    assert not any(
        _docker_argv(record)[:2] == ["create", "--name"]
        for record in _logged_calls(call_log)
    )
    assert controller["claims"] and set(controller["claims"].values()) == {False}


@pytest.mark.parametrize(
    "scenario",
    [
        "implicit-volume",
        "implicit-onbuild",
        "implicit-entrypoint",
        "implicit-healthcheck",
        "wrong-runtime-user",
        "wrong-runtime-workdir",
    ],
)
def test_build_rejects_unsafe_unit_image_config_before_freeze_probe(
    tmp_path: Path, scenario: str
) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, scenario)
    evidence = tmp_path / f"unsafe-build-config-{scenario}"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "unit_image_config_refused"
        for reason in controller["reasons"]
    )
    assert any(argv[:1] == ["build"] for argv in calls)
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert not any(argv[:1] == ["cp"] for argv in calls)


@pytest.mark.parametrize(
    "scenario",
    [
        "probe-running",
        "probe-pid",
        "probe-command",
        "probe-network",
        "probe-mount",
        "probe-volume",
        "probe-device",
        "probe-log-driver",
    ],
)
def test_build_freeze_probe_must_pass_its_own_admission_check(
    tmp_path: Path, scenario: str
) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, scenario)
    evidence = tmp_path / f"unsafe-build-probe-{scenario}"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "probe_admission_failed"
        for reason in controller["reasons"]
    )
    assert any(argv[:1] == ["build"] for argv in calls)
    assert sum(argv[:1] == ["create"] for argv in calls) == 1
    assert any(
        argv[:2] == ["container", "inspect"] and argv[-1] == "f" * 64
        for argv in calls
    )
    assert not any(argv[:1] == ["cp"] for argv in calls)
    assert not any(argv[:2] == ["container", "start"] for argv in calls)


def test_repo_local_git_helpers_cannot_execute_during_source_inspection(
    tmp_path: Path,
) -> None:
    docker_bin, call_log = _fake_engine(tmp_path, "build-success")
    evidence = tmp_path / "git-helper-build-evidence"
    repo, controller_path, commit = _synthetic_checkout(tmp_path)
    marker = tmp_path / "git-helper-marker"
    helper = tmp_path / "git-helper"
    helper.write_text(
        f"#!/bin/sh\nprintf 'synthetic git helper ran\\n' >> {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    hook_dir = tmp_path / "hooks"
    hook_dir.mkdir(mode=0o700)
    hook = hook_dir / "pre-commit"
    hook.write_text(
        f"#!/bin/sh\nprintf 'synthetic hook ran\\n' >> {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    for key in (
        "core.fsmonitor",
        "diff.external",
        "diff.mu-synthetic.textconv",
        "core.pager",
        "filter.mu-synthetic.smudge",
    ):
        configured = _git(repo, tmp_path, "config", "--local", key, str(helper))
        assert configured.returncode == 0, configured.stderr
    configured = _git(
        repo, tmp_path, "config", "--local", "core.hooksPath", str(hook_dir)
    )
    assert configured.returncode == 0, configured.stderr

    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 0
    assert controller["status"] == "PASS"
    assert controller["recipe"]["commit"] == commit
    assert set(controller["recipe"]["inputs"]) == {
        "requirements.txt",
        "requirements-dev.txt",
        "scripts/test.sh",
        "scripts/multiuser_unit.Dockerfile",
    }
    assert not marker.exists(), "repo-local Git helper or hook executed"
    assert call_log.is_file()


def test_engine_probe_uses_explicit_socket_and_empty_private_environment(
    tmp_path: Path,
) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    evidence = tmp_path / "engine-probe-evidence"
    ambient_config = tmp_path / "ambient-docker-config"
    ambient_config.mkdir(mode=0o700)
    (ambient_config / "config.json").write_text(
        '{"auths":{"registry.invalid":{"auth":"mu-synthetic-auth"}},'
        '"credHelpers":{"registry.invalid":"mu-synthetic-helper"}}',
        encoding="utf-8",
    )
    caller_home = tmp_path / "caller-home"
    caller_home.mkdir(mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(caller_home),
        "DOCKER_CONFIG": str(ambient_config),
        "DOCKER_HOST": SYNTHETIC_SENTINELS["docker_host"],
        "DOCKER_CONTEXT": SYNTHETIC_SENTINELS["docker_context"],
        "HTTP_PROXY": SYNTHETIC_SENTINELS["http_proxy"],
        "AWS_SECRET_ACCESS_KEY": SYNTHETIC_SENTINELS["aws_secret"],
        "SSH_AUTH_SOCK": SYNTHETIC_SENTINELS["ssh_auth_sock"],
    }
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        env=env,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 3
    assert controller["status"] == "NOT_RUN"
    assert any(
        reason["code"] == "unit_engine_unavailable"
        for reason in controller["reasons"]
    )
    assert call_log.is_file(), "the controlled synthetic engine probe did not run"
    log = call_log.read_text(encoding="utf-8")
    socket_path = str(tmp_path / "engine.sock")
    logged_args = [line.removeprefix("ARG=") for line in log.splitlines() if line.startswith("ARG=")]
    assert logged_args[:3] == ["--host", f"unix://{socket_path}", "info"]
    assert "--context" not in logged_args
    assert "ENV_PATH=/usr/bin:/bin" in log
    assert f"ENV_HOME={evidence}/home" in log
    assert f"ENV_DOCKER_CONFIG={evidence}/docker-config" in log
    assert f"ENV_TMPDIR={evidence}/tmp" in log
    assert "ENV_DOCKER_HOST=<unset>" in log
    assert "ENV_DOCKER_CONTEXT=<unset>" in log
    assert "ENV_HTTP_PROXY=<unset>" in log
    assert "ENV_AWS_SECRET_ACCESS_KEY=<unset>" in log
    assert "ENV_SSH_AUTH_SOCK=<unset>" in log
    for secret in SYNTHETIC_SENTINELS.values():
        assert secret not in log
    docker_config = evidence / "docker-config" / "config.json"
    assert json.loads(docker_config.read_text(encoding="utf-8")) == {"auths": {}}
    assert evidence.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    ("bad_socket", "expected_code"),
    [
        ("missing", "unit_engine_unavailable"),
        ("regular-file", "unit_engine_unavailable"),
        ("symlink", "unit_engine_unavailable"),
    ],
)
def test_missing_or_non_socket_engine_endpoint_is_not_run_without_cli_call(
    tmp_path: Path, bad_socket: str, expected_code: str
) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    evidence = tmp_path / f"bad-engine-{bad_socket}-evidence"
    if bad_socket == "missing":
        socket_path = tmp_path / "missing.sock"
    elif bad_socket == "symlink":
        target = _socket_path(tmp_path)
        socket_path = tmp_path / "linked-engine.sock"
        socket_path.symlink_to(target)
    else:
        socket_path = tmp_path / "not-a-socket"
        socket_path.write_text("synthetic only", encoding="utf-8")
    _, controller_path, _ = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
        engine_socket=socket_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 3
    assert controller["status"] == "NOT_RUN"
    assert any(
        reason["code"] == expected_code for reason in controller["reasons"]
    )
    assert not call_log.exists(), "unavailable engine endpoint reached Docker CLI"


def test_existing_evidence_directory_is_refused_without_engine_call(
    tmp_path: Path,
) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    evidence = tmp_path / "already-used-evidence"
    evidence.mkdir(mode=0o700)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "evidence_dir_refused"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "reused evidence directory reached Docker CLI"


@pytest.mark.parametrize("unsafe_parent", ["shared", "symlink"])
def test_unprivate_or_linked_evidence_parent_is_refused(
    tmp_path: Path, unsafe_parent: str
) -> None:
    docker_bin, call_log = _fake_docker(tmp_path)
    if unsafe_parent == "shared":
        parent = tmp_path / "shared-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
    else:
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir(mode=0o700)
        parent = tmp_path / "linked-parent"
        parent.symlink_to(real_parent, target_is_directory=True)
    evidence = parent / "new-evidence"
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    assert result.returncode == 2
    assert controller["status"] == "REFUSED"
    assert any(
        reason["code"] == "evidence_dir_refused"
        for reason in controller["reasons"]
    )
    assert not call_log.exists(), "unsafe evidence parent reached Docker CLI"


def _run_simulated_candidate(
    tmp_path: Path,
    scenario: str,
    *,
    jq_bin: Path | None = None,
    worker_args: tuple[str, ...] = (
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
    ),
) -> tuple[subprocess.CompletedProcess[str], dict, list[dict]]:
    repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_records = _build_runtime_evidence(
        tmp_path, controller_path
    )
    return _run_simulated_request(
        tmp_path,
        controller_path=controller_path,
        commit=commit,
        runtime_evidence=runtime_evidence,
        image_id=build_result["recipe"]["unit_image_id"],
        scenario=scenario,
        jq_bin=jq_bin,
        worker_args=worker_args,
    )


def _docker_argv(record: dict) -> list[str]:
    argv = record["argv"]
    assert argv[:1] == ["--host"]
    assert argv[1].startswith("unix://")
    return argv[2:]


@pytest.mark.parametrize(("scenario", "expected_failure"), ADMISSION_MISMATCHES)
def test_controller_inspects_unit_before_start_and_cleans_only_its_resources(
    tmp_path: Path, scenario: str, expected_failure: str
) -> None:
    """Synthetic CLI simulation of the controller boundary, not OS proof."""
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    inspect_index = next(
        index
        for index, argv in enumerate(calls)
        if argv[:2] == ["container", "inspect"]
        and "{{json .}}" in argv
        and argv[-1] == FAKE_UNIT_CONTAINER_ID
    )
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "unit_admission_failed"
        for reason in controller["reasons"]
    )
    assert controller["container"]["admitted"] is False
    assert expected_failure in controller["container"]["admission_failures"]
    assert controller["container"]["started"] is False
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert not any(argv[:2] == ["container", "wait"] for argv in calls)
    assert not any(argv[:2] == ["container", "logs"] for argv in calls)
    assert any(argv[:2] == ["container", "create"] for argv in calls)
    assert inspect_index < len(calls)
    assert any(argv[:3] == ["container", "rm", "-f"] and argv[-1] == FAKE_UNIT_CONTAINER_ID for argv in calls)
    candidate_tag = controller["candidate"]["image_tag"]
    assert any(argv[:2] == ["image", "rm"] and argv[-1] == candidate_tag for argv in calls)
    assert not any(argv[:2] == ["image", "rm"] and argv[-1] == "sha256:" + "1" * 64 for argv in calls)
    assert not any("prune" in argv for argv in calls)
    assert controller["cleanup"]["verified"] is True
    assert set(controller["claims"].values()) == {False}
    assert all(record["docker_host"] is None for record in records)
    assert all(record["docker_context"] is None for record in records)
    assert all(record["http_proxy"] is None for record in records)
    assert all(record["aws_secret"] is None for record in records)
    assert all(record["ssh_auth_sock"] is None for record in records)


def test_fake_controller_simulation_accepts_only_expected_venv_link_and_worker_result(
    tmp_path: Path,
) -> None:
    """Synthetic CLI pass exercises bookkeeping only; it is not unit evidence."""
    result, controller, records = _run_simulated_candidate(tmp_path, "expected-venv-link")
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 0
    assert controller["status"] == "PASS"
    assert controller["candidate"]["source_tree_verified"] is True
    assert controller["container"]["admitted"] is True
    assert controller["container"]["started"] is True
    assert controller["container"]["post_exit_verified"] is True
    assert controller["worker"]["consistent"] is True
    assert controller["cleanup"]["verified"] is True
    assert controller["protocol_simulation"] is True
    assert controller["request"]["mode"] == "pytest"
    assert controller["request"]["tier"] == "unit"
    assert controller["docker_bin_substituted"] is True
    assert set(controller["claims"].values()) == {False}
    assert controller["worker"]["result"]["unit"]["id"] == controller["controller_id"]
    assert len(controller["worker"]["result"]["unit"]["nonce"]) == 32
    assert controller["runtime_evidence"]["unit_image_id"] == "sha256:" + "1" * 64
    assert controller["runtime_evidence"]["freeze_sha256"]
    assert controller["runtime_evidence"]["recipe_commit"]
    created_inspect = next(
        index
        for index, argv in enumerate(calls)
        if argv[:2] == ["container", "inspect"]
        and "{{json .}}" in argv
        and argv[-1] == FAKE_UNIT_CONTAINER_ID
    )
    start = next(
        index
        for index, argv in enumerate(calls)
        if argv[:3] == ["container", "start", "--attach"]
        and argv[-1] == FAKE_UNIT_CONTAINER_ID
    )
    assert created_inspect < start
    assert not any(argv[:2] in (["container", "wait"], ["container", "logs"]) for argv in calls)
    creates = [argv for argv in calls if argv[:1] == ["create"]]
    unit_create = next(argv for argv in creates if any(arg.startswith("hermes-f02-unit-") for arg in argv))
    required = [
        "--user", "10001:10001", "--read-only", "--network", "none",
        "--log-driver", "none",
        "--ipc", "private", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges", "--pids-limit", "256", "--memory", "2g",
        "--memory-swap", "2g", "--cpus", "2", "--restart", "no",
    ]
    start_at = unit_create.index("--user")
    assert unit_create[start_at : start_at + len(required)] == required
    assert "--privileged" not in unit_create
    assert not any(arg in {"-v", "--volume", "--mount", "--device"} for arg in unit_create)
    assert "--network" in unit_create and unit_create[unit_create.index("--network") + 1] == "none"
    assert unit_create.count("--tmpfs") == 2
    assert unit_create.count("--env") == 4
    assert "--workdir" in unit_create and unit_create[unit_create.index("--workdir") + 1] == "/src"
    prep_create = next(
        argv for argv in creates if any(arg.startswith("hermes-f02-prep-") for arg in argv)
    )
    assert prep_create[prep_create.index("--network") + 1] == "none"
    assert prep_create[prep_create.index("--log-driver") + 1] == "none"
    assert controller["attested"]["daemon_logging_disabled"] is True


@pytest.mark.parametrize("scenario", ["extra-source", "changed-source"])
def test_unexpected_source_tree_change_fails_before_container_start(
    tmp_path: Path, scenario: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "snapshot_mismatch" for reason in controller["reasons"])
    assert controller["candidate"]["source_tree_verified"] is False
    assert controller["container"]["started"] is False
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert controller["cleanup"]["verified"] is True


@pytest.mark.parametrize(
    "scenario",
    [
        "implicit-volume",
        "implicit-onbuild",
        "implicit-entrypoint",
        "implicit-healthcheck",
        "wrong-runtime-user",
        "wrong-runtime-workdir",
    ],
)
def test_unsafe_unit_image_configuration_is_refused_before_container_create(
    tmp_path: Path, scenario: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "unit_image_config_refused"
        for reason in controller["reasons"]
    )
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert not any(argv[:1] == ["cp"] for argv in calls)


@pytest.mark.parametrize(
    ("scenario", "expected_status", "expected_reason"),
    [
        ("runtime-image-id-mismatch", "FAIL", "runtime_evidence_mismatch"),
        ("runtime-image-absent", "NOT_RUN", "unit_image_mismatch"),
    ],
)
def test_live_image_identity_must_match_the_admitted_build_record(
    tmp_path: Path, scenario: str, expected_status: str, expected_reason: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    expected_exit = 1 if expected_status == "FAIL" else 3
    assert result.returncode == expected_exit
    assert controller["status"] == expected_status
    assert any(reason["code"] == expected_reason for reason in controller["reasons"])
    assert not any(argv[:1] == ["create"] for argv in calls)


def test_live_image_runtime_configuration_must_match_build_evidence(
    tmp_path: Path,
) -> None:
    result, controller, records = _run_simulated_candidate(
        tmp_path, "runtime-config-env-mismatch"
    )
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "runtime_evidence_mismatch"
        for reason in controller["reasons"]
    )
    assert not any(argv[:1] == ["create"] for argv in calls)


@pytest.mark.parametrize(
    "scenario",
    [
        "probe-running",
        "probe-pid",
        "probe-command",
        "probe-network",
        "probe-mount",
        "probe-volume",
        "probe-device",
        "probe-log-driver",
    ],
)
def test_never_started_probe_must_pass_its_own_admission_check(
    tmp_path: Path, scenario: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "probe_admission_failed"
        for reason in controller["reasons"]
    )
    assert sum(argv[:1] == ["create"] for argv in calls) == 1
    assert any(argv[:2] == ["container", "inspect"] and argv[-1] == FAKE_PREP_CONTAINER_ID for argv in calls)
    assert not any(argv[:1] == ["cp"] for argv in calls)
    assert not any(argv[:1] == ["commit"] for argv in calls)
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert controller["cleanup"]["verified"] is True


def test_actual_freeze_mismatch_stops_after_never_started_probe(
    tmp_path: Path,
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "wrong-freeze")
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "runtime_evidence_mismatch"
        for reason in controller["reasons"]
    )
    assert sum(argv[:1] == ["create"] for argv in calls) == 1
    assert any(
        argv[:1] == ["create"]
        and any(arg.startswith("hermes-f02-prep-") for arg in argv)
        for argv in calls
    )
    assert any(
        argv[:1] == ["cp"] and "/opt/mu/freeze.txt" in " ".join(argv)
        for argv in calls
    )
    assert not any(argv[:1] == ["commit"] for argv in calls)
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert controller["container"] is None or controller["container"]["started"] is False


@pytest.mark.parametrize(
    "scenario",
    [
        "engine-switch-before-prep-removal",
        "socket-swap-before-prep-removal",
    ],
)
def test_changed_engine_binding_stops_mutations_and_quarantines_probe(
    tmp_path: Path, scenario: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "engine_binding_lost" for reason in controller["reasons"])
    assert sum(argv[:1] == ["create"] for argv in calls) == 1
    assert not any(argv[:1] == ["commit"] for argv in calls)
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert not any(argv[:2] == ["container", "kill"] for argv in calls)
    assert not any(argv[:3] == ["container", "rm", "-f"] for argv in calls)
    assert not any(argv[:2] == ["image", "rm"] for argv in calls)
    assert controller["cleanup"]["quarantine"]


@pytest.mark.parametrize(
    ("scenario", "reason_code"),
    [
        ("candidate-tag-conflict", "resource_conflict"),
        ("container-name-conflict", "resource_conflict"),
        ("container-name-unknown", "engine_state_unknown"),
    ],
)
def test_preexisting_or_unknown_named_resource_is_never_adopted_or_removed(
    tmp_path: Path, scenario: str, reason_code: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == reason_code for reason in controller["reasons"])
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert not any(argv[:2] == ["container", "rm"] for argv in calls)
    assert not any(argv[:2] == ["image", "rm"] for argv in calls)
    assert not any("prune" in argv for argv in calls)


@pytest.mark.parametrize("scenario", ["create-lost-reply", "create-malformed-id"])
def test_unknown_container_creation_identity_is_quarantined_not_adopted(
    tmp_path: Path, scenario: str
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "creation_identity_unknown"
        for reason in controller["reasons"]
    )
    create = next(index for index, argv in enumerate(calls) if argv[:1] == ["create"])
    assert not any(argv[:2] == ["container", "rm"] for argv in calls[create + 1 :])
    assert not any(argv[:2] == ["image", "rm"] for argv in calls[create + 1 :])
    assert not any(
        argv[:2] == ["container", "inspect"]
        and argv[-1].startswith("hermes-f02-prep-")
        for argv in calls[create + 1 :]
    )
    assert {
        "kind": "container",
        "ref": next(arg for arg in calls[create] if arg.startswith("hermes-f02-prep-")),
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]


def test_unknown_commit_identity_never_removes_candidate_tag(
    tmp_path: Path,
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "commit-lost-reply")
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "creation_identity_unknown"
        for reason in controller["reasons"]
    )
    commit_index = next(index for index, argv in enumerate(calls) if argv[:1] == ["commit"])
    candidate_tag = calls[commit_index][-1]
    assert any(
        argv[:3] == ["container", "rm", "-f"] and argv[-1] == FAKE_PREP_CONTAINER_ID
        for argv in calls[commit_index + 1 :]
    )
    assert not any(
        argv[:2] == ["image", "rm"] and candidate_tag in argv
        for argv in calls[commit_index + 1 :]
    )
    assert {
        "kind": "image",
        "ref": candidate_tag,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]


@pytest.mark.parametrize(
    ("scenario", "expected_probe"),
    [
        ("journal-intent-prep", "hermes-f02-prep-"),
        ("journal-intent-prep-jq", "hermes-f02-prep-"),
        ("journal-intent-candidate-tag", "hermes-f02-cand:"),
        ("journal-intent-candidate-tag-jq", "hermes-f02-cand:"),
    ],
)
def test_failed_intent_update_preserves_previous_lease_and_prevents_create(
    tmp_path: Path, scenario: str, expected_probe: str
) -> None:
    jq_bin = None
    if scenario.endswith("-jq"):
        run_evidence = tmp_path / f"candidate-{scenario}-evidence"
        fake_root = tmp_path / f"run-engine-state-{scenario}"
        jq_bin = _fake_jq_failure_wrapper(
            tmp_path,
            fake_root / "jq-fail.marker",
            run_evidence / "lease.json.next",
        )
    result, controller, records = _run_simulated_candidate(
        tmp_path, scenario, jq_bin=jq_bin
    )
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    fake_root = tmp_path / f"run-engine-state-{scenario}"
    lease = _assert_previous_lease_preserved(evidence, fake_root)
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "journal_unwritable" for reason in controller["reasons"])
    if expected_probe.startswith("hermes-f02-prep-"):
        assert not any(argv[:1] == ["create"] for argv in calls)
        assert lease["containers"] == []
    else:
        assert sum(argv[:1] == ["create"] for argv in calls) == 1
        assert not any(argv[:1] == ["commit"] for argv in calls)
        assert lease["containers"][-1]["id"] == FAKE_PREP_CONTAINER_ID
    assert any(expected_probe in " ".join(argv) for argv in calls)


@pytest.mark.parametrize("scenario", ["journal-intent-unit-tag", "journal-intent-unit-tag-jq"])
def test_failed_build_tag_intent_prevents_image_build(
    tmp_path: Path, scenario: str
) -> None:
    docker_bin, call_log = _fake_engine(
        tmp_path, scenario, state_root=tmp_path / f"build-engine-state-{scenario}"
    )
    evidence = tmp_path / f"build-evidence-{scenario}"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    jq_bin = None
    fake_root = tmp_path / f"build-engine-state-{scenario}"
    if scenario.endswith("-jq"):
        jq_bin = _fake_jq_failure_wrapper(
            tmp_path,
            fake_root / "jq-fail.marker",
            evidence / "lease.json.next",
        )
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
        jq_bin=jq_bin,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    lease = _assert_previous_lease_preserved(evidence, fake_root)
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "journal_unwritable" for reason in controller["reasons"])
    assert not any(argv[:1] == ["build"] for argv in calls)
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert lease["images"] == []


@pytest.mark.parametrize("scenario", ["journal-after-build", "journal-after-build-jq"])
def test_failed_build_image_identity_record_quarantines_image_id_and_tag(
    tmp_path: Path, scenario: str
) -> None:
    fake_root = tmp_path / f"build-engine-state-{scenario}"
    docker_bin, call_log = _fake_engine(
        tmp_path, scenario, state_root=fake_root
    )
    evidence = tmp_path / f"build-evidence-{scenario}"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    jq_bin = None
    if scenario.endswith("-jq"):
        jq_bin = _fake_jq_failure_wrapper(
            tmp_path,
            fake_root / "jq-fail.marker",
            evidence / "lease.json.next",
        )
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
        jq_bin=jq_bin,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    lease = _assert_previous_lease_preserved(evidence, fake_root)
    unit_tag = lease["images"][-1]["tag"]
    unit_id = "sha256:" + "1" * 64
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "journal_unwritable" for reason in controller["reasons"])
    build = next(argv for argv in calls if argv[:1] == ["build"])
    assert "--iidfile" in build
    assert lease["images"][-1]["id"] is None
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert not any(argv[:2] == ["image", "rm"] and unit_tag in argv for argv in calls)
    assert not any(argv[:2] == ["image", "rm"] and unit_id in argv for argv in calls)
    assert {
        "kind": "image",
        "ref": unit_id,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert {
        "kind": "image",
        "ref": unit_tag,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert controller["cleanup"]["verified"] is False


@pytest.mark.parametrize("scenario", ["journal-after-create", "journal-after-create-jq"])
def test_failed_post_create_identity_record_quarantines_known_container(
    tmp_path: Path, scenario: str
) -> None:
    jq_bin = None
    if scenario.endswith("-jq"):
        run_evidence = tmp_path / f"candidate-{scenario}-evidence"
        fake_root = tmp_path / f"run-engine-state-{scenario}"
        jq_bin = _fake_jq_failure_wrapper(
            tmp_path,
            fake_root / "jq-fail.marker",
            run_evidence / "lease.json.next",
        )
    result, controller, records = _run_simulated_candidate(
        tmp_path, scenario, jq_bin=jq_bin
    )
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    fake_root = tmp_path / f"run-engine-state-{scenario}"
    lease = _assert_previous_lease_preserved(evidence, fake_root)
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "journal_unwritable" for reason in controller["reasons"])
    assert lease["containers"] and lease["containers"][-1]["id"] is None
    assert not any(argv[:2] == ["container", "start"] for argv in calls)
    assert not any(
        argv[:3] == ["container", "rm", "-f"] and argv[-1] == FAKE_PREP_CONTAINER_ID
        for argv in calls
    )
    assert not any(
        argv[:2] == ["container", "kill"] and argv[-1] == FAKE_PREP_CONTAINER_ID
        for argv in calls
    )
    assert {
        "kind": "container",
        "ref": FAKE_PREP_CONTAINER_ID,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert {
        "kind": "container",
        "ref": lease["containers"][-1]["name"],
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert controller["cleanup"]["verified"] is False
    assert controller["protocol_simulation"] is True
    if jq_bin is not None:
        assert controller["jq_bin"] == str(jq_bin)


@pytest.mark.parametrize("scenario", ["journal-after-commit", "journal-after-commit-jq"])
def test_failed_post_commit_identity_record_quarantines_unrecorded_image(
    tmp_path: Path, scenario: str
) -> None:
    jq_bin = None
    if scenario.endswith("-jq"):
        run_evidence = tmp_path / f"candidate-{scenario}-evidence"
        fake_root = tmp_path / f"run-engine-state-{scenario}"
        jq_bin = _fake_jq_failure_wrapper(
            tmp_path,
            fake_root / "jq-fail.marker",
            run_evidence / "lease.json.next",
        )
    result, controller, records = _run_simulated_candidate(
        tmp_path, scenario, jq_bin=jq_bin
    )
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    fake_root = tmp_path / f"run-engine-state-{scenario}"
    lease = _assert_previous_lease_preserved(evidence, fake_root)
    commit_index = next(index for index, argv in enumerate(calls) if argv[:1] == ["commit"])
    candidate_id = "sha256:" + "2" * 64
    candidate_tag = next(
        entry["tag"] for entry in lease["images"] if entry["tag"].startswith("hermes-f02-cand:")
    )
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "journal_unwritable" for reason in controller["reasons"])
    assert lease["images"][-1]["id"] is None
    assert not any(argv[:1] == ["create"] for argv in calls[commit_index + 1 :])
    assert not any(
        argv[:2] == ["image", "rm"] and candidate_tag in argv
        for argv in calls[commit_index + 1 :]
    )
    assert {
        "kind": "image",
        "ref": candidate_id,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert {
        "kind": "image",
        "ref": candidate_tag,
        "reason": "unrecorded_identity",
    } in controller["cleanup"]["quarantine"]
    assert controller["cleanup"]["verified"] is False


def test_worker_prerequisite_not_run_cannot_be_promoted_to_controller_pass(
    tmp_path: Path,
) -> None:
    result, controller, _records = _run_simulated_candidate(tmp_path, "worker-not-run")
    assert result.returncode == 3
    assert controller["status"] == "NOT_RUN"
    assert controller["exit_code"] == 3
    assert controller["worker"]["consistent"] is True
    assert controller["worker"]["result"]["status"] == "NOT_RUN"
    assert controller["cleanup"]["verified"] is True
    assert set(controller["claims"].values()) == {False}


def test_attached_exit_mismatch_fails_after_independent_disposal(tmp_path: Path) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "worker-attach-mismatch")
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "worker_result_inconsistent"
        for reason in controller["reasons"]
    )
    assert controller["container"]["attach_state"] == "done"
    assert any(argv[:3] == ["container", "start", "--attach"] for argv in calls)
    assert not any(argv[:2] in (["container", "wait"], ["container", "logs"]) for argv in calls)
    assert controller["cleanup"]["verified"] is True


def test_duplicate_worker_result_lines_cannot_pass(tmp_path: Path) -> None:
    result, controller, _records = _run_simulated_candidate(
        tmp_path, "duplicate-worker-result"
    )
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "worker_result_unparseable"
        for reason in controller["reasons"]
    )
    assert controller["cleanup"]["verified"] is True


@pytest.mark.parametrize(
    ("scenario", "request_field", "reported"),
    [
        ("worker-mode-mismatch", "mode", "script"),
        ("worker-tier-mismatch", "tier", "native"),
    ],
)
def test_requested_worker_mode_and_tier_bind_the_simulated_result(
    tmp_path: Path,
    scenario: str,
    request_field: str,
    reported: str,
) -> None:
    result, controller, _records = _run_simulated_candidate(tmp_path, scenario)
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(
        reason["code"] == "worker_result_inconsistent"
        for reason in controller["reasons"]
    )
    assert controller["request"][request_field] != reported
    assert controller["worker"]["result"][request_field] == reported
    assert controller["cleanup"]["verified"] is True


def test_unknown_worker_option_cannot_receive_a_simulated_pass(tmp_path: Path) -> None:
    result, controller, _records = _run_simulated_candidate(
        tmp_path,
        "unknown-request-option",
        worker_args=("--no-agent", "--tier", "unit", "--unknown=value"),
    )
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert controller["request"]["tier"] == "unknown"
    assert any(
        reason["code"] == "worker_result_inconsistent"
        for reason in controller["reasons"]
    )
    assert controller["worker"]["result"]["status"] == "PASS"
    assert controller["cleanup"]["verified"] is True


def test_controller_attach_timeout_settles_and_removes_exact_synthetic_unit(tmp_path: Path) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "attach-timeout")
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "unit_timeout" for reason in controller["reasons"])
    assert controller["container"]["timed_out"] is True
    assert controller["container"]["attach_state"] == "timeout"
    assert controller["container"]["output_overflow"] is False
    assert any(argv[:2] == ["container", "kill"] and argv[-1] == FAKE_UNIT_CONTAINER_ID for argv in calls)
    assert any(argv[:3] == ["container", "rm", "-f"] and argv[-1] == FAKE_UNIT_CONTAINER_ID for argv in calls)
    assert controller["cleanup"]["verified"] is True
    assert not any(argv[:2] in (["container", "wait"], ["container", "logs"]) for argv in calls)
    fake_root = tmp_path / "run-engine-state-attach-timeout"
    _assert_process_group_child_gone(fake_root / "stall-child.pid")
    assert not (fake_root / "caught-signal.marker").exists()


def test_result_reports_fixed_deadlines_and_bounded_capture_limits(tmp_path: Path) -> None:
    scenario = "expected-venv-link"
    result, controller, _records = _run_simulated_candidate(tmp_path, scenario)
    limits = controller["limits"]
    assert result.returncode == 0
    assert limits["operation_seconds"] == 1810
    assert limits["cleanup_seconds"] == 300
    assert limits["kill_grace_seconds"] == 5
    assert limits["control_seconds"] == 60
    assert limits["control_bytes"] == 65536
    assert limits["inspect_bytes"] == 1048576
    assert limits["build_output_bytes"] == 8388608
    assert limits["worker_stdout_bytes"] == 4194304
    assert limits["worker_stderr_bytes"] == 1048576
    assert limits["snapshot_bytes_max"] == 268435456
    assert limits["archive_bytes"] >= 1048576
    assert controller["binding"]["engine_id"] == FAKE_ENGINE_ID
    assert controller["binding"]["socket_identity"]
    assert controller["binding"]["parent_identity"]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    for name, cap in (
        ("worker.stdout", limits["worker_stdout_bytes"]),
        ("worker.stderr", limits["worker_stderr_bytes"]),
        ("src-actual.tar", limits["archive_bytes"]),
        ("candidate.tar", limits["archive_bytes"]),
    ):
        target = evidence / name
        if target.exists():
            assert target.stat().st_size <= cap + 1, name
    assert controller["container"]["attach_state"] == "done"
    assert controller["container"]["output_overflow"] is False


@pytest.mark.parametrize(
    ("scenario", "stream", "cap"),
    [
        ("info-stdout-overflow", "stdout", 1048576),
        ("info-stderr-overflow", "stderr", 65536),
        ("inspect-stdout-overflow", "stdout", 1048576),
        ("inspect-stderr-overflow", "stderr", 65536),
    ],
)
def test_bounded_info_and_inspect_stream_overflow_stops_before_create(
    tmp_path: Path, scenario: str, stream: str, cap: int
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "output_overflow" for reason in controller["reasons"])
    assert not any(argv[:1] == ["create"] for argv in calls)
    assert controller["limits"]["inspect_bytes"] == 1048576
    assert controller["limits"]["control_bytes"] == 65536
    _assert_cap_plus_one_stream_file(evidence, cap, f"{scenario} {stream}")


@pytest.mark.parametrize(
    ("scenario", "response_label"),
    [("info-large-json", "info"), ("inspect-large-json", "inspect")],
)
def test_valid_info_and_inspect_json_above_control_cap_is_accepted(
    tmp_path: Path, scenario: str, response_label: str
) -> None:
    result, controller, _records = _run_simulated_candidate(tmp_path, scenario)
    fake_root = tmp_path / f"run-engine-state-{scenario}"
    response_size = int(
        (fake_root / f"{response_label}-json-bytes.txt").read_text(encoding="ascii")
    )
    assert 65536 < response_size < 1048576
    assert result.returncode == 0
    assert controller["status"] == "PASS"
    assert controller["worker"]["consistent"] is True
    assert controller["limits"]["control_bytes"] == 65536
    assert controller["limits"]["inspect_bytes"] == 1048576


@pytest.mark.parametrize(
    ("scenario", "forbidden_calls"),
    [
        (
            "probe-inspect-stdout-overflow",
            (("cp", "-", FAKE_PREP_CONTAINER_ID + ":/src"), ("commit",)),
        ),
        (
            "unit-inspect-stdout-overflow",
            (("container", "start", "--attach"),),
        ),
        (
            "freeze-output-overflow",
            (("cp", "-", FAKE_PREP_CONTAINER_ID + ":/src"), ("commit",)),
        ),
    ],
)
def test_probe_and_unit_inspection_overflow_stops_before_next_side_effect(
    tmp_path: Path, scenario: str, forbidden_calls: tuple[tuple[str, ...], ...]
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "output_overflow" for reason in controller["reasons"])
    _assert_cap_plus_one_stream_file(evidence, 1048576, scenario)
    for forbidden in forbidden_calls:
        assert not any(argv[: len(forbidden)] == list(forbidden) for argv in calls)
    if scenario == "probe-inspect-stdout-overflow":
        assert not any(argv[:1] == ["commit"] for argv in calls)
        assert not any(
            argv[:1] == ["create"] and any("hermes-f02-unit-" in part for part in argv)
            for argv in calls
        )
    elif scenario == "unit-inspect-stdout-overflow":
        assert controller["container"]["started"] is False
        assert not any(argv[:3] == ["container", "start", "--attach"] for argv in calls)
    else:
        assert not any(argv[:1] == ["commit"] for argv in calls)
        assert not any(
            argv[:1] == ["create"] and any("hermes-f02-unit-" in part for part in argv)
            for argv in calls
        )


@pytest.mark.parametrize(
    ("scenario", "stream"),
    [("build-stdout-overflow", "build.out"), ("build-stderr-overflow", "build.err")],
)
def test_build_stream_overflow_is_capped_at_cap_plus_one(
    tmp_path: Path, scenario: str, stream: str
) -> None:
    fake_root = tmp_path / f"build-engine-state-{scenario}"
    docker_bin, call_log = _fake_engine(tmp_path, scenario, state_root=fake_root)
    evidence = tmp_path / f"build-evidence-{scenario}"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert result.returncode == 1
    assert any(reason["code"] == "output_overflow" for reason in controller["reasons"])
    assert (evidence / stream).stat().st_size == controller["limits"]["build_output_bytes"] + 1
    assert not any(argv[:1] == ["create"] for argv in calls)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_control_reply_overflow_prevents_build_mutation(
    tmp_path: Path, stream: str
) -> None:
    scenario = f"control-{stream}-overflow"
    docker_bin, call_log = _fake_engine(tmp_path, scenario)
    evidence = tmp_path / f"control-overflow-{stream}-evidence"
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    result = _run_controller(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    controller = _result(result.stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert result.returncode == 1
    assert any(reason["code"] == "output_overflow" for reason in controller["reasons"])
    assert controller["limits"]["control_bytes"] == 65536
    _assert_cap_plus_one_stream_file(evidence, 65536, f"control {stream}")
    assert not any(argv[:1] == ["build"] for argv in calls)


@pytest.mark.parametrize(
    ("scenario", "filename", "cap"),
    [
        ("worker-stdout-overflow", "worker.stdout", 4194304),
        ("worker-stderr-overflow", "worker.stderr", 1048576),
    ],
)
def test_attached_worker_stream_overflow_is_capped_at_cap_plus_one(
    tmp_path: Path, scenario: str, filename: str, cap: int
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    evidence = tmp_path / f"candidate-{scenario}-evidence"
    assert result.returncode == 1
    assert controller["status"] == "FAIL"
    assert any(reason["code"] == "output_overflow" for reason in controller["reasons"])
    assert controller["container"]["attach_state"] == "overflow"
    assert controller["container"]["output_overflow"] is True
    assert (evidence / filename).stat().st_size == cap + 1
    assert any(argv[:3] == ["container", "start", "--attach"] for argv in calls)
    assert not any(argv[:2] in (["container", "wait"], ["container", "logs"]) for argv in calls)
    assert controller["cleanup"]["verified"] is True


def test_capture_sink_failure_is_reported_and_does_not_send_catchable_signal(
    tmp_path: Path,
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "capture-failed")
    calls = [_docker_argv(record) for record in records]
    fake_root = tmp_path / "run-engine-state-capture-failed"
    evidence = tmp_path / "candidate-capture-failed-evidence"
    assert result.returncode == 1
    assert any(reason["code"] == "capture_failed" for reason in controller["reasons"])
    assert controller["container"]["attach_state"] == "capture_failed"
    assert (evidence / "worker.stdout").is_dir()
    assert any(argv[:3] == ["container", "start", "--attach"] for argv in calls)
    _assert_process_group_child_gone(fake_root / "stall-child.pid")
    assert not (fake_root / "caught-signal.marker").exists()
    assert controller["cleanup"]["verified"] is True


def test_running_daemon_is_independently_killed_inspected_and_disposed(
    tmp_path: Path,
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, "daemon-still-running")
    calls = [_docker_argv(record) for record in records]
    attach = next(index for index, argv in enumerate(calls) if argv[:3] == ["container", "start", "--attach"])
    kill = next(index for index, argv in enumerate(calls) if argv[:2] == ["container", "kill"])
    inspections = [
        index for index, argv in enumerate(calls)
        if argv[:2] == ["container", "inspect"] and argv[-1] == FAKE_UNIT_CONTAINER_ID
    ]
    remove = next(index for index, argv in enumerate(calls) if argv[:3] == ["container", "rm", "-f"] and argv[-1] == FAKE_UNIT_CONTAINER_ID)
    assert result.returncode == 1
    assert controller["container"]["attach_state"] == "done"
    assert len(inspections) >= 2
    assert attach < inspections[-2] < kill < inspections[-1] < remove
    assert controller["container"]["post_exit_verified"] is False
    assert controller["cleanup"]["verified"] is True


def test_started_unit_removal_failure_is_not_reported_as_disposed(tmp_path: Path) -> None:
    result, controller, _records = _run_simulated_candidate(tmp_path, "unit-removal-unverified")
    assert result.returncode == 1
    assert any(reason["code"] == "unit_disposal_unverified" for reason in controller["reasons"])
    assert controller["cleanup"]["verified"] is False
    assert controller["container"]["started"] is True
    assert {
        "kind": "container",
        "ref": FAKE_UNIT_CONTAINER_ID,
        "reason": "unverified_removal",
    } in controller["cleanup"]["quarantine"]


@pytest.mark.parametrize(
    ("scenario", "forbidden_mutation"),
    [
        ("engine-switch-before-unit-start", ["container", "start", "--attach"]),
        ("engine-switch-before-unit-removal", ["container", "rm", "-f"]),
    ],
)
def test_changed_engine_binding_blocks_later_unit_mutation(
    tmp_path: Path, scenario: str, forbidden_mutation: list[str]
) -> None:
    result, controller, records = _run_simulated_candidate(tmp_path, scenario)
    calls = [_docker_argv(record) for record in records]
    assert result.returncode == 1
    assert any(reason["code"] == "engine_binding_lost" for reason in controller["reasons"])
    assert not any(argv[: len(forbidden_mutation)] == forbidden_mutation for argv in calls)
    assert controller["cleanup"]["quarantine"]
    assert controller["cleanup"]["verified"] is False


def test_bounded_client_timeout_kills_descendants_without_catchable_signals(
    tmp_path: Path,
) -> None:
    """The fixed 60 s control-call timeout is exercised only in the admitted unit."""
    fake_root = tmp_path / "run-engine-state-client-call-timeout"
    docker_bin, call_log = _fake_engine(tmp_path, "client-call-timeout", state_root=fake_root)
    _repo, controller_path, _commit = _synthetic_checkout(tmp_path)
    evidence = tmp_path / "client-call-timeout-evidence"
    argv = _controller_command(
        tmp_path,
        docker_bin,
        evidence,
        "build",
        "--base-image",
        BASE_IMAGE,
        controller_path=controller_path,
    )
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "caller-home")},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_file(fake_root / "client-call-entered.marker", 20)
        stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
    elapsed = time.monotonic() - started
    controller = _result(stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert elapsed < 90
    assert process.returncode == 1
    assert any(reason["code"] == "client_timeout" for reason in controller["reasons"])
    assert controller["limits"]["control_seconds"] == 60
    assert not any(argv[:1] == ["build"] for argv in calls)
    _assert_process_group_child_gone(fake_root / "stall-child.pid")
    assert not (fake_root / "caught-signal.marker").exists()


def test_parent_interrupt_is_visible_and_cancels_only_owned_client_group(
    tmp_path: Path,
) -> None:
    """Cancellation is exercised against a synthetic client inside the admitted unit."""
    fake_root = tmp_path / "run-engine-state-interrupt-attach"
    docker_bin, call_log = _fake_engine(
        tmp_path, "interrupt-attach", state_root=fake_root
    )
    repo, controller_path, commit = _synthetic_checkout(tmp_path)
    runtime_evidence, build_result, _build_records = _build_runtime_evidence(
        tmp_path, controller_path
    )
    evidence = tmp_path / "interrupt-attach-evidence"
    argv = _controller_command(
        tmp_path,
        docker_bin,
        evidence,
        "run",
        "--runtime-evidence",
        str(runtime_evidence),
        "--image-id",
        build_result["recipe"]["unit_image_id"],
        "--candidate",
        commit,
        "--timeout",
        "60",
        "--",
        "--no-agent",
        "--tier",
        "unit",
        "--",
        "-q",
        "tests/multiuser/test_f02_unit.py",
        controller_path=controller_path,
    )
    process = subprocess.Popen(
        argv,
        cwd=repo,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "caller-home")},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_file(fake_root / "attach-entered.marker", 30)
        os.kill(process.pid, signal.SIGINT)
        stdout, stderr = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
    controller = _result(stdout, CONTROLLER_PREFIX)
    calls = [_docker_argv(record) for record in _logged_calls(call_log)]
    assert process.returncode == 1
    assert any(reason["code"] == "interrupted" for reason in controller["reasons"])
    assert controller["container"]["attach_state"] == "cancelled"
    assert controller["cleanup"]["verified"] is True
    assert not any(argv[:2] in (("container", "wait"), ("container", "logs")) for argv in calls)
    _assert_process_group_child_gone(fake_root / "stall-child.pid")
    assert not (fake_root / "caught-signal.marker").exists()
