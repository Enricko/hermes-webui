"""Behavioral regression coverage for the independent F02 proof launcher."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import urllib.request

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "multiuser" / "fixtures"
PROBE = "tests/multiuser/fixtures/child_environment_probe.py"
ADVERSARIAL = json.loads(
    (FIXTURES / "adversarial_inputs.json").read_text(encoding="utf-8")
)
SECRET_MARKERS = (
    "f02-synthetic-openai-secret-71f0",
    "f02-synthetic-anthropic-secret-46ab",
    "f02-synthetic-hermes-auth-5a21",
    "f02-synthetic-aws-secret-92d4",
)


def _status(result: subprocess.CompletedProcess[str]) -> dict:
    status = None
    for line in reversed((result.stdout + "\n" + result.stderr).splitlines()):
        line = line.strip()
        if line.startswith("MULTIUSER_RESULT "):
            line = line.removeprefix("MULTIUSER_RESULT ")
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "status" in candidate:
            status = candidate
            break
    assert status is not None, (
        f"launcher omitted its machine-readable result: {result.stdout!r} {result.stderr!r}"
    )
    return status


def _reason(
    result: subprocess.CompletedProcess[str], code: str, status_name: str = "REFUSED"
) -> None:
    status = _status(result)
    assert status["status"] == status_name
    assert result.returncode == status["exit_code"]
    assert result.returncode != 0
    assert code in {row["code"] for row in status["reasons"]}


def _environment_prerequisite_not_run(result: subprocess.CompletedProcess[str]) -> bool:
    """Accept only explicit safe non-run when the host cannot prove prerequisites."""
    status = _status(result)
    if status["status"] != "NOT_RUN":
        return False
    codes = {row["code"] for row in status["reasons"]}
    if not codes & {
        "implicit_agent_discoverable",
        "checkout_dotenv_present",
        "venv_provenance_unknown",
        "venv_unavailable",
        "venv_dependencies_missing",
        "platform_route_unverified",
    }:
        return False
    assert result.returncode == 3
    return True


def _probe_payload(result: subprocess.CompletedProcess[str]) -> dict:
    for line in result.stdout.splitlines():
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict) and "secret_presence" in decoded:
            return decoded
    raise AssertionError(
        f"child environment probe did not emit JSON: {result.stdout!r}"
    )


def _helper_module():
    helper_path = REPO_ROOT / "scripts" / "multiuser_test_fixtures.py"
    spec = importlib.util.spec_from_file_location(
        "f02_fixture_helper_under_test", helper_path
    )
    assert spec is not None and spec.loader is not None, (
        f"fixture helper missing: {helper_path}"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _launcher_module():
    launcher_path = REPO_ROOT / "scripts" / "test_multiuser.py"
    spec = importlib.util.spec_from_file_location(
        "f02_launcher_under_test", launcher_path
    )
    assert spec is not None and spec.loader is not None, (
        f"launcher missing: {launcher_path}"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_shadow_probe_checkout(tmp_path: Path, shadow_name: str) -> tuple[Path, Path]:
    """Create a disposable, statically complete checkout with a runner marker."""
    repo = tmp_path / f"synthetic-shadow-{shadow_name.replace('/', '_')}"
    scripts = repo / "scripts"
    tests = repo / "tests" / "multiuser"
    venv_root = repo / ".venv"
    bin_dir = venv_root / "bin"
    config_lines = (REPO_ROOT / ".venv" / "pyvenv.cfg").read_text().splitlines()
    config = dict(line.split(" = ", 1) for line in config_lines if " = " in line)
    base_python = Path(config["executable"]).resolve()
    base_tag = ".".join(config["version"].split(".")[:2])
    base_bin = base_python.parent
    site = venv_root / "lib" / f"python{base_tag}" / "site-packages"
    for directory in (scripts, tests, bin_dir, site):
        directory.mkdir(parents=True, exist_ok=True)

    for module_name in (
        "cryptography",
        "mcp",
        "pytest",
        "pytest_asyncio",
        "pytest_shard",
        "pytest_timeout",
        "ruff",
        "yaml",
        "pip",
    ):
        module_path = site / module_name
        if module_name in {"cryptography", "mcp", "pytest", "pytest_asyncio", "pip"}:
            module_path.mkdir()
            (module_path / "__init__.py").write_text("# synthetic module\n")
        else:
            module_path.with_suffix(".py").write_text("# synthetic module\n")

    for name in ("test_multiuser.py", "multiuser_test_fixtures.py"):
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)
    runner_marker = tmp_path / f"{shadow_name.replace('/', '_')}-runner-invoked"
    runner = scripts / "test.sh"
    runner.write_text(
        "#!/bin/sh\n"
        f"printf 'invoked' > {str(runner_marker)!r}\n"
        'if [ "${1:-}" = --prepare-only ]; then exit 0; fi\n'
        'if [ "${1:-}" = --execute-only ]; then exit 78; fi\n'
        "exit 91\n",
        encoding="utf-8",
    )
    runner.chmod(0o700)
    (venv_root / "pyvenv.cfg").write_text(
        f"home = {base_bin}\nversion = {config['version']}\n"
        "include-system-site-packages = false\n",
        encoding="utf-8",
    )
    (bin_dir / "python").symlink_to(base_python)
    shadow_path = repo / shadow_name
    shadow_path.parent.mkdir(parents=True, exist_ok=True)
    shadow_path.write_bytes(b"synthetic compiled shadow; never execute\n")
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    return repo, runner_marker


def test_standalone_self_test_is_independent_and_scrubs_hostile_environment(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    marker = Path(hostile_parent_env["F02_SITE_MARKER_PATH"])
    shell_marker = Path(hostile_parent_env["BASH_ENV"]).with_name("bash-env-imported")
    result = run_launcher("--self-test", env=hostile_parent_env)

    assert result.returncode == 0, result.stderr
    status = _status(result)
    assert status["status"] == "PASS"
    assert status["tier"] == "self-test"
    assert status["mode"] == "self-test"
    assert status["entry"]["isolated"] is True
    assert status["entry"]["no_site"] is True
    assert set(status["claims"].values()) == {False}
    assert not marker.exists(), (
        "synthetic PYTHONPATH sitecustomize ran before the isolated launcher"
    )
    assert not shell_marker.exists(), (
        "synthetic BASH_ENV hook ran before the isolated launcher"
    )
    for secret in SECRET_MARKERS:
        assert secret not in result.stdout + result.stderr


def test_machine_readable_report_matches_stdout_record(
    run_launcher, tmp_path: Path
) -> None:
    report = tmp_path / "launcher-result.json"
    result = run_launcher("--self-test", "--report", str(report))
    assert result.returncode == 0, result.stderr
    assert report.is_file() and not report.is_symlink()
    assert json.loads(report.read_text(encoding="utf-8")) == _status(result)


def test_script_child_has_disposable_separate_paths_and_no_inherited_secrets(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    parent_before = dict(os.environ)
    marker = Path(hostile_parent_env["F02_SITE_MARKER_PATH"])
    shell_marker = Path(hostile_parent_env["BASH_ENV"]).with_name("bash-env-imported")
    hermes_marker = Path(hostile_parent_env["PATH"]).parent / "hermes-path-used"
    result = run_launcher(
        "--no-agent", "--tier", "unit", "--script", PROBE, env=hostile_parent_env
    )

    if _environment_prerequisite_not_run(result):
        assert not marker.exists()
        assert not shell_marker.exists()
        return
    assert result.returncode == 0, result.stderr
    status = _status(result)
    assert status["status"] == "PASS"
    assert status["tier"] == "unit"
    assert status["agent"] == "none"
    assert status["entry"]["isolated"] is True
    assert status["entry"]["no_site"] is True
    assert set(status["claims"].values()) == {False}
    payload = _probe_payload(result)
    assert not any(payload["secret_presence"].values())
    assert payload["hermes_agent_path_present"] is False
    assert payload["pythonpath_present"] is True
    assert payload["pythonpath"] == str(
        Path(payload["paths"]["HERMES_MU_STATE_ROOT"]) / "launcher" / "importguard"
    )
    assert not any(payload["poison_present"].values())
    assert payload["agent_modules_loaded"] == []
    assert payload["path_contains_hostile_bin"] is False
    assert payload["fake_hermes_visible"] is False
    assert payload["safe_values"] == {
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "HERMES_DISABLE_LAZY_INSTALLS": "1",
        "HERMES_WEBUI_HOST": "127.0.0.1",
    }
    assert payload["path_exists"] == {
        "NETRC": False,
        "AWS_SHARED_CREDENTIALS_FILE": False,
        "KUBECONFIG": False,
    }
    root = Path(payload["paths"]["HERMES_MU_STATE_ROOT"])
    assert payload["paths"]["HERMES_MU_STATE_ROOT"]
    assert payload["paths"]["HERMES_WEBUI_AGENT_DIR"]
    assert payload["agent_checkout"] is None
    alias_vars = {
        "USERPROFILE": "HOME",
        "TMP": "TMPDIR",
        "TEMP": "TMPDIR",
        "HERMES_BASE_HOME": "HERMES_HOME",
    }
    for alias, target in alias_vars.items():
        assert payload["paths"][alias] == payload["paths"][target]
    path_values = [
        Path(value)
        for name, value in payload["paths"].items()
        if name not in alias_vars and value is not None
    ]
    assert all(path.is_relative_to(root) for path in path_values), payload["paths"]
    primary_dir_names = {
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
    }
    primary_dirs = {name: payload["paths"][name] for name in primary_dir_names}
    assert len(set(primary_dirs.values())) == len(primary_dirs)
    assert Path(payload["venv_python"]).is_relative_to(REPO_ROOT / ".venv")
    assert not Path(hostile_parent_env["TMPDIR"]).exists(), (
        "launcher used the inherited temporary root"
    )
    assert status["state"]["root_removed"] is True
    assert not root.exists(), "launcher left disposable state on disk"
    assert os.environ == parent_before, (
        "launcher mutated the parent test process environment"
    )
    assert not marker.exists(), (
        "synthetic PYTHONPATH sitecustomize escaped into a child"
    )
    assert not shell_marker.exists(), "synthetic BASH_ENV hook reached the child runner"
    assert not hermes_marker.exists(), (
        "launcher executed the synthetic PATH hermes executable"
    )
    for secret in SECRET_MARKERS:
        assert secret not in result.stdout + result.stderr


def test_no_agent_pytest_does_not_import_root_conftest_or_product_agent(
    run_launcher,
) -> None:
    result = run_launcher(
        "--no-agent",
        "--",
        "-q",
        "tests/multiuser/fixtures/test_f02_collection_probe.py",
    )
    if _environment_prerequisite_not_run(result):
        return
    assert result.returncode == 0, result.stderr
    status = _status(result)
    assert status["status"] == "PASS"
    assert status["tests"]["total"] == 1
    assert status["tests"]["skipped"] == 0


def test_child_failure_still_removes_disposable_state(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    result = run_launcher(
        "--no-agent",
        "--tier",
        "unit",
        "--script",
        "tests/multiuser/fixtures/exit_nonzero.py",
        env=hostile_parent_env,
    )
    if _environment_prerequisite_not_run(result):
        return
    status = _status(result)
    assert status["status"] == "FAIL"
    assert status["child_exit_code"] == 17
    assert result.returncode != 0
    assert status["state"]["root_removed"] is True
    root = Path(result.stdout.splitlines()[0])
    assert not root.exists(), "failing child left the disposable root behind"


def test_teardown_refuses_to_follow_child_replaced_state_root(
    run_launcher, hostile_parent_env: dict[str, str], tmp_path: Path
) -> None:
    external = tmp_path / "external-sentinel"
    external.mkdir()
    sentinel = external / "keep.txt"
    sentinel.write_text("f02 external fixture must survive", encoding="utf-8")
    result = run_launcher(
        "--no-agent",
        "--tier",
        "unit",
        "--script",
        "tests/multiuser/fixtures/replace_state_root.py",
        "--",
        str(external),
        env=hostile_parent_env,
    )
    if _environment_prerequisite_not_run(result):
        return
    status = _status(result)
    assert status["status"] == "FAIL"
    assert "teardown_failed" in {reason["code"] for reason in status["reasons"]}
    assert status["state"]["root_removed"] is False
    details = json.loads(result.stdout.splitlines()[0])
    assert Path(details["root"]).is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "f02 external fixture must survive"
    moved_root = Path(details["moved_root"])
    if moved_root.exists():
        shutil.rmtree(moved_root)
    Path(details["root"]).unlink(missing_ok=True)


def test_skipped_mandatory_pytest_case_is_not_reported_as_pass(run_launcher) -> None:
    result = run_launcher(
        "--no-agent", "--", "-q", "tests/multiuser/fixtures/test_f02_skip_probe.py"
    )
    if _environment_prerequisite_not_run(result):
        return
    _reason(result, "tests_skipped", "NOT_RUN")
    status = _status(result)
    assert status["tests"]["skipped"] == 1


def test_zero_collected_pytest_cases_cannot_report_pass(run_launcher) -> None:
    result = run_launcher(
        "--no-agent", "--", "-q", "tests/multiuser/fixtures/test_f02_empty_probe.py"
    )
    if _environment_prerequisite_not_run(result):
        return
    _reason(result, "no_tests_collected", "FAIL")
    assert _status(result)["tests"]["total"] == 0


def test_unavailable_mandatory_tiers_are_machine_readable_not_run(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    if sys.platform == "darwin":
        host_os, backend = "macos", "docker-desktop"
    elif sys.platform == "win32":
        host_os, backend = "windows", "docker-desktop"
    else:
        host_os, backend = "linux", "docker"
    cases = [
        (("--tier", "native", "--", "-q"), "agent_checkout_required"),
        (
            ("--no-agent", "--tier", "browser", "--script", PROBE),
            {"browser_runtime_unavailable", "browser_transport_unverified"},
        ),
        (
            (
                "--tier",
                "containment",
                "--host-os",
                host_os,
                "--backend",
                backend,
                "--",
                "-q",
            ),
            "containment_backend_unverified",
        ),
        (("--tier", "remote", "--", "-q"), "deployment_manifest_required"),
    ]
    for args, reason in cases:
        result = run_launcher(*args, env=hostile_parent_env)
        if _environment_prerequisite_not_run(result):
            continue
        if isinstance(reason, set):
            status = _status(result)
            assert result.returncode == 3
            assert status["status"] == "NOT_RUN"
            assert {row["code"] for row in status["reasons"]} & reason
        else:
            _reason(result, reason, "NOT_RUN")


def test_implicit_agent_discovery_never_uses_synthetic_installed_path(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    fake = Path(hostile_parent_env["HERMES_AGENT_PATH"])
    fake.mkdir()
    sentinel = fake / "imported"
    (fake / "run_agent.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    result = run_launcher("--tier", "native", "--", "-q", env=hostile_parent_env)
    if _environment_prerequisite_not_run(result):
        assert not sentinel.exists()
        return
    _reason(result, "agent_checkout_required", "NOT_RUN")
    assert not sentinel.exists(), (
        "launcher imported the synthetic implicit Agent source"
    )


def test_explicit_synthetic_agent_checkout_is_the_only_child_source(
    run_launcher, hostile_parent_env: dict[str, str], tmp_path: Path
) -> None:
    checkout = tmp_path / "explicit-agent-checkout"
    checkout.mkdir()
    (checkout / "run_agent.py").write_text(
        "# synthetic explicit source; never imported\n", encoding="utf-8"
    )
    result = run_launcher(
        "--agent-checkout",
        str(checkout),
        "--tier",
        "native",
        "--script",
        PROBE,
        env=hostile_parent_env,
    )
    status = _status(result)
    assert result.returncode == 3
    assert status["status"] == "NOT_RUN"
    reason_codes = {row["code"] for row in status["reasons"]}
    assert reason_codes & {
        "credential_compartment_unverified",
        "implicit_agent_discoverable",
        "venv_provenance_unknown",
        "venv_unavailable",
        "venv_dependencies_missing",
    }
    assert status["agent"] == "explicit"
    assert "f02-synthetic-openai-secret-71f0" not in result.stdout + result.stderr


def test_agent_checkout_dotenv_is_not_loaded_or_used_as_source(
    run_launcher, hostile_parent_env: dict[str, str], tmp_path: Path
) -> None:
    checkout = tmp_path / "synthetic-agent-with-dotenv"
    checkout.mkdir()
    sentinel = checkout / "imported"
    (checkout / "run_agent.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    dotenv_marker = "F02_SYNTHETIC_AGENT_DOTENV=must-not-load"
    (checkout / ".env").write_text(dotenv_marker + "\n", encoding="utf-8")
    result = run_launcher(
        "--agent-checkout",
        str(checkout),
        "--tier",
        "native",
        "--script",
        PROBE,
        env=hostile_parent_env,
    )
    status = _status(result)
    assert status["status"] == "NOT_RUN"
    assert result.returncode == 3
    assert "checkout_dotenv_present" in {reason["code"] for reason in status["reasons"]}
    assert not sentinel.exists()
    assert dotenv_marker not in result.stdout + result.stderr


def test_explicit_source_symlink_and_invalid_checkout_fail_closed(
    run_launcher, hostile_parent_env: dict[str, str], tmp_path: Path
) -> None:
    real_source = tmp_path / "real-agent"
    real_source.mkdir()
    sentinel = real_source / "imported"
    (real_source / "run_agent.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n",
        encoding="utf-8",
    )
    linked_source = tmp_path / "linked-agent"
    linked_source.symlink_to(real_source, target_is_directory=True)
    linked = run_launcher(
        "--agent-checkout",
        str(linked_source),
        "--tier",
        "native",
        "--",
        "-q",
        env=hostile_parent_env,
    )
    if _environment_prerequisite_not_run(linked):
        assert not sentinel.exists()
        return
    _reason(linked, "unsafe_symlink")
    assert not sentinel.exists()

    invalid_source = tmp_path / "empty-agent"
    invalid_source.mkdir()
    invalid = run_launcher(
        "--agent-checkout",
        str(invalid_source),
        "--tier",
        "native",
        "--",
        "-q",
        env=hostile_parent_env,
    )
    if _environment_prerequisite_not_run(invalid):
        return
    _reason(invalid, "agent_checkout_invalid")


def test_replaced_explicit_source_identity_is_detected_at_function_boundary(
    tmp_path: Path,
) -> None:
    launcher = _launcher_module()
    repo = tmp_path / "synthetic-webui"
    checkout = tmp_path / "replaceable-agent"
    repo.mkdir()
    checkout.mkdir()
    (checkout / "run_agent.py").write_text(
        "# synthetic initial source\n", encoding="utf-8"
    )
    source, ident = launcher.validate_agent_checkout(
        str(checkout), str(repo), str(tmp_path)
    )
    moved = tmp_path / "original-agent-moved"
    checkout.rename(moved)
    checkout.mkdir()
    replacement_marker = checkout / "synthetic-replacement-sentinel"
    replacement_marker.write_text("preserve replacement", encoding="utf-8")
    assert launcher.checkout_unchanged(source, ident) is False
    assert replacement_marker.read_text(encoding="utf-8") == "preserve replacement"


@pytest.mark.parametrize("option", ADVERSARIAL["unsafe_pytest_options"])
def test_pytest_arguments_cannot_escape_isolated_collection(
    run_launcher, hostile_parent_env: dict[str, str], option: str
) -> None:
    result = run_launcher("--no-agent", "--", option, env=hostile_parent_env)
    _reason(result, "pytest_arg_disallowed")
    assert "tests/conftest.py" not in result.stdout + result.stderr


@pytest.mark.parametrize("script", ADVERSARIAL["bad_script_paths"])
def test_script_paths_outside_checkout_are_refused(
    run_launcher, hostile_parent_env: dict[str, str], script: str
) -> None:
    result = run_launcher("--no-agent", "--script", script, env=hostile_parent_env)
    if _environment_prerequisite_not_run(result):
        return
    _reason(result, "path_outside_checkout")


def test_symlink_script_is_refused_even_when_target_is_inside_checkout(
    run_launcher, hostile_parent_env: dict[str, str]
) -> None:
    link = FIXTURES / "linked_probe.py"
    assert link.is_symlink(), "test's tracked symlink fixture is missing"
    result = run_launcher(
        "--no-agent",
        "--script",
        str(link.relative_to(REPO_ROOT)),
        env=hostile_parent_env,
    )
    if _environment_prerequisite_not_run(result):
        return
    _reason(result, "unsafe_symlink")


def test_untrusted_synthetic_venv_hooks_are_not_executed_before_not_run(
    tmp_path: Path,
) -> None:
    """A candidate .venv with startup code is never executed to decide trust."""
    repo = tmp_path / "synthetic-checkout"
    scripts = repo / "scripts"
    tests = repo / "tests" / "multiuser"
    # Use only the statically recorded base of this worktree's already audited
    # venv. The synthetic checkout and hooks stay under tmp_path.
    venv_cfg = {}
    for line in (REPO_ROOT / ".venv" / "pyvenv.cfg").read_text().splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            venv_cfg[key] = value
    base_python = Path(venv_cfg["executable"]).resolve()
    base_bin = base_python.parent
    base_version = venv_cfg["version"].split(".")[:2]
    version_tag = ".".join(base_version)
    site = repo / ".venv" / "lib" / f"python{version_tag}" / "site-packages"
    bin_dir = repo / ".venv" / "bin"
    for directory in (scripts, tests, site, bin_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for module_name in (
        "cryptography",
        "mcp",
        "pytest",
        "pytest_asyncio",
        "pytest_shard",
        "pytest_timeout",
        "ruff",
        "yaml",
        "pip",
    ):
        module_path = site / module_name
        if module_name in {"cryptography", "mcp", "pytest_asyncio", "pip"}:
            module_path.mkdir()
            (module_path / "__init__.py").write_text("# synthetic module\n")
        else:
            module_path.with_suffix(".py").write_text("# synthetic module\n")
    for name in ("test_multiuser.py", "multiuser_test_fixtures.py"):
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)
    # If the launcher wrongly reaches the runner, this marker records it. Never
    # execute the candidate interpreter: it resolves to the host distribution.
    runner = scripts / "test.sh"
    candidate_python = bin_dir / "python"
    runner_marker = tmp_path / "runner-was-invoked"
    runner.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = --prepare-only ]; then exit 0; fi\n'
        f"printf 'ran' > {str(runner_marker)!r}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    runner.chmod(0o700)
    (repo / ".venv" / "pyvenv.cfg").write_text(
        f"home = {base_bin}\nversion = {venv_cfg['version']}\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    candidate_python.symlink_to(base_python)

    site_marker = tmp_path / "sitecustomize-ran"
    pth_marker = tmp_path / "pth-ran"
    (site / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(site_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (site / "f02-startup.pth").write_text(
        f"import pathlib; pathlib.Path({str(pth_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (tests / "test_synthetic.py").write_text(
        "def test_placeholder(): pass\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)

    def invoke(expected_status: str | None = "NOT_RUN") -> dict:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(scripts / "test_multiuser.py"),
                "--no-agent",
                "--",
                "-q",
            ],
            cwd=repo,
            env={"PATH": os.environ.get("PATH", "")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        status = _status(result)
        assert result.returncode != 0
        if expected_status is not None:
            assert status["status"] == expected_status
        return status

    # The launcher must reject .env by its presence, without loading its marker.
    (repo / ".env").write_text(
        "F02_SYNTHETIC_DOTENV_SENTINEL=never-load-me\n", encoding="utf-8"
    )
    dotenv_status = invoke()
    assert "checkout_dotenv_present" in {r["code"] for r in dotenv_status["reasons"]}
    (repo / ".env").unlink()

    pyvenv_cfg = repo / ".venv" / "pyvenv.cfg"
    pyvenv_cfg.write_text(
        f"home = {base_bin}\nversion = {venv_cfg['version']}\ninclude-system-site-packages = true\n",
        encoding="utf-8",
    )
    system_site_status = invoke()
    assert "venv_provenance_unknown" in {
        r["code"] for r in system_site_status["reasons"]
    }
    assert not runner_marker.exists(), "system-site venv reached the test runner"
    pyvenv_cfg.write_text(
        f"home = {base_bin}\nversion = {venv_cfg['version']}\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )

    status = invoke()
    assert {"venv_provenance_unknown", "venv_unavailable"} & {
        r["code"] for r in status["reasons"]
    }
    assert not site_marker.exists(), (
        "candidate venv sitecustomize executed before provenance acceptance"
    )
    assert not pth_marker.exists(), (
        ".pth executable line ran before provenance acceptance"
    )
    assert not runner_marker.exists(), (
        "untrusted venv reached its configured test runner"
    )

    (site / "sitecustomize.py").unlink()
    (site / "f02-startup.pth").unlink()

    outside_path = tmp_path / "external-python-path"
    outside_path.mkdir()
    (site / "f02-external-path.pth").write_text(
        str(outside_path) + "\n", encoding="utf-8"
    )
    path_pth_status = invoke()
    assert "venv_provenance_unknown" in {r["code"] for r in path_pth_status["reasons"]}
    assert not runner_marker.exists(), (
        ".pth external path reached its configured test runner"
    )
    (site / "f02-external-path.pth").unlink()

    # A path can be inside the venv and still expose unreviewed startup hooks
    # or Agent source. The launcher must inspect the complete effective path.
    extra_site = repo / ".venv" / "extra"
    extra_site.mkdir()
    extra_hook_marker = tmp_path / "internal-extra-sitecustomize-ran"
    extra_agent_marker = tmp_path / "internal-extra-agent-imported"
    (extra_site / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(extra_hook_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (extra_site / "run_agent.py").write_text(
        f"from pathlib import Path; Path({str(extra_agent_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (site / "f02-internal-path.pth").write_text(
        str(extra_site) + "\n", encoding="utf-8"
    )
    internal_path_status = invoke()
    assert "venv_provenance_unknown" in {
        r["code"] for r in internal_path_status["reasons"]
    }
    assert not extra_hook_marker.exists()
    assert not extra_agent_marker.exists()
    assert not runner_marker.exists(), (
        "an in-venv .pth path exposed unchecked startup or Agent files"
    )
    (site / "f02-internal-path.pth").unlink()
    shutil.rmtree(extra_site)

    (site / "f02-editable.egg-link").write_text(
        str(tmp_path / "external-package") + "\n", encoding="utf-8"
    )
    egg_status = invoke()
    assert "venv_provenance_unknown" in {r["code"] for r in egg_status["reasons"]}
    assert not runner_marker.exists(), "egg-link candidate venv reached the test runner"

    (site / "f02-editable.egg-link").unlink()
    (site / "__editable__.f02.pth").write_text(
        f"import pathlib; pathlib.Path({str(pth_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    editable_status = invoke()
    assert "venv_provenance_unknown" in {r["code"] for r in editable_status["reasons"]}
    assert not pth_marker.exists(), (
        "editable-install .pth hook executed before provenance acceptance"
    )
    assert not runner_marker.exists(), (
        "editable-install venv reached its configured test runner"
    )
    (site / "__editable__.f02.pth").unlink()

    # Repository pytest.ini is executable configuration input. An addopts
    # plugin escape must be refused before the child runner is admitted.
    (repo / "pytest.ini").write_text(
        "[pytest]\naddopts = -p f02_synthetic_unreviewed_plugin\n",
        encoding="utf-8",
    )
    ini_status = invoke(expected_status=None)
    assert ini_status["status"] == "REFUSED"
    assert "pytest_config_disallowed" in {r["code"] for r in ini_status["reasons"]}
    assert not runner_marker.exists(), "unreviewed pytest.ini reached the runner"
    (repo / "pytest.ini").unlink()

    fake_agent_marker = tmp_path / "venv-agent-source-imported"
    (site / "run_agent.py").write_text(
        f"from pathlib import Path; Path({str(fake_agent_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    agent_status = invoke()
    assert "implicit_agent_discoverable" in {r["code"] for r in agent_status["reasons"]}
    assert not fake_agent_marker.exists(), "site-packages Agent sentinel was imported"
    assert not runner_marker.exists(), (
        "Agent-discoverable venv reached its configured test runner"
    )
    (site / "run_agent.py").unlink()

    fake_hermes_marker = tmp_path / "venv-hermes-command-imported"
    venv_hermes = repo / ".venv" / "bin" / "hermes"
    venv_hermes.write_text(
        f"#!/bin/sh\nprintf 'ran' > {str(fake_hermes_marker)!r}\n", encoding="utf-8"
    )
    venv_hermes.chmod(0o700)
    hermes_status = invoke()
    assert "implicit_agent_discoverable" in {
        r["code"] for r in hermes_status["reasons"]
    }
    assert not fake_hermes_marker.exists(), "venv Hermes executable was launched"
    assert not runner_marker.exists(), (
        "venv Hermes executable reached its configured test runner"
    )
    venv_hermes.unlink()

    lib_dir = repo / ".venv" / "lib"
    external_lib = tmp_path / "external-venv-lib"
    lib_dir.rename(external_lib)
    lib_dir.symlink_to(external_lib, target_is_directory=True)
    lib_status = invoke()
    assert "venv_provenance_unknown" in {r["code"] for r in lib_status["reasons"]}
    assert not runner_marker.exists(), (
        "venv lib symlink reached its configured test runner"
    )
    lib_dir.unlink()
    external_lib.rename(lib_dir)

    external_venv = tmp_path / "external-venv"
    (repo / ".venv").rename(external_venv)
    (repo / ".venv").symlink_to(external_venv, target_is_directory=True)
    linked_status = invoke()
    assert {"venv_provenance_unknown", "venv_unavailable"} & {
        r["code"] for r in linked_status["reasons"]
    }
    assert not site_marker.exists(), "venv symlink allowed sitecustomize to execute"
    assert not pth_marker.exists(), "venv symlink allowed .pth code to execute"
    assert not runner_marker.exists(), "venv symlink reached its configured test runner"

    (repo / ".venv").unlink()
    external_venv.rename(repo / ".venv")
    no_junit_status = invoke(expected_status=None)
    no_junit_codes = {r["code"] for r in no_junit_status["reasons"]}
    if no_junit_status["status"] == "NOT_RUN" and no_junit_codes & {
        "implicit_agent_discoverable",
        "checkout_dotenv_present",
    }:
        assert not runner_marker.exists()
        return
    assert no_junit_status["status"] == "FAIL"
    assert "junit_unparseable" in no_junit_codes
    assert no_junit_status["child_exit_code"] == 0
    assert runner_marker.exists(), "clean fake runner was not actually invoked"


def test_synthetic_base_startup_hook_is_refused_without_execution(
    tmp_path: Path,
) -> None:
    """Exercise base-hook scanning only against a synthetic stdlib tree."""
    launcher = _launcher_module()
    base_root = tmp_path / "synthetic-base"
    stdlib = base_root / "lib" / "python3.13"
    (stdlib / "lib-dynload").mkdir(parents=True)
    marker = tmp_path / "synthetic-base-sitecustomize-ran"
    hook = stdlib / "sitecustomize.py"
    hook.write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    synthetic_base = launcher.BaseInterpreter(
        str(base_root / "bin" / "python3.13"),
        str(base_root / "bin" / "python3.13"),
        str(base_root),
        (3, 13),
        str(stdlib),
    )
    try:
        launcher.scan_interpreter_hooks(synthetic_base)
    except launcher.Outcome as exc:
        assert exc.status == "NOT_RUN"
        assert exc.code == "venv_provenance_unknown"
        assert str(hook) in exc.detail
    else:
        pytest.fail("synthetic base stdlib startup hook was accepted")
    assert hook.is_file() and hook.parent.is_relative_to(tmp_path)
    assert not marker.exists(), "synthetic base startup hook executed during inspection"


def test_helper_reports_real_hermetic_facts_not_environment_labels() -> None:
    helper = _helper_module()
    problems = helper.verify_hermetic_environment(
        {
            "HOME": str(Path.home()),
            "HERMES_MU_STATE_ROOT": "/tmp/fake-proof-root",
            "HERMES_MU_AGENT_MODE": "none",
            "OPENAI_API_KEY": "mu-synthetic-test-secret",
        }
    )
    assert problems, (
        "labels and a token-shaped sentinel were incorrectly accepted as containment proof"
    )


def test_loopback_fixture_and_guard_allow_only_the_owned_endpoint() -> None:
    helper = _helper_module()
    with helper.LoopbackUpstream() as upstream:
        assert upstream.host in {"127.0.0.1", "::1"}
        with helper.NetworkGuard(allowed=()) as guard:
            guard.allow(upstream)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(upstream.url, timeout=3) as response:
                assert response.status == 200
            for destination in (
                *ADVERSARIAL["forbidden_destinations"],
                f"http://127.0.0.1:{upstream.port + 1}/",
            ):
                with pytest.raises(helper.DestinationRefused):
                    helper.validate_destination(destination, owned=(upstream,))


def test_loopback_guard_refuses_unowned_service_without_connecting() -> None:
    helper = _helper_module()
    with helper.NetworkGuard():
        with pytest.raises(helper.DestinationRefused):
            socket.create_connection(("127.0.0.1", 1), timeout=0.1)


def test_no_proxy_routes_owned_loopback_around_unowned_synthetic_proxy(
    monkeypatch,
) -> None:
    """Prove bypass routes directly; a proxy attempt is refused before contact."""
    helper = _helper_module()
    with helper.LoopbackUpstream() as target, helper.LoopbackUpstream() as proxy:
        # Both listeners are synthetic and owned by this test, but only target is
        # admitted by NetworkGuard. A proxy request must therefore be visible as
        # a refused connect, never as a request received by the proxy listener.
        monkeypatch.setenv("http_proxy", proxy.url)
        monkeypatch.delenv("HTTP_PROXY", raising=False)
        monkeypatch.setenv("no_proxy", target.host)
        monkeypatch.setenv("NO_PROXY", target.host)

        with helper.NetworkGuard() as guard:
            guard.allow(target)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler())
            with opener.open(target.url, timeout=3) as response:
                assert response.status == 200
                response.read()

            assert len(target.requests) == 1
            assert proxy.requests == []
            assert guard.refused == [], (
                "configured proxy was contacted instead of bypassed for the owned target"
            )

            # Remove only the bypass policy. This control request must try the
            # configured unowned proxy, where the guard refuses it before the
            # synthetic proxy receives anything.
            monkeypatch.setenv("no_proxy", "")
            monkeypatch.setenv("NO_PROXY", "")
            proxied_opener = urllib.request.build_opener(
                urllib.request.ProxyHandler()
            )
            with pytest.raises(urllib.error.URLError) as proxy_error:
                proxied_opener.open(target.url, timeout=3)
            assert isinstance(proxy_error.value.reason, helper.DestinationRefused)
            assert guard.refused == [
                (
                    "connect",
                    f"unowned loopback endpoint {proxy.host}:{proxy.port}",
                )
            ]
            assert len(target.requests) == 1
            assert proxy.requests == []


def test_refused_report_cannot_overwrite_foreign_file_or_follow_replaced_parent(
    run_launcher, tmp_path: Path, monkeypatch, capsys
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    auth_file = foreign / "auth.json"
    sentinel = '{"credential":"f02-synthetic-report-sentinel"}\n'
    auth_file.write_text(sentinel, encoding="utf-8")

    # The public CLI must reject an unrelated existing report target before
    # _emit can truncate it, even for an outcome that would otherwise be REFUSED.
    result = run_launcher(
        "--agent-checkout",
        str(REPO_ROOT / ".git"),
        "--tier",
        "native",
        "--report",
        str(auth_file),
    )
    assert result.returncode != 0
    status = _status(result)
    assert status["status"] == "REFUSED"
    assert "report_path_disallowed" in {r["code"] for r in status["reasons"]}
    assert auth_file.read_text(encoding="utf-8") == sentinel

    launcher = _launcher_module()
    selected = tmp_path / "selected-report-parent"
    selected.mkdir()
    report = selected / "result.json"
    if hasattr(launcher, "ReportTarget"):
        validated = launcher.ReportTarget(str(report), str(tmp_path))
    else:
        validated = launcher.validate_output_file(str(report), "--report")
    original_parent = tmp_path / "selected-report-parent-original"
    selected.rename(original_parent)
    selected.symlink_to(foreign, target_is_directory=True)
    outcome = launcher.Result()
    outcome.settle("REFUSED", "synthetic_refusal", "synthetic report-path race")
    try:
        try:
            exit_code = launcher._emit(outcome, validated)
        except launcher.Outcome as exc:
            assert exc.status == "REFUSED"
            exit_code = 2
        assert exit_code != 0
        captured = capsys.readouterr()
        emitted_status = _status(
            subprocess.CompletedProcess([], exit_code, captured.out, captured.err)
        )
        assert emitted_status["status"] == "FAIL"
        assert "report_write_failed" in {
            row["code"] for row in emitted_status["reasons"]
        }
        assert auth_file.read_text(encoding="utf-8") == sentinel
        assert not (foreign / "result.json").exists()
        assert not (original_parent / "result.json").exists(), (
            "report write followed a parent after its validated path was replaced"
        )
    finally:
        if hasattr(validated, "close"):
            validated.close()
        selected.unlink()
        original_parent.rename(selected)


@pytest.mark.parametrize("replacement_has_contents", [True, False])
def test_state_root_remove_does_not_delete_a_replacement_at_rmtree_boundary(
    tmp_path: Path, monkeypatch, replacement_has_contents: bool
) -> None:
    launcher = _launcher_module()
    state = launcher.StateRoot(str(tmp_path))
    root_path = Path(state.path)
    owned_marker = root_path / "owned.txt"
    owned_marker.write_text("allocated-root", encoding="utf-8")
    moved_original = tmp_path / "original-root-moved-aside"
    replacement = tmp_path / "replacement-directory"
    replacement.mkdir()
    replacement_marker = replacement / "foreign-synthetic-sentinel.txt"
    if replacement_has_contents:
        replacement_marker.write_text("must-survive", encoding="utf-8")

    real_rmtree = launcher.shutil.rmtree
    calls = []

    def swap_at_delete_boundary(*_args, **_kwargs):
        calls.append(True)
        root_path.rename(moved_original)
        replacement.rename(root_path)

    try:
        if hasattr(state, "_before_unlink"):
            # The fixed implementation exposes this private deterministic
            # barrier after anchored clearing and before the final identity check.
            state._before_unlink = swap_at_delete_boundary
        else:
            # This path reproduces the original vulnerable check/use window.
            def vulnerable_rmtree(path, *args, **kwargs):
                assert Path(path) == root_path
                swap_at_delete_boundary()
                return real_rmtree(path, *args, **kwargs)

            monkeypatch.setattr(launcher.shutil, "rmtree", vulnerable_rmtree)
        try:
            removed = state.remove()
        except launcher.Outcome as exc:
            assert exc.status == "FAIL"
            assert exc.code == "teardown_failed"
            removed = False
        assert calls or hasattr(state, "_before_unlink"), (
            "StateRoot.remove skipped the deterministic teardown barrier"
        )
        assert removed is False, "replacement race was reported as successful cleanup"
        if replacement_has_contents:
            assert (root_path / replacement_marker.name).read_text(
                encoding="utf-8"
            ) == "must-survive"
        else:
            assert root_path.is_dir(), "empty replacement directory was removed"
        assert moved_original.is_dir(), (
            "original allocation disappeared without safe cleanup"
        )
        assert list(moved_original.iterdir()) == [], (
            "original contents were not cleared through the allocation-time handle"
        )
    finally:
        if hasattr(state, "_close"):
            state._close()
        if root_path.is_symlink():
            root_path.unlink()
        if root_path.exists():
            real_rmtree(root_path)
        if moved_original.exists():
            real_rmtree(moved_original)
        if replacement.exists():
            real_rmtree(replacement)


def test_loopback_close_reports_or_waits_for_blocked_request_handler() -> None:
    helper = _helper_module()
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    request_errors = []

    def blocked_handler(_request):
        entered.set()
        if not release.wait(3):
            raise RuntimeError("synthetic handler release timed out")
        completed.set()
        return 200, {"Content-Type": "text/plain"}, b"released"

    upstream = helper.LoopbackUpstream(blocked_handler)
    upstream.start()

    def request():
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(upstream.url, timeout=4) as response:
                response.read()
        except Exception as exc:  # shutdown may close the synthetic socket
            request_errors.append(exc)

    client = threading.Thread(target=request, name="f02-owned-loopback-client")
    client.start()
    teardown_error = None
    close_returned_with_handler_live = False
    try:
        assert entered.wait(2), "synthetic handler never received the owned request"
        try:
            upstream.close(timeout=0.2)
        except helper.FixtureTeardownError as exc:
            teardown_error = exc
        close_returned_with_handler_live = not completed.is_set()
        assert teardown_error is not None or not close_returned_with_handler_live, (
            "close() returned successfully while an owned request handler was blocked"
        )
    finally:
        release.set()
        client.join(timeout=4)
        if client.is_alive():
            # Give the owned listener another bounded shutdown attempt before failing.
            try:
                upstream.close(timeout=1)
            except helper.FixtureTeardownError:
                pass
            client.join(timeout=1)
        assert not client.is_alive(), "owned loopback client thread leaked"
        try:
            upstream.close(timeout=1)
        except helper.FixtureTeardownError:
            pass
    assert completed.is_set() or teardown_error is not None


def test_loopback_start_failure_closes_the_newly_bound_listener(monkeypatch) -> None:
    helper = _helper_module()
    real_start = threading.Thread.start

    def fail_server_thread(thread):
        if thread.name == "mu-loopback-upstream":
            raise RuntimeError("synthetic thread.start failure")
        return real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_server_thread)
    upstream = helper.LoopbackUpstream()
    start_error = None
    rebound = False
    try:
        try:
            upstream.start()
        except Exception as exc:
            start_error = exc
        assert start_error is not None, "synthetic start failure was swallowed"
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((upstream.host, upstream.port))
            rebound = True
        except OSError:
            rebound = False
        finally:
            probe.close()
        assert rebound, "failed startup leaked its newly bound loopback listener"
    finally:
        if upstream._server is not None:
            upstream._server.server_close()
            upstream._server = None
            upstream._thread = None


def test_spawn_publication_interrupt_reaps_the_owned_child(tmp_path: Path) -> None:
    launcher = _launcher_module()
    spawned = []

    def interrupt_after_publication(proc):
        spawned.append(proc)
        # Deterministically deliver the interrupt at the ownership boundary.
        launcher._signal_handler(launcher.signal.SIGINT, None)

    launcher._SignalState.phase = "run"
    launcher._SignalState.received = None
    interrupted = False
    leaked_before_test_cleanup = False
    try:
        try:
            launcher.run_child(
                ["/bin/sh", "-c", "exec sleep 30"],
                env={"PATH": "/bin:/usr/bin"},
                cwd=str(tmp_path),
                timeout=5,
                after_spawn=interrupt_after_publication,
            )
        except launcher.Outcome as exc:
            interrupted = exc.status == "FAIL" and exc.code == "interrupted"
        except launcher._Interrupted:
            interrupted = True
        assert spawned, "synthetic Popen boundary did not create its owned child"
        leaked_before_test_cleanup = spawned[0].poll() is None
        assert interrupted and not leaked_before_test_cleanup, (
            "interrupt in the Popen publication window escaped without reaping the child"
        )
    finally:
        for proc in spawned:
            if proc.poll() is None:
                launcher.terminate_group(proc, first_signal=launcher.signal.SIGINT)
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
        launcher._SignalState.phase = "teardown"


def test_signal_after_popen_before_cleanup_is_deferred_and_reaped(
    tmp_path: Path,
) -> None:
    """A trace barrier hits the formerly unprotected post-Popen run phase."""
    launcher = _launcher_module()
    spawned = []
    barrier_hits = []
    old_handler = signal.getsignal(signal.SIGINT)
    old_phase = launcher._SignalState.phase
    old_received = launcher._SignalState.received
    launcher._SignalState.phase = "run"
    launcher._SignalState.received = None
    signal.signal(signal.SIGINT, launcher._signal_handler)

    def trace_run_child(frame, event, _arg):
        if (
            frame.f_code is launcher.run_child.__code__
            and event == "line"
            and not barrier_hits
            and "proc" in frame.f_locals
            and launcher._SignalState.phase == "run"
        ):
            spawned.append(frame.f_locals["proc"])
            barrier_hits.append(frame.f_lineno)
            # Inject the handler at this exact trace boundary. Before the fix,
            # this phase was restored after Popen but before cleanup's try.
            launcher._signal_handler(signal.SIGINT, None)
        return trace_run_child

    failure = None
    escaped_interrupt = False
    try:
        sys.settrace(trace_run_child)
        try:
            launcher.run_child(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import time; time.sleep(60)",
                ],
                env={"PATH": "/usr/bin:/bin"},
                cwd=str(tmp_path),
                timeout=10,
                label="synthetic post-Popen interrupt",
            )
        except launcher.Outcome as exc:
            failure = exc
        except launcher._Interrupted:
            escaped_interrupt = True
    finally:
        sys.settrace(None)
        try:
            for proc in spawned:
                try:
                    if proc.poll() is None:
                        launcher.terminate_group(
                            proc, first_signal=signal.SIGINT
                        )
                except BaseException:
                    # The test owns the Popen handle; product cleanup may be
                    # the defect under test, so retain an independent fallback.
                    pass
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=3)
        finally:
            signal.signal(signal.SIGINT, old_handler)
            launcher._SignalState.phase = old_phase
            launcher._SignalState.received = old_received

    assert barrier_hits, "trace barrier never reached the post-Popen run phase"
    assert not escaped_interrupt, (
        "SIGINT escaped run_child before its guaranteed cleanup region"
    )
    assert failure is not None
    assert failure.status == "FAIL" and failure.code == "interrupted"
    assert "owned group terminated=True" in failure.detail
    assert spawned and all(proc.poll() is not None for proc in spawned), (
        "run_child returned an interrupt outcome with its owned child still alive"
    )


def test_synthetic_operator_local_agent_install_path_is_not_an_explicit_source(
    tmp_path: Path,
) -> None:
    launcher = _launcher_module()
    repo = tmp_path / "webui"
    home = tmp_path / "synthetic-operator-home"
    installed = home / ".local" / "share" / "hermes-agent"
    repo.mkdir()
    installed.mkdir(parents=True)
    (installed / "run_agent.py").write_text("# synthetic installed marker\n")
    try:
        launcher.validate_agent_checkout(str(installed), str(repo), str(home))
    except launcher.Outcome as exc:
        assert exc.status == "REFUSED"
        assert exc.code == "installed_agent_location"
    else:
        pytest.fail("synthetic ~/.local/share/hermes-agent was accepted as a checkout")


def test_discovered_test_tree_rejects_symlinked_test_and_conftest_files(
    tmp_path: Path,
) -> None:
    launcher = _launcher_module()
    repo = tmp_path / "synthetic-repo"
    tests = repo / "tests" / "multiuser"
    outside = tmp_path / "outside-test.py"
    tests.mkdir(parents=True)
    outside.write_text("def test_outside(): pass\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    for name in ("test_link.py", "conftest.py"):
        (tests / name).symlink_to(outside)
        try:
            launcher.validate_test_path("tests/multiuser", str(repo))
        except launcher.Outcome as exc:
            assert exc.status in {"REFUSED", "NOT_RUN"}
            assert exc.code in {"unsafe_symlink", "path_outside_checkout"}
        else:
            pytest.fail(f"directory discovery accepted symlinked {name}")
        (tests / name).unlink()


def test_import_manifest_rejects_changed_new_and_linked_synthetic_modules(
    tmp_path: Path,
) -> None:
    launcher = _launcher_module()
    repo = tmp_path / "manifest-repo"
    package = repo / "synthetic_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("\n", encoding="utf-8")
    module = package / "approved.py"
    module.write_text("VALUE = 'approved'\n", encoding="utf-8")
    helper_source = repo / "multiuser_test_fixtures.py"
    helper_source.write_text("VALUE = 'reviewed helper'\n", encoding="utf-8")
    state = tmp_path / "manifest-state"
    (state / "launcher").mkdir(parents=True)
    bound = launcher.write_import_guard(
        str(state), launcher.build_import_manifest(str(repo))
    )

    def import_module(module_name: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            **bound,
        }
        code = (
            "import sys; "
            f"sys.path.insert(0, {bound['PYTHONPATH']!r}); import mu_import_guard; "
            f"sys.path.insert(0, {str(repo)!r}); import {module_name}"
        )
        return subprocess.run(
            [sys.executable, "-I", "-S", "-c", code],
            cwd=state,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

    accepted = import_module("synthetic_pkg.approved")
    assert accepted.returncode == 0, accepted.stderr
    (repo / ".env").write_text("F02_SYNTHETIC_DOTENV=never-load\n", encoding="utf-8")
    dotenv_added = import_module("synthetic_pkg.approved")
    assert dotenv_added.returncode != 0
    assert "ImportError" in dotenv_added.stderr
    (repo / ".env").unlink()
    helper_source.write_text("raise RuntimeError('changed helper executed')\n")
    helper_code = (
        "import importlib.util, sys; "
        f"sys.path.insert(0, {bound['PYTHONPATH']!r}); import mu_import_guard; "
        f"spec=importlib.util.spec_from_file_location('synthetic_helper', {str(helper_source)!r}); "
        "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)"
    )
    helper_changed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", helper_code],
        cwd=state,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", **bound},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert helper_changed.returncode != 0
    assert "ImportError" in helper_changed.stderr
    module.write_text("raise RuntimeError('synthetic changed source executed')\n")
    changed = import_module("synthetic_pkg.approved")
    assert changed.returncode != 0
    assert "ImportError" in changed.stderr
    (package / "new.py").write_text("VALUE = 'new'\n", encoding="utf-8")
    added = import_module("synthetic_pkg.new")
    assert added.returncode != 0
    assert "ImportError" in added.stderr
    outside = tmp_path / "synthetic-outside-module.py"
    outside.write_text(
        "raise RuntimeError('linked source executed')\n", encoding="utf-8"
    )
    (package / "linked.py").symlink_to(outside)
    linked = import_module("synthetic_pkg.linked")
    assert linked.returncode != 0
    assert "ImportError" in linked.stderr


@pytest.mark.parametrize(
    "shadow_name",
    [
        "pytest.pyc",
        "pytest/__init__.pyc",
        f"pytest{importlib.machinery.EXTENSION_SUFFIXES[0]}",
        f"pytest/__init__{importlib.machinery.EXTENSION_SUFFIXES[0]}",
    ],
)
def test_compiled_checkout_modules_cannot_shadow_pytest_before_runner(
    tmp_path: Path, shadow_name: str
) -> None:
    repo, runner_marker = _write_shadow_probe_checkout(tmp_path, shadow_name)
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(repo / "scripts" / "test_multiuser.py"),
            "--no-agent",
            "--tier",
            "unit",
            "--",
            "-q",
        ],
        cwd=repo,
        env={"PATH": str(empty_path)},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    status = _status(result)
    assert result.returncode == 2
    assert status["status"] == "REFUSED"
    assert "import_shadowing" in {item["code"] for item in status["reasons"]}
    assert not runner_marker.exists(), (
        f"runner executed before compiled checkout shadow was refused: {shadow_name}"
    )


def test_import_shadow_check_fails_closed_without_child_stdlib_inventory(
    tmp_path: Path,
) -> None:
    launcher = _launcher_module()
    repo = tmp_path / "inventory-repo"
    site = tmp_path / "inventory-site"
    repo.mkdir()
    site.mkdir()

    unavailable = launcher.Venv(str(tmp_path), None, (3, 13), [str(site)], None)
    try:
        launcher.check_import_shadowing(str(repo), unavailable)
    except launcher.Outcome as exc:
        assert exc.status == "NOT_RUN"
        assert exc.code == "venv_provenance_unknown"
    else:
        pytest.fail("missing child base incorrectly certified import safety")

    synthetic_stdlib = tmp_path / "incomplete-child-stdlib"
    (synthetic_stdlib / "lib-dynload").mkdir(parents=True)
    (synthetic_stdlib / "json.py").write_text("# synthetic stdlib inventory\n")
    incomplete_base = launcher.BaseInterpreter(
        sys.executable,
        sys.executable,
        str(tmp_path),
        (3, 13),
        str(synthetic_stdlib),
    )
    incomplete = launcher.Venv(
        str(tmp_path), None, (3, 13), [str(site)], incomplete_base
    )
    try:
        launcher.check_import_shadowing(str(repo), incomplete)
    except launcher.Outcome as exc:
        assert exc.status == "NOT_RUN"
        assert exc.code == "venv_provenance_unknown"
    else:
        pytest.fail("stdlib inventory without os was accepted as complete")


def test_report_does_not_admit_synthetic_credential_reader_or_network_script(
    run_launcher,
) -> None:
    helper = _helper_module()
    requests_seen = []

    def record_request(request):
        requests_seen.append(request)
        return 200, {"Content-Type": "text/plain"}, b"synthetic"

    with helper.LoopbackUpstream(record_request) as upstream:
        result = run_launcher(
            "--no-agent",
            "--script",
            "tests/multiuser/fixtures/unsupported_scope_probe.py",
            "--",
            upstream.url,
        )
        status = _status(result)
        assert result.returncode != 0
        assert status["status"] in {"NOT_RUN", "REFUSED"}
        assert not requests_seen, (
            "unsupported browser/script scope reached the newly owned listener"
        )


def test_synthetic_credential_reader_is_not_imported_by_unsupported_scope(
    run_launcher, tmp_path: Path
) -> None:
    marker = tmp_path / "synthetic-credential-reader-imported"
    result = run_launcher(
        "--no-agent",
        "--script",
        "tests/multiuser/fixtures/unsupported_scope_probe.py",
        "--",
        "credential-reader",
        str(marker),
    )
    status = _status(result)
    assert result.returncode != 0
    assert status["status"] in {"NOT_RUN", "REFUSED"}
    assert not marker.exists(), "synthetic credential-reader sentinel was imported"


def test_script_snapshot_does_not_import_unsnapshotted_repo_sibling(
    run_launcher, tmp_path: Path
) -> None:
    marker = tmp_path / "unsnapshotted-sibling-imported"
    result = run_launcher(
        "--no-agent",
        "--script",
        "tests/multiuser/fixtures/import_closure_probe.py",
        "--",
        str(marker),
    )
    status = _status(result)
    assert result.returncode != 0
    assert status["status"] in {"NOT_RUN", "REFUSED", "FAIL"}
    assert not marker.exists(), (
        "script imported mutable sibling source outside its snapshot"
    )


def test_fake_base_interpreter_is_refused_before_it_can_execute(tmp_path: Path) -> None:
    repo = tmp_path / "synthetic-base-checkout"
    scripts = repo / "scripts"
    tests = repo / "tests" / "multiuser"
    base = tmp_path / "fake-distribution"
    base_bin = base / "bin"
    stdlib = base / "lib" / "python3.13"
    for directory in (scripts, tests, base_bin, stdlib / "lib-dynload"):
        directory.mkdir(parents=True, exist_ok=True)
    for name in ("test_multiuser.py", "multiuser_test_fixtures.py"):
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)
    marker = tmp_path / "fake-base-executed"
    fake_python = base_bin / "python3.13"
    fake_python.write_text(
        f"#!/bin/sh\nprintf ran > {str(marker)!r}\nexit 0\n", encoding="utf-8"
    )
    fake_python.chmod(0o700)
    (stdlib / "os.py").write_text("# synthetic stdlib name only\n", encoding="utf-8")
    runner = scripts / "test.sh"
    runner.write_text(
        '#!/bin/sh\n"$HERMES_WEBUI_TEST_PYTHON" -c pass\n', encoding="utf-8"
    )
    runner.chmod(0o700)
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(scripts / "test_multiuser.py"),
            "--no-agent",
            "--tier",
            "unit",
        ],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin",
            "HERMES_WEBUI_TEST_PYTHON": str(fake_python),
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    status = _status(result)
    assert result.returncode == 3
    assert status["status"] == "NOT_RUN"
    assert "venv_provenance_unknown" in {r["code"] for r in status["reasons"]}
    assert not marker.exists(), "unverified fake base interpreter executed"


def test_prepare_phase_is_audited_before_execute_only_can_start(tmp_path: Path) -> None:
    repo = tmp_path / "synthetic-provision-checkout"
    scripts = repo / "scripts"
    tests = repo / "tests" / "multiuser"
    bin_dir = repo / ".venv" / "bin"
    cfg = {}
    for line in (REPO_ROOT / ".venv" / "pyvenv.cfg").read_text().splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            cfg[key] = value
    version_tag = ".".join(cfg["version"].split(".")[:2])
    site = repo / ".venv" / "lib" / f"python{version_tag}" / "site-packages"
    for directory in (scripts, tests, bin_dir, site):
        directory.mkdir(parents=True, exist_ok=True)
    for name in ("test_multiuser.py", "multiuser_test_fixtures.py"):
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)
    base_python = Path(cfg["executable"]).resolve()
    candidate = bin_dir / "python"
    candidate.symlink_to(base_python)
    (repo / ".venv" / "pyvenv.cfg").write_text(
        f"home = {base_python.parent}\nversion = {cfg['version']}\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    hook_marker = tmp_path / "install-created-pth-executed"
    execute_marker = tmp_path / "execute-only-reached"
    runner = scripts / "test.sh"
    runner.write_text(
        "#!/bin/sh\n"
        f"SITE={str(site)!r}\n"
        f"HOOK_MARKER={str(hook_marker)!r}\n"
        f"EXECUTE_MARKER={str(execute_marker)!r}\n"
        'if [ "${1:-}" = --prepare-only ]; then\n'
        '  printf "import pathlib; pathlib.Path(\'%s\').write_text(\'ran\')\\n" "$HOOK_MARKER" > "$SITE/provisioned.pth"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "${1:-}" = --execute-only ]; then\n'
        '  printf ran > "$EXECUTE_MARKER"\n'
        "  exit 0\n"
        "fi\n"
        # Legacy install-then-exec path: create a synthetic hook but never
        # invoke the candidate, which resolves into the host Python distribution.
        'printf "import pathlib; pathlib.Path(\'%s\').write_text(\'ran\')\\n" "$HOOK_MARKER" > "$SITE/provisioned.pth"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    runner.chmod(0o700)
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(scripts / "test_multiuser.py"),
            "--no-agent",
            "--tier",
            "unit",
            "--",
            "-q",
        ],
        cwd=repo,
        env={"PATH": "/usr/bin:/bin"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    status = _status(result)
    assert result.returncode == 3
    assert status["status"] == "NOT_RUN"
    assert "venv_provenance_unknown" in {r["code"] for r in status["reasons"]}
    assert not hook_marker.exists(), "prepare-created .pth executed before post-audit"
    assert not execute_marker.exists(), (
        "execute-only started before post-provision audit"
    )


def test_test_sh_default_invocation_still_executes_pytest_without_installing(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "synthetic-test-sh-checkout"
    scripts = repo / "scripts"
    venv_bin = repo / ".venv" / "bin"
    (repo / "tests" / "multiuser").mkdir(parents=True)
    scripts.mkdir(parents=True)
    venv_bin.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / "test.sh", scripts / "test.sh")
    (repo / "requirements-dev.txt").write_text("# synthetic-only\n", encoding="utf-8")
    marker = tmp_path / "default-pytest-invocation"
    fake_python = venv_bin / "python"
    fake_python.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = -m ] && [ "${2:-}" = pip ]; then exit 0; fi\n'
        'if [ "${1:-}" = - ]; then\n'
        "  code=$(cat)\n"
        '  case "$code" in\n'
        "    *importlib.util*) exit 0 ;;\n"
        "    *'sys.version_info[:2]'*) printf '3.13\\n'; exit 0 ;;\n"
        "    *'sys.version_info[:3]'*) printf '3.13.1\\n'; exit 0 ;;\n"
        "    *) exit 0 ;;\n"
        "  esac\n"
        "fi\n"
        'if [ "${1:-}" = -m ] && [ "${2:-}" = pytest ]; then\n'
        f"  printf '%s\\n' \"$*\" > {str(marker)!r}\n"
        "  exit 0\n"
        "fi\n"
        "exit 91\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o700)
    result = subprocess.run(
        ["/bin/bash", str(scripts / "test.sh"), "-q", "tests/multiuser"],
        cwd=repo,
        env={
            "PATH": "/bin:/usr/bin",
            "HERMES_WEBUI_TEST_PYTHON": str(fake_python),
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text(encoding="utf-8").split() == [
        "-m",
        "pytest",
        "-q",
        "tests/multiuser",
    ]
