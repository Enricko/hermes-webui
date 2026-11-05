"""Independent F02 launcher tests; deliberately isolated from root conftest."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "scripts" / "test_multiuser.py"
SECRET_MARKERS = {
    "OPENAI_API_KEY": "f02-synthetic-openai-secret-71f0",
    "ANTHROPIC_API_KEY": "f02-synthetic-anthropic-secret-46ab",
    "HERMES_TEST_AUTH": "f02-synthetic-hermes-auth-5a21",
    "AWS_SECRET_ACCESS_KEY": "f02-synthetic-aws-secret-92d4",
}


@pytest.fixture
def hostile_parent_env(tmp_path: Path) -> dict[str, str]:
    """Supply only synthetic credentials and a fake installed-source hint."""
    fake_bin = tmp_path / "hostile-bin"
    fake_bin.mkdir()
    fake_hermes = fake_bin / "hermes"
    fake_hermes.write_text(
        f"#!/bin/sh\nprintf 'ran' > {str(tmp_path / 'hermes-path-used')!r}\n",
        encoding="utf-8",
    )
    fake_hermes.chmod(0o700)
    env = {"PATH": str(fake_bin)}
    env.update(SECRET_MARKERS)
    env["HERMES_AGENT_PATH"] = str(tmp_path / "fake-installed-agent")
    env["PYTHONPATH"] = str(
        REPO_ROOT / "tests" / "multiuser" / "fixtures" / "hostile_pythonpath"
    )
    env["F02_SITE_MARKER_PATH"] = str(tmp_path / "sitecustomize-imported")
    shell_hook = tmp_path / "hostile-bash-env"
    shell_hook.write_text(
        f"printf 'ran' > {str(tmp_path / 'bash-env-imported')!r}\n", encoding="utf-8"
    )
    env["BASH_ENV"] = str(shell_hook)
    env["PYTEST_ADDOPTS"] = "-p no:cacheprovider --confcutdir=tests"
    env["HTTP_PROXY"] = "http://127.0.0.1:1"
    env["HTTPS_PROXY"] = "http://127.0.0.1:1"
    env["ALL_PROXY"] = "http://127.0.0.1:1"
    env["PYTHONHOME"] = str(tmp_path / "hostile-pythonhome")
    env["ENV"] = str(shell_hook)
    env["TMPDIR"] = str(tmp_path / "hostile-temp")
    env["NETRC"] = str(tmp_path / "hostile-netrc")
    env["AWS_SHARED_CREDENTIALS_FILE"] = str(tmp_path / "hostile-aws-credentials")
    env["KUBECONFIG"] = str(tmp_path / "hostile-kubeconfig")
    return env


@pytest.fixture
def launcher() -> Path:
    return LAUNCHER


@pytest.fixture
def run_launcher(launcher: Path):
    """Run the public launcher interface without altering this pytest process."""

    def run(
        *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        if not launcher.is_file():
            # Missing implementation is an expected, meaningful baseline failure.
            return subprocess.CompletedProcess(
                [sys.executable, "-I", "-S", str(launcher), *args],
                2,
                "",
                f"missing launcher: {launcher}",
            )
        return subprocess.run(
            [sys.executable, "-I", "-S", str(launcher), *args],
            cwd=REPO_ROOT,
            env=env or {"PATH": os.environ.get("PATH", "")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )

    return run
