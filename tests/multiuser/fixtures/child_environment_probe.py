"""Print non-secret facts about the launcher child process environment."""

import json
import os
from pathlib import Path
import shutil
import sys


secret_names = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HERMES_TEST_AUTH",
    "AWS_SECRET_ACCESS_KEY",
)
path_names = (
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "HERMES_HOME",
    "HERMES_BASE_HOME",
    "HERMES_CONFIG_PATH",
    "HERMES_WEBUI_STATE_DIR",
    "HERMES_WEBUI_DEFAULT_WORKSPACE",
    "CODEX_HOME",
    "HERMES_MU_STATE_ROOT",
    "TMPDIR",
    "TMP",
    "TEMP",
    "PYTHONPYCACHEPREFIX",
    "LOCALAPPDATA",
    "APPDATA",
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
    "HERMES_WEBUI_AGENT_DIR",
)

print(
    json.dumps(
        {
            "secret_presence": {name: name in os.environ for name in secret_names},
            "paths": {name: os.environ.get(name) for name in path_names},
            "hermes_agent_path_present": "HERMES_AGENT_PATH" in os.environ,
            "agent_mode": os.environ.get("HERMES_MU_AGENT_MODE"),
            "venv_python": os.environ.get("HERMES_WEBUI_PYTHON"),
            "agent_checkout": os.environ.get("HERMES_MU_AGENT_CHECKOUT"),
            "safe_values": {
                name: os.environ.get(name)
                for name in (
                    "NO_PROXY",
                    "no_proxy",
                    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                    "HERMES_DISABLE_LAZY_INSTALLS",
                    "HERMES_WEBUI_HOST",
                )
            },
            "path_exists": {
                name: Path(os.environ[name]).exists()
                for name in ("NETRC", "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG")
                if name in os.environ
            },
            "path_contains_hostile_bin": any(
                "hostile-bin" in item
                for item in os.environ.get("PATH", "").split(os.pathsep)
            ),
            "fake_hermes_visible": shutil.which("hermes") is not None
            and "hostile-bin" in (shutil.which("hermes") or ""),
            "pythonpath_present": "PYTHONPATH" in os.environ,
            "pythonpath": os.environ.get("PYTHONPATH"),
            "poison_present": {
                name: name in os.environ
                for name in (
                    "BASH_ENV",
                    "PYTEST_ADDOPTS",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "HERMES_AGENT_PATH",
                    "PYTHONHOME",
                    "ENV",
                    "SSH_AUTH_SOCK",
                    "LD_PRELOAD",
                    "DYLD_INSERT_LIBRARIES",
                    "DOCKER_HOST",
                    "HERMES_WEBUI_PORT",
                    "HERMES_WEBUI_PASSWORD",
                    "ALL_PROXY",
                )
            },
            "agent_modules_loaded": sorted(
                name
                for name in sys.modules
                if name in {"run_agent", "api.startup"}
                or name.startswith("hermes_agent")
            ),
        },
        sort_keys=True,
    )
)
