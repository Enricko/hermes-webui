"""Private container entrypoint for the unchanged WebUI and official cron tick."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def cron_loop():
    from cron.scheduler import tick
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _sig, _frame: stopping.set())
    while not stopping.is_set():
        try:
            tick(verbose=False, headless=True)
        except Exception as exc:
            # No job payloads, keys or URLs in supervisor logs.
            print('Private cron tick failed: ' + type(exc).__name__, file=sys.stderr, flush=True)
        stopping.wait(5)


def main():
    if os.geteuid() == 0:
        raise SystemExit('Worker must run as a non-root account')
    private_home = '/state/hermes'
    os.environ.update({
        'HOME': private_home, 'HERMES_HOME': private_home, 'HERMES_BASE_HOME': private_home,
        'HERMES_CONFIG_PATH': private_home + '/config.yaml',
        'HERMES_WEBUI_STATE_DIR': private_home + '/webui',
        'HERMES_WEBUI_DEFAULT_WORKSPACE': '/workspace',
        'HERMES_WEBUI_AGENT_DIR': '/opt/hermes',
        'HERMES_WEBUI_HOST': '127.0.0.1', 'HERMES_WEBUI_PORT': '8787',
        'HERMES_WEBUI_PASSWORD': '', 'HERMES_WEBUI_SKIP_ONBOARDING': '1',
        'HERMES_DISABLE_LAZY_INSTALLS': '1',
        'TMPDIR': '/tmp', 'XDG_CACHE_HOME': private_home + '/cache',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
        'HTTP_PROXY': 'http://127.0.0.1:8001', 'HTTPS_PROXY': 'http://127.0.0.1:8001',
        'http_proxy': 'http://127.0.0.1:8001', 'https_proxy': 'http://127.0.0.1:8001',
        'NO_PROXY': '127.0.0.1,localhost,::1', 'no_proxy': '127.0.0.1,localhost,::1',
        'OPENAI_API_KEY': 'tenant-broker', 'OPENAI_BASE_URL': 'http://127.0.0.1:8000/v1',
        'AWS_EC2_METADATA_DISABLED': 'true',
    })
    os.chdir('/workspace')
    if '--cron' in sys.argv[1:]:
        cron_loop()
        return
    # Fail at startup if the actual Agent cannot import. An agent-free UI is
    # useful upstream, but cannot be admitted as a complete multi-user worker.
    from run_agent import AIAgent
    if not callable(AIAgent):
        raise SystemExit('Hermes Agent import failed')
    if not Path(private_home + '/config.yaml').is_file():
        raise SystemExit('Provision an explicit capability template first')
    commands = [[sys.executable, '/opt/webui/server.py'],
                [sys.executable, '-m', 'multiuser.worker', '--cron']]
    children = [subprocess.Popen(command, start_new_session=True) for command in commands]
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _sig, _frame: stopping.set())
    failed = False
    try:
        while not stopping.wait(0.5):
            if any(child.poll() is not None for child in children):
                failed = True
                break
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
        deadline = time.monotonic() + 25
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
