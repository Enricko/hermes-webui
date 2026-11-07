"""Private container entrypoint for the unchanged WebUI and official cron tick."""

import os
from pathlib import Path
import re
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
    base_home = '/state/hermes'
    profile = sys.argv[sys.argv.index('--profile') + 1] if '--profile' in sys.argv else 'default'
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', profile):
        raise SystemExit('Invalid private scheduler profile')
    private_home = base_home if profile == 'default' else base_home + '/profiles/' + profile
    os.environ.update({
        'HOME': private_home, 'HERMES_HOME': private_home, 'HERMES_BASE_HOME': base_home,
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
    # A global config override pins every request to the root YAML and defeats
    # upstream's request-local native profile routing. Only fixed-home cron
    # processes need an explicit override; the WebUI resolves it per request.
    os.environ.pop('HERMES_CONFIG_PATH', None)
    os.chdir('/workspace')
    if '--cron' in sys.argv[1:]:
        os.environ['HERMES_CONFIG_PATH'] = private_home + '/config.yaml'
        cron_loop()
        return
    # Fail at startup if the actual Agent cannot import. An agent-free UI is
    # useful upstream, but cannot be admitted as a complete multi-user worker.
    from run_agent import AIAgent
    if not callable(AIAgent):
        raise SystemExit('Hermes Agent import failed')
    if not Path(private_home + '/config.yaml').is_file():
        raise SystemExit('Provision an explicit capability template first')
    profiles = os.environ.get('HERMES_MULTIUSER_PROFILE_NAMES', 'default').split(',')
    if (not 1 <= len(profiles) <= 32 or len(set(profiles)) != len(profiles) or
            any(not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', name) for name in profiles)):
        raise SystemExit('Invalid provisioned scheduler profiles')
    commands = [[sys.executable, '/opt/webui/server.py']]
    # Each scheduler imports the official Agent in a fresh process with its
    # own fixed home/config. Profile switching never changes a shared env.
    commands += [[sys.executable, '-m', 'multiuser.worker', '--cron', '--profile', name] for name in profiles]
    children = []
    for command in commands:
        env = dict(os.environ)
        if '--profile' in command:
            name = command[command.index('--profile') + 1]
            home = base_home if name == 'default' else base_home + '/profiles/' + name
            env.update(HOME=home, HERMES_HOME=home, HERMES_CONFIG_PATH=home+'/config.yaml',
                       HERMES_WEBUI_STATE_DIR=home+'/webui', XDG_CACHE_HOME=home+'/cache')
        children.append(subprocess.Popen(command, start_new_session=True, env=env))
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
