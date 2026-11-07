"""Opt-in real root CLI setup: synthetic homes and credentials only."""

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

import pytest

pytestmark = pytest.mark.skipif(os.getenv('HERMES_MULTIUSER_DOCKER_TEST') != '1',
    reason='Explicit trusted-operator acceptance gate; never use real Hermes homes')


def test_fresh_setup_discovers_profiles_assigns_admin_and_rerun_keeps_password_and_ids():
    root = Path(tempfile.mkdtemp(prefix='hmu-setup-', dir='/tmp'))
    fixture = Path(tempfile.mkdtemp(prefix='hmu-setup-source-', dir='/tmp'))
    source = fixture / 'original'; source.mkdir()
    for profile in [source, source / 'profiles/writer']:
        profile.mkdir(parents=True, exist_ok=True)
        (profile / 'config.yaml').write_text('model:\n  provider: custom\n  default: fixture-model\n  base_url: http://127.0.0.1:1/v1\n')
        (profile / 'USER.md').write_text('private original state')
    password = secrets.token_urlsafe(32)
    prefix = ['sudo', '-n']
    if os.environ.get('LD_LIBRARY_PATH'):
        prefix += ['env', 'LD_LIBRARY_PATH=' + os.environ['LD_LIBRARY_PATH']]
    command = [*prefix, sys.executable, '-m', 'multiuser.manage', '--root', str(root), 'setup',
        '--public-url', 'http://127.0.0.1:8799', '--images', os.environ['HERMES_MULTIUSER_TEST_IMAGES'],
        '--hermes-home', str(source), '--backup-root', str(fixture / 'backups'),
        '--username', 'test-administrator', '--password-stdin']
    try:
        first = subprocess.run(command, input=password + '\n', capture_output=True, text=True, check=True)
        result = json.loads(first.stdout)
        assert result['admin_created'] and all(p['status'] == 'ready' for p in result['profiles'])
        assert len(result['profiles']) == 2 and password not in first.stdout + first.stderr
        second = json.loads(subprocess.run(command, input='must-not-replace-existing-password\n',
            capture_output=True, text=True, check=True).stdout)
        assert second['admin_created'] is False
        assert second['profiles'] == result['profiles']
        # Root-only read assertion; no hash or secret crosses stdout.
        proof = ('import sys;from pathlib import Path;from multiuser.settings import Settings;'
            's=Settings.load(Path(sys.argv[1]));db=s.store();u=db.users();assert len(u)==1;'
            'assert u[0]["template_id"]==sys.argv[2];'
            'db.login("test-administrator",sys.stdin.readline().strip(),"setup-test");'
            'assert not any((s.root/"users").iterdir());print("setup verified")')
        checked = subprocess.run([*prefix, sys.executable, '-c', proof, str(root), result['profiles'][0]['template_id']],
            input=password + '\n', capture_output=True, text=True, check=True)
        assert checked.stdout.strip() == 'setup verified'
        assert (source / 'USER.md').read_text() == 'private original state'
    finally:
        # Only paths allocated by this test, under /tmp, may be cleaned up.
        cleanup = ('import sys,shutil;from pathlib import Path;'
            'paths=[Path(p) for p in sys.argv[1:]];'
            'assert all(p.parent==Path("/tmp") and p.name.startswith("hmu-setup-") for p in paths);'
            '[shutil.rmtree(p) for p in paths]')
        subprocess.run([*prefix, sys.executable, '-c', cleanup, str(root), str(fixture)], check=True)
        assert not root.exists() and not fixture.exists()
