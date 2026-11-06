"""Real Linux namespace probes with synthetic workspaces; no host state."""
import json
import socket
from pathlib import Path
import shutil

import pytest

from api.access_policy import AccessDenied
from api.workspace_sandbox import PrivateWorkspace, WorkspaceSandbox, validate_tool


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path/'alice-id'/'alice'
    root.mkdir(parents=True, mode=0o700)
    return PrivateWorkspace('alice-id','alice',root)


def test_workspace_name_comes_from_login_not_selected_profile(workspace):
    record = {'id':'alice-id','username':'alice','profile':'stayfalz','workspaces':[str(workspace.host_path)]}
    first = PrivateWorkspace.from_account(record)
    record['profile'] = 'default'
    second = PrivateWorkspace.from_account(record)
    assert first == second
    assert first.visible_path == '/alice'


@pytest.mark.parametrize('path', ['/', '/tmp', '/etc'])
def test_storage_root_must_belong_to_immutable_account(path):
    with pytest.raises(AccessDenied):
        PrivateWorkspace.from_account({'id':'alice-id','username':'alice','workspaces':[path]})


def test_another_accounts_storage_and_symlinks_are_rejected(workspace,tmp_path):
    other = tmp_path/'bob-id'/'bob'
    other.mkdir(parents=True)
    record = {'id':'alice-id','username':'alice','workspaces':[str(other)]}
    with pytest.raises(AccessDenied):
        PrivateWorkspace.from_account(record)
    alias = tmp_path/'alias'
    alias.symlink_to(workspace.host_path,target_is_directory=True)
    record['workspaces'] = [str(alias)]
    with pytest.raises(AccessDenied):
        PrivateWorkspace.from_account(record)


def test_unknown_tool_is_denied_before_execution(workspace):
    if not shutil.which('bwrap'):
        pytest.skip('bubblewrap unavailable')
    with pytest.raises(AccessDenied):
        WorkspaceSandbox().run(workspace,{},'ungranted',[])


def test_group_or_world_writable_program_is_not_approved(tmp_path):
    path=tmp_path/'unsafe'
    path.write_text('#!/bin/sh\ntrue\n')
    path.chmod(0o777)
    with pytest.raises(ValueError):
        validate_tool(str(path))


@pytest.mark.skipif(not shutil.which('bwrap') or not Path('/usr/bin/python3').exists(),reason='requires Linux bubblewrap and system Python')
def test_real_sandbox_blocks_host_and_other_accounts_but_runs_approved_tool(workspace,tmp_path,monkeypatch):
    source = tmp_path/'approved-script.py'
    source.write_text('print("approved")\n')
    source.chmod(0o700)
    foreign = tmp_path/'bob-id'/'bob'
    foreign.mkdir(parents=True)
    secret = foreign/'private-sentinel'
    secret.write_text('synthetic foreign private data')
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-host-key-must-not-be-inherited')
    code = """
import os,json,socket
from pathlib import Path
denied=False
try:Path('/tools/script/approved-script.py').write_text('changed')
except OSError:denied=True
network=False
try:socket.create_connection(('127.0.0.1',ProbePort),timeout=.1)
except OSError:network=True
Path('own.txt').write_text('own data')
leaked=[]
for fd in Path('/proc/self/fd').iterdir():
 if int(fd.name)>2:
  try:leaked.append(os.readlink(fd))
  except FileNotFoundError:pass
status=Path('/proc/self/status').read_text()
print(json.dumps({'cwd':os.getcwd(),'home':os.environ['HOME'],
'host_absent':not Path('/root/.hermes').exists(),'foreign_absent':not Path(Foreign).exists(),
'script_readonly':denied,'script_visible':Path('/tools/script/approved-script.py').is_file(),
'host_key_absent':'OPENAI_API_KEY' not in os.environ,'network_isolated':network,
'own_writable':Path('own.txt').read_text()=='own data','no_host_descriptors':not leaked,
'no_effective_caps':'CapEff:\\t0000000000000000' in status,'no_new_privileges':'NoNewPrivs:\\t1' in status}))
""".replace('Foreign',repr(str(secret)))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen(1)
        code=code.replace('ProbePort',str(listener.getsockname()[1]))
        result=WorkspaceSandbox().run(workspace,{'python':'/usr/bin/python3','script':str(source)},'python',['-c',code])
    assert result.returncode == 0, result.stderr
    report=json.loads(result.stdout)
    assert report == {'cwd':'/alice','home':'/alice','host_absent':True,'foreign_absent':True,
                      'script_readonly':True,'script_visible':True,'host_key_absent':True,
                      'network_isolated':True,'own_writable':True,'no_host_descriptors':True,
                      'no_effective_caps':True,'no_new_privileges':True}
    assert source.read_text()=='print("approved")\n'
    assert secret.read_text()=='synthetic foreign private data'
    executed=WorkspaceSandbox().run(workspace,{'python':'/usr/bin/python3','script':str(source)},'python',
                                    ['/tools/script/approved-script.py'])
    assert executed.returncode==0 and executed.stdout.strip()=='approved'
