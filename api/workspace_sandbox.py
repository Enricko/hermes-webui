"""Linux private-workspace boundary for approved executables.

This launcher is a containment primitive, not yet the full Agent worker bridge.
Do not use it as a terminal-only patch while Python/MCP execute on the host.
The entire untrusted worker must eventually live inside the same boundary.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import stat
import subprocess

from api.access_policy import AccessDenied, _id
from api.account_admin import workspace_alias


def validate_tool(executable: str) -> Path:
    if os.name != 'posix':
        raise ValueError('Installed tool registration requires the verified POSIX backend')
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise ValueError('An absolute installed executable path is required')
    try:
        path = Path(executable).resolve(strict=True)
        status = path.stat()
    except (OSError, RuntimeError):
        raise ValueError('Installed executable is unavailable') from None
    if not stat.S_ISREG(status.st_mode) or not status.st_mode & 0o111 or status.st_mode & 0o022:
        raise ValueError('Approved executables must be regular, executable and not group/world writable')
    if status.st_uid not in {0, os.geteuid()}:
        raise ValueError('Approved executable has an untrusted owner')
    return path


@dataclass(frozen=True)
class PrivateWorkspace:
    account_id: str
    username: str
    host_path: Path

    @property
    def visible_path(self):
        return workspace_alias(self.username)

    @classmethod
    def from_account(cls, record: dict):
        if record.get('disabled'):
            raise AccessDenied('Account is disabled')
        identifier = _id(record.get('id'))
        alias = workspace_alias(record.get('username'))
        roots = record.get('workspaces')
        if not isinstance(roots, (list, tuple)) or len(roots) != 1:
            raise AccessDenied('One private account storage root is required')
        raw = Path(roots[0])
        if not raw.is_absolute() or raw.is_symlink():
            raise AccessDenied('Private workspace must be an absolute directory, not a symlink')
        host = raw.resolve(strict=True)
        if host.parent.name != identifier or not host.is_dir():
            raise AccessDenied('Private storage is not bound to this immutable account')
        return cls(identifier, alias[1:], host)


class WorkspaceSandbox:
    """Expose one writable account root and selected read-only executables.

    A private PID, mount, IPC, user and network namespace excludes the host's
    homes, sockets, processes and network. Open descriptors pin mount sources;
    a later symlink/path replacement cannot redirect an approved mount.
    """

    def __init__(self, executable=None):
        self.executable = executable or shutil.which('bwrap')
        if not self.executable or os.name != 'posix' or not hasattr(os, 'O_PATH'):
            raise RuntimeError('Verified Linux bubblewrap backend unavailable')

    def run(self, workspace: PrivateWorkspace, approved: dict[str, str], tool_id: str,
            arguments: list[str], *, timeout=30):
        if tool_id not in approved:
            raise AccessDenied('Tool is not approved for this account')
        if not isinstance(arguments, list) or any(not isinstance(value, str) or '\0' in value for value in arguments):
            raise ValueError('Invalid tool arguments')
        destination = workspace.visible_path
        _id(workspace.account_id)
        if workspace.host_path.parent.name != workspace.account_id:
            raise AccessDenied('Private storage owner mismatch')
        with ExitStack() as stack:
            descriptors = []
            def pin(path, *, directory=False):
                flags = os.O_PATH | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0)
                fd = os.open(path, flags)
                stack.callback(os.close, fd)
                descriptors.append(fd)
                return fd
            root_fd = pin(workspace.host_path, directory=True)
            try:
                os.mkdir('.tmp', mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                temporary_fd = os.open('.tmp', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                os.close(temporary_fd)
            command = [self.executable, '--unshare-all', '--unshare-user', '--die-with-parent', '--new-session',
                       '--disable-userns', '--cap-drop', 'ALL', '--clearenv',
                       '--hostname', 'private-workspace', '--proc', '/proc', '--dev', '/dev',
                       '--dir', '/usr', '--dir', '/usr/bin', '--dir', '/etc',
                       '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib']
            for source in (Path('/usr/lib'), Path('/usr/lib64')):
                if source.exists():
                    command += ['--ro-bind-fd', str(pin(source, directory=True)), str(source)]
            if Path('/usr/lib64').exists():
                command += ['--symlink', 'usr/lib64', '/lib64']
            destinations = {}
            for identifier, raw in approved.items():
                _id(identifier)
                source = validate_tool(raw)
                if source.is_relative_to(workspace.host_path.resolve()):
                    raise AccessDenied('Shared approved tools must be outside private writable storage')
                fd = pin(source)
                status = os.fstat(fd)
                if not stat.S_ISREG(status.st_mode) or not status.st_mode & 0o111 or status.st_mode & 0o022 or status.st_uid not in {0, os.geteuid()}:
                    raise AccessDenied('Approved executable changed during admission')
                requested = Path(raw)
                target = str(Path('/usr/bin') / requested.name) if requested.parent in {Path('/usr/bin'), Path('/bin')} else '/tools/' + identifier + '/' + source.name
                command += ['--ro-bind-fd', str(fd), target]
                destinations[identifier] = target
            command += ['--bind-fd', str(root_fd), destination,
                        '--symlink', destination + '/.tmp', '/tmp',
                        '--setenv', 'HOME', destination, '--setenv', 'TMPDIR', destination + '/.tmp',
                        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                        '--chdir', destination, '--remount-ro', '/', '--', destinations[tool_id], *arguments]
            return subprocess.run(command, pass_fds=descriptors, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=timeout, check=False,
                                  env={'PATH':'/usr/bin:/bin'})
