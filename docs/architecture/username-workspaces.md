# Username workspace and installed-tool boundary

The user chose the **login username** for private folder names. A login named
`naufal` sees `/naufal`; selecting the existing Hermes `default` or `stayfalz`
profile does not move that boundary. A login named `stayfalz` would see
`/stayfalz`. A profile is an administrator-assigned template, not another
account's private home or conversation directory.

The login-scoped workspace is automatic on account creation and retained when
the administrator replaces profile/tool/provider grants. The UI shows its alias
as read only rather than offering a different user's folder as a choice.

Backing storage remains under a trusted account-data directory and immutable
account ID, with a username leaf for new accounts. The visible runtime alias is
`/<login>`. Two accounts or deletion/recreation of a username cannot substitute
one another's immutable storage owner. Existing private storage is retained;
its host directory is not renamed or exposed as a selectable arbitrary path.

The administrator panel displays the fixed private alias and can import the
server's existing Hermes profiles. Import creates persistent resource IDs for
profile names without copying `.env`, credentials, memory or conversations.
It does not grant profiles automatically. Removed profiles become unavailable
and cannot authorize new admissions; reimport retains the original resource ID.
Imported profile definitions are managed through the existing Profiles UI.

Installed scripts/executables are a separate `tool` resource with an absolute
administrator-approved source path. Their grants are explicit. A selected tool
is exposed read only, while dependencies live in read-only runtime library
trees. Tool access does not expose parent host directories, other users' homes,
credential stores, process environments, host sockets or the host network.
Executables must be regular executable files with trusted ownership and without
group/world write permission. The dispatcher cannot select an ungranted tool ID.

## Containment primitive

`api/workspace_sandbox.py` implements a Linux bubblewrap launch boundary:

- A single private writable account directory is mounted at `/<login>`.
- Runtime libraries and explicitly approved executables are read-only mounts.
  Custom script entry points appear under `/tools/<tool-id>/`; their enclosing
  host directories are not exposed. Only approved binaries appear in `/usr/bin`.
- File descriptors pin mounts, so source path/symlink replacement cannot redirect
  the mount after admission. A private `.tmp` lives inside the username folder.
- Mount, PID, user, IPC and network namespaces are unshared, capabilities dropped,
  further user namespaces disabled, and ambient credentials/environment removed.
- Backend failure is an error, never host execution fallback.

The real Linux regression launches system Python against synthetic account
directories and an approved script. It proves own-folder writes succeed, host
and foreign files are absent, host credentials are absent, shared-script writes
fail, the approved script can execute, and a synthetic host network listener is
unreachable. It also checks that no host mount descriptors, effective Linux
capabilities or privilege-gaining exec state survive into the command. This
evidence is for the containment primitive only.

## Integration status

**The full native Agent worker bridge is not implemented.** The launcher is not
an Agent runtime or a terminal-only permission patch. AIAgent, Python/MCP tools,
workspace APIs, run/event/control ownership and scoped provider brokerage must
all execute through the verified boundary before member execution is enabled.
The original Hermes UI remains in place; members cannot fall back to its
privileged host execution paths. Account/profile/tool configuration is available
for preparation, but this change does not claim live private member Agent runs.

Only Linux/POSIX behavior has been exercised. Unknown platforms/backends refuse
execution rather than inheriting the host's permissions. Shared-library and
tool dependencies require a reviewed runtime image/definition when integrating
the complete worker; a path allowlist is not a substitute for containment.
