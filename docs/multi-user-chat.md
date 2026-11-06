# Username/password multi-user chat

**Experimental alternative, not the requested/default Hermes interface.** This
separate UI was an incorrect substitution for adding multi-user features to the
original app. The staging/default integration now preserves the upstream UI and
Agent backend, with account administration inside Settings → System. See
[current status](architecture/multi-user-implementation.md). The instructions
below are retained for isolated development/regression work only.

This fork provides an opt-in, **tool-free** multi-user chat service. Each account
has private conversations and files. Administrators create username/password
accounts, disable access, reset passwords, and assign profiles, workspaces,
provider connections/models and skills through `/admin/users`.

Profiles and skills in this mode are administrator-managed **instruction
templates**, not executable Agent profiles or tool packages. Messages render as
plain text. Terminal, code execution, MCP, background agents, cron and legacy
host file/Git APIs are unavailable. The broader
[full Agent multi-user design](architecture/multi-user-access-design.md) remains
unfinished; this mode does not claim its isolated-runtime or OAuth guarantees.

## Run separately from an existing installation

Use a separate checkout and private control state. Do not reuse the production
Hermes home. Install the repository runtime dependencies in a supported Python
environment; the existing `./scripts/test.sh --prepare-only` prepares a development
environment if needed. The account CLI prompts for a password; never put one on
the command line or in a tracked file.

```bash
export HERMES_HOME=/path/to/private-control/hermes-home
export HERMES_WEBUI_STATE_DIR=/path/to/private-control/webui
export HERMES_WEBUI_USERS_FILE=/path/to/private-control/users.json
export HERMES_WEBUI_ACCESS_POLICY_FILE=/path/to/private-control/access.sqlite
export HERMES_WEBUI_MEMBER_CHAT=1

python scripts/webui_users.py add administrator --role admin
python scripts/webui_access.py --admin administrator init
python scripts/serve_members.py --port 8789
```

The dedicated server binds `127.0.0.1` and only exposes login, account/access
management, member chat and private files. It does not start the normal WebUI's
Agent lifecycle/watchers, and denies legacy execution endpoints for **both
administrators and members**. Root redirects administrators to `/admin/users`
and members to `/member`. Place an authenticated production deployment behind
the operator's HTTPS reverse proxy when separately deploying it.

The same pages/API are also present in the normal WebUI, whose existing
administrator execution features remain unchanged. Prefer the dedicated server
when the deployment should expose only private chat. A Users & access link is
available in the normal WebUI's settings for local account administrators.

## Administrator workflow

1. Sign in with the administrator username and password.
2. Define profile instructions, a private workspace and optional skill
   instructions under Resources. Workspace folders are created separately for
   each account; assigning the same workspace ID does not share files.
3. Define a provider connection: API format, trusted base URL, upstream account
   identity and API key. Use a distinct resource ID/account identity for each
   provider account, even at the same URL. Supported formats are OpenAI-compatible
   Chat Completions (base URL normally ends in `/v1`) and native Anthropic Messages.
4. Create a username/password account. New UI passwords require at least 12
   characters. Choose User or Admin and leave Account enabled checked.
5. Select the account, check its permitted resources, and enter the explicit
   allowed model names for each provider connection. Save access. Multiple
   profiles, workspaces and connections are supported; future resources are not
   granted automatically.

Passwords and API keys are write-only. Leave a password blank to retain it.
Changing a connection's endpoint/account/protocol requires entering its API key
again; credentials are bound to that exact metadata so a relink cannot reuse an
old account's key. The database contains policy metadata, not provider keys.
Keys live in a separate service-side vault with private file permissions and
never enter a member response, message, prompt, browser storage or file folder.

Disable an account to invalidate its login. Reenabling cannot revive old cookies.
Resetting a password or changing a role also invalidates existing login authority.
The last active administrator cannot be disabled or demoted. Accounts and their
private data are retained on disablement; automatic deletion is not implemented.

## Member workflow

Choose an assigned profile, workspace, provider/model and any assigned skills.
Start a conversation and send a message. A conversation retains its original
selection; start another conversation to use a different selection. Only the
account's own currently authorized conversations appear in its sidebar.

Private files support folders, upload, text preview and download, with a 2 MiB
per-file limit. Uploads are stored, not executed or automatically sent to the
provider. The current filesystem backend requires POSIX descriptor operations;
unsupported platforms refuse file operations. Files are separated by immutable
account ID and workspace ID. Model/skill/profile grants remain checked by the
server even if a client manually changes request fields.

### Read-only folder references

An administrator can let one account read another login's private folder
(`/<login>`) under **Assigned access → Boleh melihat folder (hanya-baca)**, via
the `grants` admin action's optional `references` list of account IDs, or with
`scripts/webui_access.py --admin administrator references alice bob`. Default is
no access; references are one-directional and never expose the target's
conversations, member-data files, grants or credentials.

- `GET /api/member/references` lists granted targets (`id`, `username`).
- `GET /api/member/reference/files?owner=<id>&path=<relative>` lists a folder.
- `GET /api/member/reference/file?owner=<id>&path=<relative>` returns base64
  content, 2 MiB limit.

Every request re-reads the live grant, so revocation applies to the next request.
Unknown and ungranted owners get the same 403. Absolute paths, `..`, NUL bytes,
symlinks at any component, dot entries (`.env`, `.ssh`, …) and common key files
are refused. These routes accept GET only; other methods get 405 when routed
here, and the server has no PUT/PATCH/DELETE member routes.

### Administrator read-only conversation view

Conversations are private to their owner: the ordinary list/read/send routes
only serve the authenticated owner's rows, for administrators too. As a
disclosed exception, an administrator with a live, enabled admin role in
**both** the login store and the policy may read other accounts' conversations
(the member UI does not show this notice yet; the API exposes the owner fields
below):

- `GET /api/member/admin/conversations` — metadata of every conversation (`id`,
  `owner_id`, `owner_username`, `created`, `own`). No message content; the title
  (derived from the first message) is included only for the caller's own rows.
- `GET /api/member/admin/conversation?id=<id>` — messages, `read_only: true`.

Each read of another account's conversation appends one row to
`member_admin_audit` (admin ID, owner ID, conversation ID, action `read`, time;
never message text or titles) in the same SQLite transaction as the admin check.
If the audit write or commit fails the request returns 503 and no content.
Listing metadata and reading one's own conversation are not audited. The
owner's `GET /api/member/conversation` response carries `admin_views` (count)
and `last_admin_view` (timestamp or `null`), not the administrator's identity.

Conversations of a disabled account are sealed: while the owner is disabled in
either the policy database or the login store, administrators can neither list
nor read them (same generic 403 as an unknown ID, nothing audited). They are
retained and become readable again once the account is re-enabled in both.

Roles are re-read on every request; disabling or demoting an administrator in
either store denies the next request. Non-administrators, non-GET methods,
unknown admin paths and unknown/malformed IDs all get the same generic 403.
There is no administrator send, continue, rename or delete path, and the owner
routes keep refusing an administrator's foreign conversation IDs.

The new interfaces keep private state in memory, without localStorage or offline
response caches. Logout clears the visible private state. Username/password login
clears legacy Hermes draft/session storage and shell caches before switching
accounts; service-worker shell caching is disabled in configured account mode.

## Persistence and admission

- The login JSON store owns passwords, immutable IDs and authentication generations.
- The SQLite policy database owns explicit grants and private conversation/message
  rows. Every list/read/send includes the authenticated owner ID and live grants.
- Files live under `member-data/files/<account-id>/<workspace-id>` beside the policy
  database by default. `HERMES_WEBUI_MEMBER_DATA_DIR` overrides this trusted root.
- The provider vault is `member-data/credentials.json`, outside member folders.
- One transactional lease admits a send per conversation. Failed generation does
  not append a partial turn. Policy changes during generation suppress the reply
  and message persistence; the lease is released on every exit.
- Managed HTTP inference uses only the selected granted connection and model,
  injects credentials service-side, ignores ambient proxy configuration, rejects
  redirects, and returns generic errors instead of upstream bodies. There is no
  ambient provider/credential fallback.

An upstream request already admitted before revocation may already have sent its
prompt; those bytes cannot be recalled. This synchronous mode does not promise
upstream cancellation. It rechecks authority before returning/persisting a reply.
Subscription/OAuth refresh, streaming, Agent tools, file-to-model attachments,
storage quotas and full platform compatibility remain outside this mode.

Back up the account store and marker, policy database and member-data together.
Production migration/deployment is separate from code development. Do not remove
account-mode markers or silently initialize over a broken database. Operator
access to the server and its backups remains trusted.

## Verification

Focused unit/integration tests use a synthetic local provider, isolated stores
and adversarial inputs. Real browser journeys exercise account creation, resource
and grant editing, login, private chat/files, account switching, foreign object
denial, CSRF rejection and disabling a logged-in account at desktop/narrow/mobile
widths. No real provider credentials or production state are required.

```bash
./scripts/test.sh -q tests/test_member_chat.py tests/test_account_admin.py
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
HERMES_WEBUI_BROWSER_TESTS=1 ./scripts/test.sh -q tests/test_member_browser.py
```
