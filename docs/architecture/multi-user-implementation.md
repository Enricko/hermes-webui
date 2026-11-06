# Multi-user implementation status

The requested integration preserves the **original Hermes WebUI and Agent
backend**. Username/password accounts and the account/grant editor are added to
the existing Control Center under **Settings → System → Users & access**. The
editor uses the existing theme and does not replace chat, composer, session or
workspace components. `/admin/users` returns to the main application when the
experimental member-chat flag is off.

The earlier [separate tool-free chat UI](../multi-user-chat.md) was an incorrect
substitution for this request. It remains an explicitly enabled experiment for
development/regressions, not the staging/default interface or the target product.
The [approved full Agent design](multi-user-access-design.md) remains unfinished:
private member Agent runtimes and subscription/OAuth brokerage are not complete.
Only administrator operation through the original backend is currently usable;
restricted member execution remains denied rather than claiming isolation.

Private workspace names follow the login username, independently of selected
Hermes profiles. Existing Hermes profiles can now be imported as selectable
templates; installed tool grants and a separately verified Linux containment
primitive are implemented. See [username workspace boundaries](username-workspaces.md)
for actual guarantees and the remaining worker integration.

## Implemented foundation

- Account mode stays enabled when its store is empty, corrupt, inaccessible or
  missing after use. `users.json.required` persists this state. Explicit
  `HERMES_WEBUI_USERS_FILE` enables account mode even before store creation.
- Every login path must resolve to a local account in account mode. Accountless
  shared-password, passkey, OIDC and header sessions cannot bypass policy.
  Single-user deployments without an account store keep upstream behavior.
  Linking other authentication methods to accounts remains future work.
- Server-side local sessions bind account ID, password, role, profile and auth
  generation. Resetting passwords, changing role/profile, disabling, deleting or
  recreating accounts invalidates authority. Old unbound local cookies require
  a fresh login after upgrading. The account CLI assigns IDs and supports
  `disable`/`enable`; reactivation cannot resurrect old cookies.
- `api/access_policy.py` owns transactional SQLite policy: explicit grants for
  profile templates, workspaces, connections with model allowlists, and skills.
  Accounts sharing a template receive distinct private profile-instance IDs.
  Multiple profile/workspace grants are supported; future resources are denied.
- Connection binding changes advance generation. Policy changes invalidate old
  admissions, including revoke/regrant. Credentials belong in the future trusted
  broker and are rejected from policy binding fields.
- Private-object registration binds owner, profile and workspace. Foreign IDs
  and revoked workspace grants cannot authorize reads or overwrites. These
  helpers are tested but **not yet wired into every object producer**.
- Opt-in `/api/admin/access` GET/POST administers policy through existing account
  authentication and the normal POST CSRF gate. `/api/access/me` returns only
  the caller's granted catalog, excluding trusted path/connection bindings.
- Administrator-granted read-only folder references (`reference_grants` table,
  created on demand so older policy databases still open) let one account read
  another login's private folder through the member API. Self, unknown and
  disabled targets are refused; grant/revoke advance the policy revision. The
  catalog exposes only target IDs and usernames. Worker mounts (`/referensi/*`)
  and the main WebUI file browser are not wired yet. See
  [member chat](../multi-user-chat.md#read-only-folder-references).
- Member-chat conversations stay private to their owner. A live administrator
  may list conversation metadata and read another account's conversation
  read-only; each such read appends a content-free `member_admin_audit` row in
  the same transaction (audit failure denies the read), and the owner's read
  shows the view count and last view time. Main-UI `Session` ownership is not
  wired yet. See
  [member chat](../multi-user-chat.md#administrator-read-only-conversation-view).

Authoritative state: the login account store owns identities/auth generations;
the server-side session store owns bound login proof; SQLite owns grants,
connection generations and private-object owners. A policy admission is a
decision snapshot, **not a bearer capability or proof of runtime containment**.
Supervisors/brokers must revalidate live authority at admission and cancel
dependent execution/capabilities on revocation. A policy revision conservatively
invalidates every earlier admission. Secret rotation must happen outside policy
metadata so it cannot change account binding accidentally.

## Member execution gate

The old role patch executed agent tools in the shared service's privileged
process. Endpoint/path filters cannot prevent terminal, Python or MCP tools from
opening another user's files or host credentials.

Legacy member API execution remains denied. The opt-in `/api/member/` namespace
implements tool-free chat and private file operations without importing AIAgent
or forwarding to legacy execution routes. `runtime_ready` stays false because
Agent execution is unavailable; the member catalog separately reports
`chat_available` and `tools_available`. The dedicated `serve_members.py` server
denies legacy execution for administrators as well. See the linked operational
guide for implemented workflows, provider limits and regression evidence.

## Disposable policy administration

Trials require isolated `HERMES_HOME`, `HERMES_WEBUI_STATE_DIR`,
`HERMES_WEBUI_USERS_FILE` and synthetic login/provider credentials. The account
CLI prompts for passwords. Do not copy real homes or credentials into workers.

```bash
python scripts/webui_users.py add administrator --role admin
python scripts/webui_users.py add alice --role user --profile alice --workspace /srv/alice
export HERMES_WEBUI_ACCESS_POLICY_FILE=/path/to/private/access.sqlite
python scripts/webui_access.py --admin administrator init
python scripts/webui_access.py --admin administrator account alice
python scripts/webui_access.py --admin administrator resource resource.json
python scripts/webui_access.py --admin administrator grants alice grants.json
```

A resource file contains `id`, `kind` (`profile`, `workspace`, `connection`, or
`skill`), `label`, and a non-secret `binding` object. IDs are explicit immutable
identifiers, not usernames, paths or provider URL identity. A grants file maps
resource IDs to arrays: connections require explicit model names; other kinds
use empty arrays. Register resources before assigning grants. The API accepts
equivalent `resource`, `account` and `grants` actions. Account registration
resolves the login identity and role from the local store; a body cannot invent
or promote an account.

Initialization refuses existing databases, including corrupt ones. Missing or
unreadable policy returns an error rather than creating empty authority.
Removing all login accounts does not disable account mode; recover by creating
an administrator through the CLI. Never remove the `.required` marker as an
error-recovery shortcut.

## Remaining release gates

1. Verified isolated workers/supervisor, private homes and workspace/file/Git
   operations inside the enforced containment boundary.
2. Trusted provider broker, scoped revocable capabilities, native OAuth and
   subscription refresh, auxiliary calls and Agent compatibility proof.
3. Wire policy and ownership into every session/project/upload/run/event/control/
   recovery/cron path while preserving the existing runtime contracts.
4. Member identity/runtime integration throughout the preserved upstream UI,
   including Agent events, controls and account-scoped browser state. Account
   administration itself is already embedded in the existing System settings.
5. Migration/rollback, adversarial containment, live provider evidence,
   responsive browser journeys and platform verification.

Current tests prove account/policy behavior and tool-free member/admin browser
journeys against synthetic state and a local synthetic provider. They do not
certify Agent runtime containment, native subscription/OAuth fidelity, full Agent
object ownership integration or live external-provider behavior.

## Migration and rollback

Develop in a separate checkout without production state. Before eventual
migration, back up code and state. Rollback must restore compatible login/session
state as well as code: reverting code alone could restore permissive accountless
paths. Keep account-mode markers and policy databases during administration.
