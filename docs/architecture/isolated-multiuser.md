# Isolated multi-user deployment contract

This is an opt-in deployment alongside the original single-user launcher. It
does not reinterpret profiles or terminal.cwd as security boundaries.

The account gateway owns stable random user IDs, Argon2id passwords, opaque
expiring sessions, CSRF, account roles, and routing. Each account gets an entire
upstream WebUI plus Agent process in its own non-root Docker container. No
request changes a shared Agent process's environment or cwd. Every private API,
stream, file, terminal and background job runs in the selected account's
filesystem/process namespace. Resource IDs and profile cookies cannot select
another account's runtime. The authenticated server session is the routing owner.

Each user has a separate relay container with a network namespace containing
only loopback. The Agent shares that network namespace, not its process or mount
namespace. The Agent mounts only its own Hermes home, workspace, temp and
approved read-only tool bundle. It has no host network, Docker socket, relay
socket directory, control database, other user's mount, or provider credentials.
The trusted relay exposes the WebUI to the host gateway over a private Unix
socket and forwards model/network requests to a separate per-user broker socket.
Provisioning belongs to a host CLI/reconciler with an explicit local Docker
socket. Browser/Agent input never supplies Docker arguments, mounts or images.

The gateway serves the upstream frontend from trusted source, not from a worker
that an Agent could impersonate. Worker-controlled executable frontend assets,
extensions and public sharing are not forwarded. Browser sessions are cleared
at account changes; service-worker behavior is constrained at the gateway.
Provider credentials remain in the private control plane. Templates copy only
explicit model/response configuration, SOUL and selected skill files. They do
not copy USER.md, conversations, memory, cookies, OAuth or account credentials.
External stateful integrations need independent per-user namespaces and keys;
they are not silently enabled by copying the main account's config.

Accounts may reuse one existing capability profile with independent provider
assignments. The account database owns each optional provider override. Assignment
changes revoke sessions and replace only the affected runtime. A trusted root
operator snapshots reusable skills, excluding credentials and personal state;
the immutable bundle is mounted read-only at `/shared/skills`. Hermes's official
`skills.external_dirs` loads these alongside private learned skills. Capability
reuse updates the existing template in place without importing private history.

An admin may explicitly grant several base profiles and an independent list of
providers to each account. Schema v4 stores these grants separately from the
active profile/provider selection. The worker receives only its account's
allowed provider routes, and the same grants authorize every broker request;
removing a provider denies an old worker's URL before container reconciliation.
Provider-owned model metadata may supply that provider's default model, but
another profile's instructions, skills and private state never supply account
capabilities. Existing accounts retain inherited single-profile behavior until
an admin explicitly saves an access list.

The trusted provisioner materializes every granted capability as a native private
profile in the account's one isolated runtime. Operator-owned `profiles.json`,
outside worker mounts, maps capability IDs to native names and the account's
credential generation. The existing root home remains attached to its original
capability: provisioning another profile never retags or copies its history,
USER.md or memory. New profiles receive only sanitized capability configuration,
SOUL and skills. Their private state stays under that account's own home.

Ordinary profile activation validates current grants and uses upstream's
cookie/request-local `/api/profile/switch`. It does not change the account
generation, restart containers, clear browser storage or revoke other sessions.
Existing streams/jobs retain their original profile. Each provisioned profile
gets an official scheduler process with its own fixed home/environment. Gateway
checks reserved profile names against authenticated grants; a cookie is never
account identity. Stale operator mappings close proxy admission until reconciled.
Admin credential/grant changes and changing the account default provider still
revoke sessions/reconcile the runtime; these are separate from browsing profiles.
The legacy selection path retains only its initiating session with unchanged
expiry/CSRF. Concurrent revocation cannot be undone by a stale selection.

The native Profiles panel and profile menu use the same authenticated assigned
catalog as the account switcher. `/api/profiles` keeps its worker filesystem
`profiles` list unchanged for sessions, files and cron, and adds a separate
`account_profiles` list containing only server-authorized IDs and labels. Worker
responses cannot supply that account catalog. Assigned-profile activation uses
the gateway selection endpoint, never a template ID as a filesystem profile
name or identity cookie. Shared assigned profiles have no native delete action;
personal subprofiles remain separate. The active assigned profile's detail uses
actual worker skill counts for each prepared profile.

All assigned profiles are visible immediately from the gateway identity catalog,
including after late native menu rendering. Clicking a profile activates it
directly with the current allowed provider; an unavailable provider falls back
only within the account's current grants. The optional profile/provider dialog
is not an activation prerequisite. Gateway account assets carry the same release
fingerprint as native assets to avoid mixing cached UI revisions.

Model access may use an explicit allowlist (the compatibility default) or the
live catalog of the account's assigned provider. In provider-catalog mode the
same validated, bounded catalog authorizes inference and feeds discovery.
Cache authority includes account generation, provider/credential identity and
policy; a response fetched under an old assignment cannot authorize a new one.
Provider failures fail closed without forwarding provider error text or keys.

A profile may also authorize named provider connections. Their worker-side
OpenAI-compatible URLs use fixed per-account broker paths containing opaque
connection IDs, never external URLs or real keys. The broker checks the ID
against the authenticated account's effective profile before resolving a server
endpoint. Same-named models remain distinct by provider. Catalog caches are
separate for each account/connection; removing a connection rejects late catalog
responses and closes its active inference streams. Per-account primary-provider
selection remains independent and uses a named connection's own default model.
Prepared profiles additionally bind their own capability ID into every model
route. The broker revalidates both profile and provider grants and applies that
profile's parameters/catalog policy; changing the browser's active profile
cannot reroute another profile's ongoing inference. Catalog authority includes
the full capability policy and profile scope, including on late responses.

Authorities and lifecycle invariants:

- The control database is authoritative for role, enablement, session expiry,
  credential generation and capability template. Account updates revoke all
  sessions transactionally; the last enabled admin cannot be removed.
- Gateway proxy streams regularly revalidate their authenticated session and
  close on revocation. The trusted reconciler stops disabled account containers
  and restarts a changed credential generation without deleting persistent state.
- A runtime is admitted only after actual container image, mounts, IDs,
  non-root/capability/read-only restrictions and liveness checks match policy.
- Shared tools are versioned once and mounted read-only. Work happens under each
  user's workspace/tmp. Template updates preserve personally modified files and
  report conflicts; they never overwrite memory or learned skills.
- No existing single-user home is adopted merely by starting the gateway.
  Operator `setup`/`connect-hermes` explicitly registers a source in a private
  root-owned registry outside gateway-writable storage. Main and named profiles
  become assignable sanitized capabilities; personal state is never migrated.
  A separate optional root oneshot sync has read-only source access, no network
  or Docker access, and publishes only schema-validated capability/provider data.
  The DB discovery catalog is presentation, never host-path authority. Stable
  template/provider identities survive ordinary syncs; unchanged publications
  leave runtime generations intact. Admin changes conflict rather than being
  overwritten. Missing sources preserve accounts and runtime state.

Acceptance evidence must include actual Docker filesystem/process tests,
real HTTP/API ownership and concurrent streaming/cancellation, persistence after
restart, and simultaneous execution of the same converter. Mocks alone do not
establish this boundary. Missing runtime support is a reported validation limit.
