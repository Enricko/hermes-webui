# Portable multi-user Hermes WebUI design

Status: implementation in progress on `feature/user-roles`. Account lifecycle and transactional policy foundation are implemented. Isolated execution, provider brokerage and full product integration remain release gates. No production deployment has been performed. See [implementation status](multi-user-implementation.md).

## Goal

Provide one shared WebUI service and login page for multiple users. Administrators control each user's permitted profiles, managed AI-provider connections, and workspaces. Users can share skills and SOUL without sharing private files, conversations, memories, credentials, or run controls.

## Approved requirements

- Keep one public WebUI/login. Isolated agent runtimes behind that service are permitted.
- Support deployment across Linux, macOS, Windows, and other environments capable of hosting Hermes, through a verified local container backend or a remote isolated runtime.
- Preserve multiple allowed profiles and multiple allowed workspaces. Do not reduce the feature to one profile or one workspace per user.
- Include subscription/OAuth providers in the initial release alongside API-key providers and approved local models. Do not silently substitute an API-key-only release.
- Enforce workspace privacy for agent commands, code, file tools, integrations, and WebUI file/Git operations, as well as for HTTP reads and UI choices.
- Administrators create and disable accounts and assign grants. Users cannot promote themselves, expand grants, or mutate shared connection/template configuration.
- Shared skills and SOUL are administrator-managed and read-only to user execution. Conversations, learned memory, uploads, preferences, databases, and runtime caches have private ownership.
- Include isolated Hermes Agent compatibility work when necessary. Never modify the operator's installed Hermes or real state during implementation trials.

## Boundaries

The shared service owns account authentication, authoritative access policy, the runtime registry, private-object metadata, and managed provider authorization. A trusted broker holds upstream credentials and OAuth refresh state. These trusted functions belong to the single deployment; they are not exposed as an unprotected administration API to runtimes.

An isolated runtime worker hosts AIAgent and performs workspace file, upload/download, Git, worktree, and tool execution inside the same enforced boundary. A separate ordinary process with the WebUI service's OS permissions is not containment. Runtime admission requires a verified container, VM, or equivalently isolated remote execution boundary and network policy.

The existing Gateway backend is not the default execution mechanism for this feature: the audited API lacks file/Git endpoints, per-run workspace selection, and clarification support. Reuse the WebUI runner request/client and lifecycle concepts, with explicit owner/grant authority and a worker server. Preserve the current streaming, cancellation, recovery, approval, and clarification contracts when wiring it in.

The shared service must not run Git or untrusted workspace subprocesses as its privileged identity. It must not directly open worker-local SQLite databases across a VM or remote-host boundary.

## Authoritative identities and policy

Use immutable user IDs, profile-template IDs, private user-profile-instance IDs, workspace IDs, connection IDs, grant IDs, session IDs, and run IDs. A username, profile label, provider label, URL, path prefix, or token string is not ownership evidence.

A managed connection binds one provider/auth adapter, trusted endpoint, protocol/transport, and a particular upstream account/tenant/project, or an explicitly managed set of account IDs. Accounts at the same provider and URL remain distinct connections. A credential refresh preserves account identity; replacing the account changes the connection-binding generation. Pool membership changes are authorization changes.

Authorize the complete selected user/profile-instance/workspace/connection/model/tool context before reading privileged configuration, mutating a session, persisting state, launching work, or forwarding a request. Request bodies, query parameters, signed profile cookies, model tags, fallbacks, saved sessions, and recovered state must all resolve through this rule. Denial is terminal and cannot trigger ambient credential fallback or workspace recovery success.

Use transactional policy and generation updates. Separate policy/account-binding revisions from secret rotation, so caches can survive a same-account refresh without retaining revoked authority. Policy storage failures in configured multi-user mode keep authentication and protected operations closed.

An "all current profiles" assignment expands to explicit grants when saved. Future profiles remain denied until explicitly granted. A shared workspace is accessible to multiple people only when the administrator intentionally grants it to them; sharing a profile never implicitly shares a workspace.

## Authentication and private-object ownership

Every WebUI authentication method enabled in multi-user mode must resolve to an account. AI-provider OAuth is distinct from WebUI login. No accountless legacy password, passkey, OIDC, or trusted-header path may bypass the user policy.

Sessions, projects, attachments, drafts, shares, journal entries, event subscriptions, run controls, cron jobs, queued work, and background tasks retain immutable owner metadata. Compression children, forks, imports, restart recovery, and cache eviction preserve or explicitly assign ownership server-side. Imported owner fields are untrusted. Existing unowned/CLI state remains administrator-owned until explicitly assigned.

Two users granted the same template still cannot list, read, export, mutate, subscribe to, steer, stop, approve, clarify, or attach the other's private objects. An object's owning session does not override a revoked workspace grant.

Browser caches and persisted drafts are owner-scoped. Logout and account changes clear or prevent hydration of another user's private state. Service-worker/offline caching must not expose authenticated responses from a previous account. Public sharing is a separate capability and is disabled for restricted users unless explicitly authorized.

User deletion/recreation and password resets invalidate previous login authority through immutable identity and an authentication generation. Disabling an account never grants anonymous access. Multi-user mode cannot become disabled because the account store is missing, empty, invalid, or temporarily unreadable.

## Worker and workspace contract

Workspace IDs identify a backend, target, and approved root. A user chooses a registered workspace ID rather than supplying an arbitrary host path. Target-side remote paths retain their native semantics; do not resolve them against the front-door host.

Workers receive sanitized, read-only configuration and shared templates, private writable state, the selected workspace, and scoped broker access. Do not use the current profile clone mechanism to copy `.env`, `auth.json`, CLI credential stores, or the trusted service's environment into a worker.

Worker identity, session ownership, grant selection, runtime endpoint, and lifecycle resources are chosen by the shared service. Worker-supplied identity fields cannot expand authority. Backend capabilities must include containment, admission, cancellation, event delivery, and workspace operations. Unknown or unsupported capabilities refuse restricted execution; there is no legacy-direct/host fallback.

Runtimes cannot reach the trusted administration plane, another user's runtime, host metadata/credential services, unrestricted Docker sockets, or other ungranted roots. Revocation uses a trusted supervisor and broker policy rather than relying only on an agent's cooperative cancellation flag.

## Provider broker and OAuth

Real provider API keys, refresh tokens, CLI credential stores, and administrative credentials stay outside user-controlled execution. A worker receives only revocable capabilities scoped to its user, profile instance, workspace grant, connection binding, session/run, allowed model/purpose, audience, and expiry. The broker derives authority from that capability and live policy, never from worker-supplied provider/account headers or endpoint URLs.

Adapters preserve native protocols and streaming for API-key/local connections and subscription/OAuth providers. Codex Responses and Anthropic OAuth are mandatory initial proof cases. Inventory and cover other supported Hermes subscription modes, including HTTP and external-process transports, without silently treating distinct transports as equivalent. Additional plugin transports require explicit verified capability support.

The broker supplies upstream authentication and account headers, strips attempted overrides, controls destinations and redirects, handles per-account refresh, and returns appropriately redacted errors. It cannot be a general-purpose URL proxy. Provider failures or revocation cannot cause a switch to an ungranted connection.

All managed AI calls use the same connection grant: main chat, retries, auxiliary models, vision, compression, titles, memory commits, delegation, fallback, MoA participants, discovery/quota operations, and scheduled/background work. Other secret-bearing vendor tools need an equally scoped connection path or must remain unavailable to restricted users until supported.

OAuth flow initiation, device polling/callbacks, cancellation, linking, refresh, and persistence are bound to the authorized initiator, target connection, issuer/redirect where applicable, and account-binding generation. Use single-flight refresh per account and compare-and-commit generation checks. A late callback or refresh cannot resurrect a removed, relinked, or revoked connection.

Provider grants govern application-managed connections. Blocking a user from independently contacting every external AI service from a general-purpose shell is a separate egress-policy question; runtime isolation must still block access to the host, other users, and trusted internal planes.

## Revocation and concurrency

At the authoritative revocation transaction, deny new admissions and revoke dependent scoped capabilities; cancel affected active execution and suppress further unauthorized output. Revalidate policy on every new managed outbound-call admission and privileged operation. A short token lifetime is not immediate revocation.

An already admitted upstream request may have sent bytes that cannot be recalled. Track its ownership and cancellation explicitly, cancel transport/execution where supported, and distinguish this limit from admitting a new request after revocation. Tests cover both admission/revocation orderings with deterministic barriers.

Do not switch profile homes, credentials, terminal configuration, or runtime endpoints through process-global environment mutation for concurrent users. Caches include the full owning identity and relevant binding/policy revisions, and cannot substitute for live authorization.

## Agent compatibility baseline

WebUI discovery baseline: `60475dd13`, which adds local accounts but contains no local-account regression tests and explicitly does not contain agent tools.

Candidate Agent baseline: `90c19e31968397a1d9bd1e9bb4f6d2c1d6f00be3`. This is a source-audited candidate, not a verified dependency upgrade. The older installed-source audit at `9aa7530f` must not be used to infer current behavior.

On the candidate, callable MiniMax credentials and host-independent Anthropic OAuth body identity are present. Native thinking-signature replay and fast-mode classification still need an explicit way to recognize an approved native-equivalent broker route. Preserve endpoint-specific reasoning policies for other providers as well. An explicit descriptor/hook carries semantic routing information, not access authority; the broker remains the authorization point.

Use a pinned compatible Agent release plus a reviewed compatibility extension when required. Do not rely on a broker URL containing a provider hostname, token-shape masquerading as authorization, or HTTPS interception. Prove native multi-turn thinking/tool fidelity and the existing WebUI import surface against the pin before broader integration.

## Validation and release gates

- Exercise two users with the same profile template and different workspaces and credentials, plus two connections at the same provider/URL.
- Deny foreign session/run/attachment IDs and foreign profile/provider/workspace body fields before side effects, including goal, cron, import, regeneration, recovery, and background paths.
- Test path traversal, symlink replacement, saved/revoked workspace bindings, file/Git/raw/download/upload operations, and full terminal/code/MCP attempts using synthetic private sentinel files.
- Prove secret absence from worker environments, files, mounts, process state, HTTP responses, errors, and logs, including native OAuth refresh and auxiliary/delegate/fallback paths.
- Use deterministic revoke/refresh/relink/cancel barriers; cover cached agents, reconnect, restart, and policy-store outage without fallback escape.
- Test desktop, narrow, and mobile login/admin/member flows with before/after evidence. Unauthorized choices are omitted in the UI and denied by the server.
- Run repository pytest through `./scripts/test.sh` with disposable state and synthetic credentials, then relevant neighboring tests. No real credentials or live services are authorized for trials.
- Run real containment checks on Linux and Docker Desktop on macOS/Windows, or verified remote-runtime configurations. Protocol fakes do not certify external provider behavior, and a single host does not certify all platforms.
- Keep multi-user mode default-off until the required identity, runtime, provider, migration, UI, and platform gates pass. Do not label an intermediate role-picker implementation secure or complete.

## Contract routing

Relevant contracts include `docs/CONTRACTS.md`, `docs/GUIDELINES.md`, `docs/remote-workspaces.md`, `docs/architecture/agent-api-contract.md`, `docs/architecture/send-path-model-provider.md`, `docs/architecture/models-cache-invalidation.md`, `docs/rfcs/hermes-run-adapter-contract.md`, the run/session SSE and state-consistency contracts, `DESIGN.md`, and `docs/UIUX-GUIDE.md`.

Implementation must name the authoritative policy, ownership, runtime, and event state layers, preserve lock/lifecycle invariants, update affected contracts and tests together, and document migration/rollback. Ordinary changes must not edit `CHANGELOG.md`. A PR must report actual commands, evidence, and unverified provider/platform behavior.
