# Multi-user baseline verification — 2026-11-06

The tested implementation is `57f2d9495adb6756b24e0bd37a4947e51e88c41e`.
Subsequent acceptance-harness/report commits do not change the runtime code.
The retained recovery commit is
`f37802bb1ae3ec2d6f4c236cb9a39132cfd13238`; its entire tracked tree matches
official upstream `master` at
`52e95f229405185288cedd7ef1b1ceb5fb1f3442` (empty tree diff).
Feature development preserves that history and leaves the single-user server
and original frontend source unchanged. No push, merge or live deployment is
part of this feature verification.

## Tested artifacts

| Component | Pinned artifact |
| --- | --- |
| Hermes Agent | `278aeffe16945e7b1405e3c471ad08553c059237` |
| Worker image | `sha256:b1c1d23dec7cbfd660f5c691f687a1293aa1b0b2b06ed60efebfad95e4279e04` |
| Relay image | `sha256:984c1f00da7f080f1a719938392edfbef319d0eff822659e612e0bdfd5e0133d` |
| Python base | `python:3.14-slim@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d` |
| Host test Python / SQLite | 3.13.18 / 3.53.1 |
| Container SQLite | Verified upstream 3.53.0 source and checksum |
| Docker Engine | 29.1.3, actual non-root/read-only/namespaced workers |

The build context comes from Git archive; no untracked files, local environment,
personal homes or runtime databases enter the image. The optional private host
SQLite builder was also exercised: the system interpreter loaded 3.53.0 from
the isolated prefix while its default system library remained 3.46.1.

## Results

| Check | Result |
| --- | --- |
| Official `./scripts/test.sh tests/` in five isolated shards | **26,796 passed**, 421 subtests passed, zero failures/errors |
| Existing optional/expected cases | 472 skipped, 1 xfailed, 3 xpassed |
| Explicit real Docker acceptance plus account/gateway/policy tests | **25 passed**, including all 6 Docker cases |
| Official `tests/browser_smoke.py` | Passed, zero console errors |
| Official `tests/browser_new_chat_focus.py` | Passed |
| Python compileall, forward Ruff gate, full Ruff on new modules | Passed |
| ESLint runtime guard and required scope/undefined-name guard | Passed |
| New systemd units | Static verification passed with the test checkout substituted for the installation path; units were not installed/started |

The full suite retains its upstream skips and expected outcomes. Docker tests
are skipped by default and were run explicitly in the separate acceptance gate.
The host test interpreter intentionally has no real Agent installation; actual
WebUI/Agent compatibility was proved inside the pinned worker images instead.

The first broad run had a missing Chromium cache path in its isolated HOME,
causing cascading Playwright/event-loop failures. The corrected **entire**
five-shard run passed. Checks were not disabled. The deterministic model fixture
was also corrected to satisfy the real Agent's minimum 64K context requirement.

## What the acceptance proves

- Three distinct local credentials and server-enforced admin/user roles.
  Password hashes, session expiry/logout, password/role reset revocation,
  disabled-account rejection, persistent login budgets and concurrent last-admin
  protection are exercised with real libraries and private SQLite databases.
- The authenticated account chooses the backend Unix socket. Profile cookies,
  forged identity/admin headers, guessed resource IDs, file paths, exports,
  downloads and streaming/cancel requests cannot select another worker.
  Upstream's idempotent unknown-stream cancel returns `cancelled: false` to A;
  B can still cancel its own live stream successfully.
- Real file and terminal tools read/write their own workspace successfully,
  then fail to reach B's storage and a host canary. The host/B contents remain
  unchanged. Runtime probes confirm the non-root UID, absent Docker/control
  socket and denied direct Internet connection. Broker policy tests deny private,
  metadata and mixed public/private DNS answers and provider-stored resource IDs.
- File API traversal, out-of-workspace absolute paths, symlink escape and ZIP
  extraction traversal are rejected without changing the configuration canary.
  Trusted seeding separately rejects symlink parents, non-regular destinations
  and tampered persisted template/tool paths.
- A and B concurrently invoke the real Agent's terminal tool to run the same
  published converter, with `same.png` and `same.jpg` in each private workspace.
  Output pixel colors remain distinct. Both scripts have the same inode and
  cannot be rewritten or unlinked by the runtime user.
- Real conversation history, memory and workspace files survive worker restart.
  Disabling A revokes its browser session and stops its container/background
  processes while B's heartbeat keeps advancing. Re-enabling A preserves data.
- Template updates preserve private edits/deletions and learned skills. Explicit
  conflict resolution retains personal bytes. Migration creates a protected
  archive first and shares only selected capability fields/SOUL/skill text;
  private conversations, memory and credentials stay out of the template.
- The gateway serves trusted upstream assets, rejects worker script/service-worker
  responses and unsafe origins/CSRF, and closes revoked proxy streams without
  closing B's stream. The browser sees matching frontend version/auth metadata.

Only the **external model API** is deterministic protocol test data. The Agent,
WebUI, tools, HTTP/SSE, filesystem operations, containers and restarts are real.
No paid provider, existing personal conversation or live credentials are used.
Actual third-party OAuth/stateful-provider interoperability is not claimed.

## UI evidence and practical limits

The browser harness checks desktop (1440), narrow (760) and mobile (390) widths:
local login/logout, active identity, admin account creation/disablement and all
capability-management tabs. The regular-user flow sends a real chat, receives
streamed output, stages/uploads an attachment on Send and receives its reply,
while another account's conversation remains absent. Screenshot and JSON/error
evidence are produced in the operator-selected evidence directory. A separate
disposable server using the original upstream tree supplies before screenshots;
the harness also labels a visual reference with only the additive account bar
hidden. The normal chat UI remains upstream.

The reproducible commands and operational rollback are in
[the runbook](multiuser.md). Persistent installation accounts/provider keys and
TLS cutover are deliberate operator steps; the existing service was not switched
by feature development. Shared model access currently requires a stateless
OpenAI-compatible endpoint. External memory/browser/MCP credentials are not
imported from the main account and need an independently reviewed per-user
namespace. Account disk/billing quotas are not implemented. Existing external
scripts require an explicitly selected reviewed source file for publishing;
the bundled converter and both publishing mechanisms are implemented.

## Portable installed-profile discovery — 2026-11-07

This additional gate exercises the trusted `setup`, `connect-hermes` and
`sync-profiles` flow. It uses the later verified worker image
`sha256:2ad401659e258e14a5d0e203689258b5c440bf390d2b42fec730dde28e051858`
and relay image
`sha256:fa6c499a140f2073ca88ec936a26e542192d83c832c8086d30e5b685f4b17cc0`,
with the same pinned Agent revision. Discovery/UI changes run in the trusted
host control plane and do not require rebuilding those worker images.

- The official test runner passed **48 tests** across account, discovery,
  gateway, broker, catalog, connection, policy and neighboring profile suites;
  **11 optional Agent-dependent neighboring cases skipped** in the sanitized
  no-Agent host environment.
- **9 real Docker tests passed**, including main/named source discovery,
  explicit adoption of an existing template identity, unchanged-sync stability,
  real chat after named-profile assignment, private workspace preservation and
  exclusion of the original profile's private state. Existing direct API,
  namespace, shared converter, streams/cancel and restart acceptance still pass.
- **2 real root CLI setup tests passed** with synthetic homes/passwords and
  data roots under `/tmp` and `/srv`. Skill bundles publish atomically on the
  destination filesystem, including hosts with `/tmp` on another filesystem. Fresh
  setup imports main/named profiles and assigns the first administrator;
  rerunning retains the same template IDs and original login password.
- Native Chromium passed at **1440, 760 and 390 px** with no uncaught JavaScript
  errors or HTTP failures. Evidence includes the discovered-profile catalog,
  account creation with an explicit profile, independent provider assignment,
  regular-user streamed chat/upload and account-switch storage isolation.
- Ruff, runtime JavaScript lint, syntax checks and whitespace checks passed.

The profile unit suite also covers native provider mapping identity and legacy
precedence, profile-local credential resolution, keyless localhost, unsupported
OAuth profiles remaining visible, source/config symlinks, unavailable sources,
new/deleted profiles, admin conflicts and explicit conflict resolution. The
gateway rejects source-path/import POSTs even from an administrator; only the
trusted operator can register source authority.

The deterministic external model fixture remains separate from the real Agent,
WebUI and containers. These results do not claim automatic migration of native
OAuth providers, stateful external integrations, or personal historical data.

## Independent access lists and checkbox editor — 2026-11-07

- **50 host tests passed**, covering account/auth, independent grants, gateway,
  broker, catalog, discovery, policy and connection imports. Schema v4 migration
  retains legacy accounts and inherited connections until explicitly saved.
- **10 real Docker tests passed**. The added gate configures A with profiles A+B
  and provider A, and B with profile A and providers A+B. It executes actual
  broker requests from both workers, rejects A's direct provider-B route, switches
  A to its other assigned profile without losing workspace data, performs real
  Agent inference using B's second provider, and proves immediate revocation
  against B's old worker before reconciliation.
- **2 real root setup tests passed**, using new `/tmp` and `/srv` data roots.
- Chromium passed at **1440, 760 and 390 px** with no uncaught JavaScript or HTTP
  errors. It creates/edits both assignment patterns using checkboxes, chooses
  defaults without unchecking other grants, searches accounts, disables/enables
  an account, verifies chat/uploads/account isolation and activates an assigned
  profile through the user's real switcher. The initiating browser remains
  signed in after the worker restart, and its saved workspace canary survives.
- HTTP regressions reject forged identity/grant fields and unassigned choices.
  Active streams from an older account generation close even when the initiating
  browser's session token is retained; another user's stream continues.
- Ruff, runtime JavaScript lint, JavaScript syntax and whitespace checks pass.

Before/after screenshots and JSON results are stored in the operator-selected
evidence directory. The user-facing controls remain native HTML with the
existing Hermes theme; no frontend framework or additional dependency is used.

## Assigned profiles in native navigation — 2026-11-07

An account with two granted profiles previously saw only its worker's local
`default` profile in the native Profiles panel. The new HTTP regression fails
against the previous gateway and passes with the authenticated assigned catalog.
It also verifies that worker-supplied account IDs/catalog entries are overwritten,
and an account granted one profile receives only that profile.

**104 focused host tests passed**, covering gateway/access, account/broker/catalog
behavior, assigned-menu lifecycle and neighboring native profile/dropdown,
recovery and workspace-copy behavior. JavaScript lifecycle coverage verifies
that metadata refresh keeps an open drawer open, while an actual click/keyboard
selection closes it; active statistics come from the worker and inactive
profiles do not invent counts.

The real WebUI/Agent Docker browser harness passed at **1440, 760 and 390 px**:
two admin-assigned profiles appear in the native panel and composer menu;
selecting an inactive profile reveals Activate and preselects its granted ID;
shared-profile deletion is unavailable; regular-user activation through the
primary Profiles panel completes a real runtime restart without another login
or losing a saved workspace file. The active badge follows the selected account
profile, and the second user's catalog remains restricted. Existing chat,
stream/upload and account-switch checks pass with no browser or HTTP errors.

The native filesystem profile list remains separate for session/file/cron
callers. This change adds no schema migration, dependency or worker image, and
does not copy or alter original Hermes profile data or account grants.

## Immediate assigned menus and one-click activation — 2026-11-07

Assigned profiles now populate directly from the authenticated identity catalog,
including after a late native render replaces the menu with only its physical
`default` row. A click or keyboard activation opens an inactive assigned profile
with the current allowed provider, without the separate selection dialog. The
optional provider picker remains available. Account assets use the release
fingerprint so a fresh page loads matching native and account controls.

**108 focused host tests passed.** New frontend regressions cover keeping an
independently assigned provider, allowed fallback choices, missing providers,
duplicate clicks and refreshed revocation. All four new activation cases fail
against the previous client and pass with the change. HTTP checks verify that
the served account asset URLs carry the release version and support immutable
caching only for that version. Existing authorization, generation/stream,
broker, account/catalog and neighboring native profile tests remain green.

The real Docker WebUI/Agent browser harness passed at **1440, 760 and 390 px**
with no uncaught JavaScript or HTTP errors. It verifies automatic menu recovery
after a simulated late default-only render, both assigned menu locations,
single-click regular-user activation, preservation of its chosen provider and
login, and a saved workspace canary surviving the runtime replacement. Another
user still receives only its own profile. Chat, streaming, attachments, account
management and same-browser user switching continue to pass. Screenshots and
the JSON acceptance report are saved in the operator's evidence directory.

No schema, dependencies, runtime images or account grants change in this update.
Switching a profile still reconciles the account's isolated agent; it does not
run multiple capability profiles inside a shared process.

## Native profile switching without workspace restart — 2026-11-07

Ordinary profile switches now reuse the account's existing isolated runtime and
upstream's guarded in-page transition. All granted profiles are prepared by the
trusted operator; their configurations, model routes, skills and scheduler homes
are distinct. Existing account root history/memory stays in place. The WebUI
process has no global `HERMES_CONFIG_PATH` pinning it to the default profile;
each separate scheduler receives its own fixed configuration at process start.

**220 host checks passed**, with 10 reported skips: two explicit operator setup
gates and eight tests needing Agent modules absent from the isolated host test
environment. All **10 real Docker acceptance tests passed** against the pinned
official Agent. They cover credentials/roles, model/provider routing, private
file/terminal/network boundaries, concurrent read-only converter execution,
stream/cancel ownership, restart persistence, disablement, discovered profiles,
and independent grants. A stream survives switching away: querying/controlling
it from the wrong profile is still refused with the native 409 response;
switching back exposes the same live stream for its rightful owner to cancel.
Actual scheduler processes prove separate fixed Hermes homes.

Chromium passed at **1440, 760 and 390 px**, with no JavaScript or HTTP errors.
Six switches in both directions took **0.109–0.619 seconds** in the disposable
installation. A document sentinel, browser preference canary, container ID and
account generation remain unchanged through every switch. Regular-user chat
after activation reaches the actual Agent with the destination profile's
distinct temperature policy. The previous client fails the new no-navigation/
no-storage-reset regression. Other chat/upload/account checks remain green.

Gateway checks also reject forged/double-encoded profile cookies, direct
unassigned selectors and disabled capabilities before old mounts are replaced;
revoked native capability directories are hidden from the visible catalog while
their private files remain preserved. Legacy clients retain their selection
protocol until a fresh page loads the native-switch controls. No control schema
or Agent dependency/version change is required; the new immutable runtime image
adds the per-profile schedulers and removes the WebUI's global config override.
Admin grant/credential changes and changing the account default provider remain
separate reconciliation operations.
