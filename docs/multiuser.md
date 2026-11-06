# Opt-in isolated multi-user Hermes

This deployment retains the upstream Python/vanilla-JavaScript WebUI and runs
the **whole WebUI and real Hermes Agent separately for each account**. The
original `bootstrap.py` single-user mode is unchanged. Profiles remain personal
subprofiles inside one account; they never identify a tenant.

The host gateway provides local Argon2id accounts, admin/user roles, opaque
HttpOnly/SameSite=Strict sessions (eight hours by default), logout, persistent
login throttling, same-origin checks and session-bound CSRF. Password resets,
role/template changes and disablement revoke all account sessions immediately.
Streaming connections revalidate sessions every half second. The reconciler
also stops/recreates that account's processes on credential-generation changes.
The last enabled administrator cannot be disabled or demoted.
HTTPS sessions use a `__Host-` cookie, preventing a sibling subdomain from
injecting a parent-domain session cookie. Loopback HTTP trials use a separate
cookie name.

Read the [authority and containment contract](architecture/isolated-multiuser.md)
before changing this deployment. No existing home, `.env`, conversation database,
memory, skills, upload, workspace or Docker volume is automatically adopted.

## Requirements and compatibility

- Linux Docker Engine, default seccomp, cgroup resource limits, and root access
  for the **trusted operator CLI only**. The gateway account must not join the
  `docker` group. The Agent receives neither Docker access nor host networking.
- A root-owned source release at `/opt/hermes-multiuser`, a dedicated gateway
  UID/GID (default 10000), worker UID 10001 and relay UID 10002. Reserve distinct
  unused numbers; workers and relays do not need host login accounts. Do not
  change these numbers after creating data without an explicit ownership migration.
- A short dedicated data root, normally `/srv/hermes`, sufficient disk space,
  and approximately 2 GiB RAM/one CPU limit per active account. Accounts with an
  assigned template get a worker and a small relay; this is intentionally not
  one shared Python Agent process.
- The tested/pinned Agent revision is
  `278aeffe16945e7b1405e3c471ad08553c059237`, with Python 3.14 in workers. It
  requires a model context window of at least 64,000 tokens. Host repository
  tests use the official Python 3.11–3.13 runner. The gateway needs SQLite
  **3.51.3 or newer** for the upstream WAL-reset fix; startup rejects older
  versions. Worker images build verified SQLite 3.53.0 as upstream does.
- Shared model access currently uses **stateless OpenAI-compatible API-key
  endpoints**, including a private local compatible server. Existing OAuth
  logins are not copied or converted to API keys. Select a compatible endpoint
  explicitly; an Anthropic-native or OAuth-only endpoint needs its own compatible
  adapter. The broker rejects provider-side stored response/file/vector/container
  references and hosted stateful tools. Real provider keys stay in the gateway.

No browser or Agent can provision containers. A root operator selects immutable
image IDs; the reconciler creates containers, verifies the actual namespace,
mount, UID, security and resource policy **before starting them**, and admits
the worker only after real Agent imports pass its upstream health check.

## Install an independent release

These are deployment commands for a new installation, not authorization to
replace a running service. Build images from a reviewed **committed** feature
release. The build script archives Git HEAD, excluding `.env`, `.venv`, untracked
files and runtime state. It fetches the pinned public Agent revision and uses
its supported editable installation; it does not modify an existing Agent.

```bash
cd /opt/hermes-multiuser
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-multiuser.txt
.venv/bin/python -c 'import sqlite3; assert sqlite3.sqlite_version_info >= (3,51,3)'
.venv/bin/python scripts/build_multiuser_images.py --output /var/tmp/hermes-images.json

# Check these IDs are unused on your host before reserving them.
sudo groupadd --gid 10000 hermes-gateway
sudo useradd --uid 10000 --gid hermes-gateway --system --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin hermes-gateway
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes init \
  --public-url https://hermes.example.com --images /var/tmp/hermes-images.json
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes bootstrap-admin \
  --username administrator
```

The bootstrap command prompts twice; there is no source/default password, and
passwords are never argv or log output. `--password-stdin` is available for an
operator's secret manager. Bootstrap works only on an installation with no
accounts. Keep the release and virtualenv root-owned and unwritable by the
gateway or workers. The settings file is root-owned; the gateway may write only
its private control database and its broker sockets.

If the host interpreter's SQLite is older, keep system libraries intact and use
`scripts/build_multiuser_sqlite.py --output /opt/hermes-multiuser/sqlite` to build
the same verified upstream SQLite into a new private prefix (requires a C
compiler and make). Set `LD_LIBRARY_PATH=/opt/hermes-multiuser/sqlite/lib` for
both the gateway **and every operator CLI invocation**, and in the service
environment file, then rerun the version assertion. Never turn off the check.
Since `sudo` strips loader variables, an explicit trusted invocation is
`sudo env LD_LIBRARY_PATH=/opt/hermes-multiuser/sqlite/lib .venv/bin/python -m
multiuser.manage --root /srv/hermes list-users`.

For an independent localhost trial initialize a **new short root** with
`--public-url http://127.0.0.1:8799`. HTTP cookies are allowed only on true
loopback trials. Start the gateway with its dedicated account and the reconciler
with root in separate terminals:

```bash
sudo -u hermes-gateway .venv/bin/python -m multiuser.gateway --root /srv/hermes
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes reconcile --watch
```

For persistent operation, review and copy
[`multiuser.env.example`](../multiuser/deployment/multiuser.env.example),
[`hermes-accounts.service`](../multiuser/deployment/hermes-accounts.service),
[`hermes-provisioner.service`](../multiuser/deployment/hermes-provisioner.service)
and the [TLS proxy example](../multiuser/deployment/Caddyfile.example). Adjust
both units' `ReadWritePaths` if changing the data root, and match the configured
UIDs. Install the environment file as `/etc/hermes-multiuser.env`, mode 0640,
root-owned. Install units under `/etc/systemd/system`, then run
`systemctl daemon-reload` and `systemctl enable --now hermes-accounts
hermes-provisioner` only when intentionally enabling this new service.

The gateway listens only on loopback. Route just this listener through TLS;
workers publish no TCP ports. Set the proxy Host to the exact configured public
origin. Client `X-User-Id`, `X-Forwarded-User`, forwarded IP and profile headers
have no identity authority. Login limits use the actual peer; behind a proxy
the peer budget is intentionally shared, rather than trusting spoofable headers.
Disable proxy buffering/timeouts that cut long SSE responses. Do not expose
worker ports or the Unix socket directories to browsers.

## Accounts, capabilities and shared scripts

Sign in as administrator and open **Accounts** in the sidebar, or
`/multiuser/admin`. Its tabs manage accounts, write-only provider keys, explicit
capability templates and versioned shared scripts. Create A and B with different
passwords, assign the same template, and wait for their runtime state to become
`ready`. They then retain ordinary chat, streaming, uploads and file browsing in
their own containers. Users cannot use admin APIs or global provider/secrets
settings, regardless of visible controls.

An assigned capability template automatically provisions the user's private
workspace, file storage, conversation database and tools; these do not require
separate feature assignments. On the first sign-in, a preparing page waits for
the runtime and opens chat automatically. An unassigned account instead shows
an explicit template-assignment message. Admin account management remains
available while the admin's own runtime is preparing.

Account discovery retries temporary permission/socket failures during trusted
directory creation, without interrupting existing account brokers. `/health`
reports `account_discovery: running`; if its discovery task stops it returns
HTTP 503 instead of a misleading healthy result. Login password verification
does not wait for container provisioning, and sign-in displays its current
stage while preserving the browser-data cleanup between identities.

Sign-in clears DOM storage, IndexedDB, CacheStorage and service-worker state.
It preserves the HTTP cache of trusted public assets: the browser specification
notes that an [origin-wide network-cache scan can be expensive](https://w3c.github.io/webappsec-clear-site-data/#cache).
Private API responses, files, settings and rendered account pages always use
`Cache-Control: no-store`, including when a worker tries to enable caching.
Logout retains the full cache/storage reset. Trusted source assets support gzip
and ETag validation; immutable caching is used only for the running asset version
and an unchanged source-file signature. No private worker data enters that cache.

CLI equivalents (all from the release directory):

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes put-provider \
  --name 'Shared model endpoint' --base-url https://api.openai.com/v1
# Enter the key interactively; note the returned non-secret provider ID.
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes publish-tool \
  --name 'PNG to JPEG' --source /srv/hermes/shared/tools/png_to_jpg.py \
  --description 'Use python /shared/tools/png_to_jpg.py --input /workspace/input.png --output /workspace/output.jpg --tmp-dir /tmp before recreating a converter.'
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes put-template \
  --name 'Base Hermes' --file /root/reviewed-capabilities.json
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes create-user \
  --username alice --template TEMPLATE_ID
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes reset-password --user alice
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes disable-user --user alice
```

`TEMPLATE_ID` above means the actual ID returned by `put-template`, not a
client-selected resource owner. A capability document has this shape; replace
the example provider/tool IDs with the returned IDs and choose a supported model:

```json
{
  "provider_id": "11111111111111111111111111111111",
  "model": "gpt-4.1",
  "models": ["gpt-4.1"],
  "parameters": {"max_tokens": 4096, "context_length": 128000, "temperature": 0.7},
  "agent": {"max_iterations": 90},
  "soul": "Your explicitly reviewed shared SOUL instructions.",
  "skills": {"team/SKILL.md": "# Team skills\nUse the shared tools catalog."},
  "tools": ["22222222222222222222222222222222"],
  "egress_hosts": []
}
```

`egress_hosts` explicitly grants outbound public DNS names, `*.example.com`, or
`*` for public internet. Private/loopback/metadata/reserved IPs and ports other
than 80/443 remain denied, even after DNS resolution; the tunnel pins the checked
numeric address. Default empty egress permits only the private model broker.
Web browsing, package downloads and other network tools need explicit egress
and any runtime dependencies. Direct Internet sockets are unavailable.

Explicit temperature/top-p/service-tier values apply at the broker; max tokens
are a ceiling (smaller auxiliary requests remain smaller). Reasoning effort uses
upstream `agent.reasoning_effort`. The template's `max_iterations` maps to the
upstream configuration key `agent.max_turns`; either spelling is accepted with
one consistent value. Optional `agent.system_message` instructions append to
the seeded SOUL file, using the Agent's existing instruction-loading mechanism.

Publish existing reviewed scripts once with `publish-tool`; no user needs to
recreate their source. The supplied converter is
[`multiuser/shared_tools/png_to_jpg.py`](../multiuser/shared_tools/png_to_jpg.py).
An administrator can copy it into the desired host tools folder first, or
publish it straight from the release. Publishing imports an immutable version
under the installation's shared store. Assigned bundles hardlink that single
version and mount it at `/shared/tools` **read-only**, not an arbitrary external
folder. A source edit requires explicitly publishing a new version with `--id`;
the running Agent cannot control that operation. Tool descriptions generate a
`shared-tools/SKILL.md` catalog in every assigned Hermes home.

Pillow is present in the pinned worker. The converter handles alpha backgrounds,
requires workspace input/output and a private temp path, uses unique scratch
directories and refuses accidental output overwrite. Other existing scripts
must accept per-job input/output/cache/temp paths; review hardcoded global paths
before publishing. Add their dependencies to the reviewed worker image and build
new immutable IDs, never install them on the account gateway.

## Storage and template updates

| Host location | Worker location / owner |
| --- | --- |
| `/srv/hermes/control/accounts.sqlite` | Gateway only; accounts, sessions, provider keys, audit |
| `/srv/hermes/users/<id>/hermes` | `/state/hermes`; private profiles, history, memory, config, learned skills, credentials |
| `/srv/hermes/users/<id>/workspace` | `/workspace`; private files/uploads/outputs |
| `/srv/hermes/users/<id>/tmp` | `/tmp`; private jobs, caches and temporary files |
| `/srv/hermes/users/<id>/outputs` | `/outputs`; additional private output area |
| `/srv/hermes/runtimes/<id>/tools` | `/shared/tools`; approved read-only bundle |
| `/srv/hermes/runtimes/<id>/{relay,broker}` | Trusted relay/gateway sockets; never mounted in Agent |

Back up the entire data root privately with all workers and the gateway stopped
(or use consistent filesystem/SQLite snapshots). It contains personal data and
provider keys; never commit it. No named Docker volumes are created or pruned.
Stopping/removing a scoped worker preserves every persistent directory.

Templates seed only allowlisted configuration, SOUL and selected text skills.
They never copy USER.md, conversation, memory, OAuth, browser login, `.env` or
MCP credentials. Restart/password reset preserves personal edits and deletions.
On a template change, unmodified seeded files update; modified files are kept
and the worker stops with `template_conflict`. Review those files privately,
then explicitly retain the personal versions and accept the new baseline:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes resolve-template \
  --user alice --keep-private
```

The next reconcile restarts it without overwriting the private edits. Previously
seeded skills removed from a template remain private files; shared tool mounts
are rebuilt to the new exact selection. Runtime broker policy always enforces
the **current** assigned provider/model/network allowlist even if personal config
was retained. A user can learn skills and edit their own workspace/memory normally.

External memory providers, browser sessions and MCP services are **not imported
from the administrator**. Local files/processes remain container-private. To add
an external service, provide separate account credentials and a tenant namespace
and review its egress independently. A third-party service that merges accounts
outside the deployment cannot be made private by a local profile cookie.

## Explicit single-user migration

There is no automatic migration or sharing of old private state. First create
the new empty installation/provider, then optionally select public capabilities
from an explicitly named existing home:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes migrate-single-user \
  --source /path/to/old-hermes-home --backup /private/backups/hermes-before-multiuser \
  --name 'Reviewed main capabilities' --provider-id PROVIDER_ID \
  --parameters --soul --skill team/SKILL.md
```

The command first creates a new mode-0700 backup outside both data roots,
including a mode-0600 archive and a non-secret selection report. Only the explicit
model/response fields, optional SOUL and named skill files enter the template.
Review selected text for embedded personal information or credentials before
sharing it. Legacy conversations and personal memory remain solely in the old
home and private backup. The existing single-user service can continue independently.

## Verification

See the [recorded baseline and acceptance results](multiuser-verification.md)
for the tested image IDs, actual outcomes and validation limits.

Run the normal repository gates plus the opt-in acceptance below:

```bash
./scripts/test.sh tests/test_multiuser_accounts.py tests/test_multiuser_gateway.py \
  tests/test_multiuser_policy.py -q
HERMES_MULTIUSER_DOCKER_TEST=1 \
HERMES_MULTIUSER_TEST_IMAGES=/var/tmp/hermes-images.json \
HERMES_MULTIUSER_EVIDENCE=/tmp/hermes-multiuser-evidence \
  ./scripts/test.sh tests/test_multiuser_docker.py -v --timeout=180
```

The Docker suite requires passwordless `sudo` for its disposable operator CLI
and permission to run Docker probes. It creates **only a unique `/tmp/hmu-e2e-*`
installation** on loopback, generates three distinct credentials, runs the real
upstream WebUI/Agent, and cleans up only its own labelled containers/directories.
Only the external model API is deterministic test data; actual tool execution,
filesystem boundaries, HTTP streaming, converter runs and persistence are real.
The proof JSON reports only non-secret IDs/booleans/image provenance. Do not shard
this stateful Docker acceptance file across pytest shards. It is explicitly
skipped by ordinary CI without the opt-in flag; a skip is not isolation evidence.

With Playwright/Chromium installed, the same image/evidence variables can run
`.venv/bin/python tests/browser_multiuser.py`. It starts another private lab and
checks login, admin CRUD/tabs, logout and preserved chat chrome at desktop,
narrow and mobile widths, saving screenshots and browser error evidence.

## Rollback

Keep the original single-user home/service and previous release untouched during
validation. To withdraw a new multi-user installation, stop the provisioner first
(its stop hook stops only its labelled workers), then the account gateway. If
running manually, stop the watch loop and use `stop-all-runtimes` before stopping
the gateway. Preserve `/srv/hermes` and private backups. Restore only the proxy
route and previous source release deliberately; do not reset or merge account
data into the legacy home. To change feature source in Git, switch to the retained
`restore/upstream-20261106` branch or revert the feature commits normally; no
force-push or history rewrite is required. This implementation does not push,
merge or switch a live deployment automatically.
