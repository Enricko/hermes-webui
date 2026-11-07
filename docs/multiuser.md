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

## Connect an existing Hermes installation

After preparing the reviewed release, Python environment, immutable Docker image
manifest and dedicated gateway UID as below, run this **operator** command:

```bash
sudo /opt/hermes-multiuser/.venv/bin/python -m multiuser.manage --root /srv/hermes setup \
  --public-url https://hermes.example.com --images /var/tmp/hermes-images.json \
  --hermes-home /home/operator/.hermes --username administrator
```

Setup initializes a new multi-user data root, prompts twice for the first admin
password, discovers `config.yaml` in the Hermes home and each immediate named
`profiles/<name>` directory, and imports reusable capabilities as assignable base
profiles. The new administrator inherits the discovered main profile. It never
sets a default password. Rerunning on the same installation preserves existing
accounts, passwords and assignments. Use `upgrade --backup /private/new-path`
before setup when upgrading an older account schema. No containers are created
until the trusted reconciler is started.

`--hermes-home` is recommended under sudo. When omitted, discovery uses
`HERMES_BASE_HOME`, then `HERMES_HOME` (unwrapping an active named profile), then
the invoking/SUDO user's `~/.hermes`. It never scans other home directories.
Supported Linux Docker deployment does not require the source Agent's Python
environment to be imported into the gateway. Workers use the tested pinned
Agent revision described below.

For an already-initialized installation, connect a source without bootstrapping
again:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes discover-profiles \
  --hermes-home /home/operator/.hermes
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes connect-hermes \
  --hermes-home /home/operator/.hermes --name Hermes \
  --backup-root /var/backups/hermes-profiles
```

The first command is read-only. The second explicitly authorizes capability and
API-key reuse from that installation. It snapshots the control database and
source configuration privately **outside both data roots** before publications.
If a main profile was imported previously, add
`--adopt-template default=<existing-template-id>` at first registration to reuse
its identity and account assignments. Adoption retains already-approved local
endpoint aliases and connection defaults. Further syncs retain those choices
while the corresponding source setting is unchanged. Ordinary new setups do not
need adoption IDs or a JSON template document.

In the WebUI, open **Accounts → Hermes profiles** to see discovered profiles and
status. In **Accounts**, click **New account** or choose someone from the
searchable People list. Check every **Profile** and **AI provider** they may use,
choose one **Default** in each group, and click **Create account** or **Save
access**. The cards support keyboard checkboxes/radios and Select all/Clear;
there are no assignment dropdowns or resource IDs to type. Password reset and
account enable/disable are under **Password & account status**.

The two access lists are independent. For example, Alice may have profiles A+B
and only provider A, while Bob has only profile A and providers A+B. A provider
listed in the source profile is not automatically authorized for an account
with an explicit access list. Defaults choose the initial setup, rather than
granting access to an unchecked option. Removing a provider immediately blocks
its broker route, including requests from an old worker awaiting reconciliation.

Users switch assigned profiles from the chat composer or the **Profiles** menu,
and choose an allowed provider/model in the composer's model controls.
A prepared profile switches in place using the native Hermes
transition: no page reload, container restart, browser preference reset or
another login. Running sessions/jobs stay with their original profile. Source
profiles are shared capabilities; switching them does not import original
personal state or create a different tenant. Personal config edits remain
protected by the existing conflict policy. Changing the account's default
provider still reconciles its runtime and closes its other sessions/streams;
ordinary profile browsing keeps that provider unchanged.

The **Providers** tab manages gateway-held credentials; the advanced **Templates**
editor remains available for custom capability policies. Regular users see only
their assigned choices and cannot manage accounts or provider secrets. Existing
accounts keep inherited access until an admin explicitly saves an access list.
Schema v4 is additive; use `upgrade --backup /private/new-path` before launching
this release against an existing installation. Passwords, account IDs, active
selections and existing data remain unchanged by migration.

Assigned profiles also appear directly in **Profiles → Assigned profiles** and
the composer profile menu as soon as you sign in. Click a profile to open it
directly, keeping your current assigned provider; no confirmation picker is
required. If that provider is unavailable, the profile's allowed default (or
first assigned provider) is used. All granted profiles are provisioned together
so ordinary switches reuse the already running private workspace.
Both profile menus use the same authenticated account grants. There is no
separate sidebar selection dialog. Prepared profiles show their real
skill/runtime details. Shared source profiles are read-only in this view;
administrators change their assignments in Accounts. Additional personal
subprofiles are listed separately and remain inside the user's private runtime.

On upgrade, the existing account root home stays attached to its current
capability, retaining its conversations, memory and personal files. Additional
assigned profiles are created under that account's private `hermes/profiles/`
directory using sanitized configuration and skills only; old private data is
never copied to them. The trusted operator publishes the mapping outside the
Agent's mounts. Back up the account homes, generated seed manifests and control
database before this one-time provisioning update. New scheduler processes use
separate fixed homes for each assigned profile. Credential/grant changes still
replace the account's runtime, while switching already prepared profiles does
not. No control database schema migration is needed for this update.

Discovery imports model/response/Agent parameters, SOUL instructions and reusable
skills, including `skills.external_dirs` located **inside the registered Hermes
home**. Local skills take precedence. Source files are never modified. Skill
symlinks, credential-like files/content, USER.md, caches, memories and session
files are filtered. Conversation databases, personal memory, OAuth/browser/MCP
state, uploads, workspace files, cron jobs and source `.env` contents are never
seeded into users' homes. Only resolved provider API keys enter the private
control database; workers receive broker URLs and dummy keys. Stateful
integrations and skill roots outside the registered home require separate
reviewed per-user setup. They are not silently enabled.

Legacy `custom_providers` lists and native `providers` mappings with compatible
base URLs are recognized, as are configured OpenAI, OpenRouter, Groq, DeepSeek,
Together, Fireworks, xAI and NVIDIA API-key providers. Credentials resolve only
from that profile's config and `.env`, never the gateway's process environment.
Keyless localhost-compatible servers are supported. Native-only/OAuth-only or
incomplete profiles stay visible as **needs-provider**; configure a compatible
provider in Hermes, then sync. Discovery preserves source model IDs; it does not
claim that every saved model is still served by its router. Runtime discovery
and inference are both checked against the provider's live catalog.

### Follow profile additions and updates

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes sync-profiles
sudo install -m 644 multiuser/deployment/hermes-profile-sync.service /etc/systemd/system/
sudo install -m 644 multiuser/deployment/hermes-profile-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-profile-sync.timer
```

The optional oneshot/timer reads only root-registered sources every minute. It
needs read-only access to those homes and write access to the data/backup roots;
it has no network access or Docker socket. Match `ConditionPathExists` and
`ReadWritePaths` to a custom data/backup root in a systemd override. The gateway
cannot register paths, write the root-owned `profile-sources.json`, or submit
import jobs. The provisioner's stronger home restrictions remain unchanged.
No extra daemon is needed when using explicit CLI syncs.

Unchanged source content does not bump template versions or restart accounts.
Added profiles appear as new assignment options. Removed/unavailable sources are
marked **missing** and leave accounts/data intact. Admin-edited imported
templates or providers produce **conflict** and are preserved. An operator can
resolve a conflict using the source ID shown in the admin catalog API:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes resolve-profile-sync \
  --source-id <id> --profile default --keep-admin
# Or explicitly resume source-managed updates instead:
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes resolve-profile-sync \
  --source-id <id> --profile default --use-source
```

Both choices take a private backup. `--keep-admin` freezes automatic updates for
that profile. `--use-source` republishes capabilities using the same identity.
Existing per-user three-way seeding still preserves private edits/deletions and
reports a runtime template conflict if an update needs review. Use the existing
`resolve-template --user <id> --keep-private` flow for those personal conflicts.

To roll back discovery, stop/disable the timer, stop gateway and provisioner,
save current state, restore `accounts-before.sqlite` and the matching
`profile-sources-before.json` from one private snapshot with correct gateway DB
ownership, then restart the prior reviewed release. With all DB writers stopped,
remove stale SQLite `-wal`/`-shm` sidecars belonging to that DB before replacing
it. Never remove user data or original Hermes homes. Disable the timer before
rolling back to code that predates discovery. Source-only rollback can leave the
additive discovery tables in place. For schema v4, prefer a **frontend-only
rollback** that keeps the current grant-enforcing backend and database. Backends
predating v4 do not understand explicit profile/provider restrictions and must
not serve restricted accounts using the new database. A full release rollback
requires reviewing new accounts/permission changes and restoring a matching
pre-upgrade control snapshot, or keeping affected accounts disabled. Never run
an older schema initializer against v4. See the existing deployment rollback
procedure below.

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

The page, readiness poll and private APIs use the same admission check: a ready
database row is insufficient when the operator's profile map still belongs to
an older account generation. After an access/credential change, the preparing
page waits for the matching map and opens chat automatically. Ordinary sign-ins
to an already prepared account reuse its running container.

If provisioning or a relay restart interrupts chat initialization, the account
shell polls readiness and actual API reachability, then reloads the application
automatically once. It never replays refused writes. An open draft, attachment,
unsaved file edit, active turn or account dialog delays reconnection to preserve
work; finish or clear the draft, save file edits and close the dialog to allow
automatic reconnection. Ordinary
native profile switching still stays in place without reloading the workspace.

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

### Reuse an existing profile with independent providers

Choose the same **Base profile** for every account in **Accounts**. Each user's
**AI provider → Assign provider** selects a connection independently; **Use base
profile provider** inherits the existing connection. Add connections under
**Providers**; credentials remain in the gateway. A provider must support the
profile's allowed models. Assignment changes revoke that user's sessions and
restart only their runtime, preserving its workspace. With one enabled profile,
the create-account form selects it automatically. The sidebar shows the profile
and provider currently assigned to the signed-in account.

Upgrade an existing v1 installation with the reviewed release's CLI:

```bash
sudo systemctl stop hermes-provisioner hermes-accounts
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes upgrade \
  --backup /private/backups/accounts-before-provider-assignments
sudo systemctl start hermes-accounts hermes-provisioner
```

The additive migration preserves account IDs, passwords, profile assignments and
sessions. Its consistent SQLite backup is mode 0600 in a new mode 0700 directory
outside the installation. It retains the database file's existing mode and owner;
keep the deployment's setgid control-directory permissions.

With the provisioner stopped, explicitly reuse a main profile by updating the
existing template **in place**, using the trusted root CLI:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes reuse-profile \
  --source /path/to/existing-hermes-home --template EXISTING_TEMPLATE_ID \
  --backup /private/backups/main-profile-before-reuse
```

The command backs up selected capabilities, preserves SOUL, imports supported
model/response parameters, and publishes existing skill resources once. The source
model must match the template. Hermes loads the read-only `/shared/skills` bundle
through `skills.external_dirs`; learned skills stay private. Symlinks, caches,
logs, hidden files and recognizable/known source credentials are excluded. Review
the private `profile-reuse.json` exclusion report; automated scanning does not
prove arbitrary source text public. Conversation databases, personal memory,
USER.md, uploads, OAuth, `.env`, auth.json and jobs are never shared. The original
Hermes home remains untouched.

Three-way seed protection still preserves user changes. Review `template_conflict`
privately, then restart the provisioner after resolving it. Upstream's `default`
subprofile is each account's private root view of the common capabilities, not
a second empty base template. `/workspace` maps to a different host folder for
every user even though the path inside each container is identical.

CLI provider assignment (omit `--provider` to inherit):

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes assign-provider \
  --user alice --provider PROVIDER_ID
```

To expose all models from each account's assigned provider, set
`"model_catalog": "provider"` in the existing capability document under
**Templates**. The singular `model` remains the initial selection; it does not
narrow provider discovery. The broker fetches that account's configured
`/models` endpoint with its server-held credential. Both discovery and inference
use the returned IDs. Accounts cannot choose a URL, borrow another provider's
catalog or invoke an invented model. Catalogs are single-flight, cached for
30 seconds, bounded to 2 MiB / 4096 entries, and keyed by account generation,
provider identity, URL, credential fingerprint and policy. A late response after
reassignment is rejected; failed discovery does not authorize arbitrary models.
Provider availability and supported request types still determine which listed
models can complete a chat request. The default `"model_catalog": "allowlist"`
preserves restricted installations' existing explicit `models` policy.

Upstream keeps a short featured list in `/api/models/live`. The full catalog is
available in `/api/models` through each group's `models` plus `extra_models`.
Use the model picker's search or **Show more** to reach the remaining models;
the featured-list budget does not limit server-side model authorization.

Profile statistics include local and configured external skill roots, resolved
under the profile owner's environment with duplicate names counted once.
External changes participate in the existing invalidation/mtime cache. Account
profile cards identify the assigned provider and managed connection without
copying its API key or inventing a local `.env` file.

### Restore multiple custom routers from an existing profile

One shared profile can offer several named provider connections in the ordinary
Hermes model picker. Under **Templates**, its `connections` list contains only
`provider_id`, display `name`, and the connection's default `model`; external URLs
and API keys remain in **Providers**. For example:

```json
{"connections":[
  {"provider_id":"ACTUAL_PROVIDER_ID","name":"First Router","model":"its-default-model"},
  {"provider_id":"ANOTHER_PROVIDER_ID","name":"Second Router","model":"its-default-model"}
]}
```

Use the actual IDs returned by provider creation. Duplicate IDs or normalized
names are rejected. Each connection gets its own provider group; selecting the
same model ID under two groups retains two distinct destinations. The account's
**AI provider** assignment selects its primary connection, while the profile's
approved named connections remain available. To restrict an account to a subset,
assign a profile whose connections list contains only that subset.

The generated **Account primary** entry is an internal alias for the account's
selected primary connection, not another external router. Its explicit identity
prevents a named router with the same model ID from taking over default requests.
That display name is reserved. Per-account assignment to a named connection also
uses that connection's own default model, preserving the shared SOUL and skills.

To restore reviewed connections and their existing credentials explicitly,
stop the provisioner and use the root-only importer:

```bash
sudo .venv/bin/python -m multiuser.manage --root /srv/hermes import-providers \
  --source /path/to/existing-hermes-home --template EXISTING_TEMPLATE_ID \
  --name 'First Router' --name 'Second Router' \
  --backup /private/backups/providers-before-import
```

Add `--reuse-provider 'First Router=EXISTING_PROVIDER_ID'` to update an existing
control-plane connection without duplicating it; this retains its endpoint
(useful for an existing loopback connection to the same router). Credentials are
resolved only from that source profile, never the operator process environment.
The importer privately backs up source config/environment and a consistent
control database, verifies each live catalog without following redirects, then
publishes all provider records and profile authorization in one transaction.
The original source is untouched. A saved default absent from the live catalog
is recorded in the import report and replaced by an advertised model for the
new connection. Review the private report before restarting the provisioner.

Workers receive only dummy credentials and `127.0.0.1` broker URLs. Ordinary
users cannot add connection IDs, select another account's broker, bypass a
removed connection, or forward arbitrary URLs through a guessed provider ID.
Rotating a provider key invalidates that connection's catalog cache without
copying keys into worker environments. Existing conversations and workspace
folders are preserved during this import.

For rollback, older source can retain the additive database column. Restore an old
control database only with services stopped and only when intentionally discarding
later account-control changes. Restore profile capabilities from the private
`template-before.json` using the original template ID; retain both skill bundles
until no runtime references the newer one. Capability rollback never replaces user
homes or workspace folders.

| Host location | Worker location / owner |
| --- | --- |
| `/srv/hermes/control/accounts.sqlite` | Gateway only; accounts, sessions, provider keys, audit |
| `/srv/hermes/users/<id>/hermes` | `/state/hermes`; private profiles, history, memory, config, learned skills, credentials |
| `/srv/hermes/users/<id>/workspace` | `/workspace`; private files/uploads/outputs |
| `/srv/hermes/users/<id>/tmp` | `/tmp`; private jobs, caches and temporary files |
| `/srv/hermes/users/<id>/outputs` | `/outputs`; additional private output area |
| `/srv/hermes/runtimes/<id>/tools` | `/shared/tools`; approved read-only bundle |
| `/srv/hermes/shared/profiles/<bundle>/skills` | `/shared/skills`; common profile skills, read-only |
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

For startup recovery, run `.venv/bin/python tests/browser_multiuser_startup.py`
with those variables and a fresh evidence directory. It verifies a new account,
an existing account with a stale operator map after an admin edit, automatic
chat/file initialization, and a real Agent reply/upload. At desktop, narrow and
mobile widths it also injects one boot API interruption, checks automatic
reconnection, preserves an unsent draft/live attachment, and confirms warm
sign-ins retain the same worker. `tests/test_api_timeout.py` separately proves a
typed unavailable response is reported without replaying a chat POST.

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
