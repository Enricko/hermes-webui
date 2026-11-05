#!/bin/bash -p
# Multi-user (F02) unit controller: the trusted host side of F02 verification.
#
# Supported entry; nothing from the caller's environment reaches the shell:
#
#   /usr/bin/env -i /bin/bash -p /ABS/scripts/multiuser_unit.sh GLOBAL COMMAND ...
#   /usr/bin/env -i /ABS/scripts/multiuser_unit.sh GLOBAL COMMAND ...  (shebang: bash -p)
#
# Privileged mode (-p) reads no startup file, BASH_ENV or ENV and imports no
# shell functions, SHELLOPTS or BASHOPTS. The first code below uses builtins
# only and refuses any other shell, a shell without -p, and any inherited
# variable other than the shell's own PWD, OLDPWD, SHLVL and _.
#
#   multiuser_unit.sh GLOBAL build --base-image NAME@sha256:<64hex>
#   multiuser_unit.sh GLOBAL run --runtime-evidence ABS_BUILD_RESULT_JSON
#                                --image-id sha256:<64hex> --candidate <40hex>
#                                [--timeout SECONDS] -- <worker args>
#   multiuser_unit.sh GLOBAL cleanup --unit-id <controller uuid>
#
#   GLOBAL: --engine-socket ABS_UNIX_SOCKET --evidence-dir DIR
#           [--docker-bin ABS] [--jq-bin ABS] [--dry-run]
#
# build provisions the unit image from the recipe files of this checkout's
# HEAD commit, captured once (scripts/multiuser_unit.Dockerfile), and records
# the recipe digests, image, layers, runtime configuration and freeze digest.
# run admits that build result (--runtime-evidence) and the live unit image
# before anything is created, copies the exact candidate commit into a
# per-run image, creates ONE container with fixed isolation flags, admits it
# from `docker inspect` before `docker start`, runs the launcher
# (`python3 -I -S scripts/test_multiuser.py <worker args>`) inside it, checks
# exactly one worker result line against the container exit and the
# requested mode and tier, removes the container and per-run image, and only
# then gives a verdict. cleanup removes what an interrupted run's lease
# recorded, and nothing else.
#
# Every docker call uses an empty environment with a private HOME and
# DOCKER_CONFIG inside DIR and the explicit --host socket: no ambient context,
# DOCKER_HOST, ~/.docker config, credential helpers or keychains. Git is used
# through plumbing only, with repository helpers (fsmonitor, hooks, pager,
# external diff, attributes, filters, textconv, transports) unable to run.
# Host Python is never run. Only containers and tags whose exact identity this
# controller created and recorded on the same engine are ever removed; an
# unknown identity is quarantined, never looked up by name or label.
#
# The build evidence is trusted controller output in a private directory; a
# same-user attacker who controls this host or controller is outside this
# boundary, and a private JSON file does not attest itself.
#
# The last stdout line is `MULTIUSER_UNIT_RESULT {json}`; the same JSON is
# written to DIR/result.json. Exit: 0 PASS, 1 FAIL, 2 REFUSED, 3 NOT_RUN.
# --docker-bin/--jq-bin substitute binaries (for example in simulations); the
# substitution is recorded as protocol_simulation and is never evidence about
# a real engine or worker.
case "${BASH_VERSION:+bash}:$-" in
  bash:*p*) ;;
  *)
    printf '%s\n' 'MULTIUSER_UNIT_RESULT {"schema":"hermes-webui/multiuser-unit-controller/1","command":null,"status":"REFUSED","exit_code":2,"reasons":[{"code":"unsupported_entry","detail":"start the controller with /usr/bin/env -i /bin/bash -p"}]}'
    exit 2
    ;;
esac
IFS=$' \t\n'
if ! MU_ENV=$(compgen -e); then
  printf '%s\n' 'MULTIUSER_UNIT_RESULT {"schema":"hermes-webui/multiuser-unit-controller/1","command":null,"status":"REFUSED","exit_code":2,"reasons":[{"code":"unsupported_entry","detail":"the shell cannot list its environment"}]}'
  exit 2
fi
for MU_NAME in $MU_ENV; do
  case $MU_NAME in
    PWD|OLDPWD|SHLVL|_) ;;
    *)
      printf '%s\n' 'MULTIUSER_UNIT_RESULT {"schema":"hermes-webui/multiuser-unit-controller/1","command":null,"status":"REFUSED","exit_code":2,"reasons":[{"code":"unsupported_entry","detail":"the controller environment must be empty; start it with /usr/bin/env -i"}]}'
      exit 2
      ;;
  esac
done
unset MU_NAME MU_ENV
# Exported entries that are not shell variables (such as function exports)
# cannot be listed by builtins; the supported `env -i` entry has none, and no
# child shell is given this environment (docker, git and tar run under env -i).

set -Eeuo pipefail
umask 077
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL

SCHEMA="hermes-webui/multiuser-unit-controller/1"
LEASE_SCHEMA="hermes-webui/multiuser-unit-lease/1"
WORKER_SCHEMA="hermes-webui/multiuser-launcher/1"
RESULT_PREFIX="MULTIUSER_UNIT_RESULT "
PLAN_PREFIX="MULTIUSER_UNIT_PLAN "
WORKER_PREFIX="MULTIUSER_RESULT "
UNIT_USER="10001:10001"
UNIT_SRC="/src"
UNIT_STATE="/run/mu-state"
TMPFS_TMP="/tmp:rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700"
TMPFS_STATE="/run/mu-state:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700"
PIDS_LIMIT=256
MEMORY_BYTES=2147483648
NANO_CPUS=2000000000
DEFAULT_TIMEOUT=1800
MAX_WORKER_STDOUT=4194304
MAX_EVIDENCE_BYTES=1048576
GIT_BIN=/usr/bin/git
RECIPE_PATHS="requirements.txt requirements-dev.txt scripts/test.sh scripts/multiuser_unit.Dockerfile"
RECIPE_PATHS_JSON='["requirements.txt","requirements-dev.txt","scripts/test.sh","scripts/multiuser_unit.Dockerfile"]'
RECIPE_KEYS_JSON='["commit","tree","base_image","inputs","unit_image_tag","unit_image_id","unit_layers","runtime_config","freeze_sha256"]'
RUNTIME_KEYS_JSON='["User","WorkingDir","Env","Entrypoint","Cmd","Volumes","OnBuild","Healthcheck","StopSignal","Shell","ExposedPorts"]'
DEFAULT_DOCKER_BINS="/usr/local/bin/docker /usr/bin/docker"
DEFAULT_JQ_BIN=/usr/bin/jq

HEX40_RE='^[0-9a-f]{40}$'
HEX64_RE='^[0-9a-f]{64}$'
IMAGE_ID_RE='^sha256:[0-9a-f]{64}$'
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
BASE_IMAGE_RE='^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd -P)"

# ── Result state ──────────────────────────────────────────────────────────────

STATUS=""
REASONS=""
EMITTED=0
COMMAND=""
DRY_RUN=false
CONTROLLER_ID=""
DIR=""
DIR_CREATED=0
SOCK=""
DOCKER_BIN=""
DOCKER_SUBSTITUTED=false
JQ_BIN=""
JQ_READY=0
ENGINE_ID=""
ENGINE_JSON=null
REQUEST_JSON=null
REQ_MODE=""
REQ_TIER=""
RUNTIME_EVIDENCE_JSON=null
RECIPE_JSON=null
CANDIDATE_JSON=null
CONTAINER_JSON=null
ATTESTED_JSON='{"network_none":false,"read_only_rootfs":false,"non_root":false,"no_mounts":false,"caps_dropped":false,"no_new_privileges":false,"private_pid":false,"resource_limits":false}'
WORKER_JSON='{"result":null,"consistent":false}'
CLEANUP_JSON='{"container_removed":false,"candidate_image_removed":false,"verified":false,"quarantine":[]}'
CLAIMS_JSON='{"agent_source_pin":false,"native_clients":false,"browser_privacy":false,"os_containment":false,"external_provider":false}'
UNIT_CID=""
CREATED_ID=""
INTERRUPTED=""
ERR_LINE=""
QUARANTINE=""

# A JSON string from controller-generated text. Characters outside a plain
# set become '?', so no escaping is needed; structured data goes through jq.
json_string() {
  printf '"%s"' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9 _./:@=+,()<>#%~!?*^-' '?')"
}

# matches VALUE ERE: the whole value, newlines included, matches.
matches() {
  [[ $1 =~ $2 ]]
}

rank() {
  case "$1" in PASS) echo 0 ;; NOT_RUN) echo 1 ;; REFUSED) echo 2 ;; FAIL) echo 3 ;; *) echo 3 ;; esac
}

exit_code_for() {
  case "$1" in PASS) echo 0 ;; FAIL) echo 1 ;; REFUSED) echo 2 ;; NOT_RUN) echo 3 ;; *) echo 1 ;; esac
}

# settle STATUS [CODE DETAIL]: the most severe status wins; reasons accumulate.
settle() {
  local status=$1
  if [ -z "$STATUS" ] || [ "$(rank "$status")" -gt "$(rank "$STATUS")" ]; then
    STATUS=$status
  fi
  if [ $# -ge 3 ]; then
    add_reason_json "{\"code\":$(json_string "$2"),\"detail\":$(json_string "$3")}"
  fi
}

add_reason_json() {
  if [ -n "$REASONS" ]; then REASONS="$REASONS,$1"; else REASONS="$1"; fi
}

# stop STATUS CODE DETAIL: settle and finish (cleanup runs from the EXIT trap).
stop() {
  settle "$1" "$2" "$3"
  exit 0
}

result_json() {
  local status=${STATUS:-FAIL} json
  json="{\"schema\":\"$SCHEMA\",\"command\":$(json_string "${COMMAND:-}"),\"status\":\"$status\""
  json="$json,\"exit_code\":$(exit_code_for "$status"),\"reasons\":[${REASONS}]"
  json="$json,\"controller_id\":$(json_string "$CONTROLLER_ID"),\"dry_run\":$DRY_RUN"
  json="$json,\"docker_bin\":$(json_string "$DOCKER_BIN"),\"docker_bin_substituted\":$DOCKER_SUBSTITUTED"
  json="$json,\"protocol_simulation\":$DOCKER_SUBSTITUTED,\"request\":$REQUEST_JSON"
  json="$json,\"jq_bin\":$(json_string "$JQ_BIN"),\"engine\":$ENGINE_JSON"
  json="$json,\"runtime_evidence\":$RUNTIME_EVIDENCE_JSON,\"recipe\":$RECIPE_JSON"
  json="$json,\"candidate\":$CANDIDATE_JSON,\"container\":$CONTAINER_JSON,\"attested\":$ATTESTED_JSON"
  json="$json,\"worker\":$WORKER_JSON,\"cleanup\":$CLEANUP_JSON,\"claims\":$CLAIMS_JSON}"
  printf '%s' "$json"
}

emit_result() {
  [ "$EMITTED" -eq 0 ] || return 0
  EMITTED=1
  local json
  json=$(result_json)
  # build and run write DIR/result.json exclusively; a failed write is a FAIL.
  if [ "$DIR_CREATED" -eq 1 ] && ! ( set -o noclobber; printf '%s\n' "$json" > "$DIR/result.json" ) 2>/dev/null; then
    settle FAIL result_file_unwritten "DIR/result.json could not be created exclusively"
    json=$(result_json)
  fi
  printf '%s%s\n' "$RESULT_PREFIX" "$json"
  FINAL_CODE=$(exit_code_for "${STATUS:-FAIL}")
}

# ── Argument and host validation (no engine contact) ─────────────────────────

usage_refused() {
  stop REFUSED usage "$1"
}

is_abs() {
  case "$1" in /*) return 0 ;; *) return 1 ;; esac
}

# A directory that is a canonical path, owned by us and not group/other-writable.
private_dir() {
  local d=$1
  [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] || return 1
  [ "$(cd "$d" && pwd -P)" = "$d" ] || return 1
  [ -z "$(find "$d" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) -print)" ]
}

validate_socket() {
  local parent
  is_abs "$SOCK" || stop NOT_RUN unit_engine_unavailable "--engine-socket must be an absolute path"
  if [ -L "$SOCK" ] || [ ! -S "$SOCK" ] || [ ! -O "$SOCK" ]; then
    stop NOT_RUN unit_engine_unavailable "engine socket is missing, a link, not a socket or not owned by this user"
  fi
  parent=$(dirname "$SOCK")
  private_dir "$parent" || stop NOT_RUN unit_engine_unavailable "engine socket directory is not a private canonical directory"
}

select_binaries() {
  local candidate
  if [ -n "$DOCKER_BIN" ]; then
    DOCKER_SUBSTITUTED=true
  else
    for candidate in $DEFAULT_DOCKER_BINS; do
      if [ -x "$candidate" ] && [ ! -d "$candidate" ]; then DOCKER_BIN=$candidate; break; fi
    done
  fi
  if [ -z "$DOCKER_BIN" ] || ! is_abs "$DOCKER_BIN" || [ ! -x "$DOCKER_BIN" ] || [ -d "$DOCKER_BIN" ]; then
    stop NOT_RUN prerequisite_missing "no executable docker CLI at an explicit absolute path"
  fi
  JQ_BIN=${JQ_BIN:-$DEFAULT_JQ_BIN}
  if ! is_abs "$JQ_BIN" || [ ! -x "$JQ_BIN" ] || [ -d "$JQ_BIN" ]; then
    stop NOT_RUN prerequisite_missing "jq is required at an explicit absolute path"
  fi
  JQ_READY=1
  if [ ! -x "$GIT_BIN" ]; then
    stop NOT_RUN prerequisite_missing "git is required at $GIT_BIN"
  fi
}

prepare_new_evidence_dir() {
  local parent
  is_abs "$DIR" || stop REFUSED evidence_dir_refused "--evidence-dir must be an absolute path"
  if [ -e "$DIR" ] || [ -L "$DIR" ]; then
    stop REFUSED evidence_dir_refused "--evidence-dir must not exist yet"
  fi
  parent=$(dirname "$DIR")
  private_dir "$parent" || stop REFUSED evidence_dir_refused "the --evidence-dir parent is not a private canonical directory"
  mkdir -m 700 "$DIR" 2>/dev/null || stop REFUSED evidence_dir_refused "--evidence-dir could not be created exclusively"
  DIR_CREATED=1
  mkdir -m 700 "$DIR/home" "$DIR/docker-config" "$DIR/tmp"
  printf '{"auths":{}}\n' > "$DIR/docker-config/config.json"
}

existing_lease_dir() {
  is_abs "$DIR" || stop REFUSED evidence_dir_refused "--evidence-dir must be an absolute path"
  private_dir "$DIR" || stop REFUSED evidence_dir_refused "--evidence-dir is not a private canonical directory"
  [ -z "$(find "$DIR" -maxdepth 0 ! -perm 0700 -print)" ] || stop REFUSED evidence_dir_refused "--evidence-dir is not mode 0700"
  [ -f "$DIR/lease.json" ] && [ ! -L "$DIR/lease.json" ] || stop REFUSED evidence_dir_refused "--evidence-dir holds no lease.json"
}

random_hex() {
  od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

new_controller_id() {
  local h
  h=$(random_hex 16)
  CONTROLLER_ID="${h:0:8}-${h:8:4}-4${h:13:3}-a${h:17:3}-${h:20:12}"
  UNIT_NONCE=$(random_hex 16)
}

sha256_file() {
  if [ -x /usr/bin/shasum ]; then
    /usr/bin/shasum -a 256 "$1" | awk '{print $1}'
  else
    /usr/bin/sha256sum "$1" | awk '{print $1}'
  fi
}

json_equal() {
  "$JQ_BIN" -en --argjson a "$1" --argjson b "$2" '$a == $b' >/dev/null 2>&1
}

# ── Git: plumbing on recorded objects only ───────────────────────────────────

# No system/global config, and every repository or worktree helper that could
# execute is turned off: fsmonitor, hooks, pager, external diff, attributes,
# replace objects and transports (so a partial clone cannot lazy-fetch). Only
# rev-parse, cat-file -t/-s/blob and ls-tree run; none of them applies
# filters, textconv or export attributes.
git_plumb() {
  env -i PATH=/usr/bin:/bin HOME="$DIR/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat \
    "$GIT_BIN" --no-pager --no-replace-objects \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat -c diff.external= \
    -c core.attributesFile=/dev/null -c protocol.allow=never \
    -C "$REPO" "$@"
}

safe_rel_path() {
  case "$1" in
    ''|/*|*$'\n'*|*$'\r'*|.venv|.venv/*) return 1 ;;
  esac
  case "/$1/" in
    *//*|*/./*|*/../*|*/.git/*) return 1 ;;
  esac
}

# materialize_tree COMMIT DEST [PATH...]: write the committed tree, or only
# the named paths, from raw blobs into the new directory DEST. Directories
# end 0755 and files 0644 or 0755; links are created last, each under a
# canonical parent, so nothing is written through a link. A gitlink, an
# unsupported mode, an unsafe, duplicate or case-colliding path, or a link
# target that does not round-trip makes it fail.
materialize_tree() {
  local commit=$1 dest=$2 canon entry meta rest mode type oid path parent target size i
  local links link_oids execs
  links=()
  link_oids=()
  execs=()
  shift 2
  mkdir -m 700 "$dest" || return 1
  canon=$(cd "$dest" && pwd -P) || return 1
  git_plumb ls-tree -r -z --full-tree "$commit" -- "$@" > "$dest.lst" 2>/dev/null || return 1
  : > "$dest.paths"
  while IFS= read -r -d '' entry; do
    meta=${entry%%$'\t'*}
    path=${entry#*$'\t'}
    mode=${meta%% *}
    rest=${meta#* }
    type=${rest%% *}
    oid=${rest#* }
    matches "$oid" "$HEX40_RE" || return 1
    safe_rel_path "$path" || return 1
    printf './%s\n' "$path" >> "$dest.paths"
    case "$path" in */*) parent=${path%/*} ;; *) parent="" ;; esac
    if [ -n "$parent" ]; then mkdir -p "$canon/$parent" || return 1; fi
    case "$mode:$type" in
      100644:blob|100755:blob)
        set -o noclobber
        if git_plumb cat-file blob "$oid" 2>/dev/null > "$canon/$path"; then set +o noclobber; else set +o noclobber; return 1; fi
        if [ "$mode" = 100755 ]; then execs+=("$canon/$path"); fi
        ;;
      120000:blob)
        links+=("$path")
        link_oids+=("$oid")
        ;;
      *) return 1 ;;
    esac
  done < "$dest.lst"
  find "$canon" -type f -exec chmod 0644 {} + || return 1
  if [ "${#execs[@]}" -gt 0 ]; then chmod 0755 "${execs[@]}" || return 1; fi
  find "$canon" -type d -exec chmod 0755 {} + || return 1
  i=0
  while [ "$i" -lt "${#links[@]}" ]; do
    path=${links[$i]}
    size=$(git_plumb cat-file -s "${link_oids[$i]}" 2>/dev/null) || return 1
    target=$(git_plumb cat-file blob "${link_oids[$i]}" 2>/dev/null) || return 1
    [ -n "$target" ] && [ "${#target}" = "$size" ] || return 1
    case "$target" in *$'\n'*) return 1 ;; esac
    case "$path" in */*) parent=${path%/*} ;; *) parent="" ;; esac
    [ "$(cd "$canon/$parent" 2>/dev/null && pwd -P)" = "$canon${parent:+/$parent}" ] || return 1
    [ ! -e "$canon/$path" ] && [ ! -L "$canon/$path" ] || return 1
    ln -s -- "$target" "$canon/$path" || return 1
    i=$((i + 1))
  done
  # Exactly the listed entries exist, with their exact names.
  sort "$dest.paths" > "$dest.paths.sorted" || return 1
  ( cd "$canon" && find . -mindepth 1 ! -type d -print ) | sort > "$dest.found" || return 1
  cmp -s "$dest.paths.sorted" "$dest.found"
}

# recipe_inputs ROOT: {"<recipe path>": "<sha256>"} for regular, non-link files.
recipe_inputs() {
  local root=$1 p
  set --
  for p in $RECIPE_PATHS; do
    [ -f "$root/$p" ] && [ ! -L "$root/$p" ] || return 1
    set -- "$@" "$p" "$(sha256_file "$root/$p")"
  done
  "$JQ_BIN" -cn 'reduce range(0; $ARGS.positional | length; 2) as $i
    ({}; . + {($ARGS.positional[$i]): $ARGS.positional[$i + 1]})' --args -- "$@"
}

# tar_create SRC OUT: archive SRC's contents with no host metadata (macOS
# AppleDouble files, extended attributes or ACLs) that would alter the tree.
tar_create() {
  local opts
  opts=()
  case "$(tar --version 2>/dev/null)" in bsdtar*) opts=(--no-mac-metadata --no-xattrs --no-acls) ;; esac
  ( cd "$1" && env -i PATH=/usr/bin:/bin COPYFILE_DISABLE=1 tar ${opts[@]+"${opts[@]}"} -cf "$2" . )
}

# ── Engine access ─────────────────────────────────────────────────────────────

dk() {
  env -i PATH=/usr/bin:/bin HOME="$DIR/home" DOCKER_CONFIG="$DIR/docker-config" TMPDIR="$DIR/tmp" \
    "$DOCKER_BIN" --host "unix://$SOCK" "$@"
}

plan() {
  local line=$PLAN_PREFIX arg
  for arg in "$DOCKER_BIN" --host "unix://$SOCK" "$@"; do
    line="$line$(printf '%q' "$arg") "
  done
  printf '%s\n' "${line% }"
}

engine_identity() {
  local info
  if ! info=$(dk info --format '{{json .}}' 2>"$DIR/engine.stderr"); then
    stop NOT_RUN unit_engine_unavailable "the engine at --engine-socket did not answer docker info"
  fi
  ENGINE_ID=$(printf '%s' "$info" | "$JQ_BIN" -r 'if type == "object" then (.ID // "") else "" end' 2>/dev/null || true)
  [ -n "$ENGINE_ID" ] || stop NOT_RUN unit_engine_unavailable "docker info returned no engine identity"
  ENGINE_JSON=$(printf '%s' "$info" | "$JQ_BIN" -c '{id: .ID, server_version: .ServerVersion, operating_system: .OperatingSystem}')
}

# True only while the live engine is the one the lease was taken on.
engine_unchanged() {
  local info now leased
  leased=$("$JQ_BIN" -r '.engine_id // ""' "$DIR/lease.json" 2>/dev/null) || return 1
  info=$(dk info --format '{{json .}}' 2>/dev/null) || return 1
  now=$(printf '%s' "$info" | "$JQ_BIN" -r '.ID // ""' 2>/dev/null) || return 1
  [ -n "$now" ] && [ -n "$leased" ] && [ "$now" = "$leased" ]
}

# absent KIND REF: 0 when the engine explicitly reports no such object,
# 1 when it exists, 2 when the answer is anything else (unknown is not absent).
absent() {
  if dk "$1" inspect --format '{{.Id}}' "$2" >/dev/null 2>"$DIR/absent.err"; then
    return 1
  fi
  if grep -qi 'no such' "$DIR/absent.err"; then
    return 0
  fi
  return 2
}

# reserve KIND NAME: the engine must explicitly report the name or tag free.
reserve() {
  local rc=0
  absent "$1" "$2" || rc=$?
  case "$rc" in
    0) ;;
    1) stop FAIL resource_conflict "a $1 named $2 already exists and was left untouched" ;;
    *) stop FAIL engine_state_unknown "the engine did not confirm that $2 is free; nothing was created" ;;
  esac
}

# Normalized runtime configuration of an inspected image (empty becomes null).
RUNTIME_CONFIG_JQ='
  def norm: if . == [] or . == {} or . == "" then null else . end;
  (.Config // {})
  | {User, WorkingDir, Env, Entrypoint, Cmd, Volumes, OnBuild, Healthcheck, StopSignal, Shell, ExposedPorts}
  | map_values(norm)'

# Runtime configuration that is never admitted, from a normalized config.
IMAGE_CONFIG_FAILURES_JQ='[
  (if .Volumes == null then empty else "volumes" end),
  (if .OnBuild == null then empty else "onbuild" end),
  (if .Entrypoint == null then empty else "entrypoint" end),
  (if .Healthcheck == null then empty else "healthcheck" end),
  (if .User == "10001:10001" then empty else "user" end),
  (if .WorkingDir == "/src" then empty else "workdir" end)
]'

# image_runtime IMAGE_JSON: prints the normalized config; fails (with the
# reasons on stderr) when it holds implicit volumes or unapproved settings.
image_runtime() {
  local config failures
  config=$(printf '%s' "$1" | "$JQ_BIN" -c "$RUNTIME_CONFIG_JQ") || return 1
  failures=$(printf '%s' "$config" | "$JQ_BIN" -c "$IMAGE_CONFIG_FAILURES_JQ") || return 1
  if [ "$failures" != "[]" ]; then
    printf '%s\n' "$failures" >&2
    return 1
  fi
  printf '%s\n' "$config"
}

# A never-started probe container: created, not running, no network or mounts.
probe_failures() {
  "$JQ_BIN" -c --arg image "$1" '
    def none: . == null or . == [] or . == {};
    . as $c | [
      (if $c.Image == $image then empty else "image" end),
      (if $c.State.Status == "created" and $c.State.Running == false and ($c.State.Pid // 0) == 0
         then empty else "state" end),
      (if $c.Config.Cmd == ["/bin/true"] then empty else "cmd" end),
      (if ($c.Config.Entrypoint | none) then empty else "entrypoint" end),
      (if $c.HostConfig.NetworkMode == "none" then empty else "network" end),
      (if $c.HostConfig.Privileged == false then empty else "privileged" end),
      (if ($c.Mounts | none) and ($c.HostConfig.Binds | none) and ($c.HostConfig.Mounts | none)
          and ($c.HostConfig.VolumesFrom | none) and ($c.Config.Volumes | none)
         then empty else "mounts" end),
      (if ($c.HostConfig.Devices | none) then empty else "devices" end)
    ]'
}

# ── Lease: the only authority for removal ────────────────────────────────────
#
# Every update is written to lease.json.next, validated whole and only then
# renamed over lease.json, so a failed write keeps the previous valid lease.
# Callers check each write: no create follows a failed intent, and nothing
# starts after a failed identity record.

LEASE_SHAPE='
  type == "object" and .schema == $schema and .controller_id == $lcid
  and (.engine_id | type) == "string" and (.engine_id | length) > 0
  and (.command == "build" or .command == "run")
  and (.containers | type) == "array" and (.images | type) == "array"
  and all(.containers[]; type == "object"
      and (.name | type) == "string"
      and (.name | test("\\Ahermes-f02-(freeze|prep|unit)-" + $lcid + "\\z"))
      and (.id == null or ((.id | type) == "string" and (.id | test("\\A[0-9a-f]{64}\\z"))))
      and (.removed | type) == "boolean")
  and all(.images[]; type == "object"
      and (.tag | type) == "string"
      and (.tag | test("\\Ahermes-f02-(unit|cand):" + $lcid + "\\z"))
      and (.id == null or ((.id | type) == "string" and (.id | test("\\Asha256:[0-9a-f]{64}\\z"))))
      and (.removed | type) == "boolean" and (.keep | type) == "boolean")
  and ([.containers[].name] | unique | length) == (.containers | length)
  and ([.images[].tag] | unique | length) == (.images | length)'

# lease_valid FILE CHECK [JQ ARGS]: exactly one well-formed lease satisfying CHECK.
lease_valid() {
  local file=$1 check=$2
  shift 2
  "$JQ_BIN" -e -s "$@" --arg schema "$LEASE_SCHEMA" --arg lcid "$CONTROLLER_ID" \
    "length == 1 and (.[0] | (($LEASE_SHAPE) and ($check)))" "$file" >/dev/null 2>&1
}

lease_publish() {
  local check=$1
  shift
  lease_valid "$DIR/lease.json.next" "$check" "$@" || return 1
  mv -f "$DIR/lease.json.next" "$DIR/lease.json" 2>/dev/null || return 1
  # A rename onto anything but the lease file (for example a directory) is a failure.
  [ -f "$DIR/lease.json" ] && [ ! -L "$DIR/lease.json" ] && lease_valid "$DIR/lease.json" "$check" "$@"
}

# lease_write FILTER CHECK [JQ ARGS]: apply FILTER; publish only if CHECK holds.
lease_write() {
  local filter=$1 check=$2
  shift 2
  "$JQ_BIN" "$@" "$filter" "$DIR/lease.json" > "$DIR/lease.json.next" 2>/dev/null || return 1
  lease_publish "$check" "$@"
}

lease_init() {
  "$JQ_BIN" -n --arg schema "$LEASE_SCHEMA" --arg cid "$CONTROLLER_ID" --arg engine "$ENGINE_ID" \
    --arg command "$COMMAND" \
    '{schema: $schema, controller_id: $cid, engine_id: $engine, command: $command, containers: [], images: []}' \
    > "$DIR/lease.json.next" 2>/dev/null || return 1
  lease_publish '.engine_id == $engine and .containers == [] and .images == []' --arg engine "$ENGINE_ID"
}

lease_container_intent() {
  lease_write '.containers += [{name: $name, id: null, removed: false}]' \
    '[.containers[] | select(.name == $name and .id == null and .removed == false)] | length == 1' \
    --arg name "$1"
}

lease_container_id() {
  lease_write '(.containers[] | select(.name == $name and .id == null) | .id) = $id' \
    '[.containers[] | select(.name == $name and .id == $id)] | length == 1' \
    --arg name "$1" --arg id "$2"
}

lease_image_intent() {
  lease_write '.images += [{tag: $tag, id: null, removed: false, keep: false}]' \
    '[.images[] | select(.tag == $tag and .id == null and .removed == false)] | length == 1' \
    --arg tag "$1"
}

lease_image_id() {
  lease_write '(.images[] | select(.tag == $tag and .id == null) | .id) = $id' \
    '[.images[] | select(.tag == $tag and .id == $id)] | length == 1' \
    --arg tag "$1" --arg id "$2"
}

lease_image_keep() {
  lease_write '(.images[] | select(.tag == $tag) | .keep) = true' \
    '[.images[] | select(.tag == $tag and .keep)] | length == 1' \
    --arg tag "$1"
}

lease_mark_removed() {
  if [ "$1" = container ]; then
    lease_write '(.containers[] | select(.name == $key) | .removed) = true' \
      '[.containers[] | select(.name == $key and .removed)] | length == 1' --arg key "$2"
  else
    lease_write '(.images[] | select(.tag == $key) | .removed) = true' \
      '[.images[] | select(.tag == $key and .removed)] | length == 1' --arg key "$2"
  fi
}

# quarantine KIND REF REASON: KIND container, image or lease; REASON
# unrecorded_identity, unverified_removal, engine_changed or lease_unreadable.
quarantine() {
  local obj
  obj="{\"kind\":$(json_string "$1"),\"ref\":$(json_string "$2"),\"reason\":$(json_string "$3")}"
  case ",$QUARANTINE," in *",$obj,"*) return 0 ;; esac
  if [ -n "$QUARANTINE" ]; then QUARANTINE="$QUARANTINE,$obj"; else QUARANTINE=$obj; fi
}

# create_container NAME ARGS...: reserve the name, publish the intent, create,
# then publish the exact id the engine returned. Sets CREATED_ID. An unknown
# reply leaves the intent quarantined; an id that cannot be recorded is
# quarantined by its exact value and never started or removed.
create_container() {
  local name=$1 out id=""
  shift
  CREATED_ID=""
  reserve container "$name"
  lease_container_intent "$name" \
    || stop FAIL journal_unwritable "the container creation intent could not be recorded; nothing was created"
  if out=$(dk create --name "$name" --label "hermes.f02.controller=$CONTROLLER_ID" "$@" 2>>"$DIR/engine.stderr"); then
    id=$(printf '%s\n' "$out" | tail -n 1)
  fi
  matches "$id" "$HEX64_RE" \
    || stop FAIL creation_identity_unknown "the engine returned no container id for $name; the intent is quarantined"
  if ! lease_container_id "$name" "$id"; then
    quarantine container "$id" unrecorded_identity
    stop FAIL journal_unwritable "the created container id could not be recorded; it is quarantined and not started"
  fi
  CREATED_ID=$id
}

# record_image_identity TAG ID: the reply must be an exact image id.
record_image_identity() {
  matches "$2" "$IMAGE_ID_RE" \
    || stop FAIL creation_identity_unknown "the engine returned no image id for $1; the tag is quarantined"
  if ! lease_image_id "$1" "$2"; then
    quarantine image "$2" unrecorded_identity
    stop FAIL journal_unwritable "the created image id could not be recorded; it is quarantined"
  fi
}

# Remove one container by its recorded id; 0 only when the engine confirms it is gone.
remove_container() {
  dk container rm -f "$1" >/dev/null 2>>"$DIR/engine.stderr" || true
  absent container "$1"
}

# Remove one recorded tag while it still names the recorded id (never parent
# images: --no-prune), then confirm the tag and that id are gone. An image
# that is shared or retagged elsewhere stays and is reported.
remove_image_tag() {
  local tag=$1 id=$2 now rc=0
  absent image "$tag" || rc=$?
  if [ "$rc" -eq 1 ]; then
    now=$(dk image inspect --format '{{.Id}}' "$tag" 2>/dev/null) || return 1
    [ "$now" = "$id" ] || return 1
    dk image rm --no-prune "$tag" >/dev/null 2>>"$DIR/engine.stderr" || true
    absent image "$tag" || return 1
  elif [ "$rc" -ne 0 ]; then
    return 1
  fi
  absent image "$id"
}

# dispose_container NAME ID WHAT: remove a probe now; the lease retries at exit.
dispose_container() {
  remove_container "$2" || stop FAIL unit_cleanup_unverified "the $3 container could not be verified removed"
  lease_mark_removed container "$1" || stop FAIL journal_unwritable "a verified removal could not be recorded in the lease"
}

finish_cleanup() {
  local verified=false
  if [ "$1" = true ] && [ "$2" = true ] && [ -z "$QUARANTINE" ]; then verified=true; fi
  CLEANUP_JSON="{\"container_removed\":$1,\"candidate_image_removed\":$2,\"verified\":$verified,\"quarantine\":[${QUARANTINE}]}"
  [ "$verified" = true ] || settle FAIL unit_cleanup_unverified "recorded resources could not be verified removed; see quarantine"
}

CLEANED=0
cleanup_lease() {
  [ "$CLEANED" -eq 0 ] || return 0
  CLEANED=1
  [ -f "$DIR/lease.json" ] || return 0
  local containers_ok=true images_ok=true entries kind name id
  if ! lease_valid "$DIR/lease.json" true; then
    quarantine lease lease.json lease_unreadable
    finish_cleanup false false
    return 0
  fi
  if ! engine_unchanged; then
    entries=$("$JQ_BIN" -r '(.containers[] | select(.removed | not) | "container \(.id // .name)"),
      (.images[] | select((.removed or .keep) | not) | "image \(.tag)")' "$DIR/lease.json")
    while read -r kind name; do
      if [ -n "$kind" ]; then quarantine "$kind" "$name" engine_changed; fi
    done <<EOF
$entries
EOF
    finish_cleanup false false
    settle FAIL engine_identity_changed "the engine identity changed or is unreachable; nothing was removed"
    return 0
  fi
  entries=$("$JQ_BIN" -r '.containers[] | select(.removed | not) | "\(.name) \(.id // "null")"' "$DIR/lease.json")
  while read -r name id; do
    [ -n "$name" ] || continue
    if ! matches "$id" "$HEX64_RE"; then
      quarantine container "$name" unrecorded_identity
      containers_ok=false
    elif remove_container "$id"; then
      lease_mark_removed container "$name" || settle FAIL journal_unwritable "a verified removal could not be recorded in the lease"
    else
      quarantine container "$id" unverified_removal
      containers_ok=false
    fi
  done <<EOF
$entries
EOF
  entries=$("$JQ_BIN" -r '.images[] | select((.removed or .keep) | not) | "\(.tag) \(.id // "null")"' "$DIR/lease.json")
  while read -r name id; do
    [ -n "$name" ] || continue
    if ! matches "$id" "$IMAGE_ID_RE"; then
      quarantine image "$name" unrecorded_identity
      images_ok=false
    elif remove_image_tag "$name" "$id"; then
      lease_mark_removed image "$name" || settle FAIL journal_unwritable "a verified removal could not be recorded in the lease"
    else
      quarantine image "$name" unverified_removal
      images_ok=false
    fi
  done <<EOF
$entries
EOF
  finish_cleanup "$containers_ok" "$images_ok"
}

on_signal() {
  INTERRUPTED=$1
  if [ -n "$UNIT_CID" ]; then
    dk container kill "$UNIT_CID" >/dev/null 2>&1 || true
  fi
}

check_interrupt() {
  [ -z "$INTERRUPTED" ] || stop FAIL interrupted "signal $INTERRUPTED received"
}

# Every exit: settle unexpected failures, remove what the lease recorded (only
# once an engine identity is known), then emit exactly one result.
on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  if [ "$EMITTED" -eq 0 ]; then
    if [ "$rc" -ne 0 ]; then
      settle FAIL controller_error "the controller stopped unexpectedly near line ${ERR_LINE:-unknown}"
    fi
    if [ -n "$INTERRUPTED" ]; then
      settle FAIL interrupted "signal $INTERRUPTED received"
    fi
    if [ "$JQ_READY" -eq 1 ] && [ -n "$ENGINE_ID" ] && [ -f "${DIR:-/nonexistent}/lease.json" ]; then
      cleanup_lease || true
    fi
    emit_result
  fi
  exit "${FINAL_CODE:-1}"
}

# ── build ─────────────────────────────────────────────────────────────────────

do_build() {
  local recipe recipe_tree inputs current tag image_id image_json layers runtime failures
  local freeze_name freeze_cid probe freeze_sha
  matches "$BASE_IMAGE" "$BASE_IMAGE_RE" || stop REFUSED base_image_unpinned "--base-image must be NAME@sha256:<64hex>"
  # The recipe commit is captured once; every later read uses it, never HEAD.
  recipe=$(git_plumb rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || recipe=""
  matches "$recipe" "$HEX40_RE" || stop REFUSED recipe_dirty "the controller checkout has no HEAD commit"
  recipe_tree=$(git_plumb rev-parse --verify "$recipe^{tree}" 2>/dev/null) || recipe_tree=""
  matches "$recipe_tree" "$HEX40_RE" || stop REFUSED recipe_dirty "the recipe commit has no readable tree"
  # shellcheck disable=SC2086
  materialize_tree "$recipe" "$DIR/context" $RECIPE_PATHS \
    || stop REFUSED recipe_dirty "the recipe files cannot be read from the recipe commit"
  inputs=$(recipe_inputs "$DIR/context") || stop REFUSED recipe_dirty "the recipe commit lacks a regular recipe file"
  current=$(recipe_inputs "$REPO") || stop REFUSED recipe_dirty "a recipe file in the checkout is missing or not a regular file"
  json_equal "$inputs" "$current" || stop REFUSED recipe_dirty "recipe files differ from the recipe commit"
  tag="hermes-f02-unit:$CONTROLLER_ID"
  freeze_name="hermes-f02-freeze-$CONTROLLER_ID"
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    plan image inspect --format '{{.Id}}' "$tag"
    plan build --iidfile "$DIR/build.iid" --file "$DIR/context/scripts/multiuser_unit.Dockerfile" \
      --build-arg "MU_BASE_IMAGE=$BASE_IMAGE" --tag "$tag" --label "hermes.f02.controller=$CONTROLLER_ID" "$DIR/context"
    plan image inspect --format '{{json .}}' "$tag"
    plan container inspect --format '{{.Id}}' "$freeze_name"
    plan create --name "$freeze_name" --label "hermes.f02.controller=$CONTROLLER_ID" \
      --network none "<unit-image-id>" /bin/true
    plan container inspect --format '{{json .}}' "<freeze-id>"
    plan cp "<freeze-id>:/opt/mu/freeze.txt" -
    plan container rm -f "<freeze-id>"
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi
  engine_identity
  lease_init || stop FAIL journal_unwritable "the lease could not be created; nothing was created"
  reserve image "$tag"
  lease_image_intent "$tag" || stop FAIL journal_unwritable "the image creation intent could not be recorded; nothing was built"
  if ! dk build --iidfile "$DIR/build.iid" --file "$DIR/context/scripts/multiuser_unit.Dockerfile" \
      --build-arg "MU_BASE_IMAGE=$BASE_IMAGE" --tag "$tag" --label "hermes.f02.controller=$CONTROLLER_ID" \
      "$DIR/context" > "$DIR/build.log" 2>&1; then
    stop FAIL build_failed "docker build failed; see build.log"
  fi
  image_id=$(cat "$DIR/build.iid" 2>/dev/null) || image_id=""
  record_image_identity "$tag" "$image_id"
  image_json=$(dk image inspect --format '{{json .}}' "$tag" 2>/dev/null) || stop FAIL build_failed "the built image cannot be inspected"
  [ "$(printf '%s' "$image_json" | "$JQ_BIN" -r '.Id')" = "$image_id" ] || stop FAIL build_failed "the unit image tag does not name the built image"
  layers=$(printf '%s' "$image_json" | "$JQ_BIN" -c '.RootFS.Layers')
  # Implicit volumes or an unapproved configuration refuse before any create.
  runtime=$(image_runtime "$image_json" 2>"$DIR/image-config.err") \
    || stop FAIL unit_image_config_refused "the unit image declares volumes or an unapproved runtime configuration"
  create_container "$freeze_name" --network none "$image_id" /bin/true
  freeze_cid=$CREATED_ID
  probe=$(dk container inspect --format '{{json .}}' "$freeze_cid" 2>/dev/null) \
    || stop FAIL probe_admission_failed "the freeze probe cannot be inspected"
  failures=$(printf '%s' "$probe" | probe_failures "$image_id") || failures='["inspect_unreadable"]'
  [ "$failures" = "[]" ] || stop FAIL probe_admission_failed "the freeze probe is not a never-started, network-less container"
  dk cp "$freeze_cid:/opt/mu/freeze.txt" - > "$DIR/freeze.tar" 2>>"$DIR/engine.stderr" \
    || stop FAIL build_failed "freeze.txt could not be read"
  mkdir -m 700 "$DIR/freeze"
  tar -xf "$DIR/freeze.tar" -C "$DIR/freeze"
  freeze_sha=$(sha256_file "$DIR/freeze/freeze.txt")
  dispose_container "$freeze_name" "$freeze_cid" "freeze probe"
  lease_image_keep "$tag" || stop FAIL journal_unwritable "the unit image could not be recorded as kept"
  RECIPE_JSON=$("$JQ_BIN" -cn --arg commit "$recipe" --arg tree "$recipe_tree" --arg base "$BASE_IMAGE" \
    --argjson inputs "$inputs" --arg tag "$tag" --arg id "$image_id" --argjson layers "$layers" \
    --argjson runtime "$runtime" --arg freeze "$freeze_sha" \
    '{commit: $commit, tree: $tree, base_image: $base, inputs: $inputs, unit_image_tag: $tag,
      unit_image_id: $id, unit_layers: $layers, runtime_config: $runtime, freeze_sha256: $freeze}')
  settle PASS
}

# ── run ───────────────────────────────────────────────────────────────────────

# The worker mode and proof tier the request asks for, from the launcher
# options before the worker's own `--`. Anything not recognized exactly
# (including --opt=value forms and repeats) makes the request unknown, which
# can never PASS.
derive_request() {
  local n=${#WORKER_ARGS[@]} i=0 a self=0 no_agent=0 agent=0 script=0 tier="" bad=0 seen=" "
  while [ "$i" -lt "$n" ]; do
    a=${WORKER_ARGS[$i]}
    case "$seen" in *" $a "*) bad=1 ;; esac
    case "$a" in
      --) break ;;
      --self-test) self=1 ;;
      --no-agent) no_agent=1 ;;
      --agent-checkout|--script|--tier|--host-os|--backend|--deployment-manifest|--child-timeout)
        if [ $((i + 1)) -ge "$n" ]; then bad=1; break; fi
        i=$((i + 1))
        case "${WORKER_ARGS[$i]}" in -*) bad=1 ;; esac
        case "$a" in
          --agent-checkout) agent=1 ;;
          --script) script=1 ;;
          --tier) tier=${WORKER_ARGS[$i]} ;;
        esac
        ;;
      *) bad=1 ;;
    esac
    seen="$seen$a "
    i=$((i + 1))
  done
  case "$tier" in ''|unit|native|browser|containment|remote) ;; *) bad=1 ;; esac
  if [ "$bad" -eq 1 ]; then
    REQ_MODE=unknown
    REQ_TIER=unknown
  elif [ "$self" -eq 1 ]; then
    REQ_MODE=self-test
    REQ_TIER=self-test
  elif [ "$script" -eq 1 ]; then
    REQ_MODE=script
    REQ_TIER=${tier:-browser}
  else
    REQ_MODE=pytest
    if [ -n "$tier" ]; then REQ_TIER=$tier
    elif [ "$agent" -eq 1 ]; then REQ_TIER=native
    elif [ "$no_agent" -eq 1 ]; then REQ_TIER=unit
    else REQ_TIER=unknown
    fi
  fi
  REQUEST_JSON=$("$JQ_BIN" -cn --arg mode "$REQ_MODE" --arg tier "$REQ_TIER" \
    '{mode: $mode, tier: $tier, worker_args: $ARGS.positional}' --args -- ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"})
}

EVIDENCE_JQ='
  def hex($n): type == "string" and test("\\A[0-9a-f]{" + ($n | tostring) + "}\\z");
  def image_id: type == "string" and test("\\Asha256:[0-9a-f]{64}\\z");
  . as $e
  | ($e | type) == "object"
    and $e.schema == $schema and $e.command == "build" and $e.status == "PASS" and $e.exit_code == 0
    and $e.reasons == [] and $e.dry_run == false
    and ($sim or $e.docker_bin_substituted == false)
    and ($e.controller_id | type) == "string"
    and ($e.controller_id | test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z"))
    and ($e.engine | type) == "object" and ($e.engine.id | type) == "string" and ($e.engine.id | length) > 0
    and ($e.cleanup | type) == "object" and $e.cleanup.verified == true and $e.cleanup.quarantine == []
    and ($e.recipe | type) == "object" and ($e.recipe | keys) == ($rkeys | sort)
    and ($e.recipe.commit | hex(40)) and ($e.recipe.tree | hex(40))
    and ($e.recipe.base_image | type) == "string"
    and ($e.recipe.base_image | test("\\A[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\\z"))
    and ($e.recipe.inputs | type) == "object" and ($e.recipe.inputs | keys) == ($paths | sort)
    and all($e.recipe.inputs[]; hex(64))
    and $e.recipe.unit_image_tag == ("hermes-f02-unit:" + $e.controller_id)
    and ($e.recipe.unit_image_id | image_id) and $e.recipe.unit_image_id == $image
    and ($e.recipe.unit_layers | type) == "array" and ($e.recipe.unit_layers | length) > 0
    and all($e.recipe.unit_layers[]; image_id)
    and ($e.recipe.runtime_config | type) == "object" and ($e.recipe.runtime_config | keys) == ($ckeys | sort)
    and ($e.recipe.freeze_sha256 | hex(64))'

ev() {
  "$JQ_BIN" -c "$1" "$DIR/runtime-evidence.json"
}

ev_raw() {
  "$JQ_BIN" -r "$1" "$DIR/runtime-evidence.json"
}

# The prior successful build result: trusted controller output in a private
# directory, copied once and validated without the engine. It must bind this
# --image-id, a recipe commit in this checkout whose blobs give the recorded
# digests, and the recipe files this controller would build from now.
admit_runtime_evidence() {
  local f=$RUNTIME_EVIDENCE parent size inputs current
  case "$f" in *$'\n'*) stop REFUSED runtime_evidence_refused "--runtime-evidence must not contain a newline" ;; esac
  is_abs "$f" || stop REFUSED runtime_evidence_refused "--runtime-evidence must be an absolute path"
  if [ -L "$f" ] || [ ! -f "$f" ] || [ ! -O "$f" ]; then
    stop REFUSED runtime_evidence_refused "--runtime-evidence is not a regular file owned by this user"
  fi
  [ -n "$(find "$f" -maxdepth 0 -perm 0600 -print)" ] || stop REFUSED runtime_evidence_refused "--runtime-evidence is not mode 0600"
  parent=$(dirname "$f")
  if ! private_dir "$parent" || [ -z "$(find "$parent" -maxdepth 0 -perm 0700 -print)" ]; then
    stop REFUSED runtime_evidence_refused "the --runtime-evidence directory is not a private 0700 canonical directory"
  fi
  size=$(wc -c < "$f" | tr -d ' ')
  [ "$size" -le "$MAX_EVIDENCE_BYTES" ] || stop REFUSED runtime_evidence_refused "--runtime-evidence exceeds 1 MiB"
  cat "$f" > "$DIR/runtime-evidence.json" 2>/dev/null || stop REFUSED runtime_evidence_refused "--runtime-evidence cannot be read"
  size=$(wc -c < "$DIR/runtime-evidence.json" | tr -d ' ')
  [ "$size" -le "$MAX_EVIDENCE_BYTES" ] || stop REFUSED runtime_evidence_refused "--runtime-evidence exceeds 1 MiB"
  if ! "$JQ_BIN" -e -s --arg schema "$SCHEMA" --arg image "$IMAGE_ID" --argjson sim "$DOCKER_SUBSTITUTED" \
      --argjson rkeys "$RECIPE_KEYS_JSON" --argjson ckeys "$RUNTIME_KEYS_JSON" --argjson paths "$RECIPE_PATHS_JSON" \
      "length == 1 and (.[0] | $EVIDENCE_JQ)" "$DIR/runtime-evidence.json" >/dev/null 2>&1; then
    stop REFUSED runtime_evidence_invalid "--runtime-evidence is not a successful, verified build result for --image-id"
  fi
  [ "$(git_plumb cat-file -t "$(ev_raw .recipe.commit)" 2>/dev/null || true)" = commit ] \
    || stop REFUSED runtime_evidence_invalid "the evidence recipe commit is not a commit in this checkout"
  [ "$(git_plumb rev-parse --verify "$(ev_raw .recipe.commit)^{tree}" 2>/dev/null || true)" = "$(ev_raw .recipe.tree)" ] \
    || stop REFUSED runtime_evidence_invalid "the evidence recipe tree does not match its commit"
  # shellcheck disable=SC2086
  materialize_tree "$(ev_raw .recipe.commit)" "$DIR/recipe" $RECIPE_PATHS \
    || stop REFUSED runtime_evidence_invalid "the evidence recipe files cannot be read from its commit"
  inputs=$(recipe_inputs "$DIR/recipe") || stop REFUSED runtime_evidence_invalid "the evidence recipe commit lacks a recipe file"
  json_equal "$inputs" "$(ev .recipe.inputs)" \
    || stop REFUSED runtime_evidence_invalid "the evidence recipe digests do not match its commit"
  current=$(recipe_inputs "$REPO") || stop REFUSED runtime_evidence_invalid "a recipe file in the checkout is missing"
  json_equal "$current" "$(ev .recipe.inputs)" \
    || stop REFUSED runtime_evidence_invalid "the evidence is stale: the checkout recipe differs from the built recipe"
  RUNTIME_EVIDENCE_JSON=$("$JQ_BIN" -c --arg path "$f" --arg sha "$(sha256_file "$DIR/runtime-evidence.json")" \
    '{path: $path, sha256: $sha, build_controller_id: .controller_id, recipe_commit: .recipe.commit,
      recipe_tree: .recipe.tree, base_image: .recipe.base_image, unit_image_id: .recipe.unit_image_id,
      freeze_sha256: .recipe.freeze_sha256}' "$DIR/runtime-evidence.json")
  RECIPE_JSON=$(ev '{unit_image_id: .recipe.unit_image_id, unit_layers: .recipe.unit_layers}')
}

# Tree manifest that never follows links: one line per directory, link
# (with its target text) and regular file (with its SHA-256). The unit's
# /src/.venv link is the only expected extra entry and is left out.
tree_manifest() {
  local root=$1 hasher=/usr/bin/sha256sum
  [ -x /usr/bin/shasum ] && hasher="/usr/bin/shasum -a 256"
  (
    cd "$root"
    find . -mindepth 1 ! -path './.venv' -type d -print | sed 's/^/D /'
    find . -mindepth 1 ! -path './.venv' -type l -print | while IFS= read -r p; do
      printf 'L %s %s\n' "$p" "$(readlink "$p")"
    done
    # shellcheck disable=SC2086
    find . -mindepth 1 -type f -exec $hasher {} + | awk '{ h = $1; sub(/^[0-9a-f]+  /, ""); print "F " $0 " " h }'
  ) | sort
}

admission_failures() {
  "$JQ_BIN" -c --arg image "$1" --argjson argv "$2" --argjson imgenv "$3" --argjson unitenv "$4" \
    --arg tmp "$TMPFS_TMP" --arg state "$TMPFS_STATE" \
    --argjson pids "$PIDS_LIMIT" --argjson memory "$MEMORY_BYTES" --argjson cpus "$NANO_CPUS" '
    def none: . == null or . == [] or . == {};
    . as $c
    | ($tmp | split(":")) as $t | ($state | split(":")) as $s
    | [
      (if $c.Image == $image then empty else "image" end),
      (if $c.Config.User == "10001:10001" then empty else "user" end),
      (if $c.Config.WorkingDir == "/src" then empty else "workdir" end),
      (if $c.Config.Cmd == $argv then empty else "cmd" end),
      (if ($c.Config.Entrypoint | none) then empty else "entrypoint" end),
      (if (($c.Config.Env // []) | sort) == (($imgenv + $unitenv) | sort) then empty else "env" end),
      (if ($c.Config.Volumes | none) then empty else "volumes" end),
      (if $c.HostConfig.ReadonlyRootfs == true then empty else "read_only_rootfs" end),
      (if $c.HostConfig.NetworkMode == "none" then empty else "network" end),
      (if $c.HostConfig.Privileged == false then empty else "privileged" end),
      (if (($c.HostConfig.CapDrop // []) | index("ALL")) != null then empty else "cap_drop" end),
      (if ($c.HostConfig.CapAdd | none) then empty else "cap_add" end),
      (if ([($c.HostConfig.SecurityOpt // [])[] | select(. == "no-new-privileges" or . == "no-new-privileges:true")] | length) > 0
         then empty else "no_new_privileges" end),
      (if ($c.HostConfig.PidMode // "") == "" then empty else "pid_mode" end),
      (if $c.HostConfig.IpcMode == "private" then empty else "ipc_mode" end),
      (if ($c.HostConfig.UTSMode // "") == "" then empty else "uts_mode" end),
      (if ($c.HostConfig.UsernsMode // "") == "" then empty else "userns_mode" end),
      (if ($c.HostConfig.CgroupnsMode // "") != "host" then empty else "cgroupns_mode" end),
      (if ($c.HostConfig.Binds | none) then empty else "binds" end),
      (if ($c.HostConfig.Mounts | none) then empty else "host_mounts" end),
      (if ($c.Mounts | none) then empty else "mounts" end),
      (if ($c.HostConfig.Devices | none) then empty else "devices" end),
      (if ($c.HostConfig.DeviceRequests | none) then empty else "device_requests" end),
      (if ($c.HostConfig.VolumesFrom | none) then empty else "volumes_from" end),
      (if ($c.HostConfig.Links | none) then empty else "links" end),
      (if ($c.HostConfig.ExtraHosts | none) then empty else "extra_hosts" end),
      (if ($c.HostConfig.Tmpfs // {}) == {($t[0]): ($t[1:] | join(":")), ($s[0]): ($s[1:] | join(":"))}
         then empty else "tmpfs" end),
      (if $c.HostConfig.PidsLimit == $pids then empty else "pids_limit" end),
      (if $c.HostConfig.Memory == $memory and $c.HostConfig.MemorySwap == $memory then empty else "memory" end),
      (if $c.HostConfig.NanoCpus == $cpus then empty else "cpus" end),
      (if ($c.HostConfig.RestartPolicy.Name // "") == "no" then empty else "restart" end),
      (if ($c.HostConfig.AutoRemove // false) == false then empty else "auto_remove" end),
      (if ($c.HostConfig.Init // false) == false then empty else "init" end)
    ]'
}

attested_from() {
  printf '%s' "$1" | "$JQ_BIN" -c '
    . as $f | def ok($k): ($f | index($k)) == null;
    {network_none: ok("network"), read_only_rootfs: ok("read_only_rootfs"), non_root: ok("user"),
     no_mounts: (ok("binds") and ok("host_mounts") and ok("mounts") and ok("volumes") and ok("devices") and ok("tmpfs")),
     caps_dropped: (ok("cap_drop") and ok("cap_add") and ok("privileged")),
     no_new_privileges: ok("no_new_privileges"),
     private_pid: (ok("pid_mode") and ok("ipc_mode") and ok("uts_mode") and ok("userns_mode")),
     resource_limits: (ok("pids_limit") and ok("memory") and ok("cpus") and ok("restart"))}'
}

# The worker result must match the unit exit, identity and requested work. A
# PASS needs the requested (known) mode and tier and that mode's own positive
# evidence; a non-PASS is an early denial (no mode) or reports the request.
validate_worker_result() {
  "$JQ_BIN" -e --argjson exit "$1" --arg uid "$CONTROLLER_ID" --arg nonce "$UNIT_NONCE" --arg schema "$WORKER_SCHEMA" \
    --arg mode "$REQ_MODE" --arg tier "$REQ_TIER" '
    def nonneg: type == "number" and . >= 0 and . == floor;
    def codes: {"PASS": 0, "FAIL": 1, "REFUSED": 2, "NOT_RUN": 3};
    . as $r
    | ($r | type) == "object"
      and $r.schema == $schema
      and (codes | has($r.status // ""))
      and codes[$r.status] == $r.exit_code
      and $r.exit_code == $exit
      and ($r.unit | type) == "object" and $r.unit.id == $uid and $r.unit.nonce == $nonce
      and ($r.claims | type) == "object" and ([$r.claims[]] | all(. == false))
      and ($r.reasons | type) == "array"
      and ($r.status != "PASS" or ($r.reasons | length) == 0)
      and ($r.tests == null
           or (($r.tests | type) == "object"
               and ($r.tests.total | nonneg) and ($r.tests.passed | nonneg) and ($r.tests.failed | nonneg)
               and ($r.tests.errors | nonneg) and ($r.tests.skipped | nonneg)
               and $r.tests.total == ($r.tests.passed + $r.tests.failed + $r.tests.errors + $r.tests.skipped)))
      and (($r.mode == null) == ($r.tier == null))
      and ($r.mode == null or (["pytest", "script", "self-test"] | index($r.mode)) != null)
      and (if $r.status == "PASS" then
             $mode != "unknown" and $tier != "unknown" and $r.mode == $mode and $r.tier == $tier
             and (if $mode == "pytest" then
                    ($r.tests | type) == "object" and $r.tests.total > 0 and $r.tests.passed == $r.tests.total
                    and $r.tests.skipped == 0 and $r.tests.failed == 0 and $r.tests.errors == 0
                  elif $mode == "self-test" then
                    $r.tests == null and ($r.checks | type) == "array" and ($r.checks | length) > 0
                    and all($r.checks[]; type == "object" and .status == "PASS")
                  else $r.tests == null end)
           else $r.mode == null or ($r.mode == $mode and $r.tier == $tier) end)
  ' >/dev/null 2>&1
}

do_run() {
  local unit_json unit_id unit_layers live_runtime ev_runtime cand_tag cand_id cand_json cand_layers img_env
  local candidate_tree archive_sha prep_name prep_cid probe out unit_name argv_json unit_env_json inspect failures
  local attested started=false exit_code="" timed_out=false oom=false post_ok=false watchdog wait_pid
  local stdout_size count last worker_line worker_status
  matches "$IMAGE_ID" "$IMAGE_ID_RE" || stop REFUSED usage "--image-id must be sha256:<64hex>"
  matches "$CANDIDATE" "$HEX40_RE" || stop REFUSED candidate_invalid "--candidate must be a full 40-hex commit"
  case "$TIMEOUT" in ''|*[!0-9]*) stop REFUSED usage "--timeout must be an integer" ;; esac
  [ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 86400 ] || stop REFUSED usage "--timeout must be between 1 and 86400"
  derive_request
  [ "$(git_plumb cat-file -t "$CANDIDATE" 2>/dev/null || true)" = commit ] \
    || stop REFUSED candidate_invalid "--candidate is not a commit in the controller checkout"
  candidate_tree=$(git_plumb rev-parse --verify "$CANDIDATE^{tree}" 2>/dev/null) || candidate_tree=""
  matches "$candidate_tree" "$HEX40_RE" || stop REFUSED candidate_invalid "--candidate has no readable tree"
  admit_runtime_evidence
  cand_tag="hermes-f02-cand:$CONTROLLER_ID"
  prep_name="hermes-f02-prep-$CONTROLLER_ID"
  unit_name="hermes-f02-unit-$CONTROLLER_ID"
  argv_json=$("$JQ_BIN" -cn '$ARGS.positional' --args -- python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"})
  unit_env_json=$("$JQ_BIN" -cn '$ARGS.positional' --args -- "HERMES_MU_UNIT_ID=$CONTROLLER_ID" \
    "HERMES_MU_UNIT_NONCE=$UNIT_NONCE" "HERMES_MU_UNIT_SRC=$UNIT_SRC" "HERMES_MU_UNIT_STATE=$UNIT_STATE")
  img_env=$(ev '.recipe.runtime_config.Env // []')

  # Immutable source: the exact commit's blobs, materialized once, archived,
  # hashed and later compared against what the unit sees.
  materialize_tree "$CANDIDATE" "$DIR/src-expected" \
    || stop REFUSED candidate_invalid "the candidate tree holds a gitlink, an unsafe path or an unsupported entry"
  tar_create "$DIR/src-expected" "$DIR/candidate.tar" || stop FAIL snapshot_mismatch "the candidate snapshot could not be archived"
  archive_sha=$(sha256_file "$DIR/candidate.tar")
  mkdir -m 700 "$DIR/src-actual"

  set -- --user "$UNIT_USER" --read-only --network none --ipc private --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit "$PIDS_LIMIT" --memory 2g --memory-swap 2g --cpus 2 \
    --restart no --tmpfs "$TMPFS_TMP" --tmpfs "$TMPFS_STATE" \
    --env "HERMES_MU_UNIT_ID=$CONTROLLER_ID" --env "HERMES_MU_UNIT_NONCE=$UNIT_NONCE" \
    --env "HERMES_MU_UNIT_SRC=$UNIT_SRC" --env "HERMES_MU_UNIT_STATE=$UNIT_STATE" \
    --workdir "$UNIT_SRC"
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    plan image inspect --format '{{json .}}' "$IMAGE_ID"
    plan container inspect --format '{{.Id}}' "$prep_name"
    plan create --name "$prep_name" --label "hermes.f02.controller=$CONTROLLER_ID" --network none "$IMAGE_ID" /bin/true
    plan container inspect --format '{{json .}}' "<prep-id>"
    plan cp "<prep-id>:/opt/mu/freeze.txt" -
    plan cp - "<prep-id>:$UNIT_SRC"
    plan image inspect --format '{{.Id}}' "$cand_tag"
    plan commit --change "USER $UNIT_USER" --change "WORKDIR $UNIT_SRC" "<prep-id>" "$cand_tag"
    plan container rm -f "<prep-id>"
    plan image inspect --format '{{json .}}' "$cand_tag"
    plan container inspect --format '{{.Id}}' "$unit_name"
    plan create --name "$unit_name" --label "hermes.f02.controller=$CONTROLLER_ID" "$@" "<cand-id>" \
      python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"}
    plan container inspect --format '{{json .}}' "<unit-id>"
    plan cp "<unit-id>:$UNIT_SRC" -
    plan container start "<unit-id>"
    plan container wait "<unit-id>"
    plan container logs "<unit-id>"
    plan container inspect --format '{{json .}}' "<unit-id>"
    plan container rm -f "<unit-id>"
    plan image rm --no-prune "$cand_tag"
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi

  engine_identity
  [ "$(ev_raw .engine.id)" = "$ENGINE_ID" ] \
    || stop REFUSED runtime_evidence_mismatch "the build evidence was taken on a different engine"
  lease_init || stop FAIL journal_unwritable "the lease could not be created; nothing was created"

  # The live unit image must be the recorded one before anything is created.
  unit_json=$(dk image inspect --format '{{json .}}' "$IMAGE_ID" 2>/dev/null) \
    || stop NOT_RUN unit_image_mismatch "--image-id is not present on this engine"
  unit_id=$(printf '%s' "$unit_json" | "$JQ_BIN" -r '.Id') || unit_id=""
  [ "$unit_id" = "$IMAGE_ID" ] || stop FAIL runtime_evidence_mismatch "the engine reported a different image id"
  unit_layers=$(printf '%s' "$unit_json" | "$JQ_BIN" -c '.RootFS.Layers') || unit_layers=null
  json_equal "$unit_layers" "$(ev .recipe.unit_layers)" \
    || stop FAIL runtime_evidence_mismatch "the unit image layers differ from the build evidence"
  live_runtime=$(image_runtime "$unit_json" 2>"$DIR/image-config.err") \
    || stop FAIL unit_image_config_refused "the unit image declares volumes or an unapproved runtime configuration"
  ev_runtime=$(ev .recipe.runtime_config)
  json_equal "$live_runtime" "$ev_runtime" \
    || stop FAIL runtime_evidence_mismatch "the unit image runtime configuration differs from the build evidence"

  # One never-started probe reads the actual freeze record before the
  # snapshot goes in; a mismatch stops here and only the probe is disposed.
  create_container "$prep_name" --network none "$IMAGE_ID" /bin/true
  prep_cid=$CREATED_ID
  probe=$(dk container inspect --format '{{json .}}' "$prep_cid" 2>/dev/null) \
    || stop FAIL probe_admission_failed "the prep container cannot be inspected"
  failures=$(printf '%s' "$probe" | probe_failures "$IMAGE_ID") || failures='["inspect_unreadable"]'
  [ "$failures" = "[]" ] || stop FAIL probe_admission_failed "the prep container is not a never-started, network-less container"
  dk cp "$prep_cid:/opt/mu/freeze.txt" - > "$DIR/prep-freeze.tar" 2>>"$DIR/engine.stderr" \
    || stop FAIL runtime_evidence_mismatch "the unit image freeze record cannot be read"
  mkdir -m 700 "$DIR/prep-freeze"
  tar -xf "$DIR/prep-freeze.tar" -C "$DIR/prep-freeze" 2>/dev/null \
    || stop FAIL runtime_evidence_mismatch "the unit image freeze record cannot be read"
  [ -f "$DIR/prep-freeze/freeze.txt" ] && [ ! -L "$DIR/prep-freeze/freeze.txt" ] \
    && [ "$(sha256_file "$DIR/prep-freeze/freeze.txt")" = "$(ev_raw .recipe.freeze_sha256)" ] \
    || stop FAIL runtime_evidence_mismatch "the unit image freeze record differs from the build evidence"

  dk cp - "$prep_cid:$UNIT_SRC" < "$DIR/candidate.tar" 2>>"$DIR/engine.stderr" \
    || stop FAIL snapshot_mismatch "the candidate snapshot could not be copied in"
  reserve image "$cand_tag"
  lease_image_intent "$cand_tag" || stop FAIL journal_unwritable "the image creation intent could not be recorded; nothing was committed"
  cand_id=""
  if out=$(dk commit --change "USER $UNIT_USER" --change "WORKDIR $UNIT_SRC" "$prep_cid" "$cand_tag" 2>>"$DIR/engine.stderr"); then
    cand_id=$(printf '%s\n' "$out" | tail -n 1)
  fi
  record_image_identity "$cand_tag" "$cand_id"
  dispose_container "$prep_name" "$prep_cid" "prep"
  cand_json=$(dk image inspect --format '{{json .}}' "$cand_tag" 2>/dev/null) \
    || stop FAIL snapshot_mismatch "the candidate image cannot be inspected"
  [ "$(printf '%s' "$cand_json" | "$JQ_BIN" -r '.Id')" = "$cand_id" ] || stop FAIL snapshot_mismatch "the candidate tag moved"
  cand_layers=$(printf '%s' "$cand_json" | "$JQ_BIN" -c '.RootFS.Layers')
  if ! "$JQ_BIN" -en --argjson unit "$unit_layers" --argjson cand "$cand_layers" \
      '($cand | length) > ($unit | length) and $cand[0:($unit | length)] == $unit' >/dev/null; then
    stop FAIL snapshot_mismatch "the candidate image does not extend the unit image"
  fi
  # Commit keeps the never-run probe command as Cmd; the unit sets its own.
  json_equal "$(printf '%s' "$cand_json" | "$JQ_BIN" -c "$RUNTIME_CONFIG_JQ | del(.Cmd)")" \
      "$(printf '%s' "$ev_runtime" | "$JQ_BIN" -c 'del(.Cmd)')" \
    || stop FAIL snapshot_mismatch "the candidate image runtime configuration differs from the build evidence"
  CANDIDATE_JSON=$("$JQ_BIN" -cn --arg commit "$CANDIDATE" --arg tree "$candidate_tree" --arg sha "$archive_sha" \
    --arg tag "$cand_tag" --arg id "$cand_id" \
    '{commit: $commit, tree: $tree, archive_sha256: $sha, image_tag: $tag, image_id: $id,
      layers_extend_unit_image: true, source_tree_verified: false}')

  # Create, then admit from inspect before anything inside can run.
  create_container "$unit_name" "$@" "$cand_id" python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"}
  UNIT_CID=$CREATED_ID
  inspect=$(dk container inspect --format '{{json .}}' "$UNIT_CID") || stop FAIL unit_admission_failed "the unit container cannot be inspected"
  printf '%s\n' "$inspect" > "$DIR/inspect-created.json"
  failures=$(printf '%s' "$inspect" | admission_failures "$cand_id" "$argv_json" "$img_env" "$unit_env_json") \
    || failures='["inspect_unreadable"]'
  attested=$(attested_from "$failures")
  ATTESTED_JSON=$attested
  CONTAINER_JSON=$("$JQ_BIN" -cn --arg name "$unit_name" --arg id "$UNIT_CID" --argjson f "$failures" \
    '{name: $name, id: $id, admitted: ($f | length == 0), admission_failures: $f, started: false,
      exit_code: null, oom_killed: null, timed_out: false, post_exit_verified: false}')
  if [ "$failures" != "[]" ]; then
    stop FAIL unit_admission_failed "the created container does not match the admitted configuration"
  fi
  dk cp "$UNIT_CID:$UNIT_SRC" - > "$DIR/src-actual.tar" 2>>"$DIR/engine.stderr" \
    || stop FAIL snapshot_mismatch "the unit source tree cannot be read back"
  tar -xf "$DIR/src-actual.tar" -C "$DIR/src-actual"
  tree_manifest "$DIR/src-expected" > "$DIR/src-expected.manifest"
  tree_manifest "$DIR/src-actual/src" > "$DIR/src-actual.manifest"
  cmp -s "$DIR/src-expected.manifest" "$DIR/src-actual.manifest" \
    || stop FAIL snapshot_mismatch "the unit source tree differs from the candidate commit"
  CANDIDATE_JSON=$(printf '%s' "$CANDIDATE_JSON" | "$JQ_BIN" -c '.source_tree_verified = true')

  # Start; the controller owns the whole-unit timeout.
  check_interrupt
  dk container start "$UNIT_CID" >/dev/null 2>>"$DIR/engine.stderr" || stop FAIL unit_start_failed "the unit container did not start"
  started=true
  (
    sleep "$TIMEOUT"
    if [ "$(dk container inspect --format '{{.State.Running}}' "$UNIT_CID" 2>/dev/null)" = true ]; then
      : > "$DIR/timed-out"
      dk container kill "$UNIT_CID" >/dev/null 2>&1
    fi
  ) &
  watchdog=$!
  dk container wait "$UNIT_CID" > "$DIR/wait.out" 2>>"$DIR/engine.stderr" &
  wait_pid=$!
  while ! wait "$wait_pid"; do
    kill -0 "$wait_pid" 2>/dev/null || break
  done
  pkill -P "$watchdog" >/dev/null 2>&1 || true
  kill "$watchdog" >/dev/null 2>&1 || true
  wait "$watchdog" 2>/dev/null || true
  [ -f "$DIR/timed-out" ] && timed_out=true
  exit_code=$(tr -dc '0-9' < "$DIR/wait.out")
  dk container logs "$UNIT_CID" 2>"$DIR/worker.stderr" | head -c $((MAX_WORKER_STDOUT + 1)) > "$DIR/worker.stdout" || true
  inspect=$(dk container inspect --format '{{json .}}' "$UNIT_CID" 2>/dev/null) || inspect=""
  printf '%s\n' "$inspect" > "$DIR/inspect-exited.json"
  if [ -n "$inspect" ] && [ -n "$exit_code" ]; then
    failures=$(printf '%s' "$inspect" | admission_failures "$cand_id" "$argv_json" "$img_env" "$unit_env_json" 2>/dev/null) \
      || failures='["inspect_unreadable"]'
    oom=$(printf '%s' "$inspect" | "$JQ_BIN" -r '.State.OOMKilled == true')
    if [ "$failures" = "[]" ] && printf '%s' "$inspect" | "$JQ_BIN" -e --argjson code "$exit_code" \
        '.State.Status == "exited" and .State.ExitCode == $code' >/dev/null 2>&1; then
      post_ok=true
    fi
  fi
  CONTAINER_JSON=$(printf '%s' "$CONTAINER_JSON" | "$JQ_BIN" -c --argjson started "$started" \
    --arg code "$exit_code" --argjson oom "$oom" --argjson timed "$timed_out" --argjson post "$post_ok" \
    '.started = $started | .exit_code = (if $code == "" then null else ($code | tonumber) end)
     | .oom_killed = $oom | .timed_out = $timed | .post_exit_verified = $post')

  # The unit is gone before any verdict.
  cleanup_lease
  [ -z "$INTERRUPTED" ] || stop FAIL interrupted "signal $INTERRUPTED received"
  [ "$timed_out" = false ] || stop FAIL unit_timeout "the unit exceeded --timeout and was killed"
  [ "$oom" = false ] || stop FAIL unit_oom "the unit was killed for memory"
  [ "$post_ok" = true ] || stop FAIL unit_post_exit_unverified "the exited unit could not be verified"

  stdout_size=$(wc -c < "$DIR/worker.stdout" | tr -d ' ')
  [ "$stdout_size" -le "$MAX_WORKER_STDOUT" ] || stop FAIL worker_result_unparseable "worker stdout exceeds the bound"
  count=$(grep -c "^$WORKER_PREFIX" "$DIR/worker.stdout" || true)
  last=$(awk 'NF { line = $0 } END { print line }' "$DIR/worker.stdout")
  case "$last" in "$WORKER_PREFIX"*) ;; *) count=0 ;; esac
  [ "$count" = 1 ] || stop FAIL worker_result_unparseable "worker stdout must end with exactly one result line"
  worker_line=${last#"$WORKER_PREFIX"}
  if ! printf '%s' "$worker_line" | validate_worker_result "$exit_code"; then
    WORKER_JSON=$(printf '%s' "$worker_line" | "$JQ_BIN" -c '{result: ., consistent: false}' 2>/dev/null \
      || printf '{"result":null,"consistent":false}')
    stop FAIL worker_result_inconsistent "the worker result does not match the unit exit, identity, schema or requested mode and tier"
  fi
  WORKER_JSON=$(printf '%s' "$worker_line" | "$JQ_BIN" -c '{result: ., consistent: true}')
  worker_status=$(printf '%s' "$worker_line" | "$JQ_BIN" -r '.status')
  while IFS= read -r reason; do
    if [ -n "$reason" ]; then add_reason_json "$reason"; fi
  done <<EOF
$(printf '%s' "$worker_line" | "$JQ_BIN" -c '.reasons[] | {code: ("worker:" + (.code | tostring)), detail: (.detail | tostring)}')
EOF
  settle "$worker_status"
}

# ── cleanup ───────────────────────────────────────────────────────────────────

do_cleanup() {
  local lease_id
  matches "$UNIT_ID" "$UUID_RE" || stop REFUSED usage "--unit-id must be a controller uuid"
  lease_id=$("$JQ_BIN" -r --arg schema "$LEASE_SCHEMA" 'if .schema == $schema then .controller_id else "" end' "$DIR/lease.json" 2>/dev/null || true)
  [ "$lease_id" = "$UNIT_ID" ] || stop REFUSED lease_mismatch "the lease in --evidence-dir does not belong to --unit-id"
  CONTROLLER_ID=$UNIT_ID
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi
  engine_identity
  # Removes only exact recorded ids on the lease's engine; anything else is quarantined.
  cleanup_lease
  settle PASS
}

# ── Entry ─────────────────────────────────────────────────────────────────────

main() {
  local arg
  trap 'ERR_LINE=$LINENO' ERR
  trap 'on_exit' EXIT
  trap 'on_signal INT' INT
  trap 'on_signal TERM' TERM
  BASE_IMAGE=""
  IMAGE_ID=""
  CANDIDATE=""
  RUNTIME_EVIDENCE=""
  UNIT_ID=""
  TIMEOUT=$DEFAULT_TIMEOUT
  WORKER_ARGS=()
  while [ $# -gt 0 ] && [ -z "$COMMAND" ]; do
    case "$1" in
      --engine-socket) [ $# -ge 2 ] || usage_refused "--engine-socket needs a value"; SOCK=$2; shift 2 ;;
      --evidence-dir) [ $# -ge 2 ] || usage_refused "--evidence-dir needs a value"; DIR=$2; shift 2 ;;
      --docker-bin) [ $# -ge 2 ] || usage_refused "--docker-bin needs a value"; DOCKER_BIN=$2; shift 2 ;;
      --jq-bin) [ $# -ge 2 ] || usage_refused "--jq-bin needs a value"; JQ_BIN=$2; shift 2 ;;
      --dry-run) DRY_RUN=true; shift ;;
      build|run|cleanup) COMMAND=$1; shift ;;
      *) usage_refused "unknown option or command: $1" ;;
    esac
  done
  [ -n "$COMMAND" ] || usage_refused "choose build, run or cleanup"
  while [ $# -gt 0 ]; do
    arg=$1
    case "$COMMAND:$arg" in
      build:--base-image) [ $# -ge 2 ] || usage_refused "--base-image needs a value"; BASE_IMAGE=$2; shift 2 ;;
      run:--runtime-evidence) [ $# -ge 2 ] || usage_refused "--runtime-evidence needs a value"; RUNTIME_EVIDENCE=$2; shift 2 ;;
      run:--image-id) [ $# -ge 2 ] || usage_refused "--image-id needs a value"; IMAGE_ID=$2; shift 2 ;;
      run:--candidate) [ $# -ge 2 ] || usage_refused "--candidate needs a value"; CANDIDATE=$2; shift 2 ;;
      run:--timeout) [ $# -ge 2 ] || usage_refused "--timeout needs a value"; TIMEOUT=$2; shift 2 ;;
      run:--) shift; WORKER_ARGS=("$@"); break ;;
      cleanup:--unit-id) [ $# -ge 2 ] || usage_refused "--unit-id needs a value"; UNIT_ID=$2; shift 2 ;;
      *) usage_refused "unknown $COMMAND option: $arg" ;;
    esac
  done
  [ -n "$SOCK" ] || usage_refused "--engine-socket is required"
  [ -n "$DIR" ] || usage_refused "--evidence-dir is required"
  case "$COMMAND" in
    build) [ -n "$BASE_IMAGE" ] || usage_refused "build needs --base-image" ;;
    run)
      [ -n "$RUNTIME_EVIDENCE" ] && [ -n "$IMAGE_ID" ] && [ -n "$CANDIDATE" ] \
        || usage_refused "run needs --runtime-evidence, --image-id and --candidate"
      ;;
    cleanup) [ -n "$UNIT_ID" ] || usage_refused "cleanup needs --unit-id" ;;
  esac
  for arg in ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"}; do
    case "$arg" in *$'\n'*|*$'\r'*) usage_refused "worker arguments cannot contain newlines" ;; esac
  done

  if [ "$COMMAND" = cleanup ]; then
    existing_lease_dir
  else
    prepare_new_evidence_dir
    new_controller_id
  fi
  select_binaries
  validate_socket
  case "$COMMAND" in
    build) do_build ;;
    run) do_run ;;
    cleanup) do_cleanup ;;
  esac
}

main "$@"
