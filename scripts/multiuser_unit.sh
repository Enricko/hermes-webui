#!/bin/bash
# Multi-user (F02) unit controller: the trusted host side of F02 verification.
#
#   multiuser_unit.sh GLOBAL build --base-image NAME@sha256:<64hex>
#   multiuser_unit.sh GLOBAL run --image-id sha256:<64hex> --candidate <40hex>
#                                [--timeout SECONDS] -- <worker args>
#   multiuser_unit.sh GLOBAL cleanup --unit-id <controller uuid>
#
#   GLOBAL: --engine-socket ABS_UNIX_SOCKET --evidence-dir DIR
#           [--docker-bin ABS] [--jq-bin ABS] [--dry-run]
#
# build provisions the unit image from this checkout's clean HEAD recipe
# (scripts/multiuser_unit.Dockerfile). run copies the exact candidate commit
# into a per-run image, creates ONE container with fixed isolation flags,
# admits it from `docker inspect` before `docker start`, runs the launcher
# (`python3 -I -S scripts/test_multiuser.py <worker args>`) inside it, checks
# exactly one worker result line against the container exit, removes the
# container and per-run image, and only then gives a verdict. cleanup removes
# what an interrupted run's lease recorded, and nothing else.
#
# Every docker call uses an empty environment with a private HOME and
# DOCKER_CONFIG inside DIR and the explicit --host socket: no ambient context,
# DOCKER_HOST, ~/.docker config, credential helpers or keychains. Host Python is
# never run. Only containers and tags created and recorded by this invocation,
# on the same engine, are ever removed.
#
# The last stdout line is `MULTIUSER_UNIT_RESULT {json}`; the same JSON is
# written to DIR/result.json. Exit: 0 PASS, 1 FAIL, 2 REFUSED, 3 NOT_RUN.
# --docker-bin/--jq-bin substitute binaries (for example in simulations); the
# substitution is recorded and is never evidence about a real engine.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin
export LC_ALL=C

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
GIT_BIN=/usr/bin/git
RECIPE_PATHS="requirements.txt requirements-dev.txt scripts/test.sh scripts/multiuser_unit.Dockerfile"
DEFAULT_DOCKER_BINS="/usr/local/bin/docker /usr/bin/docker"
DEFAULT_JQ_BIN=/usr/bin/jq

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
RECIPE_JSON=null
CANDIDATE_JSON=null
CONTAINER_JSON=null
ATTESTED_JSON='{"network_none":false,"read_only_rootfs":false,"non_root":false,"no_mounts":false,"caps_dropped":false,"no_new_privileges":false,"private_pid":false,"resource_limits":false}'
WORKER_JSON='{"result":null,"consistent":false}'
CLEANUP_JSON='{"container_removed":false,"candidate_image_removed":false,"verified":false,"quarantine":[]}'
CLAIMS_JSON='{"agent_source_pin":false,"native_clients":false,"browser_privacy":false,"os_containment":false,"external_provider":false}'
UNIT_CID=""
INTERRUPTED=""
ERR_LINE=""

# A JSON string from controller-generated text. Characters outside a plain
# set become '?', so no escaping is needed; structured data goes through jq.
json_string() {
  printf '"%s"' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9 _./:@=+,()<>#%~!?*^-' '?')"
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
  json="$json,\"jq_bin\":$(json_string "$JQ_BIN"),\"engine\":$ENGINE_JSON,\"recipe\":$RECIPE_JSON"
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

git_clean() {
  env -i PATH=/usr/bin:/bin HOME="$DIR/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    "$GIT_BIN" -C "$REPO" "$@"
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

# ── Lease: the only authority for removal ────────────────────────────────────

lease_write() {
  local filter=$1
  shift
  "$JQ_BIN" "$@" "$filter" "$DIR/lease.json" > "$DIR/lease.json.next"
  mv -f "$DIR/lease.json.next" "$DIR/lease.json"
}

lease_init() {
  "$JQ_BIN" -n --arg schema "$LEASE_SCHEMA" --arg cid "$CONTROLLER_ID" --arg engine "$ENGINE_ID" \
    --arg command "$COMMAND" \
    '{schema: $schema, controller_id: $cid, engine_id: $engine, command: $command, containers: [], images: []}' \
    > "$DIR/lease.json"
}

lease_container_intent() {
  lease_write '.containers += [{name: $name, id: null, removed: false}]' --arg name "$1"
}

lease_container_id() {
  lease_write '(.containers[] | select(.name == $name) | .id) = $id' --arg name "$1" --arg id "$2"
}

lease_image_intent() {
  lease_write '.images += [{tag: $tag, id: null, removed: false}]' --arg tag "$1"
}

lease_image_id() {
  lease_write '(.images[] | select(.tag == $tag) | .id) = $id' --arg tag "$1" --arg id "$2"
}

lease_mark_removed() {
  if [ "$1" = container ]; then
    lease_write '(.containers[] | select(.name == $key) | .removed) = true' --arg key "$2"
  else
    lease_write '(.images[] | select(.tag == $key) | .removed) = true' --arg key "$2"
  fi
}

QUARANTINE=""
quarantine() {
  if [ -n "$QUARANTINE" ]; then QUARANTINE="$QUARANTINE,$(json_string "$1")"; else QUARANTINE=$(json_string "$1"); fi
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

# Remove one recorded container: by its recorded id, or (if creation never
# returned) by its unique controller-generated name after confirming the
# controller label. Returns 0 only when the engine confirms it is gone.
remove_container() {
  local name=$1 id=$2 label rc=0
  if [ -z "$id" ] || [ "$id" = null ]; then
    absent container "$name" || rc=$?
    case "$rc" in
      0) return 0 ;;  # never created
      2) quarantine "$name"; return 1 ;;
    esac
    label=$(dk container inspect --format '{{index .Config.Labels "hermes.f02.controller"}}|{{.Id}}' "$name" 2>/dev/null) || label=""
    if [ -z "$label" ] || [ "${label%%|*}" != "$CONTROLLER_ID" ]; then
      quarantine "$name"
      return 1
    fi
    id=${label#*|}
  fi
  dk container rm -f "$id" >/dev/null 2>&1 || true
  if absent container "$id"; then
    return 0
  fi
  quarantine "$id"
  return 1
}

# Remove one recorded tag, then confirm that tag and its recorded image id are gone.
remove_image_tag() {
  local tag=$1 id=$2 now rc=0
  absent image "$tag" || rc=$?
  if [ "$rc" -eq 2 ]; then
    quarantine "$tag"
    return 1
  fi
  if [ "$rc" -eq 1 ]; then
    now=$(dk image inspect --format '{{.Id}}' "$tag" 2>/dev/null) || now=""
    if [ -z "$now" ] || { [ -n "$id" ] && [ "$id" != null ] && [ "$now" != "$id" ]; }; then
      quarantine "$tag"
      return 1
    fi
    dk image rm "$tag" >/dev/null 2>&1 || true
    if ! absent image "$tag"; then
      quarantine "$tag"
      return 1
    fi
  fi
  if [ -n "$id" ] && [ "$id" != null ] && ! absent image "$id"; then
    quarantine "$id"
    return 1
  fi
  return 0
}

CLEANED=0
cleanup_lease() {
  [ "$CLEANED" -eq 0 ] || return 0
  CLEANED=1
  [ -f "$DIR/lease.json" ] || return 0
  local ok=true containers_ok=true images_ok=true entries entry name id kind
  if ! engine_unchanged; then
    for entry in $("$JQ_BIN" -r '(.containers[] | select(.removed | not) | (.id // .name)), (.images[] | select(.removed | not) | select(.keep | not) | .tag)' "$DIR/lease.json"); do
      quarantine "$entry"
    done
    CLEANUP_JSON="{\"container_removed\":false,\"candidate_image_removed\":false,\"verified\":false,\"quarantine\":[${QUARANTINE}]}"
    settle FAIL engine_identity_changed "the engine identity changed or is unreachable; nothing was removed"
    return 0
  fi
  entries=$("$JQ_BIN" -r '.containers[] | select(.removed | not) | "\(.name) \(.id // "null")"' "$DIR/lease.json")
  while read -r name id; do
    [ -n "$name" ] || continue
    if remove_container "$name" "$id"; then lease_mark_removed container "$name"; else containers_ok=false; fi
  done <<EOF
$entries
EOF
  entries=$("$JQ_BIN" -r '.images[] | select(.removed | not) | select(.keep | not) | "\(.tag) \(.id // "null")"' "$DIR/lease.json")
  while read -r name id; do
    [ -n "$name" ] || continue
    if remove_image_tag "$name" "$id"; then lease_mark_removed image "$name"; else images_ok=false; fi
  done <<EOF
$entries
EOF
  [ "$containers_ok" = true ] && [ "$images_ok" = true ] || ok=false
  CLEANUP_JSON="{\"container_removed\":$containers_ok,\"candidate_image_removed\":$images_ok,\"verified\":$ok,\"quarantine\":[${QUARANTINE}]}"
  [ "$ok" = true ] || settle FAIL unit_cleanup_unverified "recorded resources could not be verified removed; see quarantine"
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
  local recipe tag image_json image_id layers freeze_cid freeze_sha
  case "$BASE_IMAGE" in
    *@sha256:*) ;;
    *) stop REFUSED base_image_unpinned "--base-image must be NAME@sha256:<64hex>" ;;
  esac
  printf '%s' "$BASE_IMAGE" | grep -Eq '^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$' \
    || stop REFUSED base_image_unpinned "--base-image must be NAME@sha256:<64hex>"
  recipe=$(git_clean rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || stop REFUSED recipe_dirty "the controller checkout has no HEAD commit"
  # shellcheck disable=SC2086
  if ! git_clean diff --quiet HEAD -- $RECIPE_PATHS 2>/dev/null; then
    stop REFUSED recipe_dirty "recipe files differ from HEAD"
  fi
  tag="hermes-f02-unit:$CONTROLLER_ID"
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    plan build --file "$DIR/context/scripts/multiuser_unit.Dockerfile" --build-arg "MU_BASE_IMAGE=$BASE_IMAGE" \
      --tag "$tag" --label "hermes.f02.controller=$CONTROLLER_ID" "$DIR/context"
    plan image inspect --format '{{json .}}' "$tag"
    plan create --name "hermes-f02-freeze-$CONTROLLER_ID" --label "hermes.f02.controller=$CONTROLLER_ID" \
      --network none "$tag" /bin/true
    plan cp "<freeze-id>:/opt/mu/freeze.txt" -
    plan container rm -f "<freeze-id>"
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi
  engine_identity
  lease_init
  mkdir -m 700 "$DIR/context"
  # shellcheck disable=SC2086
  git_clean archive --format=tar HEAD -- $RECIPE_PATHS > "$DIR/recipe.tar"
  tar -xf "$DIR/recipe.tar" -C "$DIR/context"
  lease_image_intent "$tag"
  lease_write '(.images[] | select(.tag == $tag) | .keep) = true' --arg tag "$tag"
  if ! dk build --file "$DIR/context/scripts/multiuser_unit.Dockerfile" --build-arg "MU_BASE_IMAGE=$BASE_IMAGE" \
      --tag "$tag" --label "hermes.f02.controller=$CONTROLLER_ID" "$DIR/context" > "$DIR/build.log" 2>&1; then
    lease_write '(.images[] | select(.tag == $tag) | .keep) = false' --arg tag "$tag"
    stop FAIL build_failed "docker build failed; see build.log"
  fi
  image_json=$(dk image inspect --format '{{json .}}' "$tag") || stop FAIL build_failed "the built image cannot be inspected"
  image_id=$(printf '%s' "$image_json" | "$JQ_BIN" -r '.Id')
  layers=$(printf '%s' "$image_json" | "$JQ_BIN" -c '.RootFS.Layers')
  lease_image_id "$tag" "$image_id"
  freeze_cid=$(container_create "hermes-f02-freeze-$CONTROLLER_ID" --network none "$tag" /bin/true) \
    || stop FAIL build_failed "the freeze probe container could not be created"
  dk cp "$freeze_cid:/opt/mu/freeze.txt" - > "$DIR/freeze.tar" 2>/dev/null || stop FAIL build_failed "freeze.txt could not be read"
  mkdir -m 700 "$DIR/freeze"
  tar -xf "$DIR/freeze.tar" -C "$DIR/freeze"
  freeze_sha=$(sha256_file "$DIR/freeze/freeze.txt")
  remove_container "hermes-f02-freeze-$CONTROLLER_ID" "$freeze_cid" && lease_mark_removed container "hermes-f02-freeze-$CONTROLLER_ID"
  RECIPE_JSON=$("$JQ_BIN" -cn --arg commit "$recipe" --arg base "$BASE_IMAGE" --arg tag "$tag" --arg id "$image_id" \
    --argjson layers "$layers" --arg freeze "$freeze_sha" \
    '{commit: $commit, base_image: $base, unit_image_tag: $tag, unit_image_id: $id, unit_layers: $layers, freeze_sha256: $freeze}')
  settle PASS
}

# container_create NAME ARGS...: records intent, creates, records the returned id.
container_create() {
  local name=$1 id
  shift
  lease_container_intent "$name"
  id=$(dk create --name "$name" --label "hermes.f02.controller=$CONTROLLER_ID" "$@" 2>>"$DIR/engine.stderr") || return 1
  id=$(printf '%s' "$id" | tail -n 1)
  lease_container_id "$name" "$id"
  printf '%s\n' "$id"
}

# ── run ───────────────────────────────────────────────────────────────────────

# Tree manifest that never follows links: one line per directory, link
# (with its target text) and regular file (with its SHA-256). The unit's
# /src/.venv link is the only expected extra entry and is left out.
tree_manifest() {
  local root=$1 hasher=/usr/bin/sha256sum
  [ -x /usr/bin/shasum ] && hasher="/usr/bin/shasum -a 256"
  (
    cd "$root"
    find . -mindepth 1 ! -path './.venv' -type d -print | sed 's/^/D /'
    find . -mindepth 1 ! -path './.venv' -type l -exec sh -c 'for p; do printf "L %s %s\n" "$p" "$(readlink "$p")"; done' sh {} +
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

validate_worker_result() {
  "$JQ_BIN" -e --argjson exit "$1" --arg uid "$CONTROLLER_ID" --arg nonce "$UNIT_NONCE" --arg schema "$WORKER_SCHEMA" '
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
      and ($r.status != "PASS" or $r.tests == null
           or ($r.tests.total > 0 and $r.tests.skipped == 0 and $r.tests.failed == 0 and $r.tests.errors == 0))
  ' >/dev/null 2>&1
}

do_run() {
  local unit_json unit_layers cand_tag cand_id cand_json cand_layers img_env archive_sha prep_cid
  local unit_name argv_json unit_env_json inspect failures attested started=false exit_code="" timed_out=false
  local oom=false post_ok=false watchdog wait_pid stdout_size count last worker_line worker_status
  printf '%s' "$IMAGE_ID" | grep -Eq '^sha256:[0-9a-f]{64}$' || stop REFUSED usage "--image-id must be sha256:<64hex>"
  printf '%s' "$CANDIDATE" | grep -Eq '^[0-9a-f]{40}$' || stop REFUSED candidate_invalid "--candidate must be a full 40-hex commit"
  [ "$(git_clean cat-file -t "$CANDIDATE" 2>/dev/null || true)" = commit ] \
    || stop REFUSED candidate_invalid "--candidate is not a commit in the controller checkout"
  case "$TIMEOUT" in ''|*[!0-9]*) stop REFUSED usage "--timeout must be an integer" ;; esac
  [ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 86400 ] || stop REFUSED usage "--timeout must be between 1 and 86400"
  cand_tag="hermes-f02-cand:$CONTROLLER_ID"
  unit_name="hermes-f02-unit-$CONTROLLER_ID"
  argv_json=$("$JQ_BIN" -cn '$ARGS.positional' --args python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"})
  unit_env_json=$("$JQ_BIN" -cn '$ARGS.positional' --args "HERMES_MU_UNIT_ID=$CONTROLLER_ID" \
    "HERMES_MU_UNIT_NONCE=$UNIT_NONCE" "HERMES_MU_UNIT_SRC=$UNIT_SRC" "HERMES_MU_UNIT_STATE=$UNIT_STATE")
  set -- --user "$UNIT_USER" --read-only --network none --ipc private --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit "$PIDS_LIMIT" --memory 2g --memory-swap 2g --cpus 2 \
    --restart no --tmpfs "$TMPFS_TMP" --tmpfs "$TMPFS_STATE" \
    --env "HERMES_MU_UNIT_ID=$CONTROLLER_ID" --env "HERMES_MU_UNIT_NONCE=$UNIT_NONCE" \
    --env "HERMES_MU_UNIT_SRC=$UNIT_SRC" --env "HERMES_MU_UNIT_STATE=$UNIT_STATE" \
    --workdir "$UNIT_SRC"
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    plan image inspect --format '{{json .}}' "$IMAGE_ID"
    plan create --name "hermes-f02-prep-$CONTROLLER_ID" --label "hermes.f02.controller=$CONTROLLER_ID" \
      --network none "$IMAGE_ID" /bin/true
    plan cp - "<prep-id>:$UNIT_SRC"
    plan commit --change "USER $UNIT_USER" --change "WORKDIR $UNIT_SRC" "<prep-id>" "$cand_tag"
    plan container rm -f "<prep-id>"
    plan image inspect --format '{{json .}}' "$cand_tag"
    plan create --name "$unit_name" --label "hermes.f02.controller=$CONTROLLER_ID" "$@" "<cand-id>" \
      python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"}
    plan container inspect --format '{{json .}}' "<unit-id>"
    plan cp "<unit-id>:$UNIT_SRC" -
    plan container start "<unit-id>"
    plan container wait "<unit-id>"
    plan container logs "<unit-id>"
    plan container inspect --format '{{json .}}' "<unit-id>"
    plan container rm -f "<unit-id>"
    plan image rm "$cand_tag"
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi

  engine_identity
  lease_init
  unit_json=$(dk image inspect --format '{{json .}}' "$IMAGE_ID" 2>/dev/null) \
    || stop NOT_RUN unit_image_mismatch "--image-id is not present on this engine"
  [ "$(printf '%s' "$unit_json" | "$JQ_BIN" -r '.Id')" = "$IMAGE_ID" ] \
    || stop FAIL unit_image_mismatch "the engine reported a different image id"
  unit_layers=$(printf '%s' "$unit_json" | "$JQ_BIN" -c '.RootFS.Layers')
  RECIPE_JSON=$("$JQ_BIN" -cn --arg id "$IMAGE_ID" --argjson layers "$unit_layers" \
    '{unit_image_id: $id, unit_layers: $layers}')

  # Immutable source: the exact commit, archived once, hashed, and copied in.
  git_clean archive --format=tar "$CANDIDATE" > "$DIR/candidate.tar"
  archive_sha=$(sha256_file "$DIR/candidate.tar")
  mkdir -m 700 "$DIR/src-expected" "$DIR/src-actual"
  tar -xf "$DIR/candidate.tar" -C "$DIR/src-expected"
  prep_cid=$(container_create "hermes-f02-prep-$CONTROLLER_ID" --network none "$IMAGE_ID" /bin/true) \
    || stop FAIL unit_start_failed "the snapshot container could not be created"
  dk cp - "$prep_cid:$UNIT_SRC" < "$DIR/candidate.tar" 2>>"$DIR/engine.stderr" \
    || stop FAIL snapshot_mismatch "the candidate snapshot could not be copied in"
  lease_image_intent "$cand_tag"
  cand_id=$(dk commit --change "USER $UNIT_USER" --change "WORKDIR $UNIT_SRC" "$prep_cid" "$cand_tag" 2>>"$DIR/engine.stderr") \
    || stop FAIL snapshot_mismatch "the candidate image could not be committed"
  cand_id=$(printf '%s' "$cand_id" | tail -n 1)
  lease_image_id "$cand_tag" "$cand_id"
  remove_container "hermes-f02-prep-$CONTROLLER_ID" "$prep_cid" && lease_mark_removed container "hermes-f02-prep-$CONTROLLER_ID"
  cand_json=$(dk image inspect --format '{{json .}}' "$cand_tag") || stop FAIL snapshot_mismatch "the candidate image cannot be inspected"
  [ "$(printf '%s' "$cand_json" | "$JQ_BIN" -r '.Id')" = "$cand_id" ] || stop FAIL snapshot_mismatch "the candidate tag moved"
  cand_layers=$(printf '%s' "$cand_json" | "$JQ_BIN" -c '.RootFS.Layers')
  img_env=$(printf '%s' "$cand_json" | "$JQ_BIN" -c '.Config.Env // []')
  if ! "$JQ_BIN" -en --argjson unit "$unit_layers" --argjson cand "$cand_layers" \
      '($cand | length) > ($unit | length) and $cand[0:($unit | length)] == $unit' >/dev/null; then
    stop FAIL snapshot_mismatch "the candidate image does not extend the unit image"
  fi
  CANDIDATE_JSON=$("$JQ_BIN" -cn --arg commit "$CANDIDATE" --arg sha "$archive_sha" --arg tag "$cand_tag" --arg id "$cand_id" \
    '{commit: $commit, archive_sha256: $sha, image_tag: $tag, image_id: $id, layers_extend_unit_image: true, source_tree_verified: false}')

  # Create, then admit from inspect before anything inside can run.
  UNIT_CID=$(container_create "$unit_name" "$@" "$cand_id" \
      python3 -I -S scripts/test_multiuser.py ${WORKER_ARGS[@]+"${WORKER_ARGS[@]}"}) \
    || stop FAIL unit_start_failed "the unit container could not be created"
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
    stop FAIL worker_result_inconsistent "the worker result does not match the unit exit, identity or schema"
  fi
  WORKER_JSON=$(printf '%s' "$worker_line" | "$JQ_BIN" -c '{result: ., consistent: true}')
  worker_status=$(printf '%s' "$worker_line" | "$JQ_BIN" -r '.status')
  while IFS= read -r reason; do
    [ -n "$reason" ] && add_reason_json "$reason"
  done <<EOF
$(printf '%s' "$worker_line" | "$JQ_BIN" -c '.reasons[] | {code: ("worker:" + (.code | tostring)), detail: (.detail | tostring)}')
EOF
  settle "$worker_status"
}

# ── cleanup ───────────────────────────────────────────────────────────────────

do_cleanup() {
  local lease_id lease_engine
  printf '%s' "$UNIT_ID" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
    || stop REFUSED usage "--unit-id must be a controller uuid"
  lease_id=$("$JQ_BIN" -r --arg schema "$LEASE_SCHEMA" 'if .schema == $schema then .controller_id else "" end' "$DIR/lease.json" 2>/dev/null || true)
  [ "$lease_id" = "$UNIT_ID" ] || stop REFUSED lease_mismatch "the lease in --evidence-dir does not belong to --unit-id"
  lease_engine=$("$JQ_BIN" -r '.engine_id' "$DIR/lease.json")
  CONTROLLER_ID=$UNIT_ID
  if [ "$DRY_RUN" = true ]; then
    plan info --format '{{json .}}'
    stop NOT_RUN dry_run "validated; no engine contacted"
  fi
  engine_identity
  [ "$ENGINE_ID" = "$lease_engine" ] || stop FAIL engine_identity_changed "this engine is not the one the lease was taken on"
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
    run) [ -n "$IMAGE_ID" ] && [ -n "$CANDIDATE" ] || usage_refused "run needs --image-id and --candidate" ;;
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
