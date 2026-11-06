#!/bin/sh
# Boundary simulator for tests/multiuser/test_f02_unit.py only.
# It records the controller's invocation and returns an empty engine identity.
# It does not contact Docker, a socket, or any service.
set -eu

mu_log=__MU_CALL_LOG__
{
    printf '%s\n' CALL
    for mu_arg in "$@"; do
        printf 'ARG=%s\n' "$mu_arg"
    done
    printf 'ENV_PATH=%s\n' "${PATH-<unset>}"
    printf 'ENV_HOME=%s\n' "${HOME-<unset>}"
    printf 'ENV_DOCKER_CONFIG=%s\n' "${DOCKER_CONFIG-<unset>}"
    printf 'ENV_TMPDIR=%s\n' "${TMPDIR-<unset>}"
    printf 'ENV_DOCKER_HOST=%s\n' "${DOCKER_HOST-<unset>}"
    printf 'ENV_DOCKER_CONTEXT=%s\n' "${DOCKER_CONTEXT-<unset>}"
    printf 'ENV_HTTP_PROXY=%s\n' "${HTTP_PROXY-<unset>}"
    printf 'ENV_AWS_SECRET_ACCESS_KEY=%s\n' "${AWS_SECRET_ACCESS_KEY-<unset>}"
    printf 'ENV_SSH_AUTH_SOCK=%s\n' "${SSH_AUTH_SOCK-<unset>}"
} >> "$mu_log"

if [ "${1-}" = --host ]; then
    shift 2
fi
if [ "${1-}" = info ]; then
    printf '%s\n' '{"ID":"","ServerVersion":"synthetic","OperatingSystem":"synthetic"}'
    exit 0
fi

printf '%s\n' 'unexpected fake Docker command' >&2
exit 97
