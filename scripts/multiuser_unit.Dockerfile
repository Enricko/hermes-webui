# Multi-user (F02) verification unit image. Provisioning only: no proof runs here.
#
# Built by `scripts/multiuser_unit.sh ... build --base-image NAME@sha256:<digest>`
# from a context holding only requirements.txt, requirements-dev.txt,
# scripts/test.sh and this file, written from the blobs of one recorded commit
# whose files match the checkout. The base image must be digest-pinned and has
# deliberately no default. The image must declare no VOLUME, ONBUILD,
# ENTRYPOINT or HEALTHCHECK; the controller refuses one that does before any
# container is created from it.
#
# The controller later copies an exact candidate commit into /src, commits it
# as a per-run image and admits a read-only, network-less, non-root container
# from it; proof runs use only `scripts/test.sh --execute-only` there.
ARG MU_BASE_IMAGE
FROM ${MU_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_INPUT=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# jq and git let the controller's own regression tests run inside a unit
# (against a tmp_path mini-checkout; /src itself never has .git).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git jq \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt /opt/mu/
COPY scripts/test.sh /opt/mu/scripts/test.sh

# Provision the test virtualenv once and record exactly what was installed.
# /src holds only the .venv link until a candidate snapshot is copied in.
RUN /opt/mu/scripts/test.sh --prepare-only \
 && /opt/mu/.venv/bin/python -m pip freeze --all > /opt/mu/freeze.txt \
 && chmod -R go-w /opt/mu \
 && mkdir -m 0755 /src \
 && ln -s /opt/mu/.venv /src/.venv \
 && groupadd --gid 10001 mu \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin mu

USER 10001:10001
WORKDIR /src
