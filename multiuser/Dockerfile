# Resolve this official base to a digest with scripts/build_multiuser_images.py.
ARG PYTHON_IMAGE=python:3.14-slim@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d
FROM ${PYTHON_IMAGE} AS relay
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY multiuser/relay.py /opt/relay.py
ENTRYPOINT ["python", "/opt/relay.py"]

FROM ${PYTHON_IMAGE} AS sqlite-build
# Same WAL-reset fix and verified source as the upstream WebUI Dockerfile.
ARG SQLITE_VERSION=3530000
ARG SQLITE_YEAR=2026
ARG SQLITE_SHA256=851e9b38192fe2ceaa65e0baa665e7fa06230c3d9bd1a6a9662d02380d73365a
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev curl ca-certificates \
    && curl -fsSL "https://sqlite.org/${SQLITE_YEAR}/sqlite-autoconf-${SQLITE_VERSION}.tar.gz" -o /tmp/sqlite.tar.gz \
    && echo "${SQLITE_SHA256}  /tmp/sqlite.tar.gz" | sha256sum -c - \
    && cd /tmp && tar xzf sqlite.tar.gz && cd "sqlite-autoconf-${SQLITE_VERSION}" \
    && CPPFLAGS="-DSQLITE_SECURE_DELETE" ./configure --prefix=/usr/local --disable-static --disable-readline \
       --enable-fts5 --enable-fts4 --enable-rtree \
    && make -j4 && make install

FROM ${PYTHON_IMAGE} AS worker
ARG AGENT_REV=278aeffe16945e7b1405e3c471ad08553c059237
ARG WEBUI_VERSION=multiuser-dev
RUN apt-get update && apt-get install -y --no-install-recommends git bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init /opt/hermes \
    && git -C /opt/hermes remote add origin https://github.com/NousResearch/hermes-agent.git \
    && git -C /opt/hermes fetch --depth=1 origin "${AGENT_REV}" \
    && git -C /opt/hermes checkout --detach FETCH_HEAD \
    && test "$(git -C /opt/hermes rev-parse HEAD)" = "${AGENT_REV}" \
    && rm -rf /opt/hermes/.git
# The compatible Agent requires Python 3.14; WebUI's host test runner stays on
# its supported 3.11–3.13 interpreter. Install the Agent's pinned core deps.
RUN pip install --no-cache-dir -e /opt/hermes 'pyyaml>=6' 'cryptography>=42'
COPY --from=sqlite-build /usr/local/lib/libsqlite3.so* /usr/local/lib/
RUN ldconfig && python -c 'import sqlite3; assert sqlite3.sqlite_version_info >= (3,51,3); assert sqlite3.connect(":memory:").execute("PRAGMA secure_delete").fetchone()[0] == 1'
COPY . /opt/webui
RUN printf "__version__ = '%s'\n" "${WEBUI_VERSION}" > /opt/webui/api/_version.py \
    && mkdir -p /state/hermes /workspace /shared/tools \
    && HERMES_HOME=/tmp/image-validation HERMES_DISABLE_LAZY_INSTALLS=1 \
       PYTHONPATH=/opt/hermes python -c 'from run_agent import AIAgent; from PIL import Image; from cron.scheduler import tick' \
    && rm -rf /tmp/image-validation
ENV PYTHONPATH=/opt/webui:/opt/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "multiuser.worker"]
