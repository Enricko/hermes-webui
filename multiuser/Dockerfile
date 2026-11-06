# Resolve this official base to a digest with scripts/build_multiuser_images.py.
ARG PYTHON_IMAGE=python:3.14-slim@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d
FROM ${PYTHON_IMAGE} AS relay
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY multiuser/relay.py /opt/relay.py
ENTRYPOINT ["python", "/opt/relay.py"]

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
RUN pip install --no-cache-dir /opt/hermes 'pyyaml>=6' 'cryptography>=42'
COPY . /opt/webui
RUN printf "__version__ = '%s'\n" "${WEBUI_VERSION}" > /opt/webui/api/_version.py \
    && mkdir -p /state/hermes /workspace /shared/tools \
    && HERMES_HOME=/tmp/image-validation HERMES_DISABLE_LAZY_INSTALLS=1 \
       PYTHONPATH=/opt/hermes python -c 'from run_agent import AIAgent; from PIL import Image; from cron.scheduler import tick' \
    && rm -rf /tmp/image-validation
ENV PYTHONPATH=/opt/webui:/opt/hermes PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "multiuser.worker"]
