# Linux amd64 scanner digest verified against the official GitHub release asset.
FROM --platform=linux/amd64 python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
ARG CODEQL_VERSION=2.27.4
ARG CODEQL_SHA256=393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
RUN apt-get update && apt-get install -y --no-install-recommends git curl unzip nodejs ca-certificates build-essential libffi-dev libpq-dev default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/avr
COPY requirements-lock.txt requirements-django.lock requirements-lessons.lock requirements-vampi.lock ./
RUN pip install --no-cache-dir -r requirements-lock.txt \
    && python -m venv /opt/pygoat-env && /opt/pygoat-env/bin/pip install --no-cache-dir -r requirements-django.lock \
    && python -m venv /opt/lessons-env && /opt/lessons-env/bin/pip install --no-cache-dir -r requirements-lessons.lock \
    && python -m venv /opt/vampi-env && /opt/vampi-env/bin/pip install --no-cache-dir -r requirements-vampi.lock
RUN test -n "$CODEQL_SHA256" \
    && (curl --fail --location --retry 4 --retry-delay 5 --retry-all-errors "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" -o /tmp/codeql.zip \
        || curl --fail --location --retry 4 --retry-delay 5 --retry-all-errors -H 'Accept: application/octet-stream' "https://api.github.com/repos/github/codeql-cli-binaries/releases/assets/692228339" -o /tmp/codeql.zip) \
    && echo "$CODEQL_SHA256  /tmp/codeql.zip" | sha256sum --check \
    && unzip -q /tmp/codeql.zip -d /opt/scanners && rm /tmp/codeql.zip
ENV PATH="/opt/scanners/codeql:${PATH}" \
    CODEQL_BIN=/opt/scanners/codeql/codeql \
    CODEQL_PACK_ROOT=/opt/scanners/packs \
    AVR_PYGOAT_PYTHON=/opt/pygoat-env/bin/python \
    AVR_VAMPI_PYTHON=/opt/vampi-env/bin/python
RUN codeql pack download codeql/python-queries@1.9.0 --dir=/opt/scanners/packs
RUN curl --fail --location --retry 4 --retry-delay 5 --retry-all-errors "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -o /tmp/zap.tar.gz \
    && echo "$ZAP_SHA256  /tmp/zap.tar.gz" | sha256sum --check \
    && tar -xzf /tmp/zap.tar.gz -C /opt/scanners && rm /tmp/zap.tar.gz
ENV ZAP_JAR=/opt/scanners/ZAP_2.17.0/zap-2.17.0.jar
COPY . .
CMD ["python", "review/smoke.py", "--out", "/tmp/avr-smoke"]
