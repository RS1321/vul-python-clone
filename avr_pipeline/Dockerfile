# Linux amd64 scanner digest verified against the official GitHub release asset.
FROM --platform=linux/amd64 python:3.12.14-slim-bookworm
ARG CODEQL_VERSION=2.27.4
ARG CODEQL_SHA256=393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d
RUN apt-get update && apt-get install -y --no-install-recommends git curl unzip nodejs ca-certificates build-essential libffi-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/avr
COPY requirements-lock.txt requirements-django.lock requirements-lessons.lock requirements-vampi.lock ./
RUN pip install --no-cache-dir -r requirements-lock.txt \
    && python -m venv /opt/pygoat-env && /opt/pygoat-env/bin/pip install --no-cache-dir -r requirements-django.lock \
    && python -m venv /opt/lessons-env && /opt/lessons-env/bin/pip install --no-cache-dir -r requirements-lessons.lock \
    && python -m venv /opt/vampi-env && /opt/vampi-env/bin/pip install --no-cache-dir -r requirements-vampi.lock
RUN test -n "$CODEQL_SHA256" \
    && curl --fail --location "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" -o /tmp/codeql.zip \
    && echo "$CODEQL_SHA256  /tmp/codeql.zip" | sha256sum --check \
    && unzip -q /tmp/codeql.zip -d /opt/scanners && rm /tmp/codeql.zip
ENV PATH="/opt/scanners/codeql:${PATH}" \
    CODEQL_BIN=/opt/scanners/codeql/codeql \
    CODEQL_PACK_ROOT=/opt/scanners/packs \
    AVR_PYGOAT_PYTHON=/opt/pygoat-env/bin/python \
    AVR_VAMPI_PYTHON=/opt/vampi-env/bin/python
RUN codeql pack download codeql/python-queries@1.9.0 --dir=/opt/scanners/packs
COPY . .
CMD ["python", "review/smoke.py", "--out", "/tmp/avr-smoke"]
