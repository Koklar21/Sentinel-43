# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

# Keep the Python minor version aligned with CI.
# Alpine is used intentionally to reduce the runtime footprint and avoid
# Debian-package findings seen in the former slim-based image.
FROM python:3.13-alpine AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only dependency metadata first so Docker can reuse this layer when
# application source changes but dependencies do not.
COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir -r /app/requirements.txt


# =============================================================================
# Test image
# =============================================================================
FROM dependencies AS test

# Test-only tooling is absent from the release image.
RUN python -m pip install --no-cache-dir pytest requests

COPY . /app

ENV S43_WATCHTOWER_URL=http://127.0.0.1:19100 \
    S43_WATCHTOWER_TIMEOUT=0.1


# =============================================================================
# Runtime image
# =============================================================================
FROM dependencies AS runtime

# Fixed unprivileged UID/GID matching deployment securityContext values.
RUN addgroup -S -g 65532 s43 \
    && adduser -S -D -H -u 65532 -G s43 -s /sbin/nologin s43 \
    && mkdir -p /app/logs /app/sentinel43_state \
    && chown -R 65532:65532 /app/logs /app/sentinel43_state

# Copy application source after user creation. Source remains root-owned and
# read-only to the runtime account; only explicitly writable runtime paths are
# owned by UID/GID 65532.
COPY . /app

# Remove the runtime package installer after all dependencies are present.
# Installed application dependencies remain intact; runtime code cannot invoke
# either `pip` or `ensurepip` to mutate the environment.
RUN python -m pip uninstall -y pip \
    && python -c "import pathlib, shutil, sysconfig; p = pathlib.Path(sysconfig.get_path('stdlib')) / 'ensurepip'; shutil.rmtree(p, ignore_errors=True)"

USER 65532:65532

EXPOSE 8000

# Runtime writes must stay outside immutable application source.
VOLUME ["/app/logs", "/app/sentinel43_state"]

# Uvicorn's proxy-header trust remains explicitly constrained here so an
# externally supplied FORWARDED_ALLOW_IPS=* cannot rewrite scope["client"]
# before SentinelFirewall evaluates the connection.
#
# Sentinel-43's application-level trusted proxy policy remains
# S43_TRUSTED_PROXIES. Deployments behind a reverse proxy must configure the
# Uvicorn allow-list to the immediate proxy addresses as well.
#
# Do not use "*" here.
CMD ["python", "-m", "uvicorn", "core.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips", "127.0.0.1"]
