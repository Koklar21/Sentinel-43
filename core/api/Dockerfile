# Alpine avoids the unfixed Debian package findings in the former slim image.
# Keep the Python minor version aligned with CI and verify the resulting image.
FROM python:3.13-alpine AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Exercise the same native dependencies and libc as the release image.
# This stage is built only by CI; test tooling is absent from the final image.
FROM dependencies AS test
RUN python -m pip install --no-cache-dir pytest requests
COPY . /app
ENV S43_WATCHTOWER_URL=http://127.0.0.1:19100
ENV S43_WATCHTOWER_TIMEOUT=0.1

FROM dependencies AS runtime
RUN python -m pip uninstall -y pip \
    && python -c "import pathlib, shutil, sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path('stdlib')) / 'ensurepip')"

COPY . /app

# Non-root by default. Fixed, unprivileged UID/GID (not allocated by the
# base image) so it's stable across rebuilds and matches the
# runAsUser/runAsGroup pinned in deploy/kubernetes' Pod securityContexts.
# The app never writes inside /app at runtime (PYTHONDONTWRITEBYTECODE=1,
# and its only writable paths — logs, sentinel43_state, /tmp — are always
# volume-mounted separately in both Docker Compose and Kubernetes), so no
# chown of /app is needed: root-owned, world-readable files are sufficient
# for a non-root process that only reads them.
#
# Pre-creating and chowning /app/logs and /app/sentinel43_state here matters
# for Docker named volumes (e.g. docker-compose.yml's sentinel43_state
# volume): on first mount, Docker initializes a named volume's contents from
# whatever exists at that path in the image, ownership included. Without
# this, a fresh named volume is created root-owned and the non-root process
# below can't write to it. This does not help host bind mounts (e.g.
# docker-compose.yml's ./logs mount) — those always take the host
# directory's own ownership, see the comment there. Kubernetes doesn't need
# this either (fsGroup in the Pod securityContext handles emptyDir/PVC
# ownership), but it's harmless there too.
#
# The s43-setup service in docker-compose.yml deliberately overrides `user:`
# back to root, since it bind-mounts the host repo root and must write
# .env as whatever user owns the host checkout — see that service's comment.
RUN addgroup -S -g 65532 s43 \
    && adduser -S -D -H -u 65532 -G s43 -s /sbin/nologin s43 \
    && mkdir -p /app/logs /app/sentinel43_state \
    && chown -R 65532:65532 /app/logs /app/sentinel43_state
USER 65532:65532

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "core.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
