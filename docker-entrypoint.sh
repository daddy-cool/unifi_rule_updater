#!/bin/sh
set -e

# PUID/PGID let an operator map the in-container user to a host user so files
# written to the mounted /app/config volume end up with sensible ownership.
# Defaults match the linuxserver.io convention.
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# If the orchestrator (k8s securityContext, `docker run --user`, etc.) has
# already forced us into a non-root UID we can't chown or su-exec — just trust
# that the host has arranged for this UID to be able to write /app/config and
# hand off to the CMD directly. The bun process will throw SQLITE_CANTOPEN if
# that assumption is wrong, which is the clearest possible failure mode.
if [ "$(id -u)" != "0" ]; then
  exec "$@"
fi

# Running as root — make the persisted volume writable by the target user.
# Tolerate failures so the container still starts on filesystems that don't
# allow chown (some Windows bind mounts, NFS exports without root squash off).
chown -R "$PUID:$PGID" /app/config 2>/dev/null || true

if [ "$PUID" = "0" ] && [ "$PGID" = "0" ]; then
  exec "$@"
fi

exec su-exec "$PUID:$PGID" "$@"
