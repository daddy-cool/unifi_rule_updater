# unifi-rule-updater

A small self-hosted web app that keeps the IP lists on UniFi traffic routes in sync with upstream CIDR feeds. Point a route at one or more URLs that return CIDRs (one per line, `#` comments allowed), hit **Apply**, and the route's `ip_addresses` are updated in place. Manual entries added through the UniFi UI are preserved.

Works against UniFi OS controllers (UDM / UDM-Pro / UDR / UDM-SE / UNVR) running Network 8.x or newer. Self-signed certs are accepted.

## What it does

- Logs into your UniFi controller with credentials you provide during setup.
- Lists the controller's zone-based firewall policies and traffic routes (the modern v2 endpoints).
- Lets you attach one or more CIDR-feed URLs to a specific traffic route.
- On sync, fetches the feeds, parses CIDRs (IPv4 only), and reconciles them against the route — adding new entries, removing stale ones previously added, and keeping anything an operator added by hand.
- Optional per-route auto-apply schedule. Once enabled, the server re-runs the sync on the interval you choose and continues running across restarts without needing anyone to log into the web UI.

## Requirements

- [Bun](https://bun.sh) 1.0+ (or Docker)
- Network access to the UniFi controller
- An admin account on the controller (local account recommended; SSO accounts won't work)


## Docker

```sh
docker run -d \
  --name unifi-rule-updater \
  -p 3000:3000 \
  -v /path/to/config:/app/config \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Europe/Berlin \
  ghcr.io/daddy-cool/unifi-rule-updater:latest
```

### `PUID` / `PGID`

The container starts as root, `chown`s `/app/config` to `PUID:PGID`, then drops to that user before running the app. Set `PUID`/`PGID` to whatever owns the host directory you bind-mounted. Default is `1000:1000`. SQLite needs read/write on both `/app/config` *and* the files inside it, which is why the entrypoint owns the directory rather than relying on existing ACLs.

### TrueNAS Scale

If you see `SQLiteError: unable to open database file` (`SQLITE_CANTOPEN`), the container couldn't write into your mounted dataset. To fix:

1. In the app config, set the container to run as **root** (User ID 0, Group ID 0). The entrypoint needs root to chown the volume and to call `su-exec`. It will drop privileges before the bun process actually runs.
2. Set the env vars `PUID` and `PGID` to the UID/GID that owns your ZFS dataset on the host. On TrueNAS Scale the apps dataset is typically `568:568` — check with `ls -ld /mnt/<pool>/<dataset>` from the TrueNAS shell.
3. Restart the app.

## First launch

1. **Setup login credentials.** The browser prompts for a username + password to secure this app. Local to this app — it has nothing to do with your UniFi account. There's no recovery path; if you lose them, delete `config/db.sqlite` and start over.
2. **Connect to UniFi.** Enter the controller hostname/IP and a UniFi admin username + password. The session is persisted so you don't need to re-enter it after restarts.
3. **Assign feeds.** Pick a traffic route, paste one or more CIDR-feed URLs.
4. **Scheduler.** Activate auto-apply and set an interval to automatically refresh IPs for this route. Auto-sync continues to run across server restarts without anyone unlocking the web UI.
5. **Apply.** Saves & applies the setting for this route.

## Behaviour worth knowing

- **Manual entries are preserved.** The sync algorithm tracks what it wrote last time, diffs that against the route's current contents, and treats anything else as operator-added — those entries stay even if they aren't in the feeds.
- **IPv6 is filtered out** by the sync step. Only IPv4 CIDRs are written.
- **`matching_target` is forced to `"IP"`** on every sync. If you change a managed route to a different matching mode in the UniFi UI, the next sync will overwrite it.
- TLS verification is disabled for the controller connection (UDMs ship with self-signed certs). If that matters to you, run this app on a trusted network segment.

## Security notes

- The browser session cookie (`sid`) is `httpOnly`; serve this app behind HTTPS in any non-trivial setup.
- This app stores your UniFi admin credentials in `config/db.sqlite` so it can re-authenticate after a session expires and so the auto-sync scheduler can log in by itself after a server restart. Use a dedicated UniFi admin account and keep the config directory off shared storage.
- The app's own login (master username + password) is a soft gate on the HTTP API — it stops casual access to the web UI but is not protecting anything at rest.