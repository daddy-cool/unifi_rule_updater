# unifi-rule-updater

A small self-hosted web app that keeps the IP lists on UniFi traffic routes in sync with upstream CIDR feeds. Point a route at one or more URLs that return CIDRs (one per line, `#` comments allowed), hit **Apply**, and the route's `ip_addresses` are updated in place. Manual entries added through the UniFi UI are preserved.

Works against UniFi OS controllers (UDM / UDM-Pro / UDR / UDM-SE / UNVR) and legacy self-hosted controllers. Self-signed certs are accepted.

## What it does

- Logs into your UniFi controller with credentials you provide during setup.
- Lists firewall rules and policy/traffic routes (queries both the v1 and v2 endpoints so you see whatever the controller exposes).
- Lets you attach one or more CIDR-feed URLs to a specific traffic route.
- On sync, fetches the feeds, parses CIDRs (IPv4 only), and reconciles them against the route — adding new entries, removing stale ones previously added, and keeping anything an operator added by hand.

## Requirements

- [Bun](https://bun.sh) 1.0+ (or Docker)
- Network access to the UniFi controller
- An admin account on the controller (local account recommended; SSO accounts won't work)


## Docker

```sh
docker run -d \
  --name unifi-rule-updater \
  -p port:3000 \
  -v /path/to/config:/app/config \
  -e 'TZ'='Europe/Berlin' \
  ghcr.io/daddy-cool/unifi-rule-updater:latest
```

## First launch

1. **Setup login credentials.** The browser prompts for a username + password to secure this app. Local to this app — it has nothing to do with your UniFi account.
2. **Connect to UniFi.** Enter the controller hostname/IP and a UniFi admin username + password. The session is persisted so you don't need to re-enter it after restarts.
3. **Assign feeds** Pick a traffic route, paste one or more CIDR-feed URLs.
4. **Scheduler** Activate auto-apply and set an interval to automatically refresh IPs for this route.
5. **Apply** Saved & applies the setting for this route.

## Behaviour worth knowing

- **Manual entries are preserved.** The sync algorithm tracks what it wrote last time, diffs that against the route's current contents, and treats anything else as operator-added — those entries stay even if they aren't in the feeds.
- **IPv6 is filtered out** by the sync step. Only IPv4 CIDRs are written.
- **`matching_target` is forced to `"IP"`** on every sync. If you change a managed route to a different matching mode in the UniFi UI, the next sync will overwrite it.
- TLS verification is disabled for the controller connection (UDMs ship with self-signed certs). If that matters to you, run this app on a trusted network segment.

## Security notes

- The browser session cookie (`sid`) is `httpOnly`; serve this app behind HTTPS in any non-trivial setup.
- This app stores your UniFi admin credentials so it can re-authenticate after a session expires. Use a dedicated UniFi admin account if that bothers you.