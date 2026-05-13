# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `bun run dev` — hot-reload dev server (`NODE_ENV=development`, `src/server.ts`)
- `bun start` — production server
- `bun run lint` / `bun run lint:fix` — ESLint (flat config, `eslint.config.js`)
- `bun run typecheck` — `tsc --noEmit`
- `bun run validate` — lint:fix + typecheck

There is no test suite. Server defaults to `PORT=3000`. The config DB is stored as plaintext JSON (config files, route sources, managed CIDR audit). API access is gated by a master username + password the operator sets via the UI on first launch; subsequent launches require entering them via the **unlock** form before any non-auth API works. The master password is stored only as a scrypt hash (`scryptSync(username+"\x00"+password, salt, 32)`); there is no env-var override and no recovery path — losing the credentials means deleting `config/db.sqlite`. If the DB still uses the legacy AES-GCM schema (older `master` table with a `verify` column), `src/config.ts` throws on startup with a "delete and restart" message rather than attempting any migration.

## Runtime

Bun + TypeScript, ESM, `moduleResolution: bundler`, `verbatimModuleSyntax: true`, `strict: true`, `noUncheckedIndexedAccess: true`. Uses `bun:sqlite` directly — no migration framework. The frontend is plain ES modules served as static files (`public/`); there is no client bundler step.

## Architecture

This is a single-process app that lets a browser drive a UniFi UDM controller to keep traffic-route IP lists in sync with upstream CIDR feeds.

### Request flow
1. Server boots with the DB **locked**. `GET /api/status` returns `{ initialized, unlocked, connected }`; the frontend uses those flags to decide whether to show the setup, unlock, connect, or rules panel.
2. First launch — browser posts `{ username, password, passwordConfirm }` to `POST /api/auth/setup`. Server inserts a `master` row (random salt + scrypt-hashed password) and unlocks in-process. Subsequent launches — browser posts `{ username, password }` to `POST /api/auth/unlock`; server re-hashes the input with the stored salt and compares against `password_hash` via `timingSafeEqual`, and on success runs `restoreSessionFromConfig()` to re-attach any persisted UDM session under `restoredSid`. While the DB is locked, every non-auth `/api/*` endpoint returns 423.
3. Browser posts credentials to `POST /api/connect`. Server logs into the UDM, stores the session in an in-memory `Map<sid, UnifiSession>`, sets an httpOnly `sid` cookie, and persists the connection credentials as plaintext JSON in SQLite (`config/db.sqlite`).
4. `/api/firewall-rules` and `/api/policy-routes` each fan out to **two** UniFi endpoints in parallel (legacy v1 + modern v2) and return both result sets so the UI can render whichever the controller exposes.
5. The user assigns one or more CIDR-list URLs to a specific traffic-route id (`PUT /api/traffic-route/:id/sources`). `POST /api/traffic-route/:id/sync` fetches those URLs, parses CIDRs, and writes them into the route's `ip_addresses`.

### Module responsibilities
- **`src/server.ts`** — `Bun.serve` HTTP handler. Owns the session map, restored-session reattach logic, cookie parsing, the lock-state gate (every non-auth `/api/*` route short-circuits with 423 when `isUnlocked()` is false), and static file serving from `public/` (with a `startsWith(PUBLIC_DIR)` traversal guard).
- **`src/unifi.ts`** — UniFi API client. Speaks both UniFi OS (`/proxy/network/...`, login at `/api/auth/login`, CSRF via `X-CSRF-Token` header) and legacy controllers (`/api/...`, login at `/api/login`). `detectUnifiOs()` probes the root for the CSRF header or UniFi OS markers. TLS verification is disabled (`rejectUnauthorized: false`) to allow self-signed UDM certs.
- **`src/config.ts`** — SQLite persistence with four tables: `master` (single-row salt + scrypt password hash), `config` (single-row connection creds), `route_sources` (per-route URL lists), `route_managed_cidrs` (per-route audit of what we wrote last time). All data tables hold plaintext JSON (`data TEXT NOT NULL`); the master row is the only login-related thing and stores a hash, not encrypted material. Unlock state is a boolean on `globalThis` so Bun `--hot` reloads don't force a re-unlock. Every public storage function calls `requireUnlocked()` and throws `DatabaseLockedError` if the DB is locked. On startup, if the legacy encrypted `master` schema is detected (a `verify` column), the module throws immediately rather than trying to migrate. `setupMaster()`, `unlock()`, `lock()`, `isInitialized()`, `isUnlocked()` drive the state machine.
- **`src/iprange.ts`** — minimal CIDR parser. Strips `#` comments, keeps one CIDR per non-empty line, IPv6 is filtered out by the sync handler.

### Two non-obvious invariants

**CSRF token rotation.** UniFi OS rotates the CSRF token on every response (returned via `x-csrf-token` or `x-updated-csrf-token`). `authedFetch()` mutates `session.csrfToken` in place after each call. Missing this causes the *next* mutating request to fail — on some firmwares with a misleading "not connected to a UDM" 400.

**Preserving manual route entries.** `updateTrafficRouteIps()` reconciles three sets:
- `currentCidrs` — what the controller currently has
- `previouslyManaged` — what we wrote last sync (from `route_managed_cidrs`)
- `cidrsToManage` — fresh CIDRs from the source feeds

It computes `notManaged = currentCidrs \ previouslyManaged` (entries an operator added by hand) and writes `notManaged ∪ cidrsToManage`. This lets removals from upstream lists propagate while preserving manual additions. After a successful PUT, `route_managed_cidrs` is rewritten with the fresh CIDR set. Any change to this algorithm needs to preserve that contract.

### Notes for changes
- The v2 trafficroutes endpoint rejects GET-by-id (HTTP 405); fetch the full list and pick by `_id`. `updateTrafficRouteIps()` already does this.
- `matching_target` is forced to `"IP"` on every sync — switching a route to a different matching mode via the UI will be overwritten on the next sync.
- The `config/` directory is gitignored; do not commit `db.sqlite`.
