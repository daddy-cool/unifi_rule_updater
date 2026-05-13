// Persisted connection config.
//
// Stored at <project>/config/db.sqlite via bun:sqlite. The single row in
// the `config` table holds the UDM host, username, password, and site so the
// server can re-establish the session on startup. Treat as a credential file —
// the config/ directory is gitignored.
//
// Data is stored as plaintext JSON. The login (master username + password)
// gates API access but is NOT a key for encrypted storage. The master
// password is stored as a scrypt-derived hash for login verification only.
//
// Database states:
//   - uninitialized: no `master` row → setupMaster() must be called.
//   - locked: `master` row present, no unlock flag → unlock() must be called.
//   - unlocked: in-memory unlock flag is set.

import { Database } from "bun:sqlite";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";
import { join, dirname } from "node:path";
import { mkdirSync } from "node:fs";

const DB_PATH = join(import.meta.dir, "..", "config", "db.sqlite");

mkdirSync(dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH, { strict: true });
db.run("PRAGMA journal_mode = WAL");

// Fail-fast against the previous encrypted schema. The old master table had
// a `verify` BLOB and data tables held AES-GCM ciphertext blobs; none of
// that is readable now. The operator must delete the DB and start fresh.
const masterCols = db
  .query<{ name: string }, []>("PRAGMA table_info(master)")
  .all();
if (masterCols.some((c) => c.name === "verify")) {
  throw new Error(
    `Legacy encrypted database detected at ${DB_PATH}. ` +
      `Encryption has been removed; delete this file and restart to set up ` +
      `master credentials and reconnect to the UDM.`,
  );
}

db.run(`
  CREATE TABLE IF NOT EXISTS master (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS route_sources (
    route_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
  )
`);

// Tracks the set of CIDRs the server itself wrote into a route on the last
// successful sync. On the next sync we subtract this set from the route's
// current ip_addresses to recover any entries an operator added by hand, then
// union with the fresh source CIDRs. That way removals from source lists
// propagate to the controller without touching manual additions.
db.run(`
  CREATE TABLE IF NOT EXISTS route_managed_cidrs (
    route_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
  )
`);

// Stash the unlock flag on globalThis so Bun hot-reloads in dev don't force
// a re-unlock on every code change.
interface UnlockState { unlocked: boolean }
const unlockState: UnlockState = ((
  globalThis as unknown as { __unifiUnlockState?: UnlockState }
).__unifiUnlockState ??= { unlocked: false });

function hashPassword(username: string, password: string, salt: Buffer): Buffer {
  // Mixing the username into the KDF input means both fields participate in
  // the hash; we don't separately compare the stored username column.
  return scryptSync(`${username}\x00${password}`, salt, 32);
}

export class MasterCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MasterCredentialError";
  }
}

export class DatabaseLockedError extends Error {
  constructor() {
    super("Database is locked");
    this.name = "DatabaseLockedError";
  }
}

function requireUnlocked(): void {
  if (!unlockState.unlocked) throw new DatabaseLockedError();
}

export function isInitialized(): boolean {
  const row = db
    .query<{ c: number }, []>("SELECT COUNT(*) AS c FROM master WHERE id = 1")
    .get();
  return (row?.c ?? 0) > 0;
}

export function isUnlocked(): boolean {
  return unlockState.unlocked;
}

export function getMasterUsername(): string | null {
  const row = db
    .query<{ username: string }, []>(
      "SELECT username FROM master WHERE id = 1",
    )
    .get();
  return row?.username ?? null;
}

export function lock(): void {
  unlockState.unlocked = false;
}

const masterInsertStmt = db.query<
  unknown,
  { u: string; s: Buffer; h: Buffer }
>(
  "INSERT INTO master (id, username, salt, password_hash) VALUES (1, $u, $s, $h)",
);

export function setupMaster(username: string, password: string): void {
  if (isInitialized()) {
    throw new MasterCredentialError("Master credentials are already set");
  }
  if (!username || !password) {
    throw new MasterCredentialError("Username and password are required");
  }
  const salt = randomBytes(16);
  const hash = hashPassword(username, password, salt);
  masterInsertStmt.run({ u: username, s: salt, h: hash });
  unlockState.unlocked = true;
}

const masterSelectStmt = db.query<
  { username: string; salt: Uint8Array; password_hash: Uint8Array },
  []
>("SELECT username, salt, password_hash FROM master WHERE id = 1");

export function unlock(username: string, password: string): void {
  const row = masterSelectStmt.get();
  if (!row) {
    throw new MasterCredentialError("Database is not initialized");
  }
  const salt = Buffer.from(
    row.salt.buffer,
    row.salt.byteOffset,
    row.salt.byteLength,
  );
  const computed = hashPassword(username, password, salt);
  const stored = Buffer.from(
    row.password_hash.buffer,
    row.password_hash.byteOffset,
    row.password_hash.byteLength,
  );
  if (
    computed.length !== stored.length ||
    !timingSafeEqual(computed, stored)
  ) {
    throw new MasterCredentialError("Invalid username or password");
  }
  unlockState.unlocked = true;
}

const selectStmt = db.query<{ data: string }, []>(
  "SELECT data FROM config WHERE id = 1",
);
const upsertStmt = db.query<unknown, { data: string }>(
  `INSERT INTO config (id, data) VALUES (1, $data)
   ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
);
const deleteStmt = db.query("DELETE FROM config WHERE id = 1");

export interface StoredConfig {
  host: string;
  username: string;
  password: string;
  site: string;
}

function isStoredConfig(v: unknown): v is StoredConfig {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.host === "string" &&
    typeof o.username === "string" &&
    typeof o.password === "string" &&
    typeof o.site === "string"
  );
}

export function loadConfig(): StoredConfig | null {
  requireUnlocked();
  const row = selectStmt.get();
  if (!row) return null;
  const parsed: unknown = JSON.parse(row.data);
  if (!isStoredConfig(parsed)) {
    throw new Error("Persisted config does not match the expected schema");
  }
  return parsed;
}

export function saveConfig(cfg: StoredConfig): void {
  requireUnlocked();
  upsertStmt.run({ data: JSON.stringify(cfg) });
}

export function clearConfig(): void {
  requireUnlocked();
  deleteStmt.run();
}

const sourcesSelectStmt = db.query<{ data: string }, [string]>(
  "SELECT data FROM route_sources WHERE route_id = ?",
);
const sourcesUpsertStmt = db.query<unknown, { id: string; data: string }>(
  `INSERT INTO route_sources (route_id, data) VALUES ($id, $data)
   ON CONFLICT(route_id) DO UPDATE SET data = excluded.data`,
);

export interface RouteSources {
  urls: string[];
  // Optional auto-apply schedule. When > 0, the server runs the same
  // save+sync flow this many seconds apart for this route. Undefined or 0
  // means disabled.
  intervalSeconds?: number;
}

function isRouteSources(v: unknown): v is RouteSources {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (!Array.isArray(o.urls) || !o.urls.every((u) => typeof u === "string")) {
    return false;
  }
  if (o.intervalSeconds !== undefined && typeof o.intervalSeconds !== "number") {
    return false;
  }
  return true;
}

export function loadRouteSources(routeId: string): RouteSources | null {
  requireUnlocked();
  const row = sourcesSelectStmt.get(routeId);
  if (!row) return null;
  const parsed: unknown = JSON.parse(row.data);
  if (!isRouteSources(parsed)) {
    throw new Error(
      `Route sources for ${routeId} do not match the expected schema`,
    );
  }
  return parsed;
}

export function saveRouteSources(routeId: string, sources: RouteSources): void {
  requireUnlocked();
  sourcesUpsertStmt.run({ id: routeId, data: JSON.stringify(sources) });
}

const sourcesAllStmt = db.query<
  { route_id: string; data: string },
  []
>("SELECT route_id, data FROM route_sources");

export function listAllRouteSources(): Record<string, RouteSources> {
  requireUnlocked();
  const out: Record<string, RouteSources> = {};
  for (const row of sourcesAllStmt.all()) {
    const parsed: unknown = JSON.parse(row.data);
    if (!isRouteSources(parsed)) {
      throw new Error(
        `Route sources for ${row.route_id} do not match the expected schema`,
      );
    }
    out[row.route_id] = parsed;
  }
  return out;
}

const managedSelectStmt = db.query<{ data: string }, [string]>(
  "SELECT data FROM route_managed_cidrs WHERE route_id = ?",
);
const managedUpsertStmt = db.query<unknown, { id: string; data: string }>(
  `INSERT INTO route_managed_cidrs (route_id, data) VALUES ($id, $data)
   ON CONFLICT(route_id) DO UPDATE SET data = excluded.data`,
);
const managedDeleteStmt = db.query<unknown, [string]>(
  "DELETE FROM route_managed_cidrs WHERE route_id = ?",
);

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

export function loadManagedCidrs(routeId: string): string[] {
  requireUnlocked();
  const row = managedSelectStmt.get(routeId);
  if (!row) return [];
  const parsed: unknown = JSON.parse(row.data);
  if (!isStringArray(parsed)) {
    throw new Error(
      `Managed CIDRs for ${routeId} do not match the expected schema`,
    );
  }
  return parsed;
}

export function saveManagedCidrs(routeId: string, cidrs: string[]): void {
  requireUnlocked();
  if (cidrs.length === 0) {
    managedDeleteStmt.run(routeId);
    return;
  }
  managedUpsertStmt.run({ id: routeId, data: JSON.stringify(cidrs) });
}
