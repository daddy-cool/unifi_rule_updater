import { file } from "bun";
import { join } from "node:path";
import { getLogger } from "./logger";
import {
  login,
  logout,
  getFirewallRules,
  getPolicyRoutes,
  updateTrafficRouteIps,
  UnifiError,
  type UnifiSession,
} from "./unifi";
import {
  loadConfig,
  saveConfig,
  clearConfig,
  loadRouteSources,
  saveRouteSources,
  listAllRouteSources,
  loadManagedCidrs,
  saveManagedCidrs,
  isInitialized,
  isUnlocked,
  setupMaster,
  unlock,
  lock,
  getMasterUsername,
  MasterCredentialError,
} from "./config";
import { parseCidrList, isIpv4Cidr } from "./iprange";

const PORT = Number(process.env.PORT ?? 3000);
const PUBLIC_DIR = join(import.meta.dir, "..", "public");

const log = getLogger(["app"]);

// In-memory session store. Keyed by a random session id we hand to the browser
// as an httpOnly cookie. Multiple users can have parallel sessions; the
// browser session id only authorizes access to the UDM connection it opened.
const sessions = new Map<string, UnifiSession>();

// Session restored from persisted config after unlock. Any browser hitting
// /api/status without a valid cookie gets attached to this so the UI reconnects
// automatically after a server restart + unlock.
let restoredSid: string | null = null;

function newSessionId(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.get("cookie") ?? "";
  const out: Record<string, string> = {};
  for (const part of header.split(/;\s*/)) {
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    out[part.slice(0, eq)] = decodeURIComponent(part.slice(eq + 1));
  }
  return out;
}

function json(
  body: unknown,
  init: Omit<ResponseInit, "headers"> & { headers?: Record<string, string> } = {},
): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

function getSession(req: Request): {
  cookieSid: string | null;
  sid: string | null;
  session: UnifiSession | null;
} {
  const cookieSid = parseCookies(req).sid ?? null;
  if (cookieSid) {
    const direct = sessions.get(cookieSid);
    if (direct) return { cookieSid, sid: cookieSid, session: direct };
  }
  // Fall back to the session we restored from persisted config on unlock so
  // that a browser whose cookie no longer matches the in-memory map (server
  // restart, --hot reload) still finds the live UDM session instead of getting
  // a 401. handleStatus is what eventually refreshes the cookie.
  if (restoredSid) {
    const restored = sessions.get(restoredSid);
    if (restored) return { cookieSid, sid: restoredSid, session: restored };
  }
  return { cookieSid, sid: cookieSid, session: null };
}

function lockedResponse(): Response {
  return json({ error: "Database is locked" }, { status: 423 });
}

async function restoreSessionFromConfig(): Promise<void> {
  // loadConfig() throws if the persisted JSON is malformed or fails schema
  // validation; we intentionally do NOT catch that so the caller surfaces it
  // rather than silently dropping persisted state.
  const cfg = loadConfig();
  if (!cfg) return;
  try {
    const session = await login(cfg);
    const sid = newSessionId();
    sessions.set(sid, session);
    restoredSid = sid;
    log.info(
      "Restored session for {user}@{host} (site: {site})",
      { user: session.username, host: session.host, site: session.site },
    );
  } catch (err) {
    log.error("Could not restore session from saved config: {err}", { err });
  }
}

async function handleAuthSetup(req: Request): Promise<Response> {
  let body: { username?: string; password?: string; passwordConfirm?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (isInitialized()) {
    return json(
      { error: "Master credentials are already set" },
      { status: 409 },
    );
  }
  const username = body.username?.trim() ?? "";
  const password = body.password ?? "";
  const confirm = body.passwordConfirm ?? "";
  if (!username || !password) {
    return json(
      { error: "Username and password are required" },
      { status: 400 },
    );
  }
  if (password !== confirm) {
    return json({ error: "Passwords do not match" }, { status: 400 });
  }
  try {
    setupMaster(username, password);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: msg }, { status: 400 });
  }
  return json({ ok: true, initialized: true, unlocked: true });
}

async function handleAuthUnlock(req: Request): Promise<Response> {
  let body: { username?: string; password?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!isInitialized()) {
    return json({ error: "Database is not initialized" }, { status: 409 });
  }
  const username = body.username?.trim() ?? "";
  const password = body.password ?? "";
  if (!username || !password) {
    return json(
      { error: "Username and password are required" },
      { status: 400 },
    );
  }
  try {
    unlock(username, password);
  } catch (err) {
    if (err instanceof MasterCredentialError) {
      return json({ error: err.message }, { status: 401 });
    }
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: msg }, { status: 500 });
  }
  await restoreSessionFromConfig();
  rescheduleAllAutoSync();
  return json({ ok: true, initialized: true, unlocked: true });
}

function handleAuthLock(req: Request): Response {
  // Drop any sessions tied to the unlocked DB — we no longer have the key to
  // re-restore them and persisted credentials become unreadable until unlock.
  const { sid } = getSession(req);
  if (sid) {
    const s = sessions.get(sid);
    if (s) void logout(s);
    sessions.delete(sid);
  }
  if (restoredSid) {
    const s = sessions.get(restoredSid);
    if (s) void logout(s);
    sessions.delete(restoredSid);
    restoredSid = null;
  }
  clearAutoSyncTimers();
  lock();
  return json(
    { ok: true, initialized: isInitialized(), unlocked: false },
    {
      headers: {
        "Set-Cookie": `sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      },
    },
  );
}

async function handleConnect(req: Request): Promise<Response> {
  let body: { host?: string; username?: string; password?: string; site?: string };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (!body.host || !body.username || !body.password) {
    return json(
      { error: "host, username, and password are required" },
      { status: 400 },
    );
  }

  try {
    const session = await login({
      host: body.host,
      username: body.username,
      password: body.password,
      site: body.site,
    });

    // Replace any existing session for this browser.
    const { sid: existingSid } = getSession(req);
    if (existingSid) {
      const existing = sessions.get(existingSid);
      if (existing) {
        void logout(existing);
        sessions.delete(existingSid);
      }
    }

    const sid = newSessionId();
    sessions.set(sid, session);

    try {
      saveConfig({
        host: body.host,
        username: body.username,
        password: body.password,
        site: body.site ?? "default",
      });
    } catch (saveErr) {
      log.error("Failed to persist config: {err}", { err: saveErr });
    }

    return json(
      {
        ok: true,
        host: session.host,
        site: session.site,
        username: session.username,
        isUnifiOs: session.isUnifiOs,
      },
      {
        headers: {
          "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`,
        },
      },
    );
  } catch (err) {
    if (err instanceof UnifiError) {
      return json({ error: err.message, status: err.status }, { status: 400 });
    }
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: `Connection failed: ${msg}` }, { status: 500 });
  }
}

function handleDisconnect(req: Request): Response {
  const { sid, session } = getSession(req);
  if (session) void logout(session);
  if (sid) sessions.delete(sid);
  if (restoredSid && (sid === restoredSid || !sid)) {
    const restored = sessions.get(restoredSid);
    if (restored) void logout(restored);
    sessions.delete(restoredSid);
    restoredSid = null;
  }
  try {
    clearConfig();
  } catch (clearErr) {
    log.error("Failed to clear persisted config: {err}", { err: clearErr });
  }
  return json(
    { ok: true },
    {
      headers: {
        "Set-Cookie": `sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      },
    },
  );
}

function handleStatus(req: Request): Response {
  const initialized = isInitialized();
  const unlocked = isUnlocked();
  if (!unlocked) {
    return json({
      initialized,
      unlocked,
      connected: false,
      masterUsername: initialized ? getMasterUsername() : null,
    });
  }
  const { cookieSid, sid: activeSid, session: active } = getSession(req);
  if (!active) return json({ initialized, unlocked, connected: false });
  const init =
    activeSid && activeSid !== cookieSid
      ? {
          headers: {
            "Set-Cookie": `sid=${activeSid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`,
          },
        }
      : {};
  return json(
    {
      initialized,
      unlocked,
      connected: true,
      host: active.host,
      site: active.site,
      username: active.username,
      isUnifiOs: active.isUnifiOs,
    },
    init,
  );
}

async function handleFirewallRules(req: Request): Promise<Response> {
  const { session } = getSession(req);
  if (!session) {
    return json({ error: "Not connected to a UDM" }, { status: 401 });
  }
  try {
    const rules = await getFirewallRules(session);
    return json(rules);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: msg }, { status: 502 });
  }
}

async function handlePolicyRoutes(req: Request): Promise<Response> {
  const { session } = getSession(req);
  if (!session) {
    return json({ error: "Not connected to a UDM" }, { status: 401 });
  }
  try {
    const routes = await getPolicyRoutes(session);
    return json(routes);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: msg }, { status: 502 });
  }
}

// Minimum interval the server will accept. Anything lower would either DoS
// the upstream CIDR feeds or beat up the UDM for no reason.
const MIN_INTERVAL_SECONDS = 60;

function handleGetSources(routeId: string): Response {
  const sources = loadRouteSources(routeId);
  return json({
    urls: sources?.urls ?? [],
    intervalSeconds: sources?.intervalSeconds ?? 0,
  });
}

async function handlePutSources(
  req: Request,
  routeId: string,
): Promise<Response> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400 });
  }
  const obj = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  if (!Array.isArray(obj.urls)) {
    return json({ error: "Body must be { urls: string[] }" }, { status: 400 });
  }
  const urls = obj.urls
    .filter((u): u is string => typeof u === "string")
    .map((u) => u.trim())
    .filter((u) => u.length > 0);
  let intervalSeconds = 0;
  if (typeof obj.intervalSeconds === "number" && Number.isFinite(obj.intervalSeconds)) {
    intervalSeconds = Math.floor(obj.intervalSeconds);
  }
  if (intervalSeconds < 0) intervalSeconds = 0;
  if (intervalSeconds > 0 && intervalSeconds < MIN_INTERVAL_SECONDS) {
    return json(
      { error: `intervalSeconds must be 0 or >= ${String(MIN_INTERVAL_SECONDS)}` },
      { status: 400 },
    );
  }
  saveRouteSources(routeId, { urls, intervalSeconds: intervalSeconds || undefined });
  rescheduleRoute(routeId);
  return json({ ok: true, urls, intervalSeconds });
}

// Per-route auto-sync timers. Stashed on globalThis so Bun --hot reloads don't
// orphan timers from the previous module instance.
interface TimerCache {
  timers: Map<string, ReturnType<typeof setInterval>>;
}
const timerCache: TimerCache = ((
  globalThis as unknown as { __unifiAutoSyncTimers?: TimerCache }
).__unifiAutoSyncTimers ??= { timers: new Map() });

function clearAutoSyncTimers(): void {
  for (const t of timerCache.timers.values()) clearInterval(t);
  timerCache.timers.clear();
}

function scheduleRoute(routeId: string, intervalSeconds: number): void {
  const existing = timerCache.timers.get(routeId);
  if (existing) clearInterval(existing);
  if (intervalSeconds < MIN_INTERVAL_SECONDS) {
    timerCache.timers.delete(routeId);
    return;
  }
  const timer = setInterval(() => {
    void runScheduledSync(routeId);
  }, intervalSeconds * 1000);
  timerCache.timers.set(routeId, timer);
  log.info(
    "auto-sync scheduled every {seconds}s for route {routeId}",
    { seconds: intervalSeconds, routeId },
  );
}

function rescheduleRoute(routeId: string): void {
  const sources = loadRouteSources(routeId);
  scheduleRoute(routeId, sources?.intervalSeconds ?? 0);
}

function rescheduleAllAutoSync(): void {
  clearAutoSyncTimers();
  if (!isUnlocked()) return;
  const all = listAllRouteSources();
  for (const [routeId, sources] of Object.entries(all)) {
    if (sources.intervalSeconds && sources.intervalSeconds >= MIN_INTERVAL_SECONDS) {
      scheduleRoute(routeId, sources.intervalSeconds);
    }
  }
}

async function runScheduledSync(routeId: string): Promise<void> {
  if (!isUnlocked()) {
    log.warn("auto-sync skipped for {routeId}: database is locked", { routeId });
    return;
  }
  const session = restoredSid ? sessions.get(restoredSid) ?? null : null;
  if (!session) {
    log.warn("auto-sync skipped for {routeId}: no active UDM session", { routeId });
    return;
  }
  try {
    const { status, report } = await runSync(session, routeId, "scheduler");
    if (!(status === 200 && report.ok)) {
      log.error(
        "auto-sync failed for {routeId} (status={status}): {errors}",
        {
          routeId,
          status,
          errors: report.errors.map((e) => e.error).join("; "),
        },
      );
    }
  } catch (err) {
    log.error("auto-sync threw for {routeId}: {err}", { routeId, err });
  }
}

interface SyncReport {
  ok: boolean;
  added?: number;
  removed?: number;
  totalCidrs?: number;
  ipv6Skipped?: number;
  errors: { source?: string; cidr?: string; error: string }[];
}

async function fetchAndExpandSources(
  urls: string[],
): Promise<{
  cidrs: string[];
  totalCidrs: number;
  ipv6Skipped: number;
  errors: SyncReport["errors"];
}> {
  const cidrs: string[] = [];
  const errors: SyncReport["errors"] = [];
  let totalCidrs = 0;
  let ipv6Skipped = 0;

  for (const u of urls) {
    let text: string;
    try {
      const res = await fetch(u);
      if (!res.ok) {
        errors.push({ source: u, error: `HTTP ${String(res.status)}` });
        continue;
      }
      text = await res.text();
    } catch (err) {
      errors.push({
        source: u,
        error: err instanceof Error ? err.message : String(err),
      });
      continue;
    }
    for (const cidr of parseCidrList(text)) {
      totalCidrs++;
      if (!isIpv4Cidr(cidr)) {
        ipv6Skipped++;
        continue;
      }
      cidrs.push(cidr);
    }
  }
  return { cidrs, totalCidrs, ipv6Skipped, errors };
}

async function runSync(
  session: UnifiSession,
  routeId: string,
  trigger: "user" | "scheduler",
): Promise<{ status: 200 | 500 | 502; report: SyncReport }> {
  const sources = loadRouteSources(routeId);
  const expanded = await fetchAndExpandSources(sources?.urls ?? []);
  const previouslyManaged = loadManagedCidrs(routeId);
  try {
    const diff = await updateTrafficRouteIps(
      session,
      routeId,
      expanded.cidrs,
      previouslyManaged,
    );
    saveManagedCidrs(routeId, expanded.cidrs);
    const changed = diff.added > 0 || diff.removed > 0;
    const level = trigger === "user" || changed ? "info" : "debug";
    log[level](
      "Route updated: {description} ({routeId}) — added={added} removed={removed} trigger={trigger}",
      {
        description: diff.description,
        routeId,
        added: diff.added,
        removed: diff.removed,
        trigger,
      },
    );
    return {
      status: 200,
      report: {
        ok: true,
        added: diff.added,
        removed: diff.removed,
        totalCidrs: expanded.totalCidrs,
        ipv6Skipped: expanded.ipv6Skipped,
        errors: expanded.errors,
      },
    };
  } catch (err) {
    if (err instanceof UnifiError) {
      const detail =
        err.body == null
          ? ""
          : typeof err.body === "string"
            ? `: ${err.body}`
            : `: ${JSON.stringify(err.body)}`;
      return {
        status: 502,
        report: {
          ok: false,
          added: 0,
          removed: 0,
          totalCidrs: expanded.totalCidrs,
          ipv6Skipped: expanded.ipv6Skipped,
          errors: [
            ...expanded.errors,
            { error: `${err.message}${detail}` },
          ],
        },
      };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return {
      status: 500,
      report: {
        ok: false,
        added: 0,
        removed: 0,
        totalCidrs: expanded.totalCidrs,
        ipv6Skipped: expanded.ipv6Skipped,
        errors: [...expanded.errors, { error: msg }],
      },
    };
  }
}

async function handleSyncSources(
  req: Request,
  routeId: string,
): Promise<Response> {
  const { session } = getSession(req);
  if (!session) {
    return json({ error: "Not connected to a UDM" }, { status: 401 });
  }
  const { status, report } = await runSync(session, routeId, "user");
  return json(report, status === 200 ? {} : { status });
}

async function serveStatic(pathname: string): Promise<Response> {
  const rel = pathname === "/" ? "/index.html" : pathname;
  const filePath = join(PUBLIC_DIR, rel);
  // Prevent path traversal.
  if (!filePath.startsWith(PUBLIC_DIR)) {
    return new Response("Forbidden", { status: 403 });
  }
  const f = file(filePath);
  if (!(await f.exists())) {
    return new Response("Not found", { status: 404 });
  }
  return new Response(f);
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const { pathname } = url;

    // Auth endpoints — always reachable regardless of lock state.
    if (pathname === "/api/auth/setup" && req.method === "POST") {
      return handleAuthSetup(req);
    }
    if (pathname === "/api/auth/unlock" && req.method === "POST") {
      return handleAuthUnlock(req);
    }
    if (pathname === "/api/auth/lock" && req.method === "POST") {
      return handleAuthLock(req);
    }
    if (pathname === "/api/status" && req.method === "GET") {
      return handleStatus(req);
    }

    // Everything else requires an unlocked DB.
    if (pathname.startsWith("/api/") && !isUnlocked()) {
      return lockedResponse();
    }

    if (pathname === "/api/connect" && req.method === "POST") {
      return handleConnect(req);
    }
    if (pathname === "/api/disconnect" && req.method === "POST") {
      return handleDisconnect(req);
    }
    if (pathname === "/api/firewall-rules" && req.method === "GET") {
      return handleFirewallRules(req);
    }
    if (pathname === "/api/policy-routes" && req.method === "GET") {
      return handlePolicyRoutes(req);
    }
    if (pathname === "/api/route-sources" && req.method === "GET") {
      return json(listAllRouteSources());
    }
    const sourcesMatch = /^\/api\/traffic-route\/([^/]+)\/sources$/.exec(pathname);
    if (sourcesMatch?.[1]) {
      const routeId = decodeURIComponent(sourcesMatch[1]);
      if (req.method === "GET") return handleGetSources(routeId);
      if (req.method === "PUT") return handlePutSources(req, routeId);
      return json({ error: "Method not allowed" }, { status: 405 });
    }
    const syncMatch = /^\/api\/traffic-route\/([^/]+)\/sync$/.exec(pathname);
    if (syncMatch?.[1] && req.method === "POST") {
      return handleSyncSources(req, decodeURIComponent(syncMatch[1]));
    }
    if (pathname.startsWith("/api/")) {
      return json({ error: "Not found" }, { status: 404 });
    }

    return serveStatic(pathname);
  },
  error(err) {
    log.error("Unhandled server error: {err}", { err });
    return json({ error: "Internal server error" }, { status: 500 });
  },
});

log.info(`Listening on ${server.url.toString()}`);
