// UniFi UDM API client.
//
// UDM/UniFi OS controllers (UDM, UDM Pro, UDM SE, UDR, UCG, Cloud Key Gen2+):
//   - Login:   POST  /api/auth/login            { username, password, remember }
//              Returns a TOKEN cookie + X-CSRF-Token response header.
//   - API:     prefixed with /proxy/network/...
//
// Legacy non-UniFi-OS controllers:
//   - Login:   POST  /api/login                 { username, password }
//   - API:     /api/...
//
// Firewall and routing data this app cares about live at the v2 endpoints:
//   - Zone-based firewall policies: /v2/api/site/{site}/firewall-policies
//   - Traffic routes:               /v2/api/site/{site}/trafficroutes

export interface UnifiSession {
  host: string;
  username: string;
  // Kept on the session so authedFetch() can transparently re-login when the
  // UDM expires the cookie (typically after ~2h). The password is already
  // plaintext in the persisted config; the in-memory copy doesn't change that.
  password: string;
  site: string;
  cookie: string;
  csrfToken: string | null;
  isUnifiOs: boolean;
  controllerInfo?: Record<string, unknown>;
  // De-dupes concurrent re-login attempts when multiple requests get 401 at
  // the same time. First caller drives the login; the rest await it.
  reloginPending?: Promise<void> | null;
}

export class UnifiError extends Error {
  status: number;
  body: unknown;
  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const FETCH_TLS_OPTS = { tls: { rejectUnauthorized: false } } as RequestInit & {
  tls: { rejectUnauthorized: boolean };
};

function normalizeHost(host: string): string {
  let h = host.trim();
  if (!/^https?:\/\//i.test(h)) h = `https://${h}`;
  return h.replace(/\/+$/, "");
}

function parseSetCookie(setCookie: string | null): string {
  if (!setCookie) return "";
  // Bun joins multiple Set-Cookie headers with ", " — split on commas that precede a cookie name.
  // Each cookie's first segment (name=value) is what we want.
  const parts = setCookie.split(/,(?=\s*[A-Za-z0-9_-]+=)/);
  return parts
    .map((c) => c.split(";")[0]?.trim() ?? "")
    .filter(Boolean)
    .join("; ");
}

async function detectUnifiOs(host: string): Promise<boolean> {
  // UniFi OS controllers respond to GET / with a redirect or HTML and expose
  // /api/system on the root. We probe HEAD on / and check for the
  // X-CSRF-Token header that UniFi OS sets, or a 200 from /proxy/network.
  try {
    const res = await fetch(`${host}/`, {
      method: "GET",
      redirect: "manual",
      ...FETCH_TLS_OPTS,
    });
    // UniFi OS sets an x-csrf-token on most responses.
    if (res.headers.get("x-csrf-token")) return true;
    // Some firmwares 302 to /manage which is UniFi OS-ish behavior.
    if (res.status === 200 || res.status === 302) {
      const body = await res.text().catch(() => "");
      if (/unifi os|unifios/i.test(body)) return true;
    }
  } catch {
    // ignore — caller will surface a clearer error on login
  }
  return false;
}

interface LoginResult {
  cookie: string;
  csrfToken: string | null;
  controllerInfo?: Record<string, unknown>;
}

async function performLogin(
  host: string,
  isUnifiOs: boolean,
  username: string,
  password: string,
): Promise<LoginResult> {
  const loginPath = isUnifiOs ? "/api/auth/login" : "/api/login";

  const res = await fetch(`${host}${loginPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, remember: true }),
    redirect: "manual",
    ...FETCH_TLS_OPTS,
  });

  if (res.status >= 400) {
    const body = await res.text().catch(() => "");
    let parsed: unknown = body;
    try {
      parsed = JSON.parse(body);
    } catch {
      // body wasn't JSON; keep raw text
    }
    throw new UnifiError(
      res.status === 401 || res.status === 403
        ? "Invalid username or password"
        : `Login failed (HTTP ${String(res.status)})`,
      res.status,
      parsed,
    );
  }

  const cookie = parseSetCookie(res.headers.get("set-cookie"));
  const csrfToken = res.headers.get("x-csrf-token");

  if (!cookie) {
    throw new UnifiError(
      "Controller accepted credentials but returned no session cookie",
      500,
      null,
    );
  }

  let controllerInfo: Record<string, unknown> | undefined;
  try {
    controllerInfo = (await res.json()) as Record<string, unknown>;
  } catch {
    // login response had no JSON body
  }

  return { cookie, csrfToken, controllerInfo };
}

export async function login(opts: {
  host: string;
  username: string;
  password: string;
  site?: string;
}): Promise<UnifiSession> {
  const host = normalizeHost(opts.host);
  const trimmedSite = opts.site?.trim();
  const site = trimmedSite && trimmedSite.length > 0 ? trimmedSite : "default";
  const isUnifiOs = await detectUnifiOs(host);
  const { cookie, csrfToken, controllerInfo } = await performLogin(
    host,
    isUnifiOs,
    opts.username,
    opts.password,
  );

  return {
    host,
    username: opts.username,
    password: opts.password,
    site,
    cookie,
    csrfToken,
    isUnifiOs,
    controllerInfo,
    reloginPending: null,
  };
}

// Refreshes the cookie/CSRF on an existing session in place. Used by
// authedFetch() when the UDM returns 401 (the cookie has expired). Concurrent
// callers share a single in-flight login via session.reloginPending so a burst
// of expired-cookie 401s only triggers one re-auth, not one per request.
async function relogin(session: UnifiSession): Promise<void> {
  if (session.reloginPending) {
    await session.reloginPending;
    return;
  }
  session.reloginPending = (async () => {
    const { cookie, csrfToken } = await performLogin(
      session.host,
      session.isUnifiOs,
      session.username,
      session.password,
    );
    session.cookie = cookie;
    session.csrfToken = csrfToken;
  })();
  try {
    await session.reloginPending;
  } finally {
    session.reloginPending = null;
  }
}

function apiPath(session: UnifiSession, suffix: string): string {
  const prefix = session.isUnifiOs ? "/proxy/network" : "";
  return `${session.host}${prefix}${suffix}`;
}

async function authedFetch(
  session: UnifiSession,
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const doFetch = async (): Promise<Response> => {
    const headers = new Headers(init.headers);
    headers.set("Cookie", session.cookie);
    if (session.csrfToken) headers.set("X-CSRF-Token", session.csrfToken);
    headers.set("Accept", "application/json");
    const res = await fetch(url, {
      ...init,
      headers,
      redirect: "manual",
      ...FETCH_TLS_OPTS,
    });
    // UniFi OS rotates the CSRF token on every response. Without picking up
    // the new value, the next mutating request gets rejected — on some
    // firmwares with a misleading "not connected to a UDM" 400 instead of a
    // clean 403.
    const nextCsrf =
      res.headers.get("x-csrf-token") ??
      res.headers.get("x-updated-csrf-token");
    if (nextCsrf) session.csrfToken = nextCsrf;
    return res;
  };

  const res = await doFetch();
  // UDM cookies expire after ~2h. On 401, transparently re-login and retry
  // once so long-running processes (the auto-sync scheduler) stay alive
  // without operator intervention. If the re-login itself fails (creds
  // changed, UDM unreachable), surface the original 401 to the caller.
  if (res.status !== 401) return res;
  try {
    await relogin(session);
  } catch {
    return res;
  }
  return doFetch();
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export interface FirewallRulesResult {
  zonePolicies: {
    ok: boolean;
    count: number;
    policies: unknown[];
    error?: string;
  };
}

export async function getFirewallRules(
  session: UnifiSession,
): Promise<FirewallRulesResult> {
  const result: FirewallRulesResult = {
    zonePolicies: { ok: false, count: 0, policies: [] },
  };

  // Zone-based firewall policies (Network 8.x+).
  try {
    const url = apiPath(
      session,
      `/v2/api/site/${encodeURIComponent(session.site)}/firewall-policies`,
    );
    const res = await authedFetch(session, url);
    const body = await readJson(res);
    if (res.ok && Array.isArray(body)) {
      result.zonePolicies.ok = true;
      result.zonePolicies.policies = body;
      result.zonePolicies.count = body.length;
    } else if (
      res.ok &&
      body &&
      typeof body === "object" &&
      Array.isArray((body as { data?: unknown[] }).data)
    ) {
      const data = (body as { data: unknown[] }).data;
      result.zonePolicies.ok = true;
      result.zonePolicies.policies = data;
      result.zonePolicies.count = data.length;
    } else {
      result.zonePolicies.error =
        typeof body === "object" && body !== null
          ? JSON.stringify(body)
          : `HTTP ${String(res.status)}`;
    }
  } catch (err) {
    result.zonePolicies.error =
      err instanceof Error ? err.message : String(err);
  }

  return result;
}

export interface PolicyRoutesResult {
  trafficRoutes: {
    ok: boolean;
    count: number;
    routes: unknown[];
    error?: string;
  };
}

export async function getPolicyRoutes(
  session: UnifiSession,
): Promise<PolicyRoutesResult> {
  const result: PolicyRoutesResult = {
    trafficRoutes: { ok: false, count: 0, routes: [] },
  };

  // Traffic routes (Network 8.x+).
  try {
    const url = apiPath(
      session,
      `/v2/api/site/${encodeURIComponent(session.site)}/trafficroutes`,
    );
    const res = await authedFetch(session, url);
    const body = await readJson(res);
    if (res.ok && Array.isArray(body)) {
      result.trafficRoutes.ok = true;
      result.trafficRoutes.routes = body;
      result.trafficRoutes.count = body.length;
    } else if (
      res.ok &&
      body &&
      typeof body === "object" &&
      Array.isArray((body as { data?: unknown[] }).data)
    ) {
      const data = (body as { data: unknown[] }).data;
      result.trafficRoutes.ok = true;
      result.trafficRoutes.routes = data;
      result.trafficRoutes.count = data.length;
    } else {
      result.trafficRoutes.error =
        typeof body === "object" && body !== null
          ? JSON.stringify(body)
          : `HTTP ${String(res.status)}`;
    }
  } catch (err) {
    result.trafficRoutes.error =
      err instanceof Error ? err.message : String(err);
  }

  return result;
}

// Merge `cidrsToManage` into a traffic route's `ip_addresses`, preserving any
// entries that were not previously written by this server. `previouslyManaged`
// is the CIDR set the server wrote on the prior sync — we subtract it from the
// controller's current list to recover manual additions, then union the fresh
// CIDRs in. Forces `matching_target = "IP"`. Returns the net change against
// the controller's pre-sync state so the caller can report add/remove counts.
export async function updateTrafficRouteIps(
  session: UnifiSession,
  routeId: string,
  cidrsToManage: string[],
  previouslyManaged: string[],
): Promise<{ added: number; removed: number; description: string }> {
  // The v2 trafficroutes endpoint rejects GET-by-id with HTTP 405; only the
  // list endpoint is readable. Fetch the full list and pick the matching route.
  const listUrl = apiPath(
    session,
    `/v2/api/site/${encodeURIComponent(session.site)}/trafficroutes`,
  );
  const url = `${listUrl}/${encodeURIComponent(routeId)}`;

  const listRes = await authedFetch(session, listUrl);
  if (!listRes.ok) {
    const body = await readJson(listRes);
    throw new UnifiError(
      `Failed to list traffic routes: HTTP ${String(listRes.status)}`,
      listRes.status,
      body,
    );
  }
  const listBody = await readJson(listRes);
  const routes: unknown[] = Array.isArray(listBody)
    ? listBody
    : Array.isArray((listBody as { data?: unknown[] } | null)?.data)
      ? (listBody as { data: unknown[] }).data
      : [];
  const current = routes.find(
    (r): r is Record<string, unknown> =>
      !!r && typeof r === "object" && (r as { _id?: unknown })._id === routeId,
  );
  if (!current) {
    throw new UnifiError(
      `Traffic route ${routeId} not found in list response`,
      404,
      listBody,
    );
  }

  const currentEntries = Array.isArray(
    (current as { ip_addresses?: unknown }).ip_addresses,
  )
    ? ((current as { ip_addresses: unknown[] }).ip_addresses)
    : [];
  const currentCidrs = currentEntries
    .map((e) =>
      e && typeof e === "object"
        ? (e as { ip_or_subnet?: unknown }).ip_or_subnet
        : undefined,
    )
    .filter((s): s is string => typeof s === "string");

  const previousSet = new Set(previouslyManaged);
  const notManaged = currentCidrs.filter((c) => !previousSet.has(c));
  const finalArr = Array.from(new Set<string>([...notManaged, ...cidrsToManage]));
  const ip_addresses = finalArr.map((cidr) => ({
    ip_or_subnet: cidr,
    ip_version: "v4",
  }));

  const currentSet = new Set(currentCidrs);
  const finalSet = new Set(finalArr);
  const added = finalArr.filter((c) => !currentSet.has(c)).length;
  const removed = currentCidrs.filter((c) => !finalSet.has(c)).length;

  const patched = {
    ...current,
    matching_target: "IP",
    ip_addresses,
  };

  const putRes = await authedFetch(session, url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patched),
  });
  if (!putRes.ok) {
    const body = await readJson(putRes);
    throw new UnifiError(
      `Failed to update traffic route ${routeId}: HTTP ${String(putRes.status)}`,
      putRes.status,
      body,
    );
  }
  const descRaw =
    (current as { description?: unknown }).description ??
    (current as { name?: unknown }).name;
  const description = typeof descRaw === "string" && descRaw.length > 0
    ? descRaw
    : "(no description)";
  return { added, removed, description };
}

export async function logout(session: UnifiSession): Promise<void> {
  const path = session.isUnifiOs ? "/api/auth/logout" : "/api/logout";
  try {
    await authedFetch(session, `${session.host}${path}`, { method: "POST" });
  } catch {
    // best-effort
  }
}
