const $ = (sel) => document.querySelector(sel);

const els = {
  status: $("#status"),
  setupPanel: $("#setup-panel"),
  setupForm: $("#setup-form"),
  setupBtn: $("#setup-btn"),
  setupError: $("#setup-error"),
  unlockPanel: $("#unlock-panel"),
  unlockForm: $("#unlock-form"),
  unlockBtn: $("#unlock-btn"),
  unlockError: $("#unlock-error"),
  lockBtn: $("#lock-btn"),
  connectPanel: $("#connect-panel"),
  rulesPanel: $("#rules-panel"),
  form: $("#connect-form"),
  connectBtn: $("#connect-btn"),
  disconnectBtn: $("#disconnect-btn"),
  refreshBtn: $("#refresh-btn"),
  connectError: $("#connect-error"),
  rulesSummary: $("#rules-summary"),
  legacyCount: $("#legacy-count"),
  legacyError: $("#legacy-error"),
  legacyTbody: $("#legacy-table tbody"),
  zoneCount: $("#zone-count"),
  zoneError: $("#zone-error"),
  zoneTbody: $("#zone-table tbody"),
  legacyRouteCount: $("#legacy-route-count"),
  legacyRouteError: $("#legacy-route-error"),
  legacyRouteTbody: $("#legacy-route-table tbody"),
  trafficRouteCount: $("#traffic-route-count"),
  trafficRouteError: $("#traffic-route-error"),
  trafficRouteTbody: $("#traffic-route-table tbody"),
  rawJson: $("#raw-json"),
};

function showError(el, msg) {
  if (!msg) {
    el.hidden = true;
    el.textContent = "";
  } else {
    el.hidden = false;
    el.textContent = msg;
  }
}

function hideAllPanels() {
  els.setupPanel.hidden = true;
  els.unlockPanel.hidden = true;
  els.connectPanel.hidden = true;
  els.rulesPanel.hidden = true;
}

function showSetup() {
  hideAllPanels();
  els.setupPanel.hidden = false;
  els.status.textContent = "First-time setup";
  els.status.className = "status status-disconnected";
  els.lockBtn.hidden = true;
  els.disconnectBtn.hidden = true;
}

function showUnlock() {
  hideAllPanels();
  els.unlockPanel.hidden = false;
  els.status.textContent = "Locked";
  els.status.className = "status status-disconnected";
  els.lockBtn.hidden = true;
  els.disconnectBtn.hidden = true;
}

function showConnect() {
  hideAllPanels();
  els.connectPanel.hidden = false;
  els.status.textContent = "Unlocked — not connected";
  els.status.className = "status status-disconnected";
  els.lockBtn.hidden = false;
  els.disconnectBtn.hidden = true;
}

function setConnected(info) {
  hideAllPanels();
  els.rulesPanel.hidden = false;
  els.status.textContent = `Connected — ${info.username}@${info.host} (site: ${info.site})`;
  els.status.className = "status status-connected";
  els.lockBtn.hidden = false;
  els.disconnectBtn.hidden = false;
}

function clearTables() {
  els.legacyTbody.innerHTML = "";
  els.zoneTbody.innerHTML = "";
  els.legacyRouteTbody.innerHTML = "";
  els.trafficRouteTbody.innerHTML = "";
  els.rawJson.textContent = "";
}

function setDisconnected() {
  clearTables();
  showConnect();
  for (const input of els.form.querySelectorAll("input")) {
    input.disabled = false;
  }
}

function actionBadge(action) {
  const a = String(action ?? "").toLowerCase();
  if (a === "accept" || a === "allow") {
    return `<span class="badge badge-accept">${a}</span>`;
  }
  if (a === "drop" || a === "reject" || a === "block" || a === "deny") {
    return `<span class="badge badge-drop">${a}</span>`;
  }
  return `<span class="badge">${a || "—"}</span>`;
}

function enabledBadge(enabled) {
  if (enabled === true || enabled === "true") {
    return `<span class="badge badge-accept">yes</span>`;
  }
  if (enabled === false || enabled === "false") {
    return `<span class="badge badge-disabled">no</span>`;
  }
  return `<span class="badge">—</span>`;
}

function legacySourceDest(rule, kind) {
  // Legacy rules have src_*/dst_* fields with addresses, networks, and ports.
  const prefix = kind === "src" ? "src" : "dst";
  const parts = [];
  const addr = rule[`${prefix}_address`];
  const net = rule[`${prefix}_networkconf_id`];
  const grp = rule[`${prefix}_firewallgroup_ids`];
  const port = rule[`${prefix}_port`];
  if (addr) parts.push(addr);
  if (net) parts.push(`net:${net.slice(0, 6)}…`);
  if (Array.isArray(grp) && grp.length) parts.push(`grp×${grp.length}`);
  if (port) parts.push(`:${port}`);
  return parts.join(" ") || "any";
}

function humanizeKey(k) {
  return String(k)
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function isEmptyValue(v) {
  if (v === null || v === undefined || v === "") return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0)
    return true;
  return false;
}

function renderValue(v) {
  if (v === null || v === undefined || v === "") {
    return `<span class="muted">—</span>`;
  }
  if (typeof v === "boolean") {
    return v
      ? `<span class="badge badge-accept">true</span>`
      : `<span class="badge badge-disabled">false</span>`;
  }
  if (typeof v === "number") {
    return escapeHtml(String(v));
  }
  if (typeof v === "string") {
    return escapeHtml(v);
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return `<span class="muted">—</span>`;
    const allScalar = v.every(
      (x) => x === null || typeof x !== "object" || x === undefined,
    );
    if (allScalar) {
      return v
        .map((x) => (x === null || x === undefined ? "—" : escapeHtml(String(x))))
        .join(", ");
    }
    return (
      `<ul class="detail-list">` +
      v
        .map((item) => `<li>${renderValue(item)}</li>`)
        .join("") +
      `</ul>`
    );
  }
  if (typeof v === "object") {
    return renderDl(v);
  }
  return escapeHtml(String(v));
}

function renderDl(obj, ignoreKeys = []) {
  const entries = Object.entries(obj).filter(
    ([k, val]) => !ignoreKeys.includes(k) && !isEmptyValue(val),
  );
  if (entries.length === 0) return `<span class="muted">(no values)</span>`;
  return (
    `<dl class="detail-dl">` +
    entries
      .map(
        ([k, val]) =>
          `<dt>${escapeHtml(humanizeKey(k))}</dt><dd>${renderValue(val)}</dd>`,
      )
      .join("") +
    `</dl>`
  );
}

function renderDetailCell(obj, ignoreKeys, colspan, extraHtml = "") {
  const dl = renderDl(obj, ignoreKeys);
  const raw = `<details class="raw-json-details"><summary>Raw JSON</summary><pre>${escapeHtml(
    JSON.stringify(obj, null, 2),
  )}</pre></details>`;
  return `<td colspan="${colspan}"><div class="rule-detail">${dl}${extraHtml}${raw}</div></td>`;
}

// Last "Apply" result per route, keyed by route id. Survives re-renders
// so the status message reappears after we refresh the table post-sync.
const lastSyncResults = new Map();

const MIN_INTERVAL_MINUTES = 1;

function renderSourcesEditor(routeId, urls, intervalSeconds) {
  const escId = escapeHtml(routeId);
  const escUrls = escapeHtml((urls ?? []).join("\n"));
  const last = lastSyncResults.get(routeId);
  const statusClass = last
    ? `sources-status sources-status-${last.kind === "ok" ? "ok" : "err"}`
    : "sources-status";
  const statusText = last ? escapeHtml(last.text) : "";
  const autoEnabled = Number(intervalSeconds) > 0;
  const intervalMinutes = autoEnabled
    ? Math.max(MIN_INTERVAL_MINUTES, Math.round(Number(intervalSeconds) / 60))
    : 5;
  return `
    <div class="sources-editor" data-route-id="${escId}">
      <h4>Source URLs</h4>
      <p class="sources-help">One URL per line (e.g. <code>https://www.cloudflare.com/ips-v4</code>). Applying fetches each URL and syncs the IPv4 CIDRs onto this route. Entries the server added previously but no longer appear in the sources are removed; entries added by hand are left alone.</p>
      <textarea class="sources-urls" rows="3" spellcheck="false" placeholder="https://www.cloudflare.com/ips-v4">${escUrls}</textarea>
      <label class="sources-auto">
        <input type="checkbox" class="sources-auto-enabled" ${autoEnabled ? "checked" : ""} />
        Auto-apply every
        <input type="number" class="sources-interval" min="${MIN_INTERVAL_MINUTES}" step="1" value="${intervalMinutes}" />
        minutes
      </label>
      <div class="sources-actions">
        <button type="button" class="sources-save" data-route-id="${escId}">Apply</button>
        <span class="${statusClass}" data-status-for="${escId}">${statusText}</span>
      </div>
    </div>
  `;
}

function appendRow(tbody, summaryCells, detail) {
  const row = document.createElement("tr");
  row.className = "rule-row";
  row.innerHTML = `<td class="chevron">▸</td>${summaryCells}`;
  const detailRow = document.createElement("tr");
  detailRow.className = "rule-detail-row";
  detailRow.hidden = true;
  detailRow.innerHTML = detail;
  row.addEventListener("click", (e) => {
    // Don't toggle when the user is clicking inside the (already-expanded) details.
    if (e.target.closest(".rule-detail-row")) return;
    const wasOpen = !detailRow.hidden;
    detailRow.hidden = wasOpen;
    row.classList.toggle("expanded", !wasOpen);
    row.querySelector(".chevron").textContent = wasOpen ? "▸" : "▾";
  });
  tbody.appendChild(row);
  tbody.appendChild(detailRow);
}

function renderLegacy(data) {
  els.legacyCount.textContent = String(data.count);
  showError(els.legacyError, data.ok ? "" : data.error || "Unavailable");
  els.legacyTbody.innerHTML = "";
  if (!data.ok) return;
  data.rules.forEach((r, i) => {
    const summary = `
      <td>${r.rule_index ?? i + 1}</td>
      <td>${escapeHtml(r.name ?? "")}</td>
      <td>${escapeHtml(r.ruleset ?? "")}</td>
      <td>${actionBadge(r.action)}</td>
      <td>${escapeHtml(r.protocol ?? r.protocol_v6 ?? "any")}</td>
      <td>${escapeHtml(legacySourceDest(r, "src"))}</td>
      <td>${escapeHtml(legacySourceDest(r, "dst"))}</td>
      <td>${enabledBadge(r.enabled)}</td>
    `;
    appendRow(els.legacyTbody, summary, renderDetailCell(r, [], 9));
  });
}

function zoneEndpoint(side) {
  if (!side) return "—";
  if (typeof side === "string") return side;
  if (side.zone_id) return `zone:${String(side.zone_id).slice(0, 6)}…`;
  if (side.matching_target) return side.matching_target;
  return JSON.stringify(side);
}

function renderZone(data) {
  els.zoneCount.textContent = String(data.count);
  showError(els.zoneError, data.ok ? "" : data.error || "Unavailable");
  els.zoneTbody.innerHTML = "";
  if (!data.ok) return;
  data.policies.forEach((p, i) => {
    const summary = `
      <td>${p.index ?? i + 1}</td>
      <td>${escapeHtml(p.name ?? "")}</td>
      <td>${actionBadge(p.action)}</td>
      <td>${escapeHtml(zoneEndpoint(p.source))}</td>
      <td>${escapeHtml(zoneEndpoint(p.destination))}</td>
      <td>${escapeHtml(p.protocol ?? "any")}</td>
      <td>${enabledBadge(p.enabled)}</td>
    `;
    appendRow(els.zoneTbody, summary, renderDetailCell(p, [], 8));
  });
}

function legacyRouteNextHop(r) {
  if (r.gateway_type === "default") return "default";
  if (r.next_hop_type === "interface" || r.type === "interface-route") {
    return r.interface ?? "interface";
  }
  if (r.gateway_device) return `device:${r.gateway_device}`;
  if (r.static_route_nexthop) return r.static_route_nexthop;
  if (r.next_hop) return r.next_hop;
  return "—";
}

function legacyRouteDest(r) {
  return (
    r.static_route_network ??
    r.policy_route_source_address ??
    r.network ??
    "—"
  );
}

function renderLegacyRoutes(data) {
  els.legacyRouteCount.textContent = String(data.count);
  showError(els.legacyRouteError, data.ok ? "" : data.error || "Unavailable");
  els.legacyRouteTbody.innerHTML = "";
  if (!data.ok) return;
  data.routes.forEach((r) => {
    const summary = `
      <td>${escapeHtml(r.name ?? "")}</td>
      <td>${escapeHtml(legacyRouteDest(r))}</td>
      <td>${escapeHtml(legacyRouteNextHop(r))}</td>
      <td>${escapeHtml(r.type ?? r.static_route_type ?? "")}</td>
      <td>${escapeHtml(r.static_route_distance ?? r.distance ?? "—")}</td>
      <td>${enabledBadge(r.enabled)}</td>
    `;
    appendRow(els.legacyRouteTbody, summary, renderDetailCell(r, [], 7));
  });
}

function trafficRouteMatching(r) {
  if (r.matching_target) {
    const detail =
      r.matching_target === "DOMAIN"
        ? (r.domains ?? []).map((d) => d.domain ?? d).join(", ")
        : r.matching_target === "IP"
          ? (r.ip_addresses ?? []).map((x) => x.ip_or_subnet ?? x).join(", ")
          : r.matching_target === "REGION"
            ? (r.regions ?? []).join(", ")
            : r.matching_target === "APP"
              ? (r.app_categories ?? r.app_ids ?? []).join(", ")
              : "";
    return detail ? `${r.matching_target}: ${detail}` : r.matching_target;
  }
  return "—";
}

function trafficRouteTargets(r) {
  const t = r.target_devices;
  if (!Array.isArray(t) || t.length === 0) return "all";
  return t
    .map((d) => d.type ?? d.client_mac ?? d.network_id ?? "?")
    .slice(0, 4)
    .join(", ");
}

function trafficRouteNextHop(r) {
  if (r.next_hop) return r.next_hop;
  if (r.interface) return r.interface;
  if (r.network_id) return `net:${String(r.network_id).slice(0, 6)}…`;
  return "—";
}

function renderTrafficRoutes(data, allSources = {}) {
  els.trafficRouteCount.textContent = String(data.count);
  showError(els.trafficRouteError, data.ok ? "" : data.error || "Unavailable");
  els.trafficRouteTbody.innerHTML = "";
  if (!data.ok) return;
  data.routes.forEach((r) => {
    const id = r._id ?? r.id ?? "";
    const summary = `
      <td>${escapeHtml(r.description ?? r.name ?? "")}</td>
      <td>${escapeHtml(trafficRouteMatching(r))}</td>
      <td>${escapeHtml(trafficRouteTargets(r))}</td>
      <td>${escapeHtml(trafficRouteNextHop(r))}</td>
      <td>${enabledBadge(r.kill_switch_enabled)}</td>
      <td>${enabledBadge(r.enabled)}</td>
    `;
    const editor = id
      ? renderSourcesEditor(
          id,
          allSources[id]?.urls ?? [],
          allSources[id]?.intervalSeconds ?? 0,
        )
      : "";
    appendRow(els.trafficRouteTbody, summary, renderDetailCell(r, [], 7, editor));
  });
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function loadRules() {
  els.refreshBtn.disabled = true;
  els.rulesSummary.textContent = "Loading…";
  try {
    const [rulesRes, routesRes, sourcesRes] = await Promise.all([
      fetch("/api/firewall-rules"),
      fetch("/api/policy-routes"),
      fetch("/api/route-sources"),
    ]);
    const rules = await rulesRes.json();
    const routes = await routesRes.json();
    const allSources = sourcesRes.ok ? await sourcesRes.json() : {};
    if (!rulesRes.ok) {
      els.rulesSummary.textContent = "";
      showError(els.connectError, rules.error ?? "Failed to load rules");
      return;
    }
    if (!routesRes.ok) {
      showError(els.connectError, routes.error ?? "Failed to load routes");
    }
    renderLegacy(rules.legacy);
    renderZone(rules.zonePolicies);
    renderLegacyRoutes(routes.legacy ?? { ok: false, count: 0, routes: [] });
    renderTrafficRoutes(
      routes.trafficRoutes ?? { ok: false, count: 0, routes: [] },
      allSources,
    );
    els.rulesSummary.textContent =
      `Legacy rules: ${rules.legacy.count} · ` +
      `Zone policies: ${rules.zonePolicies.count} · ` +
      `Legacy policy routes: ${routes.legacy?.count ?? 0} · ` +
      `Traffic routes: ${routes.trafficRoutes?.count ?? 0}`;
    els.rawJson.textContent = JSON.stringify({ rules, routes }, null, 2);
  } catch (err) {
    showError(els.connectError, String(err));
  } finally {
    els.refreshBtn.disabled = false;
  }
}

async function checkStatus() {
  const res = await fetch("/api/status");
  const data = await res.json();
  if (!data.initialized) {
    showSetup();
    return;
  }
  if (!data.unlocked) {
    showUnlock();
    if (data.masterUsername) {
      const userInput = els.unlockForm.querySelector('input[name="username"]');
      if (userInput && !userInput.value) userInput.value = data.masterUsername;
    }
    return;
  }
  if (data.connected) {
    setConnected(data);
    await loadRules();
  } else {
    clearTables();
    showConnect();
  }
}

els.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  showError(els.connectError, "");
  els.connectBtn.disabled = true;
  els.connectBtn.textContent = "Connecting…";
  const fd = new FormData(els.form);
  const body = {
    host: fd.get("host"),
    username: fd.get("username"),
    password: fd.get("password"),
    site: fd.get("site") || "default",
  };
  try {
    const res = await fetch("/api/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(els.connectError, data.error ?? "Connection failed");
      return;
    }
    setConnected(data);
    await loadRules();
  } catch (err) {
    showError(els.connectError, String(err));
  } finally {
    els.connectBtn.disabled = false;
    els.connectBtn.textContent = "Connect";
  }
});

els.disconnectBtn.addEventListener("click", async () => {
  await fetch("/api/disconnect", { method: "POST" });
  setDisconnected();
});

els.setupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showError(els.setupError, "");
  const fd = new FormData(els.setupForm);
  const username = String(fd.get("username") ?? "").trim();
  const password = String(fd.get("password") ?? "");
  const passwordConfirm = String(fd.get("passwordConfirm") ?? "");
  if (password !== passwordConfirm) {
    showError(els.setupError, "Passwords do not match");
    return;
  }
  els.setupBtn.disabled = true;
  els.setupBtn.textContent = "Creating…";
  try {
    const res = await fetch("/api/auth/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, passwordConfirm }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(els.setupError, data.error ?? `HTTP ${res.status}`);
      return;
    }
    els.setupForm.reset();
    await checkStatus();
  } catch (err) {
    showError(els.setupError, String(err));
  } finally {
    els.setupBtn.disabled = false;
    els.setupBtn.textContent = "Create";
  }
});

els.unlockForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showError(els.unlockError, "");
  const fd = new FormData(els.unlockForm);
  const username = String(fd.get("username") ?? "").trim();
  const password = String(fd.get("password") ?? "");
  els.unlockBtn.disabled = true;
  els.unlockBtn.textContent = "Unlocking…";
  try {
    const res = await fetch("/api/auth/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(els.unlockError, data.error ?? `HTTP ${res.status}`);
      return;
    }
    els.unlockForm.reset();
    await checkStatus();
  } catch (err) {
    showError(els.unlockError, String(err));
  } finally {
    els.unlockBtn.disabled = false;
    els.unlockBtn.textContent = "Unlock";
  }
});

els.lockBtn.addEventListener("click", async () => {
  await fetch("/api/auth/lock", { method: "POST" });
  clearTables();
  await checkStatus();
});

els.refreshBtn.addEventListener("click", loadRules);

els.trafficRouteTbody.addEventListener("click", async (e) => {
  const btn = e.target.closest(".sources-save");
  if (!btn) return;
  e.stopPropagation();
  await saveAndSyncSources(btn);
});

async function saveAndSyncSources(btn) {
  const routeId = btn.dataset.routeId;
  const editor = btn.closest(".sources-editor");
  const textarea = editor.querySelector("textarea.sources-urls");
  const status = editor.querySelector(".sources-status");
  const autoCheckbox = editor.querySelector(".sources-auto-enabled");
  const intervalInput = editor.querySelector(".sources-interval");
  const urls = textarea.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const autoEnabled = !!autoCheckbox?.checked;
  const minutes = Math.max(
    MIN_INTERVAL_MINUTES,
    Math.floor(Number(intervalInput?.value) || MIN_INTERVAL_MINUTES),
  );
  const intervalSeconds = autoEnabled ? minutes * 60 : 0;

  btn.disabled = true;
  status.className = "sources-status muted";
  status.textContent = "Saving URLs…";

  try {
    const saveRes = await fetch(
      `/api/traffic-route/${encodeURIComponent(routeId)}/sources`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls, intervalSeconds }),
      },
    );
    if (!saveRes.ok) {
      const j = await saveRes.json().catch(() => ({}));
      throw new Error(j.error ?? `HTTP ${saveRes.status}`);
    }
    status.textContent = "Fetching sources and pushing to UDM…";
    const syncRes = await fetch(
      `/api/traffic-route/${encodeURIComponent(routeId)}/sync`,
      { method: "POST" },
    );
    const result = await syncRes.json().catch(() => ({}));
    if (syncRes.ok && result.ok) {
      const parts = [
        `Added ${result.added ?? 0} · Removed ${result.removed ?? 0}`,
      ];
      if (result.ipv6Skipped) parts.push(`${result.ipv6Skipped} IPv6 skipped`);
      if (result.errors?.length) parts.push(`${result.errors.length} errors`);
      lastSyncResults.set(routeId, { kind: "ok", text: parts.join(" · ") });
    } else {
      const errs = (result.errors ?? [])
        .map((x) => x.error ?? "unknown")
        .slice(0, 3)
        .join("; ");
      lastSyncResults.set(routeId, {
        kind: "err",
        text: `Sync failed: ${errs || result.error || `HTTP ${syncRes.status}`}`,
      });
    }
  } catch (err) {
    lastSyncResults.set(routeId, {
      kind: "err",
      text: `Error: ${err.message ?? String(err)}`,
    });
  } finally {
    btn.disabled = false;
  }
  await loadRules();
  expandTrafficRouteRow(routeId);
}

function expandTrafficRouteRow(routeId) {
  const editorEl = els.trafficRouteTbody.querySelector(
    `.sources-editor[data-route-id="${CSS.escape(routeId)}"]`,
  );
  if (!editorEl) return;
  const detailRow = editorEl.closest("tr.rule-detail-row");
  const summaryRow = detailRow?.previousElementSibling;
  if (!summaryRow || summaryRow.classList.contains("expanded")) return;
  summaryRow.click();
}

checkStatus();
