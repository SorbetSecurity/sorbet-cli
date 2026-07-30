/* Sorbet evidence explorer.
 *
 * A dependency-free SPA over the read-only Graph API. It authenticates by the
 * httponly session cookie the server pins from `?token=` (same-origin fetch
 * carries it — the token never touches JS), so there is nothing to store. Every
 * number is clickable down to evidence: the "no dead-end numbers" rule is
 * enforced by making each stat a link to a filtered view. No external origin is
 * ever contacted; CSP (`script-src 'self'`) means all handlers are delegated,
 * never inline. */
"use strict";

const RUN = { id: "current" };
const SAVED_KEY = "sorb.savedQueries";

// -- tiny helpers ------------------------------------------------------------
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("data")) n.setAttribute(k, v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) n.append(kid?.nodeType ? kid : document.createTextNode(kid ?? ""));
  return n;
};
const $ = (sel) => document.querySelector(sel);
const status = (msg) => { const s = $("#status"); if (s) s.textContent = msg; };
const fmt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : n);

async function api(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (r.status === 401) { showAuthError(); throw new Error("unauthorized"); }
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail ?? detail; } catch { /* non-json */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return r.json();
}
const apiRun = (suffix) => api(`/api/runs/${encodeURIComponent(RUN.id)}${suffix}`);

function showAuthError() {
  $("#view").replaceChildren(el("div", { class: "empty" },
    el("b", {}, "Session not authenticated."),
    el("p", {}, "Reopen the URL that `sorb ui` printed — it carries the one-time session token.")));
}

const TIERS = ["observed", "installed", "locked", "declared", "inferred"];
const tierBadge = (t) => el("span", { class: `badge tier-${t}` }, t);
const CHART = ["chart-1", "chart-2", "chart-3", "chart-4", "chart-5"];
const colorFor = (i) => `var(--${CHART[i % CHART.length]})`;

// -- router ------------------------------------------------------------------
const ROUTES = [
  { id: "dashboard", label: "Dashboard", render: viewDashboard },
  { id: "components", label: "Components", render: viewComponents },
  { id: "graph", label: "Graph", render: viewGraph },
  { id: "containers", label: "Containers", render: viewContainers },
  { id: "findings", label: "Findings", render: viewFindings },
  { id: "fleet", label: "Fleet", render: viewFleet },
  { id: "diff", label: "Diff", render: viewDiff },
  { id: "query", label: "Query", render: viewQuery },
];

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, qs] = raw.split("?");
  const parts = path.split("/").filter(Boolean);
  return { name: parts[0] || "dashboard", arg: parts[1], params: new URLSearchParams(qs || "") };
}

async function route() {
  const { name, arg, params } = parseHash();
  for (const a of $("#nav").children) a.classList.toggle("active", a.dataset.route === name);
  const view = $("#view");
  view.replaceChildren(el("div", { class: "loading" }, "loading…"));
  try {
    if (name === "component") return await viewInspector(arg, view);
    const r = ROUTES.find((x) => x.id === name) || ROUTES[0];
    await r.render(view, params);
  } catch (e) {
    if (/no such run|no scan results/i.test(e.message)) {
      view.replaceChildren(el("div", { class: "empty" },
        el("b", {}, "Scanning…"),
        el("p", {}, "The evidence graph will appear here as soon as the run completes.")));
      status("scanning…");
      return;
    }
    view.replaceChildren(el("div", { class: "empty" }, el("b", {}, "Error"), el("p", { class: "err" }, e.message)));
    status(e.message);
  }
}

// -- live-scan stream: reflect progress and refresh on completion ------------
function connectEvents() {
  let es;
  try { es = new EventSource("/api/events"); } catch { return; }
  es.addEventListener("ScanStarted", (m) => status(`scanning ${JSON.parse(m.data).subject || ""}…`));
  es.addEventListener("StageCompleted", (m) => {
    const e = JSON.parse(m.data);
    status(`✔ ${e.stage}${e.detail ? " · " + e.detail : ""}`);
  });
  es.addEventListener("WarningRaised", (m) => status("⚠ " + JSON.parse(m.data).message));
  es.addEventListener("done", async () => {
    status("scan complete");
    try { await loadRuns(); } catch { /* keep current */ }
    route();  // the graph is now queryable — refresh the current view
  });
}

// -- dashboard ---------------------------------------------------------------
async function viewDashboard(view) {
  const summary = await apiRun("");
  const c = summary.counters;
  status(`run ${RUN.id} · ${fmt(c.components)} components`);
  const total = c.components || 1;

  const link = (filter) => `#/components?filter=${encodeURIComponent(filter)}`;
  const tiles = el("div", { class: "grid stat-grid" });
  const tile = (label, value, href, because) =>
    el("a", { class: "tile", href },
      el("div", { class: "label" }, label), el("div", { class: "value" }, fmt(value)),
      because ? el("div", { class: "because" }, because) : "");

  tiles.append(
    tile("Components", c.components, "#/components", "the emitted SBOM set"),
    tile("High confidence", c.high_confidence, link("confidence >= 0.9"),
      `${Math.round((c.high_confidence / total) * 100)}% ≥ 0.90 — the rest carry lower-tier evidence`),
    tile("Excluded", c.excluded, link("attrs.excluded ~ \"*\""),
      "below-threshold / removed — retained in the graph, not emitted"),
    tile("Layers", summary.layers, "#/containers", summary.layers ? "container image" : "not a container"),
    tile("Annotations", summary.annotations, "#/components", "drift & notes on components"),
  );

  const body = el("div", {}, el("h1", {}, "Overview"),
    el("p", { class: "sub" }, "Every number links to its evidence — nothing here is a dead end."), tiles);

  body.append(el("h2", {}, "By ecosystem"), distribution(c.by_ecosystem, (k) => link(`ecosystem = ${k}`)));
  body.append(el("h2", {}, "By technique tier"), distribution(c.by_tier, (k) => link(`tier = ${k}`), true));
  view.replaceChildren(body);
}

function distribution(counts, hrefFor, tierColors = false) {
  const entries = Object.entries(counts || {});
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  const bar = el("div", { class: "dist" });
  const legend = el("div", { class: "legend" });
  const ordered = tierColors
    ? entries.sort((a, b) => TIERS.indexOf(a[0]) - TIERS.indexOf(b[0]))
    : entries.sort((a, b) => b[1] - a[1]);
  ordered.forEach(([k, v], i) => {
    const col = tierColors ? tierColorVar(k) : colorFor(i);
    bar.append(el("span", { style: `width:${(v / total) * 100}%;background:${col}` }));
    const item = el("a", { class: "item", href: hrefFor(k) },
      el("span", { class: "swatch", style: `background:${col}` }),
      el("span", { class: "mono" }, `${k} ${fmt(v)}`));
    legend.append(item);
  });
  return el("div", {}, bar, legend);
}
const tierColorVar = (t) => ({ observed: "var(--sev-low)", installed: "var(--success)",
  locked: "var(--chart-2)", declared: "var(--warning)", inferred: "var(--muted-foreground)" }[t] || "var(--chart-1)");

// -- components table (target of every stat) ---------------------------------
async function viewComponents(view, params) {
  const filter = params.get("filter") || "";
  const body = el("div", {});
  body.append(el("h1", {}, "Components"));
  const input = el("input", { class: "filter", placeholder: 'query filter, e.g. purl ~ "pkg:npm/*"', value: filter });
  const runBtn = el("button", { class: "btn" }, "Filter");
  body.append(el("div", { class: "graph-toolbar" }, input, runBtn,
    el("span", { class: "sub", id: "count", style: "margin:0" }, "")));
  const host = el("div", {});
  body.append(host);
  view.replaceChildren(body);

  const load = async (f) => {
    host.replaceChildren(el("div", { class: "loading" }, "querying…"));
    try {
      const q = f ? `?filter=${encodeURIComponent(f)}&limit=500` : "?limit=500";
      const data = await apiRun(`/components${q}`);
      $("#count").textContent = `${fmt(data.total)} match`;
      status(`${fmt(data.total)} components`);
      host.replaceChildren(componentTable(data.rows));
    } catch (e) {
      host.replaceChildren(el("div", { class: "err" }, e.message));
    }
  };
  runBtn.addEventListener("click", () => { location.hash = `#/components?filter=${encodeURIComponent(input.value)}`; });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") runBtn.click(); });
  await load(filter);
}

function componentTable(rows) {
  if (!rows.length) return el("div", { class: "empty" }, el("b", {}, "No matching components."),
    el("p", {}, "Adjust the filter, or clear it to see the full inventory."));
  const table = el("table");
  table.append(el("thead", {}, el("tr", {},
    ...["Component", "Version", "Ecosystem", "Tier", "Confidence", "Scope"].map((h) => el("th", {}, h)))));
  const tb = el("tbody");
  for (const r of rows) {
    const conf = el("td", { class: "num conf" + (r.confidence < 0.9 ? " low" : "") }, r.confidence.toFixed(2));
    const tr = el("tr", { class: "clickable", "data-id": r.id },
      el("td", { class: "mono" }, r.name), el("td", { class: "mono" }, r.version || "—"),
      el("td", {}, r.ecosystem || "—"), el("td", {}, tierBadge(r.tier)), conf, el("td", {}, r.scope || "—"));
    tb.append(tr);
  }
  table.append(tb);
  const wrap = el("div", { class: "table-wrap" }, table);
  wrap.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) location.hash = `#/component/${tr.dataset.id}`;
  });
  return wrap;
}

// -- component inspector / visual explain ------------------------------------
async function viewInspector(key, view) {
  const detail = await apiRun(`/component/${encodeURIComponent(key)}`);
  status(detail.ref);
  const back = el("a", { class: "chip", href: "#/components" }, "← components");
  const head = el("div", {},
    el("h1", { class: "mono" }, detail.ref),
    el("p", { class: "sub" }, detail.name, " ", tierBadge(detail.tier),
      " ", el("span", { class: "conf" }, `confidence ${detail.confidence.toFixed(2)}`)));

  const identity = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, "Identity"),
    kv({ purl: detail.purl || "—", name: detail.name, version: detail.version || "—", type: detail.ctype,
      scope: detail.attrs.scope || "—", ecosystem: detail.attrs.ecosystem || "—",
      cpe: detail.attrs.cpe || "—" }));
  if (Object.keys(detail.hashes || {}).length) identity.append(el("h2", {}, "Hashes"), kv(detail.hashes));

  const paths = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, `Provenance (${detail.paths.length})`));
  if (!detail.paths.length) paths.append(el("p", { class: "sub" }, "no inbound paths (a root / direct entry)"));
  detail.paths.slice(0, 30).forEach((p) => {
    const line = el("div", { class: "path" });
    p.forEach((s, i) => {
      if (i) line.append(el("span", { class: "arrow" }, " → "));
      line.append(el("span", {}, s.label));
    });
    paths.append(line);
  });

  const evp = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, `Evidence (${detail.evidence.length})`));
  detail.evidence.forEach((ev) => {
    const loc = ev.location || {};
    const where = loc.path ? loc.path + (loc.span ? `:${loc.span[0]}` : "") : "";
    const row = el("div", { class: "evidence-row" },
      tierBadge(ev.tier), " ",
      el("span", { class: "mono", style: "font-size:12px" }, `${ev.detector || ""} ${where}`));
    if (ev.captured) row.append(el("div", { class: "snippet" }, String(ev.captured).split("\n").slice(0, 3).join("\n")));
    evp.append(row);
  });

  const cols = el("div", { class: "inspector" }, identity, paths, evp);
  // full attribute panel — surfaces binary sections, crypto/ML metadata, etc.
  const shown = new Set(["scope", "ecosystem", "cpe", "excluded"]);
  const extra = Object.fromEntries(
    Object.entries(detail.attrs || {}).filter(([k, v]) => !shown.has(k) && v !== null && v !== ""));
  if (Object.keys(extra).length) {
    cols.append(el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, "Attributes"), kv(extra)));
  }
  if (detail.annotations?.length) {
    const notes = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, "Notes / drift"));
    detail.annotations.forEach((a) => notes.append(el("div", { class: "evidence-row" },
      el("b", { class: "mono" }, a.code), a.detail ? " — " + a.detail : "")));
    cols.append(notes);
  }
  view.replaceChildren(el("div", {}, back, head, cols));
}

function kv(obj) {
  const g = el("div", { class: "kv" });
  for (const [k, v] of Object.entries(obj)) {
    g.append(el("div", { class: "k" }, k), el("div", { class: "v" }, String(v)));
  }
  return g;
}

// -- graph explorer over /lod ------------------------------------------------
async function viewGraph(view) {
  const body = el("div", {});
  const modeSel = el("select", { class: "mode" },
    ...["ecosystem", "tier", "layer"].map((m) => el("option", { value: m }, "cluster by " + m)));
  const hint = el("span", { class: "sub", style: "margin:0" }, "click a cluster to expand · click a node to inspect");
  const back = el("button", { class: "btn secondary" }, "← clusters");
  back.style.display = "none";
  body.append(el("h1", {}, "Dependency graph"),
    el("div", { class: "graph-toolbar" }, modeSel, back, hint));
  const wrap = el("div", { class: "graph-wrap" });
  const canvas = el("canvas", { height: 560 });
  wrap.append(canvas);
  body.append(wrap);
  view.replaceChildren(body);

  const gstate = { mode: "ecosystem", expand: null, nodes: [], edges: [], hitboxes: [] };

  const draw = () => {
    const dpr = window.devicePixelRatio || 1;
    const w = wrap.clientWidth, h = 560;
    canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.height = h + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const nodes = gstate.nodes, n = nodes.length;
    const cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.36;
    const pos = nodes.map((_, i) => n === 1
      ? { x: cx, y: cy }
      : { x: cx + R * Math.cos((i / n) * 2 * Math.PI - Math.PI / 2),
          y: cy + R * Math.sin((i / n) * 2 * Math.PI - Math.PI / 2) });
    const byId = new Map(nodes.map((nd, i) => [nd.id, pos[i]]));
    const css = getComputedStyle(document.body);
    ctx.strokeStyle = css.getPropertyValue("--border"); ctx.lineWidth = 1;
    for (const e of gstate.edges) {
      const a = byId.get(e.src), b = byId.get(e.dst);
      if (a && b) { ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
    }
    gstate.hitboxes = [];
    nodes.forEach((nd, i) => {
      const p = pos[i];
      const isCluster = nd.kind === "cluster";
      const r = isCluster ? Math.min(34, 12 + Math.sqrt(nd.count || 1)) : 8;
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = nodeColor(nd, i, css); ctx.fill();
      ctx.fillStyle = css.getPropertyValue("--foreground");
      ctx.font = "11px ui-monospace, monospace"; ctx.textAlign = "center";
      const label = (nd.label || "").slice(0, 22);
      ctx.fillText(label, p.x, p.y + r + 13);
      gstate.hitboxes.push({ x: p.x, y: p.y, r, node: nd });
    });
  };

  const nodeColor = (nd, i, css) => {
    if (gstate.mode === "tier" && nd.tier) return tierColorResolved(nd.tier, css);
    return css.getPropertyValue(`--${CHART[i % CHART.length]}`);
  };

  const load = async () => {
    const q = gstate.expand ? `?cluster=${gstate.mode}&expand=${encodeURIComponent(gstate.expand)}` : `?cluster=${gstate.mode}`;
    const data = await apiRun(`/lod${q}`);
    gstate.nodes = data.nodes; gstate.edges = data.edges;
    back.style.display = gstate.expand ? "" : "none";
    status(gstate.expand
      ? `${gstate.expand}: ${data.nodes.length} members${data.truncated ? " (truncated to node budget)" : ""}`
      : `${data.nodes.length} clusters`);
    draw();
  };

  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    for (const hb of gstate.hitboxes) {
      if ((mx - hb.x) ** 2 + (my - hb.y) ** 2 <= (hb.r + 4) ** 2) {
        if (hb.node.kind === "cluster") { gstate.expand = hb.node.id.split(":").pop(); load(); }
        else if (hb.node.component_id != null) location.hash = `#/component/${hb.node.component_id}`;
        return;
      }
    }
  });
  modeSel.addEventListener("change", () => { gstate.mode = modeSel.value; gstate.expand = null; load(); });
  back.addEventListener("click", () => { gstate.expand = null; load(); });
  window.addEventListener("resize", draw, { passive: true });
  await load();
}
const tierColorResolved = (t, css) => {
  const map = { observed: "--sev-low", installed: "--success", locked: "--chart-2",
    declared: "--warning", inferred: "--muted-foreground" };
  return css.getPropertyValue(map[t] || "--chart-1");
};

// -- findings / drift board --------------------------------------------------
async function viewFindings(view) {
  const data = await apiRun("/drift");
  const body = el("div", {}, el("h1", {}, "Findings & drift"),
    el("p", { class: "sub" }, `${data.total} finding${data.total === 1 ? "" : "s"} — each links to its component's evidence`));
  if (!data.findings.length) {
    body.append(el("div", { class: "empty" }, el("b", {}, "No drift or findings."),
      el("p", {}, "Phantom deps, stale lockfiles, version conflicts, weak crypto and ML risks appear here.")));
    view.replaceChildren(body); status("no findings"); return;
  }
  for (const group of data.findings) {
    body.append(el("h2", {}, `${group.category} · ${group.count}`));
    const table = el("table");
    table.append(el("thead", {}, el("tr", {}, el("th", {}, "Component"), el("th", {}, "Detail"))));
    const tb = el("tbody");
    for (const item of group.items) {
      const tr = el("tr", item.component_id != null ? { class: "clickable", "data-id": item.component_id } : {},
        el("td", { class: "mono" }, item.subject || "—"), el("td", {}, item.detail || ""));
      tb.append(tr);
    }
    table.append(tb);
    const wrap = el("div", { class: "table-wrap" }, table);
    wrap.addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-id]");
      if (tr) location.hash = `#/component/${tr.dataset.id}`;
    });
    body.append(wrap);
  }
  view.replaceChildren(body);
  status(`${data.total} findings`);
}

// -- fleet dashboard ---------------------------------------------------------
async function viewFleet(view) {
  const data = await apiRun("/fleet");
  const body = el("div", {}, el("h1", {}, "Fleet"));
  if (!data.is_fleet) {
    body.append(el("div", { class: "empty" }, el("b", {}, "Not a fleet store."),
      el("p", {}, "Aggregate hosts with "), el("code", {}, "sorb fleet '*.sorb.db' -o fleet.sorb.db"),
      el("p", {}, " then open it here to see per-host rollups.")));
    view.replaceChildren(body); status("not a fleet"); return;
  }
  body.append(el("p", { class: "sub" }, `${data.sources.length} sources · ${data.observed_components} components observed running`));
  const table = el("table");
  table.append(el("thead", {}, el("tr", {}, el("th", {}, "Host"),
    el("th", {}, "Components"), el("th", {}, "Observed running"))));
  const tb = el("tbody");
  for (const h of data.hosts) {
    tb.append(el("tr", {}, el("td", { class: "mono" }, h.host),
      el("td", { class: "num" }, fmt(h.components)),
      el("td", { class: "num" }, fmt(h.observed))));
  }
  table.append(tb);
  body.append(el("div", { class: "table-wrap" }, table));
  view.replaceChildren(body);
  status(`${data.hosts.length} hosts`);
}

// -- run diff ----------------------------------------------------------------
async function viewDiff(view, params) {
  const body = el("div", {}, el("h1", {}, "Diff runs"));
  const runs = [...$("#run-picker").options].map((o) => o.value);
  const selA = el("select", { class: "mode" }, ...runs.map((r) => el("option", { value: r }, r)));
  const selB = el("select", { class: "mode" }, ...runs.map((r) => el("option", { value: r }, r)));
  selA.value = params.get("a") || runs[Math.min(1, runs.length - 1)] || RUN.id;
  selB.value = params.get("b") || runs[0] || RUN.id;
  const runBtn = el("button", { class: "btn" }, "Compare");
  body.append(el("div", { class: "graph-toolbar" }, selA,
    el("span", { class: "arrow" }, "→"), selB, runBtn));
  const out = el("div", {});
  body.append(out);
  view.replaceChildren(body);

  const load = async () => {
    out.replaceChildren(el("div", { class: "loading" }, "diffing…"));
    try {
      const d = await api(`/api/diff?a=${encodeURIComponent(selA.value)}&b=${encodeURIComponent(selB.value)}`);
      out.replaceChildren(diffResult(d));
      status(d.empty ? "no changes" : `${d.added.length}+ ${d.removed.length}- ${d.version_changes.length}~`);
    } catch (e) { out.replaceChildren(el("div", { class: "err" }, e.message)); }
  };
  runBtn.addEventListener("click", load);
  if (runs.length >= 1) load();
}

function diffResult(d) {
  if (d.empty) return el("div", { class: "empty" }, el("b", {}, "Identical."), el("p", {}, "No components changed."));
  const box = el("div", {});
  const section = (title, rows, cls) => {
    if (!rows.length) return;
    box.append(el("h2", {}, `${title} · ${rows.length}`));
    const list = el("div", { class: "panel" });
    rows.forEach((r) => list.append(el("div", { class: "path " + cls }, r)));
    box.append(list);
  };
  section("Added", d.added.map((c) => `+ ${c.name} ${c.version || ""}`), "add");
  section("Removed", d.removed.map((c) => `− ${c.name} ${c.version || ""}`), "rem");
  section("Version changes", d.version_changes.map((c) =>
    `${c.direction === "upgraded" ? "↑" : c.direction === "downgraded" ? "↓" : "~"} ${c.name}  ${c.from} → ${c.to}`), "");
  if (d.layers_added.length || d.layers_removed.length) {
    section("Layers", [...d.layers_added.map((l) => `+ ${l}`), ...d.layers_removed.map((l) => `− ${l}`)], "");
  }
  return box;
}

// -- container explorer ------------------------------------------------------
async function viewContainers(view) {
  const data = await apiRun("/layers");
  const body = el("div", {}, el("h1", {}, "Container layers"));
  if (!data.layers.length) {
    body.append(el("div", { class: "empty" }, el("b", {}, "This run is not a container image."),
      el("p", {}, "Layer stack, whiteouts and base-image boundary appear here when you scan an image.")));
    view.replaceChildren(body); return;
  }
  body.append(el("p", { class: "sub" }, `${data.layers.length} layers, base → top`));
  data.layers.forEach((L) => {
    body.append(el("div", { class: "layer" },
      el("span", { class: "ord" }, "#" + (L.ordinal + 1)),
      el("span", { class: "cmd" }, L.created_by || L.digest || ""),
      el("span", { class: "delta" },
        el("span", { class: "add" }, `+${L.added}`),
        el("span", { class: "rem" }, `−${L.removed}`))));
  });
  view.replaceChildren(body);
  status(`${data.layers.length} layers`);
}

// -- query console + export --------------------------------------------------
async function viewQuery(view) {
  const body = el("div", {}, el("h1", {}, "Query console"),
    el("p", { class: "sub" }, "The same DSL as `sorb query`. Results export as a CycloneDX/SPDX subgraph."));
  const ta = el("textarea", { class: "query", spellcheck: "false" },
    'components where purl ~ "pkg:npm/*" and confidence < 0.9');
  const runBtn = el("button", { class: "btn" }, "Run");
  const saveBtn = el("button", { class: "btn secondary" }, "Save");
  body.append(el("div", { class: "query-row" }, ta, el("div", {}, runBtn, el("div", { style: "height:6px" }), saveBtn)));
  const saved = el("div", { class: "saved" });
  body.append(saved);
  const exportRow = el("div", { class: "graph-toolbar" });
  const fmtSel = el("select", { class: "mode" },
    el("option", { value: "cyclonedx" }, "CycloneDX"), el("option", { value: "spdx" }, "SPDX"),
    el("option", { value: "native" }, "sorb native"));
  const exportBtn = el("button", { class: "btn secondary" }, "Export result ↓");
  exportBtn.style.display = "none";
  exportRow.append(fmtSel, exportBtn);
  body.append(exportRow);
  const out = el("div", {});
  body.append(out);
  view.replaceChildren(body);

  let lastQuery = "";
  const renderSaved = () => {
    saved.replaceChildren();
    const list = JSON.parse(localStorage.getItem(SAVED_KEY) || "[]");
    list.forEach((q, i) => {
      const chip = el("span", { class: "chip", "data-q": q }, q.length > 46 ? q.slice(0, 44) + "…" : q);
      const del = el("span", { class: "chip", "data-del": i, title: "remove" }, "×");
      saved.append(chip, del);
    });
  };
  saved.addEventListener("click", (e) => {
    const chip = e.target.closest("[data-q]");
    if (chip) { ta.value = chip.dataset.q; runBtn.click(); return; }
    const del = e.target.closest("[data-del]");
    if (del) {
      const list = JSON.parse(localStorage.getItem(SAVED_KEY) || "[]");
      list.splice(Number(del.dataset.del), 1);
      localStorage.setItem(SAVED_KEY, JSON.stringify(list));
      renderSaved();
    }
  });
  saveBtn.addEventListener("click", () => {
    const list = JSON.parse(localStorage.getItem(SAVED_KEY) || "[]");
    if (ta.value.trim() && !list.includes(ta.value.trim())) list.unshift(ta.value.trim());
    localStorage.setItem(SAVED_KEY, JSON.stringify(list.slice(0, 12)));
    renderSaved();
  });

  runBtn.addEventListener("click", async () => {
    out.replaceChildren(el("div", { class: "loading" }, "running…"));
    lastQuery = ta.value.trim();
    try {
      const data = await api("/api/query", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: lastQuery, run: RUN.id }) });
      exportBtn.style.display = data.kind === "components" ? "" : "none";
      out.replaceChildren(resultGrid(data));
      status(`${data.rows.length} rows`);
    } catch (e) {
      exportBtn.style.display = "none";
      out.replaceChildren(el("div", { class: "err" }, e.message));
    }
  });
  exportBtn.addEventListener("click", async () => {
    const r = await fetch("/api/export", { method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ format: fmtSel.value, query: lastQuery, run: RUN.id }) });
    if (!r.ok) { status("export failed"); return; }
    const blob = await r.blob();
    const cd = r.headers.get("content-disposition") || "";
    const name = (cd.match(/filename="([^"]+)"/) || [])[1] || "sbom.json";
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: name });
    document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    status(`exported ${name}`);
  });

  renderSaved();
  runBtn.click();
}

function resultGrid(data) {
  if (data.kind === "paths") {
    if (!data.rows.length) return el("div", { class: "empty" }, el("b", {}, "No paths."));
    const box = el("div", { class: "panel" });
    data.rows.slice(0, 100).forEach((row) => {
      box.append(el("div", { class: "path" }, (row.path || []).map((s) => s.label).join(" → ")));
    });
    return box;
  }
  if (data.kind === "components") return componentTable(data.rows);
  // aggregation
  if (!data.rows.length) return el("div", { class: "empty" }, el("b", {}, "No rows."));
  const cols = Object.keys(data.rows[0]);
  const table = el("table");
  table.append(el("thead", {}, el("tr", {}, ...cols.map((c) => el("th", {}, c)))));
  const tb = el("tbody");
  data.rows.forEach((r) => tb.append(el("tr", {}, ...cols.map((c) =>
    el("td", { class: typeof r[c] === "number" ? "num" : "" }, String(r[c]))))));
  table.append(tb);
  return el("div", { class: "table-wrap" }, table);
}

// -- shell -------------------------------------------------------------------
function buildNav() {
  const nav = $("#nav");
  ROUTES.forEach((r) => nav.append(el("a", { href: `#/${r.id}`, "data-route": r.id }, r.label)));
}

let _pickerWired = false;
async function loadRuns() {
  const picker = $("#run-picker");
  picker.replaceChildren();
  const keep = RUN.id;
  try {
    const { runs } = await api("/api/runs");
    if (!runs.length) { picker.append(el("option", { value: "current" }, "current")); RUN.id = "current"; }
    else {
      runs.forEach((r) => picker.append(el("option", { value: r.run },
        `${r.run}${r.subject ? " · " + r.subject : ""}`)));
      RUN.id = runs.some((r) => r.run === keep) ? keep : runs[0].run;
      picker.value = RUN.id;
    }
  } catch { picker.append(el("option", { value: "current" }, "current")); RUN.id = "current"; }
  if (!_pickerWired) {
    picker.addEventListener("change", () => { RUN.id = picker.value; route(); });
    _pickerWired = true;
  }
}

function initTheme() {
  const toggle = $("#theme-toggle");
  const apply = (dark) => document.documentElement.classList.toggle("dark", dark);
  apply(localStorage.getItem("sorb.theme") !== "light");
  const flip = () => {
    const dark = !document.documentElement.classList.contains("dark");
    apply(dark); localStorage.setItem("sorb.theme", dark ? "dark" : "light");
    if (parseHash().name === "graph") route();  // recolor canvas
  };
  toggle.addEventListener("click", flip);
  window.addEventListener("keydown", (e) => {
    if (e.key === "t" && !/input|textarea|select/i.test(document.activeElement?.tagName || "")) flip();
  });
}

async function main() {
  buildNav();
  initTheme();
  await loadRuns();
  connectEvents();
  window.addEventListener("hashchange", route);
  if (!location.hash) location.hash = "#/dashboard";
  else route();
}
main();
