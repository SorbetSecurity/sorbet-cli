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
// hoverable "?" marker carrying an explanation for the section next to it
const help = (text) => el("span", { class: "help", tabindex: "0" }, "?", el("span", { class: "tip" }, text));

const CBOM_HELP = "Certificates and keys — a CBOM (Cryptography Bill of Materials), inventoried " +
  "separately from packages. Use it to audit weak or expiring trust anchors and to catch a " +
  "tampered image that slipped in an extra 'trusted' CA. Hidden from the component list, " +
  "builder queries and exports by default so packages stay in focus.";

// wrap a native <select> in the app-styled dropdown (no system menus anywhere)
function customSelect(sel) {
  const wrap = el("span", { class: "dd inline" });
  const btn = el("button", { class: "dd-btn", type: "button" });
  const menu = el("div", { class: "dd-menu" });
  menu.hidden = true;
  const sync = () => {
    const cur = sel.selectedOptions[0] || sel.options[0];
    btn.replaceChildren(el("span", { class: "dd-label" }, cur ? cur.textContent : ""),
      el("span", { class: "dd-caret" }, "▼"));
    menu.replaceChildren(...[...sel.options].map((o) =>
      el("div", { class: "dd-item" + (o.value === sel.value ? " active" : ""), "data-v": o.value },
        o.textContent)));
  };
  btn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; });
  menu.addEventListener("click", (e) => {
    const it = e.target.closest("[data-v]");
    if (!it) return;
    menu.hidden = true;
    if (it.dataset.v !== sel.value) {
      sel.value = it.dataset.v;
      sel.dispatchEvent(new Event("change"));
      sync();
    }
  });
  document.addEventListener("click", () => { menu.hidden = true; });
  sel.hidden = true;
  sync();
  wrap.append(btn, menu, sel);
  return wrap;
}

// checkbox-style dropdown for picking several values at once
function multiSelect(labelAll, options, selected, onChange) {
  const wrap = el("span", { class: "dd inline" });
  const btn = el("button", { class: "dd-btn", type: "button" });
  const menu = el("div", { class: "dd-menu" });
  menu.hidden = true;
  const syncBtn = () => btn.replaceChildren(
    el("span", { class: "dd-label" },
      selected.size ? [...selected].join(", ") : labelAll),
    el("span", { class: "dd-caret" }, "▼"));
  const build = () => menu.replaceChildren(...options.map((o) =>
    el("div", { class: "dd-item" + (selected.has(o) ? " active" : ""), "data-v": o },
      (selected.has(o) ? "✓ " : " ") + o)));
  btn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; });
  menu.addEventListener("click", (e) => {
    const it = e.target.closest("[data-v]");
    if (!it) return;
    e.stopPropagation();  // stays open for picking several
    if (selected.has(it.dataset.v)) selected.delete(it.dataset.v);
    else selected.add(it.dataset.v);
    build(); syncBtn(); onChange();
  });
  document.addEventListener("click", () => { menu.hidden = true; });
  build(); syncBtn();
  wrap.append(btn, menu);
  return wrap;
}

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

  const cbom = (c.by_ecosystem || {}).crypto || 0;
  tiles.append(
    tile("Components", c.components - cbom, "#/components", "packages in the emitted SBOM"),
    tile("High confidence", c.high_confidence, link("confidence >= 0.9"),
      `${Math.round((c.high_confidence / total) * 100)}% ≥ 0.90 — the rest carry lower-tier evidence`),
    tile("Excluded", c.excluded, link("attrs.excluded ~ \"*\""),
      "below-threshold / removed — retained in the graph, not emitted"),
    tile("Layers", summary.layers, "#/containers", summary.layers ? "container image" : "not a container"),
    tile("Annotations", summary.annotations, "#/findings", "drift & notes on components"),
  );
  if (cbom) tiles.append(tile("CBOM", cbom, "#/components?cbom=1&filter=" +
    encodeURIComponent("ecosystem = crypto"),
    "certificates & keys — kept out of the component list by default"));

  const body = el("div", {}, el("h1", {}, "Overview"), tiles);

  const pkgEco = Object.fromEntries(
    Object.entries(c.by_ecosystem || {}).filter(([k]) => k !== "crypto"));
  body.append(el("h2", {}, "By ecosystem",
    help("Emitted components grouped by package ecosystem (npm, pypi, apk…). " +
      "Certificates live in the CBOM tile above, not here. " +
      "Click a segment or legend entry to open the matching components.")),
    distribution(pkgEco, (k) => link(`ecosystem = ${k}`)));
  body.append(el("h2", {}, "By technique tier",
    help("How each component was established, strongest first: observed (seen running) → installed " +
      "(present on disk) → locked (pinned in a lockfile) → declared (listed in a manifest) → " +
      "inferred (derived indirectly). Confidence scores follow the tier of the best evidence.")),
    distribution(c.by_tier, (k) => link(`tier = ${k}`), true));
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
  const showCbom = params.get("cbom") === "1";
  let counters = {};
  try { counters = (await apiRun("")).counters || {}; } catch { /* toggle hides */ }
  const cbomCount = (counters.by_ecosystem || {}).crypto || 0;

  const body = el("div", {});
  body.append(el("h1", {}, "Components",
    help("Every package in the emitted SBOM. Tier is the strongest evidence class behind it; " +
      "confidence is a 0–1 score derived from that evidence (rows under 0.90 are highlighted). " +
      "By default only components with confidence ≥ 0.70 are listed — widen the confidence " +
      "filter to dig into the less certain tail. Click a column header to sort; " +
      "click a row to inspect its identity, provenance paths and raw evidence.")));
  const input = el("input", { class: "filter", placeholder: 'query filter, e.g. purl ~ "pkg:npm/*"', value: filter });
  const runBtn = el("button", { class: "btn" }, "Filter");
  const toolbar = el("div", { class: "graph-toolbar" }, input, runBtn,
    el("span", { class: "sub", id: "count", style: "margin:0" }, ""));

  // quick filters: confident-by-default, dig deeper on demand
  const quick = { ecos: new Set(), minConf: 0.7 };
  let allRows = [];
  let serverTotal = 0;
  const render = () => {
    const visible = allRows.filter((r) =>
      (!quick.ecos.size || quick.ecos.has(r.ecosystem || "")) && r.confidence >= quick.minConf);
    const hidden = allRows.length - visible.length;
    $("#count").textContent =
      `${fmt(visible.length)} shown` +
      (hidden ? ` · ${fmt(hidden)} hidden by quick filters` : "") +
      (serverTotal > allRows.length ? ` · ${fmt(serverTotal)} total` : "");
    host.replaceChildren(componentTable(visible));
  };
  const ecoKeys = Object.keys(counters.by_ecosystem || {}).filter((k) => k !== "crypto").sort();
  const confSel = el("select", { class: "mode" },
    el("option", { value: "0.9" }, "confidence ≥ 0.90"),
    el("option", { value: "0.7" }, "confidence ≥ 0.70"),
    el("option", { value: "0.5" }, "confidence ≥ 0.50"),
    el("option", { value: "0" }, "any confidence"));
  confSel.value = "0.7";
  confSel.addEventListener("change", () => { quick.minConf = parseFloat(confSel.value); render(); });
  const quickBar = el("div", { class: "graph-toolbar" },
    multiSelect("all ecosystems", ecoKeys, quick.ecos, render),
    customSelect(confSel),
    help("Quick filters narrow the loaded list instantly: pick one or more ecosystems and a " +
      "confidence floor. The default hides the low-confidence tail where false positives live; " +
      "choose 'any confidence' to see everything the scanner considered."));
  if (cbomCount) {
    const box = el("input", { type: "checkbox" });
    box.checked = showCbom;
    box.addEventListener("change", () => {
      const qs = new URLSearchParams();
      if (input.value.trim()) qs.set("filter", input.value.trim());
      if (box.checked) qs.set("cbom", "1");
      location.hash = "#/components?" + qs.toString();
    });
    toolbar.append(el("label", { class: "chip", style: "display:inline-flex;align-items:center;gap:6px" },
      box, `show CBOM (${fmt(cbomCount)} certificates & keys)`), help(CBOM_HELP));
  }
  body.append(toolbar, quickBar);

  // "the scanner missed one" — record an asserted component for future scans
  let corr = { enabled: false };
  try { corr = await api("/api/corrections"); } catch { /* feature hidden */ }
  if (corr.enabled) {
    const openForm = el("button", { class: "chip" }, "+ add missing component");
    const mName = el("input", { class: "filter", style: "min-width:220px", placeholder: "name@version or purl" });
    const mEco = el("input", { class: "filter", style: "min-width:110px", placeholder: "ecosystem" });
    const mWhy = el("input", { class: "filter", style: "min-width:200px", placeholder: "how you know it's there" });
    const mAdd = el("button", { class: "btn" }, "Record");
    const form = el("div", { class: "graph-toolbar", style: "display:none" }, mName, mEco, mWhy, mAdd,
      help("Records the component in the project's sorb.corrections.json; every future scan " +
        "asserts it into the SBOM (tier: declared, with a user-assertion note) until the " +
        "scanner finds it on its own."));
    openForm.addEventListener("click", () => {
      form.style.display = form.style.display === "none" ? "" : "none";
    });
    mAdd.addEventListener("click", async () => {
      if (!mName.value.trim()) return;
      await api("/api/corrections", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ op: "add", kind: "missing", ref: mName.value.trim(),
          ecosystem: mEco.value.trim(), reason: mWhy.value.trim() }) });
      status(`${mName.value.trim()} recorded — it will be asserted into the next scan's SBOM`);
      mName.value = mEco.value = mWhy.value = "";
      form.style.display = "none";
    });
    toolbar.append(openForm);
    body.append(form);
  }

  const host = el("div", {});
  body.append(host);
  view.replaceChildren(body);

  // CBOM assets stay out of the list unless toggled on or explicitly queried
  const effective = (f) => {
    if (showCbom || !cbomCount || /crypto/.test(f)) return f;
    return f ? `${f} and ecosystem != crypto` : "ecosystem != crypto";
  };

  const load = async (f) => {
    host.replaceChildren(el("div", { class: "loading" }, "querying…"));
    try {
      const eff = effective(f);
      const q = eff ? `?filter=${encodeURIComponent(eff)}&limit=500` : "?limit=500";
      const data = await apiRun(`/components${q}`);
      allRows = data.rows;
      serverTotal = data.total;
      status(`${fmt(data.total)} components`);
      render();
    } catch (e) {
      host.replaceChildren(el("div", { class: "err" }, e.message));
    }
  };
  runBtn.addEventListener("click", () => {
    const qs = new URLSearchParams();
    if (input.value.trim()) qs.set("filter", input.value.trim());
    if (showCbom) qs.set("cbom", "1");
    location.hash = "#/components?" + qs.toString();
  });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") runBtn.click(); });
  await load(filter);
}

function componentTable(rows) {
  if (!rows.length) return el("div", { class: "empty" }, el("b", {}, "No matching components."),
    el("p", {}, "Adjust the filters, or clear them to see the full inventory."));
  const COLS = [
    ["Component", (r) => (r.name || "").toLowerCase()],
    ["Version", (r) => r.version || ""],
    ["Ecosystem", (r) => r.ecosystem || ""],
    ["Tier", (r) => TIERS.indexOf(r.tier)],
    ["Confidence", (r) => r.confidence],
    ["Scope", (r) => r.scope || ""],
  ];
  const sort = { col: null, dir: 1 };
  const table = el("table");
  const ths = COLS.map(([h], i) => el("th", { class: "sortable", "data-col": i }, h));
  table.append(el("thead", {}, el("tr", {}, ...ths)));
  const tb = el("tbody");
  table.append(tb);

  const rowEl = (r) => el("tr", { class: "clickable", "data-id": r.id },
    el("td", { class: "mono" }, r.name), el("td", { class: "mono" }, r.version || "—"),
    el("td", {}, r.ecosystem || "—"), el("td", {}, tierBadge(r.tier)),
    el("td", { class: "num conf" + (r.confidence < 0.9 ? " low" : "") }, r.confidence.toFixed(2)),
    el("td", {}, r.scope || "—"));
  const render = () => {
    const view = [...rows];
    if (sort.col != null) {
      const key = COLS[sort.col][1];
      view.sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * sort.dir);
    }
    tb.replaceChildren(...view.map(rowEl));
    ths.forEach((th, i) => {
      th.textContent = COLS[i][0] + (sort.col === i ? (sort.dir === 1 ? " ▲" : " ▼") : "");
    });
  };
  table.tHead.addEventListener("click", (e) => {
    const th = e.target.closest("th[data-col]");
    if (!th) return;
    const i = Number(th.dataset.col);
    if (sort.col === i) sort.dir = -sort.dir;
    else { sort.col = i; sort.dir = 1; }
    render();
  });
  render();
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
  let corr = { enabled: false, corrections: [] };
  try { corr = await api("/api/corrections"); } catch { /* feature hidden */ }
  const fpRef = detail.purl || (detail.version ? `${detail.name}@${detail.version}` : detail.name);
  const refs = new Set([detail.purl, detail.name,
    detail.version ? `${detail.name}@${detail.version}` : null].filter(Boolean));
  const marked = corr.corrections.some((e) => e.kind === "false-positive" && refs.has(e.ref));

  const back = el("div", { style: "margin-bottom:14px; display:flex; gap:6px; align-items:center" },
    el("a", { class: "chip", href: "#/components" }, "← components"),
    el("a", { class: "chip", href: `#/graph?focus=${detail.id}` }, "show in graph ⤳"));
  if (corr.enabled) {
    const fpBtn = el("button", { class: "chip", style: marked ? "color:var(--warning)" : "" },
      marked ? "✓ marked false positive — unmark" : "mark as false positive");
    fpBtn.addEventListener("click", async () => {
      const markedEntry = corr.corrections.find((e) => e.kind === "false-positive" && refs.has(e.ref));
      await api("/api/corrections", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(markedEntry
          ? { op: "remove", kind: "false-positive", ref: markedEntry.ref }
          : { op: "add", kind: "false-positive", ref: fpRef }) });
      status(markedEntry
        ? `${fpRef} unmarked — it will emit again from the next scan`
        : `${fpRef} recorded as a false positive — excluded from the next scan onward`);
      route();
    });
    back.append(fpBtn, help("A false-positive mark is remembered in the project's " +
      "sorb.corrections.json (commit it to share with the team) and excludes this component " +
      "from every future scan's SBOM. It takes effect on the next scan."));
  }
  const head = el("div", {},
    el("h1", { class: "mono" }, detail.ref),
    el("p", { class: "sub" }, detail.name, " ", tierBadge(detail.tier),
      " ", el("span", { class: "conf" }, `confidence ${detail.confidence.toFixed(2)}`)));

  const identity = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, "Identity"),
    kv({ purl: detail.purl || "—", name: detail.name, version: detail.version || "—", type: detail.ctype,
      scope: detail.attrs.scope || "—", ecosystem: detail.attrs.ecosystem || "—",
      cpe: detail.attrs.cpe || "—" }));
  if (Object.keys(detail.hashes || {}).length) identity.append(el("h2", {}, "Hashes"), kv(detail.hashes));

  const paths = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, `Provenance (${detail.paths.length})`,
    help("Dependency chains that introduce this component, from a project root down to it. " +
      "A component with no inbound path is itself a root or direct entry.")));
  if (!detail.paths.length) paths.append(el("p", { class: "sub" }, "no inbound paths (a root / direct entry)"));
  detail.paths.slice(0, 30).forEach((p) => {
    const line = el("div", { class: "path" });
    p.forEach((s, i) => {
      if (i) line.append(el("span", { class: "arrow" }, " → "));
      line.append(el("span", {}, s.label));
    });
    paths.append(line);
  });

  const evp = el("div", { class: "panel" }, el("h2", { style: "margin-top:0" }, `Evidence (${detail.evidence.length})`,
    help("The raw occurrences behind this component: which detector fired, in which file " +
      "(and byte range), with a captured snippet where available. This is the ground truth " +
      "the confidence score is derived from.")));
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

// -- graph explorer: dependency tree (default) + /lod cluster modes ----------
const _ecoColors = new Map();
const ecoColor = (eco, css) => {
  if (!_ecoColors.has(eco)) _ecoColors.set(eco, css.getPropertyValue(`--${CHART[_ecoColors.size % CHART.length]}`));
  return _ecoColors.get(eco);
};
const GRAPH_MONO = '11.5px ui-monospace, "SF Mono", Menlo, monospace';

async function viewGraph(view, params) {
  const body = el("div", {});
  const modeSel = el("select", { class: "mode" },
    el("option", { value: "deps" }, "dependency tree"),
    ...["ecosystem", "tier", "layer"].map((m) => el("option", { value: m }, "cluster by " + m)));
  const back = el("button", { class: "btn secondary" }, "\u2190 clusters");
  back.style.display = "none";
  const hint = el("span", { class: "sub", style: "margin:0" }, "");
  body.append(el("h1", {}, "Dependency graph",
    help("The dependency tree starts at top-level components (nothing depends on them) and " +
      "expands one level at a time: \u25b8 unfolds a node's own dependencies, so you can walk any " +
      "chain from a root down to its transitive deps. Clicking a name opens its evidence. " +
      "Cluster modes group the whole run by ecosystem, tier or layer instead. CBOM assets are excluded.")),
    el("div", { class: "graph-toolbar" }, customSelect(modeSel), back, hint));
  const wrap = el("div", { class: "graph-wrap" });
  const canvas = el("canvas", { height: 400 });
  wrap.append(canvas);
  body.append(wrap);
  view.replaceChildren(body);

  const mode = params.get("cluster") || "deps";
  modeSel.value = mode;
  modeSel.addEventListener("change", () => {
    location.hash = modeSel.value === "deps" ? "#/graph" : `#/graph?cluster=${modeSel.value}`;
  });
  if (mode === "deps") return depsTree(params, { canvas, wrap, hint });
  return clusterGraph(params, { canvas, wrap, hint, back, mode });
}

// progressive dependency tree: roots \u2192 direct deps \u2192 transitive, one level per click
async function depsTree(params, ui) {
  const { canvas, wrap, hint } = ui;
  hint.textContent = "\u25b8 expands a node's dependencies \u00b7 click a name to inspect";
  const tree = { roots: [], children: new Map(), open: new Set(), hitboxes: [] };
  const rows = [];
  let focusId = null;
  let truncatedRoots = false;

  const fetchLevel = (node) => apiRun(`/deps?node=${node}`);
  const ensureChildren = async (cid) => {
    if (!tree.children.has(cid)) tree.children.set(cid, (await fetchLevel(cid)).nodes);
  };

  // open-state is keyed by row *path*: the same package appears under many
  // parents (and in cycles), and each instance must expand independently
  const rebuild = () => {
    rows.length = 0;
    const walk = (nodes, depth, parentIdx, prefix, ancestors) => {
      for (const n of nodes) {
        // a node already in its own ancestry is a dependency cycle: render it
        // as a terminal "↻ cycle" marker instead of an expandable branch
        const cyc = ancestors.has(n.component_id);
        const key = `${prefix}/${n.component_id}`;
        const idx = rows.length;
        rows.push({ n, depth, parentIdx, key, cyc });
        if (!cyc && n.count > 0 && tree.open.has(key)) {
          walk(tree.children.get(n.component_id) || [], depth + 1, idx, key,
            new Set(ancestors).add(n.component_id));
        }
      }
    };
    walk(tree.roots, 0, -1, "", new Set());
  };

  const ROW_H = 34, INDENT = 28, LEFT = 34, TOP = 20;
  let hoverIdx = -1;
  const NAME_FONT = '600 12.5px ui-sans-serif, -apple-system, "Segoe UI", sans-serif';
  const ROOT_FONT = '650 13px ui-sans-serif, -apple-system, "Segoe UI", sans-serif';
  const VER_FONT = '11.5px ui-monospace, "SF Mono", Menlo, monospace';
  const TAG_FONT = '9.5px ui-monospace, "SF Mono", Menlo, monospace';
  const parts = (n) => {
    let name = n.label || "", version = "";
    if (name.startsWith("pkg:")) name = name.slice(4 + (n.ecosystem || "").length).replace(/^\//, "");
    const at = name.lastIndexOf("@");
    if (at > 0) { version = name.slice(at + 1).split("?")[0]; name = name.slice(0, at); }
    return { name, version };
  };

  const draw = () => {
    rebuild();
    const dpr = window.devicePixelRatio || 1;
    const w = wrap.clientWidth;
    const h = Math.max(220, TOP * 2 + rows.length * ROW_H);
    canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.height = h + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
    const css = getComputedStyle(document.body);
    const fg = css.getPropertyValue("--foreground");
    const dim = css.getPropertyValue("--muted-foreground");
    const muted = css.getPropertyValue("--muted");
    tree.hitboxes = [];
    const yOf = (i) => TOP + i * ROW_H + ROW_H / 2;
    ctx.textAlign = "left";

    // pass 1 \u2014 hover / focus row backgrounds, under everything else
    rows.forEach((r, i) => {
      const isFocus = r.n.component_id === focusId;
      if (i !== hoverIdx && !isFocus) return;
      const y = yOf(i);
      ctx.fillStyle = isFocus ? css.getPropertyValue("--primary") : muted;
      ctx.globalAlpha = isFocus ? 0.16 : 0.55;
      ctx.beginPath(); ctx.roundRect(14, y - ROW_H / 2 + 3, w - 28, ROW_H - 6, 8); ctx.fill();
      ctx.globalAlpha = 1;
    });

    // pass 2 \u2014 rounded elbow connectors
    ctx.strokeStyle = css.getPropertyValue("--border"); ctx.lineWidth = 1.25;
    rows.forEach((r, i) => {
      if (r.parentIdx < 0) return;
      const px = LEFT + rows[r.parentIdx].depth * INDENT + 5;
      const y = yOf(i);
      ctx.beginPath();
      ctx.moveTo(px, yOf(r.parentIdx) + 14);
      ctx.lineTo(px, y - 7);
      ctx.quadraticCurveTo(px, y, px + 7, y);
      ctx.lineTo(LEFT + r.depth * INDENT - 10, y);
      ctx.stroke();
    });

    // pass 3 \u2014 nodes: chevron \u00b7 dot \u00b7 name \u00b7 version \u00b7 eco tag \u00b7 deps pill
    rows.forEach((r, i) => {
      const n = r.n;
      const x = LEFT + r.depth * INDENT;
      const y = yOf(i);
      const eco = n.ecosystem || "";
      const col = ecoColor(eco || "?", css);
      if (n.count > 0 && !r.cyc) {
        ctx.fillStyle = i === hoverIdx ? fg : dim;
        ctx.beginPath();
        if (tree.open.has(r.key)) {
          ctx.moveTo(x - 3, y - 3); ctx.lineTo(x + 7, y - 3); ctx.lineTo(x + 2, y + 4);
        } else {
          ctx.moveTo(x - 1, y - 5); ctx.lineTo(x + 5, y); ctx.lineTo(x - 1, y + 5);
        }
        ctx.fill();
      }
      const dotX = x + 17;
      ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(dotX, y, 4.5, 0, 2 * Math.PI); ctx.fill();

      const { name, version } = parts(n);
      let tx = dotX + 12;
      ctx.font = r.depth === 0 ? ROOT_FONT : NAME_FONT;
      ctx.fillStyle = fg;
      ctx.fillText(name, tx, y + 4);
      tx += ctx.measureText(name).width;
      if (version) {
        ctx.font = VER_FONT; ctx.fillStyle = dim;
        ctx.fillText(" " + version, tx, y + 4);
        tx += ctx.measureText(" " + version).width;
      }
      const labelEnd = tx;
      if (eco) {
        ctx.font = TAG_FONT;
        const tw = ctx.measureText(eco).width;
        ctx.fillStyle = col; ctx.globalAlpha = 0.16;
        ctx.beginPath(); ctx.roundRect(tx + 9, y - 8, tw + 12, 16, 8); ctx.fill();
        ctx.globalAlpha = 1;
        ctx.fillText(eco, tx + 15, y + 3.5);
        tx += 21 + tw;
      }
      if (r.cyc) {
        const t = "↻ cycle — already shown above";
        ctx.font = TAG_FONT;
        const tw = ctx.measureText(t).width;
        ctx.fillStyle = css.getPropertyValue("--warning"); ctx.globalAlpha = 0.15;
        ctx.beginPath(); ctx.roundRect(tx + 8, y - 8, tw + 12, 16, 8); ctx.fill();
        ctx.globalAlpha = 1;
        ctx.fillText(t, tx + 14, y + 3.5);
      } else if (n.count > 0) {
        const t = `${n.count} dep${n.count === 1 ? "" : "s"}`;
        ctx.font = TAG_FONT;
        const tw = ctx.measureText(t).width;
        ctx.fillStyle = muted;
        ctx.beginPath(); ctx.roundRect(tx + 8, y - 8, tw + 12, 16, 8); ctx.fill();
        ctx.fillStyle = dim;
        ctx.fillText(t, tx + 14, y + 3.5);
      }
      tree.hitboxes.push({ x0: x - 12, y0: y - ROW_H / 2, x1: dotX + 7, y1: y + ROW_H / 2, row: r, act: "toggle" });
      tree.hitboxes.push({ x0: dotX + 12, y0: y - ROW_H / 2, x1: labelEnd + 4, y1: y + ROW_H / 2, row: r, act: "open" });
    });
  };

  const toggle = async (r) => {
    if (!r.n.count || r.cyc) return;
    if (tree.open.has(r.key)) tree.open.delete(r.key);
    else { await ensureChildren(r.n.component_id); tree.open.add(r.key); }
    draw();
  };

  const hitAt = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    return tree.hitboxes.find((b) => mx >= b.x0 && mx <= b.x1 && my >= b.y0 && my <= b.y1);
  };
  canvas.addEventListener("click", (e) => {
    const hb = hitAt(e);
    if (!hb) return;
    if (hb.act === "open") location.hash = `#/component/${hb.row.n.component_id}`;
    else toggle(hb.row);
  });
  canvas.addEventListener("mousemove", (e) => {
    const hb = hitAt(e);
    canvas.style.cursor = hb ? "pointer" : "default";
    canvas.title = hb ? (hb.row.n.label || "") : "";
    const my = e.clientY - canvas.getBoundingClientRect().top;
    const idx = Math.floor((my - TOP) / ROW_H);
    const ni = idx >= 0 && idx < rows.length ? idx : -1;
    if (ni !== hoverIdx) { hoverIdx = ni; draw(); }
  });
  canvas.addEventListener("mouseleave", () => {
    if (hoverIdx !== -1) { hoverIdx = -1; draw(); }
  });
  window.addEventListener("resize", draw, { passive: true });

  const rootsData = await fetchLevel("root");
  tree.roots = rootsData.nodes;
  truncatedRoots = rootsData.truncated;
  status(`${tree.roots.length} top-level components${truncatedRoots ? " (truncated)" : ""}`);

  const focus = params.get("focus");
  if (focus) {
    try {
      const d = await apiRun(`/component/${encodeURIComponent(focus)}`);
      focusId = d.id;
      // anchor to a visible root by walking dependents upward, then expand down
      const chain = [];
      const seen = new Set([focusId]);
      let cur = focusId;
      for (let hop = 0; hop < 30; hop++) {
        const parents = (await apiRun(`/deps?node=${cur}&dir=up`)).nodes
          .filter((p) => !seen.has(p.component_id));
        if (!parents.length) break;
        cur = parents[0].component_id;
        seen.add(cur);
        chain.unshift(cur);
      }
      let key = "";
      for (const cid of chain) {
        key += `/${cid}`;
        await ensureChildren(cid);
        tree.open.add(key);
      }
      status(`showing ${d.ref} within its dependency path`);
    } catch { /* plain tree */ }
  }
  draw();
  if (focusId != null) {
    const i = rows.findIndex((r) => r.n.component_id === focusId);
    if (i >= 0) $("#view").scrollTop = Math.max(0, TOP + i * ROW_H - 180);
    else status("no dependency chain reaches this component from a top level \u2014 it may only appear via a project manifest");
  }
}

// /lod cluster modes: run \u2192 cluster branches \u2192 member grid
async function clusterGraph(params, ui) {
  const { canvas, wrap, hint, back, mode } = ui;
  hint.textContent = "click a cluster to expand \u00b7 click a node to inspect";
  const gstate = { mode, expand: params.get("expand") || null, nodes: [], edges: [], hitboxes: [] };
  const graphHash = (expand) => "#/graph?" + new URLSearchParams(
    expand ? { cluster: gstate.mode, expand } : { cluster: gstate.mode }).toString();

  const truncate = (ctx, text, max) => {
    let t = text || "";
    while (t.length > 1 && ctx.measureText(t).width > max) t = t.slice(0, -1);
    return t === (text || "") ? t : t.slice(0, -1) + "\u2026";
  };
  const curve = (ctx, a, b) => {
    const mx = (a.x + b.x) / 2;
    ctx.beginPath(); ctx.moveTo(a.x, a.y);
    ctx.bezierCurveTo(mx, a.y, mx, b.y, b.x, b.y); ctx.stroke();
  };
  const nodeColor = (nd, i, css) => {
    if (gstate.mode === "tier" && nd.tier) return tierColorResolved(nd.tier, css);
    return css.getPropertyValue(`--${CHART[i % CHART.length]}`);
  };

  const draw = () => {
    const dpr = window.devicePixelRatio || 1;
    const w = wrap.clientWidth;
    const css = getComputedStyle(document.body);
    const ctx = canvas.getContext("2d");
    const nodes = gstate.nodes;
    gstate.hitboxes = [];
    const hit = (x, y, w2, h2, node) => gstate.hitboxes.push({ x0: x, y0: y, x1: x + w2, y1: y + h2, node });
    let h;
    if (!gstate.expand) {
      const rowH = 56, top = 44;
      h = Math.max(320, top * 2 + nodes.length * rowH);
      canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.height = h + "px";
      ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
      const root = { x: 90, y: top + (nodes.length * rowH) / 2 };
      const cx = 300;
      ctx.strokeStyle = css.getPropertyValue("--border"); ctx.lineWidth = 1.4;
      nodes.forEach((nd, i) => {
        curve(ctx, { x: root.x + 12, y: root.y }, { x: cx - 22, y: top + rowH * (i + 0.5) });
      });
      ctx.beginPath(); ctx.arc(root.x, root.y, 11, 0, 2 * Math.PI);
      ctx.fillStyle = css.getPropertyValue("--primary"); ctx.fill();
      ctx.fillStyle = css.getPropertyValue("--muted-foreground");
      ctx.font = GRAPH_MONO; ctx.textAlign = "center";
      ctx.fillText("run", root.x, root.y + 28);
      ctx.textAlign = "left";
      nodes.forEach((nd, i) => {
        const y = top + rowH * (i + 0.5);
        const r = Math.min(16, 8 + Math.sqrt(nd.count || 1) / 2);
        ctx.beginPath(); ctx.arc(cx, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = nodeColor(nd, i, css); ctx.fill();
        ctx.fillStyle = css.getPropertyValue("--foreground"); ctx.font = GRAPH_MONO;
        ctx.fillText(`${nd.label || nd.id}`, cx + r + 10, y + 4);
        hit(cx - r, y - r - 6, r * 2 + 240, r * 2 + 12, nd);
      });
    } else {
      const colW = 190, rowH = 32, left = 260, top = 56;
      const cols = Math.max(1, Math.floor((w - left - 24) / colW));
      const rowsN = Math.ceil(nodes.length / cols) || 1;
      h = Math.max(380, top + rowsN * rowH + 40);
      canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.height = h + "px";
      ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
      ctx.font = GRAPH_MONO;
      const anchor = { x: 90, y: Math.min(h / 2, 260) };
      const posOf = (i) => ({ x: left + (i % cols) * colW, y: top + Math.floor(i / cols) * rowH });
      ctx.strokeStyle = css.getPropertyValue("--border"); ctx.lineWidth = 1; ctx.globalAlpha = 0.55;
      nodes.forEach((_, i) => { const p = posOf(i); curve(ctx, { x: anchor.x + 14, y: anchor.y }, { x: p.x - 8, y: p.y }); });
      const byId = new Map(nodes.map((nd, i) => [nd.id, posOf(i)]));
      ctx.strokeStyle = css.getPropertyValue("--primary"); ctx.globalAlpha = 0.4; ctx.lineWidth = 1.2;
      for (const e of gstate.edges) {
        const a = byId.get(e.src), b = byId.get(e.dst);
        if (a && b) curve(ctx, { x: a.x + 5, y: a.y }, { x: b.x - 8, y: b.y });
      }
      ctx.globalAlpha = 1;
      ctx.beginPath(); ctx.arc(anchor.x, anchor.y, 13, 0, 2 * Math.PI);
      ctx.fillStyle = css.getPropertyValue("--primary"); ctx.fill();
      ctx.fillStyle = css.getPropertyValue("--foreground");
      ctx.textAlign = "center";
      ctx.fillText(truncate(ctx, gstate.expand, 150), anchor.x, anchor.y + 32);
      ctx.textAlign = "left";
      nodes.forEach((nd, i) => {
        const p = posOf(i);
        ctx.beginPath(); ctx.arc(p.x, p.y, 4.5, 0, 2 * Math.PI);
        ctx.fillStyle = nodeColor(nd, i, css); ctx.fill();
        ctx.fillStyle = css.getPropertyValue("--foreground");
        ctx.fillText(truncate(ctx, nd.label || "", colW - 32), p.x + 10, p.y + 4);
        hit(p.x - 8, p.y - rowH / 2, colW - 8, rowH, nd);
      });
    }
  };

  const load = async () => {
    const q = gstate.expand
      ? `?cluster=${gstate.mode}&expand=${encodeURIComponent(gstate.expand)}`
      : `?cluster=${gstate.mode}`;
    const data = await apiRun(`/lod${q}`);
    gstate.nodes = data.nodes; gstate.edges = data.edges;
    back.style.display = gstate.expand ? "" : "none";
    status(gstate.expand
      ? `${gstate.expand}: ${data.nodes.length} members${data.truncated ? " (truncated to node budget)" : ""}`
      : `${data.nodes.length} clusters`);
    draw();
  };

  const hitAt = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    return gstate.hitboxes.find((hb) => mx >= hb.x0 && mx <= hb.x1 && my >= hb.y0 && my <= hb.y1);
  };
  canvas.addEventListener("mousemove", (e) => {
    const hb = hitAt(e);
    canvas.style.cursor = hb ? "pointer" : "default";
    canvas.title = hb ? (hb.node.label || "") : "";
  });
  canvas.addEventListener("click", (e) => {
    const hb = hitAt(e);
    if (!hb) return;
    if (hb.node.kind === "cluster") location.hash = graphHash(hb.node.id.split(":").pop());
    else if (hb.node.component_id != null) location.hash = `#/component/${hb.node.component_id}`;
  });
  back.addEventListener("click", () => { location.hash = graphHash(null); });
  window.addEventListener("resize", draw, { passive: true });
  await load();
}
const tierColorResolved = (t, css) => {
  const map = { observed: "--sev-low", installed: "--success", locked: "--chart-2",
    declared: "--warning", inferred: "--muted-foreground" };
  return css.getPropertyValue(map[t] || "--chart-1");
};

// -- findings / drift board --------------------------------------------------
// what each finding category means, and what a reader can do about it
const CATEGORY_INFO = {
  "phantom-deps": ["Imported by the code but declared nowhere.",
    "Add it to the manifest (or remove the import) so builds stop depending on ambient state."],
  "stale-lockfile": ["The lockfile no longer matches the manifest.",
    "Regenerate the lockfile (npm install / poetry lock / cargo update) and commit it."],
  "version-conflict": ["Two equally-trusted sources disagree about the version.",
    "Inspect the component's evidence to see both claims, then align the sources."],
  "drift:locked-vs-installed": ["What is installed differs from what the lockfile pinned.",
    "Reinstall from the lockfile, or re-lock if the installed version is intended."],
  "drift": ["Declared, locked and installed states disagree.",
    "Open the component to see which sources conflict, then reinstall or re-lock."],
  "weak-crypto": ["A certificate or key uses a weak algorithm or size (e.g. SHA-1 signatures).",
    "Rotate the certificate, or verify it is a legacy trust anchor you accept."],
  "unidentified-binaries": ["A binary carries no embedded identity and matched no fingerprint.",
    "Check the file's origin; consider a signature pack or an ignore rule if it is first-party."],
  "ml-risk": ["A model file uses a format that executes code when loaded (pickle, TorchScript).",
    "Load only from trusted sources, or convert to a data-only format like safetensors."],
  "analysis-gap": ["A file could not be fully analysed — the SBOM may be incomplete there.",
    "Open the detail to see the file and reason; a fixed parser closes the gap."],
};

async function viewFindings(view) {
  const data = await apiRun("/drift");
  const body = el("div", {}, el("h1", {}, "Findings & drift",
    help("Disagreements between what is declared, locked and actually installed — plus weak-crypto, " +
      "unidentified-binary and ML-risk notes. These are the annotations `--fail-on` gates on in CI.")),
    el("p", { class: "sub" }, `${data.total} finding${data.total === 1 ? "" : "s"} — each links to its component's evidence`));
  if (!data.findings.length) {
    body.append(el("div", { class: "empty" }, el("b", {}, "No drift or findings."),
      el("p", {}, "Phantom deps, stale lockfiles, version conflicts, weak crypto and ML risks appear here.")));
    view.replaceChildren(body); status("no findings"); return;
  }
  for (const group of data.findings) {
    body.append(el("h2", {}, `${group.category} · ${group.count}`));
    const info = CATEGORY_INFO[group.category] ||
      Object.entries(CATEGORY_INFO).find(([k]) => group.category.startsWith(k))?.[1];
    if (info) body.append(el("p", { class: "sub", style: "margin-bottom:8px" },
      info[0], " ", el("b", {}, "What to do: "), info[1]));
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
  const body = el("div", {}, el("h1", {}, "Fleet",
    help("A fleet store merges many host/image scans into one graph, deduplicating identical " +
      "components by digest while keeping per-source provenance — so one query answers " +
      "“which hosts run X?” across the whole fleet.")));
  if (!data.is_fleet) {
    body.append(el("div", { class: "empty" }, el("b", {}, "Not a fleet store."),
      el("p", {}, "Aggregate hosts with "), el("code", {}, "sorb fleet '*.sorb.db' -o fleet.sorb.db"),
      el("p", {}, " then open it here to see per-host rollups.")));
    view.replaceChildren(body); status("not a fleet"); return;
  }
  body.append(el("p", { class: "sub" },
    `${data.sources.length} sources · ${data.observed_components} components observed running`));

  // short, stable label per source for compact display
  const shortName = (s) => {
    if (s.startsWith("image:sha256:")) return "image:" + s.slice(13, 25);
    const tail = s.replace(/\/+$/, "").split("/").pop() || s;
    return tail.replace(/\.git$/, "");
  };
  const hostLink = (h) =>
    `#/components?filter=${encodeURIComponent(`attrs.seen_in ~ "*${h}*"`)}`;

  body.append(el("h2", {}, "Hosts",
    help("One row per scanned source. Click a row to list exactly the components " +
      "present on that host/image (the fleet keeps per-source provenance even " +
      "after deduplication).")));
  const table = el("table");
  table.append(el("thead", {}, el("tr", {}, el("th", {}, "Host"),
    el("th", {}, "Components"), el("th", {}, "Observed running"))));
  const tb = el("tbody");
  for (const h of data.hosts) {
    tb.append(el("tr", { class: "clickable", "data-host": h.host },
      el("td", { class: "mono", title: h.host }, shortName(h.host), " ",
        el("span", { class: "sub", style: "margin:0;font-size:11px" }, h.host.slice(0, 60))),
      el("td", { class: "num" }, fmt(h.components)),
      el("td", { class: "num" }, fmt(h.observed))));
  }
  table.append(tb);
  const wrap = el("div", { class: "table-wrap" }, table);
  wrap.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-host]");
    if (tr) location.hash = hostLink(tr.dataset.host);
  });
  body.append(wrap);

  const skew = data.version_skew || [];
  body.append(el("h2", {}, `Version skew · ${data.version_skew_total ?? skew.length}`,
    help("Components running as different versions on different hosts — the usual first " +
      "question asked of a fleet (which hosts still carry the old build?). " +
      "Click a row to see every occurrence with its evidence.")));
  if (!skew.length) {
    body.append(el("div", { class: "empty" }, el("b", {}, "No version skew."),
      el("p", {}, "Every shared component runs the same version on every source.")));
  } else {
    const st = el("table");
    st.append(el("thead", {}, el("tr", {}, el("th", {}, "Component"),
      ...data.hosts.map((h) => el("th", { title: h.host }, shortName(h.host))))));
    const stb = el("tbody");
    for (const row of skew) {
      stb.append(el("tr", { class: "clickable", "data-name": row.name },
        el("td", { class: "mono" }, row.name),
        ...data.hosts.map((h) => {
          const vs = row.versions[h.host];
          return el("td", { class: "mono", style: vs ? "" : "color:var(--muted-foreground)" },
            vs ? vs.join(", ") : "—");
        })));
    }
    st.append(stb);
    const swrap = el("div", { class: "table-wrap" }, st);
    swrap.addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-name]");
      if (tr) location.hash = `#/components?filter=${encodeURIComponent(`name = "${tr.dataset.name}"`)}`;
    });
    body.append(swrap);
    if ((data.version_skew_total ?? 0) > skew.length) {
      body.append(el("p", { class: "sub" }, `showing the first ${skew.length} — ` +
        "use the Query view for the full skew list"));
    }
  }
  view.replaceChildren(body);
  status(`${data.hosts.length} hosts · ${data.version_skew_total ?? 0} components with version skew`);
}

// -- run diff ----------------------------------------------------------------
async function viewDiff(view, params) {
  const body = el("div", {}, el("h1", {}, "Diff runs",
    help("Semantic comparison of two runs: components added, removed, or version-changed, and " +
      "container layers that appeared or vanished. Identical inputs produce an empty diff.")));
  const runs = [...$("#run-picker").options].map((o) => o.value);
  const selA = el("select", { class: "mode" }, ...runs.map((r) => el("option", { value: r }, r)));
  const selB = el("select", { class: "mode" }, ...runs.map((r) => el("option", { value: r }, r)));
  selA.value = params.get("a") || runs[Math.min(1, runs.length - 1)] || RUN.id;
  selB.value = params.get("b") || runs[0] || RUN.id;
  const runBtn = el("button", { class: "btn" }, "Compare");
  body.append(el("div", { class: "graph-toolbar" }, customSelect(selA),
    el("span", { class: "arrow" }, "→"), customSelect(selB), runBtn));
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
  const body = el("div", {}, el("h1", {}, "Container layers",
    help("The image's layer stack, base to top. +/− counts are components each layer added or " +
      "removed (whiteouts), so you can attribute every component to the layer — and the " +
      "Dockerfile step — that introduced it.")));
  if (!data.layers.length) {
    body.append(el("div", { class: "empty" }, el("b", {}, "This run is not a container image."),
      el("p", {}, "Layer stack, whiteouts and base-image boundary appear here when you scan an image.")));
    view.replaceChildren(body); return;
  }
  const L = data.layers;
  const baseCount = L.filter((x) => x.from_base_image).length;
  const totalComp = L.reduce((s, x) => s + (x.components || 0), 0);
  const churn = L.reduce((s, x) => s + x.added + (x.modified || 0) + x.removed, 0);
  const biggest = [...L].sort((a, b) => (b.components || 0) - (a.components || 0))[0];

  const stat = (label, value, because) => el("div", { class: "tile" },
    el("div", { class: "label" }, label), el("div", { class: "value" }, fmt(value)),
    because ? el("div", { class: "because" }, because) : "");
  body.append(el("div", { class: "grid stat-grid" },
    stat("Layers", L.length, `${baseCount} from the base image`),
    stat("Components", totalComp, "attributed to a specific layer"),
    stat("File churn", churn, "files added, modified or removed across layers"),
    stat("Busiest layer", "#" + (biggest.ordinal + 1),
      `introduces ${fmt(biggest.components || 0)} components`)));

  body.append(el("h2", {}, "Layer stack (base → top)",
    help("Each row is one image layer. The bar shows how many components that layer " +
      "introduced; +/~/− are file-level changes (− includes whiteouts). Click a layer " +
      "to list exactly the components it introduced.")));
  const maxComp = Math.max(1, ...L.map((x) => x.components || 0));
  L.forEach((Lyr) => {
    const row = el("div", { class: "layer clickable", "data-digest": Lyr.digest },
      el("span", { class: "ord" }, "#" + (Lyr.ordinal + 1)),
      Lyr.from_base_image ? el("span", { class: "badge base" }, "base") : "",
      el("span", { class: "cmd", title: Lyr.created_by || Lyr.digest || "" },
        Lyr.created_by || Lyr.digest || ""),
      el("span", { class: "bar-wrap" },
        el("span", { class: "bar", style: `width:${((Lyr.components || 0) / maxComp) * 100}%` })),
      el("span", { class: "comp" }, `${fmt(Lyr.components || 0)} comp`),
      el("span", { class: "delta" },
        el("span", { class: "add" }, `+${Lyr.added}`),
        el("span", {}, `~${Lyr.modified || 0}`),
        el("span", { class: "rem" }, `−${Lyr.removed}`)));
    body.append(row);
  });
  body.addEventListener("click", (e) => {
    const row = e.target.closest(".layer[data-digest]");
    if (row) location.hash =
      `#/components?filter=${encodeURIComponent(`attrs.layer = "${row.dataset.digest}"`)}`;
  });
  view.replaceChildren(body);
  status(`${L.length} layers`);
}

// -- query console + export --------------------------------------------------
async function viewQuery(view) {
  const body = el("div", {}, el("h1", {}, "Query console",
    help("Queries start with `components` or `paths`, take `where` filters " +
      "(=, ~ for globs, <, >), and pipe into aggregations like `| count by ecosystem`. " +
      "Component results can be exported as a CycloneDX or SPDX subgraph.")),
    el("p", { class: "sub" }, "The same DSL as `sorb query`. Results export as a CycloneDX/SPDX subgraph."));
  const ta = el("textarea", { class: "query", spellcheck: "false" },
    'components where purl ~ "pkg:npm/*" and confidence < 0.9');
  const runBtn = el("button", { class: "btn" }, "Run");
  const saveBtn = el("button", { class: "btn secondary" }, "Save");

  // builder: fields and values come from what this run actually contains
  let counters = {};
  try { counters = (await apiRun("")).counters || {}; } catch { /* raw console still works */ }
  const FIELDS = [
    { id: "ecosystem", ops: ["="], choices: Object.keys(counters.by_ecosystem || {}) },
    { id: "tier", ops: ["="], choices: Object.keys(counters.by_tier || {}) },
    { id: "confidence", ops: ["<", ">="], numeric: true },
    { id: "name", ops: ["=", "~"] },
    { id: "purl", ops: ["~"] },
    { id: "scope", ops: ["="], choices: ["runtime", "dev", "optional"] },
  ];
  const conds = [];
  const fieldSel = el("select", { class: "mode" }, ...FIELDS.map((f) => el("option", { value: f.id }, f.id)));
  const opSel = el("select", { class: "mode" });
  const valHost = el("span", {});
  let valCtl = null;
  const syncField = () => {
    const f = FIELDS.find((x) => x.id === fieldSel.value);
    opSel.replaceChildren(...f.ops.map((o) => el("option", { value: o }, o)));
    if (f.choices && f.choices.length) {
      valCtl = el("select", { class: "mode" }, ...f.choices.map((c) => el("option", { value: c }, c)));
      valHost.replaceChildren(customSelect(valCtl));
    } else {
      valCtl = el("input", { class: "filter", style: "min-width:170px",
        placeholder: f.numeric ? "0.9" : f.id === "purl" ? "pkg:npm/*" : "value" });
      valHost.replaceChildren(valCtl);
    }
  };
  fieldSel.addEventListener("change", syncField);
  syncField();
  const aggSel = el("select", { class: "mode" },
    el("option", { value: "" }, "no aggregation"),
    ...["ecosystem", "tier", "scope", "name"].map((g) => el("option", { value: g }, "count by " + g)));
  const addBtn = el("button", { class: "btn secondary" }, "+ Add");
  const cbomBox = el("input", { type: "checkbox" });
  const condChips = el("div", { class: "saved", style: "margin:0" });
  const compose = () => {
    const parts = [...conds];
    // built (and exported) queries exclude CBOM assets unless opted in
    if (!cbomBox.checked && !conds.some((c) => c.includes("crypto"))) {
      parts.push("ecosystem != crypto");
    }
    let q = "components";
    if (parts.length) q += " where " + parts.join(" and ");
    if (aggSel.value) q += ` | count by ${aggSel.value}`;
    ta.value = q;
    runBtn.click();
  };
  cbomBox.addEventListener("change", compose);
  const renderConds = () => condChips.replaceChildren(...conds.map((c, i) =>
    el("span", { class: "chip", "data-ci": i, title: "click to remove" }, `${c} ×`)));
  condChips.addEventListener("click", (e) => {
    const chip = e.target.closest("[data-ci]");
    if (chip) { conds.splice(Number(chip.dataset.ci), 1); renderConds(); compose(); }
  });
  addBtn.addEventListener("click", () => {
    const f = FIELDS.find((x) => x.id === fieldSel.value);
    let v = (valCtl.value || "").trim();
    if (!v) return;
    if (!f.numeric && !/^[a-z0-9_.:-]+$/i.test(v)) v = `"${v}"`;
    conds.push(`${f.id} ${opSel.value} ${v}`);
    renderConds();
    compose();
  });
  aggSel.addEventListener("change", compose);
  const builder = el("div", { class: "panel", style: "margin-bottom:14px" },
    el("div", { class: "label", style: "font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted-foreground);margin-bottom:10px" },
      "Query builder",
      help("Build a query from what this run actually contains — the ecosystem and tier values " +
        "are read from the current scan. Conditions AND together; pick an aggregation to roll " +
        "the results up. The composed query lands in the console below, so you can hand-tune it.")),
    el("div", { class: "graph-toolbar", style: "margin-bottom:6px" },
      customSelect(fieldSel), customSelect(opSel), valHost, addBtn, customSelect(aggSel),
      el("label", { class: "chip", style: "display:inline-flex;align-items:center;gap:6px" },
        cbomBox, "include CBOM"), help(CBOM_HELP)),
    condChips);
  body.append(builder);

  body.append(el("div", { class: "query-row" }, ta, el("div", {}, runBtn, el("div", { style: "height:6px" }), saveBtn)));
  const saved = el("div", { class: "saved" });
  body.append(saved);
  const exportRow = el("div", { class: "graph-toolbar" });
  const fmtSel = el("select", { class: "mode" },
    el("option", { value: "cyclonedx" }, "CycloneDX"), el("option", { value: "spdx" }, "SPDX"),
    el("option", { value: "native" }, "sorb native"));
  const expConf = el("input", { class: "filter", style: "min-width:120px",
    placeholder: "min confidence", value: "0.7" });
  const expScope = el("select", { class: "mode" },
    el("option", { value: "" }, "emitted only"),
    el("option", { value: "all" }, "everything (incl. excluded)"));
  const expCbom = el("input", { type: "checkbox" });
  const exportBtn = el("button", { class: "btn secondary" }, "Export result ↓");
  exportBtn.style.display = "none";
  exportRow.append(customSelect(fmtSel), expConf, customSelect(expScope),
    el("label", { class: "chip", style: "display:inline-flex;align-items:center;gap:6px" },
      expCbom, "with CBOM"),
    exportBtn,
    help("Exports the current result as an SBOM subgraph. Min confidence (0.7 by default — " +
      "clear it for everything) and the CBOM switch narrow the selection; 'everything' also " +
      "emits components the scan held back (below threshold, removed during the image build, " +
      "or user-marked false positives)."));
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
    let q = lastQuery;
    const withCond = (cond) => q + (q.includes(" where ") ? " and " : " where ") + cond;
    const conf = parseFloat(expConf.value);
    if (!Number.isNaN(conf)) q = withCond(`confidence >= ${conf}`);
    if (!expCbom.checked && !/crypto/.test(q)) q = withCond("ecosystem != crypto");
    const r = await fetch("/api/export", { method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ format: fmtSel.value, query: q, run: RUN.id,
        include_excluded: expScope.value === "all" }) });
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
  // the dashboard hides behind the brand mark — clicking the logo goes home
  ROUTES.filter((r) => r.id !== "dashboard")
    .forEach((r) => nav.append(el("a", { href: `#/${r.id}`, "data-route": r.id }, r.label)));
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
    initRunDropdown();
    _pickerWired = true;
  }
  syncRunDropdown();
}

// custom dropdown mirroring the hidden native select (which stays as state
// store so run enumeration and diff keep a single source of truth)
function syncRunDropdown() {
  const sel = $("#run-picker"), btn = $("#run-dd-btn"), menu = $("#run-dd-menu");
  const current = sel.selectedOptions[0] || sel.options[0];
  btn.replaceChildren(
    el("span", { class: "dd-label" }, current ? current.textContent : "current"),
    el("span", { class: "dd-caret" }, "▼"));
  menu.replaceChildren(...[...sel.options].map((o) =>
    el("div", { class: "dd-item" + (o.value === sel.value ? " active" : ""),
      role: "option", "data-value": o.value }, o.textContent)));
}

function initRunDropdown() {
  const sel = $("#run-picker"), btn = $("#run-dd-btn"), menu = $("#run-dd-menu");
  btn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; });
  menu.addEventListener("click", (e) => {
    const item = e.target.closest(".dd-item");
    if (!item) return;
    menu.hidden = true;
    if (item.dataset.value !== sel.value) {
      sel.value = item.dataset.value;
      sel.dispatchEvent(new Event("change"));
      syncRunDropdown();
    }
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("#run-dd")) menu.hidden = true;
  });
  window.addEventListener("keydown", (e) => { if (e.key === "Escape") menu.hidden = true; });
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
