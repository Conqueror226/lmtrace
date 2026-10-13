"use strict";
// Presentation only: every number and decision comes from the Python engines.

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const RANK = { NONE: 0, ARTIFACT: 1, SESSION: 2, ROUTE: 3 };
const LEVEL_NAME = { NONE: "None", ARTIFACT: "Artifact", SESSION: "Session", ROUTE: "Route" };
const OUTCOME = { OBSERVED: "Observed", NOT_OBSERVED: "Not observed", ADDITIONAL: "Additional category" };
const SHORT = {
  SERVICE_INSTALL: "Service install", SERVICE_CONTROL_ACCESS: "Service control access", TASK_CREATE: "Scheduled task",
  WMI_EXECUTION: "WMI execution", WINRM_SESSION: "PowerShell remoting", DCOM_EXECUTION: "DCOM execution",
  REMOTE_PROCESS: "Remote process",
};
// Short names for the overview rack; the full title is always one click away.
const RACK_NAME = {
  covenant_sharpsc_create_dcerpc_smb_svcctl: "SharpSC create", empire_psexec_dcerpc_tcp_svcctl: "PsExec",
  empire_smbexec_dcerpc_smb_svcctl: "SMBExec", covenant_sharpsc_query_dcerpc_smb_svcctl: "SharpSC query",
  covenant_sc_query_dcerpc_smb_svcctl: "sc.exe query", covenant_sharpsc_start_dcerpc_smb_svcctl: "SharpSC start",
  covenant_sharpsc_stop_dcerpc_smb_svcctl: "SharpSC stop", schtask_create: "Scheduled task",
  covenant_sharpwmi_create_dcerpc_wmi: "SharpWMI", empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod: "Invoke WMI",
  covenant_psremoting_command: "Remoting command", empire_psremoting_stager: "Invoke remoting",
  covenant_dcom_executeexcel4macro_allowed: "DCOM Excel", empire_dcom_shellwindows_stager: "DCOM Shell\u00adWindows",
};
const shortHost = (h) => String(h ?? "?").split(".")[0];
let overview = null;

function ladder(level, withLabel = false) {
  const lv = RANK[level] || 0;
  const meter = `<span class="ladder lv${lv}" role="img" aria-label="Evidence level: ${LEVEL_NAME[level] || "None"}"><i></i><i></i><i></i></span>`;
  return withLabel ? `${meter}<span class="ladder-label">${LEVEL_NAME[level] || "None"}</span>` : meter;
}

async function getJSON(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({ error: `The server answered ${response.status}.` }));
  if (!response.ok) throw new Error(body.error || `The server answered ${response.status}.`);
  return body;
}

// ------------------------------------------------------------------ routing
function show(view, arg) {
  for (const section of document.querySelectorAll(".view")) section.hidden = section.id !== `view-${view}`;
  for (const link of document.querySelectorAll(".rail a")) {
    link.toggleAttribute("aria-current", link.dataset.view === view);
    if (link.dataset.view === view) link.setAttribute("aria-current", "page");
  }
  if (view === "recordings" && overview) renderRecording(arg || overview.rows[0].archive);
  if (view === "deep-dive" && !$("deep-frame").src) $("deep-frame").src = "/deep-dive";
  window.scrollTo(0, 0);
}
function route() {
  const [view, arg] = location.hash.replace(/^#/, "").split("/");
  show(["overview", "recordings", "analyze", "deep-dive"].includes(view) ? view : "overview", arg && decodeURIComponent(arg));
}
window.addEventListener("hashchange", route);

// ----------------------------------------------------------------- overview
function routeText(findings) {
  const f = findings.find((x) => RANK[x.level] >= 2);
  if (!f) return '<span class="muted">—</span>';
  if (f.route) return `${esc(shortHost(f.route.source_host))} → ${esc(shortHost(f.route.target_host))}<span class="sub">TCP ${esc(f.route.target_port)}</span>`;
  return `? → ${esc(shortHost(f.target_host))}<span class="sub">source not recorded</span>`;
}

function renderOverview() {
  const s = overview.summary;
  $("ov-count").textContent = s.recordings;
  $("ov-verdict").textContent = `Expected technique category observed in ${s.expected_observed} of ${s.recordings}; ` +
    (s.additional_categories ? `additional remote categories in ${s.additional_categories}.` : "no additional remote technique categories reported.");
  $("ov-rack").innerHTML = overview.rows.map((r) =>
    `<a role="listitem" href="#recordings/${encodeURIComponent(r.archive)}" title="${esc(r.title)}: ${LEVEL_NAME[r.level]}">${ladder(r.level)}<span class="name">${esc(RACK_NAME[r.archive] || r.title)}</span></a>`).join("");
  $("ov-facts").innerHTML = `<span><b>${s.records.toLocaleString()}</b> original records</span>` +
    `<span><b>${s.route_level}</b> with the source host corroborated by records on both endpoints</span>` +
    `<span><b>${s.ablation_monotonic} of ${s.ablation_runs}</b> whole-event-type removals produced no new or stronger claim</span>`;
  $("ov-table").innerHTML = `<thead><tr><th>Exercise</th><th>Performed</th><th>Engine's remote claim</th><th>Evidence</th><th>Source → target</th><th>Expected category</th></tr></thead><tbody>` +
    overview.rows.map((r) => `<tr data-archive="${esc(r.archive)}" tabindex="0">
      <td>${esc(r.title)}<span class="sub">${esc(r.dataset_id)}, ${r.result.counts.records.toLocaleString()} records</span></td>
      <td>${esc(SHORT[r.expected])}</td>
      <td>${r.result.remote_techniques.map((t) => esc(SHORT[t])).join("<br>") || '<span class="muted">None</span>'}</td>
      <td>${ladder(r.level, true)}</td><td>${routeText(r.result.findings)}</td>
      <td class="out-${r.outcome.toLowerCase()}">${OUTCOME[r.outcome]}</td></tr>`).join("") + "</tbody>";
  $("ov-ablation-lead").textContent = `Each column withholds one whole event type and reruns the engine (${s.ablation_runs} runs). ` +
    "A surviving claim passes only if the original run already made it with the same session, principal, artifact records and route, " +
    "at the same or a higher level. This holds for these removals; it is not a proof for every possible removal.";
  const head = overview.ablations.map((a) => `<th>${esc(a)}</th>`).join("");
  $("ov-matrix").innerHTML = `<thead><tr><th></th>${head}</tr></thead><tbody>` + overview.rows.map((r) =>
    `<tr><th class="row">${esc(r.title)}<span class="sub">baseline: ${LEVEL_NAME[r.level].toLowerCase()}</span></th>` +
    overview.ablations.map((a) => {
      const c = r.ablation[a];
      if (!c.removed) return '<td class="cell-na" title="Not present in this recording">·</td>';
      const before = new Set(r.result.remote_techniques), after = new Set(c.techniques || []);
      const gained = [...after].filter((t) => !before.has(t)), lost = [...before].filter((t) => !after.has(t));
      const change = after.size && gained.length ? `now ${gained.map((t) => SHORT[t].toLowerCase()).join(", ")}`
        : after.size && lost.length ? `lost ${lost.map((t) => SHORT[t].toLowerCase()).join(", ")}` : "";
      return `<td class="${c.monotonic ? `cell-${c.level}` : "cell-bad"}" title="${c.removed} records withheld">${LEVEL_NAME[c.level]}${change ? `<span class="change">${esc(change)}</span>` : ""}</td>`;
    }).join("") + "</tr>").join("") + "</tbody>";
}
$("ov-table").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-archive]"); if (tr) location.hash = `recordings/${encodeURIComponent(tr.dataset.archive)}`; });
$("ov-table").addEventListener("keydown", (e) => { const tr = e.target.closest("tr[data-archive]"); if (tr && e.key === "Enter") location.hash = `recordings/${encodeURIComponent(tr.dataset.archive)}`; });

// ------------------------------------------------------------ findings view
function detailLines(d) {
  if (d.service) return `Service <code>${esc(d.service)}</code> with binary <code>${esc(d.binary)}</code>`;
  if (d.task) return `Task <code>${esc(d.task)}</code>`;
  if (d.image) return `<code>${esc(d.image)}</code> started by <code>${esc(d.parent)}</code>`;
  if (d.pipe) return `Access check on <code>${esc(d.pipe)}</code>`;
  return "";
}

// "file.json:L972" -> "Line 972"; the full reference stays in the tooltip and the viewer.
const refLabel = (ref) => { const m = /:L(\d+)$/.exec(ref); return m ? `Line ${Number(m[1]).toLocaleString()}` : ref; };

function findingCard(f, source) {
  const r = f.route;
  const routeLine = r
    ? `<div class="route">${esc(shortHost(r.source_host))} ${esc(r.source_ip)}:${esc(r.source_port)} → ${esc(shortHost(r.target_host))} ${esc(r.target_ip)}:${esc(r.target_port)}</div>`
    : `<p class="gap">${esc(f.route_gap)}</p>`;
  const refs = [...new Set([...f.evidence.map((e) => e.ref), ...(f.alias_refs || [])])];
  return `<article class="finding">${ladder(f.level)}<div class="finding-body">
    <h3>${esc(f.label)}</h3>
    <p class="muted small">Account <code>${esc(f.account)}</code>, logon <code>${esc(f.logon_id)}</code>, SID <code>${esc(f.principal && f.principal.sid)}</code></p>
    ${routeLine}
    ${f.details.map((d) => `<p>${detailLines(d)}</p>`).join("")}
    ${f.follow_on && f.follow_on.length ? `<p class="small">Then, in the same session: ${f.follow_on.map((p) => `<code>${esc(p)}</code>`).join(", ")}</p>` : ""}
    ${(f.notes || []).map((n) => `<p class="note">${esc(n)}</p>`).join("")}
    <div class="refs">${refs.map((ref) => `<button type="button" class="ref" data-source="${esc(source)}" data-ref="${esc(ref)}" title="${esc(ref)}">${esc(refLabel(ref))}</button>`).join("")}</div>
  </div></article>`;
}

function issueList(title, items, source) {
  if (!items.length) return "";
  return `<details class="panel"><summary>${esc(title)} (${items.length})</summary>${items.map((g) =>
    `<p>${esc(g.reason)}</p><div class="refs">${g.evidence.map((e) => `<button type="button" class="ref" data-source="${esc(source)}" data-ref="${esc(e.ref)}" title="${esc(e.ref)}">${esc(refLabel(e.ref))}</button>`).join("")}</div>`).join("")}</details>`;
}

function qualityLine(q) {
  const unusable = Object.values(q.unusable_identifiers || {}).reduce((a, b) => a + b, 0);
  return `Input checks: ${q.conflicting_event_identities} contradictory event versions, ${unusable} relevant records with unusable identifiers, ` +
    `${q.flow_records_unusable_for_routes} network records unusable for routes. ${q.screening.note}`;
}

function resultBody(result, source) {
  const findings = result.findings.length
    ? result.findings.map((f) => findingCard(f, source)).join("")
    : '<div class="panel"><p>No finding. The engine does not link actions it cannot show to a session.</p></div>';
  return findings +
    `<p class="muted small">${esc(qualityLine(result.quality))}</p>` +
    issueList("Contradictions", result.conflicts || [], source) +
    issueList("Rejected records (examples)", result.quality.rejected_examples || [], source) +
    issueList("Session gaps", result.gaps || [], source);
}

function renderRecording(archive) {
  const row = overview.rows.find((r) => r.archive === archive) || overview.rows[0];
  $("rec-list").innerHTML = overview.rows.map((r) =>
    `<button type="button" data-archive="${esc(r.archive)}" ${r.archive === row.archive ? 'aria-current="true"' : ""}>${ladder(r.level)}<span>${esc(r.title)}</span></button>`).join("");
  $("rec-detail").innerHTML = `<h1>${esc(row.title)}</h1>
    <p class="meta"><a href="${esc(row.documentation)}" target="_blank" rel="noopener">${esc(row.dataset_id)}</a>, ${row.result.counts.records.toLocaleString()} records.
    Performed: ${esc(SHORT[row.expected])}. Expected category: <span class="out-${row.outcome.toLowerCase()}">${OUTCOME[row.outcome]}</span>.</p>
    ${row.known_limit ? `<p class="limit"><strong>Why it is not observed:</strong> ${esc(row.known_limit)}</p>` : ""}
    ${resultBody(row.result, row.archive)}`;
}
$("rec-list").addEventListener("click", (e) => { const b = e.target.closest("button[data-archive]"); if (b) location.hash = `recordings/${encodeURIComponent(b.dataset.archive)}`; });

// ----------------------------------------------------------------- analyze
function strictPanel(strict) {
  const status = { REMOTE_SERVICE_INSTALLATION: "Remote service installation supported", REMOTE_SERVICE_ACCESS: "Service-control access only", INSUFFICIENT_EVIDENCE: "No complete service session" }[strict.status] || strict.status;
  return `<div class="panel"><h3>Strict service contract: ${esc(status)}</h3>
    <p class="small muted">${strict.counts.supported_sessions} supported sessions, ${strict.counts.supported_installations} linked installations, ${strict.counts.service_install_events} installation events recorded.</p>
    ${strict.observations.map((o) => `<details><summary>Session <code>${esc(o.logon_id)}</code></summary>${o.checks.map((c) =>
      `<div class="check"><span class="pill ${esc(c.result)}">${esc({ SUPPORTED: "Supported", NOT_OBSERVED: "Not observed", UNKNOWN: "Unknown" }[c.result])}</span><span><strong>${esc(c.check)}</strong><br>${esc(c.detail)}</span></div>`).join("")}</details>`).join("")}
  </div>`;
}

async function analyzeFile(file) {
  if (!file) return;
  const status = $("an-status");
  status.className = "status";
  status.textContent = `Analyzing ${file.name} (${(file.size / 1048576).toFixed(1)} MB)…`;
  $("an-result").innerHTML = "";
  try {
    const result = await getJSON("/api/analyze", { method: "POST", headers: { "X-Filename": file.name }, body: file });
    const files = result.integrity.files.map((f) => `${esc(f.name)} (${f.records.toLocaleString()} records, SHA-256 <code>${esc(f.sha256.slice(0, 16))}…</code>)`).join("; ");
    status.textContent = `Analyzed ${result.records.toLocaleString()} records. Strongest evidence: ${LEVEL_NAME[result.result.max_level] || "None"}.`;
    $("an-result").innerHTML = `<p class="small muted">${files}</p>
      <h2>Remote activity</h2>${resultBody(result.result, "upload")}
      <h2>Service creation, strict contract</h2>${strictPanel(result.strict)}`;
  } catch (error) {
    status.className = "status error";
    status.textContent = error.message;
  }
}
$("file").addEventListener("change", (e) => analyzeFile(e.target.files[0]));
const drop = $("drop");
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => analyzeFile(e.dataTransfer.files[0]));

// ----------------------------------------------------------- record viewer
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button.ref");
  if (!b) return;
  $("record-title").textContent = "Original record";
  $("record-ref").textContent = b.dataset.ref;
  $("record-hash").textContent = "";
  $("record-json").textContent = "Loading…";
  $("record-dialog").showModal();
  try {
    const r = await getJSON(`/api/record?source=${encodeURIComponent(b.dataset.source)}&ref=${encodeURIComponent(b.dataset.ref)}`);
    $("record-hash").textContent = `SHA-256 of the original line: ${r.sha256}`;
    $("record-json").textContent = r.json;
  } catch (error) {
    $("record-json").textContent = error.message;
  }
});
$("record-close").addEventListener("click", () => $("record-dialog").close());

// -------------------------------------------------------------------- start
getJSON("/api/overview").then((data) => { overview = data; renderOverview(); route(); })
  .catch((error) => { $("ov-verdict").textContent = `The scorecard could not be loaded: ${error.message}`; route(); });
