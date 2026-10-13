"""Render the scorecard as one offline HTML page. All numbers are computed in Python."""
from html import escape

SHORT = {
    "SERVICE_INSTALL": "Service install",
    "SERVICE_CONTROL_ACCESS": "Service control access",
    "TASK_CREATE": "Scheduled task",
    "WMI_EXECUTION": "WMI execution",
    "WINRM_SESSION": "PowerShell remoting",
    "DCOM_EXECUTION": "DCOM execution",
    "REMOTE_PROCESS": "Remote process",
}
LEVEL_TEXT = {"ROUTE": "Route", "SESSION": "Session", "ARTIFACT": "Artifact", "NONE": "None"}
OUTCOME_TEXT = {"OBSERVED": "Observed", "NOT_OBSERVED": "Not observed", "ADDITIONAL": "Additional category"}


def e(value) -> str:
    return escape(str(value if value is not None else "—"))


def host(name) -> str:
    return str(name or "?").split(".")[0]


def claim(row) -> str:
    techniques = row["result"]["remote_techniques"]
    if not techniques:
        return '<span class="muted">No remote claim</span>'
    return "<br>".join(e(SHORT[t]) for t in techniques)


def route_text(row) -> str:
    remote = [f for f in row["result"]["findings"] if f["level"] in ("ROUTE", "SESSION")]
    if not remote:
        return '<span class="muted">—</span>'
    f = remote[0]
    if f["route"]:
        r = f["route"]
        return f'{e(host(r["source_host"]))} → {e(host(r["target_host"]))}<span class="port">TCP {e(r["target_port"])}</span>'
    return f'? → {e(host(f["target_host"]))}<span class="port">source not recorded</span>'


def finding_detail(f) -> str:
    refs = "".join(f'<li><code>{e(ev["ref"])}</code> <span class="muted">event {e(ev["event_id"])} on {e(host(ev["host"]))}</span></li>'
                   for ev in f["evidence"])
    facts = []
    for d in f["details"]:
        if d.get("service"):
            facts.append(f'Service <code>{e(d["service"])}</code> → <code>{e(d["binary"])}</code>')
        elif d.get("task"):
            facts.append(f'Task <code>{e(d["task"])}</code>')
        elif d.get("image"):
            facts.append(f'<code>{e(d["image"])}</code> started by <code>{e(d["parent"])}</code>')
        elif d.get("pipe"):
            facts.append(f'Access check on <code>{e(d["pipe"])}</code>')
    follow = f'<p>Then, in the same session: {", ".join(f"<code>{e(p)}</code>" for p in f["follow_on"])}</p>' if f["follow_on"] else ""
    follow += "".join(f'<p class="note">{e(n)}</p>' for n in f.get("notes", []))
    gap = f'<p class="gap">{e(f["route_gap"])}</p>' if f["route_gap"] else ""
    return (f'<div class="finding"><p><span class="lvl lvl-{f["level"].lower()}">{LEVEL_TEXT[f["level"]]}</span> '
            f'<strong>{e(f["label"])}</strong></p><p class="muted">Account <code>{e(f["account"])}</code>, logon <code>{e(f["logon_id"])}</code>, SID <code>{e(f["principal"]["sid"])}</code></p>'
            f'{"".join(f"<p>{x}</p>" for x in facts)}{follow}{gap}<ul class="refs">{refs}</ul></div>')


def ablation_cell(row, name) -> str:
    c = row["ablation"][name]
    if not c["removed"]:
        return '<td class="na" title="Not present in this recording">·</td>'
    level = c["level"]
    changed = ""
    before, after = set(row["result"]["remote_techniques"]), set(c["techniques"] or [])
    if c["techniques"] is not None and after and before != after:
        gained, lost = after - before, before - after
        if gained:   # a stronger claim fell back to the weaker one it implies
            changed = f'<span class="drop">now {e(", ".join(SHORT[t] for t in sorted(gained)).lower())}</span>'
        elif lost:
            changed = f'<span class="drop">lost {e(", ".join(SHORT[t] for t in sorted(lost)).lower())}</span>'
    flag = "" if c["monotonic"] else '<span class="bad">stronger!</span>'
    title = f'{c["removed"]} records withheld'
    return f'<td class="cell lvl-{level.lower()}" title="{e(title)}">{LEVEL_TEXT[level]}{changed}{flag}</td>'


def build_scorecard(score: dict, meta: dict) -> str:
    s = score["summary"]
    rows_html = []
    for i, row in enumerate(score["rows"], 1):
        details = "".join(finding_detail(f) for f in row["result"]["findings"]) or \
            '<p class="muted">No finding. The engine does not guess a link it cannot show.</p>'
        limit = f'<p class="limit"><strong>Why it is not observed:</strong> {e(row["known_limit"])}</p>' if row["known_limit"] else ""
        q = row["result"]["quality"]
        unusable = sum(q["unusable_identifiers"].values())
        limit += (f'<p class="quality">Input checks: {q["conflicting_event_identities"]} contradictory event versions, '
                  f'{unusable} relevant records with unusable identifiers, {q["flow_records_unusable_for_routes"]} network records '
                  f'unusable for routes (loopback, missing or invalid endpoints). {e(q["screening"]["note"])}</p>')
        rows_html.append(f'''<tr class="row-{row["outcome"].lower()}">
<td><a href="{e(row["documentation"])}" target="_blank" rel="noreferrer">{e(row["title"])}</a><span class="sub">{e(row["dataset_id"])} · {row["result"]["counts"]["records"]:,} records</span></td>
<td>{e(SHORT[row["expected"]])}</td><td>{claim(row)}</td>
<td><span class="lvl lvl-{row["level"].lower()}">{LEVEL_TEXT[row["level"]]}</span></td>
<td>{route_text(row)}</td><td class="out">{OUTCOME_TEXT[row["outcome"]]}</td></tr>
<tr class="detail"><td colspan="6"><details><summary>Evidence behind this row</summary>{limit}{details}</details></td></tr>''')

    head = "".join(f"<th>{e(n)}</th>" for n in score["ablations"])
    matrix = "".join(
        f'<tr><th class="rowhead">{e(r["title"])}<span class="sub">baseline: {LEVEL_TEXT[r["level"]].lower()}</span></th>'
        + "".join(ablation_cell(r, n) for n in score["ablations"]) + "</tr>"
        for r in score["rows"])

    return TEMPLATE.format(
        recordings=s["recordings"], records=f'{s["records"]:,}', techniques=s["techniques"],
        observed=s["expected_observed"],
        additional_text=("no additional remote technique categories reported" if not s["additional_categories"]
                         else f'additional remote categories reported in {s["additional_categories"]}'),
        route=s["route_level"], runs=s["ablation_runs"], mono=s["ablation_monotonic"],
        rows="".join(rows_html), head=head, matrix=matrix,
        revision=e(meta["revision"][:12]), score_hash=e(meta["scorecard_sha256"]),
        code=" ".join(f"{e(k)} <code>{e(v[:12])}</code>" for k, v in sorted(meta["code_sha256"].items())))


TEMPLATE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LMTrace scorecard</title>
<style>
:root{{--ink:#182b3a;--muted:#5b6b76;--paper:#f3f5f5;--line:#dce3e5;--accent:#007d74;--wash:#e6f3ef;--amber:#9c6814;--amberwash:#fff4df;--slate:#e9edf0;--red:#a33a2c}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
a{{color:var(--accent);text-underline-offset:3px}}code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}}
header{{background:#172d3b;color:#fff;padding:34px 0 30px}}.wrap{{max-width:1180px;margin:auto;padding:0 28px}}
h1{{font-size:34px;line-height:1.2;font-weight:650;letter-spacing:-.8px;margin:0 0 10px}}header p{{margin:0;color:#c7d6dd;max-width:720px}}
.verdict{{font-size:23px;line-height:1.4;font-weight:600;letter-spacing:-.3px;max-width:900px;margin:28px 0 8px}}
.facts{{display:flex;flex-wrap:wrap;gap:10px 28px;color:var(--muted);font-size:14px;margin-bottom:26px}}.facts b{{color:var(--ink);font-weight:650}}
.panel{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:18px}}
h2{{font-size:20px;letter-spacing:-.3px;margin:0 0 6px}}.lead{{color:var(--muted);margin:0 0 16px;max-width:820px}}
.ladder{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}.step{{border:1px solid var(--line);border-radius:9px;padding:14px 16px}}.step p{{margin:6px 0 0;font-size:13px;color:var(--muted)}}
.lvl{{display:inline-block;font-size:12px;font-weight:700;padding:3px 8px;border-radius:5px}}
.lvl-route{{background:var(--accent);color:#fff}}.lvl-session{{background:var(--wash);color:var(--accent)}}.lvl-artifact{{background:var(--amberwash);color:var(--amber)}}.lvl-none{{background:var(--slate);color:var(--muted)}}
.tablewrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;font-size:12px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:9px 10px;vertical-align:bottom}}
td{{padding:12px 10px;border-bottom:1px solid #edf0f1;vertical-align:top}}.sub{{display:block;color:var(--muted);font-size:11px;margin-top:2px}}
.port{{display:block;color:var(--muted);font-size:11px}}.muted{{color:var(--muted)}}
.out{{font-weight:650}}.row-observed .out{{color:var(--accent)}}.row-not_observed .out{{color:var(--amber)}}.row-additional .out{{color:var(--red)}}.note{{font-size:13px;color:var(--muted)}}.quality{{font-size:12px;color:var(--muted);margin:4px 0 10px}}
tr.detail td{{padding:0 10px 4px;border-bottom:1px solid var(--line)}}details summary{{cursor:pointer;color:var(--muted);font-size:12px;padding:4px 0 8px}}
.finding{{border-left:3px solid var(--line);padding:4px 0 4px 14px;margin:6px 0 14px}}.finding p{{margin:4px 0}}.refs{{margin:6px 0 0;padding-left:18px;font-size:12px}}
.gap{{color:var(--amber);font-size:13px}}.limit{{background:var(--amberwash);border-radius:7px;padding:10px 13px;font-size:13px}}
.matrix td,.matrix th{{text-align:center;border:1px solid #fff;padding:9px 6px;font-size:12px}}.matrix th.rowhead{{text-align:left;color:var(--ink);font-weight:600;background:#fff;min-width:210px}}
.matrix .na{{color:#b9c3c8;background:#f8fafa}}.matrix .cell{{font-weight:650}}.drop{{display:block;font-weight:500;font-size:11px;opacity:.85}}.bad{{display:block;color:#fff;background:var(--red)}}
.property{{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;margin:0 0 16px}}.property strong{{font-size:20px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:24px;font-size:13px}}.cols p{{margin:0 0 10px}}
footer{{font-size:11px;color:var(--muted);padding:6px 0 40px}}
@media(max-width:800px){{.wrap{{padding:0 16px}}h1{{font-size:27px}}.verdict{{font-size:19px}}.ladder,.cols{{grid-template-columns:1fr}}.panel{{padding:17px}}}}
@media print{{header{{background:#fff;color:var(--ink)}}header p{{color:var(--muted)}}details{{display:block}}.panel{{break-inside:avoid}}}}
</style></head><body>
<header><div class="wrap"><h1>Remote execution across {recordings} recorded exercises</h1>
<p>One engine, six lateral-movement techniques, real Windows Security and Sysmon telemetry. Every claim states how far the evidence actually reaches.</p></div></header>
<main class="wrap">
<p class="verdict">Expected technique category observed in {observed} of {recordings} recorded exercises; {additional_text}.</p>
<div class="facts"><span><b>{records}</b> original records</span><span><b>{route}</b> with the source host corroborated by records on both endpoints</span><span><b>{mono} of {runs}</b> whole-event-type removals produced no new or stronger claim</span></div>

<section class="panel"><h2>How much each claim is worth</h2><p class="lead">The engine anchors on the network logon session Windows creates on the target, then climbs only as far as the records allow.</p>
<div class="ladder"><div class="step"><span class="lvl lvl-artifact">Artifact</span><p>An action is recorded on the target, but no remote session can be shown to own it. The reason is stated.</p></div>
<div class="step"><span class="lvl lvl-session">Session</span><p>The action belongs to a successful network logon on the same host: same logon ID and SID, or the same domain-qualified account.</p></div>
<div class="step"><span class="lvl lvl-route">Route</span><p>That logon matches one TCP connection seen on both machines, with valid addresses and ports on both records, which names the source host.</p></div></div></section>

<section class="panel"><h2>Technique categories</h2><p class="lead">The "performed" column comes from each dataset's published title. Only the scorer reads it; the engine sees raw records only, with no tool names, service names or hosts hard-coded. The outcome compares technique categories; the sessions, accounts and endpoints behind each row are shown for review but were not independently verified.</p>
<div class="tablewrap"><table><thead><tr><th>Exercise</th><th>Performed</th><th>Engine's claim</th><th>Evidence level</th><th>Source → target</th><th>Expected category</th></tr></thead><tbody>{rows}</tbody></table></div></section>

<section class="panel"><h2>Evidence removal</h2><div class="property"><strong>{mono} / {runs}</strong><span class="muted">whole-event-type removals where every surviving claim was already made</span></div>
<p class="lead">Each column withholds one whole event type from the original capture and reruns the engine. A surviving claim passes only if the original run already made it with the same session, principal, artifact records and route, at the same or a higher level; a failure would be marked in red. This holds for these 57 removals. It is not a proof for every possible removal: deleting one record that made a session ambiguous can legitimately restore a stronger claim.</p>
<div class="tablewrap"><table class="matrix"><thead><tr><th></th>{head}</tr></thead><tbody>{matrix}</tbody></table></div></section>

<section class="panel"><h2>What this does and does not show</h2><div class="cols">
<div><p><strong>Shows:</strong> the expected technique category on real recordings from several attack tools, no stronger category than the evidence supports (service query, start and stop are never reported as installs), and claims that weaken when an event type is withheld.</p>
<p><strong>Does not show:</strong> event-level attribution accuracy, which would need independently reviewed sessions, artifacts and endpoints; or a false-positive rate, since every recording is an attack exercise in one lab domain with no benign baseline. Authorization and intent stay unknown.</p></div>
<div><p><strong>Where to look next:</strong> the <a href="report.html">deep dive</a> walks one service-creation session record by record with the original JSON.</p>
<p>Source: OTRF Security-Datasets at revision <code>{revision}</code>, read straight from the pinned ZIPs and hash-checked before each run. Scorecard SHA-256 <code>{score_hash}</code>.</p><p class="muted">{code}</p></div></div></section>
<footer>LMTrace by Désiré Abdoul Kader BONZI. Python standard library, offline.</footer>
</main></body></html>'''
