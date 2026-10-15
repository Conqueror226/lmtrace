# Explaining “Remove Sysmon 3”

Use **Covenant SharpSC Create**, dataset `SDWIN-200806022635`, as the example.
The central point is: **Python recomputes the analysis at build time; JavaScript selects and displays that saved result when you change the dropdown.**

Read the functions below in this order. The comments in `build_dashboard.py` explain its executable lines; the comments in `web/dashboard.js` explain the selector, finding alignment, and rendering path. Braces and blank lines do not need separate explanations.

## 1. Start at the bottom of `build_dashboard.py`

Direct execution calls `main()`. Its key line is:

```python
(ROOT / "web/dashboard-data.js").write_text(data_script(export()))
```

Read it from the inside out:

1. `export()` prepares the baseline and every available removal result.
2. `data_script(...)` converts that data into a JavaScript assignment.
3. `write_text(...)` saves it in `web/dashboard-data.js`.

`standalone(...)` then embeds the same data, CSS, and UI code into `dashboard-offline.html`. The hosted and offline dashboards therefore use the same computed results.

Say: “This file builds the dashboard data before anyone uses the evidence selector.”

## 2. Follow `export()` to the full capture

`verify_sources(ROOT)` checks the bundled files against the hashes in the source manifest. `cached_scorecard()` reuses baseline results only when the recorded engine hashes match; otherwise it recomputes the scorecard.

Inside the recording loop:

```python
records, integrity = load(row["archive"])
original = row["result"]
```

`records` is the full parsed, deduplicated event list for one capture. `integrity` describes that input; the exporter checks it against the baseline's metadata. `original` is the general engine's baseline result.

The `variants` dictionary initially contains `"baseline"`, with zero removed records. Each removal will be added under its own name.

Say: “I begin with the complete capture and retain its baseline for comparison.”

## 3. Find the removal rule in `scorecard.py`

The exporter imports `ABLATIONS`. An *ablation* here means withholding one whole event type and analyzing what remains.

```python
"Sysmon 3 connection": lambda r: is_event(r, SYSMON, 3),
```

`lambda r: ...` is a small function taking one record. It returns true when `is_event` identifies a Sysmon event 3. In `analyze.py`, that helper checks **event ID, provider, and channel**. It does not remove every event numbered 3 regardless of origin.

The exact key is `Sysmon 3 connection`. The browser adds the word “Remove” to the visible label.

## 4. Read the three critical lines in `export()`

```python
kept = [r for r in records if not drop(r)]
removed = len(records) - len(kept)
result = reconstruct(kept)
```

| Expression | Plain-English meaning |
|---|---|
| `for r in records` | Visit every parsed event in the full capture. |
| `drop(r)` | Ask whether this event matches the selected removal rule. |
| `if not drop(r)` | Retain events that do not match. |
| `kept` | A new list containing the remaining events. |
| `removed` | The difference between the full and retained counts. |
| `reconstruct(kept)` | Analyze the remaining events with the general Python engine. |

For this capture, the actual result is **3,390 − 58 = 3,332 retained events**.

All 58 matching Sysmon 3 events are withheld, not just the two cited by the selected installation finding. The original ZIP is unchanged. Each experiment starts from `records`, so selecting another removal does not accumulate deletions. If the event type was absent, Python stores `not_present: True` and skips that experiment.

Say: “I remove the records from the engine's input and rerun the engine. I do not manually lower the displayed label.”

## 5. Follow the reason for `SESSION` into `reconstruct.py`

The exporter does not decide the evidence level. Follow the call to `reconstruct(kept)`:

- `network_sessions(...)` finds usable successful network-logon sessions.
- `artifacts(...)` finds action evidence, including service installation.
- `belongs_to(...)` checks whether an action belongs to a session.
- `FlowIndex(usable)` indexes usable Sysmon 3 connection records.
- `match_flow(logon, flows)` looks for a matching TCP connection recorded on both hosts.

The decisive lines are:

```python
route, why = match_flow(logon, flows)
# ...within the findings for an attributed session...
level = "ROUTE" if route else "SESSION"
```

Without Sysmon 3 records, the flow index has no connection evidence. For this example, `match_flow` returns no route and this explanation:

> No single TCP connection matching the logon is recorded on both hosts.

The successful 4624 logon and the 4697 installation still agree on the target and session identity. The installation therefore remains attributed to `0xba93e3` on `WORKSTATION6.theshire.local`, but its route is uncorroborated.

This conditional applies to findings that already passed session attribution. It does not mean that every finding without a route automatically qualifies as `SESSION`.

## 6. Inspect what Python saves

`variants[name]` contains several different outputs:

| Field | Meaning |
|---|---|
| `removed` | How many parsed events were withheld. |
| `level` | A summary from `strongest_related(...)`, used by the experiment matrix. |
| `result` | General-engine findings, levels, routes, citations, counts, quality, and gaps. |
| `strict` | The separate strict SCM engine's result on the same retained events. |
| `monotonic` | Whether each surviving claim is supported by baseline at equal or greater strength. |

The matrix summary is not the same object as the currently selected finding. The flow view reads the finding's own `level` and `route`.

For the selected service installation:

| Property | Baseline | Remove Sysmon 3 |
|---|---|---|
| Parsed events | 3,390 | 3,332 |
| Removed events | 0 | 58 |
| General finding | `SERVICE_INSTALL` | `SERVICE_INSTALL` |
| General level | `ROUTE` | `SESSION` |
| Session | `0xba93e3` | `0xba93e3` |
| Route | Two-host TCP connection | `null` |
| Cited source lines | 1013, 1020, 1016, 1040, 1031 | 1013, 1020, 1016 |
| Strict SCM status | `REMOTE_SERVICE_INSTALLATION` | `INSUFFICIENT_EVIDENCE` |

The strict contract requires a corroborated SMB route as well as session-attributed `svcctl` access. It does not provide the general engine's weaker `SESSION` category. These outputs answer different contract questions and are consistent with each other.

`monotonic` records a check; it never forces a downgrade. Passing these whole-event-type experiments does not prove that every possible individual-record deletion must weaken a result.

## 7. Follow the data into `web/dashboard.js`

`data_script(...)` writes:

```javascript
window.EVIDENCE_DATA = /* the exported JSON object */;
```

The UI reads it with:

```javascript
const DATA = window.EVIDENCE_DATA;
```

Inside `initialize()`, `DATA.ablations.map(...)` creates the dropdown options. One generated option is:

```html
<option value="Sysmon 3 connection">Remove Sysmon 3 connection</option>
```

`value` is the exact lookup key. Its visible label is presentation text. `renderFlow()` disables removal options whose saved `removed` count is zero.

## 8. Read the `variant-select` change handler

Search for `$('variant-select').addEventListener('change'` near the bottom of the JS file.

```javascript
state.variant = $('variant-select').value;
history.replaceState(null, '', `#flow/${row().archive}/${encodeURIComponent(state.variant)}`);
renderFlow();
```

1. Save the dropdown value in `state.variant`.
2. Update the URL fragment with the recording and variant, encoding spaces safely.
3. Call `renderFlow()` to refresh the display.

`replaceState` neither reloads the page nor fires `hashchange`. This handler makes no API request and does not rerun Python. It also leaves the current step and selected baseline observation unchanged.

Say: “The dropdown switches to a precomputed analysis, then redraws the current view.”

## 9. Follow the selected finding to the screen

Inside `renderFlow()`:

- `row()` reads the selected recording.
- `variant()` reads `row().variants[state.variant]`, falling back to baseline if no result exists.
- `baselineFinding()` keeps track of the original selected observation.
- `currentFinding()` finds its surviving counterpart in the selected variant.

Finding lists can change order or lose entries after removal, so the UI cannot reliably reuse the same array index. It prefers the same target/session, technique, and overlapping artifact references, then tries progressively broader matches in the same session. This is alignment for presentation; Python already performed the actual identity checks. If another technique survives instead, the experiment notice explains the change.

The render functions then use that surviving finding:

| Function | What changes after removing Sysmon 3 in this example |
|---|---|
| `renderStage(f)` | The Corroborate stage sees `!f?.route` and shows the route gap. |
| `claimText(f)` | Chooses the wording for a `SESSION` finding. |
| `renderConclusion(f)` | Displays `SESSION` and the separate strict SCM outcome. |
| `recordsFor(f)` / `focusRecords(f)` | Resolve only citations in the surviving finding, filtered for the current step. |
| `renderQuality(v.result)` | Displays the selected variant's quality information and gaps. |

The shared `record_lookup` contains references used by **any** variant, including baseline. Sysmon 3 records can therefore still exist in the page's lookup. They do not support the removed variant: its finding no longer cites them.

## 10. Reproduce and inspect it yourself

From the project root, build the snapshot:

```bash
python3 build_dashboard.py
```

Open `dashboard-offline.html`, choose **Covenant SharpSC Create**, and compare **Baseline · all records** with **Remove Sysmon 3 connection**. Inspect the Attribute, Corroborate, and Qualify steps.

To inspect the saved output directly, run:

```bash
python3 - <<'PY'
import json
from pathlib import Path

script = Path("web/dashboard-data.js").read_text()
data = json.loads(script.removeprefix("window.EVIDENCE_DATA=").rstrip(";\n"))
row = next(r for r in data["rows"] if r["dataset_id"] == "SDWIN-200806022635")
for name in ("baseline", "Sysmon 3 connection"):
    variant = row["variants"][name]
    finding = next(f for f in variant["result"]["findings"]
                   if f["technique"] == "SERVICE_INSTALL" and f["logon_id"] == "0xba93e3")
    print(name)
    print("removed:", variant["removed"], "retained:", variant["result"]["counts"]["records"])
    print("level:", finding["level"], "route present:", finding["route"] is not None)
    print("gap:", finding["route_gap"])
    print("strict:", variant["strict"]["status"])
    print("cited source lines:", [e["line"] for e in finding["evidence"]])
PY
```

Expected key output: baseline `ROUTE`, route present `True`; removal `SESSION`, route present `False`, 58 removed, 3,332 retained.

Existing checks cover this path:

```bash
python3 -m unittest test_dashboard_export -v
node test_dashboard_ui.cjs
```

The Python checks include actual removal levels and preserved source bytes. The Node checks include selecting Sysmon 3 removal and displaying the missing-route explanation, plus 355 recording/variant/step states. These are DOM contract checks, not browser visual tests.

## A short explanation to rehearse

“During the dashboard build, Python loads the verified capture and creates a baseline. For Remove Sysmon 3, it filters out all matching connection events and reruns both engines on the remaining records. In SharpSC Create, this removes 58 of 3,390 events. The service installation still belongs to the same successful logon session, but the engine can no longer corroborate a TCP connection on both hosts, so the general result becomes Session with no route. Python saves that result in the dashboard data. When I change the dropdown, JavaScript selects it, aligns the surviving finding with the original observation, and updates the explanation and evidence table.”

If asked whether the source connection did not happen: “The retained evidence cannot corroborate it. Missing evidence is not proof that the connection never happened.”
