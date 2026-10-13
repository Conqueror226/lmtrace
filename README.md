# LMTrace

**Evidence-graded reconstruction of Windows remote execution from real telemetry.**

LMTrace (Lateral Movement Trace) reconstructs remote execution from **recorded
Windows Security and Sysmon telemetry**: which session on which host did what,
from which source host, and how far the evidence actually reaches. Every claim
carries an evidence level (Artifact, Session, Route) and links back to the
original records.

It runs on the Python standard library alone, offline, with a **guided concept-flow
dashboard** and two static reports:

- **Scorecard** (`results/scorecard.html`): one engine run over 14 recorded
  OTRF exercises covering six techniques (service install, service-control
  access, scheduled task, WMI, PowerShell remoting, DCOM), with an
  evidence-removal matrix.
- **Deep dive** (`results/report.html`): one service-creation session traced
  record by record, with the original JSON.

## Start in under a minute

Clone the repository and open a terminal inside `lmtrace`, then run:

```bash
python3 dashboard.py
```

The first launch builds the evidence snapshot (several seconds); later launches
reuse it. It also creates **`dashboard-offline.html`** for a self-contained
explorer that needs no Python server.

On Windows, use `py -3 dashboard.py` if `python3` is unavailable. Python **3.10
or newer** is required for the engines. There are **no pip dependencies**, no
SIEM, no administrator permissions, and no network connection needed to run it.
The folder needs about 50 MB of disk space including the standalone dashboard.
To regenerate the detailed reports separately, run `python3 demo.py`.

## Dashboard: the concept flow

After the first launch or `python3 build_dashboard.py`, open **`dashboard-offline.html`** directly to explore the bundled evidence in one
self-contained page. It works without Python or internet access. For new-capture
analysis, start the local server:

```bash
python3 dashboard.py        # opens http://127.0.0.1:8765/ in your browser
```

On Windows, use `py -3 dashboard.py` if needed. No pip packages are required.

- **Concept flow:** Collect → Observe → Attribute → Corroborate → Qualify.
  Each step explains a join using real fields from the selected session, shows
  the current engine conclusion, and links the original supporting records.
  This is a reasoning flow, not a cross-host execution timeline.
- **Recording library:** search and filter all 14 captures. Inspect independent
  observations, the WinRM route gap, and the explained ShellWindows limit.
- **Evidence removal:** all 57 whole-event-type removals are computed by Python.
  Open a matrix cell or use the recording's evidence selector. Removing 4624
  leaves a local installation artifact; removing Sysmon 3 leaves a Session;
  removing 4697 can leave SCM access without installation.
- **Record inspection:** formatted JSON, the exact original NDJSON line, and
  its SHA-256. Large integers stay in text. The browser can verify the line hash
  where Web Crypto is available. Download source lines and analysis JSON.
- **Analyze a capture:** available with the local server. Choose an OTRF NDJSON
  file or ZIP; both engines run in memory and the file is not saved.
- **Presentation view:** hides workspace navigation and summary metrics so the
  reasoning and evidence remain the focus.

The hosted and standalone versions are explorers of **Python-computed snapshots**,
not browser implementations of the detector. The full inputs and engines are in
this project. Rebuild the snapshot and standalone HTML after code or data changes:

```bash
python3 build_dashboard.py
python3 -m unittest discover -v
node test_dashboard_ui.cjs   # optional Node-only interaction contract checks
```

`build_dashboard.py` verifies every pinned archive/member hash, recomputes both
engines for the removal experiments, and embeds only referenced records. The
local server verifies inputs at startup and rebuilds when engine hashes change.
The general and strict SCM contracts remain distinct: the strict one also needs
session-attributed `svcctl` access, so removing 5145 can invalidate it while the
general 4697 installation claim still has Session or Route support.

Local-server guards: loopback-only bind, Host/Origin checks, a 100 MB upload cap,
ZIP member and expanded-size limits, strict CSP, and escaped text. ZIP member
paths are retained to prevent ambiguous file/line references. Duplicate member
names are refused. No telemetry is uploaded by the hosted dashboard.

## Scorecard: one engine, 14 recordings

`reconstruct.py` anchors every finding on the network-logon session Windows
creates on the target, then assigns an evidence level:

| Level | Meaning |
|---|---|
| Artifact | A service or task is recorded on the target, but no remote session owns it |
| Session | The action belongs to a successful network logon on the same host (logon ID, account, SID) |
| Route | That logon matches one TCP connection seen on both machines, naming the source host |

| Technique | How it is recognized (never by tool, service or host name) |
|---|---|
| Service install | Security 4697 in the remote session |
| Service-control access | Security 5145 on `IPC$\svcctl` in the remote session |
| Scheduled task | Security 4698 in the remote session |
| WMI execution | Sysmon 1 process in the remote session whose parent is `WmiPrvSE.exe` |
| PowerShell remoting | Sysmon 1 `wsmprovhost.exe` in the remote session |
| DCOM execution | Sysmon 1 process in the remote session started by the `DcomLaunch` service host |

Current result: **expected technique category observed in 13 of 14 recordings;
no additional remote technique categories reported**; 11 reach the Route level.
This compares technique *categories*. Event-level attribution accuracy would
need independently reviewed expected sessions, artifacts and endpoints, which
this project does not have. PowerShell remoting stops at Session because its
Kerberos 4624 records carry no source address, and the engine says so instead
of guessing. The one category not observed is DCOM ShellWindows, which drives
the already-running desktop `explorer.exe`, so nothing starts inside the
network session; linking it needs records these captures do not contain.

The expected category comes from each dataset's published title and is read
only by the scorer (`scorecard.py`), never by the engine.

**Evidence removal.** For every recording, each whole event type (4624, 5145,
4697, 4698, Sysmon 1, Sysmon 3) is withheld in turn and the engine rerun: 57
runs. A surviving claim passes only if the original run already made it with
the same session, principal, artifact records and route, at the same or a
higher level. All 57 runs pass. This is a tested property of *these* removals,
not a proof for every removal: deleting one record that made a session
ambiguous can legitimately restore a stronger claim (a test documents this).

**What it is not.** Every recording is an attack exercise in one lab domain.
There is no benign baseline, so this is **not a false-positive rate**.

## Handling incomplete or contradictory input

Both engines use the same validation, screening, ordering and flow-matching
functions in `analyze.py`, so a fix applies to both. Before any join:

- **Unusable identifiers never match.** A blank or `-` host, a malformed or
  null SID (`S-1-0-0`), a blank account or a zero logon ID makes that record
  ineligible, with the reason counted. Two blanks are never treated as equal,
  and a missing field is reported instead of raising an error.
- **Contradictory versions are excluded.** One host, one channel and one record
  number identify one event. If the capture holds two different versions, both
  are kept in the report as a contradiction and neither supports attribution.
- **Strict audit order.** Distinct Security events must have strictly
  increasing record numbers. Record numbers are normalized first (`91138`,
  `"91138"` and `"091138"` are one event). A time zone on one record only is
  reported as a clock gap, never compared.
- **Valid endpoints only.** A route needs a valid IP address and port on both
  Sysmon records; a missing endpoint never matches another missing endpoint.
  Without one, the claim stays at Session with the reason.
- **Recognition is separate from attribution.** A service or task whose actor
  cannot be established is still reported, as an Artifact with the reason.
- **Domain-aware identity.** Process users keep their domain. NETBIOS and DNS
  forms (THESHIRE, THESHIRE.LOCAL) are accepted as one domain only when
  validated Security-Auditing records (accepted outcome, usable SID, account
  and domain) show both for the same SID; findings cite those records. A
  contradictory or foreign-provider record teaches no alias, and any other
  disagreement weakens the claim to Artifact.
- **Mechanisms need the system path.** A parent named `WmiPrvSE.exe` outside
  `System32\wbem` is a hint, reported as "mechanism not confirmed".
- **Outcome conflicts.** An `EventType` that disagrees with the `Keywords`
  bits is a contradiction and supports nothing.
- **Honest counters.** A session is one network logon on one host; an
  installation is one 4697 record. A second installation no longer inflates the
  session count.
- **Disclosed schema.** Older exports mark success with `EventType`, newer ones
  only with `Keywords` (sometimes as a signed 64-bit integer). Both are read,
  and the report states which one each capture used.

Labels follow the evidence level: for example "Scheduled task creation:
observed; remote attribution unavailable" for an Artifact. The deep-dive report
lists contradictions and rejected records with the same JSON viewer, and labels the top panel as the capture summary, gives each
session its own conclusion, and shows a checklist computed in Python for the
selected session: each condition, its result (supported, not observed,
unknown), the values that matched, and the record references.

## Deep dive: what to demonstrate

1. **Service creation:** the capture contains 3,390 original event records. Two
   remote service-control sessions are supported; one contains a service
   installation linked to the same account SID and target-host logon ID.
2. **Service query:** a separate capture contains 349 original records. Remote
   service-control access is supported, but no installation is linked.
3. **Missing logon evidence:** check “Withhold 4624 logon evidence.” In the
   creation case, the service-installation event remains, while the remote
   attribution becomes `INSUFFICIENT_EVIDENCE`.
4. Click **Inspect JSON** to trace the result to an original input line and
   SHA-256 hash. The report embeds the supporting records for offline inspection.

The query capture is an **access-only comparator**, not benign ground truth.
These are real logs from controlled attack-emulation exercises, not production
organization traffic. Nothing in the demo estimates a false-positive rate or
claims operational accuracy across enterprises.

## The exact question

> Can the observed service installation be attributed to a recorded remote
> network-logon session, with matching network evidence on both endpoints?

The answer is a statement about **observed behavior**. Authorization stays
`UNKNOWN_CONTEXT`: the source captures contain no organizational route policy,
change approval, PAW inventory, or entitlement context. Service installation
does not prove the binary executed; a short capture cannot prove a first-ever
pivot or an arbitrary-length lateral-movement path.

## Correlation contract

- Match provider AND channel AND event ID, so unrelated event numbers cannot
  accidentally join.
- Accept a successful Security 4624 type-3 logon with a usable remote address.
- Match an audit-success 5145 IPC$ / `svcctl` access check by **target host,
  account SID, account name, logon ID, source IP, and source port**.
- Corroborate the exact TCP flow using target-side and source-side Sysmon 3
  records with matching source IP/port, destination IP, and destination port 445.
- Match Security 4697 using the same target host, SID, account, and session, in
  audit-record order within **60 source-local seconds** of the logon.
- Reject missing or ambiguous links. Never promote a service name, scenario
  label, or nearby timestamp into an identity join.

5145 is an access-check event. It does not by itself prove an RPC method or a
successful file write. Logon IDs are host-local; a matching number on a different
host is insufficient. Account SIDs avoid silently equating domain display names
such as `THESHIRE` and `THESHIRE.LOCAL`.

In these captures, `host` identifies the Windows Event Collector and `Hostname`
identifies the originating endpoint. The joins use `Hostname`.

### Timestamp handling

Security `EventTime` has no timezone in these captures. It is compared only on
the same host and is not relabelled UTC. Security record numbers also enforce
local audit order. Sysmon supplies `UtcTime`, while `@timestamp` is a UTC
collection timestamp. Cross-host flow matching uses a conservative **10-second
collection-time proximity gate** alongside exact endpoints. This is a bounded
offline assumption, not proof of synchronized host clocks or packet timing.
Collection delays may make the demo abstain on a valid session.

## Source provenance

Publisher: **Open Threat Research Forge / Security-Datasets**.
Contributor: **Roberto Rodriguez (@Cyb3rWard0g)**.
Pinned repository commit: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.

| Capture | Dataset ID | Documentation |
|---|---|---|
| Covenant SharpSC Create | SDWIN-200806022635 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806022635.html |
| Covenant SharpSC Query | SDWIN-200806012009 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806012009.html |
| Empire Invoke PsExec | SDWIN-190518210652 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210652.html |
| Empire Invoke SMBExec | SDWIN-190518210125 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210125.html |
| Covenant SC.exe Utility Query | SDWIN-200805034820 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200805034820.html |
| Covenant SharpSC Start | SDWIN-200806030120 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806030120.html |
| Covenant SharpSC Stop Service | SDWIN-200806031938 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806031938.html |
| Remote Scheduled Task Creation | SDWIN-201219070027 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201219070027.html |
| Covenant SharpWMI Exec | SDWIN-200806035621 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806035621.html |
| Empire Invoke WMI | SDWIN-200921001437 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200921001437.html |
| Covenant PowerShell Remoting Command | SDWIN-200806115603 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806115603.html |
| Empire Invoke PSRemoting | SDWIN-190518211456 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518211456.html |
| DCOM ExecuteExcel4macro | SDWIN-200917174542 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200917174542.html |
| Empire Invoke DCOM ShellWindows | SDWIN-190518211052 | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518211052.html |

`data/source/` contains the original ZIPs, source metadata, and the upstream
license. The two deep-dive captures are also shipped extracted; the other twelve
are read directly from their pinned ZIPs, and each member is hash-checked inside
the archive. The original bytes are unchanged.
`data/sources.json` records pinned download URLs, sizes, and SHA-256 hashes.
Input integrity is verified before every run. Each output record references its
original filename and line number and hashes the original line bytes, including
its newline. Exact duplicate records are deduplicated during analysis only.

No capture is manually sampled to manufacture the result. The missing-logon
experiment removes records in memory and leaves source files untouched. Test
mutations are confined to the test suite and are never presented as real logs.

Microsoft event definitions:
- 4624: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- 5145: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
- 4697: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697

## Code to explain

| File / function | Purpose |
|---|---|
| `analyze.py` / `load_records` | Read NDJSON, preserve line-level provenance, report malformed records, deduplicate exact copies |
| `analyze.py` / `network_pair` | Match a flow observed on both endpoints without an invented host map |
| `analyze.py` / `correlate` | Join host-local audit sessions and preserve unsupported observations |
| `demo.py` | Verify sources, run cases and ablations, write reproducible outputs |
| `report.py` | Render a standalone report from Python's computed results |
| `reconstruct.py` / `belongs_to` | Decide whether an action belongs to a network-logon session |
| `reconstruct.py` / `process_mechanism` | Name the launch mechanism from the parent process only |
| `reconstruct.py` / `route_for` | Tie a session to one TCP connection seen on both hosts, on any port |
| `scorecard.py` / `ablate` | Withhold one evidence type at a time and check claims only weaken |
| `scorecard_report.py` | Render the scorecard page |
| `dashboard.py` | Local web app: snapshot preparation, upload analysis, original-line lookup and server guards |
| `build_dashboard.py` | Recompute both engines over removals, verify sources, export snapshot and standalone HTML |
| `web/dashboard.js` | Presentation only; every number and decision comes from the Python engines |
| `test_reconstruct.py` | Mutation tests on real records for each technique, plus the ablation property |
| `test_demo.py` | Verify original traces, reject conflicting evidence, check reproducible outputs |

The HTML controls select already-computed Python results; they do not implement
a second browser-side detection algorithm. Captured strings are escaped and
displayed as text; no command contained in telemetry is executed.

## Verify it yourself

```bash
python3 build_dashboard.py
python3 -m unittest discover -v   # 71 tests
node test_dashboard_ui.cjs        # 355 interaction-state checks, no browser required
python3 scorecard.py          # print the scorecard to the terminal
python3 demo.py --case create --without-logons --out results/ablation
```

The tests include host/SID/source-port mismatches, missing endpoint evidence,
failed share checks, provider collisions, ambiguous sessions, and late service
installation. Changing the service name does not suppress the finding.

`results/analysis.json`, `results/report.html`, `results/scorecard.json` and
`results/scorecard.html` are deterministic for the same
inputs and code. `results/run_manifest.json` records runtime and output hashes;
runtime itself varies. Measured runtime is **offline batch processing time**,
not real-time detection latency.

## Roadmap

Start with broader captures and legitimate administration examples, then add a
policy source or deployment adapter. A real production service would also need
clock/delay handling, session lifecycle boundaries, streaming ingestion,
operational monitoring, broader regression cases, and scale testing.

## Author

Désiré Abdoul Kader BONZI, Cyber Security Laboratory, Ritsumeikan University.
Telemetry: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets),
used under its upstream license (see `data/source/`).
