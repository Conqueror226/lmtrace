# Changes

## Evidence workspace: guided dashboard over v5 (current)

- Replaced the overview/iframe entry point with a five-step reasoning flow.
  Each step uses the selected finding and original fields; missing evidence
  remains visible rather than completing an assumed path.
- Recording search, all 57 Python-computed removal experiments, a presentation
  view, analysis JSON download, exact source-line viewing and hash verification.
- `build_dashboard.py` exports a hash-verified snapshot for private hosting and
  a self-contained `dashboard-offline.html`. No detector is rewritten in JS.
- The local server keeps real upload analysis, verifies the pinned sources,
  refreshes stale engine snapshots, and preserves ZIP member paths. Duplicate
  event-member names and nonpositive upload lengths are refused.
- The strict SCM and general contracts are explained separately. Process
  events without SIDs are shown as such; identity aliases cite Security records.
- Generated snapshot/standalone files are ignored by Git and rebuilt locally.
- Added export/provenance tests and Node-only interaction contract checks.
  Core reconstruction algorithms and recorded-data conclusions are unchanged.


## v5.1: published as LMTrace

- Project renamed LMTrace; titles, dashboard and README updated for a public repository.

## v5: local dashboard

- `dashboard.py` plus `web/`: an offline web app (standard library only) with
  Overview, Recordings, Analyze a capture and Deep dive views. Engines and
  scorecard results are unchanged.
- Uploads are analyzed in memory by both engines; record references open the
  original JSON line and hash.
- Guards: loopback-only bind, Host/Origin check, 100 MB cap, ZIP member and
  expanded-size limits, strict CSP without inline script.
- New `test_dashboard.py` (10 tests). Suite: 64 tests.

## v4.1: aliases from validated records only

- Domain aliases are learned only from Security-Auditing records on the
  Security channel with an accepted, non-contradictory outcome and a usable
  SID, account and domain. Each alias keeps its supporting record references,
  which findings cite in `alias_refs`. Before, a contradictory or
  foreign-provider record could supply an alias that raised a WMI finding from
  Artifact to Route.
- `implied_by` compares the complete route: source host, IP and port, and
  target host, IP and port.
- Scorecard wording: "source host corroborated by records on both endpoints".
- 3 new alias tests plus route-tuple checks. Suite: 54 tests. Scorecard
  numbers unchanged.

## v4: shared primitives and claims that match what is checked

- One set of validation, screening, ordering and flow-matching functions in
  `analyze.py`, used by both engines. Flow matching uses an index by source
  endpoint instead of a scan.
- Routes require a valid IP and port on both Sysmon records; otherwise the
  claim stays at Session with the reason (two missing endpoints matched before).
- A service or task whose actor cannot be established is kept as an Artifact
  with its gap, in both engines, instead of disappearing.
- Process identity keeps the domain. NETBIOS/DNS forms are accepted only when
  the capture records both for the same SID; other mismatches weaken the claim.
- Mechanisms (WMI, remoting, DCOM) need the parent's Windows system path; a
  matching name elsewhere is reported as "not confirmed".
- Record numbers are normalized before screening; screening coverage is
  reported; mixed clock kinds become a stated gap instead of a `TypeError`;
  conflicting `EventType`/`Keywords` outcomes support nothing.
- Level-aware labels ("observed; remote attribution unavailable" for Artifacts).
- Scorecard wording: "expected technique category observed in 13 of 14; no
  additional remote categories". The ablation check now compares session,
  principal, artifact records and route, and its scope is stated.
- Report: Contradictions and Rejected records sections with the JSON viewer;
  mobile wrapping fixed. Outputs are written as exact bytes; hashes are taken
  from disk.
- New `test_v4.py` (14 tests). Suite: 51 tests. Scorecard numbers unchanged.

## v3: input hardening

- Unusable identifiers (blank host, malformed or null SID, blank account, zero
  logon ID) no longer match each other; they are counted with a reason. A
  missing `Hostname` no longer raises `KeyError`.
- Two different versions of one event (same host, channel and record number)
  are flagged and excluded from attribution in both engines.
- Distinct Security events must have strictly increasing record numbers.
- `supported_sessions` counts network-logon sessions; installations are
  counted separately by 4697 record.
- Audit success is read from `EventType` or, for newer exports, the `Keywords`
  bits (hex or signed integer); the field used is reported.
- Deep-dive report: "Capture summary" label, a conclusion per session, a
  per-session checklist computed in Python, and an input-quality line.
- New `test_hardening.py` (8 tests). Suite: 37 tests. Scorecard results are
  unchanged: 13 of 14 correct, 0 overclaims, 57 of 57 ablation runs monotonic.

## v2: generalized engine and scorecard

- `reconstruct.py`: one engine for six techniques, anchored on the network
  logon session, with Artifact / Session / Route evidence levels.
- 12 more pinned OTRF recordings (14 total, 81,140 records), read from ZIPs.
- `scorecard.py` and `scorecard.html`: attribution results and a 57-run
  evidence-removal matrix.

## v1: strict deep dive

- Service-installation contract over two OTRF captures, with record-level
  provenance and a withheld-logon experiment.
