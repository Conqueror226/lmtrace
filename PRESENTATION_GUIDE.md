# Seven-minute dashboard demonstration

Before the meeting, run `python3 dashboard.py` once to build the snapshot,
then open `dashboard-offline.html`. For your own uploads, use the running server
`python3 dashboard.py` (Windows: `py -3 dashboard.py`). No pip packages or
internet access are needed. The hosted version explores the same exported
Python results. Click **Presentation view** when sharing your screen.

## 0:00–0:40 — The problem

“An event tells us something happened. An analyst also needs to know which
remote session owns it, from which machine, and how much the records support.
This demo keeps the claim attached to the evidence.”

Point to the five-step flow. Explain that it is the order of the reasoning,
not a timeline that assumes synchronized clocks across machines.

## 0:40–3:00 — One session, five steps

Keep **Covenant SharpSC Create**, **Service installation · 0xba93e3**, and
**Baseline** selected. Use **Next step**:

1. **Collect:** original OTRF Windows Security and Sysmon capture, pinned to
   an upstream revision. Original archives and member bytes are hash-checked.
2. **Observe:** Security 4697 records the Cyb3rWard0g service and registered
   binary. This establishes installation, not execution.
3. **Attribute:** the same target, logon ID and SID link the artifact to a
   successful 4624 type-3 logon for pgustavo. Nearby times alone are insufficient.
4. **Corroborate:** WORKSTATION5 `172.18.39.5:54736` → WORKSTATION6
   `172.18.39.6:445`. Both hosts recorded the same TCP endpoint tuple, with
   opposite initiation direction. Open a source line below to inspect it.
5. **Qualify:** the conclusion is a service installation in this session with
   a two-sided route. Authorization, malicious intent and service execution
   are not established. There is no first-pivot or multi-hop assertion.

## 3:00–4:30 — Make the claim earn its strength

Use **Evidence available** on this same observation:

- **Remove 4624:** the 4697 artifact survives; remote attribution does not.
- **Remove Sysmon 3:** the identity/session link survives, but the source route
  is uncorroborated. The level becomes Session.
- **Remove 4697:** SCM access survives in the session, but installation does
  not. A retained Route level does not mean the original action survives.
- **Remove 5145:** the general install/session contract still holds; the
  strict SCM contract fails because it also requires svcctl access. State the
  difference explicitly rather than treating the contracts as identical.

Each variant is a Python recomputation over retained original records. The
web page displays those results; it does not simulate a detector in JavaScript.

## 4:30–5:40 — Breadth and an honest gap

Exit Presentation view and open **Recording library**:

- 14 captures, six exercise categories, 81,140 events. The expected category
  is observed in 13 captures. The expected label is given only to the scorer.
- PowerShell remoting stops at Session: the 4624 lacks a usable source
  endpoint. Traffic nearby in time is not substituted as proof.
- Open **Empire Invoke DCOM ShellWindows**: the known gap is visible.
  ShellWindows reuses the desktop's running explorer.exe, so this contract
  cannot link a process start to the network session. Missing activation/RPC
  evidence needs a different join.

Open **Evidence removal** to show all 57 whole-event-type checks. These are
robustness checks over these captures, not a universal missing-data guarantee.

## 5:40–7:00 — Engineering and the next step

Explain that the strict and generalized engines share validation, contradiction
screening, time/ordering and flow matching. Show `CHANGES.md` and a mutation test,
such as `test_missing_inbound_network_record_breaks_the_link` or
`test_foreign_provider_record_cannot_teach_a_domain_alias`.

“Before production, I would collect legitimate administration traffic, obtain
independently reviewed session/endpoint labels, add session lifecycle boundaries,
and investigate the missing DCOM activation join. All current captures are
controlled attack exercises, so there is no measured false-positive rate.”

Ask which evidence problems matter most in their products.

## Short follow-up answers

- **Are the logs real?** Recorded Windows/Sysmon events from controlled OTRF
  exercises, not synthetic rows or production telemetry.
- **Why a hosted explorer and a local server?** The hosted page carries only
  the bundled public lab evidence. New captures are analyzed with the local
  Python server, in memory, on 127.0.0.1.
- **Why not detect a tool name?** The engine reads record fields and relationships;
  names can change without invalidating the evidence contract.
- **Does every action record contain a SID?** No. Process records use host,
  logon ID and domain-qualified account. Domain aliases must be evidenced by
  validated Security records for the same SID; the page cites those records.
- **What does the hash prove?** It connects the displayed exact NDJSON line to
  the bundled source bytes. It does not independently prove authenticity of
  the original lab collector or establish event-level ground truth.
- **What do 13/14 and 57/57 mean?** Expected category coverage and tested
  whole-event-type removal behavior, respectively. Neither is detection accuracy.
- **Does evidence removal always weaken a claim?** It does for these 57 tested
  whole-event-type removals. Removing one ambiguous record can restore a claim;
  a separate mutation test documents that limit.
- **How is the dashboard tested?** Python engine, API, provenance and removal
  tests, plus Node-only interaction contracts. These are not a browser layout test.
