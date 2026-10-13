"""Run the generalized engine over every bundled recording and score it.

Two questions, both answered from recorded telemetry only:

1. Technique category: is the category each exercise performed observed at the
   Session or Route level, and is no additional remote category reported?
   This checks categories, NOT event-level accuracy: the expected sessions,
   artifacts and endpoints have not been independently reviewed.
2. Evidence removal: for each whole event type withheld (57 runs), is every
   surviving claim one the original run already made, with the same principal,
   artifacts and route, at the same or a higher level? This is tested for these
   removals only. Removing a single record that made a session ambiguous can
   legitimately restore a stronger claim; that is not covered by this check.

The expected category comes from each dataset's published title. The scorer
reads it; the engine never does.
"""
from __future__ import annotations

from pathlib import Path

from analyze import SECURITY, SYSMON, is_event, load_archive_member, sha256
from reconstruct import IMPLIES, LEVELS, TECHNIQUES, implied_by, reconstruct

ROOT = Path(__file__).resolve().parent
DOCS = "https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/{}.html"

# (archive, dataset id, published title, technique the exercise performed)
CATALOG = [
    ("covenant_sharpsc_create_dcerpc_smb_svcctl", "SDWIN-200806022635", "Covenant SharpSC Create", "SERVICE_INSTALL"),
    ("empire_psexec_dcerpc_tcp_svcctl", "SDWIN-190518210652", "Empire Invoke PsExec", "SERVICE_INSTALL"),
    ("empire_smbexec_dcerpc_smb_svcctl", "SDWIN-190518210125", "Empire Invoke SMBExec", "SERVICE_INSTALL"),
    ("covenant_sharpsc_query_dcerpc_smb_svcctl", "SDWIN-200806012009", "Covenant SharpSC Query", "SERVICE_CONTROL_ACCESS"),
    ("covenant_sc_query_dcerpc_smb_svcctl", "SDWIN-200805034820", "Covenant SC.exe Utility Query", "SERVICE_CONTROL_ACCESS"),
    ("covenant_sharpsc_start_dcerpc_smb_svcctl", "SDWIN-200806030120", "Covenant SharpSC Start", "SERVICE_CONTROL_ACCESS"),
    ("covenant_sharpsc_stop_dcerpc_smb_svcctl", "SDWIN-200806031938", "Covenant SharpSC Stop Service", "SERVICE_CONTROL_ACCESS"),
    ("schtask_create", "SDWIN-201219070027", "Remote Scheduled Task Creation", "TASK_CREATE"),
    ("covenant_sharpwmi_create_dcerpc_wmi", "SDWIN-200806035621", "Covenant SharpWMI Exec", "WMI_EXECUTION"),
    ("empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod", "SDWIN-200921001437", "Empire Invoke WMI", "WMI_EXECUTION"),
    ("covenant_psremoting_command", "SDWIN-200806115603", "Covenant PowerShell Remoting Command", "WINRM_SESSION"),
    ("empire_psremoting_stager", "SDWIN-190518211456", "Empire Invoke PSRemoting", "WINRM_SESSION"),
    ("covenant_dcom_executeexcel4macro_allowed", "SDWIN-200917174542", "DCOM ExecuteExcel4macro", "DCOM_EXECUTION"),
    ("empire_dcom_shellwindows_stager", "SDWIN-190518211052", "Empire Invoke DCOM ShellWindows", "DCOM_EXECUTION"),
]

# Known, explained gaps. Shown in the report, never hidden from the score.
KNOWN_LIMITS = {
    "empire_dcom_shellwindows_stager":
        "ShellWindows drives the explorer.exe that is already running in the interactive "
        "desktop session, so no process ever starts inside the attacker's network logon. "
        "Linking it needs a different join (RPC or DCOM activation records), which these "
        "recordings do not contain.",
}

ABLATIONS = {
    "4624 network logon": lambda r: is_event(r, SECURITY, 4624),
    "5145 share access": lambda r: is_event(r, SECURITY, 5145),
    "4697 service install": lambda r: is_event(r, SECURITY, 4697),
    "4698 task created": lambda r: is_event(r, SECURITY, 4698),
    "Sysmon 1 process": lambda r: is_event(r, SYSMON, 1),
    "Sysmon 3 connection": lambda r: is_event(r, SYSMON, 3),
}


def load(archive: str) -> tuple[list[dict], dict]:
    path = ROOT / "data" / "source" / f"{archive}.zip"
    import zipfile
    with zipfile.ZipFile(path) as bundle:
        member = next(n for n in bundle.namelist() if n.endswith(".json"))
    return load_archive_member(path, member)


def outcome(expected: str, found: list[str]) -> str:
    """OBSERVED, NOT_OBSERVED, or ADDITIONAL (a remote category beyond the expected one)."""
    allowed = {expected} | IMPLIES.get(expected, set())
    if set(found) - allowed:
        return "ADDITIONAL"
    return "OBSERVED" if expected in found else "NOT_OBSERVED"


def strongest(result: dict) -> str:
    remote = [f["level"] for f in result["findings"] if LEVELS[f["level"]] >= LEVELS["SESSION"]]
    if remote:
        return max(remote, key=LEVELS.get)
    return "ARTIFACT" if result["findings"] else "NONE"


def strongest_related(result: dict, original: dict) -> str:
    """Strongest surviving claim about a session the original run reported remotely.

    Unrelated local artifacts (say, a desktop user's own scheduled task) must not
    make a cell look as if the attack were still partly attributed.
    """
    places = {(f["target_host"].casefold(), f["logon_id"]) for f in original["findings"]
              if LEVELS[f["level"]] >= LEVELS["SESSION"]}
    levels = [f["level"] for f in result["findings"]
              if LEVELS[f["level"]] >= LEVELS["SESSION"]
              or (str(f["target_host"]).casefold(), f["logon_id"]) in places]
    return max(levels, key=LEVELS.get) if levels else "NONE"


def ablate(records: list[dict], original: dict) -> dict:
    row = {}
    for name, drop in ABLATIONS.items():
        kept = [r for r in records if not drop(r)]
        removed = len(records) - len(kept)
        if removed == 0:
            row[name] = {"removed": 0, "level": None, "techniques": None, "monotonic": True}
            continue
        result = reconstruct(kept)
        row[name] = {"removed": removed, "level": strongest_related(result, original),
                     "techniques": result["remote_techniques"],
                     # Every surviving claim must already have been made: same session, principal,
                     # artifacts and route, at the same or a higher level (see implied_by).
                     "monotonic": all(implied_by(f, original["findings"]) for f in result["findings"])}
    return row


def run() -> dict:
    rows = []
    for archive, dataset_id, title, expected in CATALOG:
        records, integrity = load(archive)
        result = reconstruct(records)
        rows.append({
            "archive": archive, "dataset_id": dataset_id, "title": title,
            "documentation": DOCS.format(dataset_id), "expected": expected,
            "expected_label": TECHNIQUES[expected], "integrity": integrity,
            "result": result, "level": strongest(result),
            "outcome": outcome(expected, result["remote_techniques"]),
            "known_limit": KNOWN_LIMITS.get(archive),
            "ablation": ablate(records, result),
        })
    cells = [c for r in rows for c in r["ablation"].values() if c["removed"]]
    summary = {
        "recordings": len(rows),
        "records": sum(r["result"]["counts"]["records"] for r in rows),
        "techniques": len({r["expected"] for r in rows}),
        "expected_observed": sum(r["outcome"] == "OBSERVED" for r in rows),
        "additional_categories": sum(r["outcome"] == "ADDITIONAL" for r in rows),
        "not_observed": sum(r["outcome"] == "NOT_OBSERVED" for r in rows),
        "route_level": sum(r["level"] == "ROUTE" for r in rows),
        "ablation_runs": len(cells),
        "ablation_monotonic": sum(c["monotonic"] for c in cells),
    }
    return {"summary": summary, "rows": rows, "ablations": list(ABLATIONS),
            "levels": LEVELS, "techniques": TECHNIQUES}


if __name__ == "__main__":
    import json
    out = run()
    print(json.dumps(out["summary"], indent=2))
    for r in out["rows"]:
        print(f"{r['title'][:38]:38} {r['outcome']:9} {r['level']:8} {r['result']['remote_techniques']}")
    print("sha:", sha256(json.dumps(out, sort_keys=True, default=str).encode())[:16])
