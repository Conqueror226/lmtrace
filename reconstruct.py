"""Generalized remote-activity reconstruction over the same recorded telemetry.

`analyze.correlate` is the strict, single-technique contract used in the deep
dive. This module generalizes it to several remote-execution techniques by
anchoring everything on what they share: the network logon session Windows
creates on the target. Validation, contradiction screening, audit ordering and
flow matching are the SAME functions the strict engine uses (see analyze.py).

Every finding carries an evidence level:

    ARTIFACT  an action is recorded on the target (service, task, process), but
              no remote session can be shown to own it; the reason is stated
    SESSION   the action belongs to a successful network-logon session on the
              same host (same logon ID, SID or domain-qualified account)
    ROUTE     that session also matches one TCP connection recorded on BOTH
              endpoints with valid addresses and ports, naming the source host

The engine never reads the dataset name, a tool name, a service name or a
hard-coded host. Labels say only what the evidence level supports.
"""
from __future__ import annotations

from collections import defaultdict

from analyze import (SECURITY, SYSMON, FlowIndex, Rejections, capture_near, domain_aliases, evidence,
                     host, is_event, local_order, match_flow, screen, session, split_principal,
                     success_basis, succeeded, usable_account, usable_host, usable_sid)

LEVELS = {"ARTIFACT": 1, "SESSION": 2, "ROUTE": 3}
PROCESS_WINDOW_SECONDS = 120      # collection-time gate for Sysmon process joins

# Weaker claims a stronger finding already implies (used by the ablation check).
IMPLIES = {"SERVICE_INSTALL": {"SERVICE_CONTROL_ACCESS"}}

TECHNIQUES = {  # what was observed, independent of how far attribution reaches
    "SERVICE_INSTALL": "Service installation",
    "SERVICE_CONTROL_ACCESS": "Service Control Manager access over the network",
    "TASK_CREATE": "Scheduled task creation",
    "WMI_EXECUTION": "Process started by the WMI provider host",
    "WINRM_SESSION": "PowerShell remoting host started",
    "DCOM_EXECUTION": "Process started by the DCOM launcher",
    "REMOTE_PROCESS": "Process started (launch mechanism not confirmed)",
}
LEVEL_WORDING = {
    "ARTIFACT": "observed; remote attribution unavailable",
    "SESSION": "linked to a network-logon session",
    "ROUTE": "linked to a network-logon session with endpoints corroborated on both hosts",
}

# A mechanism is named from the parent process only when it runs from its system path.
SYSTEM_PATHS = {
    "wmiprvse.exe": {r"c:\windows\system32\wbem\wmiprvse.exe", r"c:\windows\syswow64\wbem\wmiprvse.exe"},
    "wsmprovhost.exe": {r"c:\windows\system32\wsmprovhost.exe", r"c:\windows\syswow64\wsmprovhost.exe"},
    "svchost.exe": {r"c:\windows\system32\svchost.exe"},
}


def label(technique: str, level: str) -> str:
    return f"{TECHNIQUES[technique]}: {LEVEL_WORDING[level]}"


def exe(path: object) -> str:
    return str(path or "").rsplit("\\", 1)[-1].casefold()


def system_path(path: object) -> str:
    text = str(path or "").strip().strip('"').replace("/", "\\").casefold()
    for prefix in ("\\??\\", "\\\\?\\"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text.replace("%systemroot%", r"c:\windows").replace("%windir%", r"c:\windows")


def trusted(name: str, path: object) -> bool:
    return system_path(path) in SYSTEM_PATHS[name]


# ----------------------------------------------------------------- sessions

def network_sessions(records: list[dict], rejected: Rejections) -> tuple[dict, list[dict]]:
    """Successful type-3 logons by user accounts, keyed by (host, logon ID)."""
    found, gaps = defaultdict(list), []
    for r in records:
        if not (is_event(r, SECURITY, 4624) and succeeded(r) and str(r.get("LogonType")) == "3"):
            continue
        user = str(r.get("TargetUserName", ""))
        if user.endswith("$") or user.casefold() == "anonymous logon":
            continue
        if not rejected.keep(r, [("host", usable_host(r.get("Hostname"))),
                                 ("SID", usable_sid(r.get("TargetUserSid"))),
                                 ("account", usable_account(user)),
                                 ("logon ID", session(r.get("TargetLogonId")))]):
            continue
        found[(host(r.get("Hostname")), session(r.get("TargetLogonId")))].append(r)
    sessions = {}
    for key, rows in found.items():
        if len(rows) == 1:
            sessions[key] = rows[0]
        else:  # a reused logon ID is ambiguous; refuse to pick one
            gaps.append({"reason": "Ambiguous network logon: the same logon ID appears more than once.",
                         "evidence": [evidence(r) for r in rows]})
    return sessions, gaps


# ---------------------------------------------------------------- artifacts

def process_mechanism(proc: dict) -> tuple[str, str]:
    """What started this process? Decided from the parent, never from the payload.

    A matching file NAME is only a hint: the mechanism is named when the parent
    (or the remoting host itself) runs from its Windows system path.
    """
    parent, image = exe(proc.get("ParentImage")), exe(proc.get("Image"))
    parent_cmd = str(proc.get("ParentCommandLine", "")).casefold()
    if parent == "wmiprvse.exe":
        if trusted(parent, proc.get("ParentImage")):
            return "WMI_EXECUTION", ""
        return "REMOTE_PROCESS", f"Parent is named WmiPrvSE.exe but runs from {proc.get('ParentImage')}; WMI not confirmed."
    if image == "wsmprovhost.exe":
        if trusted(image, proc.get("Image")):
            return "WINRM_SESSION", ""
        return "REMOTE_PROCESS", f"Process is named wsmprovhost.exe but runs from {proc.get('Image')}; remoting not confirmed."
    if parent == "svchost.exe" and "dcomlaunch" in parent_cmd:
        if trusted(parent, proc.get("ParentImage")):
            return "DCOM_EXECUTION", ""
        return "REMOTE_PROCESS", f"DcomLaunch host runs from {proc.get('ParentImage')}; DCOM not confirmed."
    return "REMOTE_PROCESS", ""


def artifacts(records: list[dict], rejected: Rejections) -> list[dict]:
    """Target-side actions, recognized whether or not their actor can be established."""
    out = []
    for r in records:
        if is_event(r, SECURITY, 4697) and succeeded(r):
            technique, detail = "SERVICE_INSTALL", {"service": r.get("ServiceName"), "binary": r.get("ServiceFileName")}
        elif is_event(r, SECURITY, 4698) and succeeded(r):
            technique, detail = "TASK_CREATE", {"task": r.get("TaskName")}
        elif (is_event(r, SECURITY, 5145) and succeeded(r)
              and str(r.get("ShareName", "")).rsplit("\\", 1)[-1].casefold() == "ipc$"
              and str(r.get("RelativeTargetName", "")).strip("\\").casefold() == "svcctl"):
            technique, detail = "SERVICE_CONTROL_ACCESS", {"pipe": "IPC$\\svcctl"}
        elif is_event(r, SYSMON, 1):
            if not (usable_host(r.get("Hostname")) and usable_account(r.get("User"))):
                continue  # a process without host or user cannot be placed anywhere
            technique, note = process_mechanism(r)
            domain, account = split_principal(r.get("User"))
            out.append({"technique": technique, "record": r, "kind": "process", "missing": [],
                        "logon_id": session(r.get("LogonId")), "sid": None, "domain": domain, "account": account,
                        "note": note,
                        "detail": {"image": r.get("Image"), "parent": r.get("ParentImage"),
                                   "command_line": r.get("CommandLine"),
                                   "guid": r.get("ProcessGuid"), "parent_guid": r.get("ParentProcessGuid")}})
            continue
        else:
            continue
        missing = rejected.missing([("host", usable_host(r.get("Hostname"))),
                                    ("SID", usable_sid(r.get("SubjectUserSid"))),
                                    ("account", usable_account(r.get("SubjectUserName"))),
                                    ("logon ID", session(r.get("SubjectLogonId")))])
        if missing:
            rejected.note(r, missing)
        out.append({"technique": technique, "record": r, "kind": "security", "missing": missing,
                    "logon_id": session(r.get("SubjectLogonId")), "sid": usable_sid(r.get("SubjectUserSid")),
                    "domain": str(r.get("SubjectDomainName") or "").casefold(),
                    "account": str(r.get("SubjectUserName") or "").casefold(), "note": "", "detail": detail})
    return out


def belongs_to(art: dict, logon: dict, aliases: dict) -> tuple[bool, str]:
    """Does this action belong to this network-logon session? If not, say why."""
    r = art["record"]
    if host(r.get("Hostname")) != host(logon.get("Hostname")):
        return False, "Different host."
    if art["account"] != str(logon.get("TargetUserName", "")).casefold():
        return False, "Account name differs from the logon's."
    if art["kind"] == "security":
        if art["sid"] != logon.get("TargetUserSid"):
            return False, "Account SID differs from the logon's."
        return local_order(logon, r)
    # Sysmon reports DOMAIN\\user. The domain must be the logon's, or a name the
    # capture records for the same SID (NETBIOS vs DNS form); otherwise it weakens.
    sid = logon.get("TargetUserSid")
    allowed = set(aliases.get(sid, {})) | {str(logon.get("TargetDomainName", "")).casefold()}
    if not art["domain"] or art["domain"] not in allowed:
        return False, (f"Process domain '{art['domain'] or '(none)'}' is not the logon's domain and is not "
                       f"recorded for SID {sid} in this capture.")
    if not capture_near(logon, r, PROCESS_WINDOW_SECONDS):
        return False, f"Process not collected within {PROCESS_WINDOW_SECONDS} s of the logon."
    return True, ""


# ------------------------------------------------------------------- engine

def _artifact_finding(art: dict, reason: str) -> dict:
    r = art["record"]
    return {
        "technique": art["technique"], "label": label(art["technique"], "ARTIFACT"), "level": "ARTIFACT",
        "target_host": r.get("Hostname"), "logon_id": art["logon_id"],
        "account": r.get("SubjectUserName") or r.get("User"),
        "principal": {"sid": art["sid"], "domain": art["domain"], "account": art["account"]},
        "authentication": None, "route": None, "route_gap": reason,
        "details": [art["detail"]], "notes": [art["note"]] if art["note"] else [],
        "follow_on": [], "evidence": [evidence(r)], "artifact_refs": [r["_ref"]], "alias_refs": [],
    }


def reconstruct(records: list[dict]) -> dict:
    usable, conflicts, coverage = screen(records)
    rejected = Rejections()
    sessions, gaps = network_sessions(usable, rejected)
    flows = FlowIndex(usable)
    aliases = domain_aliases(usable)
    by_session = defaultdict(list)
    weakened = []
    for art in artifacts(usable, rejected):
        if art["missing"]:
            weakened.append((art, f"Actor cannot be established (unusable {', '.join(art['missing'])})."))
            continue
        key = (host(art["record"].get("Hostname")), art["logon_id"])
        logon = sessions.get(key)
        if logon is not None:
            ok, why = belongs_to(art, logon, aliases)
            if ok:
                by_session[key].append(art)
            elif art["kind"] == "security" or art["technique"] != "REMOTE_PROCESS" or art["note"]:
                weakened.append((art, why))  # a mechanism-bearing process that fails identity is kept, weakened
        elif art["kind"] == "security" and art["technique"] != "SERVICE_CONTROL_ACCESS":
            # An audited service or task with no remote anchor stays a local artifact.
            # Processes do not: without a network session they are ordinary desktop activity.
            weakened.append((art, "No matching network-logon session on this host."))

    findings = []
    for key, arts in by_session.items():
        logon = sessions[key]
        route, why = match_flow(logon, flows)
        # Inside a session, only the first process of each chain says how it started.
        guids = {a["detail"]["guid"] for a in arts if a["kind"] == "process"}
        entries = [a for a in arts if a["kind"] == "security" or a["detail"]["parent_guid"] not in guids]
        followers = [a for a in arts if a["kind"] == "process" and a not in entries]
        techniques = {a["technique"] for a in entries}
        for technique in sorted(techniques):
            if any(technique in IMPLIES.get(t, set()) for t in techniques):
                continue  # e.g. an installation already implies service-control access
            items = [a for a in entries if a["technique"] == technique]
            implied = [a for a in entries if a["technique"] in IMPLIES.get(technique, set())]
            level = "ROUTE" if route else "SESSION"
            domain = str(logon.get("TargetDomainName", ""))
            notes = [a["note"] for a in items if a["note"]]
            seen_domains = {a["domain"] for a in items if a["kind"] == "process"} - {domain.casefold()}
            alias_refs = sorted({ref for d in seen_domains for ref in aliases.get(logon.get("TargetUserSid"), {}).get(d, [])})
            if seen_domains:
                notes.append(f"Process domain {', '.join(sorted(d.upper() for d in seen_domains))} accepted as the same "
                             f"domain as {domain}: validated Security-Auditing records show both for SID "
                             f"{logon.get('TargetUserSid')} ({len(alias_refs)} supporting records, e.g. {alias_refs[0]}).")
            findings.append({
                "technique": technique, "label": label(technique, level), "level": level,
                "target_host": logon["Hostname"], "logon_id": key[1],
                "account": f"{domain}\\{logon['TargetUserName']}",
                "principal": {"sid": logon.get("TargetUserSid"), "domain": domain.casefold(),
                              "account": str(logon["TargetUserName"]).casefold()},
                "authentication": logon.get("AuthenticationPackageName"),
                "route": route, "route_gap": None if route else why,
                "details": [a["detail"] for a in items], "notes": notes,
                "follow_on": sorted({exe(a["detail"]["image"]) for a in followers
                                     if technique != "SERVICE_CONTROL_ACCESS"}),
                "evidence": [evidence(logon)] + [evidence(a["record"]) for a in items + implied]
                            + ([route["outbound"], route["inbound"]] if route else []),
                "artifact_refs": sorted(a["record"]["_ref"] for a in items + implied),
                "alias_refs": alias_refs,
            })
    findings += [_artifact_finding(art, why) for art, why in weakened]
    findings.sort(key=lambda f: (-LEVELS[f["level"]], f["technique"], str(f["logon_id"]), f["artifact_refs"]))
    remote = [f for f in findings if LEVELS[f["level"]] >= LEVELS["SESSION"]]
    return {"findings": findings,
            "remote_techniques": sorted({f["technique"] for f in remote}),
            "max_level": max((f["level"] for f in findings), key=LEVELS.get, default="NONE"),
            "counts": {"records": len(records), "network_sessions": len(sessions),
                       "remote_findings": len(remote),
                       "unattributed_artifacts": len(findings) - len(remote)},
            "gaps": gaps, "conflicts": conflicts,
            "quality": {"conflicting_event_identities": len(conflicts),
                        "unusable_identifiers": rejected.summary()["by_reason"],
                        "rejected_examples": rejected.summary()["examples"],
                        "success_read_from": success_basis(records),
                        "screening": coverage,
                        "flow_records_unusable_for_routes": flows.invalid}}


def implied_by(weaker: dict, findings: list[dict]) -> bool:
    """True when an original finding already made at least this claim.

    "At least" means: same host and logon session, same principal (SID when both
    have one, otherwise the account), every artifact record of the weaker claim
    already among the original's, a technique that is the same or implied, a
    level no higher, and, if the weaker claim has a route, the very same route
    (source host, IP and port, and target host, IP and port).
    """
    def principal_matches(a: dict, b: dict) -> bool:
        if a["sid"] and b["sid"]:
            return a["sid"] == b["sid"]
        return a["account"] == b["account"]

    for f in findings:
        if not (host(f["target_host"]) == host(weaker["target_host"]) and f["logon_id"] == weaker["logon_id"]):
            continue
        same_or_implied = (weaker["technique"] == f["technique"]
                           or weaker["technique"] in IMPLIES.get(f["technique"], set()))
        def route_key(route: dict) -> tuple:  # the complete connection, both ends
            return (host(route["source_host"]), route["source_ip"], route["source_port"],
                    host(route["target_host"]), route["target_ip"], route["target_port"])
        same_route = weaker["route"] is None or (f["route"] is not None and route_key(f["route"]) == route_key(weaker["route"]))
        if (same_or_implied and same_route and LEVELS[weaker["level"]] <= LEVELS[f["level"]]
                and principal_matches(weaker["principal"], f["principal"])
                and set(weaker["artifact_refs"]) <= set(f["artifact_refs"])):
            return True
    return False
