"""Small, evidence-first correlation over flat OTRF Windows JSON records.

This module never consumes the scenario's attack label. It recognizes observed
remote service installation, not malicious intent or organization authorization.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import zipfile

SECURITY = "microsoft-windows-security-auditing"
SYSMON = "microsoft-windows-sysmon"
WINDOW_SECONDS = 60
NETWORK_WINDOW_SECONDS = 10


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def host(value: object) -> str:
    # Do not silently equate a short host name and an FQDN.
    return str(value or "").strip().rstrip(".").casefold()


def session(value: object) -> str | None:
    try:
        value = str(value).strip()
        number = int(value, 16 if value.lower().startswith("0x") else 10)
        return hex(number) if number > 0 else None
    except (TypeError, ValueError):
        return None


def ip(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value))
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return None
        return str(address)
    except ValueError:
        return None


def port(value: object) -> int | None:
    try:
        number = int(str(value))
        return number if 0 < number <= 65535 else None
    except (TypeError, ValueError):
        return None


def is_event(record: dict, provider: str, number: int) -> bool:
    try:
        same_number = int(record.get("EventID", -1)) == number
    except (TypeError, ValueError):
        return False
    channel = str(record.get("Channel", "")).casefold()
    expected_channel = "security" if provider == SECURITY else "microsoft-windows-sysmon/operational"
    return (same_number and str(record.get("SourceName", "")).casefold() == provider
            and channel == expected_channel)


def time_value(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


AUDIT_SUCCESS = 0x0020000000000000   # Windows keyword bits for audit success / failure
AUDIT_FAILURE = 0x0010000000000000
SID_PATTERN = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)
NULL_SIDS = {"s-1-0-0"}  # the null SID: "no security principal"


# ------------------------------------------------------------ shared validation
# Both engines use these primitives, so a fix here applies to both.

def usable_host(value: object) -> str | None:
    """A host identifier that can be compared. Blank is never a match for blank."""
    name = host(value)
    return name if name and name not in {"-", "localhost"} else None


def usable_sid(value: object) -> str | None:
    sid = str(value or "").strip()
    return sid if SID_PATTERN.match(sid) and sid.casefold() not in NULL_SIDS else None


def usable_account(value: object) -> str | None:
    name = str(value or "").strip()
    return name if name and name != "-" else None


def record_number(record: dict) -> int | None:
    """91138, "91138" and "091138" are the same record number."""
    try:
        number = int(str(record.get("RecordNumber")).strip(), 10)
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


def outcome(record: dict) -> str:
    """success, failure, conflict or unknown, from EventType and/or the Keywords bits.

    When an export carries both and they disagree, that is a contradiction, not a
    success: the record is reported and supports nothing.
    """
    event_type = {"audit_success": "success", "audit_failure": "failure"}.get(
        str(record.get("EventType", "")).casefold())
    keyword_result = None
    if record.get("Keywords") not in (None, ""):
        try:
            # Some exports write Keywords as hex, others as a signed 64-bit integer.
            bits = int(str(record.get("Keywords")), 0) & 0xFFFFFFFFFFFFFFFF
            ok, bad = bool(bits & AUDIT_SUCCESS), bool(bits & AUDIT_FAILURE)
            keyword_result = "success" if ok and not bad else "failure" if bad and not ok else None
        except (TypeError, ValueError):
            keyword_result = None
    if event_type and keyword_result and event_type != keyword_result:
        return "conflict"
    return event_type or keyword_result or "unknown"


def succeeded(record: dict) -> bool:
    return outcome(record) == "success"


def success_basis(records: list[dict]) -> dict:
    """Which field told us a Security event's outcome, and how often they disagreed."""
    basis = Counter()
    for r in records:
        if str(r.get("Channel", "")).casefold() != "security":
            continue
        basis["EventType" if r.get("EventType") else "Keywords" if r.get("Keywords") else "neither"] += 1
        if outcome(r) == "conflict":
            basis["outcome_conflicts"] += 1
    return dict(sorted(basis.items()))


def screen(records: list[dict]) -> tuple[list[dict], list[dict], dict]:
    """Exclude contradictory versions of one event before any join.

    One host, one channel and one (normalized) record number identify one event.
    If the capture holds two different versions, neither supports attribution;
    both are kept in the report as a contradiction. Records without a record
    number cannot be screened this way, and the coverage says so.
    """
    groups = defaultdict(list)
    without = 0
    for r in records:
        number = record_number(r)
        if number is None:
            without += 1
            continue
        groups[(host(r.get("Hostname")), str(r.get("Channel", "")).casefold(), number)].append(r)
    conflicts, excluded = [], set()
    for rows in groups.values():
        if len(rows) > 1:
            conflicts.append({"reason": "Conflicting versions of one event (same host, channel and record number); excluded from attribution.",
                              "evidence": [evidence(r) for r in rows]})
            excluded.update(r["_ref"] for r in rows)
    coverage = {"records_with_record_number": len(records) - without,
                "records_without_record_number": without,
                "note": ("Contradiction screening needs a record number; records without one are not screened."
                         if without else "Every record carries a record number and was screened.")}
    return [r for r in records if r["_ref"] not in excluded], conflicts, coverage


class Rejections:
    """Records that look relevant but lack identifiers a join would rely on."""

    def __init__(self):
        self.reasons, self.examples = Counter(), []

    def missing(self, checks: list[tuple[str, object]]) -> list[str]:
        return [name for name, value in checks if not value]

    def note(self, record: dict, missing: list[str]) -> str:
        reason = f"Event {record.get('EventID')}: unusable {', '.join(missing)}"
        self.reasons[reason] += 1
        if len(self.examples) < 20:
            self.examples.append({"reason": reason + ".", "evidence": [evidence(record)]})
        return reason

    def keep(self, record: dict, checks: list[tuple[str, object]]) -> bool:
        missing = self.missing(checks)
        if missing:
            self.note(record, missing)
        return not missing

    def summary(self) -> dict:
        return {"by_reason": dict(sorted(self.reasons.items())), "examples": self.examples}


def local_order(before: dict, after: dict, limit: int = WINDOW_SECONDS) -> tuple[bool, str]:
    """`before` precedes `after` on the SAME host, within `limit` seconds.

    Older OTRF exports give source-local EventTime (no zone) plus RecordNumber;
    newer ones give TimeCreated in UTC. Both records must use the same kind of
    clock; a zone on one record only is reported, never compared.
    """
    if usable_host(before.get("Hostname")) is None or host(before.get("Hostname")) != host(after.get("Hostname")):
        return False, "Records are not on the same identified host."
    field = "EventTime" if before.get("EventTime") and after.get("EventTime") else "TimeCreated"
    a, b = time_value(before.get(field)), time_value(after.get(field))
    if a is None or b is None:
        return False, f"No usable {field} on both records."
    if (a.tzinfo is None) != (b.tzinfo is None):
        return False, f"{field} has a time zone on one record only; the clocks are not comparable."
    first, second = record_number(before), record_number(after)
    if first is not None and second is not None and first >= second:
        return False, "Record numbers are not strictly increasing."  # distinct events never share one
    if not 0 <= (b - a).total_seconds() <= limit:
        return False, f"Not within {limit} s after the logon on the same host."
    return True, ""


def same_host_order(before: dict, after: dict, limit: int = WINDOW_SECONDS) -> bool:
    return local_order(before, after, limit)[0]


def capture_near(a: dict, b: dict, limit: int = NETWORK_WINDOW_SECONDS) -> bool:
    # UTC collection timestamps are an approximate proximity gate, not causal
    # timestamps. Exact network endpoints and audit identities are still needed.
    ta, tb = time_value(a.get("@timestamp")), time_value(b.get("@timestamp"))
    if ta is None or tb is None or ta.tzinfo is None or tb.tzinfo is None:
        return False
    return abs((ta - tb).total_seconds()) <= limit


def split_principal(value: object) -> tuple[str, str]:
    """THESHIRE\\pgustavo -> ("theshire", "pgustavo"). The domain is kept, never dropped."""
    text = str(value or "").strip()
    domain, _, account = text.rpartition("\\")
    return domain.casefold(), account.casefold()


def domain_aliases(records: list[dict]) -> dict[str, dict[str, list[str]]]:
    """Domain names observed for the same account SID, with the records that show it.

    Windows writes NETBIOS (THESHIRE) and DNS (THESHIRE.LOCAL) forms in different
    fields. A name counts as an alias only when a validated record shows it for
    the SID: Security-Auditing provider on the Security channel, an accepted
    (successful, non-contradictory) outcome, and a usable SID, account and
    domain. Contradictory or foreign-provider records teach nothing.
    Returns {sid: {domain: [supporting record refs]}}.
    """
    seen = defaultdict(lambda: defaultdict(list))
    for r in records:
        if not (str(r.get("SourceName", "")).casefold() == SECURITY
                and str(r.get("Channel", "")).casefold() == "security" and succeeded(r)):
            continue
        for sid_field, account_field, domain_field in (("TargetUserSid", "TargetUserName", "TargetDomainName"),
                                                       ("SubjectUserSid", "SubjectUserName", "SubjectDomainName")):
            sid, account = usable_sid(r.get(sid_field)), usable_account(r.get(account_field))
            domain = usable_account(r.get(domain_field))  # same rule: not blank, not "-"
            if sid and account and domain:
                seen[sid][domain.casefold()].append(r["_ref"])
    return {sid: {d: sorted(set(refs)) for d, refs in domains.items()} for sid, domains in seen.items()}


def evidence(record: dict) -> dict:
    return {"ref": record["_ref"], "line": record["_line"],
            "file": record["_file"], "record_sha256": record["_sha256"],
            "event_id": record.get("EventID"), "host": record.get("Hostname"),
            "channel": record.get("Channel"), "record_number": record.get("RecordNumber"),
            "event_time_local": record.get("EventTime"),
            "collected_at_utc": record.get("@timestamp")}


def load_records(path: Path, source_name: str | None = None) -> tuple[list[dict], dict]:
    """Keep a byte-level reference to each original NDJSON line; never edit input."""
    return parse_records(path.read_bytes(), source_name or path.name)


def load_archive_member(archive: Path, member: str) -> tuple[list[dict], dict]:
    """Read one NDJSON member straight from a pinned upstream ZIP (nothing extracted)."""
    with zipfile.ZipFile(archive) as bundle:
        return parse_records(bundle.read(member), member)


def parse_records(raw: bytes, filename: str) -> tuple[list[dict], dict]:
    records, seen = [], set()
    quality = Counter()
    for lineno, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record is not an object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            quality["malformed_records"] += 1
            continue
        digest = sha256(line)
        # Exact duplicate records cannot multiply findings. Preserve the first
        # line. Conflicting records are not collapsed and cause ambiguity below.
        key = sha256(canonical(record))
        if key in seen:
            quality["exact_duplicates"] += 1
            continue
        seen.add(key)
        record.update(_line=lineno, _file=filename, _sha256=digest,
                      _ref=f"{filename}:L{lineno}")
        records.append(record)
    return records, {"input_sha256": sha256(raw), "input_bytes": len(raw),
                     "input_lines": len(raw.splitlines()), "unique_records": len(records),
                     "issues": dict(quality)}


def verify_sources(root: Path) -> list[dict]:
    sources = json.loads((root / "data" / "sources.json").read_text())
    for source in sources:
        path = root / source["local_path"]
        if not path.is_file() or sha256(path.read_bytes()) != source["sha256"]:
            raise ValueError(f"Source integrity check failed: {source['local_path']}")
        for member in source.get("members", []):
            if member.get("local_path"):
                data = (root / member["local_path"]).read_bytes()
            else:  # verified inside the pinned archive; no extracted copy is shipped
                with zipfile.ZipFile(path) as bundle:
                    data = bundle.read(member["archive_name"])
            if sha256(data) != member["sha256"]:
                raise ValueError(f"Source integrity check failed: {member['archive_name']}")
    return sources


# ------------------------------------------------------------- shared flow match

def flow_endpoints(record: dict) -> dict | None:
    """A Sysmon 3 TCP record with every field a route depends on, or None.

    A missing or invalid address or port is never compared: None == None must
    not become a matching endpoint.
    """
    direction = str(record.get("Initiated", "")).casefold()
    values = {"host": usable_host(record.get("Hostname")),
              "source": (ip(record.get("SourceIp")), port(record.get("SourcePort"))),
              "destination": (ip(record.get("DestinationIp")), port(record.get("DestinationPort")))}
    if (str(record.get("Protocol", "")).casefold() != "tcp" or direction not in {"true", "false"}
            or values["host"] is None or None in values["source"] or None in values["destination"]
            or values["source"][0] == values["destination"][0]):
        return None
    values["initiated"] = direction == "true"
    return values


class FlowIndex:
    """Sysmon network records indexed by source endpoint: one lookup per logon, not a scan."""

    def __init__(self, records: list[dict]):
        self.by_source, self.invalid_sources, self.invalid = defaultdict(list), set(), 0
        for r in records:
            if not is_event(r, SYSMON, 3):
                continue
            endpoints = flow_endpoints(r)
            if endpoints is None:
                self.invalid += 1
                self.invalid_sources.add((ip(r.get("SourceIp")), port(r.get("SourcePort"))))
                continue
            self.by_source[endpoints["source"]].append((r, endpoints))


def match_flow(logon: dict, flows: FlowIndex, required_port: int | None = None) -> tuple[dict | None, str]:
    """One TCP connection seen on BOTH hosts, matching the logon's source IP and port."""
    source = (ip(logon.get("IpAddress")), port(logon.get("IpPort")))
    if None in source:
        return None, "The logon record carries no usable source address (common for Kerberos over WinRM)."
    target = usable_host(logon.get("Hostname"))
    observed = flows.by_source.get(source, [])
    candidates = []
    for inbound, a in observed:
        if (a["host"] != target or a["initiated"] or not capture_near(inbound, logon)
                or (required_port and a["destination"][1] != required_port)):
            continue
        for outbound, b in observed:
            if (b["initiated"] and b["host"] != target and b["destination"] == a["destination"]
                    and capture_near(outbound, logon) and capture_near(outbound, inbound)):
                candidates.append({"source_host": outbound.get("Hostname"), "source_ip": source[0],
                                   "source_port": source[1], "target_host": inbound.get("Hostname"),
                                   "target_ip": a["destination"][0], "target_port": a["destination"][1],
                                   "outbound": evidence(outbound), "inbound": evidence(inbound)})
    if len({(host(c["source_host"]), c["target_ip"], c["target_port"]) for c in candidates}) == 1:
        return min(candidates, key=lambda c: (c["outbound"]["line"], c["inbound"]["line"])), ""
    if candidates:
        return None, "More than one distinct connection matches the logon; the route is ambiguous."
    if source in flows.invalid_sources:
        return None, "Flow records from this source lack a valid destination address or port."
    return None, "No single TCP connection matching the logon is recorded on both hosts."


def network_pair(logon: dict, flows: FlowIndex) -> tuple[dict | None, str]:
    """Strict deep-dive contract: the same shared match, restricted to SMB (445)."""
    return match_flow(logon, flows, required_port=445)


def session_checks(logon: dict, pipe: dict, route: dict, installed: dict | None) -> list[dict]:
    """The rule, evaluated for ONE session, with the values that matched.

    Computed here so the report only displays results; the browser decides nothing.
    """
    who = f"{logon.get('TargetDomainName', '')}\\{logon.get('TargetUserName')}"
    return [
        {"check": "Successful network logon on the target", "result": "SUPPORTED",
         "detail": f"4624 type 3 for {who}, logon {session(logon.get('TargetLogonId'))}, "
                   f"from {ip(logon.get('IpAddress'))}:{port(logon.get('IpPort'))}",
         "refs": [logon["_ref"]]},
        {"check": "Host, SID, account and session agree", "result": "SUPPORTED",
         "detail": f"{logon.get('TargetUserSid')} on {logon.get('Hostname')} in 4624 and 5145 (IPC$\\svcctl)",
         "refs": [logon["_ref"], pipe["_ref"]]},
        {"check": "Same TCP connection recorded on both hosts", "result": "SUPPORTED",
         "detail": f"{route['source_host']} {route['source_ip']}:{route['source_port']} to "
                   f"{route['target_ip']}:{route['target_port']}",
         "refs": [route["outbound"]["ref"], route["inbound"]["ref"]]},
        {"check": "Service installed in the same session",
         "result": "SUPPORTED" if installed else "NOT_OBSERVED",
         "detail": (f"4697 {installed.get('ServiceName')} ({installed.get('ServiceFileName')})" if installed
                    else "No 4697 in this session within the audit window"),
         "refs": [installed["_ref"]] if installed else []},
        {"check": "Organizational authorization", "result": "UNKNOWN",
         "detail": "No change-approval or policy source was supplied", "refs": []},
    ]


def correlate(records: list[dict], *, window: int = WINDOW_SECONDS) -> dict:
    """Same-host SID + logon-ID audit joins, with bounded network corroboration."""
    usable, conflicts, coverage = screen(records)
    rejected = Rejections()
    logons = [r for r in usable if is_event(r, SECURITY, 4624)
              and str(r.get("LogonType")) == "3" and succeeded(r) and ip(r.get("IpAddress"))
              and rejected.keep(r, [("host", usable_host(r.get("Hostname"))),
                                    ("SID", usable_sid(r.get("TargetUserSid"))),
                                    ("account", usable_account(r.get("TargetUserName"))),
                                    ("logon ID", session(r.get("TargetLogonId")))])]
    pipes = [r for r in usable if is_event(r, SECURITY, 5145) and succeeded(r)
             and str(r.get("ShareName", "")).rsplit("\\", 1)[-1].casefold() == "ipc$"
             and str(r.get("RelativeTargetName", "")).strip("\\").casefold() == "svcctl"
             and rejected.keep(r, [("host", usable_host(r.get("Hostname"))),
                                   ("SID", usable_sid(r.get("SubjectUserSid"))),
                                   ("account", usable_account(r.get("SubjectUserName"))),
                                   ("logon ID", session(r.get("SubjectLogonId")))])]
    # Recognizing an installation and attributing it are separate questions: a 4697
    # whose actor cannot be established is still an observed installation.
    installs_seen = [r for r in usable if is_event(r, SECURITY, 4697) and succeeded(r)]
    services, gaps = [], []
    for r in installs_seen:
        missing = rejected.missing([("host", usable_host(r.get("Hostname"))),
                                    ("SID", usable_sid(r.get("SubjectUserSid"))),
                                    ("account", usable_account(r.get("SubjectUserName"))),
                                    ("logon ID", session(r.get("SubjectLogonId")))])
        if missing:
            rejected.note(r, missing)
            gaps.append({"reason": f"Service installation observed; its actor cannot be established (unusable {', '.join(missing)}).",
                         "evidence": [evidence(r)]})
        else:
            services.append(r)
    network = FlowIndex(usable)
    index = defaultdict(list)
    for logon in logons:
        index[(host(logon.get("Hostname")), session(logon.get("TargetLogonId")))].append(logon)
    observations, used_services = [], set()
    for pipe in pipes:
        key = (host(pipe.get("Hostname")), session(pipe.get("SubjectLogonId")))
        possible = [r for r in index.get(key, []) if same_host_order(r, pipe, window)]
        # Reject a reused/ambiguous host-local session rather than selecting a
        # convenient identity. This prevents cross-host and cross-SID joins.
        if len(possible) != 1:
            gaps.append({"reason": "Missing or ambiguous matching network logon (4624).",
                         "evidence": [evidence(pipe)]})
            continue
        logon = possible[0]
        if (pipe.get("SubjectUserSid") != logon.get("TargetUserSid")
                or str(pipe.get("SubjectUserName", "")).casefold()
                != str(logon.get("TargetUserName", "")).casefold()
                or ip(pipe.get("IpAddress")) != ip(logon.get("IpAddress"))
                or port(pipe.get("IpPort")) != port(logon.get("IpPort"))):
            gaps.append({"reason": "Pipe record conflicts with the logon SID, account, or source endpoint.",
                         "evidence": [evidence(logon), evidence(pipe)]})
            continue
        route, reason = network_pair(logon, network)
        if route is None:
            gaps.append({"reason": reason, "evidence": [evidence(logon), evidence(pipe)]})
            continue
        matches = [r for r in services
                   if host(r.get("Hostname")) == key[0]
                   and session(r.get("SubjectLogonId")) == key[1]
                   and r.get("SubjectUserSid") == logon.get("TargetUserSid")
                   and str(r.get("SubjectUserName", "")).casefold()
                   == str(logon.get("TargetUserName", "")).casefold()
                   and same_host_order(logon, r, window) and same_host_order(pipe, r, window)]
        auth = {"account": str(logon["TargetUserName"]),
                "domain": str(logon.get("TargetDomainName", "")),
                "sid": logon["TargetUserSid"], "logon_id": key[1],
                "authentication_package": logon.get("AuthenticationPackageName"),
                "evidence": evidence(logon)}
        base = {"route": route, "identity": auth, "pipe_evidence": evidence(pipe),
                "authorization": "UNKNOWN_CONTEXT",
                "claim_boundary": "Observed behavior; no malicious-intent, service-execution, first-pivot, or authorization claim."}
        if matches:
            for installed in matches:
                used_services.add(installed["_ref"])
                entry = {**base, "status": "REMOTE_SERVICE_INSTALLATION",
                         "service": {"name": installed.get("ServiceName"),
                                     "binary": installed.get("ServiceFileName"),
                                     "run_as": installed.get("ServiceAccount"),
                                     "evidence": evidence(installed)},
                         "checks": session_checks(logon, pipe, route, installed)}
                entry["observation_id"] = sha256(canonical(entry))[:16]
                observations.append(entry)
        else:
            entry = {**base, "status": "REMOTE_SERVICE_ACCESS", "service": None,
                     "checks": session_checks(logon, pipe, route, None)}
            entry["observation_id"] = sha256(canonical(entry))[:16]
            observations.append(entry)
    for service in services:
        if service["_ref"] not in used_services:
            gaps.append({"reason": "Service installation observed and attributable, but no complete remote session chain links it.",
                         "evidence": [evidence(service)]})
    # Multiple pipe checks in one session should not multiply the same finding.
    unique = {}
    for item in observations:
        key = (host(item["route"]["target_host"]), item["identity"]["logon_id"],
               item["status"], item["service"]["evidence"]["ref"] if item["service"] else None)
        unique.setdefault(key, item)
    observations = sorted(unique.values(), key=lambda x: (x["identity"]["evidence"]["line"], x["status"]))
    # A session is one network logon on one host; an installation is one 4697 record.
    # Counting observations instead would let a second install inflate the sessions.
    sessions = {(host(o["route"]["target_host"]), o["identity"]["logon_id"], o["identity"]["sid"],
                 o["identity"]["evidence"]["ref"]) for o in observations}
    installs = len({o["service"]["evidence"]["ref"] for o in observations if o["service"]})
    status = "REMOTE_SERVICE_INSTALLATION" if installs else "REMOTE_SERVICE_ACCESS" if observations else "INSUFFICIENT_EVIDENCE"
    refs = {e["ref"] for o in observations for e in [o["route"]["outbound"], o["route"]["inbound"],
            o["identity"]["evidence"], o["pipe_evidence"], *([o["service"]["evidence"]] if o["service"] else [])]}
    refs.update(e["ref"] for gap in gaps + conflicts + rejected.examples for e in gap["evidence"])
    evidence_records = []
    for r in records:
        if r["_ref"] in refs:
            raw = {k: v for k, v in r.items() if not k.startswith("_")}
            evidence_records.append({"reference": evidence(r),
                                     "raw": raw,
                                     # Format in Python so Windows' 64-bit Keywords
                                     # values never pass through JavaScript's lossy
                                     # number serialization in the record viewer.
                                     "raw_json": json.dumps(raw, indent=2, ensure_ascii=False)})
    counts = Counter(str(r.get("EventID")) for r in records)
    return {"status": status, "observations": observations, "gaps": gaps, "conflicts": conflicts,
            "quality": {"conflicting_event_identities": len(conflicts),
                        "records_excluded_as_conflicting": len(records) - len(usable),
                        "unusable_identifiers": rejected.summary(),
                        "success_read_from": success_basis(records),
                        "screening": coverage,
                        "flow_records_unusable_for_routes": network.invalid},
            "counts": {"records_analyzed": len(records), "network_logons": len(logons),
                       "service_control_checks": len(pipes), "service_install_events": len(installs_seen),
                       "attributable_install_events": len(services),
                       "supported_sessions": len(sessions), "supported_installations": installs,
                       "session_observations": len(observations),
                       "linked_evidence_records": len(evidence_records)},
            "event_counts": dict(sorted(counts.items())), "evidence_records": evidence_records,
            "parameters": {"same_host_audit_window_seconds": window,
                           "collection_time_network_window_seconds": NETWORK_WINDOW_SECONDS},
            "authorization": "UNKNOWN_CONTEXT"}
