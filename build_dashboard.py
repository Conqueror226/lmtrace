"""Export the actual Python results for the hosted and double-click dashboards.

No detection logic is reimplemented in JavaScript. Every evidence-removal result
is computed by reconstruct/correlate over the original, hash-verified capture.
Only referenced records are embedded; the downloadable project has full inputs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import zipfile

from analyze import correlate, evidence, sha256, verify_sources
from dashboard import ROOT, cached_scorecard, code_hashes, raw
from reconstruct import implied_by, reconstruct
from scorecard import ABLATIONS, load, strongest_related


def strict_summary(records: list[dict]) -> dict:
    result = correlate(records)
    return {"status": result["status"], "counts": result["counts"],
            "observations": result["observations"], "gaps": result["gaps"][:50]}


def referenced(value, found: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "ref" and isinstance(child, str):
                found.add(child)
            elif key in {"refs", "artifact_refs", "alias_refs"} and isinstance(child, list):
                found.update(r for r in child if isinstance(r, str))
            else:
                referenced(child, found)
    elif isinstance(value, list):
        for child in value:
            referenced(child, found)


def record_payload(record: dict, original_line: bytes) -> dict:
    if sha256(original_line) != record["_sha256"]:
        raise ValueError(f"Original line hash does not match {record['_ref']}")
    # Keep JSON as TEXT. JavaScript must not round large Windows integers.
    return {**evidence(record), "record_number": str(record["RecordNumber"]) if record.get("RecordNumber") is not None else None,
            "sha256": record["_sha256"],
            "json": json.dumps(raw(record), indent=2, ensure_ascii=False),
            "raw_line": original_line.decode("utf-8"),
            "fields": {k: str(v) for k, v in raw(record).items()
                       if isinstance(v, (str, int, float, bool)) or v is None}}


def export() -> dict:
    sources = verify_sources(ROOT)
    score = cached_scorecard()
    rows = []
    for row in score["rows"]:
        records, integrity = load(row["archive"])
        if integrity != row["integrity"]:
            raise ValueError(f"Stale scorecard for {row['archive']}; run python3 demo.py")
        original = row["result"]
        variants = {"baseline": {"removed": 0, "level": row["level"],
                                 "result": original, "strict": strict_summary(records)}}
        for name, drop in ABLATIONS.items():
            kept = [r for r in records if not drop(r)]
            removed = len(records) - len(kept)
            if not removed:
                variants[name] = {"removed": 0, "not_present": True}
                continue
            result = reconstruct(kept)
            variants[name] = {"removed": removed, "level": strongest_related(result, original),
                              "result": result, "strict": strict_summary(kept),
                              "monotonic": all(implied_by(f, original["findings"])
                                               for f in result["findings"])}
        refs = set()
        referenced(variants, refs)
        lookup = {r["_ref"]: r for r in records}
        with zipfile.ZipFile(ROOT / "data/source" / f"{row['archive']}.zip") as bundle:
            lines = {n: bundle.read(n).splitlines(keepends=True)
                     for n in {lookup[ref]["_file"] for ref in refs if ref in lookup}}
        record_lookup = {ref: record_payload(lookup[ref], lines[lookup[ref]["_file"]][lookup[ref]["_line"] - 1])
                         for ref in sorted(refs) if ref in lookup}
        archive_source = next(s for s in sources if s["local_path"] == f"data/source/{row['archive']}.zip")
        rows.append({**row, "variants": variants, "record_lookup": record_lookup,
                     "source": archive_source})
        print(f"Exported {row['title']}: {len(record_lookup)} referenced records", flush=True)
    return {"schema_version": 1, "engine_sha256": code_hashes(),
            "summary": score["summary"], "ablations": score["ablations"], "rows": rows,
            "repository": "OTRF/Security-Datasets", "publisher": "Roberto Rodriguez / OTRF",
            "revision": sources[0]["revision"],
            "data_kind": "Recorded, controlled attack-emulation exercises; not production telemetry.",
            "evaluation_limit": "Category checks only. Sessions and endpoints have not been independently labelled. No false-positive-rate or accuracy claim."}


def data_script(payload: dict) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Safe when this same script is embedded in the standalone HTML.
    return "window.EVIDENCE_DATA=" + encoded.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029") + ";\n"


def standalone(web: Path, output: Path) -> None:
    html = (web / "dashboard.html").read_text()
    html = html.replace('<link rel="stylesheet" href="dashboard.css">',
                        "<style>" + (web / "dashboard.css").read_text() + "</style>")
    for name in ["dashboard-data.js", "dashboard.js"]:
        script = (web / name).read_text().replace("</script", "<\\/script")
        html = html.replace(f'<script src="{name}"></script>', "<script>" + script + "</script>")
    output.write_text(html)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--standalone", type=Path, default=ROOT / "dashboard-offline.html")
    args = parser.parse_args()
    (ROOT / "web/dashboard-data.js").write_text(data_script(export()))
    standalone(ROOT / "web", args.standalone)
    print(f"Standalone dashboard: {args.standalone}")


if __name__ == "__main__":
    main()
