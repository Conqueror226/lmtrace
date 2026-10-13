#!/usr/bin/env python3
"""Run the bundled, real-telemetry cases entirely offline using Python 3.10+."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from analyze import canonical, correlate, is_event, load_records, sha256, verify_sources, SECURITY
from report import build_report
from scorecard import run as run_scorecard
from scorecard_report import build_scorecard

ROOT = Path(__file__).resolve().parent
CODE_FILES = ["analyze.py", "demo.py", "report.py", "reconstruct.py", "scorecard.py", "scorecard_report.py"]
CASES = {
    "create": {"title": "Remote service creation", "dataset_id": "SDWIN-200806022635",
               "description": "Recorded telemetry from the documented Covenant SharpSC Create exercise.",
               "source": "covenant_sharpsc_create_dcerpc_smb_svcctl_2020-08-06022635.json",
               "documentation": "https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806022635.html"},
    "query": {"title": "Remote service query", "dataset_id": "SDWIN-200806012009",
              "description": "Recorded telemetry from the documented Covenant SharpSC Query exercise. This is an access-only comparator, not a benign label.",
              "source": "covenant_sharpsc_query_dcerpc_smb_svcctl_2020-08-06012009.json",
              "documentation": "https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806012009.html"},
}


def run_case(case: str, *, without_logons: bool = False) -> dict:
    metadata = CASES[case]
    records, source = load_records(ROOT / "data" / "source" / metadata["source"])
    removed = 0
    if without_logons:
        filtered = [r for r in records if not is_event(r, SECURITY, 4624)]
        removed = len(records) - len(filtered)
        records = filtered
    return {"case": case, **metadata, "source_integrity": source,
            "experiment": {"name": "withhold_4624" if without_logons else "original_capture",
                           "removed_records": removed,
                           "note": "Removal-only ablation; no records are fabricated or edited." if without_logons else "Complete original host capture; no rows sampled or rewritten."},
            "analysis": correlate(records)}


def write(path: Path, text: str) -> Path:
    """Write exact UTF-8 bytes with LF newlines on every OS, so hashes are portable.

    Text mode on Windows would turn \n into \r\n and change the bytes after hashing.
    """
    path.write_bytes(text.encode("utf-8"))
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["all", *CASES], default="all")
    parser.add_argument("--without-logons", action="store_true", help="Withhold 4624 records as a removal-only experiment")
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    args = parser.parse_args(argv)
    started = time.perf_counter()
    try:
        sources = verify_sources(ROOT)
        code = {name: sha256((ROOT / name).read_bytes()) for name in CODE_FILES}
        selected = list(CASES) if args.case == "all" else [args.case]
        cases = [run_case(case, without_logons=args.without_logons) for case in selected]
        if not args.without_logons:
            cases += [run_case(case, without_logons=True) for case in selected]
        analysis = {"version": "1.0", "code_sha256": code, "sources": sources, "cases": cases}
        analysis["derivation_id"] = sha256(canonical(analysis))
        args.out.mkdir(parents=True, exist_ok=True)
        analysis_path = write(args.out / "analysis.json", json.dumps(analysis, indent=2, ensure_ascii=False) + "\n")
        report_path = write(args.out / "report.html", build_report(analysis))
        score = run_scorecard()
        score_path = write(args.out / "scorecard.json",
                           json.dumps({"code_sha256": code, **score}, indent=2, ensure_ascii=False, default=str) + "\n")
        scorecard_path = write(args.out / "scorecard.html", build_scorecard(score, {
            "revision": sources[0]["revision"], "code_sha256": code,
            "scorecard_sha256": sha256(score_path.read_bytes())}))  # hash of the bytes actually on disk
        outputs = {p.name: sha256(p.read_bytes()) for p in [analysis_path, report_path, score_path, scorecard_path]}
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        write(args.out / "run_manifest.json", json.dumps({"derivation_id": analysis["derivation_id"],
              "pipeline_ms": elapsed, "output_sha256": outputs, "code_sha256": code}, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Demo failed: {error}\n")
    for case in cases:
        counts = case["analysis"]["counts"]
        print(f"{case['case']:6} {case['experiment']['name']:16} {case['analysis']['status']:28} "
              f"records={counts['records_analyzed']} installs={counts['supported_installations']}")
    summary = score["summary"]
    print(f"Scorecard: expected category observed in {summary['expected_observed']}/{summary['recordings']}, "
          f"{summary['additional_categories']} with additional categories | "
          f"{summary['ablation_monotonic']}/{summary['ablation_runs']} whole-event-type removals added no new or stronger claim")
    print(f"Runtime: {elapsed:.2f} ms | derivation: {analysis['derivation_id'][:16]}")
    print(f"Open: {scorecard_path.resolve()}  (overview)")
    print(f"      {report_path.resolve()}  (deep dive)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
