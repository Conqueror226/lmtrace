"""Export the actual Python results for the hosted and double-click dashboards.

No detection logic is reimplemented in JavaScript. Every evidence-removal result
is computed by reconstruct/correlate over the original, hash-verified capture.
Only referenced records are embedded; the downloadable project has full inputs.
"""
# Keep type annotations unevaluated when this module is imported.
from __future__ import annotations

# Read command-line options such as --standalone.
import argparse
# Convert Python objects to JSON text for the browser.
import json
# Work with file and directory paths.
from pathlib import Path
# Read the original event files inside capture ZIP archives.
import zipfile

# Import the strict SCM engine, evidence summaries, hashing, and source checks.
from analyze import correlate, evidence, sha256, verify_sources
# Import the project path, baseline cache, engine hashes, and metadata remover.
from dashboard import ROOT, cached_scorecard, code_hashes, raw
# Import the general engine and the baseline-claim implication check.
from reconstruct import implied_by, reconstruct
# Import removal rules, the capture loader, and the result-level summary.
from scorecard import ABLATIONS, load, strongest_related


# Run the separate strict SCM contract on the supplied records.
def strict_summary(records: list[dict]) -> dict:
    # The strict engine evaluates these records independently of the general engine.
    result = correlate(records)
    # Keep the status and counts from the strict result.
    return {"status": result["status"], "counts": result["counts"],
            # Keep all observations but cap gap entries at 50 for this snapshot.
            "observations": result["observations"], "gaps": result["gaps"][:50]}


# Collect source-record references from nested results into a shared set.
def referenced(value, found: set[str]) -> None:
    # Dictionaries may hold references directly or contain nested results.
    if isinstance(value, dict):
        # Examine each field name and its value.
        for key, child in value.items():
            # A string under "ref" names one original source line.
            if key == "ref" and isinstance(child, str):
                # Add the reference; a set automatically removes duplicates.
                found.add(child)
            # These named fields contain lists of source-line references.
            elif key in {"refs", "artifact_refs", "alias_refs"} and isinstance(child, list):
                # Add only string entries from this list.
                found.update(r for r in child if isinstance(r, str))
            # Search other values for deeper reference fields.
            else:
                # Recursively search this child value.
                referenced(child, found)
    # Lists can hold findings, observations, and other nested values.
    elif isinstance(value, list):
        # Visit each item in the list.
        for child in value:
            # Recursively search this child value.
            referenced(child, found)


# Package one cited event for the browser record viewer.
def record_payload(record: dict, original_line: bytes) -> dict:
    # Check the source bytes against the hash recorded when loading this event.
    if sha256(original_line) != record["_sha256"]:
        # Stop rather than display an event with mismatched source bytes.
        raise ValueError(f"Original line hash does not match {record['_ref']}")
    # Keep JSON as TEXT. JavaScript must not round large Windows integers.
    # Start with evidence metadata; stringify record numbers to avoid JS rounding.
    return {**evidence(record), "record_number": str(record["RecordNumber"]) if record.get("RecordNumber") is not None else None,
            # Include the original line hash for verification.
            "sha256": record["_sha256"],
            # Store formatted JSON as text, excluding internal underscore-prefixed fields.
            "json": json.dumps(raw(record), indent=2, ensure_ascii=False),
            # Preserve the original source line, including its line ending.
            "raw_line": original_line.decode("utf-8"),
            # Supply simple field values as strings for display tables.
            "fields": {k: str(v) for k, v in raw(record).items()
                       # Exclude nested objects and lists here; they remain in the JSON text.
                       if isinstance(v, (str, int, float, bool)) or v is None}}


# Build all baseline and removal results before the browser opens the page.
def export() -> dict:
    # Verify bundled source files against their pinned SHA-256 hashes.
    sources = verify_sources(ROOT)
    # Reuse the scorecard if engine hashes match, or recompute it when needed.
    score = cached_scorecard()
    # Collect the browser-ready recording objects here.
    rows = []
    # Process each bundled capture in turn.
    for row in score["rows"]:
        # Load all parsed, deduplicated events and the capture integrity metadata.
        records, integrity = load(row["archive"])
        # Check that the loaded capture matches the scorecard input.
        if integrity != row["integrity"]:
            # Refuse to mix an old baseline with different capture contents.
            raise ValueError(f"Stale scorecard for {row['archive']}; run python3 demo.py")
        # The scorecard already contains the general engine result for the full capture.
        original = row["result"]
        # Create the full-data baseline: zero removed events and its summary level.
        variants = {"baseline": {"removed": 0, "level": row["level"],
                                 # Keep the general baseline and independently run the strict SCM engine.
                                 "result": original, "strict": strict_summary(records)}}
        # Each rule has a name and a function that returns True for events to remove.
        # Example: "Sysmon 3 connection" matches Sysmon network-connection events.
        for name, drop in ABLATIONS.items():
            # Start from the FULL capture for every rule; removals are not cumulative.
            # Keep each event only when the selected removal rule does NOT match it.
            kept = [r for r in records if not drop(r)]
            # Count withheld parsed events; the original records and ZIP stay intact.
            removed = len(records) - len(kept)
            # Zero means this event type was absent from the capture.
            if not removed:
                # Mark the experiment unavailable; the browser disables this option.
                variants[name] = {"removed": 0, "not_present": True}
                # Skip computation for this absent event type and move to the next rule.
                continue
            # Rerun the general engine on retained events; the engine decides the level.
            # There is no hard-coded "Remove Sysmon 3 => SESSION" assignment here.
            result = reconstruct(kept)
            # Save the removed count and a related-claim summary for the experiment matrix.
            variants[name] = {"removed": removed, "level": strongest_related(result, original),
                              # Keep the full general result and rerun the strict engine on the SAME input.
                              "result": result, "strict": strict_summary(kept),
                              # Check that every surviving claim is supported by baseline at equal or greater strength.
                              # This records a check result; it never modifies the computed findings.
                              "monotonic": all(implied_by(f, original["findings"])
                                               # Check each new finding; all() also returns True when no finding survives.
                                               for f in result["findings"])}
        # Collect a union of cited references across the baseline and ALL variants.
        refs = set()
        # Search both general and strict results for references.
        referenced(variants, refs)
        # Map source references to events from the original full capture.
        lookup = {r["_ref"]: r for r in records}
        # Open the original capture archive to recover exact source-line bytes.
        with zipfile.ZipFile(ROOT / "data/source" / f"{row['archive']}.zip") as bundle:
            # Read referenced members and preserve line endings for hash verification.
            lines = {n: bundle.read(n).splitlines(keepends=True)
                     # Use a set so each referenced ZIP member is read only once.
                     for n in {lookup[ref]["_file"] for ref in refs if ref in lookup}}
        # Package each cited event using its original line; subtract 1 for list indexing.
        record_lookup = {ref: record_payload(lookup[ref], lines[lookup[ref]["_file"]][lookup[ref]["_line"] - 1])
                         # Sort references for stable output and skip any absent from the original input.
                         for ref in sorted(refs) if ref in lookup}
        # Find this archive in the source manifest, including its upstream URL.
        archive_source = next(s for s in sources if s["local_path"] == f"data/source/{row['archive']}.zip")
        # Keep scorecard fields and attach all variants and their shared record lookup.
        rows.append({**row, "variants": variants, "record_lookup": record_lookup,
                     # Attach the verified source manifest entry to this recording.
                     "source": archive_source})
        # Show progress immediately as each recording finishes.
        print(f"Exported {row['title']}: {len(record_lookup)} referenced records", flush=True)
    # Return the browser data format version and hashes identifying the Python engines.
    return {"schema_version": 1, "engine_sha256": code_hashes(),
            # Include totals, removal-rule names for the selector, and all recording objects.
            "summary": score["summary"], "ablations": score["ablations"], "rows": rows,
            # Identify the upstream dataset repository and publisher.
            "repository": "OTRF/Security-Datasets", "publisher": "Roberto Rodriguez / OTRF",
            # Include the pinned upstream revision from the source manifest.
            "revision": sources[0]["revision"],
            # State that the inputs are controlled exercise recordings.
            "data_kind": "Recorded, controlled attack-emulation exercises; not production telemetry.",
            # Carry the evaluation limits into the dashboard.
            "evaluation_limit": "Category checks only. Sessions and endpoints have not been independently labelled. No false-positive-rate or accuracy claim."}


# Convert the exported data into a JavaScript assignment, not detection code.
def data_script(payload: dict) -> str:
    # Encode compact JSON, retaining readable Unicode where safe.
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Safe when this same script is embedded in the standalone HTML.
    # Expose the payload to the UI and escape characters unsafe in inline scripts.
    return "window.EVIDENCE_DATA=" + encoded.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029") + ";\n"


# Bundle HTML, CSS, data, and UI code into one double-clickable offline file.
def standalone(web: Path, output: Path) -> None:
    # Read the HTML template.
    html = (web / "dashboard.html").read_text()
    # Find the external stylesheet link in the template.
    html = html.replace('<link rel="stylesheet" href="dashboard.css">',
                        # Replace it with the stylesheet contents inside an inline style element.
                        "<style>" + (web / "dashboard.css").read_text() + "</style>")
    # Embed the generated data first, then the UI code that reads it.
    for name in ["dashboard-data.js", "dashboard.js"]:
        # Read each script and prevent its text from closing the HTML script element.
        script = (web / name).read_text().replace("</script", "<\\/script")
        # Replace the external script tag with the script contents.
        html = html.replace(f'<script src="{name}"></script>', "<script>" + script + "</script>")
    # Save the self-contained offline dashboard.
    output.write_text(html)


# Command-line entry point for generating the hosted data and offline page.
def main() -> None:
    # Use the module description as the command help text.
    parser = argparse.ArgumentParser(description=__doc__)
    # Accept a custom output path, defaulting to dashboard-offline.html.
    parser.add_argument("--standalone", type=Path, default=ROOT / "dashboard-offline.html")
    # Read the command-line options.
    args = parser.parse_args()
    # Compute all variants, encode them, and write the browser data file.
    (ROOT / "web/dashboard-data.js").write_text(data_script(export()))
    # Build the offline page from the same data and current UI files.
    standalone(ROOT / "web", args.standalone)
    # Show the offline file location.
    print(f"Standalone dashboard: {args.standalone}")


# Run main only for direct execution, not when another module imports this file.
if __name__ == "__main__":
    # Start the export command.
    main()
