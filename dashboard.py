"""LMTrace local dashboard. Run: python3 dashboard.py   (then open the printed URL)

A small web app over the same engines the reports use. Python standard library
only; it works offline and never sends data anywhere.

Views
  Overview          scorecard across the 14 bundled recordings, with the ablation matrix
  Recordings        every finding of one recording, with its evidence records
  Analyze a capture run both engines on an OTRF NDJSON or ZIP export you choose
  Deep dive         the record-by-record service-creation report

Safety choices, because a local server is still a server:
  - binds to 127.0.0.1 only;
  - rejects requests whose Host or Origin is not this server (DNS-rebinding and
    cross-site POST protection);
  - uploads are analyzed in memory, size-capped, never written to disk;
  - ZIPs are checked for member count and total uncompressed size before reading;
  - strict Content-Security-Policy on the dashboard; all text is escaped by the page.
"""
from __future__ import annotations

import argparse
import io
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import parse_qs, urlparse
import webbrowser
import zipfile

from analyze import correlate, parse_records, sha256
from reconstruct import LEVELS, LEVEL_WORDING, TECHNIQUES, reconstruct
from scorecard import CATALOG, load, run as run_scorecard

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
RESULTS = ROOT / "results"
CODE_FILES = ["analyze.py", "reconstruct.py", "scorecard.py"]
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_ZIP_MEMBERS = 50
MAX_UNCOMPRESSED_BYTES = 600 * 1024 * 1024

STATIC = {"/": ("dashboard.html", "text/html; charset=utf-8"),
          "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
          "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8")}
STRICT_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
              "connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
# The generated deep-dive report keeps its inline script; it is our own static file.
REPORT_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'self'"


class UploadError(ValueError):
    pass


# ------------------------------------------------------------------- state

class State:
    """Scorecard, per-recording record lookups and the last uploaded capture, in memory."""

    def __init__(self):
        self.lock = threading.Lock()
        self.scorecard = None
        self.records = {}      # archive name -> {ref: record}
        self.upload = None     # {"name", "records": {ref: record}, "result": ...}

    def overview(self) -> dict:
        with self.lock:
            if self.scorecard is None:
                self.scorecard = cached_scorecard()
            return self.scorecard

    def recording_records(self, archive: str) -> dict:
        with self.lock:
            if archive not in self.records:
                records, _ = load(archive)
                self.records[archive] = {r["_ref"]: r for r in records}
            return self.records[archive]


def code_hashes() -> dict:
    return {name: sha256((ROOT / name).read_bytes()) for name in CODE_FILES}


def cached_scorecard() -> dict:
    """Reuse results/scorecard.json when it was produced by this exact code; otherwise recompute."""
    path = RESULTS / "scorecard.json"
    if path.is_file():
        saved = json.loads(path.read_bytes())
        if all(saved.get("code_sha256", {}).get(k) == v for k, v in code_hashes().items()):
            return saved
    return {"code_sha256": code_hashes(), **run_scorecard()}


def raw(record: dict) -> dict:
    return {k: v for k, v in record.items() if not k.startswith("_")}


# ------------------------------------------------------------------ uploads

def read_upload(name: str, body: bytes) -> tuple[list[dict], dict]:
    """Parse an NDJSON export, or the .json/.jsonl members of a ZIP, without touching disk."""
    if not body:
        raise UploadError("The file is empty.")
    members = []
    if body[:4] == b"PK\x03\x04":
        try:
            bundle = zipfile.ZipFile(io.BytesIO(body))
        except zipfile.BadZipFile as error:
            raise UploadError("The ZIP archive could not be read.") from error
        infos = [i for i in bundle.infolist() if not i.is_dir()]
        if len(infos) > MAX_ZIP_MEMBERS:
            raise UploadError(f"The ZIP has {len(infos)} files; the limit is {MAX_ZIP_MEMBERS}.")
        wanted = [i for i in infos if i.filename.lower().endswith((".json", ".jsonl", ".ndjson"))]
        if not wanted:
            raise UploadError("The ZIP contains no .json, .jsonl or .ndjson file.")
        if sum(i.file_size for i in wanted) > MAX_UNCOMPRESSED_BYTES:
            raise UploadError("The ZIP expands beyond the 600 MB limit.")
        for info in wanted:
            members.append((Path(info.filename).name, bundle.read(info)))
    else:
        members.append((Path(name).name or "upload.json", body))
    records, integrity = [], {"files": [], "issues": {}}
    for filename, data in members:
        rows, info = parse_records(data, filename)
        records += rows
        integrity["files"].append({"name": filename, "sha256": info["input_sha256"],
                                   "lines": info["input_lines"], "records": info["unique_records"]})
        for key, count in info["issues"].items():
            integrity["issues"][key] = integrity["issues"].get(key, 0) + count
    if not records:
        raise UploadError("No JSON records were found. Expected one Windows event per line (OTRF NDJSON).")
    return records, integrity


def analyze_upload(name: str, body: bytes) -> tuple[dict, dict]:
    """Run both engines on an uploaded capture; return (response payload, records by ref)."""
    records, integrity = read_upload(name, body)
    general = reconstruct(records)
    strict = correlate(records)
    return {"name": Path(name).name, "integrity": integrity, "records": len(records),
            "result": general,
            "strict": {"status": strict["status"], "counts": strict["counts"],
                       "observations": [{"logon_id": o["identity"]["logon_id"], "status": o["status"],
                                         "checks": o["checks"]} for o in strict["observations"]],
                       "gaps": strict["gaps"][:50]}}, {r["_ref"]: r for r in records}


# ------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    server_version = "LMTrace/1.0"
    state: State = None  # set in serve()

    def log_message(self, fmt, *args):  # keep the terminal readable during a demo
        pass

    # -- guards
    def allowed_origin(self) -> bool:
        expected = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.headers.get("Host") not in expected:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin.split("://", 1)[-1] in expected

    def send(self, status: int, body: bytes, content_type: str, csp: str = STRICT_CSP):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def json(self, status: int, payload) -> None:
        self.send(status, json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
                  "application/json; charset=utf-8")

    def error(self, status: int, message: str) -> None:
        self.json(status, {"error": message})

    # -- routes
    def do_GET(self):
        if not self.allowed_origin():
            return self.error(HTTPStatus.FORBIDDEN, "Requests must come from this dashboard.")
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path in STATIC:
            name, content_type = STATIC[url.path]
            return self.send(HTTPStatus.OK, (WEB / name).read_bytes(), content_type)
        if url.path == "/deep-dive":
            report = RESULTS / "report.html"
            if not report.is_file():
                return self.error(HTTPStatus.NOT_FOUND, "Run python3 demo.py once to generate the deep-dive report.")
            return self.send(HTTPStatus.OK, report.read_bytes(), "text/html; charset=utf-8", REPORT_CSP)
        if url.path == "/api/overview":
            data = self.state.overview()
            return self.json(HTTPStatus.OK, {**data, "level_wording": LEVEL_WORDING, "level_rank": LEVELS,
                                             "technique_names": TECHNIQUES})
        if url.path == "/api/record":
            return self.record(query)
        return self.error(HTTPStatus.NOT_FOUND, "Not found.")

    def record(self, query: dict):
        source, ref = query.get("source", ""), query.get("ref", "")
        if source == "upload":
            lookup = (self.state.upload or {}).get("records", {})
        elif source in {a for a, *_ in CATALOG}:
            lookup = self.state.recording_records(source)
        else:
            return self.error(HTTPStatus.NOT_FOUND, "Unknown source.")
        record = lookup.get(ref)
        if record is None:
            return self.error(HTTPStatus.NOT_FOUND, "No record with that reference in this source.")
        return self.json(HTTPStatus.OK, {"ref": ref, "sha256": record["_sha256"],
                                         "json": json.dumps(raw(record), indent=2, ensure_ascii=False)})

    def do_POST(self):
        if not self.allowed_origin():
            return self.error(HTTPStatus.FORBIDDEN, "Requests must come from this dashboard.")
        if urlparse(self.path).path != "/api/analyze":
            return self.error(HTTPStatus.NOT_FOUND, "Not found.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.error(HTTPStatus.BAD_REQUEST, "Missing file length.")
        if length > MAX_UPLOAD_BYTES:
            return self.error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Files up to 100 MB can be analyzed.")
        body = self.rfile.read(length)
        name = self.headers.get("X-Filename", "upload.json")[:200]
        try:
            payload, records = analyze_upload(name, body)
        except UploadError as error:
            return self.error(HTTPStatus.BAD_REQUEST, str(error))
        with self.state.lock:
            self.state.upload = {"name": payload["name"], "records": records}
        return self.json(HTTPStatus.OK, payload)


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    Handler.state = State()
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local evidence dashboard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    server = make_server(args.port)
    url = f"http://127.0.0.1:{server.server_port}/"
    print("Preparing the scorecard (a few seconds the first time)...")
    Handler.state.overview()
    print(f"Dashboard: {url}   (Ctrl+C to stop; nothing leaves this computer)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
