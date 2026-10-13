"""Regression checks grounded in original records plus removal/conflict tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analyze import correlate, load_records, sha256, verify_sources
from demo import ROOT, run_case


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ROOT / "data/source/covenant_sharpsc_create_dcerpc_smb_svcctl_2020-08-06022635.json"
        cls.records, _ = load_records(cls.source)

    def changed(self, record_number, **fields):
        records = copy.deepcopy(self.records)
        for row in records:
            if row.get("RecordNumber") == record_number:
                row.update(fields)
        return correlate(records)

    def test_source_bytes_match_pinned_downloads(self):
        self.assertEqual(len(verify_sources(ROOT)), 29)

    def test_original_creation_trace_matches_manually_inspected_records(self):
        result = correlate(self.records)
        self.assertEqual(result["counts"]["records_analyzed"], 3390)
        installs = [r for r in result["observations"] if r["status"] == "REMOTE_SERVICE_INSTALLATION"]
        self.assertEqual(len(installs), 1)
        row = installs[0]
        self.assertEqual(row["identity"]["logon_id"], "0xba93e3")
        self.assertEqual(row["identity"]["account"], "pgustavo")
        self.assertEqual(row["identity"]["evidence"]["record_number"], 91131)
        self.assertEqual(row["pipe_evidence"]["record_number"], 91134)
        self.assertEqual(row["service"]["evidence"]["record_number"], 91138)
        self.assertEqual(row["route"]["outbound"]["record_number"], 299509)
        self.assertEqual(row["route"]["inbound"]["record_number"], 311043)
        self.assertEqual(row["route"]["source_host"], "WORKSTATION5.theshire.local")
        self.assertEqual(row["route"]["target_ip"], "172.18.39.6")
        self.assertEqual(row["authorization"], "UNKNOWN_CONTEXT")

    def test_query_capture_is_access_only_not_a_benign_label(self):
        result = run_case("query")["analysis"]
        self.assertEqual(result["counts"]["records_analyzed"], 349)
        self.assertEqual(result["status"], "REMOTE_SERVICE_ACCESS")
        self.assertEqual(result["counts"]["supported_installations"], 0)
        self.assertEqual(result["observations"][0]["identity"]["logon_id"], "0xae3a35")

    def test_removing_logons_retains_installation_without_remote_attribution(self):
        case = run_case("create", without_logons=True)
        self.assertEqual(case["experiment"]["removed_records"], 17)
        self.assertEqual(case["analysis"]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(case["analysis"]["counts"]["service_install_events"], 1)
        self.assertEqual(case["analysis"]["counts"]["supported_installations"], 0)

    def test_same_session_on_different_host_does_not_link_service(self):
        result = self.changed(91138, Hostname="DIFFERENT.theshire.local")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_account_sid_mismatch_does_not_link_service(self):
        result = self.changed(91138, SubjectUserSid="S-1-5-21-999-999-999-999")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_source_port_mismatch_breaks_the_network_link(self):
        result = self.changed(91131, IpPort="55555")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_missing_inbound_network_record_breaks_the_link(self):
        rows = [r for r in self.records if r.get("RecordNumber") != 311043]
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)

    def test_late_installation_is_not_joined(self):
        result = self.changed(91138, EventTime="2020-08-06 02:32:29")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_failed_share_check_is_not_accepted(self):
        result = self.changed(91134, EventType="AUDIT_FAILURE")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_provider_collision_is_not_accepted(self):
        result = self.changed(91138, SourceName="SomeOtherProvider")
        self.assertEqual(result["counts"]["supported_installations"], 0)

    def test_ambiguous_logon_is_not_selected_by_convenience(self):
        rows = copy.deepcopy(self.records)
        conflicting = copy.deepcopy(next(r for r in rows if r.get("RecordNumber") == 91131))
        conflicting.update(TargetUserSid="S-1-5-21-OTHER", _ref="conflict:L1", _line=1,
                           _file="conflict", _sha256="0" * 64)
        rows.append(conflicting)
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)

    def test_service_name_is_not_a_detection_signature(self):
        result = self.changed(91138, ServiceName="ExampleUpdater", ServiceFileName="C:\\Tools\\updater.exe")
        self.assertEqual(result["counts"]["supported_installations"], 1)
        self.assertEqual(result["authorization"], "UNKNOWN_CONTEXT")

    def test_original_record_hashes_and_line_references_are_exact(self):
        result = correlate(self.records)
        lines = self.source.read_bytes().splitlines(keepends=True)
        for entry in result["evidence_records"]:
            ref = entry["reference"]
            original = lines[ref["line"] - 1]
            self.assertEqual(sha256(original), ref["record_sha256"])
            self.assertEqual(json.loads(original), entry["raw"])
            self.assertEqual(json.loads(entry["raw_json"]), entry["raw"])

    def test_two_runs_reproduce_json_and_html_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            outputs = []
            for index in range(2):
                output = Path(folder) / str(index)
                subprocess.run([sys.executable, str(ROOT / "demo.py"), "--out", str(output)],
                               check=True, capture_output=True)
                outputs.append(output)
            for name in ["analysis.json", "report.html", "scorecard.json", "scorecard.html"]:
                self.assertEqual((outputs[0] / name).read_bytes(), (outputs[1] / name).read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
