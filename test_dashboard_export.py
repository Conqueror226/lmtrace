"""The hosted snapshot must carry the same claims and original bytes as Python."""
import hashlib
import io
import json
from pathlib import Path
import unittest
import zipfile

from dashboard import ROOT, UploadError, code_hashes, read_upload
from reconstruct import implied_by


class ExportedEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snapshot = ROOT / "web/dashboard-data.js"
        if not snapshot.is_file():
            from build_dashboard import data_script, export
            snapshot.write_text(data_script(export()))
        script = snapshot.read_text()
        cls.data = json.loads(script.removeprefix("window.EVIDENCE_DATA=").rstrip(";\n"))

    def test_snapshot_is_from_current_engines(self):
        self.assertEqual(self.data["engine_sha256"], code_hashes())
        self.assertEqual(self.data["summary"]["records"], 81140)

    def test_every_embedded_source_line_retains_its_original_hash(self):
        count = 0
        for row in self.data["rows"]:
            for record in row["record_lookup"].values():
                self.assertEqual(hashlib.sha256(record["raw_line"].encode()).hexdigest(), record["sha256"])
                self.assertEqual(json.loads(record["raw_line"]), json.loads(record["json"]))
                count += 1
        self.assertGreater(count, 1000)

    def test_removals_keep_the_actual_technique_and_attribution_distinct(self):
        row = self.data["rows"][0]
        variants = row["variants"]
        self.assertEqual(variants["4624 network logon"]["level"], "ARTIFACT")
        self.assertEqual(variants["Sysmon 3 connection"]["level"], "SESSION")
        # The general installation contract does not require svcctl; the strict one does.
        self.assertIn("SERVICE_INSTALL", variants["5145 share access"]["result"]["remote_techniques"])
        self.assertEqual(variants["5145 share access"]["strict"]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertNotIn("SERVICE_INSTALL", variants["4697 service install"]["result"]["remote_techniques"])
        self.assertIn("SERVICE_CONTROL_ACCESS", variants["4697 service install"]["result"]["remote_techniques"])

    def test_all_57_variants_preserve_baseline_claim_boundaries(self):
        count = 0
        for row in self.data["rows"]:
            for name, variant in row["variants"].items():
                if name == "baseline" or not variant["removed"]:
                    continue
                count += 1
                self.assertTrue(all(implied_by(f, row["result"]["findings"])
                                    for f in variant["result"]["findings"]), (row["title"], name))
                for f in variant["result"]["findings"]:
                    self.assertTrue(set(f["artifact_refs"]) <= row["record_lookup"].keys())
                    self.assertTrue(set(f["alias_refs"]) <= row["record_lookup"].keys())
        self.assertEqual(count, 57)

    def test_shellwindows_gap_is_visible_without_fabricated_evidence(self):
        row = self.data["rows"][-1]
        self.assertEqual(row["level"], "NONE")
        self.assertEqual(row["record_lookup"], {})
        self.assertIn("explorer.exe", row["known_limit"])


class UploadReferences(unittest.TestCase):
    def bundle(self, names):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            for i, name in enumerate(names):
                z.writestr(name, json.dumps({"EventID": 4697, "RecordNumber": 9223372036854775807-i}) + "\n")
        return out.getvalue()

    def test_directory_names_prevent_colliding_line_references(self):
        records, _ = read_upload("capture.zip", self.bundle(["a/events.json", "b/events.json"]))
        self.assertEqual({r["_ref"] for r in records}, {"a/events.json:L1", "b/events.json:L1"})
        for record in records:
            self.assertEqual(hashlib.sha256(record["_original_line"]).hexdigest(), record["_sha256"])

    def test_duplicate_member_names_are_refused(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            body = self.bundle(["events.json", "events.json"])
        with self.assertRaisesRegex(UploadError, "duplicate event-file names"):
            read_upload("capture.zip", body)


if __name__ == "__main__":
    unittest.main()
