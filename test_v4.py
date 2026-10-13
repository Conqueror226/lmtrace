"""Regression tests for the v4 review findings, each starting from real records.

Every probe changes recorded data in memory only. Each test states the claim
the engine must NOT make, and what it should report instead.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from analyze import correlate, load_records, outcome, success_basis
from demo import ROOT, write
from reconstruct import implied_by, reconstruct
from scorecard import load

CREATE = ROOT / "data/source/covenant_sharpsc_create_dcerpc_smb_svcctl_2020-08-06022635.json"


def find(result, technique, logon_id=None):
    return [f for f in result["findings"] if f["technique"] == technique
            and (logon_id is None or f["logon_id"] == logon_id)]


class Endpoints(unittest.TestCase):
    def test_invalid_endpoints_never_form_a_route(self):
        rows = load("covenant_sharpwmi_create_dcerpc_wmi")[0]
        route = find(reconstruct(rows), "WMI_EXECUTION")[0]["route"]
        refs = {route["outbound"]["ref"], route["inbound"]["ref"]}
        for r in rows:
            if r["_ref"] in refs:
                r.update(DestinationIp="-", DestinationPort="0")
        wmi = find(reconstruct(rows), "WMI_EXECUTION")[0]
        self.assertEqual(wmi["level"], "SESSION")  # the session survives, the route does not
        self.assertIsNone(wmi["route"])
        self.assertIn("valid destination", wmi["route_gap"])

    def test_strict_engine_shares_the_same_flow_rules(self):
        rows, _ = load_records(CREATE)
        for r in rows:
            if r.get("RecordNumber") in (299509, 311043):
                r.update(DestinationIp="-", DestinationPort="0")
        result = correlate(rows)
        self.assertEqual(result["counts"]["supported_installations"], 0)
        self.assertTrue(any("valid destination" in g["reason"] for g in result["gaps"]))


class Identity(unittest.TestCase):
    def test_domain_disagreement_weakens_the_process_claim(self):
        rows = load("covenant_sharpwmi_create_dcerpc_wmi")[0]
        for r in rows:
            if str(r.get("EventID")) == "1" and r.get("LogonId") == "0xc93745":
                r["User"] = "OTHERDOMAIN\\pgustavo"
        result = reconstruct(rows)
        self.assertNotIn("WMI_EXECUTION", result["remote_techniques"])
        weakened = find(result, "WMI_EXECUTION")[0]
        self.assertEqual(weakened["level"], "ARTIFACT")
        self.assertIn("otherdomain", weakened["route_gap"])

    def test_netbios_and_dns_names_join_only_through_the_same_sid(self):
        wmi = find(reconstruct(load("covenant_sharpwmi_create_dcerpc_wmi")[0]), "WMI_EXECUTION")[0]
        self.assertEqual(wmi["level"], "ROUTE")
        self.assertTrue(any("validated Security-Auditing records" in n for n in wmi["notes"]))
        self.assertTrue(wmi["alias_refs"])

    def _other_domain_with_alias_record(self, **alias_fields):
        """WMI process says OTHERDOMAIN; add one Security record proposing OTHERDOMAIN for the SID."""
        rows = load("covenant_sharpwmi_create_dcerpc_wmi")[0]
        for r in rows:
            if str(r.get("EventID")) == "1" and r.get("LogonId") == "0xc93745":
                r["User"] = "OTHERDOMAIN\\pgustavo"
        logon = next(r for r in rows if str(r.get("EventID")) == "4624" and r.get("TargetLogonId") == "0xc93745")
        proposal = copy.deepcopy(logon)
        proposal.update(TargetDomainName="OTHERDOMAIN", TargetLogonId="0x1234567", RecordNumber=999999999,
                        _ref="alias:L1", _line=1, _file="alias", _sha256="2" * 64, **alias_fields)
        return find(reconstruct(rows + [proposal]), "WMI_EXECUTION")[0]

    def test_contradictory_record_cannot_teach_a_domain_alias(self):
        wmi = self._other_domain_with_alias_record(EventType="AUDIT_SUCCESS", Keywords="0x8010000000000000")
        self.assertEqual(wmi["level"], "ARTIFACT")

    def test_foreign_provider_record_cannot_teach_a_domain_alias(self):
        wmi = self._other_domain_with_alias_record(SourceName="Some-Other-Provider")
        self.assertEqual(wmi["level"], "ARTIFACT")

    def test_validated_record_can_teach_an_alias_and_is_cited(self):
        wmi = self._other_domain_with_alias_record()  # a clean, successful Security-Auditing record
        self.assertEqual(wmi["level"], "ROUTE")
        self.assertIn("alias:L1", wmi["alias_refs"])

    def test_mechanism_needs_the_system_path_not_just_the_name(self):
        rows = load("covenant_sharpwmi_create_dcerpc_wmi")[0]
        for r in rows:
            if str(r.get("EventID")) == "1" and "wmiprvse" in str(r.get("ParentImage", "")).lower():
                r["ParentImage"] = "C:\\Temp\\WmiPrvSE.exe"
        result = reconstruct(rows)
        self.assertNotIn("WMI_EXECUTION", result["remote_techniques"])
        self.assertTrue(any("not confirmed" in n for f in find(result, "REMOTE_PROCESS") for n in f["notes"]))


class Artifacts(unittest.TestCase):
    def test_installation_without_actor_is_kept_as_an_artifact(self):
        rows = load("empire_psexec_dcerpc_tcp_svcctl")[0]
        for r in rows:
            if str(r.get("EventID")) == "4697":
                r.pop("SubjectUserSid")
        install = find(reconstruct(rows), "SERVICE_INSTALL")
        self.assertEqual([f["level"] for f in install], ["ARTIFACT"])
        self.assertIn("unusable SID", install[0]["route_gap"])
        self.assertIn("remote attribution unavailable", install[0]["label"])

    def test_strict_engine_still_counts_and_shows_that_installation(self):
        rows, _ = load_records(CREATE)
        for r in rows:
            if r.get("RecordNumber") == 91138:
                r.pop("SubjectUserSid")
        result = correlate(rows)
        self.assertEqual((result["counts"]["service_install_events"],
                          result["counts"]["attributable_install_events"]), (1, 0))
        self.assertTrue(any("actor cannot be established" in g["reason"] for g in result["gaps"]))
        self.assertIn(91138, [e["raw"].get("RecordNumber") for e in result["evidence_records"]])

    def test_labels_never_claim_more_than_the_level(self):
        result = reconstruct(load("covenant_dcom_executeexcel4macro_allowed")[0])
        task = find(result, "TASK_CREATE")[0]
        self.assertEqual(task["level"], "ARTIFACT")
        self.assertNotIn("remote session", task["label"].split(":")[0])
        self.assertTrue(task["label"].endswith("observed; remote attribution unavailable"))
        dcom = find(result, "DCOM_EXECUTION")[0]
        self.assertIn("corroborated on both hosts", dcom["label"])


class Records(unittest.TestCase):
    def test_record_numbers_are_normalized_before_screening(self):
        rows, _ = load_records(CREATE)
        twin = copy.deepcopy(next(r for r in rows if r.get("RecordNumber") == 91138))
        twin.update(RecordNumber="091138", ServiceName="Other", _ref="twin:L1", _line=1, _file="twin", _sha256="0" * 64)
        rows.append(twin)
        self.assertEqual(correlate(rows)["quality"]["conflicting_event_identities"], 1)
        self.assertNotIn("SERVICE_INSTALL", reconstruct(rows)["remote_techniques"])

    def test_screening_coverage_is_reported(self):
        q = reconstruct(load("schtask_create")[0])["quality"]["screening"]
        self.assertEqual(q["records_with_record_number"], 0)
        self.assertIn("not screened", q["note"])

    def test_mixed_clock_kinds_are_a_gap_not_a_crash(self):
        rows = load("schtask_create")[0]
        for r in rows:
            if str(r.get("EventID")) == "4698":
                r["TimeCreated"] = "2020-12-19 07:00:22.264"  # zone dropped on this record only
        task = find(reconstruct(rows), "TASK_CREATE")[0]
        self.assertEqual(task["level"], "ARTIFACT")
        self.assertIn("not comparable", task["route_gap"])

    def test_contradictory_outcome_encodings_support_nothing(self):
        rows, _ = load_records(CREATE)
        for r in rows:
            if r.get("RecordNumber") == 91138:
                r["Keywords"] = "0x8010000000000000"  # failure bits, while EventType says success
        install = next(r for r in rows if r.get("RecordNumber") == 91138)
        self.assertEqual(outcome(install), "conflict")
        self.assertEqual(success_basis(rows)["outcome_conflicts"], 1)
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)


class Scope(unittest.TestCase):
    def test_removing_one_ambiguous_record_can_restore_a_claim(self):
        """Documented limit of the ablation guarantee, kept honest by a test."""
        rows = load("empire_smbexec_dcerpc_smb_svcctl")[0]
        logon = copy.deepcopy(next(r for r in rows if str(r.get("EventID")) == "4624"
                                   and r.get("TargetUserName") == "pgustavo"))
        logon.update(RecordNumber=999999999, _ref="extra:L1", _line=1, _file="extra", _sha256="1" * 64)
        ambiguous = reconstruct(rows + [logon])
        self.assertNotIn("SERVICE_INSTALL", ambiguous["remote_techniques"])
        restored = reconstruct(rows)  # one record removed again
        self.assertIn("SERVICE_INSTALL", restored["remote_techniques"])
        self.assertFalse(all(implied_by(f, ambiguous["findings"]) for f in restored["findings"]))


class Portability(unittest.TestCase):
    def test_outputs_are_lf_bytes_and_hashes_match_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            path = write(Path(folder) / "x.json", "a\nb\n")
            self.assertEqual(path.read_bytes(), b"a\nb\n")
        manifest = json.loads((ROOT / "results/run_manifest.json").read_text())
        from analyze import sha256
        for name, digest in manifest["output_sha256"].items():
            self.assertEqual(sha256((ROOT / "results" / name).read_bytes()), digest, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
