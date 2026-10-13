"""Tests for the generalized engine, grounded in the original recorded records.

Each mutation changes one real field in memory and checks that the claim gets
weaker, never stronger. Source files are never modified.
"""
import copy
import unittest

from analyze import correlate
from reconstruct import LEVELS, implied_by, reconstruct
from scorecard import CATALOG, load, outcome, run


def records_of(archive):
    return load(archive)[0]


def changed(records, match, **fields):
    rows = copy.deepcopy(records)
    hits = [r for r in rows if all(str(r.get(k)) == str(v) for k, v in match.items())]
    assert hits, f"fixture record not found: {match}"
    for r in hits:
        r.update(fields)
    return reconstruct(rows)


def only(result, technique):
    return [f for f in result["findings"] if f["technique"] == technique]


class Attribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.score = run()

    def test_scorecard_headline(self):
        s = self.score["summary"]
        self.assertEqual((s["recordings"], s["expected_observed"], s["additional_categories"], s["not_observed"]),
                         (14, 13, 0, 1))
        self.assertEqual(s["ablation_runs"], s["ablation_monotonic"])

    def test_the_only_miss_is_the_documented_one(self):
        misses = [r["archive"] for r in self.score["rows"] if r["outcome"] != "OBSERVED"]
        self.assertEqual(misses, ["empire_dcom_shellwindows_stager"])
        self.assertTrue(self.score["rows"][-1]["known_limit"])

    def test_query_start_stop_never_become_installs(self):
        for r in self.score["rows"]:
            if r["expected"] == "SERVICE_CONTROL_ACCESS":
                self.assertNotIn("SERVICE_INSTALL", r["result"]["remote_techniques"], r["title"])

    def test_outcome_rules(self):
        self.assertEqual(outcome("SERVICE_CONTROL_ACCESS", ["SERVICE_INSTALL"]), "ADDITIONAL")
        self.assertEqual(outcome("SERVICE_INSTALL", ["SERVICE_CONTROL_ACCESS", "SERVICE_INSTALL"]), "OBSERVED")
        self.assertEqual(outcome("WMI_EXECUTION", []), "NOT_OBSERVED")

    def test_engine_never_sees_the_label(self):
        # Same records, renamed file: identical findings.
        rows = records_of("empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod")
        renamed = copy.deepcopy(rows)
        for r in renamed:
            r["_file"] = "unnamed.json"
            r["_ref"] = r["_ref"].replace(rows[0]["_file"], "unnamed.json")
        a, b = reconstruct(rows), reconstruct(renamed)
        self.assertEqual(a["remote_techniques"], b["remote_techniques"])


class AgreesWithDeepDive(unittest.TestCase):
    def test_service_sessions_match_the_strict_contract(self):
        for archive in ["covenant_sharpsc_create_dcerpc_smb_svcctl", "covenant_sharpsc_query_dcerpc_smb_svcctl"]:
            rows = records_of(archive)
            strict = {(o["identity"]["logon_id"], o["status"]) for o in correlate(rows)["observations"]}
            general = {(f["logon_id"], {"SERVICE_INSTALL": "REMOTE_SERVICE_INSTALLATION",
                                        "SERVICE_CONTROL_ACCESS": "REMOTE_SERVICE_ACCESS"}[f["technique"]])
                       for f in reconstruct(rows)["findings"]}
            self.assertEqual(strict, general, archive)


class Mutations(unittest.TestCase):
    def test_wmi_mechanism_comes_from_the_parent_process(self):
        rows = records_of("covenant_sharpwmi_create_dcerpc_wmi")
        wmi = only(reconstruct(rows), "WMI_EXECUTION")[0]
        self.assertEqual((wmi["level"], wmi["logon_id"]), ("ROUTE", "0xc93745"))
        result = changed(rows, {"EventID": 1, "LogonId": "0xc93745", "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
                         ParentImage="C:\\Windows\\explorer.exe")
        self.assertFalse(only(result, "WMI_EXECUTION"))
        self.assertTrue(only(result, "REMOTE_PROCESS"))  # still in the session, mechanism now unknown

    def test_psexec_install_needs_the_same_account_sid(self):
        rows = records_of("empire_psexec_dcerpc_tcp_svcctl")
        result = changed(rows, {"EventID": 4697}, SubjectUserSid="S-1-5-21-1-2-3-999")
        self.assertEqual([f["level"] for f in only(result, "SERVICE_INSTALL")], ["ARTIFACT"])

    def test_task_created_too_late_is_not_joined(self):
        rows = records_of("schtask_create")
        self.assertEqual(only(reconstruct(rows), "TASK_CREATE")[0]["level"], "ROUTE")
        result = changed(rows, {"EventID": 4698}, TimeCreated="2020-12-19T07:10:22.264Z")
        self.assertEqual([f["level"] for f in only(result, "TASK_CREATE")], ["ARTIFACT"])

    def test_winrm_reports_its_missing_source_instead_of_guessing(self):
        f = only(reconstruct(records_of("empire_psremoting_stager")), "WINRM_SESSION")[0]
        self.assertEqual(f["level"], "SESSION")
        self.assertIsNone(f["route"])
        self.assertIn("no usable source address", f["route_gap"])
        self.assertIn("whoami.exe", f["follow_on"])

    def test_one_sided_flow_drops_route_to_session(self):
        rows = records_of("empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod")
        port = only(reconstruct(rows), "WMI_EXECUTION")[0]["route"]["source_port"]
        result = changed(rows, {"EventID": 3, "Initiated": "true", "SourcePort": port}, SourcePort="1")
        self.assertEqual(only(result, "WMI_EXECUTION")[0]["level"], "SESSION")

    def test_reused_logon_id_is_refused(self):
        rows = records_of("empire_smbexec_dcerpc_smb_svcctl")
        logon = copy.deepcopy(next(r for r in rows if str(r.get("EventID")) == "4624"
                                   and r.get("TargetUserName") == "pgustavo"))
        # A second logon reusing the logon ID (different record number, so not a
        # duplicate export): the engine must refuse to choose between them.
        logon.update(TargetUserSid="S-1-5-21-1-2-3-4242", RecordNumber=999999999,
                     _ref="conflict:L1", _line=1, _file="conflict", _sha256="0" * 64)
        result = reconstruct(rows + [logon])
        self.assertFalse([f for f in result["findings"] if LEVELS[f["level"]] >= LEVELS["SESSION"]])
        self.assertTrue(result["gaps"])


class AblationProperty(unittest.TestCase):
    def test_implied_by_rejects_a_stronger_or_different_claim(self):
        route = {"source_host": "WS5", "source_ip": "10.0.0.5", "source_port": 50000,
                 "target_host": "WS6", "target_ip": "10.0.0.6", "target_port": 445}
        base = {"target_host": "T", "logon_id": "0x1", "technique": "SERVICE_CONTROL_ACCESS", "level": "SESSION",
                "route": None, "principal": {"sid": "S-1-5-21-1-2-3-1104", "domain": "d", "account": "a"},
                "artifact_refs": ["f:L1"]}
        stronger = dict(base, technique="SERVICE_INSTALL", level="ROUTE", route=route, artifact_refs=["f:L1", "f:L2"])
        self.assertTrue(implied_by(base, [stronger]))
        self.assertFalse(implied_by(dict(base, technique="SERVICE_INSTALL"), [base]))
        self.assertFalse(implied_by(dict(base, level="ROUTE", route=route), [base]))
        self.assertFalse(implied_by(dict(base, logon_id="0x2"), [base]))
        # Same place and technique, but a different account, artifact or route: not the same claim.
        self.assertFalse(implied_by(dict(base, principal=dict(base["principal"], sid="S-1-5-21-1-2-3-9999")), [stronger]))
        self.assertFalse(implied_by(dict(base, artifact_refs=["f:L9"]), [stronger]))
        self.assertFalse(implied_by(dict(base, level="ROUTE", route=dict(route, source_host="WS9")), [stronger]))
        # The route is the whole connection: a different source port is a different connection.
        self.assertFalse(implied_by(dict(base, level="ROUTE", route=dict(route, source_port=50001)), [stronger]))
        self.assertFalse(implied_by(dict(base, level="ROUTE", route=dict(route, source_ip="10.0.0.9")), [stronger]))

    def test_every_catalog_entry_is_ablated(self):
        self.assertEqual(len(CATALOG), 14)


if __name__ == "__main__":
    unittest.main(verbosity=2)
