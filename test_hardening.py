"""Incomplete or contradictory input must weaken a claim, never support it.

Each test mutates real records in memory (source files are never modified) and
checks both engines: the strict deep-dive contract (analyze.correlate) and the
generalized engine (reconstruct.reconstruct).
"""
import copy
import unittest

from analyze import correlate, load_records
from demo import ROOT
from reconstruct import LEVELS, reconstruct

SOURCE = ROOT / "data/source/covenant_sharpsc_create_dcerpc_smb_svcctl_2020-08-06022635.json"
LOGON, PIPE, INSTALL, OUTBOUND = 91131, 91134, 91138, 299509


class Hardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, _ = load_records(SOURCE)

    def rows(self):
        return copy.deepcopy(self.records)

    def edit(self, rows, numbers, **fields):
        for r in rows:
            if r.get("RecordNumber") in numbers:
                r.update(fields)
        return rows

    def remote(self, rows):
        return [f for f in reconstruct(rows)["findings"] if LEVELS[f["level"]] >= LEVELS["SESSION"]
                and f["logon_id"] == "0xba93e3"]

    # 1. Missing identifiers never match each other
    def test_blank_target_host_supports_nothing(self):
        rows = self.rows()
        for r in rows:
            if str(r.get("Hostname", "")).lower().startswith("workstation6"):
                r["Hostname"] = ""
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)
        self.assertFalse(self.remote(rows))

    def test_null_and_placeholder_sids_support_nothing(self):
        for sid in ["S-1-0-0", "-", ""]:
            rows = self.edit(self.rows(), {LOGON}, TargetUserSid=sid)
            self.edit(rows, {PIPE, INSTALL}, SubjectUserSid=sid)
            result = correlate(rows)
            self.assertEqual(result["counts"]["supported_installations"], 0, sid)
            self.assertTrue(result["quality"]["unusable_identifiers"]["by_reason"], sid)
            self.assertFalse(self.remote(rows), sid)

    def test_missing_hostname_field_is_reported_not_a_crash(self):
        rows = self.rows()
        for r in rows:
            if r.get("RecordNumber") == OUTBOUND:
                del r["Hostname"]
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)
        reconstruct(rows)  # must not raise

    # 2. Contradictory versions of one event are flagged and excluded
    def test_conflicting_install_versions_are_excluded(self):
        rows = self.rows()
        twin = copy.deepcopy(next(r for r in rows if r.get("RecordNumber") == INSTALL))
        twin.update(ServiceName="SomethingElse", _ref="conflict:L1", _line=1, _file="conflict", _sha256="0" * 64)
        rows.append(twin)
        result = correlate(rows)
        self.assertEqual(result["counts"]["supported_installations"], 0)
        self.assertEqual(result["quality"]["conflicting_event_identities"], 1)
        general = reconstruct(rows)
        self.assertNotIn("SERVICE_INSTALL", general["remote_techniques"])
        self.assertEqual(general["quality"]["conflicting_event_identities"], 1)

    def test_events_sharing_a_record_number_are_not_ordered(self):
        rows = self.edit(self.rows(), {INSTALL}, RecordNumber=PIPE, Hostname="WORKSTATION6.theshire.local")
        # Same host + channel + number as the 5145 now: a contradiction, so neither supports anything.
        self.assertEqual(correlate(rows)["counts"]["supported_installations"], 0)

    # 3. Sessions and installations are counted separately
    def test_second_install_does_not_inflate_sessions(self):
        rows = self.rows()
        extra = copy.deepcopy(next(r for r in rows if r.get("RecordNumber") == INSTALL))
        # 91142 is unused on this host; 91139 is a real, different event.
        extra.update(RecordNumber=91142, ServiceName="Second", _ref="extra:L1", _line=1,
                     _file="extra", _sha256="1" * 64)
        rows.append(extra)
        counts = correlate(rows)["counts"]
        self.assertEqual((counts["supported_sessions"], counts["supported_installations"]), (2, 2))

    # 4. Each session carries its own computed conclusion
    def test_each_session_has_its_own_checklist(self):
        result = correlate(self.rows())
        by_session = {o["identity"]["logon_id"]: o for o in result["observations"]}
        install = {c["check"]: c["result"] for c in by_session["0xba93e3"]["checks"]}
        access = {c["check"]: c["result"] for c in by_session["0xba8b3e"]["checks"]}
        self.assertEqual(install["Service installed in the same session"], "SUPPORTED")
        self.assertEqual(access["Service installed in the same session"], "NOT_OBSERVED")
        self.assertEqual(install["Organizational authorization"], "UNKNOWN")
        for check in by_session["0xba93e3"]["checks"][:4]:
            self.assertTrue(check["refs"], check["check"])

    # 6. Exports without EventType are read from Keywords, and that is reported
    def test_keywords_only_export_still_works_and_is_disclosed(self):
        rows = self.rows()
        for r in rows:
            r.pop("EventType", None)
        result = correlate(rows)
        self.assertEqual(result["counts"]["supported_installations"], 1)
        self.assertIn("Keywords", result["quality"]["success_read_from"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
