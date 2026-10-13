"""The local dashboard: routes, upload analysis, and its safety guards."""
import http.client
import io
import json
import threading
import unittest
import zipfile

from dashboard import MAX_UPLOAD_BYTES, ROOT, make_server

CREATE_ZIP = ROOT / "data/source/covenant_sharpsc_create_dcerpc_smb_svcctl.zip"


class Dashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)  # any free port, 127.0.0.1 only
        cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response, data

    def test_binds_to_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_page_is_served_with_a_strict_policy(self):
        response, body = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Analyze a capture", body)
        csp = response.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)

    def test_overview_matches_the_scorecard(self):
        response, body = self.request("GET", "/api/overview")
        data = json.loads(body)
        self.assertEqual(response.status, 200)
        self.assertEqual((data["summary"]["recordings"], data["summary"]["expected_observed"]), (14, 13))

    def test_record_lookup_returns_the_original_line(self):
        _, body = self.request("GET", "/api/overview")
        row = json.loads(body)["rows"][0]
        ref = row["result"]["findings"][0]["evidence"][0]["ref"]
        response, body = self.request("GET", f"/api/record?source={row['archive']}&ref={ref}")
        self.assertEqual(response.status, 200)
        self.assertIn("EventID", json.loads(body)["json"])

    def test_uploaded_zip_is_analyzed_by_both_engines(self):
        response, body = self.request("POST", "/api/analyze", CREATE_ZIP.read_bytes(),
                                      {"X-Filename": CREATE_ZIP.name, "Origin": f"http://127.0.0.1:{self.port}"})
        data = json.loads(body)
        self.assertEqual(response.status, 200, data)
        self.assertIn("SERVICE_INSTALL", data["result"]["remote_techniques"])
        self.assertEqual(data["strict"]["status"], "REMOTE_SERVICE_INSTALLATION")
        ref = data["result"]["findings"][0]["evidence"][0]["ref"]
        response, _ = self.request("GET", f"/api/record?source=upload&ref={ref}")
        self.assertEqual(response.status, 200)

    def test_bad_input_gets_a_clear_message(self):
        response, body = self.request("POST", "/api/analyze", b"not json\n", {"X-Filename": "x.json"})
        self.assertEqual(response.status, 400)
        self.assertIn("No JSON records", json.loads(body)["error"])

    def test_oversized_upload_is_refused_before_reading(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.putrequest("POST", "/api/analyze", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("Content-Length", str(MAX_UPLOAD_BYTES + 1))
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 413)
        conn.close()

    def test_zip_without_event_files_is_refused(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            bundle.writestr("readme.txt", "hello")
        response, body = self.request("POST", "/api/analyze", buffer.getvalue(), {"X-Filename": "x.zip"})
        self.assertEqual(response.status, 400)
        self.assertIn("contains no .json", json.loads(body)["error"])

    def test_foreign_origin_and_host_are_refused(self):
        response, _ = self.request("POST", "/api/analyze", b"{}", {"Origin": "https://evil.example"})
        self.assertEqual(response.status, 403)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("GET", "/api/overview", headers={"Host": "attacker.example"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()

    def test_unknown_paths_and_sources_are_not_served(self):
        for path in ["/../analyze.py", "/results/../analyze.py", "/api/record?source=../x&ref=a"]:
            response, _ = self.request("GET", path)
            self.assertEqual(response.status, 404, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
