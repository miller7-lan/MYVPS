"""Read-only QQG client: two fixed requests, no secrets in any output."""
import base64
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest

from dazzle import qqg

TOKEN = "T0kenValue1234567890abcdefABCDEF"
USER = "owner@example.com"
GIB = 1024 ** 3


def jwt(expires):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return part({"alg": "HS256"}) + "." + part({"exp": expires, "info": {"id": 7}}) + "." + "c2lnbmF0dXJl"


def flow(used="6.64GB", total="500GB", leave="493.36GB", reset="2026-11-24", **extra):
    return 200, {"status": 200, "msg": "ok", "data": {"total": total, "used": used, "leave": leave,
                                                      "reset_flow_date": reset, **extra}}


class Clock:
    def __init__(self, value=1_800_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, host, path, headers, body=None):
        self.calls.append((method, host, path, dict(headers), body))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, payload = item
        return status, payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()


def login(expires=1_800_007_200):
    return 200, {"status": 200, "msg": "ok", "data": {"jwt": jwt(expires)}}


class QqgClientTests(unittest.TestCase):
    def client(self, responses, clock=None):
        self.transport = FakeTransport(responses)
        self.clock = clock or Clock()
        creds = qqg.credentials("https://www.qqg.net/", USER, TOKEN, 4920)
        return qqg.QqgClient(creds, transport=self.transport, clock=self.clock)

    def test_reads_the_card_with_exactly_two_fixed_requests(self):
        client = self.client([login(), flow()])
        reading = client.read_flow()
        self.assertEqual([(call[0], call[1], call[2]) for call in self.transport.calls],
                         [("POST", "www.qqg.net", "/api/v1/auth"), ("GET", "www.qqg.net", "/console/v1/mf_cloud/4920/flow")])
        self.assertIn(b"username=owner%40example.com", self.transport.calls[0][4])
        self.assertIn(b"password=" + TOKEN.encode(), self.transport.calls[0][4])
        self.assertEqual(self.transport.calls[1][3]["Authorization"], "Bearer " + jwt(1_800_007_200))
        self.assertNotIn("Authorization", self.transport.calls[0][3])
        self.assertEqual(reading.total_bytes, 500 * GIB)
        self.assertEqual(reading.remaining_bytes + reading.used_bytes, reading.total_bytes)
        self.assertEqual((reading.remaining_display, reading.reset_date), ("493.36GB", "2026-11-24"))

    def test_jwt_is_reused_until_shortly_before_expiry(self):
        client = self.client([login(), flow(), flow(), login(1_800_020_000), flow()])
        client.read_flow()
        client.read_flow()
        self.assertEqual(client.logins, 1)
        self.clock.value = 1_800_007_200 - qqg.JWT_REFRESH_MARGIN
        client.read_flow()
        self.assertEqual(client.logins, 2)
        self.assertGreater(client.token_valid_seconds, 7000)

    def test_a_rejected_token_logs_in_once_more_then_fails_closed(self):
        client = self.client([login(), (200, {"status": 401, "msg": "未登录"}), login(), flow()])
        self.assertEqual(client.read_flow().used_display, "6.64GB")
        self.assertEqual(client.logins, 2)
        client = self.client([login(), (200, {"status": 401}), login(), (200, {"status": 401})])
        with self.assertRaises(qqg.QqgError) as caught:
            client.read_flow()
        self.assertEqual(caught.exception.code, "UNAUTHORIZED")

    def test_redirects_http_errors_and_foreign_bodies_are_refused(self):
        cases = [((302, b""), "REDIRECT_REFUSED"), ((429, b""), "RATE_LIMITED"), ((503, b"busy"), "HTTP_STATUS"),
                 ((200, b"<html>challenge</html>"), "BAD_RESPONSE"),
                 ((200, b"{" + b" " * qqg.MAX_RESPONSE_BYTES + b"}"), "BAD_RESPONSE"),
                 ((200, {"msg": "no status"}), "BAD_RESPONSE")]
        for response, code in cases:
            with self.subTest(code=code, status=response[0]):
                client = self.client([response])
                with self.assertRaises(qqg.QqgError) as caught:
                    client.read_flow()
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(len(self.transport.calls), 1)

    def test_network_failures_map_to_fixed_codes(self):
        for error, code in ((ssl.SSLError("bad cert"), "TLS"), (TimeoutError(), "TIMEOUT"),
                            (ConnectionRefusedError(), "NETWORK")):
            with self.subTest(code=code):
                with self.assertRaises(qqg.QqgError) as caught:
                    self.client([error]).read_flow()
                self.assertEqual(caught.exception.code, code)

    def test_no_secret_reaches_an_error_or_repr(self):
        echo = (200, {"status": 400, "msg": f"鉴权失败 {USER} {TOKEN} " + "x" * 40})
        client = self.client([echo])
        with self.assertRaises(qqg.QqgError) as caught:
            client.read_flow()
        self.assertEqual(caught.exception.code, "AUTH_FAILED")
        leaked = str(caught.exception) + caught.exception.message + repr(client) + repr(client._creds)
        for secret in (USER, TOKEN):
            self.assertNotIn(secret, leaked)
        client = self.client([login(), (200, {"status": 400, "msg": "无权限 " + jwt(1_800_007_200)})])
        with self.assertRaises(qqg.QqgError) as caught:
            client.read_flow()
        self.assertEqual(caught.exception.code, "FLOW_FAILED")
        self.assertNotIn(jwt(1_800_007_200), str(caught.exception))

    def test_only_the_two_requests_can_be_sent(self):
        client = self.client([])
        for method, path in (("GET", "/console/v1/host"), ("POST", "/console/v1/mf_cloud/4920/reboot"),
                             ("GET", "/console/v1/mf_cloud/4921/flow")):
            with self.subTest(path=path):
                with self.assertRaises(qqg.QqgError) as caught:
                    client._call(method, path)
                self.assertEqual(caught.exception.code, "NOT_ALLOWED")
        self.assertEqual(self.transport.calls, [])

    def test_api_url_must_be_the_qqg_site_origin(self):
        self.assertEqual(qqg.normalize_api_url("https://WWW.QQG.NET/"), "https://www.qqg.net")
        self.assertEqual(qqg.normalize_api_url("https://qqg.net"), "https://qqg.net")
        for value in ("http://www.qqg.net", "https://www.qqg.net.evil.example", "https://evilqqg.net",
                      "https://www.qqg.net/api", "https://user:pw@www.qqg.net", "https://www.qqg.net:8443",
                      "https://www.qqg.net/?x=1", "", None):
            with self.subTest(value=value):
                with self.assertRaises(qqg.QqgError):
                    qqg.normalize_api_url(value)

    def test_flow_parsing_follows_the_module_units(self):
        reading = qqg.parse_flow({"total": "1TB", "used": "512MB", "leave": "1023.50GB"}, 1)
        self.assertEqual((reading.total_bytes, reading.used_bytes), (1024 * GIB, 512 * 1024 ** 2))
        self.assertIsNone(reading.reset_date)
        unlimited = qqg.parse_flow({"total": "不限", "used": "3.2GB", "leave": "不限", "reset_flow_date": "bad-date!"}, 1)
        self.assertTrue(unlimited.unlimited)
        self.assertEqual((unlimited.total_bytes, unlimited.remaining_bytes, unlimited.reset_date), (None, None, None))
        refined = qqg.parse_flow({"total": "500GB", "used": "6.64GB", "leave": "493.36GB", "used_num": 6.6412}, 1)
        self.assertEqual(refined.used_bytes, round(6.6412 * GIB))
        foreign = qqg.parse_flow({"total": "500GB", "used": "6.64GB", "leave": "493.36GB", "used_num": 7_129_645_711}, 1)
        self.assertEqual(foreign.used_bytes, round(6.64 * GIB))
        computed = qqg.parse_flow({"total": "500GB", "used": "100GB"}, 1)
        self.assertEqual(computed.remaining_bytes, 400 * GIB)
        for data in ({"total": "500GB", "leave": "1GB"}, {"total": "500GB", "used": "1GB", "leave": "600GB"},
                     {"total": "-5GB", "used": "1GB"}, {"total": "500GB", "used": "1,0GB"}, None):
            with self.subTest(data=data):
                with self.assertRaises(qqg.QqgError):
                    qqg.parse_flow(data, 1)


class CredentialFileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def write(self, name, content, mode=0o600):
        path = self.root / name
        path.write_text(content if isinstance(content, str) else json.dumps(content, ensure_ascii=False))
        os.chmod(path, mode)
        return path

    def test_template_placeholders_and_wide_permissions_are_refused(self):
        template = {"_说明": "fill in", "version": 1, "api_url": "https://www.qqg.net",
                    "username": "PASTE_QQG_LOGIN_EMAIL_OR_PHONE", "token": "PASTE_QQG_API_TOKEN", "host_id": 4920}
        with self.assertRaises(qqg.QqgError) as caught:
            qqg.load_credentials(self.write("a.json", template))
        self.assertEqual(caught.exception.code, "CONFIG_INCOMPLETE")
        complete = {**template, "username": USER, "token": TOKEN, "private_key": "never used"}
        with self.assertRaises(qqg.QqgError) as caught:
            qqg.load_credentials(self.write("b.json", complete, 0o644))
        self.assertEqual(caught.exception.code, "CONFIG_INSECURE")
        creds, ignored = qqg.load_credentials(self.write("c.json", complete))
        self.assertEqual((creds.host, creds.host_id, ignored), ("www.qqg.net", 4920, ["private_key"]))
        self.assertNotIn(TOKEN, repr(creds))
        self.assertNotIn(USER, repr(creds))

    def test_token_file_overrides_json_and_rejects_the_private_key(self):
        template = {"version": 1, "username": USER, "token": "PASTE_QQG_API_TOKEN", "host_id": 4920}
        creds, _ = qqg.load_credentials(self.write("d.json", template), self.write("token.txt", TOKEN + "\n"))
        self.assertEqual(creds.token, TOKEN)
        body = "\n".join(["MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQ" + "A" * 14] * 49 + ["QUJDREVGR0hJSktMTU5PUFFSU1Q="])
        for content in (body, "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"):
            with self.subTest(header="BEGIN" in content):
                with self.assertRaises(qqg.QqgError) as caught:
                    qqg.read_token_file(self.write("key.txt", content))
                self.assertEqual(caught.exception.code, "TOKEN_FILE_IS_PRIVATE_KEY")
        with self.assertRaises(qqg.QqgError) as caught:
            qqg.read_token_file(self.write("two.txt", TOKEN + "\n" + TOKEN))
        self.assertEqual(caught.exception.code, "CONFIG_INVALID")

    def test_probe_prints_only_the_traffic_card(self):
        path = self.write("e.json", {"version": 1, "username": USER, "token": TOKEN, "host_id": 4920})
        result = qqg.probe(path, transport=FakeTransport([login(), flow()]))
        text = json.dumps(result, ensure_ascii=False)
        for secret in (USER, TOKEN, jwt(1_800_007_200)):
            self.assertNotIn(secret, text)
        self.assertEqual((result["remaining"], result["reset_flow_date"], result["host_id"]), ("493.36GB", "2026-11-24", 4920))


if __name__ == "__main__":
    unittest.main()
