import base64
import datetime as dt
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

import server


def counter(rx=100, tx=200, year=2026, month=10):
    return {"interfaces": [{"name": "ens17", "traffic": {"month": [{
        "date": {"year": year, "month": month}, "rx": rx, "tx": tx}]}}]}


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "usage.json"
        self.clock = 100
        self.date = dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc)
        self.payload = counter()
        self.calls = 0
        def run(*args, **kwargs):
            self.calls += 1
            self.assertEqual(kwargs["timeout"], 3)
            if isinstance(self.payload, Exception):
                raise self.payload
            return types.SimpleNamespace(stdout=json.dumps(self.payload).encode())
        self.run = run
        self.usage = server.Usage("ens17", self.file, run,
                                  lambda: self.clock, lambda: self.date)

    def test_success_cache_and_persist(self):
        self.assertEqual(self.usage.get()["rx"], 100)
        self.assertEqual(self.usage.get()["tx"], 200)
        self.assertEqual(self.calls, 1)
        self.assertEqual(json.loads(self.file.read_text())["tx"], 200)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)

    def test_never_decreases_in_same_month(self):
        self.usage.get()
        self.clock += 31
        self.payload = counter(90, 300)
        self.assertEqual(self.usage.get(), {"year": 2026, "month": 10, "rx": 100, "tx": 300})

    def test_failure_retains_cached_and_after_restart(self):
        expected = self.usage.get()
        self.clock += 31
        self.payload = subprocess.TimeoutExpired("vnstat", 3)
        self.assertEqual(self.usage.get(), expected)
        again = server.Usage("ens17", self.file, self.run,
                             lambda: self.clock, lambda: self.date)
        self.assertEqual(again.get(), expected)

    def test_initial_failure_does_not_invent_zero(self):
        self.payload = ValueError("malformed")
        with self.assertRaises(server.UsageUnavailable):
            self.usage.get()
        self.assertFalse(self.file.exists())

    def test_new_month_requires_fresh_reading_then_resets(self):
        self.usage.get()
        self.date = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
        self.clock += 31
        with self.assertRaises(server.UsageUnavailable):
            self.usage.get()
        self.payload = counter(1, 2, month=11)
        self.clock += 31
        self.assertEqual(self.usage.get()["rx"], 1)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "nodes.txt"
        self.source.write_text("vless://redacted\ntuic://redacted\n")
        self.token = "x" * 48
        self.routes = server.load_routes({"base64_nodes": True, "devices": [{
            "token": self.token, "files": {"nodes.txt": str(self.source)}}]})
        self.usage = types.SimpleNamespace(get=lambda: {"rx": 123, "tx": 456})
        self.http = ThreadingHTTPServer(("127.0.0.1", 0),
            server.make_handler(self.routes, self.usage, 500000000000))
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        def close():
            self.http.shutdown()
            self.http.server_close()
            self.thread.join()
        self.addCleanup(close)

    def request(self, path, method="GET"):
        connection = http.client.HTTPConnection(*self.http.server_address, timeout=3)
        connection.request(method, path)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_success_header_base64_and_no_server_fingerprint(self):
        status, headers, body = self.request(f"/{self.token}/nodes.txt")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Subscription-Userinfo"],
                         "upload=123; download=456; total=500000000000")
        self.assertEqual(base64.b64decode(body), self.source.read_bytes())
        self.assertNotIn("Server", headers)
        self.assertNotIn("expire", headers["Subscription-Userinfo"])
        self.assertEqual(headers["Cache-Control"], "private, no-store, max-age=0")

    def test_404_no_secrets_reflected_and_query_rejected(self):
        for path in ["/", f"/{self.token}/", f"/{self.token}/nodes.txt?token=private"]:
            status, headers, body = self.request(path)
            self.assertEqual(status, 404)
            self.assertEqual(body, b"Not found\n")

    def test_usage_failure_503(self):
        def fail():
            raise server.UsageUnavailable()
        self.usage.get = fail
        status, headers, body = self.request(f"/{self.token}/nodes.txt")
        self.assertEqual(status, 503)
        self.assertNotIn("Subscription-Userinfo", headers)

    def test_head_has_same_usage_but_no_body(self):
        status, headers, body = self.request(f"/{self.token}/nodes.txt", "HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertIn("Subscription-Userinfo", headers)

    def test_invalid_token_fails_closed(self):
        with self.assertRaises(ValueError):
            server.load_routes({"devices": [{"token": "short", "files": {}}]})


class RateTests(unittest.TestCase):
    def test_fixed_window_and_bounded_addresses(self):
        current = [1]
        limit = server.RateLimit(lambda: current[0])
        self.assertTrue(all(limit.allow("a") for _ in range(100)))
        self.assertFalse(limit.allow("a"))
        current[0] += 60
        self.assertTrue(limit.allow("a"))
        for number in range(5000):
            limit.allow(str(number))
        self.assertEqual(len(limit.entries), 4096)


class StatusNodeTests(unittest.TestCase):
    def setUp(self):
        # Fixture credentials deliberately artificial; no production files read.
        self.first = ("vless://fixture-id@127.0.0.1:443?encryption=none&security=reality"
                      "&flow=xtls-rprx-vision&pbk=fixture&sid=fixture#"
                      + quote("Dazzle'VPS-VLESS（常用）", safe=""))
        self.second = "tuic://fixture-id:fixture-password@127.0.0.1:443#" + quote(
            "Dazzle'VPS-TUIC5（迅速）", safe="")
        self.raw = (self.first + "\n" + self.second + "\n").encode()

    def decoded_lines(self, usage, encoded=True):
        payload = base64.b64encode(self.raw) if encoded else self.raw
        result = server.status_node_payload(payload, encoded, usage, 500000000000)
        raw = base64.b64decode(result, validate=True) if encoded else result
        return raw.decode().splitlines()

    def test_adds_working_alias_preserving_original_nodes(self):
        lines = self.decoded_lines({"rx": 1000000000, "tx": 1500000000})
        self.assertEqual(lines[:2], [self.first, self.second])
        self.assertEqual(len(lines), 3)
        self.assertEqual(urlsplit(lines[2])._replace(fragment=""),
                         urlsplit(self.first)._replace(fragment=""))
        self.assertEqual(unquote(urlsplit(lines[2]).fragment),
                         "剩余 497.50 GB / 500 GB（全设备估算）")

    def test_updates_numeric_usage_and_clamps_zero(self):
        for tx, expected in [(100000000000, "剩余 400.00 GB"),
                             (700000000000, "剩余 0.00 GB")]:
            lines = self.decoded_lines({"rx": 0, "tx": tx})
            self.assertTrue(unquote(urlsplit(lines[2]).fragment).startswith(expected))

    def test_plaintext_nodes_supported(self):
        self.assertEqual(self.decoded_lines({"rx": 0, "tx": 0}, encoded=False)[:2],
                         [self.first, self.second])

    def test_feature_affects_only_nodes_and_is_disabled_by_default(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        files = {}
        for name in ["nodes.txt", "config.conf", "clash.yaml"]:
            path = Path(temporary.name) / name
            path.write_bytes(self.raw if name == "nodes.txt" else b"unchanged fixture\n")
            files[name] = str(path)
        token = "x" * 48
        routes = server.load_routes({"base64_nodes": True, "devices": [{
            "token": token, "files": files}]})
        usage = types.SimpleNamespace(get=lambda: {"rx": 0, "tx": 0})
        def request(name, enabled):
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(
                routes, usage, 500000000000, usage_status_node=enabled))
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            try:
                client = http.client.HTTPConnection(*httpd.server_address, timeout=3)
                client.request("GET", f"/{token}/{name}")
                response = client.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
                client.close()
                return result
            finally:
                httpd.shutdown();httpd.server_close();worker.join()
        for name in ["config.conf", "clash.yaml"]:
            self.assertEqual(request(name, True), request(name, False))
        status, headers, body = request("nodes.txt", False)
        self.assertEqual(base64.b64decode(body), self.raw)
        on_status, on_headers, on_body = request("nodes.txt", True)
        self.assertEqual(on_status, status)
        self.assertEqual(on_headers["Subscription-Userinfo"], headers["Subscription-Userinfo"])
        self.assertEqual(len(base64.b64decode(on_body).decode().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
