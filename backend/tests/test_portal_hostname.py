"""IP and DNS portal boundaries, using only in-process HTTP and loopback TLS."""
import base64
import hashlib
import http.client
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

try:
    from starlette.testclient import TestClient
    from dazzle.portal import CSRF, SESSION, HostCertificate, create_app, reload_tls, select_certificate
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


IP_ORIGIN = "https://203.0.113.10:9443"
HOSTNAME = "portal.example.test"
DNS_ORIGIN = "https://" + HOSTNAME + ":9443"
TOKEN = "subscription-fixture-" + "a" * 32


class BoundaryClient:
    def __init__(self):
        self.calls = []

    def call(self, operation, params, peer_ip):
        self.calls.append((operation, params, peer_ip))
        if operation == "auth.request_code":
            data = {"challenge_id": "hostname-fixture"}
        elif operation == "auth.verify":
            data = {"session_token": "s" * 43, "expires_at": "2026-12-01T00:00:00Z"}
        elif operation == "session.me":
            data = {"account": {"id": "self", "status": "pending"}}
        elif operation == "registration.status":
            data = {"enabled": True, "full": False, "accepting": True}
        elif operation == "subscription.fetch":
            data = {"status": 200, "headers": {}, "body_b64": base64.b64encode(b"fixture nodes\n").decode()}
        else:
            raise AssertionError(operation)
        return {"ok": True, "data": data}


@unittest.skipUnless(AVAILABLE, "Install portal and portal-test extras")
class PortalHostnameHTTPTests(unittest.TestCase):
    def setUp(self):
        self.backend = BoundaryClient()
        self.app = create_app(origin=[IP_ORIGIN, DNS_ORIGIN], client=self.backend)

    def client(self, origin):
        client = TestClient(self.app, base_url=origin)
        self.addCleanup(client.close)
        return client

    def test_ip_and_dns_origins_each_keep_pages_login_and_original_subscriptions_working(self):
        for origin in (IP_ORIGIN, DNS_ORIGIN):
            with self.subTest(origin=origin):
                browser = self.client(origin)
                page = browser.get("/portal/")
                self.assertEqual(page.status_code, 200)
                cookie = page.headers["set-cookie"]
                self.assertNotIn("domain=", cookie.lower())
                self.assertIn("Secure", cookie)
                self.assertIn("SameSite=lax", cookie)
                headers = {"Origin": origin, "X-CSRF-Token": browser.cookies[CSRF]}
                self.assertEqual(browser.post("/portal/api/request-code", json={"email": "fixture@example.test"}, headers=headers).status_code, 200)
                self.assertEqual(browser.post("/portal/api/verify", json={"challenge_id": "hostname-fixture", "code": "123456"}, headers=headers).status_code, 200)
                self.assertIn(SESSION, browser.cookies)
                self.assertEqual(browser.get("/portal/api/me").status_code, 200)
                response = browser.get("/" + TOKEN + "/nodes.txt")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, b"fixture nodes\n")

    def test_unknown_host_blocks_pages_status_subscription_and_post_before_ipc(self):
        browser = self.client(DNS_ORIGIN)
        browser.get("/portal/")
        csrf = browser.cookies[CSRF]
        for hostile in ("outside.example.test", HOSTNAME + ".outside.example.test", "outside-" + HOSTNAME):
            for path in ("/portal/", "/portal/api/status", "/" + TOKEN + "/nodes.txt"):
                with self.subTest(host=hostile, path=path):
                    self.assertEqual(browser.get(path, headers={"Host": hostile + ":9443"}).status_code, 400)
            response = browser.post("/portal/api/request-code", json={"email": "fixture@example.test"},
                                    headers={"Host": hostile + ":9443", "Origin": DNS_ORIGIN, "X-CSRF-Token": csrf})
            self.assertEqual(response.status_code, 400)
        self.assertFalse(self.backend.calls)

    def test_post_requires_explicit_approved_https_origin_including_9443_port(self):
        for origin in (IP_ORIGIN, DNS_ORIGIN):
            browser = self.client(origin)
            browser.get("/portal/")
            csrf = browser.cookies[CSRF]
            rejected = (None, "null", origin.replace(":9443", ""), origin.replace(":9443", ":443"),
                        origin.replace(":9443", ":9444"), origin.replace("https:", "http:"),
                        "https://outside.example.test:9443", DNS_ORIGIN + ".outside.example.test",
                        origin + "/portal/", origin + "/")
            for supplied_origin in rejected:
                with self.subTest(host=origin, origin=supplied_origin):
                    headers = {"X-CSRF-Token": csrf}
                    if supplied_origin is not None:
                        headers["Origin"] = supplied_origin
                    response = browser.post("/portal/api/request-code", json={"email": "fixture@example.test"}, headers=headers)
                    self.assertEqual(response.status_code, 403)
            self.assertFalse(self.backend.calls)
            self.assertEqual(browser.post("/portal/api/request-code", json={"email": "fixture@example.test"},
                                          headers={"Origin": origin, "X-CSRF-Token": csrf}).status_code, 200)
            self.backend.calls.clear()

    def test_correct_hostname_origin_does_not_bypass_missing_malformed_or_mismatched_csrf(self):
        browser = self.client(DNS_ORIGIN)
        browser.get("/portal/")
        csrf = browser.cookies[CSRF]
        for supplied in (None, "", "short", "x" * 43, csrf + "!"):
            with self.subTest(csrf=supplied):
                headers = {"Origin": DNS_ORIGIN}
                if supplied is not None:
                    headers["X-CSRF-Token"] = supplied
                response = browser.post("/portal/api/request-code", json={"email": "fixture@example.test"}, headers=headers)
                self.assertEqual(response.status_code, 403)
        browser.cookies.clear()
        response = browser.post("/portal/api/request-code", json={"email": "fixture@example.test"},
                                headers={"Origin": DNS_ORIGIN, "X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.backend.calls)

    def test_new_hostname_does_not_share_ip_session_or_csrf_cookie(self):
        browser = self.client(IP_ORIGIN)
        browser.get("/portal/")
        ip_csrf = browser.cookies[CSRF]
        self.assertEqual(browser.post("/portal/api/verify", json={"challenge_id": "hostname-fixture", "code": "123456"},
                                      headers={"Origin": IP_ORIGIN, "X-CSRF-Token": ip_csrf}).status_code, 200)
        self.backend.calls.clear()
        self.assertEqual(browser.get(DNS_ORIGIN + "/portal/api/me").status_code, 401)
        self.assertEqual(browser.post(DNS_ORIGIN + "/portal/api/request-code", json={"email": "fixture@example.test"},
                                      headers={"Origin": DNS_ORIGIN, "X-CSRF-Token": ip_csrf}).status_code, 403)
        self.assertFalse(self.backend.calls)
        browser.get(DNS_ORIGIN + "/portal/")
        dns_csrf = next(cookie.value for cookie in browser.cookies.jar if cookie.name == CSRF and cookie.domain == HOSTNAME)
        self.assertNotEqual(ip_csrf, dns_csrf)
        self.assertEqual(browser.post(DNS_ORIGIN + "/portal/api/request-code", json={"email": "fixture@example.test"},
                                      headers={"Origin": DNS_ORIGIN, "X-CSRF-Token": dns_csrf}).status_code, 200)


def certificate(folder, name, serial, *, ip=False):
    cert, key = Path(folder) / (name + ".pem"), Path(folder) / (name + "-key.pem")
    identity = "127.0.0.1" if ip else HOSTNAME
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=" + identity, "-addext", "subjectAltName=" + ("IP:" if ip else "DNS:") + identity,
                    "-set_serial", str(serial)], capture_output=True, check=True, timeout=10)
    return cert, key


def der(certificate_path):
    return ssl.PEM_cert_to_DER_cert(Path(certificate_path).read_text())


@unittest.skipUnless(AVAILABLE and shutil.which("openssl"), "Portal extras and OpenSSL required")
class PortalHostnameTLSTests(unittest.TestCase):
    def test_hostname_pair_unavailable_or_incomplete_rotation_keeps_last_valid_context(self):
        with tempfile.TemporaryDirectory() as folder:
            host_cert, host_key = Path(folder) / "host-cert.pem", Path(folder) / "host-key.pem"
            entry = HostCertificate(host_cert, host_key)
            original_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            connection = type("Connection", (), {"context": original_context})()
            choose = select_certificate({HOSTNAME: entry})
            choose(connection, HOSTNAME, original_context)
            self.assertIs(connection.context, original_context)
            cert_a, key_a = certificate(folder, "dns-a", 201)
            host_cert.write_bytes(cert_a.read_bytes()); host_key.write_bytes(key_a.read_bytes())
            entry.reload()
            self.assertIsNotNone(entry.fingerprint)
            fingerprint = entry.fingerprint
            choose(connection, HOSTNAME.upper() + ".", original_context)
            self.assertIs(connection.context, entry.context)
            cert_b, key_b = certificate(folder, "dns-b", 202)
            host_cert.write_bytes(cert_b.read_bytes())
            entry.reload()
            self.assertEqual(entry.fingerprint, fingerprint)
            host_key.write_bytes(key_b.read_bytes())
            entry.reload()
            self.assertNotEqual(entry.fingerprint, fingerprint)
            for unrecognized in (None, "127.0.0.1", "outside.example.test", HOSTNAME + ".outside.example.test"):
                connection.context = original_context
                choose(connection, unrecognized, original_context)
                self.assertIs(connection.context, original_context)

    def test_real_cli_selects_independent_dns_certificate_and_reloads_without_restart(self):
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 9443))
        except OSError:
            self.skipTest("Local isolated test port 9443 is occupied")
        finally:
            probe.close()
        with tempfile.TemporaryDirectory() as folder:
            ip_cert, ip_key = certificate(folder, "ip", 301, ip=True)
            cert_a, key_a = certificate(folder, "dns-a", 302)
            cert_b, key_b = certificate(folder, "dns-b", 303)
            host_cert, host_key = Path(folder) / "host-cert.pem", Path(folder) / "host-key.pem"
            host_cert.write_bytes(cert_a.read_bytes()); host_key.write_bytes(key_a.read_bytes())
            ip_digests = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (ip_cert, ip_key)]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).parents[1])
            env["DAZZLE_PORTAL_HOSTNAME"] = HOSTNAME
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            child = subprocess.Popen([sys.executable, "-B", "-m", "dazzle.portal", "--host", "127.0.0.1", "--port", "9443",
                                      "--origin", "https://127.0.0.1:9443", "--cert", str(ip_cert), "--key", str(ip_key)],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 7
                while True:
                    if child.poll() is not None:
                        self.fail("Isolated hostname portal exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", 9443), timeout=0.5):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("Isolated hostname portal did not become ready")
                        time.sleep(0.02)

                def fetch(server_name, trusted_certificate=None):
                    context = ssl.create_default_context(cafile=str(trusted_certificate)) if trusted_certificate else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    if trusted_certificate is None:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection(("127.0.0.1", 9443), timeout=3) as raw:
                        with context.wrap_socket(raw, server_hostname=server_name) as connection:
                            peer = connection.getpeercert(binary_form=True)
                            name = server_name or "127.0.0.1"
                            connection.sendall(("GET /portal/ HTTP/1.1\r\nHost: " + name + ":9443\r\nConnection: close\r\n\r\n").encode())
                            response = http.client.HTTPResponse(connection)
                            response.begin(); response.read()
                            return peer, response.status

                self.assertEqual(fetch(None), (der(ip_cert), 200))
                self.assertEqual(fetch("127.0.0.1", ip_cert), (der(ip_cert), 200))
                self.assertEqual(fetch(HOSTNAME, cert_a), (der(cert_a), 200))
                unknown_peer, unknown_status = fetch("outside.example.test")
                self.assertEqual(unknown_peer, der(ip_cert))
                self.assertEqual(unknown_status, 400)
                pid = child.pid
                host_cert.write_bytes(cert_b.read_bytes()); host_key.write_bytes(key_b.read_bytes())
                # Exercise the actual lifespan watcher with its production 15 s
                # interval. No signal, manual reload or process replacement.
                deadline = time.monotonic() + 20
                while True:
                    self.assertIsNone(child.poll(), "The portal restarted or exited while rotating the DNS pair")
                    actual, status = fetch(HOSTNAME)
                    self.assertEqual(status, 200)
                    if actual == der(cert_b):
                        break
                    self.assertEqual(actual, der(cert_a))
                    if time.monotonic() >= deadline:
                        self.fail("The live TLS watcher did not load the renewed DNS certificate")
                    time.sleep(0.2)
                self.assertEqual(child.pid, pid)
                self.assertEqual(fetch(HOSTNAME, cert_b), (der(cert_b), 200))
                self.assertEqual(fetch(None), (der(ip_cert), 200))
                self.assertEqual(fetch("127.0.0.1", ip_cert), (der(ip_cert), 200))
                self.assertEqual([hashlib.sha256(path.read_bytes()).hexdigest() for path in (ip_cert, ip_key)], ip_digests)
            finally:
                child.terminate()
                try:
                    child.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill(); child.communicate(timeout=4)


if __name__ == "__main__":
    unittest.main()
