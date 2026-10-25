"""Public HTTP boundary tests: no network, SMTP, SSH or production data."""
import base64
import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

try:
    from starlette.testclient import TestClient
    from dazzle.portal import create_app, CSRF, SESSION, normalized_origin, reload_tls, DeadlineH11Protocol
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

ORIGIN = "https://203.0.113.10:9443"
TOKEN = "a" * 43
SESSION_VALUE = "b" * 43


class FakeClient:
    def __init__(self):
        self.calls = []
        self.active = False
        self.fail = False

    def call(self, operation, params, peer_ip):
        self.calls.append((operation, params, peer_ip))
        if self.fail:
            raise RuntimeError("private fixture must not be exposed")
        if operation == "auth.request_code":
            data = {"challenge_id": "challenge-fixture"}
        elif operation == "auth.verify":
            data = {"session_token": SESSION_VALUE, "expires_at": "2026-12-01T00:00:00Z"}
        elif operation == "session.me":
            data = {"account": {"id": "self", "email": "person@example.com", "nickname": "<script>fixture</script>", "status": "active" if self.active else "pending", "proxy_user_id": "self" if self.active else None,
                    "quota_bytes": 100_000_000_000, "used_upload": 0, "used_download": 0},
                    "subscriptions": {"clash": ORIGIN + "/" + TOKEN + "/config.yaml", "shadowrocket": ORIGIN + "/" + TOKEN + "/nodes.txt"}}
        elif operation == "session.logout":
            data = {"logged_out": True}
        elif operation == "subscription.fetch":
            status = 404 if params["token"] != TOKEN else 200 if self.active else 403
            data = {"status": status, "headers": {"Subscription-Userinfo": "upload=0; download=0; total=100000000000", "Set-Cookie": "untrusted=1"},
                    "body_b64": base64.b64encode(b'proxies: []\n' if status == 200 else b'').decode()}
        else:
            raise AssertionError(operation)
        return {"ok": True, "data": data}


@unittest.skipUnless(AVAILABLE, "Install portal and portal-test extras")
class PortalWebTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeClient()
        self.client = TestClient(create_app(origin=ORIGIN, client=self.backend), base_url=ORIGIN)
        self.client.get("/portal/")

    def post(self, action, data, **kwargs):
        headers = {"Origin": ORIGIN, "X-CSRF-Token": self.client.cookies[CSRF]}
        headers.update(kwargs.pop("headers", {}))
        return self.client.post("/portal/api/" + action, json=data, headers=headers, **kwargs)

    def login(self):
        return self.post("verify", {"challenge_id": "fixture", "code": "123456"})

    def test_static_has_security_headers_and_no_third_party_assets(self):
        response = self.client.get("/portal/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertNotIn("https://", response.text)
        for name in ("app.css", "app.js"):
            self.assertEqual(self.client.get("/portal/assets/" + name).status_code, 200)
        self.assertEqual(self.client.get("/portal/assets/other.js").status_code, 404)

    def test_cross_origin_and_missing_csrf_rejected_before_ipc(self):
        self.assertEqual(self.post("request-code", {"email": "person@example.com"}, headers={"Origin": "https://outside.example"}).status_code, 403)
        self.assertEqual(self.client.post("/portal/api/request-code", json={"email": "person@example.com"}).status_code, 403)
        self.assertFalse(self.backend.calls)

    def test_host_spoofing_rejected(self):
        self.assertEqual(self.client.get("/portal/", headers={"Host": "outside.example"}).status_code, 400)

    def test_request_code_has_no_management_fields_or_forwarded_ip(self):
        self.assertEqual(self.post("request-code", {"email": "person@example.com", "role": "admin"}).status_code, 400)
        self.assertFalse(self.backend.calls)
        response = self.post("request-code", {"email": "person@example.com", "nickname": "Private"}, headers={"X-Forwarded-For": "192.0.2.9"})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(self.backend.calls[-1][2], "192.0.2.9")

    def test_honeypot_and_oversized_body_do_not_reach_agent(self):
        self.assertEqual(self.post("request-code", {"email": "person@example.com", "website": "bot"}).status_code, 429)
        self.assertEqual(self.post("request-code", {"email": "a" * 9000}).status_code, 413)
        self.assertFalse(self.backend.calls)

    def test_wrong_content_type_rejected(self):
        r = self.client.post("/portal/api/request-code", content="{}", headers={"Origin": ORIGIN, "X-CSRF-Token": self.client.cookies[CSRF], "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 415)

    def test_session_cookie_is_secret_not_in_response_body(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_VALUE, response.text)
        cookie = response.headers["set-cookie"]
        for part in ("Secure", "HttpOnly", "SameSite=lax", "Path=/portal", "Max-Age=604800"):
            self.assertIn(part, cookie)

    def test_own_me_requires_session_and_contains_only_own_account(self):
        self.assertEqual(self.client.get("/portal/api/me").status_code, 401)
        self.login()
        data = self.client.get("/portal/api/me").json()["data"]
        self.assertEqual(data["account"]["id"], "self")
        self.assertEqual(data["subscriptions"]["clash"], ORIGIN + "/" + TOKEN + "/config.yaml")
        self.assertNotIn("users", data)

    def test_same_subscription_path_pending_then_active(self):
        for route in ("config.yaml", "nodes.txt", "config.conf"):
            path = "/" + TOKEN + "/" + route
            response = self.client.get(path)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.content, b"")
            self.backend.active = True
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("set-cookie", response.headers)
            self.backend.active = False
        self.assertTrue(all(call[0] == "subscription.fetch" for call in self.backend.calls))

    def test_unknown_and_invalid_subscription_paths(self):
        self.assertEqual(self.client.get("/" + "c" * 43 + "/config.yaml").status_code, 404)
        self.assertEqual(self.client.get("/short/config.yaml").status_code, 404)
        self.assertEqual(self.client.get("/" + TOKEN + "/anything").status_code, 404)

    def test_subscription_limiter_rejects_before_agent_work(self):
        for _ in range(100):
            self.assertEqual(self.client.get("/" + TOKEN + "/config.yaml").status_code, 403)
        self.assertEqual(self.client.get("/" + TOKEN + "/config.yaml").status_code, 429)
        self.assertEqual(len(self.backend.calls), 100)

    def test_no_public_approval_or_rpc(self):
        for path in ("/portal/api/approve", "/portal/api/user.enable", "/portal/api/snapshot", "/rpc"):
            self.assertIn(self.client.post(path, json={}).status_code, (404, 405))
        self.assertFalse(self.backend.calls)

    def test_qr_requires_own_session_and_is_local_svg(self):
        self.assertEqual(self.client.get("/portal/qr/clash").status_code, 401)
        self.login()
        response = self.client.get("/portal/qr/clash")
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/svg+xml", response.headers["content-type"])
        self.assertNotIn(b"<script", response.content)
        self.assertEqual(self.client.get("/portal/qr/other").status_code, 404)

    def test_logout_clears_cookie_and_get_cannot_logout(self):
        self.login()
        self.assertEqual(self.client.get("/portal/api/logout").status_code, 405)
        response = self.post("logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Max-Age=0", response.headers["set-cookie"])
        self.assertEqual(self.client.get("/portal/api/me").status_code, 401)

    def test_agent_failure_has_no_sensitive_error_text(self):
        self.backend.fail = True
        response = self.post("request-code", {"email": "person@example.com"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private fixture", response.text)

    def test_subscription_only_rollback_retains_subscriptions(self):
        client = TestClient(create_app(origin=ORIGIN, client=self.backend, portal_enabled=False), base_url=ORIGIN)
        for path in ("/portal/", "/portal/assets/app.js", "/portal/api/me", "/portal/qr/clash"):
            self.assertEqual(client.get(path).status_code, 404)
        self.assertEqual(client.get("/" + TOKEN + "/config.yaml").status_code, 403)

    def test_origin_configuration_rejects_credentials_and_other_schemes(self):
        for value in ("http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?query=1"):
            with self.assertRaises(ValueError):
                normalized_origin(value)

    def test_invalid_tls_pair_never_replaces_live_context(self):
        class Context:
            called = False
            def load_cert_chain(self, *args):
                self.called = True
        context = Context()
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert", Path(directory) / "key"
            cert.write_text("invalid"); key.write_text("invalid")
            self.assertEqual(reload_tls(context, cert, key, b"previous"), b"previous")
            self.assertFalse(context.called)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for loopback TLS test")
    def test_tls_rotation_changes_actual_peer_certificate_in_same_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        def peer_certificate():
            listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(3)
            port = listener.getsockname()[1]
            def serve():
                try:
                    connection, _ = listener.accept()
                    with context.wrap_socket(connection, server_side=True) as tls:
                        tls.sendall(b"ok")
                finally:
                    listener.close()
            thread = threading.Thread(target=serve, daemon=True); thread.start()
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False; client_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with client_context.wrap_socket(raw, server_hostname="localhost") as tls:
                    result = tls.getpeercert(binary_form=True); self.assertEqual(tls.recv(2), b"ok")
            thread.join(3); self.assertFalse(thread.is_alive())
            return result
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            def generate(serial):
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                                "-days", "1", "-subj", "/CN=localhost", "-set_serial", str(serial)], capture_output=True, check=True)
            generate(101); first = reload_tls(context, cert, key); certificate_a = peer_certificate()
            generate(102); second = reload_tls(context, cert, key, first); certificate_b = peer_certificate()
            self.assertNotEqual(first, second); self.assertNotEqual(certificate_a, certificate_b)
            key.write_text("incomplete rotation")
            self.assertEqual(reload_tls(context, cert, key, second), second)
            self.assertEqual(peer_certificate(), certificate_b)


@unittest.skipUnless(AVAILABLE, "Install portal and portal-test extras")
class SlowRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_headers_and_bodies_have_a_protocol_deadline(self):
        import uvicorn
        from uvicorn.server import ServerState
        async def handler(scope, receive, send):
            while (await receive()).get("more_body", False):
                pass
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        class ShortDeadline(DeadlineH11Protocol):
            header_timeout = 0.08
            request_timeout = 0.12
        config = uvicorn.Config(handler, lifespan="off", access_log=False, log_level="critical")
        config.load(); state = ServerState(); loop = asyncio.get_running_loop()
        server = await loop.create_server(lambda: ShortDeadline(config, state, {}), "127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            for partial in (b"GET / HTTP/1.1\r\nHo", b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{"):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(partial); await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
                writer.close(); await writer.wait_closed()
        finally:
            server.close(); await server.wait_closed()

    async def test_body_deadline_returns_408_and_closes_without_ipc(self):
        backend = FakeClient(); app = create_app(origin=ORIGIN, client=backend)
        csrf = "c" * 43
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "https",
                 "path": "/portal/api/request-code", "raw_path": b"/portal/api/request-code", "query_string": b"", "root_path": "",
                 "headers": [(b"host", b"203.0.113.10:9443"), (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                             (b"cookie", (CSRF + "=" + csrf).encode()), (b"x-csrf-token", csrf.encode())],
                 "client": ("192.0.2.2", 40000), "server": ("203.0.113.10", 9443)}
        first = True; messages = []
        async def receive():
            nonlocal first
            if first:
                first = False
                return {"type": "http.request", "body": b"{", "more_body": True}
            await asyncio.sleep(60)
        async def send(message):
            messages.append(message)
        await asyncio.wait_for(app(scope, receive, send), 7)
        start = next(message for message in messages if message["type"] == "http.response.start")
        self.assertEqual(start["status"], 408)
        self.assertIn((b"connection", b"close"), start["headers"])
        self.assertFalse(backend.calls)


class FrontendSessionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node required for isolated frontend logic test")
    def test_logout_fences_late_responses_and_clears_sensitive_dom(self):
        result = subprocess.run(["node", str(Path(__file__).with_name("portal_browser_state.js")),
                                 str(Path(__file__).parents[1] / "dazzle/portal_static/app.js")], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(AVAILABLE and shutil.which("openssl"), "Portal extras and OpenSSL required")
class PortalTransportTests(unittest.TestCase):
    def test_real_https_cli_and_incomplete_tls_handshake_deadline(self):
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 9443))
        except OSError:
            self.skipTest("Local isolated test port 9443 is occupied")
        finally:
            probe.close()
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                            "-days", "1", "-subj", "/CN=localhost"], capture_output=True, check=True)
            env = os.environ.copy(); env["PYTHONPATH"] = str(Path(__file__).parents[1])
            child = subprocess.Popen([sys.executable, "-m", "dazzle.portal", "--host", "127.0.0.1", "--port", "9443",
                                      "--origin", "https://127.0.0.1:9443", "--cert", str(cert), "--key", str(key)],
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        raw = socket.create_connection(("127.0.0.1", 9443), timeout=1)
                        break
                    except OSError:
                        if child.poll() is not None or time.monotonic() > deadline:
                            self.fail("Isolated HTTPS process did not become ready")
                        time.sleep(0.02)
                raw.close()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(("127.0.0.1", 9443), timeout=3) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as connection:
                        connection.sendall(b"GET /portal/ HTTP/1.0\r\nHost: 127.0.0.1:9443\r\n\r\n")
                        self.assertIn(b"200 OK", connection.recv(65536))
                started = time.monotonic()
                with socket.create_connection(("127.0.0.1", 9443), timeout=8) as raw:
                    self.assertEqual(raw.recv(1), b"")
                self.assertLess(time.monotonic() - started, 7.5)
            finally:
                child.terminate()
                try:
                    child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill(); child.communicate(timeout=3)
