"""Public HTTP boundary tests: no network, SMTP, SSH or production data."""
import base64
import asyncio
import json
from http.cookies import SimpleCookie
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
        self.full = False

    def call(self, operation, params, peer_ip):
        self.calls.append((operation, params, peer_ip))
        if self.fail:
            raise RuntimeError("private fixture must not be exposed")
        if operation == "registration.status":
            data = {"enabled": True, "full": self.full, "accepting": not self.full, "message": "人员已满，稍后再试" if self.full else ""}
        elif operation == "auth.request_code":
            if self.full:
                return {"ok": False, "error": {"code": "REGISTRATION_FULL"}}
            data = {"challenge_id": "challenge-fixture"}
        elif operation == "auth.verify":
            data = {"session_token": SESSION_VALUE, "expires_at": "2026-12-01T00:00:00Z"}
        elif operation == "session.me":
            data = {"account": {"id": "self", "email": "person@example.com", "nickname": "<script>fixture</script>", "status": "active" if self.active else "pending", "proxy_user_id": "self" if self.active else None,
                    "quota_bytes": 100_000_000_000, "used_upload": 0, "used_download": 0},
                    "subscriptions": {"clash": ORIGIN + "/" + TOKEN + "/config.yaml", "shadowrocket": ORIGIN + "/" + TOKEN + "/nodes.txt"}}
        elif operation == "session.resend_subscription":
            if not self.active:
                return {"ok": False, "error": {"code": "NOT_ACTIVE"}}
            data = {"queued": True, "email": "person@example.com"}
        elif operation == "session.logout":
            data = {"logged_out": True}
        elif operation == "session.subscription":
            if not self.active:
                return {"ok": False, "error": {"code": "NOT_ACTIVE"}}
            data = {"filename": "config.yaml" if params["format"] == "clash" else "nodes.txt",
                    "content": "proxies: []\n" if params["format"] == "clash" else "vless://fixture\n",
                    "node_names": ["VLESS（常用）", "TUIC v5（迅速）"]}
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

    def test_registration_status_is_a_read_only_get_and_full_seats_show_the_message(self):
        status = self.client.get("/portal/api/status")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["data"]["accepting"], True)
        self.assertEqual(self.client.post("/portal/api/status", json={}).status_code, 405)
        self.assertEqual(self.backend.calls[-1][:2], ("registration.status", {}))
        self.backend.full = True
        self.assertTrue(self.client.get("/portal/api/status").json()["data"]["full"])
        refused = self.post("request-code", {"email": "person@example.com"})
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.json()["error"], {"code": "REGISTRATION_FULL", "message": "人员已满，稍后再试"})
        page = self.client.get("/portal/").text
        script = self.client.get("/portal/assets/app.js").text
        self.assertIn('id="capacity-note"', page)
        self.assertIn("人员已满，稍后再试", script)
        self.assertIn('api("status")', script)

    def test_static_has_security_headers_and_no_third_party_assets(self):
        response = self.client.get("/portal/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        # same-origin, never no-referrer: older mobile engines derive Origin from it.
        self.assertEqual(response.headers["referrer-policy"], "same-origin")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertNotIn("https://", response.text)
        for name in ("app.css", "app.js"):
            self.assertEqual(self.client.get("/portal/assets/" + name).status_code, 200)
        self.assertEqual(self.client.get("/portal/assets/other.js").status_code, 404)

    def test_one_address_cannot_drive_unbounded_api_work_into_the_agent(self):
        for _ in range(60):
            self.assertEqual(self.client.get("/portal/api/status").status_code, 200)
        calls = len(self.backend.calls)
        for refused in (self.client.get("/portal/api/status"), self.post("request-code", {"email": "person@example.com"})):
            self.assertEqual(refused.status_code, 429)
            self.assertEqual(refused.json()["error"]["code"], "RATE_LIMITED")
        self.assertEqual(len(self.backend.calls), calls)

    def test_cross_origin_and_missing_csrf_rejected_before_ipc(self):
        self.assertEqual(self.post("request-code", {"email": "person@example.com"}, headers={"Origin": "https://outside.example"}).status_code, 403)
        self.assertEqual(self.client.post("/portal/api/request-code", json={"email": "person@example.com"}).status_code, 403)
        self.assertFalse(self.backend.calls)

    def test_signed_in_resend_is_a_csrf_protected_post_carrying_only_the_session(self):
        self.assertEqual(self.post("resend-subscription", {}).status_code, 401)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.post("resend-subscription", {}).json()["error"]["code"], "NOT_ACTIVE")
        self.backend.active = True
        reply = self.post("resend-subscription", {})
        self.assertEqual((reply.status_code, reply.json()["data"]), (200, {"queued": True, "email": "person@example.com"}))
        self.assertEqual(self.backend.calls[-1][:2], ("session.resend_subscription", {"session_token": SESSION_VALUE}))
        calls = len(self.backend.calls)
        self.assertEqual(self.post("resend-subscription", {"email": "elsewhere@example.com"}).status_code, 400)
        self.assertEqual(self.client.get("/portal/api/resend-subscription").status_code, 405)
        self.assertEqual(self.post("resend-subscription", {}, headers={"X-CSRF-Token": "d" * 43}).status_code, 403)
        self.assertEqual(len(self.backend.calls), calls)

    def test_page_named_challenge_is_passed_to_the_agent(self):
        chosen = "0b5c4f53-5a4e-4f7c-9a8e-3c4b2a1d0e9f"
        self.assertEqual(self.post("request-code", {"email": "person@example.com", "challenge_id": chosen}).status_code, 200)
        self.assertEqual(self.backend.calls[-1][1], {"email": "person@example.com", "challenge_id": chosen})

    def test_browser_can_read_csrf_cookie_and_request_verification(self):
        page = self.client.get("/portal/")
        cookies = SimpleCookie()
        cookies.load(page.headers["set-cookie"])
        csrf_cookie = cookies[CSRF]
        browser_token = "" if csrf_cookie["httponly"] else csrf_cookie.value
        response = self.client.post("/portal/api/request-code",
                                    json={"email": "person@example.com", "nickname": "Private"},
                                    headers={"Origin": ORIGIN, "X-CSRF-Token": browser_token})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(csrf_cookie["secure"])
        self.assertEqual(csrf_cookie["samesite"], "lax")
        self.assertEqual(csrf_cookie["path"], "/portal")

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
        self.assertEqual(data["delivery"], {"method": "email"})
        self.assertEqual(set(data["account"]), {"id", "email", "nickname", "status", "expires_at"})
        for private in ("subscriptions", "quota_bytes", "used_upload", "used_download", TOKEN):
            self.assertNotIn(private, json.dumps(data))
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

    def test_removed_web_qr_and_config_cannot_disclose_links_even_when_signed_in(self):
        self.assertEqual(self.client.get("/portal/qr/clash").status_code, 404)
        self.login()
        self.backend.active = True
        self.backend.calls.clear()
        for path in ("/portal/qr/clash", "/portal/qr/shadowrocket", "/portal/config/clash", "/portal/config/shadowrocket?download=1"):
            self.assertEqual(self.client.get(path).status_code, 404)
        self.assertFalse(self.backend.calls)

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
        for path in ("/portal/", "/portal/assets/app.js", "/portal/api/me", "/portal/qr/clash", "/portal/config/clash"):
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

    @unittest.skipUnless(shutil.which("node"), "Node required for isolated frontend logic test")
    def test_phone_flow_survives_a_lost_reply_and_a_reload_and_offers_resend(self):
        result = subprocess.run(["node", str(Path(__file__).with_name("portal_mobile_flow.js")),
                                 str(Path(__file__).parents[1] / "dazzle/portal_static/app.js")], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("node"), "Node required for isolated frontend logic test")
    def test_page_explains_a_closed_registration_the_identical_reply_cannot(self):
        for state in ("closed", "accepting"):
            with self.subTest(state=state):
                result = subprocess.run(["node", str(Path(__file__).with_name("portal_closed_notice.js")),
                                         str(Path(__file__).parents[1] / "dazzle/portal_static/app.js"), state],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(AVAILABLE and shutil.which("openssl"), "Portal extras and OpenSSL required")
class TLSCipherTests(unittest.TestCase):
    def handshake(self, server_ciphers, cert, key):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.minimum_version = ssl.TLSVersion.TLSv1_2
        server.set_ciphers(server_ciphers); server.load_cert_chain(cert, key)
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); client.check_hostname = False; client.verify_mode = ssl.CERT_NONE
        # A TLS 1.2-only engine that offers AEAD suites alone.
        client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_2
        client.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305")
        pipes = [ssl.MemoryBIO() for _ in range(4)]
        ends = {"server": server.wrap_bio(pipes[0], pipes[1], server_side=True), "client": client.wrap_bio(pipes[2], pipes[3])}
        done = set()
        try:
            for _ in range(20):
                for name, end in ends.items():
                    if name not in done:
                        try:
                            end.do_handshake(); done.add(name)
                        except ssl.SSLWantReadError:
                            pass
                pipes[0].write(pipes[3].read()); pipes[2].write(pipes[1].read())
                if done == set(ends):
                    return ends["client"].cipher()[0]
        except ssl.SSLError:
            return None
        return None

    def test_tls12_clients_offering_only_aead_suites_can_connect(self):
        from dazzle.portal import TLS_CIPHERS
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=203.0.113.10"],
                           check=True, capture_output=True)
            self.assertIsNone(self.handshake("TLSv1", cert, key))  # uvicorn's default list, used before.
            self.assertIn("GCM", self.handshake(TLS_CIPHERS, cert, key))


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
