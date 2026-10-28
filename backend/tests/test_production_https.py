"""Token-only HTTP boundaries and TLS context reload, entirely local fixtures."""
import http.client
import io
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dazzle.production import DeadlineStream, RateLimit, SubscriptionServer, TLSContexts, subscription_handler


def _certificate(folder):
    cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=localhost"], capture_output=True, check=True)
    return str(cert), str(key)


def _tls(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        return context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise


def _fetch(port, path):
    """A prompt, complete request; None when the server turns the connection away."""
    try:
        with _tls(port) as connection:
            connection.sendall(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
            reply = b""
            while chunk := connection.recv(4096):
                reply += chunk
            return reply or None
    except OSError:
        return None


def _eventually(action, seconds=2):
    """A slot is released just after its connection closes, so allow that moment to pass."""
    stop = time.monotonic() + seconds
    while (result := action()) is None and time.monotonic() < stop:
        time.sleep(0.02)
    return result


def _trickle_until_closed(connections, limit):
    """Extend each unfinished request line by one byte about every 0.1 s; note when each is closed."""
    closed, stop = {}, time.monotonic() + limit
    while len(closed) < len(connections) and time.monotonic() < stop:
        for index, connection in enumerate(connections):
            if index in closed:
                continue
            try:
                connection.sendall(b"a")
                connection.settimeout(0.05)
                if connection.recv(1) == b"":
                    closed[index] = time.monotonic()
            except TimeoutError:
                pass
            except OSError:
                closed[index] = time.monotonic()
    return closed


class ProductionHTTPSTests(unittest.TestCase):
    def test_rate_limiter_has_bounded_ips_and_resets_after_window(self):
        limiter = RateLimit(limit=2, window=60, capacity=2)
        self.assertTrue(limiter.allow("192.0.2.1", now=0))
        self.assertTrue(limiter.allow("192.0.2.1", now=1))
        self.assertFalse(limiter.allow("192.0.2.1", now=2))
        self.assertTrue(limiter.allow("192.0.2.2", now=2))
        self.assertFalse(limiter.allow("192.0.2.3", now=2))
        self.assertLessEqual(len(limiter.values), 2)
        self.assertTrue(limiter.allow("192.0.2.3", now=62))

    def test_context_reload_keeps_last_valid_pair_during_mismatched_replace(self):
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            cert.write_text("fixture cert version1")
            key.write_text("fixture key version1")
            first, mismatch, renewed = Mock(), Mock(), Mock()
            mismatch.load_cert_chain.side_effect = ssl.SSLError("fixture pair mismatch")
            with patch("dazzle.production.ssl.SSLContext", side_effect=[first, mismatch, renewed]) as factory:
                cache = TLSContexts(str(cert), str(key))
                self.assertIs(cache.get(), first)
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(first.minimum_version, ssl.TLSVersion.TLSv1_2)
                cert.write_text("fixture certificate version2 changed")
                self.assertIs(cache.get(), first)
                key.write_text("fixture key version2 changed")
                self.assertIs(cache.get(), renewed)
                renewed.load_cert_chain.assert_called_once_with(str(cert), str(key))
                self.assertEqual(factory.call_count, 3)

    def test_initial_invalid_tls_pair_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(OSError):
                TLSContexts(str(Path(folder) / "missing-cert"), str(Path(folder) / "missing-key"))

    def test_server_limits_connections_and_sets_timeout_before_wrap(self):
        events = []
        raw = Mock()
        raw.settimeout.side_effect = lambda value: events.append(("timeout", value))
        context = Mock()
        context.wrap_socket.side_effect = lambda connection, **kwargs: events.append(("wrap", kwargs)) or connection
        cache = Mock()
        cache.get.return_value = context
        server = SubscriptionServer(("127.0.0.1", 0), subscription_handler({}, "/nonexistent"), cache, max_connections=2)
        self.addCleanup(server.server_close)
        with patch.object(ThreadingHTTPServer, "get_request", return_value=(raw, ("127.0.0.1", 12345))):
            server.get_request()
        self.assertEqual(events[0], ("timeout", 5))
        self.assertEqual(events[1], ("wrap", {"server_side": True, "do_handshake_on_connect": False}))
        self.assertTrue(server.slots.acquire(blocking=False))
        self.assertTrue(server.slots.acquire(blocking=False))
        self.assertFalse(server.slots.acquire(blocking=False))
        rejected = Mock()
        with patch.object(server, "shutdown_request") as close:
            server.process_request(rejected, ("127.0.0.1", 12346))
            close.assert_called_once_with(rejected)
        server.slots.release()
        server.slots.release()

    def test_deadline_stream_never_arms_a_timeout_past_its_absolute_deadline(self):
        clock = [100.0]
        class Trickle:
            def __init__(self):
                self.timeouts = []
            def settimeout(self, value):
                self.timeouts.append(round(value, 6))
            def recv_into(self, buffer):
                clock[0] += 0.4  # One byte each time, always sooner than the idle timeout.
                buffer[:1] = b"G"
                return 1
            def send(self, data):
                clock[0] += 0.4
                return 1
        connection = Trickle()
        stream = DeadlineStream(connection, 0.5, 1.0, 1.0, clock=lambda: clock[0])
        with self.assertRaises(TimeoutError):
            io.BufferedReader(stream).readline(65537)
        self.assertEqual(connection.timeouts, [0.5, 0.5, 0.2])
        connection.timeouts.clear()
        self.assertEqual(stream.write(b"ok"), 2)  # The response budget starts with its first write ...
        with self.assertRaises(TimeoutError):
            stream.write(b"more")  # ... and later writes cannot extend it.
        self.assertEqual(connection.timeouts, [0.5, 0.5, 0.2])

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for loopback TLS test")
    def test_trickled_headers_cannot_hold_slots_past_the_absolute_deadline(self):
        handler = subscription_handler({}, "/nonexistent")
        handler.idle_timeout, handler.header_timeout = 0.5, 1.5
        with tempfile.TemporaryDirectory() as folder:
            server = SubscriptionServer(("127.0.0.1", 0), handler, TLSContexts(*_certificate(folder)), max_connections=2)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            attackers = []
            try:
                port = server.server_port
                started = time.monotonic()
                with socket.create_connection(("127.0.0.1", port), timeout=5) as silent:
                    self.assertEqual(silent.recv(1), b"")  # A silent client still ends at the idle timeout.
                self.assertLess(time.monotonic() - started, handler.header_timeout)
                started = time.monotonic()
                for _ in range(2):
                    attackers.append(_tls(port))
                    attackers[-1].sendall(b"GET /")
                self.assertIsNone(_fetch(port, "/not-a-route"))  # Every slot is held by a trickling client.
                closed = _trickle_until_closed(attackers, limit=8)
                self.assertEqual(len(closed), 2, "Trickled bytes kept their slots past the header deadline")
                for moment in closed.values():
                    self.assertGreater(moment - started, handler.idle_timeout)
                    self.assertLess(moment - started, handler.header_timeout + 3)
                self.assertRegex(_eventually(lambda: _fetch(port, "/not-a-route")) or b"", rb"^HTTP/1\.0 404 ")
            finally:
                for connection in attackers:
                    connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_unknown_routes_and_unsupported_methods_never_reflect_tokens(self):
        handler = subscription_handler({}, "/nonexistent")
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                for method, route in (("GET", "/fixture-private-token-do-not-log/management"),
                                      ("GET", "/not-a-route"), ("GET", "/%2F/nodes.txt"),
                                      ("POST", "/fixture-private-token-do-not-log/nodes.txt")):
                    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                    connection.request(method, route)
                    response = connection.getresponse()
                    body = response.read()
                    self.assertIn(response.status, (404, 501))
                    self.assertEqual(body, b"")
                    self.assertEqual(response.getheader("Cache-Control"), "no-store")
                    self.assertNotIn("Python", response.getheader("Server", ""))
                    connection.close()
            self.assertEqual(stderr.getvalue(), "")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
