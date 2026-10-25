"""Token-only HTTP boundaries and TLS context reload, entirely local fixtures."""
import http.client
import io
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dazzle.production import RateLimit, SubscriptionServer, TLSContexts, subscription_handler


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
