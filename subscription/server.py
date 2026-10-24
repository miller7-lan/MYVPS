#!/usr/bin/env python3
"""Private, read-only HTTPS subscription delivery with estimated vnStat usage.

No request path, query, token, or client address is logged. This is a server
counter, not the provider's billing API. Config must be owned by the operator
and readable only by root and the service account's group.
"""
import argparse
import base64
import collections
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit, urlunsplit

MAX_BODY = 2 * 1024 * 1024
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")


class UsageUnavailable(Exception):
    pass


class Usage:
    def __init__(self, interface, state, runner=None, clock=time.time, now=None):
        self.interface, self.state = interface, Path(state)
        self.runner = runner or subprocess.run
        self.clock = clock
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.lock = threading.Lock()
        self.last_poll = -1e30
        self.values = None
        try:
            saved = json.loads(self.state.read_text())
            if self._valid(saved):
                self.values = saved
        except (OSError, ValueError, TypeError):
            pass

    @staticmethod
    def _valid(v):
        return (isinstance(v, dict) and set(v) == {"year", "month", "rx", "tx"}
                and all(type(x) is int for x in v.values())
                and 2000 <= v["year"] <= 2200 and 1 <= v["month"] <= 12
                and 0 <= v["rx"] < 2**63 and 0 <= v["tx"] < 2**63)

    def _period(self):
        current = self.now()
        return current.year, current.month

    def _parse(self, data):
        year, month = self._period()
        for interface in data["interfaces"]:
            if interface["name"] != self.interface:
                continue
            for record in interface["traffic"]["month"]:
                if (record["date"]["year"], record["date"]["month"]) == (year, month):
                    result = {"year": year, "month": month,
                              "rx": record["rx"], "tx": record["tx"]}
                    if self._valid(result):
                        return result
        raise UsageUnavailable("No valid current-month counter")

    def get(self):
        with self.lock:
            period = self._period()
            old = self.values
            old_current = old is not None and (old["year"], old["month"]) == period
            if self.clock() - self.last_poll >= 30:
                self.last_poll = self.clock()
                try:
                    result = self.runner(
                        ["/usr/bin/vnstat", "--json", "m", "-i", self.interface],
                        capture_output=True, check=True, timeout=3,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                    if len(result.stdout) > MAX_BODY:
                        raise UsageUnavailable("Counter response too large")
                    fresh = self._parse(json.loads(result.stdout))
                    if old_current:
                        fresh["rx"] = max(fresh["rx"], old["rx"])
                        fresh["tx"] = max(fresh["tx"], old["tx"])
                    # Never publish an update that cannot survive a restart.
                    self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    temporary = self.state.with_suffix(".new")
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(descriptor, "w") as target:
                        json.dump(fresh, target)
                    os.replace(temporary, self.state)
                    self.values = fresh
                except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError,
                        UsageUnavailable):
                    # Retain the latest valid reading. A new month is never shown
                    # as zero merely because vnStat is temporarily unavailable.
                    pass
            if self.values is None or (self.values["year"], self.values["month"]) != period:
                raise UsageUnavailable("Current-month usage unavailable")
            return dict(self.values)


class RateLimit:
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.entries = clock, threading.Lock(), collections.OrderedDict()

    def allow(self, address):
        with self.lock:
            now = self.clock()
            if address in self.entries:
                start, count = self.entries.pop(address)
                if now - start >= 60:
                    start, count = now, 0
            else:
                start, count = now, 0
            self.entries[address] = (start, count + 1)
            while len(self.entries) > 4096:
                self.entries.popitem(last=False)
            return count < 100


def load_routes(config):
    routes = []
    for entry in config["devices"]:
        token = entry["token"]
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise ValueError("Subscription token must contain 32–128 URL-safe characters")
        for name, source in entry["files"].items():
            if name not in {"config.conf", "clash.yaml", "nodes.txt"}:
                raise ValueError("Unsupported subscription format")
            payload = Path(source).read_bytes()
            if not payload or len(payload) > MAX_BODY:
                raise ValueError("Subscription body is empty or too large")
            encoded = name == "nodes.txt" and config.get("base64_nodes", False)
            if encoded:
                payload = base64.b64encode(payload)
            route = f"/{token}/{name}".encode("ascii")
            routes.append((hashlib.sha256(route).digest(), payload,
                           "text/yaml; charset=utf-8" if name.endswith("yaml")
                           else "text/plain; charset=utf-8", name, bool(encoded)))
    if not routes or len(routes) > 30 or len({r[0] for r in routes}) != len(routes):
        raise ValueError("Missing, duplicate, or excessive routes")
    return routes


def status_node_payload(payload, encoded, usage, total):
    """Append a working VLESS alias whose label reports the shared estimate."""
    raw = base64.b64decode(payload, validate=True) if encoded else payload
    original = raw.decode("utf-8")
    first = next((line.strip() for line in original.splitlines()
                  if line.strip().lower().startswith("vless://")), None)
    if first is None:
        return payload
    remaining = max(0, total - usage["rx"] - usage["tx"])
    label = f"剩余 {remaining / 1e9:.2f} GB / {total / 1e9:g} GB（全设备估算）"
    parsed = urlsplit(first)
    alias = urlunsplit(parsed._replace(fragment=quote(label, safe="")))
    result = raw.rstrip(b"\r\n") + b"\n" + alias.encode("utf-8") + b"\n"
    return base64.b64encode(result) if encoded else result


def make_handler(routes, usage, total, expire=None, limiter=None, usage_status_node=False):
    limiter = limiter or RateLimit()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = ""
        sys_version = ""

        def log_message(self, *args):
            pass

        def log_error(self, *args):
            pass

        def version_string(self):
            return ""

        def _reply(self, status, body=b"", headers=()):
            self.send_response_only(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "private, no-store, max-age=0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            if not limiter.allow(self.client_address[0]):
                return self._reply(429, b"Too many requests\n", [("Retry-After", "60")])
            digest = hashlib.sha256(self.path.encode("utf-8")).digest()
            selected = None
            for expected, payload, kind, name, encoded in routes:
                # Compare a fixed-size digest for every route. No prefix matches.
                if hmac.compare_digest(digest, expected):
                    selected = payload, kind, name, encoded
            if selected is None:
                return self._reply(404, b"Not found\n")
            try:
                current = usage.get()
            except UsageUnavailable:
                return self._reply(503, b"Usage temporarily unavailable\n",
                                   [("Retry-After", "30")])
            payload, kind, name, encoded = selected
            if usage_status_node and name == "nodes.txt":
                payload = status_node_payload(payload, encoded, current, total)
            info = f"upload={current['rx']}; download={current['tx']}; total={total}"
            if expire is not None:
                info += f"; expire={expire}"
            self._reply(200, payload, [
                ("Content-Type", kind), ("Content-Disposition", f'attachment; filename="{name}"'),
                ("Subscription-Userinfo", info), ("Profile-Update-Interval", "6"),
                ("X-Usage-Source", "vnstat-nic-calendar-month-estimate"),
                ("Strict-Transport-Security", "max-age=86400")])

        do_HEAD = do_GET

        def send_error(self, code, message=None, explain=None):
            # No request content reflected in errors; omit interpreter version.
            self._reply(code, b"Request rejected\n")

    return Handler


class BoundedHTTPSServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler, context):
        self.context = context
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            with self.context.wrap_socket(request, server_side=True) as tls_socket:
                tls_socket.settimeout(10)
                self.finish_request(tls_socket, client_address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.shutdown_request(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/qqg-sub/config.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    total = config.get("total_bytes", 500_000_000_000)
    expire = config.get("expire")
    if type(total) is not int or total <= 0 or (expire is not None and
            (type(expire) is not int or expire <= 0)):
        raise ValueError("Invalid subscription allowance or expiry")
    interface = config.get("interface", "ens17")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise ValueError("Invalid interface")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["certificate"], config["private_key"])
    usage = Usage(interface, config.get("state_file", "/var/lib/qqg-sub/usage.json"))
    usage_status_node = config.get("usage_status_node", False)
    if type(usage_status_node) is not bool:
        raise ValueError("usage_status_node must be a boolean")
    handler = make_handler(load_routes(config), usage, total, expire,
                           usage_status_node=usage_status_node)
    BoundedHTTPSServer(("0.0.0.0", 8443), handler, context).serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
