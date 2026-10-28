"""Unprivileged public portal. All account authority stays behind a Unix socket."""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import asynccontextmanager, suppress
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import tempfile
import uuid
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.routing import Route
from uvicorn.protocols.http.h11_impl import H11Protocol
from .production import RateLimit
from .production_state import checked_hostname

SOCKET_PATH = "/run/dazzle-vps-portal/agent.sock"
SESSION = "__Secure-dazzle_session"
CSRF = "__Secure-dazzle_csrf"
MAX_BODY = 8192
MAX_REPLY = 3_000_000
ASSETS = Path(__file__).with_name("portal_static")
MESSAGES = {"INVALID_CODE": "验证码错误、已使用或已过期，请重新获取。",
            "UNAUTHENTICATED": "请先通过邮箱验证码登录。", "RATE_LIMITED": "请求较频繁，请稍后再试。",
            "REGISTRATION_CLOSED": "暂不接受新注册，已有用户仍可登录。", "REGISTRATION_FULL": "人员已满，稍后再试",
            "UNAVAILABLE": "服务暂时不可用，请稍后重试。",
            "NOT_ACTIVE": "此账户尚未启用或已暂停，暂不能获取使用资料。",
            "RESEND_COOLDOWN": "刚刚已发送过，请稍后再试（每5分钟最多一次，每天最多5次）。",
            "MAIL_NOT_CONFIGURED": "暂时无法发送邮件，请联系管理员。",
            "EMAIL_NOT_VERIFIED": "邮箱尚未验证，请联系管理员。",
            "VALIDATION": "请检查邮箱及填写内容。"}
# TLS 1.3 suites are unaffected. TLS 1.2 previously inherited uvicorn's "TLSv1"
# list, which offers no AEAD suite; keep forward secrecy first and CBC fallbacks.
TLS_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES:AES:!aNULL:!eNULL:!MD5:!DSS:!3DES"


class PortalUnavailable(Exception):
    pass


class DeadlineH11Protocol(H11Protocol):
    header_timeout = 5
    request_timeout = 15

    def _arm_deadline(self, seconds):
        handle = getattr(self, "_request_deadline", None)
        if handle:
            handle.cancel()
        self._request_deadline = self.loop.call_later(seconds, self.transport.close)

    def connection_made(self, transport):
        super().connection_made(transport)
        self._arm_deadline(self.header_timeout)

    def data_received(self, data):
        previous = self.cycle
        super().data_received(data)
        if self.cycle is not previous:
            self._arm_deadline(self.request_timeout)

    def on_response_complete(self):
        super().on_response_complete()
        active = self.cycle is not None and not self.cycle.response_complete
        self._arm_deadline(self.request_timeout if active else self.header_timeout)

    def connection_lost(self, error):
        handle = getattr(self, "_request_deadline", None)
        if handle:
            handle.cancel()
        super().connection_lost(error)


class PortalEventLoop(asyncio.SelectorEventLoop):
    tls_handshake_timeout = 5
    async def create_server(self, *args, **kwargs):
        if kwargs.get("ssl"):
            kwargs.setdefault("ssl_handshake_timeout", self.tls_handshake_timeout)
            kwargs.setdefault("ssl_shutdown_timeout", 3)
        return await super().create_server(*args, **kwargs)


def loop_factory():
    return PortalEventLoop()


class PortalClient:
    def __init__(self, path=SOCKET_PATH):
        self.path = path

    def call(self, operation, params, peer_ip):
        identifier = str(uuid.uuid4())
        payload = json.dumps({"version": 1, "request_id": identifier, "operation": operation,
                              "params": params, "peer_ip": peer_ip}, separators=(",", ":")).encode() + b"\n"
        if len(payload) > 16384:
            raise PortalUnavailable()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(8)
                connection.connect(self.path)
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                result = bytearray()
                while not result.endswith(b"\n"):
                    block = connection.recv(min(65536, MAX_REPLY + 1 - len(result)))
                    if not block:
                        break
                    result.extend(block)
                    if len(result) > MAX_REPLY:
                        raise PortalUnavailable()
            reply = json.loads(result)
            if reply.get("request_id") != identifier or type(reply.get("ok")) is not bool:
                raise PortalUnavailable()
            return reply
        except (OSError, ValueError, KeyError, TypeError):
            raise PortalUnavailable() from None


def normalized_origin(value, *, allow_loopback_http=False):
    parsed = urlsplit(value)
    allowed_scheme = parsed.scheme == "https" or (allow_loopback_http and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"})
    if (not allowed_scheme or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ValueError("An explicit HTTPS origin is required")
    return value.rstrip("/")


def _secure_cookie(response, name, value, *, max_age, httponly=True):
    response.set_cookie(name, value, max_age=max_age, secure=True, httponly=httponly,
                        samesite="lax", path="/portal")


def _error(code, status=400):
    return JSONResponse({"ok": False, "error": {"code": code, "message": MESSAGES.get(code, "请求未能完成。")}}, status_code=status)


def reload_tls(context, certificate, key, previous=None):
    """Validate an immutable pair before updating the live server context."""
    try:
        cert_data, key_data = Path(certificate).read_bytes(), Path(key).read_bytes()
        fingerprint = hashlib.sha256(cert_data + b"\0" + key_data).digest()
        if fingerprint == previous:
            return previous
        with tempfile.TemporaryDirectory(prefix="dazzle-tls-") as temporary:
            cert_path, key_path = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            cert_path.write_bytes(cert_data); key_path.write_bytes(key_data)
            cert_path.chmod(0o600); key_path.chmod(0o600)
            check = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            check.load_cert_chain(cert_path, key_path)
            context.load_cert_chain(cert_path, key_path)
        return fingerprint
    except (OSError, ssl.SSLError):
        return previous


class HostCertificate:
    """A hostname's own pair. Clients connecting by IP send no SNI and keep the default."""
    def __init__(self, certificate, key):
        self.paths = (certificate, key)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_ciphers(TLS_CIPHERS)
        self.fingerprint = None
        self.reload()

    def reload(self):
        self.fingerprint = reload_tls(self.context, *self.paths, self.fingerprint)


def select_certificate(hosts):
    """SNI callback: switch to a hostname's pair only once that pair has loaded."""
    def select(connection, server_name, _context):
        entry = hosts.get((server_name or "").rstrip(".").lower())
        if entry is not None and entry.fingerprint is not None:
            connection.context = entry.context
    return select


class SafetyHeaders:
    def __init__(self, app):
        self.app, self.state, self.routes = app, app.state, app.routes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = completed = False
        async def safe_send(message):
            nonlocal started, completed
            if message["type"] == "http.response.start":
                started = True
                # same-origin, not no-referrer: some mobile engines apply the
                # page's referrer policy to Origin and send "null" on its own POSTs.
                security = {b"cache-control": b"no-store", b"referrer-policy": b"same-origin", b"x-content-type-options": b"nosniff",
                    b"content-security-policy": b"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()", b"x-frame-options": b"DENY"}
                message["headers"] = [(key, value) for key, value in message.get("headers", []) if key.lower() not in security] + list(security.items())
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                completed = True
            await send(message)
        try:
            await self.app(scope, receive, safe_send)
        except Exception:
            # Neither request paths nor sensitive values may enter server tracebacks.
            if not started:
                await Response(status_code=503)(scope, receive, safe_send)
            elif not completed:
                await send({"type": "http.response.body", "body": b"", "more_body": False})


def create_app(*, origin, client=None, portal_enabled=True):
    # One origin per served name (the IP and an optional hostname); links issued with either keep working.
    origins = frozenset(normalized_origin(value, allow_loopback_http=True)
                        for value in ([origin] if isinstance(origin, str) else origin))
    if not origins:
        raise ValueError("An explicit HTTPS origin is required")
    client = client or PortalClient()
    semaphore = asyncio.Semaphore(8)
    limiter = RateLimit(limit=100, window=60)
    # A page load needs two API calls and sign-in a few more. Bound what one
    # address can make the agent process before any per-account budget applies.
    api_limiter = RateLimit(limit=60, window=60)

    async def invoke(request, operation, params):
        peer = request.client.host if request.client else "127.0.0.1"
        try:
            async with semaphore:
                return await asyncio.to_thread(client.call, operation, params, peer)
        except Exception:
            return {"ok": False, "error": {"code": "UNAVAILABLE"}}

    async def index(request):
        if not portal_enabled:
            return Response(status_code=404)
        result = Response((ASSETS / "index.html").read_bytes(), media_type="text/html")
        # The same-origin client echoes this token in a request header. Session
        # authentication remains HttpOnly; only this anti-forgery cookie is readable.
        _secure_cookie(result, CSRF, secrets.token_urlsafe(32), max_age=604800, httponly=False)
        return result

    async def asset(request):
        name = request.path_params["name"]
        if not portal_enabled or name not in {"app.js", "app.css"}:
            return Response(status_code=404)
        return Response((ASSETS / name).read_bytes(), media_type="text/javascript" if name.endswith(".js") else "text/css")

    async def api(request):
        if not portal_enabled:
            return Response(status_code=404)
        action = request.path_params["action"]
        operations = {"status": "registration.status", "request-code": "auth.request_code", "verify": "auth.verify", "me": "session.me",
                      "resend-subscription": "session.resend_subscription", "logout": "session.logout"}
        if action not in operations:
            return Response(status_code=404)
        if request.method != ("GET" if action in {"me", "status"} else "POST"):
            return Response(status_code=405)
        if not api_limiter.allow(request.client.host if request.client else "127.0.0.1"):
            return _error("RATE_LIMITED", 429)
        params = {}
        if request.method == "POST":
            csrf = request.cookies.get(CSRF, "")
            supplied = request.headers.get("x-csrf-token", "")
            if (request.headers.get("origin") not in origins or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", csrf)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", supplied) or not hmac.compare_digest(csrf, supplied)):
                return _error("VALIDATION", 403)
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return _error("VALIDATION", 415)
            data = bytearray()
            try:
                async with asyncio.timeout(5):
                    async for block in request.stream():
                        data.extend(block)
                        if len(data) > MAX_BODY:
                            return _error("VALIDATION", 413)
                params = json.loads(data)
                allowed = {"request-code": {"email", "nickname", "website", "challenge_id"}, "verify": {"challenge_id", "code"},
                           "resend-subscription": set(), "logout": set()}[action]
                if not isinstance(params, dict) or set(params) - allowed:
                    return _error("VALIDATION")
                if action == "request-code" and params.pop("website", ""):
                    return _error("RATE_LIMITED", 429)
            except (ValueError, UnicodeError):
                return _error("VALIDATION")
            except TimeoutError:
                result = _error("VALIDATION", 408)
                result.headers["Connection"] = "close"
                return result
        if action in {"me", "resend-subscription", "logout"}:
            token = request.cookies.get(SESSION, "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
                return _error("UNAUTHENTICATED", 401)
            params = {"session_token": token}
        reply = await invoke(request, operations[action], params)
        if not reply.get("ok"):
            code = reply.get("error", {}).get("code", "UNAVAILABLE")
            return _error(code, {"UNAUTHENTICATED": 401, "RATE_LIMITED": 429, "UNAVAILABLE": 503}.get(code, 400))
        data = reply["data"]
        if action == "me":
            account = data.get("account", {})
            data = {"account": {key: account.get(key) for key in
                                ("id", "email", "nickname", "status", "expires_at")},
                    "delivery": {"method": "email"}}
        if action == "verify":
            result = JSONResponse({"ok": True, "data": {"expires_at": data["expires_at"]}})
            _secure_cookie(result, SESSION, data["session_token"], max_age=604800)
        else:
            result = JSONResponse({"ok": True, "data": data})
        if action == "logout":
            result.delete_cookie(SESSION, path="/portal", secure=True, httponly=True, samesite="lax")
        return result

    async def subscription(request):
        token, route = request.path_params["token"], request.path_params["route"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", token) or route not in {"config.yaml", "nodes.txt", "config.conf"}:
            return Response(status_code=404)
        if not limiter.allow(request.client.host if request.client else "127.0.0.1"):
            return Response(status_code=429)
        reply = await invoke(request, "subscription.fetch", {"token": token, "route": route})
        if not reply.get("ok"):
            return Response(status_code=503)
        try:
            data = reply["data"]
            body = base64.b64decode(data["body_b64"], validate=True)
            headers = {k: v for k, v in data.get("headers", {}).items() if k.lower() in {"subscription-userinfo", "profile-title", "profile-update-interval"}}
            return Response(body, status_code=data["status"], headers=headers, media_type="text/plain")
        except (ValueError, TypeError, KeyError):
            return Response(status_code=503)

    @asynccontextmanager
    async def lifespan(app):
        async def watch_tls():
            previous = None
            while True:
                if getattr(app.state, "tls_context", None):
                    previous = await asyncio.to_thread(reload_tls, app.state.tls_context, *app.state.tls_paths, previous)
                for entry in getattr(app.state, "host_tls", {}).values():
                    await asyncio.to_thread(entry.reload)
                await asyncio.sleep(15)
        task = asyncio.create_task(watch_tls())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = Starlette(routes=[Route("/portal", index), Route("/portal/", index),
                            Route("/portal/assets/{name}", asset), Route("/portal/api/{action}", api, methods=["GET", "POST"]),
                            Route("/{token}/{route}", subscription)], lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=sorted({urlsplit(value).hostname for value in origins}))

    return SafetyHeaders(app)


def main():
    parser = argparse.ArgumentParser(description="Unprivileged Dazzle VPS self-service portal")
    parser.add_argument("--socket", default=SOCKET_PATH)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--subscription-only", action="store_true")
    # Set by an optional unit drop-in, so the unit's own command line never changes.
    parser.add_argument("--hostname", default=os.environ.get("DAZZLE_PORTAL_HOSTNAME") or None,
                        help="DNS name also served on this port; its pair is host-cert.pem/host-key.pem beside --cert/--key")
    args = parser.parse_args()
    origins = [normalized_origin(args.origin)]
    if args.port != 9443 or args.socket != SOCKET_PATH:
        parser.error("Only the approved subscription port and private socket are supported")
    if args.hostname:
        try:
            origins.append(f"https://{checked_hostname(args.hostname)}:{args.port}")
        except ValueError:
            parser.error("--hostname must be a lowercase DNS name")
    import uvicorn
    app = create_app(origin=origins, client=PortalClient(args.socket), portal_enabled=not args.subscription_only)
    config = uvicorn.Config(app, host=args.host, port=args.port, ssl_certfile=args.cert, ssl_keyfile=args.key,
                            ssl_version=ssl.PROTOCOL_TLS_SERVER, ssl_ciphers=TLS_CIPHERS, workers=1, limit_concurrency=16, backlog=32,
                            timeout_keep_alive=5, server_header=False, access_log=False, proxy_headers=False, log_level="warning",
                            http=DeadlineH11Protocol, loop="dazzle.portal:loop_factory", h11_max_incomplete_event_size=16384)
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    app.state.tls_context = config.ssl
    app.state.tls_paths = (args.cert, args.key)
    if args.hostname:
        app.state.host_tls = {args.hostname: HostCertificate(str(Path(args.cert).with_name("host-cert.pem")),
                                                             str(Path(args.key).with_name("host-key.pem")))}
        config.ssl.sni_callback = select_certificate(app.state.host_tls)
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
