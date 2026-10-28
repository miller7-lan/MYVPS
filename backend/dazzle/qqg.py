"""Read-only QQG.NET traffic reader (IDCSmart V10 business system + 魔方云 module).

QQG's console shows an instance's traffic card from the 魔方云 module, and the
platform's documented API-key login exchanges a key token for the same client
JWT. This module performs exactly two fixed requests and nothing else:

* ``POST /api/v1/auth`` with the registered email/phone and the key token;
* ``GET /console/v1/mf_cloud/<host_id>/flow`` with the returned JWT.

The key grants the whole QQG account, so no other path, method, redirect or
host is reachable from here. Neither the token, the username nor the JWT is
part of any result, exception message or repr.

Units follow the module source: its "GB" is bytes / 1024**3 rounded to two
decimals, so one reading is precise to 0.01 GiB (about 10.7 MB).
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import datetime as dt
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time
from urllib.parse import urlencode, urlsplit

AUTH_PATH = "/api/v1/auth"
FLOW_PATH = "/console/v1/mf_cloud/{host_id}/flow"
GIB = 1024 ** 3
PRECISION_BYTES = GIB // 100  # QQG rounds every amount to 0.01 GB.
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 15
JWT_DEFAULT_TTL = 7200  # create_jwt() default in the V10 source.
JWT_REFRESH_MARGIN = 300
USER_AGENT = "DazzleVPS-provider-sync/1"
DEFAULT_API_URL = "https://www.qqg.net"
UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": GIB, "TB": 1024 ** 4}
UNLIMITED = {"不限", "无限", "无限制", "不限制", "unlimited", "not limited", "no limit"}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_JWT = re.compile(r"[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}")
_AMOUNT = re.compile(r"\s*(\d{1,9}(?:\.\d{1,6})?)\s*([KMGT]?B)?\s*", re.IGNORECASE)
_EMAIL = re.compile(r"[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{1,60}")
_PHONE = re.compile(r"\+?\d{5,20}")


class QqgError(Exception):
    """A fixed code plus a message that never contains credentials."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(code + ": " + self.message)


@dataclass(frozen=True)
class Credentials:
    api_url: str
    host_id: int
    username: str = field(repr=False)
    token: str = field(repr=False)

    @property
    def host(self) -> str:
        return urlsplit(self.api_url).hostname or ""

    @property
    def flow_path(self) -> str:
        return FLOW_PATH.format(host_id=self.host_id)


def normalize_api_url(value) -> str:
    """Only the QQG site origin itself; every request path is fixed here."""
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 200:
        raise QqgError("CONFIG_INVALID", "api_url 须为 QQG 网站地址，例如 https://www.qqg.net")
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise QqgError("CONFIG_INVALID", "api_url 不是有效地址") from None
    host = (parts.hostname or "").lower()
    if (parts.scheme != "https" or parts.username or parts.password or parts.query or parts.fragment or
            parts.path not in {"", "/"} or port not in {None, 443}):
        raise QqgError("CONFIG_INVALID", "api_url 只能是 https 网站根地址，例如 https://www.qqg.net")
    if not (host == "qqg.net" or host.endswith(".qqg.net")) or len(host) > 253 or \
            not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise QqgError("CONFIG_INVALID", "api_url 必须是 qqg.net 的地址")
    return "https://" + host


def checked_host_id(value) -> int:
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if type(value) is not int or not 1 <= value <= 2 ** 31 - 1:
        raise QqgError("CONFIG_INVALID", "host_id 须为 QQG 控制台中这台 VPS 的数字 ID")
    return value


def checked_username(value) -> str:
    if isinstance(value, str) and "PASTE_" in value:
        raise QqgError("CONFIG_INCOMPLETE", "请先填写 username（QQG 注册邮箱或手机号）")
    value = value.strip() if isinstance(value, str) else value
    if not isinstance(value, str) or not (_EMAIL.fullmatch(value) or _PHONE.fullmatch(value)):
        raise QqgError("CONFIG_INVALID", "username 须为 QQG 注册邮箱或手机号")
    return value


def checked_token(value) -> str:
    if isinstance(value, str) and "PASTE_" in value:
        raise QqgError("CONFIG_INCOMPLETE", "请先填写 token（QQG API 密钥）")
    value = value.strip() if isinstance(value, str) else value
    if not isinstance(value, str) or not 8 <= len(value) <= 512 or \
            any(not 0x21 <= ord(char) <= 0x7e for char in value):
        raise QqgError("CONFIG_INVALID", "token 格式不对：应为 QQG 创建 API 时显示的那串字符")
    return value


def credentials(api_url, username, token, host_id) -> Credentials:
    return Credentials(normalize_api_url(api_url), checked_host_id(host_id),
                       checked_username(username), checked_token(token))


def _private_text(path, what: str) -> str:
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise QqgError("CONFIG_MISSING", what + "不存在") from None
    except OSError:
        raise QqgError("CONFIG_INVALID", what + "无法读取") from None
    if not stat.S_ISREG(info.st_mode):
        raise QqgError("CONFIG_INVALID", what + "必须是普通文件，不能是链接")
    if info.st_mode & 0o077:
        raise QqgError("CONFIG_INSECURE", what + "权限过宽，请执行 chmod 600")
    if info.st_size > 8192:
        raise QqgError("CONFIG_INVALID", what + "过大")
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        raise QqgError("CONFIG_INVALID", what + "不是 UTF-8 文本") from None


def read_token_file(path) -> str:
    """A private file holding only the 32-character API token, on one line."""
    lines = [line.strip() for line in _private_text(path, "token 文件").splitlines() if line.strip()]
    # QQG shows the RSA private_key next to the token; it is never needed here.
    if any("PRIVATE KEY" in line for line in lines) or (
            len(lines) > 3 and sum(map(len, lines)) > 500 and
            all(re.fullmatch(r"[A-Za-z0-9+/=]+", line) for line in lines)):
        raise QqgError("TOKEN_FILE_IS_PRIVATE_KEY",
                       "这个文件是 API 私钥（private_key），不是 token；需要创建 API 时显示的那串 token")
    if len(lines) != 1:
        raise QqgError("CONFIG_INVALID", "token 文件里应只有一行 token")
    return checked_token(lines[0])


def load_credentials(path, token_file=None) -> tuple[Credentials, list[str]]:
    """Private local JSON file (and optional token file); returns credentials and ignored field names."""
    try:
        value = json.loads(_private_text(path, "凭据文件"))
    except ValueError:
        raise QqgError("CONFIG_INVALID", "凭据文件不是有效的 JSON") from None
    if not isinstance(value, dict):
        raise QqgError("CONFIG_INVALID", "凭据文件须为 JSON 对象")
    if value.get("version", 1) != 1:
        raise QqgError("CONFIG_INVALID", "凭据文件版本不受支持")
    known = {"version", "api_url", "username", "token", "host_id"}
    ignored = sorted(name if re.fullmatch(r"[A-Za-z0-9_]{1,40}", name) else "?"
                     for name in value if isinstance(name, str) and name not in known and not name.startswith("_"))
    token = read_token_file(token_file) if token_file is not None else value.get("token")
    result = credentials(value.get("api_url", DEFAULT_API_URL), value.get("username"),
                         token, value.get("host_id"))
    return result, ignored


@dataclass(frozen=True)
class FlowReading:
    """One traffic card, converted to bytes with the module's 1024**3 GB."""
    host_id: int
    unlimited: bool
    total_bytes: int | None
    used_bytes: int
    remaining_bytes: int | None
    total_display: str
    used_display: str
    remaining_display: str
    reset_date: str | None
    precision_bytes: int = PRECISION_BYTES
    unit: str = "GiB"


def _display(value, fallback_bytes) -> str:
    if isinstance(value, str):
        text = "".join(char for char in value if char.isprintable()).strip()[:32]
        if text:
            return text
    if fallback_bytes is None:
        return "不限"
    return f"{Decimal(fallback_bytes) / GIB:.2f}GB"


def _amount(value, name) -> int:
    if type(value) in {int, float}:
        try:
            number, unit = Decimal(str(value)), "GB"
        except InvalidOperation:
            raise QqgError("BAD_RESPONSE", name + " 不是有效数值") from None
    elif isinstance(value, str) and (match := _AMOUNT.fullmatch(value)):
        number, unit = Decimal(match.group(1)), (match.group(2) or "GB").upper()
    else:
        raise QqgError("BAD_RESPONSE", "QQG 流量字段 " + name + " 无法识别")
    if not number.is_finite() or number < 0 or number > 10 ** 7:
        raise QqgError("BAD_RESPONSE", "QQG 流量字段 " + name + " 超出范围")
    return int((number * UNITS[unit]).to_integral_value(rounding=ROUND_HALF_UP))


def _refined(text_bytes, numeric) -> int:
    """Use the numeric field only when it is the same GB quantity with more digits."""
    if type(numeric) in {int, float}:
        try:
            candidate = _amount(numeric, "numeric")
        except QqgError:
            return text_bytes
        if abs(candidate - text_bytes) <= PRECISION_BYTES:
            return candidate
    return text_bytes


def parse_flow(data, host_id: int) -> FlowReading:
    if not isinstance(data, dict):
        raise QqgError("BAD_RESPONSE", "QQG 流量数据格式不对")
    total_raw, used_raw, leave_raw = data.get("total"), data.get("used"), data.get("leave")
    unlimited = (isinstance(total_raw, str) and total_raw.strip().lower() in UNLIMITED) or \
        (total_raw is None and type(data.get("total_num")) is int and data["total_num"] == 0)
    used = _refined(_amount(used_raw if used_raw is not None else data.get("used_num"), "used"), data.get("used_num"))
    if unlimited:
        total = remaining = None
    else:
        total = _amount(total_raw if total_raw is not None else data.get("total_num"), "total")
        total = _refined(total, data.get("total_num"))
        # QQG's own "leave" is what its console shows as 剩余; fall back to total - used.
        remaining = _amount(leave_raw, "leave") if leave_raw is not None else max(0, total - used)
        if remaining > total:
            raise QqgError("BAD_RESPONSE", "QQG 剩余流量大于总量")
    reset = data.get("reset_flow_date")
    try:
        reset = dt.date.fromisoformat(reset).isoformat() if isinstance(reset, str) and len(reset) == 10 else None
    except ValueError:
        reset = None
    return FlowReading(host_id=host_id, unlimited=unlimited, total_bytes=total, used_bytes=used,
                       remaining_bytes=remaining, total_display=_display(total_raw, total),
                       used_display=_display(used_raw, used), remaining_display=_display(leave_raw, remaining),
                       reset_date=reset)


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class HttpsTransport:
    """One verified TLS connection per request; http.client follows no redirect."""

    def __init__(self, timeout: float = TIMEOUT_SECONDS, context: ssl.SSLContext | None = None):
        self.timeout = timeout
        self.context = context or _tls_context()

    def request(self, method, host, path, headers, body=None):
        connection = http.client.HTTPSConnection(host, 443, timeout=self.timeout, context=self.context)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read(MAX_RESPONSE_BYTES + 1)
        finally:
            connection.close()


def _jwt_expiry(jwt: str) -> float | None:
    try:
        payload = jwt.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        expiry = value.get("exp")
        return float(expiry) if type(expiry) in {int, float} else None
    except (ValueError, TypeError, AttributeError, IndexError):
        return None


class QqgClient:
    """Keeps the JWT in memory only and re-logs in shortly before it expires."""

    def __init__(self, creds: Credentials, *, transport=None, clock=time.time):
        self._creds = creds
        self._transport = transport or HttpsTransport()
        self._clock = clock
        self._jwt: str | None = None
        self._jwt_expires = 0.0
        self.logins = 0

    def __repr__(self) -> str:
        return f"QqgClient(host={self._creds.host!r}, host_id={self._creds.host_id})"

    @property
    def token_valid_seconds(self) -> int:
        return max(0, int(self._jwt_expires - self._clock())) if self._jwt else 0

    def _message(self, result: dict) -> str:
        text = result.get("msg")
        if not isinstance(text, str):
            return "无说明"
        for secret in (self._creds.token, self._creds.username, self._jwt):
            if secret:
                text = text.replace(secret, "[已隐藏]")
        text = re.sub(r"[A-Za-z0-9+/=_.-]{24,}", "[已隐藏]", text)
        return "".join(char for char in text if char.isprintable()).strip()[:80] or "无说明"

    def _call(self, method: str, path: str, *, form=None, bearer=None) -> dict:
        if (method, path) not in {("POST", AUTH_PATH), ("GET", self._creds.flow_path)}:
            raise QqgError("NOT_ALLOWED", "只允许 API 登录和流量读取两个请求")
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        body = None
        if form is not None:
            body = urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if bearer is not None:
            headers["Authorization"] = "Bearer " + bearer
        try:
            status, data = self._transport.request(method, self._creds.host, path, headers, body)
        except ssl.SSLError:
            raise QqgError("TLS", "与 QQG 的 TLS 证书校验失败") from None
        except (socket.timeout, TimeoutError):
            raise QqgError("TIMEOUT", "连接 QQG 超时") from None
        except (OSError, http.client.HTTPException):
            raise QqgError("NETWORK", "无法连接 QQG") from None
        if 300 <= status < 400:
            raise QqgError("REDIRECT_REFUSED", f"QQG 返回跳转（HTTP {status}），未跟随")
        if status == 429:
            raise QqgError("RATE_LIMITED", "QQG 限制了请求频率（HTTP 429）")
        if status != 200:
            raise QqgError("HTTP_STATUS", f"QQG 返回 HTTP {status}")
        if len(data) > MAX_RESPONSE_BYTES:
            raise QqgError("BAD_RESPONSE", "QQG 响应过大")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise QqgError("BAD_RESPONSE", "QQG 响应不是 JSON，可能被防护页面拦截") from None
        if not isinstance(value, dict) or type(value.get("status")) is not int:
            raise QqgError("BAD_RESPONSE", "QQG 响应缺少状态码")
        return value

    def login(self) -> None:
        self._jwt = None
        result = self._call("POST", AUTH_PATH, form={"username": self._creds.username,
                                                     "password": self._creds.token})
        if result["status"] != 200:
            raise QqgError("AUTH_FAILED", "QQG 拒绝了 API 登录：" + self._message(result))
        data = result.get("data")
        jwt = data.get("jwt") if isinstance(data, dict) else None
        if not isinstance(jwt, str) or not _JWT.fullmatch(jwt):
            raise QqgError("BAD_RESPONSE", "QQG 登录响应缺少有效令牌")
        now = self._clock()
        expires = _jwt_expiry(jwt)
        if expires is None or not now < expires <= now + 7 * 86400:
            expires = now + JWT_DEFAULT_TTL
        self._jwt, self._jwt_expires = jwt, expires
        self.logins += 1

    def read_flow(self) -> FlowReading:
        for attempt in range(2):
            if self._jwt is None or self._clock() >= self._jwt_expires - JWT_REFRESH_MARGIN:
                self.login()
            result = self._call("GET", self._creds.flow_path, bearer=self._jwt)
            if result["status"] == 401 and attempt == 0:
                self._jwt = None  # Logged out or password changed early: one fresh login.
                continue
            if result["status"] == 401:
                raise QqgError("UNAUTHORIZED", "QQG 不接受新登录令牌：" + self._message(result))
            if result["status"] != 200:
                raise QqgError("FLOW_FAILED", "QQG 未返回流量数据：" + self._message(result))
            return parse_flow(result.get("data"), self._creds.host_id)
        raise QqgError("UNAUTHORIZED", "QQG 不接受登录令牌")


def probe(path, *, token_file=None, transport=None) -> dict:
    """One read for the administrator; prints only the traffic card."""
    creds, ignored = load_credentials(path, token_file)
    client = QqgClient(creds, transport=transport)
    reading = client.read_flow()
    return {"ok": True, "api_host": creds.host, "host_id": creds.host_id, "ignored_fields": ignored,
            "requests": ["POST " + AUTH_PATH, "GET " + creds.flow_path],
            "total": reading.total_display, "used": reading.used_display, "remaining": reading.remaining_display,
            "reset_flow_date": reading.reset_date, "unlimited": reading.unlimited,
            "total_bytes": reading.total_bytes, "used_bytes": reading.used_bytes,
            "remaining_bytes": reading.remaining_bytes, "unit": "GiB (1 GB = 1024^3 bytes)",
            "precision_bytes": reading.precision_bytes, "token_valid_seconds": client.token_valid_seconds}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dazzle.qqg", description="Read-only QQG traffic probe")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("probe", help="Log in with the API key and read the traffic card once")
    command.add_argument("--credentials", required=True, help="Private JSON file with api_url/username/token/host_id")
    command.add_argument("--token-file", help="Private file holding only the API token; overrides the JSON token")
    args = parser.parse_args(argv)
    try:
        result = probe(args.credentials, token_file=args.token_file)
    except QqgError as exc:
        result = {"ok": False, "error": {"code": exc.code, "message": exc.message}}
    except Exception:
        result = {"ok": False, "error": {"code": "INTERNAL", "message": "读取失败（未输出任何凭据）"}}
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
