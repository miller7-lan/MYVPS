"""Private, dynamic-user exports. Phase 1 uses documentation-only endpoints."""
from __future__ import annotations
import base64
import json
import secrets
from urllib.parse import quote, urlencode

SERVER = "192.0.2.10"  # RFC 5737 TEST-NET; cannot be a functioning production node.
SNI = "www.microsoft.com"
TITLE = "Dazzle'VPS"


def _values(store, user, *, endpoint=None, public_key=None, production=False):
    credentials = dict(store.get_credentials(user["id"]))
    if production:
        import ipaddress
        if not endpoint or not ipaddress.ip_address(endpoint).is_global or not public_key or len(public_key) != 43:
            raise ValueError("Approved production endpoint and provisioned public key are required")
        credentials["reality_public_key"] = public_key
    elif endpoint is not None or public_key is not None:
        raise ValueError("Endpoint overrides require an explicit production renderer")
    return credentials, user["port"], endpoint if production else SERVER


def node_uris(store, user, **options) -> tuple[str, str]:
    c, port, server = _values(store, user, **options)
    vless = f"vless://{c['vless_uuid']}@{server}:{port}?" + urlencode({
        "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
        "sni": SNI, "fp": "chrome", "pbk": c["reality_public_key"],
        "sid": c["short_id"], "type": "tcp", "headerType": "none",
    }) + "#" + quote(TITLE + "-VLESS（常用）", safe="")
    tuic = f"tuic://{c['tuic_uuid']}:{quote(c['tuic_password'], safe='')}@{server}:{port}?" + urlencode({
        "congestion_control": "bbr", "udp_relay_mode": "native", "alpn": "h3", "sni": server,
        "insecure": "0", "allowInsecure": "0", "zero_rtt_handshake": "0",
    }) + "#" + quote(TITLE + "-TUIC5（迅速）", safe="")
    return vless, tuic


def mihomo(store, user, **options) -> dict:
    c, port, server = _values(store, user, **options)
    a, b = TITLE + "-VLESS（常用）", TITLE + "-TUIC5（迅速）"
    return {"mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
            "mode": "rule", "log-level": "warning", "ipv6": False,
            "proxies": [
                {"name": a, "type": "vless", "server": server, "port": port,
                 "uuid": c["vless_uuid"], "flow": "xtls-rprx-vision", "network": "tcp",
                 "tls": True, "servername": SNI, "client-fingerprint": "chrome",
                 "reality-opts": {"public-key": c["reality_public_key"], "short-id": c["short_id"]},
                 "udp": True, "packet-encoding": "xudp"},
                {"name": b, "type": "tuic", "server": server, "port": port,
                 "uuid": c["tuic_uuid"], "password": c["tuic_password"], "sni": server,
                 "alpn": ["h3"], "congestion-controller": "bbr", "udp-relay-mode": "native",
                 "reduce-rtt": False, "skip-cert-verify": False}],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [a, b]}],
            "rules": [f"IP-CIDR,{server}/32,DIRECT,no-resolve", "DOMAIN-SUFFIX,ts.net,DIRECT",
                      "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
                      "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
                      "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                      "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "GEOIP,CN,DIRECT", "MATCH,PROXY"]}


def shadowrocket(store, user, **options) -> str:
    c, port, server = _values(store, user, **options)
    a, b = TITLE + "-VLESS（常用）", TITLE + "-TUIC5（迅速）"
    return "\n".join([
        "# Dazzle VPS parallel production; personal payload allowance." if options.get("production") else "# V3.1 LOCAL SIMULATION ONLY. TEST-NET address. Not deployed.",
        "[General]", "bypass-system = true", "skip-proxy = localhost, *.local, *.lan, *.ts.net, 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16",
        "ipv6 = false", "", "[Proxy]",
        f"{a} = vless, {server}, {port}, password={c['vless_uuid']}, tls=true, xtls=2, peer={SNI}, pbk={c['reality_public_key']}, sid={c['short_id']}, udp=1, allowInsecure=0",
        f"{b} = tuic, {server}, {port}, password={c['tuic_password']}, uuid={c['tuic_uuid']}, peer={server}, alpn=h3, udp=1, allowInsecure=0",
        "", "[Proxy Group]", f"PROXY = select, {a}, {b}", "", "[Rule]",
        f"IP-CIDR,{server}/32,DIRECT,no-resolve", "DOMAIN-SUFFIX,ts.net,DIRECT", "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT", "FINAL,PROXY", ""])


def render_export(store, user, format: str) -> dict:
    if user["revoked_at"]:
        raise ValueError("Revoked users cannot export credentials")
    if format == "mihomo":
        # JSON is YAML 1.2 compatible and avoids an extra serializer dependency.
        content = json.dumps(mihomo(store, user), ensure_ascii=False, indent=2) + "\n"
        filename = "Dazzle-VPS-simulation.yaml"
    elif format == "shadowrocket":
        content, filename = shadowrocket(store, user), "Dazzle-VPS-simulation.conf"
    elif format == "uris":
        content, filename = "\n".join(node_uris(store, user)) + "\n", "Dazzle-VPS-simulation-uris.txt"
    else:
        raise ValueError("Unsupported export format")
    return {"filename": filename, "content": content, "subscription_url": None,
            "nodes_url": None, "config_url": None, "sensitive": True,
            "nodes": list(node_uris(store, user)), "deployed": False,
            "warning": "本地模拟：192.0.2.10 为保留测试地址。没有可用的线上订阅链接。"}


def subscription_response(store, token: str, format: str) -> dict:
    """Pure response function; phase 1 opens no subscription listener."""
    if not isinstance(token, str) or not 24 <= len(token) <= 128:
        return {"status": 404, "headers": {"Cache-Control": "no-store"}, "body": ""}
    matched = None
    for row in store.conn.execute("SELECT user_id,subscription_token FROM credentials"):
        if secrets.compare_digest(row["subscription_token"], token):
            matched = row["user_id"]
    if matched is None:
        return {"status": 404, "headers": {"Cache-Control": "no-store"}, "body": ""}
    user = store.conn.execute("SELECT * FROM users WHERE id=?", (matched,)).fetchone()
    from .domain import eligible
    if not user or not eligible(dict(user)):
        return {"status": 403, "headers": {"Cache-Control": "no-store"}, "body": ""}
    rendered = render_export(store, dict(user), format)
    unlimited = bool(user["unlimited"])
    total = 0 if unlimited else (user["quota_bytes"] or 0) + user["topup_bytes"]
    # Personal payload quota; NOT provider remaining. Unlimited total=0 is conventional.
    usage = f"upload={user['used_upload']}; download={user['used_download']}; total={total}"
    return {"status": 200, "headers": {"Cache-Control": "no-store", "Subscription-Userinfo": usage,
            "Profile-Title": "Dazzle'VPS (simulation, personal payload quota)"}, "body": rendered["content"]}


def worker_template(user: dict, credentials: dict, *, reality_private_key: str,
                    api_secret: str, api_port: int) -> dict:
    """Render only. No file writes or listener startup. Check with pinned core."""
    if len(api_secret) < 32 or api_port == user["port"] or not 1024 <= api_port <= 65535:
        raise ValueError("Dedicated loopback API port and strong secret are required")
    return {
        "log": {"level": "warn", "timestamp": True},
        "services": [{"type": "api", "tag": "private-meter", "listen": "127.0.0.1",
                      "listen_port": api_port, "secret": api_secret, "dashboard": {"enabled": False},
                      "access_control_allow_origin": ["https://invalid.example"],
                      "access_control_allow_private_network": False}],
        "inbounds": [
            {"type": "vless", "tag": "vless", "listen": "0.0.0.0", "listen_port": user["port"],
             "users": [{"name": user["id"], "uuid": credentials["vless_uuid"], "flow": "xtls-rprx-vision"}],
             "tls": {"enabled": True, "server_name": SNI,
                     "reality": {"enabled": True, "handshake": {"server": SNI, "server_port": 443},
                                 "private_key": reality_private_key, "short_id": [credentials["short_id"]]}}},
            {"type": "tuic", "tag": "tuic", "listen": "0.0.0.0", "listen_port": user["port"],
             "users": [{"name": user["id"], "uuid": credentials["tuic_uuid"], "password": credentials["tuic_password"]}],
             "congestion_control": "bbr", "zero_rtt_handshake": False, "auth_timeout": "3s",
             "tls": {"enabled": True, "min_version": "1.3", "alpn": ["h3"],
                     "certificate_path": "/etc/s-box/cert.pem", "key_path": "/etc/s-box/private.key"}}
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"ip_is_private": True, "action": "reject"}], "final": "direct"}}
