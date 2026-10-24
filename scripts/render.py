#!/usr/bin/env python3
"""Render private sing-box dual-protocol and cross-platform client files.

No downloads, remote writes, shell execution, or actual credential creation.
All private output is chmod 0600 and output folders are chmod 0700.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import quote, urlencode
import uuid

DEVICES = ("mac", "iphone", "windows")
DISPLAY_NAME = "Dazzle'VPS"
VLESS_NAME = DISPLAY_NAME + "-VLESS（常用）"
TUIC_NAME = DISPLAY_NAME + "-TUIC5（迅速）"
PRIVATE_NETS = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4")
PRIORITY_DOMAINS = ("openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
                    "anthropic.com", "claude.ai", "claudeusercontent.com", "google.com",
                    "googleapis.com", "gstatic.com", "googleusercontent.com", "github.com",
                    "githubusercontent.com", "githubassets.com", "github.io", "githubcopilot.com")


def validate(data):
    data = dict(data)
    ipaddress.IPv4Address(data["server_ip"])
    data.setdefault("reality_sni", "www.microsoft.com")
    data.setdefault("tuic_server_name", data["server_ip"])
    data.setdefault("vless_port", 443)
    data.setdefault("tuic_port", 443)
    for name in ("reality_private_key", "reality_public_key"):
        key = data[name]
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key):
            raise ValueError(f"{name} must be an unpadded 32-byte URL-safe base64 key")
        if len(base64.urlsafe_b64decode(key + "=")) != 32:
            raise ValueError(f"{name} must decode to 32 bytes")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", data["short_id"]):
        raise ValueError("short_id must contain 2..16 even hexadecimal digits")
    for port in (data["vless_port"], data["tuic_port"]):
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("invalid listener port")
    all_ids = []
    for device in DEVICES:
        user = data["users"][device]
        for field in ("vless_uuid", "tuic_uuid"):
            uuid.UUID(user[field])
            all_ids.append(user[field])
        if len(user["tuic_password"]) < 24:
            raise ValueError("TUIC password must contain at least 24 characters")
    if len(set(all_ids)) != len(all_ids):
        raise ValueError("each device and protocol must use a distinct UUID")
    return data


def server_config(data):
    users = data["users"]
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "dns-v4", "server": "1.1.1.1", "server_port": 53}],
                "strategy": "ipv4_only"},
        "inbounds": [
            {"type": "vless", "tag": "vless-sb", "listen": "0.0.0.0", "listen_port": data["vless_port"],
             "users": [{"name": d, "uuid": users[d]["vless_uuid"], "flow": "xtls-rprx-vision"} for d in DEVICES],
             "tls": {"enabled": True, "server_name": data["reality_sni"],
                     "reality": {"enabled": True,
                                 "handshake": {"server": data["reality_sni"], "server_port": 443},
                                 "private_key": data["reality_private_key"], "short_id": [data["short_id"]]}}},
            {"type": "tuic", "tag": "tuic5-sb", "listen": "0.0.0.0", "listen_port": data["tuic_port"],
             "users": [{"name": d, "uuid": users[d]["tuic_uuid"], "password": users[d]["tuic_password"]} for d in DEVICES],
             "congestion_control": "bbr", "zero_rtt_handshake": False, "auth_timeout": "3s", "heartbeat": "10s",
             "tls": {"enabled": True, "min_version": "1.3", "alpn": ["h3"],
                     "certificate_path": "/etc/s-box/cert.pem", "key_path": "/etc/s-box/private.key"}}
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default_domain_resolver": {"server": "dns-v4", "strategy": "ipv4_only"},
                  "rules": [{"ip_is_private": True, "action": "reject"}], "final": "direct"}
    }


def links(data, device):
    u = data["users"][device]
    ip = data["server_ip"]
    vless = f"vless://{u['vless_uuid']}@{ip}:{data['vless_port']}?" + urlencode({
        "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
        "sni": data["reality_sni"], "fp": "chrome", "pbk": data["reality_public_key"],
        "sid": data["short_id"], "type": "tcp", "headerType": "none"
    }) + "#" + quote(VLESS_NAME, safe="")
    tuic = f"tuic://{u['tuic_uuid']}:{quote(u['tuic_password'], safe='')}@{ip}:{data['tuic_port']}?" + urlencode({
        "congestion_control": "bbr", "udp_relay_mode": "native", "alpn": "h3",
        "sni": data["tuic_server_name"], "insecure": "0", "allowInsecure": "0",
        "allow_insecure": "0", "zero_rtt_handshake": "0", "reduce_rtt": "0"
    }) + "#" + quote(TUIC_NAME, safe="")
    return vless, tuic


def clash_config(data, device):
    u = data["users"][device]
    ip = data["server_ip"]
    vless = {"name": VLESS_NAME, "type": "vless", "server": ip, "port": data["vless_port"],
             "uuid": u["vless_uuid"], "flow": "xtls-rprx-vision", "tls": True,
             "servername": data["reality_sni"], "client-fingerprint": "chrome", "network": "tcp",
             "reality-opts": {"public-key": data["reality_public_key"], "short-id": data["short_id"]},
             "udp": True, "packet-encoding": "xudp", "smux": {"enabled": False}}
    tuic = {"name": TUIC_NAME, "type": "tuic", "server": ip, "port": data["tuic_port"],
            "uuid": u["tuic_uuid"], "password": u["tuic_password"], "sni": data["tuic_server_name"],
            "alpn": ["h3"], "congestion-controller": "bbr", "udp-relay-mode": "native",
            "reduce-rtt": False, "skip-cert-verify": False, "heartbeat-interval": 10000}
    rules = [f"IP-CIDR,{ip}/32,DIRECT,no-resolve", "DOMAIN-SUFFIX,ts.net,DIRECT", "DOMAIN-SUFFIX,local,DIRECT",
             "DOMAIN-SUFFIX,lan,DIRECT"]
    rules += [f"IP-CIDR,{net},DIRECT,no-resolve" for net in PRIVATE_NETS]
    rules += [f"DOMAIN-SUFFIX,{domain},PROXY" for domain in PRIORITY_DOMAINS]
    rules += ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve", "MATCH,PROXY"]
    return {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
        "log-level": "warning", "ipv6": False,
        "profile": {"store-selected": True, "store-fake-ip": True},
        "geodata-mode": True, "geodata-loader": "memconservative", "geo-auto-update": True, "geo-update-interval": 168,
        "geox-url": {
            "geoip": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
            "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"},
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True,
                "dns-hijack": ["any:53", "tcp://any:53"],
                "route-exclude-address": [f"{ip}/32", *PRIVATE_NETS]},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False, "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": ["+.lan", "+.local", "+.ts.net", "geosite:cn"],
                "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver": ["https://1.1.1.1/dns-query#PROXY"],
                "nameserver-policy": {"geosite:cn": ["https://dns.alidns.com/dns-query#DIRECT"], "+.ts.net": ["system"]}},
        "proxies": [vless, tuic],
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [VLESS_NAME, TUIC_NAME]}],
        "rules": rules
    }


def shadowrocket_config(data, device):
    """Native profile; basic node fields also appear in Shadowrocket's own parser.

    TUIC v5 is selected by the presence of a separate user UUID and password.
    Optional native congestion/0-RTT spellings are deliberately not guessed:
    the server rejects 0-RTT, and congestion algorithms need not match peers.
    """
    u = data["users"][device]
    ip = data["server_ip"]
    # Native profile node lines are comma-separated. Refuse data whose escaping
    # semantics would depend on undocumented app behavior.
    for value in (data["reality_sni"], data["tuic_server_name"],
                  u["tuic_password"]):
        if not re.fullmatch(r"[A-Za-z0-9._~:!@$%+/-]+", value):
            raise ValueError("Shadowrocket native values must not contain separators, whitespace, or comments")
    excluded = [f"{ip}/32", *PRIVATE_NETS, "255.255.255.255/32"]
    lines = [
        "# Private " + DISPLAY_NAME + " profile: " + device,
        "# VLESS REALITY primary; TUIC v5 manual fallback. Keep this file private.",
        "[General]",
        "bypass-system = true",
        "skip-proxy = localhost, *.local, *.lan, *.ts.net, " + ", ".join(excluded),
        "tun-excluded-routes = " + ", ".join(excluded),
        "dns-server = https://1.1.1.1/dns-query#proxy=" + quote(DISPLAY_NAME, safe=""),
        "direct-dns-server = system",
        "fallback-dns-server = system",
        "dns-direct-system = true",
        "dns-direct-fallback-proxy = false",
        "ipv6 = false",
        "prefer-ipv6 = false",
        "private-ip-answer = true",
        "use-local-host-item-for-proxy = false",
        "udp-policy-not-supported-behaviour = REJECT",
        "",
        "[Proxy]",
        (f"{VLESS_NAME} = vless, {ip}, {data['vless_port']}, password={u['vless_uuid']}, "
         f"tls=true, xtls=2, peer={data['reality_sni']}, pbk={data['reality_public_key']}, "
         f"sid={data['short_id']}, udp=1, allowInsecure=0"),
        (f"{TUIC_NAME} = tuic, {ip}, {data['tuic_port']}, user={u['tuic_uuid']}, "
         f"password={u['tuic_password']}, peer={data['tuic_server_name']}, "
         "alpn=h3, udp=1, allowInsecure=0"),
        "",
        "[Proxy Group]",
        f"{DISPLAY_NAME} = select, {VLESS_NAME}, {TUIC_NAME}, policy-select-name={VLESS_NAME}",
        "",
        "[Rule]",
        f"IP-CIDR,{ip}/32,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,ts.net,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
    ]
    lines += [f"IP-CIDR,{net},DIRECT,no-resolve" for net in PRIVATE_NETS]
    lines += [f"DOMAIN-SUFFIX,{domain},{DISPLAY_NAME}" for domain in PRIORITY_DOMAINS]
    lines += ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", f"FINAL,{DISPLAY_NAME}",
              "", "[Host]", "localhost = 127.0.0.1", ""]
    return "\n".join(lines)


def singbox_client(data, device, protocol, port):
    u = data["users"][device]
    outbound = {"type": protocol, "tag": "proxy", "server": data["server_ip"],
                "server_port": data["vless_port" if protocol == "vless" else "tuic_port"]}
    if protocol == "vless":
        outbound.update({"uuid": u["vless_uuid"], "flow": "xtls-rprx-vision",
                         "tls": {"enabled": True, "server_name": data["reality_sni"],
                                 "utls": {"enabled": True, "fingerprint": "chrome"},
                                 "reality": {"enabled": True, "public_key": data["reality_public_key"],
                                             "short_id": data["short_id"]}}})
    else:
        outbound.update({"uuid": u["tuic_uuid"], "password": u["tuic_password"], "congestion_control": "bbr",
                         "zero_rtt_handshake": False, "heartbeat": "10s",
                         "tls": {"enabled": True, "server_name": data["tuic_server_name"],
                                 "insecure": False, "alpn": ["h3"]}})
    return {"log": {"level": "warn", "timestamp": True},
            "inbounds": [{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound], "route": {"final": "proxy"}}


def yaml_dump(value, level=0):
    """Emit the conservative YAML subset used by these generated configs."""
    indent = "  " * level
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            k = json.dumps(str(key), ensure_ascii=False)
            if isinstance(item, (dict, list)) and item:
                lines.extend([f"{indent}{k}:", yaml_dump(item, level + 1)])
            else:
                lines.append(f"{indent}{k}: {json.dumps(item, ensure_ascii=False)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)) and item:
                lines.extend([f"{indent}-", yaml_dump(item, level + 1)])
            else:
                lines.append(f"{indent}- {json.dumps(item, ensure_ascii=False)}")
        return "\n".join(lines)
    raise ValueError("expected config object")


def private_write(path: Path, body: str):
    # Exclusive creation avoids following a pre-existing symlink or overwriting a working profile.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scope", choices=("all", "server", "clients", "shadowrocket"), default="all")
    args = parser.parse_args()
    data = validate(json.loads(args.input.read_text(encoding="utf-8")))
    if args.scope in ("all", "server"):
        private_write(args.out / "server" / "sb.json", json.dumps(server_config(data), indent=2) + "\n")
    if args.scope in ("all", "clients"):
        for index, device in enumerate(DEVICES):
            folder = args.out / "clients" / device
            vless, tuic = links(data, device)
            private_write(folder / "nodes.txt", vless + "\n" + tuic + "\n")
            private_write(folder / "vless.txt", vless + "\n")
            private_write(folder / "tuic5.txt", tuic + "\n")
            private_write(folder / "clash.yaml", yaml_dump(clash_config(data, device)) + "\n")
            for offset, protocol in enumerate(("vless", "tuic")):
                private_write(folder / f"sing-box-test-{protocol}.json",
                              json.dumps(singbox_client(data, device, protocol, 19080 + index * 2 + offset), indent=2) + "\n")
    if args.scope in ("all", "clients", "shadowrocket"):
        for device in DEVICES:
            private_write(args.out / "clients" / device / "shadowrocket.conf", shadowrocket_config(data, device))
    # Deliberately do not print secrets or generated links.
    print(json.dumps({"status": "rendered", "output": str(args.out.resolve()), "scope": args.scope,
                      "devices": list(DEVICES)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
