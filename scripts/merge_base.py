#!/usr/bin/env python3
"""Merge the user's local base rules with private per-device proxy nodes.

No network access or credential output. Existing files are never overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import quote

import render

GROUP = render.DISPLAY_NAME
CLASH_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
               "IP-ASN", "GEOIP", "DST-PORT", "SRC-PORT", "NETWORK", "PROCESS-NAME",
               "PROCESS-PATH"}


def sections_from_text(text):
    result = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*\[([^]]+)]\s*", line)
        if match:
            result.append((match.group(1), []))
        elif not result:
            result.append(("", [line]))
        else:
            result[-1][1].append(line)
    names = [name.lower() for name, _ in result if name]
    if len(names) != len(set(names)):
        raise ValueError("duplicate base sections are not supported")
    return result


def active(lines):
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith(("#", ";"))]


def add_list(value, additions):
    values = [v.strip() for v in value.split(",") if v.strip()]
    for item in additions:
        if item not in values:
            values.append(item)
    return ", ".join(values)


def native_general(lines, ip):
    updates = {
        "ipv6": "false",
        "prefer-ipv6": "false",
        "dns-server": f"https://1.1.1.1/dns-query#proxy={quote(GROUP, safe='')}",
        "fallback-dns-server": f"https://1.0.0.1/dns-query#proxy={quote(GROUP, safe='')}",
        "direct-dns-server": "system",
        "dns-direct-system": "true",
        "dns-direct-fallback-proxy": "false",
    }
    seen = set()
    result = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", ";")) or "=" not in line:
            result.append(line)
            continue
        key, value = [v.strip() for v in line.split("=", 1)]
        lowered = key.lower()
        if lowered == "skip-proxy":
            value = add_list(value, [f"{ip}/32", "100.64.0.0/10", "*.ts.net", "*.lan"])
        elif lowered == "tun-excluded-routes":
            value = add_list(value, [f"{ip}/32", "100.64.0.0/10"])
        elif lowered in updates:
            value = updates[lowered]
        seen.add(lowered)
        result.append(f"{key} = {value}")
    for key, value in updates.items():
        if key not in seen:
            result.append(f"{key} = {value}")
    for key, value in (("skip-proxy", f"{ip}/32, 100.64.0.0/10, *.ts.net, *.local, *.lan"),
                       ("tun-excluded-routes", f"{ip}/32, 100.64.0.0/10")):
        if key not in seen:
            result.append(f"{key} = {value}")
    return result


def rule_parts(line):
    parts = [value.strip() for value in line.split(",")]
    if len(parts) < 2:
        raise ValueError("malformed base rule")
    policy_index = 1 if parts[0].upper() in ("FINAL", "MATCH") else 2
    if len(parts) <= policy_index or parts[policy_index].upper() not in ("DIRECT", "PROXY"):
        raise ValueError("base rule policy is not DIRECT or PROXY")
    return parts, policy_index


def bypass_rules(ip):
    return [f"IP-CIDR,{ip}/32,DIRECT,no-resolve", "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,ts.net,DIRECT", "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT"]


def native_config(data, device, sections):
    generated = dict(sections_from_text(render.shadowrocket_config(data, device)))
    result = []
    for name, lines in sections:
        lowered = name.lower()
        if lowered in ("proxy", "proxy group"):
            raise ValueError("base already contains proxy sections; refusing to replace them")
        if lowered == "rule":
            result += ["[Proxy]", *generated["Proxy"], "", "[Proxy Group]",
                       f"{GROUP} = select, {render.VLESS_NAME}, {render.TUIC_NAME}, policy-select-name={render.VLESS_NAME}", "",
                       "[Rule]", "# Local direct exclusions added for this deployment.",
                       *bypass_rules(data["server_ip"]), "# Original base rules follow in their original order."]
            for line in lines:
                if line.strip() and not line.lstrip().startswith(("#", ";")):
                    parts, index = rule_parts(line)
                    if parts[index].upper() == "PROXY":
                        parts[index] = GROUP
                        line = ",".join(parts)
                result.append(line)
        else:
            if name:
                result.append(f"[{name}]")
            result += native_general(lines, data["server_ip"]) if lowered == "general" else lines
    return "\n".join(result).rstrip() + "\n"


def routing_only_config(body):
    """Drop only the embedded [Proxy] section; named groups use Home subscription nodes."""
    result = []
    dropping = False
    removed = 0
    for line in body.splitlines(keepends=True):
        match = re.fullmatch(r"\s*\[([^]]+)]\s*", line.rstrip("\r\n"))
        if match:
            dropping = match.group(1).lower() == "proxy"
            if dropping:
                removed += 1
        if not dropping:
            result.append(line)
    if removed != 1:
        raise ValueError("expected exactly one embedded Proxy section")
    return "".join(result)


def clash_config(data, device, sections):
    config = render.clash_config(data, device)
    rule_lines = dict((name.lower(), lines) for name, lines in sections)["rule"]
    translated = []
    omitted = []
    for line in active(rule_lines):
        parts, _ = rule_parts(line)
        kind = parts[0].upper()
        if kind in ("FINAL", "MATCH"):
            parts[0] = "MATCH"
        elif kind == "USER-AGENT":
            omitted.append(line)
            continue
        elif kind not in CLASH_TYPES:
            raise ValueError(f"base rule type cannot be translated: {kind}")
        translated.append(",".join(parts))
    config["rules"] = bypass_rules(data["server_ip"]) + translated
    hosts = {}
    for name, lines in sections:
        if name.lower() != "host":
            continue
        for line in active(lines):
            host, value = [part.strip() for part in line.split("=", 1)]
            # Only the direct scalar IPv4/IPv6 Host form is portable here.
            import ipaddress
            ipaddress.ip_address(value)
            hosts[host] = value
    if hosts:
        config["hosts"] = hosts
        config["dns"]["use-hosts"] = True
    comments = ["# Merged from the user's local Shadowrocket base; URL Rewrite is not portable."]
    comments += ["# Not portable to Mihomo (kept in native Shadowrocket): " + line for line in omitted]
    return "\n".join(comments) + "\n" + render.yaml_dump(config) + "\n", translated, omitted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--scope", choices=("all", "shadowrocket", "clash"), default="all")
    parser.add_argument("--native-routing-only", action="store_true",
                        help="omit native embedded nodes; requires matching Home subscription nodes")
    args = parser.parse_args()
    data = render.validate(json.loads(args.input.read_text()))
    sections = sections_from_text(args.base.read_text(encoding="utf-8-sig"))
    mapping = dict((name.lower(), lines) for name, lines in sections)
    if "general" not in mapping or "rule" not in mapping:
        raise ValueError("base requires General and Rule sections")
    if "mitm" in mapping:
        raise ValueError("MITM bases require a separate explicit review")
    original_rules = active(mapping["rule"])
    for line in original_rules:
        rule_parts(line)
    # Prepare every output before writing anything, so unknown rule types fail cleanly.
    outputs = []
    omitted = []
    translated = []
    for device in render.DEVICES:
        folder = args.out / "clients" / device
        if args.scope in ("all", "shadowrocket"):
            body = native_config(data, device, sections)
            outputs.append((folder / "shadowrocket.conf",
                            routing_only_config(body) if args.native_routing_only else body))
        if args.scope in ("all", "clash"):
            body, translated, omitted = clash_config(data, device, sections)
            outputs.append((folder / "clash.yaml", body))
    if (args.out / "merge-summary.json").exists() or (args.out / "merge-summary.json").is_symlink():
        raise FileExistsError("merge summary already exists; use a fresh output directory")
    if any(path.exists() or path.is_symlink() for path, _ in outputs):
        raise FileExistsError("a target file already exists; use a fresh output directory")
    for path, body in outputs:
        render.private_write(path, body)
    summary = {"status": "merged", "output": str(args.out.resolve()), "scope": args.scope,
               "base_rule_count": len(original_rules), "prepended_rule_count": len(bypass_rules(data["server_ip"])),
               "native_rule_count": len(original_rules) + len(bypass_rules(data["server_ip"])),
               "clash_translated_base_rule_count": len(translated), "clash_omitted_rule_count": len(omitted),
               "clash_omitted_rule_types": dict(Counter(rule.split(",", 1)[0] for rule in omitted)),
               "native_url_rewrite_count": len(active(mapping.get("url rewrite", []))),
               "host_count": len(active(mapping.get("host", []))),
               "files_written": len(outputs), "native_proxy_group": GROUP,
               "native_routing_only": args.native_routing_only,
               "windows_url_rewrite_supported": False}
    render.private_write(args.out / "merge-summary.json", json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
