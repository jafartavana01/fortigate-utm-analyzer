#!/usr/bin/env python3
"""
FortiGate UTM Security Analyzer v4.1.0
Author  : Jafar Tavana  (@jafartavana01)
License : MIT

Full FortiOS 6.x / 7.x / 8.0 config security analyzer.
Parses 'show full-configuration' output and produces severity-tagged
reports across every security plane:

  Management Plane  : admin accounts, interfaces, global hardening,
                      SNMP, SSH config, FIPS/CC, password-policy,
                      local-in (IPv4/IPv6), IKE global, CSF, DNS security
  Data Plane        : firewall policies (IPv4+IPv6), SSL/SSH inspection
                      (multi-version parser), AV (per-protocol 8.0 sub-blocks),
                      IPS, Web Filter, App Control, DNS Filter,
                      Virtual Patch, File Filter, WAF, Email Filter,
                      Video Filter, SCTP Filter, DoS Policy
  VPN               : IPsec Phase1/Phase2, SSL-VPN settings + portals
  Infrastructure    : HA, NTP, Logging (FA1/2/3, syslogd1-4, disk,
                      event filter), Security Fabric (CSF)
  New in FortiOS 8.0: LLM profile, ZTNA audit, anti-replay, policy expiry,
                      reputation, WAF-in-policy

All findings tagged CRITICAL / HIGH / MEDIUM / INFO.
--summary generates a scored executive report + JSON export.
"""

import argparse
import json
import re
import hashlib
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

__version__ = "4.1.0"

# ─────────────────────────────────────────────────────────────────────────────
# Generic Helpers
# ─────────────────────────────────────────────────────────────────────────────

def read_config(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")

def nv(v: Any) -> str:
    """Normalize a config value to a clean string."""
    if v is None:
        return ""
    s = str(v).strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s

def parse_set_line(line: str) -> Tuple[str, str]:
    m = re.match(r"set\s+(\S+)\s+(.+)", line.strip())
    if not m:
        return "", ""
    return m.group(1), m.group(2).strip()

def extract_block(text: str, block_name: str) -> List[Dict[str, Any]]:
    """
    Generic parser for:
      config <block_name>
          edit <id>
              set key value
          next
      end
    """
    lines = text.splitlines()
    objects, in_block, depth, current = [], False, 0, None
    for raw in lines:
        line = raw.strip()
        if line == f"config {block_name}":
            in_block, depth, current = True, 0, None
            continue
        if not in_block:
            continue
        if line.startswith("config ") and not line.startswith("config " + block_name):
            depth += 1
            continue
        if line == "end":
            if depth > 0:
                depth -= 1
                continue
            if current:
                objects.append(current)
            break
        if depth > 0:
            if current is not None and line.startswith("set "):
                k, v = parse_set_line(line)
                if k:
                    current[f"_sub_{k}"] = v
            continue
        if line.startswith("edit "):
            if current:
                objects.append(current)
            obj_id = line.split(None, 1)[1].strip().strip('"')
            current = {"_id": obj_id}
            continue
        if line == "next":
            if current:
                objects.append(current)
            current = None
            continue
        if current is None:
            continue
        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                current[k] = v
    return objects

def extract_flat_block(text: str, block_name: str) -> Dict[str, Any]:
    """Parser for flat single-object blocks like 'config system global'."""
    lines = text.splitlines()
    in_block, depth, cfg = False, 0, {}
    for raw in lines:
        line = raw.strip()
        if line == f"config {block_name}":
            in_block, depth, cfg = True, 0, {}
            continue
        if not in_block:
            continue
        if line.startswith("config "):
            depth += 1
            continue
        if line == "end":
            if depth > 0:
                depth -= 1
                continue
            break
        if depth > 0:
            continue
        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                cfg[k] = v
    return cfg

def extract_nested_block(text: str, outer: str, inner: str) -> Dict[str, Any]:
    """
    Extract a named nested sub-block inside a flat outer block.
    e.g. 'config system ntp' -> 'config ntpserver'
    Returns dict of {_id: {key: val}}.
    """
    lines = text.splitlines()
    in_outer = False
    in_inner = False
    result: Dict[str, Any] = {}
    current = None
    for raw in lines:
        line = raw.strip()
        if line == f"config {outer}":
            in_outer = True
            continue
        if not in_outer:
            continue
        if line == f"config {inner}":
            in_inner = True
            continue
        if in_inner:
            if line.startswith("edit "):
                if current:
                    result[current["_id"]] = current
                obj_id = line.split(None, 1)[1].strip().strip('"')
                current = {"_id": obj_id}
            elif line == "next":
                if current:
                    result[current["_id"]] = current
                current = None
            elif line == "end":
                if current:
                    result[current["_id"]] = current
                in_inner = False
            elif line.startswith("set ") and current is not None:
                k, v = parse_set_line(line)
                if k:
                    current[k] = v
        elif line == "end":
            break
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Parsers  (one per config section)
# ─────────────────────────────────────────────────────────────────────────────

def parse_firewall_policies(t):   return extract_block(t, "firewall policy")
def parse_firewall_policies6(t):  return extract_block(t, "firewall policy6")
def parse_ssl_profiles(t):        return extract_block(t, "firewall ssl-ssh-profile")
def parse_av_profiles(t):         return extract_block(t, "antivirus profile")
def parse_ips_sensors(t):         return extract_block(t, "ips sensor")
def parse_wf_profiles(t):         return extract_block(t, "webfilter profile")
def parse_app_profiles(t):        return extract_block(t, "application list")
def parse_dns_profiles(t):        return extract_block(t, "dnsfilter profile")
def parse_waf_profiles(t):        return extract_block(t, "waf profile")
def parse_email_profiles(t):      return extract_block(t, "emailfilter profile")
def parse_video_profiles(t):      return extract_block(t, "videofilter profile")
def parse_file_filter(t):         return extract_block(t, "file-filter profile")
def parse_virtual_patch(t):       return extract_block(t, "virtual-patch profile")
def parse_sctp_filter(t):         return extract_block(t, "sctp-filter profile")
def parse_ssh_filter(t):          return extract_block(t, "ssh-filter profile")
def parse_llm_profiles(t):        return extract_block(t, "llm profile")
def parse_admins(t):              return extract_block(t, "system admin")
def parse_interfaces(t):          return extract_block(t, "system interface")
def parse_local_in(t):            return extract_block(t, "firewall local-in-policy")
def parse_local_in6(t):           return extract_block(t, "firewall local-in-policy6")
def parse_vpn_phase1(t):          return extract_block(t, "vpn ipsec phase1-interface")
def parse_vpn_phase2(t):          return extract_block(t, "vpn ipsec phase2-interface")
def parse_snmp_community(t):      return extract_block(t, "system snmp community")
def parse_snmp_user(t):           return extract_block(t, "system snmp user")
def parse_dos_policy(t):          return extract_block(t, "firewall DoS-policy")
def parse_ssl_vpn_portals(t):     return extract_block(t, "vpn ssl web portal")
def parse_system_global(t):       return extract_flat_block(t, "system global")
def parse_ha(t):                  return extract_flat_block(t, "system ha")
def parse_ssl_vpn_settings(t):    return extract_flat_block(t, "vpn ssl settings")
def parse_log_fortianalyzer(t):   return extract_flat_block(t, "log fortianalyzer setting")
def parse_log_fortianalyzer2(t):  return extract_flat_block(t, "log fortianalyzer2 setting")
def parse_log_fortianalyzer3(t):  return extract_flat_block(t, "log fortianalyzer3 setting")
def parse_log_syslogd(t):         return extract_flat_block(t, "log syslogd setting")
def parse_log_syslogd2(t):        return extract_flat_block(t, "log syslogd2 setting")
def parse_log_syslogd3(t):        return extract_flat_block(t, "log syslogd3 setting")
def parse_log_syslogd4(t):        return extract_flat_block(t, "log syslogd4 setting")
def parse_log_setting(t):         return extract_flat_block(t, "log setting")
def parse_log_eventfilter(t):     return extract_flat_block(t, "log eventfilter")
def parse_log_disk_setting(t):    return extract_flat_block(t, "log disk setting")
def parse_log_disk_filter(t):     return extract_flat_block(t, "log disk filter")
def parse_snmp_sysinfo(t):        return extract_flat_block(t, "system snmp sysinfo")
def parse_system_dns(t):          return extract_flat_block(t, "system dns")
def parse_system_csf(t):          return extract_flat_block(t, "system csf")
def parse_system_fips(t):         return extract_flat_block(t, "system fips-cc")
def parse_password_policy(t):     return extract_flat_block(t, "system password-policy")
def parse_system_ike(t):          return extract_flat_block(t, "system ike")
def parse_system_ssh(t):          return extract_flat_block(t, "system ssh-config")
def parse_system_fortiguard(t):   return extract_flat_block(t, "system fortiguard")

def parse_ntp(text: str) -> Dict[str, Any]:
    cfg = extract_flat_block(text, "system ntp")
    cfg["servers"] = list(extract_nested_block(text, "system ntp", "ntpserver").values())
    return cfg

# ─────────────────────────────────────────────────────────────────────────────
# SSL/SSH Profile — v6.x flat + v7/8 per-protocol sub-block parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_ssl_profiles_v2(text: str) -> List[Dict[str, Any]]:
    """Parse every SSL/SSH profile block, including repeated VDOM sections.

    Only top-level edit/next delimit profiles. Nested config sections may have
    their own edit/next commands (for example, ssl-exempt); those must never
    terminate or replace an enclosing inspection profile.
    """
    profiles: List[Dict[str, Any]] = []
    current = None
    in_block = False
    nested_blocks: List[str] = []
    protocols = {"https", "ftps", "imaps", "pop3s", "smtps", "ssh",
                 "dot", "quic", "ftp", "imap", "pop3", "smtp"}

    for raw in text.splitlines():
        line = raw.strip()
        if not in_block:
            if line == "config firewall ssl-ssh-profile":
                in_block = True
                current = None
                nested_blocks = []
            continue

        if line.startswith("config "):
            nested_blocks.append(line[7:].strip())
            continue

        if line == "end":
            if nested_blocks:
                nested_blocks.pop()
            else:
                if current is not None:
                    profiles.append(current)
                current = None
                in_block = False  # Continue: another VDOM may declare profiles.
            continue

        if nested_blocks:
            # Known per-protocol settings belong to the enclosing profile.
            # Ignore nested table rows, including their edit/next delimiters.
            if (current is not None and len(nested_blocks) == 1
                    and nested_blocks[0] in protocols and line.startswith("set ")):
                key, value = parse_set_line(line)
                if key:
                    current[f"{nested_blocks[0]}.{key}"] = value
            continue

        if line.startswith("edit "):
            if current is not None:
                profiles.append(current)
            current = {"_id": line.split(None, 1)[1].strip().strip('"')}
        elif line == "next":
            if current is not None:
                profiles.append(current)
            current = None
        elif line.startswith("set ") and current is not None:
            key, value = parse_set_line(line)
            if key:
                current[key] = value

    return profiles

# ─────────────────────────────────────────────────────────────────────────────
# AV Profile — v8.0 per-protocol sub-block parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_av_profiles_v2(text: str) -> List[Dict[str, Any]]:
    """
    Handles FortiOS 8.0 AV profile per-protocol sub-block structure.
    Flat keys: feature-set, av-virus-log, fortisandbox-mode, etc.
    Nested keys prefixed: http.av-scan, smtp.outbreak-prevention, etc.
    """
    lines = text.splitlines()
    profiles: List[Dict[str, Any]] = []
    in_block = False
    current: Dict[str, Any] = {}
    sub_name: str = ""
    sub_depth = 0

    PROTOS = {"http", "https", "ftp", "smtp", "pop3", "imap", "mapi",
              "nntp", "cifs", "ssh", "websocket", "content-disarm", "nac-quar"}

    for raw in lines:
        line = raw.strip()

        if line == "config antivirus profile":
            in_block = True
            current = {}
            sub_name = ""
            sub_depth = 0
            continue
        if not in_block:
            continue

        if line == "end" and sub_depth == 0:
            if current:
                profiles.append(current)
            break

        if line.startswith("edit "):
            if current:
                profiles.append(current)
            obj_id = line.split(None, 1)[1].strip().strip('"')
            current = {"_id": obj_id}
            sub_name = ""
            sub_depth = 0
            continue

        if line == "next":
            if current:
                profiles.append(current)
            current = {}
            sub_name = ""
            sub_depth = 0
            continue

        if line.startswith("config ") and sub_depth == 0:
            candidate = line[7:].strip()
            if candidate in PROTOS:
                sub_name = candidate
                sub_depth = 1
                continue
            else:
                sub_depth += 1
                continue

        if sub_depth > 0:
            if line.startswith("config "):
                sub_depth += 1
            elif line == "end":
                sub_depth -= 1
                if sub_depth == 0:
                    sub_name = ""
            elif line.startswith("set ") and sub_name:
                k, v = parse_set_line(line)
                if k:
                    current[f"{sub_name}.{k}"] = v
            continue

        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                current[k] = v

    return profiles

# ─────────────────────────────────────────────────────────────────────────────
# Severity constants
# ─────────────────────────────────────────────────────────────────────────────

C, H, M, I = "CRITICAL", "HIGH", "MEDIUM", "INFO"

def f(sev: str, msg: str) -> str:
    return f"{sev}: {msg}"

# ─────────────────────────────────────────────────────────────────────────────
# Weakness functions
# ─────────────────────────────────────────────────────────────────────────────

# ── Firewall Policy ──────────────────────────────────────────────────────────

def fw_policy_weaknesses(p: Dict) -> List[str]:
    findings = []
    action     = nv(p.get("action", ""))
    utm        = nv(p.get("utm-status", ""))
    ips        = nv(p.get("ips-sensor", ""))
    av         = nv(p.get("av-profile", ""))
    wf         = nv(p.get("webfilter-profile", ""))
    dnsf       = nv(p.get("dnsfilter-profile", ""))
    app        = nv(p.get("application-list", ""))
    ssl        = nv(p.get("ssl-ssh-profile", ""))
    dlp        = nv(p.get("dlp-profile", "")) or nv(p.get("dlp-sensor", ""))
    casb       = nv(p.get("casb-profile", ""))
    waf        = nv(p.get("waf-profile", ""))
    email_f    = nv(p.get("emailfilter-profile", ""))
    file_f     = nv(p.get("file-filter-profile", ""))
    vpatch     = nv(p.get("virtual-patch-profile", ""))
    ssh_f      = nv(p.get("ssh-filter-profile", ""))
    llm        = nv(p.get("llm-profile", ""))
    logtraffic = nv(p.get("logtraffic", ""))
    logstart   = nv(p.get("logtraffic-start", ""))
    nat        = nv(p.get("nat", ""))
    srcaddr    = nv(p.get("srcaddr", "")) or nv(p.get("srcaddr6", ""))
    dstaddr    = nv(p.get("dstaddr", "")) or nv(p.get("dstaddr6", ""))
    service    = nv(p.get("service", ""))
    srcintf    = nv(p.get("srcintf", ""))
    dstintf    = nv(p.get("dstintf", ""))
    comments   = nv(p.get("comments", ""))
    status     = nv(p.get("status", "enable"))
    capture    = nv(p.get("capture-packet", ""))
    anti_rep   = nv(p.get("anti-replay", "enable"))
    inspect_m  = nv(p.get("inspection-mode", "flow"))
    policy_exp = nv(p.get("policy-expiry", ""))
    rep_min    = nv(p.get("reputation-minimum", ""))
    tcp_no_syn = nv(p.get("tcp-session-without-syn", "disable"))
    ztna       = nv(p.get("ztna-status", ""))
    log_http   = nv(p.get("log-http-transaction", ""))

    if action == "accept":
        if utm != "enable":
            findings.append(f(H, "UTM disabled on accept policy — all security profiles bypassed."))
        if not ips and not vpatch:
            findings.append(f(H, "No IPS sensor or virtual-patch profile — exploit traffic uninspected."))
        elif not ips and vpatch:
            findings.append(f(I, "IPS sensor missing; virtual-patch profile present but IPS is deeper coverage."))
        if not av:
            findings.append(f(H, "No antivirus profile — malware passes through undetected."))
        if not ssl:
            findings.append(f(H, "No SSL/SSH inspection profile — encrypted threats bypass all UTM."))
        if not wf:
            findings.append(f(M, "No web filter profile — malicious/uncategorized URLs allowed."))
        if not dnsf:
            findings.append(f(M, "No DNS filter — DNS-based C2, tunnelling, malware domains unblocked."))
        if not app:
            findings.append(f(M, "No application control — risky/shadow-IT apps may run freely."))
        if not dlp:
            findings.append(f(M, "No DLP profile — data exfiltration risk unaddressed."))
        if not casb:
            findings.append(f(I, "No CASB profile — unsanctioned cloud service usage not monitored."))
        if not waf:
            findings.append(f(I, "No WAF profile — web application layer attacks not inspected."))
        if not email_f:
            findings.append(f(I, "No email filter profile — if email flows through this policy, spam/phishing uninspected."))
        if not file_f:
            findings.append(f(I, "No file-filter profile — dangerous file types (executables, scripts) not blocked by policy."))
        if not vpatch:
            findings.append(f(I, "No virtual-patch profile — newly disclosed CVEs not virtually patched."))
        if not llm:
            findings.append(f(I, "No LLM profile (FortiOS 8.0) — AI/LLM traffic not inspected for data leakage."))

        if srcaddr in ("all", "") and dstaddr in ("all", "") and service in ("ALL", "all", ""):
            findings.append(f(C, "ANY-ANY-ANY accept policy — maximally permissive; full security review required."))
        elif srcaddr in ("all", "") and dstaddr in ("all", ""):
            findings.append(f(H, "Both source and destination are 'all' — extremely broad scope."))
        elif srcaddr in ("all", ""):
            findings.append(f(M, "Source address is 'all' — restrict to known subnets."))

        wan_hints = ("wan", "ppp", "vdsl", "adsl", "ftth", "internet", "outside", "untrust", "ext")
        lan_hints = ("lan", "port", "internal", "inside", "dmz", "trust", "mgmt")
        src_l, dst_l = srcintf.lower(), dstintf.lower()
        if any(w in src_l for w in wan_hints) and any(l in dst_l for l in lan_hints):
            findings.append(f(H, "Inbound WAN-to-internal accept policy — verify this is intentional."))

        if service in ("ALL", "all"):
            findings.append(f(M, "Service is ALL — restrict to required protocols only."))

        if inspect_m == "proxy":
            findings.append(f(I, "Inspection mode: proxy — thorough but higher latency; verify sizing."))

        if ztna != "enable":
            findings.append(f(I, "ZTNA not enabled on this policy — consider Zero Trust enforcement."))

        if not rep_min or rep_min == "0":
            findings.append(f(I, "reputation-minimum not set — FortiGuard IP reputation not enforced."))

        if anti_rep == "disable":
            findings.append(f(M, "Anti-replay protection disabled — replay attacks possible on this policy."))

        if tcp_no_syn != "disable":
            findings.append(f(M, f"tcp-session-without-syn is '{tcp_no_syn}' — stateless tracking risk."))

    if logtraffic in ("", "disable"):
        findings.append(f(H, "Traffic logging disabled — no visibility into flows matched by this policy."))
    elif logtraffic == "utm":
        findings.append(f(I, "Logging 'utm' only — consider 'all' for full flow visibility."))
    if logstart != "enable":
        findings.append(f(I, "logtraffic-start disabled — session start events not recorded."))
    if log_http != "enable" and action == "accept":
        findings.append(f(I, "log-http-transaction disabled — HTTP request details not captured."))

    if not comments:
        findings.append(f(I, "No policy comment — undocumented rules are an audit and compliance risk."))

    if policy_exp != "enable":
        name_lwr = nv(p.get("name", "")).lower()
        temp_keywords = ("temp", "test", "tmp", "trial", "poc", "demo", "lab")
        if any(kw in name_lwr for kw in temp_keywords):
            findings.append(f(M, "Policy name suggests temporary rule but policy-expiry is not set."))

    if status == "disable":
        findings.append(f(I, "Policy disabled — remove if no longer needed to reduce ruleset complexity."))

    if capture == "enable":
        findings.append(f(M, "Packet capture enabled — likely a debug artifact; disable in production."))

    if nat != "enable" and action == "accept":
        findings.append(f(I, "NAT disabled — verify internal IPs are not exposed."))

    return findings


# ── SSL/SSH Inspection Profile (v6.x flat + v7/8 per-proto) ──────────────────

def ssl_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name = nv(p.get("name", p.get("_id", "")))

    has_proto_keys = any(k.startswith("https.") or k.startswith("ftps.") for k in p)

    if has_proto_keys:
        caname   = nv(p.get("caname", ""))
        ssl_anom = nv(p.get("ssl-anomalies-log", "")) or nv(p.get("log-ssl-anomalies", ""))
        ech      = nv(p.get("encrypted-client-hello", ""))
        block_bl = nv(p.get("block-blacklisted-certificates", ""))

        if not caname:
            findings.append(f(H, f"SSL profile '{name}': no CA certificate — deep inspection fails silently."))
        if ssl_anom != "enable":
            findings.append(f(M, f"SSL profile '{name}': ssl-anomalies-log disabled — TLS errors unreported."))
        if block_bl != "enable":
            findings.append(f(M, f"SSL profile '{name}': blacklisted certificate blocking disabled."))
        if ech in ("", "disable"):
            findings.append(f(M, f"SSL profile '{name}': Encrypted Client Hello not handled — SNI hidden from inspection."))

        for proto in ("https", "ftps", "imaps", "pop3s", "smtps"):
            p_mode   = nv(p.get(f"{proto}.status", ""))
            p_trust  = nv(p.get(f"{proto}.untrusted-server-cert", ""))
            p_min    = nv(p.get(f"{proto}.min-allowed-ssl-version", ""))
            p_sni    = nv(p.get(f"{proto}.sni-strict", "")) or nv(p.get(f"{proto}.sni-check", ""))

            if p_mode in ("", "disable"):
                findings.append(f(M, f"SSL profile '{name}': {proto.upper()} inspection disabled — encrypted traffic on {proto} bypasses UTM."))
            if p_trust not in ("block", ""):
                findings.append(f(H, f"SSL profile '{name}': {proto.upper()} untrusted certs not blocked — MITM risk."))

            tls_map = {"ssl-3.0": 0, "tls-1.0": 1, "tls-1.1": 2, "tls-1.2": 3, "tls-1.3": 4}
            if p_min and p_min in tls_map:
                if tls_map[p_min] < 3:
                    findings.append(f(H, f"SSL profile '{name}': {proto.upper()} minimum TLS is {p_min} — deprecated protocol allowed."))
                elif p_min == "tls-1.2":
                    findings.append(f(I, f"SSL profile '{name}': {proto.upper()} minimum TLS 1.2 — consider enforcing TLS 1.3."))

            if p_sni in ("", "disable"):
                findings.append(f(M, f"SSL profile '{name}': {proto.upper()} SNI checking disabled — weaker domain validation."))

        ssh_mode = nv(p.get("ssh.inspect-all", "")) or nv(p.get("ssh.status", ""))
        if ssh_mode in ("", "disable"):
            findings.append(f(M, f"SSL profile '{name}': SSH inspection disabled — SSH tunnelling not inspected."))

        dot = nv(p.get("dot.status", "")) or nv(p.get("dns-over-tls", ""))
        if dot not in ("block", "inspect"):
            findings.append(f(M, f"SSL profile '{name}': DNS-over-TLS not blocked/inspected — DNS filter bypass possible."))

    else:
        mode       = nv(p.get("inspection-method", ""))
        caname     = nv(p.get("caname", ""))
        sni        = nv(p.get("sni-check", ""))
        untrusted  = nv(p.get("untrusted-cert", ""))
        expired    = nv(p.get("expired-cert", ""))
        invalid    = nv(p.get("invalid-cert", ""))
        revoked    = nv(p.get("revoked-server-cert", ""))
        log_anom   = nv(p.get("log-ssl-anomalies", ""))
        block_bl   = nv(p.get("block-blacklisted-certificates", ""))
        ech        = nv(p.get("encrypted-client-hello", ""))
        dot        = nv(p.get("dot", "")) or nv(p.get("dns-over-tls", ""))
        min_ver    = nv(p.get("min-allowed-ssl-version", ""))

        if not mode:
            findings.append(f(M, f"SSL profile '{name}': inspection mode not set."))
        elif mode == "certificate-inspection":
            findings.append(f(M, f"SSL profile '{name}': certificate-only inspection — TLS payload not decrypted."))
        elif mode in ("full-inspection", "deep-inspection"):
            if not caname:
                findings.append(f(H, f"SSL profile '{name}': deep inspection without CA cert — inspection fails."))

        if untrusted not in ("block", ""):
            findings.append(f(H, f"SSL profile '{name}': untrusted server certs not blocked — MITM risk."))
        if invalid not in ("block", ""):
            findings.append(f(H, f"SSL profile '{name}': invalid certs not blocked."))
        if expired not in ("block", ""):
            findings.append(f(M, f"SSL profile '{name}': expired certs not blocked."))
        if revoked == "allow":
            findings.append(f(H, f"SSL profile '{name}': revoked certificate action is 'allow'."))
        if block_bl != "enable":
            findings.append(f(M, f"SSL profile '{name}': blacklisted certificate blocking disabled."))
        if sni in ("", "disable"):
            findings.append(f(M, f"SSL profile '{name}': SNI checking disabled."))
        if log_anom != "enable":
            findings.append(f(M, f"SSL profile '{name}': SSL anomaly logging disabled."))
        if ech in ("", "disable"):
            findings.append(f(M, f"SSL profile '{name}': ECH not handled — SNI hidden from inspection."))
        if dot not in ("block", "inspect"):
            findings.append(f(M, f"SSL profile '{name}': DNS-over-TLS not blocked/inspected."))

        tls_map = {"ssl-3.0": 0, "tls-1.0": 1, "tls-1.1": 2, "tls-1.2": 3, "tls-1.3": 4}
        if min_ver and min_ver in tls_map:
            if tls_map[min_ver] < 3:
                findings.append(f(H, f"SSL profile '{name}': minimum TLS {min_ver} — deprecated."))
            elif min_ver == "tls-1.2":
                findings.append(f(I, f"SSL profile '{name}': TLS 1.2 minimum — consider TLS 1.3."))
        elif not min_ver:
            findings.append(f(M, f"SSL profile '{name}': minimum TLS version not set — downgrade possible."))

    return findings


# ── AV Profile (v8.0 sub-block aware) ───────────────────────────────────────

def av_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name         = nv(p.get("name", p.get("_id", "")))
    feature_set  = nv(p.get("feature-set", "flow"))
    av_log       = nv(p.get("av-virus-log", "enable"))
    ext_log      = nv(p.get("extended-log", "disable"))
    sandbox_mode = nv(p.get("fortisandbox-mode", ""))
    sandbox_err  = nv(p.get("fortisandbox-error-action", ""))
    sandbox_to   = nv(p.get("fortisandbox-timeout-action", ""))
    outbr_arch   = nv(p.get("outbreak-prevention-archive-scan", "enable"))
    mob_mal      = nv(p.get("mobile-malware-db", "enable"))
    ems_feed     = nv(p.get("ems-threat-feed", "disable"))
    ext_bl       = nv(p.get("external-blocklist-enable-all", "disable"))
    analytics_db = nv(p.get("analytics-db", "disable"))

    cdr_macro    = nv(p.get("content-disarm.office-macro", "enable"))
    cdr_embed    = nv(p.get("content-disarm.office-embed", "enable"))
    cdr_pdf_js   = nv(p.get("content-disarm.pdf-javacode", "enable"))
    cdr_err      = nv(p.get("content-disarm.error-action", "log-only"))
    cdr_detect   = nv(p.get("content-disarm.detect-only", "disable"))

    http_av   = nv(p.get("http.av-scan", "")) or nv(p.get("http", ""))
    https_av  = nv(p.get("https.av-scan", "")) or nv(p.get("https", ""))
    smtp_av   = nv(p.get("smtp.av-scan", "")) or nv(p.get("smtp", ""))
    pop3_av   = nv(p.get("pop3.av-scan", "")) or nv(p.get("pop3", ""))
    imap_av   = nv(p.get("imap.av-scan", "")) or nv(p.get("imap", ""))
    ftp_av    = nv(p.get("ftp.av-scan", "")) or nv(p.get("ftp", ""))
    cifs_av   = nv(p.get("cifs.av-scan", "")) or nv(p.get("cifs", ""))
    ssh_av    = nv(p.get("ssh.av-scan", ""))
    ws_av     = nv(p.get("websocket.av-scan", ""))

    http_outbr  = nv(p.get("http.outbreak-prevention", ""))
    https_outbr = nv(p.get("https.outbreak-prevention", ""))
    smtp_outbr  = nv(p.get("smtp.outbreak-prevention", ""))
    http_quar   = nv(p.get("http.quarantine", ""))
    http_sb     = nv(p.get("http.fortisandbox", ""))
    http_ndr    = nv(p.get("http.fortindr", ""))
    http_mstr   = nv(p.get("http.malware-stream", ""))

    if feature_set == "flow":
        findings.append(f(I, f"AV '{name}': flow-based mode — proxy mode provides deeper inspection when HW allows."))

    if av_log != "enable":
        findings.append(f(H, f"AV '{name}': av-virus-log disabled — malware detections not logged."))
    if ext_log != "enable":
        findings.append(f(I, f"AV '{name}': extended-log disabled — limited forensic detail in AV logs."))

    for proto, val, label, sev in [
        ("http",    http_av,  "HTTP",     M),
        ("https",   https_av, "HTTPS",    M),
        ("smtp",    smtp_av,  "SMTP",     M),
        ("pop3",    pop3_av,  "POP3",     I),
        ("imap",    imap_av,  "IMAP",     I),
        ("ftp",     ftp_av,   "FTP",      I),
        ("cifs",    cifs_av,  "CIFS/SMB", M),
        ("ssh",     ssh_av,   "SSH/SFTP", I),
        ("websocket", ws_av,  "WebSocket",I),
    ]:
        if val in ("", "disable"):
            findings.append(f(sev, f"AV '{name}': {label} not inspected."))
        elif val == "monitor":
            findings.append(f(M, f"AV '{name}': {label} av-scan in monitor mode — malware logged but not blocked."))

    if http_outbr in ("", "disable"):
        findings.append(f(M, f"AV '{name}': HTTP outbreak prevention disabled."))
    if https_outbr in ("", "disable"):
        findings.append(f(M, f"AV '{name}': HTTPS outbreak prevention disabled."))
    if smtp_outbr in ("", "disable"):
        findings.append(f(M, f"AV '{name}': SMTP outbreak prevention disabled."))
    if outbr_arch != "enable":
        findings.append(f(M, f"AV '{name}': outbreak-prevention-archive-scan disabled — archives not scanned for outbreaks."))

    if not sandbox_mode:
        findings.append(f(M, f"AV '{name}': FortiSandbox mode not configured — zero-day protection missing."))
    elif sandbox_mode == "analytics-everything":
        findings.append(f(I, f"AV '{name}': FortiSandbox in analytics-everything mode (post-transfer) — inline mode provides faster blocking."))
    if http_sb in ("", "disable"):
        findings.append(f(M, f"AV '{name}': FortiSandbox submission disabled for HTTP — zero-day files not submitted."))
    if sandbox_err == "log-only":
        findings.append(f(I, f"AV '{name}': FortiSandbox error action is log-only — scan errors allow files through."))
    if sandbox_to == "log-only":
        findings.append(f(I, f"AV '{name}': FortiSandbox timeout action is log-only — timeouts allow files through."))

    if http_ndr in ("", "disable"):
        findings.append(f(I, f"AV '{name}': FortiNDR scanning not enabled for HTTP."))

    if http_mstr in ("", "disable"):
        findings.append(f(M, f"AV '{name}': malware-stream (0-day stream) scanning disabled for HTTP."))

    if http_quar != "enable":
        findings.append(f(M, f"AV '{name}': quarantine not enabled — infected files not isolated."))

    if cdr_macro != "enable":
        findings.append(f(H, f"AV '{name}': CDR office-macro stripping disabled — weaponized macros pass through."))
    if cdr_embed != "enable":
        findings.append(f(M, f"AV '{name}': CDR office-embed stripping disabled — embedded OLE objects pass through."))
    if cdr_pdf_js != "enable":
        findings.append(f(M, f"AV '{name}': CDR pdf-javacode stripping disabled — PDF JS exploits pass through."))
    if cdr_err == "log-only":
        findings.append(f(M, f"AV '{name}': CDR error action is log-only — CDR engine errors allow files through."))
    if cdr_detect == "enable":
        findings.append(f(M, f"AV '{name}': CDR detect-only mode — content not actually disarmed, only detected."))

    if analytics_db != "enable":
        findings.append(f(I, f"AV '{name}': analytics-db (FortiSandbox signature database) not enabled."))
    if mob_mal != "enable":
        findings.append(f(I, f"AV '{name}': mobile-malware-db disabled."))
    if ems_feed != "enable":
        findings.append(f(I, f"AV '{name}': EMS threat feed not enabled — endpoint threat intel not used."))
    if ext_bl != "enable":
        findings.append(f(I, f"AV '{name}': external blocklist not fully enabled."))

    return findings


# ── IPS Sensor ──────────────────────────────────────────────────────────────

def ips_sensor_weaknesses(s: Dict) -> List[str]:
    findings = []
    name    = nv(s.get("name", s.get("_id", "")))
    block   = nv(s.get("block-malicious-url", ""))
    botnet  = nv(s.get("scan-botnet-connections", ""))
    ext_db  = nv(s.get("extended-db", ""))

    if block != "enable":
        findings.append(f(M, f"IPS '{name}': block-malicious-url disabled — known malicious URLs not blocked."))
    if botnet in ("", "disable"):
        findings.append(f(H, f"IPS '{name}': botnet C2 scanning disabled — infected host communication undetected."))
    elif botnet == "monitor":
        findings.append(f(M, f"IPS '{name}': botnet scanning monitor-only — C2 connections logged but not blocked."))
    if ext_db != "enable":
        findings.append(f(I, f"IPS '{name}': extended signature database not enabled — reduced CVE coverage."))

    return findings


# ── WAF Profile ──────────────────────────────────────────────────────────────

def waf_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name       = nv(p.get("name", p.get("_id", "")))
    method     = nv(p.get("method", ""))
    url_acc    = nv(p.get("url-access", ""))
    constraint = nv(p.get("constraint", ""))
    sig        = nv(p.get("signature", ""))
    addr_check = nv(p.get("address-list", ""))
    comment    = nv(p.get("comment", ""))

    if not sig:
        findings.append(f(H, f"WAF '{name}': no signature rules configured — no OWASP Top 10 protection."))
    if not method:
        findings.append(f(M, f"WAF '{name}': HTTP method restriction not configured — uncommon methods (TRACE, DELETE) allowed."))
    if not url_acc:
        findings.append(f(M, f"WAF '{name}': URL access rules not configured — directory traversal, path manipulation unguarded."))
    if not constraint:
        findings.append(f(M, f"WAF '{name}': constraint rules not set — oversized requests, header injection unguarded."))
    if not addr_check:
        findings.append(f(I, f"WAF '{name}': address allowlist/blocklist not configured."))
    if not comment:
        findings.append(f(I, f"WAF '{name}': no comment/description on profile."))

    return findings


# ── Web Filter ───────────────────────────────────────────────────────────────

def wf_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name       = nv(p.get("name", p.get("_id", "")))
    log_all    = nv(p.get("log-all-url", ""))
    safe_s     = nv(p.get("safe-search", ""))
    override   = nv(p.get("override", ""))
    web_log    = nv(p.get("web-content-log", ""))
    ftgd       = nv(p.get("ftgd-wf", ""))
    antiphish  = nv(p.get("antiphish", ""))

    if log_all != "enable":
        findings.append(f(M, f"WebFilter '{name}': log-all-url disabled — browsing not fully logged."))
    if safe_s not in ("enable", "url"):
        findings.append(f(I, f"WebFilter '{name}': safe search not enforced."))
    if override == "enable":
        findings.append(f(M, f"WebFilter '{name}': user override enabled — blocked categories bypassable by end users."))
    if web_log != "enable":
        findings.append(f(I, f"WebFilter '{name}': web-content-log disabled — limited forensic trail."))
    if antiphish != "enable":
        findings.append(f(M, f"WebFilter '{name}': anti-phishing not enabled — credential phishing undetected."))
    if not ftgd:
        findings.append(f(M, f"WebFilter '{name}': FortiGuard category filter (ftgd-wf) not configured."))

    return findings


# ── App Control ──────────────────────────────────────────────────────────────

def app_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name    = nv(p.get("name", p.get("_id", "")))
    log     = nv(p.get("log", ""))
    unknown = nv(p.get("unknown-application-action", ""))
    p2p     = nv(p.get("p2p-block-list", ""))
    control = nv(p.get("control-default-network-services", ""))

    if log != "enable":
        findings.append(f(M, f"AppControl '{name}': logging disabled — application usage not tracked."))
    if unknown == "pass":
        findings.append(f(M, f"AppControl '{name}': unknown applications permitted — unclassified traffic flows freely."))
    if not p2p:
        findings.append(f(I, f"AppControl '{name}': P2P block list not explicitly configured."))
    if control != "enable":
        findings.append(f(I, f"AppControl '{name}': default network service control not enabled."))

    return findings


# ── DNS Filter ───────────────────────────────────────────────────────────────

def dns_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name     = nv(p.get("name", p.get("_id", "")))
    botnet   = nv(p.get("block-botnet", ""))
    log_all  = nv(p.get("log-all-domain", ""))
    safe_s   = nv(p.get("safe-search", ""))
    ftgd     = nv(p.get("ftgd-dns", ""))
    extern   = nv(p.get("external-ip-blocklist", ""))

    if botnet != "enable":
        findings.append(f(H, f"DNS Filter '{name}': botnet domain blocking disabled — DNS C2 unblocked."))
    if log_all != "enable":
        findings.append(f(M, f"DNS Filter '{name}': log-all-domain disabled — DNS query log incomplete."))
    if safe_s != "enable":
        findings.append(f(I, f"DNS Filter '{name}': safe search DNS enforcement not enabled."))
    if ftgd != "enable":
        findings.append(f(M, f"DNS Filter '{name}': FortiGuard DNS rating not enabled — DNS category filtering inactive."))
    if not extern:
        findings.append(f(I, f"DNS Filter '{name}': external IP blocklist not linked — threat intel feeds not applied to DNS."))

    return findings


# ── Email Filter ─────────────────────────────────────────────────────────────

def email_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name     = nv(p.get("name", p.get("_id", "")))
    spam_log = nv(p.get("spam-log", ""))
    spam_fil = nv(p.get("spam-filtering", ""))
    ftgd_sp  = nv(p.get("fortishield", ""))
    dnsbl    = nv(p.get("spam-rbl-table", ""))
    phish    = nv(p.get("phishing-filter", ""))

    if spam_log != "enable":
        findings.append(f(M, f"EmailFilter '{name}': spam-log disabled — spam not logged."))
    if spam_fil != "enable":
        findings.append(f(M, f"EmailFilter '{name}': spam filtering not enabled."))
    if not ftgd_sp:
        findings.append(f(M, f"EmailFilter '{name}': FortiGuard spam service not configured."))
    if not dnsbl:
        findings.append(f(I, f"EmailFilter '{name}': DNS blacklist not configured."))
    if phish != "enable":
        findings.append(f(M, f"EmailFilter '{name}': phishing filter not enabled."))

    return findings


# ── Video Filter ─────────────────────────────────────────────────────────────

def video_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name   = nv(p.get("name", p.get("_id", "")))
    yt_res = nv(p.get("youtube-restrict", ""))
    log    = nv(p.get("log", ""))

    if not yt_res or yt_res == "none":
        findings.append(f(I, f"VideoFilter '{name}': YouTube restriction not configured."))
    if log != "enable":
        findings.append(f(I, f"VideoFilter '{name}': logging disabled."))

    return findings


# ── File Filter ──────────────────────────────────────────────────────────────

def file_filter_weaknesses(p: Dict) -> List[str]:
    findings = []
    name  = nv(p.get("name", p.get("_id", "")))
    log   = nv(p.get("log", ""))
    scan  = nv(p.get("scan-archive-contents", ""))

    if log != "enable":
        findings.append(f(M, f"FileFilter '{name}': logging disabled."))
    if scan != "enable":
        findings.append(f(M, f"FileFilter '{name}': archive content scanning disabled — malicious files inside archives bypass filter."))

    return findings


# ── Virtual Patch ────────────────────────────────────────────────────────────

def virtual_patch_weaknesses(p: Dict) -> List[str]:
    findings = []
    name  = nv(p.get("name", p.get("_id", "")))
    log   = nv(p.get("log", ""))
    action = nv(p.get("action", ""))

    if log != "enable":
        findings.append(f(M, f"VirtualPatch '{name}': logging disabled — virtual patch hits not recorded."))
    if action == "monitor":
        findings.append(f(M, f"VirtualPatch '{name}': action is monitor — CVE exploitation not blocked."))

    return findings


# ── LLM Profile (FortiOS 8.0) ────────────────────────────────────────────────

def llm_profile_weaknesses(p: Dict) -> List[str]:
    findings = []
    name    = nv(p.get("name", p.get("_id", "")))
    log     = nv(p.get("log", ""))
    dlp_chk = nv(p.get("dlp-check", ""))
    pii_chk = nv(p.get("pii-check", ""))
    prompt  = nv(p.get("prompt-injection-check", ""))
    jailbrk = nv(p.get("jailbreak-check", ""))

    if log != "enable":
        findings.append(f(M, f"LLM '{name}': logging disabled — AI traffic not logged."))
    if dlp_chk != "enable":
        findings.append(f(H, f"LLM '{name}': DLP check disabled — sensitive data may leak through AI API calls."))
    if pii_chk != "enable":
        findings.append(f(H, f"LLM '{name}': PII check disabled — personal data in AI prompts/responses undetected."))
    if prompt != "enable":
        findings.append(f(M, f"LLM '{name}': prompt injection check disabled — adversarial prompt attacks possible."))
    if jailbrk != "enable":
        findings.append(f(M, f"LLM '{name}': jailbreak check disabled — model safety bypass attempts undetected."))

    return findings


# ── Admin Accounts ───────────────────────────────────────────────────────────

def admin_weaknesses(a: Dict) -> List[str]:
    findings = []
    name      = nv(a.get("name", a.get("_id", "")))
    accprofile = nv(a.get("accprofile", ""))
    two_factor = nv(a.get("two-factor", "")) or nv(a.get("twofactor", ""))
    trusthosts = [nv(a.get(f"trusthost{i}", "")) for i in range(1, 11)]
    timeout    = nv(a.get("admintimeout", ""))
    password   = nv(a.get("password", ""))
    force_pw   = nv(a.get("force-password-change", ""))
    wildcard   = nv(a.get("wildcard", ""))

    valid_hosts = [th for th in trusthosts if th and th not in ("0.0.0.0 0.0.0.0", "")]
    if not valid_hosts:
        findings.append(f(H, f"Admin '{name}': no trusted-host restrictions — login from any IP permitted."))
    else:
        for th in valid_hosts:
            if "0.0.0.0" in th:
                findings.append(f(H, f"Admin '{name}': trusthost set to 0.0.0.0/0 — effectively unrestricted."))

    if accprofile == "super_admin":
        findings.append(f(H, f"Admin '{name}': super_admin profile — no least-privilege separation."))
    elif not accprofile:
        findings.append(f(M, f"Admin '{name}': no access profile assigned."))

    findings.extend(admin_mfa_findings(a))

    try:
        t = int(timeout)
        if t == 0:
            findings.append(f(H, f"Admin '{name}': session timeout 0 — sessions never expire."))
        elif t > 60:
            findings.append(f(M, f"Admin '{name}': session timeout {t} min — reduce to 15-30 min."))
        elif t > 30:
            findings.append(f(I, f"Admin '{name}': session timeout {t} min — consider tightening."))
    except (ValueError, TypeError):
        pass

    if password and password.lower() in ("admin", "password", "fortinet", "fortigate", "1234", "123456", "admin123"):
        findings.append(f(C, f"Admin '{name}': weak or default password detected."))

    if force_pw != "enable":
        findings.append(f(I, f"Admin '{name}': force-password-change not set — no mandatory rotation enforced."))

    if wildcard == "enable":
        findings.append(f(I, f"Admin '{name}': wildcard (LDAP group) account — verify group scope is restricted."))

    return findings


# ── Interfaces ───────────────────────────────────────────────────────────────

def interface_weaknesses(intf: Dict) -> List[str]:
    findings = []
    name        = nv(intf.get("name", intf.get("_id", "")))
    allowaccess = nv(intf.get("allowaccess", ""))
    role        = nv(intf.get("role", ""))
    intf_type   = nv(intf.get("type", ""))
    proxy_arp   = nv(intf.get("proxy-arp", ""))
    description = nv(intf.get("description", ""))

    aa = allowaccess.split()

    if "http" in aa:
        findings.append(f(H, f"Interface '{name}': HTTP management enabled — credentials in cleartext."))
    if "telnet" in aa:
        findings.append(f(H, f"Interface '{name}': Telnet enabled — fully unencrypted management."))

    if role == "wan":
        if "https" in aa:
            findings.append(f(H, f"Interface '{name}' (WAN): HTTPS management exposed to internet."))
        if "ssh" in aa:
            findings.append(f(H, f"Interface '{name}' (WAN): SSH management exposed to internet — brute-force risk."))
        if "ping" in aa:
            findings.append(f(M, f"Interface '{name}' (WAN): ping/ICMP enabled — device fingerprinting risk."))
        if "snmp" in aa:
            findings.append(f(H, f"Interface '{name}' (WAN): SNMP accessible from internet."))
        if "fabric" in aa:
            findings.append(f(H, f"Interface '{name}' (WAN): Security Fabric port on WAN — should not face internet."))
        if "fmg-access" in aa:
            findings.append(f(H, f"Interface '{name}' (WAN): FortiManager access on WAN interface."))

    if not description and intf_type not in ("loopback", "tunnel"):
        findings.append(f(I, f"Interface '{name}': no description — undocumented interfaces are an audit risk."))

    if proxy_arp == "enable":
        findings.append(f(I, f"Interface '{name}': proxy ARP enabled — may cause unexpected traffic interception."))

    return findings


# ── Global Hardening ─────────────────────────────────────────────────────────

def global_hardening_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    strong_crypto    = nv(cfg.get("strong-crypto", ""))
    static_ciphers   = nv(cfg.get("ssl-static-key-ciphers", ""))
    dh_params        = nv(cfg.get("dh-params", ""))
    lock_thr         = nv(cfg.get("admin-lockout-threshold", ""))
    lock_dur         = nv(cfg.get("admin-lockout-duration", ""))
    admintimeout     = nv(cfg.get("admintimeout", ""))
    hostname         = nv(cfg.get("hostname", ""))
    pre_banner       = nv(cfg.get("pre-login-banner", ""))
    post_banner      = nv(cfg.get("post-login-banner", ""))
    https_redir      = nv(cfg.get("admin-https-redirect", ""))
    gui_cert         = nv(cfg.get("admin-server-cert", ""))
    pw_policy        = nv(cfg.get("admin-password-policy", ""))
    revision_backup  = nv(cfg.get("revision-image-auto-backup", ""))
    rest_api         = nv(cfg.get("admin-rest-api", ""))
    gui_allow_un     = nv(cfg.get("gui-allow-unnamed-policy", ""))

    if strong_crypto != "enable":
        findings.append(f(H, "Global: strong-crypto disabled — weak ciphers (RC4/DES/MD5) may be negotiated for management TLS."))
    if static_ciphers != "disable":
        findings.append(f(M, "Global: ssl-static-key-ciphers not disabled — forward secrecy not enforced."))

    try:
        dh_val = int(dh_params)
        if dh_val < 2048:
            findings.append(f(C, f"Global: DH params {dh_val}-bit — critically weak; upgrade to 4096+ immediately."))
        elif dh_val < 4096:
            findings.append(f(H, f"Global: DH params {dh_val}-bit — below 4096-bit recommendation."))
        elif dh_val < 8192:
            findings.append(f(M, f"Global: DH params {dh_val}-bit — 8192 bits preferred for strongest forward secrecy."))
    except (ValueError, TypeError):
        if not dh_params:
            findings.append(f(M, "Global: DH params not configured — system default DH group in use."))

    try:
        thr = int(lock_thr)
        if thr == 0:
            findings.append(f(H, "Global: admin lockout threshold 0 — brute-force lockout disabled."))
        elif thr > 5:
            findings.append(f(M, f"Global: admin lockout threshold {thr} — consider 3 attempts max."))
    except (ValueError, TypeError):
        findings.append(f(M, "Global: admin lockout threshold not configured."))

    try:
        dur = int(lock_dur)
        if dur == 0:
            findings.append(f(H, "Global: admin lockout duration 0 — account unlocks immediately."))
        elif dur < 60:
            findings.append(f(M, f"Global: admin lockout duration {dur}s — consider 300s (5 min) minimum."))
    except (ValueError, TypeError):
        findings.append(f(M, "Global: admin lockout duration not configured."))

    try:
        t = int(admintimeout)
        if t == 0:
            findings.append(f(H, "Global: admin session timeout 0 — sessions never expire."))
        elif t > 60:
            findings.append(f(M, f"Global: admin timeout {t} min — reduce to 15-30 min."))
    except (ValueError, TypeError):
        pass

    if pre_banner != "enable":
        findings.append(f(I, "Global: pre-login-banner disabled — no legal warning before authentication."))
    if post_banner != "enable":
        findings.append(f(I, "Global: post-login-banner disabled — no acceptable-use notice after login."))
    if https_redir != "enable":
        findings.append(f(M, "Global: admin-https-redirect not enabled — HTTP management not auto-redirected to HTTPS."))
    if not gui_cert or gui_cert in ("self-sign", ""):
        findings.append(f(I, "Global: management GUI using self-signed certificate."))
    if hostname.lower() in ("fortigate", "fortiwifi", ""):
        findings.append(f(I, f"Global: default hostname '{hostname}' — change to naming convention to reduce fingerprinting."))
    if revision_backup != "enable":
        findings.append(f(I, "Global: revision-image-auto-backup disabled — config versioning not automated."))
    if pw_policy != "enable":
        findings.append(f(M, "Global: admin-password-policy not enabled — no complexity requirements enforced."))
    if gui_allow_un == "enable":
        findings.append(f(M, "Global: gui-allow-unnamed-policy enabled — unnamed/undocumented policies can be saved."))
    if rest_api == "enable":
        findings.append(f(I, "Global: REST API admin enabled — ensure API keys are rotated and scoped appropriately."))

    findings.extend(crypto_transport_weaknesses(cfg))
    return findings


# ── Password Policy ───────────────────────────────────────────────────────────

def password_policy_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    status     = nv(cfg.get("status", ""))
    min_len    = nv(cfg.get("min-length", ""))
    must_cont  = nv(cfg.get("must-contain", ""))
    expire_s   = nv(cfg.get("expire-status", ""))
    expire_d   = nv(cfg.get("expire-day", ""))
    reuse      = nv(cfg.get("reuse-password", ""))

    if status != "enable":
        findings.append(f(H, "PasswordPolicy: password policy disabled — no enforced complexity requirements."))
    else:
        try:
            ml = int(min_len)
            if ml < 12:
                findings.append(f(M, f"PasswordPolicy: minimum length {ml} — recommend 12+ characters."))
        except (ValueError, TypeError):
            findings.append(f(M, "PasswordPolicy: min-length not set."))

        if not must_cont:
            findings.append(f(M, "PasswordPolicy: must-contain not configured — no complexity rules (upper/lower/digit/special)."))

        if expire_s != "enable":
            findings.append(f(I, "PasswordPolicy: password expiry not enabled — passwords never forced to rotate."))
        else:
            try:
                ed = int(expire_d)
                if ed > 90:
                    findings.append(f(I, f"PasswordPolicy: password expire-day is {ed} days — consider 90 days maximum."))
            except (ValueError, TypeError):
                pass

        if reuse == "enable":
            findings.append(f(M, "PasswordPolicy: password reuse permitted — users can reuse previous passwords."))

    return findings


# ── SSH Configuration ─────────────────────────────────────────────────────────

def ssh_config_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    enc_algos  = nv(cfg.get("encryption", ""))
    mac_algos  = nv(cfg.get("integrity", ""))
    kex        = nv(cfg.get("kex", ""))
    weak_enc   = ("arcfour", "3des", "blowfish", "cast128", "des")
    weak_mac   = ("md5", "sha1", "ripemd")
    weak_kex   = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")

    if enc_algos:
        for w in weak_enc:
            if w in enc_algos.lower():
                findings.append(f(H, f"SSH: weak cipher '{w}' in encryption algorithms — remove from allowed list."))
    if mac_algos:
        for w in weak_mac:
            if w in mac_algos.lower():
                findings.append(f(M, f"SSH: weak MAC '{w}' in integrity algorithms."))
    if kex:
        for w in weak_kex:
            if w in kex.lower().split():
                findings.append(f(H, f"SSH: weak key-exchange '{w}' — insecure DH group."))
    if not enc_algos and not mac_algos:
        findings.append(f(I, "SSH: cipher/MAC restrictions not configured — system defaults may include weak algorithms."))

    findings.extend(crypto_transport_weaknesses(cfg))
    return findings


# ── SNMP ──────────────────────────────────────────────────────────────────────

def snmp_sysinfo_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    status      = nv(cfg.get("status", ""))
    description = nv(cfg.get("description", ""))

    if status == "enable":
        if not description:
            findings.append(f(I, "SNMP: sysDescription not set — device fingerprinting possible."))
    return findings

def snmp_community_weaknesses(c: Dict) -> List[str]:
    findings = []
    name    = nv(c.get("name", c.get("_id", "")))
    events  = nv(c.get("events", ""))
    status  = nv(c.get("status", "enable"))

    weak_names = ("public", "private", "admin", "monitor", "snmp", "community", "guest", "default")
    if name.lower() in weak_names:
        findings.append(f(C, f"SNMP community '{name}': default/common community string — easily guessable."))
    if status == "enable":
        hosts = nv(c.get("_sub_ip", ""))
        if not hosts or hosts in ("0.0.0.0 0.0.0.0", ""):
            findings.append(f(H, f"SNMP community '{name}': no host restriction — community accessible from any IP."))
        if "trap" in events.lower() and not hosts:
            findings.append(f(M, f"SNMP community '{name}': trap events enabled with no host restriction."))

    return findings

def snmp_user_weaknesses(u: Dict) -> List[str]:
    findings = []
    name      = nv(u.get("name", u.get("_id", "")))
    auth      = nv(u.get("auth-proto", ""))
    priv      = nv(u.get("priv-proto", ""))
    security  = nv(u.get("security-level", ""))

    if security == "no-auth-no-priv":
        findings.append(f(H, f"SNMPv3 user '{name}': no authentication, no privacy — plaintext SNMP v3 (equivalent to v1/v2c)."))
    elif security == "auth-no-priv":
        findings.append(f(M, f"SNMPv3 user '{name}': authenticated but no privacy (no encryption) — SNMP data in cleartext."))

    if auth in ("md5", ""):
        findings.append(f(M, f"SNMPv3 user '{name}': auth-proto MD5 — upgrade to SHA-256 or SHA-512."))
    if priv in ("des", ""):
        findings.append(f(H, f"SNMPv3 user '{name}': priv-proto DES — upgrade to AES-256."))

    return findings


# ── System DNS ────────────────────────────────────────────────────────────────

def dns_system_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    primary   = nv(cfg.get("primary", ""))
    secondary = nv(cfg.get("secondary", ""))
    dnssec    = nv(cfg.get("dnssec-validation", ""))
    dot       = nv(cfg.get("dns-over-tls", "")) or nv(cfg.get("protocol", ""))

    if not primary:
        findings.append(f(M, "SystemDNS: no primary DNS server configured."))
    if not secondary:
        findings.append(f(I, "SystemDNS: no secondary DNS server — single point of failure for DNS resolution."))
    if dnssec != "enable":
        findings.append(f(M, "SystemDNS: DNSSEC validation disabled — DNS response spoofing/poisoning possible."))
    if "dot" not in (dot or ""):
        findings.append(f(I, "SystemDNS: DNS-over-TLS not configured for system DNS — FortiGate's own DNS queries unencrypted."))

    return findings


# ── IKE Global (FortiOS 8.0) ─────────────────────────────────────────────────

def ike_global_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    ikev1_disable = nv(cfg.get("ikev1-disable", ""))
    aggressive    = nv(cfg.get("ike1-aggressive-mode-disable", ""))
    dhgrp         = nv(cfg.get("dh-group", ""))
    hash_alg      = nv(cfg.get("hash-algorithm", ""))

    if ikev1_disable != "enable":
        findings.append(f(M, "IKE Global: IKEv1 not globally disabled — consider disabling if all peers support IKEv2."))
    if aggressive != "enable":
        findings.append(f(H, "IKE Global: IKEv1 aggressive mode not globally disabled — PSK hash exposure risk."))

    weak_dh = {"1", "2", "5"}
    if dhgrp:
        for grp in dhgrp.split():
            if grp in weak_dh:
                findings.append(f(H, f"IKE Global: DH group {grp} in allowed list — weak, below 2048-bit."))

    if hash_alg and "md5" in hash_alg.lower():
        findings.append(f(H, "IKE Global: MD5 in hash algorithm list — deprecated, collision vulnerable."))
    if hash_alg and "sha1" in hash_alg.lower():
        findings.append(f(M, "IKE Global: SHA-1 in hash algorithm list — deprecated; use SHA-256+."))

    return findings


# ── VPN IPsec Phase1 ─────────────────────────────────────────────────────────

def vpn_phase1_weaknesses(p: Dict) -> List[str]:
    findings = []
    name      = nv(p.get("name", p.get("_id", "")))
    ike_ver   = nv(p.get("ike-version", ""))
    mode      = nv(p.get("mode", ""))
    authmethod= nv(p.get("authmethod", ""))
    proposal  = nv(p.get("proposal", ""))
    dhgrp     = nv(p.get("dhgrp", ""))
    psk       = nv(p.get("psksecret", ""))
    dpd       = nv(p.get("dpd", ""))
    rekey     = nv(p.get("rekey", ""))
    lifetime  = nv(p.get("keylifetime", ""))

    if ike_ver == "1":
        findings.append(f(M, f"VPN '{name}': IKEv1 — upgrade to IKEv2 (RFC 7296) for improved security."))
    elif not ike_ver:
        findings.append(f(I, f"VPN '{name}': IKE version not set — may default to IKEv1."))

    if ike_ver == "1" and mode == "aggressive":
        findings.append(f(H, f"VPN '{name}': IKEv1 aggressive mode — PSK hash sent in cleartext, offline cracking possible."))

    weak_algos = ["des", "3des", "md5", "sha1", "null"]
    if proposal:
        for w in weak_algos:
            if w in proposal.lower():
                findings.append(f(H, f"VPN '{name}': weak algorithm '{w.upper()}' in IKE proposal — use AES256/SHA256+."))

    weak_dh = {"1", "2", "5"}
    if dhgrp:
        for grp in dhgrp.split():
            if grp in weak_dh:
                findings.append(f(H, f"VPN '{name}': DH group {grp} is below 2048-bit."))

    if authmethod == "psk":
        findings.append(f(M, f"VPN '{name}': PSK authentication — certificate-based auth is stronger."))
        if psk and len(psk) < 20:
            findings.append(f(H, f"VPN '{name}': PSK appears short (<20 chars) — use 32+ random characters."))

    if dpd in ("", "disable"):
        findings.append(f(I, f"VPN '{name}': Dead Peer Detection disabled — stale tunnels persist."))
    if rekey == "disable":
        findings.append(f(M, f"VPN '{name}': rekey disabled — long-lived session keys reduce forward secrecy."))

    try:
        lt = int(lifetime)
        if lt > 86400:
            findings.append(f(M, f"VPN '{name}': IKE key lifetime {lt}s exceeds 24h — reduce to 8h or less."))
    except (ValueError, TypeError):
        pass

    return findings


# ── VPN IPsec Phase2 ─────────────────────────────────────────────────────────

def vpn_phase2_weaknesses(p: Dict) -> List[str]:
    findings = []
    name     = nv(p.get("name", p.get("_id", "")))
    proposal = nv(p.get("proposal", ""))
    pfs      = nv(p.get("pfs", ""))
    dhgrp    = nv(p.get("dhgrp", ""))
    lifetime = nv(p.get("keylifetime-seconds", "")) or nv(p.get("keylifeseconds", ""))
    replay   = nv(p.get("replay", ""))

    weak_algos = ["des", "3des", "md5", "sha1", "null"]
    if proposal:
        for w in weak_algos:
            if w in proposal.lower():
                findings.append(f(H, f"Phase2 '{name}': weak algorithm '{w.upper()}' in ESP proposal."))

    if pfs in ("", "disable"):
        findings.append(f(H, f"Phase2 '{name}': PFS disabled — session key compromise exposes all past sessions."))
    else:
        weak_dh = {"1", "2", "5"}
        if dhgrp:
            for grp in dhgrp.split():
                if grp in weak_dh:
                    findings.append(f(H, f"Phase2 '{name}': PFS DH group {grp} is weak."))

    if replay == "disable":
        findings.append(f(M, f"Phase2 '{name}': anti-replay disabled — packet replay attacks possible on this tunnel."))

    try:
        lt = int(lifetime)
        if lt > 28800:
            findings.append(f(M, f"Phase2 '{name}': key lifetime {lt}s exceeds 8h — shorter rekey recommended."))
        elif lt < 300:
            findings.append(f(I, f"Phase2 '{name}': key lifetime {lt}s very short — excessive rekey overhead."))
    except (ValueError, TypeError):
        pass

    return findings


# ── SSL-VPN ───────────────────────────────────────────────────────────────────

def ssl_vpn_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    status      = nv(cfg.get("status", ""))
    port        = nv(cfg.get("port", ""))
    cert        = nv(cfg.get("servercert", ""))
    tls10       = nv(cfg.get("tlsv1-0", ""))
    tls11       = nv(cfg.get("tlsv1-1", ""))
    tls12       = nv(cfg.get("tlsv1-2", ""))
    login_limit = nv(cfg.get("login-attempt-limit", ""))
    login_block = nv(cfg.get("login-block-time", ""))
    idle_to     = nv(cfg.get("idle-timeout", ""))
    auth_to     = nv(cfg.get("auth-timeout", ""))
    src_addr    = nv(cfg.get("source-address", ""))
    dtls        = nv(cfg.get("dtls-tunnel", ""))
    client_cert = nv(cfg.get("client-cert", ""))

    if status == "enable":
        if port in ("443", ""):
            findings.append(f(I, "SSL-VPN: running on default port 443 — easily discoverable; consider non-standard port."))
        if not cert or cert == "self-sign":
            findings.append(f(M, "SSL-VPN: self-signed certificate — clients cannot properly validate server identity."))
        if tls10 == "enable":
            findings.append(f(H, "SSL-VPN: TLS 1.0 permitted — deprecated protocol with known attacks (BEAST/POODLE)."))
        if tls11 == "enable":
            findings.append(f(M, "SSL-VPN: TLS 1.1 permitted — deprecated; enforce TLS 1.2 minimum."))
        if tls12 != "enable":
            findings.append(f(M, "SSL-VPN: TLS 1.2 not explicitly enabled — verify TLS version support."))

        try:
            if int(login_limit) == 0:
                findings.append(f(H, "SSL-VPN: login attempt limit 0 — brute-force protection disabled."))
            elif int(login_limit) > 5:
                findings.append(f(M, f"SSL-VPN: {login_limit} login attempts before lockout — reduce to 3-5."))
        except (ValueError, TypeError):
            findings.append(f(M, "SSL-VPN: login-attempt-limit not configured."))

        try:
            if int(login_block) < 60:
                findings.append(f(M, f"SSL-VPN: login block time {login_block}s — recommend 300s to deter brute-force."))
        except (ValueError, TypeError):
            pass

        try:
            if int(idle_to) == 0:
                findings.append(f(H, "SSL-VPN: idle timeout 0 — sessions never timeout."))
            elif int(idle_to) > 1800:
                findings.append(f(M, f"SSL-VPN: idle timeout {idle_to}s exceeds 30 min."))
        except (ValueError, TypeError):
            pass

        try:
            if int(auth_to) > 28800:
                findings.append(f(M, f"SSL-VPN: auth timeout {auth_to}s exceeds 8h — force re-authentication more frequently."))
        except (ValueError, TypeError):
            pass

        if not src_addr or src_addr in ("all", ""):
            findings.append(f(M, "SSL-VPN: source-address not restricted — any internet IP can attempt authentication."))

        if client_cert != "enable":
            findings.append(f(M, "SSL-VPN: client certificate not required — password-only auth is weaker."))

        if dtls == "enable":
            findings.append(f(I, "SSL-VPN: DTLS tunnel enabled — verify UDP/443 firewall rules are appropriate."))

    return findings

def ssl_vpn_portal_weaknesses(p: Dict) -> List[str]:
    findings = []
    name      = nv(p.get("name", p.get("_id", "")))
    split_tun = nv(p.get("split-tunneling", ""))
    ftp_proxy = nv(p.get("ftp-proxy", ""))
    smb_proxy = nv(p.get("smb-proxy", ""))
    os_check  = nv(p.get("os-check", ""))
    limit_user = nv(p.get("limit-user-logins", ""))

    if split_tun == "enable":
        findings.append(f(H, f"SSL-VPN portal '{name}': split tunneling enabled — non-VPN traffic bypasses FortiGate entirely."))
    if ftp_proxy == "enable":
        findings.append(f(I, f"SSL-VPN portal '{name}': FTP proxy enabled — verify if required."))
    if smb_proxy == "enable":
        findings.append(f(I, f"SSL-VPN portal '{name}': SMB proxy enabled — file share access via web portal."))
    if os_check != "enable":
        findings.append(f(M, f"SSL-VPN portal '{name}': OS check not enabled — non-compliant endpoints can connect."))
    if limit_user != "enable":
        findings.append(f(I, f"SSL-VPN portal '{name}': concurrent login limit not enabled — account sharing undetected."))

    return findings


# ── HA ────────────────────────────────────────────────────────────────────────

def ha_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    mode      = nv(cfg.get("mode", ""))
    password  = nv(cfg.get("password", ""))
    hbdev     = nv(cfg.get("hbdev", ""))
    monitor   = nv(cfg.get("monitor", ""))
    syncconf  = nv(cfg.get("sync-config", ""))
    encrypt   = nv(cfg.get("hb-encryption", "")) or nv(cfg.get("encrypt-ha-heartbeat", ""))
    session_pickup = nv(cfg.get("session-pickup", ""))
    mgmt_intf = nv(cfg.get("ha-mgmt-status", ""))

    if mode in ("a-p", "a-a"):
        if not password:
            findings.append(f(H, "HA: cluster has no password — any FortiGate can join."))
        elif len(password) < 16:
            findings.append(f(M, "HA: cluster password short — use 16+ random characters."))

        if encrypt != "enable":
            findings.append(f(M, "HA: heartbeat traffic not encrypted — sync data in cleartext on heartbeat interfaces."))
        if not hbdev:
            findings.append(f(M, "HA: heartbeat device not configured."))
        if not monitor:
            findings.append(f(M, "HA: interface monitoring not configured — link failures may not trigger failover."))
        if syncconf != "enable":
            findings.append(f(I, "HA: config sync disabled — secondary may diverge from primary."))
        if session_pickup != "enable":
            findings.append(f(I, "HA: session pickup disabled — active sessions dropped on failover."))
        if mgmt_intf != "enable":
            findings.append(f(I, "HA: dedicated HA management interface not configured."))

    elif mode == "standalone":
        findings.append(f(I, "HA: standalone mode — no redundancy, single point of failure."))
    elif not mode:
        findings.append(f(I, "HA: HA mode not configured — standalone operation assumed."))

    return findings


# ── NTP ───────────────────────────────────────────────────────────────────────

def ntp_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    ntpsync  = nv(cfg.get("ntpsync", ""))
    ntptype  = nv(cfg.get("type", ""))
    interval = nv(cfg.get("syncinterval", ""))
    src_ip   = nv(cfg.get("source-ip", ""))
    srv_mode = nv(cfg.get("server-mode", ""))
    auth     = nv(cfg.get("authentication", ""))
    ntpv3    = nv(cfg.get("ntpv3", ""))
    servers  = cfg.get("servers", []) or []

    if ntpsync != "enable":
        findings.append(f(H, "NTP: sync disabled — log timestamps unreliable, forensic correlation compromised."))
    if ntptype == "custom":
        if not servers:
            findings.append(f(M, "NTP: custom type with no servers — sync will fail."))
        elif len(servers) == 1:
            findings.append(f(I, "NTP: single server — no redundancy."))
    if srv_mode == "enable":
        findings.append(f(I, "NTP: FortiGate acting as NTP server — verify this is intentional."))
    if auth != "enable":
        findings.append(f(M, "NTP: authentication disabled — NTP spoofing possible (RFC 8633 recommends auth)."))
    else:
        if ntpv3 != "enable":
            findings.append(f(M, "NTP: authentication enabled but NTPv3 not explicitly set."))
    if not src_ip:
        findings.append(f(I, "NTP: source-ip not configured — NTP sourced from outgoing interface IP."))

    try:
        iv = int(interval)
        if iv < 10:
            findings.append(f(I, f"NTP: sync interval {iv} min — very frequent."))
        elif iv > 1440:
            findings.append(f(M, f"NTP: sync interval {iv} min — too infrequent; clock drift risk."))
    except (ValueError, TypeError):
        pass

    return findings


# ── Local-in Policy ───────────────────────────────────────────────────────────

def local_in_weaknesses(lip: Dict) -> List[str]:
    findings = []
    intf    = nv(lip.get("intf", ""))
    srcaddr = nv(lip.get("srcaddr", ""))
    service = nv(lip.get("service", ""))
    action  = nv(lip.get("action", ""))

    if not intf:
        findings.append(f(M, "Local-in: policy without specific interface binding — applies to all interfaces."))
    if srcaddr in ("all", ""):
        findings.append(f(H, "Local-in: source is 'all' — FortiGate management services accessible from any host."))
    if service in ("ALL", "all"):
        findings.append(f(M, "Local-in: service ALL — restrict to required management protocols only."))
    if action == "accept" and srcaddr in ("all", ""):
        findings.append(f(C, "Local-in: ACCEPT from 'all' sources — FortiGate control plane broadly exposed."))

    return findings


# ── Logging ───────────────────────────────────────────────────────────────────

def logging_weaknesses(fa1, fa2, fa3, syslog1, syslog2, syslog3, syslog4,
                       log_cfg, evtfilter, disk_cfg, disk_filter) -> List[str]:
    findings = []

    def check_fa(cfg, idx):
        status = nv(cfg.get("status", ""))
        server = nv(cfg.get("server", ""))
        enc    = nv(cfg.get("enc-algorithm", ""))
        rel    = nv(cfg.get("reliable", ""))
        if idx == 1 and status != "enable":
            findings.append(f(M, "Logging: FortiAnalyzer (FA1) not enabled — no centralized log management."))
        elif status == "enable":
            if not server:
                findings.append(f(M, f"Logging: FortiAnalyzer {idx} enabled but no server IP configured."))
            if enc in ("", "disable", "low"):
                findings.append(f(M, f"Logging: FortiAnalyzer {idx} log encryption disabled or low."))
            if rel != "enable":
                findings.append(f(I, f"Logging: FortiAnalyzer {idx} reliable delivery (TCP) not enabled — UDP may drop logs."))

    check_fa(fa1, 1); check_fa(fa2, 2); check_fa(fa3, 3)

    def check_syslog(cfg, idx):
        status = nv(cfg.get("status", ""))
        server = nv(cfg.get("server", ""))
        mode   = nv(cfg.get("mode", ""))
        enc    = nv(cfg.get("enc-algorithm", ""))
        if status == "enable":
            if not server:
                findings.append(f(M, f"Logging: syslogd{idx} enabled but no server configured."))
            if mode == "udp":
                findings.append(f(M, f"Logging: syslogd{idx} using UDP — logs may be lost under load; use TCP or TLS."))
            if enc not in ("high", ""):
                findings.append(f(I, f"Logging: syslogd{idx} not using TLS — log data in cleartext."))

    check_syslog(syslog1, 1); check_syslog(syslog2, 2)
    check_syslog(syslog3, 3); check_syslog(syslog4, 4)

    fa_active = any(nv(x.get("status", "")) == "enable" for x in [fa1, fa2, fa3])
    syslog_active = any(nv(x.get("status", "")) == "enable" for x in [syslog1, syslog2, syslog3, syslog4])
    if not fa_active and not syslog_active:
        findings.append(f(H, "Logging: no remote log destination (FortiAnalyzer or syslog) configured — logs local only."))

    ev_cfg_chng = nv(evtfilter.get("admin", ""))
    ev_system   = nv(evtfilter.get("system", ""))
    ev_vpn      = nv(evtfilter.get("vpn", ""))

    if ev_cfg_chng == "disable":
        findings.append(f(H, "Logging: admin event logging disabled — configuration changes not logged."))
    if ev_system == "disable":
        findings.append(f(M, "Logging: system event logging disabled — system events (HA, link, etc.) not logged."))
    if ev_vpn == "disable":
        findings.append(f(M, "Logging: VPN event logging disabled — tunnel up/down events not captured."))

    log_invalid = nv(log_cfg.get("log-invalid-packet", ""))
    if log_invalid != "enable":
        findings.append(f(I, "Logging: log-invalid-packet not enabled — malformed/invalid packets not logged."))

    disk_status = nv(disk_cfg.get("status", ""))
    disk_full   = nv(disk_cfg.get("diskfull", ""))
    disk_roll   = nv(disk_cfg.get("roll-day", ""))

    if disk_status == "enable":
        if disk_full == "overwrite":
            findings.append(f(I, "Logging: disk-full action is overwrite — oldest logs will be lost on disk full."))
        if not disk_roll:
            findings.append(f(I, "Logging: disk log roll schedule not configured — logs may grow unbounded."))

    return findings


# ── Security Fabric (CSF) ─────────────────────────────────────────────────────

def csf_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    status    = nv(cfg.get("status", ""))
    fabric_dt = nv(cfg.get("fabric-device-detection", ""))
    group_pwd = nv(cfg.get("group-password", ""))
    saml      = nv(cfg.get("saml-configuration-sync", ""))
    acc_veri  = nv(cfg.get("accept-auth-by-cert", ""))

    if status == "enable":
        if fabric_dt != "enable":
            findings.append(f(I, "CSF: Fabric device detection disabled — rogue devices not automatically detected."))
        if not group_pwd:
            findings.append(f(H, "CSF: Security Fabric group password not set — any device can join the fabric."))
        elif len(group_pwd) < 16:
            findings.append(f(M, "CSF: Security Fabric group password is short — use 16+ characters."))
        if acc_veri != "enable":
            findings.append(f(M, "CSF: certificate-based fabric authorization not enabled — password-only fabric auth."))
        if saml != "enable":
            findings.append(f(I, "CSF: SAML configuration sync disabled — single sign-on across fabric not available."))
    else:
        findings.append(f(I, "CSF: Security Fabric disabled — centralized policy management and visibility unavailable."))

    return findings


# ── FIPS/CC Mode ──────────────────────────────────────────────────────────────

def fips_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    status = nv(cfg.get("status", ""))
    if status != "enable":
        findings.append(f(I, "FIPS-CC: FIPS 140-2 / Common Criteria mode not enabled — relevant for regulated environments."))
    return findings


# ── DoS Policy ───────────────────────────────────────────────────────────────

def dos_policy_weaknesses(p: Dict) -> List[str]:
    findings = []
    pid     = nv(p.get("policyid", p.get("_id", "")))
    intf    = nv(p.get("interface", ""))
    srcaddr = nv(p.get("srcaddr", ""))
    dstaddr = nv(p.get("dstaddr", ""))
    status  = nv(p.get("status", "enable"))
    comment = nv(p.get("comments", ""))

    if status == "disable":
        findings.append(f(M, f"DoS Policy {pid}: policy disabled — DoS protection not active."))
    if not intf:
        findings.append(f(M, f"DoS Policy {pid}: no interface bound — DoS protection scope unclear."))
    if srcaddr in ("all", "") and dstaddr in ("all", ""):
        findings.append(f(I, f"DoS Policy {pid}: source and destination both 'all' — applies to all traffic (may be intentional)."))
    if not comment:
        findings.append(f(I, f"DoS Policy {pid}: no comment — undocumented DoS rule."))

    return findings


# ── FortiGuard ────────────────────────────────────────────────────────────────

def fortiguard_weaknesses(cfg: Dict) -> List[str]:
    findings = []
    av_fw     = nv(cfg.get("av-failopen", ""))
    ips_fw    = nv(cfg.get("ips-failopen", ""))
    web_fw    = nv(cfg.get("webfilter-failopen", ""))
    sched_upd = nv(cfg.get("scheduled-update", ""))
    auto_upd  = nv(cfg.get("auto-firmware-upgrade", ""))

    if av_fw == "pass":
        findings.append(f(M, "FortiGuard: AV fail-open mode is 'pass' — if FortiGuard unreachable, files pass without AV scan."))
    if ips_fw == "pass":
        findings.append(f(M, "FortiGuard: IPS fail-open — if FortiGuard unreachable, traffic passes without IPS inspection."))
    if web_fw == "allow":
        findings.append(f(M, "FortiGuard: web filter fail-open 'allow' — if service unreachable, all URLs allowed."))

    if sched_upd != "enable":
        findings.append(f(M, "FortiGuard: scheduled signature updates not enabled — signatures may fall behind."))
    if auto_upd == "disable":
        findings.append(f(I, "FortiGuard: auto firmware upgrade disabled — manual upgrade management required."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

def compute_summary(all_findings: Dict[str, List[str]]) -> Dict[str, Any]:
    counts = {C: 0, H: 0, M: 0, I: 0}
    by_section = {}
    for section, finds in all_findings.items():
        sc = {C: 0, H: 0, M: 0, I: 0}
        for fn in finds:
            for sev in (C, H, M, I):
                if fn.startswith(sev + ":"):
                    counts[sev] += 1
                    sc[sev] += 1
        by_section[section] = sc

    total = sum(counts.values())
    score = counts[C]*10 + counts[H]*5 + counts[M]*2 + counts[I]*0.5

    if counts[C] > 0 or score >= 50:
        risk = "CRITICAL"
    elif score >= 25:
        risk = "HIGH"
    elif score >= 10:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"counts": counts, "total": total, "score": round(score, 1),
            "risk": risk, "by_section": by_section}


# ─────────────────────────────────────────────────────────────────────────────
# ASCII table helper
# ─────────────────────────────────────────────────────────────────────────────

def ascii_table(rows: List[tuple], title: str = None) -> str:
    col1 = max((len(str(k)) for k, _ in rows), default=18)
    col2 = max((len(str(v)) for _, v in rows), default=30)
    col1, col2 = max(col1, 22), max(col2, 32)
    width = col1 + col2 + 7
    top = "+" + "-" * (width - 2) + "+"
    lines = [top]
    if title:
        lines += ["| " + title[:width-4].center(width-4) + " |", top]
    for k, v in rows:
        lines.append(f"| {str(k).ljust(col1)} | {str(v).ljust(col2)} |")
    lines.append(top)
    return "\n".join(lines)


def findings_block(finds: List[str]) -> str:
    if not finds:
        return "Findings:\n  - None detected.\n"
    lines = ["Findings:"]
    for fn in finds:
        lines.append(f"  [{fn.split(':')[0]}] {':'.join(fn.split(':')[1:]).strip()}")
    return "\n".join(lines)


def write_report(path: Path, title: str, sections: List[tuple]):
    """sections = list of (heading, content_str)"""
    lines = [title, "=" * 80, ""]
    for heading, content in sections:
        lines += [f"{'─'*3} {heading} {'─'*(74-len(heading))}", content, ""]
    path.write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Report generators
# ─────────────────────────────────────────────────────────────────────────────

def generate_policy_report(policies, policies6, out_path):
    sections = []
    all_policies = [(p, "IPv4") for p in policies] + [(p, "IPv6") for p in policies6]
    header = f"Total policies: IPv4={len(policies)}, IPv6={len(policies6)}"
    sections.append(("Overview", header))

    for p, ver in all_policies:
        pid  = nv(p.get("policyid", p.get("_id", "")))
        name = nv(p.get("name", ""))
        rows = [
            ("Policy ID",       nv(p.get("policyid", p.get("_id","")))),
            ("Name",            nv(p.get("name",""))),
            ("Version",         ver),
            ("Status",          nv(p.get("status","enable"))),
            ("Action",          nv(p.get("action",""))),
            ("Src Interface",   nv(p.get("srcintf",""))),
            ("Dst Interface",   nv(p.get("dstintf",""))),
            ("Src Address",     nv(p.get("srcaddr", nv(p.get("srcaddr6",""))))),
            ("Dst Address",     nv(p.get("dstaddr", nv(p.get("dstaddr6",""))))),
            ("Service",         nv(p.get("service",""))),
            ("Schedule",        nv(p.get("schedule",""))),
            ("NAT",             nv(p.get("nat",""))),
            ("Anti-Replay",     nv(p.get("anti-replay","enable"))),
            ("Inspection Mode", nv(p.get("inspection-mode","flow"))),
            ("UTM Status",      nv(p.get("utm-status",""))),
            ("IPS Sensor",      nv(p.get("ips-sensor",""))),
            ("AV Profile",      nv(p.get("av-profile",""))),
            ("Web Filter",      nv(p.get("webfilter-profile",""))),
            ("DNS Filter",      nv(p.get("dnsfilter-profile",""))),
            ("App Control",     nv(p.get("application-list",""))),
            ("SSL/SSH Profile", nv(p.get("ssl-ssh-profile",""))),
            ("DLP Profile",     nv(p.get("dlp-profile", nv(p.get("dlp-sensor",""))))),
            ("CASB Profile",    nv(p.get("casb-profile",""))),
            ("WAF Profile",     nv(p.get("waf-profile",""))),
            ("Email Filter",    nv(p.get("emailfilter-profile",""))),
            ("File Filter",     nv(p.get("file-filter-profile",""))),
            ("Virtual Patch",   nv(p.get("virtual-patch-profile",""))),
            ("LLM Profile",     nv(p.get("llm-profile",""))),
            ("SSH Filter",      nv(p.get("ssh-filter-profile",""))),
            ("Log Traffic",     nv(p.get("logtraffic",""))),
            ("Log Start",       nv(p.get("logtraffic-start",""))),
            ("Log HTTP Txn",    nv(p.get("log-http-transaction",""))),
            ("Policy Expiry",   nv(p.get("policy-expiry",""))),
            ("ZTNA Status",     nv(p.get("ztna-status",""))),
            ("Reputation Min",  nv(p.get("reputation-minimum",""))),
            ("Comments",        nv(p.get("comments",""))),
        ]
        w = fw_policy_weaknesses(p)
        content = ascii_table(rows) + "\n" + findings_block(w)
        sections.append((f"Policy {pid}: {name} ({ver})", content))

    write_report(out_path, "FortiGate Firewall Policy Security Audit", sections)


def generate_ssl_report(profiles, out_path):
    sections = [("Overview", f"Profiles found: {len(profiles)}")]
    for p in profiles:
        name = nv(p.get("name", p.get("_id","")))
        has_sub = any(k.startswith("https.") or k.startswith("ftps.") for k in p)
        fmt = "FortiOS 7/8 per-protocol" if has_sub else "FortiOS 6.x flat"
        rows = [("Profile Name", name), ("Config Format", fmt),
                ("CA Name", nv(p.get("caname",""))),
                ("Anomaly Log", nv(p.get("ssl-anomalies-log", nv(p.get("log-ssl-anomalies",""))))),
                ("Block Blacklisted", nv(p.get("block-blacklisted-certificates",""))),
                ("ECH Handling", nv(p.get("encrypted-client-hello",""))),
                ("Comments", nv(p.get("comments","")))]
        if not has_sub:
            rows += [("Inspection Method", nv(p.get("inspection-method",""))),
                     ("SNI Check", nv(p.get("sni-check",""))),
                     ("Untrusted Cert", nv(p.get("untrusted-cert",""))),
                     ("Expired Cert", nv(p.get("expired-cert",""))),
                     ("Invalid Cert", nv(p.get("invalid-cert",""))),
                     ("Min TLS Version", nv(p.get("min-allowed-ssl-version","")))]
        else:
            for proto in ("https", "ftps", "imaps", "pop3s", "smtps", "ssh"):
                rows += [(f"{proto.upper()} status", nv(p.get(f"{proto}.status",""))),
                         (f"{proto.upper()} min-TLS", nv(p.get(f"{proto}.min-allowed-ssl-version",""))),
                         (f"{proto.upper()} untrusted", nv(p.get(f"{proto}.untrusted-server-cert","")))]
        w = ssl_profile_weaknesses(p)
        content = ascii_table(rows) + "\n" + findings_block(w)
        sections.append((f"SSL/SSH Profile: {name}", content))
    write_report(out_path, "FortiGate SSL/SSH Inspection Profile Audit", sections)


def generate_av_report(profiles, out_path):
    sections = [("Overview", f"Profiles found: {len(profiles)}")]
    for p in profiles:
        name = nv(p.get("name", p.get("_id","")))
        has_sub = any("." in k and not k.startswith("_") for k in p)
        rows = [("Profile Name", name),
                ("Feature Set", nv(p.get("feature-set","flow"))),
                ("Config Format", "FortiOS 8.0 sub-block" if has_sub else "FortiOS 6.x flat"),
                ("AV Virus Log", nv(p.get("av-virus-log","enable"))),
                ("Extended Log", nv(p.get("extended-log","disable"))),
                ("FortiSandbox Mode", nv(p.get("fortisandbox-mode",""))),
                ("FortiSandbox Error Action", nv(p.get("fortisandbox-error-action",""))),
                ("Outbreak Prevention Archive Scan", nv(p.get("outbreak-prevention-archive-scan","enable"))),
                ("EMS Threat Feed", nv(p.get("ems-threat-feed","disable"))),
                ("Mobile Malware DB", nv(p.get("mobile-malware-db","enable"))),
                ("Analytics DB", nv(p.get("analytics-db","disable"))),
                ("CDR Office Macro", nv(p.get("content-disarm.office-macro",""))),
                ("CDR PDF JavaScript", nv(p.get("content-disarm.pdf-javacode",""))),
                ("CDR Error Action", nv(p.get("content-disarm.error-action",""))),
                ("HTTP av-scan", nv(p.get("http.av-scan", nv(p.get("http",""))))),
                ("HTTP Outbreak Prevention", nv(p.get("http.outbreak-prevention",""))),
                ("HTTP FortiSandbox", nv(p.get("http.fortisandbox",""))),
                ("HTTP Quarantine", nv(p.get("http.quarantine",""))),
                ("HTTP Malware Stream", nv(p.get("http.malware-stream",""))),
                ("SMTP av-scan", nv(p.get("smtp.av-scan", nv(p.get("smtp",""))))),
                ("CIFS av-scan", nv(p.get("cifs.av-scan", nv(p.get("cifs",""))))),
                ("SSH av-scan", nv(p.get("ssh.av-scan",""))),
                ("WebSocket av-scan", nv(p.get("websocket.av-scan","")))]
        w = av_profile_weaknesses(p)
        content = ascii_table(rows) + "\n" + findings_block(w)
        sections.append((f"AV Profile: {name}", content))
    write_report(out_path, "FortiGate AntiVirus Profile Audit (FortiOS 8.0)", sections)


def generate_utm_profiles_report(ips_s, wf_p, app_p, dns_p, waf_p, email_p,
                                  video_p, file_p, vpatch_p, sctp_p, ssh_f_p, llm_p, out_path):
    sections = []

    def add_profiles(label, profiles, weakness_fn):
        sections.append((f"{label} Overview", f"Profiles: {len(profiles)}"))
        for p in profiles:
            name = nv(p.get("name", p.get("_id","")))
            w = weakness_fn(p)
            content = findings_block(w)
            sections.append((f"{label}: {name}", content))

    add_profiles("IPS Sensor",     ips_s,    ips_sensor_weaknesses)
    add_profiles("Web Filter",     wf_p,     wf_profile_weaknesses)
    add_profiles("App Control",    app_p,    app_profile_weaknesses)
    add_profiles("DNS Filter",     dns_p,    dns_profile_weaknesses)
    add_profiles("WAF Profile",    waf_p,    waf_profile_weaknesses)
    add_profiles("Email Filter",   email_p,  email_profile_weaknesses)
    add_profiles("Video Filter",   video_p,  video_profile_weaknesses)
    add_profiles("File Filter",    file_p,   file_filter_weaknesses)
    add_profiles("Virtual Patch",  vpatch_p, virtual_patch_weaknesses)
    add_profiles("LLM Profile",    llm_p,    llm_profile_weaknesses)

    write_report(out_path, "FortiGate UTM Profile Security Audit", sections)


def generate_vpn_report(phase1, phase2, out_path):
    sections = [("Overview", f"Phase1 tunnels: {len(phase1)}  Phase2 SAs: {len(phase2)}")]
    for p in phase1:
        name = nv(p.get("name", p.get("_id","")))
        rows = [("Tunnel Name",    name),
                ("IKE Version",    nv(p.get("ike-version",""))),
                ("Mode",           nv(p.get("mode",""))),
                ("Auth Method",    nv(p.get("authmethod",""))),
                ("Proposal",       nv(p.get("proposal",""))),
                ("DH Groups",      nv(p.get("dhgrp",""))),
                ("DPD",            nv(p.get("dpd",""))),
                ("Rekey",          nv(p.get("rekey",""))),
                ("Key Lifetime",   nv(p.get("keylifetime",""))),
                ("NAT Traversal",  nv(p.get("nattraversal","")))]
        w = vpn_phase1_weaknesses(p)
        sections.append((f"Phase1: {name}", ascii_table(rows) + "\n" + findings_block(w)))

    for p in phase2:
        name = nv(p.get("name", p.get("_id","")))
        rows = [("SA Name",      name),
                ("Phase1",       nv(p.get("phase1name",""))),
                ("Proposal",     nv(p.get("proposal",""))),
                ("PFS",          nv(p.get("pfs",""))),
                ("DH Group",     nv(p.get("dhgrp",""))),
                ("Key Lifetime", nv(p.get("keylifetime-seconds",""))),
                ("Anti-Replay",  nv(p.get("replay","")))]
        w = vpn_phase2_weaknesses(p)
        sections.append((f"Phase2: {name}", ascii_table(rows) + "\n" + findings_block(w)))

    write_report(out_path, "FortiGate IPsec VPN Security Audit", sections)


def generate_sslvpn_report(cfg, portals, out_path):
    rows = [("Status",              nv(cfg.get("status",""))),
            ("Port",                nv(cfg.get("port",""))),
            ("Server Certificate",  nv(cfg.get("servercert",""))),
            ("TLS 1.0",             nv(cfg.get("tlsv1-0",""))),
            ("TLS 1.1",             nv(cfg.get("tlsv1-1",""))),
            ("TLS 1.2",             nv(cfg.get("tlsv1-2",""))),
            ("Login Attempt Limit", nv(cfg.get("login-attempt-limit",""))),
            ("Login Block Time",    nv(cfg.get("login-block-time",""))),
            ("Idle Timeout",        nv(cfg.get("idle-timeout",""))),
            ("Auth Timeout",        nv(cfg.get("auth-timeout",""))),
            ("Client Certificate",  nv(cfg.get("client-cert",""))),
            ("Source Address",      nv(cfg.get("source-address",""))),
            ("DTLS Tunnel",         nv(cfg.get("dtls-tunnel","")))]
    sections = [("SSL-VPN Global Settings",
                 ascii_table(rows) + "\n" + findings_block(ssl_vpn_weaknesses(cfg)))]

    for p in portals:
        name = nv(p.get("name", p.get("_id","")))
        rows_p = [("Portal Name",      name),
                  ("Split Tunneling",  nv(p.get("split-tunneling",""))),
                  ("FTP Proxy",        nv(p.get("ftp-proxy",""))),
                  ("SMB Proxy",        nv(p.get("smb-proxy",""))),
                  ("OS Check",         nv(p.get("os-check",""))),
                  ("Limit User Logins",nv(p.get("limit-user-logins","")))]
        w = ssl_vpn_portal_weaknesses(p)
        sections.append((f"Portal: {name}", ascii_table(rows_p) + "\n" + findings_block(w)))

    write_report(out_path, "FortiGate SSL-VPN Security Audit", sections)


def generate_ha_report(ha_cfg, out_path):
    rows = [("Mode",              nv(ha_cfg.get("mode",""))),
            ("Password",          "***" if ha_cfg.get("password") else "(not set)"),
            ("HB Device",         nv(ha_cfg.get("hbdev",""))),
            ("HB Encryption",     nv(ha_cfg.get("hb-encryption",""))),
            ("HB Interval",       nv(ha_cfg.get("hb-interval",""))),
            ("Monitor Interfaces",nv(ha_cfg.get("monitor",""))),
            ("Config Sync",       nv(ha_cfg.get("sync-config",""))),
            ("Session Pickup",    nv(ha_cfg.get("session-pickup",""))),
            ("Mgmt Interface",    nv(ha_cfg.get("ha-mgmt-status","")))]
    sections = [("HA Configuration",
                 ascii_table(rows) + "\n" + findings_block(ha_weaknesses(ha_cfg)))]
    write_report(out_path, "FortiGate High Availability Audit", sections)


def generate_system_report(admins, interfaces, global_cfg, pw_policy_cfg, ssh_cfg,
                            ntp_cfg, local_in, local_in6, snmp_info, snmp_comm,
                            snmp_users, dns_cfg, csf_cfg, fips_cfg, ike_cfg,
                            fg_cfg, out_path):
    sections = []

    admin_content = f"Accounts found: {len(admins)}\n"
    for a in admins:
        name = nv(a.get("name", a.get("_id","")))
        rows = [("Admin Name",   name),
                ("Accprofile",   nv(a.get("accprofile",""))),
                ("Two-Factor",   nv(a.get("two-factor",""))),
                ("Wildcard",     nv(a.get("wildcard",""))),
                ("Force PW Chg",nv(a.get("force-password-change","")))]
        for n in range(1, 6):
            rows.append((f"Trusthost{n}", nv(a.get(f"trusthost{n}",""))))
        admin_content += ascii_table(rows) + "\n" + findings_block(admin_weaknesses(a)) + "\n"
    sections.append(("Administrator Accounts", admin_content))

    intf_content = f"Interfaces found: {len(interfaces)}\n"
    for intf in interfaces:
        name = nv(intf.get("name", intf.get("_id","")))
        rows = [("Name",        name),
                ("IP/Mask",     nv(intf.get("ip",""))),
                ("Role",        nv(intf.get("role",""))),
                ("Type",        nv(intf.get("type",""))),
                ("Allowaccess", nv(intf.get("allowaccess",""))),
                ("Description", nv(intf.get("description",""))),
                ("Proxy ARP",   nv(intf.get("proxy-arp","")))]
        intf_content += ascii_table(rows) + "\n" + findings_block(interface_weaknesses(intf)) + "\n"
    sections.append(("Network Interfaces", intf_content))

    rows = [("Hostname",          nv(global_cfg.get("hostname",""))),
            ("Strong Crypto",     nv(global_cfg.get("strong-crypto",""))),
            ("Static Key Ciphers",nv(global_cfg.get("ssl-static-key-ciphers",""))),
            ("DH Params",         nv(global_cfg.get("dh-params",""))),
            ("Admin Timeout",     nv(global_cfg.get("admintimeout",""))),
            ("Lockout Threshold", nv(global_cfg.get("admin-lockout-threshold",""))),
            ("Lockout Duration",  nv(global_cfg.get("admin-lockout-duration",""))),
            ("Pre-Login Banner",  nv(global_cfg.get("pre-login-banner",""))),
            ("Post-Login Banner", nv(global_cfg.get("post-login-banner",""))),
            ("HTTPS Redirect",    nv(global_cfg.get("admin-https-redirect",""))),
            ("GUI Certificate",   nv(global_cfg.get("admin-server-cert",""))),
            ("Password Policy",   nv(global_cfg.get("admin-password-policy",""))),
            ("Revision Backup",   nv(global_cfg.get("revision-image-auto-backup",""))),
            ("REST API Admin",    nv(global_cfg.get("admin-rest-api",""))),
            ("Unnamed Policy GUI",nv(global_cfg.get("gui-allow-unnamed-policy","")))]
    sections.append(("Global Hardening",
                     ascii_table(rows) + "\n" + findings_block(global_hardening_weaknesses(global_cfg))))

    rows = [("Status",        nv(pw_policy_cfg.get("status",""))),
            ("Min Length",    nv(pw_policy_cfg.get("min-length",""))),
            ("Must Contain",  nv(pw_policy_cfg.get("must-contain",""))),
            ("Expire Status", nv(pw_policy_cfg.get("expire-status",""))),
            ("Expire Days",   nv(pw_policy_cfg.get("expire-day",""))),
            ("Reuse Password",nv(pw_policy_cfg.get("reuse-password","")))]
    sections.append(("Password Policy",
                     ascii_table(rows) + "\n" + findings_block(password_policy_weaknesses(pw_policy_cfg))))

    rows = [("Encryption Algos", nv(ssh_cfg.get("encryption",""))),
            ("MAC Algos",        nv(ssh_cfg.get("integrity",""))),
            ("Key Exchange",     nv(ssh_cfg.get("kex",""))),
            ("Host Key Algo",    nv(ssh_cfg.get("host-key-algorithm","")))]
    sections.append(("SSH Configuration Hardening",
                     ascii_table(rows) + "\n" + findings_block(ssh_config_weaknesses(ssh_cfg))))

    snmp_content = ascii_table([
        ("SNMP Status",     nv(snmp_info.get("status",""))),
        ("Description",     nv(snmp_info.get("description",""))),
        ("Contact",         nv(snmp_info.get("contact-info",""))),
        ("Location",        nv(snmp_info.get("location",""))),
        ("Communities",     str(len(snmp_comm))),
        ("SNMPv3 Users",    str(len(snmp_users))),
    ]) + "\n" + findings_block(snmp_sysinfo_weaknesses(snmp_info))
    for c in snmp_comm:
        snmp_content += f"\n  Community: {nv(c.get('name',c.get('_id','')))}\n"
        snmp_content += findings_block(snmp_community_weaknesses(c))
    for u in snmp_users:
        snmp_content += f"\n  SNMPv3 User: {nv(u.get('name',u.get('_id','')))}\n"
        snmp_content += findings_block(snmp_user_weaknesses(u))
    sections.append(("SNMP Hardening", snmp_content))

    rows = [("NTP Sync",    nv(ntp_cfg.get("ntpsync",""))),
            ("Type",        nv(ntp_cfg.get("type",""))),
            ("Sync Interval",nv(ntp_cfg.get("syncinterval",""))),
            ("Source IP",   nv(ntp_cfg.get("source-ip",""))),
            ("Server Mode", nv(ntp_cfg.get("server-mode",""))),
            ("Auth",        nv(ntp_cfg.get("authentication",""))),
            ("NTPv3",       nv(ntp_cfg.get("ntpv3",""))),
            ("Servers",     str(len(ntp_cfg.get("servers",[]))))]
    sections.append(("NTP Configuration",
                     ascii_table(rows) + "\n" + findings_block(ntp_weaknesses(ntp_cfg))))

    lip_content = f"IPv4 local-in: {len(local_in)}   IPv6 local-in: {len(local_in6)}\n"
    for lip in local_in + local_in6:
        rows = [("Interface", nv(lip.get("intf",""))),
                ("Src Addr",  nv(lip.get("srcaddr",""))),
                ("Dst Addr",  nv(lip.get("dstaddr",""))),
                ("Service",   nv(lip.get("service",""))),
                ("Action",    nv(lip.get("action","")))]
        lip_content += ascii_table(rows) + "\n" + findings_block(local_in_weaknesses(lip)) + "\n"
    sections.append(("Local-in Policies (Management Plane Control)", lip_content))

    rows = [("Primary DNS",   nv(dns_cfg.get("primary",""))),
            ("Secondary DNS", nv(dns_cfg.get("secondary",""))),
            ("DNSSEC",        nv(dns_cfg.get("dnssec-validation",""))),
            ("DNS-over-TLS",  nv(dns_cfg.get("dns-over-tls",nv(dns_cfg.get("protocol","")))))]
    sections.append(("System DNS Security",
                     ascii_table(rows) + "\n" + findings_block(dns_system_weaknesses(dns_cfg))))

    rows = [("IKEv1 Disable",   nv(ike_cfg.get("ikev1-disable",""))),
            ("Aggressive Mode",  nv(ike_cfg.get("ike1-aggressive-mode-disable",""))),
            ("DH Groups",        nv(ike_cfg.get("dh-group",""))),
            ("Hash Algorithm",   nv(ike_cfg.get("hash-algorithm","")))]
    sections.append(("IKE Global Settings (VPN Hardening)",
                     ascii_table(rows) + "\n" + findings_block(ike_global_weaknesses(ike_cfg))))

    rows = [("Status",            nv(csf_cfg.get("status",""))),
            ("Group Password",    "***" if csf_cfg.get("group-password") else "(not set)"),
            ("Device Detection",  nv(csf_cfg.get("fabric-device-detection",""))),
            ("Auth by Cert",      nv(csf_cfg.get("accept-auth-by-cert",""))),
            ("SAML Sync",         nv(csf_cfg.get("saml-configuration-sync","")))]
    sections.append(("Security Fabric (CSF)",
                     ascii_table(rows) + "\n" + findings_block(csf_weaknesses(csf_cfg))))

    rows = [("FIPS-CC Status", nv(fips_cfg.get("status","")))]
    sections.append(("FIPS-CC Compliance Mode",
                     ascii_table(rows) + "\n" + findings_block(fips_weaknesses(fips_cfg))))

    rows = [("AV Fail-Open",        nv(fg_cfg.get("av-failopen",""))),
            ("IPS Fail-Open",       nv(fg_cfg.get("ips-failopen",""))),
            ("WebFilter Fail-Open", nv(fg_cfg.get("webfilter-failopen",""))),
            ("Scheduled Update",    nv(fg_cfg.get("scheduled-update",""))),
            ("Auto Firmware Upgrade",nv(fg_cfg.get("auto-firmware-upgrade","")))]
    sections.append(("FortiGuard Service Configuration",
                     ascii_table(rows) + "\n" + findings_block(fortiguard_weaknesses(fg_cfg))))

    write_report(out_path, "FortiGate System & Management Plane Security Audit", sections)


def generate_logging_report(fa1, fa2, fa3, syslog1, syslog2, syslog3, syslog4,
                             log_cfg, evtfilter, disk_cfg, disk_filter, out_path):
    rows = [("FortiAnalyzer 1 Status",  nv(fa1.get("status",""))),
            ("FortiAnalyzer 1 Server",  nv(fa1.get("server",""))),
            ("FortiAnalyzer 1 Encrypt", nv(fa1.get("enc-algorithm",""))),
            ("FortiAnalyzer 1 Reliable",nv(fa1.get("reliable",""))),
            ("FortiAnalyzer 2 Status",  nv(fa2.get("status",""))),
            ("FortiAnalyzer 3 Status",  nv(fa3.get("status",""))),
            ("Syslogd 1 Status",        nv(syslog1.get("status",""))),
            ("Syslogd 1 Server",        nv(syslog1.get("server",""))),
            ("Syslogd 1 Mode",          nv(syslog1.get("mode",""))),
            ("Syslogd 1 Encrypt",       nv(syslog1.get("enc-algorithm",""))),
            ("Syslogd 2 Status",        nv(syslog2.get("status",""))),
            ("Syslogd 3 Status",        nv(syslog3.get("status",""))),
            ("Syslogd 4 Status",        nv(syslog4.get("status",""))),
            ("Log Invalid Packet",      nv(log_cfg.get("log-invalid-packet",""))),
            ("Event Filter: Admin",     nv(evtfilter.get("admin",""))),
            ("Event Filter: System",    nv(evtfilter.get("system",""))),
            ("Event Filter: VPN",       nv(evtfilter.get("vpn",""))),
            ("Event Filter: Endpoint",  nv(evtfilter.get("endpoint",""))),
            ("Disk Logging Status",     nv(disk_cfg.get("status",""))),
            ("Disk Full Action",        nv(disk_cfg.get("diskfull",""))),
            ("Disk Roll Day",           nv(disk_cfg.get("roll-day","")))]

    w = logging_weaknesses(fa1, fa2, fa3, syslog1, syslog2, syslog3, syslog4,
                           log_cfg, evtfilter, disk_cfg, disk_filter)
    sections = [("Logging Configuration", ascii_table(rows) + "\n" + findings_block(w))]
    write_report(out_path, "FortiGate Logging & SIEM Audit", sections)


def generate_dos_report(policies, out_path):
    sections = [("Overview", f"DoS policies found: {len(policies)}")]
    for p in policies:
        pid  = nv(p.get("policyid", p.get("_id","")))
        rows = [("Policy ID",  pid),
                ("Interface",  nv(p.get("interface",""))),
                ("Src Addr",   nv(p.get("srcaddr",""))),
                ("Dst Addr",   nv(p.get("dstaddr",""))),
                ("Service",    nv(p.get("service",""))),
                ("Status",     nv(p.get("status","enable"))),
                ("Comments",   nv(p.get("comments","")))]
        w = dos_policy_weaknesses(p)
        sections.append((f"DoS Policy {pid}", ascii_table(rows) + "\n" + findings_block(w)))
    if not policies:
        sections.append(("Warning",
            "MEDIUM: No DoS policies configured — FortiGate has no DoS/anomaly-based protection rules.\n"
            "  Consider configuring 'config firewall DoS-policy' to protect against flood attacks."))
    write_report(out_path, "FortiGate DoS Policy Audit", sections)


def generate_summary(all_findings: Dict[str, List[str]], config_path: str, out_path: Path):
    summary = compute_summary(all_findings)
    counts  = summary["counts"]
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" FORTIGATE SECURITY AUDIT — EXECUTIVE SUMMARY ".center(W, "="))
    lines.append("=" * W)
    lines.append(f"  Config file  : {config_path}")
    lines.append(f"  Risk Rating  : {summary['risk']}")
    lines.append(f"  Risk Score   : {summary['score']}  "
                 f"(CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5)")
    lines.append(f"  Total Findings: {summary['total']}")
    lines.append("")
    lines.append(f"  {'CRITICAL':<12}{counts[C]:>5}")
    lines.append(f"  {'HIGH':<12}{counts[H]:>5}")
    lines.append(f"  {'MEDIUM':<12}{counts[M]:>5}")
    lines.append(f"  {'INFO':<12}{counts[I]:>5}")
    lines.append("=" * W)
    lines.append("")
    lines.append("  FINDINGS BY SECTION:")
    lines.append("  " + "-" * (W - 2))
    lines.append(f"  {'Section':<35}  {'CRIT':>4}  {'HIGH':>4}  {'MED':>4}  {'INFO':>4}  {'TOT':>5}")
    lines.append("  " + "-" * (W - 2))
    for section, sc in sorted(summary["by_section"].items()):
        total_s = sum(sc.values())
        if total_s:
            lines.append(f"  {section:<35}  {sc[C]:>4}  {sc[H]:>4}  {sc[M]:>4}  {sc[I]:>4}  {total_s:>5}")
    lines.append("  " + "-" * (W - 2))
    lines.append("")
    lines.append("  CRITICAL & HIGH FINDINGS:")
    lines.append("  " + "-" * (W - 2))
    for section, finds in sorted(all_findings.items()):
        for fn in finds:
            if fn.startswith(C+":") or fn.startswith(H+":"):
                lines.append(f"  [{section[:30]:<30}]  {fn}")
    lines.append("")
    lines.append("=" * W)

    out_path.write_text("\n".join(lines), encoding="utf-8")
    json_path = out_path.with_suffix(".json")
    json_path.write_text(
        json.dumps({"summary": summary, "findings": all_findings}, indent=2),
        encoding="utf-8")
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

# ═════════════════════════════════════════════════════════════════════════════
# ANTI-DoS / DoS PROTECTION AUDIT MODULE
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# Parsers — DoS-specific config sections
# ─────────────────────────────────────────────────────────────────────────────

def parse_dos_policy_full(text: str) -> List[Dict[str, Any]]:
    """
    Parse 'config firewall DoS-policy' with full anomaly sub-block extraction.
    Each anomaly entry (edit tcp_syn_flood etc.) is captured with its
    status/action/threshold/log fields.
    """
    lines = text.splitlines()
    policies: List[Dict[str, Any]] = []
    in_block = False
    current: Dict[str, Any] = {}
    in_anomaly = False
    cur_anomaly: Dict[str, Any] = {}
    anomaly_name: str = ""
    depth = 0

    for raw in lines:
        line = raw.strip()

        if line == "config firewall DoS-policy":
            in_block = True
            current = {}
            in_anomaly = False
            depth = 0
            continue
        if not in_block:
            continue

        if line.startswith("edit ") and not in_anomaly and depth == 0:
            if current:
                policies.append(current)
            pid = line.split(None, 1)[1].strip().strip('"')
            current = {"_id": pid, "_anomalies": {}}
            continue

        if line == "next" and not in_anomaly and depth == 0:
            if current:
                policies.append(current)
            current = {"_anomalies": {}}
            continue

        if line == "end" and depth == 0:
            if current and current.get("_id"):
                policies.append(current)
            break

        # anomaly sub-block: "config anomaly"
        if line == "config anomaly" and depth == 0:
            in_anomaly = True
            depth = 1
            continue

        if in_anomaly:
            if line.startswith("edit "):
                if cur_anomaly and anomaly_name:
                    current["_anomalies"][anomaly_name] = cur_anomaly
                anomaly_name = line.split(None, 1)[1].strip().strip('"')
                cur_anomaly = {"_name": anomaly_name}
                continue
            if line == "next":
                if cur_anomaly and anomaly_name:
                    current["_anomalies"][anomaly_name] = cur_anomaly
                cur_anomaly = {}
                anomaly_name = ""
                continue
            if line == "end":
                if cur_anomaly and anomaly_name:
                    current["_anomalies"][anomaly_name] = cur_anomaly
                in_anomaly = False
                cur_anomaly = {}
                anomaly_name = ""
                depth = 0
                continue
            if line.startswith("set "):
                k, v = parse_set_line(line)
                if k:
                    cur_anomaly[k] = v
            continue

        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                current[k] = v

    return [p for p in policies if p.get("_id")]


def parse_np_global(text: str) -> Dict[str, Any]:
    """Parse 'config system np6' or 'config system np7' for DoS offload settings."""
    cfg: Dict[str, Any] = {}
    for block_name in ("system np7", "system np6", "system npu"):
        result = extract_flat_block(text, block_name)
        if result:
            cfg.update(result)
            cfg["_np_type"] = block_name
            break
    return cfg


def parse_system_resource_limit(text: str) -> Dict[str, Any]:
    return extract_flat_block(text, "system resource-limit")


def parse_system_session(text: str) -> Dict[str, Any]:
    return extract_flat_block(text, "system session-ttl")


def parse_system_global_dos(text: str) -> Dict[str, Any]:
    """Pull DoS-relevant fields from system global."""
    cfg = extract_flat_block(text, "system global")
    return {
        "tcp-halfopen-timer":   nv(cfg.get("tcp-halfopen-timer", "")),
        "tcp-timewait-timer":   nv(cfg.get("tcp-timewait-timer", "")),
        "tcp-option":           nv(cfg.get("tcp-option", "")),
        "snat-hairpin-traffic": nv(cfg.get("snat-hairpin-traffic", "")),
        "anti-replay":          nv(cfg.get("anti-replay", "")),
        "block-session-timer":  nv(cfg.get("block-session-timer", "")),
        "ip-src-check-on-tx":   nv(cfg.get("ip-src-check-on-tx", "")),
        "per-user-bwl":         nv(cfg.get("per-user-bwl", "")),
        "scanunit-count":       nv(cfg.get("scanunit-count", "")),
    }


def parse_ips_dos_anomalies(text: str) -> Dict[str, Dict[str, Any]]:
    """
    Extract DoS-related anomaly entries from all IPS sensors.
    Returns {sensor_name: {anomaly_name: {fields}}}
    """
    lines = text.splitlines()
    result: Dict[str, Dict[str, Any]] = {}
    in_sensor = False
    in_anomaly_block = False
    sensor_name = ""
    cur_anomaly: Dict[str, Any] = {}
    anomaly_name = ""
    depth = 0

    DOS_ANOMALIES = {
        "tcp_syn_flood", "tcp-syn-flood", "udp_flood", "udp-flood",
        "icmp_flood", "icmp-flood", "tcp_port_scan", "tcp-port-scan",
        "udp_scan", "udp-scan", "tcp_ack_flood", "tcp-ack-flood",
        "tcp_synack_flood", "tcp-synack-flood", "ip_src_session",
        "ip-src-session", "tcp_src_session", "tcp-src-session",
        "udp_src_session", "udp-src-session", "icmp_src_session",
        "icmp-src-session", "ip_dst_session", "ip-dst-session",
        "sctp_flood", "sctp-flood"
    }

    for raw in lines:
        line = raw.strip()

        if line == "config ips sensor":
            in_sensor = True
            continue
        if not in_sensor:
            continue

        if line.startswith("edit ") and depth == 0:
            sensor_name = line.split(None, 1)[1].strip().strip('"')
            result[sensor_name] = {}
            in_anomaly_block = False
            continue

        if line == "next" and depth == 0:
            sensor_name = ""
            in_anomaly_block = False
            continue

        if line == "end" and depth == 0:
            break

        if line == "config entries" and depth == 0:
            depth = 1
            continue

        if depth == 1:
            if line.startswith("config "):
                depth += 1
                continue
            if line == "end":
                depth = 0
                continue
            if line.startswith("edit "):
                pass  # IPS entries — skip
            if line.startswith("set "):
                pass
            continue

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DoS anomaly reference — expected thresholds per type
# ─────────────────────────────────────────────────────────────────────────────

# (anomaly_name, recommended_max_threshold, description)
ANOMALY_SPECS = {
    "tcp_syn_flood":     (2000,  "TCP SYN Flood"),
    "tcp-syn-flood":     (2000,  "TCP SYN Flood"),
    "tcp_ack_flood":     (2000,  "TCP ACK Flood"),
    "tcp-ack-flood":     (2000,  "TCP ACK Flood"),
    "tcp_synack_flood":  (1000,  "TCP SYN-ACK Flood"),
    "tcp-synack-flood":  (1000,  "TCP SYN-ACK Flood"),
    "udp_flood":         (2000,  "UDP Flood"),
    "udp-flood":         (2000,  "UDP Flood"),
    "icmp_flood":        (250,   "ICMP Flood"),
    "icmp-flood":        (250,   "ICMP Flood"),
    "tcp_port_scan":     (1000,  "TCP Port Scan"),
    "tcp-port-scan":     (1000,  "TCP Port Scan"),
    "udp_scan":          (2000,  "UDP Scan"),
    "udp-scan":          (2000,  "UDP Scan"),
    "ip_src_session":    (5000,  "Source IP Session Limit"),
    "ip-src-session":    (5000,  "Source IP Session Limit"),
    "tcp_src_session":   (5000,  "TCP Source Session Limit"),
    "tcp-src-session":   (5000,  "TCP Source Session Limit"),
    "udp_src_session":   (5000,  "UDP Source Session Limit"),
    "udp-src-session":   (5000,  "UDP Source Session Limit"),
    "icmp_src_session":  (1000,  "ICMP Source Session Limit"),
    "icmp-src-session":  (1000,  "ICMP Source Session Limit"),
    "ip_dst_session":    (10000, "Dest IP Session Limit"),
    "ip-dst-session":    (10000, "Dest IP Session Limit"),
    "ip_land_attack":    (1,     "IP Land Attack"),
    "ip-land":           (1,     "IP Land Attack"),
    "ip_bad_option":     (1,     "IP Bad Option"),
    "ip-bad-option":     (1,     "IP Bad Option"),
    "sctp_flood":        (2000,  "SCTP Flood"),
    "sctp-flood":        (2000,  "SCTP Flood"),
}

# Critical anomalies that MUST be enabled on any WAN-facing DoS policy
CRITICAL_ANOMALIES = {
    "tcp_syn_flood", "tcp-syn-flood",
    "tcp_ack_flood", "tcp-ack-flood",
    "udp_flood",     "udp-flood",
    "icmp_flood",    "icmp-flood",
    "tcp_port_scan", "tcp-port-scan",
    "ip_src_session","ip-src-session",
    "ip_land_attack","ip-land",
    "ip_bad_option", "ip-bad-option",
}


# ─────────────────────────────────────────────────────────────────────────────
# Weakness checks — Anti-DoS
# ─────────────────────────────────────────────────────────────────────────────

def antidos_policy_weaknesses(policies: List[Dict], interfaces: List[Dict]) -> List[str]:
    """Evaluate DoS policies for coverage, anomaly configuration, and action mode."""
    findings = []

    # Build WAN interface list
    wan_intfs = set()
    for intf in interfaces:
        role = nv(intf.get("role", ""))
        name = nv(intf.get("name", intf.get("_id", "")))
        aa   = nv(intf.get("allowaccess", ""))
        typ  = nv(intf.get("type", ""))
        if role == "wan":
            wan_intfs.add(name)
        # Also detect by name heuristics
        name_l = name.lower()
        if any(w in name_l for w in ("wan", "ppp", "vdsl", "adsl", "ftth", "internet", "outside", "untrust")):
            wan_intfs.add(name)

    if not policies:
        findings.append(f(C, "DoS Policies: NO DoS policies configured — FortiGate has zero flood/anomaly protection. "
                            "Any flood attack hits the kernel directly. Configure 'config firewall DoS-policy' "
                            "on all WAN interfaces immediately."))
        return findings

    # Track which WAN interfaces have a DoS policy
    covered_wans: set = set()
    enabled_policies = []

    for p in policies:
        pid    = nv(p.get("_id", ""))
        intf   = nv(p.get("interface", ""))
        status = nv(p.get("status", "enable"))
        srcaddr = nv(p.get("srcaddr", ""))
        dstaddr = nv(p.get("dstaddr", ""))
        anomalies: Dict[str, Any] = p.get("_anomalies", {})

        if status == "disable":
            findings.append(f(H, f"DoS Policy {pid}: policy is DISABLED — no protection active on interface '{intf}'."))
            continue

        if not intf:
            findings.append(f(M, f"DoS Policy {pid}: no interface bound — protection scope is undefined."))
        else:
            if intf in wan_intfs:
                covered_wans.add(intf)
            # Interface not recognized as WAN
            intf_l = intf.lower()
            if any(w in intf_l for w in ("wan", "ppp", "vdsl", "adsl", "ftth", "internet", "outside", "untrust")):
                covered_wans.add(intf)

        enabled_policies.append(p)

        if srcaddr not in ("all", "") and dstaddr not in ("all", ""):
            findings.append(f(I, f"DoS Policy {pid}: both srcaddr and dstaddr scoped — verify coverage is not too narrow."))

        # ── Per-anomaly checks ──
        if not anomalies:
            findings.append(f(H, f"DoS Policy {pid} (intf: {intf}): no anomaly sensors configured — "
                                "policy exists but provides zero protection. Add tcp_syn_flood, udp_flood, etc."))
            continue

        found_critical = set()
        for anom_name, anom in anomalies.items():
            a_status    = nv(anom.get("status", ""))
            a_action    = nv(anom.get("action", ""))
            a_threshold = nv(anom.get("threshold", ""))
            a_log       = nv(anom.get("log", ""))
            spec        = ANOMALY_SPECS.get(anom_name)
            label       = spec[1] if spec else anom_name
            rec_thresh  = spec[0] if spec else None

            if anom_name in CRITICAL_ANOMALIES:
                found_critical.add(anom_name)

            # Status
            if a_status != "enable":
                sev = C if anom_name in CRITICAL_ANOMALIES else M
                findings.append(f(sev, f"DoS Policy {pid} [{label}]: sensor DISABLED — "
                                       f"set 'status enable' in anomaly config."))
                continue  # remaining checks only apply if enabled

            # Action
            if a_action in ("pass", "monitor", ""):
                sev = H if anom_name in CRITICAL_ANOMALIES else M
                findings.append(f(sev, f"DoS Policy {pid} [{label}]: action is '{a_action or 'not set'}' — "
                                       f"change to 'block'. Monitor mode logs but never drops."))

            # Threshold sanity
            if a_threshold and rec_thresh:
                try:
                    tval = int(a_threshold)
                    if tval == 0:
                        findings.append(f(H, f"DoS Policy {pid} [{label}]: threshold is 0 — "
                                             "sensor will never trigger. Set a realistic value."))
                    elif tval > rec_thresh * 10:
                        findings.append(f(M, f"DoS Policy {pid} [{label}]: threshold {tval} is extremely high "
                                             f"(recommended ≤ {rec_thresh}) — floods may exhaust resources before triggering."))
                    elif tval > rec_thresh * 3:
                        findings.append(f(I, f"DoS Policy {pid} [{label}]: threshold {tval} is above "
                                            f"recommended {rec_thresh} — consider tightening."))
                except (ValueError, TypeError):
                    pass

            # Logging
            if a_log != "enable":
                findings.append(f(M, f"DoS Policy {pid} [{label}]: logging disabled — "
                                     "DoS events will not appear in logs or FortiAnalyzer."))

        # Check which critical anomalies are missing entirely
        missing = set()
        for crit in CRITICAL_ANOMALIES:
            canonical = crit.replace("-", "_")
            present = any(
                a.replace("-", "_") == canonical
                for a in anomalies
            )
            if not present:
                missing.add(crit.replace("-", "_"))

        # Deduplicate missing (tcp_syn_flood and tcp-syn-flood are the same)
        deduped_missing = set()
        seen_canonical = set()
        for m in missing:
            can = m.replace("-", "_")
            if can not in seen_canonical:
                seen_canonical.add(can)
                deduped_missing.add(can)

        if deduped_missing:
            missing_list = ", ".join(sorted(deduped_missing))
            findings.append(f(H, f"DoS Policy {pid} (intf: {intf}): critical anomaly sensors missing: "
                                f"{missing_list}. Add these to the anomaly config."))

    # Check WAN interfaces with no DoS policy
    uncovered = wan_intfs - covered_wans
    if uncovered:
        for wan in sorted(uncovered):
            findings.append(f(C, f"DoS Policy: WAN interface '{wan}' has NO DoS policy — "
                                "this interface is completely unprotected from flood attacks. "
                                f"Create a DoS policy with 'set interface {wan}'."))

    if wan_intfs and not covered_wans and enabled_policies:
        findings.append(f(H, "DoS Policy: DoS policies exist but none are bound to detected WAN interfaces. "
                            "Verify interface assignments match your WAN-facing ports."))

    return findings


def antidos_ips_weaknesses(ips_sensors: List[Dict], policies: List[Dict]) -> List[str]:
    """Check IPS profiles for DoS anomaly coverage in security policies."""
    findings = []

    dos_relevant = {
        "tcp_syn_flood", "tcp-syn-flood", "udp_flood", "udp-flood",
        "icmp_flood", "icmp-flood", "tcp_port_scan", "tcp-port-scan",
        "ip_src_session", "ip-src-session", "tcp_ack_flood", "tcp-ack-flood"
    }

    if not ips_sensors:
        findings.append(f(H, "IPS DoS: no IPS sensors configured — no signature-based DoS/anomaly protection."))
        return findings

    # Check which policies have IPS sensors
    policies_with_ips = [p for p in policies if nv(p.get("ips-sensor", ""))]
    policies_no_ips   = [p for p in policies if not nv(p.get("ips-sensor", ""))
                         and nv(p.get("action", "")) == "accept"]

    if policies_no_ips:
        findings.append(f(M, f"IPS DoS: {len(policies_no_ips)} accept policy/policies have no IPS sensor attached — "
                            "DoS signature protection absent on these flows."))

    # Per-sensor: check for DoS-related entries with block action
    for sensor in ips_sensors:
        name = nv(sensor.get("name", sensor.get("_id", "")))
        botnet = nv(sensor.get("scan-botnet-connections", ""))
        block_url = nv(sensor.get("block-malicious-url", ""))

        if botnet in ("", "disable"):
            findings.append(f(H, f"IPS Sensor '{name}': botnet C2 scanning disabled — "
                               "compromised hosts inside the network can communicate outbound freely."))
        elif botnet == "monitor":
            findings.append(f(M, f"IPS Sensor '{name}': botnet scanning in monitor mode — "
                               "C2 connections are logged but not blocked. Change to 'block'."))

        if block_url != "enable":
            findings.append(f(M, f"IPS Sensor '{name}': block-malicious-url disabled — "
                               "known C2/malware URLs not blocked at IPS layer."))

    return findings


def antidos_hardening_weaknesses(
    interfaces: List[Dict],
    local_in:   List[Dict],
    local_in6:  List[Dict],
    global_dos: Dict,
    res_limit:  Dict,
    np_cfg:     Dict,
    policies:   List[Dict],
) -> List[str]:
    """Check related hardening: session limits, NP offload, TCP timers, mgmt plane."""
    findings = []

    # ── TCP Session / Timer Settings ──
    tcp_halfopen = nv(global_dos.get("tcp-halfopen-timer", ""))
    tcp_timewait = nv(global_dos.get("tcp-timewait-timer", ""))
    anti_replay  = nv(global_dos.get("anti-replay", ""))
    block_timer  = nv(global_dos.get("block-session-timer", ""))
    ip_src_check = nv(global_dos.get("ip-src-check-on-tx", ""))

    try:
        if int(tcp_halfopen) > 10:
            findings.append(f(M, f"TCP Hardening: tcp-halfopen-timer is {tcp_halfopen}s — "
                                "high values extend SYN flood attack windows. Recommend ≤ 10s. "
                                "CLI: config system global → set tcp-halfopen-timer 10"))
    except (ValueError, TypeError):
        if not tcp_halfopen:
            findings.append(f(I, "TCP Hardening: tcp-halfopen-timer not explicitly set — default may be too permissive."))

    try:
        if int(tcp_timewait) > 1:
            findings.append(f(I, f"TCP Hardening: tcp-timewait-timer is {tcp_timewait}s — "
                                "consider reducing to 1s to free sessions faster under flood. "
                                "CLI: config system global → set tcp-timewait-timer 1"))
    except (ValueError, TypeError):
        pass

    if anti_replay not in ("strict", "enable"):
        findings.append(f(M, "TCP Hardening: anti-replay is not set to 'strict' — "
                            "packet replay attacks possible at the global level. "
                            "CLI: config system global → set anti-replay strict"))

    if ip_src_check != "enable":
        findings.append(f(I, "TCP Hardening: ip-src-check-on-tx not enabled — "
                            "spoofed source IP packets may not be dropped on transmit. "
                            "CLI: config system global → set ip-src-check-on-tx enable"))

    try:
        bt = int(block_timer)
        if bt < 30:
            findings.append(f(I, f"TCP Hardening: block-session-timer is {bt}s — "
                                "blocked sessions re-allowed too quickly. Recommend ≥ 30s."))
    except (ValueError, TypeError):
        pass

    # ── Resource Limits ──
    if not res_limit:
        findings.append(f(M, "Resource Limits: 'config system resource-limit' not configured — "
                            "no per-user or global session count ceilings. Under a flood attack, "
                            "the session table can be exhausted. "
                            "CLI: config system resource-limit → set type ipsec → set max-user-limit 1000"))
    else:
        sess_limit = nv(res_limit.get("max-session-limit", ""))
        if not sess_limit or sess_limit == "0":
            findings.append(f(M, "Resource Limits: max-session-limit not set — "
                                "unlimited sessions allowed per user; DoS amplification risk."))

    # ── NP Hardware DoS Offload ──
    if not np_cfg:
        findings.append(f(I, "NP Offload: no NP7/NP6 DoS offload config detected — "
                            "either this platform has no NP ASIC or offload is unconfigured. "
                            "On NP-capable hardware, DoS offload dramatically reduces CPU impact."))
    else:
        np_type = nv(np_cfg.get("_np_type", "NP"))
        # HPE (Host Protection Engine)
        hpe_policy = nv(np_cfg.get("hpe", "")) or nv(np_cfg.get("host-shortcut-mode", ""))
        fp_anomaly = nv(np_cfg.get("fp-anomaly", ""))
        np_dos_off = nv(np_cfg.get("dos-options", "")) or nv(np_cfg.get("np-queues", ""))

        if not hpe_policy:
            findings.append(f(M, f"NP Offload ({np_type}): HPE (Host Protection Engine) not explicitly configured — "
                                "management-plane traffic destined to FortiGate may not be rate-limited at ASIC level. "
                                f"CLI: config system {np_type.replace('system ','')} → config hpe → set ..."))
        if fp_anomaly in ("", "disable"):
            findings.append(f(M, f"NP Offload ({np_type}): fp-anomaly (fast-path anomaly detection) not enabled — "
                                "NP-offloaded sessions bypass CPU-level DoS anomaly checks without this."))

    # ── WAN Interface Management Access ──
    for intf in interfaces:
        name = nv(intf.get("name", intf.get("_id", "")))
        role = nv(intf.get("role", ""))
        aa   = nv(intf.get("allowaccess", ""))
        aa_parts = aa.split()
        name_l = name.lower()
        is_wan = (role == "wan") or any(
            w in name_l for w in ("wan", "internet", "outside", "untrust", "ppp")
        )
        if is_wan:
            if "https" in aa_parts:
                findings.append(f(H, f"Mgmt Exposure: HTTPS management on WAN interface '{name}' — "
                                    "management plane directly reachable from internet; "
                                    "restrict with local-in-policy or remove from allowaccess. "
                                    f"CLI: config system interface → edit {name} → set allowaccess (remove https)"))
            if "ssh" in aa_parts:
                findings.append(f(H, f"Mgmt Exposure: SSH on WAN interface '{name}' — "
                                    "brute-force target; restrict via local-in-policy to admin IPs only."))
            if "http" in aa_parts:
                findings.append(f(C, f"Mgmt Exposure: HTTP management on WAN interface '{name}' — "
                                    "cleartext management on internet-facing interface is critical risk."))
            if "ping" in aa_parts:
                findings.append(f(M, f"Mgmt Exposure: ICMP/ping enabled on WAN interface '{name}' — "
                                    "aids attacker reconnaissance and is an ICMP flood target. "
                                    f"CLI: config system interface → edit {name} → unset allowaccess ping"))
            if "snmp" in aa_parts:
                findings.append(f(C, f"Mgmt Exposure: SNMP on WAN interface '{name}' — "
                                    "community string exposed to internet; immediate risk."))
            if "telnet" in aa_parts:
                findings.append(f(C, f"Mgmt Exposure: Telnet on WAN interface '{name}' — "
                                    "cleartext, remove immediately."))

    # ── Local-in Policies for Management Plane ──
    all_lip = local_in + local_in6
    has_wan_lip = False
    for lip in all_lip:
        intf = nv(lip.get("intf", ""))
        src  = nv(lip.get("srcaddr", ""))
        act  = nv(lip.get("action", ""))
        if intf:
            intf_l = intf.lower()
            if any(w in intf_l for w in ("wan", "outside", "internet", "untrust")):
                has_wan_lip = True
                if src in ("all", "") and act == "accept":
                    findings.append(f(C, f"Local-in: ACCEPT from 'all' on WAN interface '{intf}' — "
                                       "FortiGate management plane is fully exposed. "
                                       "Restrict srcaddr to management IP ranges."))

    if not has_wan_lip:
        findings.append(f(H, "Local-in: no local-in-policies configured on WAN interfaces — "
                            "FortiGate control plane (management, VPN, BGP, etc.) has no explicit "
                            "source restriction. An attacker can target these services directly. "
                            "CLI: config firewall local-in-policy → edit 1 → set intf wan1 "
                            "→ set srcaddr <admin-ip-range> → set action accept"))

    # ── Accept policies with broad source and no rate limiting ──
    broad_accept = 0
    for p in policies:
        if (nv(p.get("action", "")) == "accept" and
                nv(p.get("srcaddr", "")) in ("all", "") and
                not nv(p.get("ips-sensor", ""))):
            broad_accept += 1
    if broad_accept:
        findings.append(f(M, f"Policy Exposure: {broad_accept} accept policy/policies with source 'all' "
                            "and no IPS sensor — these policies have no rate-limiting layer; "
                            "pair with a DoS policy on the same inbound interface."))

    return findings


def antidos_score(all_findings: List[str]) -> Dict[str, Any]:
    """
    Compute a 0–10 DoS protection score.
    Deduct points for severity: CRITICAL=-3, HIGH=-1.5, MEDIUM=-0.5, INFO=-0.1
    Cap deductions per category to avoid double-counting.
    """
    counts = {C: 0, H: 0, M: 0, I: 0}
    for fn in all_findings:
        for sev in (C, H, M, I):
            if fn.startswith(sev + ":"):
                counts[sev] += 1

    deduction = (
        min(counts[C] * 3.0, 6.0) +
        min(counts[H] * 1.5, 4.5) +
        min(counts[M] * 0.5, 2.0) +
        min(counts[I] * 0.1, 0.5)
    )
    score = max(0.0, round(10.0 - deduction, 1))

    if score >= 8:
        grade = "STRONG"
    elif score >= 6:
        grade = "ACCEPTABLE"
    elif score >= 4:
        grade = "WEAK"
    elif score >= 2:
        grade = "POOR"
    else:
        grade = "CRITICAL — NO EFFECTIVE DoS PROTECTION"

    return {"score": score, "grade": grade, "counts": counts}


# ─────────────────────────────────────────────────────────────────────────────
# Report generator — Anti-DoS
# ─────────────────────────────────────────────────────────────────────────────

def generate_antidos_report(
    dos_policies:  List[Dict],
    ips_sensors:   List[Dict],
    interfaces:    List[Dict],
    local_in:      List[Dict],
    local_in6:     List[Dict],
    fw_policies:   List[Dict],
    global_dos:    Dict,
    res_limit:     Dict,
    np_cfg:        Dict,
    out_path:      Path,
):
    W = 80

    # Run all checks
    f1 = antidos_policy_weaknesses(dos_policies, interfaces)
    f2 = antidos_ips_weaknesses(ips_sensors, fw_policies)
    f3 = antidos_hardening_weaknesses(
        interfaces, local_in, local_in6,
        global_dos, res_limit, np_cfg, fw_policies
    )
    all_findings = f1 + f2 + f3
    assessment   = antidos_score(all_findings)

    lines = []

    # ── Header ──
    lines.append("=" * W)
    lines.append(" ANTI-DoS / DoS PROTECTION AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append(f"  Overall DoS Protection Score : {assessment['score']} / 10  "
                 f"— {assessment['grade']}")
    lines.append(f"  CRITICAL: {assessment['counts'][C]}   "
                 f"HIGH: {assessment['counts'][H]}   "
                 f"MEDIUM: {assessment['counts'][M]}   "
                 f"INFO: {assessment['counts'][I]}")
    lines.append("=" * W)
    lines.append("")

    # ── Score interpretation bar ──
    filled = int(assessment['score'])
    bar = "█" * filled + "░" * (10 - filled)
    lines.append(f"  [{bar}] {assessment['score']}/10")
    lines.append("")

    # ── Section 1: DoS Policy Configuration ──
    lines.append("─" * W)
    lines.append("  1. DoS POLICY CONFIGURATION")
    lines.append("─" * W)
    lines.append(f"  DoS policies found: {len(dos_policies)}")
    lines.append("")

    if dos_policies:
        for p in dos_policies:
            pid       = nv(p.get("_id", ""))
            intf      = nv(p.get("interface", ""))
            status    = nv(p.get("status", "enable"))
            srcaddr   = nv(p.get("srcaddr", "all"))
            dstaddr   = nv(p.get("dstaddr", "all"))
            anomalies = p.get("_anomalies", {})

            lines.append(f"  Policy #{pid}  Interface: {intf or '(none)'}  "
                         f"Status: {status}  Src: {srcaddr}  Dst: {dstaddr}")
            lines.append(f"  Anomaly sensors configured: {len(anomalies)}")

            if anomalies:
                lines.append("")
                lines.append(f"  {'Sensor':<26} {'Status':<10} {'Action':<10} {'Threshold':<12} {'Log':<8} {'Assessment'}")
                lines.append(f"  {'─'*26} {'─'*10} {'─'*10} {'─'*12} {'─'*8} {'─'*20}")
                for anom_name, anom in sorted(anomalies.items()):
                    a_status    = nv(anom.get("status", "?"))
                    a_action    = nv(anom.get("action", "?"))
                    a_threshold = nv(anom.get("threshold", "?"))
                    a_log       = nv(anom.get("log", "?"))
                    spec        = ANOMALY_SPECS.get(anom_name)
                    rec         = spec[0] if spec else "?"

                    # Per-sensor assessment
                    if a_status != "enable":
                        assess = "⚠ DISABLED"
                    elif a_action in ("pass", "monitor", ""):
                        assess = "⚠ NOT BLOCKING"
                    elif a_action == "block":
                        try:
                            if int(a_threshold) == 0:
                                assess = "⚠ THRESHOLD=0"
                            elif int(a_threshold) > (rec if isinstance(rec, int) else 9999) * 10:
                                assess = "⚠ THRESH TOO HIGH"
                            else:
                                assess = "✓ OK"
                        except (ValueError, TypeError):
                            assess = "✓ OK"
                    else:
                        assess = f"action:{a_action}"

                    lines.append(f"  {anom_name:<26} {a_status:<10} {a_action:<10} "
                                 f"{a_threshold:<12} {a_log:<8} {assess}")
            lines.append("")

    # Findings for section 1
    if f1:
        lines.append("  Findings:")
        for fn in f1:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(sev, "  ")
            lines.append(f"  {icon} [{sev}] {body}")
    else:
        lines.append("  ✅ No findings in DoS policy configuration.")
    lines.append("")

    # ── Section 2: IPS DoS Anomaly Protection ──
    lines.append("─" * W)
    lines.append("  2. IPS DoS ANOMALY PROTECTION")
    lines.append("─" * W)
    lines.append(f"  IPS sensors found: {len(ips_sensors)}")
    fw_with_ips = sum(1 for p in fw_policies
                      if nv(p.get("ips-sensor", "")) and nv(p.get("action", "")) == "accept")
    fw_total_accept = sum(1 for p in fw_policies if nv(p.get("action", "")) == "accept")
    lines.append(f"  Accept policies with IPS: {fw_with_ips} / {fw_total_accept}")
    lines.append("")

    if f2:
        lines.append("  Findings:")
        for fn in f2:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(sev, "  ")
            lines.append(f"  {icon} [{sev}] {body}")
    else:
        lines.append("  ✅ No findings in IPS DoS anomaly protection.")
    lines.append("")

    # ── Section 3: Related Hardening ──
    lines.append("─" * W)
    lines.append("  3. RELATED HARDENING")
    lines.append("─" * W)

    # Current config summary
    rows_hard = [
        ("tcp-halfopen-timer",   nv(global_dos.get("tcp-halfopen-timer", "(default)"))),
        ("tcp-timewait-timer",   nv(global_dos.get("tcp-timewait-timer", "(default)"))),
        ("anti-replay",          nv(global_dos.get("anti-replay", "(default)"))),
        ("block-session-timer",  nv(global_dos.get("block-session-timer", "(default)"))),
        ("ip-src-check-on-tx",   nv(global_dos.get("ip-src-check-on-tx", "(default)"))),
        ("resource-limit config",str(bool(res_limit))),
        ("NP DoS offload",       nv(np_cfg.get("_np_type", "not detected"))),
        ("Local-in policies",    str(len(local_in + local_in6))),
    ]
    lines.append(ascii_table(rows_hard, "Current DoS-Related Settings"))
    lines.append("")

    if f3:
        lines.append("  Findings:")
        for fn in f3:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(sev, "  ")
            lines.append(f"  {icon} [{sev}] {body}")
    else:
        lines.append("  ✅ No findings in related hardening.")
    lines.append("")

    # ── Section 4: Overall Assessment ──
    lines.append("─" * W)
    lines.append("  4. OVERALL ASSESSMENT & RECOMMENDATIONS")
    lines.append("─" * W)
    lines.append("")

    criticals = [fn for fn in all_findings if fn.startswith("CRITICAL:")]
    highs     = [fn for fn in all_findings if fn.startswith("HIGH:")]

    if criticals:
        lines.append("  🔴 CRITICAL ISSUES (fix immediately):")
        for fn in criticals:
            lines.append(f"    • {':'.join(fn.split(':')[1:]).strip()}")
        lines.append("")

    if highs:
        lines.append("  🟠 HIGH RISK ISSUES:")
        for fn in highs:
            lines.append(f"    • {':'.join(fn.split(':')[1:]).strip()}")
        lines.append("")

    # Recommendation summary with CLI examples
    lines.append("  📋 RECOMMENDATIONS:")
    lines.append("")

    recs = [
        ("1. Create DoS policies on ALL WAN interfaces",
         "config firewall DoS-policy\n"
         "    edit 1\n"
         "        set interface wan1\n"
         "        set srcaddr all\n"
         "        set dstaddr all\n"
         "        set status enable\n"
         "        config anomaly\n"
         "            edit tcp_syn_flood\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 2000\n"
         "            next\n"
         "            edit udp_flood\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 2000\n"
         "            next\n"
         "            edit icmp_flood\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 250\n"
         "            next\n"
         "            edit ip_src_session\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 5000\n"
         "            next\n"
         "            edit tcp_port_scan\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 1000\n"
         "            next\n"
         "            edit ip_land_attack\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 1\n"
         "            next\n"
         "            edit ip_bad_option\n"
         "                set status enable\n"
         "                set log enable\n"
         "                set action block\n"
         "                set threshold 1\n"
         "            next\n"
         "        end\n"
         "    next\n"
         "end"),
        ("2. Harden TCP timers",
         "config system global\n"
         "    set tcp-halfopen-timer 10\n"
         "    set tcp-timewait-timer 1\n"
         "    set anti-replay strict\n"
         "    set block-session-timer 30\n"
         "    set ip-src-check-on-tx enable\n"
         "end"),
        ("3. Restrict management access with local-in-policy",
         "config firewall local-in-policy\n"
         "    edit 1\n"
         "        set intf wan1\n"
         "        set srcaddr <admin-mgmt-subnet>\n"
         "        set dstaddr all\n"
         "        set service HTTPS SSH\n"
         "        set action accept\n"
         "        set schedule always\n"
         "    next\n"
         "    edit 2\n"
         "        set intf wan1\n"
         "        set srcaddr all\n"
         "        set dstaddr all\n"
         "        set service ALL\n"
         "        set action deny\n"
         "        set schedule always\n"
         "    next\n"
         "end"),
        ("4. Configure NP hardware DoS offload (NP6/NP7 platforms)",
         "config system np7\n"
         "    config hpe\n"
         "        set enable-shaper enable\n"
         "        set tcpsyn-max 10000\n"
         "        set udp-max 10000\n"
         "        set icmp-max 1000\n"
         "        set sctp-max 10000\n"
         "    end\n"
         "    set fp-anomaly enable\n"
         "end"),
    ]

    for title, cli in recs:
        lines.append(f"  ▸ {title}")
        for cli_line in cli.splitlines():
            lines.append(f"      {cli_line}")
        lines.append("")

    # ── Footer score ──
    lines.append("=" * W)
    lines.append(f"  DoS Protection Score: {assessment['score']}/10  — {assessment['grade']}")
    lines.append("=" * W)

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: FIREWALL POLICY INTELLIGENCE
# Shadowed rules, duplicate policies, policy usage statistics
# ═════════════════════════════════════════════════════════════════════════════

def _addr_is_any(addr: str) -> bool:
    return addr.lower() in ("all", "any", "")

def _svc_is_any(svc: str) -> bool:
    return svc.upper() in ("ALL", "ANY", "")

def _addr_set(addr_str: str) -> set:
    """Split multi-value address field into a frozenset for comparison."""
    return frozenset(a.strip() for a in addr_str.split() if a.strip())

def _policy_tuple(p: Dict) -> tuple:
    """Canonical key for duplicate detection."""
    return (
        nv(p.get("srcintf", "")),
        nv(p.get("dstintf", "")),
        nv(p.get("action", "")),
        _addr_set(nv(p.get("srcaddr", ""))),
        _addr_set(nv(p.get("dstaddr", ""))),
        _addr_set(nv(p.get("service", ""))),
    )


def check_shadowed_policies(policies: List[Dict]) -> List[str]:
    """
    Detect policies that are shadowed by an earlier, broader rule.
    A policy B is shadowed by policy A if:
      - A appears before B in the list
      - A's srcintf matches B's srcintf (or A accepts any)
      - A's dstintf matches B's dstintf (or A accepts any)
      - A's srcaddr is 'all' (covers B's more specific srcaddr)
      - A's dstaddr is 'all' (covers B's more specific dstaddr)
      - A's service is 'ALL' (covers B's more specific service)
      - A's action == B's action (same permit/deny)
    """
    findings = []

    enabled = [p for p in policies if nv(p.get("status", "enable")) != "disable"]

    for i, p_b in enumerate(enabled):
        pid_b    = nv(p_b.get("policyid", p_b.get("_id", "")))
        name_b   = nv(p_b.get("name", ""))
        srcintf_b = nv(p_b.get("srcintf", ""))
        dstintf_b = nv(p_b.get("dstintf", ""))
        srcaddr_b = nv(p_b.get("srcaddr", ""))
        dstaddr_b = nv(p_b.get("dstaddr", ""))
        service_b = nv(p_b.get("service", ""))
        action_b  = nv(p_b.get("action", ""))

        # Skip if B itself is already any-any
        if (_addr_is_any(srcaddr_b) and _addr_is_any(dstaddr_b)
                and _svc_is_any(service_b)):
            continue

        for p_a in enabled[:i]:
            pid_a    = nv(p_a.get("policyid", p_a.get("_id", "")))
            name_a   = nv(p_a.get("name", ""))
            srcintf_a = nv(p_a.get("srcintf", ""))
            dstintf_a = nv(p_a.get("dstintf", ""))
            srcaddr_a = nv(p_a.get("srcaddr", ""))
            dstaddr_a = nv(p_a.get("dstaddr", ""))
            service_a = nv(p_a.get("service", ""))
            action_a  = nv(p_a.get("action", ""))

            if action_a != action_b:
                continue

            # Interface must match exactly or A must be any
            if srcintf_a and srcintf_b and srcintf_a != srcintf_b:
                continue
            if dstintf_a and dstintf_b and dstintf_a != dstintf_b:
                continue

            # A shadows B if A's addresses are superset of B's
            src_shadows = _addr_is_any(srcaddr_a)
            dst_shadows = _addr_is_any(dstaddr_a)
            svc_shadows = _svc_is_any(service_a)

            # Also check exact match — fully identical is duplicate, not shadow
            if src_shadows and dst_shadows and svc_shadows:
                findings.append(
                    f(H, f"Shadowed Policy: Policy #{pid_b} ('{name_b}') is COMPLETELY SHADOWED "
                         f"by Policy #{pid_a} ('{name_a}'). "
                         f"Policy #{pid_a} has action={action_a} with any-any-any src/dst/service "
                         f"on the same interface pair — Policy #{pid_b} will NEVER be evaluated. "
                         f"Review policy ordering or merge rules.")
                )
                break  # No need to check further shadowers for B

    return findings


def check_duplicate_policies(policies: List[Dict]) -> List[str]:
    """Detect functionally identical policies (same 5-tuple + action)."""
    findings = []
    seen: Dict[tuple, str] = {}

    for p in policies:
        if nv(p.get("status", "enable")) == "disable":
            continue
        pid  = nv(p.get("policyid", p.get("_id", "")))
        name = nv(p.get("name", ""))
        key  = _policy_tuple(p)

        if key in seen:
            first_pid = seen[key]
            findings.append(
                f(H, f"Duplicate Policy: Policy #{pid} ('{name}') is functionally identical to "
                     f"Policy #{first_pid} — same srcintf, dstintf, srcaddr, dstaddr, service, action. "
                     f"Remove the duplicate to avoid rule table confusion.")
            )
        else:
            seen[key] = pid

    return findings


def policy_usage_statistics(
    policies: List[Dict],
    policies6: List[Dict]
) -> Dict[str, Any]:
    """Compute UTM coverage statistics across all firewall policies."""
    all_pol = policies + policies6
    accept  = [p for p in all_pol if nv(p.get("action", "")) == "accept"]
    total   = len(all_pol)
    total_a = len(accept)

    def count_with(field):
        return sum(1 for p in accept if nv(p.get(field, "")))

    stats = {
        "total_policies":     total,
        "total_accept":       total_a,
        "total_deny":         sum(1 for p in all_pol if nv(p.get("action","")) == "deny"),
        "disabled":           sum(1 for p in all_pol if nv(p.get("status","enable")) == "disable"),
        "no_comment":         sum(1 for p in all_pol if not nv(p.get("comments",""))),
        "with_ips":           count_with("ips-sensor"),
        "with_av":            count_with("av-profile"),
        "with_ssl":           count_with("ssl-ssh-profile"),
        "with_webfilter":     count_with("webfilter-profile"),
        "with_dns":           count_with("dnsfilter-profile"),
        "with_appcontrol":    count_with("application-list"),
        "with_dlp":           count_with("dlp-profile"),
        "with_waf":           count_with("waf-profile"),
        "with_casb":          count_with("casb-profile"),
        "with_vpatch":        count_with("virtual-patch-profile"),
        "with_llm":           count_with("llm-profile"),
        "with_logging":       sum(1 for p in accept if nv(p.get("logtraffic","")) not in ("","disable")),
        "any_any_any":        sum(1 for p in accept
                                  if _addr_is_any(nv(p.get("srcaddr","")))
                                  and _addr_is_any(nv(p.get("dstaddr","")))
                                  and _svc_is_any(nv(p.get("service","")))),
        "nat_disabled":       sum(1 for p in accept if nv(p.get("nat","")) != "enable"),
        "capture_packet":     sum(1 for p in all_pol if nv(p.get("capture-packet","")) == "enable"),
    }
    return stats


def generate_policy_intelligence_report(
    policies: List[Dict],
    policies6: List[Dict],
    out_path: Path
):
    shadow_f = check_shadowed_policies(policies)
    dupl_f   = check_duplicate_policies(policies)
    stats    = policy_usage_statistics(policies, policies6)
    W = 80

    lines = []
    lines.append("=" * W)
    lines.append(" FIREWALL POLICY INTELLIGENCE AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")

    # ── Coverage Statistics ──
    ta = stats["total_accept"] or 1  # avoid div/0
    lines.append("─" * W)
    lines.append("  POLICY COVERAGE STATISTICS")
    lines.append("─" * W)
    lines.append("")

    stat_rows = [
        ("Total policies",           str(stats["total_policies"])),
        ("  Accept",                 str(stats["total_accept"])),
        ("  Deny/Drop",              str(stats["total_deny"])),
        ("  Disabled",               str(stats["disabled"])),
        ("  No comment/description", str(stats["no_comment"])),
        ("ANY-ANY-ANY accept rules", str(stats["any_any_any"])),
        ("NAT disabled (accept)",    str(stats["nat_disabled"])),
        ("Packet capture enabled",   str(stats["capture_packet"])),
        ("─" * 28,                   "─" * 30),
        ("WITH IPS sensor",
         f"{stats['with_ips']}/{stats['total_accept']} "
         f"({100*stats['with_ips']//ta}%)"),
        ("WITHOUT IPS sensor",
         f"{stats['total_accept']-stats['with_ips']}/{stats['total_accept']} "
         f"({100*(stats['total_accept']-stats['with_ips'])//ta}%)"),
        ("WITH SSL inspection",
         f"{stats['with_ssl']}/{stats['total_accept']} "
         f"({100*stats['with_ssl']//ta}%)"),
        ("WITHOUT SSL inspection",
         f"{stats['total_accept']-stats['with_ssl']}/{stats['total_accept']} "
         f"({100*(stats['total_accept']-stats['with_ssl'])//ta}%)"),
        ("WITH Antivirus",
         f"{stats['with_av']}/{stats['total_accept']} "
         f"({100*stats['with_av']//ta}%)"),
        ("WITH Web Filter",
         f"{stats['with_webfilter']}/{stats['total_accept']} "
         f"({100*stats['with_webfilter']//ta}%)"),
        ("WITH DNS Filter",
         f"{stats['with_dns']}/{stats['total_accept']} "
         f"({100*stats['with_dns']//ta}%)"),
        ("WITH App Control",
         f"{stats['with_appcontrol']}/{stats['total_accept']} "
         f"({100*stats['with_appcontrol']//ta}%)"),
        ("WITH DLP Profile",
         f"{stats['with_dlp']}/{stats['total_accept']} "
         f"({100*stats['with_dlp']//ta}%)"),
        ("WITH WAF Profile",
         f"{stats['with_waf']}/{stats['total_accept']} "
         f"({100*stats['with_waf']//ta}%)"),
        ("WITH CASB Profile",
         f"{stats['with_casb']}/{stats['total_accept']} "
         f"({100*stats['with_casb']//ta}%)"),
        ("WITH Virtual Patch",
         f"{stats['with_vpatch']}/{stats['total_accept']} "
         f"({100*stats['with_vpatch']//ta}%)"),
        ("WITH LLM Profile",
         f"{stats['with_llm']}/{stats['total_accept']} "
         f"({100*stats['with_llm']//ta}%)"),
        ("WITH Logging",
         f"{stats['with_logging']}/{stats['total_accept']} "
         f"({100*stats['with_logging']//ta}%)"),
    ]
    lines.append(ascii_table(stat_rows, "Security Profile Coverage"))
    lines.append("")

    # Visual coverage bars
    lines.append("  Coverage Bars (accept policies):")
    for label, key in [
        ("IPS",         "with_ips"),
        ("SSL Inspect", "with_ssl"),
        ("Antivirus",   "with_av"),
        ("Web Filter",  "with_webfilter"),
        ("App Control", "with_appcontrol"),
        ("Logging",     "with_logging"),
        ("DLP",         "with_dlp"),
        ("WAF",         "with_waf"),
    ]:
        val = stats[key]
        pct = (val * 20) // ta if ta else 0
        bar = "█" * pct + "░" * (20 - pct)
        pct_num = 100 * val // ta if ta else 0
        lines.append(f"  {label:<14} [{bar}] {pct_num:>3}%  ({val}/{stats['total_accept']})")
    lines.append("")

    # Flag low coverage
    low_cov_findings = []
    for label, key in [("IPS","with_ips"),("SSL inspection","with_ssl"),("Antivirus","with_av"),("Logging","with_logging")]:
        pct = 100 * stats[key] // ta if ta else 0
        if pct < 50:
            low_cov_findings.append(f(H, f"Coverage: only {pct}% of accept policies have {label} — "
                                        "large portion of traffic flows uninspected."))
        elif pct < 80:
            low_cov_findings.append(f(M, f"Coverage: {pct}% of accept policies have {label} — "
                                       "consider raising coverage."))
    if stats["any_any_any"] > 0:
        low_cov_findings.append(f(C, f"Coverage: {stats['any_any_any']} ANY-ANY-ANY accept "
                                     "policies found — these permit all traffic unrestricted."))
    if stats["capture_packet"] > 0:
        low_cov_findings.append(f(M, f"Coverage: {stats['capture_packet']} policies have "
                                    "packet capture enabled — debug artifact, disable in production."))

    if low_cov_findings:
        lines.append("  Coverage Findings:")
        for fn in low_cov_findings:
            sev = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
            lines.append(f"  {icon} [{sev}] {body}")
    lines.append("")

    # ── Shadowed Policies ──
    lines.append("─" * W)
    lines.append("  SHADOWED POLICY DETECTION")
    lines.append("─" * W)
    lines.append("")
    lines.append("  A policy is shadowed when an earlier rule with broader match criteria")
    lines.append("  will always be evaluated first, making the later policy unreachable.")
    lines.append("")
    if shadow_f:
        lines.append(f"  Found {len(shadow_f)} shadowed policy/policies:")
        for fn in shadow_f:
            body = ":".join(fn.split(":")[1:]).strip()
            lines.append(f"  🟠 [HIGH] {body}")
    else:
        lines.append("  ✅ No shadowed policies detected.")
    lines.append("")

    # ── Duplicate Policies ──
    lines.append("─" * W)
    lines.append("  DUPLICATE POLICY DETECTION")
    lines.append("─" * W)
    lines.append("")
    lines.append("  Duplicate policies share the same srcintf, dstintf, srcaddr,")
    lines.append("  dstaddr, service, and action. The second entry is redundant.")
    lines.append("")
    if dupl_f:
        lines.append(f"  Found {len(dupl_f)} duplicate policy pair(s):")
        for fn in dupl_f:
            body = ":".join(fn.split(":")[1:]).strip()
            lines.append(f"  🟠 [HIGH] {body}")
    else:
        lines.append("  ✅ No duplicate policies detected.")
    lines.append("")

    # ── Recommendations ──
    lines.append("─" * W)
    lines.append("  RECOMMENDATIONS")
    lines.append("─" * W)
    lines.append("")
    if shadow_f:
        lines.append("  ▸ Review and reorder shadowed policies:")
        lines.append("    Either move the specific rule ABOVE the broad rule, or")
        lines.append("    merge rules if the intent is truly the same.")
        lines.append("")
    if dupl_f:
        lines.append("  ▸ Remove duplicate policies:")
        lines.append("    Keep the first occurrence and delete the duplicate.")
        lines.append("    config firewall policy → delete <duplicate_policy_id>")
        lines.append("")
    if stats["no_comment"] > 0:
        lines.append(f"  ▸ Document {stats['no_comment']} undocumented policies:")
        lines.append("    config firewall policy → edit <id> → set comments '<purpose>'")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return low_cov_findings + shadow_f + dupl_f


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: UNUSED OBJECTS AUDIT
# Addresses, address groups, services, service groups, VIPs
# ═════════════════════════════════════════════════════════════════════════════

def parse_address_objects(t):    return extract_block(t, "firewall address")
def parse_address_groups(t):     return extract_block(t, "firewall addrgrp")
def parse_service_custom(t):     return extract_block(t, "firewall service custom")
def parse_service_groups(t):     return extract_block(t, "firewall service group")
def parse_vip_objects(t):        return extract_block(t, "firewall vip")
def parse_vip_groups(t):         return extract_block(t, "firewall vipgrp")
def parse_ip_pools(t):           return extract_block(t, "firewall ippool")
def parse_schedules(t):          return extract_block(t, "firewall schedule recurring")
def parse_schedules_onetime(t):  return extract_block(t, "firewall schedule onetime")


def build_object_reference_map(
    policies: List[Dict],
    policies6: List[Dict],
    ssl_profiles: List[Dict],
    vip_groups: List[Dict],
    addr_groups: List[Dict],
    svc_groups: List[Dict],
) -> Dict[str, set]:
    """
    Build a map of {object_name: set_of_policy_ids_referencing_it}.
    Scans all policy fields that reference named objects.
    """
    refs: Dict[str, set] = {}

    def add_ref(name: str, pid: str):
        n = nv(name)
        if n and n.lower() not in ("all", "any", ""):
            refs.setdefault(n, set()).add(pid)

    def scan_policy(p: Dict, prefix="pol"):
        pid = nv(p.get("policyid", p.get("_id", "")))
        for fld in ("srcaddr","dstaddr","srcaddr6","dstaddr6",
                    "poolname","internet-service-name","internet-service-id"):
            for token in nv(p.get(fld,"")).split():
                add_ref(token, f"{prefix}#{pid}")
        for fld in ("service",):
            for token in nv(p.get(fld,"")).split():
                add_ref(token, f"{prefix}#{pid}")
        for fld in ("schedule",):
            add_ref(nv(p.get(fld,"")), f"{prefix}#{pid}")
        # UTM profile references
        for fld in ("ips-sensor","av-profile","webfilter-profile","dnsfilter-profile",
                    "application-list","ssl-ssh-profile","dlp-profile","waf-profile",
                    "emailfilter-profile","file-filter-profile","virtual-patch-profile",
                    "casb-profile","llm-profile","voip-profile"):
            add_ref(nv(p.get(fld,"")), f"{prefix}#{pid}")

    for p in policies + policies6:
        scan_policy(p, "pol")

    # VIP groups reference VIPs
    for g in vip_groups:
        gname = nv(g.get("name", g.get("_id","")))
        for token in nv(g.get("member","")).split():
            add_ref(token, f"vipgrp:{gname}")

    # Address groups reference addresses
    for g in addr_groups:
        gname = nv(g.get("name", g.get("_id","")))
        for token in nv(g.get("member","")).split():
            add_ref(token, f"addrgrp:{gname}")

    # Service groups reference services
    for g in svc_groups:
        gname = nv(g.get("name", g.get("_id","")))
        for token in nv(g.get("member","")).split():
            add_ref(token, f"svcgrp:{gname}")

    return refs


def check_unused_objects(
    addr_objs:    List[Dict],
    addr_groups:  List[Dict],
    svc_custom:   List[Dict],
    svc_groups:   List[Dict],
    vip_objs:     List[Dict],
    vip_groups:   List[Dict],
    ip_pools:     List[Dict],
    schedules:    List[Dict],
    schedules_ot: List[Dict],
    ref_map:      Dict[str, set],
) -> List[str]:
    findings = []

    # Built-in names that are always used and should be excluded
    BUILTINS = {
        "all", "none", "any", "always", "never",
        "PING", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP",
        "POP3", "IMAP", "RDP", "NTP", "SNMP", "ALL", "ALL_TCP",
        "ALL_UDP", "ALL_ICMP",
    }

    def is_unused(name: str) -> bool:
        n = nv(name)
        return n not in BUILTINS and n not in ref_map

    # Address objects
    for obj in addr_objs:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            typ   = nv(obj.get("type",""))
            subnet = nv(obj.get("subnet","")) or nv(obj.get("fqdn","")) or nv(obj.get("iprange",""))
            findings.append(f(I, f"Unused Address: '{name}' ({typ} {subnet}) is not referenced "
                                "by any policy, group, or VIP. Consider removing to keep the "
                                "object table clean."))

    # Address groups
    for obj in addr_groups:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            findings.append(f(I, f"Unused AddressGroup: '{name}' is not referenced by any "
                                "policy. Remove or consolidate."))

    # Service custom
    for obj in svc_custom:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            proto = nv(obj.get("protocol",""))
            findings.append(f(I, f"Unused Service: '{name}' ({proto}) not referenced by any "
                                "policy or group."))

    # Service groups
    for obj in svc_groups:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            findings.append(f(I, f"Unused ServiceGroup: '{name}' not referenced anywhere."))

    # VIPs
    for obj in vip_objs:
        name    = nv(obj.get("name", obj.get("_id","")))
        ext_ip  = nv(obj.get("extip",""))
        map_ip  = nv(obj.get("mappedip",""))
        ext_intf = nv(obj.get("extintf",""))
        if is_unused(name):
            findings.append(f(M, f"Unused VIP: '{name}' (extip:{ext_ip} → mappedip:{map_ip} "
                                f"on {ext_intf}) is not used in any policy. "
                                "Unused VIPs may represent forgotten port-forwards — "
                                "verify they are intentionally disabled or remove them."))

    # IP Pools
    for obj in ip_pools:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            pool_type = nv(obj.get("type",""))
            startip   = nv(obj.get("startip",""))
            endip     = nv(obj.get("endip",""))
            findings.append(f(I, f"Unused IP Pool: '{name}' ({pool_type} {startip}-{endip}) "
                                "not referenced by any policy."))

    # Schedules
    for obj in schedules + schedules_ot:
        name = nv(obj.get("name", obj.get("_id","")))
        if is_unused(name):
            findings.append(f(I, f"Unused Schedule: '{name}' not referenced by any policy."))

    return findings


def generate_unused_objects_report(
    addr_objs, addr_groups, svc_custom, svc_groups,
    vip_objs, vip_groups, ip_pools, schedules, schedules_ot,
    policies, policies6, ssl_profiles,
    out_path: Path
):
    ref_map = build_object_reference_map(
        policies, policies6, ssl_profiles,
        vip_groups, addr_groups, svc_groups
    )
    findings = check_unused_objects(
        addr_objs, addr_groups, svc_custom, svc_groups,
        vip_objs, vip_groups, ip_pools, schedules, schedules_ot,
        ref_map
    )

    # Categorize
    unused_addr  = [f for f in findings if "Unused Address:" in f and "Group" not in f]
    unused_agrp  = [f for f in findings if "Unused AddressGroup:" in f]
    unused_svc   = [f for f in findings if "Unused Service:" in f and "Group" not in f]
    unused_sgrp  = [f for f in findings if "Unused ServiceGroup:" in f]
    unused_vip   = [f for f in findings if "Unused VIP:" in f]
    unused_pool  = [f for f in findings if "Unused IP Pool:" in f]
    unused_sched = [f for f in findings if "Unused Schedule:" in f]

    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" UNUSED OBJECTS AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")

    summary_rows = [
        ("Address objects total",    str(len(addr_objs))),
        ("  Unused",                 str(len(unused_addr))),
        ("Address groups total",     str(len(addr_groups))),
        ("  Unused",                 str(len(unused_agrp))),
        ("Custom services total",    str(len(svc_custom))),
        ("  Unused",                 str(len(unused_svc))),
        ("Service groups total",     str(len(svc_groups))),
        ("  Unused",                 str(len(unused_sgrp))),
        ("VIP objects total",        str(len(vip_objs))),
        ("  Unused",                 str(len(unused_vip))),
        ("IP Pools total",           str(len(ip_pools))),
        ("  Unused",                 str(len(unused_pool))),
        ("Schedules total",          str(len(schedules)+len(schedules_ot))),
        ("  Unused",                 str(len(unused_sched))),
    ]
    lines.append(ascii_table(summary_rows, "Object Usage Summary"))
    lines.append("")

    for label, group in [
        ("UNUSED VIPs (verify these are not forgotten port-forwards)", unused_vip),
        ("UNUSED ADDRESS OBJECTS", unused_addr),
        ("UNUSED ADDRESS GROUPS", unused_agrp),
        ("UNUSED CUSTOM SERVICES", unused_svc),
        ("UNUSED SERVICE GROUPS", unused_sgrp),
        ("UNUSED IP POOLS", unused_pool),
        ("UNUSED SCHEDULES", unused_sched),
    ]:
        lines.append("─" * W)
        lines.append(f"  {label}")
        lines.append("─" * W)
        if group:
            for fn in group:
                body = ":".join(fn.split(":")[1:]).strip()
                lines.append(f"  • {body}")
        else:
            lines.append("  ✅ None found.")
        lines.append("")

    lines.append("─" * W)
    lines.append("  CLEANUP NOTES")
    lines.append("─" * W)
    lines.append("  • Unused VIPs are Medium severity — verify before deletion.")
    lines.append("    An 'unused' VIP may be referenced by an external load balancer.")
    lines.append("  • Unused address/service objects are Info — safe to clean up")
    lines.append("    but do a final text search in the full config before deleting.")
    lines.append("  • FortiGate CLI cleanup:")
    lines.append("    config firewall address → delete <name>")
    lines.append("    config firewall service custom → delete <name>")
    lines.append("    config firewall vip → delete <name>")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: VIP SECURITY AUDIT
# Published services, exposure analysis
# ═════════════════════════════════════════════════════════════════════════════

# Well-known risky port mappings
RISKY_PORTS = {
    "21":   ("FTP",     H,  "FTP is unencrypted and uses passive mode which complicates firewall rules."),
    "23":   ("Telnet",  C,  "Telnet is cleartext. Any exposure is critical."),
    "25":   ("SMTP",    M,  "Direct SMTP from internet. Use a mail relay/gateway instead."),
    "53":   ("DNS",     M,  "DNS exposed externally — risk of DNS amplification or zone transfer."),
    "80":   ("HTTP",    M,  "HTTP (unencrypted web) published externally."),
    "110":  ("POP3",    M,  "POP3 unencrypted."),
    "135":  ("RPC",     H,  "MS-RPC exposed externally — lateral movement risk."),
    "137":  ("NetBIOS", H,  "NetBIOS exposed externally — information disclosure."),
    "138":  ("NetBIOS", H,  "NetBIOS datagram exposed externally."),
    "139":  ("NetBIOS", H,  "NetBIOS session exposed externally."),
    "143":  ("IMAP",    M,  "IMAP unencrypted."),
    "389":  ("LDAP",    H,  "LDAP exposed externally — credential enumeration risk."),
    "445":  ("SMB",     C,  "SMB/CIFS exposed to internet — EternalBlue/ransomware risk. Remove immediately."),
    "1433": ("MSSQL",   C,  "MS SQL Server exposed to internet — direct DB access risk."),
    "1521": ("Oracle",  C,  "Oracle DB exposed to internet."),
    "3306": ("MySQL",   C,  "MySQL exposed to internet."),
    "3389": ("RDP",     C,  "RDP exposed to internet — BlueKeep/credential brute-force. Use VPN instead."),
    "4899": ("Radmin",  C,  "Radmin exposed — remote admin tool with known vulnerabilities."),
    "5432": ("Postgres",C,  "PostgreSQL exposed to internet."),
    "5900": ("VNC",     C,  "VNC exposed to internet — weak auth, cleartext capable."),
    "5985": ("WinRM",   H,  "WinRM (PowerShell remoting) exposed to internet."),
    "5986": ("WinRM",   H,  "WinRM HTTPS exposed to internet."),
    "6379": ("Redis",   C,  "Redis exposed to internet — no auth by default, RCE risk."),
    "8080": ("HTTP-alt",M,  "Alternative HTTP port exposed externally."),
    "8443": ("HTTPS-alt",I, "Alternative HTTPS port exposed externally."),
    "27017":("MongoDB", C,  "MongoDB exposed to internet — no auth by default historically."),
}


def vip_weaknesses(vip: Dict, policies: List[Dict]) -> List[str]:
    """Analyze a VIP for security issues."""
    findings = []
    name     = nv(vip.get("name", vip.get("_id","")))
    extip    = nv(vip.get("extip",""))
    mappedip = nv(vip.get("mappedip",""))
    extintf  = nv(vip.get("extintf",""))
    ext_port = nv(vip.get("extservice","")) or nv(vip.get("portforward",""))
    proto    = nv(vip.get("protocol",""))
    ext_p    = nv(vip.get("extport",""))
    map_p    = nv(vip.get("mappedport",""))
    src_filt = nv(vip.get("src-filter",""))
    nat_src  = nv(vip.get("nat-source-vip",""))
    vip_type = nv(vip.get("type","static-nat"))
    comment  = nv(vip.get("comment",""))
    arp_reply = nv(vip.get("arp-reply",""))

    # Is this VIP used in any policy?
    name_in_policy = any(name in nv(p.get("dstaddr","")) for p in policies)

    if not name_in_policy:
        findings.append(f(M, f"VIP '{name}': not referenced in any firewall policy — "
                            "port-forward is defined but no policy permits traffic to it. "
                            "Verify if this VIP is intentionally inactive or is an orphan."))

    # Source filter check
    if not src_filt or src_filt in ("0.0.0.0", ""):
        findings.append(f(M, f"VIP '{name}': no src-filter configured — "
                            f"ALL internet IPs can attempt to reach the mapped destination ({mappedip}). "
                            "Add src-filter to restrict to known source IPs where possible. "
                            "CLI: edit vip → set src-filter <ip-range>"))

    # No comment
    if not comment:
        findings.append(f(I, f"VIP '{name}': no comment — document the purpose of this port-forward."))

    # Check exposed port risks
    for port_str in [ext_p, map_p]:
        for port_token in port_str.split():
            port_clean = port_token.split("-")[0].strip()
            if port_clean in RISKY_PORTS:
                svc_name, severity, detail = RISKY_PORTS[port_clean]
                findings.append(f(severity,
                    f"VIP '{name}': exposes {svc_name} (port {port_clean}) from internet → {mappedip}. "
                    f"{detail}"))

    # ARP reply on WAN (can cause issues)
    if arp_reply == "enable" and extintf:
        extintf_l = extintf.lower()
        if any(w in extintf_l for w in ("wan","internet","outside","untrust")):
            findings.append(f(I, f"VIP '{name}': arp-reply enabled on WAN interface '{extintf}' — "
                                "verify this is correct for your external IP assignment."))

    return findings


def generate_vip_report(vip_objs: List[Dict], vip_groups: List[Dict],
                         policies: List[Dict], out_path: Path) -> List[str]:
    all_findings = []
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" VIP / PORT-FORWARD SECURITY AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")
    lines.append(f"  VIP objects: {len(vip_objs)}   VIP groups: {len(vip_groups)}")
    lines.append("")

    if not vip_objs:
        lines.append("  No VIP objects configured.")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return []

    for vip in vip_objs:
        name     = nv(vip.get("name", vip.get("_id","")))
        extip    = nv(vip.get("extip",""))
        mappedip = nv(vip.get("mappedip",""))
        extintf  = nv(vip.get("extintf",""))
        ext_p    = nv(vip.get("extport",""))
        map_p    = nv(vip.get("mappedport",""))
        src_filt = nv(vip.get("src-filter",""))
        proto    = nv(vip.get("protocol","tcp"))
        vip_type = nv(vip.get("type","static-nat"))
        comment  = nv(vip.get("comment",""))

        rows = [
            ("VIP Name",        name),
            ("Type",            vip_type),
            ("External IP",     extip),
            ("External Port",   ext_p or "(all)"),
            ("Mapped IP",       mappedip),
            ("Mapped Port",     map_p or "(same)"),
            ("Interface",       extintf),
            ("Protocol",        proto),
            ("Source Filter",   src_filt or "(none — any source)"),
            ("Comment",         comment or "(none)"),
        ]
        lines.append("─" * W)
        lines.append(ascii_table(rows, f"VIP: {name}"))

        w = vip_weaknesses(vip, policies)
        all_findings.extend(w)
        if w:
            lines.append("  Findings:")
            for fn in w:
                sev  = fn.split(":")[0]
                body = ":".join(fn.split(":")[1:]).strip()
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
                lines.append(f"  {icon} [{sev}] {body}")
        else:
            lines.append("  ✅ No issues found.")
        lines.append("")

    # Critical summary
    crits = [f for f in all_findings if f.startswith("CRITICAL:")]
    if crits:
        lines.append("─" * W)
        lines.append("  🔴 CRITICAL VIP EXPOSURES (remediate immediately):")
        for fn in crits:
            body = ":".join(fn.split(":")[1:]).strip()
            lines.append(f"  • {body}")
        lines.append("")
        lines.append("  For each critical VIP, consider:")
        lines.append("  1. Remove the VIP entirely and use VPN instead (RDP, SMB, DB)")
        lines.append("  2. Add src-filter to restrict to known IPs")
        lines.append("  3. Move service behind SSL-VPN or Zero Trust proxy")
        lines.append("  CLI: config firewall vip → edit <name> → set src-filter <allowed-ip>")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return all_findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: SD-WAN AUDIT
# ═════════════════════════════════════════════════════════════════════════════

def parse_sdwan(text: str) -> Dict[str, Any]:
    """
    Parse 'config system sdwan' with nested members and health-check blocks.
    Returns flat cfg dict plus _members and _health_checks lists.
    """
    lines = text.splitlines()
    in_block = False
    cfg: Dict[str, Any] = {"_members": [], "_health_checks": [], "_rules": []}
    depth = 0
    sub_type = ""   # "member" | "health-check" | "service"
    cur_obj: Dict[str, Any] = {}

    for raw in lines:
        line = raw.strip()

        if line == "config system sdwan":
            in_block = True
            continue
        if not in_block:
            continue

        if line == "config members" and depth == 0:
            sub_type = "member"
            depth = 1
            continue
        if line == "config health-check" and depth == 0:
            sub_type = "health-check"
            depth = 1
            continue
        if line == "config service" and depth == 0:
            sub_type = "service"
            depth = 1
            continue

        if depth == 1:
            if line.startswith("edit "):
                if cur_obj:
                    if sub_type == "member":
                        cfg["_members"].append(cur_obj)
                    elif sub_type == "health-check":
                        cfg["_health_checks"].append(cur_obj)
                    elif sub_type == "service":
                        cfg["_rules"].append(cur_obj)
                oid = line.split(None,1)[1].strip().strip('"')
                cur_obj = {"_id": oid}
                continue
            if line == "next":
                if cur_obj:
                    if sub_type == "member":
                        cfg["_members"].append(cur_obj)
                    elif sub_type == "health-check":
                        cfg["_health_checks"].append(cur_obj)
                    elif sub_type == "service":
                        cfg["_rules"].append(cur_obj)
                cur_obj = {}
                continue
            if line == "end":
                if cur_obj:
                    if sub_type == "member":
                        cfg["_members"].append(cur_obj)
                    elif sub_type == "health-check":
                        cfg["_health_checks"].append(cur_obj)
                    elif sub_type == "service":
                        cfg["_rules"].append(cur_obj)
                cur_obj = {}
                sub_type = ""
                depth = 0
                continue
            if line.startswith("set "):
                k, v = parse_set_line(line)
                if k:
                    cur_obj[k] = v
            continue

        if depth == 0:
            if line == "end":
                break
            if line.startswith("set "):
                k, v = parse_set_line(line)
                if k:
                    cfg[k] = v

    return cfg


def sdwan_weaknesses(cfg: Dict) -> List[str]:
    findings = []

    status   = nv(cfg.get("status","disable"))
    members  = cfg.get("_members", [])
    hc_list  = cfg.get("_health_checks", [])
    rules    = cfg.get("_rules", [])
    load_bal = nv(cfg.get("load-balance-mode",""))

    if status != "enable":
        findings.append(f(I, "SD-WAN: SD-WAN is not enabled on this device."))
        return findings

    if not members:
        findings.append(f(H, "SD-WAN: enabled but no WAN members configured."))
        return findings

    # Member-level checks
    monitored_intfs = set()
    for hc in hc_list:
        members_str = nv(hc.get("members",""))
        for m in members_str.split():
            monitored_intfs.add(m)

    for m in members:
        mid      = nv(m.get("_id",""))
        intf     = nv(m.get("interface",""))
        gateway  = nv(m.get("gateway",""))
        priority = nv(m.get("priority",""))
        weight   = nv(m.get("weight",""))
        cost     = nv(m.get("cost",""))
        status_m = nv(m.get("status","enable"))

        if status_m == "disable":
            findings.append(f(I, f"SD-WAN member {mid} ('{intf}'): disabled — not participating in SD-WAN."))
            continue

        if not gateway:
            findings.append(f(M, f"SD-WAN member {mid} ('{intf}'): no gateway configured — "
                                "failover routing will be unreliable."))

        if mid not in monitored_intfs and intf not in monitored_intfs:
            findings.append(f(H, f"SD-WAN member {mid} ('{intf}'): NOT monitored by any health-check — "
                                "link failures will not trigger failover. "
                                "Add a health-check and reference this member."))

    # Health-check checks
    if not hc_list:
        findings.append(f(C, "SD-WAN: NO health-checks configured — link failures are UNDETECTED. "
                            "SD-WAN cannot failover without health monitoring. "
                            "CLI: config system sdwan → config health-check → edit MyHC "
                            "→ set server 8.8.8.8 → set interval 500 → set failtime 3"))
    else:
        for hc in hc_list:
            hcid       = nv(hc.get("_id",""))
            server     = nv(hc.get("server",""))
            interval   = nv(hc.get("interval",""))
            failtime   = nv(hc.get("failtime",""))
            recovertime = nv(hc.get("recovertime",""))
            probe_pkt  = nv(hc.get("probe-packets",""))
            thresh_lat = nv(hc.get("latency-threshold",""))
            thresh_jit = nv(hc.get("jitter-threshold",""))
            thresh_pkt = nv(hc.get("packetloss-threshold",""))
            protocol   = nv(hc.get("protocol",""))

            if not server:
                findings.append(f(H, f"SD-WAN health-check '{hcid}': no probe server set — "
                                    "health-check will not function."))

            try:
                if int(interval) > 2000:
                    findings.append(f(M, f"SD-WAN health-check '{hcid}': interval {interval}ms is high — "
                                       "slow failure detection; consider ≤ 500ms for fast failover."))
            except (ValueError, TypeError):
                if not interval:
                    findings.append(f(I, f"SD-WAN health-check '{hcid}': interval not set — using default."))

            try:
                if int(failtime) > 5:
                    findings.append(f(M, f"SD-WAN health-check '{hcid}': failtime {failtime} — "
                                       "requires {failtime} failures before declaring link down; "
                                       "consider 3 for faster failover."))
            except (ValueError, TypeError):
                pass

            if not thresh_lat:
                findings.append(f(M, f"SD-WAN health-check '{hcid}': no latency-threshold — "
                                    "poor-quality links with high latency will still be used. "
                                    "Set: set latency-threshold 150"))
            if not thresh_jit:
                findings.append(f(M, f"SD-WAN health-check '{hcid}': no jitter-threshold — "
                                    "jittery links will not be penalized. "
                                    "Set: set jitter-threshold 30"))
            if not thresh_pkt:
                findings.append(f(M, f"SD-WAN health-check '{hcid}': no packetloss-threshold — "
                                    "links with packet loss will still carry traffic. "
                                    "Set: set packetloss-threshold 5"))

    # SD-WAN rules / SLA
    if not rules:
        findings.append(f(M, "SD-WAN: no traffic steering rules (service rules) configured — "
                            "all traffic uses default load-balance mode without application-aware routing."))
    else:
        for rule in rules:
            rid     = nv(rule.get("_id",""))
            mode    = nv(rule.get("mode",""))
            sla_ifs = nv(rule.get("sla-stickiness",""))
            priority_m = nv(rule.get("priority-members",""))

            if mode == "manual" and not priority_m:
                findings.append(f(I, f"SD-WAN rule {rid}: manual mode with no priority-members — "
                                    "consider SLA mode for quality-aware routing."))

    return findings


def generate_sdwan_report(sdwan_cfg: Dict, out_path: Path) -> List[str]:
    findings = sdwan_weaknesses(sdwan_cfg)
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" SD-WAN CONFIGURATION AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")

    members = sdwan_cfg.get("_members", [])
    hc_list = sdwan_cfg.get("_health_checks", [])
    rules   = sdwan_cfg.get("_rules", [])

    rows = [
        ("SD-WAN Status",       nv(sdwan_cfg.get("status","disable"))),
        ("Load Balance Mode",   nv(sdwan_cfg.get("load-balance-mode",""))),
        ("Members",             str(len(members))),
        ("Health Checks",       str(len(hc_list))),
        ("Traffic Rules",       str(len(rules))),
    ]
    lines.append(ascii_table(rows, "SD-WAN Overview"))
    lines.append("")

    if members:
        lines.append("─" * W)
        lines.append("  WAN MEMBERS")
        lines.append("─" * W)
        for m in members:
            mid  = nv(m.get("_id",""))
            intf = nv(m.get("interface",""))
            gw   = nv(m.get("gateway",""))
            pri  = nv(m.get("priority","1"))
            cost = nv(m.get("cost","0"))
            stat = nv(m.get("status","enable"))
            lines.append(f"  Member {mid}: intf={intf}  gw={gw}  priority={pri}  cost={cost}  status={stat}")
        lines.append("")

    if hc_list:
        lines.append("─" * W)
        lines.append("  HEALTH CHECKS")
        lines.append("─" * W)
        for hc in hc_list:
            hcid      = nv(hc.get("_id",""))
            server    = nv(hc.get("server",""))
            interval  = nv(hc.get("interval",""))
            proto     = nv(hc.get("protocol","ping"))
            lat_thr   = nv(hc.get("latency-threshold",""))
            jit_thr   = nv(hc.get("jitter-threshold",""))
            pkt_thr   = nv(hc.get("packetloss-threshold",""))
            lines.append(f"  HC '{hcid}': server={server}  protocol={proto}  "
                         f"interval={interval}ms  latency≤{lat_thr or '?'}ms  "
                         f"jitter≤{jit_thr or '?'}ms  loss≤{pkt_thr or '?'}%")
        lines.append("")

    lines.append("─" * W)
    lines.append("  FINDINGS")
    lines.append("─" * W)
    if findings:
        for fn in findings:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
            lines.append(f"  {icon} [{sev}] {body}")
    else:
        lines.append("  ✅ SD-WAN configuration looks healthy.")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: INTERFACE EXPOSURE SCORE
# ═════════════════════════════════════════════════════════════════════════════

# Exposure scoring weights per protocol (higher = worse exposure)
EXPOSURE_WEIGHTS = {
    "telnet":   10,   # cleartext — worst possible
    "http":     9,    # cleartext management
    "snmp":     8,    # community strings / info disclosure
    "ssh":      5,    # encrypted but brute-force target
    "https":    4,    # encrypted but still exposed GUI
    "ping":     2,    # ICMP recon
    "fmg-access": 7,  # FortiManager — management fabric
    "fabric":   6,    # Security Fabric on WAN
    "fnbam":    3,    # FortiAuthenticator
}

def interface_exposure_score(intf: Dict) -> Dict[str, Any]:
    """Compute an exposure score 0-10 for one interface."""
    name   = nv(intf.get("name", intf.get("_id","")))
    role   = nv(intf.get("role",""))
    aa     = nv(intf.get("allowaccess",""))
    typ    = nv(intf.get("type",""))
    ip     = nv(intf.get("ip",""))

    aa_parts = set(aa.lower().split())
    score = 0
    exposed = []
    for proto, weight in EXPOSURE_WEIGHTS.items():
        if proto in aa_parts:
            score += weight
            exposed.append(proto)

    # Normalize to 0-10
    max_possible = sum(EXPOSURE_WEIGHTS.values())
    normalized = round(min(10.0, (score / max_possible) * 10), 1)

    if normalized >= 8:
        grade = "CRITICAL EXPOSURE"
    elif normalized >= 6:
        grade = "HIGH EXPOSURE"
    elif normalized >= 4:
        grade = "MEDIUM EXPOSURE"
    elif normalized >= 2:
        grade = "LOW EXPOSURE"
    else:
        grade = "MINIMAL"

    return {
        "name": name, "role": role, "ip": ip, "type": typ,
        "exposed_protos": exposed, "raw_score": score,
        "normalized": normalized, "grade": grade,
    }


def generate_interface_exposure_report(interfaces: List[Dict], out_path: Path) -> List[str]:
    findings = []
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" INTERFACE EXPOSURE SCORE REPORT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")
    lines.append("  Exposure score measures how much management/risky access is enabled")
    lines.append("  on each interface. Score 0=minimal exposure, 10=maximum exposure.")
    lines.append("")

    scored = [interface_exposure_score(i) for i in interfaces]
    scored.sort(key=lambda x: x["normalized"], reverse=True)

    lines.append("─" * W)
    lines.append(f"  {'Interface':<20} {'Role':<8} {'IP':<20} {'Exposed Protocols':<30} {'Score'}")
    lines.append("─" * W)

    for s in scored:
        protos_str = " ".join(s["exposed_protos"]) if s["exposed_protos"] else "(none)"
        score_bar  = "█" * int(s["normalized"]) + "░" * (10 - int(s["normalized"]))
        lines.append(f"  {s['name']:<20} {s['role']:<8} {s['ip']:<20} {protos_str:<30} "
                     f"{s['normalized']}/10")
        lines.append(f"  {'':20} {'':8} {'':20} [{score_bar}] {s['grade']}")
        lines.append("")

    lines.append("─" * W)
    lines.append("  DETAILED FINDINGS")
    lines.append("─" * W)
    lines.append("")

    for s in scored:
        if s["normalized"] == 0:
            continue
        name = s["name"]
        role = s["role"]
        score = s["normalized"]

        # Generate findings per exposed protocol
        for proto in s["exposed_protos"]:
            weight = EXPOSURE_WEIGHTS.get(proto, 1)
            if proto == "telnet":
                findings.append(f(C, f"Interface '{name}' ({role}): Telnet enabled — "
                                    "cleartext management. Remove immediately. "
                                    f"CLI: config system interface → edit {name} → "
                                    "set allowaccess (list without telnet)"))
            elif proto == "http":
                sev = C if role == "wan" else H
                findings.append(f(sev, f"Interface '{name}' ({role}): HTTP enabled — "
                                      "cleartext management. Replace with HTTPS only."))
            elif proto == "snmp":
                sev = C if role == "wan" else H
                findings.append(f(sev, f"Interface '{name}' ({role}): SNMP enabled — "
                                      f"{'WAN-facing SNMP is critical risk' if role=='wan' else 'restrict to management VLAN'}."))
            elif proto == "ssh" and role == "wan":
                findings.append(f(H, f"Interface '{name}' (WAN): SSH exposed to internet — "
                                    "restrict via local-in-policy to admin IPs only."))
            elif proto == "https" and role == "wan":
                findings.append(f(H, f"Interface '{name}' (WAN): HTTPS management on WAN — "
                                    "restrict via local-in-policy or remove from allowaccess."))
            elif proto == "ping" and role == "wan":
                findings.append(f(M, f"Interface '{name}' (WAN): ICMP ping enabled — "
                                    "aids attacker recon. Disable on WAN."))
            elif proto == "fmg-access":
                sev = H if role == "wan" else I
                findings.append(f(sev, f"Interface '{name}' ({role}): FortiManager access enabled — "
                                      f"{'should never be on WAN' if role=='wan' else 'verify FMG IP restriction'}."))
            elif proto == "fabric" and role == "wan":
                findings.append(f(H, f"Interface '{name}' (WAN): Security Fabric on WAN — "
                                    "Fabric protocol should not face internet."))

        # Overall score finding
        if score >= 8:
            findings.append(f(C, f"Interface '{name}' exposure score {score}/10 ({s['grade']}) — "
                                "multiple risky protocols enabled. Immediate hardening required."))
        elif score >= 6:
            findings.append(f(H, f"Interface '{name}' exposure score {score}/10 ({s['grade']}) — "
                                "significant management attack surface. Review and restrict."))
        elif score >= 4 and role == "wan":
            findings.append(f(M, f"Interface '{name}' (WAN) exposure score {score}/10 — "
                                "above acceptable threshold for internet-facing interfaces."))

    if findings:
        for fn in findings:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
            lines.append(f"  {icon} [{sev}] {body}")
    else:
        lines.append("  ✅ No interface exposure issues found.")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: CERTIFICATE AUDIT
# ═════════════════════════════════════════════════════════════════════════════

def parse_cert_local(t):   return extract_block(t, "vpn certificate local")
def parse_cert_ca(t):      return extract_block(t, "vpn certificate ca")
def parse_cert_remote(t):  return extract_block(t, "vpn certificate remote")


def cert_weaknesses(cert: Dict, cert_type: str = "local") -> List[str]:
    """Audit a certificate object."""
    findings = []
    name       = nv(cert.get("name", cert.get("_id","")))
    status     = nv(cert.get("status",""))
    comments   = nv(cert.get("comments",""))
    source     = nv(cert.get("source",""))
    issuer     = nv(cert.get("issuer",""))
    subject    = nv(cert.get("subject",""))
    # FortiGate stores cert validity as readable fields in some versions
    not_after  = nv(cert.get("not-after",""))
    key_size   = nv(cert.get("key-size","")) or nv(cert.get("bits",""))
    key_type   = nv(cert.get("key-type","")) or nv(cert.get("type",""))
    fingerprint = nv(cert.get("fingerprint",""))
    auto_renew = nv(cert.get("auto-regenerate",""))
    enroll_prot = nv(cert.get("enroll-protocol",""))

    # Self-signed detection
    is_self_signed = (
        source in ("self-signed","factory","built-in") or
        "factory" in name.lower() or
        "self" in name.lower() or
        (issuer and subject and issuer == subject)
    )

    if is_self_signed and cert_type == "local":
        findings.append(f(M, f"Certificate '{name}': self-signed — clients cannot properly "
                            "validate this certificate without manually trusting the CA. "
                            "Use a publicly trusted CA for external-facing services."))

    # Key size
    if key_type.lower() in ("rsa",""):
        try:
            ks = int(key_size)
            if ks < 2048:
                findings.append(f(C, f"Certificate '{name}': RSA key size {ks} bits — "
                                    "below minimum 2048 bits. This certificate is cryptographically weak. "
                                    "Replace immediately."))
            elif ks < 4096:
                findings.append(f(I, f"Certificate '{name}': RSA {ks}-bit — "
                                    "functional but consider 4096-bit for new certificates."))
        except (ValueError, TypeError):
            if not key_size:
                findings.append(f(I, f"Certificate '{name}': key size not readable from config — "
                                    "verify manually with 'get vpn certificate local'."))

    # Expiry — FortiGate exposes not-after in some parseable formats
    # Format varies: "YYYY/MM/DD HH:MM:SS" or unix timestamp
    if not_after:
        import re as _re
        m = _re.match(r"(\d{4})[/\-](\d{2})[/\-](\d{2})", not_after)
        if m:
            import datetime as _dt
            try:
                exp_date = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                today    = _dt.date.today()
                days_left = (exp_date - today).days
                if days_left < 0:
                    findings.append(f(C, f"Certificate '{name}': EXPIRED {abs(days_left)} days ago "
                                       f"(expired {not_after}). Replace immediately — "
                                       "expired certificates cause service outages and TLS errors."))
                elif days_left <= 30:
                    findings.append(f(H, f"Certificate '{name}': expires in {days_left} days "
                                       f"({not_after}). Renew now before service disruption."))
                elif days_left <= 90:
                    findings.append(f(M, f"Certificate '{name}': expires in {days_left} days "
                                       f"({not_after}). Plan renewal."))
            except (ValueError, Exception):
                pass

    # Auto-renew
    if cert_type == "local" and not is_self_signed:
        if auto_renew != "enable":
            findings.append(f(I, f"Certificate '{name}': auto-regenerate not enabled — "
                                "certificate renewal requires manual intervention."))

    return findings


def generate_cert_report(
    local_certs: List[Dict],
    ca_certs:    List[Dict],
    remote_certs: List[Dict],
    out_path: Path
) -> List[str]:
    all_findings = []
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" CERTIFICATE AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")
    lines.append(f"  Local certs: {len(local_certs)}   "
                 f"CA certs: {len(ca_certs)}   "
                 f"Remote certs: {len(remote_certs)}")
    lines.append("")

    for label, certs, ctype in [
        ("LOCAL CERTIFICATES (used for VPN, GUI, etc.)", local_certs, "local"),
        ("CA CERTIFICATES (trusted CAs)",               ca_certs,    "ca"),
        ("REMOTE CERTIFICATES",                         remote_certs, "remote"),
    ]:
        lines.append("─" * W)
        lines.append(f"  {label}")
        lines.append("─" * W)
        if not certs:
            lines.append("  (none configured)")
        for cert in certs:
            name   = nv(cert.get("name", cert.get("_id","")))
            issuer = nv(cert.get("issuer",""))
            subj   = nv(cert.get("subject",""))
            na     = nv(cert.get("not-after",""))
            ks     = nv(cert.get("key-size",""))
            src    = nv(cert.get("source",""))
            rows = [
                ("Name",        name),
                ("Source",      src or "(unknown)"),
                ("Issuer",      issuer[:60] if issuer else "(unknown)"),
                ("Subject",     subj[:60] if subj else "(unknown)"),
                ("Expires",     na or "(unknown — check device)"),
                ("Key Size",    ks + " bits" if ks else "(unknown)"),
            ]
            lines.append(ascii_table(rows))
            w = cert_weaknesses(cert, ctype)
            all_findings.extend(w)
            if w:
                for fn in w:
                    sev  = fn.split(":")[0]
                    body = ":".join(fn.split(":")[1:]).strip()
                    icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
                    lines.append(f"  {icon} [{sev}] {body}")
            else:
                lines.append("  ✅ No certificate issues detected (from config).")
            lines.append("")

    lines.append("─" * W)
    lines.append("  NOTE: FortiGate config backups contain certificate metadata but not full")
    lines.append("  certificate content. For complete expiry audit, run on the device:")
    lines.append("    diagnose vpn certificate local list")
    lines.append("    diagnose vpn certificate ca list")
    lines.append("    execute ssl-cert show all")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return all_findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: FABRIC CONNECTOR / EXTERNAL RESOURCE AUDIT
# AWS, Azure, GCP, Entra ID, EMS, ZTNA, SASE, FortiNAC
# ═════════════════════════════════════════════════════════════════════════════

def parse_fabric_connectors(t):     return extract_block(t, "system external-resource")
def parse_system_connector(t):      return extract_block(t, "system connector")
def parse_ems_settings(t):          return extract_flat_block(t, "endpoint-control fctems")
def parse_ztna_settings(t):         return extract_flat_block(t, "firewall access-proxy")
def parse_sase_connector(t):        return extract_flat_block(t, "system fortisase")
def parse_fnac_settings(t):         return extract_flat_block(t, "user fsso")
def parse_fortindr_settings(t):     return extract_flat_block(t, "system fortindr")
def parse_cloud_connectors(t):
    """Parse all cloud/fabric connector block types."""
    results = {}
    for block in ("system sdn-connector",):
        objs = extract_block(t, block)
        if objs:
            results[block] = objs
    return results


def fabric_connector_weaknesses(connector: Dict) -> List[str]:
    """Audit a single fabric/SDN connector."""
    findings = []
    name     = nv(connector.get("name", connector.get("_id","")))
    typ      = nv(connector.get("type",""))
    status   = nv(connector.get("status","enable"))
    server   = nv(connector.get("server","")) or nv(connector.get("server-ip",""))
    verify   = nv(connector.get("verify-certificate",""))
    use_meta = nv(connector.get("use-metadata-iam",""))
    access_k = nv(connector.get("access-key",""))
    secret_k = nv(connector.get("secret-key",""))
    tenant   = nv(connector.get("tenant-id",""))
    client_i = nv(connector.get("client-id",""))
    client_s = nv(connector.get("client-secret",""))
    region   = nv(connector.get("region",""))
    update_i = nv(connector.get("update-interval",""))

    if status == "disable":
        findings.append(f(I, f"Connector '{name}' ({typ}): disabled — "
                            "if no longer needed, remove to reduce attack surface."))
        return findings

    # Certificate validation
    if verify in ("", "disable"):
        findings.append(f(H, f"Connector '{name}' ({typ}): verify-certificate disabled — "
                            "connector will accept ANY TLS certificate from the cloud provider API. "
                            "MITM possible if DNS is poisoned. "
                            "CLI: set verify-certificate enable"))

    # AWS-specific
    if typ in ("aws","amazon"):
        if access_k and secret_k:
            findings.append(f(H, f"Connector '{name}' (AWS): using static access-key/secret-key — "
                                "long-lived credentials are high risk if config backup is exposed. "
                                "Switch to IAM role with use-metadata-iam enable."))
        if use_meta != "enable" and not (access_k and secret_k):
            findings.append(f(M, f"Connector '{name}' (AWS): use-metadata-iam not enabled and "
                                "no credentials visible — verify authentication method."))
        if not region:
            findings.append(f(I, f"Connector '{name}' (AWS): no region set — connector may query wrong endpoint."))

    # Azure-specific
    if typ in ("azure","microsoft"):
        if client_s:
            findings.append(f(H, f"Connector '{name}' (Azure): client-secret stored in config — "
                                "treat config backup as a secret. Prefer managed identity where possible."))
        if not tenant:
            findings.append(f(M, f"Connector '{name}' (Azure): tenant-id not set."))
        if not client_i:
            findings.append(f(M, f"Connector '{name}' (Azure): client-id not set."))

    # GCP-specific
    if typ in ("gcp","google"):
        if not server:
            findings.append(f(M, f"Connector '{name}' (GCP): no service account / server configured."))

    # Update interval
    try:
        ui = int(update_i)
        if ui > 3600:
            findings.append(f(M, f"Connector '{name}' ({typ}): update-interval {ui}s ({ui//60}min) — "
                                "stale dynamic address objects; consider ≤ 60s for cloud environments."))
        elif ui < 30:
            findings.append(f(I, f"Connector '{name}' ({typ}): update-interval {ui}s — "
                                "very frequent API polling; verify rate limits with cloud provider."))
    except (ValueError, TypeError):
        pass

    return findings


def ems_weaknesses(cfg: Dict) -> List[str]:
    """Audit EMS (Endpoint Management Server) integration."""
    findings = []
    server   = nv(cfg.get("server",""))
    status   = nv(cfg.get("status",""))
    verify   = nv(cfg.get("https-connection-verify",""))
    call_to  = nv(cfg.get("call-timeout",""))
    cert_fpr = nv(cfg.get("certificate-fingerprint",""))
    pull_cfg = nv(cfg.get("pull-sysinfo",""))
    pull_av  = nv(cfg.get("pull-av-status",""))
    pull_vul = nv(cfg.get("pull-vulnerabilities",""))

    if not server:
        findings.append(f(I, "EMS: no EMS server configured — endpoint posture check and "
                            "ZTNA tag-based policies require EMS integration."))
        return findings

    if status != "enable":
        findings.append(f(M, "EMS: EMS integration disabled — endpoint compliance "
                            "enforcement and ZTNA tags not active."))

    if verify in ("", "disable"):
        findings.append(f(H, "EMS: https-connection-verify disabled — FortiGate will not "
                            "validate EMS server certificate. MITM possible."))

    if not cert_fpr:
        findings.append(f(M, "EMS: certificate-fingerprint not set — without fingerprint "
                            "pinning, any cert from the EMS server is accepted."))

    if pull_vul != "enable":
        findings.append(f(M, "EMS: pull-vulnerabilities not enabled — vulnerability status "
                            "of endpoints not used for policy enforcement."))

    if pull_av != "enable":
        findings.append(f(I, "EMS: pull-av-status not enabled — AV compliance of endpoints "
                            "not checked."))

    return findings


def ztna_weaknesses(cfg: Dict, policies: List[Dict]) -> List[str]:
    """Audit ZTNA configuration."""
    findings = []

    # Check ZTNA usage in policies
    ztna_enabled_policies = [
        p for p in policies if nv(p.get("ztna-status","")) == "enable"
    ]
    total_accept = [p for p in policies if nv(p.get("action","")) == "accept"]

    if not ztna_enabled_policies:
        findings.append(f(I, "ZTNA: no policies have ztna-status enabled — "
                            "Zero Trust Network Access not enforced on any traffic flow. "
                            "Consider enabling ZTNA on internet-facing access policies."))
    else:
        pct = 100 * len(ztna_enabled_policies) // len(total_accept) if total_accept else 0
        if pct < 30:
            findings.append(f(I, f"ZTNA: only {len(ztna_enabled_policies)}/{len(total_accept)} "
                                f"accept policies ({pct}%) have ZTNA enabled — "
                                "consider broader Zero Trust enforcement."))

    # Check ZTNA EMS tag usage
    ztna_tag_policies = [
        p for p in policies
        if nv(p.get("ztna-ems-tag","")) or nv(p.get("ztna-device-ownership",""))
    ]
    if ztna_enabled_policies and not ztna_tag_policies:
        findings.append(f(M, "ZTNA: ZTNA enabled on policies but no EMS tags or device ownership "
                            "checks configured — ZTNA enforcement is incomplete without posture checks."))

    return findings


def sase_weaknesses(cfg: Dict) -> List[str]:
    """Audit FortiSASE connector."""
    findings = []
    status   = nv(cfg.get("status",""))
    server   = nv(cfg.get("server",""))
    interface = nv(cfg.get("interface",""))

    if not cfg or not status:
        findings.append(f(I, "SASE: FortiSASE connector not configured — "
                            "cloud-delivered security service not integrated."))
        return findings

    if status != "enable":
        findings.append(f(I, "SASE: FortiSASE configured but disabled."))

    if not server:
        findings.append(f(M, "SASE: no SASE server endpoint configured."))

    return findings


def generate_fabric_connector_report(
    fabric_connectors: List[Dict],
    cloud_connectors:  Dict,
    ems_cfg:           Dict,
    ztna_cfg:          Dict,
    sase_cfg:          Dict,
    policies:          List[Dict],
    out_path:          Path
) -> List[str]:
    all_findings = []
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" FABRIC CONNECTOR / CLOUD INTEGRATION AUDIT ".center(W, "="))
    lines.append("=" * W)
    lines.append("")

    # SDN Connectors (AWS, Azure, GCP, etc.)
    sdn_list = cloud_connectors.get("system sdn-connector", [])
    lines.append("─" * W)
    lines.append(f"  SDN / CLOUD CONNECTORS  ({len(sdn_list)} found)")
    lines.append("─" * W)
    lines.append("")
    if sdn_list:
        for conn in sdn_list:
            name = nv(conn.get("name", conn.get("_id","")))
            typ  = nv(conn.get("type",""))
            stat = nv(conn.get("status","enable"))
            rows = [
                ("Connector Name",   name),
                ("Type",             typ),
                ("Status",           stat),
                ("Server/Endpoint",  nv(conn.get("server","")) or nv(conn.get("server-ip","")) or "(cloud metadata)"),
                ("Update Interval",  nv(conn.get("update-interval","")) + "s" if conn.get("update-interval") else "(default)"),
                ("Verify Cert",      nv(conn.get("verify-certificate",""))),
                ("Use Metadata IAM", nv(conn.get("use-metadata-iam",""))),
            ]
            lines.append(ascii_table(rows, f"SDN Connector: {name} ({typ})"))
            w = fabric_connector_weaknesses(conn)
            all_findings.extend(w)
            for fn in w:
                sev  = fn.split(":")[0]
                body = ":".join(fn.split(":")[1:]).strip()
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
                lines.append(f"  {icon} [{sev}] {body}")
            lines.append("")
    else:
        lines.append("  No SDN/Cloud connectors configured.")
        lines.append("")

    # External Resources
    lines.append("─" * W)
    lines.append(f"  EXTERNAL RESOURCES  ({len(fabric_connectors)} found)")
    lines.append("─" * W)
    for res in fabric_connectors:
        name    = nv(res.get("name", res.get("_id","")))
        typ     = nv(res.get("type",""))
        uri     = nv(res.get("resource",""))
        status  = nv(res.get("status","enable"))
        refresh = nv(res.get("refresh-rate",""))
        verify  = nv(res.get("server-identity-check",""))

        rows = [
            ("Name",           name),
            ("Type",           typ),
            ("Status",         status),
            ("URI",            uri[:60] if uri else "(none)"),
            ("Refresh Rate",   refresh + "s" if refresh else "(default)"),
            ("Cert Verify",    verify),
        ]
        lines.append(ascii_table(rows))

        # External resource findings
        if verify in ("", "disable"):
            fn = f(M, f"External Resource '{name}': server-identity-check disabled — "
                       "FortiGate will not verify the TLS certificate of the threat feed source.")
            all_findings.append(fn)
            lines.append(f"  🟡 [MEDIUM] {':'.join(fn.split(':')[1:]).strip()}")
        if not uri:
            fn = f(M, f"External Resource '{name}': no resource URI configured.")
            all_findings.append(fn)
            lines.append(f"  🟡 [MEDIUM] {':'.join(fn.split(':')[1:]).strip()}")
        if status == "disable":
            fn = f(I, f"External Resource '{name}': disabled — threat feed not active.")
            all_findings.append(fn)
            lines.append(f"  🔵 [INFO] {':'.join(fn.split(':')[1:]).strip()}")
        lines.append("")

    # EMS
    lines.append("─" * W)
    lines.append("  EMS (ENDPOINT MANAGEMENT SERVER) INTEGRATION")
    lines.append("─" * W)
    w = ems_weaknesses(ems_cfg)
    all_findings.extend(w)
    if ems_cfg.get("server"):
        rows = [
            ("EMS Server",    nv(ems_cfg.get("server",""))),
            ("Status",        nv(ems_cfg.get("status",""))),
            ("Cert Verify",   nv(ems_cfg.get("https-connection-verify",""))),
            ("Cert Fingerprint", nv(ems_cfg.get("certificate-fingerprint","")) or "(not set)"),
            ("Pull Vuln",     nv(ems_cfg.get("pull-vulnerabilities",""))),
            ("Pull AV Status",nv(ems_cfg.get("pull-av-status",""))),
        ]
        lines.append(ascii_table(rows))
    for fn in w:
        sev  = fn.split(":")[0]
        body = ":".join(fn.split(":")[1:]).strip()
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
        lines.append(f"  {icon} [{sev}] {body}")
    if not w:
        lines.append("  ✅ EMS configuration looks good." if ems_cfg.get("server") else "  EMS not configured.")
    lines.append("")

    # ZTNA
    lines.append("─" * W)
    lines.append("  ZTNA (ZERO TRUST NETWORK ACCESS)")
    lines.append("─" * W)
    w = ztna_weaknesses(ztna_cfg, policies)
    all_findings.extend(w)
    ztna_pol_count = sum(1 for p in policies if nv(p.get("ztna-status","")) == "enable")
    lines.append(f"  Policies with ZTNA enabled: {ztna_pol_count}")
    for fn in w:
        sev  = fn.split(":")[0]
        body = ":".join(fn.split(":")[1:]).strip()
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
        lines.append(f"  {icon} [{sev}] {body}")
    if not w:
        lines.append("  ✅ ZTNA configured and in use.")
    lines.append("")

    # SASE
    lines.append("─" * W)
    lines.append("  FORTISASE CONNECTOR")
    lines.append("─" * W)
    w = sase_weaknesses(sase_cfg)
    all_findings.extend(w)
    for fn in w:
        sev  = fn.split(":")[0]
        body = ":".join(fn.split(":")[1:]).strip()
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
        lines.append(f"  {icon} [{sev}] {body}")
    if not w:
        lines.append("  ✅ FortiSASE configured." if sase_cfg.get("status") else "  FortiSASE not configured.")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return all_findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: LOCAL-IN HARDENING (ENHANCED)
# Combined WAN exposure + missing local-in = CRITICAL
# ═════════════════════════════════════════════════════════════════════════════

def enhanced_local_in_weaknesses(
    local_in:   List[Dict],
    local_in6:  List[Dict],
    interfaces: List[Dict],
) -> List[str]:
    """
    Enhanced local-in audit. Detects:
    - WAN interface with management access AND no local-in restriction → CRITICAL
    - No local-in policies at all → HIGH
    - IPv6 local-in not configured when IPv4 is → MEDIUM
    - Accept from 'all' → CRITICAL
    """
    findings = []
    all_lip = local_in + local_in6

    # Build WAN interface list with their allowaccess
    wan_with_mgmt: List[Dict] = []
    for intf in interfaces:
        name   = nv(intf.get("name", intf.get("_id","")))
        role   = nv(intf.get("role",""))
        aa     = nv(intf.get("allowaccess",""))
        name_l = name.lower()
        is_wan = (role == "wan") or any(
            w in name_l for w in ("wan","internet","outside","untrust","ppp","vdsl","adsl")
        )
        if is_wan and aa.strip():
            mgmt_protos = set(aa.split()) & {"https","ssh","http","telnet","ping","snmp","fmg-access"}
            if mgmt_protos:
                wan_with_mgmt.append({"name": name, "protos": mgmt_protos})

    # Find WAN interfaces covered by local-in
    lip_covered_intfs: set = set()
    for lip in all_lip:
        intf   = nv(lip.get("intf",""))
        action = nv(lip.get("action",""))
        srcaddr = nv(lip.get("srcaddr",""))
        if intf and action in ("accept","deny"):
            lip_covered_intfs.add(intf)

    # Core check: WAN with mgmt AND no local-in
    for wan in wan_with_mgmt:
        if wan["name"] not in lip_covered_intfs:
            protos_str = ", ".join(sorted(wan["protos"]))
            findings.append(f(C,
                f"Local-in CRITICAL: WAN interface '{wan['name']}' has management access "
                f"({protos_str}) enabled AND has NO local-in-policy restricting source IPs. "
                f"Any IP on the internet can attempt to reach FortiGate management. "
                f"This is a CRITICAL management plane exposure. "
                f"Fix:\n"
                f"  config firewall local-in-policy\n"
                f"      edit 1\n"
                f"          set intf {wan['name']}\n"
                f"          set srcaddr <your-admin-subnet>\n"
                f"          set service HTTPS SSH\n"
                f"          set action accept\n"
                f"      next\n"
                f"      edit 2\n"
                f"          set intf {wan['name']}\n"
                f"          set srcaddr all\n"
                f"          set service ALL\n"
                f"          set action deny\n"
                f"      next\n"
                f"  end"
            ))

    # No local-in at all
    if not all_lip:
        findings.append(f(H,
            "Local-in: NO local-in-policies configured anywhere — "
            "FortiGate management services (HTTPS, SSH, VPN, BGP, etc.) rely only on "
            "interface allowaccess for protection. No per-source-IP restrictions. "
            "Configure local-in-policies on all management-accessible interfaces."))

    # IPv4 local-in exists but no IPv6
    if local_in and not local_in6:
        findings.append(f(M,
            "Local-in: IPv4 local-in-policies exist but no IPv6 local-in-policy6 configured — "
            "if IPv6 is present on any interface, the management plane has no IPv6 source restriction. "
            "CLI: config firewall local-in-policy6"))

    # Existing local-in policy issues
    for lip in all_lip:
        pid    = nv(lip.get("policyid", lip.get("_id","")))
        intf   = nv(lip.get("intf",""))
        src    = nv(lip.get("srcaddr",""))
        svc    = nv(lip.get("service",""))
        action = nv(lip.get("action",""))
        sched  = nv(lip.get("schedule",""))

        if not intf:
            findings.append(f(M, f"Local-in #{pid}: no interface bound — "
                                "applies to ALL interfaces including WAN. "
                                "Bind to specific interface for better control."))
        if src in ("all","") and action == "accept":
            findings.append(f(C, f"Local-in #{pid} (intf:{intf}): ACCEPT from source 'all' — "
                                "any host can reach FortiGate services on this interface."))
        if src in ("all","") and action == "deny" and svc in ("ALL","all",""):
            pass  # This is actually the correct final deny-all rule
        if svc in ("ALL","all") and action == "accept":
            findings.append(f(M, f"Local-in #{pid} (intf:{intf}): ACCEPT for service ALL — "
                                "restrict to only required management protocols (HTTPS, SSH)."))
        if not sched or sched == "always":
            pass  # Fine for management policies
        if action == "accept" and src not in ("all",""):
            # This is a good restrictive rule — check for logging
            log = nv(lip.get("logtraffic",""))
            if log in ("","disable"):
                findings.append(f(I, f"Local-in #{pid}: logging not enabled — "
                                    "management plane access attempts not recorded."))

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: LLM / AI APPLICATION AUDIT (FortiOS 8.0)
# ChatGPT, Gemini, Claude, AI data exfiltration controls
# ═════════════════════════════════════════════════════════════════════════════

# Known AI/LLM application signatures by category
AI_APPS = {
    "chatgpt":       ("OpenAI ChatGPT",     H, "generative AI with potential data exfiltration risk"),
    "openai":        ("OpenAI API",         H, "direct API access enables large-scale data upload"),
    "gemini":        ("Google Gemini",      H, "Google AI — potential data residency issues"),
    "bard":          ("Google Bard",        M, "Google AI assistant"),
    "claude":        ("Anthropic Claude",   H, "AI assistant — sensitive data in prompts"),
    "copilot":       ("Microsoft Copilot",  H, "M365 Copilot — may access internal M365 data"),
    "github-copilot":("GitHub Copilot",     H, "code AI — source code exfiltration risk"),
    "midjourney":    ("Midjourney",         M, "image AI — verify acceptable use policy"),
    "stability-ai":  ("Stability AI",       M, "image generation — prompt data sent externally"),
    "huggingface":   ("HuggingFace",        M, "ML model hosting — model/data upload possible"),
    "perplexity":    ("Perplexity AI",      M, "AI search — query data sent externally"),
    "character-ai":  ("Character.AI",       I, "consumer AI chatbot"),
    "grammarly":     ("Grammarly AI",       M, "text AI — document content sent to cloud"),
    "jasper":        ("Jasper AI",          M, "marketing AI — content exfiltration possible"),
    "cohere":        ("Cohere AI",          H, "enterprise LLM API"),
    "anthropic":     ("Anthropic API",      H, "direct API access to Claude models"),
    "replicate":     ("Replicate AI",       M, "AI model API platform"),
    "together-ai":   ("Together AI",        M, "LLM inference API"),
    "mistral":       ("Mistral AI",         H, "open-weight LLM with API access"),
    "deepseek":      ("DeepSeek AI",        C, "Chinese AI — data sovereignty risk for most enterprises"),
    "ernie":         ("Baidu Ernie",        C, "Chinese AI — data sovereignty concern"),
    "qwen":          ("Alibaba Qwen",       C, "Chinese AI — data sovereignty concern"),
    "kimi":          ("Moonshot Kimi",      C, "Chinese AI — data sovereignty concern"),
}


def parse_app_control_for_ai(app_profiles: List[Dict], text: str) -> Dict[str, Any]:
    """
    Check if app control profiles have AI application controls.
    Returns dict of {profile_name: {app_name: action}}.
    """
    results = {}

    for prof in app_profiles:
        name = nv(prof.get("name", prof.get("_id","")))
        # The actual per-app settings are deep in sub-entries
        # We can detect by scanning config text for known AI app names
        profile_controls = {}
        for ai_key in AI_APPS:
            if ai_key in text.lower():
                profile_controls[ai_key] = "referenced"
        results[name] = profile_controls

    return results


def llm_ai_audit(
    llm_profiles: List[Dict],
    app_profiles: List[Dict],
    policies: List[Dict],
    wf_profiles: List[Dict],
    cfg_text: str,
) -> List[str]:
    """
    Comprehensive AI/LLM security audit.
    Checks: LLM profiles, app control for AI apps, web filter for AI sites,
    DLP coverage on AI-touching policies, data exfiltration controls.
    """
    findings = []

    # 1. LLM profile coverage
    if not llm_profiles:
        findings.append(f(M,
            "AI/LLM Audit: no LLM profiles configured (FortiOS 8.0 feature) — "
            "AI traffic through this FortiGate has no dedicated inspection. "
            "CLI: config llm profile → edit MyLLMProfile → set dlp-check enable "
            "→ set pii-check enable → set prompt-injection-check enable"))
    else:
        policies_with_llm = [p for p in policies if nv(p.get("llm-profile",""))]
        accept_policies = [p for p in policies if nv(p.get("action","")) == "accept"]
        if not policies_with_llm:
            findings.append(f(M,
                "AI/LLM Audit: LLM profiles are defined but none are attached to any "
                "firewall policy — AI traffic inspection is configured but not enforced."))
        else:
            pct = 100 * len(policies_with_llm) // len(accept_policies) if accept_policies else 0
            findings.append(f(I,
                f"AI/LLM Audit: {len(policies_with_llm)}/{len(accept_policies)} accept "
                f"policies ({pct}%) have LLM profiles attached."))

        # Check each LLM profile quality
        for prof in llm_profiles:
            name    = nv(prof.get("name", prof.get("_id","")))
            dlp     = nv(prof.get("dlp-check",""))
            pii     = nv(prof.get("pii-check",""))
            prompt  = nv(prof.get("prompt-injection-check",""))
            jailbrk = nv(prof.get("jailbreak-check",""))
            log_v   = nv(prof.get("log",""))

            if dlp != "enable":
                findings.append(f(H,
                    f"LLM Profile '{name}': dlp-check disabled — sensitive corporate data "
                    "in AI prompts (source code, customer PII, financial data) exits the network "
                    "without inspection. Enable: set dlp-check enable"))
            if pii != "enable":
                findings.append(f(H,
                    f"LLM Profile '{name}': pii-check disabled — PII (names, SSNs, emails, "
                    "credit cards) may be submitted to external AI services in violation of "
                    "GDPR/HIPAA/PCI-DSS. Enable: set pii-check enable"))
            if prompt != "enable":
                findings.append(f(M,
                    f"LLM Profile '{name}': prompt-injection-check disabled — adversarial "
                    "prompts could manipulate AI systems connected through this policy."))
            if jailbrk != "enable":
                findings.append(f(M,
                    f"LLM Profile '{name}': jailbreak-check disabled — attempts to bypass "
                    "AI safety controls not detected."))
            if log_v != "enable":
                findings.append(f(M,
                    f"LLM Profile '{name}': logging disabled — AI traffic events not recorded "
                    "for forensics or compliance audits."))

    # 2. Check App Control profiles for AI application controls
    cfg_lower = cfg_text.lower()
    detected_ai_apps = []
    for ai_key, (ai_name, severity, detail) in AI_APPS.items():
        if ai_key in cfg_lower:
            detected_ai_apps.append((ai_key, ai_name, severity, detail))

    # 3. Check web filter for AI site categories
    ai_domains = ["openai.com","chat.openai.com","api.openai.com",
                  "gemini.google.com","bard.google.com",
                  "claude.ai","api.anthropic.com",
                  "copilot.microsoft.com","github.com/copilot",
                  "deepseek.com","chat.deepseek.com"]

    wf_has_ai_control = False
    for wf in wf_profiles:
        name = nv(wf.get("name", wf.get("_id","")))
        # Check if any AI domains appear in web filter URL filters (heuristic)
        for domain in ai_domains:
            if domain in cfg_lower:
                wf_has_ai_control = True
                break

    # 4. Check DLP on policies that likely carry AI traffic
    policies_with_dlp = [p for p in policies if nv(p.get("dlp-profile","")) or nv(p.get("dlp-sensor",""))]
    accept_policies = [p for p in policies if nv(p.get("action","")) == "accept"]
    dlp_pct = 100 * len(policies_with_dlp) // len(accept_policies) if accept_policies else 0

    if dlp_pct < 50:
        findings.append(f(M,
            f"AI/LLM Audit: only {dlp_pct}% of accept policies have DLP profiles — "
            "without DLP, users can freely paste source code, customer data, and "
            "internal documents into AI services like ChatGPT."))

    # 5. Chinese AI sovereignty risk
    china_ai = ["deepseek","ernie","qwen","kimi","baidu","alibaba-ai"]
    china_detected = [ai for ai in china_ai if ai in cfg_lower]
    if china_detected:
        findings.append(f(C,
            f"AI/LLM Audit: Chinese AI services detected in config ({', '.join(china_detected)}) — "
            "data sent to Chinese AI services is subject to Chinese data law (PIPL) and "
            "national security requirements. Block or explicitly approve through legal/compliance. "
            "Add to web filter URL block list immediately for most enterprise environments."))

    # 6. No AI governance at all
    has_any_ai_control = bool(llm_profiles or detected_ai_apps or wf_has_ai_control or policies_with_dlp)
    if not has_any_ai_control:
        findings.append(f(M,
            "AI/LLM Audit: NO AI governance controls detected — no LLM profiles, no app "
            "control entries for AI tools, no web filter rules for AI sites, no DLP coverage. "
            "Users can freely access and submit corporate data to any AI service. "
            "Recommended actions:\n"
            "  1. Create LLM profile: config llm profile\n"
            "  2. Block unapproved AI in web filter URL filter\n"
            "  3. Add DLP profiles to internet-bound policies\n"
            "  4. Use app control to detect/restrict AI API usage"))

    # 7. Generate visibility summary
    if detected_ai_apps:
        findings.append(f(I,
            f"AI/LLM Audit: {len(detected_ai_apps)} AI service references found in config — "
            f"services: {', '.join(n for _,n,_,_ in detected_ai_apps[:5])}. "
            "Verify each has appropriate controls."))

    return findings


def generate_ai_audit_report(
    llm_profiles: List[Dict],
    app_profiles: List[Dict],
    policies:     List[Dict],
    wf_profiles:  List[Dict],
    cfg_text:     str,
    out_path:     Path,
) -> List[str]:
    findings = llm_ai_audit(llm_profiles, app_profiles, policies, wf_profiles, cfg_text)
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append(" AI / LLM APPLICATION SECURITY AUDIT (FortiOS 8.0) ".center(W, "="))
    lines.append("=" * W)
    lines.append("")
    lines.append("  This module audits controls over AI/LLM traffic including:")
    lines.append("  ChatGPT, Google Gemini, Claude, Copilot, DeepSeek, and AI APIs.")
    lines.append("  Covers: LLM profiles, DLP coverage, App Control, Web Filter, Data Sovereignty.")
    lines.append("")

    # Summary table
    accept_policies = [p for p in policies if nv(p.get("action","")) == "accept"]
    pol_with_llm  = sum(1 for p in policies if nv(p.get("llm-profile","")))
    pol_with_dlp  = sum(1 for p in policies if nv(p.get("dlp-profile","")) or nv(p.get("dlp-sensor","")))
    pol_with_casb = sum(1 for p in policies if nv(p.get("casb-profile","")))

    rows = [
        ("LLM profiles configured",     str(len(llm_profiles))),
        ("Policies with LLM profile",   f"{pol_with_llm}/{len(accept_policies)}"),
        ("Policies with DLP profile",   f"{pol_with_dlp}/{len(accept_policies)}"),
        ("Policies with CASB profile",  f"{pol_with_casb}/{len(accept_policies)}"),
        ("App control profiles",        str(len(app_profiles))),
        ("Web filter profiles",         str(len(wf_profiles))),
    ]
    lines.append(ascii_table(rows, "AI Security Controls Summary"))
    lines.append("")

    # AI app risk table
    lines.append("─" * W)
    lines.append("  KNOWN AI SERVICES RISK REFERENCE")
    lines.append("─" * W)
    lines.append(f"  {'AI Service':<22} {'Severity':<12} {'Risk'}")
    lines.append(f"  {'─'*22} {'─'*12} {'─'*38}")
    for ai_key, (ai_name, sev, detail) in sorted(AI_APPS.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x[1][1])):
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
        lines.append(f"  {icon} {ai_name:<22} {sev:<12} {detail[:40]}")
    lines.append("")

    lines.append("─" * W)
    lines.append("  FINDINGS")
    lines.append("─" * W)
    if findings:
        for fn in findings:
            sev  = fn.split(":")[0]
            body = ":".join(fn.split(":")[1:]).strip()
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}.get(sev,"  ")
            lines.append(f"\n  {icon} [{sev}]")
            # Wrap long lines
            for part in body.split("\n"):
                lines.append(f"  {part}")
    else:
        lines.append("  ✅ AI governance controls are in place.")
    lines.append("")

    lines.append("─" * W)
    lines.append("  RECOMMENDED AI GOVERNANCE FRAMEWORK")
    lines.append("─" * W)
    lines.append("")
    lines.append("  1. IDENTIFY: Enable App Control with AI app signatures to see what AI")
    lines.append("     tools your users are already using (monitor mode first).")
    lines.append("")
    lines.append("  2. CLASSIFY: Tier AI services:")
    lines.append("     - Approved corporate tools (M365 Copilot, approved ChatGPT Enterprise)")
    lines.append("     - Conditionally permitted (with DLP + logging)")
    lines.append("     - Blocked (Chinese AI, consumer tools, unapproved APIs)")
    lines.append("")
    lines.append("  3. CONTROL:")
    lines.append("     config llm profile")
    lines.append("         edit Corporate-AI-Policy")
    lines.append("             set dlp-check enable")
    lines.append("             set pii-check enable")
    lines.append("             set prompt-injection-check enable")
    lines.append("             set jailbreak-check enable")
    lines.append("             set log enable")
    lines.append("         next")
    lines.append("     end")
    lines.append("")
    lines.append("  4. BLOCK sovereignty-risk AI via web filter URL filter:")
    lines.append("     deepseek.com, ernie.baidu.com, qwen.ai, kimi.moonshot.cn")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return findings
# ─────────────────────────────────────────────────────────────────────────────
# Offline HTML reporting. Legacy strings remain the summary's source of truth.
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_DOMAINS = (
    'Firewall Policies', 'SSL Inspection', 'Antivirus Profiles', 'IPS Sensors',
    'Web Filter', 'App Control', 'DNS Filter', 'WAF Profiles', 'Email Filter',
    'Video Filter', 'File Filter', 'Virtual Patch', 'LLM Profiles', 'VPN Phase1',
    'VPN Phase2', 'SSL-VPN', 'SSL-VPN Portals', 'HA Config', 'Logging',
    'DoS Policies', 'Anti-DoS Policies', 'Anti-DoS IPS', 'Anti-DoS Hardening',
    'Admin Accounts', 'Interfaces', 'Global Hardening', 'Password Policy',
    'SSH Config', 'NTP', 'Local-in', 'SNMP', 'System DNS', 'IKE Global',
    'Security Fabric', 'FIPS-CC', 'FortiGuard', 'Policy Intelligence',
    'Unused Objects', 'VIP Security', 'SD-WAN', 'Interface Exposure',
    'Certificates', 'Fabric Connectors', 'AI/LLM Security', 'Enhanced Local-in',
    'BGP Security', 'RADIUS', 'LDAP', 'SAML', 'Admin MFA',
)


class ReportOutput:
    """A per-run output sink retaining report guidance before writing to disk.

    No generated TXT file is read or scraped. The complete legacy report is a
    shared technical reference, not falsely attributed to an individual finding.
    """
    def __init__(self, path, references):
        self.path = Path(path)
        self.references = references

    def __str__(self):
        return str(self.path)

    def write_text(self, content, encoding='utf-8'):
        if self.references is not None:
            self.references[self.path.name] = content
        return self.path.write_text(content, encoding=encoding)

    def with_suffix(self, suffix):
        return self.path.with_suffix(suffix)


class Finding(str):
    """Compatible severity string with optional structured, non-secret evidence."""
    def __new__(cls, severity, title, **details):
        obj = str.__new__(cls, '{}: {}'.format(severity, title))
        obj.details = details
        return obj


class ReportRedactor:
    """Remove configured credential values, including multiline quoted material.

    Reports still contain topology and arbitrary free text; they are confidential.
    Secret *field values* are removed even if echoed in a name or comment.
    """
    SECRET_FIELD = re.compile(
        r'(?:password|passwd|psksecret|secret|private[-_]?key|access[-_]?key|'
        r'api[-_]?key|token|community|certificate$|^ca$)', re.I)

    def __init__(self, config_text):
        import shlex
        values = set()
        # FortiOS quoted values can span multiple lines and contain escaped quotes.
        assignment = re.compile(
            r'^\s*set\s+(\S+)\s+("(?:\\.|[^"\\])*"|[^\r\n]+)', re.M)
        for match in assignment.finditer(config_text):
            field, raw = match.groups()
            if self.SECRET_FIELD.search(field) and not field.endswith((
                    '-policy', '-expiry', '-expire', '-renewal', '-warning')):
                value = nv(raw)
                if value and value.lower() not in ('enable', 'disable', 'none'):
                    values.add(value)
                    if raw.startswith('"'):
                        try:
                            values.update(shlex.split(raw))
                        except ValueError:
                            pass
                    if value.startswith('ENC '):
                        values.add(value[4:].strip().strip('"'))
                    # Also remove each line of PEM and multiline private material.
                    if '\n' in value:
                        values.update(x.strip() for x in value.splitlines() if x.strip())
        root, _ = parse_config_tree(config_text)
        nodes = [root]
        while nodes:
            node = nodes.pop()
            if node['kind'] == 'config' and node['name'] == 'system snmp community':
                for obj in node['children']:
                    value = nv(obj['settings'].get('name', ''))
                    if value:
                        values.add(value)
            nodes.extend(node['children'])
        self.values = sorted(values, key=len, reverse=True)
        self.pattern = re.compile('|'.join(re.escape(v) for v in self.values)) if values else None

    def text(self, value):
        text = str(value)
        if self.pattern:
            text = self.pattern.sub('[REDACTED]', text)
        text = re.sub(r'-----BEGIN [^-]+-----.*?-----END [^-]+-----',
                      '[REDACTED MATERIAL]', text, flags=re.S)
        # Covers credentials embedded in URLs, without changing ordinary URLs.
        text = re.sub(r'(https?://)[^\s/@]+:[^\s/@]+@', r'\1[REDACTED]@', text)
        return re.sub(r'([?&](?:api[_-]?key|token|password|secret)=)[^&\s]+',
                      r'\1[REDACTED]', text, flags=re.I)

    def clean(self, value):
        if isinstance(value, dict):
            return {self.text(k): self.clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        return self.text(value) if isinstance(value, str) else value


def detect_metadata(config_text, config_path):
    version = re.search(r'^#config-version=\S*?-(\d+\.\d+\.\d+)-', config_text, re.M)
    if not version:
        version = re.search(r'\bFortiOS\s+v?(\d+\.\d+\.\d+)\b', config_text)
    return {'filename': Path(config_path).name,
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'fortios': version.group(1) if version else 'Unknown',
            'hostname': nv(parse_system_global(config_text).get('hostname', '')) or 'Unknown',
            'tool_version': __version__}


def build_html_data(all_findings, config_text, config_path, references=None,
                    coverage_notes=None, domain_status=None):
    redactor = ReportRedactor(config_text)
    findings = []
    for domain, items in all_findings.items():
        for ordinal, item in enumerate(items):
            severity, sep, title = item.partition(':')
            if severity not in (C, H, M, I) or not sep:
                raise ValueError('Finding lacks a supported severity: {}'.format(domain))
            details = dict(getattr(item, 'details', {}))
            obj_match = re.search(r"(?:Policy\s+#?(\d+)|'([^']+)')", title)
            obj = details.pop('object', None)
            if obj is None and obj_match:
                obj = obj_match.group(1) or obj_match.group(2)
            cli_hint = title.split('CLI:', 1)[1].strip() if 'CLI:' in title else ''
            stable = '{}\0{}\0{}\0{}'.format(domain, details.get('vdom', ''), item, ordinal)
            findings.append(dict(
                id=hashlib.sha256(stable.encode('utf-8')).hexdigest()[:16],
                severity=severity, domain=domain, title=title.strip(),
                description=details.pop('description', title.strip()), object=obj or '',
                vdom=details.pop('vdom', 'Unscoped (legacy)'),
                evidence=details.pop('evidence', 'See the original finding and technical references.'),
                impact=details.pop('impact', 'Impact depends on the deployment; review the finding in context.'),
                recommendation=details.pop('recommendation', 'Review this finding and the domain technical reference before making changes.'),
                cli=details.pop('cli', ''), guidance=cli_hint,
                **details))
    summary = compute_summary(all_findings)
    domains = []
    for domain in dict.fromkeys(list(AUDIT_DOMAINS) + list(all_findings)):
        counts = summary['by_section'].get(domain)
        domains.append({'name': domain, 'counts': counts,
                        'status': (domain_status or {}).get(domain) or ('Findings detected' if sum(counts.values()) else
                                   'Audited; no findings (not a pass guarantee)')
                                  if counts is not None else 'Not selected'})
    # Redact configuration-derived content, not fixed schema keys or enums.
    # A password literally equal to "HIGH" must not corrupt severity counters.
    sanitized = []
    for finding in findings:
        clean = {key: (value if key in ('id', 'severity', 'domain') else redactor.clean(value))
                 for key, value in finding.items()}
        sanitized.append(clean)
    return {'schema_version': 1, 'metadata': redactor.clean(detect_metadata(config_text, config_path)),
            'summary': summary, 'findings': sanitized, 'domains': domains,
            'references': redactor.clean(references or {}), 'notes': redactor.clean(coverage_notes or [])}


def generate_html_report(all_findings, config_text, config_path, out_path,
                         references=None, coverage_notes=None, domain_status=None):
    data = build_html_data(all_findings, config_text, config_path, references, coverage_notes, domain_status)
    payload = json.dumps(data, ensure_ascii=True).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    # Hash authorizes only our static program; configuration data cannot add code.
    import base64
    script_hash = base64.b64encode(hashlib.sha256(HTML_SCRIPT.encode()).digest()).decode()
    csp = "default-src 'none'; script-src 'sha256-{}'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'".format(script_hash)
    page = HTML_TEMPLATE.replace('<!--REPORT_DATA-->', payload).replace(
        '<!--REPORT_SCRIPT-->', HTML_SCRIPT).replace('<!--CSP-->', html.escape(csp, quote=True))
    Path(out_path).write_text(page, encoding='utf-8')
    return data


HTML_TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="<!--CSP-->">
<title>FortiGate • Security assessment</title>
<style>
:root{color-scheme:dark;--bg:#0b101b;--panel:#121b2a;--raised:#192437;--line:#28354a;--text:#eaf0fa;--muted:#a5b4cb;--accent:#66e3c4;--critical:#ff7b89;--high:#ffb16b;--medium:#f5d46c;--info:#83baff;--shadow:0 16px 40px #0002}

:root[data-theme=light]{color-scheme:light;--bg:#f3f6fb;--panel:#fff;--raised:#edf2f8;--line:#d8e1ec;--text:#17243a;--muted:#51627a;--accent:#087e69;--critical:#b51e37;--high:#a34c08;--medium:#806000;--info:#1c60ad;--shadow:0 8px 30px #23395008}

*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button,select{cursor:pointer}
button,input,select{color:var(--text);background:var(--raised);border:1px solid var(--line);border-radius:9px;padding:10px 13px}
button:hover{border-color:var(--accent)}
:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
a{color:var(--accent);text-decoration:none}
p{margin:8px 0}
h1,h2,h3{line-height:1.25;margin:0 0 12px}
h1{font-size:clamp(27px,4vw,42px);letter-spacing:-1.5px}
h2{font-size:18px;letter-spacing:-.3px}
h3{font-size:14px}
small,.muted{color:var(--muted)}
.shell{max-width:1600px;margin:auto;display:grid;grid-template-columns:220px minmax(0,1fr)}
aside{position:sticky;top:0;height:100vh;padding:32px 22px;border-right:1px solid var(--line);display:flex;flex-direction:column;gap:28px}
.brand{font-size:18px;font-weight:750;letter-spacing:-.4px}
.logo{display:inline-grid;place-items:center;width:32px;height:35px;background:var(--accent);color:var(--bg);border-radius:9px 9px 14px 14px;margin-right:9px}
nav a{display:block;color:var(--muted);padding:11px 12px;border-radius:8px;margin-bottom:6px}
nav a:first-child{color:var(--accent);background:var(--raised)}
.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:2px;font-weight:700;color:var(--accent)}
.aside-foot{margin-top:auto;font-size:12px;color:var(--muted)}
main{padding:28px 36px 50px;min-width:0}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:34px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:26px}
.hero p{max-width:630px;color:var(--muted)}
.hero .tag{max-width:100%;white-space:normal;overflow-wrap:anywhere}
.tag{display:inline-block;font-size:11px;letter-spacing:1px;border:1px solid var(--line);padding:5px 9px;border-radius:6px;white-space:nowrap}
.cards{display:grid;grid-template-columns:1.3fr repeat(3,1fr);gap:16px;margin-bottom:22px}
.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}
.card{padding:21px;min-width:0}
.card .number{font-size:36px;font-weight:740;line-height:1.25;letter-spacing:-1px}
.card.risk{border-top:3px solid var(--critical)}
.stat-label{font-size:12px;color:var(--muted);margin-bottom:12px}
.mini-counts{display:flex;gap:13px;font-size:12px;margin-top:10px;flex-wrap:wrap}
.critical{color:var(--critical)}
.high{color:var(--high)}
.medium{color:var(--medium)}
.info{color:var(--info)}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.45fr);gap:20px;margin-bottom:22px}
.panel{padding:23px;min-width:0}
.chart-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:18px}
.donut-box{display:flex;align-items:center;gap:24px;justify-content:center;flex-wrap:wrap}
.donut{width:168px;height:168px;flex-shrink:0}
.legend{flex:1;min-width:130px}
.legend-row{display:flex;justify-content:space-between;gap:25px;margin:10px 0}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}
.bars{max-height:284px;overflow:auto;padding-right:7px}
.bar-row{margin:11px 0}
.bar-title{display:flex;justify-content:space-between;gap:12px;font-size:12px;margin-bottom:5px}
.bar-track{height:7px;background:var(--raised);display:flex;border-radius:5px;overflow:hidden}
.bar-segment{height:100%;min-width:1px}
.rank-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:18px}
.rank-score{font-size:24px;font-weight:700;margin-bottom:8px}
.section{margin:26px 0 16px;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px}
.filters{display:grid;grid-template-columns:minmax(180px,2fr) repeat(4,minmax(100px,1fr));gap:10px;margin:18px 0 14px}
.filters label{display:flex;flex-direction:column;gap:5px;font-size:11px;color:var(--muted)}
.filters input,.filters select{width:100%;min-width:0}
.resultbar{display:flex;justify-content:space-between;align-items:center;gap:10px;margin:14px 0;color:var(--muted);font-size:12px}
.finding{border:1px solid var(--line);background:var(--panel);border-radius:11px;margin:9px 0;overflow:hidden}
.finding>summary{cursor:pointer;list-style:none;display:flex;align-items:flex-start;gap:13px;padding:17px}
.finding>summary::-webkit-details-marker{display:none}
.finding>summary:before{content:'+';font-size:18px;line-height:1.4;color:var(--muted)}
.finding[open]>summary:before{content:'−'}
.badge{font-size:10px;font-weight:800;letter-spacing:.5px;border:1px solid currentColor;padding:3px 7px;border-radius:5px;flex-shrink:0;margin-top:2px}
.finding-title{font-weight:600;overflow-wrap:anywhere}
.finding-meta{font-size:11px;color:var(--muted);margin-top:5px}
.finding-body{padding:4px 22px 23px 47px;border-top:1px solid var(--line)}
.finding-body h3{margin:18px 0 6px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}
.finding-body p{overflow-wrap:anywhere}
.finding-body pre,pre.reference{background:var(--bg);border:1px solid var(--line);padding:15px;border-radius:8px;overflow:auto;max-width:100%;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.cli pre{white-space:pre;overflow-wrap:normal}
.cli button{font-size:11px;padding:5px 10px}
.empty{padding:50px 20px;text-align:center;border:1px dashed var(--line);border-radius:12px;color:var(--muted)}
.coverage{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.coverage-item{border:1px solid var(--line);padding:12px;border-radius:8px;overflow-wrap:anywhere}
.coverage-item small{display:block}
.metadata{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}
.metadata dt{font-size:11px;color:var(--muted)}
.metadata dd{margin:3px 0 0;overflow-wrap:anywhere}
.notice{border-left:2px solid var(--accent);padding:10px 15px;background:var(--raised);border-radius:0 7px 7px 0;font-size:12px;margin-top:18px}
.ref>summary{padding:13px;cursor:pointer}
.footer{font-size:11px;color:var(--muted);display:flex;justify-content:space-between;margin-top:30px;border-top:1px solid var(--line);padding-top:16px}
.hidden{display:none!important}
#more{display:block;margin:18px auto}
#status{font-size:12px;color:var(--accent)}

@media(max-width:1150px){.shell{grid-template-columns:170px minmax(0,1fr)}
main{padding:25px}
.cards{grid-template-columns:repeat(2,1fr)}
.filters{grid-template-columns:repeat(3,minmax(0,1fr))}
.rank-grid{grid-template-columns:repeat(3,1fr)}
}

@media(max-width:780px){.shell{display:block}
aside{height:auto;position:static;border-right:0;border-bottom:1px solid var(--line);padding:15px 20px;display:flex;flex-direction:row;align-items:center;justify-content:space-between}
nav{display:none}
.aside-foot{margin:0}
main{padding:20px 15px}
.grid{grid-template-columns:1fr}
.hero{display:block}
.hero .tag{margin-top:10px}
.cards{gap:10px}
.card{padding:17px}
.card .number{font-size:29px}
.coverage,.metadata{grid-template-columns:repeat(2,minmax(0,1fr))}
.filters{grid-template-columns:repeat(2,minmax(0,1fr))}
.rank-grid{grid-template-columns:repeat(2,1fr)}
.finding>summary{gap:9px;padding:12px}
.finding-body{padding:0 15px 16px}
.top{margin-bottom:24px;flex-wrap:wrap}
.footer{display:block}
.panel{padding:18px}
}

@media print{ :root,:root[data-theme=dark]{--bg:#fff;--panel:#fff;--raised:#f0f2f5;--line:#ccc;--text:#111;--muted:#444;--accent:#087e69;--critical:#a1132c;--high:#984500;--medium:#705000;--info:#155c9b}
body{font-size:10pt}
.shell{display:block}
aside,.actions,.filters,.resultbar,#more,button{display:none!important}
main{padding:0}
.card,.panel{box-shadow:none}
.bars{max-height:none;overflow:visible}
.finding,.card{break-inside:avoid}
.finding-body pre{white-space:pre-wrap}
.finding-body{display:block!important}
details>summary{display:block}
.coverage{grid-template-columns:repeat(3,1fr)}
.grid{grid-template-columns:1fr 1fr}
a{color:inherit}
.panel{margin-bottom:15px}
}

@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}
}

</style></head><body>
<div class="shell"><aside><div class="brand"><span class="logo">F</span>FortiGate<small style="display:block;margin:8px 0 0 42px;font-size:10px;letter-spacing:1.5px">SECURITY ANALYZER</small></div><nav aria-label="Report navigation"><a href="#overview">◈ &nbsp; Overview</a><a href="#findings">☷ &nbsp; Findings</a><a href="#coverage">◎ &nbsp; Audit coverage</a><a href="#references">⌘ &nbsp; Technical references</a><a href="#details">ⓘ &nbsp; Assessment details</a></nav><div class="aside-foot"><span class="eyebrow">Offline assessment</span><p>Local analysis.<br>No data uploaded.</p><span id="version"></span></div></aside>
<main><header class="top"><span class="muted">REPORT / CONFIGURATION SECURITY</span><div class="actions"><button id="theme" type="button" aria-label="Toggle dark and light theme">◐ &nbsp; Theme</button><button id="print" type="button">Print / PDF</button></div></header>
<section id="overview"><div class="hero"><div><div class="eyebrow">FortiGate configuration audit</div><h1>Security assessment</h1><p>Understand configuration exposure. Prioritize the changes that matter.</p></div><span class="tag" id="file"></span></div>
<div class="cards"><div class="card risk"><div class="stat-label">OVERALL RISK</div><div class="number critical" id="risk"></div><p class="muted" id="score"></p><small>Weighted findings, not a security percentage.</small></div><div class="card"><div class="stat-label">TOTAL FINDINGS</div><div class="number" id="total"></div><div id="counts" class="mini-counts"></div></div><div class="card"><div class="stat-label">AUDIT COVERAGE</div><div class="number" id="executed"></div><p class="muted">domains executed</p><small id="not-selected"></small></div><div class="card"><div class="stat-label">PRIORITY FINDINGS</div><div class="number" id="priority"></div><p class="muted">critical + high severity</p><small>Review deployment context before changes.</small></div></div>
<div class="grid"><section class="panel"><div class="chart-head"><h2>Severity distribution</h2><small>All findings</small></div><div class="donut-box"><svg id="donut" class="donut" viewBox="0 0 180 180" role="img" aria-labelledby="donut-title"><title id="donut-title">Severity distribution</title></svg><div id="legend" class="legend"></div></div></section><section class="panel"><div class="chart-head"><h2>Findings by domain</h2><small>Severity composition</small></div><div id="bars" class="bars"></div></section></div>
<section class="panel"><div class="chart-head"><h2>Highest-risk domains</h2><small>C × 10 · H × 5 · M × 2 · I × 0.5</small></div><div id="ranks" class="rank-grid"></div></section></section>
<section id="findings"><div class="section"><h2>Findings explorer</h2><span class="tag">CONFIGURATION EVIDENCE</span></div><div class="filters"><label>Search findings<input id="search" type="search" placeholder="Policy, object, keyword…"></label><label>Severity<select id="severity"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>INFO</option></select></label><label>Audit domain<select id="domain"><option value="">All audited domains</option></select></label><label>VDOM / scope<select id="vdom"><option value="">All scopes</option></select></label><label>Sort by<select id="sort"><option value="highest">Highest severity</option><option value="lowest">Lowest severity</option><option value="domain">Audit domain</option><option value="title">Finding title</option><option value="original">Original order</option></select></label></div><div class="resultbar"><span id="result-count" role="status" aria-live="polite"></span><button id="reset" type="button">Reset filters</button></div><div id="list"></div><button id="more" type="button">Load more findings</button><div id="empty" class="empty hidden">No findings match these filters. Try another keyword or reset filters.</div><div id="status" role="status" aria-live="polite"></div></section>
<section id="coverage"><div class="section"><h2>Audit coverage</h2><small>No findings does not establish a passing check.</small></div><div id="coverage-list" class="coverage"></div></section>
<section id="references"><div class="section"><h2>Technical references &amp; existing CLI guidance</h2></div><p class="muted">Original domain report content, retained in memory during this run. Examples may contain placeholders or require adaptation. Confirm syntax for the installed FortiOS release and review operational impact.</p><div id="reference-list"></div></section>
<section id="details" class="panel" style="margin-top:25px"><h2>Assessment details</h2><dl id="metadata" class="metadata"></dl><div class="notice" id="notes"><p>Static configuration analysis cannot validate live reachability, effective identity-provider MFA, peer behavior, certificate trust chains, or operational state. Unselected domains are not assessed.</p><p>Risk is CRITICAL with any critical finding or score ≥ 50; HIGH ≥ 25; MEDIUM ≥ 10; otherwise LOW. LOW is a score classification, not a security guarantee.</p><p>Reports include sensitive network context. Protect them as confidential audit artifacts. Configured credential values are redacted from HTML; legacy TXT/JSON keep their existing confidentiality behavior.</p></div></section><footer class="footer"><span>FortiGate UTM Security Analyzer · Jafar Tavana</span><span>Local. Self-contained. Entirely offline.</span></footer>
<noscript><div class="notice">Enable JavaScript to explore this self-contained report. Existing TXT reports remain available without JavaScript.</div></noscript></main></div>
<script id="report-data" type="application/json"><!--REPORT_DATA--></script><script><!--REPORT_SCRIPT--></script></body></html>'''

HTML_SCRIPT = r'''"use strict";
(() => {
  const report=JSON.parse(document.getElementById('report-data').textContent);
  const $=id=>document.getElementById(id), severities=['CRITICAL','HIGH','MEDIUM','INFO'], weights=[10,5,2,.5];
  const el=(tag,cls,text)=>{
    const n=document.createElement(tag);
    if(cls)n.className=cls;
    if(text!==undefined)n.textContent=String(text);
    return n;
  };
  const svg=(tag,attrs)=>{
    const n=document.createElementNS('http://www.w3.org/2000/svg',tag);
    Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,String(v)));
    return n;
  };
  const colors=()=>severities.map(s=>getComputedStyle(document.documentElement).getPropertyValue('--'+s.toLowerCase()).trim());
  function theme(value){
    document.documentElement.dataset.theme=value;
    try{
      localStorage.setItem('fortigate-report-theme',value);
    }catch(_){
    }drawDonut();
  } let preferred='dark';
  try{
    preferred=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
    const saved=localStorage.getItem('fortigate-report-theme');
    if(['light','dark'].includes(saved))preferred=saved;
  }catch(_){
  } $('theme').addEventListener('click',()=>theme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
  const summary=report.summary, counts=summary.counts;
  $('risk').textContent=summary.risk;
  $('risk').className='number '+(summary.risk==='LOW'?'info':summary.risk.toLowerCase());
  $('score').textContent='Risk score '+summary.score;
  $('total').textContent=summary.total;
  $('priority').textContent=counts.CRITICAL+counts.HIGH;
  $('executed').textContent=Object.keys(summary.by_section).length;
  $('not-selected').textContent=report.domains.filter(d=>d.status==='Not selected').length+' domains not selected';
  $('file').textContent=report.metadata.filename;
  $('version').textContent='v'+report.metadata.tool_version;
  severities.forEach(s=>{
    $('counts').append(el('span',s.toLowerCase(),counts[s]+' '+s));
    const row=el('div','legend-row');
    const name=el('span',s.toLowerCase());
    name.append(el('span','dot'));
    name.firstChild.style.background='var(--'+s.toLowerCase()+')';
    name.append(document.createTextNode(s));
    row.append(name,el('strong','',counts[s]));
    $('legend').append(row);
  });
  function drawDonut(){
    const d=$('donut');
    d.replaceChildren(svg('title',{
      id:'donut-title'
    }));
    d.firstChild.textContent=severities.map(s=>s+': '+counts[s]).join(', ');
    d.append(svg('circle',{
      cx:90,cy:90,r:67,fill:'none',stroke:'var(--raised)','stroke-width':20
    }));
    let offset=0;
    const circumference=2*Math.PI*67;
    severities.forEach((s,i)=>{
      const length=summary.total?counts[s]/summary.total*circumference:0;
      if(length)d.append(svg('circle',{
        cx:90,cy:90,r:67,fill:'none',stroke:colors()[i],'stroke-width':20,'stroke-dasharray':length+' '+circumference,'stroke-dashoffset':-offset,transform:'rotate(-90 90 90)'
      }));
      offset+=length;
    });
    const n=svg('text',{
      x:90,y:92,'text-anchor':'middle',fill:'var(--text)','font-size':30,'font-weight':700
    });
    n.textContent=summary.total;
    const l=svg('text',{
      x:90,y:114,'text-anchor':'middle',fill:'var(--muted)','font-size':10
    });
    l.textContent='FINDINGS';
    d.append(n,l);
  } theme(preferred);
  const domains=Object.entries(summary.by_section).map(([name,c])=>({
    name,counts:c,total:severities.reduce((a,s)=>a+c[s],0),score:severities.reduce((a,s,i)=>a+c[s]*weights[i],0)
  }));
  const max=Math.max(1,...domains.map(d=>d.total));
  domains.filter(d=>d.total).sort((a,b)=>b.total-a.total).forEach(d=>{
    const row=el('div','bar-row');
    const label=el('div','bar-title');
    label.append(el('span','',d.name),el('span','',d.total));
    const track=el('div','bar-track');
    track.setAttribute('role','img');
    track.setAttribute('aria-label',d.name+': '+severities.map(s=>s+' '+d.counts[s]).join(', '));
    severities.forEach(s=>{
      if(!d.counts[s])return;
      const b=el('span','bar-segment');
      b.style.width=(d.counts[s]/max*100)+'%';
      b.style.background='var(--'+s.toLowerCase()+')';
      track.append(b);
    });
    row.append(label,track);
    $('bars').append(row);
  });
  if(!summary.total)$('bars').append(el('p','muted','No findings in executed domains.'));
  domains.filter(d=>d.total).sort((a,b)=>b.score-a.score).slice(0,5).forEach((d,i)=>{
    const n=el('div','');
    n.append(el('small','',String(i+1).padStart(2,'0')+' / '+d.name),el('div','rank-score',d.score));
    const t=el('div','bar-track'), b=el('span','bar-segment');
    b.style.width=(100*d.score/Math.max(1,...domains.map(x=>x.score)))+'%';
    b.style.background='var(--accent)';
    t.append(b);
    n.append(t);
    $('ranks').append(n);
  });
  if(!summary.total)$('ranks').append(el('p','muted','No ranked domains.'));
  Object.keys(summary.by_section).sort().forEach(d=>{
    const o=el('option','',d);
    o.value=d;
    $('domain').append(o);
  });
  [...new Set(report.findings.map(f=>f.vdom))].sort().forEach(v=>{
    const o=el('option','',v);
    o.value=v;
    $('vdom').append(o);
  });
  report.domains.forEach(d=>{
    const n=el('div','coverage-item');
    n.append(el('strong','',d.name),el('small','',d.status));
    $('coverage-list').append(n);
  });
  Object.entries(report.metadata).forEach(([k,v])=>{
    const n=el('div','');
    n.append(el('dt','',k.replaceAll('_',' ').toUpperCase()),el('dd','',v));
    $('metadata').append(n);
  });
  report.notes.forEach(n=>$('notes').append(el('p','',n)));
  async function copy(text,button){
    try{
      if(!navigator.clipboard)throw Error();
      await navigator.clipboard.writeText(text);
      button.textContent='Copied';
    }catch(_){
      const t=el('textarea','');
      t.value=text;
      t.setAttribute('readonly','');
      document.body.append(t);
      t.select();
      let ok=false;
      try{
        ok=document.execCommand('copy');
      }catch(_){
      }t.remove();
      button.textContent=ok?'Copied':'Select and copy below';
      if(!ok){
        const pre=button.parentElement.querySelector('pre');
        if(pre){
          const range=document.createRange();
          range.selectNodeContents(pre);
          const selection=window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
        }$('status').textContent='Clipboard unavailable. Commands selected for manual copying.';
      }
    }
  } Object.entries(report.references).forEach(([name,text])=>{
    const ref=el('details','ref panel'), head=el('summary','',name);
    ref.append(head);
    ref.addEventListener('toggle',()=>{
      if(ref.open&&!ref.dataset.loaded){
        ref.dataset.loaded='1';
        const pre=el('pre','reference',text);
        ref.append(pre);
      }
    }, {
      once:false
    });
    $('reference-list').append(ref);
  });
  const indexed=report.findings.map((f,index)=>({
    f,index,search:JSON.stringify(f).toLowerCase()
  }));
  let matches=[],limit=80;
  function detail(f){
    const d=el('details','finding');
    d.id='finding-'+f.id;
    const head=el('summary','');
    const title=el('div','');
    title.append(el('div','finding-title',f.title),el('div','finding-meta',[f.domain,f.object,f.vdom].filter(Boolean).join(' · ')));
    head.append(el('span','badge '+f.severity.toLowerCase(),f.severity),title);
    d.append(head);
    function load(){
      if(d.dataset.loaded)return;
      d.dataset.loaded='1';
      const body=el('div','finding-body');
      [['Finding details',f.description],['Security impact',f.impact],['Configuration evidence',typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2)],['Recommended remediation',f.recommendation]].forEach(([name,text])=>{
        body.append(el('h3','',name),el(name==='Configuration evidence'?'pre':'p','',text));
      });
      body.append(el('h3','','FortiGate CLI remediation'));
      if(f.cli||f.guidance){
        const content=f.cli||f.guidance,block=el('div','cli'),button=el('button','',f.cli?'Copy commands':'Copy original guidance');
        button.type='button';
        button.addEventListener('click',()=>copy(content,button));
        block.append(button,el('pre','',content));
        if(!f.cli)block.append(el('p','muted','Original audit guidance; may be incomplete and require placeholders.'));
        body.append(block);
      }else{
        body.append(el('p','muted',f.guidance||'No exact command is supplied for this finding. Review the technical references for existing guidance.'));
      }body.append(el('p','muted',f.operational_note||'Review FortiOS compatibility, replace placeholders, and validate impact on management access, routing and production traffic before applying changes.'));
      d.append(body);
    } d.addEventListener('toggle',()=>{
      if(d.open)load();
    });
    d.loadDetails=load;
    return d;
  } function render(){
    const frag=document.createDocumentFragment();
    matches.slice(0,limit).forEach(x=>frag.append(detail(x.f)));
    $('list').replaceChildren(frag);
    $('result-count').textContent=matches.length+' of '+report.findings.length+' findings · '+Math.min(limit,matches.length)+' displayed';
    $('more').classList.toggle('hidden',limit>=matches.length);
    $('empty').classList.toggle('hidden',matches.length!==0);
  } function filter(){
    const q=$('search').value.toLowerCase().trim(),s=$('severity').value,d=$('domain').value,v=$('vdom').value,sort=$('sort').value;
    matches=indexed.filter(x=>(!q||x.search.includes(q))&&(!s||x.f.severity===s)&&(!d||x.f.domain===d)&&(!v||x.f.vdom===v));
    const rank=s=>severities.indexOf(s);
    matches.sort((a,b)=>{
      if(sort==='highest')return rank(a.f.severity)-rank(b.f.severity)||a.index-b.index;
      if(sort==='lowest')return rank(b.f.severity)-rank(a.f.severity)||a.index-b.index;
      if(sort==='domain'||sort==='title')return a.f[sort].localeCompare(b.f[sort])||a.index-b.index;
      return a.index-b.index;
    });
    limit=80;
    render();
  } let timer;
  $('search').addEventListener('input',()=>{
    clearTimeout(timer);
    timer=setTimeout(filter,100);
  });
  ['severity','domain','vdom','sort'].forEach(id=>$(id).addEventListener('change',filter));
  $('reset').addEventListener('click',()=>{
    $('search').value='';
    ['severity','domain','vdom'].forEach(id=>$(id).value='');
    $('sort').value='highest';
    filter();
  });
  $('more').addEventListener('click',()=>{
    limit+=80;
    render();
  });
  let printState=null;
  function preparePrint(){
    if(printState)return;
    printState={
      limit,open:[...document.querySelectorAll('#list details[open]')].map(d=>d.id)
    };
    limit=matches.length;
    render();
    document.querySelectorAll('#list details').forEach(d=>{
      d.loadDetails();
      d.open=true;
    });
    document.querySelectorAll('#reference-list details').forEach(d=>{
      d.dataset.wasOpen=d.open?'1':'0';
      d.open=true;
      if(!d.dataset.loaded){
        d.dataset.loaded='1';
        d.append(el('pre','reference',report.references[d.firstChild.textContent]));
      }
    });
  } window.addEventListener('beforeprint',preparePrint);
  window.addEventListener('afterprint',()=>{
    if(!printState)return;
    limit=printState.limit;
    const opened=printState.open;
    printState=null;
    render();
    opened.forEach(id=>{
      if($(id))$(id).open=true;
    });
    document.querySelectorAll('#reference-list details').forEach(d=>d.open=d.dataset.wasOpen==='1');
  });
  $('print').addEventListener('click',()=>{
    preparePrint();
    window.print();
  });
  filter();
})();
'''


# ─────────────────────────────────────────────────────────────────────────────
# Context-preserving parser for new audits. Legacy parsers remain compatible.
# ─────────────────────────────────────────────────────────────────────────────

def parse_config_tree(text):
    """Parse config/edit nesting, preserving VDOM boundaries and quoted values.

    Malformed nesting is reported, never silently treated as an empty config.
    Multiline quoted values cannot inject config/end control lines.
    """
    import shlex
    root = {'kind': 'root', 'name': '', 'settings': {}, 'children': []}
    stack, errors = [root], []
    pending, start_line = [], 0
    def quote_open(value):
        quoted, escaped = False, False
        for char in value:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = not quoted
        return quoted
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if pending:
            pending.append(raw)
            if not quote_open(raw):
                continue
            line, pending = '\n'.join(pending), []
        elif not line or line.startswith('#'):
            continue
        elif quote_open(line):
            pending, start_line = [line], number
            continue
        parts = line.split(None, 1)
        command, value = parts[0], parts[1] if len(parts) > 1 else ''
        if command in ('config', 'edit'):
            kind = command
            if kind == 'edit' and stack[-1]['kind'] != 'config':
                errors.append('Line {}: edit outside config'.format(number)); continue
            if kind == 'config' and stack[-1]['kind'] == 'config':
                # Flat parent blocks (router bgp) may contain nested tables.
                pass
            if not value:
                errors.append('Line {}: missing {} name'.format(number, command)); continue
            try:
                if command == 'edit':
                    names = shlex.split(value)
                    if len(names) != 1:
                        raise ValueError('An edit requires one object identifier')
                    name = names[0]
                else:
                    name = ' '.join(value.split())
            except ValueError:
                errors.append('Line {}: malformed name'.format(number)); continue
            node = {'kind': kind, 'name': name, 'settings': {}, 'children': []}
            stack[-1]['children'].append(node); stack.append(node)
        elif command in ('next', 'end'):
            expected = 'edit' if command == 'next' else 'config'
            if len(stack) == 1 or stack[-1]['kind'] != expected:
                errors.append('Line {}: unmatched {}'.format(number, command))
            else:
                stack.pop()
        elif command in ('set', 'unset', 'append'):
            assignment = value.split(None, 1)
            key = assignment[0] if assignment else ''
            val = assignment[1] if len(assignment) > 1 else ''
            if len(stack) == 1 or not key:
                errors.append('Line {}: assignment outside block'.format(number)); continue
            if command == 'unset':
                stack[-1]['settings'].pop(key, None)
            elif command == 'append':
                stack[-1]['settings'][key] = (stack[-1]['settings'].get(key, '') + ' ' + val).strip()
            else:
                stack[-1]['settings'][key] = val
        else:
            errors.append('Line {}: unsupported configuration statement'.format(number))
    if pending:
        errors.append('Line {}: unterminated quoted value'.format(start_line))
    if len(stack) != 1:
        errors.append('Incomplete configuration: {} unclosed blocks'.format(len(stack)-1))
    return root, errors


def tree_blocks(node, name):
    return [n for n in node['children'] if n['kind'] == 'config' and n['name'] == name]


def tree_objects(node, name):
    return [obj for block in tree_blocks(node, name) for obj in block['children'] if obj['kind'] == 'edit']


def configuration_scopes(root):
    """Return explicit global/unwrapped/VDOM containers; never merge names."""
    result = []
    globals_ = tree_blocks(root, 'global')
    result.extend(('Global', n) for n in globals_)
    vdoms = tree_objects(root, 'vdom')
    result.extend((n['name'], n) for n in vdoms)
    # Some backups list VDOM declarations first, then a second full vdom block.
    # Repeated containers for one VDOM are combined without crossing boundaries.
    other = [n for n in root['children'] if n['name'] not in ('global', 'vdom')]
    if other:
        result.insert(0, ('Unwrapped' if globals_ or vdoms else 'root',
                          {'kind': 'root', 'name': '', 'settings': {}, 'children': other}))
    merged = {}
    for name, node in result:
        key = (node['kind'], node['name'], name)
        if key not in merged:
            merged[key] = (name, dict(node, children=list(node['children'])))
        else:
            merged[key][1]['children'].extend(node['children'])
    return list(merged.values())


def scoped_finding(severity, rule_id, title, obj, vdom, evidence, impact, recommendation, cli=''):
    # Only explicit fields with verified syntax receive a review example. Route
    # policies and trust anchors require deployment-specific values, so no CLI
    # is guessed for them. Never interpolate control characters into commands.
    examples = {
        'LDAP-IDENTITY': ('user ldap', 'server-identity-check', 'enable'),
        'LDAP-TLS': ('user ldap', 'ssl-min-proto-version', 'TLSv1-2'),
        'SAML-DIGEST': ('user saml', 'digest-method', 'sha256'),
        'RADIUS-IDENTITY': ('user radius', 'server-identity-check', 'enable'),
        'RADIUS-MESSAGE-AUTH': ('user radius', 'require-message-authenticator', 'enable'),
    }
    if not cli and rule_id in examples and all(ord(c) >= 32 and ord(c) != 127 for c in obj):
        block, key, value = examples[rule_id]
        quoted = '"' + obj.replace('\\', '\\\\').replace('"', '\\"') + '"'
        cli = '# Review example; first select scope: {}\nconfig {}\n    edit {}\n        set {} {}\n    next\nend'.format(
            json.dumps(vdom, ensure_ascii=True), block, quoted, key, value)
    return Finding(severity, '{} [{} / {}]: {}'.format(obj, vdom, rule_id, title),
                   rule_id=rule_id, object=obj, vdom=vdom, evidence=evidence,
                   description=title, impact=impact, recommendation=recommendation, cli=cli)


def asn_number(value):
    value = nv(value)
    try:
        if '.' in value:
            high, low = map(int, value.split('.'))
            return high * 65536 + low if 0 <= high <= 65535 and 0 <= low <= 65535 else None
        return int(value) if 0 < int(value) <= 4294967295 else None
    except (ValueError, TypeError):
        return None


def audit_bgp(scope, vdom):
    findings = []
    count = 0
    for bgp in tree_blocks(scope, 'router bgp'):
        local_as = asn_number(bgp['settings'].get('as', ''))
        groups = {n['name']: n for n in tree_objects(bgp, 'neighbor-group')}
        ranges = tree_objects(bgp, 'neighbor-range') + tree_objects(bgp, 'neighbor-range6')
        used = {nv(n['settings'].get('neighbor-group', '')) for n in ranges}
        peers = [(n, 'neighbor') for n in tree_objects(bgp, 'neighbor')]
        peers += [(groups[name], 'neighbor-group') for name in sorted(used) if name in groups]
        for n in ranges:
            group = nv(n['settings'].get('neighbor-group', ''))
            if group not in groups:
                findings.append(scoped_finding(M, 'BGP-GROUP', 'Neighbor range references a group absent from this backup.',
                    n['name'], vdom, {'neighbor-group': group},
                    'The supplied backup is insufficient to establish effective peer controls.',
                    'Check the complete backup and repair the group binding if it is missing on the device.'))
        for node, kind in peers:
            count += 1
            cfg = dict(node['settings'])
            name = '{} {}'.format(kind, node['name'])
            # Accommodate an explicit group binding if exported; never assume a
            # similarly named peer inherits a template. Dynamic ranges use groups.
            binding = nv(cfg.get('neighbor-group', ''))
            if binding:
                if binding not in groups:
                    findings.append(scoped_finding(M, 'BGP-GROUP', 'Effective neighbor group unavailable.',
                        name, vdom, {'neighbor-group': binding}, 'Inherited controls cannot be determined.',
                        'Obtain the complete configuration and verify the referenced group.'))
                    continue
                cfg = dict(groups[binding]['settings'], **cfg)
            if nv(cfg.get('shutdown')) == 'enable':
                continue
            remote_as = asn_number(cfg.get('remote-as', ''))
            def add(sev, rule, title, evidence, impact, recommendation):
                findings.append(scoped_finding(sev, rule, title, name, vdom, evidence, impact, recommendation))
            if not nv(cfg.get('password', '')):
                add(M, 'BGP-AUTH', 'No session authentication shown.', {'password': 'not configured'},
                    'Session authentication can reduce peer impersonation risk; protection by tunnels is unknown.',
                    'Review transport protection and coordinate supported BGP authentication with the peer. Encrypted secret strength cannot be inferred.')
            if not local_as or not remote_as or local_as == remote_as:
                continue  # Do not apply external-boundary requirements to iBGP or unknown ASNs.
            families = [('', 'IPv4', 'activate')]
            if nv(cfg.get('activate6', '')) == 'enable':
                families.append(('6', 'IPv6', 'activate6'))
            for suffix, label, activate in families:
                if nv(cfg.get(activate, '')) == 'disable':
                    continue
                for direction in ('in', 'out'):
                    keys = ['{}-{}{}'.format(prefix, direction, suffix) for prefix in ('prefix-list', 'route-map', 'filter-list', 'distribute-list')]
                    if not any(nv(cfg.get(k, '')) for k in keys):
                        add(M, 'BGP-FILTER-' + direction.upper(), '{} eBGP {}bound filtering not shown.'.format(label, direction),
                            {k: 'not configured' for k in keys},
                            'No neighbor-level policy is visible. Intended routes, upstream controls and route leaks cannot be established offline.',
                            'Review intended route exchange and apply a restrictive policy where appropriate. A filter reference alone does not establish its effectiveness.')
                limit_key = 'maximum-prefix' + suffix
                limit = nv(cfg.get(limit_key, ''))
                if not limit or limit == '0':
                    add(M, 'BGP-LIMIT', '{} prefix ceiling not shown.'.format(label),
                        {limit_key: limit or 'not configured'}, 'Unexpected route growth may exhaust resources.',
                        'Set a ceiling based on the agreed route count and growth margin. Incorrect limits can tear down production sessions.')
                if nv(cfg.get('maximum-prefix-warning-only' + suffix, '')) == 'enable':
                    add(M, 'BGP-LIMIT-WARN', '{} prefix limit is warning-only.'.format(label),
                        {'maximum-prefix-warning-only' + suffix: 'enable'},
                        'Exceeding the prefix threshold may not enforce a protective session limit.',
                        'Confirm monitoring and decide whether enforced limits suit this peer; review outage impact first.')
            if nv(cfg.get('ebgp-enforce-multihop', '')) == 'enable':
                ttl = nv(cfg.get('ebgp-multihop-ttl', ''))
                if ttl.isdigit() and int(ttl) > 10:
                    add(M, 'BGP-MULTIHOP', 'eBGP multihop TTL exceeds 10.', {'ebgp-multihop-ttl': ttl},
                        'A large TTL permits a wider peer path than a short-hop design needs; this may be intentional.',
                        'Verify the actual hop distance, tunnel design and ACLs before reducing the TTL.')
        for name in ('redistribute', 'redistribute6'):
            for n in tree_objects(bgp, name):
                cfg = n['settings']
                if n['name'] in ('connected', 'static') and nv(cfg.get('status')) == 'enable' and not nv(cfg.get('route-map')):
                    findings.append(scoped_finding(M, 'BGP-REDIST', 'Enabled redistribution has no route-map shown.',
                        name + ' ' + n['name'], vdom, {'status': 'enable', 'route-map': 'not configured'},
                        'Routes may enter BGP beyond intended scope; outbound neighbor policies may still restrict advertisements.',
                        'Review redistribution and outbound policies together. Add explicit selection where needed; validate reachability before applying.'))
    return findings, count


def audit_authentication(scope, vdom, selected):
    results, counts = {}, {}
    if 'RADIUS' in selected:
        items = tree_objects(scope, 'user radius'); findings = []
        for node in items:
            c, name = node['settings'], node['name']
            def add(sev, rule, title, evidence, impact, recommendation):
                findings.append(scoped_finding(sev, rule, title, name, vdom, evidence, impact, recommendation))
            transport = nv(c.get('transport-protocol', ''))
            if transport in ('udp', 'tcp'):
                add(M, 'RADIUS-TRANSPORT', 'RADIUS transport is not TLS.', {'transport-protocol': transport},
                    'RADIUS transport is not encrypted end to end; an IPsec tunnel or trusted path may provide separate protection.',
                    'Review path trust, patched RADIUS servers and Message-Authenticator enforcement. Consider RADSEC where the FortiOS release and server support it.')
            if nv(c.get('auth-type')) in ('chap', 'ms_chap'):
                add(M, 'RADIUS-METHOD', 'Legacy authentication method selected.', {'auth-type': nv(c['auth-type'])},
                    'Legacy challenge-response methods can expose credentials to offline attacks depending on the environment.',
                    'Coordinate a supported authentication method with the server and protect the transport. PAP is not automatically unsafe inside a protected channel.')
            if transport == 'tls' and nv(c.get('server-identity-check')) == 'disable':
                add(H, 'RADIUS-IDENTITY', 'TLS server identity checking explicitly disabled.', {'server-identity-check': 'disable'},
                    'The connection may not authenticate the intended server identity.',
                    'Install the appropriate trust chain and enable supported server identity validation. Test authentication before deployment.')
            if nv(c.get('require-message-authenticator')) == 'disable':
                add(H, 'RADIUS-MESSAGE-AUTH', 'RADIUS Message-Authenticator requirement explicitly disabled.', {'require-message-authenticator': 'disable'},
                    'The client is configured to accept responses without requiring this integrity control.',
                    'Patch and verify the RADIUS server, then enable this requirement on supported releases. Do not bypass it to hide server compatibility errors.')
            if len(items) == 1 and not any(nv(c.get(k)) for k in ('secondary-server', 'tertiary-server')):
                add(I, 'RADIUS-REDUNDANCY', 'No alternate RADIUS endpoint shown.', {'alternate-server': 'not shown'},
                    'A single endpoint may be an availability dependency; a VIP or server-side HA cannot be determined offline.',
                    'Verify service HA and failover. Multiple configured objects do not prove effective redundancy.')
        results['RADIUS'], counts['RADIUS'] = findings, len(items)
    if 'LDAP' in selected:
        items = tree_objects(scope, 'user ldap'); findings = []
        for node in items:
            c, name = node['settings'], node['name']
            def add(sev, rule, title, evidence, impact, recommendation):
                findings.append(scoped_finding(sev, rule, title, name, vdom, evidence, impact, recommendation))
            secure = nv(c.get('secure', ''))
            if secure == 'disable':
                add(H, 'LDAP-TRANSPORT', 'LDAP encryption explicitly disabled.', {'secure': 'disable'},
                    'Directory credentials and queries may be exposed on an unprotected path.',
                    'Configure LDAPS or STARTTLS with appropriate CA trust and server identity validation. Validate bind and login behavior first.')
            if secure in ('ldaps', 'starttls'):
                if nv(c.get('server-identity-check')) == 'disable':
                    add(H, 'LDAP-IDENTITY', 'LDAP TLS server identity checking explicitly disabled.', {'secure': secure, 'server-identity-check': 'disable'},
                        'Certificate name checks are bypassed; trust-chain validation alone may not identify the intended server.',
                        'Match the configured hostname to the certificate SAN and enable identity checks on supported releases.')
                if not nv(c.get('ca-cert')):
                    add(I, 'LDAP-CA', 'No explicit LDAP CA reference shown.', {'secure': secure, 'ca-cert': 'not shown'},
                        'The explicit trust anchor is not visible. This does not prove validation is disabled.',
                        'Verify effective trust-store behavior on the deployed release and select the intended CA where required.')
                tls = nv(c.get('ssl-min-proto-version', '')).lower()
                if tls in ('sslv3', 'tlsv1', 'tlsv1-0', 'tlsv1-1'):
                    add(H, 'LDAP-TLS', 'Legacy LDAP minimum TLS version configured.', {'ssl-min-proto-version': tls},
                        'Connections can negotiate obsolete protocol versions.',
                        'Coordinate TLS 1.2 or later with directory servers and validate compatibility before changing the minimum.')
        results['LDAP'], counts['LDAP'] = findings, len(items)
    if 'SAML' in selected:
        items = tree_objects(scope, 'user saml'); findings = []
        for node in items:
            c, name = node['settings'], node['name']
            def add(sev, rule, title, evidence, impact, recommendation):
                findings.append(scoped_finding(sev, rule, title, name, vdom, evidence, impact, recommendation))
            for key in ('single-sign-on-url', 'idp-single-sign-on-url', 'single-logout-url', 'idp-single-logout-url'):
                if nv(c.get(key)).lower().startswith('http://'):
                    add(H, 'SAML-HTTP', 'SAML browser endpoint uses HTTP.', {key: nv(c[key])},
                        'Browser authentication exchanges may traverse an unencrypted endpoint.',
                        'Use HTTPS endpoints and update both SP and IdP metadata together. Entity-ID identifiers are not transport URLs and are not flagged.')
            if nv(c.get('digest-method')) == 'sha1':
                add(M, 'SAML-DIGEST', 'SAML SHA-1 digest explicitly selected.', {'digest-method': 'sha1'},
                    'SHA-1 is a legacy digest; this does not establish the algorithm used by every incoming IdP assertion.',
                    'Coordinate SHA-256 with the IdP and verify SSO on the installed FortiOS version.')
            if not nv(c.get('idp-cert')):
                add(M, 'SAML-IDP-CERT', 'IdP certificate reference absent from supplied object.', {'idp-cert': 'not shown'},
                    'The intended signing certificate cannot be identified from this object. Actual assertion validation is not testable offline.',
                    'Obtain the full configuration and verify the intended IdP signing certificate and rotation process.')
        results['SAML'], counts['SAML'] = findings, len(items)
    return results, counts


def admin_mfa_findings(a, vdom='Unscoped (legacy)'):
    name = nv(a.get('name', a.get('_id', '')))
    two_factor = nv(a.get('two-factor', a.get('twofactor', '')))
    if two_factor in ('fortitoken', 'fortitoken-cloud', 'email', 'sms'):
        return []
    external = nv(a.get('remote-auth')) == 'enable' or nv(a.get('peer-auth')) == 'enable'
    if external:
        return [Finding(I, "Admin '{}': MFA potentially delegated externally — verify effective identity-provider policy.".format(name),
                        object=name, vdom=vdom, rule_id='MFA-EXTERNAL',
                        evidence={'remote-auth': nv(a.get('remote-auth')), 'peer-auth': nv(a.get('peer-auth'))},
                        recommendation='Verify IdP MFA and fallback paths, including break-glass access. Backup data cannot establish external MFA enforcement.')]
    if not two_factor or two_factor in ('disable', 'none'):
        return [Finding(H, "Admin '{}': two-factor authentication not enabled.".format(name),
                        object=name, vdom=vdom, rule_id='MFA-LOCAL',
                        evidence={'two-factor': two_factor or 'not shown', 'remote-auth': nv(a.get('remote-auth')) or 'not shown'},
                        recommendation='Review local account MFA and any documented break-glass exception. Stage token enrollment and retain tested recovery access.')]
    return [Finding(I, "Admin '{}': unrecognized MFA mode — unable to determine.".format(name),
                    object=name, vdom=vdom, rule_id='MFA-UNKNOWN', evidence={'two-factor': two_factor})]


def crypto_transport_weaknesses(cfg):
    """Explicit modern SSH fields and management TLS; no inferred defaults.

    Supports the documented fields under system global or system ssh-config.
    Does not duplicate existing VPN, certificate, or legacy SSH field checks.
    """
    findings = []
    checks = [
        ('ssh-enc-algo', lambda s: s.endswith('-cbc') or s.startswith(('arcfour', '3des', 'blowfish', 'cast128')), H, 'legacy SSH cipher'),
        ('ssh-kex-algo', lambda s: s.endswith('-sha1'), H, 'legacy SHA-1 SSH key exchange'),
        ('ssh-mac-algo', lambda s: 'md5' in s or s.startswith('hmac-sha1'), M, 'legacy SSH MAC'),
        ('admin-https-ssl-versions', lambda s: s.lower() in ('sslv3', 'tlsv1', 'tlsv1-0', 'tlsv1-1'), H, 'obsolete management TLS version'),
    ]
    for key, weak, severity, label in checks:
        bad = [value for value in nv(cfg.get(key, '')).split() if weak(value)]
        if bad:
            findings.append(Finding(severity, '{}: {} allowed — review interoperability before removing.'.format(key, label),
                rule_id='CRYPTO-' + key.upper(), object=key, vdom='Global', evidence={key: ' '.join(bad)},
                recommendation='Restrict this explicit allow-list to supported contemporary algorithms. Verify the installed release and maintain tested management recovery access.'))
    return findings


def run_extended_audits(config_text, selected):
    """Return shared findings, explicit applicability statuses and coverage notes."""
    root, errors = parse_config_tree(config_text)
    results = {name: [] for name in selected}
    counts = {name: 0 for name in selected}
    notes = ['New checks evaluate explicit settings; absent version-dependent values remain unknown. No live session or identity-provider state is tested.']
    if errors:
        notes.extend(errors)
        return results, {name: 'Unavailable: malformed or incomplete configuration' for name in selected}, notes
    for vdom, scope in configuration_scopes(root):
        if 'BGP Security' in selected:
            finds, count = audit_bgp(scope, vdom)
            results['BGP Security'].extend(finds); counts['BGP Security'] += count
        authentication = [name for name in selected if name in ('RADIUS', 'LDAP', 'SAML')]
        found, observed = audit_authentication(scope, vdom, authentication)
        for name in found:
            results[name].extend(found[name]); counts[name] += observed[name]
        if 'Admin MFA' in selected:
            items = tree_objects(scope, 'system admin')
            counts['Admin MFA'] += len(items)
            for node in items:
                results['Admin MFA'].extend(admin_mfa_findings(dict(node['settings'], _id=node['name']), vdom))
    statuses = {name: ('Not applicable: no configured objects in supplied scope' if counts[name] == 0 and not results[name]
                       else 'Audited explicit configuration; runtime and omitted settings unknown') for name in selected}
    if tree_objects(root, 'vdom'):
        notes.append('New BGP/authentication checks keep VDOMs separate. Legacy audit domains still use the first matching block and must not be treated as complete multi-VDOM coverage.')
    return results, statuses, notes


def main():
    parser = argparse.ArgumentParser(
        description="FortiGate UTM Security Analyzer v4.1.0 — FortiOS 6.x/7.x/8.0 deep config audit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 utm.py -c fw.conf --all               # full audit
  python3 utm.py -c fw.conf -f -av -s --summary # core + system + summary
  python3 utm.py -c fw.conf -vpn -sslvpn        # VPN focus
  python3 utm.py -c fw.conf -utm                # all UTM profiles
        """
    )
    parser.add_argument("-c", "--config", required=True, help="FortiGate config file (show full-configuration)")
    parser.add_argument("-f",      action="store_true", help="Firewall policy audit (IPv4+IPv6)")
    parser.add_argument("-i",      action="store_true", help="SSL/SSH inspection profile audit")
    parser.add_argument("-av",     action="store_true", help="Antivirus profile audit (8.0 sub-block aware)")
    parser.add_argument("-ips",    action="store_true", help="IPS sensor audit")
    parser.add_argument("-wf",     action="store_true", help="Web filter profile audit")
    parser.add_argument("-app",    action="store_true", help="Application control profile audit")
    parser.add_argument("-dns",    action="store_true", help="DNS filter profile audit")
    parser.add_argument("-waf",    action="store_true", help="WAF profile audit")
    parser.add_argument("-email",  action="store_true", help="Email filter profile audit")
    parser.add_argument("-video",  action="store_true", help="Video filter profile audit")
    parser.add_argument("-file",   action="store_true", help="File filter profile audit")
    parser.add_argument("-vpatch", action="store_true", help="Virtual patch profile audit")
    parser.add_argument("-llm",    action="store_true", help="LLM profile audit (FortiOS 8.0)")
    parser.add_argument("-utm",    action="store_true", help="All UTM profile audits in one report")
    parser.add_argument("-vpn",    action="store_true", help="IPsec VPN Phase1+Phase2 audit")
    parser.add_argument("-sslvpn", action="store_true", help="SSL-VPN settings + portals audit")
    parser.add_argument("-ha",     action="store_true", help="HA configuration audit")
    parser.add_argument("-log",    action="store_true", help="Logging audit (FA1-3, syslogd1-4, disk, events)")
    parser.add_argument("-dos",       action="store_true", help="Basic DoS policy audit")
    parser.add_argument("-antidos",   action="store_true", help="Full Anti-DoS protection audit (policies, IPS anomalies, NP offload, session limits, hardening)")
    parser.add_argument("-intel",     action="store_true", help="Policy intelligence: shadowed rules, duplicates, coverage statistics")
    parser.add_argument("-unused",    action="store_true", help="Unused objects: addresses, groups, services, VIPs, IP pools, schedules")
    parser.add_argument("-vip",       action="store_true", help="VIP/port-forward security audit (exposed ports, risky services, source filtering)")
    parser.add_argument("-sdwan",     action="store_true", help="SD-WAN audit (health checks, SLA thresholds, member monitoring)")
    parser.add_argument("-iface",     action="store_true", help="Interface exposure score report")
    parser.add_argument("-cert",      action="store_true", help="Certificate audit (expiry, key size, self-signed)")
    parser.add_argument("-fabric",    action="store_true", help="Fabric connector audit (AWS/Azure/GCP, EMS, ZTNA, SASE, external resources)")
    parser.add_argument("-ai",        action="store_true", help="AI/LLM application audit (ChatGPT, Gemini, DeepSeek, data sovereignty, LLM profiles)")
    parser.add_argument("-s",      action="store_true", help="System hardening (admin, interface, global, SNMP, SSH, NTP, DNS, CSF, FIPS, IKE, local-in)")
    parser.add_argument("--summary", action="store_true", help="Executive summary + JSON export")
    parser.add_argument('-bgp', '--bgp', action='store_true', help='VDOM-aware BGP configuration security audit')
    parser.add_argument('-auth', '--auth', action='store_true', help='RADIUS, LDAP, SAML and administrator MFA audits')
    parser.add_argument('--radius', action='store_true', help='RADIUS hardening audit')
    parser.add_argument('--ldap', action='store_true', help='LDAP hardening audit')
    parser.add_argument('--saml', action='store_true', help='SAML hardening audit')
    parser.add_argument('--mfa', action='store_true', help='Administrator MFA audit (included in -s)')
    parser.add_argument("--html", action="store_true", help="Additional self-contained offline HTML report (explicit opt-in)")
    parser.add_argument("--out-dir", "--output-dir", default=None, metavar="DIRECTORY",
                        help="Write reports to DIRECTORY (default: input filename without extension)")
    parser.add_argument("--all",   action="store_true", help="Run all audit modules")

    args = parser.parse_args()

    if args.all:
        for attr in ["f","i","av","ips","wf","app","dns","waf","email","video","file",
                     "vpatch","llm","utm","vpn","sslvpn","ha","log","dos","antidos",
                     "intel","unused","vip","sdwan","iface","cert","fabric","ai",
                     "s","summary","bgp","auth"]:
            setattr(args, attr, True)

    cfg_text = read_config(args.config)
    base = Path(args.config).name

    out_dir = (Path(args.out_dir).expanduser() if args.out_dir is not None
               else Path(base).with_suffix(""))
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"Cannot create output directory '{out_dir}': {exc}")

    references = {} if args.html else None

    def out(suffix):
        path = out_dir / f"{base}{suffix}"
        return path if suffix == "_SUMMARY.txt" else ReportOutput(path, references)

    print(f"[*] Parsing config: {args.config}")

    policies       = parse_firewall_policies(cfg_text)
    policies6      = parse_firewall_policies6(cfg_text)
    ssl_profiles   = parse_ssl_profiles_v2(cfg_text)
    av_profiles    = parse_av_profiles_v2(cfg_text)
    ips_sensors    = parse_ips_sensors(cfg_text)
    wf_profiles    = parse_wf_profiles(cfg_text)
    app_profiles   = parse_app_profiles(cfg_text)
    dns_profiles   = parse_dns_profiles(cfg_text)
    waf_profiles   = parse_waf_profiles(cfg_text)
    email_profiles = parse_email_profiles(cfg_text)
    video_profiles = parse_video_profiles(cfg_text)
    file_filter    = parse_file_filter(cfg_text)
    vpatch_profs   = parse_virtual_patch(cfg_text)
    ssh_filter_p   = parse_ssh_filter(cfg_text)
    llm_profiles   = parse_llm_profiles(cfg_text)
    admins         = parse_admins(cfg_text)
    interfaces     = parse_interfaces(cfg_text)
    local_in       = parse_local_in(cfg_text)
    local_in6      = parse_local_in6(cfg_text)
    global_cfg     = parse_system_global(cfg_text)
    pw_policy_cfg  = parse_password_policy(cfg_text)
    ssh_cfg        = parse_system_ssh(cfg_text)
    ntp_cfg        = parse_ntp(cfg_text)
    snmp_info      = parse_snmp_sysinfo(cfg_text)
    snmp_comm      = parse_snmp_community(cfg_text)
    snmp_users     = parse_snmp_user(cfg_text)
    dns_cfg        = parse_system_dns(cfg_text)
    csf_cfg        = parse_system_csf(cfg_text)
    fips_cfg       = parse_system_fips(cfg_text)
    ike_cfg        = parse_system_ike(cfg_text)
    fg_cfg         = parse_system_fortiguard(cfg_text)
    phase1         = parse_vpn_phase1(cfg_text)
    phase2         = parse_vpn_phase2(cfg_text)
    ha_cfg         = parse_ha(cfg_text)
    ssl_vpn_cfg    = parse_ssl_vpn_settings(cfg_text)
    ssl_vpn_portals= parse_ssl_vpn_portals(cfg_text)
    fa1            = parse_log_fortianalyzer(cfg_text)
    fa2            = parse_log_fortianalyzer2(cfg_text)
    fa3            = parse_log_fortianalyzer3(cfg_text)
    syslog1        = parse_log_syslogd(cfg_text)
    syslog2        = parse_log_syslogd2(cfg_text)
    syslog3        = parse_log_syslogd3(cfg_text)
    syslog4        = parse_log_syslogd4(cfg_text)
    log_cfg        = parse_log_setting(cfg_text)
    evtfilter      = parse_log_eventfilter(cfg_text)
    disk_cfg       = parse_log_disk_setting(cfg_text)
    disk_filter    = parse_log_disk_filter(cfg_text)
    dos_policies      = parse_dos_policy(cfg_text)
    dos_policies_full = parse_dos_policy_full(cfg_text)
    np_cfg            = parse_np_global(cfg_text)
    res_limit         = parse_system_resource_limit(cfg_text)
    global_dos        = parse_system_global_dos(cfg_text)
    addr_objs         = parse_address_objects(cfg_text)
    addr_groups       = parse_address_groups(cfg_text)
    svc_custom        = parse_service_custom(cfg_text)
    svc_groups        = parse_service_groups(cfg_text)
    vip_objs          = parse_vip_objects(cfg_text)
    vip_groups        = parse_vip_groups(cfg_text)
    ip_pools          = parse_ip_pools(cfg_text)
    schedules         = parse_schedules(cfg_text)
    schedules_ot      = parse_schedules_onetime(cfg_text)
    sdwan_cfg         = parse_sdwan(cfg_text)
    local_certs       = parse_cert_local(cfg_text)
    ca_certs          = parse_cert_ca(cfg_text)
    remote_certs      = parse_cert_remote(cfg_text)
    fabric_connectors = parse_fabric_connectors(cfg_text)
    cloud_connectors  = parse_cloud_connectors(cfg_text)
    ems_cfg           = parse_ems_settings(cfg_text)
    ztna_cfg          = parse_ztna_settings(cfg_text)
    sase_cfg          = parse_sase_connector(cfg_text)

    print(f"[*] Parsed: {len(policies)} IPv4 policies, {len(policies6)} IPv6 policies, "
          f"{len(ssl_profiles)} SSL profiles, {len(av_profiles)} AV profiles, "
          f"{len(phase1)} VPN tunnels, {len(admins)} admins, {len(interfaces)} interfaces, "
          f"{len(dos_policies_full)} DoS policies")

    all_findings: Dict[str, List[str]] = {}

    if args.f:
        p = out("_firewall_policy_report.txt")
        generate_policy_report(policies, policies6, p)
        print(f"[+] Firewall policy report     -> {p}")
        all_findings["Firewall Policies"] = [fn for pol in policies+policies6
                                              for fn in fw_policy_weaknesses(pol)]

    if args.i:
        p = out("_ssl_inspection_report.txt")
        generate_ssl_report(ssl_profiles, p)
        print(f"[+] SSL/SSH inspection report  -> {p}")
        all_findings["SSL Inspection"] = [fn for prof in ssl_profiles
                                           for fn in ssl_profile_weaknesses(prof)]

    if args.av:
        p = out("_antivirus_report.txt")
        generate_av_report(av_profiles, p)
        print(f"[+] Antivirus report           -> {p}")
        all_findings["Antivirus Profiles"] = [fn for prof in av_profiles
                                               for fn in av_profile_weaknesses(prof)]

    if args.utm or any([args.ips, args.wf, args.app, args.dns, args.waf,
                        args.email, args.video, args.file, args.vpatch, args.llm]):
        p = out("_utm_profiles_report.txt")
        generate_utm_profiles_report(ips_sensors, wf_profiles, app_profiles,
                                      dns_profiles, waf_profiles, email_profiles,
                                      video_profiles, file_filter, vpatch_profs,
                                      parse_sctp_filter(cfg_text), ssh_filter_p,
                                      llm_profiles, p)
        print(f"[+] UTM profiles report        -> {p}")
        all_findings["IPS Sensors"]    = [fn for s in ips_sensors    for fn in ips_sensor_weaknesses(s)]
        all_findings["Web Filter"]     = [fn for s in wf_profiles    for fn in wf_profile_weaknesses(s)]
        all_findings["App Control"]    = [fn for s in app_profiles   for fn in app_profile_weaknesses(s)]
        all_findings["DNS Filter"]     = [fn for s in dns_profiles   for fn in dns_profile_weaknesses(s)]
        all_findings["WAF Profiles"]   = [fn for s in waf_profiles   for fn in waf_profile_weaknesses(s)]
        all_findings["Email Filter"]   = [fn for s in email_profiles for fn in email_profile_weaknesses(s)]
        all_findings["Video Filter"]   = [fn for s in video_profiles for fn in video_profile_weaknesses(s)]
        all_findings["File Filter"]    = [fn for s in file_filter    for fn in file_filter_weaknesses(s)]
        all_findings["Virtual Patch"]  = [fn for s in vpatch_profs  for fn in virtual_patch_weaknesses(s)]
        all_findings["LLM Profiles"]   = [fn for s in llm_profiles  for fn in llm_profile_weaknesses(s)]

    if args.vpn:
        p = out("_vpn_report.txt")
        generate_vpn_report(phase1, phase2, p)
        print(f"[+] VPN (IPsec) report         -> {p}")
        all_findings["VPN Phase1"] = [fn for t in phase1 for fn in vpn_phase1_weaknesses(t)]
        all_findings["VPN Phase2"] = [fn for t in phase2 for fn in vpn_phase2_weaknesses(t)]

    if args.sslvpn:
        p = out("_sslvpn_report.txt")
        generate_sslvpn_report(ssl_vpn_cfg, ssl_vpn_portals, p)
        print(f"[+] SSL-VPN report             -> {p}")
        all_findings["SSL-VPN"] = ssl_vpn_weaknesses(ssl_vpn_cfg)
        all_findings["SSL-VPN Portals"] = [fn for pr in ssl_vpn_portals
                                            for fn in ssl_vpn_portal_weaknesses(pr)]

    if args.ha:
        p = out("_ha_report.txt")
        generate_ha_report(ha_cfg, p)
        print(f"[+] HA report                  -> {p}")
        all_findings["HA Config"] = ha_weaknesses(ha_cfg)

    if args.log:
        p = out("_logging_report.txt")
        generate_logging_report(fa1, fa2, fa3, syslog1, syslog2, syslog3, syslog4,
                                 log_cfg, evtfilter, disk_cfg, disk_filter, p)
        print(f"[+] Logging report             -> {p}")
        all_findings["Logging"] = logging_weaknesses(
            fa1, fa2, fa3, syslog1, syslog2, syslog3, syslog4,
            log_cfg, evtfilter, disk_cfg, disk_filter)

    if args.dos:
        p = out("_dos_policy_report.txt")
        generate_dos_report(dos_policies, p)
        print(f"[+] DoS policy report          -> {p}")
        findings_dos = [fn for dp in dos_policies for fn in dos_policy_weaknesses(dp)]
        if not dos_policies:
            findings_dos.append(f(M, "No DoS policies configured — no flood/anomaly protection rules active."))
        all_findings["DoS Policies"] = findings_dos

    if args.antidos:
        p = out("_antidos_report.txt")
        generate_antidos_report(
            dos_policies_full, ips_sensors, interfaces,
            local_in, local_in6, policies,
            global_dos, res_limit, np_cfg, p
        )
        print(f"[+] Anti-DoS full audit report -> {p}")
        # Collect all findings for summary
        ad_f1 = antidos_policy_weaknesses(dos_policies_full, interfaces)
        ad_f2 = antidos_ips_weaknesses(ips_sensors, policies)
        ad_f3 = antidos_hardening_weaknesses(
            interfaces, local_in, local_in6,
            global_dos, res_limit, np_cfg, policies
        )
        all_findings["Anti-DoS Policies"]   = ad_f1
        all_findings["Anti-DoS IPS"]        = ad_f2
        all_findings["Anti-DoS Hardening"]  = ad_f3
        assessment = antidos_score(ad_f1 + ad_f2 + ad_f3)
        print(f"    DoS Protection Score: {assessment['score']}/10 — {assessment['grade']}")

    if args.s:
        p = out("_system_report.txt")
        generate_system_report(admins, interfaces, global_cfg, pw_policy_cfg, ssh_cfg,
                                ntp_cfg, local_in, local_in6, snmp_info, snmp_comm,
                                snmp_users, dns_cfg, csf_cfg, fips_cfg, ike_cfg,
                                fg_cfg, p)
        print(f"[+] System hardening report    -> {p}")
        all_findings["Admin Accounts"]    = [fn for a in admins for fn in admin_weaknesses(a)]
        all_findings["Interfaces"]        = [fn for i in interfaces for fn in interface_weaknesses(i)]
        all_findings["Global Hardening"]  = global_hardening_weaknesses(global_cfg)
        all_findings["Password Policy"]   = password_policy_weaknesses(pw_policy_cfg)
        all_findings["SSH Config"]        = ssh_config_weaknesses(ssh_cfg)
        all_findings["NTP"]               = ntp_weaknesses(ntp_cfg)
        all_findings["Local-in"]          = [fn for l in local_in+local_in6
                                              for fn in local_in_weaknesses(l)]
        all_findings["SNMP"]              = (snmp_sysinfo_weaknesses(snmp_info) +
                                             [fn for c in snmp_comm
                                              for fn in snmp_community_weaknesses(c)] +
                                             [fn for u in snmp_users
                                              for fn in snmp_user_weaknesses(u)])
        all_findings["System DNS"]        = dns_system_weaknesses(dns_cfg)
        all_findings["IKE Global"]        = ike_global_weaknesses(ike_cfg)
        all_findings["Security Fabric"]   = csf_weaknesses(csf_cfg)
        all_findings["FIPS-CC"]           = fips_weaknesses(fips_cfg)
        all_findings["FortiGuard"]        = fortiguard_weaknesses(fg_cfg)

    if args.intel:
        p = out("_policy_intelligence_report.txt")
        intel_finds = generate_policy_intelligence_report(policies, policies6, p)
        print(f"[+] Policy intelligence report -> {p}")
        all_findings["Policy Intelligence"] = intel_finds

    if args.unused:
        p = out("_unused_objects_report.txt")
        unused_finds = generate_unused_objects_report(
            addr_objs, addr_groups, svc_custom, svc_groups,
            vip_objs, vip_groups, ip_pools, schedules, schedules_ot,
            policies, policies6, ssl_profiles, p
        )
        print(f"[+] Unused objects report      -> {p}")
        all_findings["Unused Objects"] = unused_finds

    if args.vip:
        p = out("_vip_security_report.txt")
        vip_finds = generate_vip_report(vip_objs, vip_groups, policies, p)
        print(f"[+] VIP security report        -> {p}")
        all_findings["VIP Security"] = vip_finds

    if args.sdwan:
        p = out("_sdwan_report.txt")
        sdwan_finds = generate_sdwan_report(sdwan_cfg, p)
        print(f"[+] SD-WAN report              -> {p}")
        all_findings["SD-WAN"] = sdwan_finds

    if args.iface:
        p = out("_interface_exposure_report.txt")
        iface_finds = generate_interface_exposure_report(interfaces, p)
        print(f"[+] Interface exposure report  -> {p}")
        all_findings["Interface Exposure"] = iface_finds

    if args.cert:
        p = out("_certificate_report.txt")
        cert_finds = generate_cert_report(local_certs, ca_certs, remote_certs, p)
        print(f"[+] Certificate audit report   -> {p}")
        all_findings["Certificates"] = cert_finds

    if args.fabric:
        p = out("_fabric_connector_report.txt")
        fabric_finds = generate_fabric_connector_report(
            fabric_connectors, cloud_connectors, ems_cfg,
            ztna_cfg, sase_cfg, policies, p
        )
        print(f"[+] Fabric connector report    -> {p}")
        all_findings["Fabric Connectors"] = fabric_finds

    if args.ai:
        p = out("_ai_llm_audit_report.txt")
        ai_finds = generate_ai_audit_report(
            llm_profiles, app_profiles, policies,
            wf_profiles, cfg_text, p
        )
        print(f"[+] AI/LLM audit report        -> {p}")
        all_findings["AI/LLM Security"] = ai_finds

    if args.s:
        # Enhanced local-in within system report
        elip_finds = enhanced_local_in_weaknesses(local_in, local_in6, interfaces)
        all_findings["Enhanced Local-in"] = elip_finds

    selected = []
    if args.bgp:
        selected.append('BGP Security')
    for name in ('RADIUS', 'LDAP', 'SAML'):
        if args.auth or getattr(args, name.lower()):
            selected.append(name)
    if (args.auth or args.mfa) and not args.s:
        selected.append('Admin MFA')  # -s already evaluates MFA: avoid duplicates.
    extended, statuses, coverage_notes = run_extended_audits(cfg_text, selected) if selected else ({}, {}, [])
    if args.s:
        statuses['Admin MFA'] = 'Included in Admin Accounts (-s); not counted twice'
    for domain, findings in extended.items():
        all_findings[domain] = findings
        slug = domain.lower().replace(' ', '_')
        p = out('_' + slug + '_report.txt')
        safe = ReportRedactor(cfg_text)
        sections = [('Scope', statuses[domain]), ('Limitations', '\n'.join(coverage_notes))]
        for finding in findings:
            detail = getattr(finding, 'details', {})
            sections.append((str(finding), 'Evidence: ' + json.dumps(detail.get('evidence', {}), ensure_ascii=False) +
                             '\nImpact: ' + detail.get('impact', 'Review the finding in deployment context.') +
                             '\nRecommendation: ' + detail.get('recommendation', 'Review the affected configuration.') +
                             ('\nCLI:\n' + detail['cli'] if detail.get('cli') else '\nNo exact CLI supplied; coordinate version-specific changes.')))
        write_report(p, 'FortiGate ' + domain + ' Audit', [(safe.text(h), safe.text(c)) for h, c in sections])
        print(f"[+] {domain:27} -> {p}")
    if re.search(r'^\s*config vdom\s*$', cfg_text, re.M) and not coverage_notes:
        coverage_notes.append('Legacy audit domains use the first matching block. Complete multi-VDOM coverage is unavailable; new BGP/authentication checks support explicit VDOM scopes.')

    if args.html:
        p = out_dir / f"{base}_REPORT.html"
        generate_html_report(all_findings, cfg_text, args.config, p, references, coverage_notes, statuses)
        print(f"[+] Offline HTML dashboard     -> {p}")

    if args.summary and all_findings:
        p = out("_SUMMARY.txt")
        summary = generate_summary(all_findings, args.config, p)
        print(f"[+] Executive summary          -> {p}")
        print(f"[+] Summary JSON               -> {p.with_suffix('.json')}")
        print(f"\n    Risk Rating : {summary['risk']}   Score : {summary['score']}")
        print(f"    CRITICAL: {summary['counts'][C]}  HIGH: {summary['counts'][H]}"
              f"  MEDIUM: {summary['counts'][M]}  INFO: {summary['counts'][I]}")
    elif args.summary and not all_findings:
        print("[!] --summary requested but no audit flags produced findings. Run with -f -av -s etc.")

    if not any([args.f, args.i, args.av, args.utm, args.ips, args.wf, args.app, args.dns,
                args.waf, args.email, args.video, args.file, args.vpatch, args.llm,
                args.vpn, args.sslvpn, args.ha, args.log, args.dos, args.antidos,
                args.intel, args.unused, args.vip, args.sdwan, args.iface, args.cert,
                args.fabric, args.ai, args.s, args.bgp, args.auth, args.radius, args.ldap, args.saml, args.mfa]):
        print("[!] No audit flags specified. Use --all for everything, or --help for options.")


if __name__ == "__main__":
    main()

