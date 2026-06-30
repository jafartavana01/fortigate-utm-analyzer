#!/usr/bin/env python3
"""
FortiGate UTM Security Analyzer v3.0
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
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
    """
    Handles BOTH old flat ssl-ssh-profile (6.x) and new per-protocol
    sub-block format (7.x / 8.0).  Returns enriched dicts.
    """
    lines = text.splitlines()
    profiles: List[Dict[str, Any]] = []
    in_block = False
    current: Dict[str, Any] = {}
    sub_proto: str = ""
    sub_depth = 0

    PROTOCOLS = {"https", "ftps", "imaps", "pop3s", "smtps", "ssh",
                 "dot", "quic", "ftp", "imap", "pop3", "smtp"}

    for raw in lines:
        line = raw.strip()

        if line == "config firewall ssl-ssh-profile":
            in_block = True
            current = {}
            sub_proto = ""
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
            sub_proto = ""
            sub_depth = 0
            continue

        if line == "next":
            if current:
                profiles.append(current)
            current = {}
            sub_proto = ""
            sub_depth = 0
            continue

        if line.startswith("config ") and sub_depth == 0:
            proto_candidate = line[7:].strip()
            if proto_candidate in PROTOCOLS:
                sub_proto = proto_candidate
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
                    sub_proto = ""
            elif line == "next":
                sub_proto = ""
                sub_depth = max(0, sub_depth - 1)
            elif line.startswith("set ") and sub_proto:
                k, v = parse_set_line(line)
                if k:
                    current[f"{sub_proto}.{k}"] = v
            continue

        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                current[k] = v

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

    if not two_factor or two_factor in ("disable", "none"):
        findings.append(f(H, f"Admin '{name}': two-factor authentication not enabled."))

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
    weak_kex   = ("diffie-hellman-group1", "diffie-hellman-group14")

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
            if w in kex.lower():
                findings.append(f(H, f"SSH: weak key-exchange '{w}' — insecure DH group."))
    if not enc_algos and not mac_algos:
        findings.append(f(I, "SSH: cipher/MAC restrictions not configured — system defaults may include weak algorithms."))

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

def main():
    parser = argparse.ArgumentParser(
        description="FortiGate UTM Security Analyzer v3.0 — FortiOS 6.x/7.x/8.0 deep config audit.",
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
    parser.add_argument("-dos",    action="store_true", help="DoS policy audit")
    parser.add_argument("-s",      action="store_true", help="System hardening (admin, interface, global, SNMP, SSH, NTP, DNS, CSF, FIPS, IKE, local-in)")
    parser.add_argument("--summary", action="store_true", help="Executive summary + JSON export")
    parser.add_argument("--all",   action="store_true", help="Run all audit modules")

    args = parser.parse_args()

    if args.all:
        for attr in ["f","i","av","ips","wf","app","dns","waf","email","video","file",
                     "vpatch","llm","utm","vpn","sslvpn","ha","log","dos","s","summary"]:
            setattr(args, attr, True)

    cfg_text = read_config(args.config)
    base = Path(args.config).name
    out = lambda suffix: Path(f"{base}{suffix}")

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
    dos_policies   = parse_dos_policy(cfg_text)

    print(f"[*] Parsed: {len(policies)} IPv4 policies, {len(policies6)} IPv6 policies, "
          f"{len(ssl_profiles)} SSL profiles, {len(av_profiles)} AV profiles, "
          f"{len(phase1)} VPN tunnels, {len(admins)} admins, {len(interfaces)} interfaces")

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
                args.vpn, args.sslvpn, args.ha, args.log, args.dos, args.s]):
        print("[!] No audit flags specified. Use --all for everything, or --help for options.")


if __name__ == "__main__":
    main()
