#!/usr/bin/env python3
"""
FortiGate UTM Security Analyzer v2.0
Author : Jafar Tavana (@jafartavana01)
License: MIT

Parses a FortiGate 'show full-configuration' backup and produces
severity-tagged security reports across:
  - Firewall policies            (-f)
  - SSL/SSH inspection profiles  (-i)
  - AntiVirus profiles           (-av)
  - IPS sensor profiles          (-ips)
  - Web filter profiles          (-wf)
  - Application control profiles (-app)
  - DNS filter profiles          (-dns)
  - VPN IPsec Phase1/Phase2      (-vpn)
  - SSL-VPN settings             (-sslvpn)
  - HA configuration             (-ha)
  - Log / FortiAnalyzer settings (-log)
  - System hardening             (-s)
  - UTM topology diagrams        (-d)
  - Full executive summary       (--summary)
"""

import argparse
import json
from pathlib import Path
import re
from typing import List, Dict, Any, Tuple


# ─────────────────────────────────────────────
# Generic helpers
# ─────────────────────────────────────────────

def read_config(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def normalize_value(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


def parse_set_line(line: str) -> Tuple[str, str]:
    line = line.strip()
    m = re.match(r"set\s+(\S+)\s+(.+)", line)
    if not m:
        return None, None
    return m.group(1), m.group(2).strip()


def extract_block(text: str, block_name: str) -> List[Dict[str, Any]]:
    """Generic parser for 'config <block_name> ... edit ... set ... next ... end'"""
    lines = text.splitlines()
    objects, in_block, current = [], False, None

    for raw in lines:
        line = raw.strip()
        if line == f"config {block_name}":
            in_block, current = True, None
            continue
        if in_block and line == "end":
            if current:
                objects.append(current)
            break
        if not in_block:
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
    in_block, cfg = False, {}
    for raw in lines:
        line = raw.strip()
        if line == f"config {block_name}":
            in_block, cfg = True, {}
            continue
        if in_block and line == "end":
            break
        if not in_block:
            continue
        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                cfg[k] = v
    return cfg


# ─────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────

def parse_firewall_policies(text):   return extract_block(text, "firewall policy")
def parse_ssl_profiles(text):        return extract_block(text, "firewall ssl-ssh-profile")
def parse_av_profiles(text):         return extract_block(text, "antivirus profile")
def parse_ips_sensors(text):         return extract_block(text, "ips sensor")
def parse_wf_profiles(text):         return extract_block(text, "webfilter profile")
def parse_app_profiles(text):        return extract_block(text, "application list")
def parse_dns_profiles(text):        return extract_block(text, "dnsfilter profile")
def parse_admins(text):              return extract_block(text, "system admin")
def parse_interfaces(text):          return extract_block(text, "system interface")
def parse_local_in(text):            return extract_block(text, "firewall local-in-policy")
def parse_vpn_phase1(text):          return extract_block(text, "vpn ipsec phase1-interface")
def parse_vpn_phase2(text):          return extract_block(text, "vpn ipsec phase2-interface")
def parse_address_objects(text):     return extract_block(text, "firewall address")
def parse_service_objects(text):     return extract_block(text, "firewall service custom")
def parse_users(text):               return extract_block(text, "user local")
def parse_radius(text):              return extract_block(text, "user radius")
def parse_ha(text):                  return extract_flat_block(text, "system ha")
def parse_system_global(text):       return extract_flat_block(text, "system global")
def parse_log_fortianalyzer(text):   return extract_flat_block(text, "log fortianalyzer setting")
def parse_log_syslogd(text):         return extract_flat_block(text, "log syslogd setting")
def parse_log_setting(text):         return extract_flat_block(text, "log setting")
def parse_ssl_vpn_settings(text):    return extract_flat_block(text, "vpn ssl settings")
def parse_ssl_vpn_web_portals(text): return extract_block(text, "vpn ssl web portal")


def parse_ntp(text: str) -> Dict[str, Any]:
    lines = text.splitlines()
    in_block, ntp, ntpservers, current_server = False, {}, [], None
    for raw in lines:
        line = raw.strip()
        if line == "config system ntp":
            in_block, ntp, ntpservers, current_server = True, {}, [], None
            continue
        if in_block and line == "end":
            break
        if not in_block:
            continue
        if line.startswith("config ntpserver"):
            current_server = None
            continue
        if line.startswith("edit "):
            current_server = {"_id": line.split(None, 1)[1].strip().strip('"')}
            ntpservers.append(current_server)
            continue
        if line == "next":
            current_server = None
            continue
        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                (current_server if current_server is not None else ntp)[k] = v
    ntp["servers"] = ntpservers
    return ntp


# ─────────────────────────────────────────────
# Finding helper
# ─────────────────────────────────────────────

def finding(severity: str, msg: str) -> str:
    return f"{severity}: {msg}"

H = "HIGH"
M = "MEDIUM"
I = "INFO"
C = "CRITICAL"


# ─────────────────────────────────────────────
# Weakness checks
# ─────────────────────────────────────────────

def firewall_weaknesses(policy: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    action    = nv(policy.get("action", ""))
    utm       = nv(policy.get("utm-status", ""))
    ips       = nv(policy.get("ips-sensor", ""))
    av        = nv(policy.get("av-profile", ""))
    wf        = nv(policy.get("webfilter-profile", ""))
    dnsf      = nv(policy.get("dnsfilter-profile", ""))
    app       = nv(policy.get("application-list", ""))
    ssl       = nv(policy.get("ssl-ssh-profile", ""))
    log       = nv(policy.get("logtraffic", ""))
    nat       = nv(policy.get("nat", ""))
    srcaddr   = nv(policy.get("srcaddr", ""))
    dstaddr   = nv(policy.get("dstaddr", ""))
    service   = nv(policy.get("service", ""))
    srcintf   = nv(policy.get("srcintf", ""))
    dstintf   = nv(policy.get("dstintf", ""))
    comments  = nv(policy.get("comments", ""))
    status    = nv(policy.get("status", "enable"))
    logstart  = nv(policy.get("logtraffic-start", ""))
    capture   = nv(policy.get("capture-packet", ""))
    casb      = nv(policy.get("casb-profile", ""))
    dlp       = nv(policy.get("dlp-profile", "")) or nv(policy.get("dlp-sensor", ""))
    emailf    = nv(policy.get("emailfilter-profile", ""))
    voip      = nv(policy.get("voip-profile", ""))

    if action == "accept":
        if utm != "enable":
            f.append(finding(H, "UTM disabled on accept policy — all security profiles bypassed."))
        if not ips:
            f.append(finding(H, "No IPS sensor attached; exploit traffic passes uninspected."))
        if not av:
            f.append(finding(H, "No antivirus profile — malware traversal undetected."))
        if not ssl:
            f.append(finding(H, "No SSL/SSH inspection profile — encrypted threats bypass inspection."))
        if not wf:
            f.append(finding(M, "No web filter profile — malicious URLs uncategorized."))
        if not dnsf:
            f.append(finding(M, "No DNS filter — DNS-based C2, tunnelling, malware domains unblocked."))
        if not app:
            f.append(finding(M, "No application control — risky/unwanted apps may run freely."))
        if not dlp:
            f.append(finding(I, "No DLP profile — data exfiltration risk unaddressed."))
        if not casb:
            f.append(finding(I, "No CASB profile — unsanctioned cloud service usage not monitored."))

        # Any-any-any detection
        if srcaddr in ("all", "") and dstaddr in ("all", "") and service in ("ALL", "all", ""):
            f.append(finding(C, "ANY-ANY-ANY accept policy — maximally permissive rule; full audit required."))
        elif srcaddr in ("all", "") and dstaddr in ("all", ""):
            f.append(finding(H, "Source and destination both 'all' — extremely broad policy scope."))
        elif srcaddr in ("all", ""):
            f.append(finding(M, "Source address is 'all' — consider restricting to known subnets."))

        # WAN-to-LAN inbound detection
        if dstintf and srcintf:
            src_lower = srcintf.lower()
            dst_lower = dstintf.lower()
            wan_hints = ("wan", "ppp", "vdsl", "adsl", "ftth", "internet", "outside", "untrust")
            lan_hints = ("lan", "port", "internal", "inside", "dmz", "trust")
            if any(w in src_lower for w in wan_hints) and any(l in dst_lower for l in lan_hints):
                f.append(finding(H, "Inbound WAN-to-LAN accept policy — verify this is intentional."))

        # Service ALL
        if service in ("ALL", "all"):
            f.append(finding(M, "Service set to ALL — restrict to required protocols only."))

        # No schedule restriction
        schedule = normalize_value(policy.get("schedule", "always"))
        if schedule == "always":
            f.append(finding(I, "Policy active 24/7 with no schedule restriction."))

    elif action == "":
        f.append(finding(M, "Policy action not explicitly set; default behavior may be unexpected."))

    # Logging
    if log in ("", "disable"):
        f.append(finding(H, "Traffic logging disabled — no visibility into flows matched by this policy."))
    elif log == "utm":
        f.append(finding(I, "Logging UTM events only; consider 'all' for full flow visibility."))
    if logstart != "enable":
        f.append(finding(I, "Log-traffic-start disabled — session start events not captured."))

    # No comments / documentation
    if not comments:
        f.append(finding(I, "Policy has no comments/description — undocumented rules are an audit risk."))

    # Disabled policy
    if status == "disable":
        f.append(finding(I, "Policy is disabled — verify if still needed or remove to reduce attack surface."))

    # Packet capture on production policy (debug artifact)
    if capture == "enable":
        f.append(finding(M, "Packet capture enabled on this policy — likely a debug artifact; disable in production."))

    # NAT
    if nat != "enable" and action == "accept":
        f.append(finding(I, "NAT disabled — verify routing is correct and internal IPs are not exposed."))

    return f


def ssl_weaknesses(profile: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    mode        = nv(profile.get("inspection-method", ""))
    caname      = nv(profile.get("caname", ""))
    inspect_all = nv(profile.get("inspect-all-ports", ""))
    sni         = nv(profile.get("sni-check", ""))
    untrusted   = nv(profile.get("untrusted-cert", ""))
    expired     = nv(profile.get("expired-cert", ""))
    invalid     = nv(profile.get("invalid-cert", ""))
    revoked     = nv(profile.get("revoked-server-cert", ""))
    log_anom    = nv(profile.get("log-ssl-anomalies", ""))
    ech         = nv(profile.get("encrypted-client-hello", ""))
    dot         = nv(profile.get("dot", "")) or nv(profile.get("dns-over-tls", ""))
    rpc_https   = nv(profile.get("rpc-over-https", ""))
    mapi_https  = nv(profile.get("mapi-over-https", ""))
    min_ver     = nv(profile.get("min-allowed-ssl-version", ""))
    block_bl    = nv(profile.get("block-blacklisted-certificates", ""))
    exempt      = nv(profile.get("exempt-from-ssl-inspection", ""))
    ssl_anomaly_log = nv(profile.get("ssl-anomalies-log", ""))

    # Inspection mode
    if not mode:
        f.append(finding(M, "Inspection mode not set — profile may not function as expected."))
    elif mode == "certificate-inspection":
        f.append(finding(M, "Certificate-only inspection — TLS payload not decrypted; threats in HTTPS tunnel undetected."))
    elif mode in ("full-inspection", "deep-inspection"):
        if not caname:
            f.append(finding(H, "Deep/full inspection without CA cert defined — clients will receive untrusted cert errors."))

    # Certificate validation
    if untrusted != "block":
        f.append(finding(H, "Untrusted server certificates not blocked — MITM risk."))
    if invalid != "block":
        f.append(finding(H, "Invalid certificates not blocked — connections to misconfigured/malicious servers allowed."))
    if expired != "block":
        f.append(finding(M, "Expired certificates not blocked — endpoint may communicate with stale/compromised servers."))
    if revoked not in ("block", ""):
        pass  # only flag if explicitly set to allow
    if revoked == "allow":
        f.append(finding(H, "Revoked certificate action set to allow — connections with revoked certs permitted."))
    if block_bl != "enable":
        f.append(finding(M, "Blacklisted certificate blocking disabled — known bad certs may pass."))

    # TLS version
    tls_map = {"ssl-3.0": 0, "tls-1.0": 1, "tls-1.1": 2, "tls-1.2": 3, "tls-1.3": 4}
    if min_ver and min_ver in tls_map:
        if tls_map[min_ver] < 3:
            f.append(finding(H, f"Minimum TLS version is {min_ver} — TLS 1.2 is the bare minimum; TLS 1.3 preferred."))
        elif min_ver == "tls-1.2":
            f.append(finding(I, "Minimum TLS 1.2 — consider enforcing TLS 1.3 where clients support it."))
    elif not min_ver:
        f.append(finding(M, "Minimum TLS version not explicitly configured — legacy protocol downgrade possible."))

    # Encrypted Client Hello (ECH) — hides SNI from inspection
    if ech in ("", "disable"):
        f.append(finding(M, "Encrypted Client Hello (ECH) not handled — SNI may be hidden from inspection."))

    # DNS over TLS
    if dot not in ("block", "inspect"):
        f.append(finding(M, "DNS over TLS not blocked or inspected — DNS filtering may be bypassed via DoT."))

    # SNI check
    if sni in ("", "disable"):
        f.append(finding(M, "SNI checking disabled — weaker certificate/domain validation."))

    # Logging
    if log_anom != "enable" and ssl_anomaly_log != "enable":
        f.append(finding(M, "SSL anomaly logging disabled — TLS errors and anomalies go unreported."))

    # Inspect all ports
    if inspect_all == "enable":
        f.append(finding(I, "Inspect-all-ports enabled — verify performance impact and false-positive rate."))

    # RPC / MAPI over HTTPS (common C2 tunnelling vectors)
    if rpc_https != "block":
        f.append(finding(I, "RPC over HTTPS not blocked — potential lateral movement tunnelling vector."))
    if mapi_https != "block":
        f.append(finding(I, "MAPI over HTTPS not blocked — Exchange traffic may bypass inspection."))

    return f


def av_weaknesses(profile: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    feature_set = nv(profile.get("feature-set", ""))
    scan_mode   = nv(profile.get("scan-mode", ""))
    action      = nv(profile.get("default-action", "")) or scan_mode
    http        = nv(profile.get("http", ""))
    https       = nv(profile.get("https", ""))
    smtp        = nv(profile.get("smtp", ""))
    pop3        = nv(profile.get("pop3", ""))
    imap        = nv(profile.get("imap", ""))
    ftp         = nv(profile.get("ftp", ""))
    cifs        = nv(profile.get("cifs", ""))
    nntp        = nv(profile.get("nntp", ""))
    sandbox     = nv(profile.get("fortisandbox", ""))
    outbreak    = nv(profile.get("outbreak-prevention", ""))
    log_v       = nv(profile.get("log", "")) or nv(profile.get("log-malware", ""))
    quarantine  = nv(profile.get("quarantine", ""))
    content_dis = nv(profile.get("content-disarm", ""))
    emulator    = nv(profile.get("analytics-bl-filetype", ""))

    if feature_set == "flow":
        f.append(finding(I, "Flow-based AV — faster but less thorough; proxy mode recommended where latency allows."))

    if action and action.lower() in ("pass", "monitor"):
        f.append(finding(H, f"Malware action is '{action}' — infected files delivered to users."))

    # Protocol coverage
    for proto, val, sev in [
        ("HTTP",     http,  M), ("HTTPS",    https, M),
        ("SMTP",     smtp,  M), ("POP3",     pop3,  I),
        ("IMAP",     imap,  I), ("FTP",      ftp,   I),
        ("CIFS/SMB", cifs,  M), ("NNTP",     nntp,  I),
    ]:
        if val != "enable":
            f.append(finding(sev, f"{proto} not inspected by AV profile."))

    if sandbox != "enable":
        f.append(finding(M, "FortiSandbox submission disabled — zero-day and unknown malware may pass."))
    if outbreak != "enable":
        f.append(finding(M, "Outbreak prevention disabled — reactive protection to new campaigns reduced."))
    if quarantine != "enable":
        f.append(finding(M, "Malware quarantine disabled — infected files not isolated for forensic review."))
    if content_dis not in ("enable", ""):
        pass  # only flag explicit disable
    if content_dis == "disable":
        f.append(finding(M, "Content disarm & reconstruction (CDR) disabled — weaponized Office/PDF not sanitized."))
    if log_v not in ("enable", "all", "malware"):
        f.append(finding(M, "AV logging not clearly enabled — malware detections may go unrecorded."))

    return f


def ips_weaknesses(sensor: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name    = nv(sensor.get("name", sensor.get("_id", "")))
    block   = nv(sensor.get("block-malicious-url", ""))
    scan_bo = nv(sensor.get("scan-botnet-connections", ""))
    ext_db  = nv(sensor.get("extended-db", ""))

    if block != "enable":
        f.append(finding(M, f"IPS '{name}': block-malicious-url not enabled — known malicious URLs not blocked."))
    if scan_bo not in ("block", "monitor"):
        f.append(finding(H, f"IPS '{name}': botnet C2 connection scanning disabled — infected hosts communicate freely."))
    elif scan_bo == "monitor":
        f.append(finding(M, f"IPS '{name}': botnet C2 scanning in monitor mode — connections logged but not blocked."))
    if ext_db != "enable":
        f.append(finding(I, f"IPS '{name}': extended signature database not enabled — reduced coverage for new CVEs."))

    return f


def wf_weaknesses(profile: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name        = nv(profile.get("name", profile.get("_id", "")))
    log_all     = nv(profile.get("log-all-url", ""))
    safe_search = nv(profile.get("safe-search", ""))
    youtube_edu = nv(profile.get("youtube-restrict", ""))
    https_rep   = nv(profile.get("https-replacemsg", ""))
    web_content = nv(profile.get("web-content-log", ""))
    override    = nv(profile.get("override", ""))

    if safe_search not in ("enable", "url"):
        f.append(finding(I, f"Web filter '{name}': safe search not enforced — explicit search results possible."))
    if log_all != "enable":
        f.append(finding(M, f"Web filter '{name}': log-all-url disabled — browsing activity not fully logged."))
    if web_content != "enable":
        f.append(finding(I, f"Web filter '{name}': web-content-log disabled — limited forensic trail."))
    if override == "enable":
        f.append(finding(M, f"Web filter '{name}': user override permitted — blocked categories can be bypassed by end users."))

    return f


def app_weaknesses(profile: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name    = nv(profile.get("name", profile.get("_id", "")))
    log     = nv(profile.get("log", ""))
    unknown = nv(profile.get("unknown-application-action", ""))
    p2p     = nv(profile.get("p2p-block-list", ""))

    if log != "enable":
        f.append(finding(M, f"App control '{name}': logging disabled — application usage not tracked."))
    if unknown not in ("block", ""):
        pass
    if unknown == "pass":
        f.append(finding(M, f"App control '{name}': unknown applications permitted — unclassified traffic flows freely."))
    if not p2p or p2p not in ("enable", "skype", "bittorrent"):
        f.append(finding(I, f"App control '{name}': P2P block list not explicitly configured."))

    return f


def dns_weaknesses(profile: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name      = nv(profile.get("name", profile.get("_id", "")))
    botnet    = nv(profile.get("block-botnet", ""))
    log       = nv(profile.get("log-all-domain", ""))
    safe_s    = nv(profile.get("safe-search", ""))
    ftgd_dns  = nv(profile.get("ftgd-dns", ""))

    if botnet != "enable":
        f.append(finding(H, f"DNS filter '{name}': botnet domain blocking disabled — DNS-based C2 traffic unblocked."))
    if log != "enable":
        f.append(finding(M, f"DNS filter '{name}': log-all-domain disabled — DNS query log incomplete."))
    if safe_s != "enable":
        f.append(finding(I, f"DNS filter '{name}': safe search DNS enforcement not enabled."))
    if ftgd_dns != "enable":
        f.append(finding(M, f"DNS filter '{name}': FortiGuard DNS rating not enabled — category-based DNS filtering inactive."))

    return f


def admin_weaknesses(admin: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name       = nv(admin.get("name", admin.get("_id", "")))
    accprofile = nv(admin.get("accprofile", ""))
    two_factor = nv(admin.get("two-factor", "")) or nv(admin.get("twofactor", ""))
    trusthosts = [nv(admin.get(f"trusthost{i}", "")) for i in range(1, 11)]
    timeout    = nv(admin.get("admintimeout", ""))
    password   = nv(admin.get("password", ""))
    force_pw   = nv(admin.get("force-password-change", ""))
    ssh_key    = nv(admin.get("ssh-public-key1", ""))
    wildcard   = nv(admin.get("wildcard", ""))
    remote_auth= nv(admin.get("remote-auth", ""))
    scope      = nv(admin.get("scope", ""))

    # Trusted hosts
    valid_hosts = [th for th in trusthosts if th and th not in ("0.0.0.0 0.0.0.0", "")]
    if not valid_hosts:
        f.append(finding(H, f"Admin '{name}': no trusted host restrictions — login from any IP address allowed."))
    else:
        for th in valid_hosts:
            if th in ("0.0.0.0 0.0.0.0", "0.0.0.0/0"):
                f.append(finding(H, f"Admin '{name}': trusthost set to 0.0.0.0/0 — effectively unrestricted."))

    # Access profile
    if accprofile == "super_admin":
        f.append(finding(H, f"Admin '{name}': super_admin profile — no least-privilege separation."))
    if not accprofile:
        f.append(finding(M, f"Admin '{name}': no access profile set."))

    # MFA
    if not two_factor or two_factor in ("disable", "none"):
        f.append(finding(H, f"Admin '{name}': two-factor authentication not enabled."))

    # Session timeout
    if timeout and timeout.isdigit():
        t = int(timeout)
        if t == 0:
            f.append(finding(H, f"Admin '{name}': session timeout is 0 (never expires) — sessions persist indefinitely."))
        elif t > 60:
            f.append(finding(M, f"Admin '{name}': session timeout is {t} min — reduce to 15-30 min."))
        elif t > 30:
            f.append(finding(I, f"Admin '{name}': session timeout is {t} min — consider tightening to 15 min."))

    # Password fields
    if password and password.lower() in ("admin", "password", "fortinet", "fortigate", "1234", "123456", ""):
        f.append(finding(C, f"Admin '{name}': weak or default password detected."))

    # Force password change
    if force_pw != "enable":
        f.append(finding(I, f"Admin '{name}': force-password-change not set — no mandatory rotation policy enforced."))

    # Wildcard admin (LDAP group-based — verify scope is appropriate)
    if wildcard == "enable":
        f.append(finding(I, f"Admin '{name}': wildcard account — maps to an external directory group; verify group scope."))

    return f


def interface_weaknesses(intf: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name        = nv(intf.get("name", intf.get("_id", "")))
    allowaccess = nv(intf.get("allowaccess", ""))
    role        = nv(intf.get("role", ""))
    ip          = nv(intf.get("ip", ""))
    intf_type   = nv(intf.get("type", ""))
    dhcp_relay  = nv(intf.get("dhcp-relay-service", ""))
    proxy_arp   = nv(intf.get("proxy-arp", ""))
    speed       = nv(intf.get("speed", ""))
    detectprot  = nv(intf.get("detectprotocol", ""))

    aa = allowaccess.split()

    # Insecure protocols — any interface
    if "http" in aa:
        f.append(finding(H, f"Interface '{name}': HTTP management enabled — credentials transmitted in cleartext."))
    if "telnet" in aa:
        f.append(finding(H, f"Interface '{name}': Telnet enabled — fully unencrypted management access."))
    if "fnbam" in aa:
        f.append(finding(I, f"Interface '{name}': FNBAM (FortiAuthenticator) access enabled — verify intentional."))

    # WAN-role specific
    if role == "wan":
        if "https" in aa:
            f.append(finding(H, f"Interface '{name}' (WAN): HTTPS management exposed to internet — lock down with trusted hosts."))
        if "ssh" in aa:
            f.append(finding(H, f"Interface '{name}' (WAN): SSH management exposed to internet — brute-force risk."))
        if "ping" in aa:
            f.append(finding(M, f"Interface '{name}' (WAN): ping/ICMP enabled — device fingerprinting risk."))
        if "snmp" in aa:
            f.append(finding(H, f"Interface '{name}' (WAN): SNMP accessible from internet — community string exposure risk."))
        if "fabric" in aa:
            f.append(finding(H, f"Interface '{name}' (WAN): Security Fabric access on WAN — Fabric protocol should not face internet."))

    # No access configured (may be intentional for transit/loopback)
    if not allowaccess and intf_type not in ("loopback", "tunnel", "vdom-link"):
        f.append(finding(I, f"Interface '{name}': no management access configured (may be correct for transit interfaces)."))

    # Proxy ARP
    if proxy_arp == "enable":
        f.append(finding(I, f"Interface '{name}': proxy ARP enabled — may cause unexpected traffic interception."))

    return f


def global_crypto_weaknesses(cfg: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    strong_crypto  = nv(cfg.get("strong-crypto", ""))
    static_ciphers = nv(cfg.get("ssl-static-key-ciphers", ""))
    dh_params      = nv(cfg.get("dh-params", ""))
    lock_thr       = nv(cfg.get("admin-lockout-threshold", ""))
    lock_dur       = nv(cfg.get("admin-lockout-duration", ""))
    admintimeout   = nv(cfg.get("admintimeout", ""))
    hostname       = nv(cfg.get("hostname", ""))
    timezone       = nv(cfg.get("timezone", ""))
    revision_image = nv(cfg.get("revision-image-auto-backup", ""))
    gui_cert       = nv(cfg.get("admin-server-cert", ""))
    https_redir    = nv(cfg.get("admin-https-redirect", ""))
    snmp_index     = nv(cfg.get("snmp-sysinfo-visible", ""))
    pre_login      = nv(cfg.get("pre-login-banner", ""))
    post_login     = nv(cfg.get("post-login-banner", ""))
    pw_policy      = nv(cfg.get("admin-password-policy", ""))
    pw_min_len     = nv(cfg.get("password-policy-min-length", ""))
    fds_stat       = nv(cfg.get("fds-statistics", ""))
    ipv6_allow     = nv(cfg.get("admin-https-pki-required", ""))
    fortitoken     = nv(cfg.get("fortitoken-cloud", ""))
    language       = nv(cfg.get("language", ""))
    vdom_mode      = nv(cfg.get("vdom-mode", ""))

    if strong_crypto != "enable":
        f.append(finding(H, "strong-crypto disabled — weak ciphers (RC4, DES, MD5) may be negotiated for management TLS."))
    if static_ciphers != "disable":
        f.append(finding(M, "ssl-static-key-ciphers not disabled — forward secrecy not enforced on management TLS."))

    try:
        dh_val = int(dh_params)
        if dh_val < 2048:
            f.append(finding(C, f"DH params {dh_val} bits — critically weak; upgrade to 4096 minimum, 8192 preferred."))
        elif dh_val < 4096:
            f.append(finding(H, f"DH params {dh_val} bits — below 4096 bit recommendation."))
        elif dh_val < 8192:
            f.append(finding(M, f"DH params {dh_val} bits — 8192 bits recommended for strongest forward secrecy."))
    except (ValueError, TypeError):
        if dh_params:
            f.append(finding(I, f"DH params value '{dh_params}' could not be parsed as integer."))
        else:
            f.append(finding(M, "DH params not configured — system default DH group in use."))

    # Admin lockout
    try:
        thr = int(lock_thr)
        if thr == 0:
            f.append(finding(H, "Admin lockout threshold is 0 — brute-force lockout disabled."))
        elif thr > 5:
            f.append(finding(M, f"Admin lockout threshold is {thr} — consider 3–5 attempts maximum."))
    except (ValueError, TypeError):
        f.append(finding(M, "Admin lockout threshold not configured."))

    try:
        dur = int(lock_dur)
        if dur == 0:
            f.append(finding(H, "Admin lockout duration is 0 — account unlocks immediately."))
        elif dur < 60:
            f.append(finding(M, f"Admin lockout duration is {dur}s — consider 300s (5 min) minimum."))
    except (ValueError, TypeError):
        f.append(finding(M, "Admin lockout duration not configured."))

    # Global admin timeout
    try:
        t = int(admintimeout)
        if t == 0:
            f.append(finding(H, "Global admin session timeout is 0 — sessions never expire."))
        elif t > 60:
            f.append(finding(M, f"Global admin timeout {t} min — reduce to 15–30 min."))
    except (ValueError, TypeError):
        pass

    # Pre/post login banners (legal/compliance)
    if pre_login != "enable":
        f.append(finding(I, "Pre-login banner disabled — no legal warning before authentication (compliance gap)."))
    if post_login != "enable":
        f.append(finding(I, "Post-login banner disabled — no acceptable-use notice displayed after login."))

    # HTTPS redirect
    if https_redir != "enable":
        f.append(finding(M, "admin-https-redirect not enabled — HTTP management requests not automatically redirected to HTTPS."))

    # Custom GUI certificate (self-signed by default)
    if not gui_cert or gui_cert in ("self-sign", ""):
        f.append(finding(I, "Management GUI using self-signed certificate — consider deploying a trusted CA certificate."))

    # Hostname (default 'FortiGate' exposes model)
    if hostname.lower() in ("fortigate", "fortiwifi", ""):
        f.append(finding(I, f"Hostname is default ('{hostname}') — change to your naming convention to avoid fingerprinting."))

    # Revision backup
    if revision_image != "enable":
        f.append(finding(I, "Revision image auto-backup disabled — config versioning not maintained automatically."))

    # Password policy
    if pw_policy != "enable":
        f.append(finding(M, "Admin password policy not enabled — no minimum complexity requirements enforced."))
    else:
        try:
            if int(pw_min_len) < 12:
                f.append(finding(M, f"Password minimum length is {pw_min_len} — 12+ characters recommended."))
        except (ValueError, TypeError):
            pass

    return f


def ntp_weaknesses(ntp: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    ntpsync  = nv(ntp.get("ntpsync", ""))
    ntptype  = nv(ntp.get("type", ""))
    interval = nv(ntp.get("syncinterval", ""))
    src_ip   = nv(ntp.get("source-ip", ""))
    srv_mode = nv(ntp.get("server-mode", ""))
    auth     = nv(ntp.get("authentication", ""))
    ntpv3    = nv(ntp.get("ntpv3", ""))
    servers  = ntp.get("servers", []) or []

    if ntpsync != "enable":
        f.append(finding(H, "NTP sync disabled — log timestamps unreliable; forensic correlation compromised."))
    if ntptype == "custom":
        if not servers:
            f.append(finding(M, "Custom NTP with no servers defined — sync will fail."))
        elif len(servers) == 1:
            f.append(finding(I, "Single NTP server — no redundancy; time drift on server failure."))
    if ntptype not in ("fortiguard", "custom", ""):
        f.append(finding(I, f"NTP type '{ntptype}' — verify this is the intended sync method."))
    if srv_mode == "enable":
        f.append(finding(I, "FortiGate acting as NTP server — verify this is intentional and documented."))
    if auth != "enable":
        f.append(finding(M, "NTP authentication disabled — NTP spoofing/tampering possible (RFC 8633 recommends auth)."))
    else:
        if ntpv3 != "enable":
            f.append(finding(M, "NTP authentication enabled but NTPv3 not explicitly enabled — verify HMAC-MD5 key is configured."))
    if not src_ip:
        f.append(finding(I, "NTP source-ip not configured — NTP packets sourced from outgoing interface IP."))
    try:
        iv = int(interval)
        if iv < 10:
            f.append(finding(I, f"NTP sync interval {iv} min — very frequent; standard is 60 min."))
        elif iv > 1440:
            f.append(finding(M, f"NTP sync interval {iv} min — too infrequent; clock drift may exceed acceptable thresholds."))
    except (ValueError, TypeError):
        pass

    return f


def local_in_weaknesses(lip: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    intf    = nv(lip.get("intf", ""))
    srcaddr = nv(lip.get("srcaddr", ""))
    service = nv(lip.get("service", ""))
    action  = nv(lip.get("action", ""))
    sched   = nv(lip.get("schedule", ""))

    if not intf:
        f.append(finding(M, "Local-in policy without specific interface binding — applies to all interfaces."))
    if srcaddr in ("all", ""):
        f.append(finding(H, "Local-in policy source is 'all' — any external host can reach FortiGate management services."))
    if service in ("ALL", "all"):
        f.append(finding(M, "Service is ALL — restrict to only required management protocols."))
    if action == "accept" and srcaddr in ("all", ""):
        f.append(finding(C, "ACCEPT local-in-policy from 'all' sources — FortiGate control plane is broadly exposed."))

    return f


def vpn_phase1_weaknesses(phase1: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name       = nv(phase1.get("name", phase1.get("_id", "")))
    authmethod = nv(phase1.get("authmethod", ""))
    proposal   = nv(phase1.get("proposal", ""))
    dh_grp     = nv(phase1.get("dhgrp", ""))
    ike_ver    = nv(phase1.get("ike-version", ""))
    psk        = nv(phase1.get("psksecret", ""))
    mode       = nv(phase1.get("mode", ""))
    nattravers = nv(phase1.get("nattraversal", ""))
    keepalive  = nv(phase1.get("keepalive", ""))
    localid    = nv(phase1.get("localid", ""))
    dpd        = nv(phase1.get("dpd", ""))
    rekey      = nv(phase1.get("rekey", ""))
    lifetime   = nv(phase1.get("keylifetime", ""))

    # IKE version
    if ike_ver == "1":
        f.append(finding(M, f"VPN '{name}': IKEv1 in use — IKEv2 is recommended (RFC 7296); IKEv1 main mode + aggressive mode has known weaknesses."))
    elif not ike_ver:
        f.append(finding(I, f"VPN '{name}': IKE version not explicitly set — may default to IKEv1."))

    # IKEv1 aggressive mode
    if ike_ver == "1" and mode == "aggressive":
        f.append(finding(H, f"VPN '{name}': IKEv1 aggressive mode — PSK hash exposed in cleartext; offline cracking possible."))

    # Proposal — flag weak ciphers
    weak_enc = ["des", "3des", "md5", "sha1"]
    if proposal:
        proposal_lower = proposal.lower()
        for w in weak_enc:
            if w in proposal_lower:
                f.append(finding(H, f"VPN '{name}': weak algorithm '{w.upper()}' in IKE proposal — use AES256+SHA256 or better."))

    # DH groups — flag groups below 14 (2048-bit)
    weak_dh = {"1", "2", "5"}
    if dh_grp:
        for grp in dh_grp.split():
            if grp in weak_dh:
                f.append(finding(H, f"VPN '{name}': DH group {grp} is below 2048-bit — upgrade to group 14 (2048), 19 (256-bit EC), or 20 (384-bit EC)."))

    # Authentication method
    if authmethod == "psk":
        f.append(finding(M, f"VPN '{name}': pre-shared key authentication — certificate-based auth (PKI) is stronger."))
        if psk and len(psk) < 20:
            f.append(finding(H, f"VPN '{name}': PSK appears short (< 20 chars) — use 32+ random characters."))

    # DPD
    if dpd in ("", "disable"):
        f.append(finding(I, f"VPN '{name}': Dead Peer Detection (DPD) disabled — stale tunnels not detected."))

    # Rekey
    if rekey == "disable":
        f.append(finding(M, f"VPN '{name}': rekey disabled — long-lived session keys reduce forward secrecy."))

    # Key lifetime
    try:
        lt = int(lifetime)
        if lt > 86400:
            f.append(finding(M, f"VPN '{name}': IKE key lifetime {lt}s exceeds 24h — consider 28800s (8h) or less."))
    except (ValueError, TypeError):
        pass

    return f


def vpn_phase2_weaknesses(phase2: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name      = nv(phase2.get("name", phase2.get("_id", "")))
    proposal  = nv(phase2.get("proposal", ""))
    pfs_grp   = nv(phase2.get("pfs", ""))
    lifetime  = nv(phase2.get("keylifetime-seconds", "")) or nv(phase2.get("keylifeseconds", ""))
    dhgrp     = nv(phase2.get("dhgrp", ""))

    # Weak algorithms
    weak_enc = ["des", "3des", "md5", "sha1", "null"]
    if proposal:
        for w in weak_enc:
            if w in proposal.lower():
                f.append(finding(H, f"Phase2 '{name}': weak algorithm '{w.upper()}' in ESP proposal."))

    # PFS
    if pfs_grp in ("", "disable"):
        f.append(finding(H, f"Phase2 '{name}': Perfect Forward Secrecy (PFS) disabled — session key compromise exposes all past traffic."))
    else:
        weak_dh = {"1", "2", "5"}
        if dhgrp:
            for grp in dhgrp.split():
                if grp in weak_dh:
                    f.append(finding(H, f"Phase2 '{name}': PFS DH group {grp} is weak — upgrade to group 14+."))

    # Key lifetime
    try:
        lt = int(lifetime)
        if lt > 28800:
            f.append(finding(M, f"Phase2 '{name}': key lifetime {lt}s exceeds 8h — consider shorter rekey intervals."))
        elif lt < 300:
            f.append(finding(I, f"Phase2 '{name}': key lifetime {lt}s is very short — may cause rekey overhead."))
    except (ValueError, TypeError):
        pass

    return f


def ssl_vpn_weaknesses(cfg: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    status      = nv(cfg.get("status", ""))
    port        = nv(cfg.get("port", ""))
    authtype    = nv(cfg.get("auth-type", ""))
    min_ver     = nv(cfg.get("tlsv1-0", "")) or nv(cfg.get("ssl-min-proto-ver", ""))
    cert        = nv(cfg.get("servercert", ""))
    dtls        = nv(cfg.get("dtls-tunnel", ""))
    tunnel_mode = nv(cfg.get("tunnel-mode", ""))
    ipv6        = nv(cfg.get("ipv6-tunnel-mode", ""))
    login_block = nv(cfg.get("login-block-time", ""))
    login_try   = nv(cfg.get("login-attempt-limit", ""))
    idle_to     = nv(cfg.get("idle-timeout", ""))
    auth_to     = nv(cfg.get("auth-timeout", ""))
    source_addr = nv(cfg.get("source-address", ""))

    if status == "enable":
        # Port
        if port in ("443", ""):
            f.append(finding(I, "SSL-VPN on default port 443 — easily scannable; consider non-standard port."))

        # Certificate
        if not cert or cert == "self-sign":
            f.append(finding(M, "SSL-VPN using self-signed certificate — clients cannot properly validate server identity."))

        # Authentication
        if authtype and "local" in authtype.lower() and "two-factor" not in authtype.lower():
            f.append(finding(H, "SSL-VPN using local auth only without MFA — credential stuffing directly compromises VPN access."))

        # TLS
        if min_ver == "enable" or min_ver in ("tls-1.0", "ssl-3.0", "tls-1.1"):
            f.append(finding(H, "SSL-VPN: TLS 1.0 or 1.1 permitted — deprecated; enforce TLS 1.2 minimum."))

        # Login brute-force protection
        try:
            if int(login_try) == 0:
                f.append(finding(H, "SSL-VPN: login attempt limit is 0 — brute-force protection disabled."))
            elif int(login_try) > 5:
                f.append(finding(M, f"SSL-VPN: {login_try} login attempts before lockout — reduce to 3–5."))
        except (ValueError, TypeError):
            f.append(finding(M, "SSL-VPN: login-attempt-limit not configured — brute-force protection may be absent."))

        try:
            if int(login_block) < 60:
                f.append(finding(M, f"SSL-VPN: login block time {login_block}s — consider 300s (5 min) to deter brute force."))
        except (ValueError, TypeError):
            pass

        # Idle / auth timeout
        try:
            if int(idle_to) == 0:
                f.append(finding(H, "SSL-VPN: idle timeout is 0 — idle sessions persist indefinitely."))
            elif int(idle_to) > 1800:
                f.append(finding(M, f"SSL-VPN: idle timeout {idle_to}s exceeds 30 min."))
        except (ValueError, TypeError):
            pass

        try:
            if int(auth_to) > 28800:
                f.append(finding(M, f"SSL-VPN: auth timeout {auth_to}s (>{28800//3600}h) — session re-auth too infrequent."))
        except (ValueError, TypeError):
            pass

        # Source address restriction
        if not source_addr or source_addr == "all":
            f.append(finding(M, "SSL-VPN: source-address not restricted — any internet host can attempt authentication."))

    return f


def ssl_vpn_portal_weaknesses(portal: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    name        = nv(portal.get("name", portal.get("_id", "")))
    split_tun   = nv(portal.get("split-tunneling", ""))
    limit_bw    = nv(portal.get("limit-user-logins", ""))
    ftp_proxy   = nv(portal.get("ftp-proxy", ""))
    smb_proxy   = nv(portal.get("smb-proxy", ""))
    rdp_proxy   = nv(portal.get("rdp-proxy", ""))

    if split_tun == "enable":
        f.append(finding(H, f"SSL-VPN portal '{name}': split tunneling enabled — only VPN-bound traffic protected; all other traffic bypasses FortiGate."))
    if ftp_proxy == "enable":
        f.append(finding(I, f"SSL-VPN portal '{name}': FTP proxy enabled — verify if needed."))
    if smb_proxy == "enable":
        f.append(finding(I, f"SSL-VPN portal '{name}': SMB proxy enabled — file share access via VPN web portal."))

    return f


def ha_weaknesses(ha: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value
    mode        = nv(ha.get("mode", ""))
    password    = nv(ha.get("password", ""))
    hbdev       = nv(ha.get("hbdev", ""))
    hb_interval = nv(ha.get("hb-interval", ""))
    hb_lost_thr = nv(ha.get("hb-lost-threshold", ""))
    monitor     = nv(ha.get("monitor", ""))
    syncconf    = nv(ha.get("sync-config", ""))
    encrypt     = nv(ha.get("hb-encryption", "")) or nv(ha.get("encrypt-ha-heartbeat", ""))

    if mode in ("a-p", "a-a"):
        if not password:
            f.append(finding(H, "HA cluster has no password — any FortiGate can join this cluster."))
        elif len(password) < 16:
            f.append(finding(M, "HA cluster password appears short — use 16+ random characters."))

        if not hbdev:
            f.append(finding(M, "HA heartbeat device not explicitly configured."))

        if encrypt != "enable":
            f.append(finding(M, "HA heartbeat traffic not encrypted — cluster sync data transmitted in cleartext on heartbeat interfaces."))

        try:
            if int(hb_interval) > 200:
                f.append(finding(I, f"HA heartbeat interval {hb_interval} (x100ms) — relatively slow failover detection."))
        except (ValueError, TypeError):
            pass

        if not monitor:
            f.append(finding(M, "HA interface monitoring not configured — link failures may not trigger failover."))

        if syncconf != "enable":
            f.append(finding(I, "HA config sync disabled — secondary may diverge from primary configuration."))

    elif mode == "standalone":
        f.append(finding(I, "HA mode is standalone — no redundancy; single point of failure."))

    return f


def log_weaknesses(fa: Dict[str, Any], syslog: Dict[str, Any], log_cfg: Dict[str, Any]) -> List[str]:
    f = []
    nv = normalize_value

    # FortiAnalyzer
    fa_status = nv(fa.get("status", ""))
    fa_server = nv(fa.get("server", ""))
    fa_enc    = nv(fa.get("enc-algorithm", ""))
    fa_rel    = nv(fa.get("reliable", ""))
    fa_upload_day = nv(fa.get("upload-day", ""))

    if fa_status != "enable":
        f.append(finding(M, "FortiAnalyzer logging disabled — no centralized log management/SIEM forwarding."))
    else:
        if not fa_server:
            f.append(finding(M, "FortiAnalyzer enabled but no server IP/hostname configured."))
        if fa_enc in ("", "disable", "low"):
            f.append(finding(M, "FortiAnalyzer log encryption is low/disabled — logs transmitted without adequate encryption."))
        if fa_rel != "enable":
            f.append(finding(I, "FortiAnalyzer reliable delivery (TCP) not enabled — UDP log delivery may lose events."))

    # Syslog
    syslog_status = nv(syslog.get("status", ""))
    syslog_server = nv(syslog.get("server", ""))
    syslog_enc    = nv(syslog.get("enc-algorithm", ""))
    syslog_mode   = nv(syslog.get("mode", ""))

    if syslog_status != "enable":
        f.append(finding(I, "Syslog forwarding disabled — no secondary log destination configured."))
    else:
        if not syslog_server:
            f.append(finding(M, "Syslog enabled but server not configured."))
        if syslog_mode == "udp":
            f.append(finding(M, "Syslog using UDP — logs may be lost under high load; use TCP or TLS."))
        if syslog_enc not in ("high", ""):
            f.append(finding(I, "Syslog not using TLS encryption — log data transmitted in cleartext."))

    # Log settings
    resolve_ip  = nv(log_cfg.get("resolve-ip", ""))
    gui_storage = nv(log_cfg.get("gui-local-in", ""))
    log_invalid = nv(log_cfg.get("log-invalid-packet", ""))
    log_policy  = nv(log_cfg.get("log-policy-comment", ""))

    if log_invalid != "enable":
        f.append(finding(I, "log-invalid-packet not enabled — malformed/invalid packets not logged (useful for attack detection)."))

    return f


# ─────────────────────────────────────────────
# Summary / scoring
# ─────────────────────────────────────────────

def compute_summary(all_findings: Dict[str, List[str]]) -> Dict[str, Any]:
    counts = {C: 0, H: 0, M: 0, I: 0}
    total  = 0
    by_section = {}
    for section, findings in all_findings.items():
        sec_counts = {C: 0, H: 0, M: 0, I: 0}
        for fn in findings:
            for sev in (C, H, M, I):
                if fn.startswith(sev + ":"):
                    counts[sev]     += 1
                    sec_counts[sev] += 1
                    total           += 1
        by_section[section] = sec_counts

    # Risk score: CRITICAL=10, HIGH=5, MEDIUM=2, INFO=0.5
    score = (counts[C] * 10) + (counts[H] * 5) + (counts[M] * 2) + (counts[I] * 0.5)

    if counts[C] > 0 or score >= 50:
        risk = "CRITICAL"
    elif score >= 25:
        risk = "HIGH"
    elif score >= 10:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "counts": counts,
        "total": total,
        "score": round(score, 1),
        "risk": risk,
        "by_section": by_section,
    }


# ─────────────────────────────────────────────
# ASCII table helpers
# ─────────────────────────────────────────────

def ascii_table(rows: List[tuple], title: str = None) -> str:
    col1 = max((len(str(k)) for k, _ in rows), default=18)
    col2 = max((len(str(v)) for _, v in rows), default=30)
    col1 = max(col1, 18)
    col2 = max(col2, 30)
    width = col1 + col2 + 7
    top = "+" + "-" * (width - 2) + "+"
    lines = [top]
    if title:
        t = title[:width - 4]
        lines += ["| " + t.center(width - 4) + " |", top]
    for k, v in rows:
        lines.append(f"| {str(k).ljust(col1)} | {str(v).ljust(col2)} |")
    lines.append(top)
    return "\n".join(lines)


def severity_bar(counts: Dict[str, int]) -> str:
    parts = []
    for sev, label in [(C, "CRIT"), (H, "HIGH"), (M, "MED"), (I, "INFO")]:
        if counts.get(sev, 0):
            parts.append(f"{label}:{counts[sev]}")
    return "  ".join(parts) if parts else "None"


# ─────────────────────────────────────────────
# Report generators
# ─────────────────────────────────────────────

def generate_firewall_report(policies, out_path):
    lines = ["FortiGate Firewall Policy Security Audit",
             f"Policies found: {len(policies)}", "=" * 80]
    for i, p in enumerate(policies, 1):
        nv = normalize_value
        rows = [
            ("Policy ID",      nv(p.get("policyid", p.get("_id", "")))),
            ("Name",           nv(p.get("name", ""))),
            ("Status",         nv(p.get("status", "enable"))),
            ("Action",         nv(p.get("action", ""))),
            ("Src Interface",  nv(p.get("srcintf", ""))),
            ("Dst Interface",  nv(p.get("dstintf", ""))),
            ("Src Address",    nv(p.get("srcaddr", ""))),
            ("Dst Address",    nv(p.get("dstaddr", ""))),
            ("Service",        nv(p.get("service", ""))),
            ("Schedule",       nv(p.get("schedule", ""))),
            ("NAT",            nv(p.get("nat", ""))),
            ("UTM Status",     nv(p.get("utm-status", ""))),
            ("IPS Sensor",     nv(p.get("ips-sensor", ""))),
            ("AV Profile",     nv(p.get("av-profile", ""))),
            ("Web Filter",     nv(p.get("webfilter-profile", ""))),
            ("DNS Filter",     nv(p.get("dnsfilter-profile", ""))),
            ("App Control",    nv(p.get("application-list", ""))),
            ("SSL/SSH Profile",nv(p.get("ssl-ssh-profile", ""))),
            ("DLP Profile",    nv(p.get("dlp-profile", nv(p.get("dlp-sensor", ""))))),
            ("CASB Profile",   nv(p.get("casb-profile", ""))),
            ("Log Traffic",    nv(p.get("logtraffic", ""))),
            ("Log Start",      nv(p.get("logtraffic-start", ""))),
            ("Comments",       nv(p.get("comments", ""))),
        ]
        lines.append(f"\nPolicy #{i}")
        lines.append(ascii_table(rows))
        w = firewall_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_ssl_report(profiles, out_path):
    lines = ["FortiGate SSL/SSH Inspection Profile Audit",
             f"Profiles found: {len(profiles)}", "=" * 80]
    for i, p in enumerate(profiles, 1):
        nv = normalize_value
        rows = [
            ("Profile Name",     nv(p.get("name", p.get("_id", "")))),
            ("Comments",         nv(p.get("comments", ""))),
            ("Inspection Method",nv(p.get("inspection-method", ""))),
            ("CA Name",          nv(p.get("caname", ""))),
            ("Min TLS Version",  nv(p.get("min-allowed-ssl-version", ""))),
            ("SNI Check",        nv(p.get("sni-check", ""))),
            ("Untrusted Cert",   nv(p.get("untrusted-cert", ""))),
            ("Expired Cert",     nv(p.get("expired-cert", ""))),
            ("Invalid Cert",     nv(p.get("invalid-cert", ""))),
            ("Revoked Cert",     nv(p.get("revoked-server-cert", ""))),
            ("Block Blacklisted",nv(p.get("block-blacklisted-certificates", ""))),
            ("Log SSL Anomalies",nv(p.get("log-ssl-anomalies", ""))),
            ("Inspect All Ports",nv(p.get("inspect-all-ports", ""))),
            ("Encrypted ClientH",nv(p.get("encrypted-client-hello", ""))),
            ("DNS over TLS",     nv(p.get("dot", nv(p.get("dns-over-tls", ""))))),
            ("RPC over HTTPS",   nv(p.get("rpc-over-https", ""))),
            ("MAPI over HTTPS",  nv(p.get("mapi-over-https", ""))),
        ]
        lines.append(f"\nProfile #{i}")
        lines.append(ascii_table(rows))
        w = ssl_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_av_report(profiles, out_path):
    lines = ["FortiGate AntiVirus Profile Audit",
             f"Profiles found: {len(profiles)}", "=" * 80]
    for i, p in enumerate(profiles, 1):
        nv = normalize_value
        rows = [
            ("Profile Name",      nv(p.get("name", p.get("_id", "")))),
            ("Feature Set",       nv(p.get("feature-set", ""))),
            ("Scan Mode",         nv(p.get("scan-mode", ""))),
            ("HTTP",              nv(p.get("http", ""))),
            ("HTTPS",             nv(p.get("https", ""))),
            ("SMTP",              nv(p.get("smtp", ""))),
            ("POP3",              nv(p.get("pop3", ""))),
            ("IMAP",              nv(p.get("imap", ""))),
            ("FTP",               nv(p.get("ftp", ""))),
            ("CIFS/SMB",          nv(p.get("cifs", ""))),
            ("NNTP",              nv(p.get("nntp", ""))),
            ("Default Action",    nv(p.get("default-action", ""))),
            ("FortiSandbox",      nv(p.get("fortisandbox", ""))),
            ("Outbreak Prevention",nv(p.get("outbreak-prevention", ""))),
            ("Quarantine",        nv(p.get("quarantine", ""))),
            ("Content Disarm",    nv(p.get("content-disarm", ""))),
        ]
        lines.append(f"\nProfile #{i}")
        lines.append(ascii_table(rows))
        w = av_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_utm_profiles_report(ips_sensors, wf_profs, app_profs, dns_profs, out_path):
    lines = ["FortiGate UTM Profile Audit (IPS / Web Filter / App Control / DNS Filter)",
             "=" * 80]

    lines.append(f"\n{'='*30} IPS SENSORS ({len(ips_sensors)}) {'='*30}")
    for i, s in enumerate(ips_sensors, 1):
        nv = normalize_value
        rows = [
            ("Sensor Name",       nv(s.get("name", s.get("_id", "")))),
            ("Block Malicious URL",nv(s.get("block-malicious-url", ""))),
            ("Scan Botnet Conn.", nv(s.get("scan-botnet-connections", ""))),
            ("Extended DB",       nv(s.get("extended-db", ""))),
        ]
        lines.append(f"\nIPS Sensor #{i}")
        lines.append(ascii_table(rows))
        w = ips_weaknesses(s)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    lines.append(f"\n{'='*30} WEB FILTER PROFILES ({len(wf_profs)}) {'='*30}")
    for i, p in enumerate(wf_profs, 1):
        nv = normalize_value
        rows = [
            ("Profile Name",  nv(p.get("name", p.get("_id", "")))),
            ("Log All URLs",  nv(p.get("log-all-url", ""))),
            ("Safe Search",   nv(p.get("safe-search", ""))),
            ("User Override", nv(p.get("override", ""))),
            ("Web Content Log",nv(p.get("web-content-log", ""))),
        ]
        lines.append(f"\nWeb Filter Profile #{i}")
        lines.append(ascii_table(rows))
        w = wf_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    lines.append(f"\n{'='*30} APP CONTROL PROFILES ({len(app_profs)}) {'='*30}")
    for i, p in enumerate(app_profs, 1):
        nv = normalize_value
        rows = [
            ("Profile Name",     nv(p.get("name", p.get("_id", "")))),
            ("Log",              nv(p.get("log", ""))),
            ("Unknown App Action",nv(p.get("unknown-application-action", ""))),
            ("P2P Block List",   nv(p.get("p2p-block-list", ""))),
        ]
        lines.append(f"\nApp Control Profile #{i}")
        lines.append(ascii_table(rows))
        w = app_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    lines.append(f"\n{'='*30} DNS FILTER PROFILES ({len(dns_profs)}) {'='*30}")
    for i, p in enumerate(dns_profs, 1):
        nv = normalize_value
        rows = [
            ("Profile Name",  nv(p.get("name", p.get("_id", "")))),
            ("Block Botnet",  nv(p.get("block-botnet", ""))),
            ("Log All Domain",nv(p.get("log-all-domain", ""))),
            ("Safe Search",   nv(p.get("safe-search", ""))),
            ("FortiGuard DNS",nv(p.get("ftgd-dns", ""))),
        ]
        lines.append(f"\nDNS Filter Profile #{i}")
        lines.append(ascii_table(rows))
        w = dns_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_vpn_report(phase1_list, phase2_list, out_path):
    lines = ["FortiGate IPsec VPN Security Audit",
             f"Phase1 tunnels: {len(phase1_list)}  Phase2 SAs: {len(phase2_list)}", "=" * 80]

    for i, p in enumerate(phase1_list, 1):
        nv = normalize_value
        rows = [
            ("Tunnel Name",    nv(p.get("name", p.get("_id", "")))),
            ("IKE Version",    nv(p.get("ike-version", ""))),
            ("IKE Mode",       nv(p.get("mode", ""))),
            ("Auth Method",    nv(p.get("authmethod", ""))),
            ("Proposal",       nv(p.get("proposal", ""))),
            ("DH Groups",      nv(p.get("dhgrp", ""))),
            ("DPD",            nv(p.get("dpd", ""))),
            ("Rekey",          nv(p.get("rekey", ""))),
            ("Key Lifetime",   nv(p.get("keylifetime", ""))),
            ("NAT Traversal",  nv(p.get("nattraversal", ""))),
        ]
        lines.append(f"\nPhase1 #{i}")
        lines.append(ascii_table(rows))
        w = vpn_phase1_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    for i, p in enumerate(phase2_list, 1):
        nv = normalize_value
        rows = [
            ("SA Name",       nv(p.get("name", p.get("_id", "")))),
            ("Phase1 Name",   nv(p.get("phase1name", ""))),
            ("Proposal",      nv(p.get("proposal", ""))),
            ("PFS",           nv(p.get("pfs", ""))),
            ("DH Group",      nv(p.get("dhgrp", ""))),
            ("Key Lifetime",  nv(p.get("keylifetime-seconds", ""))),
        ]
        lines.append(f"\nPhase2 #{i}")
        lines.append(ascii_table(rows))
        w = vpn_phase2_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_sslvpn_report(ssl_vpn_cfg, portals, out_path):
    lines = ["FortiGate SSL-VPN Security Audit", "=" * 80]

    nv = normalize_value
    rows = [
        ("Status",           nv(ssl_vpn_cfg.get("status", ""))),
        ("Port",             nv(ssl_vpn_cfg.get("port", ""))),
        ("Server Cert",      nv(ssl_vpn_cfg.get("servercert", ""))),
        ("Auth Timeout",     nv(ssl_vpn_cfg.get("auth-timeout", ""))),
        ("Idle Timeout",     nv(ssl_vpn_cfg.get("idle-timeout", ""))),
        ("Login Attempt Lim",nv(ssl_vpn_cfg.get("login-attempt-limit", ""))),
        ("Login Block Time", nv(ssl_vpn_cfg.get("login-block-time", ""))),
        ("DTLS Tunnel",      nv(ssl_vpn_cfg.get("dtls-tunnel", ""))),
        ("TLS 1.0",          nv(ssl_vpn_cfg.get("tlsv1-0", ""))),
        ("Source Address",   nv(ssl_vpn_cfg.get("source-address", ""))),
    ]
    lines.append("\nSSL-VPN Global Settings")
    lines.append(ascii_table(rows))
    w = ssl_vpn_weaknesses(ssl_vpn_cfg)
    lines.append("Findings:")
    lines += ([f"  - {x}" for x in w] if w else ["  - None"])
    lines.append("-" * 80)

    lines.append(f"\n=== SSL-VPN Portals ({len(portals)}) ===")
    for i, p in enumerate(portals, 1):
        rows = [
            ("Portal Name",    nv(p.get("name", p.get("_id", "")))),
            ("Split Tunneling",nv(p.get("split-tunneling", ""))),
            ("FTP Proxy",      nv(p.get("ftp-proxy", ""))),
            ("SMB Proxy",      nv(p.get("smb-proxy", ""))),
        ]
        lines.append(f"\nPortal #{i}")
        lines.append(ascii_table(rows))
        w = ssl_vpn_portal_weaknesses(p)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_ha_report(ha_cfg, out_path):
    nv = normalize_value
    lines = ["FortiGate High Availability (HA) Security Audit", "=" * 80]
    rows = [
        ("Mode",             nv(ha_cfg.get("mode", ""))),
        ("Password",         "***" if ha_cfg.get("password") else "(not set)"),
        ("HB Device",        nv(ha_cfg.get("hbdev", ""))),
        ("HB Interval",      nv(ha_cfg.get("hb-interval", ""))),
        ("HB Lost Threshold",nv(ha_cfg.get("hb-lost-threshold", ""))),
        ("Monitor",          nv(ha_cfg.get("monitor", ""))),
        ("HB Encryption",    nv(ha_cfg.get("hb-encryption", nv(ha_cfg.get("encrypt-ha-heartbeat", ""))))),
        ("Sync Config",      nv(ha_cfg.get("sync-config", ""))),
    ]
    lines.append(ascii_table(rows))
    w = ha_weaknesses(ha_cfg)
    lines.append("Findings:")
    lines += ([f"  - {x}" for x in w] if w else ["  - None"])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_log_report(fa_cfg, syslog_cfg, log_cfg, out_path):
    lines = ["FortiGate Logging & SIEM Forwarding Audit", "=" * 80]
    nv = normalize_value

    lines.append("\n=== FortiAnalyzer Settings ===")
    lines.append(ascii_table([
        ("Status",      nv(fa_cfg.get("status", ""))),
        ("Server",      nv(fa_cfg.get("server", ""))),
        ("Enc Algorithm",nv(fa_cfg.get("enc-algorithm", ""))),
        ("Reliable",    nv(fa_cfg.get("reliable", ""))),
        ("Upload Day",  nv(fa_cfg.get("upload-day", ""))),
    ]))

    lines.append("\n=== Syslog Settings ===")
    lines.append(ascii_table([
        ("Status",       nv(syslog_cfg.get("status", ""))),
        ("Server",       nv(syslog_cfg.get("server", ""))),
        ("Mode",         nv(syslog_cfg.get("mode", ""))),
        ("Enc Algorithm",nv(syslog_cfg.get("enc-algorithm", ""))),
        ("Facility",     nv(syslog_cfg.get("facility", ""))),
    ]))

    lines.append("\n=== Log Global Settings ===")
    lines.append(ascii_table([
        ("Log Invalid Packet",nv(log_cfg.get("log-invalid-packet", ""))),
        ("Resolve IP",        nv(log_cfg.get("resolve-ip", ""))),
        ("Log Policy Comment",nv(log_cfg.get("log-policy-comment", ""))),
    ]))

    w = log_weaknesses(fa_cfg, syslog_cfg, log_cfg)
    lines.append("\nFindings:")
    lines += ([f"  - {x}" for x in w] if w else ["  - None"])
    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_system_report(admins, interfaces, global_cfg, ntp_cfg, local_in, out_path):
    lines = ["FortiGate System Hardening Audit", "=" * 80]

    lines.append(f"\n{'='*25} ADMINISTRATOR ACCOUNTS ({len(admins)}) {'='*25}")
    for i, adm in enumerate(admins, 1):
        nv = normalize_value
        name = nv(adm.get("name", adm.get("_id", "")))
        rows = [("Admin Name", name), ("Accprofile", nv(adm.get("accprofile", ""))),
                ("Two-Factor", nv(adm.get("two-factor", ""))),
                ("Force PW Change", nv(adm.get("force-password-change", ""))),
                ("Wildcard", nv(adm.get("wildcard", "")))]
        for n in range(1, 6):
            rows.append((f"Trusthost{n}", nv(adm.get(f"trusthost{n}", ""))))
        lines.append(f"\nAdmin #{i}")
        lines.append(ascii_table(rows))
        w = admin_weaknesses(adm)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    lines.append(f"\n{'='*25} INTERFACES ({len(interfaces)}) {'='*25}")
    for i, intf in enumerate(interfaces, 1):
        nv = normalize_value
        rows = [("Interface", nv(intf.get("name", intf.get("_id", "")))),
                ("IP/Mask", nv(intf.get("ip", ""))),
                ("Role", nv(intf.get("role", ""))),
                ("Type", nv(intf.get("type", ""))),
                ("Allowaccess", nv(intf.get("allowaccess", ""))),
                ("Proxy ARP", nv(intf.get("proxy-arp", "")))]
        lines.append(f"\nInterface #{i}")
        lines.append(ascii_table(rows))
        w = interface_weaknesses(intf)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    lines.append(f"\n{'='*25} GLOBAL CRYPTO & HARDENING {'='*25}")
    nv = normalize_value
    rows = [
        ("Hostname",           nv(global_cfg.get("hostname", ""))),
        ("Strong Crypto",      nv(global_cfg.get("strong-crypto", ""))),
        ("SSL Static Ciphers", nv(global_cfg.get("ssl-static-key-ciphers", ""))),
        ("DH Params",          nv(global_cfg.get("dh-params", ""))),
        ("Admin Timeout",      nv(global_cfg.get("admintimeout", ""))),
        ("Lockout Threshold",  nv(global_cfg.get("admin-lockout-threshold", ""))),
        ("Lockout Duration",   nv(global_cfg.get("admin-lockout-duration", ""))),
        ("Pre-Login Banner",   nv(global_cfg.get("pre-login-banner", ""))),
        ("Post-Login Banner",  nv(global_cfg.get("post-login-banner", ""))),
        ("HTTPS Redirect",     nv(global_cfg.get("admin-https-redirect", ""))),
        ("GUI Certificate",    nv(global_cfg.get("admin-server-cert", ""))),
        ("Password Policy",    nv(global_cfg.get("admin-password-policy", ""))),
        ("PW Min Length",      nv(global_cfg.get("password-policy-min-length", ""))),
        ("Revision Backup",    nv(global_cfg.get("revision-image-auto-backup", ""))),
    ]
    lines.append(ascii_table(rows))
    w = global_crypto_weaknesses(global_cfg)
    lines.append("Findings:")
    lines += ([f"  - {x}" for x in w] if w else ["  - None"])
    lines.append("-" * 80)

    lines.append(f"\n{'='*25} NTP CONFIGURATION {'='*25}")
    rows = [
        ("NTP Sync",     nv(ntp_cfg.get("ntpsync", ""))),
        ("Type",         nv(ntp_cfg.get("type", ""))),
        ("Sync Interval",nv(ntp_cfg.get("syncinterval", ""))),
        ("Source IP",    nv(ntp_cfg.get("source-ip", ""))),
        ("Server Mode",  nv(ntp_cfg.get("server-mode", ""))),
        ("Authentication",nv(ntp_cfg.get("authentication", ""))),
        ("NTPv3",        nv(ntp_cfg.get("ntpv3", ""))),
        ("Server Count", str(len(ntp_cfg.get("servers", [])))),
    ]
    lines.append(ascii_table(rows))
    w = ntp_weaknesses(ntp_cfg)
    lines.append("Findings:")
    lines += ([f"  - {x}" for x in w] if w else ["  - None"])
    lines.append("-" * 80)

    lines.append(f"\n{'='*25} LOCAL-IN POLICIES ({len(local_in)}) {'='*25}")
    for i, lip in enumerate(local_in, 1):
        rows = [("Interface", nv(lip.get("intf", ""))), ("Srcaddr", nv(lip.get("srcaddr", ""))),
                ("Dstaddr", nv(lip.get("dstaddr", ""))), ("Service", nv(lip.get("service", ""))),
                ("Action", nv(lip.get("action", ""))), ("Schedule", nv(lip.get("schedule", "")))]
        lines.append(f"\nLocal-in #{i}")
        lines.append(ascii_table(rows))
        w = local_in_weaknesses(lip)
        lines.append("Findings:")
        lines += ([f"  - {x}" for x in w] if w else ["  - None"])
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_summary(all_findings: Dict[str, List[str]], config_path: str, out_path: Path):
    summary = compute_summary(all_findings)
    counts  = summary["counts"]
    lines   = []
    width   = 80

    lines.append("=" * width)
    lines.append(" FORTIGATE SECURITY AUDIT — EXECUTIVE SUMMARY ".center(width, "="))
    lines.append("=" * width)
    lines.append(f"  Config file : {config_path}")
    lines.append(f"  Risk rating : {summary['risk']}")
    lines.append(f"  Risk score  : {summary['score']}  (CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5)")
    lines.append(f"  Total finds : {summary['total']}")
    lines.append("")
    lines.append(f"  {'CRITICAL':10s}  {counts[C]:>4d}")
    lines.append(f"  {'HIGH':10s}  {counts[H]:>4d}")
    lines.append(f"  {'MEDIUM':10s}  {counts[M]:>4d}")
    lines.append(f"  {'INFO':10s}  {counts[I]:>4d}")
    lines.append("=" * width)
    lines.append("")

    lines.append("  FINDINGS BY SECTION:")
    lines.append("  " + "-" * (width - 2))
    lines.append(f"  {'Section':<30s}  {'CRIT':>4s}  {'HIGH':>4s}  {'MED':>4s}  {'INFO':>4s}  {'TOTAL':>5s}")
    lines.append("  " + "-" * (width - 2))
    for section, sc in sorted(summary["by_section"].items()):
        total_s = sum(sc.values())
        if total_s:
            lines.append(f"  {section:<30s}  {sc[C]:>4d}  {sc[H]:>4d}  {sc[M]:>4d}  {sc[I]:>4d}  {total_s:>5d}")
    lines.append("  " + "-" * (width - 2))
    lines.append("")

    lines.append("  CRITICAL & HIGH FINDINGS:")
    lines.append("  " + "-" * (width - 2))
    for section, finds in all_findings.items():
        for fn in finds:
            if fn.startswith(C + ":") or fn.startswith(H + ":"):
                lines.append(f"  [{section}]  {fn}")
    lines.append("")
    lines.append("=" * width)

    out_path.write_text("\n".join(lines), encoding="utf-8")
    # Also write JSON version
    json_path = out_path.with_suffix(".json")
    json_path.write_text(json.dumps({"summary": summary, "findings": all_findings}, indent=2), encoding="utf-8")
    return summary


# ─────────────────────────────────────────────
# Diagram
# ─────────────────────────────────────────────

def build_policy_diagram(policy, intf_map, ssl_map, av_map):
    nv = normalize_value
    srcintf  = nv(policy.get("srcintf", ""))
    dstintf  = nv(policy.get("dstintf", ""))
    pid      = nv(policy.get("policyid", policy.get("_id", "")))
    name     = nv(policy.get("name", ""))
    si       = intf_map.get(srcintf, {})
    di       = intf_map.get(dstintf, {})

    L = []
    L.append(f"[{srcintf} - {nv(si.get('role','')) or 'unknown'}]")
    L.append(f"   +--> ip/mask: {nv(si.get('ip','unknown'))}")
    L.append(f"   +--> allowaccess: {nv(si.get('allowaccess','none')) or 'none'}")
    L.append(f"   +--> vlan: {nv(si.get('vlanid','none')) or 'none'}")
    L.append("   |"); L.append("   v")
    L.append(f"[Policy {pid}: {name}]")
    for k, v in [("src", "srcaddr"), ("dst", "dstaddr"), ("svc", "service"),
                 ("action", "action"), ("nat", "nat"), ("schedule", "schedule"),
                 ("log", "logtraffic"), ("utm", "utm-status")]:
        L.append(f"   +--> {k}: {nv(policy.get(v,''))}")
    L.append("   |")

    for label, key, detail_map, detail_fn in [
        ("SSL/SSH Profile", "ssl-ssh-profile", ssl_map, lambda o: [
            ("mode", nv(o.get("inspection-method","?"))),
            ("CA", nv(o.get("caname","none"))), ("SNI", nv(o.get("sni-check","?"))),
            ("untrusted", nv(o.get("untrusted-cert","?"))), ("min-TLS", nv(o.get("min-allowed-ssl-version","?")))]),
        ("Antivirus", "av-profile", av_map, lambda o: [
            ("feature-set", nv(o.get("feature-set","?"))), ("sandbox", nv(o.get("fortisandbox","?"))),
            ("outbreak", nv(o.get("outbreak-prevention","?"))), ("CDR", nv(o.get("content-disarm","?")))]),
    ]:
        pname = nv(policy.get(key, ""))
        L.append(f"   +--> {label}")
        if pname:
            obj = detail_map.get(pname, {})
            L.append(f"   |      name: {pname}")
            for dk, dv in detail_fn(obj):
                L.append(f"   |      {dk}: {dv}")
        else:
            L.append(f"   |      (none)")
        L.append("   |")

    for label, key in [("IPS", "ips-sensor"), ("WebFilter", "webfilter-profile"),
                       ("AppControl", "application-list"), ("DNSFilter", "dnsfilter-profile"),
                       ("DLP", "dlp-profile"), ("CASB", "casb-profile")]:
        pname = nv(policy.get(key, ""))
        L.append(f"   +--> {label}: {pname or '(none)'}")
    L.append("   |"); L.append("   v")
    L.append(f"[{dstintf} - {nv(di.get('role','')) or 'unknown'}]")
    L.append(f"   +--> ip: {nv(di.get('ip','?'))}")
    L.append(f"   +--> allowaccess: {nv(di.get('allowaccess','none')) or 'none'}")
    return "\n".join(L)


def generate_diagram(policies, interfaces, ssl_profiles, av_profiles, out_path):
    intf_map = {normalize_value(i.get("name", i.get("_id",""))): i for i in interfaces}
    ssl_map  = {normalize_value(p.get("name", p.get("_id",""))): p for p in ssl_profiles}
    av_map   = {normalize_value(p.get("name", p.get("_id",""))): p for p in av_profiles}
    blocks   = []
    for p in policies:
        blocks.append(build_policy_diagram(p, intf_map, ssl_map, av_map))
        blocks.append("")
    out_path.write_text("\n".join(blocks), encoding="utf-8")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FortiGate UTM Security Analyzer v2.0 — deep audit of FortiGate config files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 utm.py -c fw.conf -f -i -av -s --summary     # core audit + executive summary
  python3 utm.py -c fw.conf --all                       # everything
  python3 utm.py -c fw.conf -vpn -sslvpn               # VPN focus
  python3 utm.py -c fw.conf -ips -wf -app -dns         # UTM profile focus
        """
    )
    parser.add_argument("-c", "--config", required=True, help="FortiGate config file path")
    parser.add_argument("-f",        action="store_true", help="Firewall policy audit")
    parser.add_argument("-i",        action="store_true", help="SSL/SSH inspection profile audit")
    parser.add_argument("-av",       action="store_true", help="Antivirus profile audit")
    parser.add_argument("-ips",      action="store_true", help="IPS sensor audit")
    parser.add_argument("-wf",       action="store_true", help="Web filter profile audit")
    parser.add_argument("-app",      action="store_true", help="Application control profile audit")
    parser.add_argument("-dns",      action="store_true", help="DNS filter profile audit")
    parser.add_argument("-vpn",      action="store_true", help="IPsec VPN Phase1/Phase2 audit")
    parser.add_argument("-sslvpn",   action="store_true", help="SSL-VPN settings + portal audit")
    parser.add_argument("-ha",       action="store_true", help="HA configuration audit")
    parser.add_argument("-log",      action="store_true", help="Logging / FortiAnalyzer / syslog audit")
    parser.add_argument("-s",        action="store_true", help="System hardening audit (admin, interface, global, NTP, local-in)")
    parser.add_argument("-d",        action="store_true", help="UTM topology diagram per policy")
    parser.add_argument("--summary", action="store_true", help="Generate executive summary with risk score")
    parser.add_argument("--all",     action="store_true", help="Run all audits")

    args = parser.parse_args()

    if args.all:
        for attr in ["f","i","av","ips","wf","app","dns","vpn","sslvpn","ha","log","s","d","summary"]:
            setattr(args, attr, True)

    cfg_text = read_config(args.config)
    base     = Path(args.config).name
    out      = lambda suffix: Path(f"{base}{suffix}")

    # Parse once
    policies   = parse_firewall_policies(cfg_text)
    ssl_profs  = parse_ssl_profiles(cfg_text)
    av_profs   = parse_av_profiles(cfg_text)
    ips_sens   = parse_ips_sensors(cfg_text)
    wf_profs   = parse_wf_profiles(cfg_text)
    app_profs  = parse_app_profiles(cfg_text)
    dns_profs  = parse_dns_profiles(cfg_text)
    admins     = parse_admins(cfg_text)
    interfaces = parse_interfaces(cfg_text)
    global_cfg = parse_system_global(cfg_text)
    ntp_cfg    = parse_ntp(cfg_text)
    local_in   = parse_local_in(cfg_text)
    phase1     = parse_vpn_phase1(cfg_text)
    phase2     = parse_vpn_phase2(cfg_text)
    ha_cfg     = parse_ha(cfg_text)
    fa_cfg     = parse_log_fortianalyzer(cfg_text)
    syslog_cfg = parse_log_syslogd(cfg_text)
    log_cfg    = parse_log_setting(cfg_text)
    sslvpn_cfg = parse_ssl_vpn_settings(cfg_text)
    sslvpn_portals = parse_ssl_vpn_web_portals(cfg_text)

    all_findings: Dict[str, List[str]] = {}

    if args.f:
        p = out("_firewall_report.txt")
        generate_firewall_report(policies, p)
        print(f"[+] Firewall report        -> {p}")
        all_findings["Firewall Policies"] = [fn for pol in policies for fn in firewall_weaknesses(pol)]

    if args.i:
        p = out("_ssl_inspection_report.txt")
        generate_ssl_report(ssl_profs, p)
        print(f"[+] SSL/SSH report         -> {p}")
        all_findings["SSL Inspection"] = [fn for prof in ssl_profs for fn in ssl_weaknesses(prof)]

    if args.av:
        p = out("_antivirus_report.txt")
        generate_av_report(av_profs, p)
        print(f"[+] Antivirus report       -> {p}")
        all_findings["Antivirus Profiles"] = [fn for prof in av_profs for fn in av_weaknesses(prof)]

    if args.ips or args.wf or args.app or args.dns:
        p = out("_utm_profiles_report.txt")
        generate_utm_profiles_report(ips_sens, wf_profs, app_profs, dns_profs, p)
        print(f"[+] UTM profiles report    -> {p}")
        all_findings["IPS Sensors"] = [fn for s in ips_sens for fn in ips_weaknesses(s)]
        all_findings["Web Filter"]  = [fn for s in wf_profs for fn in wf_weaknesses(s)]
        all_findings["App Control"] = [fn for s in app_profs for fn in app_weaknesses(s)]
        all_findings["DNS Filter"]  = [fn for s in dns_profs for fn in dns_weaknesses(s)]

    if args.vpn:
        p = out("_vpn_report.txt")
        generate_vpn_report(phase1, phase2, p)
        print(f"[+] VPN (IPsec) report     -> {p}")
        all_findings["VPN Phase1"] = [fn for t in phase1 for fn in vpn_phase1_weaknesses(t)]
        all_findings["VPN Phase2"] = [fn for t in phase2 for fn in vpn_phase2_weaknesses(t)]

    if args.sslvpn:
        p = out("_sslvpn_report.txt")
        generate_sslvpn_report(sslvpn_cfg, sslvpn_portals, p)
        print(f"[+] SSL-VPN report         -> {p}")
        all_findings["SSL-VPN"] = ssl_vpn_weaknesses(sslvpn_cfg)
        all_findings["SSL-VPN Portals"] = [fn for pr in sslvpn_portals for fn in ssl_vpn_portal_weaknesses(pr)]

    if args.ha:
        p = out("_ha_report.txt")
        generate_ha_report(ha_cfg, p)
        print(f"[+] HA report              -> {p}")
        all_findings["HA Config"] = ha_weaknesses(ha_cfg)

    if args.log:
        p = out("_logging_report.txt")
        generate_log_report(fa_cfg, syslog_cfg, log_cfg, p)
        print(f"[+] Logging report         -> {p}")
        all_findings["Logging"] = log_weaknesses(fa_cfg, syslog_cfg, log_cfg)

    if args.s:
        p = out("_system_report.txt")
        generate_system_report(admins, interfaces, global_cfg, ntp_cfg, local_in, p)
        print(f"[+] System report          -> {p}")
        all_findings["Admin Accounts"] = [fn for a in admins for fn in admin_weaknesses(a)]
        all_findings["Interfaces"]     = [fn for i in interfaces for fn in interface_weaknesses(i)]
        all_findings["Global Hardening"] = global_crypto_weaknesses(global_cfg)
        all_findings["NTP"]            = ntp_weaknesses(ntp_cfg)
        all_findings["Local-in"]       = [fn for l in local_in for fn in local_in_weaknesses(l)]

    if args.d:
        p = out("_diagram.txt")
        generate_diagram(policies, interfaces, ssl_profs, av_profs, p)
        print(f"[+] Diagram                -> {p}")

    if args.summary and all_findings:
        p = out("_SUMMARY.txt")
        summary = generate_summary(all_findings, args.config, p)
        print(f"[+] Executive summary      -> {p}")
        print(f"[+] Summary JSON           -> {p.with_suffix('.json')}")
        print(f"\n    Risk Rating : {summary['risk']}   Score : {summary['score']}")
        print(f"    CRITICAL: {summary['counts'][C]}  HIGH: {summary['counts'][H]}  MEDIUM: {summary['counts'][M]}  INFO: {summary['counts'][I]}")

    if not any([args.f, args.i, args.av, args.ips, args.wf, args.app, args.dns,
                args.vpn, args.sslvpn, args.ha, args.log, args.s, args.d, args.summary]):
        print("[!] No flags specified. Use --all for everything, or --help for options.")


if __name__ == "__main__":
    main()
