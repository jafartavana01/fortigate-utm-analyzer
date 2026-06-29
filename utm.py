#!/usr/bin/env python3
import argparse
from pathlib import Path
import re
from typing import List, Dict, Any


# -----------------------------
# Generic helpers
# -----------------------------

def read_config(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def normalize_value(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s


def parse_set_line(line: str):
    """
    Parse lines like:
      set field value
    into (field, value_string)
    """
    line = line.strip()
    m = re.match(r"set\s+(\S+)\s+(.+)", line)
    if not m:
        return None, None
    key = m.group(1)
    value = m.group(2).strip()
    return key, value


def extract_block(text: str, block_name: str) -> List[Dict[str, Any]]:
    """
    Extract objects from a FortiGate config block, e.g.
    config firewall policy
        edit 1
            set ...
        next
    end
    """
    lines = text.splitlines()
    objects = []
    in_block = False
    current = None

    for raw in lines:
        line = raw.strip()

        if line == f"config {block_name}":
            in_block = True
            current = None
            continue
        if in_block and line == "end":
            if current:
                objects.append(current)
            break
        if not in_block:
            continue

        if line.startswith("edit "):
            # Finish previous object
            if current:
                objects.append(current)
            obj_id = line.split(None, 1)[1].strip()
            obj_id = obj_id.strip('"')
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


# -----------------------------
# Firewall policy parsing
# -----------------------------

def parse_firewall_policies(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "firewall policy")


# -----------------------------
# SSL/SSH inspection profile parsing
# -----------------------------

def parse_ssl_profiles(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "firewall ssl-ssh-profile")


# -----------------------------
# Antivirus profile parsing
# -----------------------------

def parse_av_profiles(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "antivirus profile")


# -----------------------------
# System admin / interface / global / ntp / local-in parsing
# -----------------------------

def parse_admins(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "system admin")


def parse_interfaces(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "system interface")


def parse_system_global(text: str) -> Dict[str, Any]:
    """
    system global is mostly a single object, not many 'edit' entries.
    We treat 'config system global' as one flat block of 'set' lines.
    """
    lines = text.splitlines()
    in_block = False
    current = {}

    for raw in lines:
        line = raw.strip()
        if line == "config system global":
            in_block = True
            current = {}
            continue
        if in_block and line == "end":
            break
        if not in_block:
            continue

        if line.startswith("set "):
            k, v = parse_set_line(line)
            if k:
                current[k] = v

    return current


def parse_ntp(text: str) -> Dict[str, Any]:
    """
    Parse config system ntp and optional ntpserver entries.
    """
    lines = text.splitlines()
    in_block = False
    ntp = {}
    ntpservers = []
    current_server = None

    for raw in lines:
        line = raw.strip()

        if line == "config system ntp":
            in_block = True
            ntp = {}
            ntpservers = []
            current_server = None
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
                if current_server is not None:
                    current_server[k] = v
                else:
                    ntp[k] = v

    ntp["servers"] = ntpservers
    return ntp


def parse_local_in(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "firewall local-in-policy")


# -----------------------------
# Weakness checks: firewall
# -----------------------------

def firewall_weaknesses(policy: Dict[str, Any]) -> List[str]:
    findings = []

    action = normalize_value(policy.get("action", ""))
    utm = normalize_value(policy.get("utm-status", ""))
    ips = normalize_value(policy.get("ips-sensor", ""))
    av = normalize_value(policy.get("av-profile", ""))
    wf = normalize_value(policy.get("webfilter-profile", ""))
    dnsf = normalize_value(policy.get("dnsfilter-profile", ""))
    app = normalize_value(policy.get("application-list", ""))
    ssl = normalize_value(policy.get("ssl-ssh-profile", ""))
    logtraffic = normalize_value(policy.get("logtraffic", ""))
    nat = normalize_value(policy.get("nat", ""))

    if action == "accept":
        if utm != "enable":
            findings.append("HIGH: UTM is disabled on an accept policy.")
        if not ips:
            findings.append("HIGH: IPS profile is missing on an accept policy.")
        if not av:
            findings.append("HIGH: Antivirus profile is missing on an accept policy.")
        if not wf:
            findings.append("MEDIUM: Web filter profile is missing on an accept policy.")
        if not dnsf:
            findings.append("MEDIUM: DNS filter profile is missing on an accept policy.")
        if not app:
            findings.append("MEDIUM: Application control profile is missing on an accept policy.")
        if not ssl:
            findings.append("HIGH: SSL/SSH inspection profile is missing for encrypted traffic.")
    if logtraffic in ("", "disable"):
        findings.append("MEDIUM: Logging is disabled or not configured for this policy.")
    if nat != "enable":
        findings.append("INFO: NAT is disabled; verify that this is expected for this policy.")

    return findings


# -----------------------------
# Weakness checks: SSL/SSH profiles
# -----------------------------

def ssl_weaknesses(profile: Dict[str, Any]) -> List[str]:
    findings = []

    mode = normalize_value(profile.get("inspection-method", ""))
    caname = normalize_value(profile.get("caname", ""))
    inspect_all = normalize_value(profile.get("inspect-all-ports", ""))
    sni = normalize_value(profile.get("sni-check", ""))
    untrusted = normalize_value(profile.get("untrusted-cert", ""))
    expired = normalize_value(profile.get("expired-cert", ""))
    invalid = normalize_value(profile.get("invalid-cert", ""))
    log_anom = normalize_value(profile.get("log-ssl-anomalies", ""))

    if not mode:
        findings.append("MEDIUM: SSL inspection mode not explicitly set.")
    elif mode == "certificate-inspection":
        findings.append("INFO: Certificate-only inspection used; content is not decrypted.")
    elif mode in ("full-inspection", "deep-inspection"):
        if not caname:
            findings.append("HIGH: Full inspection without a defined CA certificate.")

    if inspect_all == "enable":
        findings.append("MEDIUM: Inspect-all-ports enabled; may cause overhead and false positives.")

    if sni in ("", "disable"):
        findings.append("MEDIUM: SNI checking disabled; weaker certificate validation.")

    if untrusted != "block":
        findings.append("HIGH: Untrusted certificates not blocked.")
    if expired != "block":
        findings.append("MEDIUM: Expired certificates not blocked.")
    if invalid != "block":
        findings.append("HIGH: Invalid certificates not blocked.")

    if log_anom != "enable":
        findings.append("MEDIUM: SSL anomalies not logged.")

    return findings


# -----------------------------
# Weakness checks: AV profiles
# -----------------------------

def av_weaknesses(profile: Dict[str, Any]) -> List[str]:
    findings = []

    feature_set = normalize_value(profile.get("feature-set", ""))
    action = normalize_value(profile.get("default-action", "")) or normalize_value(profile.get("scan-mode", ""))
    http = normalize_value(profile.get("http", ""))
    https = normalize_value(profile.get("https", ""))
    smtp = normalize_value(profile.get("smtp", ""))
    pop3 = normalize_value(profile.get("pop3", ""))
    imap = normalize_value(profile.get("imap", ""))
    ftp = normalize_value(profile.get("ftp", ""))
    cifs = normalize_value(profile.get("cifs", ""))
    sandbox = normalize_value(profile.get("fortisandbox", "")) or normalize_value(profile.get("scan", ""))
    outbreak = normalize_value(profile.get("outbreak-prevention", ""))
    log = normalize_value(profile.get("log", "")) or normalize_value(profile.get("log-malware", ""))

    if feature_set == "flow":
        findings.append("INFO: Flow-based AV inspection; proxy mode is usually more thorough when available.")

    if action and action.lower() in ("pass", "monitor"):
        findings.append("HIGH: Malware action is monitor/pass; infected files may pass through.")

    if http != "enable":
        findings.append("MEDIUM: HTTP not inspected by AV profile.")
    if https != "enable":
        findings.append("MEDIUM: HTTPS not inspected by AV profile.")
    if smtp != "enable":
        findings.append("INFO: SMTP not inspected by AV profile; verify if email is in use.")
    if pop3 != "enable":
        findings.append("INFO: POP3 not inspected by AV profile.")
    if imap != "enable":
        findings.append("INFO: IMAP not inspected by AV profile.")
    if ftp != "enable":
        findings.append("INFO: FTP not inspected by AV profile.")
    if cifs != "enable":
        findings.append("INFO: CIFS/SMB not inspected by AV profile.")

    if sandbox != "enable":
        findings.append("MEDIUM: FortiSandbox submission disabled; less zero-day protection.")
    if outbreak != "enable":
        findings.append("MEDIUM: Virus outbreak prevention disabled.")

    if log not in ("enable", "all", "malware"):
        findings.append("MEDIUM: AV logging may be disabled or limited.")

    return findings


# -----------------------------
# Weakness checks: system/admin/etc
# -----------------------------

def admin_weaknesses(admin: Dict[str, Any]) -> List[str]:
    findings = []

    name = normalize_value(admin.get("name", admin.get("_id", "")))
    accprofile = normalize_value(admin.get("accprofile", ""))
    two_factor = normalize_value(admin.get("two-factor", "")) or normalize_value(admin.get("twofactor", ""))
    trusthosts = [normalize_value(admin.get(f"trusthost{i}", "")) for i in range(1, 11)]
    timeout = normalize_value(admin.get("admintimeout", ""))

    if not any(th for th in trusthosts):
        findings.append(f"HIGH: Admin '{name}' has no trusted host restrictions.")

    if accprofile == "super_admin":
        findings.append(f"HIGH: Admin '{name}' uses full super_admin access; consider least privilege.")

    if not two_factor or two_factor in ("disable", "none"):
        findings.append(f"HIGH: Admin '{name}' does not use two-factor authentication.")

    if timeout and timeout.isdigit() and int(timeout) > 30:
        findings.append(f"INFO: Admin timeout for '{name}' is relatively long ({timeout} minutes).")

    return findings


def interface_weaknesses(intf: Dict[str, Any]) -> List[str]:
    findings = []

    name = normalize_value(intf.get("name", intf.get("_id", "")))
    allowaccess = normalize_value(intf.get("allowaccess", ""))
    role = normalize_value(intf.get("role", ""))
    ip = normalize_value(intf.get("ip", ""))

    aa = allowaccess.split()

    if "http" in aa:
        findings.append(f"HIGH: HTTP management enabled on interface '{name}'.")
    if "telnet" in aa:
        findings.append(f"HIGH: Telnet management enabled on interface '{name}'.")
    if role == "wan":
        if "https" in aa:
            findings.append(f"HIGH: HTTPS management enabled on WAN interface '{name}'.")
        if "ssh" in aa:
            findings.append(f"HIGH: SSH management enabled on WAN interface '{name}'.")
        if "ping" in aa:
            findings.append(f"INFO: Ping enabled on WAN interface '{name}'.")
    if not allowaccess:
        findings.append(f"INFO: No management access configured on interface '{name}' (may be safe).")

    return findings


def global_crypto_weaknesses(global_cfg: Dict[str, Any]) -> List[str]:
    findings = []

    strong_crypto = normalize_value(global_cfg.get("strong-crypto", ""))
    static_ciphers = normalize_value(global_cfg.get("ssl-static-key-ciphers", ""))
    dh_params = normalize_value(global_cfg.get("dh-params", ""))

    if strong_crypto != "enable":
        findings.append("HIGH: strong-crypto is not enabled globally.")
    if static_ciphers != "disable":
        findings.append("MEDIUM: ssl-static-key-ciphers not disabled; static key ciphers may be allowed.")
    try:
        if dh_params and int(dh_params) < 4096:
            findings.append(f"MEDIUM: dh-params set to {dh_params}; 8192 recommended for strongest security.")
    except ValueError:
        if dh_params:
            findings.append(f"INFO: dh-params is set to '{dh_params}', could not interpret size.")

    lock_thr = normalize_value(global_cfg.get("admin-lockout-threshold", ""))
    lock_dur = normalize_value(global_cfg.get("admin-lockout-duration", ""))
    admintimeout = normalize_value(global_cfg.get("admintimeout", ""))

    if not lock_thr or lock_thr == "0":
        findings.append("MEDIUM: admin lockout threshold not configured or zero.")
    if not lock_dur or lock_dur == "0":
        findings.append("MEDIUM: admin lockout duration not configured or zero.")
    if admintimeout and admintimeout.isdigit() and int(admintimeout) > 30:
        findings.append(f"INFO: global admintimeout is relatively long ({admintimeout} minutes).")

    return findings


def ntp_weaknesses(ntp: Dict[str, Any]) -> List[str]:
    findings = []

    ntpsync = normalize_value(ntp.get("ntpsync", ""))
    ntptype = normalize_value(ntp.get("type", ""))
    syncinterval = normalize_value(ntp.get("syncinterval", ""))
    source_ip = normalize_value(ntp.get("source-ip", ""))
    server_mode = normalize_value(ntp.get("server-mode", ""))
    auth = normalize_value(ntp.get("authentication", ""))
    ntpv3 = normalize_value(ntp.get("ntpv3", ""))

    servers = ntp.get("servers", []) or []

    if ntpsync != "enable":
        findings.append("MEDIUM: NTP sync is disabled.")
    if ntptype not in ("fortiguard", "custom"):
        findings.append("INFO: NTP type is not fortiguard or custom; verify configuration.")
    if ntptype == "custom":
        if not servers:
            findings.append("MEDIUM: Custom NTP type but no ntpserver entries configured.")
        elif len(servers) == 1:
            findings.append("INFO: Only one NTP server configured; consider redundancy.")
    if server_mode == "enable":
        findings.append("INFO: NTP server-mode enabled; verify if FortiGate should serve time.")

    if syncinterval and syncinterval.isdigit():
        if int(syncinterval) < 10:
            findings.append("INFO: NTP syncinterval is very short; may be unnecessary.")
        elif int(syncinterval) > 1440:
            findings.append("INFO: NTP syncinterval is very long; may reduce time accuracy.")

    if not source_ip:
        findings.append("INFO: NTP source-ip not set; consider using a stable management IP.")

    if auth == "enable":
        if not ntpv3:
            findings.append("MEDIUM: NTP authentication enabled but ntpv3 not enabled.")
    else:
        findings.append("INFO: NTP authentication disabled; enable if policy requires it.")

    return findings


def local_in_weaknesses(lip: Dict[str, Any]) -> List[str]:
    findings = []

    intf = normalize_value(lip.get("intf", ""))
    srcaddr = normalize_value(lip.get("srcaddr", ""))
    dstaddr = normalize_value(lip.get("dstaddr", ""))
    service = normalize_value(lip.get("service", ""))
    action = normalize_value(lip.get("action", ""))

    if not intf:
        findings.append("MEDIUM: Local-in-policy without specific interface.")
    if srcaddr in ("all", ""):
        findings.append("HIGH: Local-in-policy source is 'all'; very broad access.")
    if service in ("ALL", "all"):
        findings.append("MEDIUM: Local-in-policy service is ALL; consider narrowing services.")
    if action == "accept" and srcaddr in ("all", ""):
        findings.append("HIGH: Accept local-in-policy with broad source; management may be exposed.")

    return findings


# -----------------------------
# Report formatting (ASCII tables)
# -----------------------------

def ascii_table(rows: List[tuple], title: str = None) -> str:
    col1 = max(len(str(k)) for k, _ in rows) if rows else 10
    col2 = max(len(str(v)) for _, v in rows) if rows else 10
    col1 = max(col1, 18)
    col2 = max(col2, 30)
    width = col1 + col2 + 7

    lines = []
    top = "+" + "-" * (width - 2) + "+"
    lines.append(top)
    if title:
        t = title[:width - 4]
        lines.append("| " + t.center(width - 4) + " |")
        lines.append(top)
    for k, v in rows:
        k = str(k)
        v = str(v)
        lines.append(f"| {k.ljust(col1)} | {v.ljust(col2)} |")
    lines.append(top)
    return "\n".join(lines)


# -----------------------------
# Diagram generation (-d)
# -----------------------------

def build_policy_diagram(policy: Dict[str, Any],
                         interfaces: Dict[str, Dict[str, Any]],
                         ssl_profiles: Dict[str, Dict[str, Any]],
                         av_profiles: Dict[str, Dict[str, Any]]) -> str:
    srcintf = normalize_value(policy.get("srcintf", ""))
    dstintf = normalize_value(policy.get("dstintf", ""))
    policyid = normalize_value(policy.get("policyid", policy.get("_id", "")))
    name = normalize_value(policy.get("name", ""))

    src_intf_obj = interfaces.get(srcintf, {})
    dst_intf_obj = interfaces.get(dstintf, {})

    src_lines = []
    src_lines.append(f"[{srcintf} - {normalize_value(src_intf_obj.get('role', '')) or 'unknown'}]")
    src_lines.append(f"   +--> interface name: {srcintf}")
    src_lines.append(f"   +--> ip/mask: {normalize_value(src_intf_obj.get('ip', 'unknown'))}")
    src_lines.append(f"   +--> role: {normalize_value(src_intf_obj.get('role', 'unknown'))}")
    src_lines.append(f"   +--> administrative access: {normalize_value(src_intf_obj.get('allowaccess', 'none')) or 'none'}")
    src_lines.append(f"   +--> vlan: {normalize_value(src_intf_obj.get('vlanid', 'none')) or 'none'}")
    src_lines.append("   |")
    src_lines.append("   v")

    lines = []
    lines.extend(src_lines)
    lines.append(f"[Policy {policyid}: {name}]")
    lines.append(f"   +--> policy id: {policyid}")
    lines.append(f"   +--> policy name: {name}")
    lines.append(f"   +--> incoming interface: {srcintf}")
    lines.append(f"   +--> outgoing interface: {dstintf}")
    lines.append(f"   +--> source: {normalize_value(policy.get('srcaddr', 'all'))}")
    lines.append(f"   +--> destination: {normalize_value(policy.get('dstaddr', 'all'))}")
    lines.append(f"   +--> service: {normalize_value(policy.get('service', 'ALL'))}")
    lines.append(f"   +--> action: {normalize_value(policy.get('action', '')) or 'unknown'}")
    lines.append(f"   +--> nat: {normalize_value(policy.get('nat', '')) or 'disable'}")
    lines.append(f"   +--> schedule: {normalize_value(policy.get('schedule', 'always'))}")
    lines.append(f"   +--> log: {normalize_value(policy.get('logtraffic', '')) or 'unset'}")
    lines.append(f"   +--> exemption: (see web/dns filter profiles)")
    lines.append(f"   +--> special option: utm status -> {normalize_value(policy.get('utm-status', '')) or 'disable'}")
    lines.append("   |")

    ssl_name = normalize_value(policy.get("ssl-ssh-profile", ""))
    if ssl_name:
        ssl_obj = ssl_profiles.get(ssl_name, {})
        lines.append("   +--> SSL/SSH Profile")
        lines.append(f"   |      +--> profile name: {ssl_name}")
        lines.append(f"   |      +--> mode: {normalize_value(ssl_obj.get('inspection-method', 'unknown'))}")
        lines.append(f"   |      +--> CA certificate: {normalize_value(ssl_obj.get('caname', 'none'))}")
        lines.append(f"   |      +--> SNI check: {normalize_value(ssl_obj.get('sni-check', 'disable'))}")
        lines.append(f"   |      +--> untrusted certificates: {normalize_value(ssl_obj.get('untrusted-cert', 'allow'))}")
        lines.append(f"   |      +--> expired certificates: {normalize_value(ssl_obj.get('expired-cert', 'allow'))}")
        lines.append(f"   |      +--> invalid certificates: {normalize_value(ssl_obj.get('invalid-cert', 'allow'))}")
        lines.append(f"   |      +--> DNS over TLS: {normalize_value(ssl_obj.get('dns-over-tls', 'unknown'))}")
        lines.append(f"   |      +--> encrypted client hello: {normalize_value(ssl_obj.get('encrypted-client-hello', 'unknown'))}")
        lines.append(f"   |      +--> RPC over HTTPS: {normalize_value(ssl_obj.get('rpc-over-https', 'unknown'))}")
        lines.append(f"   |      +--> MAPI over HTTPS: {normalize_value(ssl_obj.get('mapi-over-https', 'unknown'))}")
        lines.append(f"   |      +--> SSH inspection: {normalize_value(ssl_obj.get('ssh', 'disable'))}")
        lines.append("   |")
    else:
        lines.append("   +--> SSL/SSH Profile")
        lines.append("   |      +--> profile name: (none)")
        lines.append("   |")

    av_name = normalize_value(policy.get("av-profile", ""))
    if av_name:
        av_obj = av_profiles.get(av_name, {})
        lines.append("   +--> Antivirus Profile")
        lines.append(f"   |      +--> profile name: {av_name}")
        lines.append(f"   |      +--> feature set: {normalize_value(av_obj.get('feature-set', '')) or 'unknown'}")
        lines.append(f"   |      +--> scan mode: {normalize_value(av_obj.get('scan-mode', '')) or 'unknown'}")
        lines.append(f"   |      +--> HTTP: {normalize_value(av_obj.get('http', '')) or 'unknown'}")
        lines.append(f"   |      +--> HTTPS: {normalize_value(av_obj.get('https', '')) or 'unknown'}")
        lines.append(f"   |      +--> SMTP: {normalize_value(av_obj.get('smtp', '')) or 'unknown'}")
        lines.append(f"   |      +--> POP3: {normalize_value(av_obj.get('pop3', '')) or 'unknown'}")
        lines.append(f"   |      +--> IMAP: {normalize_value(av_obj.get('imap', '')) or 'unknown'}")
        lines.append(f"   |      +--> FTP: {normalize_value(av_obj.get('ftp', '')) or 'unknown'}")
        lines.append(f"   |      +--> CIFS/SMB: {normalize_value(av_obj.get('cifs', '')) or 'unknown'}")
        lines.append(f"   |      +--> NNTP: {normalize_value(av_obj.get('nntp', '')) or 'unknown'}")
        lines.append(f"   |      +--> action: {normalize_value(av_obj.get('default-action', '')) or 'unknown'}")
        lines.append(f"   |      +--> FortiSandbox: {normalize_value(av_obj.get('fortisandbox', '')) or 'unknown'}")
        lines.append(f"   |      +--> outbreak prevention: {normalize_value(av_obj.get('outbreak-prevention', '')) or 'unknown'}")
        lines.append(f"   |      +--> quarantine: {normalize_value(av_obj.get('quarantine', '')) or 'unknown'}")
        lines.append("   |")
    else:
        lines.append("   +--> Antivirus Profile")
        lines.append("   |      +--> profile name: (none)")
        lines.append("   |")

    ips_name = normalize_value(policy.get("ips-sensor", ""))
    wf_name = normalize_value(policy.get("webfilter-profile", ""))
    app_name = normalize_value(policy.get("application-list", ""))
    dnsf_name = normalize_value(policy.get("dnsfilter-profile", ""))

    lines.append("   +--> IPS Profile")
    if ips_name:
        lines.append(f"   |      +--> profile name: {ips_name}")
        lines.append("   |      +--> action: (see IPS profile config)")
        lines.append("   |      +--> severity: (profile-defined)")
        lines.append("   |      +--> logging: (profile-defined)")
    else:
        lines.append("   |      +--> profile name: (none)")
    lines.append("   |")

    lines.append("   +--> Web Filter Profile")
    if wf_name:
        lines.append(f"   |      +--> profile name: {wf_name}")
        lines.append("   |      +--> category control: (profile-defined)")
        lines.append("   |      +--> safe search: (profile-defined)")
        lines.append("   |      +--> logging: (profile-defined)")
    else:
        lines.append("   |      +--> profile name: (none)")
    lines.append("   |")

    lines.append("   +--> App Control")
    if app_name:
        lines.append(f"   |      +--> profile name: {app_name}")
        lines.append("   |      +--> risky apps: (profile-defined)")
        lines.append("   |      +--> logging: (profile-defined)")
    else:
        lines.append("   |      +--> profile name: (none)")
    lines.append("   |")

    lines.append("   +--> DNS Filter")
    if dnsf_name:
        lines.append(f"   |      +--> profile name: {dnsf_name}")
        lines.append("   |      +--> malware/phishing: (profile-defined)")
        lines.append("   |      +--> logging: (profile-defined)")
    else:
        lines.append("   |      +--> profile name: (none)")
    lines.append("   |")

    lines.append("   +--> Logging")
    lines.append(f"   |      +--> FortiAnalyzer: (see log setting/global)")
    lines.append(f"   |      +--> Syslog: (see log setting/global)")
    lines.append(f"   |      +--> event log: enable")
    lines.append(f"   |      +--> admin audit: enable")
    lines.append(f"   |      +--> threat log: enable")
    lines.append("   |")

    lines.append("   +--> Policy Extras")
    lines.append(f"   |      +--> NAT: {normalize_value(policy.get('nat', '')) or 'disable'}")
    lines.append("   |      +--> session helper: default")
    lines.append("   |      +--> routing note: default or specific route via outgoing interface")
    lines.append(f"   |      +--> security profile mode: {normalize_value(policy.get('utm-status', '')) or 'disable'}")
    lines.append(f"   |      +--> logging: {normalize_value(policy.get('logtraffic', '')) or 'unset'}")
    lines.append("   |")
    lines.append("   v")

    lines.append(f"[{dstintf} - {normalize_value(dst_intf_obj.get('role', '')) or 'unknown'}]")
    lines.append(f"   +--> interface name: {dstintf}")
    lines.append(f"   +--> role: {normalize_value(dst_intf_obj.get('role', 'unknown'))}")
    lines.append(f"   +--> administrative access: {normalize_value(dst_intf_obj.get('allowaccess', 'none')) or 'none'}")
    lines.append(f"   +--> source NAT: {normalize_value(policy.get('nat', '')) or 'disable'}")
    lines.append(f"   +--> next hop: default gateway or specific route")

    return "\n".join(lines)


# -----------------------------
# Main report generators
# -----------------------------

def generate_firewall_report(policies: List[Dict[str, Any]], out_path: Path):
    report_lines = []
    report_lines.append("FortiGate Firewall Policy Analysis")
    report_lines.append(f"Policies found: {len(policies)}")
    report_lines.append("=" * 80)

    for i, p in enumerate(policies, 1):
        rows = [
            ("Policy ID", normalize_value(p.get("policyid", p.get("_id", "")))),
            ("Name", normalize_value(p.get("name", ""))),
            ("Action", normalize_value(p.get("action", ""))),
            ("Src Interface", normalize_value(p.get("srcintf", ""))),
            ("Dst Interface", normalize_value(p.get("dstintf", ""))),
            ("Src Address", normalize_value(p.get("srcaddr", ""))),
            ("Dst Address", normalize_value(p.get("dstaddr", ""))),
            ("Service", normalize_value(p.get("service", ""))),
            ("Schedule", normalize_value(p.get("schedule", ""))),
            ("NAT", normalize_value(p.get("nat", ""))),
            ("UTM Status", normalize_value(p.get("utm-status", ""))),
            ("IPS Sensor", normalize_value(p.get("ips-sensor", ""))),
            ("AV Profile", normalize_value(p.get("av-profile", ""))),
            ("Web Filter", normalize_value(p.get("webfilter-profile", ""))),
            ("DNS Filter", normalize_value(p.get("dnsfilter-profile", ""))),
            ("App Control", normalize_value(p.get("application-list", ""))),
            ("SSL/SSH Profile", normalize_value(p.get("ssl-ssh-profile", ""))),
            ("Log Traffic", normalize_value(p.get("logtraffic", ""))),
            ("Comments", normalize_value(p.get("comments", ""))),
        ]
        report_lines.append(f"\nPolicy #{i}")
        report_lines.append(ascii_table(rows))
        w = firewall_weaknesses(p)
        report_lines.append("Weaknesses:")
        if w:
            for item in w:
                report_lines.append(f"- {item}")
        else:
            report_lines.append("- None")
        report_lines.append("-" * 80)

    out_path.write_text("\n".join(report_lines), encoding="utf-8")


def generate_ssl_report(profiles: List[Dict[str, Any]], out_path: Path):
    lines = []
    lines.append("FortiGate SSL/SSH Inspection Profile Analysis")
    lines.append(f"Profiles found: {len(profiles)}")
    lines.append("=" * 80)

    for i, prof in enumerate(profiles, 1):
        name = normalize_value(prof.get("name", prof.get("_id", "")))
        rows = [
            ("Profile Name", name),
            ("Comments", normalize_value(prof.get("comments", ""))),
            ("Inspection Method", normalize_value(prof.get("inspection-method", ""))),
            ("CA Name", normalize_value(prof.get("caname", ""))),
            ("Inspect All Ports", normalize_value(prof.get("inspect-all-ports", ""))),
            ("SNI Check", normalize_value(prof.get("sni-check", ""))),
            ("Untrusted Cert", normalize_value(prof.get("untrusted-cert", ""))),
            ("Expired Cert", normalize_value(prof.get("expired-cert", ""))),
            ("Invalid Cert", normalize_value(prof.get("invalid-cert", ""))),
            ("Log SSL Anomalies", normalize_value(prof.get("log-ssl-anomalies", ""))),
        ]
        lines.append(f"\nProfile #{i}")
        lines.append(ascii_table(rows))
        w = ssl_weaknesses(prof)
        lines.append("Weaknesses:")
        if w:
            for item in w:
                lines.append(f"- {item}")
        else:
            lines.append("- None")
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_av_report(profiles: List[Dict[str, Any]], out_path: Path):
    lines = []
    lines.append("FortiGate AntiVirus Profile Analysis")
    lines.append(f"Profiles found: {len(profiles)}")
    lines.append("=" * 80)

    for i, prof in enumerate(profiles, 1):
        name = normalize_value(prof.get("name", prof.get("_id", "")))
        rows = [
            ("Profile Name", name),
            ("Feature Set", normalize_value(prof.get("feature-set", ""))),
            ("Scan Mode", normalize_value(prof.get("scan-mode", ""))),
            ("HTTP", normalize_value(prof.get("http", ""))),
            ("HTTPS", normalize_value(prof.get("https", ""))),
            ("SMTP", normalize_value(prof.get("smtp", ""))),
            ("POP3", normalize_value(prof.get("pop3", ""))),
            ("IMAP", normalize_value(prof.get("imap", ""))),
            ("FTP", normalize_value(prof.get("ftp", ""))),
            ("CIFS/SMB", normalize_value(prof.get("cifs", ""))),
            ("NNTP", normalize_value(prof.get("nntp", ""))),
            ("Default Action", normalize_value(prof.get("default-action", ""))),
            ("FortiSandbox", normalize_value(prof.get("fortisandbox", ""))),
            ("Outbreak Prevention", normalize_value(prof.get("outbreak-prevention", ""))),
            ("Quarantine", normalize_value(prof.get("quarantine", ""))),
        ]
        lines.append(f"\nProfile #{i}")
        lines.append(ascii_table(rows))
        w = av_weaknesses(prof)
        lines.append("Weaknesses:")
        if w:
            for item in w:
                lines.append(f"- {item}")
        else:
            lines.append("- None")
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_system_report(admins: List[Dict[str, Any]],
                           interfaces: List[Dict[str, Any]],
                           global_cfg: Dict[str, Any],
                           ntp_cfg: Dict[str, Any],
                           local_in: List[Dict[str, Any]],
                           out_path: Path):
    lines = []
    lines.append("FortiGate System / Management / Crypto / NTP / Local-in Analysis")
    lines.append("=" * 80)

    lines.append("\n=== Administrator Accounts ===")
    for i, adm in enumerate(admins, 1):
        name = normalize_value(adm.get("name", adm.get("_id", "")))
        rows = [
            ("Admin Name", name),
            ("Accprofile", normalize_value(adm.get("accprofile", ""))),
            ("Two-Factor", normalize_value(adm.get("two-factor", ""))),
        ]
        for n in range(1, 5):
            rows.append((f"Trusthost{n}", normalize_value(adm.get(f"trusthost{n}", ""))))
        lines.append(f"\nAdmin #{i}")
        lines.append(ascii_table(rows))
        w = admin_weaknesses(adm)
        lines.append("Weaknesses:")
        if w:
            for item in w:
                lines.append(f"- {item}")
        else:
            lines.append("- None")
        lines.append("-" * 80)

    lines.append("\n=== Interfaces ===")
    for i, intf in enumerate(interfaces, 1):
        name = normalize_value(intf.get("name", intf.get("_id", "")))
        rows = [
            ("Interface Name", name),
            ("IP/Mask", normalize_value(intf.get("ip", ""))),
            ("Role", normalize_value(intf.get("role", ""))),
            ("Allowaccess", normalize_value(intf.get("allowaccess", ""))),
        ]
        lines.append(f"\nInterface #{i}")
        lines.append(ascii_table(rows))
        w = interface_weaknesses(intf)
        lines.append("Weaknesses:")
        if w:
            for item in w:
                lines.append(f"- {item}")
        else:
            lines.append("- None")
        lines.append("-" * 80)

    lines.append("\n=== Global Crypto / Admin Settings ===")
    rows = [
        ("Strong Crypto", normalize_value(global_cfg.get("strong-crypto", ""))),
        ("SSL Static Key Ciphers", normalize_value(global_cfg.get("ssl-static-key-ciphers", ""))),
        ("DH Params", normalize_value(global_cfg.get("dh-params", ""))),
        ("Admin Timeout", normalize_value(global_cfg.get("admintimeout", ""))),
        ("Lockout Threshold", normalize_value(global_cfg.get("admin-lockout-threshold", ""))),
        ("Lockout Duration", normalize_value(global_cfg.get("admin-lockout-duration", ""))),
    ]
    lines.append(ascii_table(rows))
    w = global_crypto_weaknesses(global_cfg)
    lines.append("Weaknesses:")
    if w:
        for item in w:
            lines.append(f"- {item}")
    else:
        lines.append("- None")
    lines.append("-" * 80)

    lines.append("\n=== NTP Settings ===")
    rows = [
        ("NTP Sync", normalize_value(ntp_cfg.get("ntpsync", ""))),
        ("Type", normalize_value(ntp_cfg.get("type", ""))),
        ("Sync Interval", normalize_value(ntp_cfg.get("syncinterval", ""))),
        ("Source IP", normalize_value(ntp_cfg.get("source-ip", ""))),
        ("Server Mode", normalize_value(ntp_cfg.get("server-mode", ""))),
        ("Authentication", normalize_value(ntp_cfg.get("authentication", ""))),
        ("NTPv3", normalize_value(ntp_cfg.get("ntpv3", ""))),
        ("Servers Count", str(len(ntp_cfg.get("servers", [])))),
    ]
    lines.append(ascii_table(rows))
    w = ntp_weaknesses(ntp_cfg)
    lines.append("Weaknesses:")
    if w:
        for item in w:
            lines.append(f"- {item}")
    else:
        lines.append("- None")
    lines.append("-" * 80)

    lines.append("\n=== Local-in Policies ===")
    for i, lip in enumerate(local_in, 1):
        rows = [
            ("Interface", normalize_value(lip.get("intf", ""))),
            ("Srcaddr", normalize_value(lip.get("srcaddr", ""))),
            ("Dstaddr", normalize_value(lip.get("dstaddr", ""))),
            ("Service", normalize_value(lip.get("service", ""))),
            ("Action", normalize_value(lip.get("action", ""))),
            ("Schedule", normalize_value(lip.get("schedule", ""))),
        ]
        lines.append(f"\nLocal-in Policy #{i}")
        lines.append(ascii_table(rows))
        w = local_in_weaknesses(lip)
        lines.append("Weaknesses:")
        if w:
            for item in w:
                lines.append(f"- {item}")
        else:
            lines.append("- None")
        lines.append("-" * 80)

    out_path.write_text("\n".join(lines), encoding="utf-8")


def generate_diagram(policies: List[Dict[str, Any]],
                     interfaces: List[Dict[str, Any]],
                     ssl_profiles: List[Dict[str, Any]],
                     av_profiles: List[Dict[str, Any]],
                     out_path: Path):
    intf_map = {normalize_value(i.get("name", i.get("_id", ""))): i for i in interfaces}
    ssl_map = {normalize_value(p.get("name", p.get("_id", ""))): p for p in ssl_profiles}
    av_map = {normalize_value(p.get("name", p.get("_id", ""))): p for p in av_profiles}

    blocks = []
    for p in policies:
        blocks.append(build_policy_diagram(p, intf_map, ssl_map, av_map))
        blocks.append("")

    out_path.write_text("\n".join(blocks), encoding="utf-8")


# -----------------------------
# CLI
# -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FortiGate UTM and system audit tool (firewall, SSL, AV, system, diagram)."
    )
    parser.add_argument("-c", "--config", required=True, help="FortiGate config file (text backup)")
    parser.add_argument("-f", action="store_true", help="Analyze firewall policies")
    parser.add_argument("-i", action="store_true", help="Analyze SSL/SSH inspection profiles")
    parser.add_argument("-av", action="store_true", help="Analyze AntiVirus profiles")
    parser.add_argument("-s", action="store_true", help="System/admin/interface/crypto/NTP/local-in audit")
    parser.add_argument("-d", action="store_true", help="Generate UTM flow diagram for each firewall rule")

    args = parser.parse_args()

    cfg_text = read_config(args.config)
    base = Path(args.config).name

    firewall_policies = parse_firewall_policies(cfg_text)
    ssl_profiles = parse_ssl_profiles(cfg_text)
    av_profiles = parse_av_profiles(cfg_text)
    admins = parse_admins(cfg_text)
    interfaces = parse_interfaces(cfg_text)
    global_cfg = parse_system_global(cfg_text)
    ntp_cfg = parse_ntp(cfg_text)
    local_in = parse_local_in(cfg_text)

    if args.f:
        out = Path(f"{base}_firewall_report.txt")
        generate_firewall_report(firewall_policies, out)
        print(f"[+] Firewall report written to {out}")

    if args.i:
        out = Path(f"{base}_ssl_inspection_report.txt")
        generate_ssl_report(ssl_profiles, out)
        print(f"[+] SSL inspection report written to {out}")

    if args.av:
        out = Path(f"{base}_antivirus_report.txt")
        generate_av_report(av_profiles, out)
        print(f"[+] AntiVirus report written to {out}")

    if args.s:
        out = Path(f"{base}_system_report.txt")
        generate_system_report(admins, interfaces, global_cfg, ntp_cfg, local_in, out)
        print(f"[+] System report written to {out}")

    if args.d:
        out = Path(f"{base}_diagram.txt")
        generate_diagram(firewall_policies, interfaces, ssl_profiles, av_profiles, out)
        print(f"[+] Diagram written to {out}")

    if not any([args.f, args.i, args.av, args.s, args.d]):
        print("[!] No report flags specified. Use -f -i -av -s -d or any combination.")
        print("    Run with --help for full usage.")


if __name__ == "__main__":
    main()
