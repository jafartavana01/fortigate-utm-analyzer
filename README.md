# 🔐 FortiGate UTM Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-FortiOS%206.x%20%7C%207.x-red?style=for-the-badge&logo=fortinet&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Checks-100%2B-orange?style=for-the-badge" />
</p>

<p align="center">
  <strong>A zero-dependency Python CLI for deep security auditing of FortiGate firewall configurations.</strong><br/>
  Parse a <code>show full-configuration</code> backup and generate severity-tagged reports across<br/>
  13 audit domains — firewall policies, SSL/TLS inspection, AV, IPS, VPN, SSL-VPN, HA, logging, and more —<br/>
  with a scored executive summary and JSON export.
</p>

---

## 📋 Table of Contents

- [What's New in v2.0](#-whats-new-in-v20)
- [Overview](#-overview)
- [Audit Domains](#-audit-domains)
- [Security Checks Reference](#-security-checks-reference)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)
- [Sample Output](#-sample-output)
- [Architecture](#-architecture)
- [Extending the Tool](#-extending-the-tool)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Author](#-author)
- [License](#-license)

---

## 🆕 What's New in v2.0

v2.0 is a major expansion — from 40 checks across 5 domains to **100+ checks across 13 domains**.

| Area | v1.0 | v2.0 |
|---|---|---|
| Firewall policies | ✅ basic UTM/log checks | ✅ + ANY-ANY-ANY detection, WAN-to-LAN inbound, DLP/CASB, schedule, packet capture flag, disabled policy detection |
| SSL/SSH inspection | ✅ basic cert checks | ✅ + TLS minimum version, Encrypted Client Hello, DNS-over-TLS, RPC/MAPI-over-HTTPS, revoked cert, blacklist blocking |
| Antivirus | ✅ protocol coverage | ✅ + Content Disarm & Reconstruction (CDR), quarantine check |
| IPS sensors | ❌ | ✅ botnet C2 scanning, malicious URL blocking, extended DB |
| Web filter | ❌ | ✅ log-all-url, safe search, user override detection, content logging |
| App control | ❌ | ✅ unknown app action, P2P blocking, logging |
| DNS filter | ❌ | ✅ botnet domain blocking, FortiGuard DNS rating, safe search DNS |
| IPsec VPN | ❌ | ✅ IKEv1/v2, aggressive mode, weak ciphers (DES/3DES/MD5), DH groups, PSK length, PFS, rekey, key lifetime |
| SSL-VPN | ❌ | ✅ TLS version, login brute-force, idle/auth timeout, split tunneling, source restriction, self-signed cert |
| HA | ❌ | ✅ cluster password, heartbeat encryption, interface monitoring, sync config |
| Logging | ❌ | ✅ FortiAnalyzer status/encryption/reliability, syslog TLS, UDP vs TCP, invalid packet logging |
| System hardening | ✅ basic | ✅ + pre/post-login banners, HTTPS redirect, self-signed GUI cert, password policy, hostname fingerprinting, revision backup, session timeout=0 detection |
| Executive summary | ❌ | ✅ CRITICAL/HIGH/MEDIUM/INFO counts by section, risk score, JSON export |
| `--all` flag | ❌ | ✅ single flag runs everything |

---

## 🔍 Overview

FortiGate firewalls power many enterprise perimeters. But even a licensed, running FortiGate can be dangerously misconfigured — accept policies with UTM completely disabled, IKEv1 aggressive-mode VPNs with short PSKs, SSL-VPN with no login lockout, admin accounts with no 2FA or trust-host restrictions, split tunneling sending user traffic outside the tunnel, HA heartbeat in cleartext, FortiAnalyzer logging disabled.

This tool automates the discovery of all of that. Point it at a plain-text FortiGate config backup and get structured, severity-tagged reports in seconds — no Python packages to install, no network access required, no cloud.

```bash
python3 utm.py -c firewall.conf --all
```

---

## 🛡️ Audit Domains

| Domain | Config Sections Parsed | Flag |
|---|---|---|
| Firewall Policies | `config firewall policy` | `-f` |
| SSL/SSH Inspection | `config firewall ssl-ssh-profile` | `-i` |
| Antivirus Profiles | `config antivirus profile` | `-av` |
| IPS Sensors | `config ips sensor` | `-ips` |
| Web Filter Profiles | `config webfilter profile` | `-wf` |
| App Control Profiles | `config application list` | `-app` |
| DNS Filter Profiles | `config dnsfilter profile` | `-dns` |
| IPsec VPN | `config vpn ipsec phase1-interface` + `phase2-interface` | `-vpn` |
| SSL-VPN | `config vpn ssl settings` + `config vpn ssl web portal` | `-sslvpn` |
| High Availability | `config system ha` | `-ha` |
| Logging & SIEM | `config log fortianalyzer setting` + `log syslogd setting` + `log setting` | `-log` |
| System Hardening | `config system admin` + `interface` + `global` + `ntp` + `local-in-policy` | `-s` |
| UTM Flow Diagrams | All of the above | `-d` |
| Executive Summary | All enabled sections | `--summary` |

---

## 🔬 Security Checks Reference

### Firewall Policy Checks (`-f`)

| Severity | Finding |
|---|---|
| `CRITICAL` | ANY-ANY-ANY accept policy |
| `HIGH` | UTM disabled on accept policy |
| `HIGH` | No IPS sensor on accept policy |
| `HIGH` | No antivirus profile on accept policy |
| `HIGH` | No SSL/SSH inspection on accept policy |
| `HIGH` | Traffic logging completely disabled |
| `HIGH` | Inbound WAN-to-LAN accept policy detected |
| `MEDIUM` | No web filter profile |
| `MEDIUM` | No DNS filter profile |
| `MEDIUM` | No application control profile |
| `MEDIUM` | No DLP profile |
| `MEDIUM` | Source address is 'all' |
| `MEDIUM` | Service set to ALL |
| `MEDIUM` | Packet capture enabled (debug artifact in production) |
| `INFO` | Log-traffic-start not enabled |
| `INFO` | No policy comment/description |
| `INFO` | Policy is disabled |
| `INFO` | Policy active 24/7 with no schedule |

### SSL/SSH Inspection Checks (`-i`)

| Severity | Finding |
|---|---|
| `HIGH` | Full/deep inspection without CA certificate |
| `HIGH` | Untrusted certificates set to allow |
| `HIGH` | Invalid certificates set to allow |
| `HIGH` | Revoked certificate action set to allow |
| `HIGH` | TLS minimum version below 1.2 |
| `MEDIUM` | Certificate-only inspection (no decryption) |
| `MEDIUM` | Inspection mode not configured |
| `MEDIUM` | SNI checking disabled |
| `MEDIUM` | Expired certificates not blocked |
| `MEDIUM` | Blacklisted certificate blocking disabled |
| `MEDIUM` | TLS minimum version not set (downgrade possible) |
| `MEDIUM` | Encrypted Client Hello not handled |
| `MEDIUM` | DNS-over-TLS not blocked or inspected |
| `MEDIUM` | SSL anomaly logging disabled |
| `INFO` | TLS 1.2 minimum (TLS 1.3 preferred) |
| `INFO` | RPC-over-HTTPS not blocked |
| `INFO` | MAPI-over-HTTPS not blocked |

### Antivirus Checks (`-av`)

| Severity | Finding |
|---|---|
| `HIGH` | Malware action is monitor or pass |
| `MEDIUM` | HTTP / HTTPS not inspected |
| `MEDIUM` | CIFS/SMB not inspected |
| `MEDIUM` | FortiSandbox disabled |
| `MEDIUM` | Outbreak prevention disabled |
| `MEDIUM` | Quarantine disabled |
| `MEDIUM` | Content Disarm & Reconstruction (CDR) disabled |
| `MEDIUM` | AV logging not enabled |
| `INFO` | Flow-based mode (proxy preferred) |
| `INFO` | SMTP / POP3 / IMAP / FTP / NNTP not inspected |

### IPS Sensor Checks (`-ips`)

| Severity | Finding |
|---|---|
| `HIGH` | Botnet C2 connection scanning disabled |
| `MEDIUM` | Botnet C2 in monitor-only mode |
| `MEDIUM` | Malicious URL blocking disabled |
| `INFO` | Extended signature database not enabled |

### Web Filter Checks (`-wf`)

| Severity | Finding |
|---|---|
| `MEDIUM` | Log-all-URL disabled |
| `MEDIUM` | User override permitted (blocked categories bypassable) |
| `INFO` | Safe search not enforced |
| `INFO` | Web content log disabled |

### App Control Checks (`-app`)

| Severity | Finding |
|---|---|
| `MEDIUM` | Unknown applications permitted |
| `MEDIUM` | Application logging disabled |
| `INFO` | P2P block list not configured |

### DNS Filter Checks (`-dns`)

| Severity | Finding |
|---|---|
| `HIGH` | Botnet domain blocking disabled |
| `MEDIUM` | FortiGuard DNS rating not enabled |
| `MEDIUM` | Log-all-domain disabled |
| `INFO` | Safe search DNS enforcement not enabled |

### IPsec VPN Checks (`-vpn`)

| Severity | Finding |
|---|---|
| `HIGH` | IKEv1 aggressive mode (PSK hash exposed, offline crackable) |
| `HIGH` | Weak encryption: DES / 3DES / MD5 in IKE proposal |
| `HIGH` | DH group below 2048-bit (groups 1, 2, 5) |
| `HIGH` | PSK shorter than 20 characters |
| `HIGH` | Weak algorithm in ESP proposal (Phase2) |
| `HIGH` | PFS (Perfect Forward Secrecy) disabled on Phase2 |
| `MEDIUM` | IKEv1 in use (IKEv2 recommended) |
| `MEDIUM` | PSK authentication (certificate-based preferred) |
| `MEDIUM` | IKE key lifetime exceeds 24 hours |
| `MEDIUM` | Phase2 key lifetime exceeds 8 hours |
| `MEDIUM` | PFS DH group is weak |
| `INFO` | IKE version not explicitly set |
| `INFO` | Dead Peer Detection (DPD) disabled |
| `INFO` | Rekey disabled |

### SSL-VPN Checks (`-sslvpn`)

| Severity | Finding |
|---|---|
| `HIGH` | TLS 1.0 or 1.1 permitted |
| `HIGH` | Login attempt limit is 0 (no brute-force protection) |
| `HIGH` | Idle timeout is 0 (sessions never expire) |
| `HIGH` | Split tunneling enabled on portal |
| `MEDIUM` | Self-signed server certificate |
| `MEDIUM` | Login block time too short |
| `MEDIUM` | Auth timeout too long |
| `MEDIUM` | Source address not restricted |
| `INFO` | Default port 443 (easily scanned) |

### HA Checks (`-ha`)

| Severity | Finding |
|---|---|
| `HIGH` | No HA cluster password |
| `MEDIUM` | HA heartbeat traffic not encrypted |
| `MEDIUM` | Config sync disabled |
| `MEDIUM` | Interface monitoring not configured |
| `MEDIUM` | HA cluster password too short |
| `INFO` | Standalone mode (no redundancy) |
| `INFO` | Slow heartbeat interval |

### Logging Checks (`-log`)

| Severity | Finding |
|---|---|
| `MEDIUM` | FortiAnalyzer logging disabled |
| `MEDIUM` | FortiAnalyzer server not configured |
| `MEDIUM` | FortiAnalyzer log encryption low or disabled |
| `MEDIUM` | Syslog server not configured |
| `MEDIUM` | Syslog using UDP (lossy) |
| `INFO` | FortiAnalyzer reliable delivery (TCP) not enabled |
| `INFO` | Syslog not using TLS |
| `INFO` | Syslog disabled |
| `INFO` | log-invalid-packet not enabled |

### System Hardening Checks (`-s`)

| Severity | Finding |
|---|---|
| `CRITICAL` | DH params below 2048 bits |
| `HIGH` | Admin session timeout = 0 (never expires) |
| `HIGH` | No trusted host restrictions on admin |
| `HIGH` | Trusthost set to 0.0.0.0/0 |
| `HIGH` | super_admin profile in use |
| `HIGH` | Two-factor authentication not enabled |
| `HIGH` | Weak or default password detected |
| `HIGH` | strong-crypto disabled |
| `HIGH` | Admin lockout threshold = 0 |
| `HIGH` | Admin lockout duration = 0 |
| `HIGH` | HTTP or Telnet on any interface |
| `HIGH` | HTTPS / SSH / SNMP on WAN interface |
| `HIGH` | Security Fabric on WAN interface |
| `HIGH` | Local-in-policy ACCEPT from source 'all' |
| `MEDIUM` | SSL static key ciphers not disabled |
| `MEDIUM` | DH params below 4096 bits |
| `MEDIUM` | Admin lockout threshold > 5 |
| `MEDIUM` | Admin lockout duration < 60 seconds |
| `MEDIUM` | Admin session timeout > 60 min |
| `MEDIUM` | Admin password policy not enabled |
| `MEDIUM` | HTTPS redirect not enabled |
| `MEDIUM` | Local-in-policy service = ALL |
| `INFO` | Pre/post-login banner disabled |
| `INFO` | Self-signed GUI management certificate |
| `INFO` | Default hostname (fingerprinting risk) |
| `INFO` | Revision auto-backup disabled |
| `INFO` | Force password change not set |
| `INFO` | Ping on WAN interface |

---

## 📦 Installation

No dependencies. Python 3.8+ only.

```bash
git clone https://github.com/jafartavana01/fortigate-utm-analyzer.git
cd fortigate-utm-analyzer
python3 utm.py --help
```

**Optional — system-wide alias (Linux/macOS):**
```bash
chmod +x utm.py
sudo ln -s $(pwd)/utm.py /usr/local/bin/fg-audit
fg-audit --help
```

---

## 🚀 Usage

### Syntax

```bash
python3 utm.py -c <config_file> [flags]
```

### Flags

| Flag | Description |
|---|---|
| `-c / --config` | **Required.** Path to FortiGate config file |
| `-f` | Firewall policy audit |
| `-i` | SSL/SSH inspection profile audit |
| `-av` | Antivirus profile audit |
| `-ips` | IPS sensor audit |
| `-wf` | Web filter profile audit |
| `-app` | Application control profile audit |
| `-dns` | DNS filter profile audit |
| `-vpn` | IPsec VPN Phase1 + Phase2 audit |
| `-sslvpn` | SSL-VPN settings + portal audit |
| `-ha` | HA configuration audit |
| `-log` | Logging / FortiAnalyzer / syslog audit |
| `-s` | System hardening (admin, interface, global, NTP, local-in) |
| `-d` | UTM topology diagram per policy |
| `--summary` | Executive summary with risk score + JSON export |
| `--all` | Run every audit module |

### Examples

```bash
# Full audit — everything at once
python3 utm.py -c firewall.conf --all

# Core security posture (most common use)
python3 utm.py -c firewall.conf -f -i -av -s --summary

# VPN-focused audit
python3 utm.py -c firewall.conf -vpn -sslvpn --summary

# UTM profile deep-dive
python3 utm.py -c firewall.conf -ips -wf -app -dns

# Quick test with bundled sample config
python3 utm.py -c sample_config.conf --all
```

### Getting the Config from FortiGate

```
# FortiGate CLI
show full-configuration
```

Or via GUI: **System → Backup → Configuration**.

---

## 📁 Output Files

All outputs written to the current directory, named from the config file:

| Flag | Output File |
|---|---|
| `-f` | `<config>_firewall_report.txt` |
| `-i` | `<config>_ssl_inspection_report.txt` |
| `-av` | `<config>_antivirus_report.txt` |
| `-ips` / `-wf` / `-app` / `-dns` | `<config>_utm_profiles_report.txt` |
| `-vpn` | `<config>_vpn_report.txt` |
| `-sslvpn` | `<config>_sslvpn_report.txt` |
| `-ha` | `<config>_ha_report.txt` |
| `-log` | `<config>_logging_report.txt` |
| `-s` | `<config>_system_report.txt` |
| `-d` | `<config>_diagram.txt` |
| `--summary` | `<config>_SUMMARY.txt` + `<config>_SUMMARY.json` |

---

## 📊 Sample Output

Running `--all` against the bundled `sample_config.conf` (intentionally misconfigured for demo):

```
================================================================================
================= FORTIGATE SECURITY AUDIT — EXECUTIVE SUMMARY =================
================================================================================
  Config file : sample_config.conf
  Risk rating : CRITICAL
  Risk score  : 486.5  (CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5)
  Total finds : 176

  CRITICAL       5
  HIGH          56
  MEDIUM        66
  INFO          49
================================================================================

  FINDINGS BY SECTION:
  ------------------------------------------------------------------------------
  Section                         CRIT  HIGH   MED  INFO  TOTAL
  ------------------------------------------------------------------------------
  Admin Accounts                     0     6     0     2      8
  Antivirus Profiles                 0     0     8     5     13
  App Control                        0     0     2     1      3
  DNS Filter                         0     1     2     1      4
  Firewall Policies                  3    16    13    19     51
  Global Hardening                   1     3     4     5     13
  HA Config                          0     1     3     1      5
  IPS Sensors                        0     0     2     1      3
  Interfaces                         0     7     1     0      8
  Local-in                           1     1     2     0      4
  Logging                            0     0     2     2      4
  NTP                                0     0     1     2      3
  SSL Inspection                     0     6    15     4     25
  SSL-VPN                            0     3     4     1      8
  SSL-VPN Portals                    0     1     0     2      3
  VPN Phase1                         0     7     4     1     12
  VPN Phase2                         0     4     1     0      5
  Web Filter                         0     0     2     2      4
  ------------------------------------------------------------------------------

  CRITICAL & HIGH FINDINGS:
  [Firewall Policies]  CRITICAL: ANY-ANY-ANY accept policy — maximally permissive rule; full audit required.
  [Firewall Policies]  HIGH: No IPS sensor attached; exploit traffic passes uninspected.
  [VPN Phase1]  HIGH: IKEv1 aggressive mode — PSK hash exposed in cleartext; offline cracking possible.
  [VPN Phase1]  HIGH: weak algorithm 'DES' in IKE proposal — use AES256+SHA256 or better.
  [VPN Phase2]  HIGH: Perfect Forward Secrecy (PFS) disabled — session key compromise exposes all past traffic.
  [SSL-VPN]  HIGH: login attempt limit is 0 — brute-force protection disabled.
  [SSL-VPN]  HIGH: idle timeout is 0 — idle sessions persist indefinitely.
  [Interfaces]  HIGH: Interface 'wan1' (WAN): SNMP accessible from internet — community string exposure risk.
  [Global Hardening]  CRITICAL: DH params 1024 bits — critically weak; upgrade to 4096 minimum.
  [Local-in]  CRITICAL: ACCEPT local-in-policy from 'all' sources — FortiGate control plane is broadly exposed.
  ...
================================================================================
```

The `--summary` flag also writes a `_SUMMARY.json` machine-readable file for SIEM/automation ingestion.

---

## 🗺️ UTM Flow Diagram (`-d`)

Each firewall policy generates an ASCII topology block:

```
[port1 - lan]
   +--> ip/mask: 192.168.1.1 255.255.255.0
   +--> allowaccess: ping https
   |
   v
[Policy 1: LAN_to_Internet]
   +--> src: all
   +--> dst: all
   +--> action: accept
   +--> nat: enable
   +--> utm: enable
   |
   +--> SSL/SSH Profile
   |      name: certificate-inspection
   |      mode: certificate-inspection
   |      SNI: strict
   |      untrusted: block
   |      min-TLS: tls-1.2
   |
   +--> Antivirus
   |      name: strict-av
   |      sandbox: enable
   |      outbreak: enable
   |      CDR: enable
   |
   +--> IPS: default-ips
   +--> WebFilter: corporate-policy
   +--> AppControl: strict-app
   +--> DNSFilter: secure-dns
   +--> DLP: dlp-profile
   |
   v
[wan1 - wan]
   +--> ip: 203.0.113.1 255.255.255.0
   +--> allowaccess: none
```

---

## 🏗️ Architecture

Single-file, zero external dependencies. Pure Python 3.8+ stdlib (`argparse`, `pathlib`, `re`, `json`, `typing`).

```
utm.py
├── Generic helpers        read_config, normalize_value, parse_set_line
├── Block parsers          extract_block (generic), extract_flat_block
│                          parse_firewall_policies, parse_ssl_profiles, parse_av_profiles,
│                          parse_ips_sensors, parse_wf_profiles, parse_app_profiles,
│                          parse_dns_profiles, parse_admins, parse_interfaces,
│                          parse_system_global, parse_ntp, parse_local_in,
│                          parse_vpn_phase1, parse_vpn_phase2, parse_ha,
│                          parse_log_fortianalyzer, parse_log_syslogd, parse_log_setting,
│                          parse_ssl_vpn_settings, parse_ssl_vpn_web_portals
├── Weakness functions     firewall_weaknesses, ssl_weaknesses, av_weaknesses,
│                          ips_weaknesses, wf_weaknesses, app_weaknesses, dns_weaknesses,
│                          admin_weaknesses, interface_weaknesses, global_crypto_weaknesses,
│                          ntp_weaknesses, local_in_weaknesses, vpn_phase1_weaknesses,
│                          vpn_phase2_weaknesses, ssl_vpn_weaknesses,
│                          ssl_vpn_portal_weaknesses, ha_weaknesses, log_weaknesses
├── Scoring                compute_summary (risk score + section breakdown)
├── Report generators      generate_firewall_report, generate_ssl_report, generate_av_report,
│                          generate_utm_profiles_report, generate_vpn_report,
│                          generate_sslvpn_report, generate_ha_report, generate_log_report,
│                          generate_system_report, generate_summary, generate_diagram
└── CLI                    main()
```

**Parsing model:** FortiGate configs follow a consistent `config … edit … set … next … end` pattern. The generic `extract_block()` handles this. All domain parsers are one-liners calling it with the right block name. Flat single-object blocks (like `config system global`) use `extract_flat_block()`.

**Weakness logic:** Each domain has a dedicated `*_weaknesses()` function returning `List[str]` with `CRITICAL:/HIGH:/MEDIUM:/INFO:` prefixes. Adding a check is a single `if` + `append`.

**Scoring model:**
```
Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (INFO × 0.5)

CRITICAL  → Score ≥ 50 or any CRITICAL finding
HIGH      → Score ≥ 25
MEDIUM    → Score ≥ 10
LOW       → Score < 10
```

---

## 🔧 Extending the Tool

### Add a check to an existing domain

```python
def firewall_weaknesses(policy):
    # ... existing checks ...

    # Example: flag any policy with schedule not set to 'always'
    schedule = normalize_value(policy.get("schedule", "always"))
    if schedule == "always" and action == "accept":
        f.append(finding(I, "Policy active 24/7 — consider restricting to business hours."))

    return f
```

### Add a new config section

```python
# 1. Add parser
def parse_email_filter(text):
    return extract_block(text, "emailfilter profile")

# 2. Add weakness function
def email_filter_weaknesses(profile):
    f = []
    if normalize_value(profile.get("spam-filtering", "")) != "enable":
        f.append(finding(H, "Spam filtering not enabled on email filter profile."))
    return f

# 3. Add CLI flag, report generator, wire into main()
```

### Export to JSON/CSV

The parsed dicts are clean Python objects. Replace `out_path.write_text()` in any `generate_*` function with `json.dumps()` or a `csv.writer` call.

---

## 🔒 Security Considerations

> **⚠️ FortiGate config files contain PSKs, admin credentials, IP addressing, and network topology. Treat them as secret.**

- The `.gitignore` excludes all `*.conf` files except `sample_config.conf`. Never commit real configs.
- Store config backups encrypted: GPG, LUKS, BitLocker, or a secrets vault.
- The tool makes **zero network connections** — all processing is local, all output stays on your machine.
- On multi-user systems: `chmod 600 firewall.conf` before running.
- When sharing audit reports with third parties, redact IPs, admin usernames, and PSKs.

---

## 🗺️ Roadmap

- [ ] HTML report with color-coded severity dashboard
- [ ] Email filter profile audit
- [ ] SNMP community string audit
- [ ] BGP / routing security checks
- [ ] FortiOS version detection and version-aware check adjustments
- [ ] VDOM-aware parsing
- [ ] Config diff mode (compare two backups, report changes)
- [ ] CSV export option
- [ ] CVSS-like per-policy composite scoring
- [ ] GitHub Actions CI with automated test against sample config

---

## 👤 Author

**Jafar Tavana**
Network Security Engineer | CCIE Candidate | FortiGate Specialist

- GitHub: [@jafartavana01](https://github.com/jafartavana01)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  If this saved you time on a real audit, consider starring the repo ⭐<br/>
  It helps other network engineers find it.
</p>
