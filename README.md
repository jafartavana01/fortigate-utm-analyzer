# 🔐 FortiGate UTM Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FortiOS-6.x%20%7C%207.x%20%7C%208.0-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Checks-200%2B-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Audit%20Domains-25-purple?style=for-the-badge" />
</p>

<p align="center">
  <strong>Deep security auditing of FortiGate configurations across every security plane.</strong><br/>
  Point it at a <code>show full-configuration</code> backup and get severity-tagged findings<br/>
  across 25 audit domains — from firewall policies to LLM profiles — with a scored executive summary.
</p>

---

## 📋 Table of Contents

- [What's New in v3.0](#-whats-new-in-v30)
- [Architecture Overview](#-architecture-overview)
- [All 25 Audit Domains](#-all-25-audit-domains)
- [Security Checks Reference](#-security-checks-reference)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)
- [Sample Output](#-sample-output)
- [Extending the Tool](#-extending-the-tool)
- [Security Considerations](#-security-considerations)
- [Author](#-author)
- [License](#-license)

---

## 🆕 What's New in v3.0

### Parser Upgrades — FortiOS Version-Aware

**SSL/SSH Profile** dual-mode parser: auto-detects whether the config is FortiOS 6.x flat format or 7.x/8.0 per-protocol sub-block format and applies the appropriate check set. The new format uses keys like `https.status`, `ftps.min-allowed-ssl-version`, `imaps.untrusted-server-cert`, `ssh.inspect-all`, `dot.status` — all captured and audited per protocol.

**AV Profile** dual-mode parser: handles both 6.x flat and 8.0 sub-block layout (`http.av-scan`, `smtp.outbreak-prevention`, `content-disarm.office-macro`, `http.malware-stream`, `http.fortindr`, `http.quarantine` etc.).

**33 new parsers** covering every hardening-relevant config section in FortiOS 8.0.

### New Audit Domains (13 added in v3.0)

| Domain | Key Checks |
|---|---|
| WAF Profile | OWASP signatures, HTTP method restriction, URL access rules, request constraints, address blocklist |
| Email Filter | Spam filtering, phishing detection, FortiGuard spam service, DNS blacklist, logging |
| Video Filter | YouTube restriction, Vimeo access, logging |
| File Filter | Archive content scanning, dangerous file type blocking, logging |
| Virtual Patch Profile | Action mode (monitor vs block), logging |
| LLM Profile *(FortiOS 8.0)* | DLP check, PII detection, prompt injection, jailbreak detection, logging |
| IKE Global | IKEv1 global disable, aggressive mode global disable, weak DH groups, deprecated hash algorithms |
| SNMP | Community string names (default/weak), host restrictions, trap targets, SNMPv3 auth-proto/priv-proto/security-level |
| System DNS | DNSSEC validation, DNS-over-TLS for system resolver, primary/secondary redundancy |
| SSH Hardening | Weak cipher algorithms (arcfour/3DES/blowfish), weak MACs (MD5/SHA-1), weak KEX (DH group1/14) |
| Password Policy | min-length, must-contain complexity, expiry, reuse prevention |
| Security Fabric (CSF) | Group password, certificate-based authorization, device detection, SAML sync |
| FIPS-CC | Compliance mode status |
| FortiGuard | Fail-open modes for AV/IPS/webfilter, scheduled updates, auto firmware |
| DoS Policy | Interface binding, policy status, anomaly thresholds |
| IPv6 | `firewall policy6` and `firewall local-in-policy6` both audited |
| Logging (expanded) | FA2/FA3, syslogd2/3/4, per-category event filter (admin/system/VPN/endpoint), disk logging, disk-full behavior |

---

## 🏗️ Architecture Overview

```
utm.py  (2555 lines, zero external dependencies)
│
├── Generic Parsers
│   ├── extract_block()           — config X / edit / set / next / end
│   ├── extract_flat_block()      — config X / set / end (no edit)
│   └── extract_nested_block()    — nested sub-blocks (e.g. NTP servers)
│
├── Version-Aware Parsers
│   ├── parse_ssl_profiles_v2()   — 6.x flat + 7/8 per-protocol sub-blocks
│   └── parse_av_profiles_v2()    — 6.x flat + 8.0 per-protocol sub-blocks
│
├── 40+ Section Parsers           — one per config section
│
├── 25 Weakness Functions         — each returns List[str] with CRITICAL/HIGH/MEDIUM/INFO
│
├── Scoring Engine                — CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5
│
├── 12 Report Generators          — ASCII tables + findings per section
│
└── CLI (argparse)                — 22 flags + --all shortcut
```

**Parsing philosophy:** FortiOS configs follow a consistent `config … edit … set … next … end` pattern. The generic `extract_block()` handles 90% of sections. Version-aware parsers handle the two cases where FortiOS 7/8 changed from flat to per-protocol sub-blocks (SSL profiles, AV profiles). All parsed data is plain Python dicts — weakness functions receive a dict and return a list of strings. Adding a check is a single `if` statement.

**Scoring model:**
```
Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (INFO × 0.5)

CRITICAL  → any CRITICAL finding OR score ≥ 50
HIGH      → score ≥ 25
MEDIUM    → score ≥ 10
LOW       → score < 10
```

---

## 🛡️ All 25 Audit Domains

| # | Domain | Config Section | Flag |
|---|---|---|---|
| 1 | Firewall Policies (IPv4) | `config firewall policy` | `-f` |
| 2 | Firewall Policies (IPv6) | `config firewall policy6` | `-f` |
| 3 | SSL/SSH Inspection | `config firewall ssl-ssh-profile` | `-i` |
| 4 | Antivirus Profiles | `config antivirus profile` | `-av` |
| 5 | IPS Sensors | `config ips sensor` | `-ips` / `-utm` |
| 6 | Web Filter | `config webfilter profile` | `-wf` / `-utm` |
| 7 | App Control | `config application list` | `-app` / `-utm` |
| 8 | DNS Filter | `config dnsfilter profile` | `-dns` / `-utm` |
| 9 | WAF Profile | `config waf profile` | `-waf` / `-utm` |
| 10 | Email Filter | `config emailfilter profile` | `-email` / `-utm` |
| 11 | Video Filter | `config videofilter profile` | `-video` / `-utm` |
| 12 | File Filter | `config file-filter profile` | `-file` / `-utm` |
| 13 | Virtual Patch | `config virtual-patch profile` | `-vpatch` / `-utm` |
| 14 | LLM Profile | `config llm profile` | `-llm` / `-utm` |
| 15 | IPsec VPN Phase1 | `config vpn ipsec phase1-interface` | `-vpn` |
| 16 | IPsec VPN Phase2 | `config vpn ipsec phase2-interface` | `-vpn` |
| 17 | SSL-VPN | `config vpn ssl settings` | `-sslvpn` |
| 18 | SSL-VPN Portals | `config vpn ssl web portal` | `-sslvpn` |
| 19 | High Availability | `config system ha` | `-ha` |
| 20 | Logging / SIEM | `config log fortianalyzer/syslogd/disk/eventfilter` | `-log` |
| 21 | DoS Policies | `config firewall DoS-policy` | `-dos` |
| 22 | System Hardening | `config system global/admin/interface/ntp/local-in` | `-s` |
| 23 | SNMP | `config system snmp sysinfo/community/user` | `-s` |
| 24 | VPN / IKE Global | `config system ike` | `-s` |
| 25 | Security Fabric | `config system csf` + `system fips-cc` + `system dns` + `system ssh-config` + `system password-policy` + `system fortiguard` | `-s` |

---

## 🔬 Security Checks Reference

### Firewall Policies (`-f`)

| Sev | Finding |
|---|---|
| `CRITICAL` | ANY-ANY-ANY accept policy |
| `HIGH` | UTM disabled on accept policy |
| `HIGH` | No IPS sensor or virtual-patch profile |
| `HIGH` | No antivirus profile |
| `HIGH` | No SSL/SSH inspection |
| `HIGH` | Traffic logging completely disabled |
| `HIGH` | Inbound WAN-to-internal accept detected |
| `MEDIUM` | No DLP profile |
| `MEDIUM` | No web / DNS / app-control filter |
| `MEDIUM` | Service ALL / source all |
| `MEDIUM` | Anti-replay disabled |
| `MEDIUM` | tcp-session-without-syn enabled |
| `MEDIUM` | Packet capture enabled (debug artifact) |
| `INFO` | No WAF / Email / File / Virtual-patch / LLM / CASB profile |
| `INFO` | ZTNA not enabled |
| `INFO` | reputation-minimum not set |
| `INFO` | log-http-transaction disabled |
| `INFO` | Policy name suggests temp rule but no expiry set |
| `INFO` | Disabled / undocumented policy |

### SSL/SSH Inspection (`-i`) — v6.x flat and v7/8 per-protocol

| Sev | Finding |
|---|---|
| `HIGH` | Deep inspection without CA certificate |
| `HIGH` | Untrusted / invalid certificates not blocked (per protocol in v7/8) |
| `HIGH` | TLS minimum below 1.2 (per protocol) |
| `HIGH` | Revoked certificate action = allow |
| `MEDIUM` | Per-protocol inspection disabled (https/ftps/imaps/pop3s/smtps) |
| `MEDIUM` | SSH inspection disabled |
| `MEDIUM` | Certificate-only inspection (no decryption) |
| `MEDIUM` | SNI checking disabled |
| `MEDIUM` | Expired certs not blocked |
| `MEDIUM` | Blacklisted certificate blocking disabled |
| `MEDIUM` | SSL anomaly logging disabled |
| `MEDIUM` | TLS min version not set |
| `MEDIUM` | ECH (Encrypted Client Hello) not handled |
| `MEDIUM` | DNS-over-TLS not blocked/inspected |
| `INFO` | TLS 1.2 min (TLS 1.3 preferred) |
| `INFO` | RPC-over-HTTPS / MAPI-over-HTTPS not blocked |

### Antivirus Profiles (`-av`) — v8.0 sub-block aware

| Sev | Finding |
|---|---|
| `HIGH` | Malware action monitor/pass |
| `HIGH` | CDR office-macro stripping disabled |
| `HIGH` | av-virus-log disabled |
| `MEDIUM` | HTTP/HTTPS/SMTP/CIFS/SMB not inspected |
| `MEDIUM` | HTTP outbreak prevention disabled |
| `MEDIUM` | FortiSandbox not configured |
| `MEDIUM` | HTTP FortiSandbox submission disabled |
| `MEDIUM` | malware-stream scanning disabled |
| `MEDIUM` | CDR office-embed / PDF JavaScript stripping disabled |
| `MEDIUM` | CDR error-action is log-only |
| `MEDIUM` | Quarantine not enabled |
| `MEDIUM` | Outbreak prevention archive scan disabled |
| `INFO` | Flow-based mode (proxy preferred) |
| `INFO` | FortiNDR not enabled |
| `INFO` | EMS threat feed / analytics-db / mobile malware DB not enabled |

### IPsec VPN (`-vpn`)

| Sev | Finding |
|---|---|
| `HIGH` | IKEv1 aggressive mode (PSK hash exposed) |
| `HIGH` | Weak cipher: DES/3DES/MD5/null in IKE proposal |
| `HIGH` | DH group below 2048-bit (group 1/2/5) |
| `HIGH` | PSK shorter than 20 characters |
| `HIGH` | Weak algorithm in Phase2 ESP proposal |
| `HIGH` | PFS disabled on Phase2 |
| `HIGH` | PFS DH group weak |
| `MEDIUM` | IKEv1 in use |
| `MEDIUM` | PSK authentication (cert-based preferred) |
| `MEDIUM` | Phase2 anti-replay disabled |
| `MEDIUM` | IKE/Phase2 key lifetime too long |
| `INFO` | IKE version not set / DPD disabled / rekey disabled |

### SSL-VPN (`-sslvpn`)

| Sev | Finding |
|---|---|
| `HIGH` | TLS 1.0 permitted |
| `HIGH` | Login attempt limit = 0 |
| `HIGH` | Idle timeout = 0 |
| `HIGH` | Split tunneling enabled on portal |
| `MEDIUM` | TLS 1.1 permitted / TLS 1.2 not explicit |
| `MEDIUM` | Self-signed certificate |
| `MEDIUM` | Client certificate not required |
| `MEDIUM` | Source-address not restricted |
| `MEDIUM` | Auth timeout > 8h / Login block time < 60s |
| `MEDIUM` | Portal OS check not enabled |

### System Hardening (`-s`)

| Sev | Finding |
|---|---|
| `CRITICAL` | DH params below 2048-bit |
| `CRITICAL` | Default/weak admin password |
| `CRITICAL` | SNMP community = public/private/admin |
| `CRITICAL` | Local-in ACCEPT from 'all' |
| `HIGH` | Admin session timeout = 0 |
| `HIGH` | No trusthost restrictions on admin |
| `HIGH` | Trusthost = 0.0.0.0/0 |
| `HIGH` | super_admin profile |
| `HIGH` | 2FA not enabled |
| `HIGH` | Admin lockout threshold/duration = 0 |
| `HIGH` | strong-crypto disabled |
| `HIGH` | HTTP/Telnet on any interface |
| `HIGH` | HTTPS/SSH/SNMP on WAN interface |
| `HIGH` | HA cluster has no password |
| `HIGH` | NTP sync disabled |
| `HIGH` | SNMP community no host restriction |
| `HIGH` | SNMPv3 no-auth-no-priv |
| `HIGH` | SSH weak cipher/KEX |
| `HIGH` | IKE global aggressive mode not disabled |
| `HIGH` | IKE global weak DH groups allowed |
| `HIGH` | No remote logging destination |
| `HIGH` | Admin event logging disabled |
| `HIGH` | CSF group password not set |
| `MEDIUM` | DH params below 4096-bit |
| `MEDIUM` | Password policy disabled or weak |
| `MEDIUM` | SSL static key ciphers not disabled |
| `MEDIUM` | HTTPS redirect not enabled |
| `MEDIUM` | DNSSEC validation disabled |
| `MEDIUM` | NTP authentication disabled |
| `MEDIUM` | Syslog using UDP |
| `MEDIUM` | FortiGuard fail-open modes set to pass/allow |
| `INFO` | Pre/post login banner disabled |
| `INFO` | Self-signed GUI certificate |
| `INFO` | Default hostname |
| `INFO` | Revision auto-backup disabled |
| `INFO` | FIPS-CC mode not enabled |

---

## 📦 Installation

```bash
git clone https://github.com/jafartavana01/fortigate-utm-analyzer.git
cd fortigate-utm-analyzer
python3 utm.py --help
```

No pip. No virtualenv. Python 3.8+ stdlib only.

**Optional system-wide alias:**
```bash
chmod +x utm.py
sudo ln -s $(pwd)/utm.py /usr/local/bin/fg-audit
fg-audit --help
```

**Get the config from FortiGate:**
```
# CLI
show full-configuration

# Or GUI: System → Backup → Configuration
```

---

## 🚀 Usage

```bash
python3 utm.py -c <config_file> [flags]
```

| Flag | Description |
|---|---|
| `-c / --config` | **Required.** Path to FortiGate config backup |
| `-f` | Firewall policy audit (IPv4 + IPv6) |
| `-i` | SSL/SSH inspection profile audit |
| `-av` | Antivirus profile audit (8.0 sub-block aware) |
| `-utm` | All UTM profiles in one report (IPS, WF, App, DNS, WAF, Email, Video, File, VPatch, LLM) |
| `-ips` `-wf` `-app` `-dns` `-waf` `-email` `-video` `-file` `-vpatch` `-llm` | Individual UTM profile audits |
| `-vpn` | IPsec VPN Phase1 + Phase2 |
| `-sslvpn` | SSL-VPN settings + all portals |
| `-ha` | HA configuration |
| `-log` | Logging: FA1/2/3, syslogd1/2/3/4, event filter, disk |
| `-dos` | DoS policy audit |
| `-s` | Full system hardening: admin, interface, global, SNMP, SSH, NTP, DNS, IKE, CSF, FIPS, FortiGuard, local-in (IPv4+IPv6) |
| `--summary` | Executive summary + JSON export |
| `--all` | Everything above in one run |

### Common workflows

```bash
# Full audit — everything
python3 utm.py -c fw.conf --all

# Core security posture (fastest useful scan)
python3 utm.py -c fw.conf -f -i -av -s --summary

# VPN hardening review
python3 utm.py -c fw.conf -vpn -sslvpn -s --summary

# Data plane only — all UTM profiles
python3 utm.py -c fw.conf -f -i -av -utm --summary

# Management plane hardening
python3 utm.py -c fw.conf -s -log -ha --summary

# Quick test with bundled sample config
python3 utm.py -c sample_config.conf --all
```

---

## 📁 Output Files

| Flag | Output File |
|---|---|
| `-f` | `<config>_firewall_policy_report.txt` |
| `-i` | `<config>_ssl_inspection_report.txt` |
| `-av` | `<config>_antivirus_report.txt` |
| `-utm` / UTM flags | `<config>_utm_profiles_report.txt` |
| `-vpn` | `<config>_vpn_report.txt` |
| `-sslvpn` | `<config>_sslvpn_report.txt` |
| `-ha` | `<config>_ha_report.txt` |
| `-log` | `<config>_logging_report.txt` |
| `-dos` | `<config>_dos_policy_report.txt` |
| `-s` | `<config>_system_report.txt` |
| `--summary` | `<config>_SUMMARY.txt` + `<config>_SUMMARY.json` |

---

## 📊 Sample Output

Running `--all` against the bundled `sample_config.conf`:

```
================================================================================
================= FORTIGATE SECURITY AUDIT — EXECUTIVE SUMMARY =================
================================================================================
  Config file  : sample_config.conf
  Risk Rating  : CRITICAL
  Risk Score   : 545.0  (CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5)
  Total Findings: 227

  CRITICAL        5
  HIGH           58
  MEDIUM         82
  INFO           82
================================================================================

  FINDINGS BY SECTION:
  ──────────────────────────────────────────────────────────────────────────────
  Section                              CRIT  HIGH   MED  INFO   TOT
  ──────────────────────────────────────────────────────────────────────────────
  Admin Accounts                          0     6     0     3      9
  Antivirus Profiles                      0     1    10     6     17
  DNS Filter                              0     1     2     1      4
  DoS Policies                            0     0     1     0      1
  FIPS-CC                                 0     0     0     1      1
  Firewall Policies                       3    14    18    24     59
  FortiGuard                              0     0     2     1      3
  Global Hardening                        1     3     4     5     13
  HA Config                               0     1     3     2      6
  IKE Global                              0     2     1     0      3
  IPS Sensors                             0     1     1     1      3
  Interfaces                              0     7     1     1      9
  Local-in                                1     1     1     0      3
  Logging                                 0     1     4     2      7
  NTP                                     0     1     1     2      4
  Password Policy                         0     1     1     0      2
  SSL Inspection                          0     6    10     4     20
  SSL-VPN                                 0     3     4     1      8
  SSL-VPN Portals                         0     1     0     3      4
  SNMP                                    0     2     1     0      3
  Security Fabric                         0     1     1     1      3
  System DNS                              0     0     1     2      3
  VPN Phase1                              0     7     2     1     10
  VPN Phase2                              0     4     1     0      5
  WAF Profiles                            0     1     3     1      5
  Web Filter                              0     0     3     2      5

  CRITICAL & HIGH FINDINGS:
  ──────────────────────────────────────────────────────────────────────────────
  [Firewall Policies    ]  CRITICAL: ANY-ANY-ANY accept policy — maximally permissive
  [Firewall Policies    ]  HIGH: No IPS sensor or virtual-patch profile
  [VPN Phase1           ]  HIGH: IKEv1 aggressive mode — PSK hash exposed in cleartext
  [VPN Phase1           ]  HIGH: weak algorithm 'DES' in IKE proposal
  [VPN Phase2           ]  HIGH: PFS disabled — session key compromise exposes all past sessions
  [SSL-VPN              ]  HIGH: TLS 1.0 permitted
  [SSL-VPN              ]  HIGH: login attempt limit 0 — brute-force protection disabled
  [Interfaces           ]  HIGH: Interface 'wan1' (WAN): SNMP accessible from internet
  [Global Hardening     ]  CRITICAL: DH params 1024-bit — critically weak
  [Local-in             ]  CRITICAL: ACCEPT from 'all' sources — control plane exposed
================================================================================
```

The `--summary` flag also writes `_SUMMARY.json` for SIEM ingest or automation.

---

## 🔧 Extending the Tool

### Add a check to an existing domain

```python
def fw_policy_weaknesses(p: Dict) -> List[str]:
    findings = []
    # ... existing checks ...

    # Example: flag policies without a schedule restriction on high-risk services
    service = nv(p.get("service", ""))
    schedule = nv(p.get("schedule", "always"))
    if "RDP" in service.upper() and schedule == "always":
        findings.append(f(M, "Policy permits RDP with no schedule — consider restricting to business hours."))

    return findings
```

### Add a completely new config section

```python
# 1. Add parser (one line for standard blocks)
def parse_my_section(t): return extract_block(t, "my section name")

# 2. Add weakness function
def my_section_weaknesses(p: Dict) -> List[str]:
    findings = []
    val = nv(p.get("some-field", ""))
    if val != "enable":
        findings.append(f(M, f"MySection: some-field not enabled."))
    return findings

# 3. Add report generator, wire into main()
```

### Consume the JSON output

```python
import json

with open("fw.conf_SUMMARY.json") as fh:
    data = json.load(fh)

print(data["summary"]["risk"])          # "CRITICAL"
print(data["summary"]["score"])         # 545.0
print(data["summary"]["counts"])        # {"CRITICAL": 5, "HIGH": 58, ...}

# All findings per section
for section, finds in data["findings"].items():
    highs = [f for f in finds if f.startswith("HIGH:")]
    if highs:
        print(f"\n[{section}]")
        for h in highs:
            print(f"  {h}")
```

---

## 🔒 Security Considerations

> **⚠️ FortiGate config files contain PSKs, admin credentials, full IP topology, and routing tables. Treat as secret.**

- `.gitignore` excludes all `*.conf` files except `sample_config.conf`. Never commit real configs.
- The tool makes **zero network connections** — all processing is local.
- Store config backups encrypted: `gpg -c firewall.conf` or full-disk encryption.
- On shared systems: `chmod 600 firewall.conf` before and after running.
- Sanitize IP addresses and admin usernames before sharing audit reports.

---

## 🗺️ Roadmap

- [ ] HTML report with color-coded severity dashboard
- [ ] BGP / routing security checks (route filtering, prefix limits, MD5 auth)
- [ ] FortiOS version detection → version-aware check adjustments
- [ ] VDOM-aware parsing (root + per-VDOM config sections)
- [ ] Config diff mode (compare two backups, report changed settings)
- [ ] CSV export for spreadsheet analysis
- [ ] RADIUS / LDAP / SAML auth server hardening audit
- [ ] FortiManager managed device config audit mode

---

## 👤 Author

**Jafar Tavana**
Network Security Engineer | CCIE Candidate | FortiGate Specialist

- GitHub: [@jafartavana01](https://github.com/jafartavana01)

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">If this caught something on a real audit, consider starring ⭐ — it helps other engineers find it.</p>
