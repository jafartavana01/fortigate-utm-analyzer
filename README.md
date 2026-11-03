# 🔐 FortiGate UTM Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/version-4.1.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FortiOS-6.x%20%7C%207.x%20%7C%208.0-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Checks-300%2B-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Audit%20Domains-35-purple?style=for-the-badge" />
</p>

<p align="center">
  <strong>Offline FortiGate security auditing with an interactive HTML dashboard.</strong><br/>
  Point it at a <code>show full-configuration</code> backup. Get 300+ severity-tagged findings<br/>
  across 35 audit domains — every security plane, every layer, every FortiOS version.
</p>

---

## What's new in 4.1.0

Generate a self-contained, entirely offline HTML security assessment alongside existing reports:

```bash
python3 utm.py -c sample_config.conf --all --html
python3 utm.py -c firewall.conf -s -vpn -cert --html
python3 utm.py -c firewall.conf -bgp -auth --summary --html
```

Open `<input-basename>_REPORT.html` directly in a current browser. It includes risk cards, three chart views, search, combined severity/domain/scope filters, sorting, expandable evidence and remediation, copy controls, dark/light modes and print/PDF styling. No third-party Python package, remote font, CDN, JavaScript library or build step is required. `--html` is explicit opt-in; it does not silently change which domains run.

New BGP, RADIUS, LDAP and SAML checks use explicit VDOM scopes. Administrator MFA distinguishes potentially delegated external authentication from missing local MFA, and explicit modern SSH/TLS settings have additional checks. **Legacy audit domains still have incomplete multi-VDOM coverage.** Version-dependent omitted values remain unknown in new checks. A report with no findings is not a passing security certification.

Existing flags and TXT/JSON schemas remain available. `--all` includes the new domains, so it adds report files/domain keys. The original sample remains **310 findings, score 876.5**. Configured credential values are redacted from HTML; arbitrary free text and legacy TXT/JSON still require confidentiality review.

See [dashboard usage, complete new check inventory, limitations, compatibility and syntax references](docs/HTML_AND_AUDITS.md). Run tests with `python3 -m unittest discover -s tests -v`. Python 3.8/3.11/3.14 CI is configured; real-browser visual/interaction validation remains outstanding.

## 📋 Table of Contents

- [What's New in v4.0](#-whats-new-in-v40)
- [Version History](#-version-history)
- [Full Audit Domain Map](#-full-audit-domain-map)
- [All 300+ Security Checks](#-all-300-security-checks)
- [Installation](#-installation)
- [Usage & Flags](#-usage--flags)
- [Output Files](#-output-files)
- [Sample Output](#-sample-output)
- [Architecture & Internals](#-architecture--internals)
- [Extending the Tool](#-extending-the-tool)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Author](#-author)

---

## 🆕 What's New in v4.0

v4.0 adds **10 completely new audit modules** and **25 new parsers**, growing the tool from 2,555 to **5,695 lines** and from 25 to **35 audit domains**.

### New Modules

#### 🧠 Policy Intelligence (`-intel`)
One of the most valuable audits for real environments — finds policy table issues that accumulate over years of operation.

- **Shadowed policy detection** — identifies rules that will NEVER be evaluated because an earlier broader rule always matches first. Example: `Policy #1: all→all ACCEPT` followed by `Policy #2: 10.0.0.0/8→DMZ ACCEPT` — Policy #2 is dead. Severity: HIGH
- **Duplicate policy detection** — finds policies with identical srcintf + dstintf + srcaddr + dstaddr + service + action. Common after years of copy-paste management. Severity: HIGH
- **Coverage statistics** — per-UTM-profile percentage bars across all accept policies (IPS, SSL, AV, WebFilter, AppControl, DLP, WAF, CASB, LLM, Logging). The one-page view your manager actually wants
- **ANY-ANY-ANY counter**, disabled policy count, undocumented policy count, packet-capture debug artifact detection

#### 🗄️ Unused Objects Audit (`-unused`)
Parses every object type and cross-references against all policy fields to find orphaned config entries.

- **Unused address objects** — addresses not referenced by any policy, group, or VIP
- **Unused address groups** — groups not used in any policy
- **Unused custom services** — service definitions with no policy references
- **Unused service groups** — service groups not referenced anywhere
- **Unused VIPs** (Medium severity) — forgotten port-forwards still defined but not in any policy. May still be active at NAT level even without a matching policy
- **Unused IP pools** — NAT pools not referenced by any policy
- **Unused schedules** — time-based schedules with no policy references

#### 🌐 VIP / Port-Forward Security Audit (`-vip`)
Reviews every published service from the internet.

- **37 risky port definitions** with per-port severity: RDP (CRITICAL), SMB (CRITICAL), MySQL (CRITICAL), Redis (CRITICAL), PostgreSQL (CRITICAL), VNC (CRITICAL), MS-SQL (CRITICAL), MongoDB (CRITICAL), LDAP (HIGH), RPC (HIGH), NetBIOS (HIGH), FTP (HIGH), WinRM (HIGH), Telnet (CRITICAL), HTTP (MEDIUM), etc.
- **Source filter check** — VIP with no `src-filter` allows any internet IP to attempt connection to the mapped internal host. Severity: MEDIUM
- **Unused VIP detection** — VIP defined but not referenced in any firewall policy
- Per-VIP exposure table with full CLI remediation

#### 🛡️ Anti-DoS Full Audit (`-antidos`)
The most thorough DoS protection audit available for FortiGate.

- **Full anomaly sub-block parser** — reads every anomaly sensor individually (tcp_syn_flood, tcp_ack_flood, tcp_synack_flood, udp_flood, icmp_flood, ip_src_session, tcp_port_scan, ip_bad_option, ip_land_attack, sctp_flood) with status/action/threshold/log per sensor
- **WAN interface with no DoS policy → CRITICAL** — if any WAN interface has no DoS policy, that's an immediate critical
- **Action=monitor detection** — DoS in monitor mode logs but never drops. HIGH severity in production
- **Threshold sanity checks** — threshold=0 (never fires), threshold 10x above recommendation (fires too late)
- **NP7/NP6 hardware DoS offload** — HPE (Host Protection Engine) and fp-anomaly config
- **TCP timer hardening** — tcp-halfopen-timer, tcp-timewait-timer, anti-replay=strict, block-session-timer, ip-src-check-on-tx
- **Resource limits** — `config system resource-limit` session ceiling checks
- **Scored 0–10** with ASCII bar chart and grade (STRONG/ACCEPTABLE/WEAK/POOR/CRITICAL)
- Full CLI remediation examples for every finding

#### 📡 SD-WAN Audit (`-sdwan`)
- **Missing health-checks → CRITICAL** — SD-WAN without health monitoring cannot detect link failures and will never failover
- **Per-member monitoring gap** — each member not covered by any health-check gets HIGH finding
- **Latency threshold check** — no `latency-threshold` means poor-quality high-latency links still carry production traffic
- **Jitter threshold check** — no `jitter-threshold` means jittery links not penalized
- **Packet loss threshold check** — no `packetloss-threshold` means lossy links used without penalty
- **Failover interval check** — slow probe intervals delay failure detection
- **Traffic steering rules** — SD-WAN without service rules is just load-balancing with no app-awareness

#### 📊 Interface Exposure Score (`-iface`)
Weighted protocol scoring per interface, giving each a numerical exposure rating.

| Protocol | Weight | Reasoning |
|---|---|---|
| Telnet | 10 | Cleartext — worst possible |
| HTTP | 9 | Cleartext management |
| SNMP | 8 | Community string / info disclosure |
| FMG-Access | 7 | FortiManager fabric on WAN |
| Security Fabric | 6 | Fabric protocol facing internet |
| SSH | 5 | Encrypted but brute-force target |
| HTTPS | 4 | Encrypted but GUI exposed |
| FNBAM | 3 | FortiAuthenticator |
| Ping | 2 | ICMP recon |

Score normalized 0–10. Grade: CRITICAL EXPOSURE / HIGH / MEDIUM / LOW / MINIMAL. ASCII bar chart per interface.

#### 🔑 Certificate Audit (`-cert`)
- **Expiry detection** with exact days remaining (`-1 days` = already expired → CRITICAL, `≤30 days` → HIGH, `≤90 days` → MEDIUM)
- **RSA key size < 2048 bits → CRITICAL** (cryptographically broken)
- **Self-signed detection** — factory certs, self-signed local certs
- **Auto-renew status** — certificates without auto-regenerate require manual intervention
- Covers `vpn certificate local`, `vpn certificate ca`, `vpn certificate remote`
- Includes note on CLI commands for complete live cert audit on device

#### 🔗 Fabric Connector / Cloud Integration Audit (`-fabric`)
- **AWS connector** — static access-key/secret-key in config (HIGH — treat backup as secret, switch to IAM role). `verify-certificate disable` check. Stale update-interval
- **Azure connector** — client-secret in config (HIGH). Missing tenant-id / client-id
- **GCP connector** — service account validation
- **EMS (Endpoint Management Server)** — `https-connection-verify`, certificate fingerprint pinning, vulnerability pull, AV status pull
- **ZTNA coverage** — percentage of accept policies with ZTNA enabled, EMS tag / device ownership usage
- **FortiSASE connector** — status and endpoint configuration
- **External resources** — TLS cert verification for threat feeds, URI validation

#### 🤖 AI / LLM Application Security Audit (`-ai`)
Brand new for FortiOS 8.0. As AI tools become standard in enterprise environments this is becoming a compliance requirement.

- **LLM profile quality checks** — dlp-check, pii-check, prompt-injection-check, jailbreak-check, logging (all HIGH/MEDIUM if disabled)
- **Chinese AI data sovereignty** — DeepSeek, Ernie (Baidu), Qwen (Alibaba), Kimi → **CRITICAL** for most enterprise environments. These services are subject to Chinese PIPL and national security laws
- **DLP coverage percentage** across accept policies — without DLP, users freely paste source code, customer PII, and financial data into ChatGPT
- **20 AI service risk table** — ChatGPT, Gemini, Claude, Copilot, GitHub Copilot, Grammarly, Mistral, Cohere, HuggingFace, etc. with per-service severity
- **No AI governance detection** — if no LLM profiles, no app control AI entries, no web filter AI rules, and no DLP → consolidated finding with governance framework
- **Full AI governance framework** in report output with CLI examples

#### 🔒 Enhanced Local-in Hardening (integrated into `-s`)
New combined check that's much more impactful than the previous per-policy checks:

- **WAN interface with management access AND no local-in-policy → CRITICAL** — this is the combination that matters. A WAN interface with HTTPS/SSH in `allowaccess` and zero local-in restriction means any internet host can attempt management access
- **No local-in policies at all → HIGH**
- **IPv4 local-in without IPv6 equivalent → MEDIUM**
- Full multi-policy CLI remediation block (accept from admin subnet + deny all)

---

## 📜 Version History

| Version | Date | Lines | Domains | Highlights |
|---|---|---|---|---|
| v1.0 | 2026-06-29 | ~800 | 5 | Initial release: firewall, SSL, AV, system, diagram |
| v2.0 | 2026-06-29 | 1,826 | 13 | IPS, WAF, WebFilter, AppControl, DNS, VPN, SSL-VPN, HA, logging, executive summary |
| v3.0 | 2026-06-30 | 2,555 | 25 | FortiOS 8.0 support, dual-mode SSL/AV parsers, LLM profile, IKE global, SNMP, SSH hardening, password policy, FIPS, DoS, IPv6, FA2/FA3, syslogd1-4, event filter, disk logging |
| **v4.0** | **2026-07-04** | **5,695** | **35** | **Policy intelligence (shadowed/duplicate), unused objects, VIP security, Anti-DoS full audit, SD-WAN, interface exposure score, certificate audit, fabric connectors, AI/LLM security, enhanced local-in** |
| **v4.1.0** | **2026-11-03** | Incremental | New scoped domains | **Offline HTML dashboard; BGP/RADIUS/LDAP/SAML; MFA classification; explicit SSH/TLS checks; regression tests. See current limitations above.** |

---

## 🗺️ Full Audit Domain Map

### Management Plane (`-s`)
| Section | Config Block |
|---|---|
| Admin accounts | `config system admin` |
| Network interfaces | `config system interface` |
| Global hardening | `config system global` |
| Password policy | `config system password-policy` |
| SSH cipher hardening | `config system ssh-config` |
| SNMP (sysinfo + communities + v3 users) | `config system snmp sysinfo/community/user` |
| NTP (auth, redundancy, source) | `config system ntp` |
| Local-in IPv4 + enhanced combined check | `config firewall local-in-policy` |
| Local-in IPv6 | `config firewall local-in-policy6` |
| System DNS (DNSSEC, DoT) | `config system dns` |
| IKE global (IKEv1 disable, aggressive mode) | `config system ike` |
| Security Fabric (CSF) | `config system csf` |
| FIPS-CC compliance mode | `config system fips-cc` |
| FortiGuard fail-open behavior | `config system fortiguard` |

### Data Plane (`-f`, `-i`, `-av`, `-utm`, `-intel`, `-unused`, `-vip`)
| Section | Config Block |
|---|---|
| Firewall policies IPv4 | `config firewall policy` |
| Firewall policies IPv6 | `config firewall policy6` |
| Policy intelligence (shadowed/duplicate/stats) | derived from `firewall policy` |
| Unused objects (7 object types) | `firewall address/addrgrp/service/vip/ippool/schedule` |
| VIP / port-forward security | `config firewall vip` |
| SSL/SSH inspection (v6 flat + v7/8 per-proto; repeated blocks and nested exemptions) | `config firewall ssl-ssh-profile` |
| Antivirus (v8.0 sub-block aware) | `config antivirus profile` |
| IPS sensors | `config ips sensor` |
| Web filter | `config webfilter profile` |
| Application control | `config application list` |
| DNS filter | `config dnsfilter profile` |
| WAF profile | `config waf profile` |
| Email filter | `config emailfilter profile` |
| Video filter | `config videofilter profile` |
| File filter | `config file-filter profile` |
| Virtual patch | `config virtual-patch profile` |
| LLM profile (FortiOS 8.0) | `config llm profile` |
| AI/LLM application security | derived from policies + profiles |

### VPN (`-vpn`, `-sslvpn`)
| Section | Config Block |
|---|---|
| IPsec Phase1 | `config vpn ipsec phase1-interface` |
| IPsec Phase2 | `config vpn ipsec phase2-interface` |
| SSL-VPN global settings | `config vpn ssl settings` |
| SSL-VPN portals | `config vpn ssl web portal` |
| Certificates | `config vpn certificate local/ca/remote` |

### Infrastructure (`-ha`, `-log`, `-dos`, `-antidos`, `-sdwan`)
| Section | Config Block |
|---|---|
| High Availability | `config system ha` |
| FortiAnalyzer 1/2/3 | `config log fortianalyzer/2/3 setting` |
| Syslog 1/2/3/4 | `config log syslogd/2/3/4 setting` |
| Event filter (per category) | `config log eventfilter` |
| Disk logging | `config log disk setting/filter` |
| DoS policies (full anomaly parse) | `config firewall DoS-policy` |
| NP7/NP6 DoS offload | `config system np7/np6` |
| Resource limits | `config system resource-limit` |
| SD-WAN (members + health-checks + rules) | `config system sdwan` |

### Cloud & Zero Trust (`-fabric`, `-ai`, `-iface`, `-cert`)
| Section | Config Block |
|---|---|
| SDN connectors (AWS/Azure/GCP) | `config system sdn-connector` |
| External resources (threat feeds) | `config system external-resource` |
| EMS integration | `config endpoint-control fctems` |
| ZTNA access proxy | `config firewall access-proxy` |
| FortiSASE connector | `config system fortisase` |
| Interface exposure scoring | derived from `system interface` |
| Certificate audit | `config vpn certificate local/ca/remote` |
| AI/LLM traffic controls | `config llm profile` + policy analysis |

---

## 🔬 All 300+ Security Checks

### Policy Intelligence (`-intel`)
| Sev | Finding |
|---|---|
| `CRITICAL` | ANY-ANY-ANY accept policy |
| `HIGH` | Shadowed policy — unreachable due to earlier broad rule |
| `HIGH` | Duplicate policy — identical 5-tuple + action |
| `HIGH` | <50% of accept policies have IPS/SSL/AV/Logging |
| `MEDIUM` | <80% coverage on critical UTM profiles |
| `MEDIUM` | Packet capture debug artifact in production |
| `INFO` | Disabled / undocumented policies |

### Unused Objects (`-unused`)
| Sev | Finding |
|---|---|
| `MEDIUM` | Unused VIP (potential forgotten port-forward) |
| `INFO` | Unused address / group / service / pool / schedule |

### VIP Security (`-vip`)
| Sev | Finding |
|---|---|
| `CRITICAL` | RDP, SMB, MySQL, Redis, PostgreSQL, MongoDB, Telnet, VNC, Radmin exposed from internet |
| `HIGH` | LDAP, RPC, NetBIOS, WinRM, FTP, MS-RPC exposed |
| `MEDIUM` | No source filter on VIP, SMTP exposed, HTTP exposed |
| `MEDIUM` | VIP defined but not referenced in any policy |
| `INFO` | HTTPS-alt, ARP-reply on WAN |

### Anti-DoS (`-antidos`)
| Sev | Finding |
|---|---|
| `CRITICAL` | No DoS policies configured at all |
| `CRITICAL` | WAN interface has no DoS policy |
| `HIGH` | Critical anomaly sensor disabled (tcp_syn_flood, udp_flood, etc.) |
| `HIGH` | Critical sensor action = monitor/pass in production |
| `HIGH` | Anomaly policy has no sensors configured |
| `MEDIUM` | Threshold=0 (sensor never fires) |
| `MEDIUM` | Threshold 10x above recommendation |
| `MEDIUM` | No NP HPE configuration (hardware platforms) |
| `MEDIUM` | fp-anomaly not enabled on NP |
| `MEDIUM` | tcp-halfopen-timer > 10s |
| `MEDIUM` | anti-replay not set to strict |
| `MEDIUM` | No resource-limit configured |
| `HIGH` | IPS botnet C2 scanning disabled |
| `INFO` | Sensor logging disabled |

### SD-WAN (`-sdwan`)
| Sev | Finding |
|---|---|
| `CRITICAL` | No health-checks configured |
| `HIGH` | WAN member not monitored by any health-check |
| `HIGH` | Health-check has no probe server |
| `MEDIUM` | No latency/jitter/packet-loss threshold |
| `MEDIUM` | Probe interval > 2000ms (slow failure detection) |
| `MEDIUM` | No traffic steering rules configured |
| `INFO` | Member has no gateway |

### Interface Exposure (`-iface`)
| Sev | Finding |
|---|---|
| `CRITICAL` | Exposure score ≥ 8/10 (e.g., Telnet + HTTP + SNMP on WAN) |
| `CRITICAL` | Telnet on any interface |
| `CRITICAL` | HTTP on WAN interface |
| `HIGH` | SSH/HTTPS/SNMP/FMG-Access on WAN |
| `HIGH` | Security Fabric on WAN |
| `HIGH` | HTTP on any interface |
| `MEDIUM` | Exposure score ≥ 4/10 on WAN |
| `MEDIUM` | Ping on WAN |

### Certificate Audit (`-cert`)
| Sev | Finding |
|---|---|
| `CRITICAL` | Certificate already expired |
| `CRITICAL` | RSA key size < 2048 bits |
| `HIGH` | Certificate expiring in ≤ 30 days |
| `MEDIUM` | Certificate expiring in ≤ 90 days |
| `MEDIUM` | Self-signed certificate on external-facing service |
| `INFO` | Auto-renew not configured |
| `INFO` | Key size unknown from config |

### Fabric Connectors (`-fabric`)
| Sev | Finding |
|---|---|
| `HIGH` | AWS static access-key/secret-key in config |
| `HIGH` | Azure client-secret in config |
| `HIGH` | verify-certificate disabled on cloud connector |
| `HIGH` | EMS HTTPS verification disabled |
| `MEDIUM` | Missing EMS certificate fingerprint |
| `MEDIUM` | EMS vulnerability pull not enabled |
| `MEDIUM` | Connector update-interval > 60 min |
| `MEDIUM` | ZTNA enabled but no EMS tags configured |
| `MEDIUM` | External resource TLS verification disabled |
| `INFO` | ZTNA coverage < 30% of accept policies |
| `INFO` | FortiSASE not configured |
| `INFO` | Disabled connector (orphan) |

### AI / LLM Security (`-ai`)
| Sev | Finding |
|---|---|
| `CRITICAL` | Chinese AI services detected (DeepSeek, Ernie, Qwen, Kimi) |
| `HIGH` | LLM profile: dlp-check disabled |
| `HIGH` | LLM profile: pii-check disabled |
| `MEDIUM` | LLM profile: prompt-injection-check disabled |
| `MEDIUM` | LLM profile: jailbreak-check disabled |
| `MEDIUM` | LLM profile: logging disabled |
| `MEDIUM` | LLM profiles defined but not attached to any policy |
| `MEDIUM` | < 50% of accept policies have DLP coverage |
| `MEDIUM` | No AI governance controls of any kind |
| `INFO` | AI service references found in config |

### Enhanced Local-in (`-s`)
| Sev | Finding |
|---|---|
| `CRITICAL` | WAN interface has mgmt access AND no local-in-policy |
| `CRITICAL` | ACCEPT from 'all' in local-in-policy |
| `HIGH` | No local-in-policies configured anywhere |
| `MEDIUM` | IPv4 local-in exists but no IPv6 equivalent |
| `MEDIUM` | Local-in service = ALL on accept rule |
| `INFO` | Local-in accept rule has no logging |

---

## 📦 Installation

No pip. No virtualenv. Python 3.8+ only.

```bash
git clone https://github.com/jafartavana01/fortigate-utm-analyzer.git
cd fortigate-utm-analyzer
python3 utm.py --help
```

**Get the config file from FortiGate:**
```
# FortiGate CLI
show full-configuration

# Or GUI: System → Backup → Full Configuration
```

---

## 🚀 Usage & Flags

```bash
python3 utm.py -c <config_file> [flags]
```

### All Flags

| Flag | Description | Output File |
|---|---|---|
| `-c` | **Required** — path to config file | — |
| **Data Plane** | | |
| `-f` | Firewall policy audit (IPv4+IPv6) | `_firewall_policy_report.txt` |
| `-i` | SSL/SSH inspection profiles | `_ssl_inspection_report.txt` |
| `-av` | Antivirus profiles (v8.0 sub-block) | `_antivirus_report.txt` |
| `-utm` | All UTM profiles (IPS+WF+App+DNS+WAF+Email+Video+File+VPatch+LLM) | `_utm_profiles_report.txt` |
| `-intel` | Policy intelligence (shadowed/duplicate/stats) | `_policy_intelligence_report.txt` |
| `-unused` | Unused objects audit | `_unused_objects_report.txt` |
| `-vip` | VIP/port-forward security | `_vip_security_report.txt` |
| **VPN** | | |
| `-vpn` | IPsec Phase1+Phase2 | `_vpn_report.txt` |
| `-sslvpn` | SSL-VPN + portals | `_sslvpn_report.txt` |
| `-cert` | Certificate audit | `_certificate_report.txt` |
| **Infrastructure** | | |
| `-ha` | HA configuration | `_ha_report.txt` |
| `-log` | Logging (FA1-3, syslogd1-4, event filter, disk) | `_logging_report.txt` |
| `-dos` | Basic DoS policy audit | `_dos_policy_report.txt` |
| `-antidos` | Full Anti-DoS protection audit | `_antidos_report.txt` |
| `-sdwan` | SD-WAN audit | `_sdwan_report.txt` |
| **System** | | |
| `-s` | Full system hardening (admin+interface+global+SNMP+SSH+NTP+DNS+IKE+CSF+FIPS+FortiGuard+local-in) | `_system_report.txt` |
| `-iface` | Interface exposure score | `_interface_exposure_report.txt` |
| **Cloud / Zero Trust** | | |
| `-fabric` | Fabric connectors (AWS/Azure/GCP/EMS/ZTNA/SASE) | `_fabric_connector_report.txt` |
| `-ai` | AI/LLM application security | `_ai_llm_audit_report.txt` |
| **Reporting** | | |
| `--summary` | Executive summary + JSON export | `_SUMMARY.txt` + `_SUMMARY.json` |
| `--out-dir DIRECTORY` (`--output-dir`) | Override the default output folder (input filename without extension); creates directories as needed | All generated reports |
| `--all` | Everything above in one run | all of the above |

### Common Workflows

```bash
# Full audit — everything
python3 utm.py -c fw.conf --all

# Quick security posture (most impactful checks first)
python3 utm.py -c fw.conf -f -i -av -s -antidos --summary

# Policy table cleanup (valuable for aged environments)
python3 utm.py -c fw.conf -intel -unused -vip --summary

# VPN & remote access hardening
python3 utm.py -c fw.conf -vpn -sslvpn -cert -s --summary

# Management plane security
python3 utm.py -c fw.conf -s -iface -log -ha -antidos --summary

# Cloud & Zero Trust readiness
python3 utm.py -c fw.conf -fabric -ai -f --summary

# SD-WAN health review
python3 utm.py -c fw.conf -sdwan -iface --summary

# Quick test — bundled sample config
python3 utm.py -c sample_config.conf --all
```

---

## 📁 Output Files

All outputs keep their input-derived filenames. By default, the analyzer creates a subdirectory of the current working directory named after the **configuration filename without its final extension** (not the hostname inside the FortiGate configuration). For example, `-c firewal_001.cfg` writes to `./firewal_001/`. Use `--out-dir` (or `--output-dir`) to override this directory for **all TXT, JSON, and HTML reports**; missing parent directories are created automatically. Pass `--out-dir .` to write directly to the current working directory as in older releases. For example:

```bash
python3 utm.py -c /backups/fw-prod.conf --all --html --out-dir /reports/fw-prod
```

Repeated runs with the same input basename in the same output directory overwrite existing reports. Running `--all` against `fw-prod.conf` produces:

```
fw-prod.conf_firewall_policy_report.txt
fw-prod.conf_ssl_inspection_report.txt
fw-prod.conf_antivirus_report.txt
fw-prod.conf_utm_profiles_report.txt
fw-prod.conf_policy_intelligence_report.txt
fw-prod.conf_unused_objects_report.txt
fw-prod.conf_vip_security_report.txt
fw-prod.conf_vpn_report.txt
fw-prod.conf_sslvpn_report.txt
fw-prod.conf_certificate_report.txt
fw-prod.conf_ha_report.txt
fw-prod.conf_logging_report.txt
fw-prod.conf_dos_policy_report.txt
fw-prod.conf_antidos_report.txt
fw-prod.conf_sdwan_report.txt
fw-prod.conf_system_report.txt
fw-prod.conf_interface_exposure_report.txt
fw-prod.conf_fabric_connector_report.txt
fw-prod.conf_ai_llm_audit_report.txt
fw-prod.conf_SUMMARY.txt
fw-prod.conf_SUMMARY.json          ← machine-readable, ingest into Splunk/SIEM
```

---

## 📊 Sample Output

Running `--all` against the bundled `sample_config.conf` (intentionally misconfigured):

```
================================================================================
================= FORTIGATE SECURITY AUDIT — EXECUTIVE SUMMARY =================
================================================================================
  Config file   : sample_config.conf
  Risk Rating   : CRITICAL
  Risk Score    : 876.5  (CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5)
  Total Findings: 312

  CRITICAL        12
  HIGH            89
  MEDIUM         118
  INFO            93
================================================================================

  FINDINGS BY SECTION:
  ──────────────────────────────────────────────────────────────────────────────
  Section                              CRIT  HIGH   MED  INFO   TOT
  ──────────────────────────────────────────────────────────────────────────────
  AI/LLM Security                         1     3     4     1      9
  Admin Accounts                          0     6     0     3      9
  Anti-DoS Hardening                      0     5     3     2     10
  Anti-DoS IPS                            0     2     1     0      3
  Anti-DoS Policies                       1     4     2     0      7
  Antivirus Profiles                      0     1    10     6     17
  Certificates                            0     0     1     1      2
  Enhanced Local-in                       2     1     1     0      4
  Fabric Connectors                       0     4     3     1      8
  Firewall Policies                       3    14    18    24     59
  Global Hardening                        1     3     4     5     13
  HA Config                               0     1     3     2      6
  IKE Global                              0     2     1     0      3
  Interface Exposure                      0     7     2     1     10
  Interfaces                              0     7     1     1      9
  Logging                                 0     1     4     2      7
  NTP                                     0     1     1     2      4
  Policy Intelligence                     1     2     3     5     11
  SD-WAN                                  1     1     2     0      4
  SSL Inspection                          0     6    10     4     20
  SSL-VPN                                 0     3     4     1      8
  SNMP                                    1     1     1     0      3
  Unused Objects                          0     0     2     8     10
  VIP Security                            2     1     1     2      6
  VPN Phase1                              0     7     2     1     10
  ...

  CRITICAL & HIGH FINDINGS (excerpt):
  ──────────────────────────────────────────────────────────────────────────────
  [VIP Security         ] CRITICAL: VIP 'RDP-Server' exposes RDP (port 3389) from internet
  [VIP Security         ] CRITICAL: VIP 'SMB-Server' exposes SMB (port 445) from internet
  [Anti-DoS Policies    ] CRITICAL: WAN interface 'wan1' has NO DoS policy
  [Enhanced Local-in    ] CRITICAL: WAN 'wan1' has mgmt access AND no local-in-policy
  [SD-WAN               ] CRITICAL: No health-checks configured
  [AI/LLM Security      ] CRITICAL: Chinese AI detected (deepseek) — data sovereignty risk
  [Fabric Connectors    ] HIGH: AWS static access-key/secret-key in config
  [Fabric Connectors    ] HIGH: Azure client-secret stored in config
  [VPN Phase1           ] HIGH: IKEv1 aggressive mode — PSK hash exposed
================================================================================
```

### Anti-DoS Scored Report Sample

```
══════════════════════════════════════════════════════════════════════════════
═══════════════ ANTI-DoS / DoS PROTECTION AUDIT ════════════════════════════
══════════════════════════════════════════════════════════════════════════════
  Overall DoS Protection Score : 0.0 / 10  — CRITICAL — NO EFFECTIVE DoS PROTECTION
  CRITICAL: 1   HIGH: 4   MEDIUM: 2   INFO: 0

  [░░░░░░░░░░] 0.0/10

  Policy #1  Interface: wan1  Status: enable  Src: all  Dst: all
  Anomaly sensors configured: 7

  Sensor                     Status     Action     Threshold    Log      Assessment
  ─────────────────────────  ─────────  ─────────  ───────────  ───────  ──────────
  tcp_syn_flood              enable     monitor    2000         disable  ⚠ NOT BLOCKING
  udp_flood                  enable     block      999999       disable  ⚠ THRESH TOO HIGH
  icmp_flood                 disable    block      250          enable   ⚠ DISABLED
  ip_src_session             enable     block      5000         enable   ✓ OK
```

### Interface Exposure Score Sample

```
  Interface            Role     IP                   Exposed Protocols              Score
  ─────────────────────────────────────────────────────────────────────────────────────
  wan1                 wan      203.0.113.1/24       ping https ssh http snmp telnet  9.2/10
                                                     [█████████░] CRITICAL EXPOSURE
  dmz                  dmz      10.10.10.1/24        http telnet                      7.8/10
                                                     [███████░░░] HIGH EXPOSURE
  port1                lan      192.168.1.1/24       ping https                       2.1/10
                                                     [██░░░░░░░░] LOW EXPOSURE
```

---

## 🏗️ Architecture & Internals

### Parser Design

```
utm.py (5695 lines, 0 external dependencies)
│
├── Base Parsers
│   ├── extract_block()           — config X / edit / set / next / end
│   ├── extract_flat_block()      — flat blocks (system global etc.)
│   └── extract_nested_block()    — nested sub-blocks (NTP servers)
│
├── Version-Aware Parsers
│   ├── parse_ssl_profiles_v2()   — 6.x flat + 7/8 per-protocol sub-blocks
│   │                               (https.status, ftps.min-allowed-ssl-version etc.)
│   └── parse_av_profiles_v2()    — 6.x flat + 8.0 sub-blocks
│                                   (http.av-scan, content-disarm.office-macro etc.)
│
├── Specialized Parsers
│   ├── parse_dos_policy_full()   — anomaly sub-block aware (reads every sensor)
│   ├── parse_sdwan()             — nested members + health-checks + rules
│   └── parse_np_global()         — NP7/NP6/NPU auto-detection
│
├── 58 Section Parsers            — one per config section
│
├── 35 Weakness Functions         — each: Dict → List[str] with severity prefix
│
├── Object Reference Engine       — cross-references all object types vs all policies
│
├── Scoring Engine
│   ├── Firewall scoring          — CRITICAL×10 + HIGH×5 + MEDIUM×2 + INFO×0.5
│   └── Anti-DoS 0-10             — deduction model with per-category caps
│
├── 22 Report Generators          — ASCII tables + findings + CLI remediation
│
└── CLI (argparse)                — 30 flags + --all
```

### Scoring Model

```
Global Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (INFO × 0.5)

Risk Tier:
  CRITICAL  → any CRITICAL finding  OR  Score ≥ 50
  HIGH      → Score ≥ 25
  MEDIUM    → Score ≥ 10
  LOW       → Score < 10

Anti-DoS Score (0–10):
  Starts at 10, deductions per finding:
  CRITICAL: -3 (capped at -6)
  HIGH:     -1.5 (capped at -4.5)
  MEDIUM:   -0.5 (capped at -2)
  INFO:     -0.1 (capped at -0.5)
  Grade: STRONG (8+) / ACCEPTABLE (6+) / WEAK (4+) / POOR (2+) / CRITICAL
```

---

## 🔧 Extending the Tool

### Add a check to an existing domain

```python
def fw_policy_weaknesses(p: Dict) -> List[str]:
    findings = []
    # ... existing checks ...

    # Example: flag RDP service in any accept policy
    service = nv(p.get("service", ""))
    if "RDP" in service.upper() and nv(p.get("action","")) == "accept":
        findings.append(f(H, "Policy permits RDP — use SSL-VPN instead of direct RDP exposure."))

    return findings
```

### Add a new config section (3 steps)

```python
# Step 1: Parser — one line for standard blocks
def parse_my_section(t):
    return extract_block(t, "my config block name")

# Step 2: Weakness function
def my_section_weaknesses(obj: Dict) -> List[str]:
    findings = []
    name = nv(obj.get("name", obj.get("_id", "")))
    if nv(obj.get("some-field", "")) != "enable":
        findings.append(f(M, f"MySection '{name}': some-field not enabled."))
    return findings

# Step 3: Wire into main() — parse, generate report, collect findings
```

### Consume the JSON output in Splunk or Python

```python
import json

with open("fw.conf_SUMMARY.json") as fh:
    data = json.load(fh)

# Risk overview
print(data["summary"]["risk"])     # "CRITICAL"
print(data["summary"]["score"])    # 876.5
print(data["summary"]["counts"])   # {"CRITICAL": 12, "HIGH": 89, ...}

# All CRITICAL findings across all sections
for section, finds in data["findings"].items():
    crits = [f for f in finds if f.startswith("CRITICAL:")]
    for c in crits:
        print(f"[{section}] {c}")

# Per-section breakdown
for section, sc in data["summary"]["by_section"].items():
    if sc["CRITICAL"] > 0 or sc["HIGH"] > 0:
        print(f"{section}: C={sc['CRITICAL']} H={sc['HIGH']}")
```

---

## 🔒 Security Considerations

> **⚠️ FortiGate config files contain PSKs, admin credentials, cloud API keys, full IP topology, and routing tables. Handle as a secret document.**

- `.gitignore` excludes all `*.conf` files except `sample_config.conf` — never commit real device configs
- Store config backups encrypted: `gpg --symmetric --cipher-algo AES256 firewall.conf`
- The tool makes **zero network connections** — everything is local, nothing leaves your machine
- After running: `chmod 600 firewall.conf` on shared systems
- Sanitize IPs, usernames, PSKs, and API keys before sharing reports externally
- The `_SUMMARY.json` contains all finding text — treat it with the same care as the config

---

## 🗺️ Roadmap

- [ ] HTML report with color-coded severity dashboard and charts
- [ ] BGP security audit (route filtering, prefix limits, MD5 auth, max-prefix)
- [ ] FortiOS version detection → version-conditional check logic
- [ ] VDOM-aware parsing (per-VDOM config sections + global section)
- [ ] Config diff mode: compare two backups, report changed settings and new risks
- [ ] CSV/Excel export for enterprise audit reporting
- [ ] RADIUS / LDAP / SAML authentication server hardening
- [ ] FortiNAC integration audit
- [ ] FortiMonitor cloud monitoring integration check
- [ ] Automated multi-device audit runner (accepts a list of config files)
- [ ] GitHub Actions CI with regression tests against sample config

---

## 👤 Author

**Jafar Tavana**
Network Security Engineer | CCIE Candidate | FortiGate Specialist

15+ years in network engineering. Cisco, Fortinet, Mikrotik, Linux, Windows Server.
Building security tools that eliminate the mechanical parts of firewall auditing.

- GitHub: [@jafartavana01](https://github.com/jafartavana01)

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  If this caught something real on a production audit, consider starring ⭐<br/>
  It helps other engineers find the tool.
</p>
