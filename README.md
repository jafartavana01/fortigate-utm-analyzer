# 🔐 FortiGate UTM Security Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-FortiOS%206.x%20%7C%207.x-red?style=for-the-badge&logo=fortinet&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Reports-5%20types-orange?style=for-the-badge" />
</p>

<p align="center">
  <strong>A zero-dependency Python CLI tool for deep security auditing of FortiGate firewall configurations.</strong><br/>
  Parse a <code>show full-configuration</code> backup and generate structured security reports across firewall policies, SSL/SSH inspection, antivirus profiles, system hardening, NTP, and more — with severity-tagged findings and ASCII topology diagrams.
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What It Audits](#-what-it-audits)
- [Security Checks Reference](#-security-checks-reference)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)
- [Report Deep Dive](#-report-deep-dive)
- [UTM Flow Diagram](#-utm-flow-diagram)
- [Sample Output](#-sample-output)
- [Architecture](#-architecture)
- [Extending the Tool](#-extending-the-tool)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Author](#-author)
- [License](#-license)

---

## 🔍 Overview

FortiGate firewalls are the backbone of many enterprise perimeters. But even a correctly-licensed FortiGate can be dangerously misconfigured — UTM profiles missing from accept policies, SSL inspection in certificate-only mode, admin accounts without 2FA or trust-host restrictions, NTP unauthenticated, WAN interfaces with management access open.

This tool automates the discovery of those misconfigurations. You feed it a plain-text FortiGate configuration backup (the output of `show full-configuration` or `execute backup config`), and it outputs:

- A **firewall policy audit** — every policy, every missing security profile, every logging gap
- An **SSL/SSH inspection profile audit** — inspection mode, cert validation posture, anomaly logging
- An **antivirus profile audit** — protocol coverage, sandbox integration, outbreak prevention
- A **system hardening audit** — admin hardening, interface exposure, global crypto settings, NTP, local-in policies
- An **ASCII UTM topology diagram** — per-policy visual of the full security stack from source to destination interface

All output is plain `.txt`, structured and readable by both humans and downstream tools (grep, awk, SIEM ingest).

---

## 🛡️ What It Audits

| Module | Config Section Parsed | Flag |
|---|---|---|
| Firewall Policies | `config firewall policy` | `-f` |
| SSL/SSH Inspection Profiles | `config firewall ssl-ssh-profile` | `-i` |
| AntiVirus Profiles | `config antivirus profile` | `-av` |
| Admin Accounts | `config system admin` | `-s` |
| Interfaces | `config system interface` | `-s` |
| Global Crypto & Hardening | `config system global` | `-s` |
| NTP Configuration | `config system ntp` | `-s` |
| Local-in Policies | `config firewall local-in-policy` | `-s` |
| UTM Flow Diagrams | All of the above | `-d` |

---

## 🔬 Security Checks Reference

### Firewall Policy Checks (`-f`)

| Severity | Check |
|---|---|
| `HIGH` | UTM disabled on an `action = accept` policy |
| `HIGH` | IPS sensor missing on an accept policy |
| `HIGH` | Antivirus profile missing on an accept policy |
| `HIGH` | SSL/SSH inspection profile missing on an accept policy |
| `MEDIUM` | Web filter profile missing |
| `MEDIUM` | DNS filter profile missing |
| `MEDIUM` | Application control profile missing |
| `MEDIUM` | Traffic logging disabled or not configured |
| `INFO` | NAT disabled (may be valid; flagged for review) |

### SSL/SSH Inspection Profile Checks (`-i`)

| Severity | Check |
|---|---|
| `HIGH` | Full/deep inspection without a CA certificate defined |
| `HIGH` | Untrusted certificates set to `allow` instead of `block` |
| `HIGH` | Invalid certificates set to `allow` instead of `block` |
| `MEDIUM` | Inspection mode not explicitly set |
| `MEDIUM` | SNI checking disabled |
| `MEDIUM` | Expired certificates not blocked |
| `MEDIUM` | SSL anomaly logging disabled |
| `MEDIUM` | Inspect-all-ports enabled (performance and accuracy risk) |
| `INFO` | Certificate-only inspection in use (no decryption) |

### Antivirus Profile Checks (`-av`)

| Severity | Check |
|---|---|
| `HIGH` | Malware action set to `monitor` or `pass` |
| `MEDIUM` | HTTP not inspected |
| `MEDIUM` | HTTPS not inspected |
| `MEDIUM` | FortiSandbox submission disabled |
| `MEDIUM` | Outbreak prevention disabled |
| `MEDIUM` | AV logging not clearly enabled |
| `INFO` | Flow-based mode in use (proxy preferred for thoroughness) |
| `INFO` | SMTP / POP3 / IMAP / FTP / CIFS not inspected |

### Admin Account Checks (`-s`)

| Severity | Check |
|---|---|
| `HIGH` | No trusted host restrictions on admin account |
| `HIGH` | Admin account using `super_admin` profile (no least privilege) |
| `HIGH` | Two-factor authentication not configured |
| `INFO` | Session timeout longer than 30 minutes |

### Interface Checks (`-s`)

| Severity | Check |
|---|---|
| `HIGH` | HTTP management access enabled on any interface |
| `HIGH` | Telnet management access enabled on any interface |
| `HIGH` | HTTPS management enabled on a WAN-role interface |
| `HIGH` | SSH management enabled on a WAN-role interface |
| `INFO` | Ping enabled on a WAN interface |

### Global Crypto / Hardening Checks (`-s`)

| Severity | Check |
|---|---|
| `HIGH` | `strong-crypto` not enabled |
| `MEDIUM` | `ssl-static-key-ciphers` not disabled |
| `MEDIUM` | DH parameters below 4096 bits (8192 recommended) |
| `MEDIUM` | Admin lockout threshold not configured |
| `MEDIUM` | Admin lockout duration not configured |
| `INFO` | Global admin timeout exceeds 30 minutes |

### NTP Checks (`-s`)

| Severity | Check |
|---|---|
| `MEDIUM` | NTP synchronization disabled |
| `MEDIUM` | Custom NTP type with no servers configured |
| `MEDIUM` | NTP authentication enabled but NTPv3 not set |
| `INFO` | Single NTP server (no redundancy) |
| `INFO` | NTP server-mode enabled |
| `INFO` | Sync interval extreme (very short or very long) |
| `INFO` | Source IP not set for NTP |
| `INFO` | NTP authentication disabled |

### Local-in Policy Checks (`-s`)

| Severity | Check |
|---|---|
| `HIGH` | Source address `all` on local-in-policy |
| `HIGH` | Accept policy with broad source (management exposure) |
| `MEDIUM` | No specific interface bound to local-in-policy |
| `MEDIUM` | Service set to `ALL` |

---

## 📦 Installation

No external dependencies. Python 3.8 or newer is all you need.

```bash
# Clone the repo
git clone https://github.com/jafartavana01/fortigate-utm-analyzer.git
cd fortigate-utm-analyzer

# Verify Python version
python3 --version   # 3.8+ required

# Run directly
python3 utm.py --help
```

Optional: make it executable system-wide on Linux/macOS:

```bash
chmod +x utm.py
sudo ln -s $(pwd)/utm.py /usr/local/bin/fg-audit
fg-audit --help
```

---

## 🚀 Usage

### Basic Syntax

```bash
python3 utm.py -c <config_file> [flags]
```

### Flags

| Flag | Description |
|---|---|
| `-c / --config` | **Required.** Path to FortiGate config file |
| `-f` | Generate firewall policy report |
| `-i` | Generate SSL/SSH inspection profile report |
| `-av` | Generate antivirus profile report |
| `-s` | Generate system hardening report (admins, interfaces, crypto, NTP, local-in) |
| `-d` | Generate per-policy UTM ASCII flow diagram |

### Examples

**Full audit — all reports at once:**
```bash
python3 utm.py -c firewall.conf -f -i -av -s -d
```

**Firewall policy audit only:**
```bash
python3 utm.py -c firewall.conf -f
```

**SSL/SSH and AV profile audit:**
```bash
python3 utm.py -c firewall.conf -i -av
```

**System hardening audit only:**
```bash
python3 utm.py -c firewall.conf -s
```

**Generate diagrams only:**
```bash
python3 utm.py -c firewall.conf -d
```

**Quick test with the bundled sample config:**
```bash
python3 utm.py -c sample_config.conf -f -i -av -s -d
```

### Getting the Config File from FortiGate

From the FortiGate CLI:
```
show full-configuration > backup.conf
```

Or via the GUI: **System → Backup → Full Configuration**, then save as a `.conf` file.

---

## 📁 Output Files

All outputs are written to the same directory where you run the tool. File names are automatically derived from the config file name:

| Flag | Output File |
|---|---|
| `-f` | `<config>_firewall_report.txt` |
| `-i` | `<config>_ssl_inspection_report.txt` |
| `-av` | `<config>_antivirus_report.txt` |
| `-s` | `<config>_system_report.txt` |
| `-d` | `<config>_diagram.txt` |

Example — running against `fw-prod.conf`:
```
fw-prod.conf_firewall_report.txt
fw-prod.conf_ssl_inspection_report.txt
fw-prod.conf_antivirus_report.txt
fw-prod.conf_system_report.txt
fw-prod.conf_diagram.txt
```

---

## 📄 Report Deep Dive

### Firewall Report (`-f`)

Each policy is rendered as an ASCII table followed by a severity-tagged weakness list:

```
Policy #1
+----------------------------------------------+
| Policy ID         | 1                        |
| Name              | LAN_to_Internet          |
| Action            | accept                   |
| Src Interface     | port1                    |
| Dst Interface     | wan1                     |
| Src Address       | all                      |
| Dst Address       | all                      |
| Service           | ALL                      |
| UTM Status        |                          |
| IPS Sensor        |                          |
| AV Profile        |                          |
| SSL/SSH Profile   |                          |
| Log Traffic       | disable                  |
+----------------------------------------------+
Weaknesses:
- HIGH: UTM is disabled on an accept policy.
- HIGH: IPS profile is missing on an accept policy.
- HIGH: Antivirus profile is missing on an accept policy.
- HIGH: SSL/SSH inspection profile is missing for encrypted traffic.
- MEDIUM: Web filter profile is missing on an accept policy.
- MEDIUM: DNS filter profile is missing on an accept policy.
- MEDIUM: Application control profile is missing on an accept policy.
- MEDIUM: Logging is disabled or not configured for this policy.
```

### System Report (`-s`)

Combines admin, interface, global crypto, NTP, and local-in into one file with clearly separated sections:

```
=== Administrator Accounts ===
=== Interfaces ===
=== Global Crypto / Admin Settings ===
=== NTP Settings ===
=== Local-in Policies ===
```

---

## 🗺️ UTM Flow Diagram

The `-d` flag generates a full ASCII topology diagram for every firewall policy, showing the source interface, all attached UTM profiles with their key settings, and the destination interface:

```
[port1 - lan]
   +--> interface name: port1
   +--> ip/mask: 192.168.1.1 255.255.255.0
   +--> role: lan
   +--> administrative access: ping https
   +--> vlan: none
   |
   v
[Policy 1: LAN_to_Internet]
   +--> policy id: 1
   +--> incoming interface: port1
   +--> outgoing interface: wan1
   +--> source: all
   +--> destination: all
   +--> service: ALL
   +--> action: accept
   +--> nat: enable
   +--> utm status -> enable
   |
   +--> SSL/SSH Profile
   |      +--> profile name: certificate-inspection
   |      +--> mode: certificate-inspection
   |      +--> SNI check: strict
   |      +--> untrusted certificates: block
   |
   +--> Antivirus Profile
   |      +--> profile name: strict-av
   |      +--> feature set: proxy
   |      +--> HTTP: enable
   |      +--> HTTPS: enable
   |      +--> outbreak prevention: enable
   |
   +--> IPS Profile
   |      +--> profile name: default-ips
   |
   +--> Web Filter Profile
   |      +--> profile name: corporate-policy
   |
   +--> App Control
   |      +--> profile name: strict-app
   |
   +--> DNS Filter
   |      +--> profile name: secure-dns
   |
   v
[wan1 - wan]
   +--> interface name: wan1
   +--> role: wan
   +--> source NAT: enable
   +--> next hop: default gateway or specific route
```

---

## 🏗️ Architecture

The tool is intentionally built with zero external dependencies — nothing to `pip install`, no virtualenv required. This makes it trivially portable: copy the script to any machine with Python 3.8+ and run it.

### Parsing Model

FortiGate config files follow a consistent structure:

```
config <block_name>
    edit <id>
        set <key> <value>
        set <key> <value>
    next
end
```

The core generic parser `extract_block(text, block_name)` handles this pattern. All domain-specific parsers (`parse_firewall_policies`, `parse_ssl_profiles`, etc.) are one-liners that call `extract_block` with the right block name.

The only special cases are `config system global` (no `edit` entries, just flat `set` lines) and `config system ntp` (nested `config ntpserver` sub-block), which have dedicated parsers.

### Weakness Logic

Each object type has a dedicated `*_weaknesses()` function that receives a parsed dict and returns a list of strings, each prefixed with severity (`HIGH`, `MEDIUM`, `INFO`). Adding a new check is as simple as adding an `if` condition and appending to the list.

### Module Overview

```
utm.py
├── Generic helpers       read_config, normalize_value, parse_set_line, extract_block
├── Parsers               parse_firewall_policies, parse_ssl_profiles, parse_av_profiles,
│                         parse_admins, parse_interfaces, parse_system_global,
│                         parse_ntp, parse_local_in
├── Weakness checks       firewall_weaknesses, ssl_weaknesses, av_weaknesses,
│                         admin_weaknesses, interface_weaknesses,
│                         global_crypto_weaknesses, ntp_weaknesses, local_in_weaknesses
├── Report generators     generate_firewall_report, generate_ssl_report,
│                         generate_av_report, generate_system_report, generate_diagram
├── Diagram builder       build_policy_diagram
└── CLI                   main()
```

---

## 🔧 Extending the Tool

### Adding a New Check

Open `utm.py` and find the relevant `*_weaknesses()` function. Add your check:

```python
def firewall_weaknesses(policy: Dict[str, Any]) -> List[str]:
    findings = []
    # ... existing checks ...

    # New check: flag any policy permitting ICMP broadly
    service = normalize_value(policy.get("service", ""))
    if "ICMP" in service.upper() and srcaddr in ("all", ""):
        findings.append("MEDIUM: Policy permits ICMP from all sources; consider restricting.")

    return findings
```

### Adding a New Config Section

1. Add a parser function using `extract_block` (or a custom parser for flat sections):

```python
def parse_vpn_ipsec(text: str) -> List[Dict[str, Any]]:
    return extract_block(text, "vpn ipsec phase1-interface")
```

2. Add a `*_weaknesses()` function for the new section.
3. Add a new report generator or extend `generate_system_report`.
4. Wire it into `main()` under a new CLI flag.

### Exporting to JSON / CSV

Replace the `out_path.write_text(...)` calls in any `generate_*` function with `json.dumps()` or `csv.writer` output. The parsed dicts are already clean Python objects — no reformatting needed.

---

## 🔒 Security Considerations

> **⚠️ FortiGate configuration files contain sensitive information.** Treat them as secret material.

- Never commit real FortiGate config files to version control. The `.gitignore` in this repo excludes all `*.conf` files except `sample_config.conf`.
- Store config backups in encrypted storage (LUKS, BitLocker, or an encrypted vault like HashiCorp Vault / GPG-encrypted archive).
- The tool reads the file locally and never makes network connections. Audit results stay on your machine.
- When sharing reports with third parties, redact IP addresses, admin usernames, and pre-shared keys before sending.
- On multi-user systems, restrict read permissions on config files: `chmod 600 firewall.conf`.

---

## 🗺️ Roadmap

- [ ] JSON and CSV output format options (`--format json`)
- [ ] CVSS-like composite scoring per policy and per section
- [ ] IPS sensor profile parsing and audit
- [ ] Web filter profile parsing and audit
- [ ] Application control profile parsing and audit
- [ ] DNS filter profile parsing and audit
- [ ] VPN IPsec Phase 1 / Phase 2 audit
- [ ] SSL VPN configuration audit
- [ ] HA configuration check
- [ ] FortiOS version detection and version-aware checks
- [ ] HTML report output with color-coded severity table
- [ ] VDOM-aware parsing (multi-VDOM environments)
- [ ] Diff mode: compare two config files and report what changed

---

## 👤 Author

**Jafar Tavana**
Network Security Engineer | CCIE Candidate | FortiGate Specialist

- GitHub: [@jafartavana01](https://github.com/jafartavana01)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⭐ If This Helped You

If this tool saved you time on a security audit or helped you catch a misconfiguration before it became an incident, consider starring the repo. It helps other network engineers find it.
