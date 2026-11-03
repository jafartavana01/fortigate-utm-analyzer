# Offline dashboard and extended audits (4.1.0)

## Generate and open the dashboard

```bash
python3 utm.py -c firewall.conf --all --html
python3 utm.py -c firewall.conf -s -vpn -cert --html
python3 utm.py -c firewall.conf -bgp --summary --html
python3 utm.py -c firewall.conf -auth --summary --html
python3 utm.py -c firewall.conf --radius --ldap --saml --mfa --html
```

Open `firewall.conf_REPORT.html` directly in a current browser. No server, internet connection, fonts, CDN, Node build, or additional Python package is required. By default, outputs go in a newly created subdirectory of the current working directory named after the **input filename without its final extension**: `firewal_001.cfg` → `./firewal_001/`. This uses the filename stem, not the FortiGate hostname declared inside the backup. All report filenames retain their original input basename prefix. Pass `--out-dir DIRECTORY` (alias: `--output-dir DIRECTORY`) to override the destination for every TXT, JSON, summary and HTML report; use `--out-dir .` for the legacy current-directory layout. For example: `python3 utm.py -c firewall.conf --all --html --out-dir ./reports/firewall`. Missing parent directories are created automatically. Repeated runs with the same basename in the same output directory overwrite their corresponding outputs; use different directories for separate assessments.

`--html` explicitly adds a dashboard; `--all` retains text/JSON operation unless `--html` is supplied. `--html` alone produces a report with no executed audit domains, never silently runs a full audit. `--summary` alone retains its original warning and produces no summary. Individual UTM flags retain their original grouped behavior: for example, `-ips` executes the entire UTM profile group. The HTML coverage list reflects the domains actually collected, including that group.

The dashboard contains an executive risk overview, exact severity counts, an SVG distribution ring, severity bars by domain, and the five highest weighted domain scores. Risk weights and thresholds use the existing `compute_summary()` function: critical × 10, high × 5, medium × 2, informational × 0.5. Any critical finding or score at least 50 means CRITICAL; at least 25 means HIGH; at least 10 means MEDIUM; otherwise LOW. This is **not a normalized security percentage or a guarantee of security**.

Search is case-insensitive across finding fields, evidence, scope, and available remediation. Severity, domain and scope filters combine with search and sorting. The explorer initially renders 80 findings; Load more displays additional results. Charts describe the **whole executed assessment**, while filters affect the explorer. Details are expanded on demand. Native keyboard-operable disclosures, visible focus outlines, text severity labels, accessible chart descriptions and narrow-screen layouts support accessible use.

The theme starts with the system preference and can be toggled. Preference persistence is best effort when browser local storage is available. CLI blocks offer a copy control and selection fallback if clipboard permissions are unavailable. Print/PDF expands all **matching** findings and the technical references, including findings beyond the on-screen page. Restoring the normal view after printing preserves filters and restores open findings. Browser print layout and clipboard permissions depend on the browser.

## Findings and original remediation

Legacy weakness functions still return severity-prefixed strings. `compute_summary()` and the existing `SUMMARY.json` schema consume those same results; HTML does not run separate detection logic.

A small `Finding(str)` adapter adds structured evidence, recommendations, affected object, scope and rule ID for new findings. It still serializes as a string for existing JSON consumers. Structured HTML data is separately versioned (`schema_version: 1`); it does not change legacy JSON field types.

`ReportOutput` retains report content in a per-run sink before writing it to disk. HTML includes these shared domain technical references without reading or scraping completed TXT files. Existing references may contain multiline commands, arrow-separated guidance and placeholders. They are labeled as original guidance and may require adaptation; they are not represented as universally safe, complete commands for every finding. Legacy findings often lack independent impact/evidence fields; the dashboard states this rather than inventing them. Object attribution for legacy strings is best effort; their VDOM is explicitly unscoped.

Exact review examples are provided for explicit LDAP identity/TLS settings, SAML SHA-256 selection and RADIUS identity/Message-Authenticator settings. They must be applied in the displayed scope after compatibility and operational checks. No route policies, passwords, CA names or numeric prefix limits are fabricated. New BGP findings supply operational recommendations rather than guessed executable configuration.

## Implemented check inventory

Counts below are distinct rule families, not the number of object-specific findings. IPv4/IPv6 and repeated objects can produce multiple findings for one rule.

| Domain / selection | Rules | Configuration-backed conditions |
| --- | ---: | --- |
| BGP (`-bgp`, `--bgp`) | 8 | Authentication not shown; inbound filtering not shown; outbound filtering not shown; missing/zero prefix ceiling; warning-only prefix limit; explicit multihop TTL over 10; enabled connected/static redistribution without a route-map; missing referenced neighbor group |
| RADIUS (`--radius`, `-auth`) | 5 | Explicit UDP/TCP transport; CHAP/MS-CHAP v1 selection; TLS identity check disabled; Message-Authenticator requirement disabled; no alternate endpoint shown for a single object |
| LDAP (`--ldap`, `-auth`) | 4 | Encryption explicitly disabled; TLS identity check disabled; no explicit CA reference for TLS; obsolete explicit minimum TLS version |
| SAML (`--saml`, `-auth`) | 3 | HTTP browser SSO/logout endpoint; explicit SHA-1 digest; missing IdP certificate reference |
| Administrator MFA (`--mfa`, `-auth`, `-s`) | 1 refined control | Known local MFA; local MFA not shown; potentially delegated external/PKI authentication; unrecognized setting. The last two are informational uncertainty outcomes, not missing-MFA claims. |
| Cryptography (`-s`) | 4 added field families | Explicit modern `ssh-enc-algo`, `ssh-kex-algo`, `ssh-mac-algo`, and `admin-https-ssl-versions` allow weak/legacy algorithms or obsolete protocol versions. Read at the documented global/SSH block locations. |

`--all` includes BGP and authentication. `-s` already evaluates administrator MFA; selecting it alongside `-auth`/`--mfa` does not count that control twice. Explicit MFA exceptions for break-glass accounts require operator review; no account name is automatically exempted.

New TXT files are `_bgp_security_report.txt`, `_radius_report.txt`, `_ldap_report.txt`, `_saml_report.txt` and, when MFA is selected separately from `-s`, `_admin_mfa_report.txt`. These share the usual input basename prefix and join existing summary/HTML collection.

## Scope, defaults and applicability

The new parser preserves `config`/`edit` nesting, quoted names, multiline values, `unset` and `append`. Each VDOM retains its own object namespace. Global settings are not merged into a VDOM. Repeated declaration/full-configuration containers for the same VDOM are combined. Malformed, unsupported or truncated statements make new audits **unavailable** rather than generating a reassuring empty result. A selected domain with no applicable objects is labeled not applicable to the supplied scope.

New BGP and authentication audits use this model. **Legacy policy, VPN, object-reference and other domains still use their original first-matching-block parsers. Their multi-VDOM coverage is incomplete.** HTML and extended report notes disclose this. Comprehensive migration of those domains remains future work. Do not interpret a full `--all` report as an exhaustive multi-VDOM assessment.

BGP dynamic neighbor groups are evaluated once when referenced by a neighbor range. Unused templates are skipped. eBGP policy/prefix-limit suggestions apply only when both ASNs are known and differ. iBGP and unknown ASNs do not inherit those requirements. ASDOT notation is supported. Shutdown neighbors are skipped. IPv4 is checked unless explicitly disabled; IPv6-specific filter checks require explicit `activate6 enable`. Other address families and implicit IPv6 defaults are outside this release's verified coverage. A filter reference does not prove a route policy's contents are restrictive; actual route advertisements and upstream controls cannot be inferred. Missing authentication is a review finding because an encrypted tunnel may provide other protection.

New authentication and crypto checks evaluate explicit settings and avoid inferring insecure version-dependent defaults. Missing transport/TLS/digest fields are unknown, not a claim of secure configuration. A missing explicit LDAP CA reference is informational; this does not prove disabled trust-chain validation. HTTP SAML entity IDs are identifiers, not browser transport, and are not flagged. RADIUS over UDP/TCP may be appropriate over a protected network or tunnel. A single endpoint may be a VIP backed by service HA. Encrypted secrets are never assessed for recovered plaintext strength.

Version detection reads backup `#config-version` headers or explicit FortiOS version text; unknown remains unknown. Existing version-specific parsers are retained. The new checks use documented explicit keys across the referenced releases, not a complete default/feature matrix for every FortiOS 6/7/8 release. Default-based analysis, full SAML assertion validation, certificate chain validation, runtime BGP state and IdP MFA enforcement are outside offline coverage.

## Security and confidentiality

HTML uses JSON escaping for `<`, `>` and `&`, including script terminators; configuration-derived values are rendered with text nodes. A Content Security Policy authorizes the exact static application script by SHA-256 and denies network connections and external assets. No configuration is uploaded by the analyzer.

Configured password/hash, PSK, secret, token, access/API key, private-key and certificate-material field values are redacted before embedding in HTML, including known values echoed in report text, encrypted values and multiline material. SNMP community names and obvious URL credentials/token parameters are also handled. Hidden JSON and search data use the same sanitized payload. This is field-based redaction, **not a guarantee that arbitrary free text, novel secret formats, user-generated comments or encoded copies of credentials are identifiable**. New extended TXT reports are sanitized; legacy TXT/JSON confidentiality behavior is preserved and may contain sensitive data. Review all outputs before sharing and protect them as confidential network assessment artifacts.

There are no telemetry, network requests or external asset dependencies at runtime. The README's existing online badges are documentation assets and are not included in generated HTML.

## Compatibility and verified limits

The bundled original sample remains 310 findings, 876.5 risk points, CRITICAL. Existing domain TXT reports preserve their contents on that sample. `--all` adds the new domain TXT reports and additive empty finding/section keys where their objects are absent. JSON retains top-level `summary` and `findings`, existing keys/types and weights. Consumers should permit additional domain names. Summary counts can change when new audit evidence is present.

Two intentional correctness fixes may change findings on other backups: external/PKI admin MFA now yields informational uncertainty rather than a definite missing-MFA warning; SHA-256 SSH group14 key exchange is no longer falsely matched as legacy group1/group14 SHA-1. Existing legacy audit assumptions outside these changes have not been comprehensively revalidated.

## Tests

```bash
python3 -m py_compile utm.py
python3 utm.py --help
python3 utm.py -c sample_config.conf --all
python3 utm.py -c sample_config.conf --all --html
python3 -m unittest discover -s tests -v
```

The standard-library suite covers reporting, XSS, redaction, counts, applicability, empty and 5,000-finding cases, parser nesting/malformed input, BGP families/groups, auth/MFA/crypto positive and negative examples, VDOM isolation, all 29 legacy domain flags, selected modules and preserved TXT/JSON behavior. Node is optional and used only for development checks: generated JavaScript syntax and a dependency-free DOM harness that exercises counters, combined filters, search, sorting, pagination, detail expansion, blocked clipboard/storage fallbacks, themes and print state transitions. The harness is not a real browser and cannot establish rendering or browser-platform behavior. The GitHub Actions matrix targets Python 3.8, 3.11 and 3.14. Initial remote jobs were marked failed before recording any steps, and job logs returned HTTP 404 through the connector. Remote CI is blocked/unverified; its cause was not exposed. Local verification used the available Python interpreter. No browser binary was available in the implementation environment; search/filter/copy/theme/print behavior and final visual layout still require real-browser validation. No screenshot is supplied.

## Fortinet syntax references

These references informed the explicit keys and examples; they do not establish that every feature exists or has identical defaults in every release.

- [FortiOS 7.4.7 BGP CLI reference](https://docs.fortinet.com/document/fortigate/7.4.7/cli-reference/225427711/config-router-bgp)
- [FortiOS 6.4.15 BGP CLI reference](https://docs.fortinet.com/document/fortigate/6.4.15/cli-reference/492620/config-router-bgp)
- [FortiOS 7.4.1 LDAP CLI reference](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/470620)
- [FortiOS 7.4.7 RADIUS configuration guide](https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/759080/configuring-a-radius-server)
- [FortiOS 7.4.11 RADIUS CLI reference](https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/164332072)
- [FortiOS 7.4.8 SAML CLI reference](https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/104734780)
- [FortiOS 7.4.5 encryption/SSH guide](https://docs.fortinet.com/document/fortigate/7.4.5/administration-guide/484445)
- [FortiOS 7.0.2 SSH algorithm selection changes](https://docs.fortinet.com/document/fortigate/7.0.0/new-features/765236)
- [FortiOS 7.0.2 administrator CLI reference](https://docs.fortinet.com/document/fortigate/7.0.2/cli-reference/16620/config-system-admin)
