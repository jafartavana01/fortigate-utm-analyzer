# 4.1.0 implementation report

## A. Implementation summary

An incremental extension of upstream commit `37501a07e08665223af253e913b12a8135c0d4c8` adds an entirely offline HTML dashboard and documented configuration-backed BGP, identity and crypto checks. `utm.py` remains the sole executable and has no mandatory external dependencies. Existing audit functions and summary scoring remain the shared source of truth.

## B. Modified files

| File | Purpose |
| --- | --- |
| `utm.py` | Structured string adapter, sanitized HTML payload and embedded UI, per-run report references, context-preserving parser, new audits and CLI integration |
| `README.md` | Current release entry, usage, compatibility notes and feature-document link |
| `.gitignore` | Exclude all generated assessment outputs |
| `docs/HTML_AND_AUDITS.md` | Features, exact rule inventory, applicability limits, examples, architecture, confidentiality and Fortinet syntax references |
| `tests/test_html.py` | HTML security, data, CLI compatibility and optional JavaScript checks |
| `tests/test_audits.py` | Parser, scope, BGP/authentication/MFA/crypto checks and legacy flag smoke tests |
| `tests/dashboard_runtime.cjs` | Dependency-free development DOM harness for actual embedded JavaScript state transitions |
| `.github/workflows/tests.yml` | Standard-library test matrix for Python 3.8, 3.11 and 3.14 |
| `docs/IMPLEMENTATION_REPORT.md` | This completion report |

## C. HTML dashboard

`--html` generates `<input-basename>_REPORT.html` in the working directory. The dashboard includes executive cards; three chart views; combined search/severity/domain/scope filters; five sort orders; expandable findings; explicit evidence and remediation where available; shared original technical references; copy fallback; themes; responsive CSS; and print/PDF styling. Findings render in pages of 80. A 5,000-finding generation case is covered.

HTML is opt-in, including with `--all`. `--html` without an audit selection produces an explicitly empty assessment. No TXT rereads, CDN, external font, build pipeline or browser network request is needed. JSON script terminators are encoded; configuration data uses text nodes. The static script is authorized by a CSP hash. Configured secret values are removed from the embedded data and references. Arbitrary free text still requires confidentiality review.

Legacy strings do not always provide separate impact/evidence or exact CLI. The UI states those limits and retains original domain guidance without attributing every domain example to every finding. New settings receive exact review examples only where a documented explicit field allows it; route-policy values and trust anchors are never invented.

## D. New and improved audits

| Domain | Implemented rules | Severity coverage | Local test status |
| --- | ---: | --- | --- |
| BGP | 8 | MEDIUM | Pass |
| RADIUS | 5 | HIGH, MEDIUM, INFO | Pass |
| LDAP | 4 | HIGH, INFO | Pass |
| SAML | 3 | HIGH, MEDIUM | Pass |
| MFA | 1 existing control refined; external/unknown informational outcomes added | HIGH, INFO | Pass |
| Cryptography | 4 explicit-field families added | HIGH, MEDIUM | Pass |

See `HTML_AND_AUDITS.md` for conditions, rule IDs, assumptions and boundaries. Counts are rule families, not object instances. No new CRITICAL condition is claimed without evidence justifying it.

## E. Compatibility assessment

The original bundled sample remains **310 findings, score 876.5, CRITICAL**. Its existing 19 domain TXT reports remain byte-for-byte identical to the recorded baseline. The phase-one HTML-only extension also preserved the original summary files byte-for-byte before audit expansion.

The final `--all` intentionally adds four extended domain TXT files and additive BGP/RADIUS/LDAP/SAML keys in summary findings/sections when sample objects are absent. JSON retains `summary` and `findings`, existing value types, weights and thresholds. Selected original-module workflows preserve their outputs unless their input triggers an intentional correctness change or a newly added explicit-field crypto check.

Intentional correctness changes: external/PKI administrator authentication is no longer definitive proof of absent MFA; group14 SHA-256 is no longer matched as legacy SHA-1. Grouped UTM flags, current-directory output naming, summary-only warning, and existing error behavior are retained. Empty enhanced-local-in results are now represented as audited rather than unselected.

## F. Testing results and limits

Executed locally:

```text
python3 -m py_compile utm.py
python3 utm.py --help
python3 utm.py -c sample_config.conf --all
python3 utm.py -c sample_config.conf --all --html
python3 -m unittest discover -s tests -v
# 80 tests passed; no skipped tests in the local run

git diff --check
```

The suite exercises all 29 original domain flags as subcases. Node syntax and the DOM harness passed. Those checks do **not** replace a browser: no Chromium executable was available, so pixel layout, actual file-URL behavior, clipboard permissions, browser printing and browser accessibility still need verification. No screenshot is fabricated or supplied. Python version-matrix CI is configured; local success is not a claim that all remote interpreter jobs have run.

## G. Usage examples

```bash
# Complete audit plus HTML; retain existing reports
python3 utm.py -c firewall.conf --all --html

# Selected original modules plus HTML
python3 utm.py -c firewall.conf -s -vpn -cert --html

# BGP, or identity, with shared executive TXT/JSON and HTML
python3 utm.py -c firewall.conf -bgp --summary --html
python3 utm.py -c firewall.conf -auth --summary --html

# Original TXT/JSON workflow
python3 utm.py -c firewall.conf -f -av -s --summary
```

## H. Remaining work

- Real-browser acceptance and visual/accessibility review on desktop/mobile, file URLs and print/PDF.
- Migrate legacy policy, VPN, object-reference and other audits to the new VDOM model; they still use first-block parsing. New BGP/authentication checks are scoped, and reports disclose the difference.
- A verified FortiOS release/default matrix. New checks conservatively evaluate explicit settings, not speculative insecure defaults. Some older legacy checks still infer defaults and need a separate accuracy review.
- Evaluate actual routing-policy contents, other BGP address families and implicit IPv6 defaults. Referenced filters do not establish effective route safety.
- Live reachability, upstream protection, actual IdP MFA, trust-chain validation and runtime authentication are outside this offline tool's capabilities.

The implementation is prepared for review. These remaining items are not represented as completed production validation.
