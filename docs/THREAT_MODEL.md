# Threat model

This document covers the risks of *running* Surya Kundal, as opposed to the attackers it is
designed to observe. It is a living document: update it when the architecture changes.

## Assets

- The honeypot host and anything else on its network.
- The captured data: attacker IPs, credentials they tried, commands, malware samples.
- API keys (AbuseIPDB, VirusTotal, MaxMind) and the dashboard password.
- The analyst's workstation and browser.
- The integrity of the analysis (an attacker should not be able to falsify or poison it).

## Trust boundaries

1. Internet to Cowrie: fully hostile.
2. Cowrie's log to the parser and database: still hostile, since every field is attacker-chosen.
3. Database to dashboard, terminal and SIEM: hostile text on its way to a person or a tool.
4. Platform to third-party APIs: our secrets and indicators leave the machine.

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | The attacker escapes the honeypot and reaches the host or its network | Dedicated host or VM with nothing else on it; Cowrie runs as an unprivileged user; outbound traffic restricted; no credentials for other systems on the box | Cowrie or Python vulnerabilities; keep Cowrie updated |
| 2 | The honeypot is used to attack others (downloads, tunnels, scans) | Egress firewall (deny by default); Cowrie's tunnels are emulated; port-forward attempts are logged as T1090 | Misconfigured firewall; verify before exposing |
| 3 | A crafted log line crashes, hangs or corrupts the pipeline | Defensive parser; bounded command analysis (no unbounded regex work); failure-isolated storage; property-based tests | Unknown parser bugs |
| 4 | Terminal or browser manipulation through attacker text | `printable` removes control and invisible characters; Jinja autoescape; strict CSP with no inline script or style | A new view that forgets the filter; reviewed in CONTRIBUTING |
| 5 | Attackers learn they are in a honeypot and stay away or feed it misleading data | Deception kit; the list of residual tells is public in `cowrie/FINGERPRINTING.md`; fingerprinting attempts are themselves detected (T1497) | A capable adversary can still tell; the project raises cost, it does not promise invisibility |
| 6 | Dashboard exposure: unauthenticated access, password guessing, DNS rebinding | Localhost by default; refuses non-local without a password; throttling; unknown `Host` refused without a password; read-only database | Plain HTTP unless fronted by TLS |
| 7 | Denial of service on the dashboard | Cached overview, bounded queries and page sizes, request-size and connection limits | A determined flood needs a real reverse proxy or firewall |
| 8 | Secret leakage | `.env` git-ignored with permission warning; clients never log URLs; no secrets in errors; `doctor` never prints keys | Secrets in shell history or screenshots |
| 9 | Dependency or supply-chain compromise | `pip-audit` and CodeQL in CI; Dependabot; a small dependency set | Zero-day in a dependency; actions are pinned to tags, not commit hashes |
| 10 | Captured malware executed by accident | Samples are stored by hash and never executed; the platform only records hashes and metadata | Analyst handling samples elsewhere |
| 11 | Legal and privacy: attacker IPs and credentials are personal data in some jurisdictions | Data stays local; GeoLite2 not redistributed; publish only aggregates or anonymised data | Check local law and the hosting provider's policy before public deployment |

## Out of scope

Defending a real production network, or the confidentiality of data an attacker sends to the
honeypot (it is, by design, collected).
