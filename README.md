# Surya Kundal

**An SSH honeypot platform that turns raw attacker activity into structured, enriched, ATT&CK-mapped intelligence.**

Surya Kundal runs a [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot, reconstructs every attacker visit as a structured session, and stores it in a queryable database. The planned phases add per-IP threat-intelligence enrichment, mapping of attacker commands to MITRE ATT&CK techniques, Wazuh SIEM alerting, and a live dashboard.

> **Status:** early development. Capture, session reconstruction, storage, and the command-line tools work today. Enrichment, ATT&CK mapping, Wazuh integration, and the dashboard are not built yet. The table below is explicit about which is which.

## Why this exists

A honeypot's native output is a flat stream of events: one JSON line per connection, key exchange, login attempt, and command. That is hard to turn into answers to the questions that matter: *who is this, what technique are they using, and how dangerous is it?* Surya Kundal is the analysis layer on top of the honeypot that answers them.

## Capabilities

| Capability | Status |
|---|---|
| SSH honeypot capture (Cowrie) | Working |
| Session reconstruction from the event stream: credentials tried, commands typed, files downloaded (with SHA-256), timing, client version, HASSH fingerprint | Working |
| Durable SQLite storage with idempotent, failure-isolated import | Working |
| `surya-kundal ingest` / `list` command-line tools | Working |
| Live log following (store events as they arrive) | In progress |
| Threat-intelligence enrichment of attacker IPs, cached per IP to respect free-tier limits | Planned |
| MITRE ATT&CK technique mapping of attacker commands | Planned |
| Wazuh SIEM rules for high-risk behaviour | Planned |
| Web dashboard: live feed, attack map, ATT&CK heatmap, session drill-down | Planned |
| One-command deployment with Docker Compose | Planned |
| Public deployment and real-world data collection | Planned |

## Architecture

```
Internet / attacker
        |
  [Cowrie SSH honeypot]          cowrie.json (one JSON event per line)
        |
  [Log parser]                   groups events into one record per session
        |
  [Enrichment]                   free-tier and offline sources (provider list finalised in Phase 3)
        |
  [ATT&CK mapper]                command -> technique ID (e.g. T1105)
        |
  [SQLite via SQLAlchemy]        sessions, logins, commands, downloads (+ intel, mappings later)
        |
  +-----+------------------+
  |                        |
[Wazuh rules]        [Flask dashboard]
```

Everything from the log parser onward is code in this repository. Cowrie itself is used unmodified as the capture engine.

## Data model

| Table | One row per | Key fields |
|---|---|---|
| `sessions` | attacker visit | Cowrie session ID, source IP, start/end time, duration, SSH client version, HASSH |
| `logins` | credential attempt | username, password, success flag, timestamp |
| `commands` | command typed | order within the session, command text, timestamp |
| `downloads` | file fetched by the attacker | URL, SHA-256, timestamp |

## Engineering approach

What is in place today:

- **Idempotent import.** Importing the same log twice never creates duplicates, and a session stored while still in progress is completed when its closing events arrive.
- **Failure isolation.** A malformed log line is skipped, and a session that fails to save is logged without aborting the rest of the import.
- **Correct time handling.** Timestamps are stored and returned as timezone-aware UTC. SQLite returns naive datetimes by default, so a custom column type enforces this.
- **Database integrity.** Foreign keys are enforced (SQLite ignores them unless enabled) and WAL mode lets a reader, such as the dashboard, work while the importer writes.
- **Typed SQLAlchemy 2.0 models** and a clean `src/` package layout, installable with `pip`.
- **Tests built on real data.** The suite covers the parser, storage, import, and CLI, using events taken from a real captured session.
- **CI.** Every push runs ruff (lint and format check) and pytest on Python 3.11 and 3.13.

Planned alongside the later phases: secrets only through the environment, API rate limiting and quota management, per-IP intel caching, and a containerised deployment with outbound traffic restricted on the honeypot host.

## Getting started

Prerequisites: Python 3.11+ and a running Cowrie instance. Our Cowrie settings are noted in [`cowrie/README.md`](cowrie/README.md).

```bash
git clone https://github.com/TurlaFSB/SuryaKundal.git
cd SuryaKundal
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

Import a Cowrie log and look at what was captured:

```bash
surya-kundal ingest --log ~/cowrie/var/log/cowrie/cowrie.json
surya-kundal list
```

The database location comes from `DATABASE_URL` (default `sqlite:///data/surya_kundal.db`). See `.env.example` for all settings.

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Repo skeleton, tests, CI | Done |
| 1 | Cowrie running, log parser | Done |
| 2 | Database layer and live log watcher | Database and batch import done; live watcher next |
| 3 | Threat-intel enrichment with caching and rate limits | Planned |
| 4 | MITRE ATT&CK mapping engine | Planned |
| 5 | Wazuh custom rules | Planned |
| 6 | Flask dashboard | Planned |
| 7 | Docker Compose for the whole stack | Planned |
| 8 | Deploy to a cloud VM and collect real attacker data | Planned |
| 9 | Write-up, demo, documentation | Planned |

Only free tiers and free offline datasets are used. No paid services are required. Free-tier limits are checked against each provider's own documentation before a provider is adopted.

## Project layout

```
src/surya_kundal/
    parser/        Cowrie log parsing
    database/      SQLAlchemy models, engine setup, storage
    enrichment/    Threat-intel clients (Phase 3)
    mapping/       ATT&CK mapping engine (Phase 4)
    dashboard/     Flask web UI (Phase 6)
    ingest.py      Log import orchestration
    cli.py         surya-kundal command
wazuh/             Custom Wazuh rules (Phase 5)
cowrie/            Notes on our Cowrie configuration
tests/             pytest suite
pyproject.toml     Packaging, dependencies, ruff and pytest config
.env.example       Required environment variables
```

`docker-compose.yml` is added in Phase 7, once there is a real stack to orchestrate.

## Security notes

- Honeypot logs, captured malware samples, databases, and `.env` files are git-ignored. Never commit them.
- When deployed on the public internet, outbound traffic from the honeypot host must be restricted. Cowrie performs real downloads when an attacker runs `wget` or `curl`.
- Run the honeypot on an isolated host or network, never alongside real services.
