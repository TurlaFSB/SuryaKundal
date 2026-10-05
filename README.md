# Surya Kundal

An SSH honeypot platform built on [Cowrie](https://github.com/cowrie/cowrie). Attacker sessions are parsed, enriched with threat intelligence, mapped to MITRE ATT&CK techniques, stored in a database, and surfaced on a live dashboard and in Wazuh.

The name comes from Karna's *kavach and kundal* in the Mahabharata: armour that looks like protection but is the thing the gods schemed to take. A honeypot is the same idea turned around, a system that looks like a real target and exists only to be studied.

> **Status:** early development. Phase 1 (Cowrie + log parser) is in progress. Nothing below the "Built" line is implemented yet.

## Architecture

```
Internet / attacker
        |
  [Cowrie SSH honeypot]          cowrie.json (one JSON event per line)
        |
  [Log parser]                   groups events into one record per session
        |
  [Enrichment]                   AbuseIPDB, IPInfo, VirusTotal, GreyNoise
        |
  [ATT&CK mapper]                command -> technique ID (e.g. T1105)
        |
  [SQLite via SQLAlchemy]        sessions, commands, intel, mappings
        |
  +-----+------------------+
  |                        |
[Wazuh rules]        [Flask dashboard]
```

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 0 | Repo skeleton, tests, CI | in progress |
| 1 | Cowrie running, log parser | in progress |
| 2 | Database layer and live log watcher | planned |
| 3 | Threat-intel enrichment with caching and rate limits | planned |
| 4 | MITRE ATT&CK mapping engine | planned |
| 5 | Wazuh custom rules | planned |
| 6 | Flask dashboard (live feed, map, ATT&CK heatmap, session drill-down) | planned |
| 7 | Docker Compose for the whole stack | planned |
| 8 | Deploy to a cloud VM and collect real attacker data | planned |
| 9 | Write-up, demo, documentation | planned |

All enrichment sources use free tiers. No paid services are required.

## Built so far

- Cowrie 3.x running locally in a Kali VM, logging JSON events
- Log parser in `parser/log_parser.py`
- Test suite for the parser in `tests/`, with sample events taken from a real captured session
- CI running `pytest` on every push
- Project skeleton for the later phases (empty packages, config template)

## Project layout

```
parser/        Cowrie log parsing (Phase 1)
database/      SQLAlchemy models and storage (Phase 2)
enrichment/    Threat-intel API clients (Phase 3)
mapping/       ATT&CK mapping engine (Phase 4)
wazuh/         Custom Wazuh rules (Phase 5)
dashboard/     Flask web UI (Phase 6)
cowrie/        Notes on our Cowrie configuration
tests/         pytest suite
.env.example   Required environment variables
```

`docker-compose.yml` is added in Phase 7, once there is a real stack to orchestrate.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -v
```

Run the parser against a local Cowrie log:

```bash
python -m parser.log_parser
```

## Security notes

- Honeypot logs, captured malware samples, databases, and `.env` files are git-ignored. Never commit them.
- When deployed on the public internet, outbound traffic from the honeypot host must be restricted. Cowrie performs real downloads when an attacker runs `wget` or `curl`.
- Run the honeypot on an isolated host or network, never alongside real services.
