# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Read-only web dashboard (`surya-kundal dashboard`): attack map, session-depth funnel,
  honeypot-check panel, ATT&CK matrix, session drill-down, optional Wazuh alerts.
- `surya-kundal doctor`: read-only installation check; exit code 1 on failure.
- `wazuh/export-alerts.sh` to copy Wazuh alerts for the dashboard.
- Cowrie deception kit and fingerprinting threat model (`cowrie/`).
- Threat model for the platform itself (`docs/THREAT_MODEL.md`).
- Migration 0007: composite index on `technique_matches (technique_id, session_id)`.

- `Dockerfile` and `compose.yaml` for the pipeline and dashboard: unprivileged user, read-only
  root filesystem, no capabilities, resource limits, health checks; policy tests keep it that way.
- CI job that builds the image and runs it hardened.
- Cowrie container (`cowrie/Dockerfile`, Compose profile `honeypot`): Cowrie 3.1.1 pinned to a
  commit, deception kit applied at every start, persona kept in a volume, unprivileged uid 10002,
  health check that does not create sessions, loopback-only port by default.

- Supply-chain workflow: Trivy scans both images for fixable high and critical vulnerabilities
  and the Dockerfiles and Compose file for misconfiguration, and writes a CycloneDX software bill
  of materials per image (kept 90 days). Runs on every change and weekly.

### Changed
- Every GitHub Action is pinned to a full commit hash (Dependabot keeps them current); a test
  fails if an unpinned action is added.
- `COWRIE_LOG_DIR` is optional in Compose: unset, the pipeline reads the honeypot container's log.
- Only the pipeline container receives `.env`; the dashboard and honeypot no longer do.
- The dashboard opens the database read-only at the SQLite level, caches the overview for
  15 seconds, throttles wrong passwords per address, refuses unknown `Host` headers when no
  password is set, bounds request sizes, and caps the rows shown for very large sessions.
- Dashboard "took action" now requires an accepted login, so the funnel is strictly nested.
- Wazuh export keeps the previous file when the copy fails, and never exposes it to other users.
- `DASHBOARD_TOKEN` must be at least 12 characters.

### Removed
- An experimental local-LLM summary feature (never released). Migration 0005 remains in the
  history; migration 0006 removes its table.

## [0.1.0]

Initial development releases: Cowrie log parser, SQLite storage with Alembic migrations,
live watcher, GeoLite2 / AbuseIPDB / Tor / VirusTotal enrichment, MITRE ATT&CK mapping
engine and Wazuh rules.
