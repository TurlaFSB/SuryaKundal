# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Operations: `surya-kundal backup` (online, verified, private, optional gzip and rotation),
  `restore` (refuses to overwrite, keeps what it replaced, rejects damaged or newer-schema files),
  and `prune --older-than DAYS` (reports first, deletes only with `--yes`, recomputes campaigns).
  A password-protected Prometheus `/metrics` endpoint. See `docs/OPERATIONS.md`.
- Deception test harness (`evaluation/deception_check.py`, `docs/DECEPTION_TESTING.md`): 45 probes
  grouped by attacker class, JSON output, before/after comparison. Stock Cowrie 3.1.1 passes 10 of
  45; with the kit, 30 of 45 (every check configuration can fix).
- The kit sets the persona's memory to the host's real `MemTotal` at deploy time (scaling the related
  `/proc/meminfo` fields), so `free` and `/proc/meminfo` agree on any VM. `--memtotal-kb` overrides it.
- The kit builds a `/proc/<pid>` directory (`cmdline`, `comm`, `status`, `stat`) for every process
  `ps` lists, replacing the two container leftovers; tests keep `ps` and `/proc` in agreement.
- ATT&CK mapper accuracy set (`evaluation/`, `docs/MAPPER_ACCURACY.md`): 103 hand-labelled
  commands, a scoring script, and a test that fails if precision or recall fall below 0.97.
  The first run scored precision 0.90 and recall 0.93.
- Campaign clustering (`surya-kundal campaigns build|list|show`): sessions that share a payload,
  a script, a tooling fingerprint or an unusual command sequence are grouped, with the evidence
  shown. IDs are stable between rebuilds. `run` regroups in the background
  (`--campaign-interval`), and the dashboard has Campaigns pages. Migration 0008.
- `surya-kundal export`: indicators of compromise (addresses, file hashes, URLs) as CSV,
  STIX 2.1, a plain blocklist, or an nftables script with self-expiring entries. Only public
  addresses are listed, an allow-list protects your own infrastructure, and values are
  validated and escaped for each format. Documented in `docs/IOC_EXPORT.md`.
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
- Mapper fixes found by the accuracy set: a miner name inside `ps | grep` no longer counts as
  mining; `curl -F` uploads are no longer downloads; `scp` uploads count as exfiltration;
  `chmod go=`, `service auditd stop`, `grep -r password`, and `ls /var/log` are now recognised;
  `rm -rf /` is no longer reported as clearing traces. Wazuh rule prefix is now possessive so
  rules that begin with a negative lookahead cannot be bypassed by backtracking.
- Both images build from a base image pinned to an exact digest; Dependabot proposes updates.
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
