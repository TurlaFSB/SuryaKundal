# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- After a restart across Cowrie's daily log rotation, the watcher first reads the rotated file to the end,
  so events written just before the rotation are not lost.
- Dashboard dependency pinned to `werkzeug>=3.1.9` (fixes CVE-2026-102598).
- CI now shellchecks every script in `cowrie/` and `wazuh/`; Dependabot also watches the Cowrie image.
- Ingestion no longer stops on odd log content: every field is type-checked and size-capped, one
  session that fails cannot affect the others, and a locked database retries the whole batch
  instead of waiting out the lock once per session. Lines of deep nesting or digit floods are skipped.
- Shell redirects (`echo x > file`) are no longer counted as downloads, which inflated statistics, the
  export and the VirusTotal quota.
- The IOC export no longer lists innocent addresses: look-up services and popular sites are never
  listed, disguised local hosts are refused, URLs only typed in commands need 3 different sources and
  are labelled unverified, and `--exclude` and `INTERNAL_NETWORKS` apply to URLs. Campaigns ignore the
  same hosts, and the campaign rebuild uses less memory.

### Added
- Community files: a fuller CONTRIBUTING guide, a Code of Conduct, issue forms (bug, wrong ATT&CK mapping,
  feature) and a pull request template. The README gains a documentation index, release verification
  steps and a short statement of purpose.
- `docs/DEPLOYMENT_AWS.md`: ordered, checked steps for a single-server deployment (honeypot on port 22,
  administration moved to 22222 from one address, metadata service locked, egress control, dashboard
  through an SSH tunnel). `COWRIE_PORT` sets the host port the honeypot listens on.

## [0.2.0] - 2026-10-10

### Added
- The Wazuh alerts export now reaches the dashboard container: `wazuh/export-alerts.sh` writes to
  `data/wazuh/`, which the dashboard mounts read-only (it previously wrote a host file the container
  could not see). The docs note that the manager needs about 4 GB of RAM.
- Your own traffic no longer passes for attackers. Sessions from loopback, private ranges, the Docker
  bridges (so the deception harness and your test logins) and anything listed in `INTERNAL_NETWORKS`
  are marked internal (migration 0010; existing sessions are classified once). The dashboard,
  `/metrics`, campaigns and the IOC export leave them out; `DASHBOARD_SHOW_INTERNAL=1` shows them and
  `surya-kundal reclassify` re-checks after a change.
- Attempted downloads: with egress blocked no download completes, so Cowrie logs no file and no hash and
  the address was only in the command text. The mapper now reads fetch addresses out of commands
  (`wget`, `curl`, `tftp`, `busybox ftpget`, `git clone`, also behind `sudo`, `sh -c`, `cd x &&`;
  never anything built from variables, and `echo wget ...` is not a fetch) into a new
  `fetch_attempts` table (migration 0009). They show on the session page, link sessions into campaigns
  exactly like completed downloads, and appear in the IOC export as URLs (confidence 50, against 60 for
  a completed download). Existing sessions are re-mapped once after the upgrade.
- Egress control for the honeypot (`cowrie/egress.sh`, `docs/EGRESS.md`): the honeypot container gets
  its own Docker bridge, and a host firewall stops it opening connections to the internet (`deny`, the
  default) or limits it to rate-limited web traffic to public addresses (`captures`). In both modes the
  host, your LAN and the cloud metadata address are unreachable, and replies to attackers' inbound
  connections still pass. `verify` proves it from inside the container; `install` re-applies it at boot.
  Tested on a real kernel firewall with packets crossing network namespaces, and checked with ShellCheck.
- Deny mode closes DNS too. Docker's built-in resolver forwards a container's lookups to the internet
  without touching the container's packets, so a firewall alone let names resolve. The honeypot now
  uses its own resolver file and a local stub (`cowrie/tools/sinkdns.py`) that answers every lookup
  with an instant SERVFAIL, so a blocked `wget` or `curl` fails the way a real offline server does
  (previously: `connected.`, a ten-second hang, then wording real wget never prints). `captures` mode
  allows DNS only to two named resolvers. Selected with `EGRESS_MODE` in `.env`.
- Two harness checks, `wget-failure-realistic` and `curl-failure-realistic`, keep that behavior from
  regressing. The committed results are re-measured: stock Cowrie 12 of 47, with the kit 32 of 47.
- Release pipeline (`release.yml`): a version tag builds both images, publishes them to GHCR, signs each by digest with Sigstore (keyless) and attaches a CycloneDX bill of materials to the GitHub release. CI also scans the full git history for secrets with Gitleaks.
- Operations: `surya-kundal backup` (online, verified, private, optional gzip and rotation),
  `restore` (refuses to overwrite, keeps what it replaced, rejects damaged or newer-schema files),
  and `prune --older-than DAYS` (reports first, deletes only with `--yes`, recomputes campaigns).
  A password-protected Prometheus `/metrics` endpoint. See `docs/OPERATIONS.md`.
- Deception test harness (`evaluation/deception_check.py`, `docs/DECEPTION_TESTING.md`): 47 probes
  grouped by attacker class, JSON output, before/after comparison. Stock Cowrie 3.1.1 passes 12 of
  47; with the kit, 32 of 47 (every check configuration can fix).
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
