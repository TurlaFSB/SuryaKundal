# Operations

What to do to keep a long-running honeypot safe, bounded and monitored. Commands assume the
Docker Compose deployment; drop the `docker compose exec -T pipeline` prefix when running the
program directly.

## Backups

```
docker compose exec -T pipeline surya-kundal backup --compress --keep 14
```

- Safe while the pipeline is running. It uses SQLite's online backup, so the copy is consistent,
  and it never includes a half-written session.
- Every backup is verified (integrity check, schema version) before it is kept, written with
  permissions `0600`, and is a single self-contained file.
- `--keep 14` deletes older backups after the new one is safely written.
- In the container, backups go to `/data/backups`, which is **the same volume as the database**.
  That protects against a bad upgrade or a mistaken delete, not against losing the disk. Copy them
  somewhere else:

```
docker compose cp pipeline:/data/backups ./backups
```

Run it daily from the host's cron (`crontab -e`):

```
17 3 * * * cd ~/surya-kundal && docker compose exec -T pipeline surya-kundal backup --compress --keep 14
```

## Restoring

Stop what writes to the database, restore, start again:

```
docker compose stop pipeline dashboard
docker compose run --rm --no-deps pipeline \
    surya-kundal restore /data/backups/surya-kundal-YYYYMMDD-HHMMSS.db.gz --force
docker compose up -d pipeline dashboard
```

A restore refuses to overwrite anything without `--force`, keeps a copy of what it replaced
(`surya_kundal.db.before-restore-<time>`), removes the old write-ahead log so stale data cannot be
replayed, and refuses damaged files, files that are not Surya Kundal databases, and backups from a
newer version of the program. Test a restore once before you need one.

## Retention

A public honeypot adds sessions without limit. Delete old ones on a schedule you choose:

```
docker compose exec -T pipeline surya-kundal prune --older-than 180          # shows what it would do
docker compose exec -T pipeline surya-kundal backup --compress               # keep a copy first
docker compose exec -T pipeline surya-kundal prune --older-than 180 --yes --vacuum
```

- Without `--yes` nothing is changed; the command reports what it would delete.
- A session is deleted when it ended (or started, if it never ended) before the cutoff, together
  with its logins, commands, file transfers, tunnels, ATT&CK matches and campaign links. Cached
  address and file lookups that no remaining session uses are dropped. Campaigns are recomputed
  so they never count deleted sessions.
- `--vacuum` returns the freed space to the filesystem; it needs room for a temporary copy.
- Raw Cowrie logs and tty recordings are separate and are not touched. Rotate or remove them
  according to the law and policy that apply to you (see `docs/THREAT_MODEL.md`).

## Metrics

The dashboard serves Prometheus metrics at `/metrics`, behind the same password as every other
page. Values are counts and a freshness timestamp only; nothing an attacker typed can appear in
them.

| Metric | Meaning |
|---|---|
| `surya_kundal_sessions` | Sessions stored |
| `surya_kundal_source_ips` | Distinct source addresses |
| `surya_kundal_accepted_logins` | Logins the honeypot accepted |
| `surya_kundal_commands` | Shell commands recorded |
| `surya_kundal_files` | Files downloaded or uploaded by attackers |
| `surya_kundal_campaigns` | Campaigns found |
| `surya_kundal_last_session_timestamp_seconds` | Start of the newest session (0 if none) |
| `surya_kundal_database_size_bytes` | Database file size |

Prometheus scrape config (the token is the password; the username is ignored):

```yaml
scrape_configs:
  - job_name: surya-kundal
    metrics_path: /metrics
    basic_auth:
      username: metrics
      password_file: /etc/prometheus/surya-kundal-token
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

Alerts worth having: no new session for a long time while the honeypot is exposed
(`time() - surya_kundal_last_session_timestamp_seconds > 21600`) usually means the honeypot, the
log volume or the pipeline stopped; and a database that grows faster than expected
(`deriv(surya_kundal_database_size_bytes[1h])`).

These are gauges of what is stored, so they fall after a prune. They show the data, not the
processes: container health still comes from `docker compose ps` and the Compose health checks.
