# Exporting indicators of compromise

`surya-kundal export` reads the database (never writes to it) and lists what the honeypot
learned about its attackers in a form other systems can use.

```bash
surya-kundal export [--format csv|stix|blocklist|nftables] [--days 30]
                    [--min-level guessing] [--types ip,file,url]
                    [--exclude CIDR]... [--exclude-file FILE]
                    [--output FILE] [--include-private] [--author NAME]
```

Without `--output` the result goes to standard output and a one-line summary goes to
standard error, so `surya-kundal export --format stix > iocs.json` works in a script. Under
Docker: `docker compose exec -T pipeline surya-kundal export --format stix > iocs.json`.

## What is exported

| Kind | Where it comes from | Used in |
|---|---|---|
| Address (IPv4, IPv6) | Source of a session | every format |
| File hash (SHA-256) | Files an attacker downloaded or uploaded | CSV, STIX |
| URL | Where a download came from | CSV, STIX |

Blocklist and nftables output contain addresses only.

Only activity inside the window (`--days`, default 30) is listed. Each indicator keeps its
earliest sighting ever, so its STIX creation time never moves when the window slides.

## How far an address got

An address is listed when it reached at least `--min-level` (default `guessing`).

| Level | Meaning | Confidence |
|---|---|---|
| `contact` | connected and nothing more | 25 |
| `guessing` | 10 or more failed logins | 45 |
| `access` | a login was accepted | 55 |
| `hands-on` | ran commands | 70 |
| `action` | moved files or asked to tunnel | 85 |

Confidence rises by 10 (maximum 95) when AbuseIPDB scores the address 50 or higher. For a
file it is 60 by default, 90 when VirusTotal reports 5 or more malicious engines, 75 for 1
to 4, and 30 when VirusTotal knows the file and every engine says clean. A URL is 60.

## Safety rules

An exported list is usually acted on by a machine, so the export refuses to be dangerous.

- **Only public addresses.** Private, loopback, link-local, shared and documentation
  addresses are never listed. `--include-private` lifts this for CSV and STIX, to test in a
  lab where every attacker is on your own network. It is refused for blocklist formats.
- **Allow-list.** `--exclude` and `--exclude-file` remove your own addresses and networks
  from every output. One address or CIDR range per line; `#` starts a comment.
- **Validated values.** Malformed addresses and hashes, URLs with spaces, control or
  non-ASCII characters, local or private hosts, and the hash of an empty file are dropped
  and counted in the summary.
- **Escaped for each format.** CSV cells never start a spreadsheet formula, and control
  characters appear as visible escapes. STIX patterns escape quotes and backslashes.
- **Atomic writes.** `--output` writes a temporary file and renames it, so a reader never
  sees half a list.

## Formats

**CSV** has one row per indicator and a `type` column (`ipv4`, `ipv6`, `sha256`, `url`).
Columns: `type value first_seen last_seen sessions level confidence country asn as_org
abuse_score tor vt_malicious vt_engines techniques detail`.

**STIX 2.1** is one bundle with an identity (`--author`) and one indicator per value. Each
has a pattern, a validity period, a confidence and, for addresses, references to the ATT&CK
techniques seen. IDs are derived from the pattern, so importing the file again updates the
existing objects in MISP or OpenCTI instead of duplicating them. Address and URL indicators
expire (`valid_until` is the last sighting plus the window); file hashes do not.

**Blocklist** is one address per line with `#` comments. Expiry is the window: an address
that has been quiet for `--days` days leaves the list at the next export. Run the export on
a schedule.

**nftables** creates the table `surya_kundal` with the sets `surya_kundal_v4` and
`surya_kundal_v6`. Every element has its own timeout (the time left in the window), so a
stale address removes itself even if you never run the export again. Loading the file
replaces the sets' contents. It blocks nothing by itself; add a rule of your own:

```bash
sudo nft -c -f block.nft                                  # check the syntax
sudo nft -f block.nft                                     # load it
sudo nft add rule inet filter input ip saddr @surya_kundal_v4 drop
```

Decide deliberately where such a list is enforced. Blocking attackers on the honeypot host
itself defeats the point of the honeypot; the lists are for the rest of your network.
