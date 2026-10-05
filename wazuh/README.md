# Wazuh integration

Wazuh's built-in JSON decoder reads Cowrie's log, so only **rules** are needed. They are generated from the project's own ATT&CK rules (`rules.toml`), so the SIEM and the database always agree on what is suspicious.

| File | Purpose |
| --- | --- |
| `rules/surya_kundal_cowrie_rules.xml` | Generated rules (IDs 100500-100599 session level, 100600+ commands), each tagged with an ATT&CK technique |
| `docker-compose.yml` | Wazuh manager only (about 1 GB RAM), with the rules mounted |
| `agent-localfile.xml` | Snippet that points a Wazuh agent at `cowrie.json` |
| `samples/cowrie_events.jsonl` | Sample events for `logtest.sh` |
| `logtest.sh` | Shows which rule fires for each sample event on a real manager |

Regenerate after editing `rules.toml` (CI fails if the committed file is stale):

    surya-kundal wazuh-rules --output wazuh/rules/surya_kundal_cowrie_rules.xml

## What alerts

| Level | Event | ATT&CK |
| --- | --- | --- |
| 5 / 8 / 11 | Failed login / 3 in 2 min / 10 in 5 min from one IP | T1110.001 |
| 8 / 10 | Login succeeded / with a default account such as root | T1078 / T1078.001 |
| 10 | File downloaded or uploaded | T1105 |
| 9 | Port-forwarding request | T1090 |
| 4-10 | Each command rule (low/medium/high confidence) | per rule |

Differences from the Python mapping, stated plainly: Wazuh cannot split a command line, so a leading `^` is widened to also match after `;`, `&&`, `|` and `sudo`; and Wazuh raises only the first matching rule per event, so high-confidence rules come first.

## Setting it up

The unit tests check the rules offline. `logtest.sh` is the real check; it was verified against Wazuh 4.14.7.

1. Start the manager: `cd wazuh && docker compose up -d`
2. Check the rules load: `docker logs surya-wazuh-manager 2>&1 | grep -i -E "error|critical" | head`
3. Run `./logtest.sh` and compare with the table above.
4. Point the agent at the manager: set `<address>127.0.0.1</address>` in `/var/ossec/etc/ossec.conf`, add `agent-localfile.xml`, then `sudo /var/ossec/bin/agent-auth -m 127.0.0.1` and `sudo systemctl enable --now wazuh-agent`.
5. Alerts appear in `docker exec surya-wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json`.

The agent must not be newer than the manager (both 4.14.7 here).
