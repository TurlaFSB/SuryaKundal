#!/usr/bin/env bash
# Copy the Surya Kundal alerts out of the Wazuh manager so the dashboard can show them.
# Run it from cron or by hand:  wazuh/export-alerts.sh [output-file]
# The default output, data/wazuh/wazuh_alerts.jsonl, is the folder the dashboard container reads.
#
# The previous export is only replaced when the copy succeeded, so a stopped container
# or a Docker error leaves the dashboard showing the last good data.
set -euo pipefail
umask 077  # alerts contain attacker commands; never world-readable, not even briefly

OUT="${1:-data/wazuh/wazuh_alerts.jsonl}"
CONTAINER="${WAZUH_CONTAINER:-surya-wazuh-manager}"
SOURCE="/var/ossec/logs/alerts/alerts.json"

mkdir -p "$(dirname "$OUT")"
RAW="$(mktemp "$OUT.XXXXXX")"
TMP="$(mktemp "$OUT.XXXXXX")"
trap 'rm -f "$RAW" "$TMP"' EXIT

if ! docker exec "$CONTAINER" tail -n 5000 "$SOURCE" > "$RAW"; then
  echo "error: could not read $SOURCE from container '$CONTAINER'; keeping the old export" >&2
  exit 1
fi
# Keep only this project's rules (IDs 100500 and up). grep exits 1 for "no match",
# which is fine; any other failure is not.
status=0
grep -E '"rule":\{[^}]*"id":"1[0-9]{5}"' "$RAW" > "$TMP" || status=$?
if [ "$status" -gt 1 ]; then
  echo "error: filtering failed (grep exit $status); keeping the old export" >&2
  exit 1
fi
mv "$TMP" "$OUT"
trap 'rm -f "$RAW"' EXIT
echo "wrote $(wc -l < "$OUT") alerts to $OUT"
