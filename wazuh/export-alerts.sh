#!/usr/bin/env bash
# Copy the Surya Kundal alerts out of the Wazuh manager so the dashboard can show them.
# Run it from cron or by hand:  wazuh/export-alerts.sh [output-file]
set -euo pipefail

OUT="${1:-data/wazuh_alerts.jsonl}"
CONTAINER="${WAZUH_CONTAINER:-surya-wazuh-manager}"
SOURCE="/var/ossec/logs/alerts/alerts.json"

mkdir -p "$(dirname "$OUT")"
# Keep the last 5000 lines; only our rules (IDs 1005xx and up) are interesting.
docker exec "$CONTAINER" tail -n 5000 "$SOURCE" \
  | grep -E '"id":"1[0-9]{5}"' > "$OUT.tmp" || true
mv "$OUT.tmp" "$OUT"
chmod 600 "$OUT"
echo "wrote $(wc -l < "$OUT") alerts to $OUT"
