#!/usr/bin/env bash
# Feed the sample Cowrie events to the Wazuh manager's rule tester and print which
# rule fires for each. Usage: wazuh/logtest.sh [container-name]
set -euo pipefail
container="${1:-surya-wazuh-manager}"
here="$(cd "$(dirname "$0")" && pwd)"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  echo "--- $(echo "$line" | cut -c1-110)"
  printf '%s\n' "$line" | docker exec -i "$container" /var/ossec/bin/wazuh-logtest -q 2>&1 \
    | grep -E "id:|level:|description:|id: 'T|ERROR|WARNING" || true
done < "$here/samples/cowrie_events.jsonl"
