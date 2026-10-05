#!/usr/bin/env bash
# Feed each sample Cowrie event to the Wazuh manager's rule tester and check the
# output contains what samples/expected.txt says (a rule id or a [rule-name]).
# Prints PASS/FAIL per event and exits non-zero if any fail.
# Usage: wazuh/logtest.sh [container-name]
set -euo pipefail
container="${1:-surya-wazuh-manager}"
here="$(cd "$(dirname "$0")" && pwd)"
mapfile -t events <"$here/samples/cowrie_events.jsonl"
mapfile -t expected <"$here/samples/expected.txt"
[[ ${#events[@]} -eq ${#expected[@]} ]] || { echo "samples and expected.txt differ in length" >&2; exit 2; }
failed=0
for i in "${!events[@]}"; do
    out="$(printf '%s\n' "${events[$i]}" | docker exec -i "$container" /var/ossec/bin/wazuh-logtest 2>&1 || true)"
    if grep -qF -- "${expected[$i]}" <<<"$out"; then
        echo "PASS  ${expected[$i]}"
    else
        echo "FAIL  expected ${expected[$i]} for: ${events[$i]:0:100}"
        grep -E "^\s+(id|level|description):|ERROR|WARNING" <<<"$out" | sed 's/^/        /' || true
        failed=$((failed + 1))
    fi
done
echo "$((${#events[@]} - failed))/${#events[@]} passed"
((failed == 0))
