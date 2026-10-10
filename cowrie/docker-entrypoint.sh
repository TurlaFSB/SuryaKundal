#!/usr/bin/env bash
# Container entrypoint: apply the deception kit to the state volume, then start Cowrie in
# the foreground. The kit is idempotent: persona (seed, boot offset) and host keys are
# created once and kept in the volume, so a restart does not change what a scanner sees.
set -euo pipefail

cd /cowrie
# Cowrie 3.x does not create these itself; a missing tty/ makes every login fail with
# "Error getting shell" (session recordings) and downloads/ is where captured files go.
mkdir -p etc var/log/cowrie var/lib/cowrie/tty var/lib/cowrie/downloads var/run

if [[ "${1:-}" != "start" ]]; then
    exec "$@"   # e.g. `docker compose run cowrie bash`, for debugging
fi

case "${COWRIE_POLICY:-collect}" in
    collect | stealth) ;;
    *) echo "entrypoint: COWRIE_POLICY must be collect or stealth" >&2; exit 2 ;;
esac

/opt/kit/deploy.sh --cowrie-home /cowrie --policy "${COWRIE_POLICY:-collect}"

# Deny mode (compose.yaml mounts cowrie/resolv.deny.conf): the container's resolver is
# 127.0.0.1, so answer lookups there with an instant SERVFAIL. Nothing is forwarded. Without
# this, Cowrie's DNS library would wait about a minute for a resolver that is not there.
if grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
    python /opt/kit/tools/sinkdns.py &
    sink=$!
    sleep 0.5
    if ! kill -0 "$sink" 2>/dev/null; then
        echo "entrypoint: WARNING the local resolver stub did not start (compose.yaml sets" \
             "net.ipv4.ip_unprivileged_port_start=53 for it); downloads will hang before failing" >&2
    fi
fi
exec cowrie start
