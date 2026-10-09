#!/usr/bin/env bash
# Container entrypoint: apply the deception kit to the state volume, then start Cowrie in
# the foreground. The kit is idempotent: persona (seed, boot offset) and host keys are
# created once and kept in the volume, so a restart does not change what a scanner sees.
set -euo pipefail

cd /cowrie
mkdir -p etc var/log/cowrie var/lib/cowrie var/run

if [[ "${1:-}" != "start" ]]; then
    exec "$@"   # e.g. `docker compose run cowrie bash`, for debugging
fi

case "${COWRIE_POLICY:-collect}" in
    collect | stealth) ;;
    *) echo "entrypoint: COWRIE_POLICY must be collect or stealth" >&2; exit 2 ;;
esac

/opt/kit/deploy.sh --cowrie-home /cowrie --policy "${COWRIE_POLICY:-collect}"
exec cowrie start
