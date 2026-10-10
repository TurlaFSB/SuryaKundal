#!/usr/bin/env bash
# egress.sh - host firewall that stops the honeypot container being used against others.
#
# Cowrie's wget, curl, nc and tftp open REAL connections to attacker-chosen hosts, and from
# inside its container the honeypot can also reach the host, the LAN and the cloud metadata
# address. This script limits only the honeypot's own Docker bridge; nothing else on the
# machine is touched. Run it as root, on the Docker host.
#
#   egress.sh [--dry-run] apply [deny|captures]   install the rules (default: deny)
#   egress.sh remove                              take them out again
#   egress.sh status                              show the mode and the packet counters
#   egress.sh verify                              prove it from inside the running container
#   egress.sh [--dry-run] install [deny|captures] re-apply on every boot (systemd)
#   egress.sh uninstall                           remove the boot unit and the rules
#
# Modes:
#   deny      nothing the honeypot starts itself may leave (the default). Cowrie still logs the
#             URL an attacker tried to fetch, which is the indicator; it just cannot save the file.
#   captures  web only: TCP 80/443 to public addresses, plus DNS to two named resolvers,
#             rate-limited and capped. Real malware samples are collected, but this machine makes
#             real connections for attackers. Private, link-local, multicast and other reserved
#             ranges are always refused. Set EGRESS_MODE=captures in .env so the honeypot's
#             resolver (cowrie/resolv.captures.conf) matches.
#
# In both modes, replies on connections an attacker opened INTO the honeypot are always allowed
# (that is how SSH works), and anything the honeypot tries to open towards the host itself is
# refused. Dropped packets are logged at a limited rate with the prefix "surya-egress-drop: ".
#
# Settings (environment):
#   SURYA_HONEY_BRIDGE     bridge name; must match compose.yaml            (br-suryahoney)
#   SURYA_HONEY_CONTAINER  container used by `verify`                      (surya-cowrie)
#   SURYA_EGRESS_RATE      captures: new connections allowed, e.g. 30/minute (30/minute)
#   SURYA_EGRESS_BURST     captures: burst above that rate                 (15)
#   SURYA_EGRESS_MAX_CONNS captures: concurrent connections cap            (20)
#   SURYA_EGRESS_DNS       captures: the only resolvers the honeypot may ask, comma separated
#                          (1.1.1.1,9.9.9.9). Must match cowrie/resolv.captures.conf.
set -euo pipefail

BRIDGE="${SURYA_HONEY_BRIDGE:-br-suryahoney}"
CONTAINER="${SURYA_HONEY_CONTAINER:-surya-cowrie}"
RATE="${SURYA_EGRESS_RATE:-30/minute}"
BURST="${SURYA_EGRESS_BURST:-15}"
MAX_CONNS="${SURYA_EGRESS_MAX_CONNS:-20}"
DNS_ALLOW="${SURYA_EGRESS_DNS:-1.1.1.1,9.9.9.9}"

FWD_CHAIN="SURYA-HONEY-FWD"   # traffic the honeypot sends through the host
IN_CHAIN="SURYA-HONEY-IN"     # traffic the honeypot sends to the host itself
DROP_CHAIN="SURYA-HONEY-DROP" # log (rate-limited) then drop
TAG="surya-honey"
UNIT_NAME="surya-honey-egress.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
SELF="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

# Addresses a honeypot must never reach (IANA special-purpose and private ranges).
RESERVED_V4=(
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
  192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
  203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
)

DRY_RUN=0
FW=iptables

die() { echo "egress.sh: $*" >&2; exit 1; }
say() { echo "egress.sh: $*"; }

usage() { sed -n '2,/^set -euo/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'; }

# --- validation --------------------------------------------------------------------------------

validate_settings() {
  [[ "$BRIDGE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] \
    || die "SURYA_HONEY_BRIDGE '$BRIDGE' is not a valid interface name (1 to 15 characters)"
  [[ "$RATE" =~ ^[0-9]+/(sec|second|min|minute|hour|day)$ ]] \
    || die "SURYA_EGRESS_RATE '$RATE' must look like 30/minute (units: second, minute, hour, day)"
  [[ "$BURST" =~ ^[0-9]+$ && "$MAX_CONNS" =~ ^[0-9]+$ ]] \
    || die "SURYA_EGRESS_BURST and SURYA_EGRESS_MAX_CONNS must be whole numbers"
  [[ "$DNS_ALLOW" =~ ^[0-9./]+(,[0-9./]+)*$ ]] \
    || die "SURYA_EGRESS_DNS must be comma-separated IPv4 addresses or networks"
}

valid_mode() { [[ "$1" == "deny" || "$1" == "captures" ]]; }

# --- firewall plumbing -------------------------------------------------------------------------

# Run (or, with --dry-run, print) one firewall command.
fw() {
  if ((DRY_RUN)); then echo "$FW $*"; else "$FW" "$@"; fi
}

# Does a rule or chain query succeed? A dry run has no state, so nothing exists yet.
fw_has() {
  ((DRY_RUN)) && return 1
  "$FW" "$@" >/dev/null 2>&1
}

need_root_and_tools() {
  ((DRY_RUN)) && return 0
  [[ "$(id -u)" -eq 0 ]] || die "run as root (the rules change the host firewall)"
  command -v iptables >/dev/null || die "iptables is not installed"
}

# Remove every rule in $1 that jumps to chain $2.
unhook() {
  local table_chain="$1" target="$2" n
  ((DRY_RUN)) && return 0
  while n="$("$FW" -L "$table_chain" --line-numbers -n 2>/dev/null \
      | awk -v t="$target" '$2 == t { print $1; exit }')" && [[ -n "$n" ]]; do
    "$FW" -D "$table_chain" "$n"
  done
}

fresh_chain() {
  if fw_has -S "$1"; then fw -F "$1"; else fw -N "$1"; fi
}

drop_chain_rules() {
  fresh_chain "$DROP_CHAIN"
  fw -A "$DROP_CHAIN" -m limit --limit 10/minute --limit-burst 20 \
    -j LOG --log-prefix "surya-egress-drop: " --log-level 4
  fw -A "$DROP_CHAIN" -j DROP
}

forward_rules() {
  local mode="$1" range resolver proto
  fresh_chain "$FWD_CHAIN"
  # Replies to connections an attacker opened into the honeypot.
  fw -A "$FWD_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  fw -A "$FWD_CHAIN" -m conntrack --ctstate INVALID -j "$DROP_CHAIN"
  if [[ "$mode" == "captures" && "$FW" == "iptables" ]]; then
    # The only names the honeypot may resolve go to these resolvers (cowrie/resolv.captures.conf).
    for resolver in ${DNS_ALLOW//,/ }; do
      for proto in udp tcp; do
        fw -A "$FWD_CHAIN" -d "$resolver" -p "$proto" --dport 53 -m conntrack --ctstate NEW \
          -m limit --limit "$RATE" --limit-burst "$BURST" -j RETURN
      done
    done
    for range in "${RESERVED_V4[@]}"; do
      fw -A "$FWD_CHAIN" -d "$range" -j "$DROP_CHAIN"
    done
    fw -A "$FWD_CHAIN" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW \
      -m connlimit --connlimit-above "$MAX_CONNS" --connlimit-mask 32 -j "$DROP_CHAIN"
    fw -A "$FWD_CHAIN" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW \
      -m limit --limit "$RATE" --limit-burst "$BURST" -j RETURN
  fi
  fw -A "$FWD_CHAIN" -j "$DROP_CHAIN"
}

input_rules() {
  fresh_chain "$IN_CHAIN"
  fw -A "$IN_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  fw -A "$IN_CHAIN" -j "$DROP_CHAIN"
}

# While the chains are rebuilt (flushed and refilled) nothing may slip through the gap, so for that
# moment everything from the honeypot's bridge is dropped. If the script dies half way, the block
# stays in place: failing closed is the safe state. A later successful apply removes it.
hold_closed() {
  fw -I DOCKER-USER 1 -i "$BRIDGE" -m comment --comment "${TAG}:applying" -j DROP
  fw -I INPUT 1 -i "$BRIDGE" -m comment --comment "${TAG}:applying" -j DROP
}

release_hold() {
  local table_chain
  for table_chain in DOCKER-USER INPUT; do
    # delete every leftover block (a failed earlier run may have left one)
    while fw_has -C "$table_chain" -i "$BRIDGE" -m comment --comment "${TAG}:applying" -j DROP; do
      fw -D "$table_chain" -i "$BRIDGE" -m comment --comment "${TAG}:applying" -j DROP
    done
  done
}

# Build chains and hook them in, for iptables (v4) or ip6tables (v6).
apply_family() {
  local mode="$1"
  if [[ "$FW" == "ip6tables" ]]; then
    # IPv6 is off on Docker's default networks. If it is on, the honeypot gets deny, always.
    command -v ip6tables >/dev/null || return 0
    fw_has -S DOCKER-USER || { ((DRY_RUN)) || return 0; }
    mode=deny
  fi
  release_hold
  hold_closed
  drop_chain_rules
  forward_rules "$mode"
  input_rules
  unhook DOCKER-USER "$FWD_CHAIN"
  unhook INPUT "$IN_CHAIN"
  fw -I DOCKER-USER 1 -i "$BRIDGE" -m comment --comment "${TAG}:${mode}" -j "$FWD_CHAIN"
  fw -I INPUT 1 -i "$BRIDGE" -m comment --comment "${TAG}:${mode}" -j "$IN_CHAIN"
  release_hold
}

remove_family() {
  [[ "$FW" == "ip6tables" ]] && { command -v ip6tables >/dev/null || return 0; }
  release_hold
  unhook DOCKER-USER "$FWD_CHAIN"
  unhook INPUT "$IN_CHAIN"
  local chain
  for chain in "$FWD_CHAIN" "$IN_CHAIN" "$DROP_CHAIN"; do
    if fw_has -S "$chain" || ((DRY_RUN)); then
      fw -F "$chain"
      fw -X "$chain"
    fi
  done
}

cmd_apply() {
  local mode="${1:-deny}"
  valid_mode "$mode" || die "mode must be deny or captures, not '$mode'"
  validate_settings
  need_root_and_tools
  if ! ((DRY_RUN)) && ! iptables -S DOCKER-USER >/dev/null 2>&1; then
    die "Docker's DOCKER-USER chain does not exist; start Docker first"
  fi
  trap 'say "apply FAILED part way: traffic from ${BRIDGE} stays blocked (fail closed); fix the error and run apply again" >&2' ERR
  FW=iptables apply_family "$mode"
  FW=ip6tables apply_family "$mode"
  trap - ERR
  say "applied mode=${mode} to bridge ${BRIDGE}"
  if [[ "$mode" == "captures" ]]; then
    say "set EGRESS_MODE=captures and HONEY_MASQUERADE=true in .env, then recreate the network:"
    say "  docker compose --profile honeypot down && docker compose --profile honeypot up -d"
  else
    say "keep EGRESS_MODE unset (or deny) in .env so the honeypot's resolver matches"
  fi
  ((DRY_RUN)) || say "check it from inside the container with: $0 verify"
}

cmd_remove() {
  validate_settings
  need_root_and_tools
  FW=iptables remove_family
  FW=ip6tables remove_family
  say "removed"
}

current_mode() {
  iptables -S DOCKER-USER 2>/dev/null | grep -o "${TAG}:[a-z]*" | head -n1 | cut -d: -f2 || true
}

cmd_status() {
  validate_settings
  need_root_and_tools
  local mode
  mode="$(current_mode)"
  if [[ -z "$mode" ]]; then
    say "not applied (no rules hooked for ${BRIDGE})"
    return 3
  fi
  say "applied: mode=${mode}, bridge=${BRIDGE}"
  iptables -L "$FWD_CHAIN" -n -v
  iptables -L "$DROP_CHAIN" -n -v
}

# --- verification ------------------------------------------------------------------------------

PROBE_PY='
import socket, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    if kind == "tcp":
        socket.create_connection((host, port), timeout=3).close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"surya", (host, port))
except OSError:
    pass
'

dropped_packets() {
  iptables -L "$DROP_CHAIN" -n -v -x 2>/dev/null | awk '$3 == "DROP" { print $1; exit }'
}

container_gateway() {
  docker exec "$CONTAINER" python -c '
import socket, struct
for line in open("/proc/net/route").read().splitlines()[1:]:
    f = line.split()
    if f[1] == "00000000":
        print(socket.inet_ntoa(struct.pack("<L", int(f[2], 16))))
        break
' 2>/dev/null || true
}

# probe KIND HOST PORT: how many packets did the honeypot's drop rule count for this attempt?
probe() {
  local before after
  before="$(dropped_packets)"
  docker exec "$CONTAINER" python -c "$PROBE_PY" "$1" "$2" "$3" >/dev/null 2>&1 || true
  sleep 1
  after="$(dropped_packets)"
  echo $((after - before))
}

FAILED=0
expect_dropped() { # label kind host port
  local n; n="$(probe "$2" "$3" "$4")"
  if ((n > 0)); then printf '  PASS  blocked   %s\n' "$1"
  else printf '  FAIL  NOT BLOCKED  %s\n' "$1"; FAILED=1; fi
}
expect_passed() { # label kind host port
  local n; n="$(probe "$2" "$3" "$4")"
  if ((n == 0)); then printf '  PASS  allowed   %s\n' "$1"
  else printf '  FAIL  blocked but should be allowed  %s\n' "$1"; FAILED=1; fi
}

# Can the honeypot resolve a name through its own system resolver (what wget and curl use)?
lookup_works() {
  docker exec "$CONTAINER" python -c '
import socket, sys
try:
    socket.getaddrinfo("example.com", 80)
except OSError:
    sys.exit(1)
' >/dev/null 2>&1
}

expect_lookup() { # label want(yes|no)
  local worked=no
  lookup_works && worked=yes
  if [[ "$worked" == "$2" ]]; then
    printf '  PASS  %-9s %s\n' "$([[ $2 == yes ]] && echo works || echo blocked)" "$1"
  elif [[ "$2" == "no" ]]; then
    printf '  FAIL  NOT BLOCKED  %s (name lookups leave through the resolver)\n' "$1"; FAILED=1
  else
    printf '  FAIL  lookups fail but captures needs them  %s (set EGRESS_MODE=captures in .env, then: docker compose --profile honeypot up -d)\n' "$1"; FAILED=1
  fi
}

cmd_verify() {
  validate_settings
  need_root_and_tools
  command -v docker >/dev/null || die "docker is not installed"
  local mode gateway
  mode="$(current_mode)"
  [[ -n "$mode" ]] || die "rules are not applied; run: $0 apply"
  [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == "true" ]] \
    || die "container ${CONTAINER} is not running"
  say "verifying mode=${mode} from inside ${CONTAINER}"
  gateway="$(container_gateway)"
  if [[ "$mode" == "deny" ]]; then
    expect_dropped "public web (1.1.1.1:443)" tcp 1.1.1.1 443
    expect_dropped "public web (1.1.1.1:80)" tcp 1.1.1.1 80
    expect_dropped "public DNS (1.1.1.1:53/udp)" udp 1.1.1.1 53
    expect_lookup "name lookups through the system resolver" no
  else
    expect_lookup "name lookups through the system resolver" yes
    expect_passed "public web (1.1.1.1:443)" tcp 1.1.1.1 443
    expect_dropped "mail port (1.1.1.1:25)" tcp 1.1.1.1 25
    expect_dropped "remote shell port (1.1.1.1:22)" tcp 1.1.1.1 22
  fi
  expect_dropped "cloud metadata (169.254.169.254:80)" tcp 169.254.169.254 80
  expect_dropped "private network (10.255.255.1:80)" tcp 10.255.255.1 80
  expect_dropped "private network (192.168.255.1:80)" tcp 192.168.255.1 80
  if [[ -n "$gateway" ]]; then
    expect_dropped "the host (${gateway}:22)" tcp "$gateway" 22
    expect_dropped "the host (${gateway}:8080)" tcp "$gateway" 8080
  else
    say "could not read the container's gateway; host probes skipped"
  fi
  if ((FAILED)); then
    say "VERIFICATION FAILED: do not expose the honeypot"
    return 1
  fi
  say "all checks passed"
}

# --- boot persistence --------------------------------------------------------------------------

unit_text() {
  local mode="$1" var env_lines=""
  for var in SURYA_HONEY_BRIDGE SURYA_HONEY_CONTAINER SURYA_EGRESS_RATE SURYA_EGRESS_BURST \
      SURYA_EGRESS_MAX_CONNS SURYA_EGRESS_DNS; do
    [[ -n "${!var:-}" ]] && env_lines+="Environment=${var}=${!var}"$'\n'
  done
  cat <<EOF
[Unit]
Description=Surya Kundal honeypot egress firewall (${mode})
Documentation=https://github.com/TurlaFSB/SuryaKundal/blob/main/docs/EGRESS.md
Wants=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=120
# Docker creates the DOCKER-USER chain a moment after it starts; wait for it instead of failing.
ExecStartPre=/bin/sh -c 'for i in \$\$(seq 1 60); do iptables -S DOCKER-USER >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
${env_lines}ExecStart=${SELF} apply ${mode}
ExecStop=${SELF} remove

[Install]
WantedBy=multi-user.target
EOF
}

cmd_install() {
  local mode="${1:-deny}"
  valid_mode "$mode" || die "mode must be deny or captures, not '$mode'"
  validate_settings
  if ((DRY_RUN)); then
    echo "# would write ${UNIT_PATH}:"
    unit_text "$mode"
    echo "systemctl daemon-reload"
    echo "systemctl enable --now ${UNIT_NAME}"
    return 0
  fi
  [[ "$(id -u)" -eq 0 ]] || die "run as root"
  command -v systemctl >/dev/null || die "systemd is not available; apply the rules from your own boot script"
  unit_text "$mode" >"$UNIT_PATH"
  chmod 0644 "$UNIT_PATH"
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME"
  say "installed ${UNIT_NAME}; the rules are re-applied after every boot"
}

cmd_uninstall() {
  ((DRY_RUN)) && { echo "systemctl disable --now ${UNIT_NAME}; rm ${UNIT_PATH}"; return 0; }
  [[ "$(id -u)" -eq 0 ]] || die "run as root"
  if command -v systemctl >/dev/null && [[ -f "$UNIT_PATH" ]]; then
    systemctl disable --now "$UNIT_NAME" || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
  fi
  cmd_remove
}

# --- entry point -------------------------------------------------------------------------------

main() {
  if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; shift; fi
  local action="${1:-}"
  shift || true
  case "$action" in
    apply) cmd_apply "$@" ;;
    remove) cmd_remove ;;
    status) cmd_status ;;
    verify) cmd_verify ;;
    install) cmd_install "$@" ;;
    uninstall) cmd_uninstall ;;
    -h | --help | help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
