#!/usr/bin/env bash
# deploy.sh - install the Surya Kundal Cowrie kit into an existing Cowrie 3.x
# directory (default ~/cowrie).
#
# Safety properties:
#   * Never deletes or overwrites anything without a timestamped copy first.
#     Backups go to <cowrie>/suryakundal-backups/<timestamp>/ and are created
#     only when something is actually replaced.
#   * Idempotent: a second run with unchanged inputs changes nothing and makes
#     no backup. Per-deployment randomness (seed, boot offset) is created once
#     and kept in <cowrie>/suryakundal/.state.
#   * --dry-run builds everything in a scratch directory and only reports.
#   * The only thing it removes is its own scratch directory under
#     <cowrie>/suryakundal/.build.* once the run ends.
#   * It does not stop, start or restart Cowrie.
#
# Usage: deploy.sh [--cowrie-home DIR] [--policy collect|stealth] [--dry-run]
#                  [--refresh-boot] [--regen-hostkeys] [--memtotal-kb N|auto|persona]
#                  [--allow-root] [-h]
#
# --policy collect (default) accepts a few dozen common weak root passwords so
#   scanners get in and you capture sessions; --policy stealth accepts three
#   exact pairs only (hardest to spot, very little data). See etc/.
#
# --memtotal-kb auto (default) makes the persona's memory equal this machine's real
#   MemTotal, because Cowrie's `free` reads the host and would otherwise disagree with
#   /proc/meminfo. `persona` keeps the kit's own 4 GB figure; a number sets it.
set -euo pipefail

KIT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COWRIE_HOME="${COWRIE_HOME:-$HOME/cowrie}"
DRY_RUN=0
REFRESH_BOOT=0
REGEN_KEYS=0
ALLOW_ROOT=0
POLICY=collect
MEMTOTAL=auto

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

while (($# > 0)); do
    case "$1" in
        --cowrie-home)
            [[ $# -ge 2 ]] || { echo "deploy: --cowrie-home needs a directory" >&2; exit 2; }
            COWRIE_HOME="$2"
            shift 2
            ;;
        --policy)
            [[ $# -ge 2 && ( "$2" == collect || "$2" == stealth ) ]] || { echo "deploy: --policy must be collect or stealth" >&2; exit 2; }
            POLICY="$2"
            shift 2
            ;;
        --memtotal-kb)
            [[ $# -ge 2 && ( "$2" == auto || "$2" == persona || "$2" =~ ^[0-9]+$ ) ]] || { echo "deploy: --memtotal-kb must be auto, persona or a number" >&2; exit 2; }
            MEMTOTAL="$2"
            shift 2
            ;;
        --dry-run) DRY_RUN=1; shift ;;
        --refresh-boot) REFRESH_BOOT=1; shift ;;
        --regen-hostkeys) REGEN_KEYS=1; shift ;;
        --allow-root) ALLOW_ROOT=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) echo "deploy: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

die() { echo "deploy: error: $*" >&2; exit 1; }
note() { echo "  $*"; }

if [[ $EUID -eq 0 && $ALLOW_ROOT -eq 0 ]]; then
    die "do not run as root: Cowrie refuses to run as root and root-owned files would break it (use --allow-root only in a test container)"
fi

COWRIE_HOME="$(cd -- "$COWRIE_HOME" 2>/dev/null && pwd)" || die "Cowrie directory not found: $COWRIE_HOME"
[[ -d "$COWRIE_HOME/etc" ]] || die "$COWRIE_HOME/etc missing: is this a Cowrie state directory? (run 'cowrie init' first)"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$COWRIE_HOME/suryakundal-backups/$STAMP"
STATE_DIR="$COWRIE_HOME/suryakundal"
STATE_FILE="$STATE_DIR/.state"
KEY_DIR="$COWRIE_HOME/var/lib/cowrie"
CHANGED=()
UNCHANGED=()
BACKED_UP=()

# ---------------------------------------------------------------- python/venv
find_python() {
    local d
    for d in "${COWRIE_VENV:-}" "$COWRIE_HOME/cowrie-env" "$COWRIE_HOME/cowrie-venv" "$COWRIE_HOME/venv" "$COWRIE_HOME/.venv"; do
        [[ -n "$d" && -x "$d/bin/python" ]] || continue
        if "$d/bin/python" -c 'import cowrie' >/dev/null 2>&1; then
            echo "$d/bin/python"
            return 0
        fi
    done
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import cowrie' >/dev/null 2>&1; then
        command -v python3
        return 0
    fi
    return 1
}
if [[ "$POLICY" == stealth ]]; then USERDB_SRC="$KIT_DIR/etc/userdb.example.txt"; else USERDB_SRC="$KIT_DIR/etc/userdb.collect.example.txt"; fi
PYTHON="$(find_python)" || die "no Python with the 'cowrie' package found. Set COWRIE_VENV to your Cowrie virtualenv, e.g. COWRIE_VENV=\$HOME/cowrie/cowrie-env"
command -v openssl >/dev/null 2>&1 || die "openssl is required (password hashes for /etc/shadow)"

echo "Cowrie home : $COWRIE_HOME"
echo "Python      : $PYTHON"
echo "Login policy: $POLICY"
((DRY_RUN)) && echo "Mode        : DRY RUN (nothing is installed)"

if [[ -f "$COWRIE_HOME/var/run/cowrie.pid" ]]; then
    pid="$(cat -- "$COWRIE_HOME/var/run/cowrie.pid" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "Note        : Cowrie is running (pid $pid); restart it after this script to load the changes."
    fi
fi

# ------------------------------------------------------------------- helpers
backup_path() { # path
    local p="$1" rel
    rel="${p#"$COWRIE_HOME"/}"
    mkdir -p -- "$BACKUP_DIR"
    cp -a -- "$p" "$BACKUP_DIR/${rel//\//__}"
    BACKED_UP+=("$rel")
}

install_file() { # src dest label [text]
    local src="$1" dest="$2" label="$3" kind="${4:-bin}"
    if [[ -f "$dest" ]] && cmp -s -- "$src" "$dest"; then
        UNCHANGED+=("$label")
        return 0
    fi
    if ((DRY_RUN)); then
        CHANGED+=("$label (would change)")
        if [[ -f "$dest" && "$kind" == text ]]; then
            diff -u -- "$dest" "$src" | sed 's/^/      /' | head -n 60 || true
        fi
        return 0
    fi
    if [[ -e "$dest" ]]; then
        backup_path "$dest"
    fi
    mkdir -p -- "$(dirname -- "$dest")"
    cp -- "$src" "$dest"
    CHANGED+=("$label")
}

state_get() { # key
    [[ -f "$STATE_FILE" ]] || return 0
    sed -n "s/^$1=//p" "$STATE_FILE" | head -n 1
}

# ----------------------------------------------------- per-deployment state
SEED="$(state_get SEED)"
BOOT_OFFSET="$(state_get BOOT_OFFSET)"
DEPLOY_EPOCH="$(state_get DEPLOY_EPOCH)"
if [[ -z "$SEED" ]]; then
    SEED="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
fi
if [[ -z "$BOOT_OFFSET" ]]; then
    BOOT_OFFSET=$(((40 + RANDOM % 41) * 86400 + (RANDOM * 32768 + RANDOM) % 86400))
fi
if [[ -z "$DEPLOY_EPOCH" || $REFRESH_BOOT -eq 1 ]]; then
    DEPLOY_EPOCH="$(date +%s)"
fi

if ((!DRY_RUN)); then
    mkdir -p -- "$STATE_DIR"
    printf 'SEED=%s\nBOOT_OFFSET=%s\nDEPLOY_EPOCH=%s\n' "$SEED" "$BOOT_OFFSET" "$DEPLOY_EPOCH" >"$STATE_FILE.new"
    if [[ -f "$STATE_FILE" ]] && cmp -s -- "$STATE_FILE.new" "$STATE_FILE"; then
        mv -- "$STATE_FILE.new" "$STATE_FILE"
    else
        [[ -f "$STATE_FILE" ]] && backup_path "$STATE_FILE"
        mv -- "$STATE_FILE.new" "$STATE_FILE"
    fi
fi

# ------------------------------------------------------- host keys (optional)
echo
echo "Host keys ($KEY_DIR)"
HAVE_KEYGEN=0
command -v ssh-keygen >/dev/null 2>&1 && HAVE_KEYGEN=1
gen_key() { # type bits file
    local type="$1" bits="$2" file="$3"
    if ((DRY_RUN)); then
        note "would generate $type host key $file"
        return 0
    fi
    mkdir -p -- "$KEY_DIR"
    if [[ "$bits" == 0 ]]; then
        ssh-keygen -q -t "$type" -N '' -C '' -f "$file"
    else
        ssh-keygen -q -t "$type" -b "$bits" -N '' -C '' -f "$file"
    fi
    CHANGED+=("host key $(basename -- "$file")")
}
if ((HAVE_KEYGEN)); then
    rsa_pub="$KEY_DIR/ssh_host_rsa_key.pub"
    if ((REGEN_KEYS)) && [[ -f "$rsa_pub" || -f "$KEY_DIR/ssh_host_ed25519_key.pub" ]]; then
        if ((DRY_RUN)); then
            note "would move existing host keys to the backup dir and generate new ones"
        else
            mkdir -p -- "$BACKUP_DIR/var/lib/cowrie"
            for k in rsa ecdsa ed25519; do
                for f in "$KEY_DIR/ssh_host_${k}_key" "$KEY_DIR/ssh_host_${k}_key.pub"; do
                    [[ -e "$f" ]] || continue
                    mv -- "$f" "$BACKUP_DIR/var/lib/cowrie/"
                    BACKED_UP+=("${f#"$COWRIE_HOME"/} (moved)")
                done
            done
        fi
    fi
    [[ -f "$KEY_DIR/ssh_host_rsa_key" ]] || gen_key rsa 3072 "$KEY_DIR/ssh_host_rsa_key"
    [[ -f "$KEY_DIR/ssh_host_ecdsa_key" ]] || gen_key ecdsa 256 "$KEY_DIR/ssh_host_ecdsa_key"
    [[ -f "$KEY_DIR/ssh_host_ed25519_key" ]] || gen_key ed25519 0 "$KEY_DIR/ssh_host_ed25519_key"
    if [[ -f "$rsa_pub" ]]; then
        bits="$(ssh-keygen -lf "$rsa_pub" | awk '{print $1}')"
        if [[ "$bits" != 3072 ]]; then
            note "RSA host key is $bits bits; Debian 12's ssh-keygen -A makes 3072. Re-run with --regen-hostkeys (old keys are moved to the backup dir, clients will see a host-key change)."
        else
            note "RSA host key is 3072 bits (matches Debian 12)"
        fi
    fi
else
    note "ssh-keygen not found: Cowrie will create its own (RSA 2048) host keys on first start"
fi

# --------------------------------------------------------- build fs + assets
echo
echo "Building filesystem assets"
if ((DRY_RUN)); then
    BUILD_PARENT="$(mktemp -d)"
else
    mkdir -p -- "$STATE_DIR"
    BUILD_PARENT="$STATE_DIR"
fi
BUILD="$(mktemp -d "$BUILD_PARENT/.build.XXXXXX")"
cleanup() { # removes only the scratch directories created above
    [[ -n "${BUILD:-}" && -d "$BUILD" ]] && rm -rf -- "$BUILD"
    if ((DRY_RUN)); then rmdir -- "$BUILD_PARENT" 2>/dev/null || true; fi
    return 0
}
trap cleanup EXIT

MEMTOTAL_KB=0
case "$MEMTOTAL" in
    auto) MEMTOTAL_KB="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)" ;;
    persona) MEMTOTAL_KB=0 ;;
    *) MEMTOTAL_KB="$MEMTOTAL" ;;
esac
if ! [[ "${MEMTOTAL_KB:-0}" =~ ^[0-9]+$ ]] || ((MEMTOTAL_KB < 262144)); then
    MEMTOTAL_KB=0 # unreadable or implausibly small: keep the persona's own figure
fi

"$PYTHON" "$KIT_DIR/tools/build_fs.py" \
    --memtotal-kb "$MEMTOTAL_KB" \
    --out "$BUILD/fs.pickle" \
    --overlay "$KIT_DIR/honeyfs-overlay" \
    --userdb "$USERDB_SRC" \
    --txtcmds-src "$KIT_DIR/txtcmds-overlay" \
    --txtcmds-out "$BUILD/txtcmds" \
    --cmdoutput-src "$KIT_DIR/etc/cmdoutput.example.json" \
    --cmdoutput-out "$BUILD/cmdoutput.json" \
    --hostkey-dir "$KEY_DIR" \
    --seed "$SEED" \
    --boot-offset "$BOOT_OFFSET" \
    --now "$DEPLOY_EPOCH" | sed 's/^/  /'

# ----------------------------------------------------------------- config
RENDERED_CFG="$BUILD/cowrie.cfg"
cfg_text="$(<"$KIT_DIR/etc/cowrie.cfg.example")"
cfg_text="${cfg_text//@COWRIE_HOME@/$COWRIE_HOME}"
cfg_text="${cfg_text//@BOOT_OFFSET@/$BOOT_OFFSET}"
printf '%s\n' "$cfg_text" >"$RENDERED_CFG"
if grep -q '@[A-Z_]*@' "$RENDERED_CFG"; then
    # the comment block mentions the tokens by name; only fail on assignments
    if grep -E '^[a-z_]+ *=.*@[A-Z_]+@' "$RENDERED_CFG" >/dev/null; then
        die "unrendered token in generated cowrie.cfg"
    fi
fi

echo
echo "Installing"
# honeyfs: Cowrie 3.x has no honeyfs directory; back up an old one if present.
if [[ -d "$COWRIE_HOME/honeyfs" ]]; then
    if ((DRY_RUN)); then
        note "would back up legacy $COWRIE_HOME/honeyfs (Cowrie 3.x ignores it unless [honeypot] contents_path is set)"
    else
        # one copy is enough: skip if an earlier run already saved it
        if ! compgen -G "$COWRIE_HOME/suryakundal-backups/*/honeyfs" >/dev/null; then
            mkdir -p -- "$BACKUP_DIR"
            cp -a -- "$COWRIE_HOME/honeyfs" "$BACKUP_DIR/honeyfs"
            BACKED_UP+=("honeyfs/ (copy; original left in place)")
        fi
    fi
fi

install_file "$RENDERED_CFG" "$COWRIE_HOME/etc/cowrie.cfg" "etc/cowrie.cfg" text
install_file "$USERDB_SRC" "$COWRIE_HOME/etc/userdb.txt" "etc/userdb.txt" text
install_file "$BUILD/fs.pickle" "$STATE_DIR/fs.pickle" "suryakundal/fs.pickle"
install_file "$BUILD/cmdoutput.json" "$STATE_DIR/cmdoutput.json" "suryakundal/cmdoutput.json" text
while IFS= read -r -d '' f; do
    rel="${f#"$BUILD"/}"
    install_file "$f" "$STATE_DIR/$rel" "suryakundal/$rel" text
done < <(find "$BUILD/txtcmds" -type f -print0 | sort -z)

# ------------------------------------------------------------------ report
echo
echo "Result"
if ((${#CHANGED[@]})); then
    printf '  changed   : %s\n' "${CHANGED[@]}"
else
    echo "  changed   : (nothing)"
fi
if ((${#UNCHANGED[@]})); then
    printf '  unchanged : %s\n' "${UNCHANGED[@]}"
fi
if ((${#BACKED_UP[@]})); then
    printf '  backed up : %s\n' "${BACKED_UP[@]}"
    echo "  backup dir: $BACKUP_DIR"
fi
if ((DRY_RUN)); then
    echo
    echo "Dry run only. Re-run without --dry-run to install."
elif ((${#CHANGED[@]})); then
    echo
    echo "Next: restart Cowrie so it loads the new files, e.g."
    echo "  cd \"$COWRIE_HOME\" && cowrie stop && cowrie start"
    echo "Then check from another machine: ssh -p 2222 -v root@<honeypot-ip>"
fi
