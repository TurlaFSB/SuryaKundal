#!/usr/bin/env python3
"""Build the Surya Kundal filesystem assets for Cowrie 3.x.

What it does (all offline, stdlib only, plus the `openssl` binary for password
hashes):

  1. Loads Cowrie's bundled fs.pickle (or --src) and writes a *new* pickle.
     It never modifies the input and refuses to overwrite --out.
  2. Removes the container giveaways the bundled pickle carries (/.dockerenv,
     /proc/docker, docker-* apt/dpkg files).
  3. Renames /home/phil to /home/deploy, creates /home/ops, and writes every
     file from the overlay directory into the pickle with the correct content,
     size, owner and mtime. Cowrie's `ls -l` uses the pickle size, so content
     and size must be set together (fsctl "load"/"embed" only set content).
  4. Generates per-deployment values: machine-id, root filesystem UUID,
     /etc/shadow (real sha512-crypt hashes of the passwords that userdb
     accepts, so an offline crack matches the login), /etc/{passwd,group,
     shadow}-, and the public host keys under /etc/ssh.
  5. Renders the @TOKEN@ placeholders in txtcmds and cmdoutput.json.

The pickle format (10-field lists, A_*/T_* constants) is taken from
cowrie/scripts/createfs.py, Cowrie 3.1.1. pickle.load() executes code from the
file: only ever load pickles you built or that ship with Cowrie.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import random
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(
    10
)
T_LINK, T_DIR, T_FILE = 0, 1, 2

REMOVE_PATHS = [
    "/.dockerenv",
    "/proc/docker",
    "/etc/apt/apt.conf.d/docker-autoremove-suggests",
    "/etc/apt/apt.conf.d/docker-clean",
    "/etc/apt/apt.conf.d/docker-gzip-indexes",
    "/etc/apt/apt.conf.d/docker-no-languages",
    "/etc/dpkg/dpkg.cfg.d/docker-apt-speedup",
]

# user -> (uid, gid) for ownership of files created under their home
HOME_OWNERS = {"deploy": (1000, 1000), "ops": (1001, 1001), "root": (0, 0)}
OLD_HOME_USER = "phil"  # Cowrie's well-known default user


def die(msg: str) -> None:
    print(f"build_fs: error: {msg}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------- tree helpers
def lookup(root, path, follow_final=True, _depth=0):
    """Resolve path in the tree. Link targets are root-relative (createfs)."""
    if _depth > 16:
        return None
    node = root
    for part in [p for p in path.split("/") if p]:
        if node[A_TYPE] == T_LINK:
            node = lookup(root, node[A_TARGET], True, _depth + 1)
            if node is None:
                return None
        if node[A_TYPE] != T_DIR:
            return None
        child = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
        if child is None:
            return None
        node = child
    if follow_final and node[A_TYPE] == T_LINK:
        return lookup(root, node[A_TARGET], True, _depth + 1)
    return node


def mkdirs(root, path, mtime, uid=0, gid=0, mode=0o40755):
    node = root
    for part in [p for p in path.split("/") if p]:
        if node[A_TYPE] == T_LINK:
            node = lookup(root, node[A_TARGET])
        child = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
        if child is None:
            child = [part, T_DIR, uid, gid, 4096, mode, int(mtime), [], None, None]
            node[A_CONTENTS].append(child)
        node = child
    return node


def remove(root, path) -> bool:
    parent_path, _, name = path.rstrip("/").rpartition("/")
    parent = lookup(root, parent_path or "/")
    if parent is None or parent[A_TYPE] != T_DIR:
        return False
    before = len(parent[A_CONTENTS])
    parent[A_CONTENTS] = [c for c in parent[A_CONTENTS] if c[A_NAME] != name]
    return len(parent[A_CONTENTS]) != before


def put_file(root, path, data: bytes, uid, gid, mode, mtime, stats):
    """Create or update a regular file (following a final symlink)."""
    node = lookup(root, path, follow_final=True)
    if node is None:
        parent_path, _, name = path.rpartition("/")
        parent = mkdirs(root, parent_path, mtime)
        node = [name, T_FILE, uid, gid, len(data), mode, int(mtime), data, None, None]
        parent[A_CONTENTS].append(node)
        stats["created"] += 1
        return node
    if node[A_TYPE] != T_FILE:
        die(f"{path} exists in the pickle but is not a regular file")
    node[A_CONTENTS] = data
    node[A_SIZE] = len(data)
    node[A_UID], node[A_GID], node[A_MODE], node[A_CTIME] = uid, gid, mode, int(mtime)
    node[A_REALFILE] = None
    stats["updated"] += 1
    return node


# ----------------------------------------------------------------- policy bits
def parse_passwd(text: str):
    users = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) != 7:
            die(f"passwd line does not have 7 fields: {line!r}")
        users.append(
            {"name": f[0], "uid": int(f[2]), "gid": int(f[3]), "home": f[5], "shell": f[6]}
        )
    return users


def userdb_accepts(path: Path):
    """Exact (user, password) pairs the userdb accepts. Wildcards/regex ignored."""
    pairs = []
    for raw in path.read_text(encoding="ascii").splitlines():
        if raw.startswith("#") or raw.count(":") < 2:
            continue  # same rule Cowrie applies: comments and short lines are skipped
        fields = raw.split(":")
        user, pw = fields[0], fields[2].strip()
        if not user or user == "*" or user.startswith("/"):
            continue
        if pw.startswith(("!", "/", "*")) or pw == "":
            continue
        pairs.append((user, pw))
    return pairs


def sha512_crypt(password: str, salt: str) -> str:
    try:
        r = subprocess.run(
            ["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
            input=password + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        die(f"`openssl passwd -6` failed ({exc}); OpenSSL >= 1.1.1 is required")
    return r.stdout.strip()


def render(text: str, tokens: dict) -> str:
    for k, v in tokens.items():
        text = text.replace(f"@{k}@", v)
    leftover = re.findall(r"@[A-Z_]+@", text)
    if leftover:
        die(f"unrendered tokens {sorted(set(leftover))}")
    return text


# ------------------------------------------------------------------------ main
def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--src", help="input fs.pickle (default: the one bundled with the installed cowrie)"
    )
    ap.add_argument("--out", required=True, help="output pickle (must not exist)")
    ap.add_argument("--overlay", required=True, help="honeyfs-overlay directory")
    ap.add_argument(
        "--userdb",
        required=True,
        help="userdb file whose accepted passwords are hashed into /etc/shadow",
    )
    ap.add_argument("--txtcmds-src", required=True)
    ap.add_argument("--txtcmds-out", required=True)
    ap.add_argument("--cmdoutput-src", required=True)
    ap.add_argument("--cmdoutput-out", required=True)
    ap.add_argument(
        "--hostkey-dir",
        help="dir holding Cowrie's ssh_host_*_key.pub (public keys are mirrored into /etc/ssh)",
    )
    ap.add_argument(
        "--seed", required=True, help="per-deployment seed; same seed -> same machine-id/UUID/salts"
    )
    ap.add_argument(
        "--install-days",
        type=int,
        default=0,
        help="machine 'installed' this many days ago (default: seed-derived 150-450)",
    )
    ap.add_argument(
        "--boot-offset", type=int, required=True, help="seconds; must equal [honeypot] boot_offset"
    )
    ap.add_argument("--now", type=int, default=int(time.time()), help=argparse.SUPPRESS)
    a = ap.parse_args()

    rng = random.Random(a.seed)
    out = Path(a.out)
    if out.exists():
        die(f"{out} already exists; refusing to overwrite")
    overlay = Path(a.overlay)

    # --- load source pickle
    if a.src:
        src = Path(a.src)
    else:
        try:
            import importlib.resources as res

            src = Path(str(res.files("cowrie.data") / "fs.pickle"))
        except Exception as exc:
            die(f"cannot locate bundled fs.pickle ({exc}); run inside Cowrie's venv or pass --src")
    with open(src, "rb") as fh:
        root = pickle.load(fh, encoding="utf-8")  # trusted input only

    # --- per-deployment values
    install_days = a.install_days or rng.randint(150, 450)
    install_ts = a.now - install_days * 86400 - rng.randint(0, 86399)
    root_uuid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    machine_id = "%032x" % rng.getrandbits(128)
    boot_ts = a.now - a.boot_offset
    tokens = {
        "ROOT_UUID": root_uuid,
        "BOOT_DAY": time.strftime("%b%d", time.gmtime(boot_ts)),
        "UPTIME_DAYS": str(a.boot_offset // 86400),
    }
    stats = {"created": 0, "updated": 0, "removed": 0}

    # --- 1. container giveaways
    for p in REMOVE_PATHS:
        if remove(root, p):
            stats["removed"] += 1

    # --- 2. users / homes
    home = lookup(root, "/home")
    if home is None:
        die("no /home in source pickle")
    old = next((c for c in home[A_CONTENTS] if c[A_NAME] == OLD_HOME_USER), None)
    if old is not None:
        old[A_NAME] = "deploy"
    for user in ("deploy", "ops"):
        uid, gid = HOME_OWNERS[user]
        node = mkdirs(root, f"/home/{user}", install_ts, uid, gid, 0o40700)
        node[A_UID], node[A_GID], node[A_MODE], node[A_CTIME] = uid, gid, 0o40700, int(install_ts)
        node[A_CONTENTS] = [
            c for c in node[A_CONTENTS] if c[A_TYPE] != T_FILE
        ]  # drop stale entries

    # --- 3. overlay files
    passwd_text = (overlay / "etc/passwd").read_text(encoding="ascii")
    users = parse_passwd(passwd_text)
    names = {u["name"] for u in users}
    for user, _pw in userdb_accepts(Path(a.userdb)):
        if user not in names:
            die(
                f"userdb accepts {user!r} but it is not in the overlay /etc/passwd (a login that has no passwd entry is a tell)"
            )
    for f in sorted(p for p in overlay.rglob("*") if p.is_file()):
        if f.parent == overlay and f.name.startswith("README"):
            continue  # documentation, not filesystem content
        rel = "/" + f.relative_to(overlay).as_posix()
        if rel in {"/etc/shadow", "/etc/machine-id"}:
            die(f"{rel} is generated; remove it from the overlay")
        data = render(f.read_text(encoding="utf-8"), tokens).encode("utf-8")
        uid = gid = 0
        mode = 0o100644
        m = re.match(r"^/(home/(deploy|ops)|root)/", rel)
        if m:
            owner = m.group(2) or "root"
            uid, gid = HOME_OWNERS[owner]
            if rel.endswith(".bash_history"):
                mode = 0o100600
        jitter = rng.randint(0, 3600)
        put_file(root, rel, data, uid, gid, mode, install_ts + jitter, stats)

    # --- 4. generated files
    put_file(
        root, "/etc/machine-id", (machine_id + "\n").encode(), 0, 0, 0o100444, install_ts, stats
    )
    pairs = dict(userdb_accepts(Path(a.userdb)))
    days = install_ts // 86400
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    shadow = []
    for u in users:
        if u["name"] in pairs:
            salt = "".join(rng.choice(alphabet) for _ in range(16))
            h = sha512_crypt(pairs[u["name"]], salt)
        elif u["shell"].endswith("nologin") or u["name"] in {"sync"}:
            h = "*"
        else:
            h = "!"
        shadow.append(f"{u['name']}:{h}:{days}:0:99999:7:::")
    shadow_text = "\n".join(shadow) + "\n"
    put_file(root, "/etc/shadow", shadow_text.encode(), 0, 42, 0o100640, install_ts, stats)
    # Debian keeps backups of the account databases next to the live ones
    group_text = (overlay / "etc/group").read_text(encoding="ascii")
    put_file(
        root,
        "/etc/passwd-",
        "\n".join(passwd_text.splitlines()[:-1]).encode() + b"\n",
        0,
        0,
        0o100644,
        install_ts,
        stats,
    )
    put_file(
        root,
        "/etc/group-",
        "\n".join(group_text.splitlines()[:-1]).encode() + b"\n",
        0,
        0,
        0o100644,
        install_ts,
        stats,
    )
    put_file(
        root,
        "/etc/shadow-",
        "\n".join(shadow[:-1]).encode() + b"\n",
        0,
        42,
        0o100640,
        install_ts,
        stats,
    )

    # --- 5. mirror public host keys (never private keys)
    hostname = (overlay / "etc/hostname").read_text().strip()
    mirrored = 0
    if a.hostkey_dir:
        for kind in ("rsa", "ecdsa", "ed25519"):
            kp = Path(a.hostkey_dir) / f"ssh_host_{kind}_key.pub"
            if kp.is_file():
                parts = kp.read_text().split()
                line = f"{parts[0]} {parts[1]} root@{hostname}\n".encode()
                put_file(
                    root,
                    f"/etc/ssh/ssh_host_{kind}_key.pub",
                    line,
                    0,
                    0,
                    0o100644,
                    install_ts,
                    stats,
                )
                mirrored += 1

    # --- 6. write pickle
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "xb") as fh:
        pickle.dump(root, fh)

    # --- 7. txtcmds + cmdoutput
    txt_out = Path(a.txtcmds_out)
    for f in sorted(p for p in Path(a.txtcmds_src).rglob("*") if p.is_file()):
        dest = txt_out / f.relative_to(a.txtcmds_src)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render(f.read_text(encoding="utf-8"), tokens), encoding="utf-8")
    cmd = render(Path(a.cmdoutput_src).read_text(encoding="utf-8"), tokens)
    json.loads(cmd)  # fail early if the template rendered to invalid JSON
    Path(a.cmdoutput_out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.cmdoutput_out).write_text(cmd, encoding="utf-8")

    sha = hashlib.sha256(out.read_bytes()).hexdigest()[:16]
    print(f"pickle     : {out}  (sha256 {sha}...)")
    print(
        f"changes    : {stats['created']} files created, {stats['updated']} updated, {stats['removed']} removed"
    )
    print(f"host keys  : {mirrored} public key(s) mirrored into /etc/ssh")
    print(
        f"identity   : machine-id {machine_id[:8]}..., root UUID {root_uuid[:8]}..., 'installed' {install_days} days ago"
    )
    print(
        f"boot       : {tokens['UPTIME_DAYS']} days before start, ps START column = {tokens['BOOT_DAY']}"
    )


if __name__ == "__main__":
    main()
