"""The decoy files that make the honeypot look worth exploring."""

import base64
import importlib.util
import ipaddress
import pickle
import re
import subprocess
import sys
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[1] / "cowrie"
LURES = KIT / "lures-overlay"


def _load():
    spec = importlib.util.spec_from_file_location("build_fs", KIT / "tools" / "build_fs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_fs"] = module
    spec.loader.exec_module(module)
    return module


bf = _load()
FILES = {"/" + p.relative_to(LURES).as_posix(): p for p in LURES.rglob("*") if p.is_file()}


def test_tokens_are_stable_per_seed_and_differ_between_seeds():
    assert bf.lure_tokens("alpha") == bf.lure_tokens("alpha")
    assert bf.lure_tokens("alpha") != bf.lure_tokens("beta")


def test_token_shapes_look_like_the_real_thing():
    t = bf.lure_tokens("alpha")
    assert re.fullmatch(r"AKIA[A-Z2-7]{16}", t["LURE_AWS_KEY_ID"])
    assert re.fullmatch(r"[A-Za-z0-9+/]{40}", t["LURE_AWS_SECRET"])
    for n in (1, 2, 3):
        blob = base64.b64decode(t[f"LURE_HOSTKEY_{n}"])
        assert blob.startswith(b"\x00\x00\x00\x0bssh-ed25519") and len(blob) == 51
    assert base64.b64decode(t["LURE_DOCKER_AUTH"]).decode() == f"deploy:{t['LURE_DB_PASS']}"


def test_no_secret_is_committed_every_one_is_a_placeholder():
    """A fixed key or password in a public repository would identify every deployment."""
    for path, f in FILES.items():
        text = f.read_text(encoding="utf-8")
        assert "AKIA" not in text and "BEGIN " not in text, path
        for line in text.splitlines():
            if "password_hash" in line:  # a column name, not a secret
                continue
            if re.search(
                r"(?i)(secret|password|passwd|-p'|aws_access_key_id|auth\"?\s*[:=])", line
            ):
                assert "@LURE_" in line, f"{path}: {line}"


def test_every_file_renders_with_no_token_left():
    tokens = bf.lure_tokens("alpha")
    for f in FILES.values():
        rendered = bf.render(f.read_text(encoding="utf-8"), tokens)  # dies on an unfilled token
        assert "@LURE_" not in rendered


def test_the_files_agree_with_each_other():
    t = bf.lure_tokens("alpha")
    text = {p: bf.render(f.read_text(encoding="utf-8"), t) for p, f in FILES.items()}
    for path in ("/opt/app/.env", "/home/deploy/backup.sh"):
        assert t["LURE_DB_PASS"] in text[path]
    for path in ("/opt/app/.env", "/root/.aws/credentials"):
        assert t["LURE_AWS_KEY_ID"] in text[path] and t["LURE_AWS_SECRET"] in text[path]
    env = dict(line.split("=", 1) for line in text["/opt/app/.env"].splitlines() if "=" in line)
    assert env["DB_HOST"] in text["/home/deploy/backup.sh"]
    assert env["BACKUP_HOST"] in text["/root/.ssh/config"]
    assert env["BACKUP_HOST"] in text["/root/.bash_history"]


def test_lure_hosts_sit_on_the_resolvers_network_and_never_on_the_honeypots_own_address():
    addresses = set()
    for f in FILES.values():
        addresses |= set(re.findall(r"\b10\.20\.0\.\d{1,3}\b", f.read_text(encoding="utf-8")))
    assert addresses
    for a in addresses:
        last = int(a.rsplit(".", 1)[1])
        assert ipaddress.ip_address(a) in ipaddress.ip_network("10.20.0.0/24")
        # network_identity picks the honeypot's own address from 20 to 250
        assert last < 20, a


def test_history_does_not_name_a_date_that_post_dates_the_files_around_it():
    history = (LURES / "root" / ".bash_history").read_text()
    assert not re.search(r"20\d\d-\d\d-\d\d", history)


def _build(tmp_path, name, *extra):
    pytest.importorskip("cowrie.shell.fs", reason="needs Cowrie's bundled filesystem")
    keys = tmp_path / "keys"
    keys.mkdir(exist_ok=True)
    out = tmp_path / f"{name}.pickle"
    subprocess.run(  # noqa: S603 - our own script, fixed arguments
        [
            sys.executable, str(KIT / "tools" / "build_fs.py"),
            "--memtotal-kb", "2000000",
            "--out", str(out),
            "--overlay", str(KIT / "honeyfs-overlay"),
            "--userdb", str(KIT / "etc" / "userdb.collect.example.txt"),
            "--txtcmds-src", str(KIT / "txtcmds-overlay"),
            "--txtcmds-out", str(tmp_path / f"{name}-txt"),
            "--cmdoutput-src", str(KIT / "etc" / "cmdoutput.example.json"),
            "--cmdoutput-out", str(tmp_path / f"{name}.json"),
            "--hostkey-dir", str(keys),
            "--seed", "test-seed",
            "--boot-offset", "4000000",
            "--now", "1790000000",
            *extra,
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    return pickle.loads(out.read_bytes())  # noqa: S301 - a file this test just built


def test_built_filesystem_has_the_lures_and_nothing_else_moves(tmp_path):
    plain = _build(tmp_path, "plain")
    luring = _build(tmp_path, "luring", "--lures-src", str(LURES))

    for path in ("/etc/shadow", "/etc/machine-id", "/etc/hostname", "/etc/passwd"):
        a, b = bf.lookup(plain, path), bf.lookup(luring, path)
        assert a[bf.A_CONTENTS] == b[bf.A_CONTENTS], f"{path} must not change"
    env = bf.lookup(luring, "/opt/app/.env")
    assert env[bf.A_MODE] == 0o100600 and b"DB_PASSWORD=" in env[bf.A_CONTENTS]
    assert bf.lookup(luring, "/root/.ssh")[bf.A_MODE] == 0o40700
    script = bf.lookup(luring, "/home/deploy/backup.sh")
    assert script[bf.A_MODE] == 0o100750 and script[bf.A_UID] == 1000
    assert bf.lookup(plain, "/opt/app/.env") is None
    # no ssh-keygen output was provided, so no private key is invented
    assert bf.lookup(luring, "/root/.ssh/id_ed25519") is None


def test_the_private_key_comes_from_the_state_directory(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "lure_id_ed25519").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    (keys / "lure_id_ed25519.pub").write_text("ssh-ed25519 AAAAexample ignored-comment\n")
    root = _build(tmp_path, "keyed", "--lures-src", str(LURES))
    private = bf.lookup(root, "/root/.ssh/id_ed25519")
    assert private[bf.A_CONTENTS].startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    assert private[bf.A_MODE] == 0o100600
    pub = bf.lookup(root, "/root/.ssh/id_ed25519.pub")[bf.A_CONTENTS].decode()
    assert pub == "ssh-ed25519 AAAAexample root@stg-util02\n"


# ----------------------------------------------------------- the wider lure set
def test_the_first_lure_values_do_not_move_when_more_lures_are_added():
    """Servers already running keep the same AWS key and DB password after an upgrade."""
    t = bf.lure_tokens("x")
    assert t["LURE_AWS_KEY_ID"] == "AKIALPHU3KOVD4N2HGLH"
    assert t["LURE_DB_PASS"] == "ysFFjp1stJUhGvfh"  # noqa: S105


def test_new_token_shapes():
    t = bf.lure_tokens("alpha")
    assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", t["LURE_GH_TOKEN"])
    assert re.fullmatch(r"npm_[A-Za-z0-9]{36}", t["LURE_NPM_TOKEN"])
    assert t["LURE_PYPI_TOKEN"].startswith("pypi-AgEIcHlwaS5vcmc")
    assert re.fullmatch(r"[0-9a-f]{40}", t["LURE_ETH_ADDR"])
    assert re.fullmatch(r"[0-9a-f]{64}", t["LURE_ETH_CT"])
    assert len(base64.b64decode(t["LURE_WG_PRIVATE"])) == 32
    assert len(t["LURE_SEED"].split()) == 12
    assert len(__import__("json").loads(t["LURE_SOLANA_KEY"])) == 64
    assert t["LURE_K8S_TOKEN"].count(".") == 2
    pem = t["LURE_GCP_PEM"]
    assert pem.startswith("-----BEGIN PRIVATE KEY-----\\n") and "\n" not in pem
    rows = t["LURE_SQL_USERS"].splitlines()
    assert len(rows) == 25
    assert all(
        re.fullmatch(r"\(\d+,'[^']+@example\.(com|org|net)','\$2y\$10\$.{53}','[^']+'\),?", r)
        for r in rows
    )


def test_wallet_is_a_berkeley_db_btree_page():
    data = bf.wallet_bytes("alpha")
    assert len(data) == 8192 and data[12:16] == b"\x62\x31\x05\x00"
    assert data[16:20] == (9).to_bytes(4, "little") and data[20:24] == (4096).to_bytes(4, "little")
    assert data == bf.wallet_bytes("alpha") and data != bf.wallet_bytes("beta")


def test_built_filesystem_has_the_wider_lures_with_the_right_owner_and_mode(tmp_path):
    root = _build(tmp_path, "wide", "--lures-src", str(LURES))
    tokens = bf.lure_tokens("test-seed")
    addr = tokens["LURE_ETH_ADDR"]
    keystore = bf.lookup(root, f"/root/.ethereum/keystore/UTC--2025-11-02T09-14-33.512Z--{addr}")
    assert keystore is not None and addr.encode() in keystore[bf.A_CONTENTS]
    wallet = "/root/.bitcoin/wallet.dat"
    private = [
        "/root/.kube/config",
        "/root/.git-credentials",
        "/root/.npmrc",
        "/root/.pypirc",
        "/root/.pgpass",
        "/root/.my.cnf",
        "/root/.config/gcloud/application_default_credentials.json",
        "/root/.config/solana/id.json",
        "/root/.config/rclone/rclone.conf",
        "/root/.bitcoin/bitcoin.conf",
        wallet,
        "/etc/wireguard/wg0.conf",
        "/opt/infra/ansible/.vault_pass",
        "/srv/backups/appdb-latest.sql",
    ]
    for path in private:
        node = bf.lookup(root, path)
        assert node is not None, path
        assert node[bf.A_MODE] == 0o100600, path
        assert node[bf.A_SIZE] == len(node[bf.A_CONTENTS])
    assert len(bf.lookup(root, wallet)[bf.A_CONTENTS]) == 8192
    for path in ("/home/ops/passwords.txt", "/home/ops/seed.txt"):
        node = bf.lookup(root, path)
        assert (node[bf.A_UID], node[bf.A_GID]) == (1001, 1001), path
    for path in ("/root/.kube", "/etc/wireguard", "/root/.ethereum/keystore", "/root/.bitcoin"):
        assert bf.lookup(root, path)[bf.A_MODE] == 0o40700, path
    seed = bf.lookup(root, "/home/ops/seed.txt")[bf.A_CONTENTS].decode()
    assert tokens["LURE_SEED"] in seed


def test_the_wider_files_agree_with_each_other():
    t = bf.lure_tokens("alpha")
    text = {p: bf.render(f.read_text(encoding="utf-8"), t) for p, f in FILES.items()}
    assert t["LURE_DB_PASS"] in text["/root/.my.cnf"]
    assert t["LURE_VAULT_PASS"] in text["/opt/infra/ansible/.vault_pass"]
    assert t["LURE_PG_PASS"] in text["/root/.pgpass"]
    assert t["LURE_GH_TOKEN"] in text["/root/.git-credentials"]
    assert t["LURE_WG_PRIVATE"] in text["/etc/wireguard/wg0.conf"]


def test_canary_key_replaces_the_made_up_pair_only_when_well_formed(capsys):
    base = bf.lure_tokens("alpha")
    key, secret = "AKIA" + "Q" * 16, "s" * 40
    both = {"LURE_AWS_ACCESS_KEY_ID": key, "LURE_AWS_SECRET_ACCESS_KEY": secret}
    swapped = bf.apply_canary(base, both)
    assert swapped["LURE_AWS_KEY_ID"] == key and swapped["LURE_AWS_SECRET"] == secret
    assert swapped["LURE_DB_PASS"] == base["LURE_DB_PASS"]
    assert bf.apply_canary(base, {}) == base
    assert bf.apply_canary(base, {"LURE_AWS_ACCESS_KEY_ID": ""}) == base
    assert capsys.readouterr().out == ""
    for bad in (
        {"LURE_AWS_ACCESS_KEY_ID": key},
        {"LURE_AWS_ACCESS_KEY_ID": "nope", "LURE_AWS_SECRET_ACCESS_KEY": secret},
        {"LURE_AWS_ACCESS_KEY_ID": key, "LURE_AWS_SECRET_ACCESS_KEY": "short"},
    ):
        assert bf.apply_canary(base, bad) == base
        assert "LURE_AWS_* ignored" in capsys.readouterr().out
