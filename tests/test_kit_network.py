"""The persona's network identity and the text commands that report it."""

import importlib.util
import ipaddress
import re
import sys
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[1] / "cowrie"


def _load():
    spec = importlib.util.spec_from_file_location("build_fs", KIT / "tools" / "build_fs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_fs"] = module
    spec.loader.exec_module(module)
    return module


bf = _load()
CFG = (KIT / "etc" / "cowrie.cfg.example").read_text()
RESOLV = (KIT / "honeyfs-overlay" / "etc" / "resolv.conf").read_text()


def test_identity_is_stable_for_a_seed_and_differs_between_seeds():
    assert bf.network_identity("abc") == bf.network_identity("abc")
    assert bf.network_identity("abc") != bf.network_identity("abd")


def test_address_is_on_the_resolvers_network_and_never_the_resolver():
    resolver = re.search(r"nameserver\s+(\S+)", RESOLV).group(1)
    network = ipaddress.ip_network(resolver + "/24", strict=False)
    seen = set()
    for n in range(400):
        ident = bf.network_identity(f"seed-{n}")
        address = ipaddress.ip_address(ident["HOST_IP"])
        assert address in network
        assert str(address) != resolver
        assert ident["HOST_BRD"] == str(network.broadcast_address)
        seen.add(str(address))
    assert len(seen) > 100  # spread over the range, not one fixed value for every deployment


def test_mac_and_link_local_address_belong_together():
    for n in range(50):
        ident = bf.network_identity(f"seed-{n}")
        mac = bytes(int(x, 16) for x in ident["HOST_MAC"].split(":"))
        assert mac[:3] == b"\x52\x54\x00"
        eui = bytes([mac[0] ^ 2, *mac[1:3], 0xFF, 0xFE, *mac[3:]])
        expected = ipaddress.IPv6Address(b"\xfe\x80" + b"\x00" * 6 + eui)
        assert ipaddress.IPv6Address(ident["HOST_LINK_LOCAL"]) == expected


def test_ip_command_renders_the_same_values_as_the_identity():
    ident = bf.network_identity("seed-1")
    text = bf.render((KIT / "txtcmds-overlay" / "usr" / "bin" / "ip").read_text(), ident)
    assert f"inet {ident['HOST_IP']}/24 brd {ident['HOST_BRD']}" in text
    assert f"link/ether {ident['HOST_MAC']}" in text
    assert ident["HOST_LINK_LOCAL"] in text
    assert "@" not in text


def test_config_template_carries_the_address_token():
    assert re.search(r"(?m)^internet_facing_ip = @HOST_IP@$", CFG)


def test_built_pickle_contains_the_text_command_binaries(tmp_path):
    """Cowrie only runs a txtcmd whose path exists in the filesystem, so the real build (not a
    copy of its logic) must put /usr/bin/ip in the pickle that is written to disk."""
    import pickle
    import subprocess

    pytest.importorskip("cowrie.shell.fs", reason="needs Cowrie's bundled filesystem")
    keys = tmp_path / "keys"
    keys.mkdir()
    out = tmp_path / "fs.pickle"
    subprocess.run(  # noqa: S603 - our own script, fixed arguments
        [
            sys.executable, str(KIT / "tools" / "build_fs.py"),
            "--memtotal-kb", "2000000",
            "--out", str(out),
            "--overlay", str(KIT / "honeyfs-overlay"),
            "--userdb", str(KIT / "etc" / "userdb.collect.example.txt"),
            "--txtcmds-src", str(KIT / "txtcmds-overlay"),
            "--txtcmds-out", str(tmp_path / "txtcmds"),
            "--cmdoutput-src", str(KIT / "etc" / "cmdoutput.example.json"),
            "--cmdoutput-out", str(tmp_path / "cmdoutput.json"),
            "--hostkey-dir", str(keys),
            "--persona-out", str(tmp_path / "persona.env"),
            "--seed", "test-seed",
            "--boot-offset", "4000000",
            "--now", "1790000000",
        ],
        check=True, capture_output=True,
    )  # fmt: skip
    root = pickle.loads(out.read_bytes())  # noqa: S301 - a file this test just built
    ip = bf.lookup(root, "/usr/bin/ip")
    assert ip is not None and ip[bf.A_TYPE] == bf.T_FILE
    assert ip[bf.A_SIZE] == bf.TEXT_COMMAND_BINARIES["/usr/bin/ip"]
    assert ip[bf.A_MODE] == 0o100755
    assert "HOST_IP=10.20.0." in (tmp_path / "persona.env").read_text()


class TestPackageList:
    lines = tuple((KIT / "txtcmds-overlay" / "usr" / "bin" / "dpkg").read_text().splitlines())
    packages = tuple(line for line in lines if line.startswith("ii "))

    def test_it_is_a_believable_size_with_dpkgs_header(self):
        assert len(self.lines) > 100
        assert self.lines[0].startswith("Desired=Unknown/Install/Remove/Purge/Hold")
        assert self.lines[4].startswith("+++-")
        assert len(self.packages) == len(self.lines) - 5

    def test_it_is_sorted_and_free_of_duplicates(self):
        names = [line.split()[1] for line in self.packages]
        assert names == sorted(names)
        assert len(names) == len(set(names))

    def test_columns_line_up(self):
        starts = {
            line.index(" amd64 ") if " amd64 " in line else line.index(" all ")
            for line in self.packages
        }
        assert len(starts) == 1

    def _version(self, name):
        for line in self.packages:
            fields = line.split()
            if fields[1] == name:
                return fields[2]
        raise AssertionError(name)

    def test_it_agrees_with_the_banner_and_the_kernel_the_honeypot_reports(self):
        banner = re.search(r"(?m)^version = SSH-2\.0-OpenSSH_(\S+) Debian-(\S+)$", CFG)
        assert self._version("openssh-server") == f"1:{banner.group(1)}-{banner.group(2)}"
        kernel = re.search(r"(?m)^kernel_version = (\S+)$", CFG).group(1)
        assert any(line.split()[1] == f"linux-image-{kernel}" for line in self.packages)

    def test_it_lists_what_the_honeypot_offers(self):
        # `ifconfig` and `netstat` answer, so net-tools must be installed; `ip` so must iproute2
        for name in ("net-tools", "iproute2", "openssh-server", "sudo"):
            self._version(name)
