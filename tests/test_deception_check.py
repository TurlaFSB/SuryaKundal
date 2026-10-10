"""The deception harness: parsing, scoring, and the verdict on good and stock personas."""

import importlib.util
import json
import struct
import sys
from pathlib import Path

EVALUATION = Path(__file__).resolve().parents[1] / "evaluation"


def _load():
    spec = importlib.util.spec_from_file_location(
        "deception_check", EVALUATION / "deception_check.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["deception_check"] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


dc = _load()

GOOD = {
    "hostname": "stg-util02",
    "uname -n": "stg-util02",
    "cat /etc/hostname": "stg-util02",
    "cat /etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
    "cat /etc/debian_version": "12.15",
    "ls -a /": ".\n..\nbin\netc",
    "cat /proc/1/cgroup": "0::/init.scope",
    "cat /etc/group": "root:x:0:",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash"
    ),
    "ls /home": "deploy",
    "uname -r": "6.1.0-50-amd64",
    "cat /proc/version": "Linux version 6.1.0-50-amd64 (debian)",
    "ssh -V": "OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.20",
    "cat /etc/ssh/sshd_config | wc -c": "3200",
    "df -h": "Filesystem Size Used Avail Use% Mounted on\n/dev/vda1 40G 9G 29G 24% /",
    "mount": "/dev/vda1 on / type ext4 (rw)",
    "dmesg | head -5": "[    0.000000] Linux version 6.1.0-50-amd64",
    "ps aux": "USER PID\nroot 1 systemd",
    "top -bn1 | head -1": "top - 10:00:00 up 57 days",
    "getconf LONG_BIT": "64",
    "cat /proc/meminfo": "MemTotal:        4018204 kB",
    "free -k": "Mem:       4018204   100   200",
    "cat /proc/cpuinfo": "model name\t: AMD EPYC 7763 64-Core Processor",
    "lscpu": "Model name:    AMD EPYC 7763 64-Core Processor",
    "cat /proc/uptime": "4933420.67 9570836.11",
    "uptime": "10:00:00 up 57 days, 2:23, 1 user",
    "ls -l /etc/hostname": "-rw-r--r-- 1 root root 11 Jul 27 01:49 /etc/hostname",
    "wc -c < /etc/hostname": "11",
    "ls /proc": " ".join(str(n) for n in range(1, 60)) + " acpi",
    "ls -ld /etc": "drwxr-xr-x 74 root root 4096 Oct  1 10:00 /etc",
    "dpkg -l | wc -l": "412",
    "ip a": "1: lo: <LOOPBACK,UP>",
    "sudo -l": "User deploy may run the following commands",
    "echo hello | grep -c hello": "1",
    "wc -c /etc/hostname /etc/hosts": "11 /etc/hostname\n200 /etc/hosts\n211 total",
    "echo $0": "bash",
}


class FakeProbe(dc.Probe):
    def __init__(self, outputs, *, banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10", **extra):
        super().__init__("127.0.0.1", 2222, "deploy", "x")
        self.outputs, self._banner, self.extra = outputs, banner, extra

    def run(self, command):
        if command not in self.outputs:
            raise KeyError(command)
        return self.outputs[command]

    def banner(self):
        return self._banner

    def prelogin_banner(self):
        return self.extra.get("prelogin")

    def login_ok(self, user, password):
        return self.extra.get("accepts_any", False)

    def rsa_bits(self):
        return self.extra.get("bits", 3072)

    def kex_lists(self):
        return self.extra.get("lists", {})

    def odd_version_survives(self):
        return self.extra.get("odd", True), "fake"

    def exec_acknowledged(self):
        return self.extra.get("ack", True)


def _by_id(results):
    return {r.id: r for r in results}


def test_a_consistent_persona_passes_tiers_one_to_three():
    lists = {
        "cipher_s2c": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        "kex": ["sntrup761x25519-sha512@openssh.com"],
        "host_key": ["rsa-sha2-512"],
        "mac_s2c": ["hmac-sha2-256-etm@openssh.com"],
    }
    results = dc.run_checks(FakeProbe(GOOD, lists=lists))
    failed = [(r.id, r.detail) for r in results if r.status != "pass"]
    assert failed == []


def test_stock_cowrie_signals_are_caught():
    stock = dict(GOOD)
    stock.update(
        {
            "hostname": "svr04",
            "uname -n": "svr04",
            "cat /etc/hostname": "svr04",
            "cat /etc/os-release": "",
            "ls -a /": ".dockerenv",
            "cat /etc/passwd": (
                "root:x:0:0:root:/root:/bin/sh\nphil:x:1000:1000::/home/phil:/bin/sh"
            ),
            "uname -r": "6.1.0-21-amd64",
            "cat /proc/version": "Linux version 6.1.0-21-amd64",
            "ssh -V": "OpenSSH_7.9p1, OpenSSL 1.1.1a",
            "cat /proc/meminfo": "MemTotal:        4054744 kB",
            "free -k": "Mem:       8222320   100   200",
            "ls /proc": "1 969 acpi",
            "ls -l /etc/hostname": "-rw-r--r-- 1 root root 6 2026-05-04 14:44 /etc/hostname",
        }
    )
    probe = FakeProbe(
        stock,
        banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        accepts_any=True,
        bits=2048,
        ack=False,
        odd=False,
    )
    got = _by_id(dc.run_checks(probe))
    for failing in (
        "banner-not-default",
        "wildcard-login-refused",
        "default-credentials-refused",
        "hostname-not-default",
        "hostkey-rsa-3072",
        "os-release-filled",
        "no-container-artifacts",
        "no-default-user-phil",
        "kernel-not-default",
        "ssh-version-matches-banner",
        "free-matches-meminfo",
        "meminfo-not-default",
        "proc-has-many-pids",
        "ls-date-format",
        "exec-acknowledged",
        "accepts-ssh-2-x",
    ):
        assert got[failing].status == "fail", failing
    assert got["uname-matches-proc-version"].status == "pass"


def test_a_probe_that_raises_is_reported_not_fatal():
    results = dc.run_checks(FakeProbe({}), only={"hostname-not-default", "banner-not-default"})
    by_id = _by_id(results)
    assert by_id["hostname-not-default"].status == "error"
    assert by_id["banner-not-default"].status == "pass"


def test_summary_counts_tiers_and_fixable_separately():
    results = dc.run_checks(FakeProbe(GOOD, ack=False))
    summary = dc.summarise(results)
    assert summary["overall"]["total"] == len(results)
    assert summary["tiers"]["4"]["total"] >= 5
    assert summary["fixable"]["total"] < summary["overall"]["total"]
    assert summary["fixable"]["score"] == 1.0  # only limit checks fail here


def test_compare_lists_what_changed():
    def snapshot(label, statuses):
        rows = [
            {"id": k, "title": k, "status": v, "tier": 1, "limit": False}
            for k, v in statuses.items()
        ]
        results = [dc.Result(r["id"], 1, r["title"], r["status"], "", False, "") for r in rows]
        return {"label": label, "summary": dc.summarise(results), "results": rows}

    before = snapshot("before", {"a": "fail", "b": "pass", "c": "fail"})
    after = snapshot("after", {"a": "pass", "b": "fail", "c": "fail"})
    text = dc.compare(before, after)
    assert "+ a" in text and "- b" in text and "before -> after" in text


def test_render_marks_limits_and_failures():
    text = dc.render("x", dc.run_checks(FakeProbe(GOOD, ack=False)))
    assert "FAIL  Acknowledges an exec request" in text
    assert "(config cannot fix)" in text and "Overall" in text


def _kexinit_stream(lists):
    body = bytes([20]) + b"\x00" * 16
    for names in lists:
        body += dc._string(",".join(names).encode())
    body += b"\x00\x00\x00\x00\x00"
    return b"SSH-2.0-test\r\n" + dc._packet(body)


def test_kexinit_parser_reads_every_list():
    names = (
        "kex",
        "host_key",
        "cipher_c2s",
        "cipher_s2c",
        "mac_c2s",
        "mac_s2c",
        "comp_c2s",
        "comp_s2c",
    )
    lists = [["a", "b"], ["ssh-rsa"], ["c1"], ["c2"], ["m1"], ["m2"], ["none"], ["none"], [], []]
    got = dc.parse_kexinit(_kexinit_stream(lists), names)
    assert got["kex"] == ["a", "b"] and got["cipher_s2c"] == ["c2"] and got["comp_s2c"] == ["none"]


def test_kexinit_parser_survives_garbage_and_truncation():
    names = ("kex",)
    assert dc.parse_kexinit(b"", names) == {}
    assert dc.parse_kexinit(b"SSH-2.0-x\r\n\x00\x00\x00\x05", names) == {}
    assert dc.parse_kexinit(b"SSH-2.0-x\r\n" + struct.pack(">I", 99999) + b"x" * 20, names) == {}


def test_packets_are_padded_to_the_block_size():
    for size in range(0, 40):
        framed = dc._packet(b"x" * size)
        (length,) = struct.unpack(">I", framed[:4])
        assert (length + 4) % 8 == 0 and framed[4] >= 4


def test_rsa_key_size_is_read_from_the_host_key_blob():
    modulus = (1 << 3071) | 1  # a 3072-bit number
    blob = (
        dc._string(b"ssh-rsa")
        + dc._string(b"\x01\x00\x01")
        + dc._string(b"\x00" + modulus.to_bytes(384, "big"))
    )
    assert dc._rsa_bits_of(blob) == 3072
    assert dc._rsa_bits_of(dc._string(b"ssh-ed25519") + dc._string(b"k")) is None


def test_cli_compare_prints_a_table(tmp_path, capsys):
    results = dc.run_checks(FakeProbe(GOOD))
    for name in ("a", "b"):
        (tmp_path / f"{name}.json").write_text(
            json.dumps(
                {
                    "label": name,
                    "summary": dc.summarise(results),
                    "results": [dc.asdict(r) for r in results],
                }
            )
        )
    assert dc.main(["--compare", str(tmp_path / "a.json"), str(tmp_path / "b.json")]) == 0
    assert "a -> b" in capsys.readouterr().out
