"""Measure how convincing a honeypot is, the way an attacker would probe it.

Run it from another machine against YOUR OWN honeypot only:

    python evaluation/deception_check.py HOST --port 2222 --user deploy --password '...' \
        --label after --json after.json
    python evaluation/deception_check.py --compare before.json after.json

It connects, reads the banner and algorithm lists, logs in with a credential you supply, and
runs harmless read-only commands. Nothing is written to the target. Each check is tagged with the
attacker class that would run it (see cowrie/FINGERPRINTING.md):

    1  scanners and bots: banner, default credentials, wildcard logins
    2  quick manual look: commands whose output contradicts the claimed OS
    3  skilled operator: cross-checks between two views of the same fact
    4  protocol-aware tooling: how the SSH server itself behaves

A check marked "limit" cannot be fixed with Cowrie configuration. It is still scored, so the
numbers show the honest ceiling instead of hiding the hard parts.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import secrets
import socket
import struct
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

try:  # only the live probe needs paramiko; scoring and comparison do not
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]

TIERS = {
    1: "scanners and bots",
    2: "quick manual look",
    3: "skilled operator",
    4: "protocol-aware tooling",
}

# Strings that identify an unmodified Cowrie install (3.1.1 dist and the code fallback).
DEFAULT_BANNERS = ("OpenSSH_6.0p1 Debian-4+deb7u2", "OpenSSH_9.2p1 Debian-2+deb12u3")
DEFAULT_HOSTNAMES = {"svr04", "nas3"}
DEFAULT_KERNELS = ("6.1.0-21", "6.1.90-1")
DEFAULT_MEMTOTAL_KB = 4054744


class Probe:
    """One honeypot, reached over SSH. Every command opens its own connection because Cowrie
    closes the connection after an exec request."""

    def __init__(self, host: str, port: int, user: str, password: str, timeout: float = 15.0):
        self.host, self.port, self.user, self.password, self.timeout = (
            host,
            port,
            user,
            password,
            timeout,
        )
        self._cache: dict[str, str] = {}

    # --- raw socket views -------------------------------------------------------------
    def banner(self) -> str:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            data = b""
            while b"\n" not in data and len(data) < 512:
                chunk = sock.recv(256)
                if not chunk:
                    break
                data += chunk
        return data.split(b"\n", 1)[0].decode("latin-1").strip()

    def kex_lists(self) -> dict[str, list[str]]:
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
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10\r\n")
            buffer = _read_until_packet(sock)
        return parse_kexinit(buffer, names)

    def odd_version_survives(self) -> tuple[bool, str]:
        """OpenSSH accepts any 2.x protocol version. Does the server keep talking?"""
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(2.0)
            try:
                sock.recv(512)  # server version line (and maybe KEXINIT)
                sock.sendall(b"SSH-2.2-OpenSSH_9.2p1 Debian-2+deb12u10\r\n")
                seen = b""
                while True:
                    chunk = sock.recv(512)
                    if not chunk:
                        return False, "connection closed after a 2.2 version string"
                    seen += chunk
                    if b"Protocol major versions differ" in seen:
                        return False, "server said: Protocol major versions differ"
            except TimeoutError:
                return True, "connection stayed open"
            except OSError as exc:
                return False, f"connection error: {exc}"

    # --- authenticated views ----------------------------------------------------------
    def login_ok(self, user: str, password: str) -> bool:
        client = self._client()
        try:
            client.connect(
                self.host,
                self.port,
                user,
                password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        finally:
            client.close()

    def _exec(self, command: str) -> tuple[str, bool]:
        """Run one command. Returns (output, acknowledged). Cowrie closes the channel before it
        replies to the exec request, so paramiko raises; the output has already arrived."""
        transport = paramiko.Transport((self.host, self.port))
        try:
            transport.start_client(timeout=self.timeout)
            transport.auth_password(self.user, self.password)
            channel = transport.open_session(timeout=self.timeout)
            channel.set_combine_stderr(True)
            channel.settimeout(self.timeout)
            acknowledged = True
            try:
                channel.exec_command(command)
            except paramiko.SSHException:
                acknowledged = False
            data = b""
            while True:
                try:
                    chunk = channel.recv(4096)
                except (OSError, EOFError):
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", "replace").strip(), acknowledged
        finally:
            transport.close()

    def run(self, command: str) -> str:
        if command not in self._cache:
            self._cache[command] = self._exec(command)[0]
        return self._cache[command]

    def exec_acknowledged(self) -> bool:
        return self._exec("true")[1]

    def rsa_bits(self) -> int | None:
        """Size of the RSA host key, read with a bare-bones curve25519 key exchange (paramiko
        no longer speaks SHA-1 ssh-rsa, which is what Cowrie offers)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(b"SSH-2.0-surya-probe\r\n")
            ours = _kexinit_packet(["curve25519-sha256"], ["ssh-rsa"])
            sock.sendall(ours)
            public = (
                X25519PrivateKey.generate()
                .public_key()
                .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            )
            sock.sendall(_packet(bytes([30]) + _string(public)))
            sock.settimeout(5.0)
            data = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                except TimeoutError:
                    return None
                if not chunk:
                    return None
                data += chunk
                for payload in _packets(data):
                    if payload[:1] == bytes([31]):
                        return _rsa_bits_of(_read_string(payload, 1)[0])

    def prelogin_banner(self) -> str | None:
        transport = paramiko.Transport((self.host, self.port))
        try:
            transport.start_client(timeout=self.timeout)
            with contextlib.suppress(paramiko.BadAuthenticationType):
                transport.auth_none(self.user)
            return (
                transport.get_banner().decode("utf-8", "replace")
                if transport.get_banner()
                else None
            )
        finally:
            transport.close()

    def _client(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _read_string(data: bytes, cursor: int) -> tuple[bytes, int]:
    (size,) = struct.unpack(">I", data[cursor : cursor + 4])
    return data[cursor + 4 : cursor + 4 + size], cursor + 4 + size


def _packet(payload: bytes) -> bytes:
    padding = 8 - ((5 + len(payload)) % 8)
    padding = padding + 8 if padding < 4 else padding
    body = bytes([padding]) + payload + b"\x00" * padding
    return struct.pack(">I", len(body)) + body


def _kexinit_packet(kex: list[str], host_keys: list[str]) -> bytes:
    lists = [
        kex,
        host_keys,
        ["aes128-ctr"],
        ["aes128-ctr"],
        ["hmac-sha2-256"],
        ["hmac-sha2-256"],
        ["none"],
        ["none"],
        [],
        [],
    ]
    body = (
        bytes([20])
        + b"\x00" * 16
        + b"".join(_string(",".join(x).encode()) for x in lists)
        + b"\x00"
        + b"\x00\x00\x00\x00"
    )
    return _packet(body)


def _packets(data: bytes):
    """Yield the payload of each complete binary packet after the server's version line."""
    index = data.find(b"SSH-")
    end = data.find(b"\n", index) if index >= 0 else -1
    rest = data[end + 1 :] if end >= 0 else b""
    while len(rest) >= 5:
        (length,) = struct.unpack(">I", rest[:4])
        if length > 35000 or len(rest) < 4 + length:
            return
        yield rest[5 : 4 + length - rest[4]]
        rest = rest[4 + length :]


def _rsa_bits_of(blob: bytes) -> int | None:
    kind, cursor = _read_string(blob, 0)
    if kind != b"ssh-rsa":
        return None
    _, cursor = _read_string(blob, cursor)  # exponent
    modulus, _ = _read_string(blob, cursor)
    return int.from_bytes(modulus, "big").bit_length()


def _read_until_packet(sock: socket.socket) -> bytes:
    sock.settimeout(5.0)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        if _first_packet(data) is not None:
            break
    return data


def _first_packet(data: bytes) -> bytes | None:
    """The first binary packet after the server's version line, or None if incomplete."""
    index = data.find(b"SSH-")
    if index < 0:
        return None
    end = data.find(b"\n", index)
    if end < 0:
        return None
    rest = data[end + 1 :]
    if len(rest) < 5:
        return None
    (length,) = struct.unpack(">I", rest[:4])
    if length > 35000 or len(rest) < 4 + length:
        return None if length <= 35000 else b""
    return rest[4 : 4 + length]


def parse_kexinit(data: bytes, names: tuple[str, ...]) -> dict[str, list[str]]:
    packet = _first_packet(data)
    if not packet or len(packet) < 18 or packet[1] != 20:
        return {}
    cursor, lists = 18, {}  # padding byte, message type 20, 16 cookie bytes
    for name in names:
        if cursor + 4 > len(packet):
            return {}
        (size,) = struct.unpack(">I", packet[cursor : cursor + 4])
        cursor += 4
        lists[name] = packet[cursor : cursor + size].decode("ascii", "replace").split(",")
        cursor += size
    return lists


# --- the checks ----------------------------------------------------------------------


@dataclass
class Check:
    id: str
    tier: int
    title: str
    fn: Callable[[Probe], tuple[bool, str]]
    limit: bool = False  # cannot be fixed with Cowrie configuration
    ref: str = ""  # row of cowrie/FINGERPRINTING.md


CHECKS: list[Check] = []


def check(id: str, tier: int, title: str, *, limit: bool = False, ref: str = ""):
    def register(fn: Callable[[Probe], tuple[bool, str]]):
        CHECKS.append(Check(id, tier, title, fn, limit, ref))
        return fn

    return register


def _first_int(text: str) -> int | None:
    match = re.search(r"\d+", text)
    return int(match.group()) if match else None


# tier 1 ---------------------------------------------------------------------------------


@check("banner-not-default", 1, "SSH banner is not a stock Cowrie string", ref="row 1")
def _(p: Probe):
    banner = p.banner()
    return not any(d in banner for d in DEFAULT_BANNERS), banner


@check(
    "banner-current-openssh",
    1,
    "Banner claims a recent OpenSSH, not a 10-year-old one",
    ref="row 1",
)
def _(p: Probe):
    banner = p.banner()
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", banner)
    ok = bool(match) and (int(match.group(1)), int(match.group(2))) >= (8, 4)
    return ok, banner


@check("no-prelogin-text", 1, "No text shown before login")
def _(p: Probe):
    text = p.prelogin_banner()
    return not text, repr(text) if text else "none"


@check("wildcard-login-refused", 1, "A random password for root is refused", ref="row 4")
def _(p: Probe):
    accepted = p.login_ok("root", secrets.token_urlsafe(12))
    return not accepted, "accepted" if accepted else "refused"


@check("default-credentials-refused", 1, "Well-known default credentials are refused", ref="row 4")
def _(p: Probe):
    tried = [
        ("root", "root"),
        ("root", "123456"),
        ("root", "password"),
        ("admin", "admin"),
        ("phil", "phil"),
    ]
    accepted = [f"{u}/{pw}" for u, pw in tried if p.login_ok(u, pw)]
    return not accepted, "accepted: " + ", ".join(accepted) if accepted else "all refused"


@check("hostname-not-default", 1, "Hostname is not a stock Cowrie or T-Pot name", ref="row 2")
def _(p: Probe):
    name = p.run("hostname")
    return name.strip() not in DEFAULT_HOSTNAMES and bool(name), name


@check("hostkey-rsa-3072", 1, "RSA host key is at least 3072 bits (Debian default)", ref="row 12")
def _(p: Probe):
    bits = p.rsa_bits()
    return bool(bits) and bits >= 3072, f"{bits} bits"


# tier 2 ---------------------------------------------------------------------------------


@check("hostname-views-agree", 2, "hostname, uname -n and /etc/hostname agree", ref="row 3")
def _(p: Probe):
    views = {p.run("hostname"), p.run("uname -n"), p.run("cat /etc/hostname")}
    return len(views) == 1 and "" not in views, " | ".join(sorted(views))


@check("os-release-filled", 2, "/etc/os-release is not empty and says Debian 12", ref="row 6")
def _(p: Probe):
    text = p.run("cat /etc/os-release")
    return "Debian" in text and "12" in text, text.splitlines()[0] if text else "empty"


@check("debian-version-matches", 2, "/etc/debian_version agrees with os-release", ref="row 5")
def _(p: Probe):
    version = p.run("cat /etc/debian_version")
    return version.startswith("12"), version or "empty"


@check("no-container-artifacts", 2, "No Docker or VirtualBox leftovers", ref="row 5")
def _(p: Probe):
    seen = p.run("ls -a /") + p.run("cat /proc/1/cgroup") + p.run("cat /etc/group")
    bad = [w for w in (".dockerenv", "docker", "vboxsf") if w in seen]
    return not bad, "found: " + ", ".join(bad) if bad else "clean"


@check("no-default-user-phil", 2, "The stock account 'phil' does not exist", ref="row 5")
def _(p: Probe):
    present = "phil" in p.run("cat /etc/passwd") or "phil" in p.run("ls /home")
    return not present, "present" if present else "absent"


@check("uname-matches-proc-version", 2, "uname -r appears in /proc/version", ref="row 9")
def _(p: Probe):
    release = p.run("uname -r")
    return bool(release) and release in p.run("cat /proc/version"), release


@check("kernel-not-default", 2, "Kernel is not the stock Cowrie one", ref="row 9")
def _(p: Probe):
    release = p.run("uname -r")
    return not any(release.startswith(k) for k in DEFAULT_KERNELS), release


@check("ssh-version-matches-banner", 2, "`ssh -V` inside the shell matches the banner", ref="row 8")
def _(p: Probe):
    banner = re.search(r"OpenSSH_[\w.]+", p.banner())
    inside = re.search(r"OpenSSH_[\w.]+", p.run("ssh -V"))
    ok = bool(banner and inside and banner.group() == inside.group())
    return (
        ok,
        f"banner {banner.group() if banner else '?'}, shell {inside.group() if inside else '?'}",
    )


@check("sshd-config-filled", 2, "/etc/ssh/sshd_config has content", ref="row 6")
def _(p: Probe):
    size = _first_int(p.run("cat /etc/ssh/sshd_config | wc -c")) or 0
    return size > 500, f"{size} bytes"


@check("df-works", 2, "`df -h` runs and lists a root filesystem", ref="row 7")
def _(p: Probe):
    out = p.run("df -h")
    return "Exec format" not in out and " /" in out, out.splitlines()[0] if out else "no output"


@check("mount-modern", 2, "`mount` shows no ext3 or VirtualBox", ref="row 7")
def _(p: Probe):
    out = p.run("mount")
    bad = [w for w in ("ext3", "vbox") if w in out.lower()]
    return bool(out) and not bad, "found: " + ", ".join(bad) if bad else "ok"


@check("dmesg-matches-kernel", 2, "dmesg is from the claimed kernel, not a 2009 one", ref="row 7")
def _(p: Probe):
    head = p.run("dmesg | head -5")
    major = ".".join(p.run("uname -r").split(".")[:2])
    return bool(major) and major in head and "2.6" not in head, head.splitlines()[
        0
    ] if head else "empty"


@check("ps-no-virtualbox", 2, "`ps` shows no VirtualBox services", ref="row 10")
def _(p: Probe):
    out = p.run("ps aux")
    bad = [w for w in ("VBox", "iprt", "rcu_bh") if w in out]
    return bool(out) and not bad, "found: " + ", ".join(bad) if bad else "ok"


@check("top-runs", 2, "`top` produces a normal header", ref="row 7")
def _(p: Probe):
    out = p.run("top -bn1 | head -1")
    return out.startswith("top -"), out or "no output"


@check("getconf-64bit", 2, "getconf LONG_BIT says 64", ref="row 7")
def _(p: Probe):
    out = p.run("getconf LONG_BIT")
    return out == "64", out


@check("root-shell-bash", 2, "Accounts use /bin/bash like a Debian 12 install", ref="row 5")
def _(p: Probe):
    line = next((x for x in p.run("cat /etc/passwd").splitlines() if x.startswith("root:")), "")
    return line.endswith("/bin/bash"), line or "no root entry"


# tier 3 ---------------------------------------------------------------------------------


def _meminfo_kb(p: Probe) -> int | None:
    match = re.search(r"MemTotal:\s+(\d+)", p.run("cat /proc/meminfo"))
    return int(match.group(1)) if match else None


@check("free-matches-meminfo", 3, "`free` and /proc/meminfo report the same memory", ref="row 21")
def _(p: Probe):
    meminfo = _meminfo_kb(p)
    match = re.search(r"Mem:\s+(\d+)", p.run("free -k"))
    free = int(match.group(1)) if match else None
    ok = bool(meminfo and free) and abs(meminfo - free) / meminfo < 0.02
    return ok, f"/proc/meminfo {meminfo} kB, free {free} kB"


@check("meminfo-not-default", 3, "MemTotal is not the value shared by every Cowrie", ref="row 11")
def _(p: Probe):
    value = _meminfo_kb(p)
    return value is not None and value != DEFAULT_MEMTOTAL_KB, f"{value} kB"


@check("cpu-views-agree", 3, "lscpu and /proc/cpuinfo name the same CPU", ref="row 7")
def _(p: Probe):
    cpuinfo = re.search(r"model name\s*:\s*(.+)", p.run("cat /proc/cpuinfo"))
    lscpu = re.search(r"Model name:\s*(.+)", p.run("lscpu"))
    a, b = (cpuinfo.group(1).strip() if cpuinfo else ""), (lscpu.group(1).strip() if lscpu else "")
    return bool(a) and a == b, f"cpuinfo '{a}', lscpu '{b}'"


@check("cpu-not-default", 3, "CPU model is not the one shared by every Cowrie", ref="row 11")
def _(p: Probe):
    match = re.search(r"model name\s*:\s*(.+)", p.run("cat /proc/cpuinfo"))
    name = match.group(1).strip() if match else ""
    return bool(name) and "E5-2680" not in name, name


@check("uptime-consistent", 3, "`uptime` agrees with /proc/uptime", ref="row 13")
def _(p: Probe):
    seconds = float((p.run("cat /proc/uptime").split() or ["0"])[0])
    match = re.search(r"up\s+(\d+)\s+day", p.run("uptime"))
    days = int(match.group(1)) if match else 0
    return abs(
        days - seconds / 86400
    ) < 1.5 and seconds > 3600, f"/proc/uptime {seconds / 86400:.1f} d, uptime {days} d"


@check("ls-size-matches-wc", 3, "ls -l size equals wc -c for a file", ref="row 6")
def _(p: Probe):
    listed = re.match(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s", p.run("ls -l /etc/hostname"))
    counted = _first_int(p.run("wc -c < /etc/hostname"))
    ok = bool(listed) and counted is not None and int(listed.group(1)) == counted
    return ok, f"ls {listed.group(1) if listed else '?'}, wc {counted}"


@check("proc-has-many-pids", 3, "/proc lists a realistic number of processes", ref="row 5")
def _(p: Probe):
    count = sum(token.isdigit() for token in p.run("ls /proc").split())
    return count >= 20, f"{count} process directories"


@check("dir-link-counts", 3, "Directories have link counts above 1", limit=True, ref="row 22")
def _(p: Probe):
    match = re.search(r"^\S+\s+(\d+)", p.run("ls -ld /etc"))
    count = int(match.group(1)) if match else 0
    return count > 1, f"/etc has {count}"


@check("dpkg-populated", 3, "The package database is populated", limit=True, ref="row 6")
def _(p: Probe):
    count = _first_int(p.run("dpkg -l | wc -l")) or 0
    return count > 100, f"{count} lines"


@check("ip-command", 3, "`ip a` exists, as on any Debian 12", limit=True, ref="row 22")
def _(p: Probe):
    out = p.run("ip a")
    return "not found" not in out and bool(out), out.splitlines()[0] if out else "no output"


@check("sudo-l-sane", 3, "`sudo -l` gives a sensible answer", limit=True, ref="row 22")
def _(p: Probe):
    out = p.run("sudo -l")
    ok = bool(out) and "illegal option" not in out and "usage:" not in out
    return ok, out.splitlines()[0] if out else "no output"


@check(
    "ls-date-format",
    3,
    "`ls -l` dates look like GNU ls (May  4 14:44), not ISO",
    limit=True,
    ref="row 22",
)
def _(p: Probe):
    line = p.run("ls -l /etc/hostname")
    return not re.search(r"\s\d{4}-\d{2}-\d{2}\s", line), line


@check("grep-count-in-pipe", 3, "`grep -c` works on piped input", limit=True, ref="row 22")
def _(p: Probe):
    out = p.run("echo hello | grep -c hello")
    return out == "1", repr(out[:60])


@check(
    "wc-multiple-files",
    3,
    "`wc -c a b` prints a line per file plus a total",
    limit=True,
    ref="row 22",
)
def _(p: Probe):
    lines = p.run("wc -c /etc/hostname /etc/hosts").splitlines()
    return len(lines) == 3, f"{len(lines)} lines"


@check("echo-dollar-zero", 3, "`echo $0` names the shell", limit=True, ref="row 22")
def _(p: Probe):
    out = p.run("echo $0")
    return "bash" in out, repr(out)


# tier 4 ---------------------------------------------------------------------------------


@check(
    "exec-acknowledged",
    4,
    "Acknowledges an exec request before closing the channel",
    limit=True,
    ref="row 20",
)
def _(p: Probe):
    return (
        p.exec_acknowledged(),
        "acknowledged" if p.exec_acknowledged() else "channel closed before any reply",
    )


@check(
    "accepts-ssh-2-x", 4, "Accepts any 2.x protocol version like OpenSSH", limit=True, ref="row 15"
)
def _(p: Probe):
    return p.odd_version_survives()


def _offers(p: Probe, group: str, name: str) -> tuple[bool, str]:
    lists = p.kex_lists()
    return name in lists.get(group, []), f"{len(lists.get(group, []))} offered"


@check(
    "offers-chacha20",
    4,
    "Offers chacha20-poly1305, the OpenSSH default cipher",
    limit=True,
    ref="row 18",
)
def _(p: Probe):
    return _offers(p, "cipher_s2c", "chacha20-poly1305@openssh.com")


@check("offers-aes-gcm", 4, "Offers AES-GCM ciphers", limit=True, ref="row 18")
def _(p: Probe):
    return _offers(p, "cipher_s2c", "aes256-gcm@openssh.com")


@check(
    "offers-sntrup761",
    4,
    "Offers the post-quantum key exchange OpenSSH 9.x defaults to",
    limit=True,
    ref="row 18",
)
def _(p: Probe):
    return _offers(p, "kex", "sntrup761x25519-sha512@openssh.com")


@check("offers-rsa-sha2", 4, "Offers rsa-sha2-512 host key signatures", limit=True, ref="row 18")
def _(p: Probe):
    return _offers(p, "host_key", "rsa-sha2-512")


@check("offers-etm-macs", 4, "Offers -etm MACs", limit=True, ref="row 18")
def _(p: Probe):
    return _offers(p, "mac_s2c", "hmac-sha2-256-etm@openssh.com")


# --- running and reporting -----------------------------------------------------------


@dataclass
class Result:
    id: str
    tier: int
    title: str
    status: str  # pass | fail | error
    detail: str
    limit: bool
    ref: str


def run_checks(probe: Probe, only: set[str] | None = None) -> list[Result]:
    results = []
    for item in CHECKS:
        if only and item.id not in only:
            continue
        try:
            ok, detail = item.fn(probe)
            status = "pass" if ok else "fail"
        except Exception as exc:  # a broken probe is a result, not a crash
            status, detail = "error", f"{type(exc).__name__}: {exc}"
        results.append(
            Result(item.id, item.tier, item.title, status, detail[:200], item.limit, item.ref)
        )
    return results


def summarise(results: list[Result]) -> dict:
    def tally(rows: list[Result]) -> dict:
        passed = sum(r.status == "pass" for r in rows)
        return {
            "passed": passed,
            "total": len(rows),
            "score": round(passed / len(rows), 3) if rows else None,
        }

    return {
        "overall": tally(results),
        "fixable": tally([r for r in results if not r.limit]),
        "tiers": {str(t): tally([r for r in results if r.tier == t]) for t in TIERS},
    }


def render(label: str, results: list[Result]) -> str:
    summary = summarise(results)
    lines = [f"Deception check: {label}", ""]
    for tier, name in TIERS.items():
        rows = [r for r in results if r.tier == tier]
        done = summary["tiers"][str(tier)]
        lines.append(f"Tier {tier}  {name}  {done['passed']}/{done['total']}")
        for r in rows:
            mark = {"pass": "PASS", "fail": "FAIL", "error": "ERR "}[r.status]
            note = "  (config cannot fix)" if r.limit and r.status != "pass" else ""
            lines.append(f"  {mark}  {r.title}{note}")
            if r.status != "pass":
                lines.append(f"        {r.detail}")
        lines.append("")
    o, f = summary["overall"], summary["fixable"]
    lines.append(
        f"Overall {o['passed']}/{o['total']} ({o['score']:.0%}). "
        f"Fixable by configuration {f['passed']}/{f['total']} ({f['score']:.0%})."
    )
    return "\n".join(lines)


def compare(before: dict, after: dict) -> str:
    old = {r["id"]: r for r in before["results"]}
    new = {r["id"]: r for r in after["results"]}
    lines = [f"{before['label']} -> {after['label']}", ""]
    for tier, name in TIERS.items():
        a, b = before["summary"]["tiers"][str(tier)], after["summary"]["tiers"][str(tier)]
        was, now = f"{a['passed']}/{a['total']}", f"{b['passed']}/{b['total']}"
        lines.append(f"Tier {tier}  {name:<24} {was:>6} -> {now:>6}")
    o1, o2 = before["summary"]["overall"], after["summary"]["overall"]
    lines.append(
        f"Overall {'':<28} {o1['passed']:>2}/{o1['total']:<2} -> {o2['passed']:>2}/{o2['total']:<2}"
    )
    gained = [
        new[i]["title"]
        for i in new
        if i in old and old[i]["status"] != "pass" and new[i]["status"] == "pass"
    ]
    lost = [
        new[i]["title"]
        for i in new
        if i in old and old[i]["status"] == "pass" and new[i]["status"] != "pass"
    ]
    if gained:
        lines += ["", "Now passing:"] + [f"  + {t}" for t in gained]
    if lost:
        lines += ["", "No longer passing:"] + [f"  - {t}" for t in lost]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("host", nargs="?")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", help="a credential the honeypot accepts")
    parser.add_argument("--label", default="honeypot")
    parser.add_argument("--json", type=Path, help="write the full result here")
    parser.add_argument("--only", help="comma-separated check ids")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("BEFORE", "AFTER"))
    parser.add_argument("--fail-under", type=float, help="exit 1 if the fixable score is lower")
    args = parser.parse_args(argv)

    if args.compare:
        before, after = (json.loads(p.read_text()) for p in args.compare)
        print(compare(before, after))
        return 0
    if not args.host or args.password is None:
        parser.error("HOST and --password are required (or use --compare)")
    if paramiko is None:
        parser.error("paramiko is required: pip install paramiko")

    probe = Probe(args.host, args.port, args.user, args.password)
    if not probe.login_ok(args.user, args.password):
        print(
            f"Cannot log in as {args.user}; pass a credential the honeypot accepts.",
            file=sys.stderr,
        )
        return 2
    results = run_checks(probe, set(args.only.split(",")) if args.only else None)
    print(render(args.label, results))
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "label": args.label,
                    "summary": summarise(results),
                    "results": [asdict(r) for r in results],
                },
                indent=2,
            )
        )
    if (
        args.fail_under is not None
        and (summarise(results)["fixable"]["score"] or 0) < args.fail_under
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
