"""Packet-level proof of cowrie/egress.sh, in throwaway Linux network namespaces.

Run by tests/test_egress.py inside `unshare -n` (so nothing touches the real network):

  honeypot namespace --veth--> [bridge br-suryahoney | host] --veth--> internet namespace

The host routes between them. Servers listen in the "internet" namespace on 443, 80 and 25
and on the host's bridge address; a client in the honeypot namespace tries to reach each.
Prints one JSON object per phase. Needs root, iptables and pyroute2.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from pyroute2 import IPRoute, NetNS, netns

SCRIPT = Path(sys.argv[1])
BRIDGE = "br-suryahoney"
GATEWAY, HONEYPOT = "172.29.77.1", "172.29.77.2"
HOST_OUT, INTERNET = "1.1.1.254", "1.1.1.1"
PRIVATE = "10.9.9.9"  # reachable on purpose, so only the firewall can stop it


def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def in_namespace(name: str | None, fn) -> int:  # type: ignore[no-untyped-def]
    """Run fn() in a forked child inside namespace ``name``; return its exit status."""
    pid = os.fork()
    if pid == 0:
        try:
            if name:
                netns.setns(name)
            os._exit(0 if fn() else 1)
        except BaseException:
            os._exit(2)
    return os.waitpid(pid, 0)[1] >> 8


SERVERS: list[int] = []


def serve(name: str | None, host: str, ports: list[int]) -> None:
    pid = os.fork()
    SERVERS.append(pid)
    if pid == 0:
        sys.stdout.close()
        sys.stderr.close()
        if name:
            netns.setns(name)
        listeners = []
        for port in ports:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen(8)
            listeners.append(s)
        import selectors

        sel = selectors.DefaultSelector()
        for s in listeners:
            sel.register(s, selectors.EVENT_READ)
        while True:
            for key, _ in sel.select():
                conn, _ = key.fileobj.accept()  # type: ignore[union-attr]
                conn.sendall(b"hello")
                conn.close()


def connects(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            return s.recv(5) == b"hello"
    except OSError:
        return False


def forget_namespaces() -> None:
    for name in ("cont", "inet"):
        with contextlib.suppress(OSError):
            netns.remove(name)


def build() -> None:
    forget_namespaces()
    for name in ("cont", "inet"):
        netns.create(name)
    ipr = IPRoute()
    ipr.link("add", ifname=BRIDGE, kind="bridge")
    br = ipr.link_lookup(ifname=BRIDGE)[0]
    ipr.addr("add", index=br, address=GATEWAY, prefixlen=24)
    ipr.link("set", index=br, state="up")
    ipr.link("add", ifname="vh-c", kind="veth", peer={"ifname": "vc", "net_ns_fd": "cont"})
    ipr.link("set", index=ipr.link_lookup(ifname="vh-c")[0], master=br, state="up")
    ipr.link("add", ifname="vh-i", kind="veth", peer={"ifname": "vi", "net_ns_fd": "inet"})
    vhi = ipr.link_lookup(ifname="vh-i")[0]
    ipr.addr("add", index=vhi, address=HOST_OUT, prefixlen=24)
    ipr.link("set", index=vhi, state="up")
    ipr.link("set", index=ipr.link_lookup(ifname="lo")[0], state="up")
    ipr.route("add", dst=f"{PRIVATE}/32", gateway=INTERNET)
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    cont = NetNS("cont")
    cont.link("set", index=cont.link_lookup(ifname="lo")[0], state="up")
    vc = cont.link_lookup(ifname="vc")[0]
    cont.addr("add", index=vc, address=HONEYPOT, prefixlen=24)
    cont.link("set", index=vc, state="up")
    cont.route("add", dst="default", gateway=GATEWAY)
    inet = NetNS("inet")
    inet.link("set", index=inet.link_lookup(ifname="lo")[0], state="up")
    vi = inet.link_lookup(ifname="vi")[0]
    inet.addr("add", index=vi, address=INTERNET, prefixlen=24)
    inet.addr("add", index=inet.link_lookup(ifname="lo")[0], address=PRIVATE, prefixlen=32)
    inet.link("set", index=vi, state="up")
    inet.route("add", dst="172.29.77.0/24", gateway=HOST_OUT)
    # What Docker sets up: FORWARD hands everything to DOCKER-USER first.
    run("iptables", "-N", "DOCKER-USER")
    run("iptables", "-A", "DOCKER-USER", "-j", "RETURN")
    run("iptables", "-I", "FORWARD", "1", "-j", "DOCKER-USER")


def observe() -> dict[str, bool]:
    def from_honeypot(host: str, port: int) -> bool:
        return in_namespace("cont", lambda: connects(host, port)) == 0

    def into_honeypot() -> bool:
        return in_namespace("inet", lambda: connects(HONEYPOT, 2222)) == 0

    return {
        "web_443": from_honeypot(INTERNET, 443),
        "web_80": from_honeypot(INTERNET, 80),
        "mail_25": from_honeypot(INTERNET, 25),
        "private_10": from_honeypot(PRIVATE, 80),
        "host_gateway": from_honeypot(GATEWAY, 8080),
        "attacker_into_honeypot": into_honeypot(),
    }


def main() -> None:
    try:
        lab()
    finally:
        for pid in SERVERS:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass
        forget_namespaces()


def lab() -> None:
    build()
    serve("inet", INTERNET, [443, 80, 25])
    serve("inet", PRIVATE, [80])
    serve(None, GATEWAY, [8080])
    serve("cont", HONEYPOT, [2222])
    time.sleep(0.5)
    report = {"baseline": observe()}
    for mode in ("deny", "captures"):
        run("bash", str(SCRIPT), "apply", mode)
        report[mode] = observe()
    run("bash", str(SCRIPT), "remove")
    report["removed"] = observe()
    print(json.dumps(report))


if __name__ == "__main__":
    main()
