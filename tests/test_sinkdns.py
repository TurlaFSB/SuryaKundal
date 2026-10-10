"""cowrie/tools/sinkdns.py: the deny-mode resolver stub answers every query with SERVFAIL."""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("sinkdns", ROOT / "cowrie" / "tools" / "sinkdns.py")
assert _spec and _spec.loader
sinkdns = importlib.util.module_from_spec(_spec)
sys.modules["sinkdns"] = sinkdns
_spec.loader.exec_module(sinkdns)


def query(name: str = "example.com", *, ident: int = 0xABCD, flags: int = 0x0100) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return (
        struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", 1, 1)
    )


def rcode(reply: bytes) -> int:
    return struct.unpack("!H", reply[2:4])[0] & 0xF


def test_a_query_gets_servfail_with_its_id_and_question_echoed():
    q = query()
    reply = sinkdns.answer(q)
    assert reply is not None
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", reply[:12])
    assert ident == 0xABCD
    assert flags & 0x8000  # a response
    assert flags & 0x0100  # recursion desired is copied
    assert flags & 0x0080  # recursion available is claimed
    assert rcode(reply) == 2
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    assert reply[12:] == q[12:]  # the question comes back unchanged


def test_recursion_desired_is_copied_not_assumed():
    assert not struct.unpack("!H", sinkdns.answer(query(flags=0))[2:4])[0] & 0x0100


def test_opcode_is_preserved():
    flags = 0x2000 | 0x0100  # opcode 4 (notify)
    reply = sinkdns.answer(query(flags=flags))
    assert struct.unpack("!H", reply[2:4])[0] & 0x7800 == 0x2000


def test_extra_sections_such_as_edns_are_ignored():
    q = query() + b"\0\0\x29\x10\0\0\0\0\0\0\0"  # a trailing OPT record
    reply = sinkdns.answer(q)
    assert reply is not None and len(reply) == len(query())


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"short",
        query()[:20],  # cut off inside the question
        struct.pack("!HHHHHH", 1, 0x8100, 1, 0, 0, 0) + b"\3foo\0\0\1\0\1",  # already a response
        struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0),  # no question
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1",  # compressed name
    ],
)
def test_anything_that_is_not_a_usable_query_is_ignored(packet):
    assert sinkdns.answer(packet) is None


def test_long_names_and_many_labels_are_handled():
    name = ".".join(["a" * 60] * 4)
    assert rcode(sinkdns.answer(query(name))) == 2


def test_it_answers_over_a_real_udp_socket_and_ignores_garbage():
    async def run() -> tuple[bytes, bytes | None]:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            sinkdns._Sink, local_addr=("127.0.0.1", 0)
        )
        port = transport.get_extra_info("sockname")[1]

        def ask(packet: bytes) -> bytes | None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                s.sendto(packet, ("127.0.0.1", port))
                try:
                    return s.recv(512)
                except TimeoutError:
                    return None

        try:
            good = await loop.run_in_executor(None, ask, query())
            junk = await loop.run_in_executor(None, ask, b"\x00" * 5)
        finally:
            transport.close()
        assert good is not None
        return good, junk

    good, junk = asyncio.run(run())
    assert rcode(good) == 2
    assert junk is None


def test_the_entrypoint_starts_the_stub_only_when_the_resolver_is_local():
    script = (ROOT / "cowrie" / "docker-entrypoint.sh").read_text()
    assert "grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf" in script
    assert "python /opt/kit/tools/sinkdns.py &" in script
    assert script.index("sinkdns.py") < script.index("exec cowrie start")
    deny = (ROOT / "cowrie" / "resolv.deny.conf").read_text()
    assert "nameserver 127.0.0.1" in deny.splitlines()
    captures = (ROOT / "cowrie" / "resolv.captures.conf").read_text()
    assert "127.0.0.1" not in captures  # captures mode must not start the stub
