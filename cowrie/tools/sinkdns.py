"""A resolver that answers every lookup with SERVFAIL, at once.

In deny mode the honeypot container must not send DNS queries anywhere (a query is a covert
channel, and a name that resolves tells the attacker the machine has internet). Pointing
/etc/resolv.conf at a port nobody listens on would work, but Cowrie's DNS library then waits
about a minute before giving up. A real offline machine fails in about a second, and glibc
prints "Temporary failure in name resolution" for exactly this answer. So the container's
resolver is this stub, bound to 127.0.0.1 only: it reads nothing, logs nothing, forwards
nothing, and replies SERVFAIL to anything that looks like a query.

    python sinkdns.py [--host 127.0.0.1] [--port 53]
"""

from __future__ import annotations

import argparse
import asyncio
import struct

SERVFAIL = 2
QR = 0x8000  # this message is a response
RD = 0x0100  # recursion desired (copied from the query)
RA = 0x0080  # recursion available (we claim it, as a real resolver does)
HEADER = 12


def answer(query: bytes) -> bytes | None:
    """The SERVFAIL reply for a DNS query, or None when the packet is not a usable query."""
    if len(query) < HEADER:
        return None
    ident, flags, questions = struct.unpack("!HHH", query[:6])
    if flags & QR or questions < 1:
        return None
    position = HEADER
    while True:  # walk the first question's name: length-prefixed labels ending in a zero byte
        if position >= len(query):
            return None
        length = query[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0:  # compression pointers do not belong in a question
            return None
        position += 1 + length
    end = position + 4  # QTYPE and QCLASS
    if end > len(query):
        return None
    opcode = flags & 0x7800
    reply_flags = QR | opcode | (flags & RD) | RA | SERVFAIL
    return struct.pack("!HHHHHH", ident, reply_flags, 1, 0, 0, 0) + query[HEADER:end]


class _Sink(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = answer(data)
        if reply is not None:
            self.transport.sendto(reply, addr)


async def serve(host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_Sink, local_addr=(host, port))
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=53)
    args = parser.parse_args()
    asyncio.run(serve(args.host, args.port))


if __name__ == "__main__":
    main()
