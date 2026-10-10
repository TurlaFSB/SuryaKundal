"""Tell the operator's own traffic apart from real attackers.

Test logins, the deception harness and health probes reach the honeypot from loopback, the
Docker bridges, your LAN or your own address. They are useful for checking that the system
works but they are not attackers, and if they are counted they distort every statistic,
join unrelated sessions into campaigns and could put your own address on a blocklist.

A session is *internal* when its source address is loopback, private (10/8, 172.16/12,
192.168/16, fc00::/7), link-local, shared (100.64/10) or unspecified, or when it falls inside a
network you list in ``INTERNAL_NETWORKS`` (comma separated addresses or CIDR ranges, for
example your own public address while you test from outside).
Internal sessions are stored and mapped like any other, so you can still study them; the
dashboard, campaigns, metrics and exports leave them out unless asked.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from surya_kundal.database.models import HoneypotSession

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


# Documentation ranges (192.0.2/24 and friends) are deliberately not listed: nothing real uses
# them, and the examples and tests in this project do.
_LOCAL = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


class InternalNetworksError(ValueError):
    """``INTERNAL_NETWORKS`` contains something that is not an address or network."""


def parse_networks(text: str) -> tuple[Network, ...]:
    networks: list[Network] = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise InternalNetworksError(
                f"INTERNAL_NETWORKS: {part!r} is not an address or network"
            ) from exc
    return tuple(networks)


@lru_cache(maxsize=8)
def _cached(text: str) -> tuple[Network, ...]:
    return parse_networks(text)


def configured_networks() -> tuple[Network, ...]:
    return _cached(os.environ.get("INTERNAL_NETWORKS", ""))


def is_internal(ip: str | None, extra: tuple[Network, ...] | None = None) -> bool:
    """True for a local source address or one inside a configured network.

    A missing or unreadable address is not internal: it is better to show an odd session
    than to hide an attacker.
    """
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    networks = _LOCAL + (configured_networks() if extra is None else extra)
    return any(address.version == net.version and address in net for net in networks)


def reclassify(db: Session) -> tuple[int, int, int]:
    """Apply the current rules to every stored session. Returns (changed, internal, total)."""
    extra = configured_networks()
    changed = 0
    for ip in db.scalars(select(HoneypotSession.src_ip).distinct()).all():
        verdict = is_internal(ip, extra)
        same_ip = HoneypotSession.src_ip.is_(None) if ip is None else HoneypotSession.src_ip == ip
        result = db.execute(
            update(HoneypotSession)
            .where(same_ip, HoneypotSession.internal.is_(not verdict))
            .values(internal=verdict)
        )
        changed += int(result.rowcount or 0)  # type: ignore[attr-defined]
    db.commit()
    total = int(db.scalar(select(func.count()).select_from(HoneypotSession)) or 0)
    internal = int(
        db.scalar(
            select(func.count())
            .select_from(HoneypotSession)
            .where(HoneypotSession.internal.is_(True))
        )
        or 0
    )
    return changed, internal, total
