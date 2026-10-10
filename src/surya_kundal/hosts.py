"""Which hosts in attacker-typed addresses are worth recording, and which are only noise.

An attacker (or an ordinary bot checking connectivity) can type any address into ``wget`` or
``curl``. Writing ``curl ifconfig.me`` into the honeypot does not make ifconfig.me malicious,
and an exported blocklist that says so would hurt other people. Two lists keep that out:

* ``COMMON_HOSTS``: public look-up services, popular sites and package mirrors. Nothing is ever
  exported or used to link sessions because of them.
* ``SHARED_HOSTING``: places anyone can put a file (code hosting, paste and file-sharing sites).
  A full address on them is a real indicator, but the host alone says nothing about who used it,
  so it is not used to link sessions and the host itself is never exported.
"""

from __future__ import annotations

import ipaddress
import re

COMMON_HOSTS = frozenset(
    {
        # "what is my address" and connectivity checks, the commonest bot recon
        "ifconfig.me", "ifconfig.co", "ipinfo.io", "icanhazip.com", "ipecho.net", "ipify.org",
        "api.ipify.org", "checkip.amazonaws.com", "ident.me", "myip.com", "ip.sb", "ipapi.co",
        "ip-api.com", "wtfismyip.com", "whatismyip.com", "httpbin.org", "ipv4.icanhazip.com",
        "speedtest.net", "fast.com", "connectivitycheck.gstatic.com", "captive.apple.com",
        # popular sites and public resolvers
        "google.com", "googleapis.com", "gstatic.com", "bing.com", "yahoo.com", "baidu.com",
        "qq.com", "microsoft.com", "windowsupdate.com", "apple.com", "amazon.com", "facebook.com",
        "twitter.com", "youtube.com", "wikipedia.org", "cloudflare.com", "one.one.one.one",
        "example.com", "example.org", "example.net", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "208.67.222.222", "208.67.220.220",
        # package and update mirrors
        "ubuntu.com", "debian.org", "kernel.org", "python.org", "pypi.org", "npmjs.org",
        "npmjs.com", "apache.org", "gnu.org", "centos.org", "fedoraproject.org", "alpinelinux.org",
        "rubygems.org", "crates.io", "golang.org", "docker.com", "docker.io",
    }
)  # fmt: skip
SHARED_HOSTING = frozenset(
    {
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "pastebin.com",
        "paste.ee", "hastebin.com", "transfer.sh", "file.io", "anonfiles.com", "dropbox.com",
        "dropboxusercontent.com", "discordapp.com", "discord.com", "mediafire.com", "mega.nz",
        "sourceforge.net", "archive.org", "ghostbin.com", "termbin.com", "0x0.st", "catbox.moe",
        "telegram.org", "t.me", "docs.google.com", "drive.google.com", "onedrive.live.com",
        "amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "workers.dev",
        "pages.dev", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "repl.co",
        "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    }
)  # fmt: skip
# Wildcard DNS services that turn any address into a name, used to dress up local targets.
WILDCARD_DNS = ("nip.io", "sslip.io", "xip.io", "lvh.me", "localtest.me", "traefik.me")

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^[a-z]{2,24}$|^xn--[a-z0-9-]{2,59}$")


def _matches(host: str, names: frozenset[str]) -> bool:
    parts = host.lower().rstrip(".").split(".")
    return any(".".join(parts[i:]) in names for i in range(len(parts)))


def is_common_host(host: str) -> bool:
    """True for look-up services, popular sites and package mirrors."""
    return _matches(host, COMMON_HOSTS)


def is_shared_hosting(host: str) -> bool:
    """True for places anyone can publish a file."""
    return _matches(host, SHARED_HOSTING)


def usable_host(host: str | None) -> bool:
    """A host that is a canonical IP address or a plain DNS name with a real top-level domain.

    Rejects the forms used to disguise local targets: ``127.1``, ``2130706433``, ``0x7f.1``,
    single-word names such as ``router``, and wildcard-DNS names such as ``10.0.0.1.nip.io``.
    """
    if not host or len(host) > 253:
        return False
    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return True
    labels = host.lower().split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return False
    if not _TLD.match(labels[-1]):
        return False
    return not any(host.lower().endswith("." + d) or host.lower() == d for d in WILDCARD_DNS)
