"""Rule-based mapping from attacker commands and logins to ATT&CK techniques.

Rules live in ``rules.toml`` so they can be reviewed and extended without touching
code. Each rule carries its own positive and negative examples, and the test suite
checks every one, so a rule cannot silently drift.

How a command is analysed
-------------------------
1. It is split into simple commands at ``;``, ``&&``, ``||``, ``|`` and ``&``, but
   only outside quotes, so ``echo "a; b"`` stays one command. Text inside ``$(...)``
   and backticks is analysed as well.
2. Each piece is normalised: leading ``sudo``/``nohup``/``env X=1`` wrappers and
   directory prefixes (``/usr/bin/wget`` -> ``wget``) are removed.
3. ``segment`` rules run on each normalised piece, ``command`` rules on the whole
   original line (needed for patterns that span a pipe, such as ``curl ... | sh``).

Limits, stated plainly: this is pattern matching, not a shell interpreter. It does
not follow variables or decode obfuscated payloads, and a command that is merely
quoted (``echo "wget http://x"``) is read as quoted text, not executed. Confidence
levels say how specific the pattern is, not how dangerous the command is.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from surya_kundal.mapping.attack import Catalog, load_catalog

CONFIDENCES = ("low", "medium", "high")
SCOPES = ("segment", "command")
SESSION_RULES_REVISION = "2"  # bump when the session-level logic below changes

# Commands are attacker-controlled, and regular expressions can be made to run slowly
# by crafted input. Anything longer than this is analysed as its first and last
# halves (the tail matters: ``... | base64 -d | sh`` ends a long encoded payload).
MAX_ANALYSED_CHARS = 2048

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_HIGH = 10
DEFAULT_USERNAMES = frozenset(
    {"root", "admin", "administrator", "user", "pi", "ubuntu", "test", "guest", "oracle",
     "postgres", "ftpuser", "support", "ec2-user", "debian", "vagrant", "git"}
)  # fmt: skip


class RuleError(ValueError):
    """The rule file is invalid."""


@dataclass(frozen=True)
class Rule:
    id: str
    technique: str
    confidence: str
    scope: str
    pattern: re.Pattern[str]
    description: str
    examples: tuple[str, ...]
    not_examples: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    rule_id: str
    technique: str
    confidence: str
    evidence: str


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    version: str  # changes whenever rules or session logic change


def _parse_rule(raw: dict, catalog: Catalog) -> Rule:
    rid = raw.get("id")
    if not rid:
        raise RuleError("every rule needs an id")
    for key in ("technique", "pattern", "description"):
        if not raw.get(key):
            raise RuleError(f"rule {rid}: missing '{key}'")
    if raw["technique"] not in catalog:
        raise RuleError(f"rule {rid}: {raw['technique']} is not an ATT&CK technique")
    confidence = raw.get("confidence", "medium")
    if confidence not in CONFIDENCES:
        raise RuleError(f"rule {rid}: confidence must be one of {CONFIDENCES}")
    scope = raw.get("scope", "segment")
    if scope not in SCOPES:
        raise RuleError(f"rule {rid}: scope must be one of {SCOPES}")
    try:
        pattern = re.compile(raw["pattern"])
    except re.error as exc:
        raise RuleError(f"rule {rid}: bad regex: {exc}") from exc
    return Rule(
        id=rid,
        technique=raw["technique"],
        confidence=confidence,
        scope=scope,
        pattern=pattern,
        description=raw["description"],
        examples=tuple(raw.get("examples", ())),
        not_examples=tuple(raw.get("not_examples", ())),
    )


def parse_rules(text: str, catalog: Catalog | None = None) -> RuleSet:
    catalog = catalog or load_catalog()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"rules file is not valid TOML: {exc}") from exc
    rules = tuple(_parse_rule(raw, catalog) for raw in data.get("rule", []))
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise RuleError(f"duplicate rule ids: {sorted(duplicates)}")
    digest = hashlib.sha256(f"{SESSION_RULES_REVISION}\n{text}".encode()).hexdigest()[:12]
    return RuleSet(rules=rules, version=digest)


@lru_cache(maxsize=1)
def load_rules() -> RuleSet:
    text = resources.files("surya_kundal.mapping").joinpath("rules.toml").read_text("utf-8")
    return parse_rules(text)


# --- command splitting and normalisation -----------------------------------

_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+")
_WRAPPERS = re.compile(
    r"^(?:sudo(?:\s+-\S+)*|nohup|time|exec|env|setsid|stdbuf\s+-\S+|busybox(?=\s+[a-z]))\s+"
)
_SYSTEM_BIN_DIR = re.compile(r"^/(?:usr/)?(?:local/)?s?bin/")


def split_commands(command: str) -> list[str]:
    """Split a shell line into simple commands, respecting quotes."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "\\" and quote != "'" and i + 1 < len(command):
            current.append(command[i : i + 2])
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            current.append(ch)
        elif ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch in ";\n|" or (ch == "&" and not _is_redirect(command, i)):
            segments.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    segments.append("".join(current))
    return [s.strip() for s in segments if s.strip()]


def _is_redirect(command: str, i: int) -> bool:
    """True for the & in ``2>&1``, ``>&`` and ``&>``, which is not a command separator."""
    before = command[i - 1] if i else ""
    after = command[i + 1] if i + 1 < len(command) else ""
    return before in "<>" or after == ">"


def normalize_segment(segment: str) -> str:
    """Drop wrappers and system directory prefixes so rules see the actual command.

    ``/usr/bin/wget`` becomes ``wget``, but ``/tmp/x`` stays as it is: running a
    file from a world-writable directory is itself worth seeing.
    """
    text = segment.strip()
    changed = True
    while changed:
        changed = False
        for pattern in (_ENV_ASSIGN, _SYSTEM_BIN_DIR, _WRAPPERS):
            stripped = pattern.sub("", text, count=1)
            if stripped != text:
                text, changed = stripped, True
    return text


def _segments_of(command: str) -> list[str]:
    pieces = split_commands(command)
    for match in _SUBSTITUTION.finditer(command):
        inner = match.group(1) or match.group(2) or ""
        pieces.extend(split_commands(inner))
    return [normalize_segment(p) for p in pieces]


def bound_command(command: str) -> str:
    """Return the command, or its head and tail if it is longer than the analysis limit."""
    if len(command) <= MAX_ANALYSED_CHARS:
        return command
    half = MAX_ANALYSED_CHARS // 2
    return f"{command[:half]} {command[-half:]}"


def map_command(command: str, ruleset: RuleSet | None = None) -> list[Match]:
    """Return every rule that matches this command line (at most one hit per rule)."""
    ruleset = ruleset or load_rules()
    command = bound_command(command)
    segments = _segments_of(command)
    matches: list[Match] = []
    for rule in ruleset.rules:
        evidence = None
        if rule.scope == "command":
            if rule.pattern.search(command):
                evidence = command
        else:
            evidence = next((s for s in segments if rule.pattern.search(s)), None)
        if evidence is not None:
            matches.append(Match(rule.id, rule.technique, rule.confidence, evidence[:300]))
    return matches


# --- session-level rules ---------------------------------------------------


def map_transfers(downloads: list[dict], uploads: list[dict]) -> list[Match]:
    """File transfers into the honeypot are ingress tool transfer, whatever tool was used."""
    matches = [
        Match("transfer-download", "T1105", "high", f"downloaded {item.get('url') or '?'}"[:300])
        for item in downloads
    ]
    matches += [
        Match("transfer-upload", "T1105", "high", f"uploaded {item.get('filename') or '?'}"[:300])
        for item in uploads
    ]
    return matches


def map_tunnels(tunnels: list[dict]) -> list[Match]:
    """Port-forwarding requests mean the attacker wants to use the host as a relay."""
    if not tunnels:
        return []
    targets = {f"{t.get('dst_ip')}:{t.get('dst_port')}" for t in tunnels}
    sample = ", ".join(sorted(targets)[:3])
    evidence = (
        f"{len(tunnels)} forwarding request(s) to {len(targets)} destination(s), e.g. {sample}"
    )
    return [Match("tunnel-request", "T1090", "high", evidence[:300])]


def map_logins(logins: list[dict]) -> list[Match]:
    """Map a session's login attempts. Each item needs ``username`` and ``success``."""
    matches: list[Match] = []
    failed = [entry for entry in logins if not entry.get("success")]
    if len(failed) >= FAILED_LOGIN_THRESHOLD:
        confidence = "high" if len(failed) >= FAILED_LOGIN_HIGH else "medium"
        matches.append(
            Match("login-guessing", "T1110.001", confidence, f"{len(failed)} failed attempts")
        )
    succeeded = [entry for entry in logins if entry.get("success")]
    if succeeded:
        user = succeeded[0].get("username") or ""
        technique = "T1078.001" if user.lower() in DEFAULT_USERNAMES else "T1078"
        rule_id = "login-default-account" if technique == "T1078.001" else "login-valid-account"
        matches.append(Match(rule_id, technique, "medium", f"login accepted for {user!r}"))
    return matches
