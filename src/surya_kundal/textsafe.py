"""Make attacker-controlled text safe to print.

Everything an attacker types or sends ends up in our database, and the command-line
tools print it. A command containing terminal escape sequences could clear the
analyst's screen, rewrite what was just shown, or (with right-to-left override
characters) make a line read differently from what it says. ``printable`` replaces
every control and formatting character with a visible escape, so what is shown is
what was sent.
"""

from __future__ import annotations

import unicodedata


def printable(value: object, *, limit: int | None = None) -> str:
    """Return ``value`` as text with control and invisible characters escaped."""
    text = "" if value is None else str(value)
    out: list[str] = []
    for ch in text:
        if unicodedata.category(ch)[0] == "C" or ch in "\u2028\u2029":
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    result = "".join(out)
    if limit is not None and len(result) > limit:
        return result[: limit - 1] + "\u2026"
    return result
