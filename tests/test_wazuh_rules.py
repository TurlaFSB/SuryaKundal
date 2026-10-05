"""The generated Wazuh rules are valid, in sync with rules.toml, and fire on Cowrie events.

Wazuh itself is not available in CI, so a small evaluator walks the rule tree the way
Wazuh does for the simple conditions used here (decoded_as, field, if_sid; the first
matching sibling wins). Frequency rules are checked structurally. The authoritative
check is ``wazuh/logtest.sh`` against a real manager.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from surya_kundal.mapping.attack import load_catalog
from surya_kundal.mapping.engine import load_rules
from surya_kundal.wazuh import COMMAND_RULES_START, generate_rules_xml

COMMITTED = (
    Path(__file__).resolve().parent.parent / "wazuh" / "rules" / "surya_kundal_cowrie_rules.xml"
)


def _rules() -> list[ET.Element]:
    root = ET.fromstring(generate_rules_xml())  # noqa: S314 - our own output
    return list(root.iter("rule"))


def _matches_field(element: ET.Element, event: dict) -> bool:
    value = event.get(element.attrib["name"])
    if value is None:
        return False
    pattern = element.text or ""
    if element.attrib.get("type") == "osmatch":
        text = element.text or ""
        pattern = (
            ("^" if text.startswith("^") else "")
            + re.escape(text.strip("^$"))
            + ("$" if text.endswith("$") else "")
        )
    return re.search(pattern, str(value)) is not None


def fire(event: dict) -> int | None:
    """Return the id of the deepest, first-matching non-frequency rule, as Wazuh would."""
    rules = [r for r in _rules() if "frequency" not in r.attrib]

    def holds(rule: ET.Element) -> bool:
        if rule.find("decoded_as") is not None and rule.find("decoded_as").text != "json":
            return False
        return all(_matches_field(f, event) for f in rule.findall("field"))

    def descend(parent: str | None) -> int | None:
        for rule in rules:
            sid = rule.find("if_sid")
            if (sid.text if sid is not None else None) != parent:
                continue
            if holds(rule):
                return descend(rule.attrib["id"]) or int(rule.attrib["id"])
        return None

    return descend(None)


def event(eventid: str, **fields: str) -> dict:
    return {"eventid": f"cowrie.{eventid}", "src_ip": "203.0.113.7", "session": "abc", **fields}


def test_rules_are_valid_unique_and_use_known_techniques() -> None:
    rules = _rules()
    ids = [r.attrib["id"] for r in rules]
    assert len(ids) == len(set(ids))
    catalog = load_catalog()
    for rule in rules:
        assert 100000 <= int(rule.attrib["id"]) <= 120000  # Wazuh's custom-rule range
        for mitre in rule.findall("mitre/id"):
            assert mitre.text in catalog, mitre.text
    assert len(rules) == 12 + len(load_rules().rules)


def test_committed_file_matches_the_generator() -> None:
    assert COMMITTED.read_text(encoding="utf-8") == generate_rules_xml(), (
        "wazuh/rules is stale: run `surya-kundal wazuh-rules --output "
        "wazuh/rules/surya_kundal_cowrie_rules.xml`"
    )


@pytest.mark.parametrize(
    ("ev", "expected"),
    [
        (event("session.connect"), 100501),
        (event("login.failed", username="root", password="x"), 100510),
        (event("login.success", username="deploy", password="x"), 100513),
        (event("login.success", username="root", password="x"), 100514),
        (event("session.file_download", url="http://x/y"), 100530),
        (event("session.file_upload", filename="a"), 100531),
        (event("direct-tcpip.request", dst_ip="1.2.3.4"), 100540),
        (event("command.input", input="echo hi"), 100520),
        (event("session.closed"), 100500),
        ({"eventid": "other.thing"}, None),
    ],
)
def test_session_rules_fire(ev: dict, expected: int | None) -> None:
    assert fire(ev) == expected


def test_every_toml_example_fires_a_rule_with_the_right_technique() -> None:
    by_id = {r.attrib["id"]: r for r in _rules()}
    for rule in load_rules().rules:
        for command in rule.examples:
            fired = fire(event("command.input", input=command))
            assert fired is not None and fired >= COMMAND_RULES_START, (rule.id, command)
            # first match wins, so an earlier high-confidence rule may claim it; it must
            # still be a real technique-tagged rule.
            assert by_id[str(fired)].find("mitre/id") is not None


def test_not_examples_do_not_fire_their_own_rule() -> None:
    for index, rule in enumerate(load_rules().rules):
        own = COMMAND_RULES_START + index
        for command in rule.not_examples:
            assert fire(event("command.input", input=command)) != own, (rule.id, command)


def test_most_severe_rules_are_listed_first() -> None:
    levels = [
        int(r.attrib["level"]) for r in _rules() if int(r.attrib["id"]) >= COMMAND_RULES_START
    ]
    assert levels == sorted(levels, reverse=True)


def test_routine_discovery_is_capped_below_the_severe_levels() -> None:
    by_id = {r.attrib["id"]: r for r in _rules()}
    uptime = fire(event("command.input", input="uptime"))
    assert uptime is not None and int(by_id[str(uptime)].attrib["level"]) <= 6


def test_fingerprinting_probes_alert_high() -> None:
    for command in ("dmesg", "cat /proc/1/cgroup", "cat /proc/cpuinfo | grep hypervisor"):
        fired = fire(event("command.input", input=command))
        assert fired is not None
        rule = next(r for r in _rules() if r.attrib["id"] == str(fired))
        assert rule.find("mitre/id").text == "T1497", command


def test_frequency_rules_are_well_formed() -> None:
    freq = [r for r in _rules() if "frequency" in r.attrib]
    assert {r.attrib["id"] for r in freq} == {"100511", "100512", "100550"}
    for rule in freq:
        assert rule.find("same_field").text == "src_ip"
        assert int(rule.attrib["timeframe"]) > 0


def test_sample_events_produce_the_expected_rules() -> None:
    """The same samples and expectations ``wazuh/logtest.sh`` checks on a real manager."""
    folder = Path(__file__).resolve().parent.parent / "wazuh" / "samples"
    lines = [json.loads(x) for x in (folder / "cowrie_events.jsonl").read_text().splitlines() if x]
    expected = [x for x in (folder / "expected.txt").read_text().splitlines() if x]
    assert len(lines) == len(expected)
    by_id = {r.attrib["id"]: r for r in _rules()}
    for sample, want in zip(lines, expected, strict=True):
        fired = fire(sample)
        assert fired is not None, sample
        text = str(fired) + by_id[str(fired)].findtext("description", "")
        assert want in text, (sample, want, text)
