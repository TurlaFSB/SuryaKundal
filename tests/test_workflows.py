"""Policy tests for the CI workflows: third-party code must be pinned to an exact commit."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")


def _uses(path):
    for line in path.read_text().splitlines():
        match = USES.match(line)
        if match:
            yield match.group(1), match.group(2)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_commit_hash(path):
    for action, rest in _uses(path):
        _, _, ref = action.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (
            f"{path.name}: {action} is not pinned to a commit"
        )
        assert re.search(r"#\s*v\d", rest), f"{path.name}: {action} needs a version comment"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_use_least_privilege_tokens(path):
    text = path.read_text()
    assert re.search(r"^permissions:", text, re.M), f"{path.name}: set top-level permissions"
    assert "write-all" not in text


def test_supply_chain_workflow_scans_both_images_and_runs_weekly():
    text = (ROOT / ".github" / "workflows" / "supply-chain.yml").read_text()
    assert "surya-kundal-cowrie" in text and "schedule:" in text
    assert "cyclonedx" in text and "ignore-unfixed" in text
