"""wazuh/export-alerts.sh: only replaces the export when the copy succeeded."""

import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "wazuh" / "export-alerts.sh"

OURS = '{"rule":{"level":8,"id":"100601","description":"x"},"data":{"src_ip":"1.2.3.4"}}'
OTHER = '{"rule":{"level":3,"id":"5710","description":"y"}}'


def _run(tmp_path, docker_body: str, existing: str | None = None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_text("#!/usr/bin/env bash\n" + docker_body)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    out = tmp_path / "out" / "alerts.jsonl"
    if existing is not None:
        out.parent.mkdir(exist_ok=True)
        out.write_text(existing)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(  # noqa: S603 - our own script and a fake docker
        ["/usr/bin/env", "bash", str(SCRIPT), str(out)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, out


@pytest.mark.skipif(os.name != "posix", reason="needs bash")
def test_keeps_only_our_rules_and_locks_down_the_file(tmp_path):
    result, out = _run(tmp_path, f"printf '%s\\n' '{OTHER}' '{OURS}'\n")
    assert result.returncode == 0, result.stderr
    assert out.read_text().splitlines() == [OURS]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert list(out.parent.glob("*.??????")) == []  # no temp files left behind


@pytest.mark.skipif(os.name != "posix", reason="needs bash")
def test_docker_failure_keeps_the_previous_export(tmp_path):
    result, out = _run(tmp_path, "echo 'no such container' >&2\nexit 1\n", existing=OURS + "\n")
    assert result.returncode == 1 and "keeping the old export" in result.stderr
    assert out.read_text() == OURS + "\n"


@pytest.mark.skipif(os.name != "posix", reason="needs bash")
def test_no_matching_alerts_is_a_valid_empty_export(tmp_path):
    result, out = _run(tmp_path, f"printf '%s\\n' '{OTHER}'\n", existing=OURS + "\n")
    assert result.returncode == 0 and out.read_text() == ""
