"""Policy tests for the container files: hardening must not quietly regress."""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
DOCKERFILE = (ROOT / "Dockerfile").read_text()
SERVICES = COMPOSE["services"]


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_every_service_is_locked_down(name):
    service = SERVICES[name]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"] and "cap_add" not in service
    assert "no-new-privileges:true" in service["security_opt"]
    assert not service.get("privileged") and "user" not in service  # image already runs as 10001
    assert service.get("pids_limit") and service.get("mem_limit")
    assert service.get("init") is True
    assert "healthcheck" in service
    assert service["logging"]["options"]["max-size"]
    assert "network_mode" not in service and "pid" not in service


def test_only_the_dashboard_and_honeypot_publish_ports_and_both_default_to_loopback():
    published = {n: s["ports"] for n, s in SERVICES.items() if "ports" in s}
    assert set(published) == {"dashboard", "cowrie"}
    assert all(p.startswith("127.0.0.1:") for p in published["dashboard"])
    # The honeypot is exposed deliberately, by setting COWRIE_BIND, never by default.
    assert published["cowrie"] == ["${COWRIE_BIND:-127.0.0.1}:2222:2222"]


def test_honeypot_is_opt_in_and_gets_no_secrets():
    cowrie = SERVICES["cowrie"]
    assert cowrie["profiles"] == ["honeypot"]
    assert "env_file" not in cowrie  # the internet-facing container must not receive .env
    assert "env_file" not in SERVICES["dashboard"]
    assert "env_file" in SERVICES["pipeline"]
    assert not any("TOKEN" in k or "KEY" in k for k in cowrie["environment"])


def test_honeypot_log_reaches_the_pipeline_read_only_through_a_shared_volume():
    cowrie_mounts = SERVICES["cowrie"]["volumes"]
    assert "cowrie_log:/cowrie/var/log/cowrie" in cowrie_mounts
    pipeline_mount = next(v for v in SERVICES["pipeline"]["volumes"] if "/cowrie-log" in v)
    assert pipeline_mount == "${COWRIE_LOG_DIR:-cowrie_log}:/cowrie-log:ro"
    assert {"cowrie_state", "cowrie_log"} <= set(COMPOSE["volumes"])


def test_secrets_are_not_written_into_the_compose_file():
    token = SERVICES["dashboard"]["environment"]["DASHBOARD_TOKEN"]
    assert token.startswith("${DASHBOARD_TOKEN:?")  # required, taken from .env, no default
    text = (ROOT / "compose.yaml").read_text()
    assert "API_KEY" not in text and "LICENSE_KEY" not in text


def test_cowrie_log_is_mounted_read_only():
    volumes = SERVICES["pipeline"]["volumes"]
    log = next(v for v in volumes if "/cowrie-log" in v)
    assert log.endswith(":/cowrie-log:ro")


def test_image_runs_as_a_fixed_unprivileged_user():
    assert "USER 10001:10001" in DOCKERFILE
    assert DOCKERFILE.index("USER 10001:10001") > DOCKERFILE.index("pip install")
    assert "chown 10001:10001 /data" in DOCKERFILE


def test_image_is_built_reproducibly_and_small():
    assert "AS build" in DOCKERFILE and "COPY --from=build" in DOCKERFILE
    assert "--no-cache-dir" in DOCKERFILE or "PIP_NO_CACHE_DIR=1" in DOCKERFILE
    assert ":latest" not in DOCKERFILE and "ADD http" not in DOCKERFILE.lower()
    assert "sudo" not in DOCKERFILE


def test_dockerignore_keeps_secrets_and_data_out_of_the_build():
    ignored = (ROOT / ".dockerignore").read_text().split()
    for entry in (".env", ".git", "*.db", "*.mmdb", "cowrie.json*", "data"):
        assert entry in ignored


COWRIE_DOCKERFILE = (ROOT / "cowrie" / "Dockerfile").read_text()


def test_honeypot_image_pins_cowrie_to_a_commit_and_runs_unprivileged():
    assert "COWRIE_COMMIT=" in COWRIE_DOCKERFILE and "rev-parse HEAD" in COWRIE_DOCKERFILE
    assert "USER 10002:10002" in COWRIE_DOCKERFILE  # a different uid from the pipeline's 10001
    assert ":latest" not in COWRIE_DOCKERFILE and "sudo" not in COWRIE_DOCKERFILE
    assert "ENTRYPOINT" in COWRIE_DOCKERFILE


def test_honeypot_healthcheck_does_not_open_ssh_sessions():
    health = (ROOT / "cowrie" / "healthcheck.py").read_text()
    assert "socket" not in health  # a connection would be logged as an attacker session
    assert "/proc/net/tcp" in health


def test_honeypot_creates_the_directories_cowrie_needs_for_a_shell():
    # Cowrie 3.x does not create these; without tty/ every login ends in "Error getting shell".
    entrypoint = (ROOT / "cowrie" / "docker-entrypoint.sh").read_text()
    for needed in ("var/lib/cowrie/tty", "var/lib/cowrie/downloads", "var/log/cowrie"):
        assert needed in entrypoint
        assert needed in COWRIE_DOCKERFILE


@pytest.mark.parametrize("text", [DOCKERFILE, COWRIE_DOCKERFILE], ids=["main", "cowrie"])
def test_base_image_is_pinned_to_a_digest(text):
    froms = [line for line in text.splitlines() if line.startswith("FROM ")]
    assert froms
    for line in froms:
        assert "@sha256:" in line and ":latest" not in line, line
