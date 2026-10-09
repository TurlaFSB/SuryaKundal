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


def test_only_the_dashboard_publishes_a_port_and_only_on_localhost():
    published = {n: s["ports"] for n, s in SERVICES.items() if "ports" in s}
    assert set(published) == {"dashboard"}
    assert all(p.startswith("127.0.0.1:") for p in published["dashboard"])


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
