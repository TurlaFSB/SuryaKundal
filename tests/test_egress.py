"""cowrie/egress.sh: the rules it builds, its input checks, and what they do to real packets."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "cowrie" / "egress.sh"
LAB = Path(__file__).with_name("netns_egress_lab.py")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")

FWD = "SURYA-HONEY-FWD"
RESERVED = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)  # fmt: skip


def egress(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], **(env or {})},
        timeout=30,
    )


def v4_rules(mode: str, env: dict[str, str] | None = None) -> list[str]:
    result = egress("--dry-run", "apply", mode, env=env)
    assert result.returncode == 0, result.stderr
    return [ln for ln in result.stdout.splitlines() if ln.startswith("iptables ")]


def forward_chain(rules: list[str]) -> list[str]:
    return [ln for ln in rules if ln.startswith(f"iptables -A {FWD} ")]


def test_default_resolvers_match_the_captures_resolver_file():
    """The firewall allows exactly the resolvers the honeypot is configured to ask."""
    conf = (ROOT / "cowrie" / "resolv.captures.conf").read_text()
    configured = set(re.findall(r"^nameserver (\S+)$", conf, re.MULTILINE))
    default = re.search(r'DNS_ALLOW="\$\{SURYA_EGRESS_DNS:-([^}]+)\}"', SCRIPT.read_text())
    assert default and set(default.group(1).split(",")) == configured


def test_script_is_valid_bash_and_executable():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0
    assert os.access(SCRIPT, os.X_OK)


def test_deny_lets_nothing_new_leave():
    rules = v4_rules("deny")
    chain = forward_chain(rules)
    assert "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN" in chain[0]
    assert chain[-1] == f"iptables -A {FWD} -j SURYA-HONEY-DROP"
    # The only RETURN is the one for replies on connections an attacker opened inward.
    assert [ln for ln in chain if "-j RETURN" in ln] == [chain[0]]
    assert not any("ACCEPT" in ln for ln in rules)


def test_every_denied_packet_is_logged_then_dropped():
    rules = v4_rules("deny")
    log = next(i for i, ln in enumerate(rules) if "-j LOG" in ln)
    drop = next(i for i, ln in enumerate(rules) if ln == "iptables -A SURYA-HONEY-DROP -j DROP")
    assert log < drop
    assert "--limit 10/minute" in rules[log]
    assert "surya-egress-drop:" in rules[log]


def test_rules_are_hooked_in_first_and_only_for_the_honeypot_bridge():
    rules = v4_rules("deny")
    forward_hook = [
        ln for ln in rules if " DOCKER-USER " in ln and " -I " in ln and "applying" not in ln
    ]
    input_hook = [ln for ln in rules if " INPUT " in ln and " -I " in ln and "applying" not in ln]
    assert len(forward_hook) == 1 and len(input_hook) == 1
    assert "-I DOCKER-USER 1 -i br-suryahoney" in forward_hook[0]
    assert "-I INPUT 1 -i br-suryahoney" in input_hook[0]
    assert "surya-honey:deny" in forward_hook[0]


def test_connections_towards_the_host_itself_are_refused():
    rules = v4_rules("deny")
    inbound = [ln for ln in rules if ln.startswith("iptables -A SURYA-HONEY-IN ")]
    assert "ESTABLISHED,RELATED -j RETURN" in inbound[0]
    assert inbound[-1] == "iptables -A SURYA-HONEY-IN -j SURYA-HONEY-DROP"


def test_captures_refuses_reserved_ranges_before_allowing_anything():
    chain = forward_chain(v4_rules("captures"))
    text = "\n".join(chain)
    first_allow = next(i for i, ln in enumerate(chain) if "--dports 80,443" in ln)
    for net in RESERVED:
        index = next(i for i, ln in enumerate(chain) if f"-d {net} " in ln)
        assert index < first_allow, net
        assert chain[index].endswith("-j SURYA-HONEY-DROP")
    assert chain[-1] == f"iptables -A {FWD} -j SURYA-HONEY-DROP"
    assert "--dport 25" not in text and "--dports 22" not in text


def test_captures_allows_only_web_and_the_two_named_resolvers():
    chain = forward_chain(v4_rules("captures"))
    returns = [ln for ln in chain if ln.endswith("-j RETURN")]
    assert len(returns) == 6  # replies, web, and UDP + TCP DNS for each of two resolvers
    web = next(ln for ln in returns if "--dports 80,443" in ln)
    assert "-p tcp" in web and "--ctstate NEW" in web and "--limit 30/minute" in web
    dns = [ln for ln in returns if "--dport 53" in ln]
    assert len(dns) == 4 and all("--limit" in ln and " -d " in ln for ln in dns)
    assert {re.search(r"-d (\S+)", ln).group(1) for ln in dns} == {"1.1.1.1", "9.9.9.9"}
    # No rule allows DNS to an arbitrary address.
    assert not any("--dport 53" in ln and " -d " not in ln for ln in chain)
    cap = next(ln for ln in chain if "connlimit" in ln)
    assert "--connlimit-above 20" in cap and cap.endswith("-j SURYA-HONEY-DROP")
    assert chain.index(cap) < chain.index(web)  # the cap is checked before the allow


def test_rate_and_cap_are_configurable():
    env = {
        "SURYA_EGRESS_RATE": "5/second",
        "SURYA_EGRESS_BURST": "3",
        "SURYA_EGRESS_MAX_CONNS": "7",
    }
    text = "\n".join(forward_chain(v4_rules("captures", env)))
    assert "--limit 5/second --limit-burst 3" in text
    assert "--connlimit-above 7" in text


def test_named_resolver_is_allowed_ahead_of_the_reserved_ranges():
    chain = forward_chain(v4_rules("captures", {"SURYA_EGRESS_DNS": "169.254.169.254,10.0.0.2"}))
    allow = next(i for i, ln in enumerate(chain) if "-d 169.254.169.254 " in ln)
    refuse = next(i for i, ln in enumerate(chain) if "-d 169.254.0.0/16 " in ln)
    assert allow < refuse
    assert "-p udp --dport 53" in chain[allow] and chain[allow].endswith("-j RETURN")
    assert any("-d 10.0.0.2 " in ln for ln in chain)


def test_ipv6_is_denied_outright_even_in_captures_mode():
    out = egress("--dry-run", "apply", "captures").stdout
    v6 = [ln for ln in out.splitlines() if ln.startswith("ip6tables -A SURYA-HONEY-FWD")]
    assert v6 and "--dports" not in "\n".join(v6)
    assert v6[-1] == "ip6tables -A SURYA-HONEY-FWD -j SURYA-HONEY-DROP"


def test_dry_run_changes_nothing_and_needs_no_root():
    result = egress("--dry-run", "apply", "deny")
    assert result.returncode == 0
    assert "applied mode=deny" in result.stdout


def test_remove_deletes_the_chains_it_made():
    out = egress("--dry-run", "remove").stdout
    for chain in (FWD, "SURYA-HONEY-IN", "SURYA-HONEY-DROP"):
        assert f"-F {chain}" in out and f"-X {chain}" in out


@pytest.mark.parametrize(
    ("args", "env", "message"),
    [
        (["apply", "allow-all"], {}, "mode must be deny or captures"),
        (["apply", "deny"], {"SURYA_HONEY_BRIDGE": "a-bridge-name-too-long"}, "interface name"),
        (["apply", "deny"], {"SURYA_HONEY_BRIDGE": "br;rm -rf"}, "interface name"),
        (["apply", "captures"], {"SURYA_EGRESS_RATE": "fast"}, "SURYA_EGRESS_RATE"),
        (["apply", "captures"], {"SURYA_EGRESS_BURST": "many"}, "whole numbers"),
        (["apply", "captures"], {"SURYA_EGRESS_DNS": "dns.example"}, "SURYA_EGRESS_DNS"),
        (["apply", "captures"], {"SURYA_EGRESS_DNS": "1.1.1.1; reboot"}, "SURYA_EGRESS_DNS"),
    ],
)
def test_bad_input_is_refused_before_any_rule_is_built(args, env, message):
    result = egress("--dry-run", *args, env=env)
    assert result.returncode == 1
    assert message in result.stderr
    assert "iptables" not in result.stdout


def test_without_an_action_it_prints_usage_and_fails():
    result = egress()
    assert result.returncode == 2
    assert "apply [deny|captures]" in result.stderr
    assert egress("--help").returncode == 0


def test_apply_needs_root():
    if os.geteuid() == 0:
        pytest.skip("running as root")
    result = egress("apply", "deny")
    assert result.returncode == 1 and "run as root" in result.stderr


def test_boot_unit_runs_after_docker_and_removes_the_rules_on_stop():
    out = egress("--dry-run", "install", "captures", env={"SURYA_EGRESS_DNS": "10.0.0.2"}).stdout
    assert "After=docker.service" in out
    assert f"ExecStart={SCRIPT} apply captures" in out
    assert f"ExecStop={SCRIPT} remove" in out
    assert "Environment=SURYA_EGRESS_DNS=10.0.0.2" in out
    assert "RemainAfterExit=yes" in out


def test_compose_puts_only_the_honeypot_on_its_own_bridge():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert compose["services"]["cowrie"]["networks"] == ["honeynet"]
    cowrie = compose["services"]["cowrie"]
    # The honeypot's resolver is chosen by EGRESS_MODE and Docker's own resolver is not used.
    resolv = next(
        v for v in cowrie["volumes"] if isinstance(v, dict) and v["target"] == "/etc/resolv.conf"
    )
    assert resolv["source"] == "./cowrie/resolv.${EGRESS_MODE:-deny}.conf"
    assert resolv["read_only"] is True and resolv["bind"]["create_host_path"] is False
    assert cowrie["sysctls"] == {"net.ipv4.ip_unprivileged_port_start": "53"}
    for mode in ("deny", "captures"):
        assert (ROOT / "cowrie" / f"resolv.{mode}.conf").is_file()
    assert "networks" not in compose["services"]["pipeline"]
    assert "networks" not in compose["services"]["dashboard"]
    bridge = compose["networks"]["honeynet"]["driver_opts"]["com.docker.network.bridge.name"]
    default = re.search(r'BRIDGE="\$\{SURYA_HONEY_BRIDGE:-([^}]+)\}"', SCRIPT.read_text())
    assert default and default.group(1) == bridge  # the script and compose agree
    assert len(bridge) <= 15


# --- packets -----------------------------------------------------------------------------------


def _cannot_run_lab() -> str | None:
    if os.geteuid() != 0:
        return "needs root"
    for tool in ("unshare", "iptables"):
        if shutil.which(tool) is None:
            return f"needs {tool}"
    try:
        import pyroute2  # noqa: F401
    except ImportError:
        return "needs pyroute2"
    probe = subprocess.run(["unshare", "-n", "true"], capture_output=True)
    return None if probe.returncode == 0 else "cannot create network namespaces"


def test_real_packets_follow_the_rules():
    """Honeypot, router and internet in network namespaces; see tests/netns_egress_lab.py."""
    reason = _cannot_run_lab()
    if reason:
        pytest.skip(reason)
    result = subprocess.run(
        ["unshare", "-n", sys.executable, str(LAB), str(SCRIPT)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    seen = json.loads(result.stdout.strip().splitlines()[-1])

    everything = {
        "web_443": True, "web_80": True, "mail_25": True, "private_10": True,
        "host_gateway": True, "attacker_into_honeypot": True,
    }  # fmt: skip
    assert seen["baseline"] == everything  # the lab network itself works
    assert seen["deny"] == {**dict.fromkeys(everything, False), "attacker_into_honeypot": True}
    assert seen["captures"] == {
        "web_443": True,
        "web_80": True,
        "mail_25": False,
        "private_10": False,
        "host_gateway": False,
        "attacker_into_honeypot": True,
    }
    assert seen["removed"] == everything  # nothing is left behind


def test_nothing_slips_through_while_the_chains_are_rebuilt():
    rules = v4_rules("deny")
    hold = next(i for i, ln in enumerate(rules) if "surya-honey:applying" in ln and " -I " in ln)
    first_chain_change = next(i for i, ln in enumerate(rules) if " -N " in ln or " -F " in ln)
    final_hook = next(i for i, ln in enumerate(rules) if "surya-honey:deny" in ln)
    release = (
        next(i for i, ln in enumerate(rules) if " -D " in ln and "applying" in ln)
        if any(" -D " in ln and "applying" in ln for ln in rules)
        else None
    )
    assert hold < first_chain_change < final_hook
    # in a dry run no rule exists yet, so the release is only a query; the real run is covered by
    # the packet lab below
    assert release is None or release > final_hook


def test_boot_unit_waits_for_dockers_chain():
    out = egress("--dry-run", "install", "deny").stdout
    assert "ExecStartPre=" in out and "DOCKER-USER" in out and "$$(seq" in out
    assert "TimeoutStartSec=120" in out
