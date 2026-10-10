# Egress control for the honeypot

Cowrie's `wget`, `curl`, `nc` and `tftp` make **real connections** to hosts the attacker names. From
inside its container the honeypot can also reach the Docker host, your LAN and, on a cloud VM, the
metadata service at `169.254.169.254` (which can hand out credentials). Without a firewall your
address would be used to attack other people, and a container escape would start from inside your
network. `cowrie/egress.sh` closes both gaps. It limits only the honeypot's own Docker bridge.

## Use it

On the Docker host, as root, **before** you expose the honeypot (`COWRIE_BIND=0.0.0.0`):

```
sudo ./cowrie/egress.sh apply deny          # install the rules (works before the first compose up)
docker compose --profile honeypot up -d
sudo ./cowrie/egress.sh verify              # probe from inside the container; must say "all checks passed"
sudo ./cowrie/egress.sh install deny        # re-apply after every reboot (systemd)
```

| Command | Does |
|---|---|
| `apply [deny\|captures]` | Installs the rules. Safe to repeat; switching modes replaces the old rules. |
| `status` | Shows the active mode and packet counters. Exits 3 if nothing is applied. |
| `verify` | Tries real connections from inside the running container and checks that the drop counters moved. Exits 1 on any failure. |
| `remove` | Takes the rules out and restores the firewall to how it was. |
| `install` / `uninstall` | Adds or removes a systemd unit that re-applies the rules at boot. |
| `--dry-run` (before the command) | Prints what would run, changes nothing, needs no root. |

## Two modes

**`deny` (the default).** Nothing the honeypot starts can leave. Cowrie still records the URL an
attacker tried to fetch, which is the indicator you want, but it cannot save the file itself. A failed
fetch looks like a server with no internet access, which is common behind a firewall.

**`captures`.** Only web traffic leaves: TCP 80 and 443 and DNS to public addresses, at a limited rate
(`SURYA_EGRESS_RATE`, default 30/minute, burst 15) with a cap on concurrent connections
(`SURYA_EGRESS_MAX_CONNS`, default 20). Real malware samples come in, and file hashes feed campaign
clustering. The cost is that this machine makes real HTTP requests on an attacker's behalf. Use it only
on a disposable VM with its own address that you are prepared to see on blocklists.

Both modes also refuse, always: private, link-local, carrier-grade NAT, multicast and other reserved
ranges (so the LAN and the metadata service are unreachable), and every connection the honeypot tries
to open to the host itself. Replies on connections an attacker opened into the honeypot always pass;
that is how SSH works.

Cloud images often use a private or link-local DNS resolver. In `captures` mode, name it so lookups
keep working: `SURYA_EGRESS_DNS=169.254.169.254 sudo -E ./cowrie/egress.sh apply captures`.

## What was verified

Run against a real Linux kernel firewall in isolated network namespaces (`tests/test_egress.py`): a
honeypot, a bridge-and-router host, and an "internet" with servers on ports 443, 80 and 25, on a
private address, and on the host itself.

| From the honeypot to | no firewall | `deny` | `captures` |
|---|---|---|---|
| internet, web ports 80 and 443 | reaches | blocked | reaches |
| internet, mail port 25 | reaches | blocked | blocked |
| a private network address | reaches | blocked | blocked |
| the host (bridge gateway) | reaches | blocked | blocked |
| attacker connecting **in**, replies out | works | works | works |

After `remove`, every row returns to "reaches": the rules leave nothing behind.

## Limits to know about

- **It needs Docker's `DOCKER-USER` chain.** That exists with the standard Docker engine on iptables or
  nftables. It does not apply to rootless Docker or Podman, or when Docker runs with `iptables: false`.
- **Boot has a short window.** After a reboot, Docker restarts the honeypot before the systemd unit has
  re-applied the rules, for a few seconds. Keep `COWRIE_BIND` on loopback until `verify` passes after
  boot, or accept that window.
- **After a Docker upgrade or restart, run `status`.** If it reports "not applied", run `apply` again.
- **IPv6 is off on Docker's default networks.** If you enabled it, the script adds a deny-all for the
  honeypot's bridge automatically; `captures` is IPv4 only.
- **Defence in depth.** Also deny outbound traffic from the honeypot VM in your cloud provider's own
  network rules (for example the VCN security list or security group), so one layer failing is not
  enough. Allow only what the VM itself needs: package updates and, if used, your log shipper.
- **Dropped packets are logged** at a limited rate with the prefix `surya-egress-drop:`. Read them with
  `journalctl -k | grep surya-egress-drop`. Repeated drops from the honeypot mean attackers are trying.

## Settings

All optional, set as environment variables when you run the script.

| Variable | Default | Meaning |
|---|---|---|
| `SURYA_HONEY_BRIDGE` | `br-suryahoney` | The honeypot's bridge; must match `compose.yaml`. |
| `SURYA_HONEY_CONTAINER` | `surya-cowrie` | The container `verify` probes. |
| `SURYA_EGRESS_RATE` | `30/minute` | `captures`: new connections allowed. |
| `SURYA_EGRESS_BURST` | `15` | `captures`: burst above that rate. |
| `SURYA_EGRESS_MAX_CONNS` | `20` | `captures`: concurrent connections. |
| `SURYA_EGRESS_DNS` | empty | `captures`: extra resolver addresses to allow. |

The bridge subnet defaults to `172.29.77.0/24`; if that clashes with a network you already use, set
`HONEY_SUBNET` in `.env`.
