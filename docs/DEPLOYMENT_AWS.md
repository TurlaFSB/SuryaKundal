# Deploying on AWS

A single small virtual machine, the honeypot on port 22, everything else locked down. Steps are
in order; each one has a check. Cost: a t3.small is covered by the AWS Free plan credits.

## What the machine looks like when you finish

| Port | Open to | What answers |
|---|---|---|
| 22 | the whole internet | the honeypot (Cowrie, in a container) |
| 22222 | **your address only** | your real SSH, to administer the machine |
| 8080 | nobody (loopback) | the dashboard, reached through an SSH tunnel |

Nothing the honeypot starts can leave the machine (`deny` mode), and the cloud metadata address is
unreachable from it.

## 1. Launch the instance

- Ubuntu Server 24.04 LTS, `t3.small`, 20 GiB gp3 disk. A new key pair (ED25519); keep the `.pem`.
- Network: create a security group with **one** inbound rule, SSH (TCP 22) from your address. You open
  the others later, in this order, so you never lock yourself out. Type the address by hand if you
  administer from a virtual machine or a phone hotspot: the console's *My IP* button reports the
  address of your **browser**, which is not always the address your SSH client leaves from. Check
  the real one with `curl -4 ifconfig.me` in the terminal you will use.
- Advanced details: *Metadata version* = **V2 only**, *Metadata response hop limit* = **1**.
  (A container then cannot read the instance's credentials even if egress control failed.)
- Do not attach an IAM role. The machine needs no AWS permissions.

## 2. Install the tools

```
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker ubuntu     # log out and back in afterwards (or run: newgrp docker)
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab   # 2 GB of RAM is tight for three containers
```

Check: `docker compose version` prints a version.

A fresh Ubuntu instance runs `unattended-upgrades` for the first minutes and holds the apt lock;
it can also restart `sshd`, which shows up as a brief "connection refused" or "reset". If `apt`
says it cannot get the lock, or your session drops right after the first boot, wait two minutes
and retry. Do not kill the process.

## 3. Move your own SSH off port 22

Ubuntu 24.04 starts SSH through a socket, so editing `Port` alone does nothing. Do it in two stages,
keeping port 22 working until the new one is proven.

1. In the AWS console, add an inbound rule: TCP **22222** from your address as a `/32` (see the note
   in step 1 about *My IP*).
2. On the machine:
   ```
   printf 'Port 22\nPort 22222\n' | sudo tee /etc/ssh/sshd_config.d/10-ports.conf
   sudo systemctl disable --now ssh.socket
   sudo systemctl mask ssh.socket          # an update must not switch it back on and grab port 22
   sudo systemctl enable --now ssh.service
   sudo sshd -t && sudo systemctl restart ssh.service
   ```
3. From **another terminal** on your own computer: `ssh -p 22222 -i key.pem ubuntu@<address>`.
   It must work before you continue. Keep the first session open.
4. Only then take port 22 out:
   ```
   printf 'Port 22222\n' | sudo tee /etc/ssh/sshd_config.d/10-ports.conf
   sudo systemctl restart ssh.service
   ```
   and confirm `sudo ss -ltnp | grep sshd` shows only 22222.
5. Leave the TCP 22 rule limited to your address for now. It becomes world-open in step 6, after the
   honeypot is running and the firewall is verified.

## 4. Get the project and configure it

```
git clone https://github.com/TurlaFSB/SuryaKundal.git surya-kundal && cd surya-kundal
cp .env.example .env && chmod 600 .env
```

Edit `.env` (`nano .env`) and set:

- `DASHBOARD_TOKEN` : 24 or more random characters (`python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`)
- `COWRIE_BIND=0.0.0.0` and `COWRIE_PORT=22`
- `INTERNAL_NETWORKS` : the public address(es) you test from, so your sessions are not counted as
  attackers. An address added later only applies after `docker compose up -d pipeline` recreates the
  container
- `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, and optionally `ABUSEIPDB_API_KEY`
- leave `DASHBOARD_SHOW_INTERNAL` empty

## 5. Lock down the honeypot's network, then start it

Order matters: the firewall goes in **before** the honeypot is reachable.

```
sudo ./cowrie/egress.sh apply deny
docker compose --profile honeypot up -d --build
sudo ./cowrie/egress.sh verify         # must end with "all checks passed"
sudo ./cowrie/egress.sh install deny   # re-applies at every boot
systemctl is-enabled surya-honey-egress.service   # prints "enabled"
```

## 6. Tighten the security group, then open port 22

First the outbound rules. Replace the default "all traffic" outbound rule with TCP 80 and 443 only (deny mode, the default; `captures` mode also needs UDP and TCP 53 to 1.1.1.1 and 9.9.9.9): Ubuntu's package mirrors use
port 80, and enrichment, GeoIP updates and image pulls use 443. DNS from the host goes to the VPC
resolver, which security groups do not filter, so it needs no rule. This is a second layer: even if
the honeypot's own firewall failed, only web traffic could leave.

Then, and only now, change the inbound TCP 22 rule to **0.0.0.0/0**. From that moment real scanners
can reach the honeypot, so the egress check above must already have passed. Leave 22222 limited to
your address.

## 7. Check it from outside

From your own computer (not the instance):

```
ssh -p 22 root@<address>                       # the honeypot's banner; weak passwords are accepted
python evaluation/deception_check.py <address> --port 22 --user root --password toor
```

`toor` is one of the passwords the `collect` policy accepts; a made-up one is refused. The test sessions are
recorded like any other, so add your address to `INTERNAL_NETWORKS` first (step 4) to keep them out
of the statistics.

Then, on the instance, run `docker compose exec pipeline surya-kundal geoip update` and open the
dashboard through a tunnel:

```
ssh -p 22222 -i key.pem -L 8080:127.0.0.1:8080 ubuntu@<address>
```

and browse to `http://127.0.0.1:8080` (the password is `DASHBOARD_TOKEN`). Your own test sessions
are marked internal and hidden. Real scanners usually arrive within minutes.

## 8. Keep it healthy

- Backups, from cron (`crontab -e`), compressed and rotated; copy them off the machine now and then:
  `17 3 * * * cd ~/surya-kundal && docker compose exec -T pipeline surya-kundal backup --compress --keep 7`
- **Disk.** Cowrie never deletes its own logs, recordings or captured files, and the database and
  backups grow too. Without cleanup a 20 GiB disk fills in a few months, and a full disk stops
  recording. Add a daily cleanup of old Cowrie files (keeps 14 days of rotated logs and recordings):
  put the commands in a small script rather than in the crontab line, where quoting goes wrong
  easily (an escaped quote written as `\047` is taken literally):
  ```
  cat > ~/surya-cleanup.sh <<'EOF'
  #!/bin/sh
  cd ~/surya-kundal || exit 1
  docker compose exec -T cowrie sh -c "find /cowrie/var/log/cowrie -name 'cowrie.json.*' -mtime +14 -delete; find /cowrie/var/lib/cowrie/tty -type f -mtime +14 -delete"
  EOF
  chmod 700 ~/surya-cleanup.sh
  ```
  and the crontab line `27 3 * * * ~/surya-cleanup.sh >> ~/surya-cron.log 2>&1`. After each update run `docker image prune -f`. Set a CloudWatch alarm on disk use if you can, or check
  `df -h /` when you log in.
- Updates: `sudo apt-get -y upgrade` weekly; `git pull && docker compose --profile honeypot up -d --build` to update the project.
- Stop everything cleanly: `docker compose --profile honeypot down`, then `sudo ./cowrie/egress.sh remove`.

## Troubleshooting access

Your address changes more often than you expect (a phone hotspot gets a new one when you toggle
airplane mode; a laptop and a virtual machine on it may leave from different addresses). When SSH
to port 22222 times out:

1. Run `curl -4 ifconfig.me` **in the terminal you connect from** and compare it with the `/32` in the
   security group's 22222 rule. Edit the rule if they differ.
2. If they match, test whether your network lets the port out at all:
   `nc -vz -w 6 portquiz.net 22222`. If that fails too, your carrier or ISP filters outgoing ports other
   than 80 and 443. Move to a network that does not, or add a second `Port 443` line to
   `/etc/ssh/sshd_config.d/10-ports.conf` and a matching inbound rule, then connect on 443.
3. "Connection refused" or "reset" in the first minutes after boot is the upgrade described in
   step 2; wait and retry.

The instance keeps running and collecting whether or not you can reach it. Losing access does not
stop the honeypot.

## Before you walk away

- [ ] `egress.sh verify` passed, and `egress.sh install deny` is in place
- [ ] Port 22222 is open to your address only; nothing else is open except 22
- [ ] `DASHBOARD_SHOW_INTERNAL` is empty
- [ ] The metadata options show V2 only and hop limit 1
- [ ] `docs/THREAT_MODEL.md` read; you accept that this machine will be attacked and may be blocklisted
