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
- Network: create a security group with **one** inbound rule, SSH (TCP 22) from **My IP**. You open
  the others later, in this order, so you never lock yourself out.
- Advanced details: *Metadata version* = **V2 only**, *Metadata response hop limit* = **1**.
  (A container then cannot read the instance's credentials even if egress control failed.)
- Do not attach an IAM role. The machine needs no AWS permissions.

## 2. Install the tools

```
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker ubuntu     # log out and back in afterwards
```

Check: `docker compose version` prints a version.

## 3. Move your own SSH off port 22

Ubuntu 24.04 starts SSH through a socket, so editing `Port` alone does nothing. Do it in two stages,
keeping port 22 working until the new one is proven.

1. In the AWS console, add an inbound rule: TCP **22222** from **My IP**.
2. On the machine:
   ```
   printf 'Port 22\nPort 22222\n' | sudo tee /etc/ssh/sshd_config.d/10-ports.conf
   sudo systemctl disable --now ssh.socket
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
5. In the console, change the inbound rule for TCP 22 to **0.0.0.0/0** (the honeypot's port) and
   delete nothing else.

## 4. Get the project and configure it

```
git clone https://github.com/TurlaFSB/SuryaKundal.git surya-kundal && cd surya-kundal
cp .env.example .env && chmod 600 .env
```

Edit `.env` (`nano .env`) and set:

- `DASHBOARD_TOKEN` : 24 or more random characters (`python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`)
- `COWRIE_BIND=0.0.0.0` and `COWRIE_PORT=22`
- `INTERNAL_NETWORKS` : your own public address, so your tests are not counted as attackers
- `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, and optionally `ABUSEIPDB_API_KEY`
- leave `DASHBOARD_SHOW_INTERNAL` empty

## 5. Lock down the honeypot's network, then start it

Order matters: the firewall goes in **before** the honeypot is reachable.

```
sudo ./cowrie/egress.sh apply deny
docker compose --profile honeypot up -d --build
sudo ./cowrie/egress.sh verify         # must end with "all checks passed"
sudo ./cowrie/egress.sh install deny   # re-applies at every boot
```

## 6. Open the security group's outbound rules

Replace the default "all traffic" outbound rule with TCP 80 and 443 only: Ubuntu's package mirrors use
port 80, and enrichment, GeoIP updates and image pulls use 443. DNS from the host goes to the VPC
resolver, which security groups do not filter, so it needs no rule. This is a second layer: even if
the honeypot's own firewall failed, only web traffic could leave.

## 7. Check it from outside

From your own computer (not the instance):

```
ssh -p 22 root@<address>                       # the honeypot's banner; weak passwords are accepted
python evaluation/deception_check.py <address> --port 22 --user deploy --password '...'
```

Then, on the instance, run `docker compose exec pipeline surya-kundal geoip update` and open the
dashboard through a tunnel:

```
ssh -p 22222 -i key.pem -L 8080:127.0.0.1:8080 ubuntu@<address>
```

and browse to `http://127.0.0.1:8080` (the password is `DASHBOARD_TOKEN`). Your own test sessions
are marked internal and hidden. Real scanners usually arrive within minutes.

## 8. Keep it healthy

- Backups: `docker compose exec pipeline surya-kundal backup --keep 7`, from cron. Copy them off the
  machine now and then (`docs/OPERATIONS.md`).
- Updates: `sudo apt-get -y upgrade` weekly; `git pull && docker compose --profile honeypot up -d --build` to update the project.
- Stop everything cleanly: `docker compose --profile honeypot down`, then `sudo ./cowrie/egress.sh remove`.

## Before you walk away

- [ ] `egress.sh verify` passed, and `egress.sh install deny` is in place
- [ ] Port 22222 is open to your address only; nothing else is open except 22
- [ ] `DASHBOARD_SHOW_INTERNAL` is empty
- [ ] The metadata options show V2 only and hop limit 1
- [ ] `docs/THREAT_MODEL.md` read; you accept that this machine will be attacked and may be blocklisted
