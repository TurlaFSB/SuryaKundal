# Surya Kundal: Cowrie hardening kit

Makes your Cowrie 3.1.1 look like one believable Debian 12 box (`stg-util02`)
instead of a stock Cowrie. Everything lives under `cowrie/`; nothing in
Cowrie's own package files is touched.

Assumes: Kali VM, user `worm`, Cowrie in `~/cowrie` with a venv
(`cowrie-env`, `cowrie-venv`, `venv` or `.venv`), logs in
`~/cowrie/var/log/cowrie/cowrie.json`, listening on 2222.

Read `FINGERPRINTING.md` first if you want to know what this does NOT hide.
It is a lot. This raises the bar, it does not make a honeypot invisible.

## 1. Stop Cowrie

```
cd ~/cowrie && bin/cowrie stop
```

## 2. Look before you leap

```
cd ~/suryakundal/cowrie
./deploy.sh --dry-run
```

Prints what would change. Writes nothing.

If your venv has another name: `COWRIE_VENV=/path/to/venv ./deploy.sh --dry-run`.
If Cowrie is not in `~/cowrie`: add `--cowrie-home /path`.

## 3. Deploy

```
./deploy.sh
```

Run as `worm`, not root (it refuses unless you pass `--allow-root`). It:

- generates a persona (seed, fake boot time 40-80 days back) once, stored in
  `~/cowrie/suryakundal/.state`
- creates host keys if missing (rsa 3072, ecdsa, ed25519). If you have an old
  2048-bit RSA key it tells you; `--regen-hostkeys` replaces them (the old ones
  are moved into the backup dir). New keys mean scanners see a new host.
- builds a custom `fs.pickle`, `cmdoutput.json` and txtcmds
- installs `etc/cowrie.cfg` and `etc/userdb.txt`, backing up any existing ones
  to `~/cowrie/suryakundal-backups/<timestamp>/`
- lists changed, unchanged and backed-up files at the end

Run it twice: the second run should say everything is unchanged. It does not
restart Cowrie.

## 4. Before you start it

- Edit `honeyfs-overlay/etc/..` and `etc/userdb.collect.example.txt` (default) or `etc/userdb.example.txt` (stealth, with `--policy stealth`) first if you want
  different users/passwords. The accepted pairs are the only ones that log in;
  there is no wildcard. Passwords are ASCII and cannot contain `:`. If you
  add a user, add it to `honeyfs-overlay/etc/passwd` too or the build fails.
- Memory: `free` reads the real host, so `deploy.sh` makes the persona's `MemTotal` (and the
  fields that scale with it) equal this machine's, automatically. Use `--memtotal-kb persona` to
  keep the kit's 4 GiB figure, or `--memtotal-kb N` to set one. If you resize the VM, redeploy.
- Hand-written `/proc/cpuinfo`, `lscpu`, `dmesg` are not from real hardware
  (see `honeyfs-overlay/README.md`). Copy from a real Debian 12 VM if you can.

## 5. Start and check

```
cd ~/cowrie && bin/cowrie start
```

From ANOTHER machine:

```
ssh -p 2222 -v root@<vm-ip>                  # banner should be OpenSSH_9.2p1 Debian-2+deb12u10, no pre-login text
ssh -p 2222 deploy@<vm-ip>                   # password deploy123 works
ssh -p 2222 root@<vm-ip>                     # a random password must be refused; Passw0rd! works
```

Inside the session: `uname -a`, `cat /etc/os-release`, `hostname`, `uptime`,
`df -h`, `ps aux`. They should all tell the same story.

Watch it:

```
tail -f ~/cowrie/var/log/cowrie/cowrie.json
```

Check that `cowrie.cfg` got merged: `cd ~/cowrie && bin/cowrie status`.

## Decoy files

Many scanners log in, run `uname` and leave. The ones that stay (operators and the more capable
bots) look for things worth taking, so the kit plants some, in `lures-overlay/`:

| Where | What |
|---|---|
| `/root/.aws/credentials`, `/opt/app/.env`, `/root/.docker/config.json` | made-up cloud, database and registry credentials |
| `/root/.ssh/` | `id_ed25519` and its public key, a `config` and a `known_hosts` that point at two made-up internal hosts |
| `/root/.bash_history` | a short admin history that mentions those files and hosts |
| `/home/deploy/backup.sh`, `/etc/cron.d/backup` | a nightly database dump script and its cron entry |
| `/root/.kube/config`, `.git-credentials`, `.npmrc`, `.pypirc`, `.pgpass`, `.my.cnf`, `.mysql_history` | developer and operations tokens: Kubernetes, GitHub, npm, PyPI, PostgreSQL, MariaDB |
| `/root/.config/{gcloud,rclone,solana}/`, `/etc/wireguard/wg0.conf` | cloud service account, backup remote, a Solana keypair, a VPN key |
| `/root/.ethereum/keystore/`, `/root/.bitcoin/{bitcoin.conf,wallet.dat}`, `/home/ops/seed.txt` | cryptocurrency wallets: what miners and wallet thieves search for first |
| `/opt/infra/` (Terraform variables, Ansible inventory and vault password), `/opt/app/docker-compose.yml` | infrastructure-as-code secrets |
| `/srv/backups/appdb-latest.sql`, `/home/ops/passwords.txt`, `/root/notes.txt` | a database dump of fake users (reserved `example.*` addresses, bcrypt-shaped hashes) and the sticky-note files admins really leave behind |

Nothing here is real. The AWS key, database password, application secret and the three host keys are
generated per deployment from the persona seed (separate random streams, so the machine-id,
`/etc/shadow` and every other value stay what they were) and are **never committed**: a fixed key in
a public repository would identify every deployment that uses it. The SSH key pair is made by
`ssh-keygen` at the first deploy and kept next to the host keys, so it does not change on restart; it
opens nothing. Without `ssh-keygen` the key files are simply left out.

Every value is generated, so none of them opens anything. The matching packages (git, awscli,
wireguard-tools, the MariaDB and PostgreSQL clients, rsync, jq, unzip) are in the `dpkg -l` list so the
files do not contradict the machine; their version numbers are copied from Debian 12 point releases
and not re-verified, so treat them as approximate.

**Canary key (optional).** A made-up AWS key alerts nobody. If you create a free "AWS keys" token at
canarytokens.org (it emails you when the key is used anywhere), put its pair in the server's `.env` as
`LURE_AWS_ACCESS_KEY_ID` and `LURE_AWS_SECRET_ACCESS_KEY`; the next start shows that pair in
`~/.aws/credentials` and `/opt/app/.env` instead. The values stay in `.env` on the server and never in Git.
A malformed pair is ignored with a warning.

Reading these files maps to ATT&CK credential-access techniques (T1552.001, .003 and .004, and T1005 for wallets), which
makes it measurable: the dashboard's session pages show who went looking. Nothing the attacker
does with the values can leave the machine, because egress is blocked.

## Rollback

```
cd ~/cowrie && bin/cowrie stop
ls suryakundal-backups/                       # pick a timestamp
cp suryakundal-backups/<STAMP>/etc/cowrie.cfg etc/cowrie.cfg
cp suryakundal-backups/<STAMP>/etc/userdb.txt etc/userdb.txt
bin/cowrie start
```

(Copy back whichever files exist in that backup directory; if there was no
earlier `cowrie.cfg`, just delete `etc/cowrie.cfg` to go back to defaults.)

## Later

- Changed the overlay or userdb: re-run `./deploy.sh`, then restart Cowrie.
- Before restarting Cowrie after a long time: `./deploy.sh --refresh-boot`, so
  the `ps` and `top` dates match the fresh uptime.
- Running several honeypots: use a separate `--cowrie-home` each and never reuse
  one persona; identical fake hosts are trivially linkable.

## Don't forget (not handled by this kit)

- Firewall egress from the VM. Cowrie's `wget` and `curl` make real connections, and from
  inside a container the honeypot can reach your host and LAN. For the Docker deployment,
  `egress.sh` does this and proves it works: see [../docs/EGRESS.md](../docs/EGRESS.md). For a
  Cowrie you run outside Docker, apply an equivalent deny-by-default rule yourself.
- Keep your real admin SSH off port 22 and off the honeypot's address.
- Cowrie listens on 2222; redirect 22 to it with iptables/nftables if you
  want it on 22. Cowrie refuses to run as root.
