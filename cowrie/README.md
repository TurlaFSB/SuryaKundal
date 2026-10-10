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
ssh -p 2222 root@<vm-ip>                     # root/123456 must be refused; Passw0rd! works
```

Inside the session: `uname -a`, `cat /etc/os-release`, `hostname`, `uptime`,
`df -h`, `ps aux`. They should all tell the same story.

Watch it:

```
tail -f ~/cowrie/var/log/cowrie/cowrie.json
```

Check that `cowrie.cfg` got merged: `cd ~/cowrie && bin/cowrie status`.

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

- Firewall egress from the VM. Cowrie can't hurt anything, but your box can
  still be abused if something goes wrong.
- Keep your real admin SSH off port 22 and off the honeypot's address.
- Cowrie listens on 2222; redirect 22 to it with iptables/nftables if you
  want it on 22. Cowrie refuses to run as root.
