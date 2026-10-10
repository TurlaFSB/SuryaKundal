# Deception testing

`evaluation/deception_check.py` probes a honeypot the way an attacker would and scores how
convincing it is. It answers "did the hardening kit help, and by how much" with numbers instead of
a feeling, and it can be re-run after every change.

## Results

Both runs used Cowrie 3.1.1 on the same machine, from a separate client, over SSH. Both ran in a
network namespace with no route out, so the two download checks (tier 2) pass for stock Cowrie here:
on a real host with the firewall dropping packets, stock Cowrie waits about ten seconds and prints
wording real wget never uses, as seen on a live deployment. See "Failed downloads" below.

| Attacker class | Stock Cowrie | With the kit |
|---|---|---|
| 1. Scanners and bots | 2 / 7 | **7 / 7** |
| 2. Quick manual look | 8 / 18 | **18 / 18** |
| 3. Skilled operator | 2 / 15 | 7 / 15 |
| 4. Protocol-aware tooling | 0 / 7 | 0 / 7 |
| **Overall** | **12 / 47 (26%)** | **32 / 47 (68%)** |
| Checks that configuration can fix | 12 / 32 | **32 / 32** |

Raw results are in `evaluation/results/`; `--compare` regenerates this table.

What the numbers say:

- The kit closes the cheap gaps completely. A scanner or a person typing `uname`, `cat /etc/os-release`
  or `df` finds nothing to separate it from Debian 12.
- Tier 3 and 4 are mostly out of reach. Those checks look at how Cowrie is built (Twisted's SSH
  stack, Python command re-implementations, a filesystem derived from a container image). Fifteen of
  the 47 checks are marked "config cannot fix", and the kit fails exactly those and nothing else.
- Early runs showed two fixable gaps, both now closed: `/proc` listed only two process directories,
  and `free` reported the host's real memory while `/proc/meminfo` claimed 4 GB. The kit now
  generates one `/proc/<pid>` per `ps` row, and sets the persona's memory to the host's.
- A skilled operator will still identify Cowrie. The kit raises the cost; it does not make the
  honeypot invisible. `cowrie/FINGERPRINTING.md` explains each gap.

## Failed downloads

The first thing many attackers do is `wget` or `curl` a script. With egress blocked the fetch must
fail the way it would on a real server whose network is down: at once, and in the tools' own words
(`Resolving example.com (example.com)... failed: Temporary failure in name resolution` for wget,
`curl: (6) Could not resolve host` for curl). On a live deployment with outbound traffic dropped,
Docker's built-in resolver still answered, so wget printed `connected.`, hung for ten seconds, then
ended with `failed: Operation timed out.`, which real wget never prints. That also meant DNS queries
were leaving the container.

The deny-mode fix is a local resolver stub (`cowrie/tools/sinkdns.py`) that answers every lookup
with SERVFAIL instantly and forwards nothing. The two checks `wget-failure-realistic` and
`curl-failure-realistic` accept either a plausible completed fetch or the genuine offline failure,
and fail on Cowrie's own wording or on any answer slower than 20 seconds.

## Running it

Run it from another machine, against your own honeypot only. It logs in, runs read-only commands,
and writes nothing to the target. Every probe shows up in the honeypot's logs as a session.

```
pip install '.[evaluation]'        # paramiko and cryptography
python evaluation/deception_check.py HOST --port 2222 --user deploy --password '...' \
    --label "my honeypot" --json mine.json
python evaluation/deception_check.py --compare before.json after.json
```

`--user` and `--password` must be a pair the honeypot accepts. `--only id1,id2` runs selected
checks; `--fail-under 0.9` exits 1 if the score for fixable checks is lower, for use in a script.

## What each tier means

1. **Scanners and bots**: banner string, default credentials, a login with a random password,
   hostname, host key size.
2. **Quick manual look**: commands whose output contradicts the claimed OS: `/etc/os-release`,
   `uname`, `df`, `dmesg`, `mount`, `top`, `ssh -V`, leftover Docker or VirtualBox files.
3. **Skilled operator**: two views of the same fact must agree: `free` against `/proc/meminfo`,
   `lscpu` against `/proc/cpuinfo`, `ls -l` against `wc -c`, `uptime` against `/proc/uptime`, plus
   command quirks (`ls` date format, `grep -c` in a pipe, `ip`, `sudo -l`).
4. **Protocol-aware tooling**: the SSH server itself: whether it accepts any 2.x protocol version,
   acknowledges an exec request, and offers the algorithms OpenSSH 9.2 offers by default
   (chacha20-poly1305, AES-GCM, sntrup761, rsa-sha2-512, -etm MACs).

## Limits of these numbers

- The lab was a sandbox, not the production container. `ssh-keygen` was unavailable there, so the
  RSA host key for the kit run was generated with the `cryptography` library at 3072 bits, which is
  what `deploy.sh` produces when OpenSSH is installed.
- Checks encode what a Debian 12 machine does. I wrote them from the fingerprinting notes and
  from Cowrie's observed behaviour. They have not been compared against a real Debian 12 host
  over the same probe, which is the obvious next step for a stronger claim.
- The score weights every check equally. A banner mismatch matters more than `echo $0`.
- The `collect` login policy accepts about 30 weak root passwords on purpose, to let scanners in
  and capture sessions. The harness does not penalise that; it only checks that stock-Cowrie
  accounts and wildcard passwords are refused. `stealth` accepts three exact logins.
- It measures the honeypot against these probes only; it is not a measure of how real attackers
  will fare.
