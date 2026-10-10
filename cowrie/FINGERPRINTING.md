# Fingerprinting: threat model for the Surya Kundal Cowrie kit

Cowrie is a **medium-interaction** honeypot written in Python on top of
Twisted Conch. It re-implements an SSH server and a shell in Python; it does
not run OpenSSH, bash or a kernel. A determined operator can always find
seams. The goal of this kit is to make the cheap checks fail (scanners,
off-the-shelf "is this Cowrie" scripts, a quick manual look) and to make the
expensive checks cost time, not to be undetectable.

Verification status used below: **verified** = read in Cowrie 3.1.1 source or
reproduced live against Cowrie 3.1.1 (pip `cowrie==3.1.1` + Twisted 26.4.0,
tested on 2026-10-05); **cited** = taken from a source linked in the row;
**UNVERIFIED** = from memory or inference, check before relying on it.

## 1. Attacker classes assumed

| Class | What they check | Realistic outcome |
|---|---|---|
| Internet-wide scanners and bots | banner string, default creds, a login with a random password | defeated by non-default banner/hostname/userdb |
| Honeypot-aware tooling | protocol quirks, default filesystem, known command outputs, Shodan-style honeyscore | partly defeated; protocol quirks remain |
| Skilled manual operator | `uname`, `/proc`, `ps`, `mount`, `df`, `dmesg`, timing, odd commands | wastes time on a consistent persona, will eventually hit a seam |
| APT-style operator | all of the above plus protocol-level fingerprints (HASSH-server, malformed-packet replies), cross-checking several views of the same fact | will likely identify Cowrie; the kit makes them do more work first |

## 2. Known tells of default Cowrie, and what this kit does

| # | Tell | Source | Status in this kit |
|---|---|---|---|
| 1 | Default SSH version string. `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` was on 72% of honeypots found in 2018; the 3.1.1 dist default is `...9.2p1 Debian-2+deb12u3`, shared by every unconfigured install. The code still falls back to the deb7u2 string if the option is missing | [talk slides](https://www.cl.cam.ac.uk/~amv42/papers/vetterl-we-know-where-you-live-honeypots-first-19-slides.pdf) (cited); [cowrie.cfg.dist](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/data/etc/cowrie.cfg.dist), [ssh/factory.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/ssh/factory.py) (verified) | **Mitigated**: `Debian-2+deb12u10`, matched to the claimed release |
| 2 | Default hostname (`svr04` in 3.1.1; the talk reports a default name on 296 honeypots, mostly T-Pot) | talk slides (cited); dist (verified) | **Mitigated**: `stg-util02` in the prompt, `uname`, `/etc/hostname`, `/etc/hosts`, dmesg |
| 3 | `cat /etc/hostname` disagrees with the prompt (Cowrie prints `svr04` from the pickle whatever `hostname` is) | reproduced live | **Mitigated** (overlay) |
| 4 | Login policy: default accepts `root` with any password, plus a default user `phil`; a login with a random password succeeding is a one-request test | [auth.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/core/auth.py), [FAQ.rst](https://github.com/cowrie/cowrie/blob/v3.1.1/docs/FAQ.rst) (verified) | **Mitigated**: three exact pairs, everything else refused (tested) |
| 5 | Bundled `fs.pickle` is a Debian 12 **Docker image**: `/.dockerenv`, `/proc/docker`, `docker-*` apt files, `/home/phil`, `vboxsf` group, `/etc/hosts` naming another host (`nas3`), Debian-7-style passwd with `/bin/sh` shells, `/etc/debian_version` 12.5 | inspected the 3.1.1 pickle (verified) | **Mostly mitigated**: container files removed, users/home/hosts/group/passwd rewritten. `/etc/mtab`, `/etc/init.d`, `runit`, `sv`, `/proc/969` and other container leftovers remain |
| 6 | Many pickle files exist with a size but **empty content** (`cat /etc/ssh/sshd_config`, `/etc/os-release` printed nothing; `dpkg/status` is 121925 bytes of nothing) | reproduced live; [createfs.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/scripts/createfs.py) embeds only 19 paths | **Partly mitigated**: the files an attacker reads first are filled with matching size. Everything else stays empty |
| 7 | Static text commands describe other machines: `dmesg` is a 2009 Linux 2.6.26 (Debian 5) boot, `mount` shows ext3 `/dev/sda1`, `df` fails with "Exec format error" (merged-usr path mismatch), `top` prints a vim error, `getconf LONG_BIT` prints 32 | reproduced live; [data/txtcmds](https://github.com/cowrie/cowrie/tree/v3.1.1/src/cowrie/data/txtcmds) | **Mitigated** for `df mount dmesg lscpu top getconf` via `txtcmds_path`. Editors (`vi`, `nano`, `pico`, `emacs`) still print other editors' error messages |
| 8 | `ssh -V` inside the shell prints OpenSSH 7.9p1 / OpenSSL 1.1.1a, contradicting the banner | `[shell] ssh_version` default (verified) | **Mitigated** |
| 9 | `uname -a`, `/proc/version` report kernel 6.1.0-21 / 6.1.90-1 in every default install | dist (verified) | **Mitigated** (6.1.0-50 / 6.1.176-1) |
| 10 | `ps` list from a VirtualBox guest with a 3.x-era kernel thread set (`VBoxService`, `iprt-VBoxWQueue`, `rcu_bh`, exim4, rpcbind) | [cmdoutput.json](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/data/cmdoutput.json) (verified) | **Mitigated** via `[shell] processes`. The `ps` code still prints a hard-coded `Jul22` sshd row and misaligned columns (reproduced live) |
| 11 | Shared public data: every install ships the same `/proc/cpuinfo` (Xeon E5-2680 v4) and `/proc/meminfo` (4054744 kB) | inspected pickle (verified) | **Mitigated**: different CPU/memory persona. Do not reuse across your own deployments |
| 12 | Host key reuse between deployments (only 65 to 78.9% of honeypots had unique keys) | [Bitter Harvest](https://www.usenix.org/system/files/conference/woot18/woot18-paper-vetterl.pdf) (cited) | **Mitigated**: keys are per deployment; deploy.sh offers 3072-bit RSA (Debian 12 default) and mirrors the public keys into `/etc/ssh` so `cat` matches what was presented |
| 13 | Uptime restarts at a random 1 to 90 days on every Cowrie restart | [protocol.py `boot_offset`](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/protocol.py) (verified) | **Partly mitigated**: fixed per deployment, but still resets to that value on restart |
| 14 | Idle shells are dropped after 180 s, which real sshd never does | dist (verified) | **Mitigated** (900 s). A longer patient wait still ends |
| 15 | `ssh` banner/version-string handling: "SSH-2.2-..." gets `Protocol major versions differ.` and a disconnect; OpenSSH accepts any 2.x | [Bitter Harvest §4.4.2](https://www.usenix.org/system/files/conference/woot18/woot18-paper-vetterl.pdf) (cited); reproduced live (3.1.1 reply text differs from the 2018 paper) | **Not mitigable** with config |
| 16 | Malformed binary packet gets a Twisted-specific disconnect text (`bad packet mod (9%8 == 1)` observed); OpenSSH replies differently | Bitter Harvest §4.4.2 (cited); reproduced live | **Not mitigable** |
| 17 | KEXINIT padding: Kippo/Cowrie used random bytes, OpenSSH uses NULs | Bitter Harvest §4.4.1 (cited) | **Fixed upstream**: 3.1.1 sends NULs (verified in `ssh/transport.py` and on the wire) |
| 18 | Server-side algorithm lists (a HASSH-server-style fingerprint): see section 4 | Twisted source and a live KEXINIT capture (verified) | **Reduced, not fixed** |
| 19 | `direct-tcpip` forwarding is accepted and the channel then discards data, so a SOCKS/proxy test through the honeypot never returns anything | [forwarding.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/ssh/forwarding.py) (verified) | **Not mitigable** (kept on so attempts are logged) |
| 20 | `exec` requests close the whole SSH connection after the command; real sshd keeps it open for more channels. The channel is also closed before the exec request is acknowledged, so a client that waits for the reply (paramiko) sees `Channel closed` where OpenSSH replies first | reproduced live; measured by `evaluation/deception_check.py` | **Not mitigable** |
| 21 | `free` shows the **real host's** memory (reads `/proc/meminfo` of the machine Cowrie runs on) | [commands/free.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/commands/free.py) (verified); live: 8223 MB vs 4018204 kB in `/proc/meminfo` | **Operational fix only**: size the VM to match, set `MemTotal` in the overlay |
| 22 | Other command-implementation seams seen live: `wc -c a b` prints one number, `sudo -l` rejected, `ls` link counts are all 1, `ifconfig` is net-tools style with `eth0` and a 192.0.2.x TEST-NET address while `ip` is missing, `netstat` lists an Ubuntu `upstart` socket, `echo $0` empty, `ls -l` prints ISO dates (`2026-05-04 14:44`) where GNU ls prints `May  4 14:44`, `grep -c` does nothing on piped input | reproduced live; measured by `evaluation/deception_check.py` | **Not mitigable** with config |

## 3. What this kit mitigates, and what it cannot

**Mitigates (when deployed with `deploy.sh`):**
persona consistency (Debian 12.15, kernel 6.1.176-1, OpenSSH 9.2p1 deb12u10
and OpenSSL 3.0.20 all real bookworm versions as of 2026-10-05); hostname in
all views; `/etc` and `/proc` files an attacker reads first, with matching
sizes; shadow hashes that crack to the passwords that work; per-deployment
machine-id, root UUID, host keys, install date and boot time; a login policy
that is not "any password"; removal of Docker/VirtualBox/phil artifacts; a
`ps` list and text-command outputs that match the persona.

**Cannot mitigate (inherent to Cowrie / Python / Twisted, or to the VM):**

* **Protocol implementation.** Twisted Conch answers malformed input
  differently from OpenSSH (rows 15, 16). Anyone who sends one crafted
  packet gets a Twisted answer.
* **Server algorithm lists / HASSH-server.** On the wire, with this kit's config,
  Cowrie 3.1.1 offers: KEX `curve25519-sha256, curve25519-sha256@libssh.org,
  ecdh-sha2-nistp256/384/521, diffie-hellman-group14-sha1, ext-info-s`; host
  key `ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519`; ciphers
  `aes128/192/256-ctr`; MACs `hmac-sha2-256, hmac-sha2-512, hmac-sha1`
  (captured live). Missing compared with a stock OpenSSH 9.2 server
  (**UNVERIFIED** from memory, not captured from a real Debian 12 sshd):
  `sntrup761x25519-sha512@openssh.com`, `diffie-hellman-group-exchange-sha256`,
  `diffie-hellman-group16/18-sha512`, `rsa-sha2-256/512` host-key names (Cowrie
  advertises SHA-1 `ssh-rsa` instead), `chacha20-poly1305@openssh.com`,
  AES-GCM, the `-etm` MACs, and probably the `kex-strict-s-v00@openssh.com`
  marker that Debian's 9.2p1-2+deb12u2 added for Terrapin. Twisted 26.4.0
  has no implementation of chacha20 or GCM
  ([transport.py](https://github.com/twisted/twisted/blob/twisted-26.4.0/src/twisted/conch/ssh/transport.py),
  tag name assumed), so `ciphers` cannot be completed. `kex` and host-key
  algorithm names are not configurable in Cowrie 3.1.1.
* **Timing.** Every command runs inside one single-threaded Twisted reactor
  in Python, with no real process start-up cost, no disk latency and no
  scheduler noise. Pre-auth handshake time, command latency distributions and
  behaviour under many parallel sessions differ from a real host
  (**UNVERIFIED**: not measured here).
* **Command output imperfections.** Roughly 50 commands are re-implemented;
  everything else is "command not found" or an "Exec format error" stub
  (row 22). Arguments, error text and corner cases differ from GNU coreutils.
  `ps`, `top`, `ifconfig`, `netstat`, `w`, `last` are canned or generated.
* **Fake filesystem seams.** The tree comes from a Docker image: `ls /proc`
  shows two PIDs, directory link counts are 1, `/` and `/home` carry
  image-build dates older than the "install" date, package databases are
  empty, binaries are stubs (Cowrie returns a small bundled ELF for `cat
  /bin/ls`), and private host-key files are empty. Sizes in `ls -l` are only
  consistent for files this kit wrote.
* **Single-view consistency.** Facts that Cowrie computes live (`free`, the
  clock in `w`, `last`, uptime) can disagree with static files (`top` header,
  `dmesg`, `ps` START). The kit aligns them on the deployment day only.
* **Host and network layer.** TCP/IP stack behaviour, TTL, MSS/window options,
  TLS-less port banners, response to port 22 vs 2222, hosting provider/ASN
  and reverse DNS belong to the VM and network, not Cowrie. A Kali (or other)
  host kernel will not be bit-identical to the claimed Debian 12 stack
  (**UNVERIFIED**: not fingerprinted here).
* **SFTP and file transfer.** Cowrie implements a fake SFTP over its virtual
  filesystem; behaviour on unusual SFTP operations was not tested
  (**UNVERIFIED**).

## 4. Operational advice

1. **Keep the real admin SSH off port 22 and unrelated to the honeypot.**
   Put it on a management interface or VPN, a different port, different host
   keys, key-only auth, no shared usernames, banner or credentials, and never
   on an address range the honeypot shares. An attacker who finds the real
   sshd next to a "Debian" honeypot learns which one is real. If the
   honeypot should answer on 22, forward 22 to 2222 at the router/firewall,
   or follow Cowrie's authbind/setcap notes in
   [INSTALL.rst](https://github.com/cowrie/cowrie/blob/v3.1.1/INSTALL.rst);
   do not run Cowrie as root (it refuses to).
2. **Isolate the VM.** Dedicated VM, no shared folders, no clipboard, no
   credentials or keys that work anywhere else, no route to your LAN or
   management network. Cowrie's `wget`, `curl`, `nc`, `ftpget` and `tftp`
   make **real outbound connections** to attacker-chosen hosts (verified
   in the dist rate-limit and `out_addr` text), so apply an egress firewall:
   deny RFC1918 and your management ranges, rate-limit, log. Decide
   consciously whether to allow any outbound at all (denied fetches are
   themselves a tell, allowed ones are risky).
3. **No real data.** Nothing in the fake tree is real; keep it that way. The
   only secrets in the kit are the example passwords, which are deliberately
   weak and not reused anywhere.
4. **Rotate per deployment so one deployment's fingerprints do not match
   another.** `deploy.sh` already generates a fresh seed, machine-id,
   root UUID, shadow salts, install date and boot offset for each new Cowrie
   directory. For each additional honeypot also change: the hostname and
   domain (`cowrie.cfg.example`, overlay `etc/hostname`, `etc/hosts`,
   `etc/resolv.conf`, `dmesg`), the userdb pairs and usernames
   (`etc/userdb.example.txt` plus overlay `etc/passwd`, `etc/group`, home
   directories), the CPU and memory values, and the process list. Consider a
   different but equally real OS persona per site. Use `--regen-hostkeys`
   when cloning a VM so two honeypots never share host keys.
5. **Keep Cowrie current and watch its issues.** A third of the honeypots in
   the 2018 survey were months out of date (talk slides). Re-check the persona
   versions (openssh, linux, openssl, point release) every few months; stale
   "current" versions are a tell, and so is a patched version on a box that
   claims never to be updated.
6. **Ship logs off the box** and treat the VM as disposable: snapshot, run,
   revert. `cowrie.json` and the tty logs hold attacker data; protect and
   retain them according to the law and policy that apply to you.
7. **Re-test after every change** with the checklist in `README.md`; do the
   cross-checks an attacker would (`hostname` vs `/etc/hostname` vs `dmesg`,
   `uname -r` vs `/proc/version` vs `dmesg`, `free` vs `/proc/meminfo`,
   `ls -l` vs `wc -c`).

## 5. Top residual tells (most to least likely to matter)

1. Twisted/Cowrie protocol behaviour: crafted version strings and malformed
   packets (rows 15, 16), and the server algorithm lists (row 18).
2. Command-level seams (row 22) and everything not implemented ("command not
   found" for tools a Debian 12 box would have, e.g. `ip`, `sudo -l`).
3. `free` and live-computed values disagreeing with the static `/proc` files
   (row 21, section 3), and uptime resetting on restart.
4. Filesystem seams from the container-derived pickle: two PIDs in `/proc`,
   empty file contents, link counts, image-build dates.
5. Exec/forwarding behaviour (rows 19, 20) and timing of the single-threaded
   Python reactor.

## Appendix A. Cowrie options used, and where each was verified

All against Cowrie 3.1.1 (`github.com/cowrie/cowrie`, tag `v3.1.1`; the dist
file is identical in the repository `main` branch on 2026-10-05).

| Option | Verified in |
|---|---|
| `[honeypot] hostname`, `idle_timeout`, `authentication_timeout`, `download_limit_size`, `boot_offset`, `txtcmds_path`, `etc_path`, `auth_class`, `timezone`, `fake_addr`, `internet_facing_ip`, `out_addr`, `contents_path` | [src/cowrie/data/etc/cowrie.cfg.dist](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/data/etc/cowrie.cfg.dist) and the readers: [shell/protocol.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/protocol.py), [shell/fs.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/fs.py), [shell/server.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/server.py), [core/auth.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/core/auth.py) |
| `[shell] filesystem`, `processes`, `arch`, `kernel_version`, `kernel_build_string`, `hardware_platform`, `operating_system`, `ssh_version` | same dist file; [commands/uname.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/commands/uname.py), [shell/honeyfs.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/honeyfs.py), [shell/server.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/server.py) |
| `[ssh] version`, `ciphers`, `macs`, `compression`, `enabled`, `listen_endpoints`, `sftp_enabled`, `forwarding`, `public_key_auth` | dist file; [ssh/factory.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/ssh/factory.py), [shell/avatar.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/shell/avatar.py) |
| `[output_jsonlog] enabled`, `logfile` | dist file |
| userdb syntax | [core/auth.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/core/auth.py), [data/etc/userdb.example](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/data/etc/userdb.example) |
| `createfs -l DIR -d DEPTH -o FILE`, `fsctl <pickle> [command]` | [docs/HONEYFS.rst](https://github.com/cowrie/cowrie/blob/v3.1.1/docs/HONEYFS.rst), [scripts/createfs.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/scripts/createfs.py), [scripts/fsctl.py](https://github.com/cowrie/cowrie/blob/v3.1.1/src/cowrie/scripts/fsctl.py), and `createfs -h` run live |

**Option names that do not exist in 3.1.1** and are therefore not used:
`[honeypot] report_hostname`, `data_path` (existed in 2.x), `[honeypot]
kernel_version/kernel_build_string/hardware_platform/operating_system` (they
are under `[shell]`), and `[ssh] mac` (the option is `macs`). `fake_addr` does
exist but only changes the address shown by `w` and `last`, so it is left
unset. `[shell] kernel_name` is read by the code but absent from the dist; it
is left at its default (`Linux`).

## Appendix B. Persona version checks (2026-10-05)

| Fact | Value | Source |
|---|---|---|
| bookworm openssh | `1:9.2p1-2+deb12u10` (security channel `u9`) | [Debian security tracker](https://security-tracker.debian.org/tracker/source-package/openssh), [package tracker](https://tracker.debian.org/pkg/openssh) |
| bookworm linux | `6.1.176-1` (security `6.1.187-1`) | [security tracker](https://security-tracker.debian.org/tracker/source-package/linux) |
| kernel release + build string | `6.1.0-50-amd64`, `#1 SMP PREEMPT_DYNAMIC Debian 6.1.176-1 (2026-07-02)` | uname line of a real bookworm image: [immers.cloud listing](https://en.immers.cloud/marketplace/linux/debian12_140726/) (cloud flavour; same source version and date) |
| bookworm openssl | `3.0.20-1~deb12u2`; upstream 3.0.20 dated 7 Apr 2026 | [security tracker](https://security-tracker.debian.org/tracker/source-package/openssl), [OpenSSL 3.0 notes](https://openssl-library.org/news/openssl-3.0-notes/) |
| latest point release | Debian 12.15, 2026-07-11 | [debian.org/releases/bookworm](https://www.debian.org/releases/bookworm/) |
| gcc string in `/proc/version` (`12.2.0-14+deb12u1`), systemd `252.39-1~deb12u1`, base-passwd account list and UIDs, `/proc` and `dmesg` details | **UNVERIFIED**, from memory | none fetched |

If you change any version, change all of them together.
