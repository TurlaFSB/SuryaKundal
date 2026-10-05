# honeyfs-overlay

Content for the files an attacker reads to fingerprint the host. Everything
here describes one machine: **stg-util02**, Debian GNU/Linux 12 (bookworm,
point release 12.15), kernel 6.1.0-50-amd64 (linux 6.1.176-1), 2 vCPU,
about 4 GiB RAM, one ext4 root on `/dev/vda1`, KVM guest.

## Important: Cowrie 3.x has no `honeyfs/` directory

Older Cowrie shipped a `honeyfs/` directory next to `fs.pickle`. In Cowrie
3.1.1 file contents live **inside the pickle** (`A_CONTENTS`), and the
bundled pickle carries contents for few files (`createfs` embeds a fixed list
of 19 paths, everything else is empty, so `cat /etc/ssh/sshd_config` printed
nothing). Checked in the 3.1.1 sources and by running it:

* `[honeypot] contents_path` is optional and unset by default. When set, Cowrie
  reads files from that directory instead, but only for paths that already
  exist in the pickle as **regular files** (`shell/fs.py`, `init_honeyfs`).
  Symlinks are skipped, so an overlay `etc/os-release` would be silently
  ignored (it is a symlink to `usr/lib/os-release`; that is why the file
  here is `usr/lib/os-release`).
* Neither `contents_path` nor `fsctl load` / `fsctl embed` updates the file
  **size** stored in the pickle, so `ls -l` and `cat | wc -c` disagree.
  `tools/build_fs.py` sets content and size together.
* `/etc/passwd`, `/etc/group` and `/etc/issue.net` are read once at startup
  (`shell/pwd.py`, `ssh/userauth.py`); a change needs a Cowrie restart.

## How the files get into Cowrie (three ways)

### A. `deploy.sh` (recommended, no Docker)

```
cd ~/suryakundal/cowrie && ./deploy.sh
```

It runs `tools/build_fs.py`, which takes Cowrie's bundled pickle, removes the
container artifacts, writes every file in this directory into a **new**
pickle with correct sizes, and adds the generated files below. The result is
`~/cowrie/suryakundal/fs.pickle`, referenced by `[shell] filesystem` in the
installed `cowrie.cfg`. Nothing is written into Cowrie's own package files.

### B. Real Debian tree + `createfs` (best fidelity, needs Docker)

Verified command (`docs/HONEYFS.rst` and `createfs -h`, Cowrie 3.1.1):

```
createfs -l <DIRECTORY-WITH-A-ROOT-FILESYSTEM> -d <DEPTH> -o custom.pickle
```

`-l` local root (default: current directory), `-d` max depth, `-o` output
file (it **refuses to overwrite** an existing file: `File: ... exists!`),
`-p` includes `/proc` when the root is a real `/`. `createfs` embeds the
contents of only these paths: `/etc/debian_version /etc/group /etc/host.conf
/etc/hostname /etc/hosts /etc/inittab /etc/issue /etc/issue.net /etc/motd
/etc/os-release /etc/passwd /etc/resolv.conf /etc/shadow /proc/cpuinfo
/proc/meminfo /proc/modules /proc/mounts /proc/net/arp /proc/version`.

Cowrie's own script builds a pickle from a clean Debian container (needs a
Cowrie source checkout and Docker):

```
cd cowrie-source-checkout
IMAGE=debian:bookworm bin/build-fs-pickle.sh     # writes src/cowrie/data/fs.pickle.new
```

Then apply this overlay and the per-deployment values on top of that pickle:

```
~/cowrie/cowrie-env/bin/python tools/build_fs.py --src /path/to/fs.pickle.new ...
```

(`deploy.sh` does the same with the bundled pickle; run `build_fs.py --help`
for the arguments.) A container tree still lacks things a booted host has
(`/etc/machine-id`, host keys, `/home/<user>`), which `build_fs.py` adds.

### C. `contents_path` (quick edits only)

For iterating on one file without rebuilding, point `[honeypot] contents_path`
at a directory laid out like `/` and restart Cowrie. Remember the limits
above (existing regular files only, sizes unchanged). The kit does not use it.

## Files

| Path | Notes |
|---|---|
| `etc/hostname`, `etc/hosts`, `etc/resolv.conf` | must match `[honeypot] hostname` in `cowrie.cfg` (Cowrie does not derive them) |
| `usr/lib/os-release` | Debian 12 text; `/etc/os-release` is a symlink to it in the pickle |
| `etc/issue`, `etc/debian_version`, `etc/motd`, `etc/timezone` | `12.15` was the latest bookworm point release on 2026-10-05 |
| `etc/issue.net` | **empty on purpose.** Cowrie sends this file as the pre-login SSH banner, and a stock Debian sshd sends no banner. A real box would show `Debian GNU/Linux 12` if you `cat` it; that is a known seam |
| `etc/passwd`, `etc/group` | 7-field, ASCII (Cowrie requirement). Users `root`, `deploy` (1000), `ops` (1001) must match `etc/userdb.example.txt`; `build_fs.py` refuses to build if userdb accepts a user that is missing here |
| `etc/fstab`, `proc/cmdline`, `proc/mounts` | share one root UUID, generated per deployment (`@ROOT_UUID@`) |
| `etc/ssh/sshd_config` | Debian 12 default with `PermitRootLogin yes` (so root password login is coherent) |
| `etc/apt/sources.list.d/debian.sources` | bookworm deb822 file |
| `proc/cpuinfo`, `proc/meminfo`, `proc/version` | see "Hand-written /proc" below |
| `home/*`, `root/*` | Debian skel dotfiles and a short believable `.bash_history` per user |

`build_fs.py` also generates (do not put these here): `etc/shadow` (real
sha512-crypt hashes of the passwords userdb accepts, so a cracked hash
equals the working password), `etc/machine-id`, `etc/{passwd,group,shadow}-`,
and `/etc/ssh/ssh_host_*_key.pub` copied from Cowrie's real public host keys
so `cat` and the presented key agree.

## `/proc/uptime` and friends

* `/proc/uptime`, `uptime`, `w` and `last` are generated by Cowrie
  (`generated_files["/proc/uptime"]` in `shell/protocol.py`) from
  `[honeypot] boot_offset`. You cannot override them with a file. The kit
  sets `boot_offset` once per deployment (stored in `~/cowrie/suryakundal/.state`).
* The `ps` START column and `top` header are rendered from the same boot
  offset at build time, so they agree **on the day of deployment**. If Cowrie
  is restarted later, uptime restarts from `boot_offset` while the static
  `ps` dates stay put. Run `./deploy.sh --refresh-boot` before a restart to
  re-sync them.
* `/proc/loadavg`, `/proc/stat` and the `/proc/<pid>` tree are static or
  empty in the pickle (`ls /proc` shows only PIDs 1 and 969 while `ps` lists
  57 processes). Not fixable with files.

## Hand-written /proc (read this)

`cpuinfo` (Intel Xeon Platinum 8259CL, 2 threads on one core, family 6
model 85 stepping 7), `meminfo` (MemTotal 4018204 kB, no swap), the flag
and field lists, `dmesg` and `lscpu` were assembled by hand from knowledge of
what such a KVM guest looks like. **They are not captured from real
hardware and were not verified field by field** (microcode revision, bug
list, `Vulnerabilities` text, systemd and kernel boot-message numbers).
For the best result, boot a throwaway Debian 12 VM with the same kernel and
copy `/proc/cpuinfo`, `/proc/meminfo`, `lscpu` and `dmesg` from it into
this overlay and `../txtcmds-overlay`. Do not reuse one set of values across
several honeypots.

`free` is **not** served from the overlay: Cowrie's `free` reads the real
host `/proc/meminfo` (`commands/free.py`). Give the honeypot VM about
4 GiB of RAM and set `MemTotal` here to the VM's real value
(`grep MemTotal /proc/meminfo` on the VM) so `cat /proc/meminfo` and `free`
roughly agree.
