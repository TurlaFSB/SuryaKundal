"""The kit's fake /proc/<pid> directories must match the ps list the shell prints."""

import importlib.util
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "cowrie" / "tools"


def _load():
    spec = importlib.util.spec_from_file_location("build_fs", TOOLS / "build_fs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_fs"] = module
    spec.loader.exec_module(module)
    return module


bf = _load()

PROCESSES = [
    {"USER": "root", "PID": 1, "COMMAND": "/sbin/init", "STAT": "Ss", "VSZ": 168712, "RSS": 11776},
    {"USER": "root", "PID": 2, "COMMAND": "[kthreadd]", "STAT": "S", "VSZ": 0, "RSS": 0},
    {"USER": "root", "PID": 3, "COMMAND": "[rcu_gp]", "STAT": "I<", "VSZ": 0, "RSS": 0},
    {
        "USER": "root",
        "PID": 481,
        "COMMAND": "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
        "STAT": "Ss",
        "VSZ": 15432,
        "RSS": 5888,
    },
    {
        "USER": "messagebus",
        "PID": 412,
        "COMMAND": "/usr/bin/dbus-daemon --system --address=systemd: --nofork",
        "STAT": "Ss",
        "VSZ": 8200,
        "RSS": 4100,
    },
    {
        "USER": "root",
        "PID": 600,
        "COMMAND": "sshd: deploy [priv]",
        "STAT": "Ss",
        "VSZ": 17000,
        "RSS": 7000,
    },
]
UIDS = {"root": 0, "messagebus": 101}


def _tree():
    def directory(name, children=()):
        return [name, bf.T_DIR, 0, 0, 4096, 0o40755, 0, list(children), None, None]

    stale = [
        directory("1"),
        directory("969"),
        ["cpuinfo", bf.T_FILE, 0, 0, 3, 0o100444, 0, b"x", None, None],
    ]
    return directory("/", [directory("proc", stale)])


def _files(root, pid):
    node = bf.lookup(root, f"/proc/{pid}")
    return {c[bf.A_NAME]: c[bf.A_CONTENTS] for c in node[bf.A_CONTENTS]}


def _stats():
    return {"created": 0, "updated": 0, "removed": 0}


def test_every_ps_row_gets_a_proc_directory_and_stale_ones_go():
    root = _tree()
    count = bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    proc = bf.lookup(root, "/proc")
    numeric = sorted(int(c[bf.A_NAME]) for c in proc[bf.A_CONTENTS] if c[bf.A_NAME].isdigit())
    assert count == len(PROCESSES)
    assert numeric == sorted(p["PID"] for p in PROCESSES)  # 969 is gone
    assert any(c[bf.A_NAME] == "cpuinfo" for c in proc[bf.A_CONTENTS])  # non-process files stay


def test_process_files_agree_with_the_ps_row():
    root = _tree()
    bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    sshd = _files(root, 481)
    assert sshd["cmdline"].startswith(b"sshd:\x00/usr/sbin/sshd\x00") and sshd["cmdline"].endswith(
        b"\x00"
    )
    status = sshd["status"].decode()
    assert "Name:\tsshd" in status and "Pid:\t481" in status and "PPid:\t1" in status
    assert "VmSize:\t   15432 kB" in status and "VmRSS:\t    5888 kB" in status
    assert _files(root, 412)["status"].decode().count("Uid:\t101\t101\t101\t101") == 1


def test_kernel_threads_have_no_cmdline_and_hang_off_kthreadd():
    root = _tree()
    bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    thread = _files(root, 3)
    assert thread["cmdline"] == b""
    assert thread["comm"] == b"rcu_gp\n"
    status = thread["status"].decode()
    assert "PPid:\t2" in status and "State:\tI (idle)" in status and "VmSize" not in status
    assert "PPid:\t0" in _files(root, 2)["status"].decode()


def test_pid_one_is_systemd_and_sshd_sessions_hang_off_the_listener():
    root = _tree()
    bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    assert _files(root, 1)["comm"] == b"systemd\n"
    assert "PPid:\t481" in _files(root, 600)["status"].decode()


def test_stat_line_has_the_fields_procps_expects():
    root = _tree()
    bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    fields = _files(root, 481)["stat"].decode().split()
    assert fields[:4] == ["481", "(sshd)", "S", "1"]
    assert len(fields) == 52


def test_proc_directories_are_read_only_and_owned_by_root():
    root = _tree()
    bf.add_proc_entries(root, PROCESSES, UIDS, 1_700_000_000, _stats())
    node = bf.lookup(root, "/proc/481")
    assert node[bf.A_MODE] == 0o40555 and node[bf.A_UID] == 0
