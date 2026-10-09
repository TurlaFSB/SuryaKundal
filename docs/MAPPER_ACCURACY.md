# ATT&CK mapper accuracy

`evaluation/mapper_cases.toml` holds 103 commands labelled by hand with the techniques an analyst
would assign. `python evaluation/evaluate_mapper.py --verbose` scores the mapper against them, and
`tests/test_mapper_accuracy.py` fails the build if precision or recall drop below 0.97.

## Results

| | Precision | Recall | Exact match |
|---|---|---|---|
| First run | 0.899 | 0.930 | 84% (87 of 103) |
| After review | 1.000 | 0.992 | 99% (102 of 103) |

The first run disagreed on 16 commands. I reviewed each one:

- **Mapper bugs, fixed:** a miner name inside `ps | grep` counted as mining; `curl -F` upload
  also counted as a download; `scp` upload was not exfiltration; `chmod go=` was not a permission
  change; `service auditd stop` was not audit tampering; `grep -r password` was not credential
  search; `ls /var/log` was not log enumeration; `rm -rf /` counted as cleaning up traces.
- **Labelling mistakes, corrected:** the mapper's answer was defensible, for example
  `systemctl stop firewalld` is both a firewall change and a service stop, and `scp` runs over SSH.
- **Known gap:** a download written inside a quoted cron line is not reported, because the
  mapper does not look inside strings that are only written to a file.

## Read these numbers with care

- The commands are written from public honeypot playbooks, not captured from this deployment.
- The rules were adjusted after seeing this set, so the second row is optimistic. The first row is
  the honest measure; the way to get an unbiased number is a fresh set labelled before looking at
  the mapper, ideally from real captured sessions.
- It scores individual command lines. It does not measure session-level rules (logins, transfers,
  tunnels).
