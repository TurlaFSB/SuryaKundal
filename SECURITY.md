# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/TurlaFSB/SuryaKundal/security/advisories/new)
rather than a public issue. Include what you found, how to reproduce it, and the
version or commit. Expect an acknowledgement within a few days.

## What is in scope

Surya Kundal processes data from attackers, so the code that reads it is the part most
worth attacking. Reports about any of these are welcome:

- a crafted Cowrie log line, command, username or password that crashes, hangs or
  corrupts the pipeline (parser, mapping engine, storage, watcher);
- output that can manipulate an analyst's terminal or, later, the dashboard;
- credential or secret exposure (API keys, MaxMind licence key) in logs, errors or the repository;
- unsafe handling of downloaded data (database archives, captured files).

## Design choices that matter for security

- Attacker-controlled text is escaped before it is printed (`surya_kundal.textsafe`).
- The ATT&CK mapper bounds the length of every command it analyses, so crafted input
  cannot cause pathological regular-expression run time.
- Secrets are read only from the environment or an untracked `.env`; the loader warns if
  the file is readable by other users. HTTP clients never log request URLs, and the
  MaxMind downloader does not forward credentials across redirects.
- Downloaded archives are never extracted wholesale and are validated before they replace
  a working database.
- Dependencies are audited in CI (`pip-audit`), updated by Dependabot, and the code is
  scanned by CodeQL and ruff's security rules.

## Operating a honeypot safely

Run the honeypot on an isolated host, restrict its outbound traffic (Cowrie performs real
downloads when an attacker runs `wget`), and never store real credentials or services on it.
