# Contributing

Thanks for helping. This is a security tool that handles hostile data, so the bar for
changes is: correct, tested, and unable to be tricked by what an attacker types.

## Set up

```bash
git clone https://github.com/TurlaFSB/SuryaKundal.git && cd SuryaKundal
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install            # optional: runs the checks below before each commit
```

## Checks (the same ones CI runs)

```bash
ruff format --check . && ruff check . && mypy && pytest
```

`pytest` enforces a 90% coverage floor and treats leaked resources as errors.

## Rules of the road

- **Attacker text is untrusted.** Anything from a Cowrie event (usernames, passwords,
  commands, URLs, client strings) must go through `surya_kundal.textsafe.printable` before it
  reaches a terminal or a page, and must never be used to build a path, query or command.
- **Schema changes need a migration** in `database/migrations/versions/`. A test fails if a
  model changes without one. Migrations are append-only; never edit one that has been released.
- **ATT&CK rules** go in `mapping/rules.toml` with an example that must match and one that
  must not. Regenerate the Wazuh rules afterwards:
  `surya-kundal wazuh-rules --output wazuh/rules/surya_kundal_cowrie_rules.xml`.
- **No secrets** in code, tests, logs or commit history. Use `.env` (git-ignored).
- **Free only.** The project must stay runnable on free tiers and free datasets.

## Pull requests

Keep them focused, explain *why*, and add or update tests. Describe any security-relevant
behaviour change in the pull request. Report vulnerabilities privately; see
[SECURITY.md](SECURITY.md).
