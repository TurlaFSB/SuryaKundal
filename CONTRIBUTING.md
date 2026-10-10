# Contributing

Thanks for helping. This is a security tool that handles hostile data, so the bar for
changes is: correct, tested, and unable to be tricked by what an attacker types.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are
licensed under the project's [MIT License](LICENSE).

## Ways to help

- **Report a bug or suggest a feature** with an [issue](https://github.com/TurlaFSB/SuryaKundal/issues/new/choose).
  For a wrong ATT&CK mapping, include the command and the technique you expected.
- **Report a vulnerability** privately; see [SECURITY.md](SECURITY.md). Do not open a public issue.
- **Improve a rule, a document or a test.** Small, focused changes are the easiest to review.
- **Share real-world samples** only after removing anything that identifies a victim or a network.

For anything larger than a small fix, open an issue first so the approach can be agreed before you
spend time on it.

## Set up

```bash
git clone https://github.com/TurlaFSB/SuryaKundal.git && cd SuryaKundal
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install            # optional: runs the checks below before each commit
```

Python 3.11 or newer. You do not need Cowrie, Docker or any API key to run the tests.

## Checks (the same ones CI runs)

```bash
ruff format --check . && ruff check . && mypy && pytest
```

`pytest` enforces a 90% coverage floor and treats leaked resources as errors. If you change a shell
script under `cowrie/` or `wazuh/`, also run `shellcheck cowrie/*.sh wazuh/*.sh`. Firewall changes in
`cowrie/egress.sh` have a real-packet test that needs Linux network namespaces:
`unshare -rn python tests/netns_egress_lab.py cowrie/egress.sh`.

## Rules of the road

- **Attacker text is untrusted.** Anything from a Cowrie event (usernames, passwords,
  commands, URLs, client strings) must go through `surya_kundal.textsafe.printable` before it
  reaches a terminal or a page, and must never be used to build a path, query or command.
- **Bound everything attackers control.** New parsing or matching code needs a size limit, and
  regular expressions need bounded quantifiers. Add a test with hostile input.
- **Schema changes need a migration** in `database/migrations/versions/`. A test fails if a
  model changes without one. Migrations are append-only; never edit one that has been released.
- **ATT&CK rules** go in `mapping/rules.toml` with an example that must match and one that
  must not. Regenerate the Wazuh rules afterwards:
  `surya-kundal wazuh-rules --output wazuh/rules/surya_kundal_cowrie_rules.xml`.
  Changing rules re-maps stored sessions once, which is expected.
- **The dashboard stays read-only** and keeps its strict Content-Security-Policy: no inline script
  or style, no external resources, no write routes.
- **New settings** are documented in `.env.example` and the README table. The dashboard container
  receives only the variables listed for it in `compose.yaml`, so a setting it reads must be added there.
- **No secrets** in code, tests, logs or commit history. Use `.env` (git-ignored).
- **Free only.** The project must stay runnable on free tiers and free datasets.
- **Document user-visible changes** under *Unreleased* in the [CHANGELOG](CHANGELOG.md).

## Commits and pull requests

Write commit messages in the imperative ("Fix rotation handling"), with the reason in the body when
it is not obvious. Keep pull requests focused, explain *why*, and add or update tests. Describe any
security-relevant behaviour change in the pull request. CI must pass before review.
