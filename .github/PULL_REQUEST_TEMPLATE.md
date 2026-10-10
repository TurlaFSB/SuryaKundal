## What and why

## How it was tested

- [ ] `ruff format --check . && ruff check . && mypy && pytest` pass
- [ ] Tests added or updated (hostile input covered where attacker text is involved)
- [ ] Migration added if a model changed
- [ ] Wazuh rules regenerated if `rules.toml` changed
- [ ] `.env.example`, `compose.yaml` and docs updated for any new setting
- [ ] CHANGELOG *Unreleased* updated

## Security impact

Describe any change to what attackers can influence, what the dashboard exposes, or what the honeypot can reach. Write "none" if there is none.
