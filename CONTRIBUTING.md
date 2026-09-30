# Contributing

Contributions are welcome if they keep endpoint safety and operator clarity first.

## Rules

- Do not submit secrets, customer data, logs, databases, private scripts, enrollment keys, tokens, or production backup files.
- Keep endpoint-agent changes small, reviewable, and pilot-friendly.
- Preserve outbound-only endpoint communication unless a change is explicitly discussed.
- Do not add code that blocks normal check-in, job pickup, self-update, or recovery when optional features fail.
- Add or update tests for server/dashboard changes when practical.
- Keep installer changes compatible with fresh Debian/Ubuntu installs.

## Local checks

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
bash -n install.sh backup-now.sh restore-backup.sh
python -m compileall -q server agent
OUTPOST_ADMIN_PASSWORD=test OUTPOST_ENROLL_KEY=test python -m pytest -q
```

## Licensing

By contributing, you agree that your contribution may be distributed under the project license in LICENSE.md.
