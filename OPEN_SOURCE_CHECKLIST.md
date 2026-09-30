# Open-source release checklist

Before publishing to GitHub:

- Choose and add a LICENSE file. Recommended: AGPL-3.0 if hosted forks should publish source changes; Apache-2.0 if you want broad adoption with patent grant; MIT if you want maximum simplicity.
- Run a final secret scan on the repository and release archive.
- Build a clean release ZIP from tracked files only, excluding .venv, server/data, databases, logs, and generated installer secrets.
- Test `sudo bash install.sh` on a fresh Debian/Ubuntu VM.
- Smoke-test Fedora and openSUSE if you want to advertise them as supported instead of best-effort.
- Add screenshots and a short architecture diagram to the README.
- Add SECURITY.md with responsible disclosure/contact and supported versions.
- Add CONTRIBUTING.md and a Code of Conduct if you expect outside contributors.
- Add GitHub Actions for Python compile, bash syntax, and pytest.
- Decide whether to rename legacy internal paths like `OUTPOST_*` environment variables in a breaking v2.
- Add release notes for the first public version, including endpoint safety warnings.
