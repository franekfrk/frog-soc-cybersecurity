# Project instructions

- Keep user-facing documentation in both Polish and English.
- `README.md` is Polish; `README.en.md` is English. Update both whenever features,
  configuration, setup, limitations or deployment instructions change.
- Each README must link to the other language at the top. Preserve equivalent
  coverage and accurate version numbers in both languages.
- `deploy/app.py` is the canonical application source. Regenerate the standalone
  updater using `python3 tools/build_update.py` after changing deployment sources.
- Run `python3 tools/build_update.py --check`, shell syntax checks, and relevant
  unit/integration tests before publishing application changes.
- Never commit live credentials, webhook URLs, SSH keys, database files or logs.
