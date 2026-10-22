# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-22

### Added

- `shouldibump` CLI: scans a project and prints one table of what to update.
- Manifest support: `requirements*.txt`, `pyproject.toml` (PEP 621 and Poetry),
  and `package.json` (npm / pnpm / yarn).
- Latest-version lookups against the public PyPI and npm registries.
- Risk scoring from bump size, including the `0.x` caveat where a minor bump is
  allowed to break.
- Known-vulnerability checks against the OSV database, with an explicit warning
  when the lookup itself is unreachable.
- Flags: `--json`, `--only-outdated`, `--no-dev`, `--no-vulns`, `--ignore`,
  `--fail-on`, `--timeout`, `--jobs`, `--no-color`.
- Zero runtime dependencies.
