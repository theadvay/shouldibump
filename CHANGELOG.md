# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-10-23

### Added

- `--format` with four outputs: `table` (default), `json`, `markdown` and `sarif`.
- Markdown reports, for pasting into pull-request comments and CI job summaries.
- SARIF 2.1.0 export, so GitHub code scanning can ingest the results.
- A `py.typed` marker; the package ships its type information.
- Coverage and lint tooling (`pytest-cov`, `ruff`) wired into CI.

### Fixed

- A dependency declared in more than one manifest is now reported once, with
  every source file kept.
- `requirements.txt` `-r other.txt` includes are followed, cycle-safely.
- Releases whose files have all been yanked on PyPI are no longer suggested as
  an upgrade target.
- A dependency whose current version cannot be determined no longer scores as
  `none` — it stays `unknown`.
- SARIF locations are relative to the scan root, so code scanning can map them
  back to files in the repository.
- Source manifests are now recorded per dependency instead of being dropped.

### Changed

- All outbound requests go through one HTTP layer with retry and exponential
  backoff on transient failures.

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
