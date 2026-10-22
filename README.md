# shouldibump

**Know which dependencies are actually worth updating — and what might break.**

One command. Zero dependencies. No config file.

`shouldibump` reads your dependency manifests, asks PyPI and npm what the latest
versions are, scores how risky each upgrade is, and checks the [OSV](https://osv.dev)
database for known vulnerabilities — then prints a single table you can act on.

```console
$ shouldibump
```

```text
shouldibump  ·  which dependencies are worth updating

  target   .
  scanned  requirements.txt

  PACKAGE   CURRENT  LATEST  BUMP   RISK      NOTE
  ────────  ───────  ──────  ─────  ────────  ──────────────────────────────────
  django    3.2.18   6.1.2   major  CRITICAL  2 known vulnerabilities
  pyyaml    5.3.1    6.0.3   major  HIGH      breaking changes likely
  urllib3   1.26.18  2.8.0   major  HIGH      breaking changes likely
  requests  2.28.1   2.34.2  minor  LOW       new features, backwards compatible
  click     8.1.7    8.1.7   —      —         up to date

  4 to update · 1 with known vulnerabilities · 3 high risk · 1 up to date
```

## Why

"Update your dependencies" is easy advice and a terrible chore. The hard part
isn't *finding* newer versions — it's deciding **which ones are worth the risk
this week**. A patch bump you can merge blind. A major bump across three
packages the day before a release is how you lose a weekend.

`shouldibump` gives you the short list, sorted by what actually needs attention.

## Install

```bash
pip install git+https://github.com/theadvay/shouldibump
```

Or from a clone:

```bash
git clone https://github.com/theadvay/shouldibump
cd shouldibump
pip install .
```

`shouldibump` is not on PyPI yet — until it is, use one of the commands above.

Python 3.9+ and no third-party packages. (On 3.9/3.10, reading `pyproject.toml`
additionally needs `pip install tomli`; the other manifest types work as-is.)

## Usage

```bash
shouldibump                      # scan the current directory
shouldibump ./backend            # scan a specific project
shouldibump requirements.txt     # scan a single file
shouldibump --only-outdated      # hide everything that is already current
shouldibump --no-dev             # skip dev / optional dependencies
shouldibump --no-vulns           # skip the vulnerability check
shouldibump --ignore django,pyyaml
shouldibump --json               # machine-readable output
```

It auto-detects `requirements*.txt`, `pyproject.toml` (PEP 621 **and** Poetry)
and `package.json` (npm / pnpm / yarn).

### In CI

Fail the build only when something genuinely dangerous shows up:

```yaml
- run: pip install shouldibump
- run: shouldibump --fail-on high
```

`--fail-on` accepts `none`, `low`, `medium`, `high` or `critical`, and exits with
status `1` when any dependency reaches that level. Default is `none` (never fails).

## How the risk score works

| Signal | Risk |
| --- | --- |
| A known vulnerability affects the current version | **high** / **critical** |
| Major version bump | **high** |
| Minor bump while the package is still `0.x` (semver lets those break) | **high** |
| Minor version bump on a `1.x`+ package | **medium** |
| Patch / pre-release bump | **low** |
| Already current, no known issues | **none** |

The final score is the worst of the signals. The version comparison understands
both PEP 440 and SemVer, including pre-releases (`2.0.0rc1 < 2.0.0`) and
numeric ordering (`1.10.0 > 1.9.0`).

## A note on honesty

Vulnerability checks run against a **resolved** version. If a requirement only
declares a range (`flask>=2.0`), `shouldibump` first tries the version installed
in your environment, and falls back to reporting the bump without a
vulnerability check rather than guessing. It would rather say less than be wrong.

If the OSV lookup itself cannot be reached (an offline machine, a restrictive
proxy), the report says so explicitly at the bottom instead of quietly implying
"no known vulnerabilities".

## Contributing

Issues and PRs are welcome. To run the tests:

```bash
pip install -e ".[test]"
pytest
```

## License

[MIT](LICENSE)
