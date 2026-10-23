# Contributing to shouldibump

Thanks for wanting to help. Bug reports, fixes, and new manifest parsers are
all welcome.

## Getting set up

```bash
git clone https://github.com/theadvay/shouldibump
cd shouldibump
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]" ruff
```

## Running the checks

Everything CI runs, you can run locally:

```bash
ruff check .           # lint
ruff format --check .  # formatting
pytest --cov=shouldibump --cov-report=term-missing
```

Please make sure all three pass before opening a pull request.

## Guidelines

- **Keep it dependency-free.** The whole point of this tool is that installing
  it never pulls in anything else. Use the standard library.
- **Test the network code without the network.** All HTTP goes through
  `shouldibump/http.py`; tests monkeypatch that module. No test should make a
  real request.
- **Add a test for every behaviour change.** The suite is the contract.
- **Keep the output clean.** The table is the product — if a change makes it
  noisier, it needs a good reason.
- One logical change per pull request.

## Adding a new manifest type

1. Add a parser in `src/shouldibump/parsers.py` returning dicts shaped like the
   existing ones.
2. Teach `scan.discover()` which filename to look for.
3. Add tests in `tests/test_parsers.py`.
4. Update the README's supported-manifests list.

## Reporting a bug

Open an issue with the output of `shouldibump --version`, the manifest that
triggered it (redacted if needed), and what you expected to see.
