# Security policy

## Reporting a vulnerability

If you find a security issue in shouldibump itself, please **do not open a
public issue**. Instead, use GitHub's private
[security advisory](https://github.com/theadvay/shouldibump/security/advisories/new)
form, or email the maintainer directly.

Please include:

- what the issue is and how it can be triggered,
- the version (`shouldibump --version`),
- and any proof-of-concept input.

You can expect an acknowledgement within a few days.

## Scope

shouldibump makes outbound HTTPS requests to `pypi.org`, `registry.npmjs.org`
and `api.osv.dev`, and reads dependency manifests from your local disk. It does
not execute your project's code, run package installs, or write to your files.

Reports about the *accuracy* of a vulnerability result (for example, a finding
that OSV does not actually list) are still useful — open a normal issue for
those.
