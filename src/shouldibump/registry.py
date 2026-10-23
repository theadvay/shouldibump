"""Look up the latest published version of a package.

Uses the public PyPI and npm registry JSON APIs. No keys, no dependencies.
For PyPI we also ignore releases whose files have all been yanked, so we never
nudge someone onto a version the maintainer has pulled.
"""

from __future__ import annotations

import urllib.parse

from . import http
from .versions import parse_version

__all__ = ["latest_version", "latest_pypi", "latest_npm", "RegistryError"]

#: Backwards-compatible alias for the error type callers used to catch.
RegistryError = http.HttpError

_PYPI_URL = "https://pypi.org/pypi/{}/json"
_NPM_URL = "https://registry.npmjs.org/{}"


def _fully_yanked(files):
    return bool(files) and all(bool(item.get("yanked")) for item in files)


def _pick_stable(versions):
    """Return the highest version, preferring final releases over pre-releases."""
    parsed = [(v, parse_version(v)) for v in versions]
    parsed = [(v, key) for v, key in parsed if key is not None]
    if not parsed:
        return None
    finals = [(v, key) for v, key in parsed if key[2] == (1, 0, 0)]
    pool = finals or parsed
    return max(pool, key=lambda item: item[1])[0]


def latest_pypi(name, timeout=10.0):
    """Latest stable version on PyPI, or ``None`` if the package is unknown."""
    data = http.get_json(_PYPI_URL.format(urllib.parse.quote(name)), timeout=timeout)
    if not data:
        return None

    info = data.get("info") or {}
    declared = info.get("version")
    releases = data.get("releases") or {}

    usable = [v for v, files in releases.items() if files and not _fully_yanked(files)]
    if not usable:
        return declared
    if declared in usable:
        # PyPI's own idea of "latest" wins when it is not yanked.
        return declared
    return _pick_stable(usable) or declared


def latest_npm(name, timeout=10.0):
    """Latest version on the npm registry, or ``None`` if the package is unknown."""
    data = http.get_json(_NPM_URL.format(urllib.parse.quote(name, safe="@")), timeout=timeout)
    if not data:
        return None
    return (data.get("dist-tags") or {}).get("latest")


def latest_version(name, ecosystem, timeout=10.0):
    """Dispatch to the right registry for *ecosystem*."""
    if ecosystem == "pypi":
        return latest_pypi(name, timeout)
    if ecosystem == "npm":
        return latest_npm(name, timeout)
    raise http.HttpError(f"unsupported ecosystem: {ecosystem}")
