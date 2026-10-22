"""Look up the latest published version of a package.

Uses the public PyPI and npm registry JSON APIs. No keys, no dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

__all__ = ["latest_version", "RegistryError"]

_USER_AGENT = f"shouldibump/{__version__} (+https://github.com/theadvay/shouldibump)"


class RegistryError(RuntimeError):
    """Raised when a registry cannot be reached or answers with an error."""


def _get_json(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # package does not exist on this registry
        raise RegistryError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RegistryError(f"network error: {exc.reason}") from exc


def latest_pypi(name, timeout=10):
    """Latest stable version on PyPI, or ``None`` if the package is unknown."""
    data = _get_json(
        "https://pypi.org/pypi/{}/json".format(urllib.parse.quote(name)), timeout
    )
    if not data:
        return None
    return (data.get("info") or {}).get("version")


def latest_npm(name, timeout=10):
    """Latest version on the npm registry, or ``None`` if the package is unknown."""
    data = _get_json(
        "https://registry.npmjs.org/{}".format(urllib.parse.quote(name, safe="@")),
        timeout,
    )
    if not data:
        return None
    return (data.get("dist-tags") or {}).get("latest")


def latest_version(name, ecosystem, timeout=10):
    """Dispatch to the right registry for *ecosystem*."""
    if ecosystem == "pypi":
        return latest_pypi(name, timeout)
    if ecosystem == "npm":
        return latest_npm(name, timeout)
    raise RegistryError(f"unsupported ecosystem: {ecosystem}")
