"""Query the OSV.dev database for known vulnerabilities.

OSV is a free, open, aggregated vulnerability database (Google-maintained)
covering PyPI and npm among many others. The batch/query API needs no key.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__
from .models import Vuln

__all__ = ["query_osv", "severity_rank"]

_API = "https://api.osv.dev/v1/query"
_USER_AGENT = f"shouldibump/{__version__} (+https://github.com/theadvay/shouldibump)"

_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}


def severity_rank(text):
    """Map a free-text severity label to a 0-4 rank."""
    lowered = (text or "").lower()
    if "critical" in lowered:
        return 4
    if "high" in lowered:
        return 3
    if "moderate" in lowered or "medium" in lowered:
        return 2
    if "low" in lowered:
        return 1
    return 0


def _fixed_version(vuln):
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _to_vuln(raw):
    severity = ""
    for entry in raw.get("severity") or []:
        if str(entry.get("type", "")).upper().startswith("CVSS"):
            severity = entry.get("score", "")
            break
    if not severity:
        database = raw.get("database_specific") or {}
        severity = database.get("severity", "") or ""

    summary = raw.get("summary") or (raw.get("details") or "").strip().split("\n")[0]
    return Vuln(
        id=raw.get("id", ""),
        summary=summary[:160],
        severity=str(severity),
        fixed=_fixed_version(raw),
    )


def query_osv(name, ecosystem, version, timeout=10):
    """Return a list of :class:`Vuln` affecting ``name==version``.

    Raises on network trouble; callers decide whether that is fatal.
    """
    osv_ecosystem = _ECOSYSTEM.get(ecosystem)
    if osv_ecosystem is None:
        return []

    payload = {"package": {"name": name, "ecosystem": osv_ecosystem}}
    if version:
        payload["version"] = version

    request = urllib.request.Request(
        _API,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "User-Agent": _USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"OSV HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OSV network error: {exc.reason}") from exc

    return [_to_vuln(item) for item in data.get("vulns") or []]
