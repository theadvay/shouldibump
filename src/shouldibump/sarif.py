"""Build a SARIF 2.1.0 report so CI code-scanning can ingest our results.

Works with GitHub code scanning (``github/codeql-action/upload-sarif``) and
any other tool that understands SARIF.
"""

from __future__ import annotations

import os

from . import __version__

__all__ = ["build_sarif"]

#: Only findings at this risk rank or above are worth reporting to a scanner.
_MIN_RANK = 2  # "medium"

_RULES = [
    {
        "id": "vulnerable-dependency",
        "name": "VulnerableDependency",
        "shortDescription": {"text": "Dependency has a known vulnerability"},
        "helpUri": "https://osv.dev",
        "properties": {"tags": ["security", "dependencies"]},
    },
    {
        "id": "outdated-dependency",
        "name": "OutdatedDependency",
        "shortDescription": {"text": "Dependency is a risky number of versions behind"},
        "helpUri": "https://github.com/theadvay/shouldibump",
        "properties": {"tags": ["maintainability", "dependencies"]},
    },
]

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _level(finding):
    if finding.vulnerable:
        return "error"
    return _LEVEL.get(finding.risk, "note")


def _message(finding):
    current = finding.current or finding.spec or "?"
    latest = finding.latest or "?"
    detail = finding.note or finding.risk
    return f"{finding.name} {current} → {latest}: {detail}"


def _relative_uri(source, target):
    """Make a manifest path relative to the scan root, as SARIF expects."""
    if not source:
        return source
    base = target
    if base and os.path.isfile(base):
        base = os.path.dirname(base)
    try:
        relative = os.path.relpath(source, base or ".")
    except ValueError:  # pragma: no cover - e.g. different drives on Windows
        return source
    return relative.replace(os.sep, "/")


def build_sarif(findings, target=None):
    """Return a SARIF document (a plain dict) for *findings*."""
    results = []
    for finding in findings:
        if not (finding.vulnerable or finding.risk_rank >= _MIN_RANK):
            continue

        result = {
            "ruleId": ("vulnerable-dependency" if finding.vulnerable else "outdated-dependency"),
            "level": _level(finding),
            "message": {"text": _message(finding)},
        }
        if finding.sources:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _relative_uri(finding.sources[0], target)}
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shouldibump",
                        "version": __version__,
                        "informationUri": "https://github.com/theadvay/shouldibump",
                        "rules": _RULES,
                    }
                },
                "results": results,
            }
        ],
    }
