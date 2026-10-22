"""Orchestration: discover manifests, look things up, and score each dependency."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

from . import osv, parsers, registry
from .models import RISK_BY_RANK, RISK_ORDER, Finding
from .versions import classify_bump, major_of

__all__ = ["discover", "scan", "enrich", "compute_risk", "MANIFESTS"]

MANIFESTS = ("requirements.txt", "pyproject.toml", "package.json")

# The risk implied by the size of the version jump alone.
_BUMP_RISK = {
    "major": "high",
    "minor": "medium",
    "patch": "low",
    "prerelease": "low",
    "none": "none",
    "unknown": "unknown",
}

_MANIFEST_ORDER = {"requirements": 0, "pyproject": 1, "package": 2}


def discover(target):
    """Return the manifest paths to read for *target* (a file or a directory)."""
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        return []

    found = []
    for name in os.listdir(target):
        if name in ("pyproject.toml", "package.json") or (
            name.startswith("requirements") and name.endswith(".txt")
        ):
            found.append(os.path.join(target, name))

    def rank(path):
        base = os.path.basename(path)
        key = base.split("-")[0].split(".")[0]
        return (_MANIFEST_ORDER.get(key, 9), base)

    return sorted(found, key=rank)


def _installed_pypi(name):
    """Best-effort: the version installed in the current environment, if any."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except Exception:  # pragma: no cover
        return None
    for candidate in (name, name.replace("_", "-").lower()):
        try:
            return version(candidate)
        except Exception:
            continue
    return None


def _installed_npm(name, root):
    """Best-effort: the version present in node_modules, if any."""
    if not root:
        return None
    path = os.path.join(root, "node_modules", *name.split("/"), "package.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return (json.load(handle) or {}).get("version")
    except Exception:
        return None


def compute_risk(bump, current, vulns):
    """Combine the bump size and any known vulnerabilities into one risk level."""
    risk = _BUMP_RISK.get(bump, "unknown")
    if bump == "minor" and major_of(current) == 0:
        risk = "high"  # under 0.x, a "minor" bump is allowed to break things

    rank = RISK_ORDER.get(risk, -1)
    vuln_rank = max((osv.severity_rank(v.severity) for v in vulns), default=0)
    if vulns and vuln_rank == 0:
        vuln_rank = 3  # a vulnerability with no severity data is still serious
    if vuln_rank > rank:
        rank = vuln_rank

    return RISK_BY_RANK.get(rank, "unknown")


def build_note(finding):
    """A short human hint for the NOTE column."""
    if finding.error:
        return finding.error
    if finding.vulns:
        count = len(finding.vulns)
        return f"{count} known {'vulnerability' if count == 1 else 'vulnerabilities'}"
    if finding.bump == "major":
        return "breaking changes likely"
    if finding.bump == "minor":
        if major_of(finding.current) == 0:
            return "0.x: minor may break"
        return "new features, backwards compatible"
    if finding.bump == "patch":
        return "bug fixes only"
    if finding.bump == "prerelease":
        return "pre-release only"
    if finding.bump == "none":
        return "up to date"
    return ""


def enrich(dep, timeout=10.0, check_vulns=True, root=None):
    """Turn a parsed dependency dict into a scored :class:`Finding`."""
    finding = Finding(
        name=dep["name"],
        ecosystem=dep["ecosystem"],
        spec=dep.get("spec", ""),
        current=dep.get("current"),
        group=dep.get("group", "main"),
        source=dep.get("source", ""),
        exact=bool(dep.get("exact")),
    )

    # If we only have a declared floor, try the environment / node_modules.
    if not finding.exact:
        installed = (
            _installed_pypi(finding.name)
            if finding.ecosystem == "pypi"
            else _installed_npm(finding.name, root)
        )
        if installed:
            finding.current = installed
            finding.exact = True

    try:
        finding.latest = registry.latest_version(
            finding.name, finding.ecosystem, timeout
        )
    except Exception as exc:
        finding.error = f"lookup failed ({exc})"

    if finding.latest is None and not finding.error:
        finding.error = "not found on registry"

    if finding.latest and finding.current:
        finding.bump = classify_bump(finding.current, finding.latest)

    if check_vulns and finding.exact and finding.current:
        try:
            finding.vulns = osv.query_osv(
                finding.name, finding.ecosystem, finding.current, timeout
            )
        except Exception as exc:
            # Best-effort: never fatal, but record it so the report can say so
            # rather than implying "no known vulnerabilities".
            finding.vuln_error = str(exc)

    finding.risk = compute_risk(finding.bump, finding.current, finding.vulns)
    finding.note = build_note(finding)
    return finding


def _sort_key(finding):
    # Risk first, then known vulns, then anything outdated, then name.
    return (
        -finding.risk_rank,
        0 if finding.vulnerable else 1,
        0 if finding.outdated else 1,
        finding.name.lower(),
    )


def scan(target=".", timeout=10.0, jobs=8, check_vulns=True, include_dev=True):
    """Scan *target* and return ``(findings, manifest_paths)``."""
    paths = discover(target)
    deps = parsers.collect_dependencies(paths, include_dev=include_dev)

    root = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(target))

    findings = []
    if deps:
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            futures = [
                pool.submit(enrich, dep, timeout, check_vulns, root) for dep in deps
            ]
            for future in futures:
                findings.append(future.result())

    findings.sort(key=_sort_key)

    meta = {
        "vuln_attempted": sum(
            1 for f in findings if check_vulns and f.exact and f.current
        ),
        "vuln_failed": sum(1 for f in findings if f.vuln_error),
    }
    return findings, paths, meta
