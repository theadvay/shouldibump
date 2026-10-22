"""Tests for risk scoring and reporting (no network access)."""

from shouldibump.models import Vuln
from shouldibump.report import Style, render_table
from shouldibump.scan import build_note, compute_risk


def test_risk_from_bump_size():
    assert compute_risk("major", "1.0.0", []) == "high"
    assert compute_risk("minor", "1.9.0", []) == "medium"
    assert compute_risk("patch", "1.0.0", []) == "low"
    assert compute_risk("none", "1.0.0", []) == "none"


def test_zero_major_minor_bump_is_high_risk():
    # Under 0.x, semver allows a minor bump to be breaking.
    assert compute_risk("minor", "0.9.0", []) == "high"


def test_vulnerabilities_raise_risk():
    high = [Vuln(id="GHSA-x", severity="HIGH")]
    critical = [Vuln(id="GHSA-y", severity="CRITICAL")]
    assert compute_risk("patch", "1.0.0", high) == "high"
    assert compute_risk("patch", "1.0.0", critical) == "critical"


def test_vuln_without_severity_still_serious():
    assert compute_risk("none", "1.0.0", [Vuln(id="OSV-1")]) == "high"


def test_table_alignment_ignores_ansi():
    style = Style(enabled=True)
    table = render_table(["A", "B"], [[style.red("longer"), "x"], ["s", "y"]])
    lines = table.splitlines()
    # Every row must have the same visible width.
    import re

    stripped = [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in lines]
    assert len({len(line) for line in stripped}) == 1


def test_build_note():
    from shouldibump.models import Finding

    assert "breaking" in build_note(Finding(name="x", ecosystem="pypi", bump="major"))
    assert "0.x" in build_note(
        Finding(name="x", ecosystem="pypi", bump="minor", current="0.4.0")
    )
    assert build_note(
        Finding(name="x", ecosystem="pypi", bump="patch", vulns=[Vuln(id="A")])
    ) == "1 known vulnerability"
