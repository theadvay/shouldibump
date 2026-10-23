"""Tests for the SARIF exporter."""

from shouldibump.models import Finding, Vuln
from shouldibump.sarif import build_sarif


def _finding(**overrides):
    base = dict(
        name="pkg",
        ecosystem="pypi",
        current="1.0.0",
        latest="2.0.0",
        bump="major",
        risk="high",
        note="breaking changes likely",
        sources=["requirements.txt"],
    )
    base.update(overrides)
    return Finding(**base)


def test_document_shape():
    doc = build_sarif([_finding()])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "shouldibump"
    assert len(doc["runs"][0]["results"]) == 1


def test_low_risk_is_not_reported():
    doc = build_sarif([_finding(risk="low", bump="patch")])
    assert doc["runs"][0]["results"] == []


def test_medium_risk_is_a_warning():
    doc = build_sarif([_finding(risk="medium", bump="minor")])
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "outdated-dependency"
    assert result["level"] == "warning"


def test_vulnerable_is_an_error():
    finding = _finding(risk="low", vulns=[Vuln(id="CVE-1", severity="HIGH")])
    result = build_sarif([finding])["runs"][0]["results"][0]
    assert result["ruleId"] == "vulnerable-dependency"
    assert result["level"] == "error"


def test_location_points_at_manifest():
    result = build_sarif([_finding()])["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "requirements.txt"


def test_message_mentions_versions():
    result = build_sarif([_finding()])["runs"][0]["results"][0]
    assert "1.0.0" in result["message"]["text"]
    assert "2.0.0" in result["message"]["text"]


def test_finding_without_sources_has_no_location():
    result = build_sarif([_finding(sources=[])])["runs"][0]["results"][0]
    assert "locations" not in result


def test_location_is_relative_to_target(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("")
    finding = _finding(sources=[str(manifest)])
    result = build_sarif([finding], str(tmp_path))["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "requirements.txt"
