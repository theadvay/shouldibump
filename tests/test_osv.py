"""Tests for the OSV vulnerability client (network mocked out)."""

from shouldibump import http, osv


def _patch(monkeypatch, payload):
    monkeypatch.setattr(http, "post_json", lambda url, body, timeout=10.0: payload)


def test_parses_vulnerabilities(monkeypatch):
    _patch(
        monkeypatch,
        {
            "vulns": [
                {
                    "id": "GHSA-aaaa",
                    "summary": "Something bad",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "affected": [
                        {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
                    ],
                }
            ]
        },
    )
    vulns = osv.query_osv("pkg", "pypi", "1.0.0")
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-aaaa"
    assert vulns[0].summary == "Something bad"
    assert vulns[0].severity == "9.8"
    assert vulns[0].fixed == "2.0.0"


def test_falls_back_to_database_severity(monkeypatch):
    _patch(monkeypatch, {"vulns": [{"id": "X", "database_specific": {"severity": "HIGH"}}]})
    assert osv.query_osv("pkg", "npm", "1.0.0")[0].severity == "HIGH"


def test_no_vulns(monkeypatch):
    _patch(monkeypatch, {"vulns": []})
    assert osv.query_osv("pkg", "pypi", "1.0.0") == []


def test_missing_vulns_key(monkeypatch):
    _patch(monkeypatch, {})
    assert osv.query_osv("pkg", "pypi", "1.0.0") == []


def test_unknown_ecosystem_short_circuits():
    assert osv.query_osv("pkg", "cargo", "1.0.0") == []


def test_severity_rank():
    assert osv.severity_rank("CRITICAL") == 4
    assert osv.severity_rank("High") == 3
    assert osv.severity_rank("moderate") == 2
    assert osv.severity_rank("low") == 1
    assert osv.severity_rank("") == 0
    assert osv.severity_rank(None) == 0


def test_summary_truncated(monkeypatch):
    _patch(monkeypatch, {"vulns": [{"id": "X", "summary": "y" * 500}]})
    assert len(osv.query_osv("pkg", "pypi", "1.0.0")[0].summary) == 160
