"""Tests for risk scoring, merging, discovery and the scan pipeline."""

import os

from shouldibump import scan as scanner
from shouldibump.models import Finding, Vuln


def test_risk_from_bump_size():
    assert scanner.compute_risk("major", "1.0.0", []) == "high"
    assert scanner.compute_risk("minor", "1.9.0", []) == "medium"
    assert scanner.compute_risk("patch", "1.0.0", []) == "low"
    assert scanner.compute_risk("none", "1.0.0", []) == "none"


def test_zero_major_minor_bump_is_high_risk():
    assert scanner.compute_risk("minor", "0.9.0", []) == "high"


def test_vulnerabilities_raise_risk():
    assert scanner.compute_risk("patch", "1.0.0", [Vuln(id="a", severity="HIGH")]) == "high"
    assert scanner.compute_risk("patch", "1.0.0", [Vuln(id="a", severity="CRITICAL")]) == "critical"


def test_vuln_without_severity_still_serious():
    assert scanner.compute_risk("none", "1.0.0", [Vuln(id="OSV-1")]) == "high"


def test_build_note():
    assert "breaking" in scanner.build_note(Finding(name="x", ecosystem="pypi", bump="major"))
    assert "0.x" in scanner.build_note(
        Finding(name="x", ecosystem="pypi", bump="minor", current="0.4.0")
    )
    assert (
        scanner.build_note(Finding(name="x", ecosystem="pypi", bump="patch", vulns=[Vuln(id="A")]))
        == "1 known vulnerability"
    )
    assert scanner.build_note(Finding(name="x", ecosystem="pypi", bump="none")) == "up to date"


def test_discover_orders_manifests(tmp_path):
    for name in ("package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt"):
        (tmp_path / name).write_text("")
    names = [os.path.basename(p) for p in scanner.discover(str(tmp_path))]
    assert names == ["requirements-dev.txt", "requirements.txt", "pyproject.toml", "package.json"]


def test_discover_single_file_and_missing(tmp_path):
    target = tmp_path / "requirements.txt"
    target.write_text("")
    assert scanner.discover(str(target)) == [str(target)]
    assert scanner.discover(str(tmp_path / "nope")) == []


def test_merge_duplicates_prefers_exact_version():
    deps = [
        {
            "name": "Flask",
            "ecosystem": "pypi",
            "spec": ">=2.0",
            "current": "2.0",
            "exact": False,
            "source": "a.txt",
        },
        {
            "name": "flask",
            "ecosystem": "pypi",
            "spec": "==2.3.0",
            "current": "2.3.0",
            "exact": True,
            "source": "b.txt",
        },
    ]
    merged = scanner.merge_duplicates(deps)
    assert len(merged) == 1
    assert merged[0]["current"] == "2.3.0"
    assert merged[0]["exact"] is True
    assert merged[0]["sources"] == ["a.txt", "b.txt"]


def test_merge_duplicates_keeps_distinct_ecosystems():
    deps = [
        {"name": "foo", "ecosystem": "pypi", "source": "a"},
        {"name": "foo", "ecosystem": "npm", "source": "b"},
    ]
    assert len(scanner.merge_duplicates(deps)) == 2


def _stub_network(monkeypatch, latest, vulns=None):
    monkeypatch.setattr(
        scanner.registry,
        "latest_version",
        lambda name, ecosystem, timeout=10.0: latest.get(name),
    )
    monkeypatch.setattr(
        scanner.osv,
        "query_osv",
        lambda name, ecosystem, version, timeout=10.0: (vulns or {}).get(name, []),
    )


def test_scan_end_to_end(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\nrequests==2.28.1\n")
    _stub_network(
        monkeypatch,
        latest={"django": "5.0.0", "requests": "2.28.1"},
        vulns={"django": [Vuln(id="CVE-1", severity="HIGH")]},
    )
    findings, paths, meta = scanner.scan(str(tmp_path), check_vulns=True)
    by_name = {f.name: f for f in findings}

    assert by_name["django"].vulnerable
    assert by_name["django"].risk == "high"
    assert by_name["django"].sources == [str(tmp_path / "requirements.txt")]
    assert by_name["requests"].bump == "none"
    assert meta == {"vuln_attempted": 2, "vuln_failed": 0}
    # Highest risk first
    assert findings[0].name == "django"


def test_scan_records_lookup_failure(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("ghost==1.0.0\n")
    _stub_network(monkeypatch, latest={"ghost": None})
    findings, _, _ = scanner.scan(str(tmp_path))
    assert findings[0].error == "not found on registry"
    assert findings[0].risk == "unknown"


def test_scan_records_vuln_failure(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("pkg==1.0.0\n")
    monkeypatch.setattr(
        scanner.registry,
        "latest_version",
        lambda name, ecosystem, timeout=10.0: "2.0.0",
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("OSV unreachable")

    monkeypatch.setattr(scanner.osv, "query_osv", boom)
    _, _, meta = scanner.scan(str(tmp_path), check_vulns=True)
    assert meta["vuln_failed"] == 1


def test_scan_empty_project(tmp_path, monkeypatch):
    findings, paths, meta = scanner.scan(str(tmp_path))
    assert findings == []
    assert paths == []
    assert meta["vuln_attempted"] == 0
