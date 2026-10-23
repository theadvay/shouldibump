"""End-to-end tests for the CLI, with the network layer stubbed out."""

import json

import pytest

from shouldibump import __version__, cli
from shouldibump.models import Finding, Vuln


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


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project directory with a stubbed scan pipeline."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("pkg==1.0.0\n")

    def fake_scan(target, **_kwargs):
        return (
            [_finding()],
            [str(manifest)],
            {"vuln_attempted": 1, "vuln_failed": 0},
        )

    monkeypatch.setattr(cli.scanner, "scan", fake_scan)
    return tmp_path


def test_default_table_output(project, capsys):
    assert cli.main([str(project)]) == 0
    assert "pkg" in capsys.readouterr().out


def test_json_output(project, capsys):
    assert cli.main([str(project), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "shouldibump"
    assert data["version"] == __version__
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["name"] == "pkg"
    assert data["findings"][0]["sources"] == ["requirements.txt"]


def test_markdown_output(project, capsys):
    assert cli.main([str(project), "--format", "markdown"]) == 0
    assert "| Package | Current |" in capsys.readouterr().out


def test_sarif_output(project, capsys):
    assert cli.main([str(project), "--format", "sarif"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_fail_on_threshold(project, capsys):
    assert cli.main([str(project), "--fail-on", "high"]) == 1
    assert cli.main([str(project), "--fail-on", "critical"]) == 0
    assert cli.main([str(project), "--fail-on", "none"]) == 0


def test_fail_on_vulnerable(project, monkeypatch, capsys):
    monkeypatch.setattr(
        cli.scanner,
        "scan",
        lambda target, **kw: (
            [_finding(risk="critical", vulns=[Vuln(id="CVE-1", severity="CRITICAL")])],
            ["requirements.txt"],
            {"vuln_attempted": 1, "vuln_failed": 0},
        ),
    )
    assert cli.main([str(project), "--fail-on", "critical"]) == 1


def test_ignore_flag(project, capsys):
    assert cli.main([str(project), "--json", "--ignore", "pkg"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["total"] == 0


def test_ignore_accepts_comma_list(project, capsys):
    assert cli.main([str(project), "--json", "--ignore", "a,b,pkg"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["total"] == 0


def test_missing_path_returns_2(capsys):
    assert cli.main(["/definitely/not/here"]) == 2


def test_empty_directory_returns_2(tmp_path, capsys):
    assert cli.main([str(tmp_path)]) == 2


def test_invalid_jobs_is_a_usage_error(project):
    with pytest.raises(SystemExit) as excinfo:
        cli.main([str(project), "--jobs", "0"])
    assert excinfo.value.code == 2


def test_invalid_timeout_is_a_usage_error(project):
    with pytest.raises(SystemExit):
        cli.main([str(project), "--timeout", "0"])


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_color_env_is_respected(project, monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    cli.main([str(project)])
    assert "\x1b[" not in capsys.readouterr().out
