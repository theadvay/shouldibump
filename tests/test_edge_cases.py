"""Extra edge-case coverage for versions, scan and reporting."""

from shouldibump import scan as scanner
from shouldibump.models import Finding, Vuln
from shouldibump.report import Style, render, render_markdown
from shouldibump.versions import compare, major_of, parse_version


# --------------------------------------------------------------------------- #
# versions
# --------------------------------------------------------------------------- #
def test_epoch_beats_release():
    assert compare("1!1.0.0", "2.0.0") == 1
    assert parse_version("1!2.0")[0] == 1


def test_post_release_sorts_above_final():
    assert compare("1.0.0.post1", "1.0.0") == 1


def test_dev_release_sorts_below_prerelease():
    assert compare("1.0.0.dev1", "1.0.0a1") == -1


def test_build_metadata_ignored():
    assert compare("1.0.0+build5", "1.0.0") == 0


def test_non_numeric_versions_are_unparseable():
    assert parse_version("abc") is None
    assert parse_version("") is None
    assert parse_version(None) is None
    assert compare("abc", "1.0.0") is None


def test_version_with_letters_only_after_digits():
    # e.g. an "r2" style build tag still yields a usable ordering
    assert parse_version("r2") == parse_version("2")


def test_major_of_missing():
    assert major_of("") is None


# --------------------------------------------------------------------------- #
# scan helpers
# --------------------------------------------------------------------------- #
def test_build_note_error():
    assert (
        scanner.build_note(Finding(name="x", ecosystem="pypi", error="lookup failed"))
        == "lookup failed"
    )


def test_build_note_branches():
    assert scanner.build_note(Finding(name="x", ecosystem="pypi", bump="patch")) == "bug fixes only"
    assert (
        scanner.build_note(Finding(name="x", ecosystem="pypi", bump="prerelease"))
        == "pre-release only"
    )
    assert "backwards compatible" in scanner.build_note(
        Finding(name="x", ecosystem="pypi", bump="minor", current="1.2.0")
    )
    assert scanner.build_note(Finding(name="x", ecosystem="pypi", bump="weird")) == ""


def test_installed_pypi_missing_package_is_none():
    assert scanner._installed_pypi("definitely-not-a-real-package-xyz-123") is None


def test_installed_npm_used_when_unpinned(tmp_path, monkeypatch):
    node = tmp_path / "node_modules" / "left-pad"
    node.mkdir(parents=True)
    (node / "package.json").write_text('{"version": "1.3.0"}')
    (tmp_path / "package.json").write_text('{"dependencies": {"left-pad": "^1.0.0"}}')

    monkeypatch.setattr(
        scanner.registry,
        "latest_version",
        lambda name, ecosystem, timeout=10.0: "1.3.0",
    )
    monkeypatch.setattr(
        scanner.osv,
        "query_osv",
        lambda name, ecosystem, version, timeout=10.0: [],
    )
    findings, _, _ = scanner.scan(str(tmp_path))
    assert findings[0].current == "1.3.0"
    assert findings[0].exact is True


def test_installed_npm_missing_is_none(tmp_path):
    assert scanner._installed_npm("nope", str(tmp_path)) is None
    assert scanner._installed_npm("nope", None) is None


def test_enrich_accepts_plain_source_key():
    finding = scanner.enrich(
        {
            "name": "pkg",
            "ecosystem": "pypi",
            "current": "1.0.0",
            "exact": True,
            "source": "requirements.txt",
        },
        check_vulns=False,
    )
    assert finding.sources == ["requirements.txt"]


# --------------------------------------------------------------------------- #
# report edge cases
# --------------------------------------------------------------------------- #
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


def test_render_unknown_risk_and_group_suffix():
    text = render(
        [_finding(risk="unknown", bump="unknown", group="dev", note="lookup failed")],
        ["r.txt"],
        Style(False),
    )
    assert "(dev)" in text
    assert "?" in text


def test_render_vulnerable_note_is_coloured():
    text = render(
        [_finding(vulns=[Vuln(id="X")], note="1 known vulnerability")], ["r.txt"], Style(True)
    )
    assert "\x1b[" in text


def test_render_partial_vuln_warning():
    text = render(
        [_finding()], ["r.txt"], Style(False), meta={"vuln_attempted": 3, "vuln_failed": 1}
    )
    assert "failed for 1 of 3" in text


def test_markdown_only_outdated():
    current = _finding(
        name="fresh", current="2.0.0", latest="2.0.0", bump="none", risk="none", note="up to date"
    )
    md = render_markdown([_finding(), current], ["r.txt"], only_outdated=True)
    assert "fresh" not in md


def test_markdown_group_suffix():
    assert "pkg (dev)" in render_markdown([_finding(group="dev")], ["r.txt"])


def test_markdown_all_current():
    current = _finding(
        name="fresh", current="2.0.0", latest="2.0.0", bump="none", risk="none", note="up to date"
    )
    md = render_markdown([current], ["r.txt"], only_outdated=True)
    assert "Nothing to do" in md
