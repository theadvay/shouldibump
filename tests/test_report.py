"""Tests for the terminal and Markdown renderers."""

import re

from shouldibump.models import Finding, Vuln
from shouldibump.report import Style, render, render_markdown, render_table

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


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


def test_table_columns_align_ignoring_ansi():
    style = Style(enabled=True)
    table = render_table(["A", "B"], [[style.red("longer"), "x"], ["s", "y"]])
    widths = {len(_ANSI.sub("", line)) for line in table.splitlines()}
    assert len(widths) == 1


def test_render_lists_findings():
    text = render([_finding()], ["requirements.txt"], Style(False), target=".")
    assert "pkg" in text
    assert "2.0.0" in text
    assert "HIGH" in text


def test_render_only_outdated_hides_current():
    current = _finding(
        name="fresh", current="2.0.0", latest="2.0.0", bump="none", risk="none", note="up to date"
    )
    text = render([_finding(), current], ["r.txt"], Style(False), only_outdated=True)
    assert "pkg" in text
    assert "fresh" not in text


def test_render_all_current_message():
    current = _finding(
        name="fresh", current="2.0.0", latest="2.0.0", bump="none", risk="none", note="up to date"
    )
    text = render([current], ["r.txt"], Style(False), only_outdated=True)
    assert "Nothing to do" in text


def test_render_vuln_warning():
    text = render(
        [_finding()], ["r.txt"], Style(False), meta={"vuln_attempted": 3, "vuln_failed": 3}
    )
    assert "vulnerability lookup failed for all 3" in text


def test_render_no_warning_when_none_failed():
    text = render(
        [_finding()], ["r.txt"], Style(False), meta={"vuln_attempted": 3, "vuln_failed": 0}
    )
    assert "note:" not in text


def test_style_can_be_disabled():
    assert Style(False).red("x") == "x"
    assert "\x1b[" in Style(True).red("x")


def test_markdown_has_table_and_summary():
    md = render_markdown([_finding()], ["requirements.txt"], target=".")
    assert "| Package | Current | Latest | Bump | Risk | Note |" in md
    assert "| pkg | 1.0.0 | 2.0.0 | major | HIGH | breaking changes likely |" in md
    assert "**1 to update" in md


def test_markdown_escapes_pipes():
    md = render_markdown([_finding(name="we|rd")], ["r.txt"])
    assert "we\\|rd" in md


def test_markdown_vuln_warning():
    md = render_markdown([_finding()], ["r.txt"], meta={"vuln_attempted": 1, "vuln_failed": 1})
    assert "> note: vulnerability lookup failed for all 1" in md


def test_markdown_empty():
    assert "No dependencies found." in render_markdown([], ["r.txt"])


def test_markdown_vulnerable_note_is_reported():
    finding = _finding(
        risk="critical", vulns=[Vuln(id="X", severity="CRITICAL")], note="1 known vulnerability"
    )
    md = render_markdown([finding], ["r.txt"])
    assert "1 known vulnerability" in md
