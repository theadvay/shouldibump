"""Tests for version parsing and bump classification."""

from shouldibump.versions import classify_bump, compare, major_of, parse_version


def test_parse_strips_prefixes():
    assert parse_version("v1.2.3") == parse_version("1.2.3")
    assert parse_version("^1.2.3") == parse_version("1.2.3")
    assert parse_version(">=2.0") == parse_version("2.0")


def test_padding_makes_trailing_zeros_equal():
    assert compare("1.2", "1.2.0") == 0
    assert compare("1.0", "1") == 0


def test_numeric_not_lexical_ordering():
    assert compare("1.10.0", "1.9.0") == 1
    assert compare("2.0.0", "10.0.0") == -1


def test_prerelease_sorts_before_final():
    assert compare("2.0.0rc1", "2.0.0") == -1
    assert compare("1.0.0-alpha.1", "1.0.0") == -1
    assert compare("1.0.0b2", "1.0.0b10") == -1


def test_classify_bump():
    assert classify_bump("1.2.3", "1.2.4") == "patch"
    assert classify_bump("1.2.3", "1.3.0") == "minor"
    assert classify_bump("1.2.3", "2.0.0") == "major"
    assert classify_bump("1.2.3", "1.2.3") == "none"
    assert classify_bump("2.0.0", "1.9.0") == "none"  # downgrades are not "updates"
    assert classify_bump("2.0.0rc1", "2.0.0") == "prerelease"


def test_classify_unknown_inputs():
    assert classify_bump("not-a-version", "1.0.0") == "unknown"
    assert classify_bump("1.0.0", None) == "unknown"


def test_major_of():
    assert major_of("0.9.1") == 0
    assert major_of("v3.1.4") == 3
    assert major_of(None) is None
