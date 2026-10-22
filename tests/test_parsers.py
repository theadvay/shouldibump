"""Tests for manifest parsing."""

import json

from shouldibump import parsers


def test_pinned_requirement():
    parsed = parsers.parse_requirement("requests==2.31.0")
    assert parsed["name"] == "requests"
    assert parsed["current"] == "2.31.0"
    assert parsed["exact"] is True
    assert parsed["ecosystem"] == "pypi"


def test_range_requirement_uses_floor():
    parsed = parsers.parse_requirement("flask>=2.0,<3.0")
    assert parsed["name"] == "flask"
    assert parsed["current"] == "2.0"
    assert parsed["exact"] is False


def test_requirement_with_extras_and_marker():
    parsed = parsers.parse_requirement("uvicorn[standard]==0.27.0 ; python_version >= '3.8'")
    assert parsed["name"] == "uvicorn"
    assert parsed["current"] == "0.27.0"
    assert parsed["exact"] is True


def test_blank_comment_and_flags_are_skipped():
    assert parsers.parse_requirement("") is None
    assert parsers.parse_requirement("# just a comment") is None
    assert parsers.parse_requirement("-r other.txt") is None
    assert parsers.parse_requirement("--index-url https://example.com") is None


def test_direct_url_reference():
    parsed = parsers.parse_requirement("mylib @ https://example.com/mylib.whl")
    assert parsed["name"] == "mylib"
    assert parsed["current"] is None


def test_base_version():
    assert parsers.base_version("^1.2.3") == "1.2.3"
    assert parsers.base_version("~=1.4.2") == "1.4.2"
    assert parsers.base_version("") is None


def test_package_json(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({
        "dependencies": {"react": "^18.2.0", "left-pad": "1.3.0"},
        "devDependencies": {"vite": "~5.0.0"},
    }))
    deps = {d["name"]: d for d in parsers.collect_dependencies([str(manifest)])}
    assert deps["react"]["current"] == "18.2.0"
    assert deps["react"]["exact"] is False
    assert deps["left-pad"]["exact"] is True
    assert deps["vite"]["group"] == "dev"


def test_pyproject_pep621(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["requests>=2.28", "click==8.1.7"]\n'
        "\n[project.optional-dependencies]\n"
        'dev = ["pytest>=7"]\n'
    )
    deps = {d["name"]: d for d in parsers.collect_dependencies([str(manifest)])}
    assert deps["requests"]["current"] == "2.28"
    assert deps["click"]["exact"] is True
    assert deps["pytest"]["group"] == "dev"


def test_no_dev_filter(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({
        "dependencies": {"react": "^18.0.0"},
        "devDependencies": {"vite": "^5.0.0"},
    }))
    deps = parsers.collect_dependencies([str(manifest)], include_dev=False)
    assert [d["name"] for d in deps] == ["react"]
