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


def test_include_target():
    assert parsers.include_target("-r base.txt") == "base.txt"
    assert parsers.include_target("--requirement=base.txt") == "base.txt"
    assert parsers.include_target("-r") is None
    assert parsers.include_target("requests==1.0") is None


def test_package_json(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {"react": "^18.2.0", "left-pad": "1.3.0"},
                "devDependencies": {"vite": "~5.0.0"},
            }
        )
    )
    deps = {d["name"]: d for d in parsers.collect_dependencies([str(manifest)])}
    assert deps["react"]["current"] == "18.2.0"
    assert deps["react"]["exact"] is False
    assert deps["left-pad"]["exact"] is True
    assert deps["vite"]["group"] == "dev"
    assert deps["react"]["source"] == str(manifest)


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


def test_pyproject_poetry(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'requests = "^2.31"\n'
        'click = { version = "8.1.7" }\n'
        "\n[tool.poetry.group.dev.dependencies]\n"
        'pytest = "^7.0"\n'
    )
    deps = {d["name"]: d for d in parsers.collect_dependencies([str(manifest)])}
    assert "python" not in deps
    assert deps["click"]["exact"] is True
    assert deps["pytest"]["group"] == "dev"


def test_requirements_include_followed(tmp_path):
    (tmp_path / "base.txt").write_text("click==8.1.7\n")
    (tmp_path / "requirements.txt").write_text("-r base.txt\nrequests==2.31.0\n")
    deps = {
        d["name"]: d for d in parsers.collect_dependencies([str(tmp_path / "requirements.txt")])
    }
    assert set(deps) == {"click", "requests"}
    assert deps["click"]["source"] == str(tmp_path / "base.txt")


def test_requirements_include_cycle_is_safe(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r base.txt\nflask==2.0.0\n")
    (tmp_path / "base.txt").write_text("-r requirements.txt\nclick==8.0.0\n")
    deps = parsers.collect_dependencies([str(tmp_path / "requirements.txt")])
    assert sorted(d["name"] for d in deps) == ["click", "flask"]


def test_dev_requirements_group(tmp_path):
    manifest = tmp_path / "requirements-dev.txt"
    manifest.write_text("pytest==7.0.0\n")
    assert parsers.collect_dependencies([str(manifest)])[0]["group"] == "dev"


def test_no_dev_filter(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"vite": "^5.0.0"},
            }
        )
    )
    deps = parsers.collect_dependencies([str(manifest)], include_dev=False)
    assert [d["name"] for d in deps] == ["react"]


def test_broken_manifest_is_skipped(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{ not valid json")
    assert parsers.collect_dependencies([str(manifest)]) == []
