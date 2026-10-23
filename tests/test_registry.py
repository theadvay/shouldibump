"""Tests for registry lookups (network mocked out)."""

import pytest

from shouldibump import http, registry


def _patch(monkeypatch, payload):
    monkeypatch.setattr(http, "get_json", lambda url, timeout=10.0: payload)


def test_pypi_uses_declared_latest(monkeypatch):
    _patch(
        monkeypatch,
        {
            "info": {"version": "2.0.0"},
            "releases": {"1.0.0": [{"yanked": False}], "2.0.0": [{"yanked": False}]},
        },
    )
    assert registry.latest_pypi("pkg") == "2.0.0"


def test_pypi_skips_yanked_declared_release(monkeypatch):
    _patch(
        monkeypatch,
        {
            "info": {"version": "2.0.0"},
            "releases": {"1.0.0": [{"yanked": False}], "2.0.0": [{"yanked": True}]},
        },
    )
    assert registry.latest_pypi("pkg") == "1.0.0"


def test_pypi_prefers_stable_over_prerelease(monkeypatch):
    _patch(
        monkeypatch,
        {
            "info": {"version": "2.0.0"},
            "releases": {
                "1.0.0": [{"yanked": False}],
                "1.1.0rc1": [{"yanked": False}],
                "2.0.0": [{"yanked": True}],
            },
        },
    )
    assert registry.latest_pypi("pkg") == "1.0.0"


def test_pypi_unknown_package(monkeypatch):
    _patch(monkeypatch, None)
    assert registry.latest_pypi("nope") is None


def test_pypi_falls_back_to_declared_without_releases(monkeypatch):
    _patch(monkeypatch, {"info": {"version": "3.4.5"}, "releases": {}})
    assert registry.latest_pypi("pkg") == "3.4.5"


def test_npm_latest(monkeypatch):
    _patch(monkeypatch, {"dist-tags": {"latest": "3.1.0", "next": "4.0.0-rc.1"}})
    assert registry.latest_npm("pkg") == "3.1.0"


def test_npm_unknown(monkeypatch):
    _patch(monkeypatch, None)
    assert registry.latest_npm("nope") is None


def test_latest_version_dispatch(monkeypatch):
    _patch(monkeypatch, {"dist-tags": {"latest": "1.2.3"}})
    assert registry.latest_version("pkg", "npm") == "1.2.3"
    with pytest.raises(http.HttpError):
        registry.latest_version("pkg", "cargo")


def test_registry_error_is_http_error():
    assert registry.RegistryError is http.HttpError
