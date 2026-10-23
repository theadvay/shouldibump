"""Tests for the shared HTTP layer (no real network access)."""

import urllib.error

import pytest

from shouldibump import http


class FakeResponse:
    def __init__(self, payload=b"{}"):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_urlopen(monkeypatch, handler):
    monkeypatch.setattr(http.urllib.request, "urlopen", handler)
    monkeypatch.setattr(http.time, "sleep", lambda _seconds: None)


def test_get_json_parses_body(monkeypatch):
    _patch_urlopen(monkeypatch, lambda req, timeout: FakeResponse(b'{"a": 1}'))
    assert http.get_json("https://example.com") == {"a": 1}


def test_get_json_returns_none_on_404(monkeypatch):
    def not_found(req, timeout):
        raise urllib.error.HTTPError("u", 404, "not found", {}, None)

    _patch_urlopen(monkeypatch, not_found)
    assert http.get_json("https://example.com") is None


def test_get_json_fails_fast_on_forbidden(monkeypatch):
    def forbidden(req, timeout):
        raise urllib.error.HTTPError("u", 403, "forbidden", {}, None)

    _patch_urlopen(monkeypatch, forbidden)
    with pytest.raises(http.HttpError) as excinfo:
        http.get_json("https://example.com")
    assert excinfo.value.status == 403


def test_retries_then_succeeds(monkeypatch):
    calls = {"count": 0}

    def flaky(req, timeout):
        calls["count"] += 1
        if calls["count"] < 3:
            raise urllib.error.URLError("temporary")
        return FakeResponse(b'{"ok": true}')

    _patch_urlopen(monkeypatch, flaky)
    assert http.get_json("https://example.com", retries=2) == {"ok": True}
    assert calls["count"] == 3


def test_retries_are_exhausted(monkeypatch):
    def down(req, timeout):
        raise urllib.error.URLError("down")

    _patch_urlopen(monkeypatch, down)
    with pytest.raises(http.HttpError):
        http.get_json("https://example.com", retries=1)


def test_post_json_sends_body(monkeypatch):
    captured = {}

    def fake(req, timeout):
        captured["data"] = req.data
        captured["method"] = req.get_method()
        return FakeResponse(b'{"vulns": []}')

    _patch_urlopen(monkeypatch, fake)
    assert http.post_json("https://example.com", {"x": 1}) == {"vulns": []}
    assert b'"x"' in captured["data"]
    assert captured["method"] == "POST"
