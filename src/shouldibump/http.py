"""Tiny HTTP helpers with retry/backoff, shared by the registry and OSV clients.

Kept in one place so it can be swapped out wholesale in tests and so every
network call gets the same timeout, User-Agent and retry behaviour.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from . import __version__

__all__ = ["HttpError", "get_json", "post_json", "USER_AGENT"]

USER_AGENT = f"shouldibump/{__version__} (+https://github.com/theadvay/shouldibump)"

#: Statuses worth retrying (everything else fails fast).
_RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpError(RuntimeError):
    """Raised when a request fails after retries, or the server errors out."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _build_request(url, data=None, headers=None, method=None):
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        merged.update(headers)
    return urllib.request.Request(url, data=data, headers=merged, method=method)


def _send(request, timeout, retries, backoff, allow_404):
    """Perform *request*, retrying transient failures with exponential backoff.

    Returns the raw body, or ``None`` for a 404 when *allow_404* is set.
    """
    last_error = "unknown error"
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            last_error = f"HTTP {exc.code}"
            if exc.code not in _RETRY_STATUS:
                raise HttpError(last_error, status=exc.code) from exc
        except urllib.error.URLError as exc:
            last_error = f"network error: {exc.reason}"
        except (TimeoutError, OSError) as exc:  # pragma: no cover - defensive
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < retries:
            time.sleep(backoff * (2**attempt))

    raise HttpError(f"{last_error} (after {retries + 1} attempt(s))")


def get_json(url, timeout=10.0, retries=2, backoff=0.5):
    """GET *url* and parse the JSON body. Returns ``None`` on 404."""
    body = _send(_build_request(url), timeout, retries, backoff, allow_404=True)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def post_json(url, payload, timeout=10.0, retries=2, backoff=0.5):
    """POST *payload* as JSON to *url* and parse the JSON response."""
    request = _build_request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    body = _send(request, timeout, retries, backoff, allow_404=False)
    return json.loads(body.decode("utf-8"))
