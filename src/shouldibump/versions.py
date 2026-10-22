"""Version parsing, comparison and bump classification.

This has to cope with both PEP 440 (Python) and SemVer (npm) version strings
without pulling in a dependency for either. We only need enough fidelity to
answer one question: *how big is the jump from A to B?*
"""

from __future__ import annotations

import re

__all__ = ["parse_version", "compare", "classify_bump", "major_of"]

# Pre-release tags, ordered so that a lower value sorts *before* the final release.
_PRE_ORDER = {
    "dev": -5,
    "a": -3, "alpha": -3,
    "b": -2, "beta": -2,
    "c": -1, "rc": -1, "pre": -1, "preview": -1,
}

_RELEASE_RE = re.compile(r"(\d+(?:\.\d+)*)")

# How many numeric components we pad release tuples to before comparing,
# so that "1.2" and "1.2.0" compare equal.
_PAD_WIDTH = 8


def parse_version(value):
    """Parse *value* into a sortable key ``(epoch, release, pre)``.

    Returns ``None`` when the string cannot be understood.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None

    # Drop range/prefix operators and a leading "v" (e.g. "^1.2.3", ">=2.0", "v1.0").
    text = text.lstrip("v=~^<>=! ").strip()
    if not text:
        return None

    epoch = 0
    if "!" in text:  # PEP 440 epoch, e.g. "1!2.0"
        head, _, tail = text.partition("!")
        if head.isdigit():
            epoch = int(head)
            text = tail

    text = text.split("+", 1)[0]  # build metadata is not part of ordering

    match = _RELEASE_RE.match(text)
    if match:
        release = tuple(int(part) for part in match.group(1).split("."))
        rest = text[match.end():]
    else:
        numbers = re.findall(r"\d+", text)
        if not numbers:  # a version with no digits at all is not a version
            return None
        release = tuple(int(n) for n in numbers)
        rest = ""

    return (epoch, release, _parse_prerelease(rest))


def _parse_prerelease(rest):
    """Turn the non-numeric tail of a version into a sortable 3-tuple."""
    rest = rest.lstrip(".-_ ")
    if not rest:
        return (1, 0, 0)  # a final release sorts above any pre-release

    match = re.match(r"([a-z]+)\.?(\d*)", rest)
    if match:
        tag, number = match.group(1), match.group(2)
        num = int(number) if number else 0
        if tag == "post":
            return (2, 0, num)  # post-release sorts above the final release
        order = _PRE_ORDER.get(tag)
        if order is not None:
            return (0, order, num)

    if rest.startswith("post"):
        return (2, 0, 0)
    if rest.startswith("dev"):
        return (0, -5, 0)
    return (0, 0, 0)


def _pad(release):
    padded = list(release) + [0] * (_PAD_WIDTH - len(release))
    return tuple(padded[:_PAD_WIDTH])


def _key(parsed):
    epoch, release, pre = parsed
    return (epoch, _pad(release), pre)


def compare(a, b):
    """Return -1, 0 or 1 for ``a`` vs ``b``, or ``None`` if either is unparseable."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    ka, kb = _key(pa), _key(pb)
    return (ka > kb) - (ka < kb)


def major_of(value):
    """Return the major version number of *value*, or ``None``."""
    parsed = parse_version(value)
    if parsed is None or not parsed[1]:
        return None
    return parsed[1][0]


def classify_bump(current, latest):
    """Classify the size of the jump from *current* to *latest*.

    One of: ``none``, ``patch``, ``prerelease``, ``minor``, ``major``, ``unknown``.
    """
    parsed_current, parsed_latest = parse_version(current), parse_version(latest)
    if parsed_current is None or parsed_latest is None:
        return "unknown"
    if _key(parsed_current) >= _key(parsed_latest):
        return "none"

    current_release = _pad(parsed_current[1])
    latest_release = _pad(parsed_latest[1])
    if latest_release[0] != current_release[0]:
        return "major"
    if latest_release[1] != current_release[1]:
        return "minor"
    if latest_release[2] != current_release[2]:
        return "patch"
    return "prerelease"
