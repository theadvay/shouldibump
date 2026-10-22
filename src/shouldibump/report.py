"""Render findings as a clean, coloured terminal table."""

from __future__ import annotations

import os
import re

__all__ = ["Style", "render", "render_table"]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_RISK_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "—",
    "unknown": "?",
}

_BUMP_LABEL = {
    "major": "major",
    "minor": "minor",
    "patch": "patch",
    "prerelease": "pre",
    "none": "—",
    "unknown": "?",
}


class Style:
    """Minimal ANSI helper that turns itself off cleanly."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text):
        return self._wrap("1", text)

    def dim(self, text):
        return self._wrap("2", text)

    def red(self, text):
        return self._wrap("31", text)

    def green(self, text):
        return self._wrap("32", text)

    def yellow(self, text):
        return self._wrap("33", text)

    def cyan(self, text):
        return self._wrap("36", text)

    def bold_red(self, text):
        return self._wrap("1;31", text)


def _risk_color(style, risk):
    return {
        "critical": style.bold_red,
        "high": style.red,
        "medium": style.yellow,
        "low": style.green,
    }.get(risk, style.dim)


def _width(text):
    return len(_ANSI_RE.sub("", text))


def render_table(headers, rows):
    """Pad *rows* into aligned columns, ignoring ANSI escape codes."""
    widths = [_width(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], _width(cell))

    def line(cells):
        padded = [
            cell + " " * (widths[i] - _width(cell)) for i, cell in enumerate(cells)
        ]
        return "  ".join(padded).rstrip()

    output = [line(headers), "  ".join("─" * w for w in widths)]
    output.extend(line(row) for row in rows)
    return "\n".join(output)


def _summary(findings, style):
    outdated = sum(1 for f in findings if f.outdated)
    vulnerable = sum(1 for f in findings if f.vulnerable)
    high = sum(1 for f in findings if f.risk_rank >= 3)
    current = sum(1 for f in findings if not f.outdated and not f.vulnerable)

    parts = []
    if outdated:
        parts.append(style.yellow(f"{outdated} to update"))
    if vulnerable:
        parts.append(style.red(f"{vulnerable} with known vulnerabilities"))
    if high:
        parts.append(style.bold_red(f"{high} high risk"))
    if current:
        parts.append(style.green(f"{current} up to date"))
    if not parts:
        parts.append(f"{len(findings)} packages")
    return style.dim(" · ").join(parts)


def _vuln_warning(meta, style):
    """A dim caveat when the OSV lookup could not be completed."""
    if not meta:
        return ""
    failed = meta.get("vuln_failed", 0)
    attempted = meta.get("vuln_attempted", 0)
    if not failed:
        return ""
    if failed == attempted:
        text = f"vulnerability lookup failed for all {failed} checked packages — results may be incomplete"
    else:
        text = f"vulnerability lookup failed for {failed} of {attempted} checked packages"
    return "  " + style.dim("note: " + text)


def render(findings, paths, style, only_outdated=False, target=".", meta=None):
    """Return the full report as a string."""
    if only_outdated:
        shown = [f for f in findings if f.outdated or f.vulnerable]
    else:
        shown = list(findings)

    lines = [
        style.bold("shouldibump") + style.dim("  ·  which dependencies are worth updating"),
        "",
        "  " + style.dim("target   ") + target,
        "  " + style.dim("scanned  ") + ", ".join(os.path.basename(p) for p in paths),
        "",
    ]

    warning = _vuln_warning(meta, style)

    if not shown:
        if findings:
            lines.append(
                "  " + style.green("Nothing to do — every dependency is current, with no known vulnerabilities.")
            )
        else:
            lines.append("  " + style.dim("No dependencies found."))
        if warning:
            lines.append("")
            lines.append(warning)
        return "\n".join(lines)

    headers = ["PACKAGE", "CURRENT", "LATEST", "BUMP", "RISK", "NOTE"]
    rows = []
    for finding in shown:
        name = finding.name
        if finding.group not in ("main", ""):
            name = f"{name} {style.dim('(' + finding.group + ')')}"

        note = finding.note
        if finding.vulnerable:
            note = style.red(note)
        elif not finding.outdated:
            note = style.dim(note)

        rows.append([
            name,
            finding.current or (finding.spec or "?"),
            finding.latest or "—",
            _BUMP_LABEL.get(finding.bump, finding.bump),
            _risk_color(style, finding.risk)(_RISK_LABEL.get(finding.risk, finding.risk)),
            note,
        ])

    table = render_table(headers, rows)
    lines.extend("  " + row for row in table.splitlines())
    lines.append("")
    lines.append("  " + _summary(findings, style))
    if warning:
        lines.append("")
        lines.append(warning)
    return "\n".join(lines)
