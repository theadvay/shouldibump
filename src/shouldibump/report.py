"""Render findings: a coloured terminal table, or Markdown for PR comments."""

from __future__ import annotations

import os
import re

__all__ = ["Style", "render", "render_table", "render_markdown"]

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
        padded = [cell + " " * (widths[i] - _width(cell)) for i, cell in enumerate(cells)]
        return "  ".join(padded).rstrip()

    output = [line(headers), "  ".join("─" * w for w in widths)]
    output.extend(line(row) for row in rows)
    return "\n".join(output)


def _summary_parts(findings):
    """Return ``[(colour, text), ...]`` describing the run."""
    outdated = sum(1 for f in findings if f.outdated)
    vulnerable = sum(1 for f in findings if f.vulnerable)
    high = sum(1 for f in findings if f.risk_rank >= 3)
    current = sum(1 for f in findings if not f.outdated and not f.vulnerable)

    parts = []
    if outdated:
        parts.append(("yellow", f"{outdated} to update"))
    if vulnerable:
        parts.append(("red", f"{vulnerable} with known vulnerabilities"))
    if high:
        parts.append(("bold_red", f"{high} high risk"))
    if current:
        parts.append(("green", f"{current} up to date"))
    return parts


def _summary(findings, style):
    rendered = [getattr(style, colour)(text) for colour, text in _summary_parts(findings)]
    return style.dim(" · ").join(rendered)


def _summary_plain(findings):
    return " · ".join(text for _, text in _summary_parts(findings))


def _vuln_warning(meta, style=None):
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
    return "note: " + text


def render(findings, paths, style, only_outdated=False, target=".", meta=None):
    """Return the full terminal report as a string."""
    shown = [f for f in findings if f.outdated or f.vulnerable] if only_outdated else list(findings)

    lines = [
        style.bold("shouldibump") + style.dim("  ·  which dependencies are worth updating"),
        "",
        "  " + style.dim("target   ") + target,
        "  " + style.dim("scanned  ") + ", ".join(os.path.basename(p) for p in paths),
        "",
    ]

    warning = _vuln_warning(meta)

    if not shown:
        if findings:
            lines.append(
                "  "
                + style.green(
                    "Nothing to do — every dependency is current, with no known vulnerabilities."
                )
            )
        else:
            lines.append("  " + style.dim("No dependencies found."))
        if warning:
            lines.append("")
            lines.append("  " + style.dim(warning))
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

        rows.append(
            [
                name,
                finding.current or (finding.spec or "?"),
                finding.latest or "—",
                _BUMP_LABEL.get(finding.bump, finding.bump),
                _risk_color(style, finding.risk)(_RISK_LABEL.get(finding.risk, finding.risk)),
                note,
            ]
        )

    table = render_table(headers, rows)
    lines.extend("  " + row for row in table.splitlines())
    lines.append("")
    lines.append("  " + _summary(findings, style))
    if warning:
        lines.append("")
        lines.append("  " + style.dim(warning))
    return "\n".join(lines)


def _md_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(findings, paths, meta=None, target=".", only_outdated=False):
    """Return a Markdown report, handy for PR comments and CI summaries."""
    shown = [f for f in findings if f.outdated or f.vulnerable] if only_outdated else list(findings)

    lines = ["## shouldibump report", ""]
    scanned = ", ".join(f"`{os.path.basename(p)}`" for p in paths)
    lines.append(f"Scanned {scanned} in `{target}`.")
    lines.append("")

    if not shown:
        if findings:
            lines.append(
                "Nothing to do — every dependency is current, with no known vulnerabilities."
            )
        else:
            lines.append("No dependencies found.")
        warning = _vuln_warning(meta)
        if warning:
            lines += ["", f"> {warning}"]
        return "\n".join(lines)

    lines.append("| Package | Current | Latest | Bump | Risk | Note |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for finding in shown:
        name = finding.name
        if finding.group not in ("main", ""):
            name = f"{name} ({finding.group})"
        lines.append(
            "| {} | {} | {} | {} | {} | {} |".format(
                _md_cell(name),
                _md_cell(finding.current or (finding.spec or "?")),
                _md_cell(finding.latest or "—"),
                _md_cell(_BUMP_LABEL.get(finding.bump, finding.bump)),
                _md_cell(_RISK_LABEL.get(finding.risk, finding.risk)),
                _md_cell(finding.note),
            )
        )

    lines += ["", f"**{_summary_plain(findings)}**"]
    warning = _vuln_warning(meta)
    if warning:
        lines += ["", f"> {warning}"]
    return "\n".join(lines)
