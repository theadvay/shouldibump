"""Command-line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

from . import __version__, report
from . import scan as scanner
from .models import RISK_ORDER

__all__ = ["main", "build_parser"]

_FAIL_LEVELS = ["none", "low", "medium", "high", "critical"]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="shouldibump",
        description=(
            "Know which dependencies are actually worth updating — and what might break. "
            "Reads requirements*.txt, pyproject.toml and package.json."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory or a single manifest file (default: current directory)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--only-outdated",
        action="store_true",
        help="hide dependencies that are already current",
    )
    parser.add_argument(
        "--no-dev", action="store_true", help="skip dev and optional dependencies"
    )
    parser.add_argument(
        "--no-vulns", action="store_true", help="skip the OSV vulnerability check"
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="NAME",
        help="skip a package; repeat the flag or pass a comma-separated list",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_LEVELS,
        default="none",
        help="exit with status 1 if any dependency is at or above this risk (default: none)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--jobs", type=int, default=8, help="parallel lookups (default: 8)"
    )
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument(
        "--version", action="version", version=f"shouldibump {__version__}"
    )
    return parser


def _as_json(findings, paths, target, meta=None):
    return {
        "tool": "shouldibump",
        "version": __version__,
        "target": target,
        "manifests": [os.path.basename(p) for p in paths],
        "summary": {
            "total": len(findings),
            "outdated": sum(1 for f in findings if f.outdated),
            "vulnerable": sum(1 for f in findings if f.vulnerable),
            "high_risk": sum(1 for f in findings if f.risk_rank >= 3),
        },
        "vulnerability_check": meta or {},
        "findings": [dataclasses.asdict(f) for f in findings],
    }


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not os.path.exists(args.path):
        print(f"shouldibump: no such file or directory: {args.path}", file=sys.stderr)
        return 2

    paths = scanner.discover(args.path)
    if not paths:
        print(
            f"shouldibump: no requirements*.txt, pyproject.toml or package.json found in {args.path}",
            file=sys.stderr,
        )
        return 2

    ignore = {
        token.strip().lower()
        for chunk in args.ignore
        for token in chunk.split(",")
        if token.strip()
    }

    findings, paths, meta = scanner.scan(
        args.path,
        timeout=args.timeout,
        jobs=args.jobs,
        check_vulns=not args.no_vulns,
        include_dev=not args.no_dev,
    )
    if ignore:
        findings = [f for f in findings if f.name.lower() not in ignore]

    if args.json:
        print(json.dumps(_as_json(findings, paths, args.path, meta), indent=2))
    else:
        use_color = (
            not args.no_color
            and not os.environ.get("NO_COLOR")
            and sys.stdout.isatty()
        )
        print(
            report.render(
                findings,
                paths,
                report.Style(use_color),
                args.only_outdated,
                args.path,
                meta,
            )
        )

    threshold = RISK_ORDER[args.fail_on]
    if threshold > 0:
        worst = max((f.risk_rank for f in findings), default=-1)
        if worst >= threshold:
            return 1
    return 0
