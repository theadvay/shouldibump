"""Small data containers shared across the package."""

from __future__ import annotations

from dataclasses import dataclass, field

# Higher = more attention required. "unknown" is deliberately negative so it
# never outranks a known risk in a sort.
RISK_ORDER = {
    "unknown": -1,
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

RISK_BY_RANK = {rank: name for name, rank in RISK_ORDER.items() if name != "unknown"}


@dataclass
class Vuln:
    """One known vulnerability affecting a dependency's current version."""

    id: str
    summary: str = ""
    severity: str = ""
    fixed: str = ""


@dataclass
class Finding:
    """The verdict for a single dependency."""

    name: str
    ecosystem: str  # "pypi" or "npm"
    spec: str = ""
    current: str | None = None
    latest: str | None = None
    bump: str = "unknown"
    risk: str = "unknown"
    note: str = ""
    group: str = "main"  # main | dev | optional | peer | <extra-name>
    sources: list = field(default_factory=list)  # manifest files it came from
    exact: bool = False  # is `current` a resolved version, or just a declared floor?
    vulns: list = field(default_factory=list)
    error: str | None = None
    vuln_error: str | None = None  # set when the OSV lookup itself failed

    @property
    def outdated(self):
        return self.bump not in ("none", "unknown")

    @property
    def vulnerable(self):
        return bool(self.vulns)

    @property
    def risk_rank(self):
        return RISK_ORDER.get(self.risk, -1)
