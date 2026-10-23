"""Read dependency manifests into a common shape.

Supported today:
  * ``requirements*.txt``  (pip / pip-tools, including ``-r other.txt`` includes)
  * ``pyproject.toml``     (PEP 621 and Poetry)
  * ``package.json``       (npm / pnpm / yarn)

Each parser returns a list of plain dicts with the keys:
``name, ecosystem, spec, current, exact, group, source``.
"""

from __future__ import annotations

import json
import os
import re

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for 3.9/3.10
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None

__all__ = ["collect_dependencies", "parse_requirement", "base_version"]

_OPERATOR_RE = re.compile(r"(===|==|~=|!=|<=|>=|<|>|=)\s*([^\s,;]+)")
_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)*")

# Operators whose operand is a *lower bound* we can treat as the current version.
_FLOOR_OPS = {"==", "===", "~=", ">=", "=", "^", "~"}

_INCLUDE_FLAGS = ("-r", "--requirement")


def base_version(spec):
    """Pull the first concrete version token out of a requirement spec.

    ``"==2.31.0" -> "2.31.0"``, ``"^1.2.3" -> "1.2.3"``, ``">=2.0,<3" -> "2.0"``.
    """
    if not spec:
        return None
    match = _NUMBER_RE.search(spec)
    return match.group(0) if match else None


def include_target(line):
    """Return the file named by an ``-r``/``--requirement`` line, else ``None``."""
    for flag in _INCLUDE_FLAGS:
        if line == flag:
            return None
        for prefix in (flag + " ", flag + "="):
            if line.startswith(prefix):
                return line[len(prefix) :].strip() or None
    return None


def parse_requirement(line):
    """Parse a single ``requirements.txt``-style line.

    Returns a dict, or ``None`` for blank lines, comments and pip flags.
    """
    if line is None:
        return None

    text = line.split("#", 1)[0].strip()
    if not text or text.startswith("-"):
        return None
    if ";" in text:  # environment marker
        text = text.split(";", 1)[0].strip()

    # Direct URL reference: "name @ https://..."
    url_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*\S+$", text)
    if url_match:
        return {
            "name": url_match.group(1),
            "ecosystem": "pypi",
            "spec": text,
            "current": None,
            "exact": False,
        }

    name_match = _NAME_RE.match(text)
    if not name_match:
        return None
    name = name_match.group(1)

    rest = text[name_match.end() :].strip()
    rest = re.sub(r"^\[[^\]]*\]", "", rest).strip()  # drop extras: pkg[extra]

    current = None
    exact = False
    for operator, version in _OPERATOR_RE.findall(rest):
        if operator in ("==", "==="):
            current, exact = version, True
            break
        if operator in _FLOOR_OPS and current is None:
            current = version

    if current is None:
        current = base_version(rest)

    return {
        "name": name,
        "ecosystem": "pypi",
        "spec": rest,
        "current": current,
        "exact": exact,
    }


def _load_toml(path):
    if tomllib is None:  # pragma: no cover
        raise RuntimeError(
            "Reading pyproject.toml needs Python 3.11+ or the 'tomli' package (pip install tomli)."
        )
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def _poetry_spec(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("version", "")
    return ""


def _from_pyproject(path):
    data = _load_toml(path)
    deps = []

    def add(raw, group):
        parsed = parse_requirement(raw)
        if parsed:
            parsed["group"] = group
            deps.append(parsed)

    project = data.get("project") or {}
    for raw in project.get("dependencies") or []:
        add(raw, "main")
    for group, items in (project.get("optional-dependencies") or {}).items():
        for raw in items:
            add(raw, group)

    poetry = (data.get("tool") or {}).get("poetry") or {}
    for name, value in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        deps.append(_poetry_dep(name, value, "main"))
    for name, value in (poetry.get("dev-dependencies") or {}).items():
        deps.append(_poetry_dep(name, value, "dev"))
    for group, block in (poetry.get("group") or {}).items():
        for name, value in (block.get("dependencies") or {}).items():
            deps.append(_poetry_dep(name, value, group))

    return deps


def _poetry_dep(name, value, group):
    spec = _poetry_spec(value)
    exact = False
    current = None
    if spec and not any(spec.startswith(op) for op in ("^", "~", ">", "<")):
        current = base_version(spec)
        exact = bool(current)
    return {
        "name": name,
        "ecosystem": "pypi",
        "spec": spec,
        "current": current,
        "exact": exact,
        "group": group,
    }


_NPM_GROUPS = (
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
)


def _from_package_json(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    deps = []
    for key, group in _NPM_GROUPS:
        for name, spec in (data.get(key) or {}).items():
            spec = spec or ""
            exact = bool(re.fullmatch(r"\d+(?:\.\d+)*", spec.strip()))
            deps.append(
                {
                    "name": name,
                    "ecosystem": "npm",
                    "spec": spec,
                    "current": base_version(spec),
                    "exact": exact,
                    "group": group,
                }
            )
    return deps


def _requirements_group(filename):
    lowered = filename.lower()
    if "dev" in lowered or "test" in lowered:
        return "dev"
    return "main"


def _read_requirements(path, group, seen, deps):
    """Read a requirements file, following ``-r`` includes (cycle-safe)."""
    real = os.path.realpath(path)
    if real in seen:
        return
    seen.add(real)

    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return

    for line in lines:
        target = include_target(line.split("#", 1)[0].strip())
        if target:
            _read_requirements(os.path.join(os.path.dirname(path), target), group, seen, deps)
            continue
        parsed = parse_requirement(line)
        if parsed:
            parsed["group"] = group
            parsed["source"] = path
            deps.append(parsed)


def collect_dependencies(paths, include_dev=True):
    """Parse every recognised manifest in *paths* into a flat dependency list."""
    deps = []
    seen_requirements = set()

    for path in paths:
        filename = os.path.basename(path)
        try:
            if filename.startswith("requirements") and filename.endswith(".txt"):
                _read_requirements(path, _requirements_group(filename), seen_requirements, deps)
            elif filename == "pyproject.toml":
                for dep in _from_pyproject(path):
                    dep["source"] = path
                    deps.append(dep)
            elif filename == "package.json":
                for dep in _from_package_json(path):
                    dep["source"] = path
                    deps.append(dep)
        except Exception:  # a broken manifest should not kill the whole run
            continue

    for dep in deps:
        dep.setdefault("group", "main")
        dep.setdefault("source", "")

    if not include_dev:
        deps = [d for d in deps if d.get("group") == "main"]
    return deps
