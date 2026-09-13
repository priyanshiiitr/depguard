"""
Minimal, deterministic semver comparison for npm-style versions.
Not a full semver spec implementation on purpose (see project scope rules) --
handles the common case of dotted numeric versions with an optional
prerelease/build suffix. Anything it cannot confidently parse is treated as
"uncertain" by the caller (parse() returns None), which routes the finding to
human review rather than risking an unsafe auto-decision.
"""
import re

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def parse(version: str):
    if not version:
        return None
    m = _VERSION_RE.match(version.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def compare(a: str, b: str):
    """Return -1, 0, 1 comparing a vs b. Returns None if either is unparseable."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def is_gt(a: str, b: str):
    c = compare(a, b)
    return None if c is None else c > 0


def min_version(versions):
    """Return the smallest parseable version from a list, or None."""
    parsed = [(v, parse(v)) for v in versions if parse(v) is not None]
    if not parsed:
        return None
    parsed.sort(key=lambda t: t[1])
    return parsed[0][0]


def max_version(versions):
    """Return the largest parseable version from a list, or None."""
    parsed = [(v, parse(v)) for v in versions if parse(v) is not None]
    if not parsed:
        return None
    parsed.sort(key=lambda t: t[1])
    return parsed[-1][0]


def extract_range_spec(range_spec: str):
    """Extract a bare version + the operator prefix from a package.json range
    like '^4.17.15', '~1.2.0', '>=2.0.0', or an exact '4.17.15'."""
    if not range_spec:
        return "", ""
    m = re.match(r"^(\^|~|>=|<=|>|<)?\s*(.+)$", range_spec.strip())
    if not m:
        return "", range_spec
    return m.group(1) or "", m.group(2)
