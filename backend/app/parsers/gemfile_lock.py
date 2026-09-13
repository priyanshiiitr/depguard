"""
Gemfile.lock parser. Only lines inside the `GEM ... specs:` block, at
exactly 4-space indent (`    name (version)`), are resolved top-level gem
entries. Deeper-indented lines under a gem are that gem's OWN requirement on
another gem (e.g. "      rack (>= 1.0, < 3)") -- a constraint, not a
resolved pin -- and are intentionally not captured here (the gem they refer
to is already captured at its own top-level entry with its resolved
version).
"""
import re

from . import ParsedDependency, SkippedEntry

_SPEC_RE = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$")
_CONCRETE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-]*$")


def parse(text: str):
    deps: list[ParsedDependency] = []
    skipped: list[SkippedEntry] = []
    in_gem_specs = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped == "GEM":
            in_gem_specs = False
            continue
        if stripped == "specs:":
            in_gem_specs = True
            continue
        if raw_line and not raw_line.startswith(" "):
            # a new top-level section: PLATFORMS, DEPENDENCIES, BUNDLED WITH, ...
            in_gem_specs = False
            continue
        if not in_gem_specs:
            continue

        m = _SPEC_RE.match(raw_line)
        if not m:
            continue  # deeper sub-dependency line, "remote:" line, or blank

        name, version = m.groups()
        if not _CONCRETE_VERSION_RE.match(version):
            skipped.append(SkippedEntry(raw=raw_line, reason="not a concrete version pin"))
            continue
        deps.append(ParsedDependency(name=name, version=version, ecosystem="RubyGems", raw_line=raw_line))

    return deps, skipped
