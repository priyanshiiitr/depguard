"""
requirements.txt parser.

Only exact pins (`name==version`) are treated as resolvable dependencies.
Ranges (`>=`, `~=`, etc.), unpinned names, `-r`/`-e`/option lines, and lines
carrying an environment marker (`; python_version < "3.8"`) are skipped with
a reason rather than guessed at -- DepGuard does not know which environment
the repo installs into, so it will not silently pick a version for a range.
Extras (`package[extra]==1.0.0`) are kept: the pin is still exact, extras
only add optional sub-requirements, not version ambiguity.
"""
import re

from . import ParsedDependency, SkippedEntry

_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*$")


def parse(text: str):
    deps: list[ParsedDependency] = []
    skipped: list[SkippedEntry] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if line.startswith("-"):
            skipped.append(SkippedEntry(raw=raw_line, reason="pip option/include line (-r/-e/--...), not a direct pin"))
            continue

        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        if ";" in line:
            skipped.append(SkippedEntry(raw=raw_line, reason="environment marker present; cannot resolve applicability deterministically"))
            continue

        m = _PIN_RE.match(line)
        if not m:
            skipped.append(SkippedEntry(raw=raw_line, reason="not an exact pin (name==version); ranges/unpinned requirements are not auto-analyzed"))
            continue

        name, _extras, version = m.groups()
        deps.append(ParsedDependency(name=name, version=version, ecosystem="PyPI", raw_line=raw_line))

    return deps, skipped
