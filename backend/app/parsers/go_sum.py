"""
go.sum parser. Each real entry is `module version[/go.mod] hash`. Lines
whose version field ends in "/go.mod" are hashes of the module's go.mod
file, not of the module's actual content, and are ignored per Go's own
convention. The leading "v" in the version is kept, since OSV.dev's Go
ecosystem expects versions in that form.
"""
from . import ParsedDependency, SkippedEntry


def parse(text: str):
    deps: list[ParsedDependency] = []
    skipped: list[SkippedEntry] = []
    seen = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            skipped.append(SkippedEntry(raw=raw_line, reason="malformed go.sum line (expected 'module version hash')"))
            continue

        module, version_field = parts[0], parts[1]
        if version_field.endswith("/go.mod"):
            continue  # hash of go.mod itself, not a package content entry

        key = (module, version_field)
        if key in seen:
            continue
        seen.add(key)
        deps.append(ParsedDependency(name=module, version=version_field, ecosystem="Go", raw_line=raw_line))

    return deps, skipped
