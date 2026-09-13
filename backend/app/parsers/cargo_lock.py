"""
Cargo.lock parser. TOML `[[package]]` tables always carry a concrete,
resolved `name` + `version` -- there is no range/pin ambiguity in a lockfile,
so every well-formed entry is a dependency.
"""
import tomllib

from . import ParsedDependency, SkippedEntry


def parse(text: str):
    deps: list[ParsedDependency] = []
    skipped: list[SkippedEntry] = []

    try:
        data = tomllib.loads(text)
    except Exception as e:
        skipped.append(SkippedEntry(raw="<entire file>", reason=f"failed to parse TOML: {e}"))
        return deps, skipped

    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            skipped.append(SkippedEntry(raw=str(pkg)[:200], reason="package entry missing name or version"))
            continue
        deps.append(ParsedDependency(name=name, version=version, ecosystem="crates.io", raw_line=f'name = "{name}"\nversion = "{version}"'))

    return deps, skipped
