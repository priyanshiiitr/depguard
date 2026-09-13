"""
composer.lock parser. The `packages` (production) and `packages-dev`
sections both carry resolved, concrete `name` + `version` fields -- a
lockfile, so no range ambiguity.
"""
import json

from . import ParsedDependency, SkippedEntry


def parse(text: str):
    deps: list[ParsedDependency] = []
    skipped: list[SkippedEntry] = []

    try:
        data = json.loads(text)
    except Exception as e:
        skipped.append(SkippedEntry(raw="<entire file>", reason=f"failed to parse JSON: {e}"))
        return deps, skipped

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                skipped.append(SkippedEntry(raw=str(pkg)[:200], reason="package entry missing name or version"))
                continue
            deps.append(ParsedDependency(name=name, version=version, ecosystem="Packagist", raw_line=f'"{name}": "{version}"'))

    return deps, skipped
