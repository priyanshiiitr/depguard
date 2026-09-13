"""
Deterministic package.json / package-lock.json parsing and patching.

Scope note: this intentionally does NOT implement a full npm dependency
resolver. It parses the dependency graph that is already resolved in the
lockfile, and when patching a fix, only rewrites the entries for the exact
package name/old-version being remediated, using real npm registry metadata
(tarball URL + integrity hash) as the source of truth for the new entry. The
PR body tells reviewers to run `npm install` to fully reconcile the lockfile,
which is an honest limitation for an MVP rather than a fabricated "fixed"
lockfile.
"""
import json


def parse_package_json(content: str) -> dict:
    return json.loads(content)


def get_direct_dependencies(package_json: dict) -> dict:
    """Returns {name: range_spec} merging dependencies + devDependencies."""
    deps = {}
    deps.update(package_json.get("dependencies", {}) or {})
    deps.update(package_json.get("devDependencies", {}) or {})
    return deps


def get_project_license(package_json: dict) -> str:
    lic = package_json.get("license")
    if isinstance(lic, dict):
        return lic.get("type", "UNKNOWN")
    return lic or "UNKNOWN"


def get_engines_node(package_json: dict):
    return (package_json.get("engines") or {}).get("node")


def parse_lockfile(content: str) -> dict:
    return json.loads(content)


def get_all_name_version_pairs(lock_data: dict) -> set:
    """Returns a set of (name, version) tuples found anywhere in the lockfile."""
    pairs = set()
    version = lock_data.get("lockfileVersion", 1)

    if "packages" in lock_data:
        for key, entry in lock_data["packages"].items():
            if key == "" or not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not name:
                # derive from the key path, e.g. "node_modules/foo/node_modules/bar"
                parts = key.split("node_modules/")
                name = parts[-1] if parts else None
            v = entry.get("version")
            if name and v:
                pairs.add((name, v))

    if "dependencies" in lock_data and (version == 1 or "packages" not in lock_data):
        def walk(deps: dict):
            for name, entry in deps.items():
                v = entry.get("version")
                if v:
                    pairs.add((name, v))
                if "dependencies" in entry:
                    walk(entry["dependencies"])

        walk(lock_data["dependencies"])

    return pairs


def find_direct_lock_version(lock_data: dict, name: str):
    """Best-effort: find the top-level (direct) resolved version of `name`."""
    if "packages" in lock_data:
        entry = lock_data["packages"].get(f"node_modules/{name}")
        if entry:
            return entry.get("version")
    if "dependencies" in lock_data:
        entry = lock_data["dependencies"].get(name)
        if entry:
            return entry.get("version")
    return None


def patch_package_json(content: str, name: str, new_version: str) -> str:
    """Rewrites the version range for `name` in dependencies/devDependencies,
    preserving the existing range operator (^, ~, exact, etc.)."""
    from .semver import extract_range_spec

    data = json.loads(content)
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if block and name in block:
            operator, _ = extract_range_spec(block[name])
            block[name] = f"{operator}{new_version}"
    return json.dumps(data, indent=2) + "\n"


def patch_lockfile(content: str, name: str, old_version: str, new_version: str, registry_meta: dict) -> str:
    """Patches all lockfile entries for name@old_version to new_version using
    real npm registry metadata for resolved/integrity fields."""
    data = json.loads(content)
    dist = (registry_meta or {}).get("dist", {}) or {}
    new_resolved = dist.get("tarball")
    new_integrity = dist.get("integrity")

    def patch_entry(entry: dict):
        entry["version"] = new_version
        if new_resolved:
            entry["resolved"] = new_resolved
        if new_integrity:
            entry["integrity"] = new_integrity
        elif "integrity" in entry:
            del entry["integrity"]

    if "packages" in data:
        for key, entry in data["packages"].items():
            if key == "" or not isinstance(entry, dict):
                continue
            entry_name = entry.get("name") or key.split("node_modules/")[-1]
            if entry_name == name and entry.get("version") == old_version:
                patch_entry(entry)

    if "dependencies" in data:
        def walk(deps: dict):
            for dep_name, entry in deps.items():
                if dep_name == name and entry.get("version") == old_version:
                    patch_entry(entry)
                if "dependencies" in entry:
                    walk(entry["dependencies"])

        walk(data["dependencies"])

    return json.dumps(data, indent=2) + "\n"
