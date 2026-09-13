"""
Deterministic decision rules for DepGuard.

Ground truth for "does a vulnerability exist" and "what version fixes it"
comes from OSV.dev data, never from an LLM. These functions apply small,
conservative, explainable rules on top of that data. Anything the rules
cannot confidently resolve is routed to NEEDS_REVIEW rather than guessed.
"""
from . import semver

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "NONE": 0}

PERMISSIVE_LICENSES = {
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "0BSD",
    "CC0-1.0", "Unlicense", "Python-2.0", "BlueOak-1.0.0",
}

COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
}


def severity_from_osv(vuln: dict) -> str:
    db_specific = vuln.get("database_specific") or {}
    sev = (db_specific.get("severity") or "").upper()
    if sev == "MEDIUM":
        sev = "MODERATE"
    if sev in _SEVERITY_ORDER:
        return sev
    # Fallback: some records carry a CVSS vector but no bucketed severity.
    # Without a real CVSS parser, do not guess a number -- classify as
    # MODERATE (a defensible conservative default) rather than fabricate.
    if vuln.get("severity"):
        return "MODERATE"
    return "MODERATE"


def max_risk(risks: list[str]) -> str:
    if not risks:
        return "NONE"
    return max(risks, key=lambda r: _SEVERITY_ORDER.get(r, 0))


def extract_fixed_versions(vuln: dict, name: str, ecosystem: str = "npm") -> list[str]:
    """Extract explicit "fixed" versions from OSV ranges.

    Accepts both "SEMVER" and "ECOSYSTEM" range types: npm advisories are
    almost always SEMVER-typed, but PyPI/RubyGems/Packagist advisories (PEP
    440 / RubyGems / Composer versioning isn't strict semver) commonly use
    "ECOSYSTEM" ranges instead. Both types can carry an explicit "fixed"
    event, which is what matters here.

    Deliberately NOT handled: a range that only gives "last_affected"
    (the last known-bad version, with no explicit fixed version). Resolving
    that into a concrete "next safe version" would require querying each
    ecosystem's registry for its full version list and guessing which
    release comes next -- exactly the kind of guess this project's policy
    refuses to make. Those advisories correctly fall through to
    "no fixed version published" (NEEDS_REVIEW) instead.
    """
    fixed = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed


def decide_vulnerability(name: str, current_version: str, is_direct: bool, vulns: list[dict], ecosystem: str = "npm") -> dict:
    """vulns: list of full OSV vuln records affecting this name@current_version.
    Returns a dict of finding fields.

    Safety note: when multiple distinct advisories affect the same current
    version, a single target version only counts as "safe" if it is high
    enough to satisfy EVERY advisory. So this computes each advisory's own
    minimum fix above the current version, then takes the MAX across
    advisories (not the min of the pooled fix list) -- upgrading to the
    minimum across the pool could leave a different advisory unfixed.
    """
    current_parsed = semver.parse(current_version)
    all_fixed = []
    per_vuln_min_safe = []
    for v in vulns:
        fixed_for_this = [f for f in extract_fixed_versions(v, name, ecosystem) if semver.parse(f) is not None]
        all_fixed.extend(fixed_for_this)
        if current_parsed is None:
            per_vuln_min_safe.append(None)
            continue
        safe_for_this = [f for f in fixed_for_this if semver.is_gt(f, current_version)]
        per_vuln_min_safe.append(semver.min_version(safe_for_this) if safe_for_this else None)

    min_safe = None
    if current_parsed is not None and all_fixed and all(m is not None for m in per_vuln_min_safe):
        min_safe = semver.max_version(per_vuln_min_safe)

    risk = max_risk([severity_from_osv(v) for v in vulns])
    ids = [v.get("id", "unknown") for v in vulns]
    advisory_id = ", ".join(ids[:3]) + (f" (+{len(ids) - 3} more)" if len(ids) > 3 else "")
    summary = vulns[0].get("summary") or (vulns[0].get("details") or "")[:200] if vulns else ""

    if not all_fixed:
        return dict(
            risk=risk, advisory_id=advisory_id, advisory_summary=summary,
            min_safe_version=None,
            reason="Vulnerability confirmed via OSV.dev but no fixed version has been published yet.",
            recommended_action="NEEDS_REVIEW",
        )

    if current_parsed is None:
        return dict(
            risk=risk, advisory_id=advisory_id, advisory_summary=summary,
            min_safe_version=None,
            reason=f"Current version '{current_version}' could not be reliably parsed; refusing to auto-upgrade.",
            recommended_action="NEEDS_REVIEW",
        )

    if min_safe is None:
        unfixed_count = sum(1 for m in per_vuln_min_safe if m is None)
        reason = (
            f"{unfixed_count} of {len(vulns)} advisories affecting this package have no fixed version above "
            f"{current_version} (or an unparsable version range); refusing to auto-upgrade without a version that "
            "satisfies every known advisory."
        )
        return dict(
            risk=risk, advisory_id=advisory_id, advisory_summary=summary,
            min_safe_version=None, reason=reason,
            recommended_action="NEEDS_REVIEW",
        )

    if not is_direct:
        return dict(
            risk=risk, advisory_id=advisory_id, advisory_summary=summary,
            min_safe_version=min_safe,
            reason=f"Fix available ({min_safe}) but this is a transitive dependency. MVP policy limits automatic upgrades to direct dependencies.",
            recommended_action="NEEDS_REVIEW",
        )

    return dict(
        risk=risk, advisory_id=advisory_id, advisory_summary=summary,
        min_safe_version=min_safe,
        reason=f"OSV.dev confirms a fix at {min_safe} for a {risk} severity issue in a direct dependency. Safe to auto-remediate.",
        recommended_action="AUTO_REMEDIATE",
    )


def check_license_conflict(project_license: str, dep_license: str):
    """Returns (is_conflict: bool, reason: str). Policy signal only, not legal advice."""
    proj = (project_license or "").strip()
    dep = (dep_license or "").strip()
    if not dep or dep == "UNKNOWN":
        return False, ""
    if proj in PERMISSIVE_LICENSES and dep in COPYLEFT_LICENSES:
        return True, (
            f"Project is licensed {proj} (permissive) but depends on {dep} (copyleft). "
            "This is a policy signal requiring human/legal review, not legal advice."
        )
    return False, ""
