import asyncio
from datetime import datetime, timezone

from . import lockfile, policy
from .clients.github import GitHubClient, GitHubError, parse_repo_url
from .clients.osv import OSVClient
from .clients.depsdev import DepsDevClient
from .clients.eol import EOLClient, extract_major_version, classify_eol

# In-memory cache: "owner/repo" -> raw analysis context needed for remediation.
ANALYSIS_CACHE: dict = {}

MAX_OSV_QUERIES = 300  # keep the batch call fast and within OSV limits


class AnalysisError(Exception):
    def __init__(self, message: str, trace: list):
        super().__init__(message)
        self.message = message
        self.trace = trace


def _step(trace, step, status, detail):
    trace.append({"step": step, "status": status, "detail": detail})


async def analyze_repo(repo_url: str) -> dict:
    trace = []
    gh = GitHubClient()
    osv = OSVClient()
    dd = DepsDevClient()
    eol = EOLClient()
    try:
        try:
            owner, repo = parse_repo_url(repo_url)
        except GitHubError as e:
            _step(trace, "Repository discovered", "FAILED", str(e))
            raise AnalysisError(str(e), trace)

        try:
            repo_info = await gh.get_repo(owner, repo)
        except GitHubError as e:
            _step(trace, "Repository discovered", "FAILED", str(e))
            raise AnalysisError(str(e), trace)

        default_branch = repo_info["default_branch"]
        full_name = repo_info["full_name"]
        _step(trace, "Repository discovered", "SUCCESS", f"{full_name} (default branch: {default_branch})")

        pkg_json_content, pkg_json_sha = await gh.get_file(owner, repo, "package.json", default_branch)
        if pkg_json_content is None:
            msg = "package.json not found in the repository root."
            _step(trace, "Lockfile found", "FAILED", msg)
            raise AnalysisError(msg, trace)

        lock_content, lock_sha = await gh.get_file(owner, repo, "package-lock.json", default_branch)
        if lock_content is None:
            msg = "package-lock.json not found. DepGuard's MVP requires a committed lockfile for deterministic version resolution."
            _step(trace, "Lockfile found", "FAILED", msg)
            raise AnalysisError(msg, trace)
        _step(trace, "Lockfile found", "SUCCESS", "package-lock.json located")

        try:
            package_json = lockfile.parse_package_json(pkg_json_content)
            lock_data = lockfile.parse_lockfile(lock_content)
        except ValueError as e:
            msg = f"Malformed JSON in package.json or package-lock.json: {e}"
            _step(trace, "Dependencies parsed", "FAILED", msg)
            raise AnalysisError(msg, trace)

        direct_deps = lockfile.get_direct_dependencies(package_json)
        all_pairs = lockfile.get_all_name_version_pairs(lock_data)
        if not all_pairs:
            msg = "No resolvable dependencies found in package-lock.json."
            _step(trace, "Dependencies parsed", "FAILED", msg)
            raise AnalysisError(msg, trace)

        pairs_list = list(all_pairs)[:MAX_OSV_QUERIES]
        _step(
            trace, "Dependencies parsed", "SUCCESS",
            f"{len(all_pairs)} unique package versions ({len(direct_deps)} direct dependencies)"
            + (f"; limited OSV lookups to first {MAX_OSV_QUERIES}" if len(all_pairs) > MAX_OSV_QUERIES else ""),
        )

        # --- OSV.dev query ---
        try:
            batch_results = await osv.query_batch(
                [{"name": n, "version": v} for n, v in pairs_list]
            )
        except Exception as e:
            _step(trace, "OSV query", "FAILED", f"OSV.dev query failed: {e}")
            batch_results = [{} for _ in pairs_list]
        else:
            vuln_count = sum(1 for r in batch_results if r.get("vulns"))
            _step(trace, "OSV query", "SUCCESS", f"Queried {len(pairs_list)} packages against OSV.dev; {vuln_count} have known advisories")

        vulnerable = []  # (name, version, [vuln_id,...])
        for (name, version), result in zip(pairs_list, batch_results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            if vuln_ids:
                vulnerable.append((name, version, vuln_ids))

        # fetch full vuln records (dedup by id)
        unique_ids = sorted({vid for _, _, ids in vulnerable for vid in ids})
        vuln_records = {}
        for vid in unique_ids:
            try:
                vuln_records[vid] = await osv.get_vuln(vid)
            except Exception:
                continue

        findings = []
        fid = 0
        for name, version, vuln_ids in vulnerable:
            records = [vuln_records[v] for v in vuln_ids if v in vuln_records]
            if not records:
                continue
            # Direct vs. transitive is determined by package.json, not the lockfile:
            # npm lockfileVersion 3 lists every installed package (direct AND
            # transitive) as a flat "node_modules/X" key, so presence there is
            # not a valid direct/transitive signal.
            is_direct = name in direct_deps
            decision = policy.decide_vulnerability(name, version, is_direct, records)
            fid += 1
            findings.append({
                "id": f"vuln-{fid}",
                "type": "VULNERABILITY",
                "dependency": name,
                "current_version": version,
                "is_direct": is_direct,
                **decision,
            })

        # --- deps.dev query (license info for direct dependencies) ---
        project_license = lockfile.get_project_license(package_json)
        license_checked = 0
        try:
            for name, range_spec in direct_deps.items():
                resolved_version = lockfile.find_direct_lock_version(lock_data, name)
                if not resolved_version:
                    continue
                info = await dd.get_version_info(name, resolved_version)
                license_checked += 1
                dep_license = None
                if info and info.get("licenses"):
                    dep_license = info["licenses"][0]
                if not dep_license:
                    continue
                conflict, reason = policy.check_license_conflict(project_license, dep_license)
                if conflict:
                    fid += 1
                    findings.append({
                        "id": f"license-{fid}",
                        "type": "LICENSE",
                        "dependency": name,
                        "current_version": resolved_version,
                        "is_direct": True,
                        "risk": "MODERATE",
                        "advisory_id": None,
                        "advisory_summary": f"Dependency license: {dep_license}; project license: {project_license}",
                        "min_safe_version": None,
                        "reason": reason,
                        "recommended_action": "NEEDS_REVIEW",
                    })
            _step(trace, "deps.dev query", "SUCCESS", f"Checked license metadata for {license_checked} direct dependencies")
        except Exception as e:
            _step(trace, "deps.dev query", "FAILED", f"deps.dev query failed: {e}")

        # --- EOL check (Node.js runtime via package.json engines.node) ---
        engines_node = lockfile.get_engines_node(package_json)
        if engines_node:
            major = extract_major_version(engines_node)
            cycles = await eol.get_cycles("nodejs")
            if major is not None and cycles:
                cycle_entry = next((c for c in cycles if str(c.get("cycle")) == str(major)), None)
                if cycle_entry:
                    status, reason = classify_eol(cycle_entry)
                    _step(trace, "EOL check", "SUCCESS", f"Node.js {major}.x is {status}: {reason}")
                    if status in ("eol", "nearing_eol"):
                        fid += 1
                        findings.append({
                            "id": f"eol-{fid}",
                            "type": "EOL",
                            "dependency": f"node@{major}",
                            "current_version": str(major),
                            "is_direct": True,
                            "risk": "HIGH" if status == "eol" else "MODERATE",
                            "advisory_id": None,
                            "advisory_summary": None,
                            "min_safe_version": None,
                            "reason": f"Node.js {major}.x is {status.replace('_', ' ')}: {reason}",
                            "recommended_action": "INFORMATIONAL",
                        })
                else:
                    _step(trace, "EOL check", "SUCCESS", f"No endoflife.date cycle data for Node.js {major}.x")
            else:
                _step(trace, "EOL check", "SUCCESS", "Could not determine Node.js major version from engines field")
        else:
            _step(trace, "EOL check", "SUCCESS", "No engines.node specified in package.json; skipping EOL check")

        overall_risk = policy.max_risk([f["risk"] for f in findings]) if findings else "NONE"
        _step(trace, "Decision made", "SUCCESS", f"{len(findings)} finding(s); overall risk: {overall_risk}")

        auto_count = sum(1 for f in findings if f["recommended_action"] == "AUTO_REMEDIATE")
        _step(
            trace, "Safety check", "SUCCESS",
            f"{auto_count} finding(s) meet the conservative bar for automatic remediation; "
            f"{len(findings) - auto_count} require human review or are informational.",
        )

        result = {
            "repo": full_name,
            "repo_url": repo_url,
            "default_branch": default_branch,
            "dependency_count": len(all_pairs),
            "direct_dependency_count": len(direct_deps),
            "findings": findings,
            "overall_risk": overall_risk,
            "trace": trace,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

        ANALYSIS_CACHE[full_name] = {
            "result": result,
            "owner": owner,
            "repo": repo,
            "default_branch": default_branch,
            "package_json_content": pkg_json_content,
            "package_json_sha": pkg_json_sha,
            "lock_content": lock_content,
            "lock_sha": lock_sha,
            "lock_data": lock_data,
        }
        return result
    finally:
        await asyncio.gather(gh.close(), osv.close(), dd.close(), eol.close())
