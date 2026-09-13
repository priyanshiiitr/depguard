import asyncio
from datetime import datetime, timezone

from . import lockfile, policy, llm_parser, config
from .parsers import FILENAME_TO_PARSER
from .clients.github import GitHubClient, GitHubError, parse_repo_url
from .clients.osv import OSVClient
from .clients.depsdev import DepsDevClient
from .clients.eol import EOLClient, extract_major_version, classify_eol

# In-memory cache: "owner/repo" -> raw analysis context needed for remediation.
ANALYSIS_CACHE: dict = {}

# Manifest files with no deterministic parser -- handled by the LLM Manifest Agent
# (backend/app/llm_parser.py) instead, gated behind three deterministic verification
# checks before anything from them reaches the OSV/policy pipeline.
LLM_ONLY_FILES = {
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Pipfile.lock": "PyPI",
    "pyproject.toml": "PyPI",
}

MAX_OSV_QUERIES = 300  # keep each ecosystem's batch call fast and within OSV limits


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

        findings = []
        fid = 0
        ecosystems_detected = []
        skipped_dependencies = []  # [{"ecosystem", "file", "raw", "reason"}] -- parser-level skips, never guessed
        total_dependency_count = 0
        total_direct_dependency_count = 0
        npm_cache_fields = None
        pypi_cache_fields = None

        # ==================== npm (package.json + package-lock.json) ====================
        # Unchanged from the original single-ecosystem MVP, just wrapped so that npm being
        # absent/broken no longer aborts the whole analysis now that other ecosystems exist.
        try:
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
                f"npm: {len(all_pairs)} unique package versions ({len(direct_deps)} direct dependencies)"
                + (f"; limited OSV lookups to first {MAX_OSV_QUERIES}" if len(all_pairs) > MAX_OSV_QUERIES else ""),
            )

            # --- OSV.dev query ---
            try:
                batch_results = await osv.query_batch(
                    [{"name": n, "version": v} for n, v in pairs_list]
                )
            except Exception as e:
                _step(trace, "OSV query", "FAILED", f"OSV.dev query failed (npm): {e}")
                batch_results = [{} for _ in pairs_list]
            else:
                vuln_count = sum(1 for r in batch_results if r.get("vulns"))
                _step(trace, "OSV query", "SUCCESS", f"npm: queried {len(pairs_list)} packages against OSV.dev; {vuln_count} have known advisories")

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
                    "ecosystem": "npm",
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
                            "ecosystem": "npm",
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
                                "ecosystem": "npm",
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

            ecosystems_detected.append("npm")
            total_dependency_count += len(all_pairs)
            total_direct_dependency_count += len(direct_deps)
            npm_cache_fields = {
                "package_json_content": pkg_json_content,
                "package_json_sha": pkg_json_sha,
                "lock_content": lock_content,
                "lock_sha": lock_sha,
                "lock_data": lock_data,
            }
        except AnalysisError:
            # npm not applicable or broken in this repo -- other ecosystems may still apply.
            pass

        # ==================== other ecosystems (deterministic parsers) ====================
        for filename, (parse_fn, ecosystem) in FILENAME_TO_PARSER.items():
            content, file_sha = await gh.get_file(owner, repo, filename, default_branch)
            if content is None:
                continue
            if filename == "requirements.txt":
                pypi_cache_fields = {"requirements_txt_content": content, "requirements_txt_sha": file_sha}

            try:
                deps, skipped = parse_fn(content)
            except Exception as e:
                _step(trace, "Dependencies parsed", "FAILED", f"{filename}: failed to parse ({e})")
                continue

            for s in skipped:
                skipped_dependencies.append({"ecosystem": ecosystem, "file": filename, "raw": s.raw, "reason": s.reason})

            if not deps:
                _step(trace, "Dependencies parsed", "SUCCESS", f"{filename} ({ecosystem}): 0 resolvable dependencies ({len(skipped)} skipped)")
                continue

            pairs_list = deps[:MAX_OSV_QUERIES]
            ecosystems_detected.append(ecosystem)
            total_dependency_count += len(deps)
            # Direct vs. transitive is not determinable from these lockfiles alone
            # (would require also parsing Cargo.toml/composer.json/Gemfile/go.mod) --
            # out of MVP scope; every entry is counted/treated as direct for messaging.
            total_direct_dependency_count += len(deps)
            _step(
                trace, "Dependencies parsed", "SUCCESS",
                f"{filename} ({ecosystem}): {len(deps)} resolvable dependencies"
                + (f", {len(skipped)} skipped" if skipped else "")
                + (f"; limited OSV lookups to first {MAX_OSV_QUERIES}" if len(deps) > MAX_OSV_QUERIES else ""),
            )

            try:
                batch_results = await osv.query_batch(
                    [{"name": d.name, "version": d.version, "ecosystem": ecosystem} for d in pairs_list]
                )
            except Exception as e:
                _step(trace, "OSV query", "FAILED", f"OSV.dev query failed ({ecosystem}): {e}")
                batch_results = [{} for _ in pairs_list]
            else:
                vuln_count = sum(1 for r in batch_results if r.get("vulns"))
                _step(trace, "OSV query", "SUCCESS", f"{ecosystem}: queried {len(pairs_list)} packages against OSV.dev; {vuln_count} have known advisories")

            vulnerable = []  # (ParsedDependency, [vuln_id,...])
            for d, result in zip(pairs_list, batch_results):
                vuln_ids = [v["id"] for v in result.get("vulns", [])]
                if vuln_ids:
                    vulnerable.append((d, vuln_ids))

            unique_ids = sorted({vid for _, ids in vulnerable for vid in ids})
            vuln_records = {}
            for vid in unique_ids:
                try:
                    vuln_records[vid] = await osv.get_vuln(vid)
                except Exception:
                    continue

            for d, vuln_ids in vulnerable:
                records = [vuln_records[v] for v in vuln_ids if v in vuln_records]
                if not records:
                    continue
                is_direct = True  # see note above
                decision = policy.decide_vulnerability(d.name, d.version, is_direct, records, ecosystem=ecosystem)
                # Remediation is only wired up for npm and PyPI so far (Phase 2). Every
                # other ecosystem is detection-only: the advisory is real and still
                # surfaced (UI, Slack, Sheets), but DepGuard cannot yet execute the fix,
                # so it must not claim AUTO_REMEDIATE for it.
                if ecosystem != "PyPI" and decision["recommended_action"] == "AUTO_REMEDIATE":
                    decision = dict(decision)
                    decision["recommended_action"] = "DETECTION_ONLY"
                    decision["reason"] = (
                        decision["reason"] + " Advisory detected -- manual upgrade required for this ecosystem "
                        "(automatic remediation is currently only supported for npm and PyPI)."
                    )
                fid += 1
                findings.append({
                    "id": f"vuln-{fid}",
                    "type": "VULNERABILITY",
                    "ecosystem": ecosystem,
                    "dependency": d.name,
                    "current_version": d.version,
                    "is_direct": is_direct,
                    "raw_line": d.raw_line,
                    **decision,
                })

        # ==================== LLM Manifest Agent (extraction only) ====================
        # For manifest formats with no deterministic parser. The LLM only proposes
        # {ecosystem, name, version, raw_line} candidates; every candidate must pass
        # three deterministic checks (verbatim raw_line, concrete version, real
        # registry entry) before it reaches OSV/policy. The LLM never decides
        # vulnerability or a fix version -- policy.py does that, unchanged, same as
        # every other ecosystem. Findings from here are always DETECTION_ONLY: no
        # remediation path has been built for these formats yet.
        llm_candidates = list(LLM_ONLY_FILES.items())
        try:
            root_files = await gh.list_root_files(owner, repo, default_branch)
            for name in root_files:
                if name.endswith(".csproj"):
                    llm_candidates.append((name, "NuGet"))
        except Exception:
            pass

        llm_summary = []  # [{"file", "ecosystem", "extracted", "verified", "rejected": [...]}]
        for filename, ecosystem in llm_candidates:
            content, _sha = await gh.get_file(owner, repo, filename, default_branch)
            if content is None:
                continue

            if not config.GROQ_API_KEY:
                _step(trace, "LLM manifest parsing", "SKIPPED", f"{filename} detected but GROQ_API_KEY is not configured; not analyzed.")
                continue

            result = await llm_parser.extract_and_verify(filename, content)
            llm_summary.append({
                "file": filename, "ecosystem": ecosystem,
                "extracted": result["extracted"], "verified": len(result["verified"]), "rejected": result["rejected"],
            })
            for rej in result["rejected"]:
                skipped_dependencies.append({"ecosystem": ecosystem, "file": filename, "raw": rej["raw"], "reason": rej["reason"]})

            deps = result["verified"]
            _step(
                trace, "LLM manifest parsing", "SUCCESS",
                f"{filename} ({ecosystem}): {result['extracted']} candidate(s) extracted, {len(deps)} verified, {len(result['rejected'])} rejected",
            )
            if not deps:
                continue

            pairs_list = deps[:MAX_OSV_QUERIES]
            ecosystems_detected.append(ecosystem)
            total_dependency_count += len(deps)
            total_direct_dependency_count += len(deps)

            try:
                batch_results = await osv.query_batch(
                    [{"name": d.name, "version": d.version, "ecosystem": d.ecosystem} for d in pairs_list]
                )
            except Exception as e:
                _step(trace, "OSV query", "FAILED", f"OSV.dev query failed ({ecosystem}, LLM-derived): {e}")
                batch_results = [{} for _ in pairs_list]
            else:
                vuln_count = sum(1 for r in batch_results if r.get("vulns"))
                _step(trace, "OSV query", "SUCCESS", f"{ecosystem} (LLM-derived, {filename}): queried {len(pairs_list)} packages; {vuln_count} have known advisories")

            vulnerable = []
            for d, result_ in zip(pairs_list, batch_results):
                vuln_ids = [v["id"] for v in result_.get("vulns", [])]
                if vuln_ids:
                    vulnerable.append((d, vuln_ids))

            unique_ids = sorted({vid for _, ids in vulnerable for vid in ids})
            vuln_records = {}
            for vid in unique_ids:
                try:
                    vuln_records[vid] = await osv.get_vuln(vid)
                except Exception:
                    continue

            for d, vuln_ids in vulnerable:
                records = [vuln_records[v] for v in vuln_ids if v in vuln_records]
                if not records:
                    continue
                decision = policy.decide_vulnerability(d.name, d.version, True, records, ecosystem=d.ecosystem)
                if decision["recommended_action"] == "AUTO_REMEDIATE":
                    decision = dict(decision)
                    decision["recommended_action"] = "DETECTION_ONLY"
                    decision["reason"] = (
                        decision["reason"] + " Advisory detected -- manual upgrade required "
                        "(this dependency was extracted by the LLM manifest agent; no automatic remediation path exists for it yet)."
                    )
                fid += 1
                findings.append({
                    "id": f"vuln-{fid}",
                    "type": "VULNERABILITY",
                    "ecosystem": d.ecosystem,
                    "dependency": d.name,
                    "current_version": d.version,
                    "is_direct": True,
                    "raw_line": d.raw_line,
                    "source": "llm",
                    **decision,
                })

        if not ecosystems_detected:
            msg = (
                "No supported manifest/lockfile found (package.json+package-lock.json, "
                "requirements.txt, Cargo.lock, go.sum, composer.lock, Gemfile.lock, or an "
                "LLM-parseable manifest such as pom.xml/build.gradle/Pipfile.lock/pyproject.toml/*.csproj)."
            )
            _step(trace, "Dependencies parsed", "FAILED", msg)
            raise AnalysisError(msg, trace)

        ecosystems_detected = list(dict.fromkeys(ecosystems_detected))  # dedupe, preserve order

        overall_risk = policy.max_risk([f["risk"] for f in findings]) if findings else "NONE"
        _step(
            trace, "Decision made", "SUCCESS",
            f"{len(findings)} finding(s) across {len(ecosystems_detected)} ecosystem(s) "
            f"({', '.join(ecosystems_detected)}); overall risk: {overall_risk}",
        )

        auto_count = sum(1 for f in findings if f["recommended_action"] == "AUTO_REMEDIATE")
        detection_only_count = sum(1 for f in findings if f["recommended_action"] == "DETECTION_ONLY")
        _step(
            trace, "Safety check", "SUCCESS",
            f"{auto_count} finding(s) meet the conservative bar for automatic remediation; "
            f"{detection_only_count} are detected but not yet auto-fixable for their ecosystem; "
            f"{len(findings) - auto_count - detection_only_count} require human review or are informational.",
        )

        result = {
            "repo": full_name,
            "repo_url": repo_url,
            "default_branch": default_branch,
            "dependency_count": total_dependency_count,
            "direct_dependency_count": total_direct_dependency_count,
            "ecosystems_detected": ecosystems_detected,
            "findings": findings,
            "skipped_dependencies": skipped_dependencies,
            "llm_manifest_summary": llm_summary,
            "overall_risk": overall_risk,
            "trace": trace,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

        cache_entry = {"result": result, "owner": owner, "repo": repo, "default_branch": default_branch}
        if npm_cache_fields:
            cache_entry.update(npm_cache_fields)
        if pypi_cache_fields:
            cache_entry.update(pypi_cache_fields)
        ANALYSIS_CACHE[full_name] = cache_entry
        return result
    finally:
        await asyncio.gather(gh.close(), osv.close(), dd.close(), eol.close())
