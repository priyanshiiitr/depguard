import asyncio

from . import lockfile, policy
from .analyzer import ANALYSIS_CACHE
from .clients.github import GitHubClient, GitHubError, parse_repo_url
from .clients.npm_registry import NpmRegistryClient
from .clients import slack, sheets


class RemediationError(Exception):
    def __init__(self, message: str, trace: list):
        super().__init__(message)
        self.message = message
        self.trace = trace


def _step(trace, step, status, detail):
    trace.append({"step": step, "status": status, "detail": detail})


def _patch_requirements_txt(content: str, raw_line: str, old_version: str, new_version: str) -> str:
    """Rewrites one exact `name==old_version` line to `name==new_version`.
    Refuses to patch if the original line can't be found verbatim (the file
    may have changed since analysis), rather than guessing which line to edit.
    """
    if raw_line not in content:
        raise ValueError(f"original requirements.txt line not found verbatim: {raw_line!r}")
    new_line = raw_line.replace(f"=={old_version}", f"=={new_version}", 1)
    return content.replace(raw_line, new_line, 1)


async def remediate_repo(repo_url: str, github_token: str | None = None) -> dict:
    trace = []
    try:
        owner, repo = parse_repo_url(repo_url)
    except GitHubError as e:
        raise RemediationError(str(e), trace)

    full_name = f"{owner}/{repo}"
    cached = ANALYSIS_CACHE.get(full_name)
    if not cached:
        msg = "No analysis found for this repository. Run Analyze Repository first."
        _step(trace, "Safety check", "FAILED", msg)
        raise RemediationError(msg, trace)

    findings = cached["result"]["findings"]
    # Remediation is wired up for npm and PyPI only; analyzer.py already relabels
    # every other ecosystem's would-be auto-fix as DETECTION_ONLY, so this filter
    # naturally excludes them without needing an ecosystem check here.
    npm_auto = [f for f in findings if f["recommended_action"] == "AUTO_REMEDIATE" and f.get("ecosystem", "npm") == "npm"]
    pypi_auto = [f for f in findings if f["recommended_action"] == "AUTO_REMEDIATE" and f.get("ecosystem") == "PyPI"]
    auto_findings = npm_auto + pypi_auto
    detection_only = [f for f in findings if f["recommended_action"] == "DETECTION_ONLY"]

    if not auto_findings:
        sheets_updated, slack_sent = await _log_detection_only_only(full_name, detection_only, trace)
        _step(trace, "Safety check", "NEEDS_REVIEW", "No findings meet the conservative bar for automatic remediation. No PR was created.")
        return {
            "repo": full_name,
            "status": "NEEDS_REVIEW",
            "branch": None,
            "pr_url": None,
            "remediated": [],
            "skipped": [f["dependency"] for f in findings],
            "trace": trace,
            "sheets_updated": sheets_updated,
            "slack_sent": slack_sent,
        }

    gh = GitHubClient(token=github_token)
    npm = NpmRegistryClient()
    default_branch = cached["default_branch"]
    dep_slug = "-".join(sorted({f["dependency"].replace("/", "-").lstrip("@") for f in auto_findings}))[:60]
    branch_name = f"depguard/fix-{dep_slug}"

    try:
        try:
            base_sha = await gh.get_ref_sha(owner, repo, default_branch)
            await gh.create_branch(owner, repo, branch_name, base_sha)
            _step(trace, "Branch created", "SUCCESS", f"{branch_name} (from {default_branch})")
        except GitHubError as e:
            _step(trace, "Branch created", "FAILED", str(e))
            raise RemediationError(str(e), trace)

        changes = []
        files_touched = []

        # ---- npm: package.json + package-lock.json ----
        if npm_auto:
            if "package_json_content" not in cached:
                _step(trace, "Files updated", "FAILED", "npm findings present but no cached package.json/package-lock.json; re-run analysis.")
            else:
                pkg_content = cached["package_json_content"]
                lock_content = cached["lock_content"]
                npm_changes = []
                for f in npm_auto:
                    name, old_version, new_version = f["dependency"], f["current_version"], f["min_safe_version"]
                    meta = await npm.get_version_metadata(name, new_version)
                    if meta is None:
                        _step(trace, "Files updated", "NEEDS_REVIEW", f"Could not fetch npm registry metadata for {name}@{new_version}; skipped.")
                        continue
                    pkg_content = lockfile.patch_package_json(pkg_content, name, new_version)
                    lock_content = lockfile.patch_lockfile(lock_content, name, old_version, new_version, meta)
                    npm_changes.append({"dependency": name, "old_version": old_version, "new_version": new_version, "risk": f["risk"], "advisory": f.get("advisory_id") or "", "ecosystem": "npm"})

                if npm_changes:
                    try:
                        await gh.update_file(
                            owner, repo, "package.json", branch_name, pkg_content, cached["package_json_sha"],
                            f"depguard: bump {', '.join(c['dependency'] for c in npm_changes)} for security fix(es)",
                        )
                        await gh.update_file(
                            owner, repo, "package-lock.json", branch_name, lock_content, cached["lock_sha"],
                            f"depguard: update lockfile for {', '.join(c['dependency'] for c in npm_changes)}",
                        )
                        files_touched += ["package.json", "package-lock.json"]
                        changes += npm_changes
                    except GitHubError as e:
                        _step(trace, "Files updated", "FAILED", f"npm: {e}")

        # ---- PyPI: requirements.txt ----
        if pypi_auto:
            if "requirements_txt_content" not in cached:
                _step(trace, "Files updated", "FAILED", "PyPI findings present but no cached requirements.txt; re-run analysis.")
            else:
                req_content = cached["requirements_txt_content"]
                pypi_changes = []
                for f in pypi_auto:
                    name, old_version, new_version = f["dependency"], f["current_version"], f["min_safe_version"]
                    try:
                        req_content = _patch_requirements_txt(req_content, f.get("raw_line", ""), old_version, new_version)
                    except ValueError as e:
                        _step(trace, "Files updated", "NEEDS_REVIEW", f"PyPI: {e}")
                        continue
                    pypi_changes.append({"dependency": name, "old_version": old_version, "new_version": new_version, "risk": f["risk"], "advisory": f.get("advisory_id") or "", "ecosystem": "PyPI"})

                if pypi_changes:
                    try:
                        await gh.update_file(
                            owner, repo, "requirements.txt", branch_name, req_content, cached["requirements_txt_sha"],
                            f"depguard: bump {', '.join(c['dependency'] for c in pypi_changes)} for security fix(es)",
                        )
                        files_touched.append("requirements.txt")
                        changes += pypi_changes
                    except GitHubError as e:
                        _step(trace, "Files updated", "FAILED", f"PyPI: {e}")

        if not changes:
            msg = "None of the recommended upgrades could be applied (registry metadata unavailable or source lines changed)."
            _step(trace, "Files updated", "FAILED", msg)
            raise RemediationError(msg, trace)

        _step(trace, "Files updated", "SUCCESS", f"{', '.join(files_touched)} updated for {len(changes)} dependency(ies)")
        _step(trace, "Commit created", "SUCCESS", f"{len(files_touched)} commit(s) pushed to remediation branch")

        pr_body_lines = [
            "**DepGuard automated remediation**",
            "",
            "This PR was opened by DepGuard after analyzing this repository's dependency manifests against OSV.dev, deps.dev, and endoflife.date.",
            "",
            "| Ecosystem | Dependency | Old | New | Risk | Advisory | Reason |",
            "|---|---|---|---|---|---|---|",
        ]
        for f in npm_auto + pypi_auto:
            pr_body_lines.append(
                f"| {f.get('ecosystem', 'npm')} | {f['dependency']} | {f['current_version']} | {f['min_safe_version']} | {f['risk']} | {f.get('advisory_id') or '-'} | {f['reason']} |"
            )
        if detection_only:
            pr_body_lines += ["", "**Detected but not included in this PR (manual upgrade required for these ecosystems):**", ""]
            for f in detection_only:
                pr_body_lines.append(f"- `{f.get('ecosystem')}` {f['dependency']}@{f['current_version']} -- {f.get('advisory_id') or 'advisory'}: {f['reason']}")
        pr_body_lines += [
            "",
            "**Note:** `package-lock.json` (if changed) has been patched for the changed package entries only. "
            "Run `npm install` after merging to fully reconcile the lockfile.",
            "",
            "_Opened automatically by DepGuard. Review before merging._",
        ]

        try:
            pr_url = await gh.create_pull_request(
                owner, repo,
                title=f"depguard: security fix for {', '.join(c['dependency'] for c in changes)}",
                body="\n".join(pr_body_lines),
                head=branch_name, base=default_branch,
            )
            _step(trace, "PR created", "SUCCESS", pr_url)
        except GitHubError as e:
            _step(trace, "PR created", "FAILED", str(e))
            raise RemediationError(str(e), trace)

        overall_risk = policy.max_risk([c["risk"] for c in changes] + [f["risk"] for f in detection_only])

        sheets_updated = False
        try:
            rows = [
                {
                    "repo": full_name, "dependency": c["dependency"], "current_version": c["old_version"],
                    "recommended_version": c["new_version"], "risk": c["risk"], "advisory": c["advisory"],
                    "pr_url": pr_url, "status": "SUCCESS",
                }
                for c in changes
            ] + [
                {
                    "repo": full_name, "dependency": f["dependency"], "current_version": f["current_version"],
                    "recommended_version": f.get("min_safe_version") or "manual upgrade required",
                    "risk": f["risk"], "advisory": f.get("advisory_id") or "",
                    "pr_url": "", "status": f"DETECTION_ONLY ({f.get('ecosystem')})",
                }
                for f in detection_only
            ]
            sheets_updated = await asyncio.to_thread(sheets.append_remediation_rows, rows)
            _step(trace, "Sheets updated", "SUCCESS" if sheets_updated else "SKIPPED",
                  "Remediation log appended to Google Sheets" if sheets_updated else "Google Sheets not configured or write failed")
        except Exception as e:
            _step(trace, "Sheets updated", "FAILED", str(e))

        slack_sent = False
        try:
            slack_sent = await slack.send_remediation_notification(full_name, changes, pr_url, overall_risk, detection_only=detection_only)
            _step(trace, "Slack sent", "SUCCESS" if slack_sent else "SKIPPED",
                  "Slack notification delivered" if slack_sent else "Slack webhook not configured or delivery failed")
        except Exception as e:
            _step(trace, "Slack sent", "FAILED", str(e))

        _step(trace, "Final result", "SUCCESS", f"PR opened: {pr_url}")

        skipped = [f["dependency"] for f in findings if f["recommended_action"] not in ("AUTO_REMEDIATE",)]
        return {
            "repo": full_name,
            "status": "SUCCESS",
            "branch": branch_name,
            "pr_url": pr_url,
            "remediated": [c["dependency"] for c in changes],
            "skipped": skipped,
            "trace": trace,
            "sheets_updated": sheets_updated,
            "slack_sent": slack_sent,
        }
    finally:
        await asyncio.gather(gh.close(), npm.close())


async def _log_detection_only_only(full_name: str, detection_only: list, trace: list):
    """Called when there is nothing to auto-remediate but there ARE detection-only
    findings from other ecosystems -- per policy, those must still reach Sheets and
    Slack rather than being silently dropped just because no PR was opened."""
    if not detection_only:
        return False, False

    sheets_updated = False
    try:
        rows = [
            {
                "repo": full_name, "dependency": f["dependency"], "current_version": f["current_version"],
                "recommended_version": f.get("min_safe_version") or "manual upgrade required",
                "risk": f["risk"], "advisory": f.get("advisory_id") or "",
                "pr_url": "", "status": f"DETECTION_ONLY ({f.get('ecosystem')})",
            }
            for f in detection_only
        ]
        sheets_updated = await asyncio.to_thread(sheets.append_remediation_rows, rows)
        _step(trace, "Sheets updated", "SUCCESS" if sheets_updated else "SKIPPED",
              "Detection-only findings logged to Google Sheets" if sheets_updated else "Google Sheets not configured or write failed")
    except Exception as e:
        _step(trace, "Sheets updated", "FAILED", str(e))

    slack_sent = False
    try:
        overall_risk = policy.max_risk([f["risk"] for f in detection_only])
        slack_sent = await slack.send_remediation_notification(full_name, [], None, overall_risk, detection_only=detection_only)
        _step(trace, "Slack sent", "SUCCESS" if slack_sent else "SKIPPED",
              "Slack notification delivered" if slack_sent else "Slack webhook not configured or delivery failed")
    except Exception as e:
        _step(trace, "Slack sent", "FAILED", str(e))

    return sheets_updated, slack_sent
