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


async def remediate_repo(repo_url: str) -> dict:
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
    # Phase 1 safety guard: only npm remediation is wired up so far (patch_package_json /
    # patch_lockfile below are npm-specific). Other ecosystems can already reach
    # AUTO_REMEDIATE via policy.py's ecosystem-agnostic rules; until Phase 2 adds their
    # own remediation path (or the DETECTION_ONLY gate), they must not be acted on here.
    auto_findings = [f for f in findings if f["recommended_action"] == "AUTO_REMEDIATE" and f.get("ecosystem", "npm") == "npm"]
    if not auto_findings:
        _step(trace, "Safety check", "NEEDS_REVIEW", "No findings meet the conservative bar for automatic remediation. No PR was created.")
        return {
            "repo": full_name,
            "status": "NEEDS_REVIEW",
            "branch": None,
            "pr_url": None,
            "remediated": [],
            "skipped": [f["dependency"] for f in findings],
            "trace": trace,
            "sheets_updated": False,
            "slack_sent": False,
        }

    gh = GitHubClient()
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

        pkg_content = cached["package_json_content"]
        lock_content = cached["lock_content"]
        lock_data = cached["lock_data"]
        changes = []

        for f in auto_findings:
            name, old_version, new_version = f["dependency"], f["current_version"], f["min_safe_version"]
            meta = await npm.get_version_metadata(name, new_version)
            if meta is None:
                _step(trace, "Files updated", "NEEDS_REVIEW", f"Could not fetch npm registry metadata for {name}@{new_version}; skipped.")
                continue
            pkg_content = lockfile.patch_package_json(pkg_content, name, new_version)
            lock_content = lockfile.patch_lockfile(lock_content, name, old_version, new_version, meta)
            changes.append({"dependency": name, "old_version": old_version, "new_version": new_version, "risk": f["risk"], "advisory": f.get("advisory_id") or ""})

        if not changes:
            msg = "None of the recommended upgrades could be resolved against the npm registry."
            _step(trace, "Files updated", "FAILED", msg)
            raise RemediationError(msg, trace)

        try:
            await gh.update_file(
                owner, repo, "package.json", branch_name, pkg_content, cached["package_json_sha"],
                f"depguard: bump {', '.join(c['dependency'] for c in changes)} for security fix(es)",
            )
            await gh.update_file(
                owner, repo, "package-lock.json", branch_name, lock_content, cached["lock_sha"],
                f"depguard: update lockfile for {', '.join(c['dependency'] for c in changes)}",
            )
            _step(trace, "Files updated", "SUCCESS", f"package.json and package-lock.json updated for {len(changes)} dependency(ies)")
            _step(trace, "Commit created", "SUCCESS", "2 commits pushed to remediation branch")
        except GitHubError as e:
            _step(trace, "Files updated", "FAILED", str(e))
            raise RemediationError(str(e), trace)

        pr_body_lines = [
            "**DepGuard automated remediation**",
            "",
            "This PR was opened by DepGuard after analyzing this repository's `package-lock.json` against OSV.dev, deps.dev, and endoflife.date.",
            "",
            "| Dependency | Old | New | Risk | Advisory | Reason |",
            "|---|---|---|---|---|---|",
        ]
        for f in auto_findings:
            pr_body_lines.append(
                f"| {f['dependency']} | {f['current_version']} | {f['min_safe_version']} | {f['risk']} | {f.get('advisory_id') or '-'} | {f['reason']} |"
            )
        pr_body_lines += [
            "",
            "**Note:** `package-lock.json` has been patched for the changed package entries only. "
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

        overall_risk = policy.max_risk([c["risk"] for c in changes])

        sheets_updated = False
        try:
            rows = [
                {
                    "repo": full_name, "dependency": c["dependency"], "current_version": c["old_version"],
                    "recommended_version": c["new_version"], "risk": c["risk"], "advisory": c["advisory"],
                    "pr_url": pr_url, "status": "SUCCESS",
                }
                for c in changes
            ]
            sheets_updated = await asyncio.to_thread(sheets.append_remediation_rows, rows)
            _step(trace, "Sheets updated", "SUCCESS" if sheets_updated else "SKIPPED",
                  "Remediation log appended to Google Sheets" if sheets_updated else "Google Sheets not configured or write failed")
        except Exception as e:
            _step(trace, "Sheets updated", "FAILED", str(e))

        slack_sent = False
        try:
            slack_sent = await slack.send_remediation_notification(full_name, changes, pr_url, overall_risk)
            _step(trace, "Slack sent", "SUCCESS" if slack_sent else "SKIPPED",
                  "Slack notification delivered" if slack_sent else "Slack webhook not configured or delivery failed")
        except Exception as e:
            _step(trace, "Slack sent", "FAILED", str(e))

        _step(trace, "Final result", "SUCCESS", f"PR opened: {pr_url}")

        skipped = [f["dependency"] for f in findings if f["recommended_action"] != "AUTO_REMEDIATE"]
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
