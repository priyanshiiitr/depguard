import httpx
from .. import config


async def send_remediation_notification(repo: str, changes: list[dict], pr_url: str | None, overall_risk: str, detection_only: list[dict] | None = None, webhook_url: str | None = None) -> bool:
    """changes: [{"dependency", "old_version", "new_version", "risk"}]
    detection_only: findings from ecosystems DepGuard can detect but not yet auto-fix --
    surfaced here rather than silently dropped just because they aren't in the PR.
    webhook_url: per-connection override (e.g. from the OAuth "Connect Slack" flow),
    takes precedence over the server's SLACK_WEBHOOK_URL env var.
    Returns True if the Slack message was accepted, False otherwise (never raises)."""
    target_webhook = webhook_url or config.SLACK_WEBHOOK_URL
    if not target_webhook:
        return False

    lines = ["*DepGuard completed a dependency remediation.*" if changes else "*DepGuard analysis found advisories requiring manual review.*"]
    lines.append(f"*Repository:* {repo}")
    for c in changes:
        lines.append(
            f"*Dependency:* {c['dependency']}  |  *Old:* {c['old_version']}  |  *New:* {c['new_version']}  |  *Risk:* {c['risk']}"
        )
    if detection_only:
        lines.append(f"*Advisory detected -- manual upgrade required ({len(detection_only)}):*")
        for f in detection_only:
            lines.append(
                f"  - `{f.get('ecosystem')}` {f['dependency']}@{f['current_version']}  |  *Risk:* {f['risk']}  |  {f.get('advisory_id') or 'advisory'}"
            )
    lines.append(f"*Overall risk:* {overall_risk}")
    if pr_url:
        lines.append(f"*PR:* {pr_url}")

    payload = {"text": "\n".join(lines)}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(target_webhook, json=payload)
            return r.status_code == 200
    except httpx.HTTPError:
        return False
