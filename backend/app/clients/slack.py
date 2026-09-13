import httpx
from .. import config


async def send_remediation_notification(repo: str, changes: list[dict], pr_url: str, overall_risk: str) -> bool:
    """changes: [{"dependency", "old_version", "new_version", "risk"}]
    Returns True if the Slack message was accepted, False otherwise (never raises)."""
    if not config.SLACK_WEBHOOK_URL:
        return False

    lines = [
        "*DepGuard completed a dependency remediation.*",
        f"*Repository:* {repo}",
    ]
    for c in changes:
        lines.append(
            f"*Dependency:* {c['dependency']}  |  *Old:* {c['old_version']}  |  *New:* {c['new_version']}  |  *Risk:* {c['risk']}"
        )
    lines.append(f"*Overall risk:* {overall_risk}")
    lines.append(f"*PR:* {pr_url}")

    payload = {"text": "\n".join(lines)}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(config.SLACK_WEBHOOK_URL, json=payload)
            return r.status_code == 200
    except httpx.HTTPError:
        return False
