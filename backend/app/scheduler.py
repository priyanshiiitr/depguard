"""
Scheduled monitoring: re-scan a repository every N minutes or at fixed daily times,
and alert Slack / log to Sheets only when the findings change.

Scoping decisions:
- Scheduled scans analyze and alert only. They never open a pull request: code
  changes require an explicit human click ("Create Remediation PR"), and a timer
  is not a human.
- No new dependencies (no APScheduler, no cron parser): one asyncio loop started
  with the app and two schedule types, which cover "every 5 minutes" and
  "twice a day".
- In memory, like the OAuth connections: schedules stop when the server stops. A
  pasted GitHub token is held for the schedule only and never returned by the API.
"""
import asyncio
import re
import secrets
from datetime import datetime, timedelta

from . import oauth
from .analyzer import analyze_repo, AnalysisError
from .clients import slack, sheets
from .clients.github import parse_repo_url, GitHubError

TICK_SECONDS = 5
MIN_INTERVAL_MINUTES = 1
MAX_JOBS = 10
MAX_HISTORY = 10

JOBS: dict[str, dict] = {}
_RUNNING_TASKS: set = set()
_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def _now() -> datetime:
    return datetime.now().astimezone()


def now_iso() -> str:
    return _now().isoformat()


def parse_daily_times(raw) -> list[str]:
    parts = raw.split(",") if isinstance(raw, str) else list(raw or [])
    times = set()
    for part in parts:
        part = str(part).strip()
        if not part:
            continue
        m = _TIME_RE.match(part)
        if not m:
            raise ValueError(f"Invalid time {part!r}; use 24-hour HH:MM, e.g. 09:00")
        times.add(f"{int(m.group(1)):02d}:{m.group(2)}")
    if not times:
        raise ValueError("Provide at least one daily time, e.g. 09:00, 18:00")
    return sorted(times)


def compute_next_run(job: dict, after: datetime) -> datetime:
    if job["schedule_type"] == "interval":
        return after + timedelta(minutes=job["interval_minutes"])
    candidates = []
    for day_offset in (0, 1):
        day = after + timedelta(days=day_offset)
        for t in job["daily_times"]:
            hour, minute = map(int, t.split(":"))
            candidate = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate > after:
                candidates.append(candidate)
    return min(candidates)


def schedule_label(job: dict) -> str:
    if job["schedule_type"] == "interval":
        mins = job["interval_minutes"]
        if mins % 60 == 0:
            hours = mins // 60
            return "Every hour" if hours == 1 else f"Every {hours} hours"
        return "Every minute" if mins == 1 else f"Every {mins} minutes"
    return "Daily at " + ", ".join(job["daily_times"])


def public_view(job: dict) -> dict:
    view = {k: v for k, v in job.items() if not k.startswith("_")}
    view["label"] = schedule_label(job)
    view["has_latest_result"] = job["_last_result"] is not None
    return view


def list_jobs() -> list[dict]:
    return [public_view(j) for j in sorted(JOBS.values(), key=lambda j: j["created_at"])]


def _launch(job: dict, trigger: str) -> None:
    task = asyncio.create_task(run_job(job, trigger))
    _RUNNING_TASKS.add(task)
    task.add_done_callback(_RUNNING_TASKS.discard)


def create_job(repo_url: str, github_token: str | None, schedule_type: str,
               interval_minutes: int | None = None, daily_times=None, notify: bool = True) -> dict:
    if len(JOBS) >= MAX_JOBS:
        raise ValueError(f"At most {MAX_JOBS} schedules can exist at once; delete one first.")
    try:
        owner, repo = parse_repo_url(repo_url)
    except GitHubError as e:
        raise ValueError(str(e))

    job = {
        "id": secrets.token_hex(4),
        "repo_url": repo_url.strip(),
        "repo": f"{owner}/{repo}",
        "schedule_type": schedule_type,
        "interval_minutes": None,
        "daily_times": None,
        "notify": bool(notify),
        "paused": False,
        "running": False,
        "created_at": now_iso(),
        "next_run_at": None,
        "last_run_at": None,
        "last_run": None,
        "history": [],
        "run_count": 0,
        "_github_token": github_token or None,
        "_previous_findings": None,
        "_last_result": None,
    }
    if schedule_type == "interval":
        if not interval_minutes or int(interval_minutes) < MIN_INTERVAL_MINUTES:
            raise ValueError(f"Interval must be at least {MIN_INTERVAL_MINUTES} minute(s).")
        job["interval_minutes"] = int(interval_minutes)
    elif schedule_type == "daily":
        job["daily_times"] = parse_daily_times(daily_times)
    else:
        raise ValueError("schedule_type must be 'interval' or 'daily'.")

    # The first scan runs immediately as the baseline; later scans follow the schedule.
    job["next_run_at"] = compute_next_run(job, _now()).isoformat()
    JOBS[job["id"]] = job
    _launch(job, "initial")
    return job


def get_job(job_id: str) -> dict | None:
    return JOBS.get(job_id)


def run_now(job: dict) -> None:
    if not job["running"]:
        _launch(job, "manual")


def set_paused(job: dict, paused: bool) -> None:
    job["paused"] = paused
    if not paused:
        job["next_run_at"] = compute_next_run(job, _now()).isoformat()


def delete_job(job_id: str) -> None:
    JOBS.pop(job_id, None)


def _finding_key(f: dict) -> tuple:
    return (f.get("ecosystem"), f.get("type"), f.get("dependency"), f.get("current_version"), f.get("advisory_id"))


def _describe(f: dict) -> str:
    return f"{f.get('ecosystem') or '-'} {f['dependency']}@{f.get('current_version') or '-'}"


async def _notify(job: dict, result: dict, new: list, resolved: list, is_baseline: bool) -> tuple[bool, bool]:
    if is_baseline:
        rows_source = [(f, "SCHEDULED SCAN: BASELINE") for f in result["findings"]]
    else:
        rows_source = [(f, "SCHEDULED SCAN: NEW FINDING") for f in new] + [(f, "SCHEDULED SCAN: RESOLVED") for f in resolved]
    rows = [
        {
            "repo": result["repo"], "dependency": f["dependency"], "current_version": f.get("current_version") or "",
            "recommended_version": f.get("min_safe_version") or "-", "risk": f["risk"],
            "advisory": f.get("advisory_id") or "", "pr_url": "", "status": status,
        }
        for f, status in rows_source
    ]

    sheets_updated = False
    if rows:
        try:
            creds, sheet_id = oauth.get_google_override()
            sheets_updated = await asyncio.to_thread(sheets.append_remediation_rows, rows, creds, sheet_id)
        except Exception:
            sheets_updated = False

    try:
        slack_sent = await slack.send_scan_alert(
            repo=result["repo"], schedule=schedule_label(job), overall_risk=result["overall_risk"],
            findings=result["findings"], new=new, resolved=resolved, is_baseline=is_baseline,
            webhook_url=oauth.get_slack_webhook_override(),
        )
    except Exception:
        slack_sent = False
    return slack_sent, sheets_updated


async def run_job(job: dict, trigger: str) -> None:
    if job["running"]:
        return
    job["running"] = True
    record = {"started_at": now_iso(), "trigger": trigger}
    try:
        result = await analyze_repo(job["repo_url"], github_token=job["_github_token"])
        current = {_finding_key(f): f for f in result["findings"]}
        previous = job["_previous_findings"]
        is_baseline = previous is None
        new = [] if is_baseline else [f for k, f in current.items() if k not in previous]
        resolved = [] if is_baseline else [f for k, f in previous.items() if k not in current]
        job["_previous_findings"] = current
        job["_last_result"] = result

        record.update({
            "status": "SUCCESS",
            "baseline": is_baseline,
            "overall_risk": result["overall_risk"],
            "findings": len(result["findings"]),
            "auto_fixable": sum(1 for f in result["findings"] if f["recommended_action"] == "AUTO_REMEDIATE"),
            "new": len(new),
            "resolved": len(resolved),
            "new_items": [_describe(f) for f in new[:10]],
            "resolved_items": [_describe(f) for f in resolved[:10]],
        })

        if not job["notify"]:
            record.update({"slack_sent": False, "sheets_updated": False, "notify_note": "Alerts are off for this schedule"})
        elif is_baseline or new or resolved:
            slack_sent, sheets_updated = await _notify(job, result, new, resolved, is_baseline)
            record.update({
                "slack_sent": slack_sent, "sheets_updated": sheets_updated,
                "notify_note": "Baseline reported" if is_baseline else "Changes reported",
            })
        else:
            record.update({"slack_sent": False, "sheets_updated": False, "notify_note": "No change since last scan, no alert sent"})
    except AnalysisError as e:
        record.update({"status": "FAILED", "error": e.message})
    except Exception as e:
        record.update({"status": "FAILED", "error": f"Unexpected error: {e}"})
    finally:
        record["finished_at"] = now_iso()
        job["last_run_at"] = record["finished_at"]
        job["last_run"] = record
        job["history"] = ([record] + job["history"])[:MAX_HISTORY]
        job["run_count"] += 1
        job["running"] = False


async def run_loop() -> None:
    while True:
        try:
            now = _now()
            for job in list(JOBS.values()):
                if job["paused"] or not job["next_run_at"]:
                    continue
                if datetime.fromisoformat(job["next_run_at"]) <= now:
                    job["next_run_at"] = compute_next_run(job, now).isoformat()
                    if not job["running"]:
                        _launch(job, "schedule")
        except Exception:
            pass  # one bad job must never stop the scheduler loop
        await asyncio.sleep(TICK_SECONDS)
