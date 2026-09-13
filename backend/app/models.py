from typing import Optional, Union
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None  # per-request override; falls back to server .env GITHUB_TOKEN if unset


class RemediateRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None


class ScheduleCreateRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None
    schedule_type: str = "interval"  # "interval" (every N minutes) or "daily" (fixed HH:MM times, server local time)
    interval_minutes: Optional[int] = None
    daily_times: Optional[Union[str, list[str]]] = None
    notify: bool = True
