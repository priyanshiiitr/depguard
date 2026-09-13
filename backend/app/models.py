from typing import Optional
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None  # per-request override; falls back to server .env GITHUB_TOKEN if unset


class RemediateRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None
