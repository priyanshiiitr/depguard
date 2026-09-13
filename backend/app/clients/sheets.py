import json
import os
from datetime import datetime, timezone
from .. import config

_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
_HEADER = ["Timestamp", "Repository", "Dependency", "Current Version", "Recommended Version", "Risk", "Advisory", "PR URL", "Status"]


def _load_credentials():
    from google.oauth2.service_account import Credentials

    raw = config.GOOGLE_SERVICE_ACCOUNT_JSON
    if not raw:
        return None
    if os.path.exists(raw):
        with open(raw, "r", encoding="utf-8") as f:
            info = json.load(f)
    else:
        info = json.loads(raw)
    return Credentials.from_service_account_info(info, scopes=_SCOPES)


def append_remediation_rows(rows: list[dict]) -> bool:
    """rows: [{dependency, current_version, recommended_version, risk, advisory, pr_url, status}]
    Appends one row per remediation to the configured Google Sheet, ensuring a header row exists.
    Returns True on success, False otherwise (never raises)."""
    if not config.GOOGLE_SHEETS_ID or not config.GOOGLE_SERVICE_ACCOUNT_JSON:
        return False
    try:
        from googleapiclient.discovery import build

        creds = _load_credentials()
        if creds is None:
            return False
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        sheet = service.spreadsheets()

        existing = sheet.values().get(spreadsheetId=config.GOOGLE_SHEETS_ID, range="A1:I1").execute()
        if not existing.get("values"):
            sheet.values().update(
                spreadsheetId=config.GOOGLE_SHEETS_ID,
                range="A1",
                valueInputOption="RAW",
                body={"values": [_HEADER]},
            ).execute()

        ts = datetime.now(timezone.utc).isoformat()
        values = [
            [
                ts,
                row["repo"],
                row["dependency"],
                row["current_version"],
                row["recommended_version"],
                row["risk"],
                row.get("advisory", ""),
                row.get("pr_url", ""),
                row.get("status", ""),
            ]
            for row in rows
        ]
        sheet.values().append(
            spreadsheetId=config.GOOGLE_SHEETS_ID,
            range="A1",
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": values},
        ).execute()
        return True
    except Exception:
        return False
