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


def append_remediation_rows(rows: list[dict], creds_override=None, spreadsheet_id: str | None = None) -> bool:
    """rows: [{dependency, current_version, recommended_version, risk, advisory, pr_url, status}]
    Appends one row per remediation to the target Google Sheet, ensuring a header row exists.
    creds_override: an already-built google.oauth2 Credentials object (e.g. from the OAuth
    "Connect Google Sheets" flow) -- takes precedence over the server's service-account config.
    spreadsheet_id: target sheet ID to use with creds_override; falls back to config.GOOGLE_SHEETS_ID.
    Returns True on success, False otherwise (never raises)."""
    target_sheet_id = spreadsheet_id or config.GOOGLE_SHEETS_ID
    if not target_sheet_id or (creds_override is None and not config.GOOGLE_SERVICE_ACCOUNT_JSON):
        return False
    try:
        from googleapiclient.discovery import build

        creds = creds_override or _load_credentials()
        if creds is None:
            return False
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        sheet = service.spreadsheets()

        existing = sheet.values().get(spreadsheetId=target_sheet_id, range="A1:I1").execute()
        if not existing.get("values"):
            sheet.values().update(
                spreadsheetId=target_sheet_id,
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
            spreadsheetId=target_sheet_id,
            range="A1",
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": values},
        ).execute()
        return True
    except Exception:
        return False


def create_spreadsheet(creds, title: str) -> dict | None:
    """Creates a brand-new spreadsheet using OAuth user credentials and returns
    {"id": ..., "url": ...}, or None on failure. Used by the "Connect Google Sheets"
    flow so a visitor gets a fresh log sheet in their own Drive, no pre-sharing needed."""
    try:
        from googleapiclient.discovery import build

        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        result = service.spreadsheets().create(body={
            "properties": {"title": title},
            "sheets": [{"properties": {"title": "Remediation Log"}}],
        }).execute()
        return {"id": result["spreadsheetId"], "url": result["spreadsheetUrl"]}
    except Exception:
        return None
