"""
"Connect Slack" / "Connect Google Sheets" OAuth flows for the demo dashboard.

Deliberately simple, matching the hackathon's own guidance (no database, no
elaborate multi-tenant auth): this is a single-process, single-demo-user, purely
in-memory connection store. A visitor clicks "Connect", authorizes in a popup,
and the resulting webhook URL / Sheets credentials are held in this process's
memory only -- never written to disk, never sent back to the browser, and gone
the moment the server restarts. That's the right tradeoff for a live demo, not
a production multi-user SaaS.
"""
import secrets
import httpx

from . import config
from .clients import sheets as sheets_client

# In-memory connection state (see module docstring for why this is fine here).
CONNECTIONS: dict = {"slack": None, "google": None}
_PENDING_STATES: set = set()


def new_state() -> str:
    state = secrets.token_urlsafe(16)
    _PENDING_STATES.add(state)
    return state


def consume_state(state: str) -> bool:
    if state in _PENDING_STATES:
        _PENDING_STATES.discard(state)
        return True
    return False


def slack_configured() -> bool:
    return bool(config.SLACK_CLIENT_ID and config.SLACK_CLIENT_SECRET)


def google_configured() -> bool:
    return bool(config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET)


def slack_authorize_url() -> str:
    state = new_state()
    redirect_uri = f"{config.OAUTH_REDIRECT_BASE}/oauth/slack/callback"
    return (
        f"{config.SLACK_OAUTH_AUTHORIZE_URL}?client_id={config.SLACK_CLIENT_ID}"
        f"&scope=incoming-webhook&redirect_uri={redirect_uri}&state={state}"
    )


def google_authorize_url() -> str:
    state = new_state()
    redirect_uri = f"{config.OAUTH_REDIRECT_BASE}/oauth/google/callback"
    scope = "https://www.googleapis.com/auth/spreadsheets"
    return (
        f"{config.GOOGLE_OAUTH_AUTHORIZE_URL}?client_id={config.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}&response_type=code&scope={scope}"
        f"&access_type=offline&prompt=consent&state={state}"
    )


async def slack_exchange_code(code: str) -> tuple[bool, str]:
    """Exchanges the OAuth code for an incoming webhook. Returns (ok, message)."""
    redirect_uri = f"{config.OAUTH_REDIRECT_BASE}/oauth/slack/callback"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(config.SLACK_OAUTH_TOKEN_URL, data={
                "client_id": config.SLACK_CLIENT_ID,
                "client_secret": config.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            })
            data = r.json()
    except httpx.HTTPError as e:
        return False, f"Network error contacting Slack: {e}"

    if not data.get("ok"):
        return False, f"Slack rejected the OAuth exchange: {data.get('error', 'unknown error')}"

    webhook = data.get("incoming_webhook") or {}
    if not webhook.get("url"):
        return False, "Slack did not return an incoming webhook URL (check the 'incoming-webhook' scope is added)."

    CONNECTIONS["slack"] = {
        "webhook_url": webhook["url"],
        "channel": webhook.get("channel", "unknown channel"),
        "team": (data.get("team") or {}).get("name", "unknown workspace"),
    }
    return True, "Slack connected."


async def google_exchange_code(code: str) -> tuple[bool, str]:
    """Exchanges the OAuth code for tokens, then creates a fresh remediation-log
    spreadsheet in the connecting user's own Drive. Returns (ok, message)."""
    from google.oauth2.credentials import Credentials

    redirect_uri = f"{config.OAUTH_REDIRECT_BASE}/oauth/google/callback"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(config.GOOGLE_OAUTH_TOKEN_URL, data={
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            })
            data = r.json()
    except httpx.HTTPError as e:
        return False, f"Network error contacting Google: {e}"

    if "access_token" not in data:
        return False, f"Google rejected the OAuth exchange: {data.get('error_description') or data.get('error', 'unknown error')}"

    creds = Credentials(
        token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        token_uri=config.GOOGLE_OAUTH_TOKEN_URL,
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        scopes=["https://www.googleapis.com/auth/spreadsheets"],
    )

    sheet = sheets_client.create_spreadsheet(creds, "DepGuard Remediation Log")
    if sheet is None:
        return False, "Connected to Google, but failed to create a spreadsheet (check the Sheets API is enabled)."

    CONNECTIONS["google"] = {"credentials": creds, "sheet_id": sheet["id"], "sheet_url": sheet["url"]}
    return True, "Google Sheets connected."


def get_slack_webhook_override() -> str | None:
    conn = CONNECTIONS.get("slack")
    return conn["webhook_url"] if conn else None


def get_google_override():
    """Returns (credentials, sheet_id) or (None, None)."""
    conn = CONNECTIONS.get("google")
    if not conn:
        return None, None
    return conn["credentials"], conn["sheet_id"]


def status() -> dict:
    slack = CONNECTIONS.get("slack")
    google = CONNECTIONS.get("google")
    return {
        "slack": {
            "available": slack_configured(),
            "connected": slack is not None,
            "team": slack["team"] if slack else None,
            "channel": slack["channel"] if slack else None,
        },
        "google": {
            "available": google_configured(),
            "connected": google is not None,
            "sheet_url": google["sheet_url"] if google else None,
        },
    }
