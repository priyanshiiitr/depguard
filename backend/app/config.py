import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
GOOGLE_SHEETS_ID = os.getenv("GOOGLE_SHEETS_ID", "")
GOOGLE_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# OAuth ("Connect Slack" / "Connect Google Sheets" buttons) -- optional. Without these,
# the app still works via the static SLACK_WEBHOOK_URL / GOOGLE_SERVICE_ACCOUNT_JSON above.
SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
OAUTH_REDIRECT_BASE = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8010")

GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev"
DEPSDEV_API = "https://api.deps.dev"
ENDOFLIFE_API = "https://endoflife.date/api"
GROQ_API = "https://api.groq.com/openai/v1"
GROQ_MODEL = "openai/gpt-oss-120b"
SLACK_OAUTH_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
SLACK_OAUTH_TOKEN_URL = "https://slack.com/api/oauth.v2.access"
GOOGLE_OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Deterministic policy thresholds
EOL_WARNING_DAYS = 90  # flag as "nearing EOL" if EOL date is within this many days
