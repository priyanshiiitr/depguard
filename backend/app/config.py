import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
GOOGLE_SHEETS_ID = os.getenv("GOOGLE_SHEETS_ID", "")
GOOGLE_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev"
DEPSDEV_API = "https://api.deps.dev"
ENDOFLIFE_API = "https://endoflife.date/api"
GROQ_API = "https://api.groq.com/openai/v1"
GROQ_MODEL = "openai/gpt-oss-120b"

# Deterministic policy thresholds
EOL_WARNING_DAYS = 90  # flag as "nearing EOL" if EOL date is within this many days
