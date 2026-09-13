import re
from datetime import date, datetime, timedelta
import httpx
from .. import config


class EOLClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=config.ENDOFLIFE_API, timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def get_cycles(self, product: str):
        try:
            r = await self.client.get(f"/{product}.json")
            if r.status_code != 200:
                return None
            return r.json()
        except httpx.HTTPError:
            return None


def extract_major_version(engine_spec: str):
    """Extract the leading major version number from a package.json engines
    spec like '>=14.0.0', '^18.x', '16', '14.17.0'. Returns int or None."""
    if not engine_spec:
        return None
    m = re.search(r"(\d+)", engine_spec)
    if not m:
        return None
    return int(m.group(1))


def classify_eol(cycle_entry: dict) -> tuple[str, str]:
    """Given an endoflife.date cycle entry, return (status, reason).
    status in {"supported", "nearing_eol", "eol", "unknown"}."""
    eol = cycle_entry.get("eol")
    if eol is False or eol is None:
        return "supported", "No EOL date published; treated as supported."
    if eol is True:
        return "eol", "Marked end-of-life with no specific date."
    try:
        eol_date = datetime.strptime(eol, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return "unknown", "Could not parse EOL date."
    today = date.today()
    if eol_date < today:
        return "eol", f"End-of-life since {eol}."
    if eol_date < today + timedelta(days=config.EOL_WARNING_DAYS):
        return "nearing_eol", f"Reaches end-of-life on {eol} (within {config.EOL_WARNING_DAYS} days)."
    return "supported", f"Supported until {eol}."
