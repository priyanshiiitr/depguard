from urllib.parse import quote
import httpx
from .. import config


class DepsDevClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=config.DEPSDEV_API, timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def get_version_info(self, name: str, version: str):
        """Returns deps.dev version metadata (licenses, etc.) or None if unavailable."""
        enc_name = quote(name, safe="")
        enc_version = quote(version, safe="")
        try:
            r = await self.client.get(f"/v3/systems/npm/packages/{enc_name}/versions/{enc_version}")
            if r.status_code != 200:
                return None
            return r.json()
        except httpx.HTTPError:
            return None

    async def get_package_info(self, name: str):
        """Fallback: fetch package-level info (list of known versions)."""
        enc_name = quote(name, safe="")
        try:
            r = await self.client.get(f"/v3/systems/npm/packages/{enc_name}")
            if r.status_code != 200:
                return None
            return r.json()
        except httpx.HTTPError:
            return None
