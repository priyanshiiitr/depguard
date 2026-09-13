from urllib.parse import quote
import httpx

_REGISTRY = "https://registry.npmjs.org"


class NpmRegistryClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=_REGISTRY, timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def get_version_metadata(self, name: str, version: str):
        """Returns the real npm registry record for name@version (dist.tarball,
        dist.integrity, license, etc.), or None if not found. This is the
        authoritative source used to patch package-lock.json entries."""
        enc_name = quote(name, safe="") if not name.startswith("@") else name.replace("/", "%2f")
        try:
            r = await self.client.get(f"/{enc_name}/{version}")
            if r.status_code != 200:
                return None
            return r.json()
        except httpx.HTTPError:
            return None
