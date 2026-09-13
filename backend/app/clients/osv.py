import httpx
from .. import config


class OSVClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=config.OSV_API, timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def query_batch(self, packages: list[dict]) -> list[dict]:
        """packages: [{"name": str, "version": str}]
        Returns list aligned with input, each item a dict with 'vulns': [{'id':...}, ...] (possibly empty)."""
        if not packages:
            return []
        queries = [
            {"package": {"name": p["name"], "ecosystem": "npm"}, "version": p["version"]}
            for p in packages
        ]
        r = await self.client.post("/v1/querybatch", json={"queries": queries})
        r.raise_for_status()
        results = r.json().get("results", [])
        # pad in case of mismatch
        while len(results) < len(packages):
            results.append({})
        return results

    async def get_vuln(self, vuln_id: str) -> dict:
        r = await self.client.get(f"/v1/vulns/{vuln_id}")
        r.raise_for_status()
        return r.json()
