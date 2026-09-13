import asyncio
import base64
import re
import httpx
from .. import config

_TRANSIENT_STATUS = {409, 500, 502, 503, 504}


async def _get_with_retry(client: httpx.AsyncClient, url: str, params: dict | None = None, retries: int = 2) -> httpx.Response:
    """GitHub occasionally returns a transient 409/5xx on GET (e.g. during an
    eventual-consistency window right after a push) that succeeds on immediate
    retry. One short retry here avoids surfacing that as a user-facing error."""
    last_response = None
    for attempt in range(retries + 1):
        r = await client.get(url, params=params)
        if r.status_code not in _TRANSIENT_STATUS:
            return r
        last_response = r
        if attempt < retries:
            await asyncio.sleep(0.6 * (attempt + 1))
    return last_response


class GitHubError(Exception):
    pass


def parse_repo_url(repo_url: str):
    repo_url = repo_url.strip().rstrip("/")
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+?)(\.git)?$", repo_url)
    if not m:
        raise GitHubError(f"Could not parse GitHub repository URL: {repo_url}")
    return m.group(1), m.group(2)


def _headers(token: str | None = None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    effective_token = token or config.GITHUB_TOKEN
    if effective_token:
        headers["Authorization"] = f"Bearer {effective_token}"
    return headers


class GitHubClient:
    def __init__(self, token: str | None = None):
        """token: optional per-request override (e.g. pasted into the UI for a demo)
        that takes precedence over the server's GITHUB_TOKEN env var for this
        client instance only. Never logged, never echoed back in any response."""
        self.client = httpx.AsyncClient(base_url=config.GITHUB_API, headers=_headers(token), timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def get_repo(self, owner: str, repo: str) -> dict:
        r = await _get_with_retry(self.client, f"/repos/{owner}/{repo}")
        if r.status_code == 404:
            raise GitHubError("Repository not found (or private without access).")
        if r.status_code == 403:
            raise GitHubError("GitHub API rate limit or permission error while reading repository.")
        r.raise_for_status()
        return r.json()

    async def list_root_files(self, owner: str, repo: str, ref: str) -> list[str]:
        """Returns filenames (not directories) at the repo root. Used only to find
        wildcard-named files (e.g. *.csproj) that can't be looked up by exact path."""
        r = await self.client.get(f"/repos/{owner}/{repo}/contents/", params={"ref": ref})
        if r.status_code != 200:
            return []
        items = r.json()
        if not isinstance(items, list):
            return []
        return [item["name"] for item in items if item.get("type") == "file"]

    async def get_file(self, owner: str, repo: str, path: str, ref: str):
        """Returns (content_str, sha) or (None, None) if the file does not exist."""
        r = await _get_with_retry(self.client, f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
        if r.status_code == 404:
            return None, None
        if r.status_code == 403:
            raise GitHubError("GitHub API rate limit or permission error while reading file.")
        r.raise_for_status()
        data = r.json()
        content = base64.b64decode(data["content"]).decode("utf-8")
        return content, data["sha"]

    async def get_ref_sha(self, owner: str, repo: str, branch: str) -> str:
        r = await self.client.get(f"/repos/{owner}/{repo}/git/ref/heads/{branch}")
        r.raise_for_status()
        return r.json()["object"]["sha"]

    async def find_open_pr_for_branch(self, owner: str, repo: str, branch: str, base: str) -> str | None:
        """Returns the URL of an already-open PR for this exact branch, if one exists."""
        r = await self.client.get(f"/repos/{owner}/{repo}/pulls", params={"state": "open", "head": f"{owner}:{branch}", "base": base})
        if r.status_code != 200:
            return None
        items = r.json()
        return items[0]["html_url"] if items else None

    async def create_branch(self, owner: str, repo: str, new_branch: str, base_sha: str):
        r = await self.client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        if r.status_code == 422:
            # Branch already exists. Caller (remediator.py) has already confirmed there is no
            # OPEN PR for it before reaching here, so it's safe to assume this is a stale/orphaned
            # branch (e.g. from a previously closed test run) and reset it to base_sha -- otherwise
            # its files would carry SHAs from whatever it was last patched to, and the next
            # update_file() call would fail with a genuine 409 (SHA mismatch), not a transient error.
            reset = await self.client.patch(
                f"/repos/{owner}/{repo}/git/refs/heads/{new_branch}",
                json={"sha": base_sha, "force": True},
            )
            reset.raise_for_status()
            return
        if r.status_code == 403:
            raise GitHubError("GitHub token lacks permission to create a branch (needs Contents: Read and write).")
        r.raise_for_status()

    async def update_file(self, owner: str, repo: str, path: str, branch: str, content: str, sha: str, message: str):
        r = await self.client.put(
            f"/repos/{owner}/{repo}/contents/{path}",
            json={
                "message": message,
                "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
                "sha": sha,
                "branch": branch,
            },
        )
        if r.status_code == 403:
            raise GitHubError("GitHub token lacks permission to update files (needs Contents: Read and write).")
        r.raise_for_status()
        return r.json()

    async def create_pull_request(self, owner: str, repo: str, title: str, body: str, head: str, base: str) -> str:
        r = await self.client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={"title": title, "body": body, "head": head, "base": base},
        )
        if r.status_code == 403:
            raise GitHubError("GitHub token lacks permission to open pull requests (needs Pull requests: Read and write).")
        if r.status_code == 422:
            raise GitHubError(f"GitHub rejected the pull request (already exists or no diff): {r.text}")
        r.raise_for_status()
        return r.json()["html_url"]
