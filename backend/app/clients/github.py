import base64
import re
import httpx
from .. import config


class GitHubError(Exception):
    pass


def parse_repo_url(repo_url: str):
    repo_url = repo_url.strip().rstrip("/")
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+?)(\.git)?$", repo_url)
    if not m:
        raise GitHubError(f"Could not parse GitHub repository URL: {repo_url}")
    return m.group(1), m.group(2)


def _headers():
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return headers


class GitHubClient:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=config.GITHUB_API, headers=_headers(), timeout=20.0)

    async def close(self):
        await self.client.aclose()

    async def get_repo(self, owner: str, repo: str) -> dict:
        r = await self.client.get(f"/repos/{owner}/{repo}")
        if r.status_code == 404:
            raise GitHubError("Repository not found (or private without access).")
        if r.status_code == 403:
            raise GitHubError("GitHub API rate limit or permission error while reading repository.")
        r.raise_for_status()
        return r.json()

    async def get_file(self, owner: str, repo: str, path: str, ref: str):
        """Returns (content_str, sha) or (None, None) if the file does not exist."""
        r = await self.client.get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
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

    async def create_branch(self, owner: str, repo: str, new_branch: str, base_sha: str):
        r = await self.client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        if r.status_code == 422:
            # branch already exists - reuse it
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
