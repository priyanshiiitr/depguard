"""
LLM Manifest Agent -- extraction ONLY, never a vulnerability decision.

Runs only for manifest files that have no deterministic parser (pom.xml,
build.gradle, Pipfile.lock, pyproject.toml, *.csproj). The LLM's sole job is
to propose {ecosystem, name, version, raw_line} candidates from free-form
text it's better suited to read than a regex. Every candidate is then run
through three deterministic checks before it's allowed anywhere near the
OSV/policy pipeline; anything that fails is dropped and counted, never
guessed into place. The LLM never sees or influences whether something is
vulnerable or which version fixes it -- that remains policy.py, unchanged.
"""
import asyncio
import json
import re

import httpx

from . import config
from .parsers import ParsedDependency

_HEADERS = {"User-Agent": "DepGuard-Hackathon-Agent/1.0 (+https://github.com/priyanshiiitr/depguard)"}

_SYSTEM_PROMPT = (
    "You extract dependency name/version pairs from software manifest files. "
    "Return JSON ONLY: a JSON array, no prose, no markdown code fences, no commentary. "
    "Each element must be an object with exactly these keys: "
    '"ecosystem" (the exact OSV.dev ecosystem string -- one of: PyPI, Maven, NuGet, crates.io, RubyGems, Packagist, Go, npm), '
    '"name" (the package name; for Maven use "groupId:artifactId"), '
    '"version" (the exact version string as it literally appears in the file), '
    '"raw_line" (the exact substring copied verbatim from the file where this dependency and its version appear together). '
    "Omit any dependency whose version is not a concrete literal: do not include placeholders such as "
    '"${spring.version}", version ranges such as "^1.2.0" or ">=2.0", the word "latest", or a version inherited '
    "from a parent POM / BOM with no literal value written in this file. Never guess or infer a version that "
    "is not explicitly written next to the dependency. If you are not certain a line pins a concrete dependency "
    "version, omit it entirely rather than include it."
)

_CONCRETE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-_]*$")
_PLACEHOLDER_SUBSTRINGS = ("$", "{", "}", "^", "~", "*", ">", "<", "latest", "snapshot")


def _is_concrete_version(version) -> bool:
    if not isinstance(version, str) or not version:
        return False
    if not _CONCRETE_VERSION_RE.match(version):
        return False
    lower = version.lower()
    return not any(marker in lower for marker in _PLACEHOLDER_SUBSTRINGS)


def _strip_markdown_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


async def _check_pypi(client, name, version):
    r = await client.get(f"https://pypi.org/pypi/{name}/{version}/json", headers=_HEADERS)
    return r.status_code == 200


async def _check_crates(client, name, version):
    r = await client.get(f"https://crates.io/api/v1/crates/{name}/{version}", headers=_HEADERS)
    return r.status_code == 200


async def _check_rubygems(client, name, version):
    r = await client.get(f"https://rubygems.org/api/v1/versions/{name}.json", headers=_HEADERS)
    if r.status_code != 200:
        return False
    return any(v.get("number") == version for v in r.json())


async def _check_packagist(client, name, version):
    r = await client.get(f"https://repo.packagist.org/p2/{name}.json", headers=_HEADERS)
    if r.status_code != 200:
        return False
    packages = (r.json().get("packages") or {}).get(name, [])
    return any(p.get("version") == version for p in packages)


async def _check_maven(client, name, version):
    if ":" not in name:
        return False
    group, artifact = name.split(":", 1)
    params = {"q": f'g:"{group}" AND a:"{artifact}" AND v:"{version}"', "rows": 1, "wt": "json"}
    r = await client.get("https://search.maven.org/solrsearch/select", params=params, headers=_HEADERS)
    if r.status_code != 200:
        return False
    return r.json().get("response", {}).get("numFound", 0) > 0


async def _check_nuget(client, name, version):
    name_l = name.lower()
    r = await client.get(f"https://api.nuget.org/v3-flatcontainer/{name_l}/{version}/{name_l}.nuspec", headers=_HEADERS)
    return r.status_code == 200


async def _check_go(client, name, version):
    r = await client.get(f"https://proxy.golang.org/{name.lower()}/@v/{version}.info", headers=_HEADERS)
    return r.status_code == 200


REGISTRY_CHECKS = {
    "PyPI": _check_pypi,
    "crates.io": _check_crates,
    "RubyGems": _check_rubygems,
    "Packagist": _check_packagist,
    "Maven": _check_maven,
    "NuGet": _check_nuget,
    "Go": _check_go,
}


async def _verify_entry(client: httpx.AsyncClient, sema: asyncio.Semaphore, file_text: str, entry: dict):
    """Returns (ParsedDependency, None) on success or (None, reason) on rejection.
    Order matters: (a) raw_line verbatim in file, (b) concrete version literal,
    (c) name@version exists in the real registry."""
    if not isinstance(entry, dict):
        return None, "malformed LLM output entry (not an object)"

    raw_line = entry.get("raw_line")
    name = entry.get("name")
    version = entry.get("version")
    ecosystem = entry.get("ecosystem")

    if not (isinstance(raw_line, str) and raw_line and isinstance(name, str) and name and isinstance(ecosystem, str) and ecosystem):
        return None, "malformed LLM output entry (missing ecosystem/name/raw_line)"

    if raw_line not in file_text:
        return None, "fabricated raw_line: substring not found verbatim in the source file"

    if not _is_concrete_version(version):
        return None, f"version {version!r} is not a concrete literal (placeholder, range, or inherited)"

    check_fn = REGISTRY_CHECKS.get(ecosystem)
    if check_fn is None:
        return None, f"no registry verifier available for ecosystem {ecosystem!r}"

    async with sema:
        try:
            exists = await asyncio.wait_for(check_fn(client, name, version), timeout=10.0)
        except Exception as e:
            return None, f"registry check failed: {e}"

    if not exists:
        return None, f"{name}@{version} does not exist in the {ecosystem} registry"

    return ParsedDependency(name=name, version=version, ecosystem=ecosystem, raw_line=raw_line), None


async def verify_entry(file_text: str, entry: dict):
    """Standalone single-entry verification (used by the eval harness to test
    the verifier deterministically, with no LLM call and no API key required)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await _verify_entry(client, asyncio.Semaphore(1), file_text, entry)


async def extract_and_verify(filename: str, file_text: str) -> dict:
    """Returns {"extracted": int, "verified": [ParsedDependency,...], "rejected": [{"raw","reason"},...], "skipped_reason": str|None}."""
    if not config.GROQ_API_KEY:
        return {"extracted": 0, "verified": [], "rejected": [], "skipped_reason": "GROQ_API_KEY not configured"}

    truncated = file_text[:12000]
    user_prompt = f"Filename: {filename}\n\nFile content:\n{truncated}"

    raw_entries = []
    llm_error = None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{config.GROQ_API}/chat/completions",
                headers={"Authorization": f"Bearer {config.GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": config.GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0,
                    "max_tokens": 4000,
                    "reasoning_effort": "low",
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            content = _strip_markdown_fence(content)
            raw_entries = json.loads(content)
            if not isinstance(raw_entries, list):
                raw_entries = []
    except Exception as e:
        llm_error = str(e)

    verified: list[ParsedDependency] = []
    rejected: list[dict] = []

    if llm_error:
        rejected.append({"raw": "<LLM call>", "reason": f"LLM extraction failed: {llm_error}"})
        return {"extracted": 0, "verified": verified, "rejected": rejected, "skipped_reason": None}

    dict_entries = [e for e in raw_entries if isinstance(e, dict)]
    sema = asyncio.Semaphore(5)
    async with httpx.AsyncClient(timeout=10.0) as client:
        results = await asyncio.gather(*[_verify_entry(client, sema, file_text, e) for e in dict_entries]) if dict_entries else []

    for entry, (dep, reason) in zip(dict_entries, results):
        if dep is not None:
            verified.append(dep)
        else:
            rejected.append({"raw": entry.get("raw_line", str(entry)[:200]), "reason": reason})

    return {"extracted": len(raw_entries), "verified": verified, "rejected": rejected, "skipped_reason": None}
