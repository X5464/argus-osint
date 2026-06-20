"""GitHub public API metadata and commit-email extraction (unauthenticated)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

import requests

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

_GITHUB_API = "https://api.github.com"
_NOREPLY_RE = re.compile(
    r"(noreply@github\.com|users\.noreply\.github\.com|@users\.noreply\.github\.com$)",
    re.I,
)


def _github_headers() -> Dict[str, str]:
    headers = Config.get_random_headers()
    headers["Accept"] = "application/vnd.github+json"
    try:
        from vault import get_key
    except ImportError:
        from api.vault import get_key
    token = get_key("github")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_get(path: str, params: Optional[Dict[str, str]] = None) -> tuple[Optional[Any], Optional[str]]:
    """GET a GitHub API path; return (json_body, error_message)."""
    url = f"{_GITHUB_API}{path}"
    try:
        resp = requests.get(
            url,
            headers=_github_headers(),
            params=params,
            proxies=Config.get_proxies(),
            timeout=15,
        )
    except requests.RequestException as exc:
        return None, f"Network error: {exc}"

    if resp.status_code == 403:
        remaining = resp.headers.get("X-RateLimit-Remaining", "?")
        return None, f"GitHub API rate limit (403) — remaining: {remaining}. Retry later."
    if resp.status_code == 404:
        return None, "GitHub resource not found (404)."
    if resp.status_code != 200:
        return None, f"GitHub returned HTTP {resp.status_code}."

    try:
        return resp.json(), None
    except ValueError:
        return None, "GitHub response was not valid JSON."


def _clean_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    email = email.strip().lower()
    if not email or _NOREPLY_RE.search(email):
        return None
    if "@" not in email:
        return None
    return email


def _emails_from_push_event(event: Dict[str, Any]) -> Set[str]:
    emails: Set[str] = set()
    for commit in event.get("payload", {}).get("commits", []) or []:
        for key in ("author", "committer"):
            block = commit.get(key) or {}
            cleaned = _clean_email(block.get("email"))
            if cleaned:
                emails.add(cleaned)
    return emails


def _emails_from_repos(username: str) -> tuple[List[str], List[str], Optional[str]]:
    """Fallback: scan recent commits on public repos when events are empty."""
    data, err = _github_get(f"/users/{username}/repos", {"per_page": "10", "sort": "updated"})
    if err or not isinstance(data, list):
        return [], [], err

    repos: List[str] = []
    emails: Set[str] = set()
    for repo in data[:10]:
        name = repo.get("full_name") or repo.get("name", "")
        if name:
            repos.append(name)
        commits, commit_err = _github_get(f"/repos/{name}/commits", {"per_page": "5"})
        if commit_err or not isinstance(commits, list):
            continue
        for commit in commits:
            commit_obj = commit.get("commit") or {}
            for key in ("author", "committer"):
                cleaned = _clean_email((commit_obj.get(key) or {}).get("email"))
                if cleaned:
                    emails.add(cleaned)
    return sorted(emails), repos, None


def extract_github_intel(username: str) -> Dict[str, Any]:
    """Extract public commit emails and repo list for a GitHub username."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"success": False, "error": "A GitHub username is required."}

    events, err = _github_get(f"/users/{username}/events/public", {"per_page": "100"})
    if err and "404" in err:
        return {"success": False, "error": err, "username": username}

    emails: Set[str] = set()
    events_parsed = 0
    if isinstance(events, list):
        for event in events:
            if event.get("type") == "PushEvent":
                events_parsed += 1
                emails.update(_emails_from_push_event(event))

    repos: List[str] = []
    warnings: List[str] = []
    if err:
        warnings.append(err)

    if not emails:
        fallback_emails, repos, repo_err = _emails_from_repos(username)
        if repo_err:
            warnings.append(repo_err)
        emails.update(fallback_emails)

    if not repos:
        repo_data, _ = _github_get(f"/users/{username}/repos", {"per_page": "10"})
        if isinstance(repo_data, list):
            repos = [
                r.get("full_name", r.get("name", ""))
                for r in repo_data
                if r.get("full_name") or r.get("name")
            ]

    return {
        "success": True,
        "username": username,
        "emails": sorted(emails),
        "repos": repos,
        "events_parsed": events_parsed,
        "source": "github_public_api",
        "warnings": warnings,
    }


def extract_github_by_domain(domain: str) -> Dict[str, Any]:
    """Search GitHub for users/code associated with *domain* in email fields."""
    try:
        from modules.domain_crawler import normalize_domain  # type: ignore
    except ImportError:  # pragma: no cover
        from api.modules.domain_crawler import normalize_domain  # type: ignore

    apex = normalize_domain(domain)
    if not apex or "." not in apex:
        return {"success": False, "error": "A valid domain is required."}

    warnings: List[str] = []
    users_found: List[Dict[str, Any]] = []
    code_emails: Set[str] = set()

    user_search, user_err = _github_get("/search/users", {"q": f"{apex} in:email", "per_page": "20"})
    if user_err:
        warnings.append(f"User search: {user_err}")
    elif isinstance(user_search, dict):
        for item in user_search.get("items", []) or []:
            users_found.append({
                "login": item.get("login", ""),
                "url": item.get("html_url", ""),
                "type": item.get("type", ""),
            })

    code_search, code_err = _github_get(
        "/search/code",
        {"q": f'"{apex}" in:email', "per_page": "20"},
    )
    if code_err:
        if "401" in code_err:
            warnings.append(
                "Code search skipped: GitHub code search API requires authentication. "
                "Set a GitHub token using 'keys set github <token>' to enable code-level email harvesting."
            )
        else:
            warnings.append(f"Code search: {code_err}")
    elif isinstance(code_search, dict):
        for item in code_search.get("items", []) or []:
            repo = (item.get("repository") or {}).get("full_name", "")
            if repo:
                users_found.append({"login": repo.split("/")[0], "url": f"https://github.com/{repo}", "type": "code_hit"})

    emails: Set[str] = set()
    for user in users_found[:10]:
        login = user.get("login", "")
        if not login:
            continue
        intel = extract_github_intel(login)
        if intel.get("warnings"):
            warnings.extend(intel["warnings"])
        emails.update(intel.get("emails", []))

    return {
        "success": True,
        "domain": apex,
        "emails": sorted(emails | code_emails),
        "users": users_found,
        "source": "github_public_api",
        "warnings": warnings,
    }
