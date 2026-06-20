"""Async deep-domain web crawler — BFS internal link harvest with contact extraction."""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}(?:[-.\s]?\d{1,5})?"
)
_SOCIAL_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("twitter", re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[\w./%-]+", re.I)),
    ("facebook", re.compile(r"https?://(?:www\.)?facebook\.com/[\w./%-]+", re.I)),
    ("linkedin", re.compile(r"https?://(?:www\.)?linkedin\.com/[\w./%-]+", re.I)),
    ("instagram", re.compile(r"https?://(?:www\.)?instagram\.com/[\w./%-]+", re.I)),
    ("github", re.compile(r"https?://(?:www\.)?github\.com/[\w./%-]+", re.I)),
    ("youtube", re.compile(r"https?://(?:www\.)?(?:youtube\.com|youtu\.be)/[\w./?&=%-]+", re.I)),
)


def normalize_domain(raw: str) -> str:
    """Strip scheme, path, port, and leading ``www.`` from a domain input."""
    raw = (raw or "").strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0].split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


class _PageParser(HTMLParser):
    """Extract links, title, meta description, and raw text from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.title_parts: List[str] = []
        self.meta_description = ""
        self.text_parts: List[str] = []
        self._in_title = False
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {k: (v or "") for k, v in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self.links.append(href)
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            if attr_map.get("name", "").lower() == "description":
                self.meta_description = attr_map.get("content", "").strip()
        elif tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        elif not self._in_script and not self._in_style:
            self.text_parts.append(data)


def _same_domain(url: str, apex: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return False
    if host.startswith("www."):
        host = host[4:]
    return host == apex or host.endswith("." + apex)


def _extract_page_data(html: str, base_url: str) -> Dict[str, Any]:
    parser = _PageParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass

    title = "".join(parser.title_parts).strip()
    body_text = " ".join(parser.text_parts)
    combined = f"{html}\n{body_text}"

    emails = sorted({m.lower() for m in _EMAIL_RE.findall(combined)})
    phones: Set[str] = set()
    for match in _PHONE_RE.findall(combined):
        digits = re.sub(r"\D", "", match)
        if 7 <= len(digits) <= 15:
            phones.add(match.strip())

    social: List[str] = []
    seen_social: Set[str] = set()
    for _name, pattern in _SOCIAL_PATTERNS:
        for link in pattern.findall(combined):
            if link not in seen_social:
                seen_social.add(link)
                social.append(link)

    internal_links: List[str] = []
    seen_links: Set[str] = set()
    for href in parser.links:
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        clean = parsed._replace(fragment="").geturl()
        if clean not in seen_links:
            seen_links.add(clean)
            internal_links.append(clean)

    return {
        "title": title,
        "meta_description": parser.meta_description,
        "emails": emails,
        "phones": sorted(phones),
        "links": social,
        "internal_links": internal_links,
    }


async def _fetch_page(
    client: "httpx.AsyncClient",
    sem: asyncio.Semaphore,
    url: str,
    timeout: float,
) -> Optional[str]:
    async with sem:
        try:
            resp = await client.get(url, timeout=timeout, follow_redirects=True)
            if resp.status_code >= 400:
                return None
            return resp.text
        except Exception:
            return None


async def crawl_domain(
    domain: str,
    max_depth: int = 2,
    max_pages: int = 30,
) -> Dict[str, Any]:
    """BFS-crawl *domain* and extract contact intelligence from each page."""
    apex = normalize_domain(domain)
    if not apex or "." not in apex:
        return {"success": False, "error": "A valid domain is required."}
    if httpx is None:
        return {
            "success": False,
            "error": "httpx is not installed. Install with: pip install 'httpx[socks]'.",
        }

    max_depth = max(0, min(int(max_depth), 5))
    max_pages = max(1, min(int(max_pages), 100))

    start_urls = [f"https://{apex}/", f"http://{apex}/"]
    visited: Set[str] = set()
    queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
    for start in start_urls:
        await queue.put((start, 0))

    pages_crawled: List[Dict[str, Any]] = []
    all_emails: Set[str] = set()
    sem = asyncio.Semaphore(10)
    timeout = 12.0

    client_kwargs: Dict[str, Any] = {
        "headers": Config.get_random_headers(),
        "follow_redirects": True,
    }
    proxy = Config.get_httpx_proxy()
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        while not queue.empty() and len(pages_crawled) < max_pages:
            url, depth = await queue.get()
            normalized = urlparse(url)._replace(fragment="").geturl()
            if normalized in visited:
                continue
            visited.add(normalized)

            html = await _fetch_page(client, sem, normalized, timeout)
            if html is None:
                if depth == 0 and normalized.startswith("https://"):
                    await queue.put((normalized.replace("https://", "http://", 1), depth))
                continue

            data = _extract_page_data(html, normalized)
            page_entry = {
                "url": normalized,
                "title": data["title"],
                "meta_description": data["meta_description"],
                "emails": data["emails"],
                "phones": data["phones"],
                "links": data["links"],
            }
            pages_crawled.append(page_entry)
            all_emails.update(data["emails"])

            if depth < max_depth:
                for link in data["internal_links"]:
                    if _same_domain(link, apex) and link not in visited:
                        await queue.put((link, depth + 1))

    return {
        "success": True,
        "domain": apex,
        "pages_crawled": pages_crawled,
        "all_emails": sorted(all_emails),
        "total_pages": len(pages_crawled),
    }


def crawl_domain_sync(domain: str, max_depth: int = 2, max_pages: int = 30) -> Dict[str, Any]:
    """Synchronous wrapper for Flask routes and CLI."""
    try:
        return asyncio.run(crawl_domain(domain, max_depth=max_depth, max_pages=max_pages))
    except Exception as exc:
        return {"success": False, "error": f"Crawl failed: {exc}"}
