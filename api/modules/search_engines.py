"""Dual search engine — Google dork URLs + DuckDuckGo HTML live results.

Supplements offline Google dork generation with scraped DDG result links when
Google CAPTCHAs or blocks manual searches. All outbound requests honour
:class:`api.config.Config` User-Agent rotation and optional Tor proxying.
"""

from __future__ import annotations

import random
import re
import time
from html import unescape
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote_plus, urljoin

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

DDG_HTML_URL = "https://html.duckduckgo.com/html/"
_GOOGLE = "https://www.google.com/search?q="

# Platforms probed via DDG for username footprinting.
_USERNAME_DDG_QUERIES: List[tuple[str, str]] = [
    ("instagram", 'site:instagram.com "{}"'),
    ("twitter", '(site:twitter.com OR site:x.com) "{}"'),
    ("facebook", 'site:facebook.com "{}"'),
    ("reddit", 'site:reddit.com "{}"'),
    ("linkedin", 'site:linkedin.com/in "{}"'),
    ("github", 'site:github.com "{}"'),
    ("youtube", 'site:youtube.com "{}"'),
    ("tiktok", 'site:tiktok.com "{}"'),
]

_EMAIL_RE_TEMPLATE = r"[a-zA-Z0-9._%+-]+@{domain}"


def _normalize_domain(raw: str) -> str:
    """Strip scheme, port, path, and leading ``www.`` from a domain input."""
    raw = (raw or "").strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0].split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


class _DdgResultParser(HTMLParser):
    """Extract result links from DuckDuckGo HTML lite result pages."""

    def __init__(self) -> None:
        super().__init__()
        self.results: List[Dict[str, str]] = []
        self._in_result_a = False
        self._in_snippet = False
        self._current_title_parts: List[str] = []
        self._current_url = ""
        self._current_snippet_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        attr_map = {k: (v or "") for k, v in attrs}
        classes = attr_map.get("class", "")
        if tag == "a" and "result__a" in classes.split():
            self._in_result_a = True
            href = attr_map.get("href", "")
            self._current_url = urljoin(DDG_HTML_URL, href)
            self._current_title_parts = []
        elif tag == "a" and "result__snippet" in classes.split():
            self._in_snippet = True
            self._current_snippet_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_result_a:
            title = unescape("".join(self._current_title_parts)).strip()
            if self._current_url and title:
                self.results.append({
                    "title": title,
                    "url": self._current_url,
                    "snippet": "",
                })
            self._in_result_a = False
            self._current_url = ""
            self._current_title_parts = []
        elif tag == "a" and self._in_snippet:
            snippet = unescape("".join(self._current_snippet_parts)).strip()
            if self.results and snippet:
                self.results[-1]["snippet"] = snippet
            self._in_snippet = False
            self._current_snippet_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_result_a:
            self._current_title_parts.append(data)
        elif self._in_snippet:
            self._current_snippet_parts.append(data)


class _DdgFormParser(HTMLParser):
    """Extract hidden form fields (vqd, s, q) from DDG pagination footer."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: List[Dict[str, str]] = []
        self._current: Dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        attr_map = {k: (v or "") for k, v in attrs}
        if tag == "form":
            action = attr_map.get("action", "")
            if "html" in action or not action:
                self._in_form = True
                self._current = {}
        elif self._in_form and tag == "input":
            name = attr_map.get("name", "")
            if name:
                self._current[name] = attr_map.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            if self._current:
                self.forms.append(dict(self._current))
            self._in_form = False
            self._current = {}


class DualSearchEngine:
    """Google dork URL generation + DuckDuckGo HTML scraping."""

    REQUEST_TIMEOUT = 18.0

    def _ddg_headers(self) -> Dict[str, str]:
        headers = Config.get_random_headers()
        headers.update({
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Referer": DDG_HTML_URL,
            "Upgrade-Insecure-Requests": "1",
        })
        return headers

    def _jitter(self, skip: bool = False) -> None:
        if not skip:
            time.sleep(random.uniform(4.0, 9.0))

    def _decode_response(self, resp: "httpx.Response") -> str:
        try:
            return resp.text
        except UnicodeDecodeError:
            return resp.content.decode("utf-8", errors="replace")

    def parse_ddg_html(self, html: str) -> List[Dict[str, str]]:
        """Parse DDG HTML lite page into structured result dicts."""
        parser = _DdgResultParser()
        try:
            parser.feed(html or "")
            parser.close()
        except Exception:
            pass
        if parser.results:
            return parser.results
        # Fallback regex when markup shifts slightly.
        fallback: List[Dict[str, str]] = []
        link_re = re.compile(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        for href, raw_title in link_re.findall(html or ""):
            title = unescape(re.sub(r"<[^>]+>", "", raw_title)).strip()
            url = urljoin(DDG_HTML_URL, href)
            if title and url:
                fallback.append({"title": title, "url": url, "snippet": ""})
        return fallback

    def _ddg_request(self, query: str) -> str:
        """Perform a single DDG HTML search and return raw HTML."""
        if httpx is None:
            raise RuntimeError("httpx is not installed. Install with: pip install 'httpx[http2,socks]'.")

        client_kwargs: Dict[str, Any] = {
            "headers": self._ddg_headers(),
            "timeout": self.REQUEST_TIMEOUT,
            "follow_redirects": True,
            "http2": True,
        }
        proxy = Config.get_httpx_proxy()
        if proxy:
            client_kwargs["proxy"] = proxy

        with httpx.Client(**client_kwargs) as client:
            resp = client.post(DDG_HTML_URL, data={"q": query})
            if resp.status_code in (403, 429):
                raise PermissionError(f"DuckDuckGo returned HTTP {resp.status_code} (rate limited or blocked).")
            resp.raise_for_status()
            return self._decode_response(resp)

    def _extract_ddg_form_fields(self, html: str) -> Dict[str, str]:
        """Return hidden pagination fields from the first DDG result form."""
        parser = _DdgFormParser()
        try:
            parser.feed(html or "")
            parser.close()
        except Exception:
            pass
        for form in parser.forms:
            if form.get("vqd"):
                return form
        # Regex fallback when markup shifts.
        vqd_match = re.search(r'name="vqd"\s+value="([^"]+)"', html or "")
        if vqd_match:
            fields: Dict[str, str] = {"vqd": vqd_match.group(1)}
            for name in ("q", "s", "o", "dc", "kl"):
                m = re.search(rf'name="{name}"\s+value="([^"]*)"', html or "")
                if m:
                    fields[name] = m.group(1)
            return fields
        return {}

    def search_ddg_html_paginated(self, query: str, max_pages: int = 5) -> Dict[str, Any]:
        """Paginate DuckDuckGo HTML lite results with jitter between pages."""
        query = (query or "").strip()
        if not query:
            return {"success": False, "error": "A search query is required.", "source": "duckduckgo"}

        if httpx is None:
            return {
                "success": False,
                "query": query,
                "results": [],
                "pages_fetched": 0,
                "source": "duckduckgo",
                "error": "httpx is not installed.",
            }

        max_pages = max(1, min(int(max_pages), 10))
        all_results: List[Dict[str, str]] = []
        seen_urls: Set[str] = set()
        warnings: List[str] = []
        pages_fetched = 0
        form_data: Dict[str, str] = {"q": query}

        try:
            html = self._ddg_request(query)
            pages_fetched = 1
            for hit in self.parse_ddg_html(html):
                url = hit.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(hit)
            form_data = self._extract_ddg_form_fields(html) or {"q": query}

            for page_num in range(2, max_pages + 1):
                if not form_data.get("vqd"):
                    warnings.append(f"Pagination stopped at page {pages_fetched} — no vqd token.")
                    break
                self._jitter()
                offset = str((page_num - 1) * 30)
                post_data = dict(form_data)
                post_data["q"] = query
                post_data["s"] = offset

                client_kwargs: Dict[str, Any] = {
                    "headers": self._ddg_headers(),
                    "timeout": self.REQUEST_TIMEOUT,
                    "follow_redirects": True,
                    "http2": True,
                }
                proxy = Config.get_httpx_proxy()
                if proxy:
                    client_kwargs["proxy"] = proxy

                with httpx.Client(**client_kwargs) as client:
                    resp = client.post(DDG_HTML_URL, data=post_data)
                    if resp.status_code in (403, 429):
                        warnings.append(f"DuckDuckGo HTTP {resp.status_code} on page {page_num}.")
                        break
                    resp.raise_for_status()
                    page_html = self._decode_response(resp)

                pages_fetched += 1
                page_results = self.parse_ddg_html(page_html)
                if not page_results:
                    warnings.append(f"No results on page {page_num} — stopping pagination.")
                    break
                for hit in page_results:
                    url = hit.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_results.append(hit)
                next_fields = self._extract_ddg_form_fields(page_html)
                if next_fields.get("vqd"):
                    form_data = next_fields

            return {
                "success": True,
                "query": query,
                "results": all_results,
                "pages_fetched": pages_fetched,
                "source": "duckduckgo",
                "warnings": warnings,
            }
        except PermissionError as exc:
            return {
                "success": False,
                "query": query,
                "results": all_results,
                "pages_fetched": pages_fetched,
                "source": "duckduckgo",
                "error": str(exc),
                "warnings": warnings + [str(exc)],
            }
        except Exception as exc:
            return {
                "success": False,
                "query": query,
                "results": all_results,
                "pages_fetched": pages_fetched,
                "source": "duckduckgo",
                "error": f"DuckDuckGo paginated search failed: {exc}",
                "warnings": warnings,
            }

    def search_ddg_html(self, query: str) -> Dict[str, Any]:
        """Query html.duckduckgo.com and parse result links."""
        query = (query or "").strip()
        if not query:
            return {"success": False, "error": "A search query is required.", "source": "duckduckgo"}

        try:
            html = self._ddg_request(query)
            results = self.parse_ddg_html(html)
            return {
                "success": True,
                "query": query,
                "results": results,
                "source": "duckduckgo",
            }
        except PermissionError as exc:
            return {
                "success": False,
                "query": query,
                "results": [],
                "source": "duckduckgo",
                "error": str(exc),
                "warning": str(exc),
            }
        except Exception as exc:
            return {
                "success": False,
                "query": query,
                "results": [],
                "source": "duckduckgo",
                "error": f"DuckDuckGo search failed: {exc}",
            }

    def search_username(self, username: str) -> Dict[str, Any]:
        """Run DDG platform queries + return Google dork URLs."""
        username = (username or "").strip().lstrip("@")
        if not username:
            return {"success": False, "error": "A username is required."}

        try:
            from modules.recon import generate_username_dorks  # type: ignore
        except ImportError:  # pragma: no cover
            from api.modules.recon import generate_username_dorks  # type: ignore

        google = generate_username_dorks(username)
        if not google.get("success"):
            return google

        ddg_results: List[Dict[str, Any]] = []
        combined_links: List[Dict[str, str]] = []
        seen_urls: Set[str] = set()
        warnings: List[str] = []

        if httpx is None:
            return {
                "success": True,
                "username": username,
                "google_dorks": google,
                "ddg_results": [],
                "combined_links": [],
                "warnings": ["httpx is not installed — DDG live search skipped."],
            }

        for idx, (platform, template) in enumerate(_USERNAME_DDG_QUERIES):
            query = template.format(username)
            self._jitter(skip=(idx == 0))
            payload = self.search_ddg_html_paginated(query, max_pages=3)
            entry = {
                "platform": platform,
                "query": query,
                "success": payload.get("success", False),
                "results": payload.get("results", []),
                "pages_fetched": payload.get("pages_fetched", 0),
            }
            if payload.get("warnings"):
                warnings.extend(str(w) for w in payload["warnings"])
            if payload.get("warning"):
                warnings.append(str(payload["warning"]))
            elif payload.get("error") and not payload.get("results"):
                warnings.append(str(payload["error"]))
            ddg_results.append(entry)
            for hit in entry["results"]:
                url = hit.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    combined_links.append({
                        "platform": platform,
                        "title": hit.get("title", ""),
                        "url": url,
                    })

        return {
            "success": True,
            "username": username,
            "google_dorks": google,
            "ddg_results": ddg_results,
            "combined_links": combined_links,
            "warnings": warnings,
        }

    def search_emails_in_domain(self, domain: str) -> Dict[str, Any]:
        """Harvest public emails for *domain* via DDG + Google dork URL."""
        apex = _normalize_domain(domain)
        if not apex or "." not in apex:
            return {"success": False, "error": "A valid domain is required."}

        google_query = f'site:{apex} "@{apex}"'
        google_dork_url = _GOOGLE + quote_plus(google_query)

        emails: Set[str] = set()
        ddg_pages: List[Dict[str, Any]] = []
        warnings: List[str] = []

        email_re = re.compile(_EMAIL_RE_TEMPLATE.format(domain=re.escape(apex)), re.IGNORECASE)
        queries = [
            f'site:{apex} "@{apex}"',
            f'"{apex}" email contact',
        ]

        if httpx is None:
            return {
                "success": True,
                "domain": apex,
                "emails": [],
                "ddg_pages": [],
                "google_dork_url": google_dork_url,
                "google_query": google_query,
                "warnings": ["httpx is not installed — DDG email harvest skipped."],
            }

        for idx, query in enumerate(queries):
            self._jitter(skip=(idx == 0))
            try:
                payload = self.search_ddg_html_paginated(query, max_pages=5)
                results = payload.get("results", [])
                html_blob = " ".join(
                    f"{r.get('title', '')} {r.get('snippet', '')} {r.get('url', '')}"
                    for r in results
                )
                page = {
                    "query": query,
                    "success": payload.get("success", True),
                    "result_count": len(results),
                    "pages_fetched": payload.get("pages_fetched", 0),
                    "results": results,
                }
                if payload.get("warnings"):
                    warnings.extend(str(w) for w in payload["warnings"])
                for match in email_re.findall(html_blob):
                    emails.add(match.lower())
            except PermissionError as exc:
                msg = str(exc)
                warnings.append(msg)
                page = {
                    "query": query,
                    "success": False,
                    "result_count": 0,
                    "results": [],
                    "error": msg,
                }
            except Exception as exc:
                msg = f"DuckDuckGo search failed: {exc}"
                warnings.append(msg)
                page = {
                    "query": query,
                    "success": False,
                    "result_count": 0,
                    "results": [],
                    "error": msg,
                }
            ddg_pages.append(page)

        return {
            "success": True,
            "domain": apex,
            "emails": sorted(emails),
            "ddg_pages": ddg_pages,
            "google_dork_url": google_dork_url,
            "google_query": google_query,
            "warnings": warnings,
        }


_dual_search_engine: Optional[DualSearchEngine] = None


def get_dual_search_engine() -> DualSearchEngine:
    global _dual_search_engine
    if _dual_search_engine is None:
        _dual_search_engine = DualSearchEngine()
    return _dual_search_engine
