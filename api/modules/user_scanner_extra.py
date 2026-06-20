"""Supplementary OSINT helpers adapted from user-scanner (MIT, kaifcodec/user-scanner).

Provides:
* Username pattern expansion (permutation generator)
* Hudson Rock infostealer intelligence (free public API)
* Supplementary email registration probes (platforms not covered by holehe)
"""

from __future__ import annotations

import asyncio
import itertools
import json
import random
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Union

import httpx
import requests

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore


# ── Username pattern expansion (from user-scanner/core/patterns.py) ──────────

Block = Union[str, "PatternBlock"]


@dataclass
class PatternBlock:
    charset: List[str]
    lenset: List[int]


class _Lexer:
    def __init__(self, input_str: str) -> None:
        self.tokens = list(input_str)

    def peek(self) -> str:
        return self.tokens[0] if self.tokens else ""

    def next(self) -> str:
        return self.tokens.pop(0) if self.tokens else ""

    def parse_number(self) -> int | None:
        res = None
        while (nxt := self.peek()) and nxt in "0123456789":
            self.next()
            n = int(nxt)
            res = n if res is None else res * 10 + n
        return res


def _char_range(start: str, end: str) -> List[str]:
    return [chr(i) for i in range(ord(start), ord(end) + 1)]


def _parse_charset(lexer: _Lexer) -> Set[str]:
    charset: Set[str] = set()
    while lexer.peek() != "]":
        cur = lexer.next()
        if not cur:
            raise ValueError('Missing "]" at the end of pattern')
        if cur == "\\":
            nxt = lexer.next()
            if not nxt:
                raise ValueError('Invalid "\\"')
            charset.add(nxt)
        elif cur == "-":
            charset.add(cur)
        else:
            if lexer.peek() == "-":
                lexer.next()
                other = lexer.next()
                if not other:
                    raise ValueError('Incomplete range in charset (e.g. "a-" without end)')
                charset.update(_char_range(cur, other))
            else:
                charset.add(cur)
    lexer.next()
    return charset


def _parse_lenset(lexer: _Lexer) -> Set[int]:
    lenset: Set[int] = set()
    numbers = "0123456789"
    while (cur := lexer.peek()) != "}":
        if not cur:
            raise ValueError('Missing "}" at the end of pattern')
        if cur not in numbers + "-;":
            raise ValueError(f"Invalid character: {cur}")
        if cur == "-":
            raise ValueError('Invalid character at the lenset: "-"')
        if cur in numbers:
            lhs = lexer.parse_number()
            if lexer.peek() == "-":
                lexer.next()
                rhs = lexer.parse_number()
                if lhs is not None and rhs is not None:
                    for i in range(lhs, rhs + 1):
                        lenset.add(i)
            elif lhs is not None:
                lenset.add(lhs)
        else:
            lexer.next()
    lexer.next()
    return lenset


def _append_string(blocks: list, new: str) -> None:
    if not blocks:
        blocks.append(new)
    elif isinstance(blocks[-1], str):
        blocks[-1] += new
    else:
        blocks.append(new)


def _parse_patterns(input_str: str) -> List[Block]:
    lexer = _Lexer(input_str)
    res: List[Block] = []
    while lexer.peek():
        cur = lexer.next()
        if cur == "\\":
            if lexer.peek() in ("[", "]", "\\"):
                _append_string(res, lexer.next())
        elif cur == "[":
            charset = _parse_charset(lexer)
            lenset: Set[int] = set()
            if lexer.peek() == "{":
                lexer.next()
                lenset = _parse_lenset(lexer)
            else:
                lenset.add(1)
            res.append(PatternBlock(charset=sorted(charset), lenset=sorted(lenset)))
        elif cur == "]":
            raise ValueError('Invalid unescaped "]"')
        else:
            _append_string(res, cur)
    return res


def _iter_block(block: PatternBlock) -> Iterator[str]:
    for length in block.lenset:
        for combo in itertools.product(block.charset, repeat=length):
            yield "".join(combo)


def _iter_pattern(blocks: List[Block]) -> Iterator[str]:
    if not blocks:
        yield ""
        return
    first, *rest = blocks
    if isinstance(first, str):
        for suffix in _iter_pattern(rest):
            yield first + suffix
    else:
        for middle in _iter_block(first):
            for suffix in _iter_pattern(rest):
                yield middle + suffix


def expand_username_patterns(input_str: str) -> Iterator[str]:
    """Expand a wildcard username pattern into all matching handles."""
    blocks = _parse_patterns(input_str)
    yield from _iter_pattern(blocks)


def expand_username_patterns_random(input_str: str, capacity: int = 1000) -> Iterator[str]:
    """Expand a pattern in randomized order (reservoir sampling for large sets)."""
    patterns = expand_username_patterns(input_str)
    buffer: List[str] = []
    for _ in range(capacity):
        try:
            buffer.append(next(patterns))
        except StopIteration:
            random.shuffle(buffer)
            yield from buffer
            return
    random.shuffle(buffer)
    for item in patterns:
        pos = random.randrange(capacity)
        buffer[pos], item = item, buffer[pos]
        yield item
    random.shuffle(buffer)
    yield from buffer


def count_username_patterns(input_str: str) -> int:
    """Return total permutations without generating them."""
    blocks = _parse_patterns(input_str)
    total = 1
    for block in blocks:
        if isinstance(block, PatternBlock):
            total *= sum(len(block.charset) ** length for length in block.lenset)
    return total


# ── Hudson Rock infostealer intelligence ───────────────────────────────────

HUDSON_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"


def query_hudson_rock(target: str, *, is_email: bool = False) -> Dict[str, Any]:
    """Query Hudson Rock's free infostealer OSINT API.

    Returns structured JSON suitable for API/CLI/GUI consumers. Never raises.
    """
    target = (target or "").strip()
    if not target:
        return {"success": False, "error": "A target email or username is required."}

    endpoint = "search-by-email" if is_email else "search-by-username"
    param = "email" if is_email else "username"
    url = f"{HUDSON_BASE}{endpoint}?{param}={target}"

    result: Dict[str, Any] = {
        "success": True,
        "target": target,
        "target_type": param,
        "source": "Hudson Rock",
        "source_url": "https://www.hudsonrock.com/free-tools",
        "infection_count": 0,
        "infections": [],
        "status": "clean",
    }

    try:
        resp = requests.get(
            url,
            timeout=12,
            headers=Config.get_random_headers(),
            proxies=Config.get_proxies(),
        )
    except Exception as exc:
        return {"success": False, "target": target, "error": f"Hudson Rock unreachable: {exc}"}

    if resp.status_code == 404:
        result["status"] = "not_found"
        result["message"] = "No infostealer data found for this identifier."
        return result

    if resp.status_code != 200:
        return {
            "success": False,
            "target": target,
            "error": f"Hudson Rock API HTTP {resp.status_code}",
        }

    try:
        data = resp.json()
    except ValueError:
        return {"success": False, "target": target, "error": "Invalid JSON from Hudson Rock"}

    stealers = data.get("stealers") or []
    infections: List[Dict[str, Any]] = []
    for item in stealers:
        infections.append({
            "stealer_family": item.get("stealer_family", "Unknown"),
            "date_compromised": item.get("date_compromised", "Unknown"),
            "operating_system": item.get("operating_system", "Unknown"),
            "computer_name": item.get("computer_name", "Unknown"),
            "antiviruses": item.get("antiviruses") or [],
            "top_logins": (item.get("top_logins") or [])[:5],
        })

    result["infection_count"] = len(infections)
    result["infections"] = infections
    if infections:
        result["status"] = "infected"
        result["message"] = f"{len(infections)} infostealer infection(s) associated with this {param}."
    else:
        result["status"] = "clean"
        result["message"] = "No infostealer infections found."
    return result


# ── Supplementary email probes (adapted from user-scanner email_scan) ────────

def _httpx_proxy() -> Optional[str]:
    return Config.get_httpx_proxy()


async def _check_komoot(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    name, url = "Komoot", "https://www.komoot.com"
    payload = {"email": email, "reason": "header", "new_tab": False}
    headers = Config.get_random_headers()
    headers.update({
        "Content-Type": "application/json",
        "origin": "https://www.komoot.com",
        "referer": "https://www.komoot.com/signin",
    })
    try:
        resp = await client.post(
            "https://www.komoot.com/v1/signin",
            content=json.dumps(payload),
            headers=headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            rtype = data.get("type")
            if rtype == "login":
                return {"name": name, "exists": True, "domain": "komoot.com", "url": url}
            if rtype == "register":
                return {"name": name, "exists": False, "domain": "komoot.com", "url": url}
        return {"name": name, "exists": None, "domain": "komoot.com", "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"name": name, "exists": None, "domain": "komoot.com", "error": str(exc)}


async def _check_polarsteps(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    name, url = "Polarsteps", "https://polarsteps.com"
    headers = Config.get_random_headers()
    headers.update({
        "polarsteps-api-version": "55",
        "polarsteps-user-language": "en-US",
        "polarsteps-device-platform": "1",
    })
    try:
        resp = await client.post(
            "https://www.polarsteps.com/validation/unique",
            data={"field": "users.email", "value": email},
            headers=headers,
        )
        text = resp.text.strip().upper()
        if text == "INVALID":
            return {"name": name, "exists": True, "domain": "polarsteps.com", "url": url}
        if text == "OK":
            return {"name": name, "exists": False, "domain": "polarsteps.com", "url": url}
        return {"name": name, "exists": None, "domain": "polarsteps.com", "error": text[:40]}
    except Exception as exc:
        return {"name": name, "exists": None, "domain": "polarsteps.com", "error": str(exc)}


async def _check_letterboxd(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    name, url = "Letterboxd", "https://letterboxd.com"
    headers = Config.get_random_headers()
    headers.update({
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://letterboxd.com",
        "Referer": "https://letterboxd.com/register/standalone/",
    })
    try:
        await client.get("https://letterboxd.com/sign-in/", headers=headers)
        csrf = client.cookies.get("com.xk72.webparts.csrf")
        if not csrf:
            return {"name": name, "exists": None, "domain": "letterboxd.com", "error": "CSRF unavailable"}
        payload = {
            "__csrf": csrf,
            "token": "",
            "emailAddress": email,
            "username": "argus_probe_user",
            "password": "ArgusProbe123!",
            "termsAndAge": "true",
            "g-recaptcha-response": "",
            "h-captcha-response": "",
        }
        resp = await client.post(
            "https://letterboxd.com/user/standalone/register.do",
            data=payload,
            headers=headers,
        )
        data = resp.json()
        messages = data.get("messages") or []
        error_fields = data.get("errorFields") or []
        taken = any("already associated with an account" in m for m in messages)
        if taken or "emailAddress" in error_fields:
            return {"name": name, "exists": True, "domain": "letterboxd.com", "url": url}
        if "result" in data and not taken:
            return {"name": name, "exists": False, "domain": "letterboxd.com", "url": url}
        return {"name": name, "exists": None, "domain": "letterboxd.com", "error": "Unexpected response"}
    except Exception as exc:
        return {"name": name, "exists": None, "domain": "letterboxd.com", "error": str(exc)}


async def _check_github_email(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    name, url = "GitHub", "https://github.com"
    headers = Config.get_random_headers()
    try:
        resp = await client.get("https://github.com/signup", headers=headers)
        match = re.search(r'data-csrf="true"\s+value="([^"]+)"', resp.text)
        if not match:
            return {"name": name, "exists": None, "domain": "github.com", "error": "CSRF unavailable"}
        payload = {"authenticity_token": match.group(1), "value": email}
        post_headers = dict(headers)
        post_headers.update({"origin": "https://github.com", "referer": "https://github.com/signup"})
        check = await client.post(
            "https://github.com/email_validity_checks",
            data=payload,
            headers=post_headers,
        )
        body = check.text
        if "already associated with an account" in body:
            return {"name": name, "exists": True, "domain": "github.com", "url": url}
        if check.status_code == 200 and "Email is available" in body:
            return {"name": name, "exists": False, "domain": "github.com", "url": url}
        return {"name": name, "exists": None, "domain": "github.com", "error": f"HTTP {check.status_code}"}
    except Exception as exc:
        return {"name": name, "exists": None, "domain": "github.com", "error": str(exc)}


async def _check_eventbrite(email: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    name, url = "Eventbrite", "https://www.eventbrite.com"
    headers = Config.get_random_headers()
    headers.update({"Content-Type": "application/json", "origin": "https://www.eventbrite.com"})
    try:
        resp = await client.post(
            "https://www.eventbrite.com/api/v3/users/lookup/",
            json={"email": email},
            headers=headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("exists"):
                return {"name": name, "exists": True, "domain": "eventbrite.com", "url": url}
            return {"name": name, "exists": False, "domain": "eventbrite.com", "url": url}
        return {"name": name, "exists": None, "domain": "eventbrite.com", "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"name": name, "exists": None, "domain": "eventbrite.com", "error": str(exc)}


_SUPPLEMENTARY_CHECKS: List[Callable[[str, httpx.AsyncClient], Any]] = [
    _check_komoot,
    _check_polarsteps,
    _check_letterboxd,
    _check_github_email,
    _check_eventbrite,
]


async def _run_supplementary_async(email: str) -> List[Dict[str, Any]]:
    proxy = _httpx_proxy()
    client_kwargs: Dict[str, Any] = {
        "headers": Config.get_random_headers(),
        "follow_redirects": True,
        "timeout": httpx.Timeout(12.0),
    }
    if proxy:
        client_kwargs["proxy"] = proxy
    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [fn(email, client) for fn in _SUPPLEMENTARY_CHECKS]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
    results: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            item["source"] = "supplementary"
            results.append(item)
        elif isinstance(item, Exception):
            results.append({"name": "Unknown", "exists": None, "error": str(item), "source": "supplementary"})
    return results


def run_supplementary_email_scan(email: str) -> Dict[str, Any]:
    """Run supplementary email registration probes (non-holehe platforms)."""
    email = (email or "").strip()
    if "@" not in email:
        return {"success": False, "error": "Invalid email format."}
    try:
        results = asyncio.run(_run_supplementary_async(email))
    except Exception as exc:
        return {"success": False, "email": email, "error": str(exc)}

    registered = [r for r in results if r.get("exists") is True]
    return {
        "success": True,
        "email": email,
        "platforms_checked": len(results),
        "registered_count": len(registered),
        "registered_on": registered,
        "all_results": results,
    }


# Platform profile URLs merged from user-scanner site modules (non-exhaustive).
SUPPLEMENTARY_PLATFORM_URLS: Dict[str, str] = {
    "komoot": "https://www.komoot.com",
    "polarsteps": "https://polarsteps.com",
    "letterboxd": "https://letterboxd.com",
    "eventbrite": "https://www.eventbrite.com",
    "replit": "https://replit.com",
    "huggingface": "https://huggingface.co",
    "envato": "https://account.envato.com",
    "deezer": "https://www.deezer.com",
    "mixcloud": "https://www.mixcloud.com",
    "gaana": "https://gaana.com",
    "etsy": "https://www.etsy.com",
    "vivino": "https://www.vivino.com",
    "flipkart": "https://www.flipkart.com",
    "freelancer": "https://www.freelancer.com",
    "codecademy": "https://www.codecademy.com",
    "codewars": "https://www.codewars.com",
    "leetcode": "https://leetcode.com",
    "hackthebox": "https://app.hackthebox.com",
    "hackerone": "https://hackerone.com",
    "justwatch": "https://www.justwatch.com",
    "myanimelist": "https://myanimelist.net",
    "anilist": "https://anilist.co",
    "stremio": "https://www.stremio.com",
    "classmates": "https://www.classmates.com",
    "mewe": "https://mewe.com",
    "plurk": "https://www.plurk.com",
    "mastodon": "https://mastodon.social",
    "nextdoor": "https://nextdoor.com",
    "anydo": "https://www.any.do",
    "deviantart": "https://www.deviantart.com",
    "screener": "https://www.screener.in",
    "office365": "https://login.microsoftonline.com/",
    "firefox": "https://accounts.firefox.com/",
    "patreon": "https://www.patreon.com",
    "buymeacoffee": "https://www.buymeacoffee.com",
    "gumroad": "https://gumroad.com",
    "flickr": "https://www.flickr.com",
    "adobe": "https://account.adobe.com/",
    "amazon": "https://www.amazon.com/ap/forgotpassword",
    "netflix": "https://www.netflix.com/loginhelp",
    "spotify": "https://open.spotify.com/",
    "instagram": "https://www.instagram.com/accounts/password/reset/",
    "facebook": "https://www.facebook.com/login/identify/",
    "pinterest": "https://www.pinterest.com/password/reset/",
    "x": "https://twitter.com/i/flow/login",
    "twitter": "https://twitter.com/i/flow/login",
}
