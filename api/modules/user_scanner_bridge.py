"""Bridge to vendored user_scanner engine for extended email/username OSINT."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

_VENDOR_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vendor"))
if _VENDOR_ROOT not in sys.path:
    sys.path.insert(0, _VENDOR_ROOT)

# Tunables — full catalog with bounded concurrency (expect ~2–5 min).
MAX_CONCURRENT = 25
MODULE_TIMEOUT = 12.0
OVERALL_TIMEOUT = 300.0
SKIP_NSFW = True
SKIP_LOUD = True

_HTTP_PATCHED = False


def _ensure_user_scanner() -> None:
    global _HTTP_PATCHED
    try:
        import user_scanner  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Vendored user_scanner not found under api/vendor/user_scanner"
        ) from exc
    if not _HTTP_PATCHED:
        _patch_user_scanner_http()
        _HTTP_PATCHED = True


def _patch_user_scanner_http() -> None:
    """Route sync username probes through ARGUS headers/proxy where possible."""
    from user_scanner.core import helpers, orchestrator

    def _argus_proxy() -> Optional[str]:
        return Config.get_httpx_proxy()

    def _argus_user_agent() -> str:
        return Config.get_random_user_agent()

    helpers.get_proxy = _argus_proxy  # type: ignore[assignment]
    helpers.get_random_user_agent = _argus_user_agent  # type: ignore[assignment]

    original_make_request = orchestrator.make_request

    def _patched_make_request(url: str, **kwargs: Any):
        if "headers" not in kwargs:
            kwargs["headers"] = Config.get_random_headers()
        proxy = Config.get_httpx_proxy()
        if proxy and "proxy" not in kwargs:
            kwargs["proxy"] = proxy
        return original_make_request(url, **kwargs)

    orchestrator.make_request = _patched_make_request  # type: ignore[assignment]


def _collect_modules(is_email: bool, categories: Optional[List[str]] = None) -> List[Any]:
    from user_scanner.core.helpers import get_site_name, is_loud, load_categories, load_modules

    cat_map = load_categories(is_email=is_email, no_nsfw=SKIP_NSFW)
    if categories:
        wanted = {c.lower() for c in categories}
        cat_map = {name: path for name, path in cat_map.items() if name.lower() in wanted}

    modules: List[Any] = []
    for cat_path in cat_map.values():
        modules.extend(load_modules(cat_path))

    if SKIP_LOUD:
        modules = [
            m for m in modules
            if not is_loud(get_site_name(m).lower(), is_email=is_email)
        ]
    return modules


def _result_bucket(result: Any, is_email: bool) -> tuple[str, Dict[str, Any]]:
    from user_scanner.core.result import Status

    payload = result.to_dict()
    hit: Dict[str, Any] = {
        "site_name": payload.get("site_name"),
        "category": payload.get("category"),
        "url": payload.get("url") or "",
        "status": payload.get("status"),
        "extra": payload.get("extra") or {},
    }
    if payload.get("reason"):
        hit["reason"] = payload.get("reason")
    if is_email:
        hit["email"] = payload.get("email")
    else:
        hit["username"] = payload.get("username")

    if result.status == Status.TAKEN:
        return "registered", hit
    if result.status == Status.AVAILABLE:
        return "available", hit
    if result.status == Status.SKIPPED:
        return "skipped", hit
    return "errors", hit


async def _check_one(
    module: Any,
    identifier: str,
    sem: asyncio.Semaphore,
    is_email: bool,
) -> Any:
    from user_scanner.core import engine

    async with sem:
        try:
            return await asyncio.wait_for(
                engine.check(module, identifier),
                timeout=MODULE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            from user_scanner.core.result import Result

            name = module.__name__.split(".")[-1]
            return Result.error(
                "Module timeout",
                site_name=name.capitalize(),
                username=identifier,
                is_email=is_email,
            )
        except Exception as exc:
            from user_scanner.core.result import Result

            name = module.__name__.split(".")[-1]
            return Result.error(exc, site_name=name.capitalize(), username=identifier, is_email=is_email)


async def _scan_extended(
    identifier: str,
    *,
    is_email: bool,
    categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    _ensure_user_scanner()

    identifier = (identifier or "").strip()
    if is_email:
        if "@" not in identifier:
            return {"success": False, "error": "Invalid email format.", "source": "user-scanner"}
    elif not identifier:
        return {"success": False, "error": "A username is required.", "source": "user-scanner"}

    modules = _collect_modules(is_email, categories)
    if not modules:
        return {
            "success": True,
            "source": "user-scanner",
            "total_checked": 0,
            "registered": [],
            "available": [],
            "errors": [],
            "skipped": [],
        }

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [_check_one(m, identifier, sem, is_email) for m in modules]

    try:
        raw = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=OVERALL_TIMEOUT)
    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": f"Extended scan exceeded {int(OVERALL_TIMEOUT)}s overall timeout.",
            "source": "user-scanner",
            "total_checked": len(modules),
            "registered": [],
            "available": [],
            "errors": [],
            "skipped": [],
        }

    registered: List[Dict[str, Any]] = []
    available: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for item in raw:
        if isinstance(item, Exception):
            errors.append({"site_name": "Unknown", "status": "Error", "reason": str(item), "url": ""})
            continue
        bucket, hit = _result_bucket(item, is_email)
        if bucket == "registered":
            registered.append(hit)
        elif bucket == "available":
            available.append(hit)
        elif bucket == "skipped":
            skipped.append(hit)
        else:
            errors.append(hit)

    registered.sort(key=lambda h: ((h.get("category") or ""), (h.get("site_name") or "").lower()))
    available.sort(key=lambda h: (h.get("site_name") or "").lower())

    return {
        "success": True,
        "source": "user-scanner",
        "total_checked": len(modules),
        "registered": registered,
        "available": available,
        "errors": errors,
        "skipped": skipped,
        "registered_count": len(registered),
    }


async def scan_email_extended(
    email: str,
    categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run vendored user_scanner email modules (100+ platforms)."""
    result = await _scan_extended(email, is_email=True, categories=categories)
    result["email"] = email.strip()
    return result


async def scan_username_extended(
    username: str,
    categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run vendored user_scanner username modules (185+ platforms)."""
    username = username.strip().lstrip("@")
    result = await _scan_extended(username, is_email=False, categories=categories)
    result["username"] = username
    result["found"] = result.get("registered", [])
    result["found_count"] = len(result.get("registered", []))
    return result


def _hit_richness(hit: Dict[str, Any]) -> tuple:
    """Score hits for dedupe tie-breaks — prefer richer metadata."""
    return (
        len(hit.get("extra") or {}),
        1 if hit.get("username") else 0,
        1 if hit.get("extra_summary") else 0,
    )


def dedupe_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe platform hits by site name / domain; prefer profile over recovery."""
    try:
        from api.modules.identity import _LINK_PRIORITY  # type: ignore
    except ImportError:
        from modules.identity import _LINK_PRIORITY  # type: ignore

    merged: Dict[str, Dict[str, Any]] = {}
    for hit in hits:
        key = (hit.get("site_name") or hit.get("name") or hit.get("domain") or "").strip().lower()
        if not key:
            continue
        existing = merged.get(key)
        if not existing:
            merged[key] = hit
            continue
        lt_new = hit.get("link_type") or ""
        lt_old = existing.get("link_type") or ""
        if _LINK_PRIORITY.get(lt_new, 0) > _LINK_PRIORITY.get(lt_old, 0):
            merged[key] = hit
            continue
        if _LINK_PRIORITY.get(lt_new, 0) == _LINK_PRIORITY.get(lt_old, 0):
            if _hit_richness(hit) > _hit_richness(existing):
                merged[key] = hit
    return list(merged.values())
