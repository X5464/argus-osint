"""Optional Truecaller deep phone intelligence for ARGUS."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

SETUP_HINT = (
    "keys set truecaller <id> — obtain via: npx truecallerjs installation_id"
)

SETUP_STEPS = (
    "  Truecaller installation ID required for deep lookup:\n"
    "    1. npx truecallerjs login\n"
    "    2. npx truecallerjs installation_id\n"
    "    3. keys set truecaller <installation_id>"
)


def _normalize_phone(phone: str) -> str:
    s = re.sub(r"\s+", "", (phone or "").strip())
    if s and not s.startswith("+"):
        s = "+" + s
    return s


def _region_from_phone(phone: str) -> str:
    try:
        import phonenumbers

        parsed = phonenumbers.parse(phone, None)
        return phonenumbers.region_code_for_number(parsed) or "IN"
    except Exception:
        return "IN"


def _national_number(phone: str, region: str) -> str:
    try:
        import phonenumbers

        parsed = phonenumbers.parse(phone, region)
        return str(parsed.national_number)
    except Exception:
        return re.sub(r"\D", "", phone.lstrip("+"))


def _extract_alternate_names(record: dict, all_records: List[dict]) -> List[str]:
    names: List[str] = []
    primary = (record.get("name") or "").strip()

    for key in ("alternateName", "alternate_name", "altName"):
        alt = record.get(key)
        if isinstance(alt, str) and alt.strip() and alt.strip() != primary:
            names.append(alt.strip())

    for src in record.get("sources") or []:
        if isinstance(src, dict):
            n = (src.get("name") or "").strip()
            if n and n != primary and n not in names:
                names.append(n)

    for other in all_records[1:]:
        if not isinstance(other, dict):
            continue
        n = (other.get("name") or "").strip()
        if n and n != primary and n not in names:
            names.append(n)

    return names


def _normalize_raw(raw: Any) -> Dict[str, Any]:
    """Map Truecaller API / truecallerpy payload to ARGUS dossier fields."""
    if not raw:
        return {"available": False, "error": "No data returned"}

    if isinstance(raw, dict) and raw.get("error") and not raw.get("data"):
        return {
            "available": False,
            "error": raw.get("message") or raw.get("error"),
        }

    data = raw
    if isinstance(raw, dict):
        if "data" in raw:
            data = raw["data"]

    records: List[dict] = []
    if isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        if isinstance(data.get("data"), list):
            records = [r for r in data["data"] if isinstance(r, dict)]
        else:
            records = [data]

    if not records:
        return {"available": False, "error": "No records found"}

    rec = records[0]
    primary_name = (rec.get("name") or "").strip() or None
    alternate_names = _extract_alternate_names(rec, records)

    carrier = None
    phones = rec.get("phones") or []
    if phones and isinstance(phones[0], dict):
        carrier = phones[0].get("carrier")

    email = None
    for addr in rec.get("internetAddresses") or rec.get("emails") or []:
        if isinstance(addr, dict):
            svc = (addr.get("service") or addr.get("type") or "").lower()
            if svc in ("email", "internetaddress") or addr.get("id", "").find("@") > 0:
                email = addr.get("id") or addr.get("email")
                if email:
                    break
        elif isinstance(addr, str) and "@" in addr:
            email = addr
            break

    tags: List[str] = []
    badges = rec.get("badges") or rec.get("tags") or []
    if isinstance(badges, list):
        tags = [str(b) for b in badges if b]

    verified = any(str(t).lower() == "verified" for t in tags)

    city = country = timezone = None
    addresses = rec.get("addresses") or []
    if addresses and isinstance(addresses[0], dict):
        addr = addresses[0]
        city = addr.get("city")
        country = addr.get("countryCode") or addr.get("country")
        timezone = addr.get("timeZone") or addr.get("timezone")

    spam_score: Optional[int] = None
    spam_type = None

    score = rec.get("score")
    if score is not None:
        try:
            fscore = float(score)
            spam_score = int(fscore * 100) if fscore <= 1 else int(fscore)
        except (TypeError, ValueError):
            pass

    spam_info = rec.get("spamInfo") or rec.get("spam") or {}
    if isinstance(spam_info, dict):
        if spam_score is None and spam_info.get("spamScore") is not None:
            try:
                spam_score = int(spam_info["spamScore"])
            except (TypeError, ValueError):
                pass
        spam_type = (
            spam_info.get("spamType")
            or spam_info.get("spamtype")
            or spam_info.get("type")
            or spam_info.get("category")
        )

    if not spam_type:
        for w in rec.get("searchWarnings") or []:
            if isinstance(w, dict):
                spam_type = w.get("type") or w.get("message")
                if spam_type:
                    break

    result: Dict[str, Any] = {
        "configured": True,
        "available": True,
        "primary_name": primary_name,
        "alternate_names": alternate_names,
        "carrier": carrier,
        "email": email,
        "tags": tags,
        "verified": verified,
        "city": city,
        "country": country,
        "timezone": timezone,
        "spam_score": spam_score,
        "spam_type": spam_type,
    }

    if spam_score is not None and spam_score > 25:
        suffix = f" ({spam_type})" if spam_type else ""
        result["alert"] = f"CRITICAL — spam score {spam_score}{suffix}"

    return result


async def _lookup_truecallerpy(phone: str, installation_id: str, region: str) -> Any:
    from truecallerpy import search_phonenumber

    return await search_phonenumber(phone, region, installation_id)


def _lookup_npx(phone: str, installation_id: str, region: str) -> Optional[Any]:
    if not shutil.which("npx") or not shutil.which("node"):
        return None

    national = _national_number(phone, region)
    cmd = [
        shutil.which("npx") or "npx",
        "-y",
        "truecallerjs",
        "-s",
        national,
        "--json",
        "--installationid",
        installation_id,
        "--nc",
        region,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return {"error": err or f"npx exit {proc.returncode}"}
        out = proc.stdout.strip()
        if not out:
            return {"error": "empty npx output"}
        return json.loads(out)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return {"error": str(exc)}


def _lookup_http(phone: str, installation_id: str, region: str) -> Any:
    try:
        import httpx
        import phonenumbers

        parsed = phonenumbers.parse(phone, region)
        headers = {
            "content-type": "application/json; charset=UTF-8",
            "accept-encoding": "gzip",
            "user-agent": "Truecaller/11.75.5 (Android;10)",
            "Authorization": f"Bearer {installation_id}",
        }
        params = {
            "q": str(parsed.national_number),
            "countryCode": parsed.country_code,
            "type": 4,
            "locAddr": "",
            "placement": "SEARCHRESULTS,HISTORY,DETAILS",
            "encoding": "json",
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                "https://search5-noneu.truecaller.com/v2/search",
                params=params,
                headers=headers,
            )
            resp.raise_for_status()
            return {"status_code": resp.status_code, "data": resp.json()}
    except Exception as exc:
        return {"error": str(exc)}


def _lookup_raw(phone: str, installation_id: str, region: str) -> Any:
    """Try truecallerpy, then npx truecallerjs, then direct HTTP."""
    raw: Any = None
    last_error: Optional[str] = None

    try:
        loop = asyncio.new_event_loop()
        try:
            raw = loop.run_until_complete(
                _lookup_truecallerpy(phone, installation_id, region)
            )
        finally:
            loop.close()
        if isinstance(raw, dict) and raw.get("error"):
            last_error = str(raw.get("message") or raw.get("error"))
            raw = None
    except ImportError:
        pass
    except Exception as exc:
        last_error = str(exc)
        raw = None

    if raw is None:
        npx_raw = _lookup_npx(phone, installation_id, region)
        if npx_raw is not None:
            if isinstance(npx_raw, dict) and npx_raw.get("error"):
                last_error = str(npx_raw["error"])
            else:
                return npx_raw

    if raw is None:
        http_raw = _lookup_http(phone, installation_id, region)
        if isinstance(http_raw, dict) and http_raw.get("error"):
            last_error = str(http_raw["error"])
        else:
            return http_raw

    if raw is not None:
        return raw

    return {"error": last_error or "Truecaller lookup failed"}


def lookup_truecaller(phone: str, installation_id: str) -> dict:
    """Returns normalized dossier dict or {configured: false, ...}."""
    if not (installation_id or "").strip():
        return {"configured": False, "setup_hint": SETUP_HINT}

    phone = _normalize_phone(phone)
    if not phone:
        return {"configured": True, "available": False, "error": "Invalid phone number"}

    installation_id = installation_id.strip()
    region = _region_from_phone(phone)

    try:
        raw = _lookup_raw(phone, installation_id, region)
    except Exception as exc:
        return {"configured": True, "available": False, "error": str(exc)}

    if isinstance(raw, dict) and raw.get("error") and not raw.get("data"):
        return {
            "configured": True,
            "available": False,
            "error": raw.get("message") or raw.get("error"),
        }

    return _normalize_raw(raw)
