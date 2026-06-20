from flask import Blueprint, request, jsonify
import requests
# pyrefly: ignore [missing-import]
import phonenumbers
# pyrefly: ignore [missing-import]
from phonenumbers import carrier, geocoder, timezone as pn_timezone
import asyncio
import concurrent.futures
from typing import Any, Callable, Literal, Optional
from urllib.parse import quote
import warnings

LinkType = Literal["profile", "recovery", "platform_home"]

_LINK_PRIORITY: dict[str, int] = {
    "profile": 3,
    "recovery": 2,
    "platform_home": 1,
}

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

try:
    from modules.user_scanner_extra import (  # type: ignore
        SUPPLEMENTARY_PLATFORM_URLS,
        query_hudson_rock,
        run_supplementary_email_scan,
    )
except ImportError:  # pragma: no cover
    from api.modules.user_scanner_extra import (  # type: ignore
        SUPPLEMENTARY_PLATFORM_URLS,
        query_hudson_rock,
        run_supplementary_email_scan,
    )

try:
    from modules.user_scanner_bridge import (  # type: ignore
        dedupe_hits,
        scan_email_extended,
    )
except ImportError:  # pragma: no cover
    from api.modules.user_scanner_bridge import (  # type: ignore
        dedupe_hits,
        scan_email_extended,
    )

identity_bp = Blueprint('identity_bp', __name__)


def _query_internetdb(ip: str) -> dict:
    """Query Shodan InternetDB (free, unauthenticated) for an IP.

    Returns a dict with ports, vulns (CVEs), cpes, hostnames and tags. Never
    raises — a 404 (no data) or timeout degrades to an informational status so
    the primary ipwho.is result is always preserved.
    """
    try:
        resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=6,
            headers=Config.get_random_headers(),
            proxies=Config.get_proxies(),
        )
    except Exception as exc:
        return {"error": f"InternetDB unreachable: {exc}"}

    if resp.status_code == 404:
        return {"status": "no data — IP not found in Shodan InternetDB"}
    if resp.status_code != 200:
        return {"error": f"InternetDB HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "InternetDB returned invalid JSON"}

    return {
        "ports": data.get("ports", []),
        "cves": data.get("vulns", []),
        "cpes": data.get("cpes", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
    }

# ──────────────────────────────────────────────
# API KEYS — loaded from encrypted vault (never hardcoded)
# ──────────────────────────────────────────────
try:
    from vault import get_identity_keys
except ImportError:  # pragma: no cover
    from api.vault import get_identity_keys  # type: ignore


def _vault_keys() -> dict:
    try:
        from flask import g

        user = getattr(g, "current_user", None)
        username = user.get("username") if user else None
    except Exception:
        username = None
    return get_identity_keys(username)


def _vt_key() -> str:
    header = ""
    try:
        from flask import request

        header = (request.headers.get("X-VT-Key") or "").strip()
    except Exception:
        pass
    return header or _vault_keys().get("VT_API_KEY", "")


def _abuse_key() -> str:
    header = ""
    try:
        from flask import request

        header = (request.headers.get("X-Abuse-Key") or "").strip()
    except Exception:
        pass
    return header or _vault_keys().get("ABUSE_IPDB_KEY", "")


def _truecaller_id() -> str:
    arg = ""
    try:
        from flask import request

        arg = (request.args.get("installation_id") or "").strip()
    except Exception:
        pass
    return arg or _vault_keys().get("TRUECALLER_ID", "")

# ──────────────────────────────────────────────
# SOCIAL PLATFORMS for username footprinting
# ──────────────────────────────────────────────
SOCIAL_PLATFORMS = [
    {"name": "GitHub",     "url": "https://github.com/{}",            "check": "status"},
    {"name": "Instagram",  "url": "https://www.instagram.com/{}/",    "check": "status"},
    {"name": "Twitter/X",  "url": "https://twitter.com/{}",           "check": "status"},
    {"name": "Reddit",     "url": "https://www.reddit.com/user/{}/",  "check": "status"},
    {"name": "TikTok",     "url": "https://www.tiktok.com/@{}",       "check": "status"},
    {"name": "LinkedIn",   "url": "https://www.linkedin.com/in/{}/",  "check": "status"},
    {"name": "Pinterest",  "url": "https://www.pinterest.com/{}/",    "check": "status"},
    {"name": "Medium",     "url": "https://medium.com/@{}",           "check": "status"},
    {"name": "Dev.to",     "url": "https://dev.to/{}",                "check": "status"},
    {"name": "GitLab",     "url": "https://gitlab.com/{}",            "check": "status"},
]

# Platforms holehe supports (subset shown — holehe handles the full 120+)
HOLEHE_PLATFORMS = [
    "twitter", "instagram", "github", "snapchat", "spotify",
    "adobe", "amazon", "dropbox", "facebook", "google",
    "netflix", "paypal", "pinterest", "reddit", "tumblr",
]

# Backward-compatible alias (recovery/home URLs — prefer build_email_hit_url()).
PLATFORM_PROFILE_URLS: dict[str, str] = {
    **SUPPLEMENTARY_PLATFORM_URLS,
}


def _norm_platform(name: str) -> str:
    n = (name or "").strip().lower()
    aliases = {
        "twitter/x": "twitter",
        "twitter": "twitter",
        "x": "twitter",
        "dev.to": "devto",
    }
    if n in aliases:
        return aliases[n]
    return n.replace(" ", "").replace("/", "")


def _clean_meta_value(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip().lstrip("@")
    if not s or s.lower() in ("n/a", "none", "unknown", "null"):
        return None
    return s


def _get_username(extra: dict, hit: dict) -> Optional[str]:
    for key in ("username", "login", "handle", "login_name", "screen_name"):
        val = _clean_meta_value(extra.get(key)) or _clean_meta_value(hit.get(key))
        if val:
            return val
    return None


_HOMEPAGE_ROOTS = frozenset({
    "https://github.com",
    "https://www.github.com",
    "https://open.spotify.com",
    "https://www.spotify.com",
    "https://spotify.com",
    "https://twitter.com",
    "https://x.com",
    "https://www.twitter.com",
    "https://etsy.com",
    "https://www.etsy.com",
    "https://coursera.org",
    "https://www.coursera.org",
    "https://deviantart.com",
    "https://www.deviantart.com",
    "https://facebook.com",
    "https://www.facebook.com",
    "https://instagram.com",
    "https://www.instagram.com",
    "https://reddit.com",
    "https://www.reddit.com",
    "https://linkedin.com",
    "https://www.linkedin.com",
})


def _is_homepage_url(url: str, domain: str = "", platform: str = "") -> bool:
    if not url or not isinstance(url, str):
        return True
    u = url.strip().rstrip("/").lower()
    if u in _HOMEPAGE_ROOTS:
        return True
    if u.endswith("/i/flow/login") or u.endswith("/login") and "password" not in u:
        return True
    if domain:
        d = domain.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
        if u in (f"https://{d}", f"https://www.{d}"):
            return True
    return False


def _extract_profile_url(extra: dict) -> Optional[str]:
    for key in ("profile_url", "profile", "profile_link", "user_url", "shop_url"):
        val = extra.get(key)
        if isinstance(val, str) and val.strip() and not _is_homepage_url(val):
            return val.strip()
    return None


def _tpl_github(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://github.com/{quote(u, safe='')}" if u else None


def _tpl_twitter(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://twitter.com/{quote(u, safe='')}" if u else None


def _tpl_spotify(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    if u:
        return f"https://open.spotify.com/user/{quote(u, safe='')}"
    uid = _clean_meta_value(extra.get("id"))
    if uid:
        return f"https://open.spotify.com/user/{quote(uid, safe='')}"
    return None


def _tpl_etsy(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    if u:
        return f"https://www.etsy.com/people/{quote(u, safe='')}"
    uid = _clean_meta_value(extra.get("id"))
    if uid:
        return f"https://www.etsy.com/people/{quote(uid, safe='')}"
    return None


def _tpl_deviantart(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://www.deviantart.com/{quote(u, safe='')}" if u else None


def _tpl_reddit(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://www.reddit.com/user/{quote(u, safe='')}" if u else None


def _tpl_instagram(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://www.instagram.com/{quote(u, safe='')}/" if u else None


def _tpl_pinterest(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://www.pinterest.com/{quote(u, safe='')}/" if u else None


def _tpl_linkedin(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    if u:
        return f"https://www.linkedin.com/in/{quote(u, safe='')}/"
    return None


def _tpl_coursera(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    if u:
        return f"https://www.coursera.org/user/{quote(u, safe='')}"
    return _extract_profile_url(extra)


def _tpl_gravatar(extra: dict, email: str, hit: dict) -> Optional[str]:
    return f"https://gravatar.com/{quote(email.strip().lower(), safe='')}"


def _tpl_pypi(extra: dict, email: str, hit: dict) -> Optional[str]:
    u = _get_username(extra, hit)
    return f"https://pypi.org/user/{quote(u, safe='')}/" if u else None


PLATFORM_PROFILE_TEMPLATES: dict[str, Callable[[dict, str, dict], Optional[str]]] = {
    "github": _tpl_github,
    "twitter": _tpl_twitter,
    "x": _tpl_twitter,
    "spotify": _tpl_spotify,
    "etsy": _tpl_etsy,
    "deviantart": _tpl_deviantart,
    "reddit": _tpl_reddit,
    "instagram": _tpl_instagram,
    "pinterest": _tpl_pinterest,
    "linkedin": _tpl_linkedin,
    "coursera": _tpl_coursera,
    "gravatar": _tpl_gravatar,
    "pypi": _tpl_pypi,
    "gitlab": lambda e, em, h: (
        f"https://gitlab.com/{quote(u, safe='')}" if (u := _get_username(e, h)) else None
    ),
    "medium": lambda e, em, h: (
        f"https://medium.com/@{quote(u, safe='')}" if (u := _get_username(e, h)) else None
    ),
    "tiktok": lambda e, em, h: (
        f"https://www.tiktok.com/@{quote(u, safe='')}" if (u := _get_username(e, h)) else None
    ),
    "twitch": lambda e, em, h: (
        f"https://www.twitch.tv/{quote(u, safe='')}" if (u := _get_username(e, h)) else None
    ),
    "snapchat": lambda e, em, h: (
        f"https://www.snapchat.com/add/{quote(u, safe='')}" if (u := _get_username(e, h)) else None
    ),
}


PLATFORM_RECOVERY_URLS: dict[str, str] = {
    "twitter": "https://twitter.com/account/begin_password_reset",
    "x": "https://twitter.com/account/begin_password_reset",
    "instagram": "https://www.instagram.com/accounts/password/reset/",
    "github": "https://github.com/password_reset",
    "spotify": "https://accounts.spotify.com/en/password-reset",
    "facebook": "https://www.facebook.com/login/identify/",
    "google": "https://accounts.google.com/signin/v2/identifier",
    "amazon": "https://www.amazon.com/ap/forgotpassword",
    "netflix": "https://www.netflix.com/loginhelp",
    "paypal": "https://www.paypal.com/authflow/password-recovery/",
    "reddit": "https://www.reddit.com/password",
    "pinterest": "https://www.pinterest.com/password/reset/",
    "snapchat": "https://accounts.snapchat.com/accounts/password_reset_request",
    "adobe": "https://account.adobe.com/forgot",
    "dropbox": "https://www.dropbox.com/forgot",
    "tumblr": "https://www.tumblr.com/forgot_password",
    "linkedin": "https://www.linkedin.com/uas/request-password-reset",
    "microsoft": "https://account.live.com/password/reset",
    "apple": "https://iforgot.apple.com/",
    "yahoo": "https://login.yahoo.com/forgot",
    "discord": "https://discord.com/login",
    "tiktok": "https://www.tiktok.com/login/phone-or-email/email",
    "twitch": "https://www.twitch.tv/login",
    "steam": "https://store.steampowered.com/login/",
    "ebay": "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
    "wordpress": "https://wordpress.com/log-in",
    "imgur": "https://imgur.com/signin",
    "flickr": "https://www.flickr.com/forgotpassword/",
    "strava": "https://www.strava.com/login",
    "patreon": "https://www.patreon.com/login",
    "medium": "https://medium.com/m/signin",
    "quora": "https://www.quora.com/login",
    "hubspot": "https://app.hubspot.com/login/",
    "lastpass": "https://lastpass.com/",
    "firefox": "https://accounts.firefox.com/reset_password",
    "docker": "https://hub.docker.com/password-reset",
    "office365": "https://passwordreset.microsoftonline.com/",
    "deviantart": "https://www.deviantart.com/users/login",
    "coursera": "https://www.coursera.org/forgot",
    "etsy": "https://www.etsy.com/forgot",
    "komoot": "https://www.komoot.com/signin",
    "polarsteps": "https://www.polarsteps.com/login",
    "letterboxd": "https://letterboxd.com/sign-in/",
    "eventbrite": "https://www.eventbrite.com/signin/",
    "deezer": "https://www.deezer.com/login",
    "codecademy": "https://www.codecademy.com/login",
    "leetcode": "https://leetcode.com/accounts/password/reset/",
    "hackthebox": "https://account.hackthebox.com/login",
    "hackerone": "https://hackerone.com/users/sign_in",
    "myanimelist": "https://myanimelist.net/login.php?from=%2Faccount%2Fmembership%2Frecover",
    "mastodon": "https://mastodon.social/auth/sign_in",
}


def _build_extra_summary(extra: dict) -> Optional[str]:
    if not extra:
        return None
    parts: list[str] = []
    stats = extra.get("stats")
    if stats:
        parts.append(str(stats))
    elif extra.get("followers") is not None:
        parts.append(f"{extra['followers']} followers")
    if not stats:
        joined = extra.get("joined") or extra.get("date_created") or extra.get("member_since")
        if joined:
            joined_s = str(joined)
            parts.append(f"joined {joined_s[:10] if len(joined_s) >= 10 else joined_s}")
    for key in ("location", "bio", "name"):
        val = _clean_meta_value(extra.get(key))
        if val and key == "name" and _get_username(extra, {}):
            continue
        if val:
            parts.append(f"{key}: {val}")
    return " | ".join(parts[:4]) if parts else None


def _profile_from_template(platform: str, extra: dict, email: str, hit: dict) -> Optional[str]:
    key = _norm_platform(platform)
    fn = PLATFORM_PROFILE_TEMPLATES.get(key)
    if fn:
        return fn(extra, email, hit)
    domain_root = (hit.get("domain") or "").split(".")[0].lower()
    if domain_root:
        fn = PLATFORM_PROFILE_TEMPLATES.get(domain_root)
        if fn:
            return fn(extra, email, hit)
    return None


def _recovery_url(platform: str, hit: dict) -> Optional[str]:
    recovery = hit.get("emailrecovery")
    if isinstance(recovery, str) and recovery.strip():
        return recovery.strip()
    key = _norm_platform(platform)
    if key in PLATFORM_RECOVERY_URLS:
        return PLATFORM_RECOVERY_URLS[key]
    domain_root = (hit.get("domain") or "").split(".")[0].lower()
    return PLATFORM_RECOVERY_URLS.get(domain_root)


def build_email_hit_url(
    platform: str,
    extra: Optional[dict],
    email: str,
    hit: Optional[dict] = None,
) -> dict[str, Any]:
    """Build investigator-facing URL with link type for an email registration hit."""
    extra = extra or {}
    hit = hit or {}
    platform_norm = _norm_platform(
        platform or hit.get("name") or hit.get("site_name") or hit.get("domain") or ""
    )
    username = _get_username(extra, hit)
    domain = (hit.get("domain") or "").strip().lower()

    profile_url = _extract_profile_url(extra)
    if profile_url:
        return {
            "url": profile_url,
            "link_type": "profile",
            "username": username,
            "extra_summary": _build_extra_summary(extra),
        }

    raw_url = (hit.get("url") or "").strip()
    if raw_url and not _is_homepage_url(raw_url, domain, platform_norm):
        return {
            "url": raw_url,
            "link_type": "profile",
            "username": username,
            "extra_summary": _build_extra_summary(extra),
        }

    tpl_url = _profile_from_template(platform_norm, extra, email, hit)
    if tpl_url:
        return {
            "url": tpl_url,
            "link_type": "profile",
            "username": username,
            "extra_summary": _build_extra_summary(extra),
        }

    rec_url = _recovery_url(platform_norm, hit)
    if rec_url:
        return {
            "url": rec_url,
            "link_type": "recovery",
            "username": username,
            "extra_summary": _build_extra_summary(extra),
        }

    if domain:
        home = domain if domain.startswith("http") else f"https://{domain}/"
        return {
            "url": home,
            "link_type": "platform_home",
            "username": username,
            "extra_summary": _build_extra_summary(extra),
        }

    local = email.split("@")[0] if "@" in email else email
    search_q = quote(f"{platform_norm} {email} account") if platform_norm else quote(local)
    return {
        "url": f"https://www.google.com/search?q={search_q}",
        "link_type": "platform_home",
        "username": username,
        "extra_summary": _build_extra_summary(extra),
    }


def _sanitize_utf8(value: Any) -> Any:
    """Recursively coerce strings to valid UTF-8 (fixes httpx decode warnings)."""
    if isinstance(value, dict):
        return {k: _sanitize_utf8(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_utf8(v) for v in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace").decode("utf-8")
    return value


def _build_platform_url(hit: dict, email: str, extra: Optional[dict] = None) -> str:
    """Derive an investigator-facing URL for a platform hit (legacy wrapper)."""
    platform = hit.get("name") or hit.get("site_name") or hit.get("domain") or ""
    merged_extra = dict(extra or {})
    merged_extra.update(hit.get("extra") or {})
    return build_email_hit_url(platform, merged_extra, email, hit)["url"]


def enrich_email_hit(hit: dict, email: str, merged_extra: Optional[dict] = None) -> dict:
    """Add url/link_type/username/extra_summary and sanitize text for API consumers."""
    clean = _sanitize_utf8(hit)
    extra = dict(merged_extra or {})
    extra.update(clean.get("extra") or {})

    platform = clean.get("name") or clean.get("site_name") or clean.get("domain") or ""
    domain = (clean.get("domain") or "").strip().lower() or None
    built = build_email_hit_url(platform, extra, email, clean)

    name = (clean.get("name") or clean.get("site_name") or platform or "").strip()
    if name:
        clean["name"] = name
    if domain:
        clean["domain"] = domain
    clean["url"] = built["url"]
    clean["link_type"] = built["link_type"]
    if built.get("username"):
        clean["username"] = built["username"]
    if built.get("extra_summary"):
        clean["extra_summary"] = built["extra_summary"]
    if extra:
        clean["extra"] = extra
    return clean


def _enrich_holehe_hit(hit: dict, email: str, merged_extra: Optional[dict] = None) -> dict:
    """Add url/domain fields and sanitize text for API + CLI/GUI consumers."""
    return enrich_email_hit(hit, email, merged_extra=merged_extra)

SESSION_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# ──────────────────────────────────────────────
# Helper: single platform username probe
# ──────────────────────────────────────────────

def _probe_platform(platform: dict) -> dict:
    target_url = platform["url"].format(platform.get("_username", ""))
    try:
        resp = requests.get(
            target_url,
            timeout=6,
            headers=SESSION_HEADERS,
            allow_redirects=True
        )
        found = resp.status_code == 200
        return {
            "platform": platform["name"],
            "url": target_url if found else None,
            "found": found,
            "status_code": resp.status_code,
        }
    except Exception as exc:
        return {
            "platform": platform["name"],
            "url": None,
            "found": False,
            "error": str(exc),
        }


# ──────────────────────────────────────────────
# Route: /api/ip
# ──────────────────────────────────────────────

@identity_bp.route('/ip', methods=['GET'])
def ip_lookup():
    """
    Query params: ip – IPv4 or IPv6 address
    Returns geolocation, ASN, and network metadata from ipwho.is
    """
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({"success": False, "error": "The 'ip' query parameter is required."}), 400
    try:
        results = {}

        # 1. Base IP Geolocation (ipwho.is)
        resp = requests.get(f"http://ipwho.is/{ip}", timeout=8)
        resp.raise_for_status()
        base_data = resp.json()
        results.update(base_data)

        # 1b. Shodan InternetDB enrichment (free, unauthenticated).
        #     Failures here never break the primary geolocation result.
        results["internetdb"] = _query_internetdb(ip)

        # 2. VirusTotal (if key provided)
        vt_key = _vt_key()
        if vt_key:
            try:
                vt_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": vt_key},
                    timeout=5
                )
                if vt_resp.status_code == 200:
                    vt_data = vt_resp.json().get("data", {}).get("attributes", {})
                    results["virustotal"] = {
                        "reputation": vt_data.get("reputation", 0),
                        "malicious": vt_data.get("last_analysis_stats", {}).get("malicious", 0),
                        "suspicious": vt_data.get("last_analysis_stats", {}).get("suspicious", 0),
                        "harmless": vt_data.get("last_analysis_stats", {}).get("harmless", 0)
                    }
                elif vt_resp.status_code == 401:
                    results["virustotal"] = {"error": "Invalid API Key or Unauthorized (HTTP 401)"}
                else:
                    results["virustotal"] = {"error": f"HTTP {vt_resp.status_code}"}
            except Exception as e:
                results["virustotal"] = {"error": str(e)}

        # 3. AbuseIPDB (if key provided)
        abuse_key = _abuse_key()
        if abuse_key:
            try:
                abuse_resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    timeout=5
                )
                if abuse_resp.status_code == 200:
                    abuse_data = abuse_resp.json().get("data", {})
                    results["abuseipdb"] = {
                        "abuseConfidenceScore": abuse_data.get("abuseConfidenceScore"),
                        "totalReports": abuse_data.get("totalReports"),
                        "isPublic": abuse_data.get("isPublic"),
                        "domain": abuse_data.get("domain")
                    }
                else:
                    results["abuseipdb"] = {"error": f"HTTP {abuse_resp.status_code}"}
            except Exception as e:
                results["abuseipdb"] = {"error": str(e)}

        return jsonify(results)
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "IP lookup service timed out."}), 504
    except requests.exceptions.HTTPError as exc:
        return jsonify({"success": False, "error": f"Upstream HTTP error: {exc}"}), 502
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ──────────────────────────────────────────────
# Route: /api/phone
# ──────────────────────────────────────────────

def _parse_phone_request():
    """Return (phone, installation_id, truecaller_enabled)."""
    user_phone = ""
    installation_id = ""
    truecaller_enabled = True

    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        user_phone = (body.get("phone") or "").strip()
        installation_id = (body.get("installation_id") or "").strip()
        truecaller_enabled = bool(body.get("truecaller", False))
    else:
        user_phone = request.args.get("phone", "").strip()
        installation_id = request.args.get("installation_id", "").strip()
        tc_flag = request.args.get("truecaller", "").strip().lower()
        if tc_flag in ("0", "false", "no", "off"):
            truecaller_enabled = False

    return user_phone, installation_id, truecaller_enabled


def _phone_lookup_result(user_phone: str, installation_id: str, truecaller_enabled: bool) -> dict:
    result: dict = {}

    # ── phonenumbers library ──────────────────
    try:
        # Default to 'IN' if no country code provided to prevent parsing crashes
        default_region = None if user_phone.startswith('+') else 'IN'
        parsed = phonenumbers.parse(user_phone, default_region)
        result["is_valid"]    = phonenumbers.is_valid_number(parsed)
        result["region"]      = phonenumbers.region_code_for_number(parsed)
        result["carrier"]     = carrier.name_for_number(parsed, "en") or "Unknown"
        result["location"]    = geocoder.description_for_number(parsed, "en") or "Unknown"
        result["timezones"]   = list(pn_timezone.time_zones_for_number(parsed))
        result["number_type"] = str(phonenumbers.number_type(parsed))
        result["e164_format"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )
        result["international_format"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
    except phonenumbers.phonenumberutil.NumberParseException as exc:
        result["phonenumbers_error"] = f"Could not parse number: {exc}"
    except Exception as exc:
        result["phonenumbers_error"] = str(exc)

    # ── Truecaller (optional enrichment) ──
    if truecaller_enabled:
        tc_id = (installation_id or _truecaller_id()).strip()
        tc_phone = result.get("e164_format") or user_phone
        try:
            from modules.truecaller_intel import lookup_truecaller  # type: ignore
        except ImportError:  # pragma: no cover
            from api.modules.truecaller_intel import lookup_truecaller  # type: ignore
        result["truecaller"] = lookup_truecaller(tc_phone, tc_id)
    else:
        result["truecaller"] = {"skipped": True, "reason": "offline phonenumbers only"}

    return result


@identity_bp.route('/phone', methods=['GET', 'POST'])
def phone_lookup():
    """
    GET query params:
        phone           – E.164 number, e.g. +62812345678
        installation_id – (optional) Truecaller auth token
        truecaller      – set to false to skip Truecaller (default: true for GET)

    POST JSON body:
        phone           – E.164 number (required)
        truecaller      – bool, enable deep lookup (default: false)
        installation_id – (optional) Truecaller auth token
    """
    user_phone, installation_id, truecaller_enabled = _parse_phone_request()

    if not user_phone:
        msg = "The 'phone' field is required." if request.method == "POST" else "The 'phone' query parameter is required."
        return jsonify({"success": False, "error": msg}), 400

    return jsonify(_phone_lookup_result(user_phone, installation_id, truecaller_enabled))


# ──────────────────────────────────────────────
# Route: /api/username
# NOTE: CLI and Web GUI use POST /api/recon/username (WhatsMyName 600+ site scan).
# This shallow 10-platform endpoint remains for API backward compatibility only.
# ──────────────────────────────────────────────

@identity_bp.route('/username', methods=['GET'])
def username_lookup():
    """
    Query params: username – handle to footprint (without @)
    Probes social platforms concurrently for public profile existence.
    """
    username = request.args.get('username', '').strip().lstrip('@')
    if not username:
        return jsonify({"error": "The 'username' query parameter is required."}), 400

    # Inject username into each platform dict
    platforms = [{**p, "_username": username} for p in SOCIAL_PLATFORMS]

    found_on: list  = []
    not_found: list = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_probe_platform, p): p for p in platforms}
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
            except Exception as exc:
                res = {"platform": "Unknown", "found": False, "error": str(exc)}
            if res.get("found"):
                found_on.append(res)
            else:
                not_found.append(res)

    return jsonify({
        "username": username,
        "platforms_checked": len(SOCIAL_PLATFORMS),
        "found_count": len(found_on),
        "found_on": found_on,
        "not_found": not_found,
    })


# ──────────────────────────────────────────────
# Route: /api/email
# ──────────────────────────────────────────────

@identity_bp.route('/email', methods=['GET'])
def email_lookup():
    """
    Query params: email – target email address
    Uses holehe (if installed) to probe 120+ platforms via
    their forgot-password endpoints — without alerting the target.
    Falls back to a descriptive error if holehe is not available.
    """
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({"success": False, "error": "The 'email' query parameter is required."}), 400

    # Basic format validation
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"success": False, "error": "Invalid email format."}), 400

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="Some characters could not be decoded*",
            )
            # holehe uses async — run it inside a new event loop
            # pyrefly: ignore [missing-import]
            from holehe import core as holehe_core
            # pyrefly: ignore [missing-import]
            import holehe.modules  # triggers registration of all platform modules

            # get_functions expects a dict or list of modules, not the holehe.modules package directly
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            modules_dict = holehe_core.import_submodules("holehe.modules")
            websites = holehe_core.get_functions(modules_dict)

            async def _run_holehe():
                client = None
                out_list: list[dict] = []
                try:
                    import httpx
                    proxy = Config.get_httpx_proxy()
                    client = httpx.AsyncClient(
                        timeout=httpx.Timeout(12.0),
                        follow_redirects=True,
                        proxy=proxy,
                        headers=Config.get_random_headers(),
                    )
                    tasks = [func(email, client, out_list) for func in websites]
                    await asyncio.gather(*tasks, return_exceptions=True)
                finally:
                    if client:
                        await client.aclose()
                return out_list

            async def _run_all_scans():
                holehe_task = _run_holehe()
                us_task = scan_email_extended(email)
                results = await asyncio.gather(holehe_task, us_task, return_exceptions=True)
                holehe_out = results[0] if not isinstance(results[0], Exception) else []
                us_out = results[1] if not isinstance(results[1], Exception) else {
                    "success": False,
                    "error": str(results[1]),
                    "source": "user-scanner",
                    "registered": [],
                    "total_checked": 0,
                }
                return holehe_out, us_out

            raw_results, user_scanner = loop.run_until_complete(_run_all_scans())
            loop.close()

        raw_results = [_sanitize_utf8(r) for r in raw_results if isinstance(r, dict)]

        us_registered = (
            user_scanner.get("registered", [])
            if isinstance(user_scanner, dict) else []
        )
        us_by_name = {
            (r.get("site_name") or "").strip().lower(): r
            for r in us_registered
            if isinstance(r, dict)
        }

        registered = []
        for r in raw_results:
            if not r.get("exists"):
                continue
            name_key = (r.get("name") or "").strip().lower()
            us_hit = us_by_name.get(name_key)
            merged_extra = dict(us_hit.get("extra") or {}) if us_hit else None
            registered.append(_enrich_holehe_hit(r, email, merged_extra=merged_extra))

        registered = dedupe_hits(registered)
        unregistered = [r for r in raw_results if not r.get("exists") and not r.get("rateLimit")]
        rate_limited = [r for r in raw_results if r.get("rateLimit")]

        payload = {
            "email": email,
            "platforms_checked": len(raw_results),
            "registered_count": len(registered),
            "registered_on": registered,
            "not_registered_count": len(unregistered),
            "rate_limited_count": len(rate_limited),
        }

        if request.args.get("supplementary", "").lower() in ("1", "true", "yes"):
            supp = run_supplementary_email_scan(email)
            if supp.get("success"):
                holehe_names = {(r.get("name") or "").lower() for r in registered}
                extra = [
                    enrich_email_hit(r, email)
                    for r in supp.get("registered_on", [])
                    if (r.get("name") or "").lower() not in holehe_names
                ]
                extra = dedupe_hits(extra)
                payload["supplementary"] = {
                    "platforms_checked": supp.get("platforms_checked", 0),
                    "registered_count": len(extra),
                    "registered_on": extra,
                }

        if isinstance(user_scanner, dict) and user_scanner.get("registered"):
            holehe_keys = {
                (r.get("name") or r.get("domain") or "").lower()
                for r in registered
            }
            enriched_registered = [
                enrich_email_hit(r, email) for r in user_scanner.get("registered", [])
            ]
            us_only = [
                r for r in enriched_registered
                if (r.get("site_name") or r.get("name") or "").lower() not in holehe_keys
            ]
            us_only = dedupe_hits(us_only)
            payload["user_scanner"] = {
                **user_scanner,
                "registered": enriched_registered,
                "registered_unique": us_only,
                "registered_unique_count": len(us_only),
            }
            payload["platforms_checked"] = (
                payload.get("platforms_checked", 0)
                + user_scanner.get("total_checked", 0)
            )
        elif isinstance(user_scanner, dict):
            payload["user_scanner"] = user_scanner

        return jsonify(payload)

    except ImportError:
        # holehe not installed — return structured mock so the endpoint never 500s
        return jsonify({
            "success": False,
            "email": email,
            "error": "holehe is not installed in this environment.",
            "resolution": (
                "Install it with: pip install holehe "
                "then redeploy. The endpoint structure is ready to receive its output."
            ),
            "mock_response": {
                "registered_on": [
                    {
                        "name": "Twitter",
                        "exists": True,
                        "domain": "twitter.com",
                        "url": "https://twitter.com/account/begin_password_reset",
                        "link_type": "recovery",
                        "emailrecovery": None,
                        "phoneNumber": None,
                    },
                    {
                        "name": "Adobe",
                        "exists": True,
                        "domain": "adobe.com",
                        "url": "https://account.adobe.com/forgot",
                        "link_type": "recovery",
                        "emailrecovery": None,
                        "phoneNumber": None,
                    },
                ],
                "note": "This is illustrative mock data. Install holehe for live results."
            }
        }), 200

    except Exception as exc:
        return jsonify({
            "success": False,
            "email": email,
            "error": f"holehe analysis encountered an error: {exc}",
        }), 200  # 200 so the frontend renders the error gracefully


# ──────────────────────────────────────────────
# Route: /api/breach
# ──────────────────────────────────────────────

@identity_bp.route('/breach', methods=['GET'])
def breach_lookup():
    """
    Query params: email – target email address
    Uses the XposedOrNot public API (free, no auth) to check
    if the email has appeared in known data breaches.
    """
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({"success": False, "error": "The 'email' query parameter is required."}), 400

    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"success": False, "error": "Invalid email format."}), 400

    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            timeout=8,
            headers=SESSION_HEADERS,
        )

        if resp.status_code == 200:
            data = resp.json()
            if data.get("ExposedBreaches"):
                breaches = data.get("ExposedBreaches", {}).get("breaches_details", [])
                return jsonify({
                    "email": email,
                    "status": "breached",
                    "breach_data": breaches,
                })
            else:
                return jsonify({
                    "email": email,
                    "status": "safe",
                    "message": "No known public breaches found for this email.",
                })
        elif resp.status_code == 404:
            return jsonify({
                "email": email,
                "status": "safe",
                "message": "No known public breaches found for this email.",
            })
        else:
            return jsonify({
                "email": email,
                "status": "unknown",
                "message": f"XposedOrNot returned HTTP {resp.status_code}.",
            })

    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "email": email,
            "error": "XposedOrNot API timed out after 8 seconds.",
        }), 200
    except requests.exceptions.ConnectionError:
        return jsonify({
            "success": False,
            "email": email,
            "error": "Could not connect to XposedOrNot API.",
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "email": email,
            "error": f"Breach check failed: {exc}",
        }), 200


# ──────────────────────────────────────────────
# Route: /api/infostealer  (Hudson Rock — adapted from user-scanner)
# ──────────────────────────────────────────────

@identity_bp.route('/infostealer', methods=['GET'])
def infostealer_lookup():
    """
    Query params:
        email    – target email (mutually exclusive with username)
        username – target handle
    Uses Hudson Rock's free infostealer intelligence API.
    """
    email = request.args.get('email', '').strip()
    username = request.args.get('username', '').strip().lstrip('@')

    if email and username:
        return jsonify({
            "success": False,
            "error": "Provide either 'email' or 'username', not both.",
        }), 400
    if not email and not username:
        return jsonify({
            "success": False,
            "error": "The 'email' or 'username' query parameter is required.",
        }), 400

    target = email or username
    result = query_hudson_rock(target, is_email=bool(email))
    return jsonify(result)

