"""ARGUS Recon / OSINT module.

Free, FOSS, unauthenticated reconnaissance utilities:

* :class:`UsernameScanner`  – WhatsMyName (600+ sites) async username footprinting.
* :class:`EmailInvestigator` – Google public-profile probe + SMTP RCPT validation.
* :class:`NetworkScanner`    – native asyncio TCP scanner with banner grabbing.
* :class:`MacParser`         – IEEE OUI → manufacturer resolution.
* :func:`generate_username_dorks` – offline Google-dork URL generator.

Every network call uses :class:`api.config.Config` for User-Agent rotation and
optional Tor/SOCKS proxying, and is wrapped in defensive error handling so a
single failure never breaks a scan.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import smtplib
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests
from flask import Blueprint, jsonify, request

try:  # httpx is required for the async username scanner
    import httpx
except ImportError:  # pragma: no cover - handled gracefully at call time
    httpx = None  # type: ignore

try:  # dnspython for MX resolution
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover
    dns = None  # type: ignore

# Config import works whether 'api' is the package root (Flask) or top-level.
try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

try:
    from modules.user_scanner_extra import (  # type: ignore
        count_username_patterns,
        expand_username_patterns_random,
    )
except ImportError:  # pragma: no cover
    from api.modules.user_scanner_extra import (  # type: ignore
        count_username_patterns,
        expand_username_patterns_random,
    )

try:
    from modules.user_scanner_bridge import (  # type: ignore
        dedupe_hits,
        scan_username_extended,
    )
except ImportError:  # pragma: no cover
    from api.modules.user_scanner_bridge import (  # type: ignore
        dedupe_hits,
        scan_username_extended,
    )

recon_bp = Blueprint('recon_bp', __name__)

# ──────────────────────────────────────────────────────────────────────────
# Filesystem helpers (data directory resolution + on-demand download caching)
# ──────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_DATA_DIR = os.path.join(_PROJECT_ROOT, 'data')

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"


def _ensure_data_dir() -> None:
    """Create the ``data/`` directory if it does not yet exist."""
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
    except OSError:
        pass


def _resolve_data_file(filename: str) -> Optional[str]:
    """Return the first existing path for *filename* in data/ then project root."""
    candidates = [
        os.path.join(_DATA_DIR, filename),
        os.path.join(_PROJECT_ROOT, filename),
    ]
    for path in candidates:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return None


def _download_to_data(url: str, filename: str, timeout: int = 30) -> Optional[str]:
    """Best-effort download of *url* into ``data/<filename>``.

    Returns the cached path on success, ``None`` on any failure.
    """
    _ensure_data_dir()
    dest = os.path.join(_DATA_DIR, filename)
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers=Config.get_random_headers(),
            proxies=Config.get_proxies(),
            stream=True,
        )
        resp.raise_for_status()
        with open(dest, 'wb') as handle:
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    handle.write(chunk)
        if os.path.getsize(dest) > 0:
            return dest
        return None
    except Exception:
        # Remove partial/empty file so future reads don't see corrupt data.
        try:
            if os.path.exists(dest) and os.path.getsize(dest) == 0:
                os.remove(dest)
        except OSError:
            pass
        return None


# ══════════════════════════════════════════════════════════════════════════
# UsernameScanner — WhatsMyName
# ══════════════════════════════════════════════════════════════════════════
class UsernameScanner:
    """Async username footprinting using the WhatsMyName site database."""

    DATA_FILE = "wmn-data.json"
    CONCURRENCY = 50
    TIMEOUT = 8.0

    def __init__(self) -> None:
        self._sites: List[Dict[str, Any]] = []
        self._load_error: Optional[str] = None
        self._load_sites()

    def _load_sites(self) -> None:
        """Load wmn-data.json from disk, downloading + caching it if missing."""
        path = _resolve_data_file(self.DATA_FILE)
        if not path:
            path = _download_to_data(WMN_URL, self.DATA_FILE)
        if not path:
            self._load_error = (
                "wmn-data.json not found and could not be downloaded. "
                "Place it manually in the data/ folder "
                f"(source: {WMN_URL})."
            )
            return
        try:
            with open(path, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
            self._sites = data.get('sites', []) or []
            if not self._sites:
                self._load_error = "wmn-data.json contained no 'sites' entries."
        except Exception as exc:  # pragma: no cover - corrupt file
            self._load_error = f"Failed to parse wmn-data.json: {exc}"

    @property
    def site_count(self) -> int:
        return len(self._sites)

    async def _check_site(
        self,
        client: "httpx.AsyncClient",
        sem: asyncio.Semaphore,
        site: Dict[str, Any],
        username: str,
    ) -> Optional[Dict[str, str]]:
        """Validate a single site per the WhatsMyName schema."""
        uri = site.get('uri_check')
        if not uri:
            return None
        target = uri.replace('{account}', username)
        e_code = site.get('e_code')
        e_string = site.get('e_string')
        m_string = site.get('m_string')
        async with sem:
            try:
                resp = await client.get(target, timeout=self.TIMEOUT)
            except Exception:
                return None
        try:
            body = resp.text
        except Exception:
            return None
        # Positive detection: expected code + expected string present + miss absent.
        if e_code is not None and resp.status_code != e_code:
            return None
        if e_string and e_string not in body:
            return None
        if m_string and m_string in body:
            return None
        return {
            "name": site.get('name', 'Unknown'),
            "category": site.get('cat', 'unknown'),
            "url": target,
        }

    async def _scan_async(self, username: str) -> List[Dict[str, str]]:
        proxy = Config.get_httpx_proxy()
        client_kwargs: Dict[str, Any] = {
            "headers": Config.get_random_headers(),
            "follow_redirects": True,
            "timeout": self.TIMEOUT,
        }
        if proxy:
            client_kwargs["proxies"] = proxy
        sem = asyncio.Semaphore(self.CONCURRENCY)
        results: List[Dict[str, str]] = []
        async with httpx.AsyncClient(**client_kwargs) as client:
            tasks = [
                self._check_site(client, sem, site, username)
                for site in self._sites
            ]
            for found in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(found, dict):
                    results.append(found)
        results.sort(key=lambda r: (r["category"], r["name"].lower()))
        return results

    def scan(self, username: str) -> Dict[str, Any]:
        """Run a synchronous scan (wraps the async engine via asyncio.run)."""
        if httpx is None:
            return {
                "success": False,
                "error": "httpx is not installed. Install with: pip install 'httpx[socks]'.",
            }
        if self._load_error:
            return {"success": False, "error": self._load_error}
        username = username.strip().lstrip('@')
        if not username:
            return {"success": False, "error": "A username is required."}
        try:
            found, user_scanner = asyncio.run(self._scan_with_extended(username))
        except Exception as exc:
            return {"success": False, "error": f"Scan failed: {exc}"}

        us_found = []
        us_meta: Dict[str, Any] = {}
        if isinstance(user_scanner, dict):
            us_meta = user_scanner
            us_found = [
                {
                    "name": hit.get("site_name", "Unknown"),
                    "category": hit.get("category", "unknown"),
                    "url": hit.get("url", ""),
                    "extra": hit.get("extra") or {},
                    "source": "user-scanner",
                }
                for hit in user_scanner.get("found", [])
            ]

        wmn_keys = {(s.get("name") or "").lower() for s in found}
        us_unique = [s for s in us_found if (s.get("name") or "").lower() not in wmn_keys]
        merged_found = dedupe_hits(found + us_unique)

        return {
            "success": True,
            "username": username,
            "sites_checked": self.site_count + us_meta.get("total_checked", 0),
            "found_count": len(merged_found),
            "found": merged_found,
            "user_scanner_found": us_found,
            "user_scanner": us_meta,
        }

    async def _scan_with_extended(self, username: str):
        wmn_task = self._scan_async(username)
        us_task = scan_username_extended(username)
        results = await asyncio.gather(wmn_task, us_task, return_exceptions=True)
        wmn = results[0] if not isinstance(results[0], Exception) else []
        us = results[1] if not isinstance(results[1], Exception) else {
            "success": False,
            "error": str(results[1]),
            "source": "user-scanner",
            "found": [],
            "total_checked": 0,
        }
        return wmn, us


# Module-level singleton so the (large) site DB is parsed only once.
_username_scanner: Optional[UsernameScanner] = None


def _get_username_scanner() -> UsernameScanner:
    global _username_scanner
    if _username_scanner is None:
        _username_scanner = UsernameScanner()
    return _username_scanner


# ══════════════════════════════════════════════════════════════════════════
# EmailInvestigator — Google public profile + SMTP RCPT validation
# ══════════════════════════════════════════════════════════════════════════
class EmailInvestigator:
    """Free email investigation: Google public profile probe + SMTP validation."""

    # Public web API key embedded in Google's own front-end JS. It is NOT a
    # user credential — it identifies the web client only and requires no login.
    _GOOGLE_PUBLIC_KEY = "AIzaSyBNlYh01_9Hc5S1J9vuFmu2nUqBZJNAXxs"
    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    @classmethod
    def _valid_email(cls, email: str) -> bool:
        return bool(cls._EMAIL_RE.match(email or ""))

    def google_account_check(self, email: str) -> Dict[str, Any]:
        """Probe Google's public People API for a Gaia ID / name / avatar.

        Uses the unauthenticated public web key. Google increasingly blocks
        anonymous enrichment, so this degrades gracefully: it always returns a
        structured result and never raises.
        """
        email = (email or "").strip()
        if not self._valid_email(email):
            return {"success": False, "error": "Invalid email format."}

        result: Dict[str, Any] = {
            "success": True,
            "email": email,
            "found": False,
            "name": None,
            "gaia_id": None,
            "photo_url": None,
            "note": "",
        }

        url = (
            "https://people-pa.clients6.google.com/v2/people/lookup"
            f"?key={self._GOOGLE_PUBLIC_KEY}&id={quote_plus(email)}"
            "&type=EMAIL&match_type=EXACT"
        )
        headers = Config.get_random_headers()
        headers["X-Origin"] = "https://accounts.google.com"
        try:
            resp = requests.get(
                url,
                headers=headers,
                proxies=Config.get_proxies(),
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            result["note"] = f"Google probe network error: {exc}"
            return result

        if resp.status_code in (401, 403):
            result["note"] = (
                "Google blocks unauthenticated profile enrichment for this "
                "request (HTTP %d) — inconclusive without authenticated cookies."
                % resp.status_code
            )
            return result
        if resp.status_code != 200:
            result["note"] = f"Google returned HTTP {resp.status_code} — no public data."
            return result

        try:
            data = resp.json()
        except ValueError:
            result["note"] = "Google response was not valid JSON."
            return result

        # Walk the (deeply nested) people response for any public fields.
        try:
            people = data.get("people") or {}
            for _person_key, person in people.items():
                names = person.get("name") or []
                photos = person.get("photo") or []
                meta = person.get("metadata") or {}
                gaia = None
                ids = meta.get("identityInfo", {}).get("sourceIds", []) if meta else []
                if ids:
                    gaia = ids[0].get("id")
                if names:
                    result["name"] = names[0].get("displayName")
                if photos:
                    result["photo_url"] = photos[0].get("url")
                if gaia:
                    result["gaia_id"] = gaia
                if result["name"] or result["photo_url"] or result["gaia_id"]:
                    result["found"] = True
                    result["note"] = "Public Google profile data located."
                break
        except Exception as exc:  # pragma: no cover - schema drift
            result["note"] = f"Could not parse Google profile data: {exc}"

        if not result["found"] and not result["note"]:
            result["note"] = "No public Google profile data returned for this email."
        return result

    def smtp_validate(self, email: str) -> Dict[str, Any]:
        """Validate an email via MX lookup + SMTP RCPT TO (no mail is sent)."""
        email = (email or "").strip()
        if not self._valid_email(email):
            return {"success": False, "error": "Invalid email format."}
        domain = email.split("@", 1)[1]

        result: Dict[str, Any] = {
            "success": True,
            "email": email,
            "domain": domain,
            "mx_records": [],
            "deliverable": None,
            "smtp_code": None,
            "smtp_message": "",
        }

        if dns is None:
            result["smtp_message"] = "dnspython not installed — cannot resolve MX records."
            return result

        # ── MX resolution ───────────────────────────────────────────────
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(domain, "MX")
            mx_hosts = sorted(
                ((r.preference, str(r.exchange).rstrip('.')) for r in answers),
                key=lambda x: x[0],
            )
            result["mx_records"] = [host for _pref, host in mx_hosts]
        except Exception as exc:
            result["smtp_message"] = f"MX lookup failed: {exc}"
            result["deliverable"] = False
            return result

        if not result["mx_records"]:
            result["smtp_message"] = "Domain has no MX records — likely undeliverable."
            result["deliverable"] = False
            return result

        # ── SMTP RCPT TO probe (does not send any message) ───────────────
        mx_host = result["mx_records"][0]
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host, 25)
            server.helo("argus.local")
            server.mail("probe@argus.local")
            code, message = server.rcpt(email)
            try:
                server.quit()
            except Exception:
                pass
            result["smtp_code"] = code
            msg_text = message.decode("utf-8", errors="ignore") if isinstance(message, bytes) else str(message)
            result["smtp_message"] = msg_text.strip()
            if code in (250, 251):
                result["deliverable"] = True
            elif code in (550, 551, 553, 554):
                result["deliverable"] = False
            else:
                result["deliverable"] = None
                result["smtp_message"] = (
                    f"inconclusive — provider returned {code}: {msg_text.strip()}"
                )
        except (smtplib.SMTPException, socket.error, OSError) as exc:
            result["deliverable"] = None
            result["smtp_message"] = (
                "inconclusive — provider blocks verification or port 25 is filtered "
                f"({exc})."
            )
        return result


_email_investigator = EmailInvestigator()


# ══════════════════════════════════════════════════════════════════════════
# NetworkScanner — native asyncio TCP scanner with banner grabbing
# ══════════════════════════════════════════════════════════════════════════
class NetworkScanner:
    """Native asyncio TCP connect scanner supporting single IP or CIDR."""

    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
    CONCURRENCY = 500
    CONNECT_TIMEOUT = 2.0
    BANNER_TIMEOUT = 1.5
    MAX_HOSTS = 1024

    SERVICE_NAMES = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3389: "RDP", 8080: "HTTP-ALT",
    }

    @classmethod
    def _expand_targets(cls, target: str) -> List[str]:
        """Expand a single IP / hostname / CIDR string into a host list."""
        target = (target or "").strip()
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in network.hosts()]
            if not hosts:  # /32 or /31 edge cases
                hosts = [str(network.network_address)]
            return hosts[: cls.MAX_HOSTS]
        return [target]

    async def _scan_port(
        self,
        host: str,
        port: int,
        sem: asyncio.Semaphore,
    ) -> Optional[Dict[str, Any]]:
        """Attempt a TCP connection and grab a small banner if open."""
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.CONNECT_TIMEOUT,
                )
            except Exception:
                return None

            banner = ""
            try:
                if port in (80, 8080):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                raw = await asyncio.wait_for(reader.read(256), timeout=self.BANNER_TIMEOUT)
                banner = raw.decode("latin-1", errors="ignore").strip()
            except Exception:
                banner = ""
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            return {
                "port": port,
                "service": self.SERVICE_NAMES.get(port, "unknown"),
                "banner": banner.split("\r\n")[0][:120] if banner else "",
            }

    async def _scan_async(self, hosts: List[str], ports: List[int]) -> List[Dict[str, Any]]:
        sem = asyncio.Semaphore(self.CONCURRENCY)
        host_results: List[Dict[str, Any]] = []
        for host in hosts:
            tasks = [self._scan_port(host, port, sem) for port in ports]
            open_ports = [r for r in await asyncio.gather(*tasks) if r]
            if open_ports or len(hosts) == 1:
                host_results.append({
                    "ip": host,
                    "status": "up" if open_ports else "no open ports",
                    "open_ports": open_ports,
                })
        return host_results

    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        full: bool = False,
    ) -> Dict[str, Any]:
        """Run a scan against a single IP or CIDR block."""
        try:
            hosts = self._expand_targets(target)
        except ValueError as exc:
            return {"success": False, "error": f"Invalid target: {exc}"}
        if not hosts:
            return {"success": False, "error": "No scannable hosts in target."}

        if full:
            scan_ports = list(range(1, 65536))
        elif ports:
            scan_ports = [p for p in ports if 0 < p < 65536]
        else:
            scan_ports = list(self.DEFAULT_PORTS)
        if not scan_ports:
            return {"success": False, "error": "No valid ports to scan."}

        try:
            results = asyncio.run(self._scan_async(hosts, scan_ports))
        except Exception as exc:
            return {"success": False, "error": f"Scan failed: {exc}"}

        return {
            "success": True,
            "target": target,
            "hosts_scanned": len(hosts),
            "ports_scanned": len(scan_ports),
            "results": results,
            "hosts_up": sum(1 for h in results if h["open_ports"]),
        }


_network_scanner = NetworkScanner()


# ══════════════════════════════════════════════════════════════════════════
# MacParser — IEEE OUI → manufacturer
# ══════════════════════════════════════════════════════════════════════════
class MacParser:
    """Resolve a MAC address to its hardware manufacturer via the IEEE OUI DB."""

    DATA_FILE = "oui.txt"
    _MAC_CLEAN_RE = re.compile(r"[^0-9A-Fa-f]")

    # ~30 common vendors as a guaranteed fallback when oui.txt is unavailable.
    FALLBACK_OUI = {
        "001451": "Apple, Inc.", "0017F2": "Apple, Inc.", "3C0754": "Apple, Inc.",
        "A4C361": "Apple, Inc.", "F0DBF8": "Apple, Inc.",
        "0012FB": "Samsung Electronics", "0015B9": "Samsung Electronics",
        "5CF6DC": "Samsung Electronics", "8425DB": "Samsung Electronics",
        "00000C": "Cisco Systems", "000142": "Cisco Systems", "00400B": "Cisco Systems",
        "001B21": "Intel Corporate", "0019D1": "Intel Corporate", "3C9709": "Intel Corporate",
        "00188B": "Dell Inc.", "14FEB5": "Dell Inc.", "B8CA3A": "Dell Inc.",
        "001A4B": "Hewlett Packard", "002264": "Hewlett Packard", "3C4A92": "Hewlett Packard",
        "00259E": "Huawei Technologies", "48435A": "Huawei Technologies",
        "781DBA": "Huawei Technologies",
        "3C5AB4": "Google, Inc.", "F4F5E8": "Google, Inc.", "54600C": "Google, Inc.",
        "0017FA": "Microsoft Corporation", "28188F": "Microsoft Corporation",
        "286FB9": "Nokia Shanghai Bell", "50C7BF": "TP-Link Technologies",
        "286C07": "Xiaomi Communications", "64B473": "Xiaomi Communications",
        "001315": "Sony Corporation", "00E091": "LG Electronics",
        "0871B0": "Amazon Technologies", "000FB5": "NETGEAR", "001BFC": "ASUSTek Computer",
        "00591A": "Lenovo", "00E04C": "Realtek Semiconductor", "002722": "Ubiquiti Networks",
    }

    def __init__(self) -> None:
        self._table: Optional[Dict[str, str]] = None
        self._source: str = "fallback"

    def _load_table(self) -> Dict[str, str]:
        """Lazily build the OUI→vendor table, downloading oui.txt if needed."""
        if self._table is not None:
            return self._table

        path = _resolve_data_file(self.DATA_FILE)
        if not path:
            path = _download_to_data(OUI_URL, self.DATA_FILE)

        table: Dict[str, str] = {}
        if path:
            try:
                with open(path, 'r', encoding='latin-1', errors='ignore') as handle:
                    for line in handle:
                        if "(hex)" not in line:
                            continue
                        prefix, _, vendor = line.partition("(hex)")
                        oui = prefix.strip().replace("-", "").replace(":", "").upper()
                        vendor = vendor.strip()
                        if len(oui) == 6 and vendor:
                            table[oui] = vendor
                if table:
                    self._source = os.path.basename(path)
            except Exception:
                table = {}

        if not table:
            table = dict(self.FALLBACK_OUI)
            self._source = "built-in fallback (~30 vendors)"

        self._table = table
        return table

    def lookup(self, mac: str) -> Dict[str, Any]:
        """Return the manufacturer for a MAC address (any common format)."""
        raw = (mac or "").strip()
        cleaned = self._MAC_CLEAN_RE.sub("", raw).upper()
        if len(cleaned) < 6:
            return {"success": False, "error": "Invalid MAC address — need at least 6 hex digits."}

        oui = cleaned[:6]
        table = self._load_table()
        vendor = table.get(oui)
        formatted = "-".join(cleaned[i:i + 2] for i in range(0, min(len(cleaned), 12), 2))
        if vendor:
            return {
                "success": True,
                "mac": formatted,
                "oui": "-".join(oui[i:i + 2] for i in range(0, 6, 2)),
                "manufacturer": vendor,
                "source": self._source,
            }
        return {
            "success": True,
            "mac": formatted,
            "oui": "-".join(oui[i:i + 2] for i in range(0, 6, 2)),
            "manufacturer": "Unknown / unregistered OUI",
            "source": self._source,
        }


_mac_parser = MacParser()


# ══════════════════════════════════════════════════════════════════════════
# Username dorking — pure offline Google-dork URL generator
# ══════════════════════════════════════════════════════════════════════════
_GOOGLE = "https://www.google.com/search?q="


def _dork_url(query: str) -> str:
    """Build a ready-to-click Google search URL for *query*."""
    return _GOOGLE + quote_plus(query)


def generate_username_dorks(username: str) -> Dict[str, Any]:
    """Generate categorized Google-dork search URLs for *username* (offline).

    No network access required — this is pure string generation.
    """
    username = (username or "").strip().lstrip('@')
    if not username:
        return {"success": False, "error": "A username is required."}

    q = f'"{username}"'
    categories: List[Dict[str, Any]] = [
        {
            "name": "Social Profiles",
            "dorks": [
                {"label": "Instagram", "url": _dork_url(f'site:instagram.com {q}')},
                {"label": "Facebook", "url": _dork_url(f'site:facebook.com {q}')},
                {"label": "Twitter / X", "url": _dork_url(f'(site:twitter.com OR site:x.com) {q}')},
                {"label": "Reddit", "url": _dork_url(f'site:reddit.com {q}')},
                {"label": "LinkedIn", "url": _dork_url(f'site:linkedin.com/in {q}')},
                {"label": "YouTube", "url": _dork_url(f'site:youtube.com {q}')},
                {"label": "TikTok", "url": _dork_url(f'site:tiktok.com {q}')},
                {"label": "Pinterest", "url": _dork_url(f'site:pinterest.com {q}')},
            ],
        },
        {
            "name": "Wishlists & Shopping",
            "dorks": [
                {"label": "Amazon wishlist", "url": _dork_url(f'site:amazon.com {q} (wishlist OR "wish list")')},
                {"label": "Flipkart", "url": _dork_url(f'site:flipkart.com {q}')},
                {"label": "Pinterest boards", "url": _dork_url(f'site:pinterest.com {q} (board OR wishlist)')},
                {"label": "Generic registry", "url": _dork_url(f'{q} (wishlist OR registry OR "gift list")')},
            ],
        },
        {
            "name": "Reviews & Activity",
            "dorks": [
                {"label": "Amazon reviews", "url": _dork_url(f'site:amazon.com {q} review')},
                {"label": "Flipkart reviews", "url": _dork_url(f'site:flipkart.com {q} review')},
                {"label": "Reddit comments", "url": _dork_url(f'site:reddit.com {q} (comment OR review)')},
                {"label": "Trustpilot / Yelp", "url": _dork_url(f'(site:trustpilot.com OR site:yelp.com) {q}')},
            ],
        },
        {
            "name": "Broad Web Search",
            "dorks": [
                {"label": "Exact handle", "url": _dork_url(q)},
                {"label": "In URL", "url": _dork_url(f'inurl:{username}')},
                {"label": "In title", "url": _dork_url(f'intitle:{username}')},
                {"label": "Documents", "url": _dork_url(f'{q} (filetype:pdf OR filetype:doc OR filetype:xls)')},
                {"label": "Paste sites", "url": _dork_url(f'(site:pastebin.com OR site:ghostbin.com) {q}')},
            ],
        },
    ]
    total = sum(len(c["dorks"]) for c in categories)
    return {
        "success": True,
        "username": username,
        "total": total,
        "categories": categories,
    }


# ══════════════════════════════════════════════════════════════════════════
# Flask routes
# ══════════════════════════════════════════════════════════════════════════
@recon_bp.route('/recon/username', methods=['POST'])
def recon_username():
    """WhatsMyName async username footprint across 600+ sites.

    Optional JSON fields:
        pattern (bool) – treat ``username`` as a wildcard pattern
        limit (int)    – max permutations when pattern mode (default 25, max 100)
    """
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"success": False, "error": "The 'username' field is required."}), 400

    use_pattern = bool(data.get('pattern')) or ('[' in username and ']' in username)
    if use_pattern:
        try:
            total = count_username_patterns(username)
        except ValueError as exc:
            return jsonify({"success": False, "error": f"Invalid pattern: {exc}"}), 400
        limit = min(max(int(data.get('limit') or 25), 1), 100)
        scanner = _get_username_scanner()
        found_all: List[Dict[str, str]] = []
        scanned: List[str] = []
        for handle in expand_username_patterns_random(username):
            if len(scanned) >= limit:
                break
            scanned.append(handle)
            result = scanner.scan(handle)
            if result.get("success"):
                for hit in result.get("found", []):
                    found_all.append({**hit, "matched_username": handle})
        return jsonify({
            "success": True,
            "pattern": username,
            "pattern_total": total,
            "pattern_scanned": len(scanned),
            "pattern_limit": limit,
            "usernames_scanned": scanned,
            "found_count": len(found_all),
            "found": found_all,
        })

    result = _get_username_scanner().scan(username)
    status = 200 if result.get("success") else 200  # never 500 — keep GUI happy
    return jsonify(result), status


@recon_bp.route('/recon/email/google', methods=['POST'])
def recon_email_google():
    """Public Google account profile probe for an email address."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({"success": False, "error": "The 'email' field is required."}), 400
    return jsonify(_email_investigator.google_account_check(email))


@recon_bp.route('/recon/email/smtp', methods=['POST'])
def recon_email_smtp():
    """SMTP RCPT TO deliverability probe (no message is sent)."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({"success": False, "error": "The 'email' field is required."}), 400
    return jsonify(_email_investigator.smtp_validate(email))


@recon_bp.route('/recon/portscan-async', methods=['POST'])
def recon_portscan_async():
    """Native asyncio TCP scan of a single IP or CIDR with banner grabbing."""
    data = request.get_json(silent=True) or {}
    target = (data.get('ip') or data.get('target') or '').strip()
    if not target:
        return jsonify({"success": False, "error": "The 'ip' (or 'target') field is required."}), 400
    ports = data.get('ports')
    if isinstance(ports, str):
        try:
            ports = [int(p) for p in re.split(r"[,\s]+", ports) if p]
        except ValueError:
            ports = None
    full = bool(data.get('full', False))
    return jsonify(_network_scanner.scan(target, ports=ports, full=full))


@recon_bp.route('/recon/mac', methods=['POST'])
def recon_mac():
    """Resolve a MAC address to its manufacturer via the IEEE OUI database."""
    data = request.get_json(silent=True) or {}
    mac = (data.get('mac') or '').strip()
    if not mac:
        return jsonify({"success": False, "error": "The 'mac' field is required."}), 400
    return jsonify(_mac_parser.lookup(mac))


@recon_bp.route('/recon/dork', methods=['POST'])
def recon_dork():
    """Generate categorized Google-dork URLs for a username (offline).

    When ``live`` is true, also runs DuckDuckGo HTML searches and adds
    ``ddg_results`` / ``combined_links`` alongside the Google dork payload.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"success": False, "error": "The 'username' field is required."}), 400
    result = generate_username_dorks(username)
    if not result.get("success"):
        return jsonify(result)
    if data.get("live"):
        try:
            from modules.search_engines import get_dual_search_engine  # type: ignore
        except ImportError:  # pragma: no cover
            from api.modules.search_engines import get_dual_search_engine  # type: ignore
        live = get_dual_search_engine().search_username(username)
        result["ddg_results"] = live.get("ddg_results", [])
        result["combined_links"] = live.get("combined_links", [])
        if live.get("warnings"):
            result["warnings"] = live["warnings"]
    return jsonify(result)


@recon_bp.route('/search/username', methods=['POST'])
def search_username():
    """Dual Google dork URLs + DuckDuckGo live username footprint."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"success": False, "error": "The 'username' field is required."}), 400
    try:
        from modules.search_engines import get_dual_search_engine  # type: ignore
    except ImportError:  # pragma: no cover
        from api.modules.search_engines import get_dual_search_engine  # type: ignore
    return jsonify(get_dual_search_engine().search_username(username))


@recon_bp.route('/search/emails', methods=['POST'])
def search_emails():
    """Harvest public emails for a domain via DuckDuckGo + Google dork URL."""
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip()
    if not domain:
        return jsonify({"success": False, "error": "The 'domain' field is required."}), 400
    try:
        from modules.search_engines import get_dual_search_engine  # type: ignore
    except ImportError:  # pragma: no cover
        from api.modules.search_engines import get_dual_search_engine  # type: ignore
    return jsonify(get_dual_search_engine().search_emails_in_domain(domain))


@recon_bp.route('/recon/domain-crawl', methods=['POST'])
def recon_domain_crawl():
    """Async deep-domain web crawler — BFS internal pages with contact extraction."""
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip()
    if not domain:
        return jsonify({"success": False, "error": "The 'domain' field is required."}), 400
    max_depth = data.get('max_depth', 2)
    max_pages = data.get('max_pages', 30)
    try:
        from modules.domain_crawler import crawl_domain_sync  # type: ignore
    except ImportError:  # pragma: no cover
        from api.modules.domain_crawler import crawl_domain_sync  # type: ignore
    return jsonify(crawl_domain_sync(domain, max_depth=max_depth, max_pages=max_pages))


@recon_bp.route('/recon/github', methods=['POST'])
def recon_github():
    """GitHub public API metadata / commit-email extraction."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    domain = (data.get('domain') or '').strip()
    if not username and not domain:
        return jsonify({
            "success": False,
            "error": "Provide 'username' or 'domain'.",
        }), 400
    try:
        from modules.github_intel import extract_github_by_domain, extract_github_intel  # type: ignore
    except ImportError:  # pragma: no cover
        from api.modules.github_intel import extract_github_by_domain, extract_github_intel  # type: ignore
    if username:
        return jsonify(extract_github_intel(username))
    return jsonify(extract_github_by_domain(domain))
