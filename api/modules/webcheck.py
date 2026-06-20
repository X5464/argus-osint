from __future__ import annotations

from flask import Blueprint, request, jsonify
import json
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote
# pyrefly: ignore [missing-import]
import dns.resolver

try:
    from config import Config  # type: ignore
except ImportError:  # pragma: no cover
    from api.config import Config  # type: ignore

webcheck_bp = Blueprint('webcheck_bp', __name__)

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def safe_resolve(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> list:
    """Resolve a DNS record type. Returns an empty list on any failure."""
    try:
        answers = resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def extract_domain(raw: str) -> str:
    """Strip scheme and path so we always work with a bare hostname."""
    return normalize_domain(raw)


def normalize_domain(raw: str) -> str:
    """Strip scheme, port, path, and leading ``www.`` from a domain input."""
    raw = raw.strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0].split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def _is_subdomain_of(name: str, apex: str) -> bool:
    """Return True when *name* is *apex* or a subdomain of it."""
    name = name.strip().lower().rstrip(".")
    apex = apex.strip().lower().rstrip(".")
    return name == apex or name.endswith(f".{apex}")


def _check_dns_live(hostname: str) -> bool:
    """Return True when *hostname* resolves to at least one A/AAAA record."""
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except OSError:
        return False


# ──────────────────────────────────────────────
# Route: /api/domain
# ──────────────────────────────────────────────

@webcheck_bp.route('/domain', methods=['GET'])
def domain_analysis():
    """
    Query params:
        url  – the target domain or full URL (e.g. example.com / https://example.com)

    Returns:
        JSON with IP, DNS records, HTTP security headers,
        and a basic reputation assessment.
    """
    raw_url = request.args.get('url', '').strip()
    if not raw_url:
        return jsonify({"error": "The 'url' query parameter is required."}), 400

    domain = extract_domain(raw_url)
    base_url = f"https://{domain}"

    result: dict = {
        "domain": domain,
        "ip_address": None,
        "dns_records": {},
        "security_headers": {},
        "missing_headers": [],
        "server_software": None,
        "threat_summary": {
            "flagged": False,
            "notes": []
        }
    }

    # ── IP resolution ──────────────────────────
    try:
        result["ip_address"] = socket.gethostbyname(domain)
    except Exception as exc:
        result["ip_error"] = str(exc)

    # ── DNS records ────────────────────────────
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 4

    result["dns_records"]["A"]     = safe_resolve(resolver, domain, "A")
    result["dns_records"]["AAAA"]  = safe_resolve(resolver, domain, "AAAA")
    result["dns_records"]["MX"]    = safe_resolve(resolver, domain, "MX")
    result["dns_records"]["NS"]    = safe_resolve(resolver, domain, "NS")
    result["dns_records"]["TXT"]   = safe_resolve(resolver, domain, "TXT")
    result["dns_records"]["CNAME"] = safe_resolve(resolver, domain, "CNAME")
    result["dns_records"]["SOA"]   = safe_resolve(resolver, domain, "SOA")

    # ── HTTP headers & security posture ────────
    REQUIRED_SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    SENSITIVE_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

    try:
        resp = requests.get(
            base_url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (SecurityAuditBot/1.0)"}
        )
        headers = dict(resp.headers)

        # Populate present security headers
        for h in REQUIRED_SECURITY_HEADERS:
            if h in headers:
                result["security_headers"][h] = headers[h]
            else:
                result["missing_headers"].append(h)

        # Server software disclosure
        for disclosure in SENSITIVE_DISCLOSURE_HEADERS:
            if disclosure in headers:
                result["server_software"] = headers[disclosure]
                result["threat_summary"]["notes"].append(
                    f"Server version disclosure via '{disclosure}' header: {headers[disclosure]}"
                )

        # HTTP-only flag
        if resp.url.startswith("http://"):
            result["threat_summary"]["notes"].append(
                "Domain does not redirect to HTTPS — plaintext traffic is possible."
            )

        # Missing critical headers threat annotation
        critical_missing = {"Content-Security-Policy", "Strict-Transport-Security"} & set(result["missing_headers"])
        if critical_missing:
            result["threat_summary"]["notes"].append(
                f"Critical security headers absent: {', '.join(critical_missing)}"
            )

        if result["threat_summary"]["notes"]:
            result["threat_summary"]["flagged"] = True

        result["http_status_code"] = resp.status_code

    except requests.exceptions.SSLError:
        result["threat_summary"]["flagged"] = True
        result["threat_summary"]["notes"].append("SSL/TLS handshake failed — certificate may be invalid or self-signed.")
    except requests.exceptions.ConnectionError:
        result["http_error"] = "Could not establish a connection to the target domain."
    except requests.exceptions.Timeout:
        result["http_error"] = "HTTP request timed out after 8 seconds."
    except Exception as exc:
        result["http_error"] = str(exc)

    # ── Subdomain discovery via Certificate Transparency ──
    result["subdomains"] = _fetch_subdomains(domain)

    return jsonify(result)


# ──────────────────────────────────────────────
# Helper: crt.sh subdomain discovery
# ──────────────────────────────────────────────

def _parse_crt_sh_payload(raw_text: str) -> list[dict[str, Any]]:
    """Parse crt.sh JSON payload with explicit UTF-8 handling."""
    if not raw_text.strip():
        return []
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _crawl_html_subdomains(apex: str) -> set[str]:
    """Crawl the homepage of apex using BeautifulSoup + regex to extract subdomains."""
    import re
    from bs4 import BeautifulSoup
    discovered = set()
    
    # Try HTTPS and HTTP
    urls_to_try = [f"https://{apex}", f"http://{apex}"]
    html_content = ""
    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                timeout=10,
                headers=Config.get_random_headers(),
                proxies=Config.get_proxies(),
                allow_redirects=True
            )
            if resp.status_code == 200:
                html_content = resp.text
                break
        except Exception:
            continue
            
    if not html_content:
        return discovered

    # 1. BeautifulSoup parsing
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Gather URLs from typical attributes
        urls = []
        for tag in soup.find_all(True):
            # Check href, src, action
            for attr in ("href", "src", "action"):
                val = tag.get(attr)
                if isinstance(val, str) and val.strip():
                    urls.append(val.strip())
                    
        # Parse hostnames from extracted URLs
        from urllib.parse import urlparse
        for u in urls:
            try:
                # Handle schemeless URLs like //sub.domain.com/path
                if u.startswith("//"):
                    u = "http:" + u
                elif not u.startswith("http://") and not u.startswith("https://"):
                    # Relative path or non-HTTP scheme, skip
                    continue
                parsed = urlparse(u)
                netloc = parsed.netloc or parsed.path
                host = netloc.split(":")[0].lower().rstrip(".")
                if _is_subdomain_of(host, apex) and host != apex:
                    discovered.add(host)
            except Exception:
                pass
    except Exception:
        pass

    # 2. Regex parsing on the raw HTML to catch any inline references
    try:
        # Regex matching subdomains of the apex (e.g. sub.domain.com)
        pattern = rf"\b([a-z0-9_-]+\.)+{re.escape(apex)}\b"
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            host = match.group(0).lower().rstrip(".")
            if _is_subdomain_of(host, apex) and host != apex:
                discovered.add(host)
    except Exception:
        pass

    return discovered


def enumerate_subdomains(
    raw_domain: str,
    limit: int = 100,
    check_live: bool = True,
) -> dict[str, Any]:
    """
    Query crt.sh Certificate Transparency logs and perform a homepage
    web crawl (via BeautifulSoup + regex) to extract discovered subdomains.
    Additionally marks which hostnames currently resolve via DNS.
    """
    apex = normalize_domain(raw_domain)
    result: dict[str, Any] = {
        "domain": apex,
        "input_domain": raw_domain.strip(),
        "source": "crt.sh + Web Crawler",
        "ct_subdomain_count": 0,
        "live_subdomain_count": 0,
        "subdomain_count": 0,
        "ct_subdomains": [],
        "live_subdomains": [],
        "subdomains": [],
        "results": [],
        "error": None,
    }

    if not apex or "." not in apex:
        result["error"] = "Invalid domain."
        return result

    # Track discovered hosts and their sources
    subdomain_sources: dict[str, set[str]] = {}

    # ── Step 1: crt.sh Certificate Transparency Logs ─────────────────────
    try:
        resp = requests.get(
            f"https://crt.sh/?q={quote(f'%.{apex}')}&output=json",
            timeout=30,
            headers=Config.get_random_headers(),
            proxies=Config.get_proxies(),
        )
        if resp.status_code == 200:
            raw_text = resp.content.decode("utf-8", errors="replace")
            raw_entries = _parse_crt_sh_payload(raw_text)
            for entry in raw_entries:
                names = entry.get("name_value", "")
                if not isinstance(names, str):
                    continue
                for name in names.split("\n"):
                    name = name.strip().lower().rstrip(".")
                    if not name or name.startswith("*"):
                        continue
                    if _is_subdomain_of(name, apex) and name != apex:
                        subdomain_sources.setdefault(name, set()).add("ct_log")
    except Exception as exc:
        # Don't fail the entire search if crt.sh times out; we still have the webcrawler
        result["error"] = f"crt.sh warning: {exc}"

    # ── Step 2: BeautifulSoup & Regex Webcrawler ──────────────────────────
    try:
        crawled_names = _crawl_html_subdomains(apex)
        for name in crawled_names:
            subdomain_sources.setdefault(name, set()).add("web_crawler")
    except Exception as exc:
        pass

    # Compile sorted subdomain list up to the limit
    sorted_hosts = sorted(subdomain_sources.keys())[:limit]
    live_names: set[str] = set()

    # ── Step 3: Concurrently probe live DNS status ────────────────────────
    if check_live and sorted_hosts:
        def _probe(host: str) -> tuple[str, bool]:
            return host, _check_dns_live(host)

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(_probe, host) for host in sorted_hosts]
            for future in as_completed(futures):
                try:
                    host, is_live = future.result()
                    if is_live:
                        live_names.add(host)
                except Exception:
                    pass

    # Build response format
    ct_subdomains = [
        {
            "subdomain": host,
            "url": f"https://{host}",
            "source": ", ".join(sorted(subdomain_sources[host])),
            "live": host in live_names,
        }
        for host in sorted_hosts
    ]
    live_subdomains = [entry for entry in ct_subdomains if entry["live"]]

    result.update({
        "ct_subdomain_count": len(ct_subdomains),
        "live_subdomain_count": len(live_subdomains),
        "subdomain_count": len(ct_subdomains),
        "ct_subdomains": ct_subdomains,
        "live_subdomains": live_subdomains,
        "subdomains": [entry["subdomain"] for entry in ct_subdomains],
        "results": ct_subdomains,
    })
    return result


def _fetch_subdomains(domain: str, limit: int = 100) -> list[str]:
    """Legacy helper — returns hostname strings from CT logs."""
    payload = enumerate_subdomains(domain, limit=limit, check_live=False)
    return payload.get("subdomains", [])


# ──────────────────────────────────────────────
# Route: /api/subdomains
# ──────────────────────────────────────────────

@webcheck_bp.route('/subdomains', methods=['GET'])
def subdomain_lookup():
    """
    Query params: domain – target domain (e.g. example.com)
    Uses crt.sh Certificate Transparency logs (free, no auth)
    to discover all known subdomains for a domain.
    """
    raw_domain = request.args.get('domain', '').strip()
    if not raw_domain:
        return jsonify({"error": "The 'domain' query parameter is required."}), 400

    payload = enumerate_subdomains(raw_domain)
    if payload.get("error") and not payload.get("ct_subdomains"):
        return jsonify({"success": False, **payload}), 200

    return jsonify({"success": True, **payload})


# ──────────────────────────────────────────────
# Threat Intelligence Endpoints
# ──────────────────────────────────────────────

@webcheck_bp.route('/scan-abuseip', methods=['POST'])
def scan_abuseip():
    data = request.get_json() or {}
    target_ip = data.get('target')
    api_key = request.headers.get('X-Abuse-Key')
    if not api_key:
        try:
            from vault import get_key
        except ImportError:
            from api.vault import get_key  # type: ignore
        api_key = get_key('abuse')
    
    if not api_key:
        return jsonify({"error": "AbuseIPDB API key locked or missing. Please configure the API Vault."}), 401

    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        req = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params={"ipAddress": target_ip, "maxAgeInDays": 30}, timeout=10)
        
        # Extract live token quotas directly from the AbuseIPDB headers
        limit = req.headers.get('x-ratelimit-limit', 1000)
        remaining = req.headers.get('x-ratelimit-remaining', 'Unknown')
        
        response_data = req.json()
        response_data["quota_tracker"] = {"limit": limit, "remaining": remaining}
        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 200

@webcheck_bp.route('/scan-virustotal', methods=['POST'])
def scan_virustotal():
    data = request.get_json() or {}
    target = data.get('target')
    api_key = request.headers.get('X-VT-Key')
    if not api_key:
        try:
            from vault import get_key
        except ImportError:
            from api.vault import get_key  # type: ignore
        api_key = get_key('vt')
    
    if not api_key:
        return jsonify({"error": "VirusTotal API key locked or missing. Please configure the API Vault."}), 401

    try:
        headers = {"x-apikey": api_key}
        # Assuming target is an IP for this specific scan
        req = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{target}", headers=headers, timeout=10)
        
        response_data = req.json()
        response_data["quota_tracker"] = {"limit": 500, "remaining": "Tracked internally by VT (Max 4/min)"}
        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 200
