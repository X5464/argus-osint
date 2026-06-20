"""Central runtime configuration for ARGUS.

Provides realistic User-Agent rotation and a runtime-mutable Tor / SOCKS proxy
toggle that every ``api/`` module can share. The CLI Tor OpSec engine flips the
proxy switch at runtime; because the Flask app runs in-process (background
thread) the change is visible to all outbound network helpers immediately.

All values are 100% free / FOSS friendly — no API keys, no tokens.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────
# Module-level mutable proxy state (single source of truth)
# ──────────────────────────────────────────────────────────────────────────
TOR_PROXY: str = "socks5h://127.0.0.1:9050"
# Default OFF. The CLI `tor on` command flips this at runtime via
# Config.set_proxy_enabled(True). Never enabled implicitly.
USE_PROXY: bool = False


class Config:
    """Shared configuration namespace.

    Class attributes are intentionally mutable so the CLI can toggle the proxy
    at runtime (e.g. ``Config.USE_PROXY = True``). Helper class methods always
    read the live value so the change propagates everywhere.
    """

    # Tor SOCKS endpoint. ``socks5h`` resolves DNS through Tor (no DNS leaks).
    TOR_PROXY: str = TOR_PROXY

    # Live toggle. Mirror of the module-level flag; kept in sync by the setters.
    USE_PROXY: bool = USE_PROXY

    #: 20+ realistic, modern desktop User-Agents spanning Windows, macOS and
    #: Linux across Chrome, Firefox, Safari and Edge.
    USER_AGENTS: List[str] = [
        # ── Chrome · Windows ──
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        # ── Chrome · macOS ──
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        # ── Chrome · Linux ──
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        # ── Firefox · Windows ──
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        # ── Firefox · macOS ──
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
        # ── Firefox · Linux ──
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        # ── Safari · macOS ──
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        # ── Edge · Windows ──
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        # ── Edge · macOS ──
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        # ── Chrome · Windows (older minor) ──
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        # ── Firefox · Windows ESR ──
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        # ── Chrome · Linux (Fedora) ──
        "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        # ── Safari · macOS (older) ──
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    ]

    # ──────────────────────────────────────────────────────────────────
    # User-Agent / header helpers
    # ──────────────────────────────────────────────────────────────────
    @classmethod
    def get_random_user_agent(cls) -> str:
        """Return one random realistic User-Agent string."""
        return random.choice(cls.USER_AGENTS)

    @classmethod
    def get_random_headers(cls) -> Dict[str, str]:
        """Return a realistic browser-like header set with a random UA.

        Suitable for ``requests`` and ``httpx`` alike.
        """
        return {
            "User-Agent": cls.get_random_user_agent(),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

    # ──────────────────────────────────────────────────────────────────
    # Proxy helpers
    # ──────────────────────────────────────────────────────────────────
    @classmethod
    def set_proxy_enabled(cls, enabled: bool) -> None:
        """Flip the Tor/SOCKS proxy on or off at runtime.

        Keeps both the class attribute and the module-level mirror in sync so
        any caller reading either sees a consistent value.
        """
        global USE_PROXY
        cls.USE_PROXY = bool(enabled)
        USE_PROXY = bool(enabled)

    @classmethod
    def is_proxy_enabled(cls) -> bool:
        """Return the live proxy toggle state."""
        return bool(cls.USE_PROXY)

    @classmethod
    def get_proxies(cls) -> Optional[Dict[str, str]]:
        """Return a ``requests``-style proxies dict, or ``None`` when disabled.

        Example return value::

            {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        """
        if not cls.USE_PROXY:
            return None
        return {"http": cls.TOR_PROXY, "https": cls.TOR_PROXY}

    @classmethod
    def get_httpx_proxy(cls) -> Optional[str]:
        """Return the proxy URL string for ``httpx``, or ``None`` when disabled.

        ``httpx`` accepts a single proxy URL (``proxies=`` / ``proxy=``) rather
        than the http/https mapping that ``requests`` uses.
        """
        if not cls.USE_PROXY:
            return None
        return cls.TOR_PROXY
