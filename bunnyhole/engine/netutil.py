"""Shared network-safety helpers: SSRF guards and host validation.

Bunnyhole fetches URLs and runs tools against seeds that may originate from an untrusted
investigation target (a scraped domain, a CT-log sister host, an ENS text record). Those seeds
must never be allowed to make the engine reach internal, loopback, or cloud-metadata endpoints.
These helpers centralize that check so every outbound fetch can validate before connecting.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

# A selector that is safe to pass as a single argv token to a subprocess (no leading dash, no shell
# metacharacters). Used to validate domains/handles/emails before they reach whois/sherlock/etc.
SAFE_SELECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$")

# The default Tor SOCKS listener. socks5h:// keeps DNS resolution on the Tor side, which is the
# only way a .onion name (which has no clearnet DNS) can be reached. Used for onion fetches and by
# the `--tor` convenience flag. Overridable via set_tor_proxy() / BUNNYHOLE_TOR_PROXY.
DEFAULT_TOR_PROXY = "socks5h://127.0.0.1:9050"

# Proxy URL schemes we accept from configuration. http(s) covers a plain forward proxy; socks5/5h
# covers Tor and other SOCKS proxies (requires the httpx[socks] extra to actually connect).
_ALLOWED_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4")

# Module-level proxy defaults. The CLI sets these once at startup so every outbound httpx client
# built via new_async_client() inherits them without threading a proxy argument through every agent
# constructor and call site. None means "direct connection".
_DEFAULT_PROXY: Optional[str] = None
_TOR_PROXY: str = DEFAULT_TOR_PROXY


class InvalidProxyError(ValueError):
    """Raised when a configured proxy URL is missing a host or uses an unsupported scheme."""


def validate_proxy_url(proxy: str) -> str:
    """Return the proxy URL unchanged if it is a supported scheme with a host; raise otherwise."""
    parts = urlsplit((proxy or "").strip())
    if parts.scheme not in _ALLOWED_PROXY_SCHEMES:
        raise InvalidProxyError(
            f"Unsupported proxy scheme {parts.scheme!r}; use one of {', '.join(_ALLOWED_PROXY_SCHEMES)}"
        )
    if not parts.hostname:
        raise InvalidProxyError(f"Proxy URL is missing a host: {proxy!r}")
    return proxy.strip()


def set_default_proxy(proxy: Optional[str]) -> None:
    """Set (or clear, with None/empty) the global proxy every new_async_client() call inherits."""
    global _DEFAULT_PROXY
    _DEFAULT_PROXY = validate_proxy_url(proxy) if proxy else None


def get_default_proxy() -> Optional[str]:
    """Return the global default proxy, or None for a direct connection."""
    return _DEFAULT_PROXY


def set_tor_proxy(proxy: str) -> None:
    """Override the Tor SOCKS proxy used for .onion fetches (default socks5h://127.0.0.1:9050)."""
    global _TOR_PROXY
    _TOR_PROXY = validate_proxy_url(proxy)


def get_tor_proxy() -> str:
    """Return the Tor SOCKS proxy URL used for .onion fetches."""
    return _TOR_PROXY


def new_async_client(
    *,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    follow_redirects: bool = False,
    proxy: Optional[str] = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Build an httpx.AsyncClient that honours the globally configured proxy.

    Every outbound call in Bunnyhole should go through this factory instead of instantiating
    httpx.AsyncClient directly, so a single --proxy / --tor setting routes the whole engine
    (including through Tor via anonsurf or a SOCKS listener) with no per-call-site plumbing.

    A `proxy` passed explicitly wins; otherwise the module default (set_default_proxy) is used.
    Pass proxy="" to force a direct connection for one client even when a global proxy is set.
    """
    chosen = proxy if proxy is not None else _DEFAULT_PROXY
    if chosen:
        kwargs["proxy"] = chosen
    return httpx.AsyncClient(
        timeout=timeout,
        headers=headers,
        follow_redirects=follow_redirects,
        **kwargs,
    )


def is_onion_host(host_or_url: str) -> bool:
    """True if the host (or the host of a URL) is a Tor .onion hidden service address."""
    raw = (host_or_url or "").strip()
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    host = raw.strip().strip("[]").lower().split("/")[0].split(":")[0]
    return host.endswith(".onion")


class UnsafeHostError(ValueError):
    """Raised when a host or URL resolves to a non-public address (SSRF protection)."""


def is_safe_selector(value: str) -> bool:
    """True if value is a single safe argv token (no leading '-', no shell metacharacters)."""
    return bool(SAFE_SELECTOR.match(value or "")) and not (value or "").startswith("-")


def _addr_is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def host_is_public(host: str) -> bool:
    """Resolve host and return True only if every resolved address is a public, routable IP.

    A bare IP literal is checked directly. A hostname is resolved and all A/AAAA records must be
    public; if resolution fails or any record is private/loopback/link-local, the host is unsafe.
    """
    host = (host or "").strip().strip("[]")
    if not host:
        return False
    # Literal IP?
    try:
        ipaddress.ip_address(host)
        return _addr_is_public(host)
    except ValueError:
        pass
    # Hostname: block obvious internal names fast, then resolve.
    low = host.lower()
    if low == "localhost" or low.endswith(".localhost") or low.endswith(".internal") or low.endswith(".local"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    resolved = {info[4][0] for info in infos}
    return bool(resolved) and all(_addr_is_public(addr) for addr in resolved)


def assert_public_url(url: str) -> str:
    """Validate that url is http(s) with a public host; raise UnsafeHostError otherwise.

    Returns the url unchanged on success so it can be used inline.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeHostError(f"Refusing non-http(s) URL scheme: {parts.scheme!r}")
    if not parts.hostname or not host_is_public(parts.hostname):
        raise UnsafeHostError(f"Refusing request to non-public host: {parts.hostname!r}")
    return url


def public_host_or_none(host: str) -> str | None:
    """Return the cleaned host if it is public, else None (convenience for callers that skip)."""
    cleaned = (host or "").strip().strip("[]")
    return cleaned if host_is_public(cleaned) else None


def safe_argv_selectors(values: List[str]) -> List[str]:
    """Filter a list of selectors down to the ones safe to pass as subprocess arguments."""
    return [v for v in values if is_safe_selector(v)]


async def fetch_onion(
    url: str,
    *,
    tor_proxy: Optional[str] = None,
    timeout: float = 25.0,
    headers: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Fetch a Tor .onion page through the Tor SOCKS proxy, or return None.

    This is the ONE sanctioned way to reach a non-clearnet host. It deliberately bypasses the
    host_is_public() SSRF guard (a .onion name has no resolvable clearnet IP), so it is locked down
    hard: the host must end in .onion (never a clearnet or internal name), the scheme must be
    http(s), and the request is forced through the Tor SOCKS proxy with remote DNS (socks5h). That
    combination means this path can only ever egress via Tor and can never be turned into an SSRF
    primitive against the local network. Returns the response text, or None on any failure
    (Tor not running, httpx[socks] missing, timeout, non-200).
    """
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https"):
        return None
    if not is_onion_host(url):
        return None
    proxy = validate_proxy_url(tor_proxy) if tor_proxy else _TOR_PROXY
    try:
        async with httpx.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=False, proxy=proxy
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.text
    except Exception:
        # Tor down, httpx[socks] not installed, DNS/circuit failure, timeout — all degrade to None.
        return None
    return None
