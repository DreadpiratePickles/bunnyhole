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
from typing import List
from urllib.parse import urlsplit

# A selector that is safe to pass as a single argv token to a subprocess (no leading dash, no shell
# metacharacters). Used to validate domains/handles/emails before they reach whois/sherlock/etc.
SAFE_SELECTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$")


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
