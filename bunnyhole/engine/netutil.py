"""Shared network-safety helpers: SSRF guards and host validation.

Bunnyhole fetches URLs and runs tools against seeds that may originate from an untrusted
investigation target (a scraped domain, a CT-log sister host, an ENS text record). Those seeds
must never be allowed to make the engine reach internal, loopback, or cloud-metadata endpoints.
These helpers centralize that check so every outbound fetch can validate before connecting.
"""

from __future__ import annotations

import asyncio
import functools
import ipaddress
import logging
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlsplit, urlunsplit

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


logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

#: ``cb(url, status_code, error)``: called once per finished HTTP exchange. ``status_code`` is None and ``error``
#: is the exception class name (never its message, which can echo URLs) when the transport failed.
ResponseObserver = Callable[[str, Optional[int], Optional[str]], None]

# Opt-in response observer. Default None: httpx is never touched and nothing is wrapped. The PI source log
# registers one for the duration of a run so a source that was answered HTTP 401 is not logged as a clean
# negative (see pi_runtime.PIRunRecorder).
_RESPONSE_OBSERVER: Optional[ResponseObserver] = None
_ORIGINAL_ASYNC_SEND: Any = None


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


def _notify(observer: ResponseObserver, url: str, status: Optional[int], error: Optional[str]) -> None:
    try:
        observer(url, status, error)
    except Exception:  # noqa: BLE001 - an observer bug must never break an investigative request
        logger.debug("response observer raised", exc_info=True)


def _install_send_observer() -> None:
    """Wrap ``httpx.AsyncClient.send`` once. Covers clients from new_async_client() and direct httpx clients."""
    global _ORIGINAL_ASYNC_SEND
    if _ORIGINAL_ASYNC_SEND is not None:
        return
    original = httpx.AsyncClient.send
    _ORIGINAL_ASYNC_SEND = original

    @functools.wraps(original)
    async def observed_send(self: httpx.AsyncClient, request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
        observer = _RESPONSE_OBSERVER
        if observer is None:
            return await original(self, request, *args, **kwargs)
        try:
            response = await original(self, request, *args, **kwargs)
        except Exception as exc:
            _notify(observer, str(request.url), None, type(exc).__name__)
            raise
        _notify(observer, str(response.request.url), response.status_code, None)
        return response

    httpx.AsyncClient.send = observed_send  # type: ignore[method-assign]


def _uninstall_send_observer() -> None:
    global _ORIGINAL_ASYNC_SEND
    if _ORIGINAL_ASYNC_SEND is not None:
        httpx.AsyncClient.send = _ORIGINAL_ASYNC_SEND  # type: ignore[method-assign]
        _ORIGINAL_ASYNC_SEND = None


def set_response_observer(observer: Optional[ResponseObserver]) -> None:
    """Register (or clear, with None) a callback told the status of every async HTTP exchange.

    Opt-in and process-wide. While unset there is zero overhead: ``httpx.AsyncClient.send`` is the untouched
    original. While set, every ``httpx.AsyncClient`` (built by :func:`new_async_client` or directly, as most
    agents do) reports ``(url, status_code, None)`` per response, or ``(url, None, "<ExceptionClass>")`` before
    the transport error is re-raised. The observer must be fast and non-blocking; exceptions it raises are
    swallowed. Redirect hops are not reported separately (only the final response).
    """
    global _RESPONSE_OBSERVER
    _RESPONSE_OBSERVER = observer
    if observer is None:
        _uninstall_send_observer()
    else:
        _install_send_observer()


def get_response_observer() -> Optional[ResponseObserver]:
    """Return the registered response observer, or None."""
    return _RESPONSE_OBSERVER


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


# Explicit deny list on top of ``ipaddress`` ``is_global``. ``is_global`` already excludes most of these, but its
# exact contents changed between Python releases (3.11 -> 3.13), so the ranges that matter for SSRF are pinned here.
_DENY_NETWORKS: Tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT, incl. Alibaba Cloud metadata 100.100.100.200
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, incl. AWS/GCP/Azure metadata 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, incl. 255.255.255.255
        "::/128",
        "::1/128",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",  # unique local, incl. fd00::/8
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")

# Hostname suffixes that are internal by definition and must never be resolved for an outbound fetch. ``.onion``
# is here because it has no clearnet address: it may only be reached via fetch_onion (and resolving it locally
# would leak the name to the local resolver).
_INTERNAL_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain", ".home.arpa", ".lan", ".onion")

# Something that inet_aton could read as an IPv4 address: 1-4 dot-separated decimal, octal or hex parts.
_IPV4_ISH = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}\.?$", re.IGNORECASE)

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _ip_is_public(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _ip_is_public(ip.ipv4_mapped)
        if ip.teredo is not None:
            return False
        if ip.sixtofour is not None:
            return _ip_is_public(ip.sixtofour)
        if ip in _NAT64_WELL_KNOWN:
            return _ip_is_public(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if any(ip.version == net.version and ip in net for net in _DENY_NETWORKS):
        return False
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _addr_is_public(addr: str) -> bool:
    """True only for a globally routable unicast address (IPv4-mapped / 6to4 / NAT64 judged by the embedded v4)."""
    try:
        ip = ipaddress.ip_address((addr or "").split("%", 1)[0])  # drop an IPv6 zone id ("fe80::1%en0")
    except ValueError:
        return False
    return _ip_is_public(ip)


def _literal_verdict(host: str) -> Optional[bool]:
    """Judge ``host`` without DNS if it is any IP literal form; None means "a name, resolve it".

    Covers dotted-quad, IPv6 (bracketed or not) and the legacy inet_aton forms that resolvers and some HTTP stacks
    still accept (``2130706433``, ``0x7f000001``, ``0177.0.0.1``, ``127.1``). A numeric-looking host that is not a
    valid address is refused rather than sent to DNS.
    """
    raw = host.strip().strip("[]").split("%", 1)[0]
    try:
        return _ip_is_public(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if _IPV4_ISH.match(raw):
        try:
            return _ip_is_public(ipaddress.IPv4Address(socket.inet_aton(raw.rstrip("."))))
        except (OSError, ValueError):
            return False
    if ":" in raw:
        return False  # neither a valid IPv6 literal nor a hostname
    return None


def _ascii_hostname(host: str) -> Optional[str]:
    """Lower-case, strip the root dot and IDNA-encode a hostname; None if it cannot be encoded."""
    name = host.strip().strip("[]").rstrip(".").lower()
    if not name:
        return None
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _name_is_internal(name: str) -> bool:
    return name == "localhost" or "." not in name or name.endswith(_INTERNAL_SUFFIXES)


def _getaddrinfo_sync(host: str) -> List[Any]:
    return socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)


async def _getaddrinfo_async(host: str) -> List[Any]:
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)


def _public_addresses(infos: List[Any]) -> List[str]:
    """The resolved addresses, in resolver order, or [] if any one of them is non-public (fail closed)."""
    resolved: List[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in resolved:
            resolved.append(addr)
    if not resolved or not all(_addr_is_public(a) for a in resolved):
        return []
    return resolved


def host_is_public(host: str) -> bool:
    """Resolve host and return True only if every resolved address is a public, routable IP.

    A literal IP in any form is checked directly; internal names (localhost, *.internal, *.local, single-label
    names, .onion) are refused without a lookup; a hostname is IDNA-encoded and every A/AAAA record must be
    public. Resolution failure means unsafe. Blocking: async code must use :func:`host_is_public_async`.
    """
    verdict = _literal_verdict(host or "")
    if verdict is not None:
        return verdict
    name = _ascii_hostname(host or "")
    if not name or _name_is_internal(name):
        return False
    try:
        infos = _getaddrinfo_sync(name)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    return bool(_public_addresses(infos))


async def resolve_public_addresses_async(host: str) -> List[str]:
    """Resolve ``host`` on the event loop and return its addresses; raise UnsafeHostError unless all are public.

    An IP literal is returned (normalised) without DNS when it is public.
    """
    raw = (host or "").strip()
    verdict = _literal_verdict(raw)
    if verdict is not None:
        if not verdict:
            raise UnsafeHostError(f"Refusing request to non-public address: {raw!r}")
        stripped = raw.strip("[]").split("%", 1)[0]
        try:
            return [str(ipaddress.ip_address(stripped))]
        except ValueError:
            return [str(ipaddress.IPv4Address(socket.inet_aton(stripped.rstrip("."))))]
    name = _ascii_hostname(raw)
    if not name or _name_is_internal(name):
        raise UnsafeHostError(f"Refusing request to internal or invalid host: {raw!r}")
    try:
        infos = await _getaddrinfo_async(name)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise UnsafeHostError(f"Could not resolve host {name!r}") from exc
    public = _public_addresses(infos)
    if not public:
        raise UnsafeHostError(f"Refusing request to host with a non-public address: {name!r}")
    return public


async def host_is_public_async(host: str) -> bool:
    """Non-blocking :func:`host_is_public` (uses ``loop.getaddrinfo``); for use inside async code."""
    try:
        await resolve_public_addresses_async(host)
    except UnsafeHostError:
        return False
    return True


def _check_url_shape(url: str) -> Tuple[Any, str]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeHostError(f"Refusing non-http(s) URL scheme: {parts.scheme!r}")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UnsafeHostError("Refusing URL with userinfo (user:pass@host)")
    try:
        host = parts.hostname or ""
    except ValueError as exc:
        raise UnsafeHostError("Refusing URL with a malformed host") from exc
    if not host:
        raise UnsafeHostError("Refusing URL without a host")
    return parts, host


def assert_public_url(url: str) -> str:
    """Validate that url is http(s) with a public host and no userinfo; raise UnsafeHostError otherwise.

    Returns the url unchanged on success so it can be used inline. Blocking (DNS): async code should use
    :func:`assert_public_url_async`.
    """
    _, host = _check_url_shape(url)
    if not host_is_public(host):
        raise UnsafeHostError(f"Refusing request to non-public host: {host!r}")
    return url


async def assert_public_url_async(url: str) -> str:
    """Non-blocking :func:`assert_public_url`."""
    _, host = _check_url_shape(url)
    await resolve_public_addresses_async(host)
    return url


def public_host_or_none(host: str) -> str | None:
    """Return the cleaned host if it is public, else None (convenience for callers that skip)."""
    cleaned = (host or "").strip().strip("[]")
    return cleaned if host_is_public(cleaned) else None


def normalize_domain_lead(raw: str) -> Optional[str]:
    """Reduce a domain lead to a bare ASCII hostname, or None if it is not one.

    Strips a scheme, path, query and the root dot, lower-cases and IDNA-encodes. Rejects anything carrying userinfo
    (``a.com:b@127.0.0.1``), a port, an IP literal in any form, a single-label or malformed name: a domain lead is a
    registrable name, never an address or an authority string.
    """
    text = (raw or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = re.split(r"[/?#\\]", text, maxsplit=1)[0]
    if not text or "@" in text or ":" in text or "[" in text or "]" in text:
        return None
    if _literal_verdict(text) is not None:
        return None
    name = _ascii_hostname(text)
    if not name or len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        return None
    return name


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


async def fetch_public_url(
    url: str,
    *,
    timeout: float = 8.0,
    headers: Optional[Dict[str, str]] = None,
    max_redirects: int = 3,
) -> httpx.Response:
    """GET an untrusted URL safely: validate, pin to the validated IP, and re-validate every redirect hop.

    - Scheme must be http(s); userinfo is refused; the host must resolve only to public addresses (async DNS).
    - Direct connection: the request is sent to the validated IP itself with the original ``Host`` header and TLS
      SNI / certificate check against the hostname (httpx ``sni_hostname`` extension), so a DNS answer that changes
      between the check and the connect (DNS rebinding) cannot redirect the connection.
    - Through a proxy (``--proxy`` / ``--tor``): the hostname is sent to the proxy, which resolves it. The local
      check still runs first, but a rebinding answer given only to the proxy is a residual risk (and the local
      check is itself a DNS query outside the proxy).
    - Redirects are never followed by httpx; each ``Location`` is re-validated the same way, up to
      ``max_redirects`` hops, then UnsafeHostError.
    """
    current = url
    for _hop in range(max_redirects + 1):
        parts, host = _check_url_shape(current)
        addresses = await resolve_public_addresses_async(host)
        req_headers = dict(headers or {})
        extensions: Dict[str, Any] = {}
        target = current
        if not _DEFAULT_PROXY:
            pinned = addresses[0]
            pinned_host = f"[{pinned}]" if ":" in pinned else pinned
            netloc = f"{pinned_host}:{parts.port}" if parts.port else pinned_host
            target = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
            req_headers["Host"] = parts.netloc
            if parts.scheme == "https":
                extensions["sni_hostname"] = host
        async with new_async_client(timeout=timeout, headers=req_headers, follow_redirects=False) as client:
            resp = await client.get(target, extensions=extensions)
            await resp.aread()
        location = resp.headers.get("location")
        if resp.status_code in _REDIRECT_STATUSES and location:
            current = urljoin(current, location)
            continue
        return resp
    raise UnsafeHostError(f"Refusing to follow more than {max_redirects} redirects")


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
