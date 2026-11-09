"""Audit regressions for ``bunnyhole.engine.netutil``: SSRF address policy, literal forms, async resolution,
domain-lead normalisation and the pinned, redirect-revalidating public fetch.

DNS is never queried: the resolver hooks (``_getaddrinfo_sync`` / ``_getaddrinfo_async``) are monkeypatched, and
HTTP is mocked with respx.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

import httpx
import pytest
import respx

from bunnyhole.engine import netutil
from bunnyhole.engine.netutil import (
    UnsafeHostError,
    _addr_is_public,
    assert_public_url_async,
    fetch_public_url,
    host_is_public,
    host_is_public_async,
    normalize_domain_lead,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def _infos(*addrs: str) -> List[Any]:
    out = []
    for a in addrs:
        fam = socket.AF_INET6 if ":" in a else socket.AF_INET
        out.append((fam, socket.SOCK_STREAM, 6, "", (a, 0)))
    return out


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Dict[str, List[str]]:
    table: Dict[str, List[str]] = {}
    asked: List[str] = []

    def lookup(host: str) -> List[Any]:
        asked.append(host)
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return _infos(*table[host])

    async def lookup_async(host: str) -> List[Any]:
        return lookup(host)

    monkeypatch.setattr(netutil, "_getaddrinfo_sync", lookup)
    monkeypatch.setattr(netutil, "_getaddrinfo_async", lookup_async)
    table["__asked__"] = asked  # type: ignore[assignment]
    return table


@pytest.fixture(autouse=True)
def _no_proxy():
    netutil.set_default_proxy(None)
    yield
    netutil.set_default_proxy(None)


# --- address policy ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        "100.64.0.1",  # CGNAT
        "100.100.100.200",  # Alibaba Cloud metadata (inside CGNAT)
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "169.254.0.1",
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "198.18.0.1",
        "192.0.0.8",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "2002:a9fe:a9fe::1",  # 6to4 of 169.254.169.254
        "2001:db8::1",
        "fe80::1%en0",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_refused(addr: str) -> None:
    assert _addr_is_public(addr) is False


@pytest.mark.parametrize("addr", [PUBLIC_V4, "8.8.8.8", PUBLIC_V6, "::ffff:8.8.8.8", "2002:0808:0808::1"])
def test_public_addresses_are_allowed(addr: str) -> None:
    assert _addr_is_public(addr) is True


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",  # decimal 127.0.0.1
        "0x7f000001",  # hex
        "0177.0.0.1",  # octal first octet
        "017700000001",
        "127.1",  # short form
        "0x7f.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[fd00::1]",
        "2852039166",  # decimal 169.254.169.254
        "999.1.1.1",  # numeric but invalid: never sent to DNS
    ],
)
def test_alternate_ip_literal_forms_are_refused_without_dns(host: str, fake_dns: Dict[str, Any]) -> None:
    assert host_is_public(host) is False
    assert asyncio.run(host_is_public_async(host)) is False
    assert fake_dns["__asked__"] == []


def test_alternate_literal_of_a_public_address_is_allowed_without_dns(fake_dns: Dict[str, Any]) -> None:
    assert host_is_public("134744072") is True  # decimal 8.8.8.8
    assert fake_dns["__asked__"] == []


@pytest.mark.parametrize("host", ["localhost", "db.localhost", "metadata.google.internal", "printer.local",
                                  "router.home.arpa", "intranet", "abc.onion"])
def test_internal_names_are_refused_without_dns(host: str, fake_dns: Dict[str, Any]) -> None:
    assert host_is_public(host) is False
    assert asyncio.run(host_is_public_async(host)) is False
    assert fake_dns["__asked__"] == []


def test_hostname_must_resolve_only_to_public_addresses(fake_dns: Dict[str, Any]) -> None:
    fake_dns["good.example"] = [PUBLIC_V4, PUBLIC_V6]
    fake_dns["mixed.example"] = [PUBLIC_V4, "10.0.0.5"]
    fake_dns["cgnat.example"] = ["100.64.1.1"]
    assert host_is_public("good.example") is True
    assert host_is_public("mixed.example") is False
    assert host_is_public("cgnat.example") is False
    assert host_is_public("missing.example") is False
    assert asyncio.run(host_is_public_async("good.example")) is True
    assert asyncio.run(host_is_public_async("mixed.example")) is False


def test_unicode_hostname_is_resolved_as_punycode(fake_dns: Dict[str, Any]) -> None:
    fake_dns["xn--bcher-kva.example"] = [PUBLIC_V4]
    assert host_is_public("bücher.example") is True
    assert asyncio.run(host_is_public_async("BÜCHER.example")) is True
    assert "xn--bcher-kva.example" in fake_dns["__asked__"]


def test_async_variant_does_not_call_blocking_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("blocking getaddrinfo used inside async code")

    async def fake_async(host: str) -> List[Any]:
        return _infos(PUBLIC_V4)

    monkeypatch.setattr(netutil, "_getaddrinfo_sync", boom)
    monkeypatch.setattr(netutil.socket, "getaddrinfo", boom)
    monkeypatch.setattr(netutil, "_getaddrinfo_async", fake_async)
    assert asyncio.run(host_is_public_async("good.example")) is True


def test_default_async_resolver_uses_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[str] = []

    async def loop_getaddrinfo(self: Any, host: str, *args: Any, **kwargs: Any) -> List[Any]:
        calls.append(host)
        return _infos(PUBLIC_V4)

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", loop_getaddrinfo)
    assert asyncio.run(host_is_public_async("good.example")) is True
    assert calls == ["good.example"]


def test_assert_public_url_async_rejects_userinfo_tricks_and_bad_schemes(fake_dns: Dict[str, Any]) -> None:
    fake_dns["a.com"] = [PUBLIC_V4]
    for url in ("https://a.com:b@127.0.0.1/", "ftp://a.com/", "https://[::1]/", "http://169.254.169.254/latest"):
        with pytest.raises(UnsafeHostError):
            asyncio.run(assert_public_url_async(url))
    assert asyncio.run(assert_public_url_async("https://a.com/x")) == "https://a.com/x"


# --- domain-lead normalisation -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("https://example.com/about?x=1", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("sub.xn--bcher-kva.example", "sub.xn--bcher-kva.example"),
    ],
)
def test_normalize_domain_lead_accepts_plain_hostnames(raw: str, expected: str) -> None:
    assert normalize_domain_lead(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "a.com:b@127.0.0.1",  # userinfo + IP
        "user@example.com",
        "example.com:8443",  # port
        "127.0.0.1",
        "2130706433",
        "[::1]",
        "::1",
        "",
        "localhost",  # single label
        "-bad.example",
        "exa mple.com",
        "1.2.3.4.5",  # all-numeric last label: an IPv4 form, not a hostname
        "a" * 64 + ".com",
    ],
)
def test_normalize_domain_lead_rejects_userinfo_ports_ip_literals_and_junk(raw: str) -> None:
    assert normalize_domain_lead(raw) is None


# --- fetch_public_url --------------------------------------------------------------------------------------


def test_fetch_public_url_pins_the_validated_ip_and_keeps_host_and_sni(fake_dns: Dict[str, Any]) -> None:
    fake_dns["site.example"] = [PUBLIC_V4]
    with respx.mock(assert_all_called=True) as router:
        route = router.get(f"https://{PUBLIC_V4}/favicon.ico").mock(return_value=httpx.Response(200, content=b"x"))
        resp = asyncio.run(fetch_public_url("https://site.example/favicon.ico", timeout=3.0))
    assert resp.status_code == 200
    req = route.calls.last.request
    assert req.headers["host"] == "site.example"
    assert req.extensions.get("sni_hostname") == "site.example"


def test_fetch_public_url_revalidates_every_redirect_hop(fake_dns: Dict[str, Any]) -> None:
    fake_dns["site.example"] = [PUBLIC_V4]
    with respx.mock(assert_all_called=False) as router:
        router.get(f"https://{PUBLIC_V4}/favicon.ico").mock(
            return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
        )
        meta = router.get(url__regex=r"http://169\.254\.169\.254/.*").mock(return_value=httpx.Response(200))
        with pytest.raises(UnsafeHostError):
            asyncio.run(fetch_public_url("https://site.example/favicon.ico", timeout=3.0))
    assert not meta.called


def test_fetch_public_url_follows_a_public_redirect(fake_dns: Dict[str, Any]) -> None:
    fake_dns["site.example"] = [PUBLIC_V4]
    fake_dns["cdn.example"] = ["8.8.4.4"]
    with respx.mock(assert_all_called=True) as router:
        router.get(f"https://{PUBLIC_V4}/favicon.ico").mock(
            return_value=httpx.Response(301, headers={"location": "https://cdn.example/f.ico"})
        )
        final = router.get("https://8.8.4.4/f.ico").mock(return_value=httpx.Response(200, content=b"icon"))
        resp = asyncio.run(fetch_public_url("https://site.example/favicon.ico", timeout=3.0))
    assert resp.content == b"icon"
    assert final.calls.last.request.headers["host"] == "cdn.example"


def test_fetch_public_url_stops_after_max_redirects(fake_dns: Dict[str, Any]) -> None:
    fake_dns["loop.example"] = [PUBLIC_V4]
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=f"https://{PUBLIC_V4}/").mock(
            return_value=httpx.Response(302, headers={"location": "https://loop.example/again"})
        )
        with pytest.raises(UnsafeHostError):
            asyncio.run(fetch_public_url("https://loop.example/", timeout=3.0, max_redirects=2))


def test_fetch_public_url_through_a_proxy_uses_the_hostname_and_the_proxy(
    fake_dns: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_dns["site.example"] = [PUBLIC_V4]
    built: List[Dict[str, Any]] = []
    real_client = httpx.AsyncClient

    class RecordingClient(real_client):  # type: ignore[misc,valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            built.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(netutil.httpx, "AsyncClient", RecordingClient)
    netutil.set_default_proxy("http://127.0.0.1:8080")
    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://site.example/").mock(return_value=httpx.Response(200, text="ok"))
        resp = asyncio.run(fetch_public_url("https://site.example/", timeout=3.0))
    assert resp.text == "ok"
    assert route.called
    assert built and built[-1].get("proxy") == "http://127.0.0.1:8080"
    assert built[-1].get("follow_redirects") is False


def test_fetch_public_url_refuses_internal_targets_before_any_request(fake_dns: Dict[str, Any]) -> None:
    fake_dns["internal.example"] = ["10.0.0.7"]
    with respx.mock(assert_all_called=False) as router:
        anything = router.route().mock(return_value=httpx.Response(200))
        for url in ("https://internal.example/", "https://127.0.0.1/", "https://a.com:b@127.0.0.1/favicon.ico"):
            with pytest.raises(UnsafeHostError):
                asyncio.run(fetch_public_url(url, timeout=3.0))
    assert not anything.called
