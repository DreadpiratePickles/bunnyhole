"""Audit regressions for the OSINT agent: favicon SSRF, domain-lead hygiene, no Scrapling bypass, subprocess reaping.

DNS is faked through netutil's resolver hooks; HTTP is mocked with respx.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import types
from typing import Any, List

import httpx
import pytest
import respx

from bunnyhole.agents import osint as osint_module
from bunnyhole.agents.osint import OSINTAgent, _communicate
from bunnyhole.engine import netutil
from bunnyhole.engine.graph import InvestigationGraph

PUBLIC_V4 = "93.184.216.34"


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> dict:
    table = {"site.example": [PUBLIC_V4], "a.com": [PUBLIC_V4]}

    def infos(host: str) -> List[Any]:
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in table[host]]

    async def infos_async(host: str) -> List[Any]:
        return infos(host)

    monkeypatch.setattr(netutil, "_getaddrinfo_sync", infos)
    monkeypatch.setattr(netutil, "_getaddrinfo_async", infos_async)
    netutil.set_default_proxy(None)
    yield table
    netutil.set_default_proxy(None)


def _agent() -> tuple[OSINTAgent, InvestigationGraph]:
    graph = InvestigationGraph("osint-audit", "site.example")
    return OSINTAgent(graph), graph


# --- M1: SSRF through userinfo in the favicon URL -------------------------------------------------------------


def test_userinfo_domain_never_reaches_loopback(fake_dns: dict) -> None:
    agent, graph = _agent()
    with respx.mock(assert_all_called=False) as router:
        anything = router.route().mock(return_value=httpx.Response(200, text="<html>G-ABCDEFGH12</html>"))
        asyncio.run(agent._scrape_and_fingerprint_site("a.com:b@127.0.0.1", "case:root", 1))
    hosts = [c.request.url.host for c in anything.calls]
    assert "127.0.0.1" not in hosts
    assert not anything.called
    assert any(e.action == "SSRF_BLOCKED" for e in graph.logs)


def test_favicon_is_fetched_from_the_validated_host_without_blind_redirects(fake_dns: dict) -> None:
    agent, graph = _agent()
    with respx.mock(assert_all_called=False) as router:
        page = router.get(f"https://{PUBLIC_V4}/").mock(return_value=httpx.Response(200, text="<html>hello</html>"))
        fav = router.get(f"https://{PUBLIC_V4}/favicon.ico").mock(
            return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        )
        meta = router.get(url__regex=r"http://169\.254\.169\.254/.*").mock(return_value=httpx.Response(200, content=b"x" * 200))
        asyncio.run(agent._scrape_and_fingerprint_site("site.example", "case:root", 1))
    assert page.called and fav.called
    assert fav.calls.last.request.headers["host"] == "site.example"
    assert not meta.called
    assert not any(n.id.startswith("tracker:favicon:") for n in graph.nodes.values())


def test_favicon_hash_still_recorded_for_a_public_site(fake_dns: dict) -> None:
    agent, graph = _agent()
    icon = bytes(range(256)) * 2
    with respx.mock(assert_all_called=False) as router:
        router.get(f"https://{PUBLIC_V4}/").mock(return_value=httpx.Response(200, text="<html>G-ABCDEFGH12</html>"))
        router.get(f"https://{PUBLIC_V4}/favicon.ico").mock(return_value=httpx.Response(200, content=icon))
        asyncio.run(agent._scrape_and_fingerprint_site("site.example", "case:root", 1))
    assert any(n.id.startswith("tracker:favicon:") for n in graph.nodes.values())
    assert "tracker:G-ABCDEFGH12" in graph.nodes


@pytest.mark.parametrize("lead", ["a.com:b@127.0.0.1", "site.example:8443", "127.0.0.1", "2130706433", "[::1]"])
def test_domain_infrastructure_rejects_userinfo_ports_and_ip_literals(lead: str, monkeypatch: pytest.MonkeyPatch) -> None:
    agent, graph = _agent()
    called: List[str] = []

    def no_dns(self: OSINTAgent, domain: str) -> Any:
        called.append(domain)
        return ([], [], None)

    monkeypatch.setattr(OSINTAgent, "_resolve_dns_sync", no_dns)
    asyncio.run(agent.investigate_domain_infrastructure(lead, "case:root", 1))
    assert called == []
    assert any(e.action == "DOMAIN_LEAD_REJECTED" for e in graph.logs)


# --- M13: Scrapling must never be used (dead path that would bypass --proxy/--tor) --------------------------------


def test_site_fetch_never_uses_scrapling_and_honours_the_proxy(fake_dns: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    used: List[str] = []

    class FakeFetcher:
        def __init__(self, *a: Any, **k: Any) -> None:
            used.append("init")

        def get(self, *a: Any, **k: Any) -> Any:
            used.append("get")
            return types.SimpleNamespace(html_content="<html>G-SCRAPLING1</html>")

    monkeypatch.setitem(sys.modules, "scrapling", types.SimpleNamespace(Fetcher=FakeFetcher))
    built: List[dict] = []
    real_client = httpx.AsyncClient

    class RecordingClient(real_client):  # type: ignore[misc,valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            built.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(netutil.httpx, "AsyncClient", RecordingClient)
    netutil.set_default_proxy("socks5h://127.0.0.1:9050")
    agent, graph = _agent()
    with respx.mock(assert_all_called=False) as router:
        router.get("https://site.example/").mock(return_value=httpx.Response(200, text="<html>G-HTTPXPATH1</html>"))
        router.get("https://site.example/favicon.ico").mock(return_value=httpx.Response(404))
        asyncio.run(agent._scrape_and_fingerprint_site("site.example", "case:root", 1))
    assert used == []
    assert "tracker:G-HTTPXPATH1" in graph.nodes
    assert built and all(b.get("proxy") == "socks5h://127.0.0.1:9050" for b in built)


def test_osint_module_has_no_scrapling_import() -> None:
    import inspect

    assert "from scrapling" not in inspect.getsource(osint_module)


# --- subprocess reaping ---------------------------------------------------------------------------------------


class _HangingProc:
    def __init__(self) -> None:
        self.returncode: Any = None
        self.killed = False
        self.waited = False

    async def communicate(self) -> Any:
        await asyncio.sleep(3600)

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        self.waited = True
        return -9


def test_communicate_kills_and_reaps_the_child_on_cancellation() -> None:
    proc = _HangingProc()

    async def go() -> None:
        task = asyncio.create_task(_communicate(proc, 60.0))  # type: ignore[arg-type]
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    assert proc.killed and proc.waited


def test_communicate_kills_and_reaps_the_child_on_timeout() -> None:
    proc = _HangingProc()
    assert asyncio.run(_communicate(proc, 0.01)) == b""  # type: ignore[arg-type]
    assert proc.killed and proc.waited


def test_communicate_returns_stdout_and_leaves_a_finished_child_alone() -> None:
    class Done:
        returncode = 0
        killed = False

        async def communicate(self) -> Any:
            return (b"ok", b"")

        def kill(self) -> None:
            self.killed = True

    proc = Done()
    assert asyncio.run(_communicate(proc, 1.0)) == b"ok"  # type: ignore[arg-type]
    assert proc.killed is False
