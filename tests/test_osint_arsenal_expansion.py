"""Tests for the OSINT arsenal expansion: proxy/Tor routing, dark-web (Ahmia) search,
the new keyed entity sources (Censys, SecurityTrails, Hunter, LeakCheck), and the anonsurf
controller. HTTP is mocked with respx; anonsurf is tested with platform/subprocess monkeypatched
so the Linux/root-only paths are exercised on any OS."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from bunnyhole.agents.osint import OSINTAgent
from bunnyhole.arsenal import manager
from bunnyhole.engine import netutil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode, SourceClass, classify_source_class


@pytest.fixture(autouse=True)
def _reset_proxy_state():
    """Keep the module-level proxy defaults from leaking between tests."""
    netutil.set_default_proxy(None)
    netutil.set_tor_proxy(netutil.DEFAULT_TOR_PROXY)
    yield
    netutil.set_default_proxy(None)
    netutil.set_tor_proxy(netutil.DEFAULT_TOR_PROXY)


def _agent_with_origin(origin: GraphNode) -> tuple[OSINTAgent, InvestigationGraph]:
    g = InvestigationGraph("test_case", origin.attributes.get("seed", "seed"))
    g.upsert_node(origin)
    return OSINTAgent(g), g


# --------------------------------------------------------------------------------------
# netutil: proxy validation + routing + onion helpers
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    ["http://host:8080", "https://proxy:443", "socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050"],
)
def test_validate_proxy_url_accepts_supported_schemes(url):
    assert netutil.validate_proxy_url(url) == url


@pytest.mark.parametrize("url", ["ftp://host:21", "socks5://", "not-a-url", ""])
def test_validate_proxy_url_rejects_bad(url):
    with pytest.raises(netutil.InvalidProxyError):
        netutil.validate_proxy_url(url)


def test_default_proxy_roundtrip_and_clear():
    netutil.set_default_proxy("socks5h://127.0.0.1:9050")
    assert netutil.get_default_proxy() == "socks5h://127.0.0.1:9050"
    netutil.set_default_proxy(None)
    assert netutil.get_default_proxy() is None


def test_tor_proxy_override():
    netutil.set_tor_proxy("socks5h://10.0.0.1:9150")
    assert netutil.get_tor_proxy() == "socks5h://10.0.0.1:9150"


def test_new_async_client_builds_client_with_and_without_proxy():
    async def _run():
        netutil.set_default_proxy("socks5h://127.0.0.1:9050")
        c1 = netutil.new_async_client()
        assert isinstance(c1, httpx.AsyncClient)
        await c1.aclose()
        # proxy="" forces a direct client even when a global proxy is set.
        c2 = netutil.new_async_client(proxy="")
        assert isinstance(c2, httpx.AsyncClient)
        await c2.aclose()

    asyncio.run(_run())


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://duskgytldkxiuqc6.onion/path", True),
        ("duskgytldkxiuqc6.onion", True),
        ("example.com", False),
        ("http://example.com", False),
        ("", False),
    ],
)
def test_is_onion_host(value, expected):
    assert netutil.is_onion_host(value) is expected


def test_fetch_onion_rejects_non_onion_without_network():
    # A clearnet host or non-http scheme must short-circuit to None and never egress.
    assert asyncio.run(netutil.fetch_onion("http://example.com/")) is None
    assert asyncio.run(netutil.fetch_onion("ftp://abcdef234567qwer.onion/")) is None


# --------------------------------------------------------------------------------------
# Dark-web search via Ahmia (keyless, clearnet-indexed)
# --------------------------------------------------------------------------------------

def test_search_darkweb_ahmia_parses_onion_results():
    onion_a = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"  # 56-char v3-style
    onion_b = "bcdefg234567bcde"  # 16-char legacy v2-style
    html = (
        f'<li class="result"><h4><a href="http://{onion_a}.onion/leak">Acme dump</a></h4></li>'
        f'<li class="result"><h4><a href="http://{onion_b}.onion/">Mirror</a></h4></li>'
    )
    agent, g = _agent_with_origin(
        GraphNode(id="seed:dw", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT)
    )
    with respx.mock:
        respx.route(host="ahmia.fi").mock(return_value=httpx.Response(200, text=html))
        urls = asyncio.run(agent.search_darkweb_ahmia("acme.io", "seed:dw", 1, fetch_pages=False))

    assert any(onion_a in u for u in urls)
    onion_nodes = [n for n in g.nodes.values() if n.entity_type == EntityType.ONION_SERVICE]
    assert onion_nodes, "expected OnionService nodes to be created"
    # Ahmia hits are keyless public data -> PAI, and low-confidence SOFT leads.
    assert all(r.source_class == SourceClass.PAI for n in onion_nodes for r in n.receipts)


def test_search_darkweb_ahmia_empty_on_no_results():
    agent, g = _agent_with_origin(
        GraphNode(id="seed:dw", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT)
    )
    with respx.mock:
        respx.route(host="ahmia.fi").mock(return_value=httpx.Response(200, text="<p>no results</p>"))
        urls = asyncio.run(agent.search_darkweb_ahmia("acme.io", "seed:dw", 1))
    assert urls == []


# --------------------------------------------------------------------------------------
# Keyed entity sources
# --------------------------------------------------------------------------------------

def test_censys_host_enrichment(monkeypatch):
    monkeypatch.setenv("CENSYS_API_ID", "id")
    monkeypatch.setenv("CENSYS_API_SECRET", "secret")
    origin = GraphNode(id="ip:1.2.3.4", label="1.2.3.4", entity_type=EntityType.IP_HOST, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    body = {
        "result": {
            "services": [{"port": 22, "service_name": "SSH"}, {"port": 443, "service_name": "HTTP"}],
            "autonomous_system": {"asn": 64500, "name": "ACME-AS"},
            "location": {"country": "United States"},
        }
    }
    with respx.mock:
        respx.route(host="search.censys.io").mock(return_value=httpx.Response(200, json=body))
        asyncio.run(agent._scan_censys_host("1.2.3.4", "ip:1.2.3.4", 1))

    node = g.nodes["ip:1.2.3.4"]
    assert node.attributes.get("censys_ports") == [22, 443]
    assert "SENSITIVE_MANAGEMENT_PORTS_OPEN" in node.risk_flags  # port 22 present
    assert any(r.tool == "censys_search_v2_hosts" for r in node.receipts)


def test_censys_skipped_without_keys(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    origin = GraphNode(id="ip:9.9.9.9", label="9.9.9.9", entity_type=EntityType.IP_HOST, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    # No respx routes registered: if it tried to call out, respx would raise. It must no-op.
    with respx.mock:
        asyncio.run(agent._scan_censys_host("9.9.9.9", "ip:9.9.9.9", 1))
    assert "censys_ports" not in g.nodes["ip:9.9.9.9"].attributes


def test_leakcheck_keyless_public_email(monkeypatch):
    monkeypatch.delenv("LEAKCHECK_API_KEY", raising=False)
    origin = GraphNode(id="email:a@acme.io", label="a@acme.io", entity_type=EntityType.EMAIL, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    body = {"success": True, "found": 2, "sources": [{"name": "BreachX"}, {"name": "BreachY"}]}
    with respx.mock:
        respx.route(host="leakcheck.io", path="/api/public").mock(return_value=httpx.Response(200, json=body))
        asyncio.run(agent._scan_leakcheck("a@acme.io", "email", "email:a@acme.io", 1))

    breach = [n for n in g.nodes.values() if n.entity_type == EntityType.BREACH_RECORD]
    assert breach and breach[0].attributes["found"] == 2
    assert "BreachX" in breach[0].attributes["breach_sources"]


def test_leakcheck_domain_requires_key(monkeypatch):
    monkeypatch.delenv("LEAKCHECK_API_KEY", raising=False)
    origin = GraphNode(id="domain:acme.io", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    # Domain lookups have no keyless path: must no-op (no network, no breach node).
    with respx.mock:
        asyncio.run(agent._scan_leakcheck("acme.io", "domain", "domain:acme.io", 1))
    assert not [n for n in g.nodes.values() if n.entity_type == EntityType.BREACH_RECORD]


def test_hunter_footprint(monkeypatch):
    monkeypatch.setenv("HUNTER_API_KEY", "k")
    origin = GraphNode(id="domain:acme.io", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    body = {
        "data": {
            "organization": "Acme LLC",
            "pattern": "{first}.{last}",
            "emails": [
                {"value": "info@acme.io", "type": "generic"},
                {"value": "jane.doe@acme.io", "type": "personal"},
            ],
        }
    }
    with respx.mock:
        respx.route(host="api.hunter.io").mock(return_value=httpx.Response(200, json=body))
        asyncio.run(agent._scan_hunter_footprint("acme.io", "domain:acme.io", 1))

    node = g.nodes["domain:acme.io"]
    assert node.attributes.get("hunter_organization") == "Acme LLC"
    # Only the generic/role mailbox is pivoted; the personal address is not auto-expanded.
    lead_values = {lead.seed_value for lead in g.leads.values()}
    assert "info@acme.io" in lead_values
    assert "jane.doe@acme.io" not in lead_values


def test_securitytrails_historical_ip(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "k")
    origin = GraphNode(id="domain:acme.io", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT)
    agent, g = _agent_with_origin(origin)
    with respx.mock:
        respx.route(host="api.securitytrails.com", path__regex=r".*/subdomains").mock(
            return_value=httpx.Response(200, json={"subdomains": ["dev", "vpn"]})
        )
        respx.route(host="api.securitytrails.com", path__regex=r".*/dns/a").mock(
            return_value=httpx.Response(200, json={"records": [{"values": [{"ip": "203.0.113.5"}]}]})
        )
        asyncio.run(agent._scan_securitytrails("acme.io", "domain:acme.io", 1))

    assert g.nodes["domain:acme.io"].attributes.get("securitytrails_subdomains") == ["dev.acme.io", "vpn.acme.io"]
    assert "ip:203.0.113.5" in g.nodes


# --------------------------------------------------------------------------------------
# PAI/CAI provenance tagging of the new sources
# --------------------------------------------------------------------------------------

def test_source_class_tagging_of_new_tools():
    assert classify_source_class("ahmia_darkweb_search") == SourceClass.PAI
    for cai_tool in ("censys_search_v2_hosts", "leakcheck_breach_feed", "hunter_io_domain_search", "securitytrails_subdomains"):
        assert classify_source_class(cai_tool) == SourceClass.CAI


# --------------------------------------------------------------------------------------
# Arsenal catalog + anonsurf controller
# --------------------------------------------------------------------------------------

def test_catalog_includes_new_tools():
    names = {t["name"] for t in manager.ARSENAL_TOOLS_CATALOG}
    for expected in [
        "phoneinfoga", "spiderfoot", "tookie-osint", "anonsurf",
        "assetfinder", "findomain", "dnsx", "dnsrecon", "tlsx", "katana",
        "mosint", "bbot", "shodan", "censys", "metagoofil", "onionsearch",
    ]:
        assert expected in names, f"{expected} missing from arsenal catalog"


def test_anonsurf_refuses_on_non_linux(monkeypatch):
    monkeypatch.setattr(manager.platform, "system", lambda: "Darwin")
    ctl = manager.AnonsurfController()
    for res in (ctl.start(), ctl.stop(), ctl.install(), ctl.status()):
        assert res["success"] is False
        assert "Linux-only" in res["error"]


def test_anonsurf_status_reports_missing_binary_on_linux(monkeypatch):
    monkeypatch.setattr(manager.platform, "system", lambda: "Linux")
    monkeypatch.setattr(manager.shutil, "which", lambda name, **kw: None)
    ctl = manager.AnonsurfController()
    res = ctl.status()
    assert res["success"] is False
    assert "not installed" in res["error"]


def test_anonsurf_start_runs_sudo_when_available(monkeypatch):
    monkeypatch.setattr(manager.platform, "system", lambda: "Linux")
    monkeypatch.setattr(manager.shutil, "which", lambda name, **kw: f"/usr/bin/{name}")
    monkeypatch.setattr(manager.AnonsurfController, "_is_root", lambda self: False)
    captured = {}

    def _fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(manager.subprocess, "run", _fake_run)
    ctl = manager.AnonsurfController()
    res = ctl.start()
    assert res["success"] is True
    assert captured["cmd"] == ["sudo", "anonsurf", "start"]
