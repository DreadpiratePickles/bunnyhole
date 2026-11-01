"""bunnyhole-solar tests: playbook rules, the Solar Scout agent (HTTP mocked with respx), the planner and the CLI."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from bunnyhole.agents import solar_scout as scout_mod
from bunnyhole.agents.solar_scout import SolarScoutAgent
from bunnyhole.cli.main import app
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode, RelationType
from bunnyhole.solar import playbook as pb
from bunnyhole.solar.orchestrator import SolarOrchestrator, resolve_profile
from bunnyhole.solar.planner import ApproachPlanner, TargetProfile
from bunnyhole.solar.targets import TARGET_UNIVERSE, filter_targets, find_target, prior_heat


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """The scout refuses non-public hosts via DNS resolution; tests run offline, so bypass the resolver only."""
    monkeypatch.setattr(scout_mod, "assert_public_url", lambda u: u)
    yield


def _graph_with_root(slug: str = "acme_solar") -> tuple[InvestigationGraph, GraphNode]:
    g = InvestigationGraph("solar_test", "Acme Solar")
    root = g.upsert_node(GraphNode(id=f"company:{slug}", label="☀️ Acme Solar", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.COMMERCIAL))
    return g, root


RSS = """<?xml version="1.0"?><rss><channel>
<item><title>Acme Solar commissions 500 MW at Khavda, deploys waterless robotic cleaning amid water scarcity</title><link>https://news.example/1</link><pubDate>Mon, 06 Oct 2026 08:00:00 GMT</pubDate><source url="https://pv.example">PV Daily</source></item>
<item><title>Acme Solar appoints new Head of O&amp;M</title><link>https://news.example/2</link><pubDate>Tue, 07 Oct 2026 08:00:00 GMT</pubDate><source url="https://m.example">Mercom</source></item>
<item><title>Weather report: sunny week ahead</title><link>https://news.example/3</link><pubDate>Tue, 07 Oct 2026 08:00:00 GMT</pubDate><source url="https://w.example">Weather</source></item>
<item><title>Other Corp launches innovation accelerator for startups</title><link>https://news.example/4</link><pubDate>Tue, 07 Oct 2026 08:00:00 GMT</pubDate><source url="https://o.example">Other</source></item>
</channel></rss>"""

HOME = """<html><head><title>Acme Solar</title></head><body>
<a href="/about/leadership">Leadership</a> <a href="/investors">Investors</a> <a href="/vendor-registration">Vendor Registration</a>
<a href="https://www.linkedin.com/company/acme-solar/">LinkedIn</a>
Contact: info@acme-solar.com | procurement@acme-solar.com | priya.sharma@acme-solar.com
</body></html>"""
LEADERSHIP = "<html><head><title>Leadership | Acme Solar</title></head><body>Chief Executive Officer; Head of Operations &amp; Maintenance; Vice President Asset Management</body></html>"
VENDOR = "<html><head><title>Supplier Registration</title></head><body>Vendor registration portal for suppliers. Email vendor.registration@acme-solar.com</body></html>"
INVESTORS = "<html><head><title>Investors</title></head><body>Annual report 2026, investor presentation, results</body></html>"


# ------------------------------------------------------------------ playbook
def test_buying_signal_classifier_orders_by_weight():
    hits = [t.trigger_id for t in pb.classify_buying_signals("Commissioned 1 GW at Khavda; Ecoppia robots amid water scarcity")]
    assert hits[0] == "COMPETITOR_CLEANING_ADOPTED"
    assert {"WATER_CONSTRAINT", "NEW_PLANT_COMMISSIONED", "DUSTY_GEOGRAPHY"} <= set(hits)
    assert pb.classify_buying_signals("sunny week ahead") == []


@pytest.mark.parametrize("email,ok", [
    ("procurement@x.com", True), ("vendor.registration@x.com", True), ("info@x.com", True), ("media-relations@x.com", True),
    ("investor_relations@x.com", True), ("john.smith@x.com", False), ("rkumar@x.com", False), ("priya.sharma@x.com", False), ("", False),
])
def test_role_mailbox_whitelist_rejects_personal(email, ok):
    assert pb.is_role_mailbox(email) is ok


def test_routes_for_region_and_type_filtering():
    india_ipp = {r.route_id for r in pb.routes_for(pb.Region.INDIA, pb.CompanyType.IPP)}
    us_om = {r.route_id for r in pb.routes_for(pb.Region.US, pb.CompanyType.OM)}
    assert "nsefi_india" in india_ipp and "whatsapp_business_india" in india_ipp
    assert "nsefi_india" not in us_om and "re_plus" in us_om
    assert "seia" not in india_ipp
    # best routes first
    first = pb.routes_for(pb.Region.INDIA, pb.CompanyType.IPP)[0]
    assert first.effectiveness == 5


def test_target_universe_lookup_and_filters():
    assert find_target("adani green").name == "Adani Green Energy"
    assert find_target("renew.com").name == "ReNew"
    assert find_target("ACWA").name == "ACWA Power"
    assert find_target("Definitely Unknown Co") is None
    india = filter_targets(region=pb.Region.INDIA)
    assert all(t.hq_country == "IN" for t in india) and len(india) >= 25
    assert len({t.domain for t in TARGET_UNIVERSE}) >= len(TARGET_UNIVERSE) - 3  # a couple of group domains repeat on purpose
    assert prior_heat(find_target("Adani Green Energy")) > prior_heat(find_target("NHPC"))


def test_resolve_profile_inference_and_overrides():
    p = resolve_profile("https://sunnyco-example.com/about", region="IN", company_type="developer")
    assert p.domain == "sunnyco-example.com" and p.region == pb.Region.INDIA and p.ctype == pb.CompanyType.IPP and p.source == "inferred"
    p2 = resolve_profile("Tata Power Renewable")
    assert p2.source == "curated" and p2.region == pb.Region.INDIA


# ------------------------------------------------------------------ scout: news signals
@respx.mock
def test_news_signals_create_dated_buying_signal_nodes():
    respx.get(url__regex=r"https://news\.google\.com/rss/search.*").mock(return_value=httpx.Response(200, text=RSS))
    g, root = _graph_with_root()
    agent = SolarScoutAgent(g)
    summary = asyncio.run(agent.investigate_buying_signals_news("Acme Solar", root.id, 1))
    sigs = [n for n in g.nodes.values() if n.entity_type == EntityType.BUYING_SIGNAL]
    assert len(sigs) == 3  # weather item has no trigger; 'Other Corp' innovation item is kept but marked SOFT
    assert summary["heat"] > 40
    assert {"COMPETITOR_CLEANING_ADOPTED", "WATER_CONSTRAINT", "EXEC_CHANGE", "INNOVATION_OPEN"} <= set(summary["triggers"])
    unnamed = [n for n in sigs if not n.attributes["named_in_headline"]]
    assert len(unnamed) == 1 and "COMPANY_NOT_IN_HEADLINE" in unnamed[0].risk_flags
    edges = [e for e in g.edges.values() if e.relation == RelationType.HAS_BUYING_SIGNAL]
    assert len(edges) == 3 and all(e.receipts and e.receipts[0].source_url.startswith("https://news.example/") for e in edges)
    assert any(t.anomaly_flag == "COMPETITOR_CLEANING_ADOPTED" for t in g.timeline)


# ------------------------------------------------------------------ scout: front door
@respx.mock
def test_front_door_confirms_routes_and_keeps_only_role_mailboxes():
    respx.get("https://acme-solar.com/about/leadership").mock(return_value=httpx.Response(200, text=LEADERSHIP))
    respx.get("https://acme-solar.com/vendor-registration").mock(return_value=httpx.Response(200, text=VENDOR))
    respx.get("https://acme-solar.com/investors").mock(return_value=httpx.Response(200, text=INVESTORS))
    respx.get(host="acme-solar.com", path="/").mock(return_value=httpx.Response(200, text=HOME))
    respx.get(url__regex=r"https://acme-solar\.com/.*").mock(return_value=httpx.Response(404))
    g, root = _graph_with_root()
    agent = SolarScoutAgent(g)
    res = asyncio.run(agent.investigate_corporate_front_door("acme-solar.com", "acme_solar", root.id, 1))
    assert {"leadership_page", "vendor_registration_portal", "annual_report_ir"} <= set(res["confirmed"])
    assert res["confirmed"]["leadership_page"]["url"] == "https://acme-solar.com/about/leadership"
    assert res["mailboxes"] == ["info@acme-solar.com", "procurement@acme-solar.com", "vendor.registration@acme-solar.com"]
    assert res["discarded_personal"] >= 1
    dumped = json.dumps(g.to_dict())
    assert "priya.sharma" not in dumped, "personal-looking addresses must never be stored"
    lead = g.nodes["route:acme_solar:leadership_page"]
    assert lead.attributes["status"] == "CONFIRMED" and "ROUTE_CONFIRMED_LIVE" in lead.risk_flags
    assert lead.receipts[0].admiralty_code == "B1" and lead.receipts[0].source_url.endswith("/about/leadership")
    li = g.nodes["route:acme_solar:linkedin_company_people"]
    assert li.attributes["linkedin"] == ["https://www.linkedin.com/company/acme-solar/"]


@respx.mock
def test_front_door_probe_is_budgeted_and_refuses_silently_on_failures():
    respx.get(url__regex=r"https://dead-solar\.com.*").mock(side_effect=httpx.ConnectError("boom"))
    g, root = _graph_with_root("dead_solar")
    agent = SolarScoutAgent(g, max_probe_requests=5)
    res = asyncio.run(agent.investigate_corporate_front_door("dead-solar.com", "dead_solar", root.id, 1))
    assert res["confirmed"] == {} and res["mailboxes"] == []
    assert len(respx.calls) <= 5


# ------------------------------------------------------------------ scout: jobs, wayback, research, tenders, playbook seeding
@respx.mock
def test_public_job_boards_only_keep_om_roles():
    respx.get(scout_mod.GREENHOUSE_BOARD.format(slug="acme")).mock(return_value=httpx.Response(200, json={"jobs": [
        {"title": "Plant Manager - Rajasthan", "absolute_url": "https://boards.greenhouse.io/acme/jobs/1", "location": {"name": "Jodhpur"}},
        {"title": "Software Engineer", "absolute_url": "https://boards.greenhouse.io/acme/jobs/2", "location": {"name": "Remote"}},
        {"title": "O&M Engineer (Solar)", "absolute_url": "https://boards.greenhouse.io/acme/jobs/3", "location": {"name": "Bhuj"}},
    ]}))
    respx.get(scout_mod.LEVER_BOARD.format(slug="acme")).mock(return_value=httpx.Response(404))
    g, root = _graph_with_root()
    n = asyncio.run(SolarScoutAgent(g).investigate_public_job_boards("acme", root.id, 1))
    assert n == 2
    jobs = [x for x in g.nodes.values() if x.entity_type == EntityType.JOB_POSTING]
    assert {j.attributes["title"] for j in jobs} == {"Plant Manager - Rajasthan", "O&M Engineer (Solar)"}


@respx.mock
def test_wayback_route_discovery_dedupes_paths():
    rows = [["timestamp", "original", "statuscode"],
            ["20250101000000", "https://acme-solar.com/leadership/", "200"],
            ["20260101000000", "https://acme-solar.com/leadership", "200"],
            ["20240101000000", "https://acme-solar.com/vendor-registration", "200"],
            ["20240101000000", "https://acme-solar.com/blog/post-1", "200"]]
    respx.get(url__regex=r"https://web\.archive\.org/cdx/.*").mock(return_value=httpx.Response(200, json=rows))
    g, root = _graph_with_root()
    paths = asyncio.run(SolarScoutAgent(g).investigate_wayback_route_discovery("acme-solar.com", "acme_solar", root.id, 1))
    assert paths == ["/leadership", "/vendor-registration"]
    node = g.nodes["route:acme_solar:archived_paths"]
    assert node.attributes["paths"][0]["last_seen"] == "20260101"


@respx.mock
def test_research_partner_discovery_via_openalex():
    respx.get(url__regex=r"https://api\.openalex\.org/works.*").mock(return_value=httpx.Response(200, json={"results": [
        {"title": "Soiling losses in Rajasthan", "publication_year": 2026, "doi": "https://doi.org/10.1/abc",
         "authorships": [{"institutions": [{"display_name": "Indian Institute of Technology Bombay", "country_code": "IN"}]}]},
    ]}))
    g, root = _graph_with_root()
    n = asyncio.run(SolarScoutAgent(g).investigate_research_partners("India", root.id, 1))
    assert n == 1
    inst = [x for x in g.nodes.values() if "RESEARCH_PARTNER_CANDIDATE" in x.risk_flags][0]
    assert "Technology Bombay" in inst.label and inst.receipts[0].source_url == "https://doi.org/10.1/abc"


@respx.mock
def test_india_tender_boards_keyword_filter():
    html = '<a href="/tender/1">Operation and Maintenance of 50 MW Solar Plant at Bhadla</a> <a href="/tender/2">Supply of office furniture</a> <a href="/t/3">Robotic module cleaning for 100 MW PV park</a>'
    respx.get(url__regex=r"https://www\.seci\.co\.in/.*").mock(return_value=httpx.Response(200, text=html))
    respx.get(url__regex=r"https://www\.ntpctender\.ntpc\.co\.in/.*").mock(return_value=httpx.Response(500))
    respx.get(url__regex=r"https://eprocure\.gov\.in/.*").mock(side_effect=httpx.ReadTimeout("slow"))
    g, root = _graph_with_root()
    n = asyncio.run(SolarScoutAgent(g).scan_tender_boards(pb.Region.INDIA, root.id, 1))
    assert n == 2
    titles = {x.attributes["title"] for x in g.nodes.values() if x.entity_type == EntityType.TENDER}
    assert titles == {"Operation and Maintenance of 50 MW Solar Plant at Bhadla", "Robotic module cleaning for 100 MW PV park"}


def test_playbook_seeding_then_live_confirmation_merges_same_node():
    g, root = _graph_with_root()
    agent = SolarScoutAgent(g)
    counts = agent.seed_playbook_routes("acme_solar", pb.Region.INDIA, pb.CompanyType.IPP, root.id, 1, tags=("dusty_fleet",))
    assert counts["routes"] >= 40 and counts["roles"] >= 6 and counts["events"] >= 5 and counts["programs"] >= 8
    node = g.nodes["route:acme_solar:leadership_page"]
    assert node.attributes["status"] == "CATALOG"
    with respx.mock:
        respx.get("https://acme-solar.com/about/leadership").mock(return_value=httpx.Response(200, text=LEADERSHIP))
        respx.get(host="acme-solar.com", path="/").mock(return_value=httpx.Response(200, text=HOME))
        respx.get(url__regex=r"https://acme-solar\.com/.*").mock(return_value=httpx.Response(404))
        asyncio.run(agent.investigate_corporate_front_door("acme-solar.com", "acme_solar", root.id, 1))
    node = g.nodes["route:acme_solar:leadership_page"]
    assert node.attributes["status"] == "CONFIRMED" and len(node.receipts) == 2  # catalog receipt + live receipt


def test_portal_subdomain_promotion():
    g, root = _graph_with_root()
    g.upsert_node(GraphNode(id="domain:vendor.acme-solar.com", label="🌐 vendor.acme-solar.com", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT))
    g.upsert_node(GraphNode(id="domain:www.acme-solar.com", label="🌐 www.acme-solar.com", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT))
    n = SolarScoutAgent(g).promote_portal_subdomains("acme_solar", root.id, 1)
    assert n == 1
    assert g.nodes["route:acme_solar:vendor_registration_portal"].attributes["portal_host"] == "vendor.acme-solar.com"


# ------------------------------------------------------------------ planner
def _planned_graph():
    g, root = _graph_with_root()
    agent = SolarScoutAgent(g)
    agent.seed_playbook_routes("acme_solar", pb.Region.INDIA, pb.CompanyType.IPP, root.id, 1, tags=("dusty_fleet", "listed"))
    with respx.mock:
        respx.get(url__regex=r"https://news\.google\.com/rss/search.*").mock(return_value=httpx.Response(200, text=RSS))
        respx.get("https://acme-solar.com/about/leadership").mock(return_value=httpx.Response(200, text=LEADERSHIP))
        respx.get("https://acme-solar.com/vendor-registration").mock(return_value=httpx.Response(200, text=VENDOR))
        respx.get(host="acme-solar.com", path="/").mock(return_value=httpx.Response(200, text=HOME))
        respx.get(url__regex=r"https://acme-solar\.com/.*").mock(return_value=httpx.Response(404))
        news = asyncio.run(agent.investigate_buying_signals_news("Acme Solar", root.id, 1))
        asyncio.run(agent.investigate_corporate_front_door("acme-solar.com", "acme_solar", root.id, 1))
    prof = TargetProfile(name="Acme Solar", slug="acme_solar", domain="acme-solar.com", region=pb.Region.INDIA, ctype=pb.CompanyType.IPP, tags=("dusty_fleet", "listed"), hq_country="IN", source="curated")
    return g, ApproachPlanner(g, prof, news, extras={"named_ratio": 0.67})


def test_planner_ranks_confirmed_routes_and_builds_plan():
    g, planner = _planned_graph()
    d = planner.to_dict()
    assert d["heat"]["band"] in ("WARM", "HOT") and d["heat"]["vendor_portal_confirmed"] is True
    ranked = d["ranked_routes"]
    statuses = {r["route_id"]: r["status"] for r in ranked}
    assert statuses["leadership_page"] == "CONFIRMED" and statuses["vendor_registration_portal"] == "CONFIRMED"
    scores = {r["route_id"]: r["score"] for r in ranked}
    assert scores["vendor_registration_portal"] > scores["seia"] if "seia" in scores else True
    assert scores["leadership_page"] > scores["public_plant_registries"]
    assert any("CONFIRMED live" in x for r in ranked if r["status"] == "CONFIRMED" for x in r["reasons"])
    # innovation signal fired -> programme routes boosted
    prog = next(r for r in ranked if r["category"] == "program")
    assert any("innovation" in x for x in prog["reasons"])
    dmu = d["decision_unit"]
    assert dmu[0]["dmu_role"] == "CHAMPION" and any("Leadership page confirmed" in e for r in dmu for e in r["evidence"])
    phases = d["sequenced_plan"]
    assert len(phases) == 4 and phases[0]["routes"] and phases[3]["routes"]
    all_ids = [r["route_id"] for ph in phases for r in ph["routes"]]
    assert len(all_ids) == len(set(all_ids)), "a route appears in only one phase"
    assert any(k["fragility"] == "FRAGILE" for k in d["key_assumptions"])
    assert d["compliance"][0]["jurisdiction"] == "India"


def test_planner_markdown_export_has_all_sections():
    _, planner = _planned_graph()
    md = planner.export_markdown_plan()
    for marker in ("# ☀️ SOLAR APPROACH PLAN", "## 1. Heat", "## 2. Decision-making unit", "## 3. Ranked routes", "## 4. Sequenced plan", "## 5. Dated buying signals",
                   "## 6. Where the buying unit gathers", "## 7. Regional notes", "## 8. Outreach compliance", "## 9. Key assumptions check", "## 10. Receipts"):
        assert marker in md, marker
    assert "https://acme-solar.com/about/leadership" in md and "COMPETITOR_CLEANING_ADOPTED" in md
    assert "priya.sharma" not in md


# ------------------------------------------------------------------ orchestrator end-to-end (all HTTP mocked)
@respx.mock
def test_orchestrator_end_to_end_offline():
    respx.get(url__regex=r"https://news\.google\.com/rss/search.*").mock(return_value=httpx.Response(200, text=RSS))
    respx.get("https://acme-solar.com/about/leadership").mock(return_value=httpx.Response(200, text=LEADERSHIP))
    respx.get(host="acme-solar.com", path="/").mock(return_value=httpx.Response(200, text=HOME))
    respx.get(url__regex=r"https://acme-solar\.com/.*").mock(return_value=httpx.Response(404))
    respx.route().mock(return_value=httpx.Response(503))  # everything else (GLEIF, wayback, openalex, job boards) fails gracefully
    orch = SolarOrchestrator("https://acme-solar.com", region="india", company_type="ipp", persist=False, follow_parents=0)
    result = asyncio.run(orch.run())
    sol = result["solar"]
    assert sol["profile"]["slug"] == "acme_solar" and sol["profile"]["region"] == "india"
    assert sol["heat"]["score"] > 0 and any(r["status"] == "CONFIRMED" for r in sol["ranked_routes"])
    md = orch.export_markdown_plan()
    assert "Acme Solar" in md and "## 4. Sequenced plan" in md
    assert result["stats"]["total_receipts"] > 50
    json.dumps(result, default=str)  # serialisable


@respx.mock
def test_sweep_ranks_targets_by_heat():
    respx.get(url__regex=r"https://news\.google\.com/rss/search\?q=%22Adani.*").mock(return_value=httpx.Response(200, text=RSS.replace("Acme Solar", "Adani Green")))
    respx.route().mock(return_value=httpx.Response(200, text="<rss><channel></channel></rss>"))
    targets = [find_target("Adani Green Energy"), find_target("NHPC")]
    orch = SolarOrchestrator(targets[0].name, persist=False)
    rows = asyncio.run(orch.run_sweep(targets))
    assert rows[0]["name"] == "Adani Green Energy" and rows[0]["heat"] > rows[1]["heat"]
    assert rows[0]["top_triggers"] and rows[1]["signals"] == 0


# ------------------------------------------------------------------ CLI (offline commands)
runner = CliRunner(env={"COLUMNS": "300"})


def test_cli_solar_routes_targets_roles_playbook():
    r = runner.invoke(app, ["solar", "routes", "--region", "india", "--type", "ipp", "--category", "guerrilla"])
    assert r.exit_code == 0 and "soiling audit" in r.output.lower()
    r = runner.invoke(app, ["solar", "targets", "--region", "india", "--tag", "robotic_cleaning_adopter"])
    assert r.exit_code == 0 and "Adani Green" in r.output
    r = runner.invoke(app, ["solar", "roles", "--type", "epc"])
    assert r.exit_code == 0 and "DECIDER" in r.output
    for section in ("india", "guerrilla", "compliance", "events", "programs", "partners", "triggers"):
        r = runner.invoke(app, ["solar", "playbook", section])
        assert r.exit_code == 0, section
    r = runner.invoke(app, ["solar", "playbook", "nope"])
    assert r.exit_code == 2


def test_new_enums_do_not_break_graph_analytics_or_dossier():
    g, root = _graph_with_root()
    SolarScoutAgent(g).seed_playbook_routes("acme_solar", pb.Region.US, pb.CompanyType.OM, root.id, 1)
    d = g.to_dict()
    assert "commercial" in d["stats"]["domains_covered"]
    assert "BUNNYHOLE INVESTIGATIVE DOSSIER" in g.export_markdown_dossier()
