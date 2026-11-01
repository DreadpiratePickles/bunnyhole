"""Solar BD Orchestrator: one target in, a receipt-backed Approach Plan out (plus a fleet sweep mode)."""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence

from bunnyhole.agents.accountant import AccountantAgent
from bunnyhole.agents.journalist import JournalistAgent
from bunnyhole.agents.osint import OSINTAgent
from bunnyhole.agents.solar_scout import SolarScoutAgent
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, EvidenceReceipt, GearMode, GraphNode, SelectorStrength
from bunnyhole.engine.storage import CaseStore
from bunnyhole.solar.planner import ApproachPlanner, TargetProfile
from bunnyhole.solar.playbook import CompanyType, Region, parse_company_type, parse_region
from bunnyhole.solar.targets import SolarTarget, find_target, prior_heat

_DOMAIN_RE = re.compile(r"^(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:/.*)?$", re.IGNORECASE)
_REGION_QUERY = {
    Region.INDIA: "India", Region.US: "United States", Region.EU: "Europe", Region.MENA: "Middle East desert",
    Region.APAC: "Asia", Region.LATAM: "Chile Atacama", Region.AFRICA: "Africa", Region.GLOBAL: "",
}


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")[:40] or "target"


def resolve_profile(seed: str, region: Optional[str] = None, company_type: Optional[str] = None) -> TargetProfile:
    """Curated target if we know it; otherwise infer name/domain and accept operator hints."""
    seed = (seed or "").strip()
    t = find_target(seed)
    if t is not None:
        prof = TargetProfile(name=t.name, slug=slugify(t.slug), domain=t.domain, region=t.region, ctype=t.ctype, tags=t.tags,
                             hq_country=t.hq_country, parent=t.parent, note=t.note, source="curated")
    else:
        m = _DOMAIN_RE.match(seed)
        if m and " " not in seed:
            domain = m.group(1).lower()
            stem = domain.split(".")[0]
            prof = TargetProfile(name=stem.replace("-", " ").title(), slug=slugify(stem), domain=domain, region=Region.GLOBAL, ctype=CompanyType.UNKNOWN)
        else:
            prof = TargetProfile(name=seed, slug=slugify(seed), domain=None, region=Region.GLOBAL, ctype=CompanyType.UNKNOWN)
    if region:
        prof.region = parse_region(region)
    if company_type:
        prof.ctype = parse_company_type(company_type)
    return prof


class SolarOrchestrator:
    """Runs the Solar Scout alongside Bunnyhole's GLEIF / journalist / OSINT agents and hands the graph to the planner."""

    def __init__(
        self,
        seed: str,
        region: Optional[str] = None,
        company_type: Optional[str] = None,
        gear: GearMode = GearMode.FAST,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        follow_parents: int = 1,
        persist: bool = True,
    ) -> None:
        self.profile = resolve_profile(seed, region, company_type)
        self.gear = gear
        self.follow_parents = max(0, min(3, follow_parents))
        self.persist = persist
        self.graph = InvestigationGraph(
            case_id=f"solar_{uuid.uuid4().hex[:8]}",
            seed_query=self.profile.name,
            hypothesis=f"Best lawful route to sell solar-panel self-cleaning technology to {self.profile.name}",
        )
        if event_callback:
            self.graph.subscribe(event_callback)
        self.scout = SolarScoutAgent(self.graph, gear=gear)
        self.accountant = AccountantAgent(self.graph, gear=gear)
        self.journalist = JournalistAgent(self.graph, gear=gear)
        self.osint = OSINTAgent(self.graph, gear=gear)
        self.case_store = CaseStore() if persist else None
        self.news_summary: Dict[str, Any] = {}
        self.planner: Optional[ApproachPlanner] = None

    # ------------------------------------------------------------------ seed
    def _seed_node(self, profile: TargetProfile, hop_depth: int = 0) -> GraphNode:
        rcpt = EvidenceReceipt(
            tool="bunnyhole_solar_director", domain=DomainCategory.COMMERCIAL, admiralty_code="A1", selector_strength=SelectorStrength.STRONG,
            source_url=f"seed://{profile.slug}", extracted_fact=f"Solar BD target '{profile.name}' profiled as {profile.ctype.value.upper()} in {profile.region.value.upper()} ({profile.source})",
            raw_snippet=f"name={profile.name} | domain={profile.domain} | tags={list(profile.tags)}",
        )
        return self.graph.upsert_node(GraphNode(
            id=f"company:{profile.slug}", label=f"☀️ {profile.name}", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.COMMERCIAL,
            ftm_schema="Organization", smoke_score=30.0 + 0.5 * prior_heat_tags(profile.tags),
            risk_flags=["SOLAR_BD_TARGET"] + [f"TAG_{t.upper()}" for t in profile.tags], attributes=profile.to_dict(), receipts=[rcpt], hop_depth=hop_depth,
        ))

    # ------------------------------------------------------------------ single target
    async def run(self) -> Dict[str, Any]:
        p = self.profile
        root = self._seed_node(p)
        self.graph.explored_seeds.add(f"company:{p.name.lower().strip()}")
        if p.domain:
            self.graph.explored_seeds.add(f"domain:{p.domain.lower()}")
        self.graph.log(DomainCategory.COMMERCIAL, "SOLAR_SCOUT_START", p.name,
                       f"Mapping routes to {p.name} ({p.ctype.value}/{p.region.value}, {p.source}) in {self.gear.value.upper()} gear", level="discovery")

        # Catalog first; live probes upsert the same node ids and promote them to CONFIRMED.
        self.scout.seed_playbook_routes(p.slug, p.region, p.ctype, root.id, hop_depth=1, tags=p.tags)

        tasks: List[Any] = [self._news(p.name, root.id, 1)]
        if p.domain:
            tasks.append(self.scout.investigate_corporate_front_door(p.domain, p.slug, root.id, 1))
            tasks.append(self.scout.investigate_wayback_route_discovery(p.domain, p.slug, root.id, 1))
            tasks.append(self.scout.investigate_public_job_boards(p.domain.split(".")[0], root.id, 1))
        tasks.append(self.scout.investigate_research_partners(_REGION_QUERY.get(p.region, ""), root.id, 1))
        if p.region == Region.US or ("listed" in p.tags and p.region in (Region.US, Region.GLOBAL)):
            tasks.append(self.scout.investigate_edgar_soiling_mentions(p.name, root.id, 1))
        if p.region in (Region.INDIA, Region.EU) and (p.ctype in (CompanyType.UTILITY, CompanyType.EPC, CompanyType.OM) or "public_tender" in p.tags):
            tasks.append(self.scout.scan_tender_boards(p.region, root.id, 1))
        tasks.append(self.accountant.investigate_gleif_corporate_hierarchy(p.name, root.id, 1))
        if self.gear == GearMode.DEEP:
            tasks.append(self.journalist.investigate_news_and_narrative(p.name, root.id, 1))
            tasks.append(self.journalist.investigate_court_dockets(p.name, root.id, 1))
            if p.domain:
                tasks.append(self.osint.investigate_domain_infrastructure(p.domain, root.id, 1))
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.gear == GearMode.DEEP and p.domain:
            self.scout.promote_portal_subdomains(p.slug, root.id, 1)

        # Follow the corporate tree one hop: parent / platform companies get their own signal sweep.
        if self.follow_parents:
            leads = [l for l in self.graph.pop_next_leads(max_hop=2, batch_size=self.follow_parents * 3) if l.lead_type in ("company",)][: self.follow_parents]
            if leads:
                self.graph.log(DomainCategory.COMMERCIAL, "SOLAR_PARENT_SWEEP", p.name, f"Sweeping signals on related entities: {[l.seed_value for l in leads]}")
                await asyncio.gather(*[self.scout.investigate_buying_signals_news(l.seed_value, l.origin_node_id, 2) for l in leads], return_exceptions=True)

        self.planner = ApproachPlanner(self.graph, p, self.news_summary, extras={"named_ratio": self._named_ratio()})
        result = self.graph.to_dict()
        result["solar"] = self.planner.to_dict()
        result["deep_research"] = {"gear": self.gear.value, "max_depth": 2 if self.follow_parents else 1, "initial_breadth": 4, "hypothesis": self.graph.hypothesis, "exclusions": [], "mode": "solar"}
        if self.case_store is not None:
            try:
                self.case_store.save_case(self.graph, result)
            except Exception:
                pass
        return result

    async def _news(self, name: str, origin: str, hop: int) -> None:
        try:
            self.news_summary = await self.scout.investigate_buying_signals_news(name, origin, hop)
        except Exception:
            self.news_summary = {"heat": 0.0, "triggers": {}, "signals": 0, "articles": 0}

    def _named_ratio(self) -> Optional[float]:
        sigs = [n for n in self.graph.nodes.values() if n.entity_type == EntityType.BUYING_SIGNAL]
        if not sigs:
            return None
        return round(sum(1 for n in sigs if n.attributes.get("named_in_headline")) / len(sigs), 2)

    def export_markdown_plan(self) -> str:
        if self.planner is None:
            self.planner = ApproachPlanner(self.graph, self.profile, self.news_summary)
        return self.planner.export_markdown_plan()

    # ------------------------------------------------------------------ fleet sweep
    async def run_sweep(self, targets: Sequence[SolarTarget], front_door: bool = False) -> List[Dict[str, Any]]:
        """Rank many targets by live heat (news signals; optionally front-door probes). Uses this orchestrator's graph."""
        ordered = sorted(targets, key=prior_heat, reverse=True)
        sem = asyncio.Semaphore(4)
        rows: List[Dict[str, Any]] = []

        async def one(t: SolarTarget) -> None:
            prof = TargetProfile(name=t.name, slug=slugify(t.slug), domain=t.domain, region=t.region, ctype=t.ctype, tags=t.tags, hq_country=t.hq_country, parent=t.parent, note=t.note, source="curated")
            node = self._seed_node(prof, hop_depth=1)
            async with sem:
                try:
                    news = await self.scout.investigate_buying_signals_news(t.name, node.id, 1)
                except Exception:
                    news = {"heat": 0.0, "triggers": {}, "signals": 0, "articles": 0}
                fd: Dict[str, Any] = {}
                if front_door and t.domain:
                    try:
                        fd = await self.scout.investigate_corporate_front_door(t.domain, prof.slug, node.id, 1)
                    except Exception:
                        fd = {}
            heat = min(100.0, float(news.get("heat", 0.0)) + 0.5 * prior_heat(t) + (8.0 if "vendor_registration_portal" in (fd.get("confirmed") or {}) else 0.0))
            top = sorted(news.get("triggers", {}).items(), key=lambda kv: kv[1]["weight"], reverse=True)
            rows.append({
                "name": t.name, "domain": t.domain, "type": t.ctype.value, "region": t.region.value, "heat": round(heat, 1),
                "band": "HOT" if heat >= 60 else ("WARM" if heat >= 35 else "COLD"), "prior": prior_heat(t), "news_heat": news.get("heat", 0.0),
                "signals": news.get("signals", 0), "top_triggers": [k for k, _ in top[:3]], "top_headline": (top[0][1]["headline"] if top else ""),
                "top_url": (top[0][1]["url"] if top else ""), "confirmed_routes": sorted((fd.get("confirmed") or {}).keys()), "tags": list(t.tags), "note": t.note,
            })

        await asyncio.gather(*[one(t) for t in ordered], return_exceptions=True)
        rows.sort(key=lambda r: r["heat"], reverse=True)
        return rows


def prior_heat_tags(tags: Sequence[str]) -> float:
    return prior_heat(SolarTarget(name="x", domain="x.com", ctype=CompanyType.UNKNOWN, hq_country="", tags=tuple(tags)))
