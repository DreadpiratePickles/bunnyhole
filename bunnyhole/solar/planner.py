"""Approach Planner: turns the solar route graph into a ranked, sequenced Approach Plan.

Scoring is deterministic and explainable - every route's score lists the reasons it earned it, every
assumption is graded (CIA Key Assumptions Check style) and every confirmed route carries the receipt
URL the scout found it at.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import EntityType
from bunnyhole.solar import playbook as pb
from bunnyhole.solar.playbook import CompanyType, Region, RouteCategory
from bunnyhole.solar.targets import prior_heat


@dataclass
class TargetProfile:
    name: str
    slug: str
    domain: Optional[str]
    region: Region
    ctype: CompanyType
    tags: Tuple[str, ...] = ()
    hq_country: str = ""
    parent: str = ""
    note: str = ""
    source: str = "inferred"      # curated | inferred

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["region"] = self.region.value
        d["ctype"] = self.ctype.value
        d["tags"] = list(self.tags)
        return d


_DMU_ORDER = {"CHAMPION": 0, "DECIDER": 1, "APPROVER": 2, "GATEKEEPER": 3, "INFLUENCER": 4}
_COST_BONUS = {"free": 10.0, "low": 7.0, "mid": 3.0, "high": 0.0}
_REGION_LABEL = {
    Region.INDIA: "India", Region.US: "United States", Region.EU: "Europe", Region.MENA: "Middle East & North Africa",
    Region.APAC: "Asia-Pacific", Region.LATAM: "Latin America", Region.AFRICA: "Africa", Region.GLOBAL: "Global",
}


class ApproachPlanner:
    def __init__(self, graph: InvestigationGraph, profile: TargetProfile, news_summary: Optional[Dict[str, Any]] = None, extras: Optional[Dict[str, Any]] = None) -> None:
        self.graph = graph
        self.profile = profile
        self.news = news_summary or {"heat": 0.0, "triggers": {}, "signals": 0, "articles": 0}
        self.extras = extras or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ inputs
    @property
    def triggers(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.news.get("triggers", {}))

    def _route_nodes(self) -> List[Any]:
        prefix = f"route:{self.profile.slug}:"
        return [n for n in self.graph.nodes.values() if n.entity_type == EntityType.CONTACT_ROUTE and n.id.startswith(prefix)]

    def _nodes_of(self, et: EntityType) -> List[Any]:
        return [n for n in self.graph.nodes.values() if n.entity_type == et]

    # ------------------------------------------------------------------ heat
    def heat(self) -> Dict[str, Any]:
        news_heat = float(self.news.get("heat", 0.0))
        prior = 0.5 * prior_heat_from_tags(self.profile.tags)
        jobs = len(self._nodes_of(EntityType.JOB_POSTING))
        filings = len(self._nodes_of(EntityType.FILING))
        tenders = len(self._nodes_of(EntityType.TENDER))
        portal = any("PORTAL_SUBDOMAIN" in n.risk_flags or (n.attributes.get("route_id") == "vendor_registration_portal" and n.attributes.get("status") == "CONFIRMED") for n in self._route_nodes())
        score = news_heat + prior + min(15.0, 5.0 * jobs) + min(20.0, 10.0 * filings) + min(10.0, 2.0 * tenders) + (8.0 if portal else 0.0)
        score = round(min(100.0, score), 1)
        band = "HOT" if score >= 60 else ("WARM" if score >= 35 else "COLD")
        return {
            "score": score, "band": band, "news_heat": round(news_heat, 1), "prior_from_tags": round(prior, 1),
            "job_signals": jobs, "filing_signals": filings, "tender_signals": tenders, "vendor_portal_confirmed": portal,
            "triggers": self.triggers,
        }

    # ------------------------------------------------------------------ route ranking
    def _score_route(self, node: Any) -> Tuple[float, List[str]]:
        a = node.attributes
        route_id = a.get("route_id", "")
        cat = a.get("category", "")
        eff = float(a.get("effectiveness", 2))
        days = int(a.get("days_to_meeting", 60))
        status = a.get("status", "CATALOG")
        reasons: List[str] = []
        score = eff * 14.0
        reasons.append(f"effectiveness {int(eff)}/5")
        cb = _COST_BONUS.get(str(a.get("cost", "mid")), 3.0)
        score += cb
        if cb >= 7:
            reasons.append(f"{a.get('cost')} cost")
        if days <= 7:
            score += 10
            reasons.append("meeting within a week")
        elif days <= 30:
            score += 7
            reasons.append("meeting within a month")
        elif days <= 60:
            score += 3
        if status == "CONFIRMED":
            score += 22
            reasons.append("CONFIRMED live by the scout")
        elif status == "ARCHIVE":
            score += 8
            reasons.append("paths found in the web archive")

        trig = set(self.triggers)
        if "INNOVATION_OPEN" in trig and cat == RouteCategory.PROGRAM.value:
            score += 15
            reasons.append("company signals innovation openness")
        if "COMPETITOR_CLEANING_ADOPTED" in trig and route_id in ("standards_test_reports", "oem_partnerships", "om_contractor_channel", "no_gain_no_fee_pilot"):
            score += 10
            reasons.append("already uses automated cleaning -> differentiate on proof & risk")
        if trig & {"NEW_PLANT_COMMISSIONED", "OM_CONTRACT_CYCLE", "YIELD_SHORTFALL", "WATER_CONSTRAINT", "SOILING_AWARENESS"} and cat in (RouteCategory.DIRECT.value, RouteCategory.GUERRILLA.value):
            score += 8
            reasons.append("hot timing signal favours direct/proof-first routes")
        if "EXEC_CHANGE" in trig and route_id in ("linkedin_personal_outreach", "press_newsroom", "conference_speaker_lists"):
            score += 8
            reasons.append("new executive: 90-day window")
        if "DUSTY_GEOGRAPHY" in trig and route_id in ("free_soiling_audit", "regional_soiling_index", "roi_one_pager"):
            score += 6
            reasons.append("high-soiling geography strengthens the ROI hook")

        tags = set(self.profile.tags)
        if "public_tender" in tags and cat == RouteCategory.TENDER.value:
            score += 18
            reasons.append("public buyer: tender channel is mandatory")
        if "outsourced_om" in tags and route_id == "om_contractor_channel":
            score += 15
            reasons.append("O&M is outsourced: go through the contractor")
        if "listed" in tags and route_id in ("annual_report_ir", "regulatory_filings"):
            score += 8
            reasons.append("listed company: filings name the owners of the issue")
        if "in_house_om" in tags and route_id in ("om_practitioner_events", "solar_asset_management_events", "one_row_demo", "local_om_roundtable"):
            score += 6
            reasons.append("large in-house O&M team: champion sits inside")
        if "robotic_cleaning_adopter" in tags and route_id in ("standards_test_reports", "oem_partnerships"):
            score += 6
            reasons.append("educated buyer expects module-compatibility proof")
        if "innovation_program" in tags and cat == RouteCategory.PROGRAM.value:
            score += 10
            reasons.append("runs a public innovation programme")

        if self.profile.region == Region.INDIA and route_id in ("whatsapp_business_india", "nsefi_india", "local_om_roundtable", "plant_manager_community_india", "mercom_solar_quarter_india_summits", "intersolar_india", "rei_expo_india"):
            score += 6
            reasons.append("India-native route")
        if self.profile.ctype == CompanyType.IE and route_id == "ie_validation":
            score += 20
        if self.profile.ctype == CompanyType.FUND and route_id == "warm_intro_investors":
            score += 15
            reasons.append("target is an investor: portfolio-wide mandate")
        if self.profile.ctype == CompanyType.OEM and route_id == "oem_partnerships":
            score += 15
            reasons.append("target is an OEM: partnership, not procurement")
        if self.profile.ctype in (CompanyType.EPC, CompanyType.OM) and route_id in ("om_contractor_channel", "oem_partnerships"):
            score += 8
            reasons.append("EPC/O&M target: channel and spec-in routes")
        return (round(min(100.0, score), 1), reasons)

    def ranked_routes(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for n in self._route_nodes():
            score, reasons = self._score_route(n)
            a = n.attributes
            route = pb.ROUTES_BY_ID.get(a.get("route_id", ""))
            rows.append({
                "route_id": a.get("route_id", ""), "name": route.name if route else n.label.replace("🚪 ", ""), "category": a.get("category", ""),
                "status": a.get("status", "CATALOG"), "score": score, "reasons": reasons, "cost": a.get("cost", ""), "days_to_meeting": a.get("days_to_meeting", ""),
                "reaches": a.get("reaches", []), "how_to": a.get("how_to", []), "url": a.get("confirmed_url") or (a.get("urls") or [None])[0] or (a.get("linkedin") or [None])[0],
                "mailboxes": a.get("mailboxes", []), "portal_host": a.get("portal_host", ""), "paths": a.get("paths", [])[:8], "legal_note": a.get("legal_note", ""),
                "receipts": [{"url": r.source_url, "sha256": r.sha256_proof[:12], "grade": r.admiralty_code} for r in n.receipts[:2]],
            })
        rows.sort(key=lambda r: (r["score"], r["status"] == "CONFIRMED"), reverse=True)
        return rows

    # ------------------------------------------------------------------ decision unit
    def decision_unit(self) -> List[Dict[str, Any]]:
        confirmed = {n.attributes.get("route_id"): n.attributes for n in self._route_nodes() if n.attributes.get("status") == "CONFIRMED"}
        jobs = self._nodes_of(EntityType.JOB_POSTING)
        out: List[Dict[str, Any]] = []
        for n in self._nodes_of(EntityType.DECISION_ROLE):
            if not n.id.startswith(f"role:{self.profile.slug}:"):
                continue
            a = n.attributes
            evidence: List[str] = []
            if "leadership_page" in confirmed:
                evidence.append(f"Leadership page confirmed: {confirmed['leadership_page'].get('confirmed_url')} - look for titles {a.get('title_patterns', [])[:3]}")
            if "annual_report_ir" in confirmed and a.get("dmu_role") in ("DECIDER", "APPROVER"):
                evidence.append(f"Investor page confirmed: {confirmed['annual_report_ir'].get('confirmed_url')} - management section names this function")
            if jobs and a.get("role_id") in ("head_om", "plant_manager"):
                evidence.append(f"{len(jobs)} O&M/asset openings on public boards - the function is growing (hiring manager = your champion's peer)")
            if a.get("role_id") == "procurement" and "vendor_registration_portal" in confirmed:
                evidence.append(f"Vendor registration portal confirmed: {confirmed['vendor_registration_portal'].get('confirmed_url') or confirmed['vendor_registration_portal'].get('portal_host')}")
            ft = pb.ROUTES_BY_ID.get(a.get("first_touch", ""))
            out.append({
                "role_id": a.get("role_id"), "dmu_role": a.get("dmu_role"), "titles": a.get("title_patterns", [])[:5], "cares_about": a.get("cares_about", []),
                "fears": a.get("fears", []), "pitch_angle": a.get("pitch_angle", ""), "first_touch": ft.name if ft else a.get("first_touch", ""), "evidence": evidence,
            })
        out.sort(key=lambda r: _DMU_ORDER.get(str(r["dmu_role"]), 9))
        return out

    # ------------------------------------------------------------------ sequence
    def sequenced_plan(self) -> List[Dict[str, Any]]:
        ranked = self.ranked_routes()
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for r in ranked:
            by_cat.setdefault(r["category"], []).append(r)

        def pick(cats: List[str], n: int, exclude: Set[str]) -> List[Dict[str, Any]]:
            pool = [r for c in cats for r in by_cat.get(c, []) if r["route_id"] not in exclude]
            pool.sort(key=lambda r: r["score"], reverse=True)
            chosen = pool[:n]
            exclude.update(r["route_id"] for r in chosen)
            return chosen

        used: Set[str] = set()
        prep_ids = {"standards_test_reports", "oem_partnerships", "vendor_registration_portal", "free_soiling_audit", "roi_one_pager", "leadership_page", "annual_report_ir", "regulatory_filings", "public_plant_registries", "gleif_corporate_tree"}
        prep = [r for r in ranked if r["route_id"] in prep_ids][:7]
        used.update(r["route_id"] for r in prep)
        phases = [
            {"phase": "Weeks 0-2: Prepare & identify", "goal": "Know who holds the role, get the compliance and proof pack ready, start vendor registration, write the plant-specific ROI.", "routes": prep},
            {"phase": "Weeks 2-6: Open doors", "goal": "Warm introductions and direct, compliant outreach to the champion and decider; cheapest proof-first tactics.",
             "routes": pick([RouteCategory.WARM_INTRO.value, RouteCategory.DIRECT.value, RouteCategory.MEDIA.value, RouteCategory.GUERRILLA.value], 7, used)},
            {"phase": "Weeks 6-12: Be in the room", "goal": "Events, programmes and associations where the buying unit gathers; apply before deadlines; host your own side-room.",
             "routes": pick([RouteCategory.EVENT.value, RouteCategory.PROGRAM.value, RouteCategory.ASSOCIATION.value, RouteCategory.TENDER.value], 6, used)},
            {"phase": "Months 3-9: Pilot to contract", "goal": "A measured trial with a named economic owner, written success criteria, a fixed window, a price and a conversion clause; independent validation in parallel.",
             "routes": [r for r in ranked if r["route_id"] in ("one_row_demo", "no_gain_no_fee_pilot", "ie_validation", "co_authored_study", "dirtiest_plant_challenge") and r["route_id"] not in used][:5]},
        ]
        return phases

    # ------------------------------------------------------------------ assumptions
    def key_assumptions(self) -> List[Dict[str, str]]:
        p = self.profile
        tags = set(p.tags)
        out: List[Dict[str, str]] = []
        om_frag = "SOLID" if "in_house_om" in tags else ("FRAGILE" if "outsourced_om" in tags else "SUPPORTED")
        out.append({"assumption": "The target's O&M (and therefore cleaning) decisions are made in-house.", "fragility": om_frag,
                    "if_wrong": "Pivot to the O&M contractor channel: the contractor carries cleaning cost and margin; sell to them, reference the owner.",
                    "signal": f"tags={sorted(tags) or 'none'}; confirm from the annual report's O&M section or a plant manager."})
        out.append({"assumption": "The probed domain is the operating renewable-energy company, not only a group holding site.", "fragility": "FRAGILE" if (p.source == "inferred" or p.parent) else "SUPPORTED",
                    "if_wrong": "Routes (leadership, vendor portal) belong to the group; re-run scout on the RE subsidiary's own domain.",
                    "signal": f"profile source={p.source}; parent='{p.parent or '-'}'; domain={p.domain or '-'}"})
        named_ratio = self.extras.get("named_ratio")
        out.append({"assumption": "News-derived buying signals refer to this company and not a namesake.", "fragility": "SUPPORTED" if (named_ratio is None or named_ratio >= 0.5) else "FRAGILE",
                    "if_wrong": "Heat is overstated; open the cited articles before quoting them in outreach.",
                    "signal": f"share of signals naming the company in the headline = {named_ratio if named_ratio is not None else 'n/a'}"})
        out.append({"assumption": f"Region classified as {p.region.value.upper()} ({_REGION_LABEL.get(p.region, '')}) drives the route set.", "fragility": "SUPPORTED" if p.source == "curated" else "FRAGILE",
                    "if_wrong": "Re-run with --region to switch event, association, tender and compliance routes.",
                    "signal": f"hq_country={p.hq_country or 'unknown'}; source={p.source}"})
        out.append({"assumption": "Event dates, programme deadlines and tender boards in the playbook are current.", "fragility": "FRAGILE",
                    "if_wrong": "A missed deadline or a moved event; verify on the organiser site before booking or applying.",
                    "signal": "playbook entries are dated 'verify' where the research could not confirm the next edition"})
        out.append({"assumption": "The buyer will require module-OEM compatibility evidence before any field trial.", "fragility": "SOLID",
                    "if_wrong": "Only an upside: skip ahead to the one-row demo.",
                    "signal": "First Solar requires cleaning-system approval; JinkoSolar bans chemicals/abrasives; tenders ask for PI Berlin-style abrasion tests."})
        return out

    # ------------------------------------------------------------------ outputs
    def regional_notes(self) -> List[str]:
        p = self.profile
        if p.region == Region.INDIA:
            ip = pb.INDIA_PLAYBOOK
            return list(ip["culture_and_norms"])[:5] + list(ip["calendar"])[:3] + list(ip["compliance_checklist"])[:4]
        if p.region == Region.MENA:
            return ["GCC buyers specify cleaning robots at tender stage (ACWA Sudair / Al Shuaibah): get into the EPC spec and the IE's technology review.",
                    "Local-content scoring (IKTVA in KSA, ICV in UAE) affects awards; a local service partner is a scoring item, not just logistics.",
                    "Saudi PDPL requires opt-in consent for direct marketing; use utility supplier portals, MESIA and WFES/MEE as the primary doors."]
        if p.region == Region.US:
            return ["US fleet runs ~8.6% below P50 (kWh Analytics 2025) and IEs often assume only 1-3% soiling: the gap is your pitch to asset managers.",
                    "CAN-SPAM permits B2B cold email with identity, postal address and opt-out; TCPA governs calls/texts to mobiles.",
                    "Solarplaza Summit Asset Management NA (Apr, San Diego) is the densest room; RE+ for scale; SEIA O&M working group for standing."]
        if p.region == Region.EU:
            return ["SolarPower Europe's O&M Task Force and Best Practice Guidelines are the standard owners write into contracts: contribute to them.",
                    "Germany/Austria need prior consent for cold B2B email; most other states accept legitimate interest with identity and opt-out.",
                    "Iberdrola (PERSEO) and Enel (Open Innovability) have run cleaning-specific challenges - the programme door is proven here."]
        return ["Use the ranked routes; re-run with --region for region-specific events, associations and compliance."]

    def compliance_notes(self) -> List[Dict[str, str]]:
        p = self.profile
        want = {Region.INDIA: ("India", "Platform"), Region.US: ("US", "Platform"), Region.EU: ("EU", "UK", "Platform"), Region.MENA: ("GCC", "Platform")}.get(p.region, ("US", "EU", "India", "GCC", "Platform"))
        return [{"jurisdiction": c.jurisdiction, "law": c.law, "rule": c.rule} for c in pb.COMPLIANCE_RULES if c.jurisdiction in want]

    def signals_table(self) -> List[Dict[str, Any]]:
        rows = []
        for n in self._nodes_of(EntityType.BUYING_SIGNAL):
            a = n.attributes
            rows.append({"date": a.get("published_at", ""), "triggers": a.get("triggers", [])[:3], "headline": a.get("headline", ""), "publisher": a.get("publisher", ""),
                         "url": a.get("url", ""), "weight": a.get("weight", 0), "named": a.get("named_in_headline", False), "pitch": a.get("pitch", "")})
        rows.sort(key=lambda r: r["weight"], reverse=True)
        return rows

    def events_and_programs(self) -> Dict[str, List[Dict[str, Any]]]:
        evs = sorted((n.attributes for n in self._nodes_of(EntityType.CONFERENCE)), key=lambda a: a.get("om_density", 0), reverse=True)
        prs = [n.attributes for n in self._nodes_of(EntityType.PROGRAM)]
        orgs = [n.attributes | {"name": n.label.replace("🤝 ", "")} for n in self.graph.nodes.values() if "CATEGORY_WARM_INTRO" in n.risk_flags]
        research = [n.attributes | {"name": n.label.replace("🎓 ", "")} for n in self.graph.nodes.values() if "RESEARCH_PARTNER_CANDIDATE" in n.risk_flags]
        tenders = [n.attributes for n in self._nodes_of(EntityType.TENDER)]
        jobs = [n.attributes for n in self._nodes_of(EntityType.JOB_POSTING)]
        return {"events": evs, "programs": prs, "warm_intro_orgs": orgs, "research_partners": research, "tenders": tenders, "jobs": jobs}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "profile": self.profile.to_dict(),
            "heat": self.heat(),
            "signals": self.signals_table(),
            "decision_unit": self.decision_unit(),
            "ranked_routes": self.ranked_routes(),
            "sequenced_plan": self.sequenced_plan(),
            "regional_notes": self.regional_notes(),
            "compliance": self.compliance_notes(),
            "key_assumptions": self.key_assumptions(),
            **self.events_and_programs(),
        }

    def export_markdown_plan(self) -> str:
        d = self.to_dict()
        p = d["profile"]
        h = d["heat"]
        L: List[str] = [
            f"# ☀️ SOLAR APPROACH PLAN: `{p['name']}`",
            f"**Case:** `{self.graph.case_id}` | **Generated:** `{self.generated_at}` | **Profile:** `{p['ctype'].upper()}` in `{p['region'].upper()}` ({'curated target' if p['source']=='curated' else 'inferred from seed'}) | **Domain:** `{p['domain'] or '-'}`",
            "",
            "> Routes and roles, not people. Every confirmed route carries the URL it was found at. Findings are leads, not verdicts - verify before you act.",
            "",
            "---",
            "",
            f"## 1. Heat: **{h['band']}** ({h['score']}/100)",
            f"- News-derived heat `{h['news_heat']}` + prior from tags `{h['prior_from_tags']}` + hiring signals `{h['job_signals']}` + filings mentioning soiling `{h['filing_signals']}` + tender notices `{h['tender_signals']}`" + (" + **vendor portal confirmed**" if h["vendor_portal_confirmed"] else ""),
        ]
        if h["triggers"]:
            L += ["", "| Trigger | Weight | Evidence | Date | Pitch |", "| :--- | :---: | :--- | :--- | :--- |"]
            for tid, t in sorted(h["triggers"].items(), key=lambda kv: kv[1]["weight"], reverse=True):
                L.append(f"| `{tid}` | {t['weight']} | [{t['headline'][:80]}]({t['url']}) | {t['date'][:16]} | {t['pitch']} |")
        else:
            L.append("- No dated buying signals surfaced in the news sweep; rely on catalog routes and tag priors.")

        L += ["", "---", "", "## 2. Decision-making unit (roles to find, in order)", "", "| DMU | Titles to look for | Cares about | Fears | Pitch angle | First touch |", "| :--- | :--- | :--- | :--- | :--- | :--- |"]
        for r in d["decision_unit"]:
            L.append(f"| **{r['dmu_role']}** | {', '.join(r['titles'][:3])} | {'; '.join(r['cares_about'][:3])} | {'; '.join(r['fears'][:2])} | {r['pitch_angle']} | {r['first_touch']} |")
        ev_lines = [e for r in d["decision_unit"] for e in r["evidence"]]
        if ev_lines:
            L += ["", "**Where the scout found them:**"] + [f"- {e}" for e in dict.fromkeys(ev_lines)]

        L += ["", "---", "", "## 3. Ranked routes (every lawful way in)", "", "| # | Route | Category | Status | Score | Cost | ~Days | First step | Where |", "| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- |"]
        for i, r in enumerate(d["ranked_routes"][:30], 1):
            where = r["url"] or (", ".join(r["mailboxes"][:3]) if r["mailboxes"] else (r["portal_host"] or ""))
            first = (r["how_to"][0] if r["how_to"] else "")[:110]
            L.append(f"| {i} | **{r['name']}** | `{r['category']}` | {'✅ ' + r['status'] if r['status']=='CONFIRMED' else r['status']} | {r['score']} | {r['cost']} | {r['days_to_meeting']} | {first} | {where} |")
        L += ["", "<details><summary>Why each route scored what it did</summary>", ""]
        for r in d["ranked_routes"][:30]:
            L.append(f"- **{r['name']}** ({r['score']}): {'; '.join(r['reasons'])}" + (f" - _{r['legal_note']}_" if r["legal_note"] else ""))
        L += ["", "</details>"]

        L += ["", "---", "", "## 4. Sequenced plan"]
        for ph in d["sequenced_plan"]:
            L += ["", f"### {ph['phase']}", f"_{ph['goal']}_", ""]
            for r in ph["routes"]:
                steps = " ".join(f"({i}) {s}" for i, s in enumerate(r["how_to"][:3], 1))
                L.append(f"- **{r['name']}** [{r['status']}, score {r['score']}]: {steps}" + (f" -> {r['url']}" if r["url"] else ""))

        if d["signals"]:
            L += ["", "---", "", "## 5. Dated buying signals (newest value first)", "", "| Date | Triggers | Headline | Publisher | Named? |", "| :--- | :--- | :--- | :--- | :---: |"]
            for s in d["signals"][:20]:
                L.append(f"| {s['date'][:16]} | {', '.join(s['triggers'])} | [{s['headline'][:90]}]({s['url']}) | {s['publisher']} | {'yes' if s['named'] else 'no'} |")

        ep = d
        if ep["events"]:
            L += ["", "---", "", f"## 6. Where the buying unit gathers ({_REGION_LABEL.get(self.profile.region, '')})", "", "| Event | Next | City | O&M density | Audience |", "| :--- | :--- | :--- | :---: | :--- |"]
            for e in ep["events"][:12]:
                L.append(f"| [{e.get('event_id')}]({e.get('url')}) | {e.get('next_dates') or e.get('month')} | {e.get('city')} | {e.get('om_density')}/5 | {e.get('audience')} |")
        if ep["programs"]:
            L += ["", "**Programme doors (bypass procurement):**"] + [f"- [{pr.get('program_id')}]({pr.get('url')}) - {pr.get('owner')}: {pr.get('note')}" for pr in ep["programs"][:12]]
        if ep["warm_intro_orgs"]:
            L += ["", "**Warm-intro organisations:**"] + [f"- {o['name']} (`{o.get('kind')}`): {o.get('note')}" for o in ep["warm_intro_orgs"][:16]]
        if ep["research_partners"]:
            L += ["", "**Research partners publishing soiling work (credibility route):**"] + [f"- {o['name']} ({o.get('country')}): " + "; ".join(f"[{w['title'][:60]} ({w['year']})]({w['doi']})" for w in o.get("works", [])[:2]) for o in ep["research_partners"][:8]]
        if ep["tenders"]:
            L += ["", "**Public tender notices with cleaning / O&M scope:**"] + [f"- [{t.get('title')[:100]}]({t.get('url')}) ({t.get('board')})" for t in ep["tenders"][:12]]
        if ep["jobs"]:
            L += ["", "**Hiring signals:**"] + [f"- [{j.get('title')}]({j.get('url')}) - {j.get('location')}" for j in ep["jobs"][:10]]

        L += ["", "---", "", "## 7. Regional notes"] + [f"- {n}" for n in d["regional_notes"]]
        L += ["", "## 8. Outreach compliance"] + [f"- **{c['jurisdiction']} - {c['law']}:** {c['rule']}" for c in d["compliance"]]
        L += ["", "## 9. Key assumptions check", "", "| | Fragility | Assumption | If wrong | Signal |", "| :---: | :---: | :--- | :--- | :--- |"]
        icon = {"FRAGILE": "🔴", "SUPPORTED": "🟡", "SOLID": "🟢"}
        for ka in d["key_assumptions"]:
            L.append(f"| {icon.get(ka['fragility'], '🟡')} | `{ka['fragility']}` | {ka['assumption']} | {ka['if_wrong']} | {ka['signal']} |")

        L += ["", "---", "", "## 10. Receipts (confirmed routes & signals)"]
        for r in d["ranked_routes"]:
            if r["status"] in ("CONFIRMED", "ARCHIVE"):
                for rc in r["receipts"][:1]:
                    L.append(f"- `{rc['grade']}` **{r['name']}** - {rc['url']} (sha256 `{rc['sha256']}`)")
        for s in d["signals"][:15]:
            L.append(f"- `C2` **{', '.join(s['triggers'][:2])}** - {s['url']}")
        return "\n".join(L)


def prior_heat_from_tags(tags: Tuple[str, ...]) -> float:
    from bunnyhole.solar.targets import SolarTarget
    return prior_heat(SolarTarget(name="x", domain="x.com", ctype=CompanyType.UNKNOWN, hq_country="", tags=tuple(tags)))
