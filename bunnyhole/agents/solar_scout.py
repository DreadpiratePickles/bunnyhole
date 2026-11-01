"""Agent 7: The Solar Scout (bunnyhole-solar).

Maps every lawful public route to a solar company's O&M / asset-management decision-makers and
scores dated buying signals. It is a *route* finder: it records corporate pages, functional
mailboxes, portals, filings, job ads, tenders and research partners - never private individuals'
personal data. Every node carries an EvidenceReceipt with the URL it came from.

Keyless sources: Google News RSS, the company's own website, Wayback CDX, Greenhouse/Lever public
job boards, OpenAlex, SEC EDGAR full-text search, Indian tender boards (SECI/NTPC/CPPP), EU TED.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote_plus, urljoin, urlsplit

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
    TimelineItem,
)
from bunnyhole.engine.netutil import UnsafeHostError, assert_public_url, new_async_client
from bunnyhole.solar import playbook as pb
from bunnyhole.solar.playbook import (
    EVENTS,
    NEWS_QUERY_ANGLES,
    PROGRAMS,
    ROUTE_CATALOG,
    WARM_INTRO_ORGS,
    CompanyType,
    Region,
    Route,
    classify_buying_signals,
    is_role_mailbox,
    roles_for,
    routes_for,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SOCIAL_RE = re.compile(
    r"https?://(?:www\.)?(?:linkedin\.com/company/[A-Za-z0-9_\-./]+|(?:twitter|x)\.com/[A-Za-z0-9_]+|youtube\.com/(?:@|c/|channel/|user/)[A-Za-z0-9_\-]+)",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href=["']([^"'#?]+)["']""", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")

# Job titles that signal O&M / asset-management capacity growth (used only as an org-level signal).
_OM_JOB_RE = re.compile(
    r"o&m|operations? (?:and|&) maintenance|plant (?:manager|head|engineer)|site (?:manager|engineer|in-?charge)|asset (?:manager|management|performance)|"
    r"module cleaning|cleaning supervisor|performance (?:engineer|analyst)|solar (?:operations|maintenance)|cluster head|o and m",
    re.IGNORECASE,
)
_TENDER_KW_RE = re.compile(r"cleaning|o\s*&\s*m|operation\s+and\s+maintenance|robotic|soiling|module\s+wash", re.IGNORECASE)
_WAYBACK_PATH_RE = re.compile(
    r"/(leadership|management|our-team|team|board|investor|supplier|vendor|procurement|tender|career|contact|innovation|sustainability|media|press|newsroom)",
    re.IGNORECASE,
)

# Tender boards the scout sweeps (HTML, best effort; failures are logged and skipped).
INDIA_TENDER_BOARDS: Tuple[Tuple[str, str], ...] = (
    ("SECI Tenders", "https://www.seci.co.in/tenders"),
    ("NTPC Tenders", "https://www.ntpctender.ntpc.co.in/"),
    ("CPPP (eprocure.gov.in) - solar cleaning search", "https://eprocure.gov.in/eprocure/app?page=FrontEndTendersByOrganisation&service=page"),
)
EU_TED_SEARCH = "https://api.ted.europa.eu/v3/notices/search"
EDGAR_FTS = "https://efts.sec.gov/LatestSearch/search-index"
GREENHOUSE_BOARD = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=false"
LEVER_BOARD = "https://api.lever.co/v0/postings/{slug}?mode=json"
OPENALEX_WORKS = "https://api.openalex.org/works?search={q}&per-page=6&sort=publication_year:desc"
WAYBACK_CDX = (
    "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original,statuscode"
    "&filter=statuscode:200&collapse=urlkey&limit=400"
)


def _sha_id(prefix: str, raw: str) -> str:
    return f"{prefix}:{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _strip_html(html: str, limit: int = 200_000) -> str:
    return _TAG_RE.sub(" ", html[:limit])


class SolarScoutAgent:
    """Finds routes, roles, signals and doors into a solar company - from public sources only."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST, max_probe_requests: int = 36) -> None:
        self.graph = graph
        self.gear = gear
        self.max_probe_requests = max_probe_requests
        self.headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BunnyholeSolarScout/0.1; +https://github.com/DreadpiratePickles/bunnyhole)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
        self._sem = asyncio.Semaphore(6)

    # ------------------------------------------------------------------ helpers
    def _log(self, action: str, target: str, detail: str, level: str = "info", receipts: int = 0) -> None:
        self.graph.log(DomainCategory.COMMERCIAL, action, target, detail, receipt_count=receipts, level=level)

    def _receipt(self, tool: str, url: str, fact: str, snippet: str, grade: str = "B2", strength: SelectorStrength = SelectorStrength.STRONG) -> EvidenceReceipt:
        return EvidenceReceipt(
            tool=tool,
            domain=DomainCategory.COMMERCIAL,
            admiralty_code=grade,
            selector_strength=strength,
            source_url=url,
            extracted_fact=fact,
            raw_snippet=snippet[:400],
        )

    def route_node_id(self, slug: str, route_id: str) -> str:
        return f"route:{slug}:{route_id}"

    async def _get(self, client: Any, url: str, *, max_bytes: int = 400_000, method: str = "GET") -> Optional[Any]:
        """Guarded fetch: public hosts only, bounded body, never raises."""
        try:
            assert_public_url(url)
        except UnsafeHostError:
            return None
        except Exception:
            return None
        try:
            async with self._sem:
                resp = await client.request(method, url)
            if resp is not None and len(resp.content or b"") > max_bytes:
                resp._content = resp.content[:max_bytes]  # noqa: SLF001 - bound memory on huge pages
            return resp
        except Exception:
            return None

    # ------------------------------------------------------------------ 1. buying signals from news
    async def investigate_buying_signals_news(self, company: str, origin_node_id: str, hop_depth: int, angles: Sequence[Tuple[str, str]] = NEWS_QUERY_ANGLES) -> Dict[str, Any]:
        """Google News RSS across solar-specific angles -> dated BuyingSignal nodes with trigger classification."""
        self._log("SOLAR_SIGNAL_SWEEP", company, f"Scanning news for O&M, soiling, commissioning, leadership and capital signals around '{company}'")
        seen_links: Set[str] = set()
        signals: List[Dict[str, Any]] = []
        async with new_async_client(timeout=12.0, follow_redirects=True, headers=self.headers) as client:
            for angle, template in angles:
                q = template.format(c=company)
                url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=en-US&gl=US&ceid=US:en"
                resp = await self._get(client, url)
                if resp is None or resp.status_code != 200 or not resp.text:
                    continue
                try:
                    root = ET.fromstring(resp.text)
                except ET.ParseError:
                    continue
                for item in root.findall(".//item")[:12]:
                    title = (item.findtext("title") or "").strip()
                    link = (item.findtext("link") or "").strip()
                    pub = (item.findtext("pubDate") or "").strip()
                    src_el = item.find("source")
                    source = (src_el.text if src_el is not None and src_el.text else "News").strip()
                    if not title or not link or link in seen_links:
                        continue
                    seen_links.add(link)
                    triggers = classify_buying_signals(f"{title} {angle}")
                    # Require the company to actually be named in the headline for a hard match; otherwise SOFT.
                    named = company.lower().split()[0] in title.lower()
                    signals.append({
                        "angle": angle, "title": title, "link": link, "pub_date": pub, "source": source,
                        "triggers": triggers, "named": named,
                    })

        heat = 0.0
        fired: Dict[str, Dict[str, Any]] = {}
        for sig in signals:
            if not sig["triggers"]:
                continue
            top = sig["triggers"][0]
            weight = sum(t.weight for t in sig["triggers"][:2]) * (1.0 if sig["named"] else 0.5)
            sig_id = _sha_id("signal", sig["link"])
            rcpt = self._receipt(
                "google_news_rss + solar_trigger_classifier",
                sig["link"],
                f"{sig['source']} ({sig['pub_date']}): {sig['title']} -> {', '.join(t.trigger_id for t in sig['triggers'][:3])}",
                f"angle={sig['angle']} | title={sig['title']} | triggers={[t.trigger_id for t in sig['triggers']]}",
                grade="C2" if sig["named"] else "C3",
                strength=SelectorStrength.STRONG if sig["named"] else SelectorStrength.SOFT,
            )
            self.graph.upsert_node(GraphNode(
                id=sig_id,
                label=f"📈 {top.trigger_id}: {sig['title'][:60]}",
                entity_type=EntityType.BUYING_SIGNAL,
                domain=DomainCategory.COMMERCIAL,
                selector_strength=rcpt.selector_strength,
                ftm_schema="Event",
                smoke_score=min(95.0, 20.0 + weight),
                risk_flags=[t.trigger_id for t in sig["triggers"][:3]] + ([] if sig["named"] else ["COMPANY_NOT_IN_HEADLINE"]),
                attributes={
                    "headline": sig["title"], "publisher": sig["source"], "published_at": sig["pub_date"], "url": sig["link"],
                    "angle": sig["angle"], "triggers": [t.trigger_id for t in sig["triggers"]], "pitch": top.pitch, "why": top.why,
                    "weight": round(weight, 1), "named_in_headline": sig["named"],
                },
                receipts=[rcpt],
                hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(
                source_id=origin_node_id, target_id=sig_id, relation=RelationType.HAS_BUYING_SIGNAL,
                domain=DomainCategory.COMMERCIAL, admiralty_code=rcpt.admiralty_code,
                confidence=0.8 if sig["named"] else 0.5, summary=f"{top.trigger_id} ({sig['source']})",
                event_date=sig["pub_date"], receipts=[rcpt],
            ))
            self.graph.add_timeline_event(TimelineItem(
                timestamp=sig["pub_date"] or datetime.now(timezone.utc).isoformat(), domain=DomainCategory.COMMERCIAL,
                title=f"Signal {top.trigger_id}: {sig['title'][:70]}", description=top.why, node_ids=[origin_node_id, sig_id],
                source_url=sig["link"], admiralty_code=rcpt.admiralty_code, anomaly_flag=top.trigger_id,
            ))
            heat += weight
            for t in sig["triggers"][:2]:
                if t.trigger_id not in fired or fired[t.trigger_id]["weight"] < weight:
                    fired[t.trigger_id] = {"weight": round(weight, 1), "headline": sig["title"], "url": sig["link"], "date": sig["pub_date"], "pitch": t.pitch}

        if fired:
            self._log("SOLAR_SIGNALS_FOUND", company, f"{len(fired)} trigger types across {sum(1 for s in signals if s['triggers'])} dated articles: {sorted(fired)}", level="discovery", receipts=len(fired))
        return {"articles": len(signals), "signals": len([s for s in signals if s["triggers"]]), "heat": round(min(100.0, heat), 1), "triggers": fired}

    # ------------------------------------------------------------------ 2. corporate front door
    async def investigate_corporate_front_door(self, domain: str, slug: str, origin_node_id: str, hop_depth: int) -> Dict[str, Any]:
        """Probe the company's own site for leadership, investor, newsroom, careers, contact and vendor-registration routes.

        Confirms catalog routes with a live receipt, extracts *functional* mailboxes only (procurement@, media@...)
        and official social-profile links. Personal-looking addresses are discarded, never stored.
        """
        clean = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        base = f"https://{clean}"
        self._log("SOLAR_FRONT_DOOR_PROBE", clean, f"Probing {clean} for leadership / investor / newsroom / careers / contact / vendor-registration routes")
        confirmed: Dict[str, Dict[str, Any]] = {}
        mailboxes: Set[str] = set()
        socials: Set[str] = set()
        discarded_personal = 0
        budget = self.max_probe_requests

        async with new_async_client(timeout=10.0, follow_redirects=True, headers=self.headers) as client:
            home = await self._get(client, base)
            budget -= 1
            home_html = home.text if (home is not None and home.status_code == 200) else ""
            site_links: Set[str] = set()
            if home_html:
                for href in _HREF_RE.findall(home_html):
                    full = urljoin(base + "/", href)
                    if urlsplit(full).netloc.lower().endswith(clean):
                        site_links.add(full)
                for m in _EMAIL_RE.findall(home_html):
                    if is_role_mailbox(m):
                        mailboxes.add(m.lower())
                    else:
                        discarded_personal += 1
                socials.update(x.rstrip("/") + "/" for x in _SOCIAL_RE.findall(home_html))

            # Candidate URLs per route: catalog probe paths + any homepage link whose path matches the route's probe keywords.
            probe_plan: List[Tuple[Route, str]] = []
            for route in ROUTE_CATALOG:
                if not route.probe_paths:
                    continue
                cands: List[str] = [base + p for p in route.probe_paths]
                kw = {p.strip("/").split("/")[-1].split("-")[0] for p in route.probe_paths}
                for link in site_links:
                    path = urlsplit(link).path.lower()
                    if any(k and k in path for k in kw):
                        cands.insert(0, link)
                seen: Set[str] = set()
                for c in cands:
                    if c not in seen:
                        seen.add(c)
                        probe_plan.append((route, c))

            # Budgeted probing: prefer homepage-linked candidates (they come first per route), round-robin across routes.
            per_route: Dict[str, int] = {}
            for route, url in probe_plan:
                if budget <= 0:
                    break
                if route.route_id in confirmed or per_route.get(route.route_id, 0) >= 5:
                    continue
                per_route[route.route_id] = per_route.get(route.route_id, 0) + 1
                resp = await self._get(client, url)
                budget -= 1
                if resp is None or resp.status_code != 200 or not resp.text:
                    continue
                final_url = str(resp.url)
                text_low = _strip_html(resp.text).lower()
                title_m = _TITLE_RE.search(resp.text)
                title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:120] if title_m else ""
                kw_hits = [k for k in route.scan_keywords if k in text_low]
                if route.scan_keywords and not kw_hits:
                    continue
                for m in _EMAIL_RE.findall(resp.text):
                    if is_role_mailbox(m):
                        mailboxes.add(m.lower())
                    else:
                        discarded_personal += 1
                socials.update(x.rstrip("/") + "/" for x in _SOCIAL_RE.findall(resp.text))
                confirmed[route.route_id] = {"url": final_url, "title": title, "keywords": kw_hits[:5]}

        # Persist confirmed routes (same node id the playbook seeding uses, so catalog + live merge).
        for route_id, info in confirmed.items():
            route = pb.ROUTES_BY_ID[route_id]
            rcpt = self._receipt(
                "solar_scout_front_door",
                info["url"],
                f"Live page confirms route '{route.name}' at {info['url']} (title: '{info['title']}'; keywords: {info['keywords']})",
                f"route={route_id} | url={info['url']} | title={info['title']} | kw={info['keywords']}",
                grade="B1",
            )
            self.graph.upsert_node(GraphNode(
                id=self.route_node_id(slug, route_id),
                label=f"🚪 {route.name}",
                entity_type=EntityType.CONTACT_ROUTE,
                domain=DomainCategory.COMMERCIAL,
                selector_strength=SelectorStrength.STRONG,
                ftm_schema="Thing",
                smoke_score=min(95.0, 45.0 + route.effectiveness * 10.0),
                risk_flags=["ROUTE_CONFIRMED_LIVE", f"CATEGORY_{route.category.value.upper()}"],
                attributes={"route_id": route_id, "category": route.category.value, "confirmed_url": info["url"], "page_title": info["title"],
                            "cost": route.cost.value, "days_to_meeting": route.days_to_meeting, "effectiveness": route.effectiveness,
                            "reaches": list(route.reaches), "how_to": list(route.how_to), "status": "CONFIRMED"},
                receipts=[rcpt],
                hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(
                source_id=origin_node_id, target_id=self.route_node_id(slug, route_id), relation=RelationType.REACHABLE_VIA,
                domain=DomainCategory.COMMERCIAL, admiralty_code="B1", confidence=0.92, summary=f"Live: {route.name}", receipts=[rcpt],
            ))

        if mailboxes:
            rcpt = self._receipt("solar_scout_front_door", base, f"Published functional mailboxes on {clean}: {sorted(mailboxes)}", f"mailboxes={sorted(mailboxes)}", grade="B1")
            self.graph.upsert_node(GraphNode(
                id=self.route_node_id(slug, "role_mailboxes"),
                label=f"📮 Role mailboxes ({len(mailboxes)})",
                entity_type=EntityType.CONTACT_ROUTE,
                domain=DomainCategory.COMMERCIAL,
                ftm_schema="Thing",
                smoke_score=55.0,
                risk_flags=["ROUTE_CONFIRMED_LIVE", "CATEGORY_DIRECT"],
                attributes={"route_id": "role_mailboxes", "category": "direct", "mailboxes": sorted(mailboxes), "status": "CONFIRMED",
                            "cost": "free", "days_to_meeting": 7, "effectiveness": 2, "how_to": list(pb.ROUTES_BY_ID["role_mailboxes"].how_to), "reaches": ["procurement", "head_om"]},
                receipts=[rcpt],
                hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(
                source_id=origin_node_id, target_id=self.route_node_id(slug, "role_mailboxes"), relation=RelationType.REACHABLE_VIA,
                domain=DomainCategory.COMMERCIAL, admiralty_code="B1", confidence=0.9, summary="Published role mailboxes", receipts=[rcpt],
            ))
        if socials:
            rcpt = self._receipt("solar_scout_front_door", base, f"Official social profiles linked from {clean}: {sorted(socials)[:5]}", f"socials={sorted(socials)}", grade="B1")
            li = [s for s in socials if "linkedin.com/company" in s.lower()]
            self.graph.upsert_node(GraphNode(
                id=self.route_node_id(slug, "linkedin_company_people"),
                label="🔗 Official LinkedIn company page" if li else "🔗 Official social profiles",
                entity_type=EntityType.CONTACT_ROUTE,
                domain=DomainCategory.COMMERCIAL,
                ftm_schema="Thing",
                smoke_score=60.0 if li else 40.0,
                risk_flags=["ROUTE_CONFIRMED_LIVE", "CATEGORY_IDENTIFY"],
                attributes={"route_id": "linkedin_company_people", "category": "identify", "profiles": sorted(socials), "linkedin": li[:1], "status": "CONFIRMED",
                            "cost": "low", "days_to_meeting": 3, "effectiveness": 4, "how_to": list(pb.ROUTES_BY_ID["linkedin_company_people"].how_to),
                            "reaches": list(pb.ROUTES_BY_ID["linkedin_company_people"].reaches)},
                receipts=[rcpt],
                hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(
                source_id=origin_node_id, target_id=self.route_node_id(slug, "linkedin_company_people"), relation=RelationType.REACHABLE_VIA,
                domain=DomainCategory.COMMERCIAL, admiralty_code="B1", confidence=0.9, summary="Official social profiles", receipts=[rcpt],
            ))

        self._log(
            "SOLAR_FRONT_DOOR_RESULT", clean,
            f"Confirmed {len(confirmed)} routes {sorted(confirmed)}; {len(mailboxes)} role mailboxes; {len(socials)} social profiles; discarded {discarded_personal} personal-looking addresses (never stored)",
            level="discovery" if confirmed else "info", receipts=len(confirmed),
        )
        return {"confirmed": confirmed, "mailboxes": sorted(mailboxes), "socials": sorted(socials), "discarded_personal": discarded_personal}

    # ------------------------------------------------------------------ 3. wayback route discovery
    async def investigate_wayback_route_discovery(self, domain: str, slug: str, origin_node_id: str, hop_depth: int) -> List[str]:
        """Use the Wayback CDX index to discover leadership/vendor/procurement paths the live site hides behind JS or menus."""
        clean = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        url = WAYBACK_CDX.format(domain=clean)
        found: Dict[str, Tuple[str, str]] = {}
        async with new_async_client(timeout=15.0, headers=self.headers) as client:
            resp = await self._get(client, url, max_bytes=2_000_000)
            if resp is None or resp.status_code != 200 or not resp.text.strip():
                return []
            try:
                rows = resp.json()
            except Exception:
                return []
            for row in rows[1:]:
                if len(row) < 3:
                    continue
                ts, orig = row[0], row[1]
                path = urlsplit(orig).path or "/"
                m = _WAYBACK_PATH_RE.search(path)
                if not m:
                    continue
                key = path.lower().rstrip("/")
                if key not in found or ts > found[key][0]:
                    found[key] = (ts, orig)
        if not found:
            return []
        paths = sorted(found.items(), key=lambda kv: kv[1][0], reverse=True)[:15]
        rcpt_url = f"https://web.archive.org/web/*/{clean}/*"
        rcpt = self._receipt("waybackpy_cdx_route_discovery", rcpt_url,
                             f"Wayback CDX exposes {len(paths)} route-like paths on {clean}: {[p for p, _ in paths][:8]}",
                             f"paths={[(p, v[0]) for p, v in paths]}", grade="B2")
        self.graph.upsert_node(GraphNode(
            id=self.route_node_id(slug, "archived_paths"),
            label=f"🕰️ Archived route paths ({len(paths)})",
            entity_type=EntityType.CONTACT_ROUTE,
            domain=DomainCategory.COMMERCIAL,
            ftm_schema="Thing",
            smoke_score=35.0,
            risk_flags=["ROUTE_PATHS_FROM_ARCHIVE", "CATEGORY_IDENTIFY"],
            attributes={"route_id": "archived_paths", "category": "identify", "status": "ARCHIVE",
                        "paths": [{"path": p, "last_seen": v[0][:8], "wayback": f"https://web.archive.org/web/{v[0]}/{v[1]}"} for p, v in paths],
                        "cost": "free", "days_to_meeting": 1, "effectiveness": 2, "reaches": ["head_om", "procurement"],
                        "how_to": ["Open each archived path on the live site (drop the archive prefix); menus often still link them.",
                                   "Leadership and vendor-registration pages discovered here are the fastest first touch."]},
            receipts=[rcpt],
            hop_depth=hop_depth,
        ))
        self.graph.upsert_edge(GraphEdge(
            source_id=origin_node_id, target_id=self.route_node_id(slug, "archived_paths"), relation=RelationType.REACHABLE_VIA,
            domain=DomainCategory.COMMERCIAL, admiralty_code="B2", confidence=0.7, summary="Archive-discovered paths", receipts=[rcpt],
        ))
        self._log("SOLAR_WAYBACK_ROUTES", clean, f"{len(paths)} route-like paths from the archive index", level="discovery", receipts=1)
        return [p for p, _ in paths]

    # ------------------------------------------------------------------ 4. public job boards (org-level signal only)
    async def investigate_public_job_boards(self, slug: str, origin_node_id: str, hop_depth: int) -> int:
        """Greenhouse / Lever public boards: O&M, plant and asset-performance openings as a growth/buying signal."""
        postings: List[Dict[str, str]] = []
        async with new_async_client(timeout=10.0, headers={**self.headers, "Accept": "application/json"}) as client:
            gh = await self._get(client, GREENHOUSE_BOARD.format(slug=slug))
            if gh is not None and gh.status_code == 200:
                try:
                    for j in gh.json().get("jobs", [])[:200]:
                        title = str(j.get("title", ""))
                        if _OM_JOB_RE.search(title):
                            postings.append({"title": title, "url": str(j.get("absolute_url", "")), "location": str((j.get("location") or {}).get("name", "")), "board": "greenhouse"})
                except Exception:
                    pass
            lv = await self._get(client, LEVER_BOARD.format(slug=slug))
            if lv is not None and lv.status_code == 200:
                try:
                    data = lv.json()
                    for j in (data if isinstance(data, list) else [])[:200]:
                        title = str(j.get("text", ""))
                        if _OM_JOB_RE.search(title):
                            postings.append({"title": title, "url": str(j.get("hostedUrl", "")), "location": str((j.get("categories") or {}).get("location", "")), "board": "lever"})
                except Exception:
                    pass
        for p in postings[:12]:
            jid = _sha_id("job", p["url"] or p["title"])
            rcpt = self._receipt(f"{p['board']}_public_job_board", p["url"] or f"https://{p['board']}.io", f"Open role '{p['title']}' ({p['location']}) signals O&M / asset capacity growth", f"title={p['title']} | location={p['location']}", grade="B2")
            self.graph.upsert_node(GraphNode(
                id=jid, label=f"🧑‍🔧 Hiring: {p['title'][:50]}", entity_type=EntityType.JOB_POSTING, domain=DomainCategory.COMMERCIAL,
                ftm_schema="Thing", smoke_score=45.0, risk_flags=["OM_CAPACITY_GROWTH_SIGNAL"],
                attributes={"title": p["title"], "location": p["location"], "url": p["url"], "board": p["board"]}, receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=jid, relation=RelationType.HIRING_FOR, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B2", confidence=0.85, summary=f"Hiring {p['title'][:40]}", receipts=[rcpt]))
        if postings:
            self._log("SOLAR_JOB_SIGNALS", slug, f"{len(postings)} O&M/asset-related openings on public boards", level="discovery", receipts=min(12, len(postings)))
        return len(postings)

    # ------------------------------------------------------------------ 5. research partners (credibility route)
    async def investigate_research_partners(self, region_query: str, origin_node_id: str, hop_depth: int) -> int:
        """OpenAlex: recent soiling studies for the target's region -> institutions to co-author / validate with."""
        q = f"solar photovoltaic soiling {region_query}".strip()
        url = OPENALEX_WORKS.format(q=quote_plus(q))
        insts: Dict[str, Dict[str, Any]] = {}
        async with new_async_client(timeout=12.0, headers=self.headers) as client:
            resp = await self._get(client, url)
            if resp is None or resp.status_code != 200:
                return 0
            try:
                works = resp.json().get("results", [])
            except Exception:
                return 0
            for w in works:
                title = w.get("title") or "Soiling study"
                year = str(w.get("publication_year") or "")
                doi = w.get("doi") or w.get("id") or "https://openalex.org"
                for a in w.get("authorships", [])[:6]:
                    for inst in a.get("institutions", []):
                        name = inst.get("display_name")
                        if not name:
                            continue
                        entry = insts.setdefault(name, {"country": inst.get("country_code", ""), "works": []})
                        if len(entry["works"]) < 3 and (title, year, doi) not in entry["works"]:
                            entry["works"].append((title, year, doi))
        for name, info in list(insts.items())[:8]:
            nid = _sha_id("research_partner", name.lower())
            w0 = info["works"][0]
            rcpt = self._receipt("openalex_scholarly_graph", w0[2], f"{name} ({info['country']}) published soiling research: '{w0[0][:80]}' ({w0[1]})", f"institution={name} | works={info['works']}", grade="B2")
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🎓 {name[:48]}", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.COMMERCIAL, ftm_schema="Organization",
                smoke_score=40.0, risk_flags=["RESEARCH_PARTNER_CANDIDATE", "CATEGORY_CREDIBILITY"],
                attributes={"country": info["country"], "works": [{"title": t, "year": y, "doi": d} for t, y, d in info["works"]], "route_id": "co_authored_study"},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.OPENS_DOOR_VIA, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B2", confidence=0.7, summary=f"Co-author / validation partner: {name[:40]}", receipts=[rcpt]))
        if insts:
            self._log("SOLAR_RESEARCH_PARTNERS", region_query or "global", f"{len(insts)} institutions publishing soiling research: {list(insts)[:5]}", level="discovery", receipts=min(8, len(insts)))
        return len(insts)

    # ------------------------------------------------------------------ 6. SEC EDGAR full-text (US-listed)
    async def investigate_edgar_soiling_mentions(self, company: str, origin_node_id: str, hop_depth: int) -> int:
        """EDGAR full-text search: filings by the company that mention soiling / panel cleaning (the issue is on the record)."""
        q = f'"{company}" (soiling OR "panel cleaning" OR "module cleaning")'
        url = f"{EDGAR_FTS}?q={quote_plus(q)}&forms=10-K,10-Q,8-K,20-F,S-1"
        hits: List[Dict[str, Any]] = []
        async with new_async_client(timeout=12.0, headers={**self.headers, "User-Agent": "BunnyholeSolarScout/0.1 research (open-source; see repository)"}) as client:
            resp = await self._get(client, url)
            if resp is None or resp.status_code != 200:
                return 0
            try:
                for h in resp.json().get("hits", {}).get("hits", [])[:8]:
                    src = h.get("_source", {})
                    names = src.get("display_names") or []
                    if not any(company.lower().split()[0] in str(n).lower() for n in names):
                        continue
                    acc, _, fname = str(h.get("_id", "")).partition(":")
                    ciks = src.get("ciks") or []
                    cik = str(ciks[0]).lstrip("0") if ciks else ""
                    doc_url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc.replace('-', '')}/{fname}" if cik and acc and fname else "https://efts.sec.gov/LatestSearch/"
                    hits.append({"form": src.get("form_type", ""), "date": src.get("file_date", ""), "names": names[:2], "url": doc_url})
            except Exception:
                return 0
        for h in hits:
            fid = _sha_id("filing", h["url"])
            rcpt = self._receipt("sec_edgar_fulltext_search", h["url"], f"{h['names']} {h['form']} filed {h['date']} mentions soiling / panel cleaning", f"form={h['form']} | date={h['date']} | names={h['names']}", grade="A2")
            self.graph.upsert_node(GraphNode(
                id=fid, label=f"📄 {h['form']} ({h['date']}): mentions soiling", entity_type=EntityType.FILING, domain=DomainCategory.COMMERCIAL, ftm_schema="Document",
                smoke_score=50.0, risk_flags=["SOILING_AWARENESS", "ON_THE_RECORD"], attributes=h, receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=fid, relation=RelationType.HAS_BUYING_SIGNAL, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="A2", confidence=0.9, summary=f"Filing mentions soiling ({h['form']})", event_date=h["date"], receipts=[rcpt]))
        if hits:
            self._log("SOLAR_EDGAR_SOILING", company, f"{len(hits)} filings mention soiling / panel cleaning", level="discovery", receipts=len(hits))
        return len(hits)

    # ------------------------------------------------------------------ 7. tender boards
    async def scan_tender_boards(self, region: Region, origin_node_id: str, hop_depth: int) -> int:
        """Sweep public tender boards for cleaning / O&M scopes (India: SECI, NTPC, CPPP; EU: TED API). Best effort."""
        found: List[Dict[str, str]] = []
        async with new_async_client(timeout=15.0, follow_redirects=True, headers=self.headers) as client:
            if region == Region.INDIA:
                for board, url in INDIA_TENDER_BOARDS:
                    resp = await self._get(client, url, max_bytes=1_500_000)
                    if resp is None or resp.status_code != 200 or not resp.text:
                        continue
                    for m in re.finditer(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", resp.text, re.IGNORECASE | re.DOTALL):
                        text = re.sub(r"\s+", " ", _TAG_RE.sub(" ", m.group(2))).strip()
                        if 12 <= len(text) <= 240 and _TENDER_KW_RE.search(text) and re.search(r"solar|pv|mw", text, re.IGNORECASE):
                            found.append({"board": board, "title": text, "url": urljoin(url, m.group(1))})
                        if len(found) >= 25:
                            break
            elif region in (Region.EU,):
                try:
                    assert_public_url(EU_TED_SEARCH)
                    async with self._sem:
                        resp = await client.post(EU_TED_SEARCH, json={"query": "(solar OR photovoltaic) AND (cleaning OR maintenance)", "fields": ["publication-number", "notice-title", "publication-date"], "limit": 15})
                    if resp.status_code == 200:
                        for n in resp.json().get("notices", [])[:15]:
                            title = n.get("notice-title")
                            if isinstance(title, dict):
                                title = title.get("eng") or next(iter(title.values()), "")
                            pub = n.get("publication-number", "")
                            found.append({"board": "EU TED", "title": str(title)[:200], "url": f"https://ted.europa.eu/en/notice/-/detail/{pub}", "date": str(n.get("publication-date", ""))})
                except Exception:
                    pass
        for t in found[:20]:
            tid = _sha_id("tender", t["url"])
            rcpt = self._receipt("public_tender_board", t["url"], f"{t['board']}: '{t['title'][:120]}'", f"board={t['board']} | title={t['title']}", grade="B2")
            self.graph.upsert_node(GraphNode(
                id=tid, label=f"📋 Tender: {t['title'][:56]}", entity_type=EntityType.TENDER, domain=DomainCategory.COMMERCIAL, ftm_schema="Thing",
                smoke_score=50.0, risk_flags=["PUBLIC_CLEANING_OM_SCOPE", "CATEGORY_TENDER"], attributes=t, receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=tid, relation=RelationType.PUBLISHED_TENDER, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B2", confidence=0.75, summary=f"{t['board']} scope", receipts=[rcpt]))
        self._log("SOLAR_TENDER_SWEEP", region.value, f"{len(found)} cleaning/O&M tender notices found on public boards", level="discovery" if found else "info", receipts=min(20, len(found)))
        return len(found)

    # ------------------------------------------------------------------ 8. deterministic playbook seeding
    def seed_playbook_routes(self, slug: str, region: Region, ctype: CompanyType, origin_node_id: str, hop_depth: int, tags: Iterable[str] = ()) -> Dict[str, int]:
        """Attach every applicable catalog route, decision role, event, programme and warm-intro org as CATALOG nodes.

        Live probes upsert the same route ids and promote them to CONFIRMED; the planner ranks both.
        """
        tagset = set(tags)
        counts = {"routes": 0, "roles": 0, "events": 0, "programs": 0, "orgs": 0}
        for route in routes_for(region, ctype):
            nid = self.route_node_id(slug, route.route_id)
            rcpt = self._receipt("solar_playbook", route.urls[0] if route.urls else f"playbook://route/{route.route_id}",
                                 f"Catalog route '{route.name}' applies to a {ctype.value.upper()} in {region.value.upper()} (effectiveness {route.effectiveness}/5, cost {route.cost.value}, ~{route.days_to_meeting}d to a meeting)",
                                 f"route={route.route_id} | how_to={route.how_to[0]}", grade="B3", strength=SelectorStrength.SOFT)
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🚪 {route.name}", entity_type=EntityType.CONTACT_ROUTE, domain=DomainCategory.COMMERCIAL, ftm_schema="Thing",
                selector_strength=SelectorStrength.SOFT, smoke_score=min(60.0, 10.0 + route.effectiveness * 9.0),
                risk_flags=[f"CATEGORY_{route.category.value.upper()}"],
                attributes={"route_id": route.route_id, "category": route.category.value, "cost": route.cost.value, "days_to_meeting": route.days_to_meeting,
                            "effectiveness": route.effectiveness, "reaches": list(route.reaches), "how_to": list(route.how_to), "urls": list(route.urls),
                            "legal_note": route.legal_note, "status": "CATALOG"},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.REACHABLE_VIA, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.55, summary=f"Catalog: {route.name}", receipts=[rcpt]))
            counts["routes"] += 1

        for role in roles_for(ctype):
            nid = f"role:{slug}:{role.role_id}"
            rcpt = self._receipt("solar_playbook", f"playbook://role/{role.role_id}", f"Decision role '{role.role_id}' ({role.dmu_role}) is part of the buying unit for cleaning technology at a {ctype.value.upper()}",
                                 f"titles={role.title_patterns[:4]} | cares={role.cares_about[:3]}", grade="B3", strength=SelectorStrength.SOFT)
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🎯 {role.dmu_role}: {role.title_patterns[0].title()}", entity_type=EntityType.DECISION_ROLE, domain=DomainCategory.COMMERCIAL, ftm_schema="Thing",
                selector_strength=SelectorStrength.SOFT, smoke_score={"DECIDER": 70.0, "CHAMPION": 65.0, "APPROVER": 55.0, "GATEKEEPER": 45.0, "INFLUENCER": 40.0}.get(role.dmu_role, 40.0),
                risk_flags=[f"DMU_{role.dmu_role}"],
                attributes={"role_id": role.role_id, "dmu_role": role.dmu_role, "title_patterns": list(role.title_patterns), "cares_about": list(role.cares_about),
                            "fears": list(role.fears), "pitch_angle": role.pitch_angle, "first_touch": role.first_touch},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.TARGET_ROLE, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.6, summary=f"{role.dmu_role}", receipts=[rcpt]))
            counts["roles"] += 1

        for ev in EVENTS:
            if ev.region not in (region, Region.GLOBAL) and region != Region.GLOBAL:
                continue
            nid = f"event:{ev.event_id}"
            rcpt = self._receipt("solar_playbook", ev.url, f"{ev.name} ({ev.city}, {ev.month}; next: {ev.next_dates or 'verify'}) gathers {ev.audience}", f"event={ev.event_id} | density={ev.om_density}", grade="B3", strength=SelectorStrength.SOFT)
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"📅 {ev.name[:52]}", entity_type=EntityType.CONFERENCE, domain=DomainCategory.COMMERCIAL, ftm_schema="Event",
                selector_strength=SelectorStrength.SOFT, smoke_score=20.0 + ev.om_density * 10.0, risk_flags=["CATEGORY_EVENT"],
                attributes={"event_id": ev.event_id, "city": ev.city, "month": ev.month, "next_dates": ev.next_dates, "audience": ev.audience, "om_density": ev.om_density, "url": ev.url, "region": ev.region.value},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.GATHERS_AT, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.5, summary=f"Likely present: {ev.name[:36]}", receipts=[rcpt]))
            counts["events"] += 1

        for pr in PROGRAMS:
            if pr.region not in (region, Region.GLOBAL) and region != Region.GLOBAL:
                continue
            nid = f"program:{pr.program_id}"
            rcpt = self._receipt("solar_playbook", pr.url, f"{pr.name} ({pr.owner}): {pr.note}", f"program={pr.program_id}", grade="B3", strength=SelectorStrength.SOFT)
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🚀 {pr.name[:52]}", entity_type=EntityType.PROGRAM, domain=DomainCategory.COMMERCIAL, ftm_schema="Thing",
                selector_strength=SelectorStrength.SOFT, smoke_score=50.0, risk_flags=["CATEGORY_PROGRAM"],
                attributes={"program_id": pr.program_id, "owner": pr.owner, "url": pr.url, "note": pr.note, "region": pr.region.value},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.OPENS_DOOR_VIA, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.5, summary=f"Programme door: {pr.name[:36]}", receipts=[rcpt]))
            counts["programs"] += 1

        wanted_kinds = {"investor", "ie", "om_contractor", "oem_tracker", "oem_module", "sensor", "research", "lender"}
        if "outsourced_om" in tagset or ctype in (CompanyType.EPC, CompanyType.OM):
            wanted_kinds.add("om_contractor")
        for org in WARM_INTRO_ORGS:
            if org.kind not in wanted_kinds:
                continue
            if org.region not in (region, Region.GLOBAL) and region != Region.GLOBAL:
                continue
            nid = f"warm_intro:{org.org_id}"
            rcpt = self._receipt("solar_playbook", f"playbook://warm_intro/{org.org_id}", f"{org.name} ({org.kind}): {org.note}", f"org={org.org_id}", grade="B3", strength=SelectorStrength.SOFT)
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🤝 {org.name[:50]}", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.COMMERCIAL, ftm_schema="Organization",
                selector_strength=SelectorStrength.SOFT, smoke_score=35.0, risk_flags=["CATEGORY_WARM_INTRO", f"KIND_{org.kind.upper()}"],
                attributes={"org_id": org.org_id, "kind": org.kind, "note": org.note, "region": org.region.value},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.OPENS_DOOR_VIA, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B3", confidence=0.45, summary=f"Warm intro via {org.kind}", receipts=[rcpt]))
            counts["orgs"] += 1

        self._log("SOLAR_PLAYBOOK_SEEDED", slug, f"Seeded {counts['routes']} catalog routes, {counts['roles']} decision roles, {counts['events']} events, {counts['programs']} programmes, {counts['orgs']} warm-intro orgs for {ctype.value}/{region.value}", level="discovery")
        return counts

    # ------------------------------------------------------------------ 9. subdomain portals (post-process OSINT output)
    def promote_portal_subdomains(self, slug: str, origin_node_id: str, hop_depth: int) -> int:
        """Turn OSINT-discovered subdomains like vendor./supplier./eprocure./careers. into confirmed portal routes."""
        promoted = 0
        for node in list(self.graph.nodes.values()):
            if node.entity_type != EntityType.DOMAIN:
                continue
            host = node.label.lower().replace("🌐", "").strip()
            m = re.match(r"^(vendor|vendors|supplier|suppliers|procurement|eproc\w*|tender\w*|careers?|jobs|partners?|investors?|ir|media|press)\.", host)
            if not m:
                continue
            kind = m.group(1)
            route_id = "vendor_registration_portal" if kind.startswith(("vendor", "supplier", "procure", "eproc", "tender")) else ("job_postings_signal" if kind.startswith(("career", "job")) else ("annual_report_ir" if kind.startswith(("investor", "ir")) else "press_newsroom"))
            url = f"https://{host}"
            rcpt = self._receipt("ct_log_subdomain_portal", url, f"Subdomain '{host}' indicates a dedicated {kind} portal", f"host={host} | via={node.id}", grade="B2")
            nid = self.route_node_id(slug, route_id)
            route = pb.ROUTES_BY_ID[route_id]
            self.graph.upsert_node(GraphNode(
                id=nid, label=f"🚪 {route.name}", entity_type=EntityType.CONTACT_ROUTE, domain=DomainCategory.COMMERCIAL, ftm_schema="Thing",
                smoke_score=70.0, risk_flags=["ROUTE_CONFIRMED_LIVE", "PORTAL_SUBDOMAIN", f"CATEGORY_{route.category.value.upper()}"],
                attributes={"route_id": route_id, "category": route.category.value, "portal_host": host, "status": "CONFIRMED", "cost": route.cost.value,
                            "days_to_meeting": route.days_to_meeting, "effectiveness": route.effectiveness, "reaches": list(route.reaches), "how_to": list(route.how_to)},
                receipts=[rcpt], hop_depth=hop_depth,
            ))
            self.graph.upsert_edge(GraphEdge(source_id=origin_node_id, target_id=nid, relation=RelationType.REACHABLE_VIA, domain=DomainCategory.COMMERCIAL,
                                             admiralty_code="B2", confidence=0.85, summary=f"Portal subdomain {host}", receipts=[rcpt]))
            promoted += 1
        if promoted:
            self._log("SOLAR_PORTAL_SUBDOMAINS", slug, f"Promoted {promoted} portal-like subdomains to confirmed routes", level="discovery", receipts=promoted)
        return promoted
