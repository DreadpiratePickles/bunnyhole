"""Agent 1: The Investigative Journalist (News Trails, Wayback CDX Ghost-Edits, Pink-Slime Syndication, Court Dockets, and PDF/Word RSID Document Forensics)."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urlparse

import httpx
from pypdf import PdfReader

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    ConfidenceTier,
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    Lead,
    RelationType,
    SelectorStrength,
    TimelineItem,
)


def _shingle_set(text: str, k: int = 4) -> Set[Tuple[str, ...]]:
    tokens = re.findall(r"[a-z0-9]{2,}", text.lower())
    if len(tokens) < k:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + k]) for i in range(len(tokens) - k + 1)}


def _jaccard_similarity(s1: Set[Any], s2: Set[Any]) -> float:
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / max(1, len(s1 | s2))


class JournalistAgent:
    """Follows narrative arcs, hunts deleted Wayback pages, detects Pink-Slime PR syndication, checks CourtListener dockets, and runs PDF/DOCX RSID forensics."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) BunnyholeInvestigativeEngine/0.2"
        }

    async def investigate_news_and_narrative(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Pull live news trail, detect narrative laundering cascades, and build chronological timeline."""
        self.graph.log(
            DomainCategory.JOURNALISM,
            "NEWS_TRAIL_SWEEP",
            query,
            f"Querying Google News RSS & narrative syndication patterns for '{query}'",
        )
        rss_url = f"https://news.google.com/rss/search?q={quote_plus(query)}&hl=en-US&gl=US&ceid=US:en"
        articles: List[Dict[str, str]] = []
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=self.headers) as client:
                resp = await client.get(rss_url)
                if resp.status_code == 200 and resp.text:
                    root = ET.fromstring(resp.text)
                    for item in root.findall(".//item")[:14]:
                        title = (item.findtext("title") or "").strip()
                        link = (item.findtext("link") or "").strip()
                        pub_date = (item.findtext("pubDate") or "").strip()
                        source_el = item.find("source")
                        source_name = (source_el.text if source_el is not None and source_el.text else "News Outlet").strip()
                        if title and link:
                            articles.append({
                                "title": title,
                                "link": link,
                                "pub_date": pub_date,
                                "source": source_name,
                            })
        except Exception as exc:
            self.graph.log(
                DomainCategory.JOURNALISM,
                "NEWS_RSS_WARN",
                query,
                f"RSS lookup warning: {exc}",
                level="warning",
            )

        if not articles:
            return

        # Check for Narrative Laundering / "Pink Slime" Syndication (high 4-gram overlap across distinct outlets)
        shingled = [(a, _shingle_set(re.sub(r"\s+-\s+[^-]+$", "", a["title"]))) for a in articles]
        syndicated_pairs: List[Tuple[str, str, float]] = []
        for i in range(len(shingled)):
            for j in range(i + 1, len(shingled)):
                a1, sh1 = shingled[i]
                a2, sh2 = shingled[j]
                if a1["source"].lower() != a2["source"].lower():
                    sim = _jaccard_similarity(sh1, sh2)
                    if sim >= 0.55:
                        syndicated_pairs.append((a1["source"], a2["source"], sim))

        for idx, art in enumerate(articles[:8]):
            # Stable, process-independent id keyed on the URL so the same article dedupes across
            # queries and runs (Python's built-in hash() is salted per process).
            art_id = f"article:{hashlib.sha1(str(art.get('link', '')).encode('utf-8')).hexdigest()[:12]}"
            rcpt = EvidenceReceipt(
                tool="google_news_rss + shingling_detector",
                domain=DomainCategory.JOURNALISM,
                admiralty_code="C2",
                selector_strength=SelectorStrength.SOFT,
                source_url=art["link"],
                extracted_fact=f"Published by {art['source']} ({art['pub_date']}): {art['title']}",
                raw_snippet=f"Title: {art['title']} | Source: {art['source']} | Date: {art['pub_date']}",
            )
            risk_flags: List[str] = []
            smoke = 25.0
            title_low = art["title"].lower()
            for kw, flag, boost in [
                ("sec ", "REGULATORY_SCRUTINY", 30.0),
                ("subpoena", "SUBPOENA_REPORTED", 35.0),
                ("fraud", "FRAUD_ALLEGATION", 40.0),
                ("hack", "EXPLOIT_OR_BREACH", 35.0),
                ("exploit", "EXPLOIT_OR_BREACH", 35.0),
                ("lawsuit", "LITIGATION_MENTION", 25.0),
                ("bankrupt", "INSOLVENCY_SIGNAL", 35.0),
                ("resign", "EXECUTIVE_TURNOVER", 25.0),
                ("sanction", "SANCTIONS_MENTION", 45.0),
                ("short seller", "SHORT_REPORT_TARGET", 35.0),
                ("hindenburg", "SHORT_REPORT_TARGET", 40.0),
            ]:
                if kw in title_low and flag not in risk_flags:
                    risk_flags.append(flag)
                    smoke = min(95.0, smoke + boost)

            if syndicated_pairs and any(art["source"] in (p[0], p[1]) for p in syndicated_pairs):
                risk_flags.append("NARRATIVE_SYNDICATION_CLUSTER")
                smoke = min(95.0, smoke + 20.0)

            node = GraphNode(
                id=art_id,
                label=f"📰 {art['source']}: {art['title'][:58]}...",
                entity_type=EntityType.NEWS_ARTICLE,
                domain=DomainCategory.JOURNALISM,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema="Document",
                smoke_score=smoke,
                risk_flags=risk_flags,
                attributes={
                    "full_title": art["title"],
                    "publisher": art["source"],
                    "published_at": art["pub_date"],
                    "url": art["link"],
                },
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
            self.graph.upsert_node(node)
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=art_id,
                    relation=RelationType.MENTIONED_IN,
                    domain=DomainCategory.JOURNALISM,
                    admiralty_code="C2",
                    confidence=0.82,
                    summary=f"Covered by {art['source']}",
                    event_date=art["pub_date"],
                    receipts=[rcpt],
                )
            )
            self.graph.add_timeline_event(
                TimelineItem(
                    timestamp=art["pub_date"] or datetime.now(timezone.utc).isoformat(),
                    domain=DomainCategory.JOURNALISM,
                    title=f"News ({art['source']}): {art['title'][:75]}",
                    description=art["title"],
                    node_ids=[origin_node_id, art_id],
                    source_url=art["link"],
                    admiralty_code="C2",
                    anomaly_flag=risk_flags[0] if risk_flags else None,
                )
            )

        if syndicated_pairs:
            p0, p1, sim = syndicated_pairs[0]
            self.graph.log(
                DomainCategory.JOURNALISM,
                "NARRATIVE_LAUNDERING_ALERT",
                query,
                f"Detected {sim*100:.0f}% 4-gram headline syndication overlap between '{p0}' and '{p1}' (potential PR wire or Pink-Slime cascade)",
                receipt_count=1,
                level="anomaly",
            )

    async def investigate_wayback_ghost_edits(self, domain: str, origin_node_id: str, hop_depth: int) -> None:
        """Query Wayback Machine CDX Server API with collapse=digest to spot scrubbed /team, /about, and historical snapshots."""
        clean_domain = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        self.graph.log(
            DomainCategory.JOURNALISM,
            "WAYBACK_CDX_GHOST_HUNT",
            clean_domain,
            f"Scanning Internet Archive CDX digest history for '{clean_domain}' (/team, /about, /legal, root)",
        )
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url={clean_domain}/*&output=json"
            f"&fl=timestamp,original,statuscode,digest,length&filter=statuscode:200&collapse=digest&limit=60"
        )
        try:
            async with httpx.AsyncClient(timeout=12.0, headers=self.headers) as client:
                resp = await client.get(cdx_url)
                if resp.status_code != 200 or not resp.text.strip():
                    return
                rows = resp.json()
                if len(rows) <= 1:
                    return
                entries = rows[1:]
                high_value_paths = [
                    r for r in entries
                    if any(k in r[1].lower() for k in ("/team", "/about", "/leadership", "/founder", "/terms", "/privacy", "/whitepaper", "/docs"))
                ]
                selected = (high_value_paths or entries)[:5]
                for row in selected:
                    ts, orig_url, _status, digest, length = row[0], row[1], row[2], row[3], row[4]
                    iso_date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z" if len(ts) >= 14 else ts
                    wb_link = f"https://web.archive.org/web/{ts}/{orig_url}"
                    rcpt = EvidenceReceipt(
                        tool="waybackpy_cdx_digest",
                        domain=DomainCategory.JOURNALISM,
                        admiralty_code="B1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=wb_link,
                        archive_url=wb_link,
                        extracted_fact=f"Historical snapshot of {orig_url} captured on {iso_date} (SHA-1 digest: {digest[:12]}..., size: {length}B)",
                        raw_snippet=f"CDX Row: timestamp={ts} url={orig_url} digest={digest} length={length}",
                    )
                    snap_id = f"archive:{clean_domain}:{ts}"
                    is_sensitive_path = any(k in orig_url.lower() for k in ("/team", "/about", "/leadership", "/founder"))
                    node = GraphNode(
                        id=snap_id,
                        label=f"🕰️ Wayback ({ts[:8]}): {urlparse(orig_url).path or '/'}",
                        entity_type=EntityType.EVENT,
                        domain=DomainCategory.JOURNALISM,
                        selector_strength=SelectorStrength.STRONG,
                        ftm_schema="Event",
                        smoke_score=55.0 if is_sensitive_path else 30.0,
                        risk_flags=["HISTORICAL_TEAM_OR_ABOUT_SNAPSHOT"] if is_sensitive_path else [],
                        attributes={
                            "timestamp": iso_date,
                            "original_url": orig_url,
                            "wayback_url": wb_link,
                            "sha1_digest": digest,
                            "byte_length": length,
                        },
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                    self.graph.upsert_node(node)
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=snap_id,
                            relation=RelationType.ARCHIVED_AT,
                            domain=DomainCategory.JOURNALISM,
                            admiralty_code="B1",
                            confidence=0.95,
                            summary=f"CDX Digest {digest[:8]} ({ts[:8]})",
                            event_date=iso_date,
                            receipts=[rcpt],
                        )
                    )
                    self.graph.add_timeline_event(
                        TimelineItem(
                            timestamp=iso_date,
                            domain=DomainCategory.JOURNALISM,
                            title=f"Wayback Snapshot: {orig_url}",
                            description=f"Unique content digest {digest[:10]} captured ({length} bytes)",
                            node_ids=[origin_node_id, snap_id],
                            source_url=wb_link,
                            admiralty_code="B1",
                            anomaly_flag="GHOST_EDIT_CANDIDATE" if is_sensitive_path else None,
                        )
                    )
        except Exception as exc:
            self.graph.log(
                DomainCategory.JOURNALISM,
                "WAYBACK_CDX_INFO",
                clean_domain,
                f"Wayback CDX query completed ({exc})",
            )

    async def investigate_court_dockets(self, entity_name: str, origin_node_id: str, hop_depth: int) -> None:
        """Query CourtListener / RECAP federal litigation archive for lawsuits, bankruptcies & enforcement actions."""
        self.graph.log(
            DomainCategory.JOURNALISM,
            "COURTLISTENER_RECAP_SEARCH",
            entity_name,
            f"Searching Federal Court Dockets (RECAP) for '{entity_name}'",
        )
        url = f"https://www.courtlistener.com/api/rest/v4/search/?q={quote_plus(entity_name)}&type=r"
        try:
            async with httpx.AsyncClient(timeout=12.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                data = resp.json()
                results = data.get("results", [])[:5]
                for item in results:
                    case_name = item.get("caseName") or item.get("case_name") or "Federal Docket"
                    docket_num = item.get("docketNumber") or item.get("docket_number") or "N/A"
                    court = item.get("court") or item.get("court_id") or "U.S. District/Bankruptcy Court"
                    date_filed = item.get("dateFiled") or item.get("date_filed") or ""
                    abs_url = "https://www.courtlistener.com" + (item.get("absolute_url") or "")
                    suit_nature = item.get("suitNature") or item.get("nature_of_suit") or ""

                    case_id = f"docket:{docket_num.lower().replace(' ', '_')}_{hashlib.sha1(case_name.encode('utf-8')).hexdigest()[:8]}"
                    rcpt = EvidenceReceipt(
                        tool="courtlistener_recap_v4",
                        domain=DomainCategory.JOURNALISM,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=abs_url,
                        extracted_fact=f"Federal Case '{case_name}' (Docket {docket_num}, {court}) filed {date_filed}. Nature: {suit_nature}",
                        raw_snippet=f"caseName={case_name} | docketNumber={docket_num} | court={court} | dateFiled={date_filed} | suitNature={suit_nature}",
                    )
                    flags = ["FEDERAL_LITIGATION_RECORD"]
                    smoke = 62.0
                    if any(w in (case_name + " " + suit_nature).lower() for w in ("sec ", "securities", "fraud", "bankrupt", "criminal", "united states v", "ftc", "cftc")):
                        flags.append("REGULATORY_OR_FRAUD_DOCKET")
                        smoke = 85.0

                    node = GraphNode(
                        id=case_id,
                        label=f"⚖️ {case_name[:52]} ({docket_num})",
                        entity_type=EntityType.LEGAL_CASE,
                        domain=DomainCategory.JOURNALISM,
                        selector_strength=SelectorStrength.STRONG,
                        ftm_schema="CourtCase",
                        smoke_score=smoke,
                        risk_flags=flags,
                        attributes={
                            "case_name": case_name,
                            "docket_number": docket_num,
                            "court": court,
                            "date_filed": date_filed,
                            "nature_of_suit": suit_nature,
                            "url": abs_url,
                        },
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                    self.graph.upsert_node(node)
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=case_id,
                            relation=RelationType.LITIGATED_IN,
                            domain=DomainCategory.JOURNALISM,
                            admiralty_code="A1",
                            confidence=0.92,
                            summary=f"Docket {docket_num} ({date_filed})",
                            event_date=date_filed,
                            receipts=[rcpt],
                        )
                    )
                    if date_filed:
                        self.graph.add_timeline_event(
                            TimelineItem(
                                timestamp=date_filed,
                                domain=DomainCategory.JOURNALISM,
                                title=f"Federal Lawsuit Filed: {case_name[:65]}",
                                description=f"Docket {docket_num} in {court} ({suit_nature})",
                                node_ids=[origin_node_id, case_id],
                                source_url=abs_url,
                                admiralty_code="A1",
                                anomaly_flag=flags[-1],
                            )
                        )
        except Exception as exc:
            self.graph.log(
                DomainCategory.JOURNALISM,
                "COURTLISTENER_INFO",
                entity_name,
                f"CourtListener query note: {exc}",
            )

    async def investigate_wikipedia_revisions(self, title_query: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Inspect Wikipedia revision history via MediaWiki API to catch:
        1. Large deletions ('Controversies'/'Lawsuits' whitewashing)
        2. Anonymous IP editors (piping discovered IPs to Shodan InternetDB & RIPEstat as OSINT leads!).
        """
        self.graph.log(
            DomainCategory.JOURNALISM,
            "WIKIPEDIA_SOCKPUPPET_SCAN",
            title_query,
            f"Inspecting Wikipedia revision history & anonymous IP edits for '{title_query}'",
        )
        api_url = (
            f"https://en.wikipedia.org/w/api.php?action=query&prop=revisions"
            f"&titles={quote_plus(title_query)}&rvlimit=30&rvprop=ids|timestamp|user|userid|size|comment&format=json"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=self.headers) as client:
                resp = await client.get(api_url)
                if resp.status_code != 200:
                    return
                pages = resp.json().get("query", {}).get("pages", {})
                for page_id, page_data in pages.items():
                    if str(page_id) == "-1":
                        continue
                    revs = page_data.get("revisions", [])
                    anon_ips: List[str] = []
                    whitewash_edits: List[Dict[str, Any]] = []
                    prev_size = None
                    # MediaWiki returns revisions newest-first; walk oldest-first so prev_size is the
                    # earlier revision. A removal is then (prev_size - size) > 0 and is correctly
                    # attributed to `user`, the editor who authored the shrinking revision.
                    for rev in reversed(revs):
                        user = rev.get("user", "")
                        userid = rev.get("userid", 1)
                        comment = rev.get("comment", "")
                        size = rev.get("size", 0)
                        ts = rev.get("timestamp", "")
                        # userid == 0 or IP pattern indicates an unlogged IP edit!
                        if userid == 0 or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user):
                            if user not in anon_ips:
                                anon_ips.append(user)
                        if prev_size is not None and (prev_size - size) > 600:
                            whitewash_edits.append({"user": user, "timestamp": ts, "bytes_removed": prev_size - size, "comment": comment})
                        prev_size = size

                    if revs:
                        wiki_url = f"https://en.wikipedia.org/w/index.php?title={quote_plus(title_query)}&action=history"
                        rcpt = EvidenceReceipt(
                            tool="mediawiki_revision_forensics",
                            domain=DomainCategory.JOURNALISM,
                            admiralty_code="B1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=wiki_url,
                            extracted_fact=f"Wikipedia '{title_query}' revision analysis: {len(revs)} recent edits, {len(anon_ips)} anonymous IP editors ({anon_ips[:3]}), {len(whitewash_edits)} large deletion events",
                            raw_snippet=f"anon_ips={anon_ips[:5]} | whitewash_events={whitewash_edits[:2]}",
                        )
                        wiki_id = f"wiki:{re.sub(r'[^a-z0-9]+', '_', title_query.lower())}"
                        flags = ["WIKIPEDIA_REVISION_ANALYZED"]
                        if anon_ips:
                            flags.append("WIKIPEDIA_ANON_IP_EDITORS_EXPOSED")
                        if whitewash_edits:
                            flags.append("WIKIPEDIA_LARGE_DELETION_WHITEWASH_CANDIDATE")

                        self.graph.upsert_node(
                            GraphNode(
                                id=wiki_id,
                                label=f"🌐 Wiki History: {title_query} ({len(anon_ips)} IP leaks)",
                                entity_type=EntityType.DOCUMENT,
                                domain=DomainCategory.JOURNALISM,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=65.0 if (anon_ips or whitewash_edits) else 25.0,
                                risk_flags=flags,
                                attributes={"anon_ips": anon_ips[:8], "whitewash_edits": whitewash_edits[:5]},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=wiki_id,
                                relation=RelationType.MENTIONED_IN,
                                domain=DomainCategory.JOURNALISM,
                                admiralty_code="B1",
                                confidence=0.90,
                                summary=f"{len(anon_ips)} Anon IPs / {len(whitewash_edits)} Deletions",
                                receipts=[rcpt],
                            )
                        )
                        # Inject discovered anonymous Wikipedia editor IPs straight into OSINT Agent (Shodan InternetDB + RIPEstat)!
                        for ip in anon_ips[:2]:
                            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                                self.graph.add_lead(
                                    Lead(
                                        seed_value=ip,
                                        lead_type="ip",
                                        selector_strength=SelectorStrength.STRONG,
                                        target_agent=DomainCategory.OSINT,
                                        priority_score=74.0,
                                        reason=f"Anonymous IP '{ip}' edited Wikipedia article '{title_query}' -> Trace via Shodan InternetDB & RIPEstat",
                                        origin_node_id=wiki_id,
                                        hop_depth=hop_depth + 1,
                                    )
                                )
        except Exception:
            pass

    async def investigate_openalex_academic_and_grants(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Query OpenAlex API (250M+ scholarly works, authors, institutions & funding grants) for deep-tech/biotech/founder verification."""
        url = f"https://api.openalex.org/works?search={quote_plus(query)}&per-page=3"
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                works = resp.json().get("results", [])[:2]
                for w in works:
                    title = w.get("title") or "Scholarly Publication"
                    pub_year = str(w.get("publication_year") or "")
                    doi = w.get("doi") or w.get("id") or ""
                    grants = w.get("grants", [])
                    authorships = w.get("authorships", [])
                    institutions: List[str] = []
                    authors: List[str] = []
                    for a in authorships[:5]:
                        au_name = a.get("author", {}).get("display_name")
                        if au_name:
                            authors.append(au_name)
                        for inst in a.get("institutions", []):
                            iname = inst.get("display_name")
                            if iname and iname not in institutions:
                                institutions.append(iname)

                    q_low = query.lower().strip()
                    exact_author_or_inst = any(q_low in au.lower() for au in authors) or any(q_low in inst.lower() for inst in institutions)
                    sel_strength = SelectorStrength.STRONG if exact_author_or_inst else SelectorStrength.SOFT
                    edge_tier = ConfidenceTier.VERIFIED if exact_author_or_inst else ConfidenceTier.CIRCUMSTANTIAL
                    edge_conf = 0.85 if exact_author_or_inst else 0.52

                    work_id = f"openalex:{w.get('id', '').split('/')[-1]}"
                    rcpt = EvidenceReceipt(
                        tool="openalex_scholarly_graph",
                        domain=DomainCategory.JOURNALISM,
                        admiralty_code="B1" if exact_author_or_inst else "C3",
                        selector_strength=sel_strength,
                        source_url=doi or "https://openalex.org",
                        extracted_fact=f"OpenAlex Publication ({pub_year}): '{title[:80]}' | Authors: {authors[:3]} | Institutions: {institutions[:2]} | Grants: {len(grants)}",
                        raw_snippet=f"title={title} | authors={authors} | institutions={institutions} | grants={grants}",
                    )
                    self.graph.upsert_node(
                        GraphNode(
                            id=work_id,
                            label=f"🎓 Paper ({pub_year}): {title[:48]}...",
                            entity_type=EntityType.DOCUMENT,
                            domain=DomainCategory.JOURNALISM,
                            selector_strength=sel_strength,
                            smoke_score=30.0 if exact_author_or_inst else 20.0,
                            risk_flags=["OPENALEX_ACADEMIC_RECORD"],
                            attributes={"title": title, "year": pub_year, "authors": authors, "institutions": institutions, "grants": grants},
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=work_id,
                            relation=RelationType.MENTIONED_IN,
                            domain=DomainCategory.JOURNALISM,
                            admiralty_code="B1" if exact_author_or_inst else "C3",
                            confidence=edge_conf,
                            tier=edge_tier,
                            summary=f"OpenAlex ({pub_year})",
                            event_date=pub_year,
                            receipts=[rcpt],
                        )
                    )
        except Exception:
            pass

    async def investigate_hackernews_archive(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Query HackerNews Algolia API for historical Show HN launches, founder handles, and community discussions."""
        url = f"https://hn.algolia.com/api/v1/search?query={quote_plus(query)}&tags=story&hitsPerPage=4"
        try:
            async with httpx.AsyncClient(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                hits = resp.json().get("hits", [])[:3]
                for h in hits:
                    title = h.get("title") or ""
                    author = h.get("author") or ""
                    created_at = h.get("created_at") or ""
                    obj_id = h.get("objectID") or ""
                    hn_url = f"https://news.ycombinator.com/item?id={obj_id}"
                    exact_handle = author.lower() == query.lower().strip().lstrip("@")
                    sel_strength = SelectorStrength.STRONG if exact_handle else SelectorStrength.SOFT
                    edge_tier = ConfidenceTier.VERIFIED if exact_handle else ConfidenceTier.CIRCUMSTANTIAL
                    edge_conf = 0.85 if exact_handle else 0.55

                    rcpt = EvidenceReceipt(
                        tool="hackernews_algolia_archive",
                        domain=DomainCategory.JOURNALISM,
                        admiralty_code="B2" if exact_handle else "C3",
                        selector_strength=sel_strength,
                        source_url=hn_url,
                        extracted_fact=f"HN Thread by @{author} ({created_at[:10]}): '{title}' ({h.get('num_comments', 0)} comments)",
                        raw_snippet=f"title={title} | author={author} | points={h.get('points')} | url={h.get('url')}",
                    )
                    hn_id = f"hn:{obj_id}"
                    self.graph.upsert_node(
                        GraphNode(
                            id=hn_id,
                            label=f"🟧 HN (@{author}): {title[:48]}...",
                            entity_type=EntityType.NEWS_ARTICLE,
                            domain=DomainCategory.JOURNALISM,
                            selector_strength=sel_strength,
                            smoke_score=35.0 if exact_handle else 22.0,
                            attributes={"author": author, "title": title, "created_at": created_at, "hn_url": hn_url},
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=hn_id,
                            relation=RelationType.MENTIONED_IN,
                            domain=DomainCategory.JOURNALISM,
                            admiralty_code="B2" if exact_handle else "C3",
                            confidence=edge_conf,
                            tier=edge_tier,
                            summary=f"HN @{author} ({created_at[:10]})",
                            event_date=created_at,
                            receipts=[rcpt],
                        )
                    )
        except Exception:
            pass

    def inspect_document_binary_forensics(self, file_path: str, origin_node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Forensic examination of .docx (Word RSID revision tags + core.xml authors) and .pdf (/Info + XMP timezone offsets).
        Implements Bellingcat & Tow Center document attribution tradecraft.
        """
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}

        doc_id = f"doc:{path.name}"
        findings: Dict[str, Any] = {"file": str(path), "type": path.suffix.lower(), "rsids": [], "metadata": {}, "anomalies": []}

        if path.suffix.lower() == ".docx":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    if "word/settings.xml" in zf.namelist():
                        settings_xml = zf.read("word/settings.xml").decode("utf-8", errors="ignore")
                        rsid_root_match = re.search(r'rsidRoot\s+w:val="([0-9A-Fa-f]{8})"', settings_xml)
                        all_rsids = sorted(set(re.findall(r'w:rsid\w*\s+w:val="([0-9A-Fa-f]{8})"', settings_xml)))
                        findings["rsid_root"] = rsid_root_match.group(1) if rsid_root_match else None
                        findings["rsids"] = all_rsids[:50]
                        findings["total_rsid_revisions"] = len(all_rsids)
                    if "docProps/core.xml" in zf.namelist():
                        core_xml = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                        for tag in ("creator", "lastModifiedBy", "created", "modified", "revision"):
                            m = re.search(rf"<[^:>]*:{tag}[^>]*>([^<]+)</", core_xml)
                            if m:
                                findings["metadata"][tag] = m.group(1).strip()
            except Exception as exc:
                findings["error"] = str(exc)

        elif path.suffix.lower() == ".pdf":
            try:
                reader = PdfReader(str(path))
                meta = reader.metadata or {}
                for k, v in meta.items():
                    findings["metadata"][str(k)] = str(v)
                # Check for timezone offset in CreationDate / ModDate (e.g. D:20261012142210+03'00')
                for dt_key in ("/CreationDate", "/ModDate"):
                    val = str(meta.get(dt_key, ""))
                    tz_match = re.search(r"([+\-]\d{2})'(\d{2})'", val)
                    if tz_match:
                        tz_str = f"UTC{tz_match.group(1)}:{tz_match.group(2)}"
                        findings["metadata"][f"{dt_key}_timezone"] = tz_str
                        findings["anomalies"].append(f"Embedded PDF clock offset {tz_str} in {dt_key}")
            except Exception as exc:
                findings["error"] = str(exc)

        rcpt = EvidenceReceipt(
            tool="bunnyhole_doc_forensics (RSID/XMP)",
            domain=DomainCategory.JOURNALISM,
            admiralty_code="A1",
            selector_strength=SelectorStrength.STRONG,
            source_url=f"file://{path.resolve()}",
            extracted_fact=f"Binary document forensics on {path.name}: {findings.get('metadata')} | rsidRoot={findings.get('rsid_root')}",
            raw_snippet=str(findings)[:400],
        )
        doc_node = GraphNode(
            id=doc_id,
            label=f"📄 {path.name}",
            entity_type=EntityType.DOCUMENT,
            domain=DomainCategory.JOURNALISM,
            selector_strength=SelectorStrength.STRONG,
            ftm_schema="Document",
            smoke_score=65.0 if findings["anomalies"] or findings.get("rsid_root") else 30.0,
            risk_flags=["WORD_RSID_FINGERPRINTED"] if findings.get("rsid_root") else ["PDF_METADATA_EXTRACTED"],
            attributes=findings,
            receipts=[rcpt],
            hop_depth=1,
        )
        self.graph.upsert_node(doc_node)
        if findings.get("rsid_root"):
            rsid_node_id = f"tracker:rsid:{findings['rsid_root']}"
            self.graph.upsert_node(
                GraphNode(
                    id=rsid_node_id,
                    label=f"🧬 Word rsidRoot: {findings['rsid_root']}",
                    entity_type=EntityType.TRACKER_ID,
                    domain=DomainCategory.JOURNALISM,
                    selector_strength=SelectorStrength.STRONG,
                    smoke_score=70.0,
                    risk_flags=["DETERMINISTIC_TEMPLATE_FINGERPRINT"],
                    attributes={"rsid_root": findings["rsid_root"], "revision_count": findings.get("total_rsid_revisions", 0)},
                    receipts=[rcpt],
                    hop_depth=2,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=doc_id,
                    target_id=rsid_node_id,
                    relation=RelationType.SHARES_RSID_WITH,
                    domain=DomainCategory.JOURNALISM,
                    admiralty_code="A1",
                    confidence=0.99,
                    summary=f"Word rsidRoot={findings['rsid_root']}",
                    receipts=[rcpt],
                )
            )
        return findings
