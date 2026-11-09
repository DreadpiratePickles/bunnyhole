"""Graph-node builders for the reference-record sources of ``pi_sources``: Companies House PSC, CFPB, Wikidata.

Split out of ``PISourcesAgent`` to keep ``pi_sources.py`` under the module-size limit. ``_ReferenceRecordsMixin``
holds the methods that turn an already-fetched, already-validated payload into receipts, nodes and edges; they
rely on ``self.graph``, ``self._get_json`` and ``self._link_to_origin`` supplied by ``PISourcesAgent``, and behave
exactly as they did when they lived in that class. Fetching, validation and logging stay in ``pi_sources``.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

from bunnyhole.agents.sanctions_lists import _SourceSkip
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
)

CH_API_BASE = "https://api.company-information.service.gov.uk"
CH_PUBLIC_BASE = "https://find-and-update.company-information.service.gov.uk"
CFPB_API_URL = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"

_CH_SHARES_BAND = re.compile(r"^ownership-of-shares-(\d{1,3})-to-(\d{1,3})-percent$")


def _slug(text: str, limit: int = 40) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")[:limit] or "x"


def _ownership_pct(natures_of_control: Any) -> Optional[float]:
    """Midpoint of a Companies House shareholding band (e.g. 50-to-75 -> 62.5), else None."""
    if not isinstance(natures_of_control, list):
        return None
    for nature in natures_of_control:
        match = _CH_SHARES_BAND.match(str(nature))
        if match:
            low, high = int(match.group(1)), int(match.group(2))
            if 0 <= low < high <= 100:
                return (low + high) / 2.0
    return None



class _ReferenceRecordsMixin:
    """Node/edge/receipt builders for Companies House PSC, CFPB complaints and Wikidata records."""

    graph: Any  # InvestigationGraph, set by PISourcesAgent.__init__
    _get_json: Any  # PISourcesAgent._get_json (staticmethod)
    _link_to_origin: Any  # PISourcesAgent._link_to_origin

    async def _record_company_and_psc(
        self,
        client: httpx.AsyncClient,
        item: Dict[str, Any],
        number: str,
        query: str,
        origin_node_id: str,
        hop_depth: int,
    ) -> List[Dict[str, Any]]:
        title = str(item.get("title") or number)
        company_id = f"company:uk:{number}"
        company_url = f"{CH_PUBLIC_BASE}/company/{number}"
        psc_data = await self._get_json(client, f"{CH_API_BASE}/company/{number}/persons-with-significant-control")
        psc_items = psc_data.get("items") or []
        if not isinstance(psc_items, list):
            raise _SourceSkip("unexpected PSC list shape")

        company_receipt = EvidenceReceipt(
            tool="companies_house",
            domain=DomainCategory.FIAT,
            admiralty_code="B2",  # official UK registry; the match to our target is soft
            selector_strength=SelectorStrength.SOFT,
            source_url=company_url,
            extracted_fact=(
                f"Companies House lists UK company '{title}' ({number}), status {item.get('company_status') or 'n/a'}"
            ),
            raw_snippet=f"company_number={number} | title={title} | address={item.get('address_snippet') or ''}",
        )
        self.graph.upsert_node(
            GraphNode(
                id=company_id,
                label=title,
                entity_type=EntityType.ORGANIZATION,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema="Company",
                risk_flags=["SOFT_NAME_MATCH_VERIFY"],
                attributes={
                    "company_number": number,
                    "company_status": item.get("company_status"),
                    "date_of_creation": item.get("date_of_creation"),
                    "address": item.get("address_snippet"),
                    "match_query": query,
                },
                receipts=[company_receipt],
                hop_depth=hop_depth,
            )
        )
        self._link_to_origin(
            origin_node_id, company_id, RelationType.LINKED_IDENTITY, "B3", 0.55,
            "Companies House name match (verify)", company_receipt,
        )  # fmt: skip

        psc_url = f"{CH_PUBLIC_BASE}/company/{number}/persons-with-significant-control"
        owners: List[Dict[str, Any]] = []
        for psc in psc_items:
            if not isinstance(psc, dict):
                continue
            name = str(psc.get("name") or "").strip()
            if not name:
                continue  # super-secure / undisclosed PSC: nothing to name
            kind = str(psc.get("kind") or "")
            natures = psc.get("natures_of_control") or []
            pct = _ownership_pct(natures)
            is_person = kind.startswith("individual-person")
            ceased_on = str(psc.get("ceased_on") or "")
            notified_on = str(psc.get("notified_on") or "")
            psc_id = f"psc:uk:{number}:{_slug(name)}"
            nature_text = ", ".join(str(n) for n in natures) if isinstance(natures, list) else ""
            receipt = EvidenceReceipt(
                tool="companies_house",
                domain=DomainCategory.FIAT,
                admiralty_code="B2",
                selector_strength=SelectorStrength.SOFT,
                source_url=psc_url,
                extracted_fact=(
                    f"Companies House PSC register for {title} ({number}) lists '{name}' ({kind or 'PSC'})"
                    + (f" with {nature_text}" if nature_text else "")
                    + (f", notified {notified_on}" if notified_on else "")
                    + (f", ceased {ceased_on}" if ceased_on else "")
                ),
                raw_snippet=f"name={name} | kind={kind} | natures={natures} | notified_on={notified_on} | ceased_on={ceased_on}",
            )
            flags = ["SOFT_NAME_MATCH_VERIFY"] + (["CEASED_PSC"] if ceased_on else [])
            self.graph.upsert_node(
                GraphNode(
                    id=psc_id,
                    label=name,
                    entity_type=EntityType.PERSON if is_person else EntityType.ORGANIZATION,
                    domain=DomainCategory.FIAT,
                    selector_strength=SelectorStrength.SOFT,
                    ftm_schema="Person" if is_person else "Company",
                    risk_flags=flags,
                    attributes={
                        "psc_kind": kind,
                        "natures_of_control": natures,
                        "ownership_pct_midpoint": pct,
                        "notified_on": notified_on,
                        "ceased_on": ceased_on,
                        "country_of_residence": psc.get("country_of_residence"),
                        "company_number": number,
                    },
                    receipts=[receipt],
                    hop_depth=hop_depth + 1,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=psc_id,
                    target_id=company_id,
                    relation=RelationType.OWNS,
                    domain=DomainCategory.FIAT,
                    admiralty_code="B3",  # register entry is solid; the company match upstream is soft
                    confidence=0.35 if ceased_on else 0.55,
                    summary=f"PSC of {title}" + (f" ({nature_text})" if nature_text else ""),
                    event_date=notified_on or None,
                    receipts=[receipt],
                )
            )
            if ceased_on:
                continue  # historical holder: recorded in the graph but not a current owner
            owners.append(
                {
                    "parent_id": psc_id,
                    "parent_name": name,
                    "pct": pct,
                    "is_natural_person": is_person,
                    "source": psc_url,
                    "as_of": notified_on,
                    "child_id": company_id,
                }
            )
        return owners

    def _record_cfpb_summary(
        self, query: str, total: int, sampled: int, ours: List[Dict[str, Any]], origin_node_id: str, hop_depth: int
    ) -> None:
        issues = [str(s.get("issue")) for s in ours if s.get("issue")]
        top_issues = [issue for issue, _ in Counter(issues).most_common(3)]
        products = sorted({str(s.get("product")) for s in ours if s.get("product")})
        states = sorted({str(s.get("state")) for s in ours if s.get("state")})
        dates = sorted(str(s.get("date_received"))[:10] for s in ours if s.get("date_received"))
        company_names = sorted({str(s.get("company")) for s in ours if s.get("company")})
        search_url = f"{CFPB_API_URL}?{urlencode({'search_term': query, 'size': 5, 'no_aggs': 'true'})}"
        receipt = EvidenceReceipt(
            tool="cfpb_complaints",
            domain=DomainCategory.FIAT,
            admiralty_code="B3",  # official database, but its content is unverified consumer claims
            selector_strength=SelectorStrength.SOFT,
            source_url=search_url,
            extracted_fact=(
                f"CFPB complaint database full-text search for '{query}' returned {total} complaints; "
                f"{len(ours)} of the {sampled} sampled name {', '.join(company_names[:2])}"
                + (f" (top issues: {'; '.join(top_issues)})" if top_issues else "")
                + ". Complaint content is unverified consumer claims, not findings."
            ),
            raw_snippet=f"total={total} | sampled={sampled} | attributed={len(ours)} | products={products} | states={states}",
        )
        node_id = f"cfpb:{_slug(query)}"
        self.graph.upsert_node(
            GraphNode(
                id=node_id,
                label=f"CFPB complaints: {total} full-text hits for {query}",
                entity_type=EntityType.DOCUMENT,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema="Document",
                smoke_score=30.0,
                risk_flags=["UNVERIFIED_CONSUMER_CLAIMS", "SOFT_NAME_MATCH_VERIFY"],
                attributes={
                    "total_hits": total,
                    "sampled": sampled,
                    "attributed_in_sample": len(ours),
                    "top_issues": top_issues,
                    "products": products,
                    "states": states,
                    "date_range": [dates[0], dates[-1]] if dates else [],
                    "match_query": query,
                },
                receipts=[receipt],
                hop_depth=hop_depth,
            )
        )
        self._link_to_origin(
            origin_node_id, node_id, RelationType.MENTIONED_IN, "B3", 0.45,
            "CFPB consumer complaints naming the company (unverified)", receipt,
        )  # fmt: skip

    def _record_wikidata_entity(
        self, rec: Dict[str, Any], qid: str, query: str, origin_node_id: str, hop_depth: int
    ) -> None:
        label = str(rec.get("label") or qid)
        description = str(rec.get("description") or "")
        receipt = EvidenceReceipt(
            tool="wikidata",
            domain=DomainCategory.FIAT,
            admiralty_code="C3",  # community-edited reference
            selector_strength=SelectorStrength.SOFT,
            source_url=f"https://www.wikidata.org/wiki/{qid}",
            extracted_fact=(
                f"Wikidata {qid} '{label}'" + (f": {description}" if description else "")
                + ". Entity-resolution aid only; verify against the primary registry."
            ),
            raw_snippet=f"qid={qid} | label={label} | description={description} | concepturi={rec.get('concepturi') or ''}",
        )
        node_id = f"wikidata:{qid}"
        self.graph.upsert_node(
            GraphNode(
                id=node_id,
                label=f"Wikidata {qid}: {label}",
                entity_type=EntityType.DOCUMENT,  # a reference record, not an assertion of what the entity is
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema="Document",
                risk_flags=["ENTITY_RESOLUTION_AID_VERIFY"],
                attributes={
                    "qid": qid,
                    "label": label,
                    "description": description,
                    "concepturi": rec.get("concepturi"),
                    "match_query": query,
                },
                receipts=[receipt],
                hop_depth=hop_depth,
            )
        )
        self._link_to_origin(
            origin_node_id, node_id, RelationType.LINKED_IDENTITY, "C3", 0.40,
            "Wikidata name match (entity-resolution aid, verify)", receipt,
        )  # fmt: skip
