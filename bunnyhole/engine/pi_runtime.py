"""PI stream runtime: the assembly of ``result["pi"]`` from the live investigation graph and the source log.

This is the glue between the live investigation graph and the pure PI modules (``pi``, ``pi_identity``,
``pi_ubo``, ``pi_analysis``, ``pi_escalation``, ``pi_reference``). Everything here is a pure function over
plain dicts, so the orchestrator changes stay small and the assembly is testable offline. No network, no
model calls; the only clock is ``now_iso``.

Responsibilities live in sibling modules and are re-exported here so ``from bunnyhole.engine.pi_runtime import X``
keeps working: ``pi_recorder`` (source-log recorder, passive-mode blockers), ``pi_notes`` (identity notes,
playbook progress, escalation triggers) and ``pi_credentials`` (credential scrubbing).
Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md sections 2, 3.1 and 4.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Coroutine, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from bunnyhole.engine.pi import (
    NOTICES,
    CustodyEntry,
    EntityProfile,
    Finding,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    SourceLogEntry,
    count_independent_sources,
    identifier_warnings,
    label_finding,
)
from bunnyhole.engine.pi_analysis import (
    build_coverage,
    detect_contradictions,
    downgrade_unrelated_hits,
    falsifiers_for,
    find_gaps,
    freshness_class,
)
from bunnyhole.engine.pi_credentials import (
    REDACTED_CREDENTIAL,
    redact_value,
    scrub_credential_text,
    strip_packet_credentials,
)
from bunnyhole.engine.pi_escalation import custodians_for, handoff_sheet
from bunnyhole.engine.pi_graph_access import (
    _ADDRESS_ATTRS,
    _clean_label,
    _dict,
    _is_external,
    _receipts,
    _val,
)
from bunnyhole.engine.pi_notes import (
    ESCALATION_EVALUATORS,
    MAX_IDENTITY_NOTES,
    MAX_RECORDS_PER_NAME_GROUP,
    PLAYBOOK_SOURCE_MAP,
    SANCTIONS_LISTS,
    SOFT_LISTED_TAG,
    SUBJECT_NOT_ANCHORED_NOTE,
    _EscalationContext,
    escalation_triggers_for,
    identity_notes_for,
    playbook_progress_for,
    sanctions_screening_for,
    soft_listed_matches,
    soft_match_hit,
    soft_match_note,
)
from bunnyhole.engine.pi_recorder import (
    BREACH_SKIP_REASON,
    CREDENTIAL_SKIP_REASON,
    PIRunRecorder,
    make_breach_blocker,
    make_holehe_blocker,
)
from bunnyhole.engine.pi_reference import playbook_for
from bunnyhole.engine.pi_relevance import score_subject_relevance
from bunnyhole.engine.pi_ubo import (
    OwnerLink,
    apply_50_percent_rule,
    false_link_reason,
    is_registered_agent_address,
    unresolved_node_id,
    walk_ownership,
)

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------------------------
# Source classes
# ----------------------------------------------------------------------------------------------

#: Recorded source name -> ``pi_analysis.SOURCE_CLASSES`` entry. A source maps only to the class it
#: really searches. ``wikidata`` / ``wikipedia`` / ``hudsonrock`` are reference or breach-exposure aids
#: and are deliberately unmapped so they never inflate the coverage matrix (they still appear in the
#: source log). ``sec_edgar`` maps to the registry class because the scan reads filings, not enforcement.
SOURCE_CLASS_MAP: Dict[str, str] = {
    "gleif": "corporate_registry",
    "sec_edgar": "corporate_registry",
    "nonprofit_990s": "corporate_registry",
    "uk_psc": "beneficial_ownership",
    "opensanctions": "sanctions_pep",
    "ca_sanctions": "sanctions_pep",
    "ofac_sdn": "sanctions_pep",
    "un_consolidated": "sanctions_pep",
    "uk_sanctions_list": "sanctions_pep",
    "court_dockets": "court_dockets",
    "news_narrative": "news_adverse_media",
    "wayback": "news_adverse_media",
    "cfpb_complaints": "regulatory_enforcement",
    "openalex": "social_osint",
    "hackernews": "social_osint",
    "osint_identity": "social_osint",
    "email_pivots": "social_osint",
    "phone_lookup": "social_osint",
    "osint_domain": "domain_infrastructure",
    "ip_shodan_ripestat": "domain_infrastructure",
    "dexscreener": "crypto_onchain",
    "onchain_evm": "crypto_onchain",
    "onchain_bitcoin": "crypto_onchain",
    "aircraft_adsb": "property_assets",
}

#: Recorder source name -> receipt ``tool`` prefixes of the nodes that source adds to the graph. Used only to tell
#: whether a source "hit" produced anything about the subject (``pi_analysis.downgrade_unrelated_hits``); a source that
#: is not listed is never downgraded.
SOURCE_RECEIPT_TOOLS: Dict[str, Tuple[str, ...]] = {
    "gleif": ("gleif",),
    "sec_edgar": ("sec_edgar",),
    "nonprofit_990s": ("propublica",),
    "uk_psc": ("companies_house",),
    "opensanctions": ("opensanctions",),
    "ca_sanctions": ("gac_sema",),
    "ofac_sdn": ("ofac_sdn",),
    "un_consolidated": ("un_consolidated",),
    "uk_sanctions_list": ("uk_sanctions_list",),
    "court_dockets": ("courtlistener",),
    "news_narrative": ("google_news",),
    "wayback": ("waybackpy",),
    "cfpb_complaints": ("cfpb",),
    "openalex": ("openalex",),
    "hackernews": ("hackernews",),
}


# ----------------------------------------------------------------------------------------------
# Conflict check and selectors
# ----------------------------------------------------------------------------------------------

MIN_CONFLICT_QUERY_CHARS = 3
_NAME_LEAD_TYPES = ("company",)
_SELECTOR_KEYS: Dict[str, str] = {
    "email": "emails",
    "phone": "phones",
    "username": "usernames",
    "wallet": "wallets",
    "bitcoin": "wallets",
    "domain": "domains",
    "ip": "domains",
}


def selectors_from_seeds(seeds: Iterable[Tuple[str, str]], subject_is_person: bool) -> Dict[str, List[str]]:
    """Group ``(lead_type, value)`` seed tuples into the selector dict ``pi.identifier_warnings`` expects.

    Credentials and documents are never included (secrets and local files are not selectors).
    """
    out: Dict[str, List[str]] = {}
    for lead_type, raw in seeds:
        value = (raw or "").strip()
        if not value:
            continue
        if lead_type in _NAME_LEAD_TYPES:
            key = "names" if subject_is_person else "organizations"
        else:
            key = _SELECTOR_KEYS.get(lead_type, "")
        if key and value not in out.setdefault(key, []):
            out[key].append(value)
    return {k: v for k, v in out.items() if v}


def run_conflict_check(
    store: Any, values: Iterable[str], current_case_id: str, recorder: PIRunRecorder, *, per_query_limit: int = 10
) -> List[Dict[str, Any]]:
    """Look for prior cases that already hold the seed or any selector (a PI's conflict check).

    Returns ``[{"case_id","seed","at","matched_on","entity"}]`` deduplicated by case. A failure is
    non-fatal: it is recorded as an ``error`` entry and whatever was found so far is returned.
    """
    queries: List[str] = []
    for raw in values:
        value = (raw or "").strip()
        if len(value) >= MIN_CONFLICT_QUERY_CHARS and value.lower() not in {q.lower() for q in queries}:
            queries.append(value)
    target = queries[0] if queries else ""
    prior: Dict[str, Dict[str, Any]] = {}
    try:
        for query in queries:
            for row in store.search_entity_memory(query, limit=per_query_limit):
                case_id = str(row.get("case_id") or "")
                if not case_id or case_id == current_case_id or case_id in prior:
                    continue
                prior[case_id] = {
                    "case_id": case_id,
                    "seed": str(row.get("seed_query") or ""),
                    "at": str(row.get("sighted_at") or ""),
                    "matched_on": query,
                    "entity": str(row.get("label") or ""),
                }
    except Exception as exc:  # noqa: BLE001 - non-fatal by spec; recorded, never swallowed silently
        logger.warning("PI conflict check failed: %s: %s", type(exc).__name__, exc)
        recorder.error("conflict_check", target, f"{type(exc).__name__}: {exc}")
        return list(prior.values())
    if prior:
        recorder.note("conflict_check", target, "hit", f"{len(prior)} prior case(s) already mention these selectors")
    else:
        recorder.note("conflict_check", target, "negative", "no prior case mentions these selectors")
    return list(prior.values())


def with_objective(engagement: PIEngagement) -> PIEngagement:
    """Return the engagement with ``objective`` filled from the case-type playbook when blank (no mutation)."""
    if engagement.objective.strip():
        return engagement
    return engagement.model_copy(update={"objective": playbook_for(engagement.case_type).objective})



# ----------------------------------------------------------------------------------------------
# Plain-dict access helpers (the shared ones live in ``pi_graph_access``)
# ----------------------------------------------------------------------------------------------

_LISTING_TOOL_MARKERS = ("opensanctions", "gac_sema") + tuple(prefix for _d, _r, prefix in SANCTIONS_LISTS)
_LISTING_FLAGS = frozenset({"OFAC_EU_UN_SANCTIONS_LIST_MATCH"})


def _parse_date(text: Any) -> Optional[datetime]:
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)



# ----------------------------------------------------------------------------------------------
# Findings and freshness
# ----------------------------------------------------------------------------------------------

_AS_OF_KEYS = ("as_of", "last_updated", "updated_at", "notified_on", "filing_date", "event_date", "last_seen")
_REGISTRY_ID_PREFIXES = ("lei:", "company:", "psc:", "cik:")


def _newest_as_of(node: Mapping[str, Any], edge_dates: Sequence[str], timeline_dates: Sequence[str]) -> str:
    """Newest date a record about the node carries. Receipt ``timestamp`` is collection time and never used."""
    candidates: List[str] = []
    attrs = node.get("attributes") or {}
    candidates += [str(attrs[k]) for k in _AS_OF_KEYS if attrs.get(k)]
    candidates += [str(r["as_of"]) for r in _receipts(node) if r.get("as_of")]
    candidates += list(edge_dates) + list(timeline_dates)
    dated = [(parsed, text) for text in candidates if (parsed := _parse_date(text)) is not None]
    return max(dated)[1] if dated else ""


def _build_findings(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    timeline: Sequence[Mapping[str, Any]],
    now_iso: Optional[str],
    relevance: Optional[Mapping[str, Tuple[str, str]]] = None,
) -> List[Finding]:
    edge_dates: Dict[str, List[str]] = {}
    for edge in edges:
        if edge.get("event_date"):
            for end in (edge.get("source_id"), edge.get("target_id")):
                edge_dates.setdefault(str(end), []).append(str(edge["event_date"]))
    timeline_dates: Dict[str, List[str]] = {}
    for item in timeline:
        for node_id in item.get("node_ids") or []:
            timeline_dates.setdefault(str(node_id), []).append(str(item.get("timestamp") or ""))

    findings: List[Finding] = []
    for node in nodes:
        external = [r for r in _receipts(node) if _is_external(r)]
        if not external:
            continue  # the seed anchor and cross-case notes are not findings
        count = count_independent_sources(external)
        node_id = str(node.get("id"))
        as_of = _newest_as_of(node, edge_dates.get(node_id, []), timeline_dates.get(node_id, []))
        kind = "registry" if node_id.startswith(_REGISTRY_ID_PREFIXES) else "address"
        rel, reason = (relevance or {}).get(node_id, ("unknown", ""))
        findings.append(
            Finding(
                node_id=node_id,
                label=str(node.get("label") or node_id),
                finding_label=label_finding(count),
                source_count=count,
                freshness=freshness_class(as_of, kind, now_iso=now_iso) if as_of else "unknown",
                relevance=rel,  # type: ignore[arg-type]
                relevance_reason=reason,
            )
        )
    return findings


# ----------------------------------------------------------------------------------------------
# Ownership (in-memory walk, no network)
# ----------------------------------------------------------------------------------------------

_PARENT_IS_SOURCE = frozenset({"OWNS", "DIRECT_PARENT_OF", "ULTIMATE_PARENT_OF"})
_PARENT_IS_TARGET = frozenset({"SUBSIDIARY_OF"})
_CONTROL_RELATIONS = frozenset({"DIRECTOR_OF", "OFFICER_OF", "NOMINEE_FOR"})  # control, not ownership
_OWNED_TYPES = frozenset({"Organization", "ShellCompany"})
_OWNER_TYPES = frozenset({"Organization", "ShellCompany", "Person"})


def _drive_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine that never actually suspends (an in-memory fetcher) without an event loop.

    ``compile_full_result`` is synchronous and may be called from inside a running loop, so
    ``asyncio.run`` is not an option; the walk only awaits an in-memory lookup.
    """
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    coro.close()
    raise RuntimeError("in-memory ownership walk unexpectedly suspended")


def _ownership_adjacency(
    nodes_by_id: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    ownership_links: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, OwnerLink]]:
    """child id -> {parent id -> OwnerLink}, from graph ownership edges plus fetched ownership links."""
    adjacency: Dict[str, Dict[str, OwnerLink]] = {}

    def add(child: str, link: OwnerLink) -> None:
        owners = adjacency.setdefault(child, {})
        existing = owners.get(link.parent_id)
        if existing is None:
            owners[link.parent_id] = link
        elif existing.pct is None and link.pct is not None:
            owners[link.parent_id] = existing.model_copy(update={"pct": link.pct})

    for edge in edges:
        relation = str(_val(edge.get("relation")))
        if relation in _PARENT_IS_SOURCE:
            parent_id, child_id = str(edge.get("source_id")), str(edge.get("target_id"))
        elif relation in _PARENT_IS_TARGET:
            parent_id, child_id = str(edge.get("target_id")), str(edge.get("source_id"))
        else:
            continue
        parent, child = nodes_by_id.get(parent_id), nodes_by_id.get(child_id)
        if parent is None or child is None:
            continue
        if str(_val(child.get("entity_type"))) not in _OWNED_TYPES or str(_val(parent.get("entity_type"))) not in _OWNER_TYPES:
            continue
        pct = (parent.get("attributes") or {}).get("ownership_pct_midpoint") if relation == "OWNS" else None
        receipts = _receipts(edge)
        add(
            child_id,
            OwnerLink(
                parent_id=parent_id,
                parent_name=str(parent.get("label") or parent_id),
                pct=float(pct) if isinstance(pct, (int, float)) else None,
                is_natural_person=str(_val(parent.get("entity_type"))) == "Person",
                source=str(receipts[0].get("source_url") or "") if receipts else relation,
                as_of=str(edge.get("event_date") or ""),
            ),
        )

    for raw in ownership_links:
        link = _dict(raw)
        child_id, parent_id = str(link.get("child_id") or ""), str(link.get("parent_id") or "")
        if not child_id or not parent_id:
            continue
        pct = link.get("pct")
        add(
            child_id,
            OwnerLink(
                parent_id=parent_id,
                parent_name=str(link.get("parent_name") or parent_id),
                pct=float(pct) if isinstance(pct, (int, float)) else None,
                is_natural_person=bool(link.get("is_natural_person")),
                source=str(link.get("source") or ""),
                as_of=str(link.get("as_of") or ""),
            ),
        )
    return adjacency


def _listed_ids(nodes: Sequence[Mapping[str, Any]]) -> Set[str]:
    """Nodes carrying a sanctions or PEP listing receipt (OpenSanctions, Canadian GAC list)."""
    listed: Set[str] = set()
    for node in nodes:
        by_tool = any(
            marker in str(r.get("tool") or "").lower() for r in _receipts(node) for marker in _LISTING_TOOL_MARKERS
        )
        if by_tool or _LISTING_FLAGS & set(node.get("risk_flags") or []):
            listed.add(str(node.get("id")))
    return listed


def _build_ownership(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    ownership_links: Sequence[Mapping[str, Any]],
    soft_listed_ids: Iterable[str] = (),
) -> OwnershipBlock:
    nodes_by_id = {str(n.get("id")): n for n in nodes}
    adjacency = _ownership_adjacency(nodes_by_id, edges, ownership_links)
    if not adjacency:
        return OwnershipBlock()

    async def fetch(node_id: str) -> List[OwnerLink]:
        return list(adjacency.get(node_id, {}).values())

    parents = {pid for owners in adjacency.values() for pid in owners}
    starts = [child for child in adjacency if child not in parents] or list(adjacency)  # a pure loop has no bottom
    merged_edges: Dict[Tuple[str, str], OwnershipEdge] = {}
    unresolved: Dict[str, None] = {}
    levels = 0
    for start in starts:
        block: OwnershipBlock = _drive_sync(walk_ownership(start, fetch))
        levels = max(levels, block.levels_walked)
        for edge in block.edges:
            merged_edges.setdefault((edge.child, edge.parent), edge)
        for entry in block.unresolved:
            unresolved.setdefault(entry, None)
    all_edges = [
        OwnershipEdge(child=child, parent=pid, pct=link.pct, source=link.source, as_of=link.as_of)
        for child, owners in adjacency.items()
        for pid, link in owners.items()
    ]
    return OwnershipBlock(
        levels_walked=levels,
        edges=list(merged_edges.values()),
        blocked_by_50_rule=apply_50_percent_rule(all_edges, _listed_ids(nodes) | set(soft_listed_ids)),
        unresolved=list(unresolved),
    )


# ----------------------------------------------------------------------------------------------
# False-link flags
# ----------------------------------------------------------------------------------------------

_HOSTING_ATTRS = ("hosting_provider", "hosting", "asn_org", "asn_name", "isp", "org", "provider", "cdn")




def _flag(node_id: str, reason: str, severity: str) -> Dict[str, str]:
    return {"node_id": node_id, "reason": reason, "severity": severity}


OWN_REGISTERED_AGENT_REASON = "registered-agent address shared by many entities; not evidence of a link"


def _build_false_link_flags(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    selectors: Mapping[str, Sequence[str]],
    subject_is_person: bool,
    relevance: Optional[Mapping[str, Tuple[str, str]]] = None,
) -> List[Dict[str, str]]:
    """What is NOT a link. A shared registered-agent address on the SUBJECT's own record is expected (``info``);
    it stays ``high`` for any other entity and wherever the address node would link two entities."""
    sharers: Dict[str, Set[str]] = {}
    officer_targets: Dict[str, Set[str]] = {}
    for edge in edges:
        sharers.setdefault(str(edge.get("target_id")), set()).add(str(edge.get("source_id")))
        if str(_val(edge.get("relation"))) in _CONTROL_RELATIONS:
            officer_targets.setdefault(str(edge.get("source_id")), set()).add(str(edge.get("target_id")))
    anchors = {str(n.get("id")) for n in nodes if _is_anchor(n)}
    subject_ids = {node_id for node_id, (rel, _why) in (relevance or {}).items() if rel == "subject"}

    flags: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def emit(node_id: str, reason: Optional[str], severity: str) -> None:
        if reason and (node_id, reason) not in seen:
            seen.add((node_id, reason))
            flags.append(_flag(node_id, reason, severity))

    def is_subjects_own(node_id: str, etype: str) -> bool:
        if etype == "Location":  # an address node: the subject's own when only the subject (or the seed) points at it
            entities = sharers.get(node_id, set()) - anchors
            return bool(entities) and entities <= subject_ids
        return node_id in subject_ids

    def emit_agent(node_id: str, reason: str, etype: str) -> None:
        if is_subjects_own(node_id, etype):
            emit(node_id, OWN_REGISTERED_AGENT_REASON, "info")
        else:
            emit(node_id, reason, "high")

    for node in nodes:
        node_id = str(node.get("id"))
        etype = str(_val(node.get("entity_type")))
        attrs = node.get("attributes") or {}
        node_flags = set(node.get("risk_flags") or [])
        label = _clean_label(str(node.get("label") or ""))
        count = len(sharers.get(node_id, ()))

        addresses = [str(attrs[k]) for k in _ADDRESS_ATTRS if attrs.get(k)]
        if etype == "Location":
            addresses.append(label)
        for address in addresses:
            reason = false_link_reason("address", address, entity_count=count or None)
            if reason and "registered-agent" in reason:
                emit_agent(node_id, reason, etype)
            else:
                emit(node_id, reason, "medium")
        if "MASS_REGISTERED_AGENT_ADDRESS" in node_flags:
            emit_agent(node_id, "flagged by the graph as a mass registered-agent address shared by unrelated companies", etype)

        for key in _HOSTING_ATTRS:
            if attrs.get(key):
                emit(node_id, false_link_reason("hosting", str(attrs[key]), entity_count=count or None), "medium")
        if "SHARED_ANYCAST_CDN_IP" in node_flags:
            emit(node_id, "shared anycast CDN IP: thousands of unrelated sites share it", "medium")

        if etype == "Person":
            officer_count = len(officer_targets.get(node_id, ()))
            emit(node_id, false_link_reason("officer", label, entity_count=officer_count or None), "high")
            if "NOMINEE_DIRECTOR_STRAWMAN_CANDIDATE" in node_flags:
                emit(node_id, "graph analytics: linked to five or more corporate entities, possible nominee director", "medium")
            emit(node_id, false_link_reason("name", label), "medium")

    if subject_is_person:
        for name in list(selectors.get("names") or []):
            emit(f"selector:{name}", false_link_reason("name", name), "medium")
    return flags


# ----------------------------------------------------------------------------------------------
# Custodians and handoff
# ----------------------------------------------------------------------------------------------

_CEX_FLAG_MARKERS = ("CEX", "EXCHANGE", "DEPOSIT")


def _is_cex_wallet(node: Mapping[str, Any], cex_edge_nodes: Set[str]) -> bool:
    if str(node.get("id")) in cex_edge_nodes:
        return True
    if any(marker in str(flag).upper() for flag in node.get("risk_flags") or [] for marker in _CEX_FLAG_MARKERS):
        return True
    return any(("cex" in str(k).lower() or "exchange" in str(k).lower()) for k in (node.get("attributes") or {}))


def _infer_finding_kinds(
    nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]], registered_agent_flagged: bool
) -> Set[str]:
    kinds: Set[str] = {"registered_agent"} if registered_agent_flagged else set()
    cex_edge_nodes: Set[str] = set()
    for edge in edges:
        relation = str(_val(edge.get("relation")))
        if relation == "SHARED_CEX_DEPOSIT":
            cex_edge_nodes.update({str(edge.get("source_id")), str(edge.get("target_id"))})
        elif relation == "EMPLOYED_BY":
            kinds.add("employer")
    for node in nodes:
        etype = str(_val(node.get("entity_type")))
        node_id = str(node.get("id"))
        if etype == "CryptoWallet" and _is_cex_wallet(node, cex_edge_nodes):
            kinds.add("exchange_deposit_address")
        elif etype == "Domain":
            kinds.add("domain_registrant")
        elif etype in ("Aircraft", "Vessel"):
            kinds.add("vessel_aircraft_registry")
        elif etype == "Phone":
            kinds.add("phone_carrier")
        elif etype in ("Account", "Email"):
            kinds.add("social_platform_account")
        elif etype == "IPHost" and "SHARED_ANYCAST_CDN_IP" not in (node.get("risk_flags") or []):
            kinds.add("isp_ip_assignment")
        elif etype in _OWNED_TYPES and (
            node_id.startswith(("lei:", "company:", "cik:"))
            or any("gleif" in str(r.get("tool")) or "companies_house" in str(r.get("tool")) for r in _receipts(node))
        ):
            kinds.add("company_records")
    return kinds


def _handoff_addresses(nodes: Sequence[Mapping[str, Any]], limit: int = 10) -> List[str]:
    out: List[str] = []
    for node in nodes:
        attrs = node.get("attributes") or {}
        for key in _ADDRESS_ATTRS:
            value = str(attrs.get(key) or "").strip()
            if value and not is_registered_agent_address(value) and value not in out:
                out.append(value)
    return out[:limit]


# ----------------------------------------------------------------------------------------------
# Relevance, entity profile and chain evidence (presentation layer: the graph is never changed)
# ----------------------------------------------------------------------------------------------

_RELEVANCE_RANK = {"subject": 3, "related": 2, "unknown": 1, "unrelated": 0}
_LINK_RELATIONS = _PARENT_IS_SOURCE | _PARENT_IS_TARGET | _CONTROL_RELATIONS
_MAX_COLLISION_NOTES = 5
_MAX_SOFT_NOTES = 3
_REGISTRY_RECEIPT_TOOLS = (("gleif", "GLEIF"), ("companies_house", "Companies House"))  # tool-name prefixes
_LEI_FORM = re.compile(r"^[A-Z0-9]{20}$")
_JURISDICTION_SUFFIX = re.compile(r"\s*\([A-Za-z]{2}(?:-[A-Za-z0-9]+)?\)\s*$")
_PUBLIC_LISTING_ATTRS = ("ticker", "exchange", "stock_exchange", "cik")


def _subject_names(subject: str, selectors: Mapping[str, Sequence[str]], graph_dict: Mapping[str, Any]) -> List[str]:
    """Names the run is about: the explicit subject, else the entity/person selectors, else the seed query."""
    if subject.strip():
        return [subject.strip()]
    names = [v.strip() for key in ("organizations", "names") for v in selectors.get(key) or [] if v.strip()]
    if names:
        return list(dict.fromkeys(names))
    seed = str(graph_dict.get("seed_query") or "").strip()
    return [seed] if seed else []


def _first_external_tool(node: Mapping[str, Any]) -> str:
    return next((str(r.get("tool") or "") for r in _receipts(node) if _is_external(r)), "")


def _score_node(names: Sequence[str], node: Mapping[str, Any], linked: bool) -> Tuple[str, str]:
    """Best relevance of the node over the subject names (subject beats related beats unknown beats unrelated)."""
    label = _clean_label(str(node.get("label") or node.get("id") or ""))
    node_lei = str((node.get("attributes") or {}).get("lei") or "").strip().upper()
    if node_lei and any(_LEI_FORM.match(name.strip().upper()) and name.strip().upper() == node_lei for name in names):
        return "subject", f"the node's LEI {node_lei} is the subject's identifier"
    best: Tuple[str, str] = ("unknown", "no subject name to compare with")
    for index, name in enumerate(names):
        result = score_subject_relevance(
            name, label, tool=_first_external_tool(node), attributes=node.get("attributes") or {},
            linked_by_edge=linked, entity_type=str(_val(node.get("entity_type")) or ""),
        )
        if index == 0 or _RELEVANCE_RANK[result[0]] > _RELEVANCE_RANK[best[0]]:
            best = result
    return best


def _is_anchor(node: Mapping[str, Any]) -> bool:
    receipts = _receipts(node)
    return bool(receipts) and not any(_is_external(r) for r in receipts)


def _relevance_map(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    ownership_links: Sequence[Mapping[str, Any]],
    names: Sequence[str],
) -> Dict[str, Tuple[str, str]]:
    """Node id -> ``(relevance, reason)`` for every node except the seed anchor (which is the subject).

    Pass one scores names. Pass two re-scores nodes joined by an ownership or officer edge (or an ownership link)
    to a node that is the subject or the seed anchor: a company's officer or parent is related whatever its name.
    """
    out: Dict[str, Tuple[str, str]] = {}
    anchors = {str(n.get("id")) for n in nodes if _is_anchor(n)}
    for node in nodes:
        if str(node.get("id")) not in anchors:
            out[str(node.get("id"))] = _score_node(names, node, False)
    if not names:
        return out
    subject_ids = anchors | {node_id for node_id, (rel, _why) in out.items() if rel == "subject"}
    linked: Set[str] = set()
    pairs = [(str(e.get("source_id")), str(e.get("target_id"))) for e in edges if str(_val(e.get("relation"))) in _LINK_RELATIONS]
    pairs += [(str(_dict(l).get("child_id") or ""), str(_dict(l).get("parent_id") or "")) for l in ownership_links]
    for left, right in pairs:
        if left in subject_ids and right not in subject_ids:
            linked.add(right)
        if right in subject_ids and left not in subject_ids:
            linked.add(left)
    by_id = {str(n.get("id")): n for n in nodes}
    for node_id in linked:
        if node_id in out and out[node_id][0] in ("unrelated", "unknown") and node_id in by_id:
            out[node_id] = _score_node(names, by_id[node_id], True)
    return out


def _collision_notes(relevance: Mapping[str, Tuple[str, str]]) -> List[str]:
    """Namesakes that were labelled unrelated: shown as a note so a possible name collision is never dropped silently."""
    notes = [f"Node {node_id}: {why}" for node_id, (rel, why) in relevance.items()
             if rel == "unrelated" and why.startswith("possible name collision")]
    if len(notes) > _MAX_COLLISION_NOTES:
        notes = notes[:_MAX_COLLISION_NOTES] + [f"+{len(notes) - _MAX_COLLISION_NOTES} more possible name collision(s)"]
    return notes


_OMITTED_LINE = re.compile(r"^\+(\d+) more (?:identity )?note\(s\) omitted$")


def _merge_notes(base: List[str], extra: List[str]) -> List[str]:
    """``base`` plus ``extra`` notes, never more than ``MAX_IDENTITY_NOTES`` lines; the extra notes win the room.

    When the total does not fit, the tail of ``base`` is dropped and one "+N more note(s) omitted" line says how many.
    """
    if not extra:
        return list(base)
    omitted = 0
    if base and (found := _OMITTED_LINE.match(base[-1])):
        omitted, base = int(found.group(1)), base[:-1]
    kept_extra = extra[:_MAX_COLLISION_NOTES + 1]
    if len(base) + len(kept_extra) <= MAX_IDENTITY_NOTES and not omitted and len(kept_extra) == len(extra):
        return list(base) + kept_extra
    keep = max(MAX_IDENTITY_NOTES - len(kept_extra) - 1, 0)
    omitted += len(base) - min(keep, len(base)) + len(extra) - len(kept_extra)
    return list(base[:keep]) + kept_extra + [f"+{omitted} more note(s) omitted"]


def _display_name(label: str) -> str:
    return _JURISDICTION_SUFFIX.sub("", _clean_label(label)).strip()


def _attr(node: Mapping[str, Any], *keys: str) -> str:
    attrs = node.get("attributes") or {}
    return next((str(attrs[k]).strip() for k in keys if attrs.get(k) and str(attrs[k]).strip()), "")


_STATUS_ATTRS = ("status", "company_status", "entity_status", "registration_status")
_ADDRESS_KEYS = ("registered_address", "legal_address", "address", "full_address", "headquarters_address", "hq_address")
_EXCEPTION_ATTRS = (
    "reporting_exception", "reporting_exceptions", "ultimate_parent_exception", "direct_parent_exception",
    "ultimate_parent_reporting_exception", "direct_parent_reporting_exception", "parent_exception",
)
_EXCEPTION_IN_SNIPPET = re.compile(r"\b(?i:reporting_?exception|exception)\s*[=:]\s*([A-Z][A-Z_]{2,})")
_EXCEPTION_CATEGORY = re.compile(r"^[A-Z][A-Z_]{2,}$")
#: GLEIF reporting-exception categories (Level 2: why an entity reports no parent) and what each means.
_EXCEPTION_MEANING: Dict[str, str] = {
    "NO_KNOWN_PERSON": "GLEIF: no known ultimate parent",
    "NON_CONSOLIDATING": "GLEIF: the entity is not consolidated by a parent",
    "NATURAL_PERSONS": "GLEIF: the parent is a natural person or persons",
    "NO_LEI": "GLEIF: the parent has no LEI",
    "BINDING_LEGAL_COMMITMENTS": "GLEIF: parent not reported because of binding legal commitments",
    "LEGAL_OBSTACLES": "GLEIF: parent not reported because of legal obstacles",
    "DISCLOSURE_DETRIMENTAL": "GLEIF: parent not reported because disclosure would be detrimental",
    "DETRIMENT_NOT_EXCLUDED": "GLEIF: parent not reported because detriment cannot be excluded",
    "CONSENT_NOT_OBTAINED": "GLEIF: parent not reported because consent to disclose was not obtained",
    "NON_PUBLIC": "GLEIF: the entity or its parent is not publicly reported (non-public)",
}


def _headquarters(node: Mapping[str, Any]) -> str:
    """``Headquarters: <city>, <country>`` from the node's own ``hq_*`` attributes (never a registered address)."""
    place = ", ".join(part for part in (_attr(node, "hq_city"), _attr(node, "hq_country")) if part)
    return f"Headquarters: {place}" if place else ""


def _exception_categories(value: Any) -> List[str]:
    """Reporting-exception categories in a node attribute: a string, a ``{"category": ...}`` dict or a list of them."""
    if isinstance(value, Mapping):
        return _exception_categories(value.get("category") or value.get("exception") or value.get("code"))
    if isinstance(value, (list, tuple, set)):
        return [c for item in value for c in _exception_categories(item)]
    text = str(value or "").strip().upper().replace(" ", "_")
    return [text] if _EXCEPTION_CATEGORY.match(text) else []


def _reporting_exception_lines(nodes: Sequence[Mapping[str, Any]]) -> List[str]:
    """``Reporting exception: CATEGORY (meaning)`` lines for the exceptions the subject's registry nodes carry.

    Read from the node attributes (and an ``exception=CATEGORY`` field in a receipt snippet). Nothing is guessed: a
    node without such a field yields no line, and an unfamiliar category is printed as given with ``(GLEIF)``.
    """
    found: List[str] = []
    for node in nodes:
        attrs = node.get("attributes") or {}
        for key in _EXCEPTION_ATTRS:
            found += _exception_categories(attrs.get(key))
        for receipt in _receipts(node):
            found += _EXCEPTION_IN_SNIPPET.findall(str(receipt.get("raw_snippet") or ""))
    return [
        f"Reporting exception: {category} ({_EXCEPTION_MEANING.get(category, 'GLEIF')})"
        for category in dict.fromkeys(found)
    ]


def _build_entity_profile(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    ownership_links: Sequence[Mapping[str, Any]],
    relevance: Mapping[str, Tuple[str, str]],
) -> Optional[EntityProfile]:
    """Registry-first profile from the subject's registry nodes (GLEIF level 1, Companies House) only.

    Fills only what the nodes carry. When several registry nodes match the subject, the one with the most fields
    leads and the others fill blanks. ``None`` when no registry node matched the subject.
    """
    candidates: List[Tuple[Mapping[str, Any], str, str]] = []  # (node, registry name, receipt url)
    for node in nodes:
        node_id = str(node.get("id"))
        if relevance.get(node_id, ("", ""))[0] != "subject" or node_id.startswith("psc:"):
            continue
        for receipt in _receipts(node):
            registry = next(
                (name for tool, name in _REGISTRY_RECEIPT_TOOLS if str(receipt.get("tool") or "").startswith(tool)), ""
            )
            if registry:
                candidates.append((node, registry, str(receipt.get("source_url") or "")))
                break
    if not candidates:
        return None

    def filled(node: Mapping[str, Any]) -> int:
        return sum(
            bool(_attr(node, *k)) for k in (("lei",), _STATUS_ATTRS, ("jurisdiction",), _ADDRESS_KEYS)
        ) + bool(_headquarters(node))

    candidates.sort(key=lambda c: -filled(c[0]))  # stable: graph order breaks ties
    ids = {str(c[0].get("id")) for c in candidates}
    nodes_by_id = {str(n.get("id")): n for n in nodes}
    parents: List[str] = []

    def add_parent(name: str) -> None:
        clean = _display_name(name)
        if clean and clean not in parents:
            parents.append(clean)

    for edge in edges:
        relation = str(_val(edge.get("relation")))
        source, target = str(edge.get("source_id")), str(edge.get("target_id"))
        if relation in _PARENT_IS_SOURCE and target in ids and source in nodes_by_id:
            add_parent(str(nodes_by_id[source].get("label") or source))
        elif relation in _PARENT_IS_TARGET and source in ids and target in nodes_by_id:
            add_parent(str(nodes_by_id[target].get("label") or target))
    for raw in ownership_links:
        link = _dict(raw)
        if str(link.get("child_id") or "") in ids and not link.get("is_natural_person"):
            add_parent(str(link.get("parent_name") or ""))

    def pick(*keys: str) -> str:
        return next((v for node, _r, _u in candidates if (v := _attr(node, *keys))), "")

    lead = candidates[0][0]
    sources = list(dict.fromkeys(f"{name}: {url}" if url else name for _n, name, url in candidates))
    for line in _reporting_exception_lines([node for node, _r, _u in candidates]):
        if line not in parents:
            parents.append(line)
    address = pick(*_ADDRESS_KEYS) or next((h for node, _r, _u in candidates if (h := _headquarters(node))), "")
    return EntityProfile(
        legal_name=_attr(lead, "legal_name") or _display_name(str(lead.get("label") or lead.get("id"))),
        lei=pick("lei"), status=pick(*_STATUS_ATTRS), jurisdiction=pick("jurisdiction"),
        registered_address=address, parents=parents, sources=sources,
    )


#: ISO country codes of secrecy jurisdictions; mirrors ``bunnyhole.agents.accountant.OFFSHORE_HAVEN_CODES`` (a test
#: keeps the two in step; the engine does not import the agents).
SECRECY_JURISDICTION_CODES = frozenset({"KY", "VG", "BM", "MU", "CY", "SC", "PA", "MH", "BS", "BZ", "JE", "GG", "IM"})
_JURISDICTION_ATTRS = ("jurisdiction", "legal_jurisdiction", "country", "hq_country", "country_of_incorporation")
_LABEL_COUNTRY = re.compile(r"\(([A-Za-z]{2})(?:-[A-Za-z0-9]+)?\)\s*$")


def _jurisdiction_code(node: Mapping[str, Any]) -> str:
    """Two-letter country code of the node's jurisdiction (``VG`` from ``VG`` or ``VG-xyz`` or a ``(VG)`` label)."""
    for key in _JURISDICTION_ATTRS:
        value = _attr(node, key).upper()
        if value:
            return value.split("-")[0].strip() if len(value.split("-")[0].strip()) == 2 else ""
    found = _LABEL_COUNTRY.search(_clean_label(str(node.get("label") or "")))
    return found.group(1).upper() if found else ""


def _chain_flag_evidence(
    nodes: Sequence[Mapping[str, Any]],
    false_links: Sequence[Mapping[str, str]],
    ownership: OwnershipBlock,
    relevance: Mapping[str, Tuple[str, str]],
) -> List[str]:
    """Nominee or secrecy-jurisdiction evidence: the only thing that justifies the "ends at a nominee or secrecy
    jurisdiction" escalation. Never taken from nodes judged unrelated to the subject.

    * a nominee or secrecy risk flag on a node of the ownership chain;
    * a secrecy-jurisdiction country on an ownership parent (or on the node where the walk ended);
    * a nominee false-link flag (an officer that is a nominee service or serves many entities) anywhere in the block.
    """
    chain = {e.child for e in ownership.edges} | {e.parent for e in ownership.edges}
    chain |= {unresolved_node_id(u) for u in ownership.unresolved}
    parents = {e.parent for e in ownership.edges} | {unresolved_node_id(u) for u in ownership.unresolved}
    evidence: List[str] = []
    for node in nodes:
        node_id = str(node.get("id"))
        if node_id not in chain or relevance.get(node_id, ("", ""))[0] == "unrelated":
            continue
        evidence += [f"{node_id}: {f}" for f in node.get("risk_flags") or []
                     if str(f).startswith("OFFSHORE_SECRECY_JURISDICTION") or "NOMINEE" in str(f).upper()]
        code = _jurisdiction_code(node)
        if node_id in parents and code in SECRECY_JURISDICTION_CODES:
            evidence.append(f"{node_id}: ownership parent registered in secrecy jurisdiction {code}")
    for flag in false_links:
        if "nominee" in flag["reason"].lower() and relevance.get(flag["node_id"], ("", ""))[0] != "unrelated":
            evidence.append(f"{flag['node_id']}: {flag['reason']}")
    return list(dict.fromkeys(evidence))


def _public_listed_ids(nodes: Sequence[Mapping[str, Any]], relevance: Mapping[str, Tuple[str, str]]) -> List[str]:
    """Nodes that are publicly listed registrants (SEC receipt, ticker/exchange/CIK): shareholders are dispersed."""
    listed: List[str] = []
    for node in nodes:
        node_id = str(node.get("id"))
        if relevance.get(node_id, ("", ""))[0] == "unrelated":
            continue
        if (
            node_id.startswith("cik:")
            or any(str(r.get("tool") or "").startswith("sec_edgar") for r in _receipts(node))
            or _attr(node, *_PUBLIC_LISTING_ATTRS)
        ):
            listed.append(node_id)
    return listed


# ----------------------------------------------------------------------------------------------
# Assembly
# ----------------------------------------------------------------------------------------------


def _custody(nodes: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]) -> List[CustodyEntry]:
    seen: Set[str] = set()
    entries: List[CustodyEntry] = []
    for holder in list(nodes) + list(edges):
        for receipt in _receipts(holder):
            receipt_id = str(receipt.get("receipt_id") or "")
            if not receipt_id or receipt_id in seen:
                continue
            seen.add(receipt_id)
            entries.append(
                CustodyEntry(
                    receipt_id=receipt_id,
                    tool=str(receipt.get("tool") or ""),
                    url=str(receipt.get("source_url") or ""),
                    sha256=str(receipt.get("sha256_proof") or ""),
                    collected_at_utc=str(receipt.get("timestamp") or ""),
                )
            )
    return entries


def assemble_pi_block(
    engagement: PIEngagement,
    graph_dict: Mapping[str, Any],
    source_log: Sequence[SourceLogEntry],
    *,
    cross_case_prior: Sequence[Mapping[str, Any]] = (),
    selectors: Optional[Mapping[str, Sequence[str]]] = None,
    ownership_links: Sequence[Mapping[str, Any]] = (),
    now_iso: Optional[str] = None,
    deep_run: bool = False,
    subject: str = "",
) -> PIBlock:
    """Build the ``result["pi"]`` block from a graph dict (``graph.to_dict()`` shape) and the source log.

    Pure and offline: the ownership walk runs over an in-memory adjacency built from the graph's
    ownership edges plus ``ownership_links`` (dicts with ``child_id``/``parent_id``/``pct``/...). Director
    and officer edges are control, not ownership, and never end a branch of the ownership walk.
    ``now_iso`` pins the clock for freshness (tests); ``deep_run`` says the run used the deep gear (it gates the
    "no corroborated finding" escalation trigger). ``subject`` names what the run is about (relevance is scored
    against it); when blank it is taken from the selectors, then the graph's ``seed_query``. The input engagement
    and graph are not mutated: relevance only labels findings, the JSON keeps every node.
    """
    selectors_map: Dict[str, List[str]] = {k: [str(x) for x in v] for k, v in (selectors or {}).items()}
    engagement = with_objective(engagement)
    nodes = [_dict(n) for n in graph_dict.get("nodes") or []]
    edges = [_dict(e) for e in graph_dict.get("edges") or []]
    timeline = [_dict(t) for t in graph_dict.get("timeline") or []]
    log = list(source_log)

    relevance = _relevance_map(nodes, edges, ownership_links, _subject_names(subject, selectors_map, graph_dict))
    unrelated_ids = {node_id for node_id, (rel, _why) in relevance.items() if rel == "unrelated"}
    sanctions, ignored_listings = sanctions_screening_for(log, nodes, {k: v[0] for k, v in relevance.items()})
    soft_matches = soft_listed_matches(nodes, sanctions)
    for match in soft_matches:  # a listed name carried by another graph entity: tag it, keep it in the 50% rule
        rel, why = relevance.get(match.node_id, ("unknown", ""))
        relevance[match.node_id] = (rel, f"{why}; {SOFT_LISTED_TAG}: '{match.entry}' ({match.list_name})".lstrip("; "))
    if soft_matches:
        sanctions = sanctions.model_copy(update={"hits": sanctions.hits + [soft_match_hit(m) for m in soft_matches]})
    soft_ids = {m.node_id for m in soft_matches}

    findings = _build_findings(nodes, edges, timeline, now_iso, relevance)
    ownership = _build_ownership(nodes, edges, ownership_links, soft_ids)
    false_links = _build_false_link_flags(nodes, edges, selectors_map, engagement.subject_is_person, relevance)
    contradictions = detect_contradictions(timeline)
    labels = {str(n.get("id")): _display_name(str(n.get("label") or n.get("id"))) for n in nodes}
    gaps = find_gaps(timeline, skip_node_ids=unrelated_ids, drop_events_about=unrelated_ids, node_labels=labels)
    registered_agent = any("registered-agent" in f["reason"] or "registered agent" in f["reason"] for f in false_links)
    custodians = custodians_for(_infer_finding_kinds(nodes, edges, registered_agent), engagement.jurisdiction)
    entity_profile = _build_entity_profile(nodes, edges, ownership_links, relevance)
    # a source counts as a coverage "hit" only when it produced a record about the subject
    coverage_log = downgrade_unrelated_hits(log, nodes, {k: v[0] for k, v in relevance.items()}, SOURCE_RECEIPT_TOOLS)
    # falsifier leads: the Bottom line's population (subject or related). With no subject name every finding is
    # "unknown" (nothing could be judged), and then all of them are kept rather than none.
    judged = any(f.relevance != "unknown" for f in findings)
    about_subject = [f for f in findings if f.relevance in ("subject", "related")] if judged else findings

    identifiers: Dict[str, List[str]] = {k: v for k, v in selectors_map.items() if v}
    addresses = _handoff_addresses(nodes)
    if addresses:
        identifiers["addresses"] = addresses

    playbook = playbook_for(engagement.case_type)
    identity_notes = identity_notes_for(nodes, selectors_map, engagement.subject_is_person)
    identity_notes = _merge_notes(
        identity_notes, _collision_notes(relevance) + [soft_match_note(m) for m in soft_matches[:_MAX_SOFT_NOTES]]
    )
    listed_ids = sorted(
        (
            _listed_ids(nodes) | soft_ids
            | {str(n.get("id")) for n in nodes if "POLITICALLY_EXPOSED_PERSON_PEP" in (n.get("risk_flags") or [])}
        )
        - unrelated_ids
    )
    escalation_ctx = _EscalationContext(
        findings=findings, ownership=ownership, custodians=custodians, contradictions=contradictions,
        identity_notes=identity_notes, listed_ids=listed_ids, deep_run=deep_run,
        subject_is_person=engagement.subject_is_person, sanctions=sanctions,
        ownership_flags=_chain_flag_evidence(nodes, false_links, ownership, relevance),
        public_listed_ids=_public_listed_ids(nodes, relevance),
    )

    return PIBlock(
        engagement=engagement,
        identifier_warnings=identifier_warnings(selectors_map, engagement.subject_is_person),
        prior_cases=[dict(p) for p in cross_case_prior],
        source_log=coverage_log,
        findings=findings,
        ownership=ownership,
        false_link_flags=false_links,
        contradictions=contradictions,
        evidence_gaps=gaps,
        coverage=build_coverage(engagement.case_type, engagement.subject_is_person, coverage_log, SOURCE_CLASS_MAP),
        falsifiers=falsifiers_for(
            engagement.case_type, about_subject, contradictions, ownership,
            collapse_leads_above=1, unrelated_node_ids=unrelated_ids,
        ),
        custodians=custodians,
        handoff_sheet=handoff_sheet(
            engagement, identifiers, custodians, sanctions=sanctions, entity_profile=entity_profile
        ),
        custody=_custody(nodes, edges),
        notices=list(NOTICES) + ignored_listings,
        identity_notes=identity_notes,
        done_when=playbook.done_when,
        playbook_progress=playbook_progress_for(playbook, log),
        escalation_triggers=escalation_triggers_for(playbook, escalation_ctx),
        entity_profile=entity_profile,
        sanctions=sanctions,
    )


__all__ = [
    "BREACH_SKIP_REASON",
    "CREDENTIAL_SKIP_REASON",
    "ESCALATION_EVALUATORS",
    "MAX_IDENTITY_NOTES",
    "MAX_RECORDS_PER_NAME_GROUP",
    "PIRunRecorder",
    "PLAYBOOK_SOURCE_MAP",
    "REDACTED_CREDENTIAL",
    "SOURCE_CLASS_MAP",
    "SOURCE_RECEIPT_TOOLS",
    "SUBJECT_NOT_ANCHORED_NOTE",
    "assemble_pi_block",
    "escalation_triggers_for",
    "identity_notes_for",
    "make_breach_blocker",
    "make_holehe_blocker",
    "playbook_progress_for",
    "redact_value",
    "run_conflict_check",
    "scrub_credential_text",
    "selectors_from_seeds",
    "strip_packet_credentials",
    "with_objective",
]
