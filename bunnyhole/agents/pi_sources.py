"""PI-stream network sources: Companies House PSC, official sanctions lists (GAC SEMA, OFAC SDN, UN, UK), CFPB, Wikidata.

These are the free, public sources the private-investigator workflow adds on top of the existing
agents. They follow the conventions of ``AccountantAgent.investigate_opensanctions``:

* every HTTP client is built through ``netutil.new_async_client`` so ``--tor`` / ``--proxy`` apply;
* a source that cannot run (missing key, access denied, HTTP error, timeout, bad payload) logs an
  agent event and returns a clean negative, and **never raises**;
* a name match to the target is a *soft* match (``SelectorStrength.SOFT``, edge confidence <= 0.55)
  flagged for human verification, never auto-confirmed;
* the receipt carries the Admiralty rating of the *source* (B2: a registry or an official list); the
  edge to the investigation target carries the weaker rating of the *match* (B3).
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import xml.etree.ElementTree as ET  # noqa: F401  (re-exported: tests patch ``pi_sources.ET``)
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Sequence, Tuple

import httpx

from bunnyhole.agents import sanctions_lists
from bunnyhole.agents.accountant import sec_user_agent
from bunnyhole.agents.pi_source_records import (  # noqa: F401  (re-exported with the names they always had here)
    _CH_SHARES_BAND,
    CFPB_API_URL,
    CH_API_BASE,
    CH_PUBLIC_BASE,
    _ownership_pct,
    _ReferenceRecordsMixin,
    _slug,
)
from bunnyhole.agents.sanctions_lists import (  # noqa: F401  (every name below is re-exported from here)
    _DTD_OVERLAP_CHARS,
    _NAME_NOISE_TOKENS,
    _REDIRECT_STATUSES,
    _SANCTIONS_LISTS,
    _SANCTIONS_MAX_REDIRECTS,
    _SEMA_ALIASES,
    _SEMA_COUNTRY,
    _SEMA_DOB,
    _SEMA_ENTITY,
    _SEMA_GIVEN_NAME,
    _SEMA_IMO,
    _SEMA_ITEM,
    _SEMA_LAST_NAME,
    _SEMA_LISTED,
    _SEMA_SCHEDULE,
    _SEMA_SHIP_TYPE,
    _UK_FIELDS,
    _UN_NAME_PARTS,
    MAX_SANCTIONS_LIST_BYTES,
    MAX_SEMA_BYTES,
    OFAC_SDN_PAGE_URL,
    OFAC_SDN_XML_URL,
    SANCTIONS_CACHE_TTL_S,
    SANCTIONS_LIST_TIMEOUT_S,
    SANCTIONS_RETRY_AFTER_S,
    SEMA_PAGE_URL,
    SEMA_XML_URL,
    UK_SANCTIONS_PAGE_URL,
    UK_SANCTIONS_XML_URL,
    UN_CONSOLIDATED_PAGE_URL,
    UN_CONSOLIDATED_XML_URL,
    SanctionsEnv,
    _build_names,
    _cache_age_s,
    _format_cap,
    _index_xml_file,
    _iso_utc,
    _LoadedSanctionsIndex,
    _local,
    _monotonic_s,
    _parse_ofac_entry,
    _parse_sema_records,
    _parse_uk_designation,
    _parse_un_entry,
    _reject_dtd,
    _SanctionsListSpec,
    _SanctionsRecord,
    _SourceSkip,
    _text,
    _token_sets_match,
    _XmlStreamGuard,
    find_sanctions_matches,
    find_sema_matches,
    names_match,
    normalize_name_tokens,
)
from bunnyhole.arsenal.manager import BUNNYHOLE_CONFIG_DIR
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
)
from bunnyhole.engine.netutil import new_async_client
from bunnyhole.engine.pi_anchoring import judge_listing

WIKIDATA_API_URL = "https://www.wikidata.org/w/api.php"

SEMA_RETRY_AFTER_S = 300.0  # after a failed download, do not hammer the host again for this long
MIN_QUERY_CHARS = 3
MAX_SANCTION_MATCHES = 5

_CH_COMPANY_NUMBER = re.compile(r"^[A-Za-z0-9]{1,12}$")  # never put an unvalidated value in a URL path
_WIKIDATA_QID = re.compile(r"^Q[0-9]{1,12}$")


def sanctions_cache_file(source: str) -> Path:
    """Where the downloaded XML of one list is cached: ``<config dir>/cache/sanctions/<source>.xml``."""
    return sanctions_lists.sanctions_cache_path(BUNNYHOLE_CONFIG_DIR, source)


class PISourcesAgent(_ReferenceRecordsMixin):
    """Free public network sources for the Private Investigator (PI) stream."""

    # Class-level cache: the sanctions list is downloaded at most once per process (plus a retry
    # after a cooldown if the download failed).
    _sema_records: ClassVar[Optional[List[Dict[str, Any]]]] = None
    _sema_failed_at: ClassVar[Optional[float]] = None

    # Official sanctions lists (OFAC SDN, UN, UK): the per-process state lives in ``sanctions_lists``; these are
    # the same dict objects under the names this class has always exposed.
    _sanctions_indexes: ClassVar[Dict[str, _LoadedSanctionsIndex]] = sanctions_lists._SANCTIONS_INDEXES
    _sanctions_failed_at: ClassVar[Dict[str, float]] = sanctions_lists._SANCTIONS_FAILED_AT
    _sanctions_locks: ClassVar[Dict[Tuple[str, int], asyncio.Lock]] = sanctions_lists._SANCTIONS_LOCKS

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.std_headers = {
            # operator-configurable research identity (BUNNYHOLE_SEC_USER_AGENT), shared with the SEC EDGAR client
            "User-Agent": sec_user_agent(),
            "Accept": "application/json",
        }

    @classmethod
    def reset_sema_cache(cls) -> None:
        """Forget the cached sanctions list and any recorded download failure (used by tests)."""
        cls._sema_records = None
        cls._sema_failed_at = None

    @classmethod
    def reset_sanctions_process_index(cls, source: Optional[str] = None) -> None:
        """Forget the in-memory name index of one list (or all), keeping failure state and the disk cache."""
        sanctions_lists.reset_sanctions_process_index(source)

    @classmethod
    def _reset_sanctions_source(cls, source: str) -> None:
        sanctions_lists.reset_sanctions_source(source)

    @classmethod
    def reset_ofac_sdn_cache(cls) -> None:
        """Forget the cached OFAC SDN index and any recorded download failure (used by tests; disk cache kept)."""
        cls._reset_sanctions_source("ofac_sdn")

    @classmethod
    def reset_un_consolidated_cache(cls) -> None:
        """Forget the cached UN consolidated index and any recorded download failure (disk cache kept)."""
        cls._reset_sanctions_source("un_consolidated")

    @classmethod
    def reset_uk_sanctions_cache(cls) -> None:
        """Forget the cached UK Sanctions List index and any recorded download failure (disk cache kept)."""
        cls._reset_sanctions_source("uk_sanctions_list")

    @classmethod
    def reset_sanctions_caches(cls) -> None:
        """Reset all three official-list caches (in-memory only)."""
        sanctions_lists.reset_all_sanctions_sources()

    # ------------------------------------------------------------------------------------------
    # shared helpers
    # ------------------------------------------------------------------------------------------

    def _log(self, action: str, target: str, detail: str, *, level: str = "info", receipts: int = 0) -> None:
        self.graph.log(DomainCategory.FIAT, action, target, detail, receipt_count=receipts, level=level)

    def _skip(self, action: str, target: str, reason: str) -> None:
        self._log(action, target, reason, level="warning")

    @staticmethod
    async def _get_json(client: httpx.AsyncClient, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GET a JSON object or raise _SourceSkip with a human reason. Never returns a non-dict."""
        resp = await client.get(url, params=params)
        if resp.status_code in (401, 403):
            raise _SourceSkip(f"access denied (HTTP {resp.status_code})")
        if resp.status_code == 429:
            raise _SourceSkip("rate limited (HTTP 429)")
        if resp.status_code != 200:
            raise _SourceSkip(f"HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise _SourceSkip("response was not valid JSON") from exc
        if not isinstance(data, dict):
            raise _SourceSkip("unexpected response shape (expected a JSON object)")
        return data

    def _set_aside_weak_listing(
        self, label: str, names: Sequence[str], list_label: str, receipt: EvidenceReceipt
    ) -> bool:
        """PI person subject: True (after recording the candidate) when a list entry is only a weak name match.

        The entry needs the subject's surname and a compatible full name to become a node and an edge; a match on
        given-name tokens only, or a different spelling, is reported as "weak name match, not linked" and never
        feeds a path, broker or predicted link. Without a PI person subject this is always False.
        """
        subject = self.graph.pi_subject
        if subject is None:
            return False
        verdict = judge_listing(subject, names, list_name=list_label)
        if verdict.attach:
            return False
        self.graph.set_aside_candidate(
            DomainCategory.FIAT, "listing", f"{label} ({list_label})", receipt.tool, receipt.source_url, verdict, [receipt]
        )
        return True

    def _link_to_origin(
        self,
        origin_node_id: str,
        node_id: str,
        relation: RelationType,
        admiralty: str,
        confidence: float,
        summary: str,
        receipt: EvidenceReceipt,
    ) -> None:
        if node_id == origin_node_id:
            return
        self.graph.upsert_edge(
            GraphEdge(
                source_id=origin_node_id,
                target_id=node_id,
                relation=relation,
                domain=DomainCategory.FIAT,
                admiralty_code=admiralty,
                confidence=min(confidence, 0.55),  # a name match is never stronger than 0.55
                summary=summary,
                receipts=[receipt],
            )
        )

    # ------------------------------------------------------------------------------------------
    # Companies House: persons with significant control (UK public UBO register)
    # ------------------------------------------------------------------------------------------

    async def investigate_companies_house_psc(
        self, company_name: str, origin_node_id: str, hop_depth: int
    ) -> List[Dict[str, Any]]:
        """Find UK companies by name and list their persons with significant control (PSC).

        Needs a free ``COMPANIES_HOUSE_API_KEY`` (HTTP basic auth: key as username, empty password).
        Without a key this logs a skip and returns ``[]`` with no HTTP call. Company and PSC nodes are
        added with receipts; all are soft name matches to the target (verify). Returns plain dicts
        ``{parent_id, parent_name, pct, is_natural_person, source, as_of, child_id}`` for *current*
        PSCs only (``pct`` is the midpoint of the declared shareholding band, else None). Never raises.
        """
        q = (company_name or "").strip()
        if len(q) < MIN_QUERY_CHARS:
            return []
        # The arsenal key vault stores it as UK_COMPANIES_HOUSE_API_KEY; the short name is accepted too.
        api_key = (
            os.environ.get("UK_COMPANIES_HOUSE_API_KEY", "") or os.environ.get("COMPANIES_HOUSE_API_KEY", "")
        ).strip()
        if not api_key:
            self._skip(
                "UK_PSC_SKIP", q, "UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped."
            )
            return []

        self._log("UK_PSC_SCAN", q, f"Searching Companies House for '{q}' and listing persons with significant control")
        owners: List[Dict[str, Any]] = []
        try:
            async with new_async_client(
                timeout=10.0, headers=self.std_headers, auth=httpx.BasicAuth(api_key, "")
            ) as client:
                data = await self._get_json(
                    client, f"{CH_API_BASE}/search/companies", {"q": q, "items_per_page": 3}
                )
                items = data.get("items") or []
                if not isinstance(items, list) or not items:
                    self._log("UK_PSC_INFO", q, f"Companies House returned no companies matching '{q}'")
                    return []
                for item in items[:3]:
                    if not isinstance(item, dict):
                        continue
                    number = str(item.get("company_number") or "").strip()
                    if not _CH_COMPANY_NUMBER.match(number):
                        continue
                    try:
                        owners.extend(await self._record_company_and_psc(client, item, number, q, origin_node_id, hop_depth))
                    except Exception as exc:
                        self._skip("UK_PSC_SKIP", number, f"PSC lookup failed for company {number}: {exc}")
        except Exception as exc:
            self._skip("UK_PSC_SKIP", q, f"Companies House lookup failed: {type(exc).__name__}: {exc}")
        return owners

    # ------------------------------------------------------------------------------------------
    # Global Affairs Canada: consolidated Canadian autonomous sanctions (SEMA / JVCFOA)
    # ------------------------------------------------------------------------------------------

    async def _load_sema_records(self, target: str) -> Optional[List[Dict[str, Any]]]:
        """Return the parsed sanctions list (downloading once per process), or None after logging a skip."""
        cls = type(self)
        if cls._sema_records is not None:
            return cls._sema_records
        failed_at = cls._sema_failed_at
        if failed_at is not None and time.monotonic() - failed_at < SEMA_RETRY_AFTER_S:
            self._skip("CA_SANCTIONS_SKIP", target, "Canadian sanctions list download failed recently; not retrying yet.")
            return None
        try:
            payload = await self._download_sema()
            _reject_dtd(payload)
            records = _parse_sema_records(payload)
            if not records:
                raise _SourceSkip("the sanctions file contained no records")
        except Exception as exc:
            cls._sema_failed_at = time.monotonic()
            reason = str(exc) if isinstance(exc, _SourceSkip) else f"{type(exc).__name__}: {exc}"
            self._skip("CA_SANCTIONS_SKIP", target, f"Canadian sanctions list unavailable: {reason}")
            return None
        cls._sema_records = records
        cls._sema_failed_at = None
        return records

    async def _download_sema(self) -> bytes:
        return await sanctions_lists.download_sema_xml(new_async_client, self.std_headers, MAX_SEMA_BYTES)

    async def screen_canadian_sanctions(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Screen a name against Canada's consolidated autonomous sanctions list (GAC SEMA XML).

        The XML is downloaded once per process (class-level cache, 10 MB cap) and refused outright if
        it carries a DOCTYPE or ENTITY declaration. Matching is a normalised token-subset name match,
        so every hit is a **soft** match for human verification. The list is published for
        administrative purposes only; UN and OFSI lists are separate. Never raises.
        """
        q = (query or "").strip()
        if len(q) < MIN_QUERY_CHARS:
            return
        self._log("CA_SANCTIONS_SCAN", q, f"Screening Canada's consolidated autonomous sanctions list (GAC SEMA) for '{q}'")
        try:
            records = await self._load_sema_records(q)
            if records is None:
                return
            matches = find_sema_matches(records, q)
            if not matches:
                self._log("CA_SANCTIONS_INFO", q, f"No name match for '{q}' on the Canadian sanctions list (searched {len(records)} entries)")
                return
            for rec in matches[:MAX_SANCTION_MATCHES]:
                self._record_sanction_match(rec, q, origin_node_id, hop_depth)
            if len(matches) > MAX_SANCTION_MATCHES:
                self._log(
                    "CA_SANCTIONS_INFO", q,
                    f"{len(matches)} soft matches; recorded the first {MAX_SANCTION_MATCHES}. Narrow the name to verify.",
                )  # fmt: skip
        except Exception as exc:
            self._skip("CA_SANCTIONS_SKIP", q, f"Canadian sanctions screen failed: {type(exc).__name__}: {exc}")

    def _record_sanction_match(self, rec: Dict[str, Any], query: str, origin_node_id: str, hop_depth: int) -> None:
        kind = rec["kind"]
        entity_type = {"person": EntityType.PERSON, "ship": EntityType.VESSEL}.get(kind, EntityType.ORGANIZATION)
        ftm_schema = {"person": "Person", "ship": "Vessel"}.get(kind, "Organization")
        node_id = f"sanction:ca:{_slug(rec['schedule'], 12)}-{_slug(rec['item'], 8)}-{_slug(rec['name'], 30)}"
        listing = f"Schedule {rec['schedule'] or 'n/a'}, item {rec['item'] or 'n/a'}"
        receipt = EvidenceReceipt(
            tool="gac_sema_sanctions",
            domain=DomainCategory.FIAT,
            admiralty_code="B2",  # official government list; the match to our target is soft
            selector_strength=SelectorStrength.SOFT,
            source_url=SEMA_PAGE_URL,
            extracted_fact=(
                f"Canada's consolidated autonomous sanctions list ({listing}) names '{rec['name']}' ({kind}), "
                f"{rec['country'] or 'country n/a'}, listed {rec['listed'] or 'n/a'}. "
                "Published for administrative purposes only."
            ),
            raw_snippet=(
                f"data={SEMA_XML_URL} | name={rec['name']} | matched_via={rec['matched_name']} | "
                f"aliases={rec['aliases'][:4]} | dob_or_build={rec['dob_or_build']} | imo={rec['imo']}"
            ),
        )
        if self._set_aside_weak_listing(rec["name"], [rec["name"], *rec["aliases"]], "Canada SEMA", receipt):
            return
        self.graph.upsert_node(
            GraphNode(
                id=node_id,
                label=f"⛔ {rec['name']}",
                entity_type=entity_type,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema=ftm_schema,
                smoke_score=85.0,
                risk_flags=["CANADA_SEMA_SANCTIONS_LIST_MATCH", "SOFT_NAME_MATCH_VERIFY"],
                attributes={
                    "country": rec["country"],
                    "schedule": rec["schedule"],
                    "item": rec["item"],
                    "date_of_listing": rec["listed"],
                    "date_of_birth_or_build": rec["dob_or_build"],
                    "aliases": rec["aliases"],
                    "matched_name": rec["matched_name"],
                    "match_query": query,
                },
                receipts=[receipt],
                hop_depth=hop_depth,
            )
        )
        self._link_to_origin(
            origin_node_id, node_id, RelationType.LINKED_IDENTITY, "B3", 0.55,
            "Canadian sanctions list name match (verify)", receipt,
        )  # fmt: skip

    # ------------------------------------------------------------------------------------------
    # Official keyless sanctions lists: OFAC SDN, UN Security Council consolidated, UK Sanctions List
    # ------------------------------------------------------------------------------------------

    def _sanctions_env(self) -> SanctionsEnv:
        """Resolved per call from this module's names, so patching them here keeps steering the loader."""
        return SanctionsEnv(
            log=self._log,
            skip=self._skip,
            config_dir=BUNNYHOLE_CONFIG_DIR,
            max_list_bytes=MAX_SANCTIONS_LIST_BYTES,
            monotonic_s=_monotonic_s,
            client_factory=new_async_client,
            std_headers=self.std_headers,
        )

    async def _load_sanctions_index(self, spec: _SanctionsListSpec, target: str) -> Optional[_LoadedSanctionsIndex]:
        """Return the name index of one list (process cache, then fresh disk cache, then download, then stale
        disk cache), or None after logging a skip. Never raises."""
        return await sanctions_lists.load_sanctions_index(spec, target, self._sanctions_env())

    async def _screen_sanctions_list(
        self, spec: _SanctionsListSpec, query: str, origin_node_id: str, hop_depth: int
    ) -> None:
        q = (query or "").strip()
        if len(q) < MIN_QUERY_CHARS:
            return
        self._log(f"{spec.prefix}_SCAN", q, f"Screening the {spec.label} for '{q}'")
        try:
            loaded = await self._load_sanctions_index(spec, q)
            if loaded is None:
                return
            if loaded.stale_note:
                self._skip(f"{spec.prefix}_SKIP", q, f"{spec.label}: {loaded.stale_note}")
            matches = find_sanctions_matches(loaded.records, q)
            if not matches:
                self._log(
                    f"{spec.prefix}_INFO", q,
                    f"No name match for '{q}' on the {spec.label} (searched {len(loaded.records)} entries)",
                )  # fmt: skip
                return
            for _inexact, rec, matched in matches[:MAX_SANCTION_MATCHES]:
                self._record_list_match(spec, rec, matched, q, origin_node_id, hop_depth)
            if len(matches) > MAX_SANCTION_MATCHES:
                self._log(
                    f"{spec.prefix}_INFO", q,
                    f"{len(matches)} soft matches; recorded the first {MAX_SANCTION_MATCHES}. Narrow the name to verify.",
                )  # fmt: skip
        except Exception as exc:
            self._skip(f"{spec.prefix}_SKIP", q, f"{spec.label} screen failed: {type(exc).__name__}: {exc}")

    def _record_list_match(
        self, spec: _SanctionsListSpec, rec: _SanctionsRecord, matched: str, query: str, origin_node_id: str,
        hop_depth: int,
    ) -> None:  # fmt: skip
        primary = rec.names[0][0]
        aliases = [n for n, _ in rec.names[1:]]
        entity_type = {"person": EntityType.PERSON, "ship": EntityType.VESSEL, "aircraft": EntityType.AIRCRAFT}.get(
            rec.kind, EntityType.ORGANIZATION
        )
        ftm_schema = {"person": "Person", "ship": "Vessel", "aircraft": "Airplane"}.get(rec.kind, "Organization")
        node_id = f"sanction:{spec.id_prefix}:{_slug(rec.list_id, 40)}"
        programs = ", ".join(rec.programs) or "n/a"
        receipt = EvidenceReceipt(
            tool=spec.source,
            domain=DomainCategory.FIAT,
            admiralty_code="B2",  # official government list; the match to our target is soft
            selector_strength=SelectorStrength.SOFT,
            source_url=spec.page_url,
            extracted_fact=(
                f"The {spec.label} (id {rec.list_id}; {spec.program_label}: {programs}) names '{primary}' "
                f"({rec.kind})" + (f", listed {rec.listed}" if rec.listed else "") + ". Name match only; verify identifiers."
            ),
            raw_snippet=(
                f"data={spec.xml_url} | id={rec.list_id} | name={primary} | matched_via={matched} | "
                f"aliases={aliases[:4]} | {spec.program_label}={programs}" + (f" | {rec.extra}" if rec.extra else "")
            ),
        )
        if self._set_aside_weak_listing(primary, [primary, *aliases], spec.label, receipt):
            return
        self.graph.upsert_node(
            GraphNode(
                id=node_id,
                label=f"⛔ {primary}",
                entity_type=entity_type,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT,
                ftm_schema=ftm_schema,
                smoke_score=85.0,
                risk_flags=[
                    f"{spec.prefix}_LIST_MATCH",
                    "OFAC_EU_UN_SANCTIONS_LIST_MATCH",  # the generic listing flag the PI runtime already reads
                    "SOFT_NAME_MATCH_VERIFY",
                ],
                attributes={
                    "list": spec.source,
                    "list_id": rec.list_id,
                    "list_name": primary,
                    "kind": rec.kind,
                    "programs": list(rec.programs),
                    "date_listed": rec.listed,
                    "aliases": aliases[:8],
                    "matched_name": matched,
                    "match_query": query,
                },
                receipts=[receipt],
                hop_depth=hop_depth,
            )
        )
        self._link_to_origin(
            origin_node_id, node_id, RelationType.LINKED_IDENTITY, "B3", 0.55,
            f"{spec.label} name match (verify)", receipt,
        )  # fmt: skip

    async def screen_ofac_sdn(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Screen a name against the OFAC Specially Designated Nationals list (US Treasury, keyless XML).

        Stream-parsed (<= 40 MB, DOCTYPE/ENTITY refused), cached in memory and on disk for 24 h. Soft name
        matches only. Names only: confirm with identifiers on the OFAC search page. Never raises.
        """
        await self._screen_sanctions_list(_SANCTIONS_LISTS["ofac_sdn"], query, origin_node_id, hop_depth)

    async def screen_un_consolidated(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Screen a name against the UN Security Council consolidated sanctions list (keyless XML).

        Same download, cache and refusal rules as :meth:`screen_ofac_sdn`. Never raises.
        """
        await self._screen_sanctions_list(_SANCTIONS_LISTS["un_consolidated"], query, origin_node_id, hop_depth)

    async def screen_uk_sanctions_list(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Screen a name against the UK Sanctions List (FCDO, keyless XML; replaced the OFSI consolidated list).

        Same download, cache and refusal rules as :meth:`screen_ofac_sdn`. Never raises.
        """
        await self._screen_sanctions_list(_SANCTIONS_LISTS["uk_sanctions_list"], query, origin_node_id, hop_depth)

    # ------------------------------------------------------------------------------------------
    # CFPB consumer complaints
    # ------------------------------------------------------------------------------------------

    async def investigate_cfpb_complaints(self, company: str, origin_node_id: str, hop_depth: int) -> None:
        """Summarise CFPB consumer complaints naming a company (keyless, US financial firms).

        Complaint text is an unverified consumer claim, so a hit is a pattern-of-conduct note flagged
        ``UNVERIFIED_CONSUMER_CLAIMS``, never a finding. Only sampled hits whose ``company`` field
        matches the query are attributed to the target. Never raises.
        """
        q = (company or "").strip()
        if len(q) < MIN_QUERY_CHARS:
            return
        self._log("CFPB_COMPLAINTS_SCAN", q, f"Searching the CFPB consumer complaint database for '{q}'")
        try:
            async with new_async_client(timeout=10.0, headers=self.std_headers) as client:
                data = await self._get_json(
                    client, CFPB_API_URL, {"search_term": q, "size": 5, "no_aggs": "true"}
                )
            hits_block = data.get("hits")
            if not isinstance(hits_block, dict):
                raise _SourceSkip("unexpected response shape (no hits object)")
            total_raw = hits_block.get("total")
            total = int(total_raw.get("value", 0) if isinstance(total_raw, dict) else (total_raw or 0))
            sources = [
                h["_source"]
                for h in (hits_block.get("hits") or [])
                if isinstance(h, dict) and isinstance(h.get("_source"), dict)
            ]
            ours = [s for s in sources if names_match(q, str(s.get("company") or ""), allow_single_token=True)]
            if not ours:
                self._log(
                    "CFPB_COMPLAINTS_INFO", q,
                    f"No CFPB complaints attributed to '{q}' ({total} full-text hits; none of the {len(sources)} sampled name this company)",
                )  # fmt: skip
                return
            self._record_cfpb_summary(q, total, len(sources), ours, origin_node_id, hop_depth)
        except Exception as exc:
            self._skip("CFPB_COMPLAINTS_SKIP", q, f"CFPB complaint lookup failed: {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------------------------------
    # Wikidata
    # ------------------------------------------------------------------------------------------

    async def investigate_wikidata_entity(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Look up candidate Wikidata entities for a name (QID, description, URL).

        An entity-resolution aid only: Wikidata is community-edited, so every record is rated no higher
        than C3 and flagged to be verified against the primary registry. Never raises.
        """
        q = (query or "").strip()
        if len(q) < MIN_QUERY_CHARS:
            return
        self._log("WIKIDATA_SCAN", q, f"Searching Wikidata for entities named '{q}' (entity-resolution aid)")
        try:
            async with new_async_client(timeout=10.0, headers=self.std_headers) as client:
                data = await self._get_json(
                    client,
                    WIKIDATA_API_URL,
                    {"action": "wbsearchentities", "search": q, "language": "en", "format": "json", "limit": 3},
                )
            if "error" in data:
                raise _SourceSkip("Wikidata API returned an error object")
            results = data.get("search") or []
            if not isinstance(results, list):
                raise _SourceSkip("unexpected response shape (search is not a list)")
            recorded = 0
            for rec in results[:3]:
                if not isinstance(rec, dict):
                    continue
                qid = str(rec.get("id") or "")
                if not _WIKIDATA_QID.match(qid):
                    continue
                self._record_wikidata_entity(rec, qid, q, origin_node_id, hop_depth)
                recorded += 1
            if not recorded:
                self._log("WIKIDATA_INFO", q, f"Wikidata has no entity matching '{q}'")
        except Exception as exc:
            self._skip("WIKIDATA_SKIP", q, f"Wikidata lookup failed: {type(exc).__name__}: {exc}")
