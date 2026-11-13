"""A scripted public record for the casework tests: fake sources that write to the graph the way the agents do.

``CaseWorld.install`` replaces the source coroutines on a ``fake_orchestrator`` with ones that read a small,
fictional registry: a UK trading company, its Dutch parent, and a Cypriot nominee company at the top. Nothing
here touches the network, and every name is invented. Not collected by pytest (no ``test_`` prefix).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    Lead,
    RelationType,
    SelectorStrength,
)
from bunnyhole.engine.pi import CaseType, PIEngagement
from bunnyhole.engine.pi_casework_guide import DeterministicGuide

SUBJECT = "Northgate Trading Ltd"

#: name key -> registry record. ``parent`` is the key of the owner one level up.
COMPANIES: Dict[str, Dict[str, Any]] = {
    "northgate trading": {
        "lei": "213800NORTHGATE00001", "name": "NORTHGATE TRADING LTD", "jurisdiction": "GB", "status": "ACTIVE",
        "address": "12 Dock Road, Hull, GB", "parent": "borealis holdings", "uk_number": "09876543",
    },
    "borealis holdings": {
        "lei": "724500BOREALIS000002", "name": "Borealis Holdings B.V.", "jurisdiction": "NL", "status": "ACTIVE",
        "address": "Keizersgracht 100, Amsterdam, NL", "parent": "kestrel nominees",
    },
    "kestrel nominees": {
        "lei": "549300KESTREL0000003", "name": "Kestrel Nominees Ltd", "jurisdiction": "CY", "status": "ACTIVE",
        "address": "5 Makarios Avenue, Nicosia, CY", "parent": None,
    },
}

_FORMS = re.compile(r"\b(ltd|limited|b\.?v\.?|inc|llc|plc)\b\.?", re.IGNORECASE)


def _key(name: str) -> str:
    return " ".join(_FORMS.sub(" ", name).casefold().replace(".", " ").split())


def _receipt(tool: str, url: str, fact: str) -> EvidenceReceipt:
    return EvidenceReceipt(
        tool=tool, domain=DomainCategory.FIAT, admiralty_code="A1", selector_strength=SelectorStrength.STRONG,
        source_url=url, extracted_fact=fact, raw_snippet=fact,
    )


class CaseWorld:
    """Scripted sources. ``sanctioned`` names hit on OFAC; ``psc_key`` turns the Companies House source on."""

    def __init__(
        self, orch: Any, *, sanctioned: Iterable[str] = (), psc_key: bool = False, with_news: bool = True,
        calls: Optional[List[tuple]] = None,
    ) -> None:
        self.orch = orch
        self.graph = orch.graph
        self.sanctioned: Set[str] = {_key(name) for name in sanctioned}
        self.psc_key = psc_key
        self.with_news = with_news
        self.calls: List[tuple] = calls if calls is not None else []

    # -- registry -----------------------------------------------------------------------------

    def _company_node(self, record: Dict[str, Any], tool: str, hop: int) -> str:
        node_id = f"lei:{record['lei']}"
        haven = record["jurisdiction"] == "CY"
        self.graph.upsert_node(GraphNode(
            id=node_id, label=f"🏛️ {record['name']} ({record['jurisdiction']})",
            entity_type=EntityType.SHELL_COMPANY if haven else EntityType.ORGANIZATION,
            domain=DomainCategory.FIAT, selector_strength=SelectorStrength.STRONG, ftm_schema="Company",
            risk_flags=["GLEIF_LEI_VERIFIED"] + (["OFFSHORE_SECRECY_JURISDICTION_CY"] if haven else []),
            attributes={
                "lei": record["lei"], "legal_name": record["name"], "jurisdiction": record["jurisdiction"],
                "status": record["status"], "registered_address": record["address"],
            },
            receipts=[_receipt(
                tool, f"https://search.gleif.org/#/record/{record['lei']}",
                f"LEI {record['lei']}: '{record['name']}' incorporated in {record['jurisdiction']} "
                f"(Status: {record['status']})",
            )],
            hop_depth=hop,
        ))
        return node_id

    async def gleif(self, value: str, origin: str, hop: int) -> None:
        self.calls.append(("gleif", value, origin))
        record = COMPANIES.get(_key(value))
        if record is None:
            self.graph.log(DomainCategory.FIAT, "GLEIF_INFO", value, "no LEI record matched")
            return
        node_id = self._company_node(record, "gleif_level1_level2_api", hop)
        if node_id != origin:
            self.graph.upsert_edge(GraphEdge(
                source_id=origin, target_id=node_id, relation=RelationType.LINKED_IDENTITY,
                domain=DomainCategory.FIAT, admiralty_code="A1", confidence=0.95, summary="LEI record",
                receipts=self.graph.nodes[node_id].receipts[:1],
            ))
        parent = COMPANIES.get(record["parent"] or "")
        if parent is None:
            return
        parent_id = self._company_node(parent, "gleif_level2_ultimate_parent", hop + 1)
        receipt = _receipt(
            "gleif_level2_ultimate_parent", f"https://search.gleif.org/#/record/{parent['lei']}",
            f"GLEIF Level-2 parent of '{record['name']}' is '{parent['name']}'",
        )
        self.graph.upsert_edge(GraphEdge(
            source_id=parent_id, target_id=node_id, relation=RelationType.ULTIMATE_PARENT_OF,
            domain=DomainCategory.FIAT, admiralty_code="A1", confidence=0.99, summary="GLEIF Level-2 parent",
            receipts=[receipt],
        ))
        self.graph.add_lead(Lead(
            seed_value=parent["name"], lead_type="company", selector_strength=SelectorStrength.STRONG,
            target_agent=DomainCategory.FIAT, priority_score=78.0,
            reason=f"Ultimate Parent of {record['name']} discovered via GLEIF Level-2",
            origin_node_id=parent_id, hop_depth=hop + 1,
        ))

    async def companies_house(self, value: str, origin: str, hop: int) -> List[Dict[str, Any]]:
        self.calls.append(("uk_psc", value, origin))
        if not self.psc_key:
            self.graph.log(
                DomainCategory.FIAT, "UK_PSC_SKIP", value,
                "UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.",
            )
            return []
        record = COMPANIES.get(_key(value))
        if record is None or not record.get("uk_number"):
            self.graph.log(DomainCategory.FIAT, "UK_PSC_INFO", value, "no company matched")
            return []
        number = record["uk_number"]
        company_id = f"company:uk:{number}"
        url = f"https://find-and-update.company-information.service.gov.uk/company/{number}"
        self.graph.upsert_node(GraphNode(
            id=company_id, label=record["name"], entity_type=EntityType.ORGANIZATION, domain=DomainCategory.FIAT,
            selector_strength=SelectorStrength.SOFT, ftm_schema="Company",
            attributes={"company_number": number, "company_status": "active"},
            receipts=[_receipt("companies_house", url, f"Companies House lists '{record['name']}' ({number})")],
            hop_depth=hop,
        ))
        self.graph.upsert_edge(GraphEdge(
            source_id=origin, target_id=company_id, relation=RelationType.LINKED_IDENTITY,
            domain=DomainCategory.FIAT, admiralty_code="B3", confidence=0.55, summary="name match",
            receipts=self.graph.nodes[company_id].receipts[:1],
        ))
        psc_id = f"psc:uk:{number}:marta_ilves"
        receipt = _receipt("companies_house", url + "/persons-with-significant-control", "PSC register lists 'Marta Ilves'")
        self.graph.upsert_node(GraphNode(
            id=psc_id, label="Marta Ilves", entity_type=EntityType.PERSON, domain=DomainCategory.FIAT,
            selector_strength=SelectorStrength.SOFT, ftm_schema="Person",
            attributes={"ownership_pct_midpoint": 87.5, "company_number": number}, receipts=[receipt],
            hop_depth=hop + 1,
        ))
        self.graph.upsert_edge(GraphEdge(
            source_id=psc_id, target_id=company_id, relation=RelationType.OWNS, domain=DomainCategory.FIAT,
            admiralty_code="B3", confidence=0.55, summary="PSC", receipts=[receipt],
        ))
        return [{
            "parent_id": psc_id, "parent_name": "Marta Ilves", "pct": 87.5, "is_natural_person": True,
            "source": url, "as_of": "2024-03-01", "child_id": company_id,
        }]

    # -- screening and the rest ---------------------------------------------------------------

    def _screen(self, source: str):
        async def run(value: str, origin: str, hop: int) -> None:
            self.calls.append((source, value, origin))
            if source != "ofac_sdn" or _key(value) not in self.sanctioned:
                return
            node_id = f"sanction:ofac:{_key(value).replace(' ', '-')}"
            self.graph.upsert_node(GraphNode(
                id=node_id, label=f"⛔ {value}", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.SOFT, ftm_schema="Organization",
                risk_flags=["OFAC_SDN_LIST_MATCH", "OFAC_EU_UN_SANCTIONS_LIST_MATCH", "SOFT_NAME_MATCH_VERIFY"],
                attributes={"list": "ofac_sdn", "list_name": value, "matched_name": value, "match_query": value},
                receipts=[EvidenceReceipt(
                    tool="ofac_sdn", domain=DomainCategory.FIAT, admiralty_code="B2",
                    selector_strength=SelectorStrength.SOFT,
                    source_url="https://sanctionssearch.ofac.treas.gov/",
                    extracted_fact=f"The OFAC SDN list names '{value}'. Name match only; verify identifiers.",
                )],
                hop_depth=hop,
            ))
            self.graph.upsert_edge(GraphEdge(
                source_id=origin, target_id=node_id, relation=RelationType.LINKED_IDENTITY,
                domain=DomainCategory.FIAT, admiralty_code="B3", confidence=0.55, summary="OFAC name match (verify)",
                receipts=self.graph.nodes[node_id].receipts[:1],
            ))

        return run

    async def opensanctions(self, value: str, origin: str, hop: int) -> None:
        self.calls.append(("opensanctions", value, origin))
        self.graph.log(
            DomainCategory.FIAT, "SANCTIONS_PEP_SKIP", value,
            "OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.",
        )

    async def court_dockets(self, value: str, origin: str, hop: int) -> None:
        self.calls.append(("court_dockets", value, origin))
        self.graph.log(
            DomainCategory.JOURNALISM, "COURT_DOCKET_SKIP", value, "COURTLISTENER_API_TOKEN not set; docket search skipped.",
        )

    async def news(self, value: str, origin: str, hop: int) -> None:
        self.calls.append(("news_narrative", value, origin))
        if not self.with_news or _key(value) != _key(SUBJECT):
            return
        node_id = "article:northgate-trading-wins-port-contract"
        self.graph.upsert_node(GraphNode(
            id=node_id, label="📰 Northgate Trading Ltd wins Humber port logistics contract",
            entity_type=EntityType.NEWS_ARTICLE, domain=DomainCategory.JOURNALISM,
            selector_strength=SelectorStrength.SOFT,
            receipts=[EvidenceReceipt(
                tool="google_news_rss", domain=DomainCategory.JOURNALISM, admiralty_code="C3",
                source_url="https://news.example.test/northgate-port-contract",
                extracted_fact="Trade press: Northgate Trading Ltd wins Humber port logistics contract",
            )],
            hop_depth=hop,
        ))
        self.graph.upsert_edge(GraphEdge(
            source_id=origin, target_id=node_id, relation=RelationType.MENTIONED_IN, domain=DomainCategory.JOURNALISM,
            admiralty_code="C3", confidence=0.5, summary="press mention",
            receipts=self.graph.nodes[node_id].receipts[:1],
        ))

    def _quiet(self, source: str):
        async def run(value: str, origin: str, hop: int) -> None:
            self.calls.append((source, value, origin))

        return run

    def install(self) -> "CaseWorld":
        orch = self.orch
        orch.accountant.investigate_gleif_corporate_hierarchy = self.gleif
        orch.accountant.investigate_opensanctions = self.opensanctions
        orch.accountant.investigate_sec_edgar = self._quiet("sec_edgar")
        orch.accountant.investigate_nonprofit_990s_and_usaspending = self._quiet("nonprofit_990s")
        orch.journalist.investigate_news_and_narrative = self.news
        orch.journalist.investigate_court_dockets = self.court_dockets
        orch.journalist.investigate_wayback_ghost_edits = self._quiet("wayback")
        orch.pi_sources.investigate_companies_house_psc = self.companies_house
        orch.pi_sources.screen_canadian_sanctions = self._screen("ca_sanctions")
        orch.pi_sources.screen_ofac_sdn = self._screen("ofac_sdn")
        orch.pi_sources.screen_un_consolidated = self._screen("un_consolidated")
        orch.pi_sources.screen_uk_sanctions_list = self._screen("uk_sanctions_list")
        orch.pi_sources.investigate_cfpb_complaints = self._quiet("cfpb_complaints")
        orch.pi_sources.investigate_wikidata_entity = self._quiet("wikidata")
        orch.osint.investigate_domain_infrastructure = self._quiet("osint_domain")
        return self


def engagement(**overrides: Any) -> PIEngagement:
    """An entity due-diligence engagement with a fixed id and clock, so two runs dump the same case file."""
    payload: Dict[str, Any] = {
        "engagement_id": "pi_case_world",
        "case_type": CaseType.DUE_DILIGENCE,
        "purpose": "Counterparty review before a supply contract.",
        "purpose_category": "counterparty_due_diligence",
        "objective": "",
        "client": "",
        "matter_ref": "",
        "jurisdiction": "ca-on",
        "subject_is_person": False,
        "passive_only": True,
        "created_at_utc": "2026-01-01T00:00:00+00:00",
    }
    payload.update(overrides)
    return PIEngagement.model_construct(**payload)


def run_case(
    *, guide: Any = None, budget: int = 120, seeds: Optional[List[Tuple[str, str]]] = None,
    engagement_overrides: Optional[Dict[str, Any]] = None, **world: Any,
) -> Tuple[Any, "CaseWorld"]:
    """Open and work a case in the scripted world. Returns the orchestrator and the world (with its call log)."""
    from pi_helpers import fake_orchestrator

    orch = fake_orchestrator(
        engagement(**(engagement_overrides or {})), pi_loop="casework", pi_budget=budget,
        pi_guide=guide or DeterministicGuide(),
    )
    orch.seed_query = SUBJECT
    orch.graph.seed_query = SUBJECT
    orch._pi_clock = lambda: 0.0
    scripted = CaseWorld(orch, **world).install()
    roots = []
    for lead_type, value in seeds or [("company", SUBJECT)]:
        _kind, node = orch._create_seed_node(value, forced_type=lead_type)
        roots.append((lead_type, value, node))
    orch._pi_start_case([(lead_type, value) for lead_type, value, _node in roots])
    asyncio.run(orch._run_pi_casework(roots))
    return orch, scripted
