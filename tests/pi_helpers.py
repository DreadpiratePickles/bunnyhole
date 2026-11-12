"""Shared builders and fakes for the PI-stream tests (``tests/test_pi_*.py``).

Each helper was duplicated, byte for byte or with one small difference, across the version-numbered PI test files
that were consolidated on 2026-11-09. Where the copies differed, the difference is an explicit optional parameter
and every caller passes what its original copy did, so no test changed behaviour.

Test modules import these under their old local names (``from pi_helpers import run_cli as _run``), so the test
bodies themselves are unchanged. Import with a bare ``import pi_helpers`` / ``from pi_helpers import ...``:
``tests/conftest.py`` puts this directory on ``sys.path`` for both pytest import modes. (There is deliberately no
``tests`` package: a dependency installs its own top-level ``tests`` package into site-packages.)

Not collected by pytest (no ``test_`` prefix).
"""

from __future__ import annotations

import asyncio
import re
import types
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple
from unittest.mock import AsyncMock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.agents.pi_sources import PISourcesAgent
from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import netutil
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, EvidenceReceipt, GraphNode, SelectorStrength
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.pi import CaseType, Finding, PIBlock, PIEngagement, SourceLogEntry
from bunnyhole.engine.profile import InvestigatorProfile

# ==============================================================================================================
# CLI: a recording fake orchestrator, a default profile and a wide console (test_pi_cli*.py)
# ==============================================================================================================

runner = CliRunner()


def run_cli(*args: str) -> Any:
    """Invoke the ``bunnyhole`` Typer app with ``args``."""
    return runner.invoke(cli_main.app, list(args))


class FakeOrchestrator:
    """Records constructor kwargs (in ``instances``); returns a minimal result with no PI block."""

    instances: List["FakeOrchestrator"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.graph = types.SimpleNamespace(export_markdown_dossier=lambda: "# dossier")
        type(self).instances.append(self)

    def _result(self) -> Dict[str, Any]:
        return {"case_id": "bh_fake", "stats": {}, "nodes": []}

    async def run_investigation(self) -> Dict[str, Any]:
        return self._result()

    async def run_intake_investigation(self, packet: Any) -> Dict[str, Any]:
        self.packet = packet
        return self._result()


class FakePIOrchestrator(FakeOrchestrator):
    """Records constructor kwargs; returns a minimal result carrying a PI block when an engagement is set."""

    instances: List["FakeOrchestrator"] = []

    def _result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "case_id": "bh_fake01",
            "seed_query": self.kwargs.get("seed_query", ""),
            "stats": {"total_nodes": 0, "total_edges": 0, "total_receipts": 0, "cutout_brokers": 0},
            "ach_assessment": {},
            "deep_research": {"gear": "deep", "initial_breadth": 4, "max_depth": 3},
            "interconnections": {},
            "nodes": [],
        }
        engagement: Optional[PIEngagement] = self.kwargs.get("engagement")
        if engagement is not None:
            block = PIBlock(
                engagement=engagement,
                findings=[
                    {"node_id": "a", "label": "A", "finding_label": "confirmed", "source_count": 3},
                    {"node_id": "b", "label": "B", "finding_label": "lead", "source_count": 1},
                ],
                coverage=[
                    {"source_class": "court_dockets", "searched": True, "outcome": "negative"},
                    {"source_class": "crypto_onchain", "searched": False, "outcome": "not_searched"},
                ],
                custodians=[
                    {"finding": "bank", "custodian": "the bank", "instrument": "subpoena", "jurisdiction": "us"}
                ],
            )
            result["pi"] = block.model_dump(mode="json")
        return result


def isolate_cli(
    monkeypatch: pytest.MonkeyPatch, orchestrator: type = FakeOrchestrator, *, stub_render: bool = True
) -> None:
    """Swap in a fake orchestrator, a default saved profile and a 240-column console.

    ``stub_render`` also silences ``_render_investigation_results`` (the input-hardening tests); the core CLI tests
    pass ``stub_render=False`` because they read the rendered output.
    """
    orchestrator.instances = []  # type: ignore[attr-defined]
    monkeypatch.setattr(cli_main, "BunnyholeOrchestrator", orchestrator)
    monkeypatch.setattr(profile_mod, "load_profile", lambda *a, **k: profile_mod.InvestigatorProfile())
    if stub_render:
        monkeypatch.setattr(cli_main, "_render_investigation_results", lambda result: None)
    # Height is set too: a dumb terminal (pytest, CI) makes Rich ignore width unless height is also fixed.
    wide = Console(width=240, height=50)
    monkeypatch.setattr(cli_main, "console", wide)
    monkeypatch.setattr(pi_commands, "console", wide)


# ==============================================================================================================
# Report: engagement/block builders and Markdown readers (test_pi_report*.py)
# ==============================================================================================================

# The entity due-diligence engagement of the live Rosneft/Bombardier reports.
REPORT_ENGAGEMENT: Mapping[str, Any] = {
    "engagement_id": "pi_74e9482909",
    "case_type": CaseType.DUE_DILIGENCE,
    "purpose": "Counterparty due diligence ahead of a supply contract",
    "subject_is_person": False,
    "created_at_utc": "2026-11-09T07:48:55+00:00",
}


def report_engagement(defaults: Mapping[str, Any] = REPORT_ENGAGEMENT, **overrides: Any) -> PIEngagement:
    """A ``PIEngagement`` built directly (no purpose gates) from ``defaults`` updated with ``overrides``."""
    fields: Dict[str, Any] = dict(defaults)
    fields.update(overrides)
    return PIEngagement(**fields)


def report_block(make_engagement: Callable[[], PIEngagement] = report_engagement, /, **overrides: Any) -> PIBlock:
    """A ``PIBlock`` whose engagement is ``make_engagement()`` unless ``overrides`` sets one."""
    fields: Dict[str, Any] = {"engagement": make_engagement()}
    fields.update(overrides)
    return PIBlock(**fields)


def report_sections(markdown: str) -> Dict[str, str]:
    """Split a report into {H2 heading: body} (body excludes the heading line)."""
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    return {parts[i].strip(): parts[i + 1].strip() for i in range(1, len(parts), 2)}


def unescaped_pipes(line: str) -> int:
    """Number of Markdown table pipes in ``line`` that are not backslash-escaped."""
    return len(re.findall(r"(?<!\\)\|", line))


# ==============================================================================================================
# Runtime: graph builders, plain-dict builders, source log and a fully faked orchestrator (test_pi_runtime*.py)
# ==============================================================================================================

NOW = "2026-11-09T00:00:00+00:00"


def make_graph() -> InvestigationGraph:
    return InvestigationGraph("pi_test", "Acme Holdings Ltd")


def make_receipt(tool: str, url: str, fact: str = "fact") -> EvidenceReceipt:
    return EvidenceReceipt(tool=tool, domain=DomainCategory.FIAT, source_url=url, extracted_fact=fact)


def make_node(node_id: str, label: str = "", etype: EntityType = EntityType.ORGANIZATION, **kw: Any) -> GraphNode:
    return GraphNode(id=node_id, label=label or node_id, entity_type=etype, domain=DomainCategory.FIAT, **kw)


def built_engagement(case_type: CaseType = CaseType.DUE_DILIGENCE, **kw: Any) -> PIEngagement:
    """An engagement built through the purpose gates (``PIEngagement.build``), entity subject by default."""
    kw.setdefault("subject_is_person", False)
    kw.setdefault("purpose_category", "counterparty_due_diligence")
    if kw["subject_is_person"]:
        kw.setdefault("matter_ref", "MSA-2026-114")
    return PIEngagement.build(case_type, "Vet a counterparty before signing a supply contract", **kw)


# plain-dict builders (what compile_full_result hands to assemble_pi_block after to_dict())
def receipt_dict(tool: str, url: str = "", rid: str = "", ts: str = NOW) -> Dict[str, Any]:
    return {
        "receipt_id": rid or f"rcpt_{tool}_{abs(hash(url)) % 10_000}",
        "tool": tool,
        "source_url": url,
        "sha256_proof": "ab" * 32,
        "timestamp": ts,
        "extracted_fact": "f",
    }


def node_dict(node_id: str, etype: str = "Organization", label: str = "", receipts: Optional[list] = None,
              attrs: Optional[dict] = None, flags: Optional[list] = None) -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": label or node_id,
        "entity_type": etype,
        "receipts": receipts or [],
        "attributes": attrs or {},
        "risk_flags": flags or [],
    }


def edge_dict(src: str, rel: str, dst: str, receipts: Optional[list] = None,
              event_date: Optional[str] = None) -> Dict[str, Any]:
    return {
        "id": f"edge_{src}_{rel}_{dst}",
        "source_id": src,
        "target_id": dst,
        "relation": rel,
        "receipts": receipts or [],
        "event_date": event_date,
    }


def source_log(*rows: tuple) -> List[SourceLogEntry]:
    """Source-log entries from ``(source, status, detail)`` rows."""
    return [SourceLogEntry(source=s, target="x", status=st, detail=d, at_utc=NOW) for s, st, d in rows]


def all_five_sanctions_ran() -> List[SourceLogEntry]:
    """A fresh source log in which all five automated sanctions screens ran and came back negative."""
    return source_log(("ca_sanctions", "negative", "ok"), ("opensanctions", "negative", "ok"),
                      ("ofac_sdn", "negative", "ok"), ("un_consolidated", "negative", "ok"),
                      ("uk_sanctions_list", "negative", "ok"))


def findings_by_id(block: PIBlock) -> Dict[str, Finding]:
    return {f.node_id: f for f in block.findings}


class FakeCaseStore:
    def __init__(self) -> None:
        self.queries: List[str] = []

    def search_entity_memory(self, query: str, limit: int = 25) -> List[dict]:
        self.queries.append(query)
        return [{"entity_id": "lei:old", "label": query, "case_id": "bh_prior", "seed_query": query,
                 "sighted_at": "2026-02-02"}]

    def correlate_cross_case_entities(self, graph: Any, *, include_seed_text: bool = True) -> list:
        return []

    def save_case(self, graph: Any, full_result: Any) -> None:
        return None


AGENT_METHODS = {
    "accountant": ["investigate_gleif_corporate_hierarchy", "investigate_opensanctions", "investigate_sec_edgar",
                   "investigate_nonprofit_990s_and_usaspending", "investigate_aircraft_adsb"],
    "journalist": ["investigate_news_and_narrative", "investigate_court_dockets", "investigate_wikipedia_revisions",
                   "investigate_openalex_academic_and_grants", "investigate_hackernews_archive",
                   "investigate_wayback_ghost_edits"],
    "onchain": ["investigate_dexscreener_tokens"],
    "osint": ["investigate_identity_and_handle", "investigate_credential_combo", "investigate_email_pivots",
              "investigate_domain_infrastructure"],
    "pi_sources": ["investigate_companies_house_psc", "screen_canadian_sanctions", "screen_ofac_sdn",
                   "screen_un_consolidated", "screen_uk_sanctions_list", "investigate_cfpb_complaints",
                   "investigate_wikidata_entity"],
    # multi-selector (intake) runs pair the roots and sweep news.google.com + courtlistener.com live
    "link_sleuth": ["verify_interconnection_cooccurrence"],
}


def fake_orchestrator(engagement: Optional[PIEngagement], **kw: Any) -> BunnyholeOrchestrator:
    """A real orchestrator with every agent method, the synthesizer and the council replaced by ``AsyncMock``."""
    orch = BunnyholeOrchestrator(
        "Acme Holdings Ltd", max_depth=1, profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR),
        **({"engagement": engagement} if engagement is not None else {}), **kw,
    )
    orch.case_store = FakeCaseStore()
    for agent_name, methods in AGENT_METHODS.items():
        agent = getattr(orch, agent_name, None)
        if agent is None:
            continue
        for method in methods:
            setattr(agent, method, AsyncMock(return_value=None))
    orch.synthesizer.synthesize_investigation = AsyncMock(return_value={})
    orch.council.run_full_council = AsyncMock(return_value={})
    return orch


# ==============================================================================================================
# Sources: agent + origin node, coroutine runner, graph readers, cache/proxy reset (test_pi_sources_*.py)
# ==============================================================================================================

GAC_HOST = "www.international.gc.ca"
GAC_PATH = (
    "/world-monde/assets/office_docs/international_relations-relations_internationales/sanctions/sema-lmes.xml"
)

# Synthetic GAC SEMA fixture that uses the real element names of the Global Affairs Canada XML.
SEMA_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<data-set xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
\t<record>
\t\t<Country-Pays>Belarus / Bélarus</Country-Pays>
\t\t<LastName-NomDeFamille>Balaba</LastName-NomDeFamille>
\t\t<GivenName-Prenom>Dmitry Vladimirovich</GivenName-Prenom>
\t\t<DateOfBirthOrShipBuildDate-DateDeNaissanceOuDateDeConstructionDuNavire>1972</DateOfBirthOrShipBuildDate-DateDeNaissanceOuDateDeConstructionDuNavire>
\t\t<Schedule-Annexe>1, Part 1</Schedule-Annexe>
\t\t<Item-NumeroDarticle>2</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2020-09-28</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Belarus / Bélarus</Country-Pays>
\t\t<EntityOrShip-EntiteOuNavire>LLC Aktualnye Resheniya Bezopasnosti</EntityOrShip-EntiteOuNavire>
\t\t<Aliases-Alias>Aktualnye Reshenia Security Group</Aliases-Alias>
\t\t<Schedule-Annexe>1, Part 2</Schedule-Annexe>
\t\t<Item-NumeroDarticle>41</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2022-11-17</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Russia / Russie</Country-Pays>
\t\t<LastName-NomDeFamille>Oleksin</LastName-NomDeFamille>
\t\t<GivenName-Prenom>Aleksey</GivenName-Prenom>
\t\t<Aliases-Alias>Aliaksei Aleksin</Aliases-Alias>
\t\t<Schedule-Annexe>1, Part 1</Schedule-Annexe>
\t\t<Item-NumeroDarticle>56</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2021-06-17</DateOfListing-DateDinscription>
\t</record>
\t<record>
\t\t<Country-Pays>Russia / Russie</Country-Pays>
\t\t<EntityOrShip-EntiteOuNavire>SEA STAR</EntityOrShip-EntiteOuNavire>
\t\t<ShipIMONumber-NumeroOMIDuNavire>9999999</ShipIMONumber-NumeroOMIDuNavire>
\t\t<TitleOrShipType-TitreOuTypeDeNavire>Oil tanker</TitleOrShipType-TitreOuTypeDeNavire>
\t\t<Schedule-Annexe>1, Part 2</Schedule-Annexe>
\t\t<Item-NumeroDarticle>99</Item-NumeroDarticle>
\t\t<DateOfListing-DateDinscription>2023-02-24</DateOfListing-DateDinscription>
\t</record>
</data-set>
"""


def agent_with_origin(
    label: str = "Acme Holdings", *, case_id: str = "test_pi_sources"
) -> Tuple[PISourcesAgent, InvestigationGraph, str]:
    """A ``PISourcesAgent`` on a fresh graph holding one soft organisation origin node labelled ``label``."""
    g = InvestigationGraph(case_id, label)
    origin = GraphNode(
        id="org:origin",
        label=label,
        entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.FIAT,
        selector_strength=SelectorStrength.SOFT,
    )
    g.upsert_node(origin)
    return PISourcesAgent(g), g, origin.id


def run_sync(coro: Any) -> Any:
    return asyncio.run(coro)


def log_actions(g: InvestigationGraph) -> List[str]:
    return [e.action for e in g.logs]


def new_nodes(g: InvestigationGraph, origin_id: str) -> Dict[str, GraphNode]:
    return {nid: n for nid, n in g.nodes.items() if nid != origin_id}


@contextmanager
def clean_source_state(*, sema: bool = True, sanctions_lists: bool = True) -> Iterator[None]:
    """No default proxy, and empty GAC SEMA (``sema``) and official-list (``sanctions_lists``) caches, before and
    after the block."""

    def reset() -> None:
        if sema:
            PISourcesAgent.reset_sema_cache()
        if sanctions_lists:
            PISourcesAgent.reset_sanctions_caches()

    netutil.set_default_proxy(None)
    reset()
    yield
    reset()
    netutil.set_default_proxy(None)
