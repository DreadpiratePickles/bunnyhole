"""PI stream, person subject: typing of the seed, and no linking on a name alone.

Two defects found in a live run, both fixed here:

* A: a person passed as ``--org`` (or as a ``trace`` seed) was typed Organization.
* B: a first-name token pulled an unrelated Keybase/GitHub user and given-name-only sanctions matches into the
  graph, and path / keystone-broker / Adamic-Adar tables then ran through them.

Everything is offline (respx mocks, hand-built graphs) and every name is fictional ("Jane Roe", "Janet Roewood",
"roecorp.example"). Rule under test (docs/PI_STREAM.md, identity resolution): never link two people on a name
alone; a name-derived pivot needs the full name AND one more anchor (domain, email, username or company).
"""

from __future__ import annotations

import asyncio
import io
from typing import Any, Dict, List, Optional

import httpx
import pytest
import respx
from pi_helpers import FakeCaseStore, built_engagement
from rich.console import Console

from bunnyhole.agents.pi_sources import PISourcesAgent
from bunnyhole.agents.sanctions_lists import _build_names, _SanctionsRecord
from bunnyhole.cli import main as cli_main
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    RelationType,
)
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.profile import InvestigatorProfile

SUBJECT = "Jane Roe"
DOMAIN = "roecorp.example"
GITHUB_JANE = "https://api.github.com/users/jane"
KEYBASE = "https://keybase.io/_/api/1.0/user/lookup.json"


def _orch(*, person: bool = True, pi: bool = True) -> BunnyholeOrchestrator:
    kwargs: Dict[str, Any] = {}
    if pi:
        kwargs["engagement"] = built_engagement(subject_is_person=person)
    orch = BunnyholeOrchestrator(
        SUBJECT, max_depth=1, profile=InvestigatorProfile(persona=Persona.PRIVATE_INVESTIGATOR), **kwargs
    )
    orch.case_store = FakeCaseStore()
    return orch


def _started(orch: BunnyholeOrchestrator, *extra_seeds: tuple) -> GraphNode:
    """Start the case the way the intake path does (selectors, conflict check) and return the name seed node."""
    seeds = [("company", SUBJECT), ("domain", DOMAIN), *extra_seeds]
    orch._pi_start_case(seeds)
    _, node = orch._create_seed_node(SUBJECT, hop_depth=0, forced_type="company")
    for lead_type, value in seeds[1:]:  # intake passes the selector kind it already knows (".example" is no public suffix)
        orch._create_seed_node(value, hop_depth=0, forced_type=lead_type)
    return node


def _github(name: str, *, blog: str = "", company: str = "", email: str = "") -> httpx.Response:
    return httpx.Response(
        200,
        json={"id": 4242, "login": "jane", "name": name, "company": company, "blog": blog, "email": email,
              "location": "", "twitter_username": ""},
    )


def _keybase(full_name: str, proofs: Optional[List[Dict[str, str]]] = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={"them": [{"profile": {"full_name": full_name, "location": "", "bio": ""},
                        "proofs_summary": {"all": proofs or []}}]},
    )


def _sweep(orch: BunnyholeOrchestrator, seed: GraphNode, handle: str = "jane", *, github: httpx.Response,
           keybase: httpx.Response) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=KEYBASE).mock(return_value=keybase)
        router.get(url__regex=r"https://api\.github\.com/users/[^/]+$").mock(return_value=github)
        router.get(url__regex=r"https://api\.github\.com/users/[^/]+/events.*").mock(
            return_value=httpx.Response(200, json=[])
        )
        asyncio.run(orch.osint.investigate_identity_and_handle(handle, seed.id, 1))


def _edges_from(orch: BunnyholeOrchestrator, source_id: str) -> List[GraphEdge]:
    return [e for e in orch.graph.edges.values() if e.source_id == source_id]


def _table_text(result: Dict[str, Any]) -> str:
    inter = result["interconnections"]
    return repr([inter.get("keystone_brokers"), inter.get("predicted_missing_links"), inter.get("cross_domain_paths")])


# ==============================================================================================================
# Defect A: the seed is typed from the engagement, not from the shape of the string
# ==============================================================================================================


def test_person_subject_name_seed_is_a_person_and_the_receipt_says_so() -> None:
    orch = _orch(person=True)
    lead_type, node = orch._create_seed_node(SUBJECT)
    assert node.entity_type == EntityType.PERSON
    fact = node.receipts[0].extracted_fact
    assert "PERSON (Person)" in fact and "COMPANY" not in fact and "Organization" not in fact
    assert lead_type == "company"  # dispatch key is unchanged: the name still goes to the registry/sanctions/news sources


def test_entity_subject_keeps_an_organization_seed_even_for_a_person_like_name() -> None:
    orch = _orch(person=False)
    assert orch._create_seed_node("Roecorp Holdings Ltd")[1].entity_type == EntityType.ORGANIZATION
    assert orch._create_seed_node(SUBJECT)[1].entity_type == EntityType.ORGANIZATION  # --confirm-entity case


def test_person_subject_company_named_selector_stays_an_organization() -> None:
    orch = _orch(person=True)  # an employer given next to the person
    assert orch._create_seed_node("Roecorp Holdings Ltd")[1].entity_type == EntityType.ORGANIZATION


def test_non_pi_run_seed_typing_is_unchanged() -> None:
    orch = _orch(pi=False)
    assert orch._create_seed_node(SUBJECT)[1].entity_type == EntityType.ORGANIZATION


def test_person_seed_is_a_person_in_the_identity_notes_path() -> None:
    orch = _orch(person=True)
    orch._pi_start_case([("company", SUBJECT), ("domain", DOMAIN)])
    assert orch._pi_selectors["names"] == [SUBJECT]  # selectors_from_seeds still files the name under names
    seed = orch._create_seed_node(SUBJECT)[1]
    assert seed.id in orch.graph.nodes and orch.graph.nodes[seed.id].entity_type == EntityType.PERSON


# ==============================================================================================================
# Defect B1: a name-derived account pivot attaches only on full name + one more anchor
# ==============================================================================================================


def test_first_name_only_github_and_keybase_user_is_not_attached() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github("Jane"), keybase=_keybase("Jane"))
    assert "account:github:jane" not in orch.graph.nodes
    assert "account:keybase:jane" not in orch.graph.nodes
    assert _edges_from(orch, seed.id) == []
    kinds = {c["tool"] for c in orch.graph.to_dict()["set_aside_candidates"]}
    assert {"github_api_and_commit_pol", "keybase_cryptographic_proof_api"} <= kinds


def test_given_name_match_with_a_different_surname_is_not_attached() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github("Jane Doe", blog=f"https://{DOMAIN}"), keybase=_keybase("Janet Roewood"))
    assert "account:github:jane" not in orch.graph.nodes  # surname differs, even with the shared domain
    assert "account:keybase:jane" not in orch.graph.nodes


def test_full_name_without_a_second_anchor_is_not_attached() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github(SUBJECT), keybase=_keybase(SUBJECT))
    assert "account:github:jane" not in orch.graph.nodes
    assert "account:keybase:jane" not in orch.graph.nodes
    reasons = " ".join(c["reason"] for c in orch.graph.to_dict()["set_aside_candidates"])
    assert "second anchor" in reasons


def test_full_name_plus_shared_domain_is_attached_and_linked() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github(SUBJECT, blog=f"https://www.{DOMAIN}/about"), keybase=_keybase(SUBJECT))
    assert "account:github:jane" in orch.graph.nodes
    assert any(e.target_id == "account:github:jane" for e in _edges_from(orch, seed.id))
    # Keybase had the full name but no anchor in this sweep: set aside, not attached
    assert "account:keybase:jane" not in orch.graph.nodes


def test_keybase_full_name_plus_signed_dns_proof_for_the_domain_is_attached() -> None:
    orch = _orch()
    seed = _started(orch)
    proofs = [{"proof_type": "dns", "nametag": DOMAIN}]
    _sweep(orch, seed, github=_github("Jane"), keybase=_keybase(SUBJECT, proofs))
    assert "account:keybase:jane" in orch.graph.nodes
    assert any(e.target_id == "account:keybase:jane" for e in _edges_from(orch, seed.id))


def test_full_name_plus_shared_email_is_attached() -> None:
    orch = _orch()
    seed = _started(orch, ("email", f"jane.roe@{DOMAIN}"))
    _sweep(orch, seed, github=_github(SUBJECT, email=f"Jane.Roe@{DOMAIN}"), keybase=_keybase("Jane"))
    assert "account:github:jane" in orch.graph.nodes


def test_full_name_plus_company_is_attached() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github(SUBJECT, company="@Roecorp"), keybase=_keybase("Jane"))
    assert "account:github:jane" in orch.graph.nodes  # the company equals the label of the subject's domain


def test_a_handle_the_investigator_supplied_is_not_gated() -> None:
    orch = _orch()
    seed = _started(orch, ("username", "jane"))
    _sweep(orch, seed, github=_github("Jane"), keybase=_keybase("Jane"))
    assert "account:github:jane" in orch.graph.nodes  # explicit --username: attached as before


def test_non_pi_run_still_attaches_the_first_name_account() -> None:
    orch = _orch(pi=False)
    seed = orch._create_seed_node(SUBJECT)[1]
    _sweep(orch, seed, github=_github("Jane"), keybase=_keybase("Jane"))
    assert "account:github:jane" in orch.graph.nodes


def test_entity_subject_name_pivot_is_not_gated_by_the_person_rule() -> None:
    orch = _orch(person=False)
    seed = orch._create_seed_node("Roecorp Holdings Ltd")[1]
    orch._pi_start_case([("company", "Roecorp Holdings Ltd")])
    _sweep(orch, seed, github=_github("Roecorp"), keybase=_keybase("Roecorp"))
    assert "account:github:jane" in orch.graph.nodes


def test_set_aside_account_stays_out_of_the_result_tables_and_is_reported() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github("Jane"), keybase=_keybase("Jane"))
    result = orch.compile_full_result()
    tables = _table_text(result).lower()
    assert "@jane" not in tables and "github" not in tables and "keybase" not in tables
    assert all(n["id"] not in ("account:github:jane", "account:keybase:jane") for n in result["nodes"])
    notes = " ".join(result["pi"]["identity_notes"])
    assert "Weak name match, not linked" in notes and "@jane" in notes
    assert len(result["set_aside_candidates"]) == 2  # kept in the JSON result


# ==============================================================================================================
# Defect B2: sanctions / PEP soft matches need the surname and a compatible full name
# ==============================================================================================================


def _list_agent() -> tuple:
    orch = _orch()
    seed = _started(orch)
    assert orch.pi_sources is not None
    return orch.pi_sources, orch.graph, seed.id


def _listed(g: InvestigationGraph) -> List[str]:
    return [n for n in g.nodes if n.startswith("sanction:")]


def _record(*names: str, kind: str = "person") -> _SanctionsRecord:
    return _SanctionsRecord(
        list_id="9001", kind=kind, programs=("TEST-PROGRAM",), listed="2024-01-01", names=_build_names(names)
    )


def _screen_list(agent: PISourcesAgent, origin: str, query: str, record: _SanctionsRecord) -> None:
    from bunnyhole.agents.pi_sources import _SANCTIONS_LISTS

    agent._record_list_match(_SANCTIONS_LISTS["ofac_sdn"], record, record.names[0][0], query, origin, 1)


def test_given_name_tokens_only_listing_is_not_a_graph_node_or_edge_but_is_reported() -> None:
    agent, g, origin = _list_agent()
    _screen_list(agent, origin, "Jane Marie Roe", _record("Jane Marie"))
    assert _listed(g) == []
    assert g.edges == {}
    entry = g.to_dict()["set_aside_candidates"][0]
    assert "weak name match, not linked" in entry["reason"].lower()
    assert "given-name" in entry["reason"]


def test_different_spelling_with_no_surname_listing_is_set_aside() -> None:
    agent, g, origin = _list_agent()
    _screen_list(agent, origin, SUBJECT, _record("Jayne Rowe"))
    assert _listed(g) == [] and g.edges == {}
    assert len(g.to_dict()["set_aside_candidates"]) == 1


def test_surname_plus_compatible_given_name_listing_is_still_linked_as_a_soft_match() -> None:
    agent, g, origin = _list_agent()
    _screen_list(agent, origin, SUBJECT, _record("ROE, Jane"))
    assert "sanction:ofac:9001" in g.nodes
    assert [e.target_id for e in g.edges.values()] == ["sanction:ofac:9001"]
    receipt = g.nodes["sanction:ofac:9001"].receipts[0]
    assert "Name match only; verify identifiers." in receipt.extracted_fact  # the existing wording stays


def test_canadian_sema_given_name_only_record_is_set_aside() -> None:
    agent, g, origin = _list_agent()
    rec = {"kind": "person", "schedule": "1, Part 1", "item": "7", "name": "Jane Marie", "country": "n/a",
           "listed": "2024-01-01", "aliases": [], "dob_or_build": "", "imo": "", "matched_name": "Jane Marie"}
    agent._record_sanction_match(rec, "Jane Marie Roe", origin, 1)
    assert _listed(g) == [] and g.edges == {}
    assert len(g.to_dict()["set_aside_candidates"]) == 1


def test_sanctions_listing_without_a_person_subject_is_unchanged() -> None:
    g = InvestigationGraph("bh_entity", "Roecorp Holdings Ltd")
    origin = GraphNode(id="org:o", label="Roecorp Holdings Ltd", entity_type=EntityType.ORGANIZATION,
                       domain=DomainCategory.FIAT)
    g.upsert_node(origin)
    agent = PISourcesAgent(g)
    _screen_list(agent, origin.id, "Roecorp Holdings Ltd", _record("Roecorp Holdings", kind="entity"))
    assert "sanction:ofac:9001" in g.nodes


def test_opensanctions_pep_name_collision_is_set_aside_and_the_full_name_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENSANCTIONS_API_KEY", "test-key-not-real")
    orch = _orch()
    seed = _started(orch)
    results = [
        {"id": "NK-1", "caption": "Janet Roewood", "schema": "Person", "datasets": ["test_pep"],
         "properties": {"topics": ["role.pep"]}},
        {"id": "NK-2", "caption": "Jane Roe", "schema": "Person", "datasets": ["test_pep"],
         "properties": {"topics": ["role.pep"]}},
    ]
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith="https://api.opensanctions.org/search/default").mock(
            return_value=httpx.Response(200, json={"results": results})
        )
        asyncio.run(orch.accountant.investigate_opensanctions(SUBJECT, seed.id, 1))
    assert "sanction:NK-1" not in orch.graph.nodes
    assert "sanction:NK-2" in orch.graph.nodes
    assert len(orch.graph.to_dict()["set_aside_candidates"]) == 1


# ==============================================================================================================
# Defect B3: paths, keystone brokers and predicted links
# ==============================================================================================================


def _node(node_id: str, label: str, etype: EntityType, domain: DomainCategory, tool: str = "test_source",
          **attrs: Any) -> GraphNode:
    receipt = EvidenceReceipt(tool=tool, domain=domain, admiralty_code="B2", source_url=f"https://example.test/{node_id}",
                              extracted_fact=f"fact about {label}")
    return GraphNode(id=node_id, label=label, entity_type=etype, domain=domain, receipts=[receipt],
                     smoke_score=40.0, attributes=attrs, hop_depth=1)


def _link(orch: BunnyholeOrchestrator, a: str, b: str) -> None:
    receipt = EvidenceReceipt(tool="test_source", domain=DomainCategory.OSINT, admiralty_code="B2",
                              source_url=f"https://example.test/{a}-{b}", extracted_fact="linked")
    orch.graph.upsert_edge(GraphEdge(source_id=a, target_id=b, relation=RelationType.LINKED_IDENTITY,
                                     domain=DomainCategory.OSINT, receipts=[receipt]))


def test_generic_platform_account_is_never_an_endpoint_or_broker() -> None:
    orch = _orch()
    seed = _started(orch)
    platform = _node("account:github:github", "💻 GitHub: @github (GitHub)", EntityType.ACCOUNT,
                     DomainCategory.OSINT, handle="github", name="GitHub")
    other = _node("domain:other.example", "other.example", EntityType.DOMAIN, DomainCategory.OSINT)
    orch.graph.upsert_node(platform)
    orch.graph.upsert_node(other)
    _link(orch, seed.id, platform.id)
    _link(orch, other.id, platform.id)
    result = orch.compile_full_result()
    text = _table_text(result).lower()
    assert "@github" not in text and "account:github:github" not in text
    assert all(b["node_id"] != platform.id for b in result["interconnections"]["keystone_brokers"])


def test_unanchored_name_only_nodes_are_left_out_of_every_table_but_kept_in_the_json() -> None:
    orch = _orch()
    seed = _started(orch)
    stray = _node("court:roewood", "Janet Roewood", EntityType.PERSON, DomainCategory.FIAT, tool="court_dockets")
    tail = _node("email:x@other.example", "x@other.example", EntityType.EMAIL, DomainCategory.OSINT)
    orch.graph.upsert_node(stray)
    orch.graph.upsert_node(tail)
    _link(orch, seed.id, stray.id)
    _link(orch, stray.id, tail.id)
    result = orch.compile_full_result()
    assert "roewood" not in _table_text(result).lower()
    assert any(n["id"] == stray.id for n in result["nodes"])  # the JSON keeps every record
    assert stray.id in result["set_aside_node_ids"]


def test_a_node_hanging_off_the_investigators_own_domain_anchor_stays_in_the_analytics() -> None:
    orch = _orch()
    seed = _started(orch)
    domain_id = f"domain:{DOMAIN}"
    company = _node("company:roecorp", "Roecorp Holdings", EntityType.ORGANIZATION, DomainCategory.FIAT,
                    tool="gleif")
    ip = _node("ip:203.0.113.7", "203.0.113.7", EntityType.IP_HOST, DomainCategory.OSINT)
    orch.graph.upsert_node(company)
    orch.graph.upsert_node(ip)
    _link(orch, seed.id, domain_id)
    _link(orch, domain_id, company.id)
    _link(orch, company.id, ip.id)
    result = orch.compile_full_result()
    assert company.id not in result["set_aside_node_ids"]
    assert "roecorp holdings" in _table_text(result).lower()


def test_non_pi_analytics_are_unchanged() -> None:
    orch = _orch(pi=False)
    seed = orch._create_seed_node(SUBJECT)[1]
    platform = _node("account:github:github", "💻 GitHub: @github (GitHub)", EntityType.ACCOUNT,
                     DomainCategory.OSINT, handle="github")
    other = _node("domain:other.example", "other.example", EntityType.DOMAIN, DomainCategory.OSINT)
    orch.graph.upsert_node(platform)
    orch.graph.upsert_node(other)
    _link(orch, seed.id, platform.id)
    _link(orch, other.id, platform.id)
    result = orch.compile_full_result()
    assert "set_aside_node_ids" not in result
    assert "@github" in _table_text(result).lower()


def test_cli_entity_table_hides_set_aside_nodes_but_says_how_many() -> None:
    result = {
        "case_id": "bh_x", "seed_query": SUBJECT, "stats": {}, "ach_assessment": {}, "deep_research": {},
        "interconnections": {},
        "nodes": [
            {"id": "a", "label": "Kept Entity", "entity_type": "Person", "domain": "fiat", "smoke_score": 10.0,
             "risk_flags": []},
            {"id": "b", "label": "Stray Entity", "entity_type": "Person", "domain": "fiat", "smoke_score": 99.0,
             "risk_flags": []},
        ],
        "set_aside_node_ids": ["b"],
        "set_aside_candidates": [{"label": "@jane", "tool": "x", "reason": "r"}],
    }
    buffer = io.StringIO()
    original = cli_main.console
    cli_main.console = Console(file=buffer, width=200)
    try:
        cli_main._render_investigation_results(result)
    finally:
        cli_main.console = original
    text = buffer.getvalue()
    assert "Kept Entity" in text and "Stray Entity" not in text
    assert "set aside" in text.lower()


# ==============================================================================================================
# The pure rules, and the real intake path
# ==============================================================================================================


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("Jane Roe", "Jane Roe", True),
        ("Jane Roe", "ROE, Jane", True),
        ("Jane Marie Roe", "Jane Roe", True),
        ("Jane Roe", "J. Roe", True),
        ("Jane Roe", "Jane", False),  # no surname: a given-name match only
        ("Jane Roe", "Jane Marie", False),  # the second word is read as a surname, and it is not Roe
        ("Jane Roe", "Jayne Rowe", False),  # a different spelling of the surname
        ("Jane Roe", "Janet Roewood", False),
        ("Jane", "Jane", False),  # two lone given names are not a full-name match
        ("Jane Roe", "", False),
    ],
)
def test_full_names_compatible(left: str, right: str, expected: bool) -> None:
    from bunnyhole.engine.pi_identity import full_names_compatible

    assert full_names_compatible(left, right) is expected


@pytest.mark.parametrize(
    ("entity_type", "node_id", "label", "attrs", "expected"),
    [
        ("Account", "account:github:github", "💻 GitHub: @github (GitHub)", {"handle": "github"}, True),
        ("Account", "account:keybase:keybase", "🔐 Keybase: @keybase", {}, True),
        ("Account", "account:github:jane", "💻 GitHub: @jane (Jane Roe)", {"handle": "jane"}, False),
        ("Organization", "company:github", "GitHub Inc", {"handle": "github"}, False),  # only accounts
    ],
)
def test_generic_platform_account_detection(
    entity_type: str, node_id: str, label: str, attrs: Dict[str, Any], expected: bool
) -> None:
    from bunnyhole.engine.pi_anchoring import is_generic_platform_account

    assert is_generic_platform_account(entity_type, node_id, label, attrs) is expected


def test_subject_anchors_split_person_names_from_company_names_and_use_work_email_domains() -> None:
    from bunnyhole.engine.pi_anchoring import SubjectAnchors

    anchors = SubjectAnchors.from_selectors(
        {"names": [SUBJECT, "Roecorp Holdings Ltd"], "emails": ["Jane.Roe@Roecorp.example", "jroe@gmail.com"],
         "usernames": ["@JRoe"], "domains": ["https://www.Roecorp.example/about"]}
    )
    # every name the investigator gave under a person subject is a usable full-name anchor (no shape heuristic gate);
    # the organisation-looking one is also kept as a company anchor for account profiles
    assert anchors.names == (SUBJECT, "Roecorp Holdings Ltd") and anchors.companies == ("Roecorp Holdings Ltd",)
    assert anchors.domains == (DOMAIN,)  # the free-mail domain is not an anchor
    assert anchors.usernames == ("jroe",) and anchors.is_explicit_username("@JROE")


def test_intake_path_types_the_name_seed_as_a_person_and_arms_the_two_anchor_rule() -> None:
    from pi_helpers import fake_orchestrator

    from bunnyhole.engine.intake import CaseIntakePacket
    from bunnyhole.engine.pi import PIBlock

    orch = fake_orchestrator(built_engagement(subject_is_person=True))
    packet = CaseIntakePacket(orgs_or_names=[SUBJECT], domains=[DOMAIN])
    result = asyncio.run(orch.run_intake_investigation(packet))
    seed = next(n for n in result["nodes"] if n["attributes"].get("raw_seed") == SUBJECT)
    assert seed["entity_type"] == "Person" and seed["id"] == "person:jane_roe"
    assert orch.graph.pi_subject is not None and orch.graph.pi_subject.names == (SUBJECT,)
    assert orch.graph.pi_subject.domains == (DOMAIN,)
    PIBlock.model_validate(result["pi"])


# ==============================================================================================================
# Verifier round: an exact full-name listing must never be hidden, whatever the shape of the name
# ==============================================================================================================


def _person_run(subject: str) -> tuple:
    orch = _orch()
    orch.seed_query = subject
    orch._pi_start_case([("company", subject)])
    origin = orch._create_seed_node(subject, hop_depth=0, forced_type="company")[1]
    assert orch.pi_sources is not None
    return orch, origin


@pytest.mark.parametrize(
    "subject",
    ["Karim Omar Fadel Al Roe", "Zoran Mihail Petrov Roe", "Jane Church", "Grace Fund", "Madonna",
     "Jane Roe-Smith Esq", "Dr. Jane Roe", "O'Neil Mary-Jane Roe"],
)
def test_exact_name_listing_attaches_whatever_the_shape_of_the_subject_name(subject: str) -> None:
    orch, origin = _person_run(subject)
    assert origin.entity_type == EntityType.PERSON  # the engagement says person: the primary name is a Person
    _screen_list(orch.pi_sources, origin.id, subject, _record(subject))
    listed = _listed(orch.graph)
    assert listed, f"genuine exact-name match for {subject!r} was hidden"
    node = orch.graph.nodes[listed[0]]
    assert "Name match only; verify identifiers." in node.receipts[0].extracted_fact
    assert "set_aside_candidates" not in orch.graph.to_dict()


def test_single_word_subject_exact_match_attaches_only_as_a_flagged_weak_match() -> None:
    orch, origin = _person_run("Madonna")
    _screen_list(orch.pi_sources, origin.id, "Madonna", _record("Madonna"))
    node = orch.graph.nodes[_listed(orch.graph)[0]]
    assert "WEAK_NAME_MATCH_SINGLE_WORD" in node.risk_flags
    assert "single-word" in node.attributes["anchor_note"]
    other, other_origin = _person_run("Madonna")  # anything longer than the single token is still only weak
    _screen_list(other.pi_sources, other_origin.id, "Madonna", _record("Madonna Louise"))
    assert _listed(other.graph) == [] and len(other.graph.to_dict()["set_aside_candidates"]) == 1


@pytest.mark.parametrize(
    ("subject", "listed", "expected"),
    [
        ("Zoë Roe-Smith", "Zoe Roe-Smith", True),  # diacritics folded
        ("Zoë Roe-Smith", "Zoe ROE SMITH", True),  # hyphen and space are separators
        ("Zoë Roe-Smith", "ROE-SMITH, Zoë", True),
        ("Jane Roe", "  jane   ROE ", True),
        ("Jane Roe", "Roe Jane", True),  # surname first without a comma: identical token multiset
        ("Jane Roe", "Jane Roe-Smith", True),
        ("Jane Roe", "Jane de la Roe", True),
        ("Jane Roe", "Jane", False),  # given-name only
        ("Jane Roe", "Jane Marie", False),
        ("Jane Roe", "Jayne Rowe", False),  # different spelling of the surname
        ("Jane Roe", "Janet Roewood", False),
        ("Jane Roe", "Roe Trading Company", False),
        ("Zoë Roe-Smith", "Zoe Rowe-Jones", False),
        ("Jane Marie Roe", "Jane Marie", False),
    ],
)
def test_listing_name_matrix(subject: str, listed: str, expected: bool) -> None:
    from bunnyhole.engine.pi_anchoring import SubjectAnchors, judge_listing

    verdict = judge_listing(SubjectAnchors(names=(subject,)), [listed])
    assert verdict.attach is expected
    if not expected:
        assert verdict.reason.startswith("weak name match, not linked")


def test_account_name_order_and_diacritics_follow_the_same_fold() -> None:
    orch = _orch()
    seed = _started(orch)
    _sweep(orch, seed, github=_github("Roe Jane", blog=DOMAIN), keybase=_keybase("jane  ROE", [{"proof_type": "dns", "nametag": DOMAIN}]))
    assert "account:github:jane" in orch.graph.nodes and "account:keybase:jane" in orch.graph.nodes
    other = _orch()
    other_seed = _started(other)
    _sweep(other, other_seed, github=_github("Jane", blog=DOMAIN), keybase=_keybase("Jane Rowe", [{"proof_type": "dns", "nametag": DOMAIN}]))
    assert "account:github:jane" not in other.graph.nodes and "account:keybase:jane" not in other.graph.nodes


# ==============================================================================================================
# Verifier round: the report's Sanctions section discloses set-aside listings itself
# ==============================================================================================================


def test_report_sanctions_section_discloses_a_weak_listing_and_keeps_the_caveats() -> None:
    from bunnyhole.engine.pi_report import build_pi_report

    orch = _orch()
    seed = _started(orch)
    _screen_list(orch.pi_sources, seed.id, "Jane Marie Roe", _record("Jane Marie"))
    result = orch.compile_full_result()
    assert len(result["pi"]["sanctions"]["weak_matches"]) == 1
    md = build_pi_report(result)
    start = md.index("## Sanctions screening")
    section = md[start: md.index("\n## ", start + 5)]
    assert "weak name match, not linked; verify on the primary list" in section
    assert "Jane Marie" in section
    assert "not clearance" in section.lower()
    assert "EU Consolidated List" in section and "not automated" in section
    bottom = md[: md.index("\n## ", md.index("Bottom line") + 5)] if "Bottom line" in md else md
    assert "weak name match" in bottom.lower()


def test_report_without_a_weak_listing_is_unchanged() -> None:
    from bunnyhole.engine.pi_report import build_pi_report

    orch = _orch()
    _started(orch)
    md = build_pi_report(orch.compile_full_result())
    assert "weak name match" not in md.lower().split("## sanctions screening", 1)[1].split("\n## ", 1)[0]


def test_report_lists_at_most_three_weak_listings_and_counts_the_rest() -> None:
    from bunnyhole.engine.pi_report import build_pi_report

    orch = _orch()
    seed = _started(orch)
    for index in range(5):
        _screen_list(orch.pi_sources, seed.id, "Jane Marie Roe", _record(f"Jane Marie{'x' * index}"))
    md = build_pi_report(orch.compile_full_result())
    section = md.split("## Sanctions screening", 1)[1].split("\n## ", 1)[0]
    assert "(5)" in section and "+2 more" in section


# ==============================================================================================================
# Verifier round: a targeted path to a set-aside endpoint says so
# ==============================================================================================================


def test_targeted_path_to_a_set_aside_endpoint_says_it_was_set_aside() -> None:
    orch = _orch()
    seed = _started(orch)
    stray = _node("court:roewood", "Janet Roewood", EntityType.PERSON, DomainCategory.FIAT, tool="court_dockets")
    orch.graph.upsert_node(stray)
    _link(orch, seed.id, stray.id)
    result = orch.compile_full_result(source_query="Janet Roewood", target_query="Jane Roe")
    inter = result["interconnections"]
    assert inter["targeted_paths"] == []
    assert "set aside as unanchored" in inter["targeted_path_note"]
    assert "Janet Roewood" in inter["targeted_path_note"]
