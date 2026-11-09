"""Tests for the keyless official sanctions-list screens (OFAC SDN, UN consolidated, UK Sanctions List).

All HTTP is mocked with respx and every XML payload is a tiny synthetic fixture that uses the real element
names of the official files (verified against the live downloads on 2026-11-09); the live files are never
fetched or committed. The on-disk cache is redirected into ``tmp_path`` for every test.
"""

from __future__ import annotations

import asyncio
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx
import pytest
import respx

from bunnyhole.agents import pi_sources
from bunnyhole.agents.pi_sources import PISourcesAgent
from bunnyhole.engine import netutil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    GraphNode,
    RelationType,
    SelectorStrength,
)

OFAC_NS = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"

OFAC_XML = f"""<?xml version="1.0" standalone="yes"?>
<sdnList xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="{OFAC_NS}">
  <publshInformation><Publish_Date>11/06/2026</Publish_Date><Record_Count>3</Record_Count></publshInformation>
  <sdnEntry>
    <uid>1001</uid>
    <lastName>ROSNEFT OIL COMPANY</lastName>
    <sdnType>Entity</sdnType>
    <programList><program>UKRAINE-EO13662</program><program>RUSSIA-EO14024</program></programList>
    <akaList>
      <aka><uid>5</uid><type>a.k.a.</type><category>strong</category><lastName>ROSNEFT PJSC</lastName></aka>
      <aka><uid>6</uid><type>f.k.a.</type><category>weak</category><lastName>NEFTYANAYA KOMPANIYA ROSNEFT</lastName></aka>
    </akaList>
    <addressList><address><uid>9</uid><city>Moscow</city><country>Russia</country></address></addressList>
  </sdnEntry>
  <sdnEntry>
    <uid>2002</uid>
    <firstName>Sergei Petrovich</firstName>
    <lastName>IVANOV</lastName>
    <sdnType>Individual</sdnType>
    <programList><program>RUSSIA-EO14024</program></programList>
    <akaList>
      <aka><uid>7</uid><type>a.k.a.</type><category>strong</category><firstName>Serge</firstName><lastName>IVANOFF</lastName></aka>
    </akaList>
    <dateOfBirthList><dateOfBirthItem><uid>1</uid><dateOfBirth>1953</dateOfBirth></dateOfBirthItem></dateOfBirthList>
  </sdnEntry>
  <sdnEntry>
    <uid>3003</uid>
    <lastName>SEA STAR</lastName>
    <sdnType>Vessel</sdnType>
    <programList><program>IRAN</program></programList>
  </sdnEntry>
</sdnList>
"""

UN_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<CONSOLIDATED_LIST xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" dateGenerated="2026-11-08T00:00:00.869Z">
  <INDIVIDUALS>
    <INDIVIDUAL>
      <DATAID>6907993</DATAID>
      <VERSIONNUM>1</VERSIONNUM>
      <FIRST_NAME>ERIC</FIRST_NAME>
      <SECOND_NAME>BADEGE</SECOND_NAME>
      <UN_LIST_TYPE>DRC</UN_LIST_TYPE>
      <REFERENCE_NUMBER>CDi.001</REFERENCE_NUMBER>
      <LISTED_ON>2012-12-31</LISTED_ON>
      <INDIVIDUAL_ALIAS><QUALITY/><ALIAS_NAME/></INDIVIDUAL_ALIAS>
      <INDIVIDUAL_ALIAS><QUALITY>Good</QUALITY><ALIAS_NAME>FRANK KAKORERE</ALIAS_NAME></INDIVIDUAL_ALIAS>
    </INDIVIDUAL>
    <INDIVIDUAL>
      <DATAID>6908001</DATAID>
      <FIRST_NAME>MARIA</FIRST_NAME>
      <SECOND_NAME>LUISA</SECOND_NAME>
      <THIRD_NAME>GARCIA</THIRD_NAME>
      <UN_LIST_TYPE>Al-Qaida</UN_LIST_TYPE>
      <REFERENCE_NUMBER>QDi.777</REFERENCE_NUMBER>
      <LISTED_ON>2010-01-01</LISTED_ON>
    </INDIVIDUAL>
  </INDIVIDUALS>
  <ENTITIES>
    <ENTITY>
      <DATAID>6908402</DATAID>
      <FIRST_NAME>Allied Forces of Testland</FIRST_NAME>
      <UN_LIST_TYPE>DRC</UN_LIST_TYPE>
      <REFERENCE_NUMBER>CDe.001</REFERENCE_NUMBER>
      <LISTED_ON>2014-06-30</LISTED_ON>
      <ENTITY_ALIAS><QUALITY>a.k.a.</QUALITY><ALIAS_NAME>Testland Liberation Front</ALIAS_NAME></ENTITY_ALIAS>
      <ENTITY_ALIAS><QUALITY>f.k.a.</QUALITY><ALIAS_NAME>TLF Brigade</ALIAS_NAME></ENTITY_ALIAS>
    </ENTITY>
  </ENTITIES>
</CONSOLIDATED_LIST>
"""

UK_XML = """<?xml version="1.0" encoding="utf-8"?>
<Designations xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <DateGenerated>03/11/2026</DateGenerated>
  <Designation>
    <LastUpdated>04/08/2026</LastUpdated>
    <DateDesignated>29/06/2012</DateDesignated>
    <UniqueID>AFG0001</UniqueID>
    <OFSIGroupID>12703</OFSIGroupID>
    <UNReferenceNumber>TAe.010</UNReferenceNumber>
    <Names>
      <Name><Name6>HAJI TESTER MONEY EXCHANGE</Name6><NameType>Primary Name</NameType></Name>
      <Name><Name6>Haji Alim Hawala</Name6><NameType>Alias</NameType></Name>
    </Names>
    <NonLatinNames><NonLatinName><NameNonLatinScript>حاجی تستر</NameNonLatinScript></NonLatinName></NonLatinNames>
    <RegimeName>The Afghanistan (Sanctions) (EU Exit) Regulations 2020</RegimeName>
    <IndividualEntityShip>Entity</IndividualEntityShip>
    <DesignationSource>UN</DesignationSource>
  </Designation>
  <Designation>
    <DateDesignated>25/01/2001</DateDesignated>
    <UniqueID>AFG0006</UniqueID>
    <Names>
      <Name><Name1>MOHAMMAD</Name1><Name2>HASSAN</Name2><Name6>AKHUND</Name6><NameType>Primary Name</NameType></Name>
      <Name><Name1>Hasan</Name1><Name6>Akhund</Name6><NameType>Primary Name Variation</NameType></Name>
    </Names>
    <RegimeName>The Afghanistan (Sanctions) (EU Exit) Regulations 2020</RegimeName>
    <IndividualEntityShip>Individual</IndividualEntityShip>
    <DesignationSource>UN</DesignationSource>
  </Designation>
  <Designation>
    <DateDesignated>03/10/2017</DateDesignated>
    <UniqueID>DPR0075</UniqueID>
    <Names>
      <Name><Name6>Petrel 8</Name6><NameType>Primary name</NameType></Name>
      <Name><Name6>Jal Vahini</Name6><NameType>Alias</NameType></Name>
    </Names>
    <RegimeName>The Democratic People's Republic of Korea (Sanctions) (EU Exit) Regulations 2019</RegimeName>
    <IndividualEntityShip>Ship</IndividualEntityShip>
    <DesignationSource>UN</DesignationSource>
  </Designation>
</Designations>
"""


@dataclass(frozen=True)
class ListCase:
    source: str  # tool name, cache file stem and orchestrator source name
    method: str
    prefix: str  # log-action prefix
    host: str
    path: str
    xml: str
    page_url: str
    node_prefix: str
    entity_query: str  # matches the primary name of an organisation
    entity_id_text: str  # text that must appear in the receipt fact (program/regime/listing id)
    alias_query: str  # matches only through an alias
    person_query: str
    person_id_text: str
    single_token_query: str  # one shared token with a longer name: must not match
    ship_query: str
    reset: str
    redirect_host: str = ""  # a host the official site is known to redirect to (signed object storage)


CASES: List[ListCase] = [
    ListCase(
        source="ofac_sdn",
        method="screen_ofac_sdn",
        prefix="OFAC_SDN",
        host="sanctionslistservice.ofac.treas.gov",
        path="/api/PublicationPreview/exports/SDN.XML",
        xml=OFAC_XML,
        page_url="https://sanctionssearch.ofac.treas.gov/",
        node_prefix="sanction:ofac:",
        entity_query="Rosneft Oil Company",
        entity_id_text="RUSSIA-EO14024",
        alias_query="Neftyanaya Kompaniya Rosneft",
        person_query="Sergei Petrovich Ivanov",
        person_id_text="2002",
        single_token_query="Ivanov",
        ship_query="Sea Star",
        reset="reset_ofac_sdn_cache",
    ),
    ListCase(
        source="un_consolidated",
        method="screen_un_consolidated",
        prefix="UN_CONSOLIDATED",
        host="scsanctions.un.org",
        path="/resources/xml/en/consolidated.xml",
        xml=UN_XML,
        page_url="https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list",
        node_prefix="sanction:un:",
        entity_query="Allied Forces of Testland",
        entity_id_text="CDe.001",
        alias_query="Testland Liberation Front",
        person_query="Eric Badege",
        person_id_text="CDi.001",
        single_token_query="Garcia",
        ship_query="",
        reset="reset_un_consolidated_cache",
        redirect_host="unsolprodfiles.blob.core.windows.net",
    ),
    ListCase(
        source="uk_sanctions_list",
        method="screen_uk_sanctions_list",
        prefix="UK_SANCTIONS",
        host="sanctionslist.fcdo.gov.uk",
        path="/docs/UK-Sanctions-List.xml",
        xml=UK_XML,
        page_url="https://www.gov.uk/government/publications/the-uk-sanctions-list",
        node_prefix="sanction:uk:",
        entity_query="Haji Tester Money Exchange",
        entity_id_text="Afghanistan (Sanctions)",
        alias_query="Haji Alim Hawala",
        person_query="Mohammad Hassan Akhund",
        person_id_text="AFG0006",
        single_token_query="Akhund",
        ship_query="Petrel 8",
        reset="reset_uk_sanctions_cache",
    ),
]
CASE_IDS = [c.source for c in CASES]


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(pi_sources, "BUNNYHOLE_CONFIG_DIR", tmp_path / "bunnyhole_home")
    netutil.set_default_proxy(None)
    PISourcesAgent.reset_sanctions_caches()
    yield
    PISourcesAgent.reset_sanctions_caches()
    netutil.set_default_proxy(None)


def _agent_with_origin(label: str = "Acme Holdings") -> Tuple[PISourcesAgent, InvestigationGraph, str]:
    g = InvestigationGraph("test_pi_sources_v2", label)
    origin = GraphNode(
        id="org:origin",
        label=label,
        entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.FIAT,
        selector_strength=SelectorStrength.SOFT,
    )
    g.upsert_node(origin)
    return PISourcesAgent(g), g, origin.id


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _actions(g: InvestigationGraph) -> List[str]:
    return [e.action for e in g.logs]


def _new_nodes(g: InvestigationGraph, origin_id: str) -> Dict[str, GraphNode]:
    return {nid: n for nid, n in g.nodes.items() if nid != origin_id}


def _screen(case: ListCase, agent: PISourcesAgent, query: str, origin: str) -> Any:
    return _run(getattr(agent, case.method)(query, origin, 1))


def _route_ok(router: respx.MockRouter, case: ListCase, xml: Optional[str] = None) -> respx.Route:
    body = (case.xml if xml is None else xml).encode("utf-8")
    return router.route(host=case.host, path=case.path).mock(
        return_value=httpx.Response(200, content=body, headers={"content-type": "text/xml"})
    )


def _cache_file(case: ListCase) -> Path:
    return pi_sources.sanctions_cache_file(case.source)


def _seed_cache(case: ListCase, xml: str, age_s: float = 0.0) -> Path:
    path = _cache_file(case)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(xml.encode("utf-8"))
    when = time.time() - age_s
    os.utime(path, (when, when))
    return path


# ----------------------------------------------------------------------------------------------
# Constants and public surface
# ----------------------------------------------------------------------------------------------


def test_constants_follow_the_spec():
    assert pi_sources.MAX_SANCTIONS_LIST_BYTES == 40 * 1024 * 1024
    assert pi_sources.SANCTIONS_LIST_TIMEOUT_S == 60.0
    assert pi_sources.SANCTIONS_CACHE_TTL_S == 24 * 3600
    assert pi_sources.SANCTIONS_RETRY_AFTER_S == 300.0
    assert (
        pi_sources.OFAC_SDN_XML_URL
        == "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
    )
    assert pi_sources.UN_CONSOLIDATED_XML_URL == "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
    assert pi_sources.UK_SANCTIONS_XML_URL == "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.xml"
    path = pi_sources.sanctions_cache_file("ofac_sdn")
    assert path.parts[-3:] == ("cache", "sanctions", "ofac_sdn.xml")
    assert pi_sources.BUNNYHOLE_CONFIG_DIR in path.parents


# ----------------------------------------------------------------------------------------------
# Happy paths
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_entity_match_is_soft_with_official_page_exact_tool_and_listing_in_the_fact(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case)
        assert _screen(case, agent, case.entity_query, origin) is None
    nodes = _new_nodes(g, origin)
    assert len(nodes) == 1
    node = next(iter(nodes.values()))
    assert node.id.startswith(case.node_prefix)
    assert node.entity_type == EntityType.ORGANIZATION
    assert node.selector_strength == SelectorStrength.SOFT
    assert "SOFT_NAME_MATCH_VERIFY" in node.risk_flags
    assert f"{case.prefix}_LIST_MATCH" in node.risk_flags
    assert "OFAC_EU_UN_SANCTIONS_LIST_MATCH" in node.risk_flags  # the flag the PI runtime already treats as a listing
    rcpt = node.receipts[0]
    assert rcpt.tool == case.source
    assert rcpt.source_url == case.page_url
    assert rcpt.admiralty_code == "B2"
    assert rcpt.selector_strength == SelectorStrength.SOFT
    assert case.entity_id_text in rcpt.extracted_fact
    edge = next(iter(g.edges.values()))
    assert edge.source_id == origin and edge.target_id == node.id
    assert edge.relation == RelationType.LINKED_IDENTITY
    assert edge.confidence <= 0.55 and edge.receipts
    assert edge.admiralty_code == "B3"
    assert f"{case.prefix}_SCAN" in _actions(g)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_person_match_carries_the_listing_id(case: ListCase):
    agent, g, origin = _agent_with_origin(case.person_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.person_query, origin)
    node = next(iter(_new_nodes(g, origin).values()))
    assert node.entity_type == EntityType.PERSON
    assert case.person_id_text in node.receipts[0].extracted_fact


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_alias_only_match_is_found_and_reported_as_matched_via(case: ListCase):
    agent, g, origin = _agent_with_origin(case.alias_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.alias_query, origin)
    node = next(iter(_new_nodes(g, origin).values()))
    assert node.attributes["matched_name"] != node.attributes["list_name"]
    assert "matched_via" in node.receipts[0].raw_snippet


@pytest.mark.parametrize("case", [c for c in CASES if c.ship_query], ids=[c.source for c in CASES if c.ship_query])
def test_vessel_records_are_matched_by_name(case: ListCase):
    agent, g, origin = _agent_with_origin(case.ship_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.ship_query, origin)
    node = next(iter(_new_nodes(g, origin).values()))
    assert node.entity_type == EntityType.VESSEL


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_no_match_is_a_logged_negative(case: ListCase):
    agent, g, origin = _agent_with_origin("Nobody Special")
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, "Nobody Special", origin)
    assert not _new_nodes(g, origin)
    assert f"{case.prefix}_INFO" in _actions(g)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_single_shared_token_query_is_refused(case: ListCase):
    agent, g, origin = _agent_with_origin(case.single_token_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.single_token_query, origin)
    assert not _new_nodes(g, origin)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_short_query_is_a_noop_without_http(case: ListCase):
    agent, g, origin = _agent_with_origin()
    with respx.mock(assert_all_called=False) as router:
        route = _route_ok(router, case)
        _screen(case, agent, "ab", origin)
    assert route.call_count == 0
    assert not g.logs


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_more_than_five_matches_records_five_and_says_so(case: ListCase):
    many = {
        "ofac_sdn": OFAC_XML.replace(
            "</sdnList>",
            "".join(
                f"<sdnEntry><uid>{9000 + i}</uid><lastName>Acme Dupes {i}</lastName><sdnType>Entity</sdnType></sdnEntry>"
                for i in range(7)
            )
            + "</sdnList>",
        ),
        "un_consolidated": UN_XML.replace(
            "</ENTITIES>",
            "".join(
                f"<ENTITY><DATAID>{i}</DATAID><FIRST_NAME>Acme Dupes {i}</FIRST_NAME><REFERENCE_NUMBER>X{i}</REFERENCE_NUMBER></ENTITY>"
                for i in range(7)
            )
            + "</ENTITIES>",
        ),
        "uk_sanctions_list": UK_XML.replace(
            "</Designations>",
            "".join(
                f"<Designation><UniqueID>ZZ{i}</UniqueID><Names><Name><Name6>Acme Dupes {i}</Name6>"
                "<NameType>Primary Name</NameType></Name></Names><IndividualEntityShip>Entity</IndividualEntityShip></Designation>"
                for i in range(7)
            )
            + "</Designations>",
        ),
    }[case.source]
    agent, g, origin = _agent_with_origin("Acme Dupes")
    with respx.mock as router:
        _route_ok(router, case, many)
        _screen(case, agent, "Acme Dupes", origin)
    assert len(_new_nodes(g, origin)) == pi_sources.MAX_SANCTION_MATCHES
    assert any("7 soft matches" in e.detail for e in g.logs if e.action == f"{case.prefix}_INFO")


# ----------------------------------------------------------------------------------------------
# Streaming: DTD/entity/NUL refusal, size cap, memory behaviour
# ----------------------------------------------------------------------------------------------

BILLION_LAUGHS = (
    '<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>\n'
    "<Designations><Designation><UniqueID>&lol2;</UniqueID></Designation></Designations>"
)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize(
    "payload",
    [
        BILLION_LAUGHS,
        '<?xml version="1.0"?><!doctype x [<!entity a "b">]><root/>',
        '<?xml version="1.0"?><root><!ENTITY a "b"></root>',
    ],
    ids=["billion_laughs", "lower_case_doctype", "entity_decl_in_body"],
)
def test_dtd_and_entity_payloads_are_refused_before_parsing_and_never_cached(
    case: ListCase, payload: str, monkeypatch: pytest.MonkeyPatch
):
    parser_calls: List[int] = []

    def spy(*_a: Any, **_k: Any) -> Any:
        parser_calls.append(1)
        raise ValueError("parser reached")

    monkeypatch.setattr(pi_sources.ET, "iterparse", spy)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case, payload)
        _screen(case, agent, case.entity_query, origin)
    assert parser_calls == [], "a DTD/entity payload must be refused before it is parsed"
    assert not _new_nodes(g, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "DOCTYPE/ENTITY" in skips[0].detail
    assert not _cache_file(case).exists()


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_doctype_split_across_two_chunks_is_still_refused(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)

    async def chunks() -> AsyncIterator[bytes]:
        yield b"<?xml version='1.0'?><root><!DOC"
        yield b"TYPE x [<!ENTITY a 'b'>]></root>"

    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(200, content=chunks()))
        _screen(case, agent, case.entity_query, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "DOCTYPE/ENTITY" in skips[0].detail
    assert not _cache_file(case).exists()


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_doctype_in_a_late_chunk_aborts_the_download(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    served: List[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        yield b"<?xml version='1.0'?><root>"
        for i in range(50):
            served.append(i)
            yield b"<!ENTITY a 'b'>" if i == 3 else b"<x>y</x>"

    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(200, content=chunks()))
        _screen(case, agent, case.entity_query, origin)
    assert len(served) < 50, "the stream must be abandoned as soon as the refusal is hit"
    assert any("DOCTYPE/ENTITY" in e.detail for e in g.logs if e.action == f"{case.prefix}_SKIP")


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_nul_byte_payload_that_could_hide_a_doctype_is_refused(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    hidden = "<?xml version='1.0'?><!DOCTYPE x>".encode("utf-16-le")
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(200, content=hidden))
        _screen(case, agent, case.entity_query, origin)
    assert not _new_nodes(g, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "NUL" in skips[0].detail
    assert not _cache_file(case).exists()


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_oversize_stream_without_content_length_is_aborted_at_the_cap(case: ListCase, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pi_sources, "MAX_SANCTIONS_LIST_BYTES", 4096)
    agent, g, origin = _agent_with_origin(case.entity_query)
    served: List[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        yield b"<?xml version='1.0'?><root>"
        for i in range(100):
            served.append(i)
            yield b" " * 1024

    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(200, content=chunks()))
        _screen(case, agent, case.entity_query, origin)
    assert len(served) < 10, "download must stop at the cap, not drain the body"
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "cap" in skips[0].detail
    assert not _new_nodes(g, origin)
    assert not _cache_file(case).exists()
    assert list(_cache_file(case).parent.glob("*")) == [] if _cache_file(case).parent.exists() else True


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_oversize_declared_content_length_is_refused_without_reading_the_body(
    case: ListCase, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(pi_sources, "MAX_SANCTIONS_LIST_BYTES", 4096)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(
            return_value=httpx.Response(200, content=b"<root/>", headers={"content-length": "999999"})
        )
        _screen(case, agent, case.entity_query, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "cap" in skips[0].detail


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_parsing_is_streamed_with_iterparse_not_fromstring(case: ListCase, monkeypatch: pytest.MonkeyPatch):
    def boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("ET.fromstring would load the whole document in memory")

    monkeypatch.setattr(pi_sources.ET, "fromstring", boom)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    assert len(_new_nodes(g, origin)) == 1


# ----------------------------------------------------------------------------------------------
# Redirects: OFAC and the UN answer HTTP 302 to signed object storage; only allow-listed hosts are followed
# ----------------------------------------------------------------------------------------------

REDIRECT_CASES = [c for c in CASES if c.redirect_host]
SIGNED = "?X-Amz-Signature=very-secret-signature&X-Amz-Expires=3600"


@pytest.mark.parametrize("case", REDIRECT_CASES, ids=[c.source for c in REDIRECT_CASES])
def test_redirect_to_the_known_storage_host_is_followed_and_the_signed_url_is_never_logged(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(
            return_value=httpx.Response(
                302, headers={"location": f"https://{case.redirect_host}/files/list.xml{SIGNED}"}
            )
        )
        storage = router.route(host=case.redirect_host).mock(
            return_value=httpx.Response(200, content=case.xml.encode("utf-8"))
        )
        _screen(case, agent, case.entity_query, origin)
    assert storage.call_count == 1
    assert len(_new_nodes(g, origin)) == 1
    assert _cache_file(case).read_bytes() == case.xml.encode("utf-8")
    assert all("very-secret-signature" not in e.detail and "very-secret-signature" not in e.target for e in g.logs)
    node = next(iter(_new_nodes(g, origin).values()))
    assert "very-secret-signature" not in node.receipts[0].raw_snippet


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_redirect_to_an_unlisted_host_is_refused_without_contacting_it(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock(assert_all_called=False) as router:
        router.route(host=case.host, path=case.path).mock(
            return_value=httpx.Response(302, headers={"location": f"https://evil.example/steal.xml{SIGNED}"})
        )
        evil = router.route(host="evil.example").mock(return_value=httpx.Response(200, content=case.xml.encode()))
        _screen(case, agent, case.entity_query, origin)
    assert evil.call_count == 0
    assert not _new_nodes(g, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "redirect" in skips[0].detail and "evil.example" in skips[0].detail
    assert all("very-secret-signature" not in e.detail for e in g.logs)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_redirect_to_plain_http_is_refused(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock(assert_all_called=False) as router:
        router.route(host=case.host, path=case.path).mock(
            return_value=httpx.Response(302, headers={"location": f"http://{case.host}/plain.xml"})
        )
        _screen(case, agent, case.entity_query, origin)
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "redirect" in skips[0].detail


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_relative_same_host_redirect_is_followed(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(
            return_value=httpx.Response(301, headers={"location": "/moved/list.xml"})
        )
        router.route(host=case.host, path="/moved/list.xml").mock(
            return_value=httpx.Response(200, content=case.xml.encode("utf-8"))
        )
        _screen(case, agent, case.entity_query, origin)
    assert len(_new_nodes(g, origin)) == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_redirect_loop_is_cut_off(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = router.route(host=case.host).mock(return_value=httpx.Response(302, headers={"location": case.path}))
        _screen(case, agent, case.entity_query, origin)
    assert route.call_count <= 5
    skips = [e for e in g.logs if e.action == f"{case.prefix}_SKIP"]
    assert skips and "too many redirects" in skips[0].detail


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_redirect_without_a_location_header_is_a_clean_skip(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(302))
        _screen(case, agent, case.entity_query, origin)
    assert f"{case.prefix}_SKIP" in _actions(g)
    assert not _new_nodes(g, origin)


# ----------------------------------------------------------------------------------------------
# Failure handling: never raises, clean skip, backoff
# ----------------------------------------------------------------------------------------------

FAILURES: List[Tuple[str, Any]] = [
    ("http_500", httpx.Response(500, text="boom")),
    ("http_429", httpx.Response(429)),
    ("http_403", httpx.Response(403)),
    ("http_404", httpx.Response(404)),
    ("timeout", httpx.ReadTimeout("slow")),
    ("connect_error", httpx.ConnectError("refused")),
    ("empty_body", httpx.Response(200, content=b"")),
    ("malformed_xml", httpx.Response(200, content=b"<root><record>")),
    ("not_xml", httpx.Response(200, content=b"<html><body>maintenance</body></html>")),
    ("invalid_utf8", httpx.Response(200, content=b"<root>\xff\xfe</root>")),
]


@pytest.mark.parametrize("failure_name,failure", FAILURES, ids=[f[0] for f in FAILURES])
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_no_failure_ever_escapes_and_nothing_is_cached(case: ListCase, failure_name: str, failure: Any):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = router.route(host=case.host, path=case.path)
        if isinstance(failure, Exception):
            route.mock(side_effect=failure)
        else:
            route.mock(return_value=failure)
        result = _screen(case, agent, case.entity_query, origin)  # must not raise
    assert result is None
    assert not _new_nodes(g, origin), f"{failure_name} must not create nodes"
    assert f"{case.prefix}_SKIP" in _actions(g)
    assert not _cache_file(case).exists()
    leftovers = list(_cache_file(case).parent.glob("*")) if _cache_file(case).parent.exists() else []
    assert leftovers == [], "no temp file may survive a failed download"


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_failure_is_cooled_down_then_retried(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(500))
        _screen(case, agent, case.entity_query, origin)
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 1  # second call is inside the 300 s cooldown
        assert any("recently" in e.detail for e in g.logs if e.action == f"{case.prefix}_SKIP")

        PISourcesAgent._sanctions_failed_at[case.source] = time.monotonic() - 10_000
        route.mock(return_value=httpx.Response(200, content=case.xml.encode("utf-8")))
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 2
    assert len(_new_nodes(g, origin)) == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_unwritable_cache_dir_degrades_to_an_uncached_download(
    case: ListCase, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    blocker = tmp_path / "a_file_not_a_dir"
    blocker.write_text("x")
    monkeypatch.setattr(pi_sources, "BUNNYHOLE_CONFIG_DIR", blocker / "sub")
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    assert len(_new_nodes(g, origin)) == 1
    assert any("cache" in e.detail.lower() for e in g.logs if e.level == "warning")


# ----------------------------------------------------------------------------------------------
# Process cache, disk cache, TTL, stale fallback, permissions, atomic write
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_downloads_once_per_process_across_queries_and_agents(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    other, g2, origin2 = _agent_with_origin(case.person_query)
    with respx.mock as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
        _screen(case, agent, "Nobody Special", origin)
        _screen(case, other, case.person_query, origin2)
        assert route.call_count == 1
    assert len(_new_nodes(g2, origin2)) == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_concurrent_screens_share_one_download(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)

    async def go() -> None:
        await asyncio.gather(*(getattr(agent, case.method)(case.entity_query, origin, 1) for _ in range(4)))

    with respx.mock as router:
        route = _route_ok(router, case)
        _run(go())
        assert route.call_count == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_successful_download_is_cached_on_disk_0600_via_atomic_rename(case: ListCase, monkeypatch: pytest.MonkeyPatch):
    replaced: List[Tuple[Path, Path, int]] = []
    real_replace = os.replace

    def spy_replace(src: Any, dst: Any) -> None:
        replaced.append((Path(src), Path(dst), stat.S_IMODE(os.stat(src).st_mode)))
        real_replace(src, dst)

    monkeypatch.setattr(pi_sources.os, "replace", spy_replace)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    final = _cache_file(case)
    assert final.read_bytes() == case.xml.encode("utf-8")
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    assert len(replaced) == 1
    src, dst, src_mode = replaced[0]
    assert dst == final and src != final and src.parent == final.parent, "write-then-rename in the same directory"
    assert src_mode == 0o600, "the temp file must already be private when it is written"
    assert [p.name for p in final.parent.iterdir()] == [final.name], "no temp file left behind"


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_fresh_disk_cache_is_used_without_any_http_call(case: ListCase):
    _seed_cache(case, case.xml, age_s=3600)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock(assert_all_called=False) as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    assert route.call_count == 0
    assert len(_new_nodes(g, origin)) == 1
    assert any("on-disk cache" in e.detail for e in g.logs)
    assert f"{case.prefix}_SKIP" not in _actions(g), "a fresh cache is not a degraded run"


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_expired_disk_cache_is_refreshed(case: ListCase):
    path = _seed_cache(case, case.xml.replace("Acme", "Old"), age_s=pi_sources.SANCTIONS_CACHE_TTL_S + 60)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    assert route.call_count == 1
    assert len(_new_nodes(g, origin)) == 1
    assert time.time() - path.stat().st_mtime < 60, "the refreshed file replaces the stale one"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize(
    "failure",
    [httpx.Response(500), httpx.ReadTimeout("slow"), httpx.Response(200, content=BILLION_LAUGHS.encode("utf-8"))],
    ids=["http_500", "timeout", "refused_payload"],
)
def test_stale_cache_is_used_when_the_refresh_fails(case: ListCase, failure: Any):
    path = _seed_cache(case, case.xml, age_s=pi_sources.SANCTIONS_CACHE_TTL_S + 3600)
    stale_bytes = path.read_bytes()
    stale_ts = time.strftime("%Y-%m-%d", time.gmtime(path.stat().st_mtime))
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = router.route(host=case.host, path=case.path)
        if isinstance(failure, Exception):
            route.mock(side_effect=failure)
        else:
            route.mock(return_value=failure)
        _screen(case, agent, case.entity_query, origin)
    assert len(_new_nodes(g, origin)) == 1, "the stale list still screens the name"
    notes = [e.detail for e in g.logs if "using cached list from" in e.detail]
    assert notes and stale_ts in notes[0]
    assert path.read_bytes() == stale_bytes, "a failed refresh must leave the cache file untouched"
    assert [p.name for p in path.parent.iterdir()] == [path.name]


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_stale_cache_is_used_during_the_cooldown_instead_of_skipping(case: ListCase):
    _seed_cache(case, case.xml, age_s=pi_sources.SANCTIONS_CACHE_TTL_S + 3600)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(500))
        _screen(case, agent, case.entity_query, origin)
        PISourcesAgent.reset_sanctions_process_index(case.source)  # force a reload from disk inside the cooldown
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 1
    assert len(_new_nodes(g, origin)) == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_corrupt_stale_cache_and_failed_refresh_is_a_clean_skip(case: ListCase):
    _seed_cache(case, "<root><unclosed>", age_s=pi_sources.SANCTIONS_CACHE_TTL_S + 3600)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        router.route(host=case.host, path=case.path).mock(return_value=httpx.Response(500))
        _screen(case, agent, case.entity_query, origin)
    assert not _new_nodes(g, origin)
    assert f"{case.prefix}_SKIP" in _actions(g)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_cached_file_with_a_doctype_is_refused_too(case: ListCase):
    _seed_cache(case, BILLION_LAUGHS, age_s=10)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock(assert_all_called=False) as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    # A poisoned cache file is never parsed; the screen falls through to a fresh download.
    assert route.call_count == 1
    assert len(_new_nodes(g, origin)) == 1


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_process_index_expires_with_the_ttl(case: ListCase, monkeypatch: pytest.MonkeyPatch):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 1
        # Age both the in-memory index and the cache file past the TTL.
        path = _cache_file(case)
        old = time.time() - pi_sources.SANCTIONS_CACHE_TTL_S - 10
        os.utime(path, (old, old))
        real_monotonic = pi_sources._monotonic_s
        monkeypatch.setattr(
            pi_sources, "_monotonic_s", lambda: real_monotonic() + pi_sources.SANCTIONS_CACHE_TTL_S + 10
        )
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 2


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_reset_helper_clears_the_process_cache_and_failure_state(case: ListCase):
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        route = _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
        _cache_file(case).unlink()
        getattr(PISourcesAgent, case.reset)()
        _screen(case, agent, case.entity_query, origin)
        assert route.call_count == 2


# ----------------------------------------------------------------------------------------------
# netutil / proxy conventions
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_client_is_built_through_netutil_with_a_60s_timeout_and_no_redirects(
    case: ListCase, monkeypatch: pytest.MonkeyPatch
):
    built: List[Dict[str, Any]] = []
    real = netutil.new_async_client

    def spy(**kwargs: Any) -> httpx.AsyncClient:
        built.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(pi_sources, "new_async_client", spy)
    agent, g, origin = _agent_with_origin(case.entity_query)
    with respx.mock as router:
        _route_ok(router, case)
        _screen(case, agent, case.entity_query, origin)
    assert len(built) == 1
    assert built[0]["timeout"] == 60.0
    assert not built[0].get("follow_redirects")


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_default_proxy_is_inherited(case: ListCase, monkeypatch: pytest.MonkeyPatch):
    netutil.set_default_proxy("http://127.0.0.1:8899")
    seen: List[Dict[str, Any]] = []
    real_client = httpx.AsyncClient

    def recording_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        seen.append(dict(kwargs))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(netutil.httpx, "AsyncClient", recording_client)
    agent, g, origin = _agent_with_origin(case.entity_query)
    _screen(case, agent, case.entity_query, origin)  # may fail to connect: must still not raise
    assert seen and seen[0].get("proxy") == "http://127.0.0.1:8899"


# ----------------------------------------------------------------------------------------------
# Orchestrator wiring (PI mode only) and catalog entries
# ----------------------------------------------------------------------------------------------


def test_orchestrator_pi_mode_dispatches_the_three_screens_under_exact_source_names():
    from test_pi_runtime import _engagement, _orchestrator  # type: ignore[import-not-found]

    orch = _orchestrator(_engagement())

    async def go() -> dict:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)
        return orch.compile_full_result()

    result = asyncio.run(go())
    by_source = {e["source"]: e for e in result["pi"]["source_log"]}
    for source, method in (
        ("ofac_sdn", "screen_ofac_sdn"),
        ("un_consolidated", "screen_un_consolidated"),
        ("uk_sanctions_list", "screen_uk_sanctions_list"),
    ):
        assert by_source[source]["status"] == "negative", source
        getattr(orch.pi_sources, method).assert_awaited_once_with("Acme Holdings Ltd", node_id_of(orch), 1)


def node_id_of(orch: Any) -> str:
    return next(iter(orch.graph.nodes))


def test_orchestrator_without_engagement_never_touches_the_new_screens(monkeypatch: pytest.MonkeyPatch):
    from test_pi_runtime import _orchestrator  # type: ignore[import-not-found]

    called: List[str] = []

    async def spy(*_a: Any, **_k: Any) -> None:
        called.append("x")

    for method in ("screen_ofac_sdn", "screen_un_consolidated", "screen_uk_sanctions_list"):
        monkeypatch.setattr(PISourcesAgent, method, spy)
    orch = _orchestrator(None)
    assert orch.pi_sources is None

    async def go() -> None:
        _, node = orch._create_seed_node("Acme Holdings Ltd", hop_depth=0)
        await orch._execute_lead("company", "Acme Holdings Ltd", node.id, 1)

    asyncio.run(go())
    assert called == []


def test_catalog_marks_the_three_official_lists_implemented_and_verified_keyless():
    from bunnyhole.engine import pi_reference

    by_name = {s.name: s for s in pi_reference.SOURCES}
    for name in ("OFAC Sanctions List Search", "UN Security Council Consolidated List", "UK OFSI Consolidated List"):
        entry = by_name[name]
        assert entry.implemented and entry.verified and entry.access == "keyless", name
    assert "unauthenticated calls return 401" in by_name["CourtListener / RECAP"].caveats
    assert "COURTLISTENER_API_TOKEN" in by_name["CourtListener / RECAP"].caveats
    assert by_name["CourtListener / RECAP"].access == "free_account"
    assert "OPENSANCTIONS_API_KEY" in by_name["OpenSanctions"].caveats
    assert "keyless calls return 401" in by_name["OpenSanctions"].caveats
