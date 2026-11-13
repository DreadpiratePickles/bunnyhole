"""Casework may call only the source coroutines the PI sweep already runs.

The names are the recorder source names ``_execute_lead`` passes to ``_pi_task`` or ``_pi_skip``
(plus ``credential_combo``, which the credential branch logs with ``pi_recorder.skip``). Breach,
infostealer, and non-passive sources stay out of :data:`PI_DISPATCH`: casework cannot add one.
:data:`SOURCE_ACCEPTS` says which kind of target each source is built for, so a lead never sends a
person's name to a company registry or a company name to a domain tool.
This module does not import the orchestrator (that import would cycle).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, FrozenSet, List

SourceCall = Callable[[Any, str, str, int], Awaitable[Any]]

NOT_DISPATCHABLE = "not dispatchable in casework"

#: Breach contents, combo dumps, and active probes. Never keys of :data:`PI_DISPATCH`.
BLOCKED_IN_CASEWORK = frozenset({"hudsonrock", "leakcheck", "emailrep", "holehe", "credential_combo", "dexscreener"})


def _gleif(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.accountant.investigate_gleif_corporate_hierarchy(value, origin, hop)


def _opensanctions(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.accountant.investigate_opensanctions(value, origin, hop)


def _sec_edgar(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.accountant.investigate_sec_edgar(value, origin, hop)


def _nonprofit_990s(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.accountant.investigate_nonprofit_990s_and_usaspending(value, origin, hop)


def _news_narrative(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.journalist.investigate_news_and_narrative(value, origin, hop)


def _court_dockets(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.journalist.investigate_court_dockets(value, origin, hop)


def _wayback(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.journalist.investigate_wayback_ghost_edits(value, origin, hop)


def _uk_psc(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch._pi_collect_psc(value, origin, hop)


def _ca_sanctions(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.screen_canadian_sanctions(value, origin, hop)


def _ofac_sdn(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.screen_ofac_sdn(value, origin, hop)


def _un_consolidated(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.screen_un_consolidated(value, origin, hop)


def _uk_sanctions_list(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.screen_uk_sanctions_list(value, origin, hop)


def _cfpb_complaints(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.investigate_cfpb_complaints(value, origin, hop)


def _wikidata(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.pi_sources.investigate_wikidata_entity(value, origin, hop)


def _osint_domain(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.osint.investigate_domain_infrastructure(value, origin, hop)


def _osint_identity(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.osint.investigate_identity_and_handle(value, origin, hop)


def _email_pivots(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.osint.investigate_email_pivots(value, origin, hop)


def _phone_lookup(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.osint.investigate_phone_number(value, origin, hop)


def _ip_shodan_ripestat(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.osint.investigate_ip_shodan_and_ripestat(value, origin, hop)


def _onchain_evm(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.onchain.investigate_evm_address(value, origin, hop)


def _onchain_bitcoin(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.onchain.investigate_bitcoin_utxo(value, origin, hop)


def _aircraft_adsb(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.accountant.investigate_aircraft_adsb(value, origin, hop)


def _hackernews(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.journalist.investigate_hackernews_archive(value, origin, hop)


def _openalex(orch: Any, value: str, origin: str, hop: int) -> Awaitable[Any]:
    return orch.journalist.investigate_openalex_academic_and_grants(value, origin, hop)


PI_DISPATCH: Dict[str, SourceCall] = {
    "gleif": _gleif,
    "opensanctions": _opensanctions,
    "sec_edgar": _sec_edgar,
    "nonprofit_990s": _nonprofit_990s,
    "news_narrative": _news_narrative,
    "court_dockets": _court_dockets,
    "wayback": _wayback,
    "uk_psc": _uk_psc,
    "ca_sanctions": _ca_sanctions,
    "ofac_sdn": _ofac_sdn,
    "un_consolidated": _un_consolidated,
    "uk_sanctions_list": _uk_sanctions_list,
    "cfpb_complaints": _cfpb_complaints,
    "wikidata": _wikidata,
    "osint_domain": _osint_domain,
    "osint_identity": _osint_identity,
    "email_pivots": _email_pivots,
    "phone_lookup": _phone_lookup,
    "ip_shodan_ripestat": _ip_shodan_ripestat,
    "onchain_evm": _onchain_evm,
    "onchain_bitcoin": _onchain_bitcoin,
    "aircraft_adsb": _aircraft_adsb,
    "hackernews": _hackernews,
    "openalex": _openalex,
}

_NAMES: FrozenSet[str] = frozenset({"company", "person"})

#: Source -> the kinds of target it is built for. A company registry is not asked about a person, a domain
#: tool is not asked about a name, and a handle tool only takes a handle. A source that is not listed here
#: accepts nothing, so adding a dispatch entry without saying what it takes cannot run it.
SOURCE_ACCEPTS: Dict[str, FrozenSet[str]] = {
    "gleif": frozenset({"company"}),
    "uk_psc": frozenset({"company"}),
    "nonprofit_990s": frozenset({"company"}),
    "cfpb_complaints": frozenset({"company"}),
    "sec_edgar": _NAMES,
    "opensanctions": _NAMES,
    "ca_sanctions": _NAMES,
    "ofac_sdn": _NAMES,
    "un_consolidated": _NAMES,
    "uk_sanctions_list": _NAMES,
    "court_dockets": _NAMES,
    "news_narrative": _NAMES,
    "wikidata": _NAMES,
    "openalex": frozenset({"person"}),
    "wayback": frozenset({"domain"}),
    "osint_domain": frozenset({"domain"}),
    "osint_identity": frozenset({"username"}),
    "hackernews": frozenset({"username"}),
    "email_pivots": frozenset({"email"}),
    "phone_lookup": frozenset({"phone"}),
    "ip_shodan_ripestat": frozenset({"ip"}),
    "onchain_evm": frozenset({"wallet"}),
    "onchain_bitcoin": frozenset({"bitcoin"}),
    "aircraft_adsb": frozenset({"aircraft"}),
}


#: How each source is named in prose (the log, the answers, the report). The recorder name stays in tables.
SOURCE_NAMES: Dict[str, str] = {
    "gleif": "GLEIF",
    "uk_psc": "Companies House",
    "sec_edgar": "SEC EDGAR",
    "nonprofit_990s": "ProPublica 990s and USAspending",
    "opensanctions": "OpenSanctions",
    "ca_sanctions": "the Canada SEMA list",
    "ofac_sdn": "the OFAC SDN list",
    "un_consolidated": "the UN Consolidated List",
    "uk_sanctions_list": "the UK Sanctions List",
    "court_dockets": "CourtListener dockets",
    "news_narrative": "the news search",
    "wayback": "the Wayback Machine",
    "cfpb_complaints": "the CFPB complaint database",
    "wikidata": "Wikidata",
    "osint_domain": "the domain records",
    "osint_identity": "the handle search",
    "email_pivots": "the email lookup",
    "phone_lookup": "the phone lookup",
    "ip_shodan_ripestat": "Shodan and RIPEstat",
    "onchain_evm": "the EVM ledger",
    "onchain_bitcoin": "the Bitcoin ledger",
    "aircraft_adsb": "the aircraft tracker",
    "hackernews": "the Hacker News archive",
    "openalex": "OpenAlex",
    "holehe": "Holehe",
}


def source_name(source: str) -> str:
    """The prose name of a recorder source; an unknown source keeps its own name."""
    return SOURCE_NAMES.get(source, source)


def sources_for(target_type: str, sources: List[str]) -> List[str]:
    """``sources`` that casework may run and that take a ``target_type`` target, in the given order."""
    kept: List[str] = []
    for source in sources:
        if source in PI_DISPATCH and target_type in SOURCE_ACCEPTS.get(source, frozenset()) and source not in kept:
            kept.append(source)
    return kept

#: Every recorder source name the PI sweep can already log. Dispatch keys are a subset.
SWEEP_PI_SOURCES: frozenset[str] = frozenset(
    {
        "aircraft_adsb",
        "ca_sanctions",
        "cfpb_complaints",
        "court_dockets",
        "credential_combo",
        "dexscreener",
        "email_pivots",
        "gleif",
        "hackernews",
        "hudsonrock",
        "ip_shodan_ripestat",
        "news_narrative",
        "nonprofit_990s",
        "ofac_sdn",
        "onchain_bitcoin",
        "onchain_evm",
        "openalex",
        "opensanctions",
        "osint_domain",
        "osint_identity",
        "phone_lookup",
        "sec_edgar",
        "uk_psc",
        "uk_sanctions_list",
        "un_consolidated",
        "wayback",
        "wikidata",
        "wikipedia",
        *PI_DISPATCH,
    }
)


def refusal_reason(source: str) -> str | None:
    """``None`` when casework may run ``source``; otherwise :data:`NOT_DISPATCHABLE`."""
    return None if source in PI_DISPATCH else NOT_DISPATCHABLE


__all__ = [
    "BLOCKED_IN_CASEWORK",
    "NOT_DISPATCHABLE",
    "PI_DISPATCH",
    "SOURCE_ACCEPTS",
    "SOURCE_NAMES",
    "SWEEP_PI_SOURCES",
    "SourceCall",
    "refusal_reason",
    "source_name",
    "sources_for",
]
