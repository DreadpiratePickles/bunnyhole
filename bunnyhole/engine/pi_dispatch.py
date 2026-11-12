"""Casework may call only the source coroutines the PI sweep already runs.

The names are the recorder source names ``_execute_lead`` passes to ``_pi_task`` or ``_pi_skip``
(plus ``credential_combo``, which the credential branch logs with ``pi_recorder.skip``). Breach,
infostealer, and non-passive sources stay out of :data:`PI_DISPATCH`: casework cannot add one.
This module does not import the orchestrator (that import would cycle).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

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
}

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
    "SWEEP_PI_SOURCES",
    "SourceCall",
    "refusal_reason",
]
