"""Offline checks for the casework source map. No orchestrator and no network."""

from __future__ import annotations

from bunnyhole.engine.pi_dispatch import (
    BLOCKED_IN_CASEWORK,
    NOT_DISPATCHABLE,
    PI_DISPATCH,
    SOURCE_ACCEPTS,
    SOURCE_NAMES,
    SWEEP_PI_SOURCES,
    refusal_reason,
    sources_for,
)

_EXPECTED_METHODS = {
    "gleif": "accountant.investigate_gleif_corporate_hierarchy",
    "opensanctions": "accountant.investigate_opensanctions",
    "sec_edgar": "accountant.investigate_sec_edgar",
    "nonprofit_990s": "accountant.investigate_nonprofit_990s_and_usaspending",
    "news_narrative": "journalist.investigate_news_and_narrative",
    "court_dockets": "journalist.investigate_court_dockets",
    "wayback": "journalist.investigate_wayback_ghost_edits",
    "uk_psc": "_pi_collect_psc",
    "ca_sanctions": "pi_sources.screen_canadian_sanctions",
    "ofac_sdn": "pi_sources.screen_ofac_sdn",
    "un_consolidated": "pi_sources.screen_un_consolidated",
    "uk_sanctions_list": "pi_sources.screen_uk_sanctions_list",
    "cfpb_complaints": "pi_sources.investigate_cfpb_complaints",
    "wikidata": "pi_sources.investigate_wikidata_entity",
    "osint_domain": "osint.investigate_domain_infrastructure",
    "osint_identity": "osint.investigate_identity_and_handle",
    "email_pivots": "osint.investigate_email_pivots",
    "phone_lookup": "osint.investigate_phone_number",
    "ip_shodan_ripestat": "osint.investigate_ip_shodan_and_ripestat",
    "onchain_evm": "onchain.investigate_evm_address",
    "onchain_bitcoin": "onchain.investigate_bitcoin_utxo",
    "aircraft_adsb": "accountant.investigate_aircraft_adsb",
    "hackernews": "journalist.investigate_hackernews_archive",
    "openalex": "journalist.investigate_openalex_academic_and_grants",
}


def test_dispatch_is_a_subset_of_the_sweep_and_not_blocked() -> None:
    assert set(PI_DISPATCH) <= SWEEP_PI_SOURCES
    assert set(PI_DISPATCH).isdisjoint(BLOCKED_IN_CASEWORK)
    assert set(PI_DISPATCH) == set(_EXPECTED_METHODS)


def test_refusal_reason_allows_only_dispatch_keys() -> None:
    assert refusal_reason("gleif") is None
    assert refusal_reason("holehe") == NOT_DISPATCHABLE
    assert refusal_reason("not_a_source") == NOT_DISPATCHABLE
    assert refusal_reason("hudsonrock") == NOT_DISPATCHABLE
    assert refusal_reason("credential_combo") == NOT_DISPATCHABLE
    assert refusal_reason("dexscreener") == NOT_DISPATCHABLE


def test_dispatch_calls_the_sweep_methods_without_the_network() -> None:
    class _Recorder:
        def __init__(self, owner: str) -> None:
            self.owner = owner

        def __getattr__(self, name: str):
            def method(*args: object) -> tuple[str, tuple[object, ...]]:
                called = f"{self.owner}.{name}"
                return called, args

            return method

    class _Orch:
        def __init__(self) -> None:
            self.accountant = _Recorder("accountant")
            self.journalist = _Recorder("journalist")
            self.pi_sources = _Recorder("pi_sources")
            self.osint = _Recorder("osint")
            self.onchain = _Recorder("onchain")

        def _pi_collect_psc(self, value: str, origin: str, hop: int) -> tuple[str, tuple[object, ...]]:
            return "_pi_collect_psc", (value, origin, hop)

    orch = _Orch()
    for source, method in _EXPECTED_METHODS.items():
        assert PI_DISPATCH[source](orch, "Acme", "origin-1", 2) == (method, ("Acme", "origin-1", 2))


def test_every_dispatchable_source_says_what_it_takes_and_has_a_prose_name() -> None:
    assert set(SOURCE_ACCEPTS) == set(PI_DISPATCH)
    assert all(SOURCE_ACCEPTS[source] for source in PI_DISPATCH)
    assert set(PI_DISPATCH) <= set(SOURCE_NAMES)


def test_a_source_only_runs_on_the_kind_of_target_it_is_built_for() -> None:
    wanted = ["gleif", "uk_psc", "ofac_sdn", "wayback", "osint_identity", "holehe", "ofac_sdn"]
    assert sources_for("company", wanted) == ["gleif", "uk_psc", "ofac_sdn"]
    assert sources_for("person", wanted) == ["ofac_sdn"]  # a person's name never goes to a company registry
    assert sources_for("domain", wanted) == ["wayback"]
    assert sources_for("username", wanted) == ["osint_identity"]
    assert sources_for("vessel", wanted) == []
