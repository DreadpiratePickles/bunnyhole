"""Tests for the PI knowledge tables (pi_reference) and the custodian / handoff logic (pi_escalation).

Pure data and lookups: no network. Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md sections
3.5, 3.6 and 5.
"""

from __future__ import annotations

import pytest

from bunnyhole.engine import pi_escalation, pi_reference
from bunnyhole.engine.pi import CaseType, Custodian, PIEngagement
from bunnyhole.engine.pi_escalation import CUSTODIAN_RULES, custodians_for, handoff_sheet
from bunnyhole.engine.pi_reference import (
    CYCLE_STAGES,
    DOCTRINE,
    LEGAL_RULES,
    OUT_OF_SCOPE,
    PLAYBOOKS,
    SOURCES,
    UBO_STEPS,
    UNLAWFUL_METHODS,
    legal_for,
    playbook_for,
    render_guide,
    sources_for,
)

ALLOWED_ACCESS = {"keyless", "free_account", "free_api_key", "open_source", "free_noncommercial"}
SOURCE_NAMES = {s.name.casefold() for s in SOURCES}

FINDING_KINDS = {
    "exchange_deposit_address",
    "bank_account_indicated",
    "registered_agent",
    "company_records",
    "phone_carrier",
    "isp_ip_assignment",
    "employer",
    "vehicle_registry",
    "land_title",
    "social_platform_account",
    "domain_registrant",
    "vessel_aircraft_registry",
}


def _by_name(name: str):
    matches = [s for s in SOURCES if s.name == name]
    assert len(matches) == 1, f"{name!r} should appear exactly once in SOURCES"
    return matches[0]


# ----------------------------------------------------------------------------------------------
# SOURCES
# ----------------------------------------------------------------------------------------------


def test_every_source_has_https_url_and_allowed_access():
    assert len(SOURCES) >= 80
    for s in SOURCES:
        assert s.url.startswith("https://"), s.name
        assert s.access in ALLOWED_ACCESS, s.name
        assert s.what.strip(), s.name
        assert s.categories, s.name
        assert s.jurisdiction.strip(), s.name


def test_source_names_are_unique():
    names = [s.name.casefold() for s in SOURCES]
    assert len(names) == len(set(names))


def test_no_out_of_scope_name_in_sources():
    oos = {item["name"].casefold() for item in OUT_OF_SCOPE}
    assert oos, "OUT_OF_SCOPE must not be empty"
    assert not (oos & SOURCE_NAMES)


REQUIRED_SOURCE_NAMES = [
    # research/12 section 5 table
    "CFPB Consumer Complaints", "Wikidata", "GAC Canadian Sanctions (SEMA)", "Companies House PSC (UK)",
    "Corporations Canada", "crt.sh", "FINRA BrokerCheck", "NMLS Consumer Access", "FAA Aircraft Registry",
    "FCC ULS", "USCG PSIX", "NSOPW", "BOP Inmate Locator", "Charley Project", "Doe Network", "FamilySearch",
    "Find a Grave", "Chronicling America", "CRA Charities Listings", "CIPO Trademarks", "ABN Lookup",
    "Open Ownership / BODS", "Overpass Turbo", "Copernicus Browser", "InVID-WeVerify", "FotoForensics",
    "ArchiveBox", "OpenTimestamps", "Timesketch", "Datashare", "GIJN Research Tools",
    # masterclass sections 3-5
    "PACER Case Locator", "CourtListener / RECAP", "UniCourt", "Judyrecords", "SEC EDGAR", "OpenCorporates",
    "SAM.gov", "NamUs", "SearchSystems.net", "Black Book Online", "OSINT Framework",
    "Bellingcat Online Investigation Toolkit", "Awesome OSINT", "Companies House", "GLEIF LEI Search",
    "ICIJ Offshore Leaks", "OCCRP Aleph", "OpenSanctions", "OFAC Sanctions List Search",
    "UN Security Council Consolidated List", "EU Sanctions Map", "UK OFSI Consolidated List", "LittleSis",
    "Equasis", "Etherscan", "BscScan", "Blockchain.com Explorer", "Arkham Intelligence", "Breadcrumbs",
    "CanLII", "Ontario Business Registry", "Teranet / OnLand", "Wayback Machine", "archive.today", "WiGLE",
    "ADS-B Exchange", "SunCalc", "Mapillary", "Google Earth", "ExifTool", "TinEye", "Yandex Images",
    "Google Lens", "HaveIBeenPwned", "Shodan", "theHarvester", "Sherlock", "Maigret", "Holehe", "GHunt",
    "PhoneInfoga", "SpiderFoot", "Maltego CE", "Recon-ng", "Censys", "Hunter",
]


@pytest.mark.parametrize("name", REQUIRED_SOURCE_NAMES)
def test_required_source_present(name):
    _by_name(name)


def test_implemented_flags_follow_the_code():
    implemented = {s.name for s in SOURCES if s.implemented}
    must_be_implemented = {
        "GLEIF LEI Search", "OpenSanctions", "SEC EDGAR", "CourtListener / RECAP", "Wayback Machine",
        "crt.sh", "Hunter", "Censys", "Shodan", "Companies House PSC (UK)", "GAC Canadian Sanctions (SEMA)",
        "CFPB Consumer Complaints", "Wikidata", "Sherlock", "Holehe",
        "OFAC Sanctions List Search", "UN Security Council Consolidated List", "UK OFSI Consolidated List",
    }
    assert must_be_implemented <= implemented
    # Not queried by any agent today: must not claim otherwise.
    for name in ("OpenCorporates", "PACER Case Locator", "NamUs", "Etherscan",
                 "GHunt", "Maltego CE", "HaveIBeenPwned"):
        assert not _by_name(name).implemented, name


def test_verified_only_where_research_marks_v():
    verified = {s.name for s in SOURCES if s.verified}
    assert verified == {
        "CFPB Consumer Complaints", "Wikidata", "GAC Canadian Sanctions (SEMA)", "Companies House PSC (UK)",
        "Corporations Canada", "crt.sh", "NSOPW", "BOP Inmate Locator", "Charley Project", "ABN Lookup",
        "OpenTimestamps", "Timesketch", "Datashare",
        "OFAC Sanctions List Search", "UN Security Council Consolidated List", "UK OFSI Consolidated List",
    }


def test_four_new_pi_sources_have_honest_access():
    assert _by_name("Companies House PSC (UK)").access == "free_api_key"
    for name in ("GAC Canadian Sanctions (SEMA)", "CFPB Consumer Complaints", "Wikidata"):
        assert _by_name(name).access == "keyless"


def test_every_source_belongs_to_some_case_type():
    covered: set[str] = set()
    for ct in CaseType:
        covered |= {s.name for s in sources_for(ct)}
    assert {s.name for s in SOURCES} - covered == set()


def test_sources_for_no_filter_returns_everything():
    assert len(sources_for()) == len(SOURCES)


def test_sources_for_case_type_filters():
    missing = {s.name for s in sources_for(CaseType.MISSING_PERSON)}
    assert "NamUs" in missing and "Charley Project" in missing
    assert "Companies House PSC (UK)" not in missing
    asset = {s.name for s in sources_for(CaseType.ASSET_SEARCH)}
    assert {"GLEIF LEI Search", "Equasis", "Etherscan", "OpenSanctions"} <= asset
    assert "NamUs" not in asset


def test_sources_for_accepts_string_case_type():
    assert [s.name for s in sources_for("missing_person")] == [s.name for s in sources_for(CaseType.MISSING_PERSON)]
    with pytest.raises(ValueError):
        sources_for("not_a_case_type")


def test_sources_for_jurisdiction_filters_and_keeps_global_sources():
    uk = sources_for(jurisdiction="uk")
    assert {s.jurisdiction for s in uk} <= {"uk", "intl"}
    assert "Companies House PSC (UK)" in {s.name for s in uk}
    assert "SEC EDGAR" not in {s.name for s in uk}
    ontario = {s.name for s in sources_for(jurisdiction="ca-on")}
    assert {"Ontario Business Registry", "Corporations Canada", "CanLII", "OpenSanctions"} <= ontario
    assert "Companies House PSC (UK)" not in ontario
    us_state = {s.name for s in sources_for(jurisdiction="US-NY")}
    assert "SEC EDGAR" in us_state


def test_sources_for_implemented_only():
    impl = sources_for(implemented_only=True)
    assert impl and all(s.implemented for s in impl)
    assert len(impl) < len(SOURCES)
    combined = sources_for(CaseType.ASSET_SEARCH, "ca-on", implemented_only=True)
    assert all(s.implemented and s.jurisdiction in {"ca-on", "ca", "intl"} for s in combined)


def test_sources_for_returns_copies_not_the_global_list():
    got = sources_for()
    got.clear()
    assert SOURCES


# ----------------------------------------------------------------------------------------------
# OUT_OF_SCOPE, UNLAWFUL_METHODS
# ----------------------------------------------------------------------------------------------


def test_out_of_scope_entries_are_honest_and_hand_off():
    names = {i["name"] for i in OUT_OF_SCOPE}
    for must in ("TLOxp", "Tracers", "IRBsearch", "idiCORE", "Accurint", "CLEAR", "SkipSmasher", "Delvepoint",
                 "Experian", "Equifax", "Orbis", "Sayari", "Dun & Bradstreet", "Chainalysis", "TRM Labs",
                 "Elliptic", "DeHashed", "License-plate-reader (LPR) data", "Intelius", "BeenVerified",
                 "Spokeo", "TruePeopleSearch", "FastPeopleSearch", "That'sThem", "PeopleFinders"):
        assert must in names, must
    assert len(names) == len(OUT_OF_SCOPE), "OUT_OF_SCOPE names must be unique"
    for item in OUT_OF_SCOPE:
        assert item["why"].strip()
        assert "licensed investigator" in item["why"].lower(), item["name"]


def test_unlawful_methods_cover_the_manual():
    text = " ".join(UNLAWFUL_METHODS).lower()
    for needle in ("pretext", "gps", "record", "hack", "trespass", "impersonat", "wiretap", "stalk",
                   "sealed", "medical"):
        assert needle in text, needle


# ----------------------------------------------------------------------------------------------
# LEGAL_RULES / legal_for
# ----------------------------------------------------------------------------------------------


def test_legal_rules_shape_and_keys():
    assert set(LEGAL_RULES) == {"us", "ca-on", "general"}
    for key, items in LEGAL_RULES.items():
        assert items, key
        for item in items:
            assert set(item) == {"rule", "applies", "practical", "verify"}, item
            assert all(isinstance(v, str) and v.strip() for v in item.values()), item


def _rules_text(key: str) -> str:
    return " ".join(f"{i['rule']} {i['applies']} {i['practical']}" for i in LEGAL_RULES[key]).lower()


def test_us_rules_carry_the_manual_framework():
    text = _rules_text("us")
    for needle in ("fcra", "glba", "6821", "dppa", "fdcpa", "tcpa", "hipaa", "one-party", "all-party",
                   "hawaii", "michigan", "north dakota", "uk", "intelligence only", "idaho", "mississippi",
                   "south dakota"):
        assert needle in text, needle


def test_ontario_rules_carry_the_manual_framework_and_verify_notes():
    text = _rules_text("ca-on")
    for needle in ("psisa", "2005", "50-hour", "60-question", "digital", "two years", "pipeda", "s.184", "s.264",
                   "solicitor general"):
        assert needle in text, needle
    flagged = [i for i in LEGAL_RULES["ca-on"] if "psisa" in i["rule"].lower() or "criminal code" in i["rule"].lower()]
    assert flagged
    for item in flagged:
        assert item["verify"].lower().startswith("verify"), item["rule"]


def test_general_rules_cover_universal_limits():
    text = _rules_text("general")
    for needle in ("pretext", "hack", "trespass", "police", "police powers", "not legal advice"):
        assert needle in text, needle


def test_legal_for_returns_general_plus_jurisdiction():
    us = legal_for("us")
    assert us[: len(LEGAL_RULES["general"])] == LEGAL_RULES["general"]
    assert len(us) == len(LEGAL_RULES["general"]) + len(LEGAL_RULES["us"])
    on = legal_for("CA-ON ")
    assert len(on) == len(LEGAL_RULES["general"]) + len(LEGAL_RULES["ca-on"])
    assert legal_for("us-ny") == us


def test_legal_for_unknown_jurisdiction_returns_general_only():
    assert legal_for("atlantis") == LEGAL_RULES["general"]
    assert legal_for("") == LEGAL_RULES["general"]
    assert legal_for("general") == LEGAL_RULES["general"]


def test_legal_for_returns_copies():
    legal_for("us")[0]["rule"] = "tampered"
    assert LEGAL_RULES["general"][0]["rule"] != "tampered"


# ----------------------------------------------------------------------------------------------
# PLAYBOOKS
# ----------------------------------------------------------------------------------------------


def test_all_six_playbooks_present_and_consistent():
    assert set(PLAYBOOKS) == set(CaseType)
    for ct, pb in PLAYBOOKS.items():
        assert pb.case_type == ct
        assert pb.objective.strip() and pb.done_when.strip()
        assert len(pb.steps) >= 4, ct
        assert [s.order for s in pb.steps] == list(range(1, len(pb.steps) + 1)), ct
        assert len(pb.typical_hypotheses) >= 2, ct
        assert pb.escalate_when and pb.pitfalls, ct
        for step in pb.steps:
            assert step.action.strip() and step.legal_gate.strip() and step.stop_if.strip(), (ct, step.order)


def test_playbook_step_sources_exist_in_catalog_unless_handoff():
    for ct, pb in PLAYBOOKS.items():
        for step in pb.steps:
            if step.cost == "handoff":
                continue
            for src in step.sources:
                assert src.casefold() in SOURCE_NAMES, (ct, step.order, src)


def test_playbook_step_cost_matches_source_access():
    by_name = {s.name.casefold(): s for s in SOURCES}
    for ct, pb in PLAYBOOKS.items():
        for step in pb.steps:
            if step.cost == "handoff":
                continue
            needs_key = any(by_name[src.casefold()].access == "free_api_key" for src in step.sources)
            assert (step.cost == "free_key") == needs_key, (ct, step.order, step.cost)


def test_playbooks_have_at_least_one_handoff_step_where_public_data_ends():
    for ct in (CaseType.LOCATE, CaseType.ASSET_SEARCH, CaseType.FRAUD_SCREEN):
        assert any(s.cost == "handoff" for s in PLAYBOOKS[ct].steps), ct


def _playbook_text(ct: CaseType) -> str:
    pb = PLAYBOOKS[ct]
    parts = [pb.objective, pb.done_when, *pb.escalate_when, *pb.pitfalls, *pb.typical_hypotheses]
    for s in pb.steps:
        parts.extend([s.action, s.legal_gate, s.stop_if, *s.sources])
    return " ".join(parts).lower()


def test_asset_search_has_the_required_steps():
    text = _playbook_text(CaseType.ASSET_SEARCH)
    assert "lifestyle" in text and "declared income" in text
    assert "vessel" in text and "aircraft" in text and "manager" in text
    assert "cash-out" in text
    assert "12-step" in text or "12 step" in text
    assert "50%" in text or "50 percent" in text
    assert "nominee" in text


def test_missing_person_routes_to_law_enforcement_never_the_client():
    text = _playbook_text(CaseType.MISSING_PERSON)
    assert "law enforcement" in text
    assert "never" in text and "client" in text


def test_playbook_pitfalls_name_the_classic_traps():
    text = " ".join(" ".join(pb.pitfalls) for pb in PLAYBOOKS.values()).lower()
    for needle in ("stale", "marketing", "common name", "registered-agent", "consumer"):
        assert needle in text, needle


def test_background_playbook_forbids_eligibility_use():
    text = _playbook_text(CaseType.BACKGROUND)
    assert "eligibility" in text and "fcra" in text


def test_playbook_for_accepts_string_or_enum():
    assert playbook_for("locate") is PLAYBOOKS[CaseType.LOCATE]
    assert playbook_for(CaseType.LOCATE) is PLAYBOOKS[CaseType.LOCATE]
    assert playbook_for(" Asset_Search ") is PLAYBOOKS[CaseType.ASSET_SEARCH]
    with pytest.raises(ValueError):
        playbook_for("burglary")


# ----------------------------------------------------------------------------------------------
# UBO_STEPS, CYCLE_STAGES, DOCTRINE, render_guide
# ----------------------------------------------------------------------------------------------


def test_ubo_steps_are_the_twelve_in_order():
    assert [s["step"] for s in UBO_STEPS] == list(range(1, 13))
    for s in UBO_STEPS:
        assert s["action"].strip()
        assert s["tools"], s["step"]
        for tool in s["tools"]:
            assert tool.casefold() in SOURCE_NAMES, (s["step"], tool)
    actions = " ".join(s["action"] for s in UBO_STEPS).lower()
    for needle in ("anchor", "historical", "nominee", "50%", "fatf", "crypto", "sha-256"):
        assert needle in actions, needle


def test_cycle_stages_are_the_five_in_order():
    assert [c["order"] for c in CYCLE_STAGES] == [1, 2, 3, 4, 5]
    names = [c["name"].lower() for c in CYCLE_STAGES]
    for needle in ("intake", "desk research", "field verification", "corroboration", "court-ready report"):
        assert any(needle in n for n in names), needle


DOCTRINE_KEYWORDS = [
    "decision", "vet", "conflict", "cheapest", "identity", "not a link", "corroborat", "negative",
    "contradiction", "change the conclusion", "custodian", "bottom line", "passive",
]


def test_doctrine_has_thirteen_ordered_items():
    assert [d["order"] for d in DOCTRINE] == list(range(1, 14))
    for item, keyword in zip(DOCTRINE, DOCTRINE_KEYWORDS):
        assert keyword in item["title"].lower(), (item["order"], keyword)
        assert item["summary"].strip()


def test_render_guide_mentions_all_doctrine_items_and_cycle_stages():
    guide = render_guide()
    lowered = guide.lower()
    assert guide.startswith("# ")
    for item in DOCTRINE:
        assert item["title"].lower() in lowered, item["title"]
    for keyword in DOCTRINE_KEYWORDS:
        assert keyword in lowered, keyword
    for stage in CYCLE_STAGES:
        assert stage["name"].lower() in lowered, stage["name"]
    assert "not legal advice" in lowered


# ----------------------------------------------------------------------------------------------
# CUSTODIAN_RULES / custodians_for
# ----------------------------------------------------------------------------------------------


def test_custodian_rules_cover_the_full_finding_kind_vocabulary():
    assert {r["finding_kind"] for r in CUSTODIAN_RULES} == FINDING_KINDS
    assert len(CUSTODIAN_RULES) == len(FINDING_KINDS), "one rule per finding kind"
    for rule in CUSTODIAN_RULES:
        assert set(rule["instruments"]) == {"us", "ca-on", "uk", "intl"}, rule["finding_kind"]
        assert all(v.strip() for v in rule["instruments"].values())
        assert rule["custodian"].strip() and rule["note"].strip()


def test_custodians_for_differs_by_jurisdiction():
    kinds = {"exchange_deposit_address"}
    us = custodians_for(kinds, "us")[0]
    on = custodians_for(kinds, "ca-on")[0]
    uk = custodians_for(kinds, "uk")[0]
    intl = custodians_for(kinds, "intl")[0]
    assert "subpoena" in us.instrument.lower()
    assert "norwich pharmacal" in on.instrument.lower()
    assert "norwich pharmacal" in uk.instrument.lower()
    assert "mlat" in intl.instrument.lower() or "hague" in intl.instrument.lower()
    assert len({us.instrument, on.instrument, uk.instrument, intl.instrument}) == 4
    assert [c.jurisdiction for c in (us, on, uk, intl)] == ["us", "ca-on", "uk", "intl"]


def test_custodians_for_unknown_jurisdiction_falls_back_to_intl():
    got = custodians_for({"isp_ip_assignment"}, "atlantis")
    assert len(got) == 1 and got[0].jurisdiction == "intl"
    assert got[0].instrument == custodians_for({"isp_ip_assignment"}, "intl")[0].instrument
    assert custodians_for({"isp_ip_assignment"}, "")[0].jurisdiction == "intl"


def test_custodians_for_normalises_jurisdiction_aliases():
    assert custodians_for({"employer"}, " US-CA ")[0].jurisdiction == "us"
    assert custodians_for({"employer"}, "GB")[0].jurisdiction == "uk"
    assert custodians_for({"employer"}, "CA-ON")[0].jurisdiction == "ca-on"


def test_custodians_for_every_kind_every_jurisdiction_returns_model_objects():
    for jurisdiction in ("us", "ca-on", "uk", "intl"):
        got = custodians_for(FINDING_KINDS, jurisdiction)
        assert len(got) == len(FINDING_KINDS)
        assert all(isinstance(c, Custodian) for c in got)
        assert all(c.finding and c.custodian and c.instrument for c in got)


def test_custodians_for_ignores_unknown_kinds_and_empty_input():
    assert custodians_for(set(), "us") == []
    assert custodians_for({"telepathy"}, "us") == []
    assert len(custodians_for({"telepathy", "land_title"}, "us")) == 1


def test_custodians_for_order_is_deterministic():
    kinds = {"land_title", "employer", "registered_agent"}
    assert [c.finding for c in custodians_for(kinds, "us")] == [c.finding for c in custodians_for(kinds, "us")]
    order = [r["finding_kind"] for r in CUSTODIAN_RULES]
    got_kinds = [r["finding_kind"] for r in CUSTODIAN_RULES if r["finding_kind"] in kinds]
    assert [k for k in order if k in kinds] == got_kinds


def test_licensed_investigator_routes_are_named_where_records_are_confirmable():
    for kind in ("employer", "vehicle_registry", "phone_carrier"):
        rule = next(r for r in CUSTODIAN_RULES if r["finding_kind"] == kind)
        assert "licensed" in rule["note"].lower(), kind
    employer = next(r for r in CUSTODIAN_RULES if r["finding_kind"] == "employer")
    assert "field verification" in employer["note"].lower()


def test_custodian_instruments_never_suggest_unlawful_methods():
    blob = " ".join(" ".join(r["instruments"].values()) for r in CUSTODIAN_RULES).lower()
    for bad in ("pretext", "impersonat", "hack", "wiretap"):
        assert bad not in blob


# ----------------------------------------------------------------------------------------------
# handoff_sheet
# ----------------------------------------------------------------------------------------------


def _engagement(**over) -> PIEngagement:
    base = {
        "engagement_id": "pi_0123456789",
        "case_type": CaseType.ASSET_SEARCH,
        "purpose": "Enforce judgment 24-CV-1234 against the debtor",
        "matter_ref": "24-CV-1234",
        "jurisdiction": "ca-on",
        "created_at_utc": "2026-11-09T12:00:00+00:00",
    }
    base.update(over)
    return PIEngagement(**base)


def _check_no_overclaims(lines: list[str]) -> None:
    for line in lines:
        assert line.strip() == line and line, repr(line)
        scrubbed = line.lower().replace("unverified", "")
        assert "verified" not in scrubbed, line
        assert "confirmed" not in scrubbed, line
        assert "proven" not in scrubbed, line


def test_handoff_sheet_has_the_three_line_shapes():
    custodians = custodians_for({"exchange_deposit_address"}, "ca-on")
    lines = handoff_sheet(
        _engagement(),
        {"names": ["Jane Q. Debtor"], "addresses": ["12 Example Rd, Toronto ON"], "phones": ["+14165550100"]},
        custodians,
    )
    assert any(line.startswith("Run through licensed database: Jane Q. Debtor") for line in lines)
    assert any(line.startswith("Run through licensed database: +14165550100") for line in lines)
    assert any(line.startswith("Field verification (public place only; licensed investigator): 12 Example Rd")
               for line in lines)
    assert any(line.startswith("Request via counsel: ") and custodians[0].custodian in line
               and "Norwich Pharmacal" in line for line in lines)
    _check_no_overclaims(lines)


def test_handoff_sheet_never_emits_empty_identifier_lines():
    lines = handoff_sheet(
        _engagement(matter_ref=""),
        {"names": ["", "   ", "Jane Debtor", "Jane Debtor"], "addresses": [], "phones": [" "], "emails": []},
        [],
    )
    assert sum("Jane Debtor" in line for line in lines) == 1, "duplicates collapse"
    for line in lines:
        assert not line.rstrip().endswith(":"), repr(line)
        assert not line.endswith(": "), repr(line)
    assert not any("Matter reference" in line for line in lines), "no empty matter-ref line"
    _check_no_overclaims(lines)


def test_handoff_sheet_with_nothing_to_hand_off_is_still_honest():
    lines = handoff_sheet(_engagement(), {}, [])
    assert lines, "header and disclaimer lines are always present"
    assert not any(line.startswith(("Run through", "Field verification", "Request via")) for line in lines)
    _check_no_overclaims(lines)


def test_handoff_sheet_states_the_engagement_and_limits():
    lines = handoff_sheet(_engagement(), {"names": ["Jane Debtor"]}, [])
    text = "\n".join(lines)
    assert "pi_0123456789" in text
    assert "24-CV-1234" in text
    assert "asset_search" in text
    assert "not a consumer report" in text.lower()
    assert "unverified" in text.lower()


def test_handoff_sheet_wallets_and_unknown_kinds_do_not_crash_and_stay_scoped():
    lines = handoff_sheet(
        _engagement(),
        {"wallets": ["0xabc"], "domains": ["example.com"], "mystery_kind": ["zzz"], "organizations": ["Acme Ltd"]},
        [],
    )
    text = "\n".join(lines)
    for value in ("0xabc", "example.com", "Acme Ltd"):
        assert value in text
    assert "Field verification" not in text, "field verification is only for addresses"
    _check_no_overclaims(lines)


def test_handoff_sheet_does_not_mutate_inputs():
    ids = {"names": ["Jane Debtor", "Jane Debtor"]}
    handoff_sheet(_engagement(), ids, [])
    assert ids == {"names": ["Jane Debtor", "Jane Debtor"]}


def test_module_public_surface():
    assert pi_escalation.CUSTODIAN_RULES is CUSTODIAN_RULES
    assert pi_reference.SOURCES is SOURCES


# ----------------------------------------------------------------------------------------------
# escalate_keys: machine keys on playbook escalation items (evaluated by pi_runtime)
# ----------------------------------------------------------------------------------------------


def test_every_playbook_maps_some_escalation_items_to_known_machine_keys():
    for case_type, playbook in PLAYBOOKS.items():
        # missing_person has no automated source, so none of its items can be evaluated: deliberately unkeyed
        assert bool(playbook.escalate_keys) == (case_type is not CaseType.MISSING_PERSON), case_type
        for text, key in playbook.escalate_keys.items():
            assert text in playbook.escalate_when, (case_type, text)  # keyed by the verbatim escalate_when text
            assert key in pi_reference.ESCALATION_KEYS, (case_type, key)


def test_escalation_key_vocabulary_is_exactly_what_the_runtime_can_evaluate():
    from bunnyhole.engine import pi_runtime

    assert frozenset(pi_runtime.ESCALATION_EVALUATORS) == pi_reference.ESCALATION_KEYS


def test_escalate_keys_default_to_empty_and_roundtrip():
    from bunnyhole.engine.pi_reference import Playbook

    bare = Playbook(case_type=CaseType.LOCATE, objective="o", done_when="d", steps=[], escalate_when=["x"],
                    pitfalls=[], typical_hypotheses=[])
    assert bare.escalate_keys == {}
    assert Playbook.model_validate(PLAYBOOKS[CaseType.ASSET_SEARCH].model_dump()) == PLAYBOOKS[CaseType.ASSET_SEARCH]


def test_ownership_and_sanctions_items_carry_the_expected_keys():
    due = PLAYBOOKS[CaseType.DUE_DILIGENCE]
    assert set(due.escalate_keys.values()) >= {"sanctions_or_50_rule", "unresolved_ownership"}
    assert "custodian_finding" in PLAYBOOKS[CaseType.ASSET_SEARCH].escalate_keys.values()
    assert "identity_unresolved" in PLAYBOOKS[CaseType.BACKGROUND].escalate_keys.values()


# ----------------------------------------------------------------------------------------------
# Holehe-style signup probes are not used in PI mode (reconciled with the runtime)
# ----------------------------------------------------------------------------------------------


def test_legal_rules_do_not_bless_signup_flow_probes_and_state_the_pi_mode_position():
    text = _rules_text("general")
    assert "not strictly passive" in text
    assert "not used in pi mode" in text
    assert "account-recovery" in text
    assert "signup-flow probes) are the line" not in text


def test_holehe_catalog_entry_matches_the_runtime_position():
    holehe = next(s for s in SOURCES if s.name == "Holehe")
    caveat = holehe.caveats.lower()
    assert "not used" in caveat and "pi mode" in caveat and "account-recovery" in caveat
