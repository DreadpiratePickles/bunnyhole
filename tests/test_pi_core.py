"""Tests for the PI stream core: engagement build, purpose gates, labels and independent-source counting."""

from __future__ import annotations

import hashlib
from datetime import datetime

import pytest

from bunnyhole.engine.pi import (
    FORBIDDEN_ELIGIBILITY_TERMS,
    MOTIVE_RED_FLAGS,
    NOTICES,
    CaseType,
    FindingLabel,
    PIEngagement,
    PIPurposeError,
    count_independent_sources,
    identifier_warnings,
    label_finding,
    looks_like_natural_person_name,
    motive_screen,
    require_matter_ref,
    validate_purpose,
)

GOOD_PURPOSE = "Locate judgment debtor to serve enforcement papers"


# --------------------------------------------------------------------------- validate_purpose


def test_purpose_too_short_is_refused() -> None:
    with pytest.raises(PIPurposeError):
        validate_purpose("find him")


def test_purpose_length_counted_after_strip() -> None:
    with pytest.raises(PIPurposeError):
        validate_purpose("   " + "x" * 14 + "   ")


def test_purpose_exactly_15_chars_is_accepted_and_stripped() -> None:
    assert validate_purpose("  " + "a" * 15 + "  ") == "a" * 15


def test_empty_purpose_is_refused() -> None:
    with pytest.raises(PIPurposeError):
        validate_purpose("")


def test_forbidden_terms_vocabulary_is_nonempty_and_lowercase() -> None:
    assert len(FORBIDDEN_ELIGIBILITY_TERMS) >= 8
    assert all(t == t.lower() for t in FORBIDDEN_ELIGIBILITY_TERMS)


@pytest.mark.parametrize("term", FORBIDDEN_ELIGIBILITY_TERMS)
def test_every_forbidden_eligibility_term_is_refused(term: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        validate_purpose(f"Client needs this for {term} purposes soon")
    assert "FCRA" in str(exc.value)


def test_forbidden_term_match_is_case_insensitive() -> None:
    term = FORBIDDEN_ELIGIBILITY_TERMS[0]
    with pytest.raises(PIPurposeError):
        validate_purpose(f"Required for {term.upper()} by the client")


def test_eligibility_message_points_to_compliant_screener() -> None:
    with pytest.raises(PIPurposeError) as exc:
        validate_purpose("Pre-employment screening of a job applicant")
    msg = str(exc.value)
    assert "FCRA-regulated" in msg
    assert "FCRA-compliant screening provider" in msg


def test_legitimate_purpose_passes() -> None:
    assert validate_purpose(GOOD_PURPOSE) == GOOD_PURPOSE


# --------------------------------------------------------------------------- motive_screen


def test_motive_vocabulary_covers_spec_phrases() -> None:
    for phrase in (
        "ex-girlfriend",
        "ex-wife",
        "stalk",
        "revenge",
        "protective order",
        "restraining order",
        "get back at",
    ):
        assert phrase in MOTIVE_RED_FLAGS


@pytest.mark.parametrize("flag", MOTIVE_RED_FLAGS)
@pytest.mark.parametrize("case_type", [CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON])
def test_motive_red_flags_refused_for_person_subjects(flag: str, case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError) as exc:
        motive_screen(f"I just need to know where she is, {flag}, please", case_type, True)
    msg = str(exc.value).lower()
    assert "will not run" in msg
    assert "law enforcement" in msg
    assert "counsel" in msg


@pytest.mark.parametrize("flag", MOTIVE_RED_FLAGS)
def test_motive_red_flags_allowed_for_entity_subjects(flag: str) -> None:
    for case_type in CaseType:
        motive_screen(f"Company run by someone, context: {flag}, check records", case_type, False)


@pytest.mark.parametrize("case_type", [CaseType.ASSET_SEARCH, CaseType.DUE_DILIGENCE, CaseType.FRAUD_SCREEN])
def test_motive_screen_does_not_apply_to_other_case_types(case_type: CaseType) -> None:
    motive_screen("Subject is my ex-wife and owes judgment money", case_type, True)


def test_motive_screen_is_case_insensitive_and_handles_curly_apostrophes() -> None:
    with pytest.raises(PIPurposeError):
        motive_screen("My EX-GIRLFRIEND moved away", CaseType.LOCATE, True)
    with pytest.raises(PIPurposeError):
        motive_screen("She won’t talk to me anymore", CaseType.LOCATE, True)


def test_motive_screen_passes_clean_purpose() -> None:
    motive_screen(GOOD_PURPOSE, CaseType.LOCATE, True)


# --------------------------------------------------------------------------- require_matter_ref


def test_locate_person_without_matter_ref_refused() -> None:
    with pytest.raises(PIPurposeError) as exc:
        require_matter_ref(CaseType.LOCATE, True, "")
    assert "matter" in str(exc.value).lower()


def test_locate_person_with_blank_matter_ref_refused() -> None:
    with pytest.raises(PIPurposeError):
        require_matter_ref(CaseType.LOCATE, True, "   ")


def test_locate_person_with_matter_ref_allowed() -> None:
    require_matter_ref(CaseType.LOCATE, True, "CV-2026-0042")


@pytest.mark.parametrize("case_type", [c for c in CaseType if c is not CaseType.LOCATE])
def test_matter_ref_not_required_for_other_case_types(case_type: CaseType) -> None:
    require_matter_ref(case_type, True, "")


def test_matter_ref_not_required_for_entity_locate() -> None:
    require_matter_ref(CaseType.LOCATE, False, "")


# --------------------------------------------------------------------------- label_finding


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, FindingLabel.LEAD),
        (1, FindingLabel.LEAD),
        (2, FindingLabel.PROBABLE),
        (3, FindingLabel.CONFIRMED),
        (4, FindingLabel.CONFIRMED),
    ],
)
def test_label_thresholds(count: int, expected: FindingLabel) -> None:
    assert label_finding(count) is expected


def test_label_negative_count_is_lead() -> None:
    assert label_finding(-1) is FindingLabel.LEAD


# --------------------------------------------------------------------------- count_independent_sources


def test_count_empty_is_zero() -> None:
    assert count_independent_sources([]) == 0


def test_distinct_tools_count_once_each() -> None:
    receipts = [
        {"tool": "gleif", "source_url": "https://a.example/x"},
        {"tool": "opensanctions", "source_url": "https://b.example/y"},
        {"tool": "courtlistener", "source_url": "https://c.example/z"},
    ]
    assert count_independent_sources(receipts) == 3


def test_same_tool_repeated_counts_once() -> None:
    receipts = [
        {"tool": "gleif", "source_url": "https://a.example/x"},
        {"tool": "gleif", "source_url": "https://a.example/y"},
    ]
    assert count_independent_sources(receipts) == 1


def test_shared_source_url_counted_once_even_if_tool_differs() -> None:
    receipts = [
        {"tool": "tool_a", "source_url": "https://registry.example/company/123"},
        {"tool": "tool_b", "source_url": "https://registry.example/company/123"},
    ]
    assert count_independent_sources(receipts) == 1


def test_shared_url_ignores_query_string_and_case() -> None:
    receipts = [
        {"tool": "tool_a", "source_url": "https://Registry.Example/Company/123?x=1"},
        {"tool": "tool_b", "source_url": "https://registry.example/company/123?y=2#frag"},
        {"tool": "tool_c", "source_url": "https://other.example/company/123"},
    ]
    assert count_independent_sources(receipts) == 2


def test_different_path_same_host_is_independent() -> None:
    receipts = [
        {"tool": "tool_a", "source_url": "https://registry.example/company/1"},
        {"tool": "tool_b", "source_url": "https://registry.example/company/2"},
    ]
    assert count_independent_sources(receipts) == 2


def test_empty_or_missing_tool_is_ignored() -> None:
    receipts = [
        {"tool": "", "source_url": "https://a.example/x"},
        {"source_url": "https://b.example/y"},
        {"tool": None, "source_url": "https://c.example/z"},
        {"tool": "gleif", "source_url": "https://d.example/w"},
    ]
    assert count_independent_sources(receipts) == 1


def test_empty_source_url_falls_back_to_tool_alone() -> None:
    receipts = [
        {"tool": "tool_a", "source_url": ""},
        {"tool": "tool_b"},
        {"tool": "tool_a", "source_url": None},
    ]
    assert count_independent_sources(receipts) == 2


def test_chain_of_shared_urls_merges_transitively() -> None:
    receipts = [
        {"tool": "tool_a", "source_url": "https://x.example/p"},
        {"tool": "tool_b", "source_url": "https://x.example/p"},
        {"tool": "tool_b", "source_url": "https://y.example/q"},
        {"tool": "tool_c", "source_url": "https://y.example/q"},
    ]
    assert count_independent_sources(receipts) == 1


# --------------------------------------------------------------------------- identifier_warnings


def test_person_with_full_name_and_anchor_has_no_warnings() -> None:
    sel = {"organizations": ["Jane Q Smith"], "emails": ["jane@example.com"]}
    assert identifier_warnings(sel, True) == []


def test_person_with_name_only_warns_about_missing_anchor() -> None:
    warnings = identifier_warnings({"organizations": ["Jane Smith"]}, True)
    assert len(warnings) == 1
    assert "anchor" in warnings[0].lower()


def test_person_with_single_token_name_warns_about_full_name() -> None:
    warnings = identifier_warnings({"organizations": ["Jane"], "emails": ["j@example.com"]}, True)
    assert any("full name" in w.lower() for w in warnings)


def test_person_with_no_name_warns_about_full_name() -> None:
    warnings = identifier_warnings({"usernames": ["@jsmith"], "domains": ["example.com"]}, True)
    assert any("full name" in w.lower() for w in warnings)


@pytest.mark.parametrize("anchor_key", ["usernames", "emails", "phones", "wallets", "domains"])
def test_each_anchor_key_satisfies_the_anchor_requirement(anchor_key: str) -> None:
    assert identifier_warnings({"organizations": ["Jane Smith"], anchor_key: ["value"]}, True) == []


def test_person_with_nothing_gets_warnings_and_does_not_raise() -> None:
    assert len(identifier_warnings({}, True)) >= 1


def test_blank_values_do_not_count_as_identifiers() -> None:
    warnings = identifier_warnings({"organizations": ["  "], "emails": [""]}, True)
    assert any("full name" in w.lower() for w in warnings)


def test_entity_subject_with_organization_has_no_warnings() -> None:
    assert identifier_warnings({"organizations": ["Acme Holdings Ltd"]}, False) == []


def test_entity_subject_without_name_or_domain_warns() -> None:
    assert len(identifier_warnings({"emails": ["a@b.co"]}, False)) == 1


# --------------------------------------------------------------------------- PIEngagement.build


def test_build_sets_deterministic_engagement_id() -> None:
    eng = PIEngagement.build(
        CaseType.DUE_DILIGENCE, GOOD_PURPOSE, subject_is_person=False, purpose_category="judgment_enforcement"
    )
    digest = hashlib.sha256(f"{eng.created_at_utc}|{eng.case_type.value}|{eng.purpose}".encode()).hexdigest()
    assert eng.engagement_id == "pi_" + digest[:10]
    assert len(eng.engagement_id) == 13


def test_build_created_at_is_timezone_aware_utc() -> None:
    eng = PIEngagement.build(
        CaseType.DUE_DILIGENCE, GOOD_PURPOSE, subject_is_person=False, purpose_category="judgment_enforcement"
    )
    parsed = datetime.fromisoformat(eng.created_at_utc)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_build_populates_fields_and_defaults() -> None:
    eng = PIEngagement.build(
        CaseType.LOCATE,
        "  " + GOOD_PURPOSE + "  ",
        client="Acme LLP",
        matter_ref="CV-2026-0042",
        jurisdiction="ca-on",
        purpose_category="service_of_process",
    )
    assert eng.purpose == GOOD_PURPOSE
    assert eng.client == "Acme LLP"
    assert eng.matter_ref == "CV-2026-0042"
    assert eng.jurisdiction == "ca-on"
    assert eng.subject_is_person is True
    assert eng.passive_only is True
    assert eng.objective == ""


def test_build_runs_purpose_gate() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.DUE_DILIGENCE, "too short", subject_is_person=False)


def test_build_runs_eligibility_gate() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.BACKGROUND, "Tenant screening for a rental application", matter_ref="x")


def test_build_runs_motive_gate() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.LOCATE, "Find my ex-girlfriend, she blocked me", matter_ref="CV-1")


def test_build_runs_matter_ref_gate() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.LOCATE, GOOD_PURPOSE, purpose_category="service_of_process")


def test_build_allows_locate_with_matter_ref() -> None:
    eng = PIEngagement.build(
        CaseType.LOCATE, GOOD_PURPOSE, matter_ref="CV-2026-0042", purpose_category="service_of_process"
    )
    assert eng.case_type is CaseType.LOCATE


def test_build_allows_entity_subject_with_red_flag_words() -> None:
    eng = PIEngagement.build(
        CaseType.DUE_DILIGENCE,
        "Company founded in revenge against a rival, vetting counterparty",
        subject_is_person=False,
        purpose_category="counterparty_due_diligence",
    )
    assert eng.subject_is_person is False


# --------------------------------------------------------------------------- NOTICES


def test_notices_cover_required_legal_points() -> None:
    joined = " ".join(NOTICES).lower()
    assert len(NOTICES) >= 5
    assert "consumer report" in joined
    assert "eligibility" in joined
    assert "leads" in joined
    assert "absence" in joined
    assert "licen" in joined
    assert "psisa" in joined


# --------------------------------------------------------------------------- gate hardening (verifier defects)
# The gates are a documented safety net, not a guarantee: these cases pin the phrasing and normalisation
# bypasses an independent verifier found, plus the legitimate wording that must stay accepted.

ELIGIBILITY_PHRASING_BYPASSES = [
    "check if this candidate is safe to hire",
    "see whether applicant qualifies for the apartment",
    "decide whether to extend credit to this person",
    "vet a new employee before offering the position",
    "assess whether this person is a good tenant risk for the lease",
    "background check on a babysitter applicant for our family",
    "PRE EMPLOYMENT checks",
    "employment-screening for a new hire",
    "pre-emp​loyment checks of staff",
    "pre​employment checks of staff",
    "pre‑employment checks of staff",
    "PRE_EMPLOYMENT/screening of staff",
    "tenant.screening of an applicant",
    "ｅｍｐｌｏｙｍｅｎｔ ｓｃｒｅｅｎｉｎｇ for a client",
    "decide on a hiring decision about him",
    "is the nanny we want safe to trust with the kids",
    "approve a loan for this person after checking him",
    "assess the credit risk of this individual",
]


@pytest.mark.parametrize("purpose", ELIGIBILITY_PHRASING_BYPASSES)
def test_eligibility_phrasing_and_obfuscation_bypasses_are_refused(purpose: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        validate_purpose(purpose)
    assert "FCRA" in str(exc.value)


LEGITIMATE_PURPOSES = [
    GOOD_PURPOSE,
    "fraud in hiring of subcontractor",
    "underwriting syndicate litigation",
    "employee fraud investigation at a former employer",
    "vet a counterparty before signing a supply contract",
    "locate the registered office of a judgment debtor company",
    "serve papers on a judgment debtor",
    "Enforce judgment 24-CV-1234 against the debtor",
    "find rental properties owned by a judgment debtor",
    "due diligence on an acquisition candidate company",
    "map beneficial owners of a supplier under a sanctions review",
    "my ex-employee misappropriated company funds, recover the judgment",
    "incremental revenue recognition fraud review of a vendor",
]


@pytest.mark.parametrize("purpose", LEGITIMATE_PURPOSES)
def test_legitimate_purposes_are_still_accepted(purpose: str) -> None:
    assert validate_purpose(purpose) == purpose
    for case_type in CaseType:
        motive_screen(purpose, case_type, True)


def test_normalisation_is_applied_to_the_vocabulary_too() -> None:
    # a hyphenated vocabulary entry matches its space-separated and zero-width-split spellings
    assert "pre-employment" in FORBIDDEN_ELIGIBILITY_TERMS
    for variant in ("pre employment", "pre​-employment", "PRE-EMPLOYMENT", "pre/employment"):
        with pytest.raises(PIPurposeError):
            validate_purpose(f"Client wants {variant} checks")


def test_gate_docstrings_state_the_safety_net_limit() -> None:
    assert "not a guarantee" in (validate_purpose.__doc__ or "").lower()
    assert "not a guarantee" in (motive_screen.__doc__ or "").lower()


MOTIVE_PHRASING_BYPASSES = [
    "find where my ex moved",
    "I need to know where my girlfriend goes at night",
    "locate my former wife who cut off contact with me",
    "find my estranged husband who relocated",
    "check on the person who ghosted me after our relationship",
    "locate my boyfriend, he changed his number",
    "find out where she goes after work",
    "she stopped talking to me and I want to find her",
    "find my former girlfriend",
    "FIND WHERE MY EX​ MOVED",
    "find where my ex‑wife moved",
]


@pytest.mark.parametrize("purpose", MOTIVE_PHRASING_BYPASSES)
@pytest.mark.parametrize("case_type", [CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON])
def test_former_partner_phrasing_bypasses_are_refused_for_persons(purpose: str, case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError) as exc:
        motive_screen(purpose, case_type, True)
    msg = str(exc.value).lower()
    assert "will not run" in msg and "law enforcement" in msg and "counsel" in msg


@pytest.mark.parametrize("purpose", MOTIVE_PHRASING_BYPASSES)
def test_former_partner_phrasing_is_not_screened_for_entities(purpose: str) -> None:
    motive_screen(purpose, CaseType.LOCATE, False)


def test_build_runs_hardened_gates() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.BACKGROUND, "check if this candidate is safe to hire", matter_ref="x")
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.LOCATE, "find where my ex moved", matter_ref="CV-1")
    eng = PIEngagement.build(
        CaseType.DUE_DILIGENCE,
        "fraud in hiring of subcontractor",
        subject_is_person=False,
        purpose_category="fraud_investigation",
    )
    assert eng.purpose == "fraud in hiring of subcontractor"


# --------------------------------------------------------------------------- looks_like_natural_person_name


@pytest.mark.parametrize(
    "name",
    ["Jane Doe", "jane doe", "John Q. Public", "Mary-Anne O'Brien", "Jose Maria Garcia", "Zoë Müller"],
)
def test_person_names_are_recognised(name: str) -> None:
    assert looks_like_natural_person_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "Bombardier Inc",
        "Acme Holdings Ltd",
        "Acme",
        "acme.io",
        "Siemens AG",
        "Deutsche Bank",
        "Bank of America",
        "Harvard University",
        "Open Society Foundation",
        "Jane Doe Foundation",
        "Smith & Sons",
        "Acme 123",
        "Jane Doe Group",
        "Tesla Motors Corp.",
        "Alpha Beta Gamma Delta",
        "",
        "0x1234",
        "jane@example.com",
    ],
)
def test_organisation_and_non_name_seeds_are_not_person_names(name: str) -> None:
    assert looks_like_natural_person_name(name) is False
