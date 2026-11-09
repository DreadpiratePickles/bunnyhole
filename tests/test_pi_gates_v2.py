"""Second hardening pass on the PI purpose gates: recall fixes found by an independent verifier.

Covers eligibility (FCRA) recall, stalking/evasion recall, the pursuit gate that applies to every case type and
subject type, the matter-reference validator, and the compact-phrase obfuscation pass. The gates stay a safety
net, not a guarantee: the "still accepted" lists at the bottom pin the legitimate wording that must not be refused.
"""

from __future__ import annotations

import time

import pytest

from bunnyhole.engine.pi import (
    CaseType,
    PIEngagement,
    PIPurposeError,
    is_valid_matter_ref,
    motive_screen,
    pursuit_screen,
    require_matter_ref,
    validate_purpose,
)

VALID_REF = "23-CV-1182"
ALL_CASE_TYPES = list(CaseType)
PERSON_LOCATE_TYPES = [CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON]
OTHER_CASE_TYPES = [CaseType.ASSET_SEARCH, CaseType.DUE_DILIGENCE, CaseType.FRAUD_SCREEN]


def _build(case_type: CaseType, purpose: str, *, person: bool = True, matter_ref: str = VALID_REF) -> PIEngagement:
    return PIEngagement.build(
        case_type, purpose, matter_ref=matter_ref, subject_is_person=person,
        purpose_category="counterparty_due_diligence",
    )


# --------------------------------------------------------------------------- 1. eligibility recall

ELIGIBILITY_RECALL = [
    "Is she a safe hire for our accounting team",
    "Screen the person who applied for the receptionist job",
    "bring this applicant on as a software engineer",
    "Check if the guy who wants to rent my basement has any red flags",
    "Evaluate this person's financial responsibility before approving a car loan",
    "Determine if this homeowner qualifies for our insurance policy",
    "Background on our new driver before we put him on the payroll",
    "Draft the offer letter only after we know who she really is",
    "Should we hire him? run the checks first please",
    "Look into the prospective renter who toured the flat yesterday",
    "Red flags on a prospective tenant for the upstairs unit",
    "We are approving a mortgage for this couple and need their history",
    "Is the borrower good for a credit line of fifty thousand",
    "Onboard this new employee only if nothing turns up",
    "Does this couple qualify for the rental unit we advertised",
    "The person who applied for the apartment needs a once-over",
]


@pytest.mark.parametrize("purpose", ELIGIBILITY_RECALL)
def test_eligibility_recall_validate_purpose(purpose: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        validate_purpose(purpose)
    assert "FCRA" in str(exc.value)


@pytest.mark.parametrize("purpose", ELIGIBILITY_RECALL[:7])
@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
@pytest.mark.parametrize("person", [True, False])
def test_eligibility_recall_is_refused_in_every_case_and_subject_type(
    purpose: str, case_type: CaseType, person: bool
) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _build(case_type, purpose, person=person)
    assert "FCRA" in str(exc.value)


LEGITIMATE_V2 = [
    "Internal fraud investigation of an employee suspected of invoice fraud",
    "Credit risk of a counterparty company ahead of a supply agreement",
    "Due diligence on an acquisition candidate company",
    "My wife's company is the counterparty in a supply contract dispute",
    "Former business partner misappropriated funds, vet the shell company",
    "Enforce judgment 24-CV-1234 against the debtor and trace the funds",
    "Shell-company red flags in a supplier's registry filings",
    "Vendor onboarding due diligence on a corporate supplier",
    "Review Shire Pharmaceuticals filings for a Hampshire supply contract",
    "Trace payroll fraud by a ghost employee at a subcontractor",
    "Patent applicant litigation history for an IP dispute",
]


@pytest.mark.parametrize("purpose", LEGITIMATE_V2)
def test_legitimate_wording_still_accepted_by_validate_purpose(purpose: str) -> None:
    assert validate_purpose(purpose) == purpose


@pytest.mark.parametrize("purpose", LEGITIMATE_V2)
@pytest.mark.parametrize("case_type", OTHER_CASE_TYPES)
def test_legitimate_wording_builds_for_entity_subjects(purpose: str, case_type: CaseType) -> None:
    assert _build(case_type, purpose, person=False).purpose == purpose


# --------------------------------------------------------------------------- 2. stalking / evasion recall

STALKING_RECALL = [
    "find the woman I dated last summer who deleted her accounts",
    "the girl from my gym won't give me her number, find her address",
    "find the man who broke my heart",
    "find who posted the bad reviews about me online and where they live",
    "what town my sister-in-law relocated to; the family isn't speaking to me",
    "locate the guy I matched with on a dating app, he unmatched me",
    "the man I was dating stopped answering, I want to know where he is now",
]


@pytest.mark.parametrize("purpose", STALKING_RECALL)
@pytest.mark.parametrize("case_type", PERSON_LOCATE_TYPES)
def test_stalking_recall_refused_for_person_subjects(purpose: str, case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError) as exc:
        motive_screen(purpose, case_type, True)
    msg = str(exc.value).lower()
    assert "will not run" in msg and "law enforcement" in msg and "counsel" in msg


@pytest.mark.parametrize("purpose", STALKING_RECALL)
def test_stalking_recall_refused_through_build(purpose: str) -> None:
    for case_type in PERSON_LOCATE_TYPES:
        with pytest.raises(PIPurposeError):
            _build(case_type, purpose)


# --------------------------------------------------------------------------- 3. pursuit gate, every case type

PURSUIT_ALL = [
    "Find my ex-wife's current address, she blocked me everywhere",
    "Counterparty director won't talk to me, find where she lives",
    "Identify the assets of the man who deleted his accounts after the dispute",
    "Locate the current address of my ex so I can send documents",
    "She changed her number and I need to reach her about the contract",
    "Find where he goes after work and who he meets",
    "find who posted the bad reviews about me online and where they live",
]


@pytest.mark.parametrize("purpose", PURSUIT_ALL)
@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
@pytest.mark.parametrize("person", [True, False])
def test_pursuit_phrases_refused_for_every_case_type_and_subject_type(
    purpose: str, case_type: CaseType, person: bool
) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _build(case_type, purpose, person=person)
    assert "law enforcement" in str(exc.value).lower()


def test_pursuit_screen_directly_refuses_regardless_of_subject_type() -> None:
    with pytest.raises(PIPurposeError):
        pursuit_screen("Find my ex-wife's current address... she blocked me", CaseType.ASSET_SEARCH, False, VALID_REF)


@pytest.mark.parametrize("case_type", OTHER_CASE_TYPES)
def test_relationship_term_alone_needs_a_valid_matter_ref_for_person_subjects(case_type: CaseType) -> None:
    purpose = "Asset search against my ex-husband to enforce the support order"
    with pytest.raises(PIPurposeError) as exc:
        PIEngagement.build(case_type, purpose, subject_is_person=True)
    msg = str(exc.value)
    assert "--matter-ref" in msg and "support" in msg.lower()
    for placeholder in ("TBD", "12345", "n/a"):
        with pytest.raises(PIPurposeError):
            PIEngagement.build(case_type, purpose, matter_ref=placeholder, subject_is_person=True)
    ok = PIEngagement.build(
        case_type, purpose, matter_ref="FC-24-0188", subject_is_person=True, purpose_category="asset_recovery"
    )
    assert ok.matter_ref == "FC-24-0188"


@pytest.mark.parametrize(
    "purpose",
    [
        "Divorce proceeding: asset search against my former spouse",
        "Enforce support order against my estranged husband",
        "Trace the assets of my ex-wife for the family court matter",
    ],
)
def test_relationship_terms_without_matter_ref_refused_on_non_locate_types(purpose: str) -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.ASSET_SEARCH, purpose, subject_is_person=True)
    PIEngagement.build(
        CaseType.ASSET_SEARCH, purpose, matter_ref="FC-24-0188", subject_is_person=True, purpose_category="asset_recovery"
    )


def test_relationship_terms_are_not_matter_ref_gated_for_entity_subjects() -> None:
    purpose = "Vet the company owned by my ex-wife, she is the counterparty"
    built = PIEngagement.build(
        CaseType.DUE_DILIGENCE, purpose, subject_is_person=False, purpose_category="counterparty_due_diligence"
    )
    assert built.subject_is_person is False


@pytest.mark.parametrize("case_type", PERSON_LOCATE_TYPES)
def test_relationship_with_valid_matter_ref_still_refused_on_locate_types(case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError):
        _build(case_type, "Find my ex-wife for the support proceeding")


# --------------------------------------------------------------------------- 4. matter_ref validation

VALID_REFS = ["23-CV-1182", "CV-24-00123456", "2026-CV-1234", "MSA-2026-114", "MSA-7", "Smith v. Jones", "Doe vs Roe"]
INVALID_REFS = [
    "test", "tbd", "TBD", "n/a", "N/A", "na", "none", "xxx", "asdf", "12345", "abc", "unknown", "pending", "later",
    "x", "ab1", "CV-1", "abcde", "pending-case", "TEST 1234", "xxx123", "11111", "00000", "0123456",
]


@pytest.mark.parametrize("ref", VALID_REFS)
def test_valid_matter_refs(ref: str) -> None:
    assert is_valid_matter_ref(ref) is True
    require_matter_ref(CaseType.LOCATE, True, ref)


@pytest.mark.parametrize("ref", INVALID_REFS)
def test_invalid_matter_refs_are_refused_with_an_actionable_message(ref: str) -> None:
    assert is_valid_matter_ref(ref) is False
    with pytest.raises(PIPurposeError) as exc:
        require_matter_ref(CaseType.LOCATE, True, ref)
    assert "matter reference" in str(exc.value).lower()
    assert "23-CV-1182" in str(exc.value)


@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
def test_a_supplied_invalid_ref_is_refused_even_when_not_required(case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError):
        require_matter_ref(case_type, False, "TBD")
    require_matter_ref(case_type, False, "")
    require_matter_ref(case_type, False, "   ")


def test_build_rejects_an_invalid_matter_ref_on_any_case_type() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(
            CaseType.DUE_DILIGENCE, "Vet a counterparty before signing a contract", matter_ref="tbd",
            purpose_category="counterparty_due_diligence",
        )
    purpose = "Vet a counterparty before signing a contract"
    ok = PIEngagement.build(
        CaseType.DUE_DILIGENCE, purpose, matter_ref=" MSA-7 ", purpose_category="counterparty_due_diligence"
    )
    assert ok.matter_ref == "MSA-7"


# --------------------------------------------------------------------------- 5. obfuscation (skeleton pass)

OBFUSCATED_ELIGIBILITY = [
    "Run pr3-3mpl0yment checks on a person",
    "Run рre-еmрloyment checks on a person",  # Cyrillic er/ie/er lookalikes
    "Run pre-εmploυment checks on a person",  # Greek epsilon / upsilon
    "Run p r e - e m p l o y m e n t checks on a person",
    "Run pre&#45;employment checks on a person",
    "Run pre&hyphen;employment checks on a person",
    "Run pre%2Demployment checks on a person",
    "Run pre-employmént checks on a person",  # combining acute
    "Run p.r.e.-employment checks on a person",
    "Run preemploymnt checks on a person",  # one-character typo
    "Run tenantscreening on him please",
    "Run t3nant-scr33ning on him please",
    "Run employmentscreening on him please",
]


@pytest.mark.parametrize("purpose", OBFUSCATED_ELIGIBILITY)
def test_obfuscated_eligibility_phrases_are_refused(purpose: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        validate_purpose(purpose)
    assert "FCRA" in str(exc.value)


OBFUSCATED_RELATIONSHIP = [
    "find my 3x-w1fe",
    "find my e x - w i f e",
    "find my exwife",
    "find my x-wife",
    "find my previous girlfriend",
    "find my estrangd husband",
    "find my еx-wife",  # Cyrillic e
    "find my ex&#45;wife",
    "find my ex%2Dwife",
    "find my ex-wífe",
    "find my e.x.-w.i.f.e",
    "find my 3xhusband",
    "find my exgirlfriend",
    "find my ex_boyfriend",
]


@pytest.mark.parametrize("purpose", OBFUSCATED_RELATIONSHIP)
@pytest.mark.parametrize("case_type", PERSON_LOCATE_TYPES)
def test_obfuscated_relationship_phrases_are_refused_on_person_locate_types(purpose: str, case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError):
        motive_screen(purpose, case_type, True)


@pytest.mark.parametrize("purpose", OBFUSCATED_RELATIONSHIP)
def test_obfuscated_relationship_phrases_need_a_matter_ref_on_other_case_types(purpose: str) -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.ASSET_SEARCH, purpose + " for the asset search", subject_is_person=True)


def test_obfuscated_relationship_phrases_are_not_screened_for_entities() -> None:
    motive_screen("find my exwife", CaseType.LOCATE, False)
    _build(CaseType.DUE_DILIGENCE, "vet the firm of my exwife, the counterparty", person=False)


NO_SKELETON_FALSE_POSITIVES = [
    "Review Shire Pharmaceuticals filings for a Hampshire supply contract",
    "Complex wiring fraud at a Yorkshire hire company",
    "Premium Employment Agency Ltd due diligence before signing a contract",
    "Index wifi vendor counterparty vetting for a supply contract",
    "Annex Husbandry Holdings ownership walk for a supplier",
    "Ex-employee misappropriated company funds, recover the judgment",
    "Former business partner misappropriated funds in the supplier",
    "Pre-trial disclosure review for a supplier fraud case",
    "Tenant improvements fraud at a construction contractor",
    "Estimating the exposure of a supplier to sanctioned counterparties",
]


@pytest.mark.parametrize("purpose", NO_SKELETON_FALSE_POSITIVES)
def test_skeleton_pass_does_not_match_substrings_or_near_words(purpose: str) -> None:
    assert validate_purpose(purpose) == purpose
    for case_type in ALL_CASE_TYPES:
        _build(case_type, purpose, person=False)
    motive_screen(purpose, CaseType.LOCATE, True)
    pursuit_screen(purpose, CaseType.DUE_DILIGENCE, True, VALID_REF)


def test_skeleton_pass_is_fast_on_long_input() -> None:
    purpose = ("Vet a counterparty before signing a supply contract. " * 80)[:2000]
    started = time.perf_counter()
    for _ in range(5):
        validate_purpose(purpose)
        motive_screen(purpose, CaseType.LOCATE, True)
        pursuit_screen(purpose, CaseType.DUE_DILIGENCE, True, VALID_REF)
    assert time.perf_counter() - started < 3.0


def test_gate_docstrings_say_safety_net_not_guarantee() -> None:
    for fn in (validate_purpose, motive_screen, pursuit_screen):
        assert "not a guarantee" in (fn.__doc__ or "").lower()
