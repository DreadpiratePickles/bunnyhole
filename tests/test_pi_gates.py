"""Hardening tests for the PI purpose gates (the core gate tests live in ``test_pi_core.py``).

A phrase blocklist can never reach full recall, so an engagement needs an attested ``PurposeCategory`` from a short
allowlist, a person subject needs a narrower category AND a valid matter reference, and the phrase screens
(eligibility/FCRA, stalking/evasion, pursuit) run over EVERY free-text field as a cross-check. The "still accepted"
lists pin the legitimate wording that must not be refused. A safety net, not a guarantee: the category is attested,
not verified.

Sections: purpose patterns (recall and still-accepted wording); the allowlist, matter references and whole-engagement
screening; obfuscation (the compact-phrase skeleton pass); bounded time (the screens finish quickly on 300 KB of
adversarial text, generous 2 s bound, and text above the hard cap is refused, never silently skipped). The bounded-time
tests carry the ``slow`` marker (deselect with ``-m "not slow"``).
"""

# Replaces: test_pi_gates_v2.py, test_pi_gates_v3.py, test_pi_gates_v4.py (consolidated 2026-11-09).

from __future__ import annotations

import time
from typing import Callable, Dict, List

import pytest

from bunnyhole.engine import pi_gates
from bunnyhole.engine.pi import (
    CaseType,
    PIEngagement,
    PIPurposeError,
    PurposeCategory,
    is_valid_matter_ref,
    motive_screen,
    pursuit_screen,
    require_matter_ref,
    validate_purpose,
)
from bunnyhole.engine.pi_gates import MAX_SCREEN_CHARS, screen_eligibility
from bunnyhole.engine.pi_purpose import screen_free_texts

# ==============================================================================================================
# Shared constants and builders
# ==============================================================================================================


VALID_REF = "23-CV-1182"
ALL_CASE_TYPES = list(CaseType)
PERSON_LOCATE_TYPES = [CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON]
OTHER_CASE_TYPES = [CaseType.ASSET_SEARCH, CaseType.DUE_DILIGENCE, CaseType.FRAUD_SCREEN]


def _build(case_type: CaseType, purpose: str, *, person: bool = True, matter_ref: str = VALID_REF) -> PIEngagement:
    return PIEngagement.build(
        case_type, purpose, matter_ref=matter_ref, subject_is_person=person,
        purpose_category="counterparty_due_diligence",
    )


REF = "23-CV-1182"
GOOD_PURPOSE = "Enforce judgment 24-CV-1234 against the debtor and trace the funds"

ALL_CATEGORIES = [
    "judgment_enforcement", "litigation_support", "service_of_process", "asset_recovery", "fraud_investigation",
    "counterparty_due_diligence", "regulatory_compliance_kyc", "journalism_public_interest", "authorities_referral",
]
PERSON_CATEGORIES = [
    "judgment_enforcement", "litigation_support", "service_of_process", "asset_recovery", "fraud_investigation",
    "authorities_referral", "counterparty_due_diligence",
]
ENTITY_ONLY_CATEGORIES = [c for c in ALL_CATEGORIES if c not in PERSON_CATEGORIES]


def _entity(purpose: str, case_type: CaseType = CaseType.DUE_DILIGENCE, **kw: object) -> PIEngagement:
    kw.setdefault("purpose_category", "counterparty_due_diligence")
    return PIEngagement.build(case_type, purpose, subject_is_person=False, **kw)  # type: ignore[arg-type]


def _person(purpose: str, case_type: CaseType = CaseType.ASSET_SEARCH, **kw: object) -> PIEngagement:
    kw.setdefault("purpose_category", "litigation_support")
    kw.setdefault("matter_ref", REF)
    return PIEngagement.build(case_type, purpose, subject_is_person=True, **kw)  # type: ignore[arg-type]


SIZE = 300_000
LIMIT_S = 2.0
SECRET = "Zq7-secret"


def _repeat(unit: str, size: int = SIZE) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def _adversarial(size: int) -> Dict[str, str]:
    return {
        "run_of_a": "a" * size,
        "a_at": _repeat("a@", size),
        "a_dot": _repeat("a.", size),
        "password_eq": "password=" + "x" * (size - 9),
        "where_she": _repeat("where she ", size),
        "spaced_dash": _repeat(" - ", size),
        "ex": _repeat("ex ", size),
        "my_ex": _repeat("my ex ", size),
        "digits": "1" * size,
        "cyrillic_lookalikes": "а" * size,
        "zero_width_joined": _repeat("l​o​c​a​t​e ", size),
        "leetspeak": _repeat("l0c4t3 ", size),
        "spaced_letters": _repeat("e x ", size),
        "verb_gap": ("screen " + "word " * (size // 5) + "tenant")[:size],
        "before_onboarding": _repeat("before onboarding ", size),
        "monitor_movements": _repeat("monitor the daily movements of ", size),
        "dont_like": _repeat("i do not like ", size),
        "dig_up": _repeat("dig up dirt on ", size),
        "newlines": "\n" * size,
        "tabs_words": _repeat("a\t", size),
    }


ADVERSARIAL_300KB = _adversarial(SIZE)


def _guard(fn: Callable[..., object], *args: object) -> float:
    """Seconds taken; a :class:`PIPurposeError` (a refusal) is a valid, fast outcome."""
    started = time.perf_counter()
    try:
        fn(*args)
    except PIPurposeError:
        pass
    return time.perf_counter() - started


# ==============================================================================================================
# Purpose patterns: eligibility, stalking and pursuit recall; legitimate wording still accepted
# ==============================================================================================================

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


# --------------------------------------------------------------------------- 5. paraphrase recall (eligibility)

ELIGIBILITY_PARAPHRASES = [
    # found by the third independent verifier
    "Tenant vetting for the unit at 14 Elm St",
    "Employee vetting for a finance position",
    "Underwrite a life policy for the proposed insured",
    "Run a trustworthiness check on a prospective housekeeper",
    "Screening a possible lodger",
    "Eligibilidad crediticia del solicitante",
    "Check a tenant before signing the lease",
    "Screen an employee for the finance role",
    "Hiring due diligence on our incoming CFO",
    "Employment verification and reference check on Mr. Lee",
    "Loan officer wants history on the borrower to approve funding",
    # more wordings of the same decisions
    "Vet the roommate who answered my ad",
    "Suitability assessment of the caregiver for my mother",
    "Verify the applicant for the apartment on Oak Ave",
    "Assess whether the prospective hire has a clean record",
    "Checking out a would-be tenant before handing over the keys",
    "Qualify the borrower before we release the mortgage",
    "Underwriting review of this file for the life policy",
    "Reference check on the new CFO before the board vote",
    "Candidate vetting for the finance director seat",
    "Run due diligence on the policyholder before we issue the policy",
    "Is this person trustworthy enough to rent the cottage",
    "Screen the housekeeper my wife wants to engage",
    "Employee screening for the warehouse",
    "Background verification on a would-be babysitter",
    "Lodger screening for the spare room",
    "Verify employment of the person we plan to engage as bookkeeper, reference check",
    "Check out the cleaner before she starts on Monday",
    "Vérification du locataire potentiel avant la signature",
    "Bewerber prüfen vor der Einstellung",
    "Mieterprüfung für die Wohnung in Berlin",
    "Kreditprüfung des Antragstellers",
    "Evaluación del empleado para el puesto de contador",
    "Revisión del inquilino antes del contrato",
    "Vérifier ce candidat avant l'embauche",
    "Verify the renter on the lease application",
    "Vetting the au pair we are about to hire",
    "Check the prospective tenant's references",
    "Screen new hires before they start",
]


ELIGIBILITY_PARAPHRASES += [  # a second sweep of wordings written after the first held-out check
    "Need a read on the babysitter our neighbour recommended",
    "Does the prospective employee have any judgments against her",
    "Screen job seekers who submitted resumes",
    "Look up the carer who responded to our listing",
    "Run a check on someone before I rent them my guest house",
    "Credit file review of the person requesting a payment plan",
    "Examine whether she should be offered tenancy",
    "Tenancy suitability report",
    "Housing check on a family that wants the three-bedroom",
    "Quick look at the renter's finances please",
    "Confirm whether the tenant is genuine and employed",
    "Assess risk of lending to a private individual",
    "Verify what the candidate wrote on his application",
    "Staff vetting for a new receptionist",
    "Verify a new employee's identity and history",
    "Check the background of the man we are thinking of renting to",
    "Verify the person applying to be our office manager",
    "Housing association needs a background on the new resident",
]


@pytest.mark.parametrize("purpose", ELIGIBILITY_PARAPHRASES)
def test_eligibility_paraphrases_are_refused_by_validate_purpose(purpose: str) -> None:
    with pytest.raises(PIPurposeError):
        validate_purpose(purpose)


@pytest.mark.parametrize("purpose", ELIGIBILITY_PARAPHRASES)
@pytest.mark.parametrize("person", [True, False])
def test_eligibility_paraphrases_are_refused_through_build_for_every_declared_category(
    purpose: str, person: bool
) -> None:
    for case_type in (CaseType.BACKGROUND, CaseType.DUE_DILIGENCE):
        with pytest.raises(PIPurposeError):
            PIEngagement.build(
                case_type, purpose, subject_is_person=person, purpose_category="litigation_support", matter_ref=REF
            )


# --------------------------------------------------------------------------- 6. paraphrase recall (pursuit)

STALKING_PARAPHRASES = [
    # found by the third independent verifier
    "Doxx the guy who insulted me",
    "Want to surprise my old flame at her new apartment",
    "He is dodging my calls; figure out where he is staying now",
    "My baby's mother has vanished with the kid",
    "Identify the neighbor who reported me and find where they work",
    "She has unfriended me everywhere; locate her workplace",
    "Reveal where my former business partner's wife lives",
    # more wordings of the same pursuit
    "Track her phone and see where she goes after work",
    "Follow him home from work and note the address",
    "Find the person who rejected me and where they live",
    "Find out where my ex is staying",
    "Whereabouts of my ex, she moved out last week",
    "Who is the woman who bullied me online, and what's her address",
    "Find out where the girl who ignored me lives",
    "Keep tabs on my ex and her new boyfriend",
    "Spy on him and see who he meets",
    "She refuses to answer me, find where she works",
    "Find the guy from the app who ghosted me",
    "Get her new home address, she is ignoring my texts",
    "I just want to drop by unannounced at her place",
    "Figure out where she is living now, she is avoiding my calls",
    "Dox the reviewer who mocked me",
    "Find my kid's mother, she took the children and left",
    "Locate his new apartment, he won't answer my messages",
]


STALKING_PARAPHRASES += [  # a second sweep of wordings written after the first held-out check
    "Locate the woman I met on the train, I want her number and address",
    "Where does the man who laughed at me at the gym live",
    "Learn where my neighbour goes every evening",
    "Watch my girlfriend's location without her knowing",
    "Need the address of the woman my husband is texting",
    "Find my runaway wife",
    "I need her new address; she doesn't want to see me",
    "Find the man who stole my girlfriend and his address",
    "Follow the guy who owes me money to his house and see who he lives with",
    "Stalk the account behind the parody page and find who it is",
    "Find where my former friend moved, she cut me out of her life",
    "He unfriended me and I want to know where he works now",
]


@pytest.mark.parametrize("purpose", STALKING_PARAPHRASES)
@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
@pytest.mark.parametrize("person", [True, False])
def test_stalking_paraphrases_are_refused_by_the_pursuit_screen_for_every_case_and_subject_type(
    purpose: str, case_type: CaseType, person: bool
) -> None:
    with pytest.raises(PIPurposeError):
        pursuit_screen(purpose, case_type, person, REF, purpose_category="litigation_support")


@pytest.mark.parametrize("purpose", STALKING_PARAPHRASES)
def test_stalking_paraphrases_are_refused_through_build(purpose: str) -> None:
    for case_type in ALL_CASE_TYPES:
        with pytest.raises(PIPurposeError):
            PIEngagement.build(
                case_type, purpose, subject_is_person=True, purpose_category="litigation_support", matter_ref=REF
            )
        with pytest.raises(PIPurposeError):
            PIEngagement.build(
                case_type, purpose, subject_is_person=False, purpose_category="counterparty_due_diligence"
            )


# --------------------------------------------------------------------------- 7. legitimate wording still accepted

LEGITIMATE_V3 = [
    "Internal fraud investigation of an employee suspected of invoice fraud",
    "Credit risk of a counterparty company ahead of a supply agreement",
    "Due diligence on an acquisition candidate company",
    "My wife's company is the counterparty in a supply contract dispute",
    "Former business partner misappropriated funds, vet the shell company",
    "Enforce judgment 24-CV-1234 against the debtor and trace the funds",
    "Shell-company red flags in a supplier's registry filings",
    "Vendor onboarding due diligence on a corporate supplier",
    "Trace payroll fraud by a ghost employee at a subcontractor",
    "Patent applicant litigation history for an IP dispute",
    "Former partner agreement dispute: vet the counterparty entity",
    "Credit insurer exposure review for the supplier",
    "Blocked payment investigation at a bank counterparty",
    "Applicant company litigation history before signing the contract",
    "Acquisition candidate ownership walk",
    "Screen the supplier against sanctions lists before the contract is signed",
    "Verify the registered office of Acme Ltd before serving the claim",
    "Check the counterparty's beneficial owners before signing the contract",
    "Trace funds diverted by a former employee of the debtor company",
    "Locate the registered agent of the judgment debtor to serve the statement of claim",
    "Review the car hire company's filings for the supply contract",
    "Verify the borrower entity's registration for the loan syndication dispute",
    "Identify attachable assets of the judgment debtor in action 24-CV-1234",
    "Sanctions and PEP screening of the target's directors ahead of the acquisition",
    "Map the ownership chain of the supplier to its ultimate beneficial owner",
    "Public-interest investigation of a charity's funding sources for an article",
    "Check litigation history and liens against the contractor before payment",
    "Locate the defendant at his last known address for personal service of the claim",
]


LEGITIMATE_V3 += [
    "Check the tenant improvements fraud at the contractor",
    "Review the tenant ledger for the commercial lease fraud",
    "Review the lease terms between the landlord company and the tenant company",
    "Determine whether the borrower entity is a subsidiary of Acme",
    "Screen the CEO and directors against sanctions lists",
    "Determine where the defendant resides for service of process",
    "Underwriting syndicate litigation history",
    "Vet the shell company director's other appointments",
    "Retrieve court filings naming the contractor firm as a defendant",
    "Prepare KYC file on a corporate customer: ownership, directors, sanctions",
    "Stalking horse bid history of the bankrupt retailer",
    "Review the debtor's judgment history in Ontario",
]


@pytest.mark.parametrize("purpose", LEGITIMATE_V3)
def test_legitimate_wording_is_accepted_by_validate_purpose(purpose: str) -> None:
    assert validate_purpose(purpose) == purpose


@pytest.mark.parametrize("purpose", LEGITIMATE_V3)
@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
def test_legitimate_wording_builds_for_entity_subjects_with_a_category(purpose: str, case_type: CaseType) -> None:
    assert _entity(purpose, case_type).purpose == purpose


def test_candidate_for_takeover_is_still_refused_as_before() -> None:
    with pytest.raises(PIPurposeError):
        validate_purpose("Due diligence on a candidate for takeover")


def test_motive_screen_still_not_applied_to_entities() -> None:
    motive_screen("Company run by my ex-wife, she moved the office", CaseType.LOCATE, False)

# --------------------------------------------------------------------------- D3. onboarding is a cue only with a person

KYC_ONBOARDING_OK = [
    "Know-your-customer refresh on a corporate client before onboarding",
    "KYC refresh on the corporate client before onboarding",
    "Beneficial-ownership check on the supplier before onboarding",
    "Know your customer review of an offshore holding company before we onboard it",
]


@pytest.mark.parametrize("purpose", KYC_ONBOARDING_OK)
@pytest.mark.parametrize("category", ["regulatory_compliance_kyc", "counterparty_due_diligence", "fraud_investigation"])
def test_kyc_wording_before_onboarding_a_company_is_accepted(purpose: str, category: str) -> None:
    assert _entity(purpose, purpose_category=category).purpose == purpose
    assert validate_purpose(purpose) == purpose
    screen_eligibility(purpose)


@pytest.mark.parametrize(
    "purpose",
    [
        "Run checks before onboarding. He is a driver.",
        "Checks before onboarding the contractor; she is an independent contractor",
        "Before onboarding, review the candidate",
        "Before onboarding our new nanny run the checks",
        "Look into the tenant before onboarding",
        "Before onboarding: the applicant, an intern",
    ],
)
def test_before_onboarding_next_to_a_person_role_is_still_refused(purpose: str) -> None:
    with pytest.raises(PIPurposeError):
        screen_eligibility(purpose)
    with pytest.raises(PIPurposeError):
        _entity(purpose, purpose_category="counterparty_due_diligence")


@pytest.mark.parametrize(
    "purpose",
    [
        "KYC refresh before onboarding the new employee",
        "Know your customer check on the tenant before onboarding",
        "KYC on the borrower before onboarding, for the loan application",
        "Know-your-customer checks on a new hire before onboarding",
    ],
)
def test_employment_tenancy_and_credit_patterns_still_apply_under_the_kyc_category(purpose: str) -> None:
    with pytest.raises(PIPurposeError):
        _entity(purpose, purpose_category="regulatory_compliance_kyc")
    with pytest.raises(PIPurposeError):
        screen_eligibility(purpose, "regulatory_compliance_kyc")


def test_the_kyc_category_exempts_only_the_onboarding_cue() -> None:
    purpose = "Run checks before onboarding. He is a driver."
    with pytest.raises(PIPurposeError):
        screen_eligibility(purpose)
    screen_eligibility(purpose, "regulatory_compliance_kyc")
    with pytest.raises(PIPurposeError):
        screen_eligibility(purpose, "counterparty_due_diligence")


# --------------------------------------------------------------------------- D4. pursuit recall

DOXXING_PURPOSES = [
    "Monitor the daily movements of my business partner's wife",
    "Find my daughter's boyfriend's home address; I do not like him",
    "Dig up dirt on my neighbour who complained about my dog",
    "Track the daily routine of my neighbour",
    "Log the daily movements of the tenant next door",
    "Find the home address of my brother's girlfriend, I don't like her",
    "I do not like him, so find where he lives",
    "Dig up some dirt on her new husband",
    "I want the home address of my sister's husband's friend, I really dont like him",
]


@pytest.mark.parametrize("purpose", DOXXING_PURPOSES)
@pytest.mark.parametrize("case_type", list(CaseType))
@pytest.mark.parametrize("subject_is_person", [True, False])
def test_the_new_pursuit_wordings_are_refused_in_every_case_type_and_subject_type(
    purpose: str, case_type: CaseType, subject_is_person: bool
) -> None:
    with pytest.raises(PIPurposeError):
        pursuit_screen(purpose, case_type, subject_is_person, REF, "litigation_support")
    with pytest.raises(PIPurposeError):
        screen_free_texts([purpose], case_type, subject_is_person, REF, "litigation_support")


@pytest.mark.parametrize("purpose", DOXXING_PURPOSES[:3])
@pytest.mark.parametrize("category", ["litigation_support", "fraud_investigation", "counterparty_due_diligence"])
def test_the_new_wordings_are_refused_through_build_even_with_a_matter_ref(purpose: str, category: str) -> None:
    with pytest.raises(PIPurposeError):
        _entity(f"{GOOD_PURPOSE}. {purpose}", purpose_category=category, matter_ref=REF)
    with pytest.raises(PIPurposeError):
        _person(f"{GOOD_PURPOSE}. {purpose}", purpose_category="litigation_support")
    with pytest.raises(PIPurposeError):
        _entity(GOOD_PURPOSE, purpose_category=category, extra_texts=[purpose])


LEGITIMATE_PURPOSES: List[str] = [
    "Monitor the daily movements of funds through the shell company accounts for the fraud investigation",
    "Track the daily movements of the vessel using AIS data for the asset search",
    "Monitor movements on the supplier's escrow account before releasing the second payment",
    "Find the registered office address of the partner firm for service of process",
    "Locate the business address of the defendant company for service of process in 24-CV-1234",
    "Dig up the property records and liens for the parcel owned by the debtor company",
    "Dig up the filing history of the counterparty from the corporate registry",
    "I do not like the indemnity terms in the draft; vet the counterparty before signing the supply contract",
    "Verify the daily routine of the factory shift pattern against the safety filings",
    "Trace the wife's company filings listed in the judgment against the debtor and his holding company",
    "Find my company's home page address on the registry for the judgment against the debtor",
]


@pytest.mark.parametrize("purpose", LEGITIMATE_PURPOSES)
def test_legitimate_purposes_near_the_new_patterns_are_still_accepted(purpose: str) -> None:
    assert _entity(purpose, purpose_category="fraud_investigation").purpose == purpose


# ==============================================================================================================
# The permissible-purpose allowlist, matter references and whole-engagement screening
# ==============================================================================================================

# --------------------------------------------------------------------------- 1. the allowlist


def test_purpose_category_enum_is_exactly_the_documented_allowlist() -> None:
    assert [c.value for c in PurposeCategory] == ALL_CATEGORIES


@pytest.mark.parametrize("bad", ["employment", "tenancy", "credit", "insurance", "hiring", "tenant_screening"])
def test_there_is_deliberately_no_eligibility_category(bad: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _entity(GOOD_PURPOSE, purpose_category=bad)
    msg = str(exc.value)
    assert all(valid in msg for valid in ALL_CATEGORIES)  # the refusal lists every valid value


@pytest.mark.parametrize("missing", ["", "   "])
def test_a_missing_category_is_refused_with_the_list_of_valid_values(missing: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _entity(GOOD_PURPOSE, purpose_category=missing)
    assert all(valid in str(exc.value) for valid in ALL_CATEGORIES)


def test_category_is_required_when_the_argument_is_omitted() -> None:
    with pytest.raises(PIPurposeError):
        PIEngagement.build(CaseType.DUE_DILIGENCE, GOOD_PURPOSE, subject_is_person=False)


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_entity_subjects_may_use_every_category_without_a_matter_ref(category: str) -> None:
    eng = _entity(GOOD_PURPOSE, purpose_category=category)
    assert eng.purpose_category == category and eng.matter_ref == ""


@pytest.mark.parametrize("category", PERSON_CATEGORIES)
def test_person_subjects_may_use_the_person_categories_with_a_valid_ref(category: str) -> None:
    eng = _person(GOOD_PURPOSE, purpose_category=category)
    assert eng.purpose_category == category and eng.matter_ref == REF


@pytest.mark.parametrize("category", ENTITY_ONLY_CATEGORIES)
def test_person_subjects_may_not_use_the_entity_only_categories(category: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _person(GOOD_PURPOSE, purpose_category=category)
    assert "private person" in str(exc.value)


@pytest.mark.parametrize("category", PERSON_CATEGORIES)
@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
def test_every_person_category_needs_a_valid_matter_ref_on_every_case_type(category: str, case_type: CaseType) -> None:
    purpose = GOOD_PURPOSE
    with pytest.raises(PIPurposeError) as exc:
        PIEngagement.build(case_type, purpose, subject_is_person=True, purpose_category=category)
    assert "matter reference" in str(exc.value).lower()
    for bad_ref in ("TBD", "12345", "n/a", "x"):
        with pytest.raises(PIPurposeError):
            PIEngagement.build(
                case_type, purpose, subject_is_person=True, purpose_category=category, matter_ref=bad_ref
            )
    assert PIEngagement.build(
        case_type, purpose, subject_is_person=True, purpose_category=category, matter_ref=REF
    ).matter_ref == REF


def test_category_spelling_is_normalised_and_stored_as_the_value() -> None:
    assert _entity(GOOD_PURPOSE, purpose_category="Judgment-Enforcement").purpose_category == "judgment_enforcement"
    assert _entity(GOOD_PURPOSE, purpose_category=PurposeCategory.ASSET_RECOVERY).purpose_category == "asset_recovery"


def test_a_supplied_matter_ref_is_still_format_checked_for_entities() -> None:
    with pytest.raises(PIPurposeError):
        _entity(GOOD_PURPOSE, matter_ref="TBD")
    assert _entity(GOOD_PURPOSE, matter_ref="MSA-7").matter_ref == "MSA-7"


# --------------------------------------------------------------------------- 2. relationship-term exception


RELATIONSHIP_PURPOSE = "Asset search against my ex-husband to enforce the support order"


@pytest.mark.parametrize("category", ["asset_recovery", "litigation_support"])
@pytest.mark.parametrize("case_type", OTHER_CASE_TYPES)
def test_relationship_term_allowed_only_for_asset_recovery_or_litigation_support_with_a_ref(
    category: str, case_type: CaseType
) -> None:
    assert _person(RELATIONSHIP_PURPOSE, case_type, purpose_category=category).matter_ref == REF
    with pytest.raises(PIPurposeError):
        PIEngagement.build(
            case_type, RELATIONSHIP_PURPOSE, subject_is_person=True, purpose_category=category,
            matter_ref="placeholder",
        )


@pytest.mark.parametrize(
    "category",
    ["judgment_enforcement", "service_of_process", "fraud_investigation", "authorities_referral",
     "counterparty_due_diligence"],
)
@pytest.mark.parametrize("case_type", OTHER_CASE_TYPES)
def test_relationship_term_refused_under_every_other_person_category_even_with_a_valid_ref(
    category: str, case_type: CaseType
) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _person(RELATIONSHIP_PURPOSE, case_type, purpose_category=category)
    assert "former-partner relationship" in str(exc.value)


@pytest.mark.parametrize("case_type", PERSON_LOCATE_TYPES)
def test_relationship_term_never_allowed_on_person_locate_types(case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError):
        _person("Find my ex-wife for the support proceeding", case_type, purpose_category="asset_recovery")


def test_a_fake_matter_ref_no_longer_lifts_the_pursuit_screen() -> None:
    for purpose in ("She blocked me and changed her number, find her assets", "Find where my ex-wife lives now"):
        for case_type in ALL_CASE_TYPES:
            with pytest.raises(PIPurposeError):
                _person(purpose, case_type, matter_ref="CV-24-00123456", purpose_category="asset_recovery")


def test_pursuit_screen_direct_call_keeps_its_legacy_behaviour_without_a_category() -> None:
    pursuit_screen(RELATIONSHIP_PURPOSE, CaseType.ASSET_SEARCH, True, REF)
    with pytest.raises(PIPurposeError):
        pursuit_screen(RELATIONSHIP_PURPOSE, CaseType.ASSET_SEARCH, True, REF, purpose_category="fraud_investigation")
    pursuit_screen(RELATIONSHIP_PURPOSE, CaseType.ASSET_SEARCH, True, REF, purpose_category="asset_recovery")


# --------------------------------------------------------------------------- 3. category vs purpose text


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_a_declared_category_that_contradicts_an_eligibility_purpose_is_refused(category: str) -> None:
    with pytest.raises(PIPurposeError) as exc:
        _entity("Check a tenant before signing the lease", purpose_category=category)
    msg = str(exc.value)
    assert "declared purpose contradicts the described use" in msg
    assert "FCRA" in msg


def test_litigation_support_plus_check_a_tenant_is_refused_for_a_person_too() -> None:
    with pytest.raises(PIPurposeError) as exc:
        _person("check a tenant for me please", CaseType.BACKGROUND, purpose_category="litigation_support")
    assert "declared purpose contradicts the described use" in str(exc.value)


# --------------------------------------------------------------------------- 4. every free-text field is screened


@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
def test_pursuit_wording_in_another_field_is_refused(case_type: CaseType) -> None:
    for kw in (
        {"client": "Find where my ex-girlfriend lives"},
        {"extra_texts": ["she blocked me and I want to locate her ex-girlfriend"]},
        {"extra_texts": ["", "Acme Ltd", "Find where my ex-girlfriend lives"]},
        {"matter_ref": "CV-24-00123456 she blocked me"},
    ):
        with pytest.raises(PIPurposeError):
            PIEngagement.build(
                case_type, GOOD_PURPOSE, subject_is_person=False, purpose_category="fraud_investigation", **kw
            )


@pytest.mark.parametrize("case_type", ALL_CASE_TYPES)
def test_eligibility_wording_in_another_field_is_refused(case_type: CaseType) -> None:
    for text in ("Tenant screening for a rental application", "Employee vetting for a finance position"):
        with pytest.raises(PIPurposeError) as exc:
            _entity(GOOD_PURPOSE, case_type, extra_texts=[text])
        assert "FCRA" in str(exc.value)
        with pytest.raises(PIPurposeError):
            _entity(GOOD_PURPOSE, case_type, client=text)


@pytest.mark.parametrize("case_type", PERSON_LOCATE_TYPES)
def test_motive_wording_in_another_field_is_refused_for_person_locates(case_type: CaseType) -> None:
    with pytest.raises(PIPurposeError):
        _person(GOOD_PURPOSE, case_type, extra_texts=["Subject is my ex-wife, she moved away"])
    with pytest.raises(PIPurposeError):
        _person(GOOD_PURPOSE, case_type, client="my ex-girlfriend")


def test_relationship_term_in_another_field_needs_the_exception() -> None:
    with pytest.raises(PIPurposeError):
        _person(GOOD_PURPOSE, purpose_category="fraud_investigation", extra_texts=["the debtor is my ex-wife"])
    assert _person(GOOD_PURPOSE, purpose_category="asset_recovery", extra_texts=["the debtor is my ex-wife"])


def test_a_phrase_split_across_fields_is_still_caught() -> None:
    with pytest.raises(PIPurposeError):
        _entity(GOOD_PURPOSE, client="she blocked", extra_texts=["me everywhere"])


def test_long_pasted_text_is_screened_to_the_end() -> None:
    padding = "Quarterly registry filings reviewed for the supplier. " * 200  # ~10k characters
    with pytest.raises(PIPurposeError):
        _entity(GOOD_PURPOSE, extra_texts=[padding + "She blocked me and moved away, where she lives now."])
    with pytest.raises(PIPurposeError):
        _entity(GOOD_PURPOSE, extra_texts=[padding + "pr3-3mpl0yment checks of the staff"])
    assert _entity(GOOD_PURPOSE, extra_texts=[padding]).purpose == GOOD_PURPOSE


@pytest.mark.slow
def test_screening_a_large_dump_is_fast() -> None:
    dump = "Acme Holdings Ltd director filings, registered office in Toronto, annual return. " * 1500
    started = time.perf_counter()
    _entity(GOOD_PURPOSE, extra_texts=[dump])
    assert time.perf_counter() - started < 8.0


def test_clean_extra_fields_do_not_block_a_legitimate_engagement() -> None:
    eng = _entity(
        GOOD_PURPOSE,
        client="Northwind Procurement",
        matter_ref="CV-24-00123456",
        extra_texts=["Hypothesis: funds moved through the parent", "acme.example", "jane@acme.example", "+14165550123"],
    )
    assert eng.client == "Northwind Procurement"


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


# --------------------------------------------------------------------------- D2. credential-shaped text in the fields

CREDENTIAL_SHAPES = [
    f"password: {SECRET}",
    f"pw={SECRET}",
    f"bob@acme.com:{SECRET}",
    f"https://bob:{SECRET}@acme.com/",
    f'{{"password":"{SECRET}"}}',
]


@pytest.mark.parametrize("shape", CREDENTIAL_SHAPES)
@pytest.mark.parametrize("field", ["purpose", "client", "matter_ref"])
@pytest.mark.parametrize("subject_is_person", [True, False])
def test_build_refuses_credential_shaped_text_in_purpose_client_and_matter_ref(
    field: str, shape: str, subject_is_person: bool
) -> None:
    values = {"purpose": GOOD_PURPOSE, "client": "Northwind Procurement", "matter_ref": REF}
    values[field] = f"{values[field]} {shape}"
    with pytest.raises(PIPurposeError) as caught:
        PIEngagement.build(
            CaseType.ASSET_SEARCH,
            values["purpose"],
            client=values["client"],
            matter_ref=values["matter_ref"],
            subject_is_person=subject_is_person,
            purpose_category="litigation_support",
        )
    flag = "--matter-ref" if field == "matter_ref" else f"--{field}"
    message = str(caught.value)
    assert f"credential-shaped text found in {flag}" in message
    assert "remove it; credentials are not used in PI mode" in message
    assert SECRET not in message and "Zq7" not in message and "acme.com" not in message


def test_ordinary_purpose_client_and_matter_ref_are_not_mistaken_for_credentials() -> None:
    eng = _person(
        "Enforce judgment 24-CV-1234; trace the debtor's assets (note: see exhibit B, ref: 24-CV-1234)",
        client="Northwind Procurement Ltd: Attn Jane Smith, jane.smith@northwind.example",
        matter_ref="Smith v. Jones, Court File No. CV-24-00123456",
    )
    assert eng.client.startswith("Northwind")


def test_a_credential_shaped_purpose_is_refused_before_any_other_gate() -> None:
    with pytest.raises(PIPurposeError, match="credential-shaped text found in --purpose"):
        PIEngagement.build(CaseType.LOCATE, f"password: {SECRET}", subject_is_person=True, purpose_category="")


# ==============================================================================================================
# Obfuscation: the compact-phrase (skeleton) pass
# ==============================================================================================================

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


# ==============================================================================================================
# Bounded time: timing guards and the hard cap
# ==============================================================================================================

# --------------------------------------------------------------------------- D1. timing guards and the hard cap

SCREENS: Dict[str, Callable[[str], object]] = {
    "eligibility": lambda text: screen_eligibility(text),
    "validate_purpose": lambda text: validate_purpose(text),
    "motive_person_locate": lambda text: motive_screen(text, CaseType.LOCATE, True),
    "pursuit_person_locate": lambda text: pursuit_screen(text, CaseType.LOCATE, True, "", "litigation_support"),
    "pursuit_entity": lambda text: pursuit_screen(
        text, CaseType.DUE_DILIGENCE, False, "", "counterparty_due_diligence"
    ),
    "free_texts_person": lambda text: screen_free_texts([text], CaseType.ASSET_SEARCH, True, REF, "litigation_support"),
    "free_texts_entity": lambda text: screen_free_texts(
        [text], CaseType.DUE_DILIGENCE, False, "", "counterparty_due_diligence"
    ),
    "build_entity": lambda text: _entity(GOOD_PURPOSE, extra_texts=[text]),
    "build_person": lambda text: _person(GOOD_PURPOSE, extra_texts=[text]),
}


@pytest.mark.parametrize("screen", sorted(SCREENS))
@pytest.mark.parametrize("name", sorted(ADVERSARIAL_300KB))
def test_every_screen_finishes_quickly_on_300kb_of_adversarial_text(screen: str, name: str) -> None:
    assert _guard(SCREENS[screen], ADVERSARIAL_300KB[name]) < LIMIT_S, (screen, name)


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(_adversarial(MAX_SCREEN_CHARS)))
@pytest.mark.parametrize("screen", ["free_texts_person", "free_texts_entity", "eligibility", "build_entity"])
def test_text_right_at_the_cap_is_screened_in_bounded_time(screen: str, name: str) -> None:
    text = _adversarial(MAX_SCREEN_CHARS)[name]
    assert len(text) == MAX_SCREEN_CHARS
    assert _guard(SCREENS[screen], text) < LIMIT_S, (screen, name)


BENIGN_FILLER = "Quarterly registry filings were reviewed for the supplier. "


@pytest.mark.parametrize("screen", ["eligibility", "free_texts_person", "free_texts_entity", "build_entity"])
def test_text_over_the_cap_is_refused_not_silently_skipped(screen: str) -> None:
    text = _repeat(BENIGN_FILLER, MAX_SCREEN_CHARS + 1)
    with pytest.raises(PIPurposeError) as caught:
        SCREENS[screen](text)
    message = str(caught.value)
    assert f"{MAX_SCREEN_CHARS:,}" in message and "characters" in message
    assert "too long" in message.lower()


@pytest.mark.slow
def test_benign_text_at_the_cap_is_accepted() -> None:
    text = _repeat(BENIGN_FILLER, MAX_SCREEN_CHARS)
    screen_eligibility(text)
    screen_free_texts([text], CaseType.DUE_DILIGENCE, False, "", "counterparty_due_diligence")


@pytest.mark.slow
def test_a_phrase_at_the_very_end_of_a_near_cap_text_is_still_found() -> None:
    padding = _repeat(BENIGN_FILLER, MAX_SCREEN_CHARS - 60)
    with pytest.raises(PIPurposeError):
        screen_free_texts(
            [padding + " She blocked me, find where she lives"],
            CaseType.DUE_DILIGENCE,
            False,
            "",
            "fraud_investigation",
        )


def test_the_cap_constant_is_generous_enough_for_the_documented_large_dump() -> None:
    assert MAX_SCREEN_CHARS >= 150_000
    assert pi_gates.MAX_SCREEN_CHARS == MAX_SCREEN_CHARS


def test_the_skeleton_pass_agrees_with_the_slow_reference_on_disguised_phrases() -> None:
    for text, category in [
        ("pr3-3mpl0yment checks", "eligibility"),
        ("p r e - e m p l o y m e n t", "eligibility"),
        ("she is e x w i f e", "relationship"),
        ("restraning order", "motive"),
        ("shire of hire", None),
    ]:
        hits = pi_gates._skeleton_hits(text)
        assert (category in hits) if category else not hits, (text, hits)
