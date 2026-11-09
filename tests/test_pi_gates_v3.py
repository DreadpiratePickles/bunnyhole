"""Third hardening pass on the PI purpose gates: the permissible-purpose allowlist and whole-engagement screening.

A phrase blocklist can never reach full recall, so an engagement now needs an attested ``PurposeCategory`` from a short
allowlist, a person subject needs a narrower category AND a valid matter reference, and the phrase screens run over
EVERY free-text field. The phrase lists stay as a cross-check. The "still accepted" lists pin the legitimate wording
that must not be refused. A safety net, not a guarantee: the category is attested, not verified.
"""

from __future__ import annotations

import time

import pytest

from bunnyhole.engine.pi import (
    CaseType,
    PIEngagement,
    PIPurposeError,
    PurposeCategory,
    motive_screen,
    pursuit_screen,
    validate_purpose,
)

REF = "23-CV-1182"
ALL_CASE_TYPES = list(CaseType)
PERSON_LOCATE_TYPES = [CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON]
OTHER_CASE_TYPES = [CaseType.ASSET_SEARCH, CaseType.DUE_DILIGENCE, CaseType.FRAUD_SCREEN]
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
