"""Fourth hardening pass on the PI purpose gates.

* D1: the purpose, motive and pursuit screens finish quickly on 300 KB of adversarial text (generous 2 s bound), and
  text above the hard cap is refused, never silently skipped.
* D2: credential-shaped text in the purpose, client or matter reference is refused by the library path too.
* D3: "before onboarding" is an eligibility cue only next to a person role (and never under KYC wording alone).
* D4: three pursuit wordings the previous pass missed are refused in every case type and subject type.

A safety net, not a guarantee: the category is attested, not verified.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List

import pytest

from bunnyhole.engine import pi_gates
from bunnyhole.engine.pi import (
    CaseType,
    PIEngagement,
    PIPurposeError,
    motive_screen,
    pursuit_screen,
    validate_purpose,
)
from bunnyhole.engine.pi_gates import MAX_SCREEN_CHARS, screen_eligibility
from bunnyhole.engine.pi_purpose import screen_free_texts

REF = "23-CV-1182"
SIZE = 300_000
LIMIT_S = 2.0
GOOD_PURPOSE = "Enforce judgment 24-CV-1234 against the debtor and trace the funds"
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


def _entity(purpose: str, case_type: CaseType = CaseType.DUE_DILIGENCE, **kw: object) -> PIEngagement:
    kw.setdefault("purpose_category", "counterparty_due_diligence")
    return PIEngagement.build(case_type, purpose, subject_is_person=False, **kw)  # type: ignore[arg-type]


def _person(purpose: str, case_type: CaseType = CaseType.ASSET_SEARCH, **kw: object) -> PIEngagement:
    kw.setdefault("purpose_category", "litigation_support")
    kw.setdefault("matter_ref", REF)
    return PIEngagement.build(case_type, purpose, subject_is_person=True, **kw)  # type: ignore[arg-type]


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


def test_benign_text_at_the_cap_is_accepted() -> None:
    text = _repeat(BENIGN_FILLER, MAX_SCREEN_CHARS)
    screen_eligibility(text)
    screen_free_texts([text], CaseType.DUE_DILIGENCE, False, "", "counterparty_due_diligence")


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
