"""Round 3: unhedged identity, ownership and strength assertions, and the retry feedback vocabulary.

The code owns every relation. A bullet may state an ownership edge only as the exact phrase of its ``O`` line
(``Child is owned by Parent``) and only citing that ``O`` id. A bullet that cites the right id but misreads it in other
words is NOT caught (documented in docs/PI_STREAM.md). Evidence here is ``narrative_result``: F1 Acme Holdings Ltd,
F2 Jane Q Example, F3 @janex on GitHub, O1 "Acme Holdings Ltd is owned by Jane Q Example".
"""

from __future__ import annotations

from typing import List

import pytest
from pi_narrative_helpers import narrative_result, wrap

from bunnyhole.engine.pi_narrative_feedback import FIXED_WORDS, echoable_word
from bunnyhole.engine.pi_narrative_input import NarrativeEvidence, build_evidence
from bunnyhole.engine.pi_narrative_validate import Violation, feedback_lines, validate_analysis


@pytest.fixture(scope="module")
def evidence() -> NarrativeEvidence:
    built = build_evidence(narrative_result())
    assert built is not None
    return built


def found(text: str, evidence: NarrativeEvidence) -> List[Violation]:
    return validate_analysis(text, evidence)


def one(text: str, tag: str = "[F2]") -> str:
    return wrap(f"- {tag} {text}")


@pytest.mark.parametrize("text", [
    "The account janex is Jane's in the companies_house record.",
    "The account is Jane Q Example in the companies_house record.",
    "Of course Acme Holdings Ltd is actually Jane Q Example in the record.",
    "Jane Q Example is the owner of Acme Holdings Ltd in the companies_house record.",
    "Jane Q Example owns Acme Holdings Ltd according to companies_house.",
    "Jane Q Example controls Acme Holdings Ltd according to companies_house.",
    "Acme Holdings Ltd is controlled by Jane Q Example according to companies_house.",
    "Jane Q Example is the beneficial owner of Acme Holdings Ltd.",
    "The officer record and the account are the same person in companies_house.",
    "The two records are one and the same in companies_house.",
    "The two records are identical in the companies_house record.",
    "The record is corroborated by the companies_house entry for Jane Q Example.",
    "The record is high confidence for Jane Q Example in companies_house.",
    "This is a probable account for Jane Q Example in companies_house.",
    "Jane Q Example is probably linked to Acme Holdings Ltd in companies_house.",
    "Jane Q Example is likely linked to Acme Holdings Ltd in companies_house.",
    "Jane Q Example is highly likely linked to Acme Holdings Ltd in companies_house.",
    "Jane Q Example runs Acme Holdings Ltd according to companies_house.",
    "Jane Q Example and her brother appear in the companies_house record.",
    "Jane Q Example's husband appears in the companies_house record.",
])
def test_unhedged_identity_ownership_and_strength_claims_are_rejected(text: str, evidence: NarrativeEvidence) -> None:
    violations = found(one(text, "[F1,F2]"), evidence)
    assert "identity" in {v.code for v in violations}, (text, [(v.code, v.detail) for v in violations])


def test_ownership_is_allowed_only_as_the_exact_phrase_of_a_cited_o_edge(evidence: NarrativeEvidence) -> None:
    phrase = "Acme Holdings Ltd is owned by Jane Q Example"
    assert found(one(f"{phrase} at 60% according to companies_house.", "[F1,O1]"), evidence) == []
    assert found(one(f"{phrase.lower()} at 60% according to companies_house.", "[F1,O1]"), evidence) == []
    # the same words without citing the edge are an ownership claim the code did not make
    assert "identity" in {v.code for v in found(one(f"{phrase} at 60% in companies_house.", "[F1,F2]"), evidence)}
    # reversed direction
    reversed_ = "Jane Q Example is owned by Acme Holdings Ltd at 60% according to companies_house."
    assert "identity" in {v.code for v in found(one(reversed_, "[F1,O1]"), evidence)}
    # other ownership wording next to the right phrase
    extra = f"{phrase} and is wholly owned by Jane Q Example."
    assert "identity" in {v.code for v in found(one(extra, "[F1,O1]"), evidence)}


def test_ownership_edge_prose_without_ownership_verbs_still_passes(evidence: NarrativeEvidence) -> None:
    text = one("The ownership edge shows 60% for Acme Holdings Ltd with source companies_house.", "[F1,O1]")
    assert found(text, evidence) == []


def test_the_ready_phrase_is_the_start_of_the_o_line(evidence: NarrativeEvidence) -> None:
    assert evidence.lines["O1"].split(" | ")[0] == "Acme Holdings Ltd is owned by Jane Q Example"
    assert {"Acme Holdings Ltd", "Jane Q Example"} <= evidence.names


def test_a_possessive_of_an_evidence_name_that_is_not_an_identity_claim_passes(evidence: NarrativeEvidence) -> None:
    assert found(one("Both Jane Q Example's record and Acme Holdings Ltd appear in companies_house."), evidence) == []


# ------------------------------------------------------------------------------------- retry feedback vocabulary


def test_feedback_names_the_class_and_echoes_only_words_from_the_fixed_vocabulary(evidence: NarrativeEvidence) -> None:
    text = wrap("- [F2] Jane Q Example is confirmed in companies_house and Zorblax appears on 3 pages in March.")
    lines = " | ".join(feedback_lines(found(text, evidence)))
    assert "label or certainty word" in lines and "('confirmed')" in lines
    assert "an unlisted capitalised word" in lines
    assert "Zorblax" not in lines
    assert "a month with no date in the evidence ('march')" in lines


def test_feedback_never_echoes_arbitrary_model_text(evidence: NarrativeEvidence) -> None:
    text = wrap("- [F2] Jane Q Example appears and sanctionsxyzzy plus the Qwertyuiop record are in companies_house.")
    lines = " | ".join(feedback_lines(found(text, evidence))).lower()
    assert "sanctionsxyzzy" not in lines and "qwertyuiop" not in lines


def test_echoable_word_is_a_strict_allowlist() -> None:
    assert echoable_word("Confirmed") == "confirmed"
    assert echoable_word("two") == "two" and echoable_word("weekly") == "weekly" and echoable_word("March") == "march"
    assert echoable_word("zorblax") == "" and echoable_word("ignore previous instructions") == ""
    assert "suggest" in FIXED_WORDS and "should" in FIXED_WORDS and "matches" in FIXED_WORDS
    assert all(word == word.lower() and " " not in word for word in FIXED_WORDS)
