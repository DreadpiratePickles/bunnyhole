"""The deterministic validator of the AI analysis (``pi_narrative_validate``): pure, no network, no model.

Requirement map (see the task brief): (a) unknown ids, (b) uncited claims, (c) identifiers and names that are not in
the evidence, (d) forbidden-method language, (e) label upgrades and clearance wording, plus the section layout, the
markup ban and the canonical rendering.
"""

from __future__ import annotations

from typing import List

import pytest
from pi_narrative_helpers import GLEIF_URL, GOOD_ANALYSIS, INFO_EMAIL, narrative_result

from bunnyhole.engine.pi_narrative_input import NarrativeEvidence, build_evidence
from bunnyhole.engine.pi_narrative_validate import (
    EXEMPT_SENTENCES,
    SECTION_HEADINGS,
    canonical_markdown,
    cited_ids,
    validate_analysis,
)


@pytest.fixture(scope="module")
def evidence() -> NarrativeEvidence:
    built = build_evidence(narrative_result())
    assert built is not None
    return built


def _codes(text: str, evidence: NarrativeEvidence) -> List[str]:
    return [v.code for v in validate_analysis(text, evidence)]


def _with(sentence: str) -> str:
    """A full, otherwise valid analysis whose Connections section gets one extra ``sentence``."""
    return GOOD_ANALYSIS.replace("### Timeline", f"- {sentence}\n\n### Timeline", 1)


def test_good_sample_is_accepted(evidence: NarrativeEvidence) -> None:
    assert validate_analysis(GOOD_ANALYSIS, evidence) == []


def test_good_sample_cites_only_supplied_ids(evidence: NarrativeEvidence) -> None:
    assert set(cited_ids(GOOD_ANALYSIS)) <= evidence.known_ids
    assert {"F1", "F2", "F3", "S1", "G1", "O1"} <= evidence.known_ids


# ------------------------------------------------------------------------------------- (a) unknown ids


@pytest.mark.parametrize("tag", ["[F9]", "[R1]", "[F1, F9]", "[F1,S9]", "[X1]"])
def test_unknown_citation_id_is_rejected(evidence: NarrativeEvidence, tag: str) -> None:
    assert "unknown_id" in _codes(_with(f"Acme Holdings Ltd is registered {tag}."), evidence)


def test_non_citation_square_brackets_are_rejected(evidence: NarrativeEvidence) -> None:
    assert "markup" in _codes(_with("Acme Holdings Ltd is registered [see the registry] [F1]."), evidence)


# ------------------------------------------------------------------------------------- (b) uncited claims


@pytest.mark.parametrize(
    "sentence",
    [
        "Acme Holdings Ltd is registered.",
        "Acme Holdings Ltd is registered. Jane Q Example is a director [F2].",
        "Acme Holdings Ltd is registered [F1] and Jane Q Example is a director.",
    ],
)
def test_sentence_without_a_trailing_citation_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "uncited" in _codes(_with(sentence), evidence)


@pytest.mark.parametrize(
    "sentence",
    ["Acme Holdings Ltd is registered [F1].", "Acme Holdings Ltd is registered. [F1]", "Acme Holdings Ltd. is a company [F1,F2]."],
)
def test_citation_before_or_after_the_full_stop_is_accepted(evidence: NarrativeEvidence, sentence: str) -> None:
    assert validate_analysis(_with(sentence), evidence) == []


@pytest.mark.parametrize("exempt", sorted(EXEMPT_SENTENCES))
def test_exempt_sentences_need_no_citation(evidence: NarrativeEvidence, exempt: str) -> None:
    text = GOOD_ANALYSIS.replace("- Obtain the corporate registry extract to confirm the ownership chain [O1].", f"- {exempt}")
    assert validate_analysis(text, evidence) == []


# ------------------------------------------------------------------------------------- (c) invented identifiers


@pytest.mark.parametrize(
    "sentence",
    [
        "Acme Holdings Ltd has a site at https://evil.example/path [F1].",
        "Acme Holdings Ltd has a site at www.evil.example [F1].",
        "Acme Holdings Ltd is hosted at evil-corp.example [F1].",
        "Acme Holdings Ltd can be reached at boss@evil-corp.example [F1].",
        "Acme Holdings Ltd can be called on +1 416 555 0199 [F1].",
        "Acme Holdings Ltd has the digest " + "ab12" * 16 + " [F1].",
        "Acme Holdings Ltd has the receipt rcpt_0123456789 [F1].",
        "Acme Holdings Ltd was linked to Viktor Orlov [F1].",
        "Acme Holdings Ltd was linked to Globex Corporation [F1].",
        "Acme Holdings Ltd was founded on 1999-01-02 [F1].",
        "Acme Holdings Ltd was dissolved in 1987 [F1].",
    ],
)
def test_identifier_or_name_not_in_the_evidence_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "invented" in _codes(_with(sentence), evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        f"Acme Holdings Ltd is described at {GLEIF_URL} [F1].",
        f"Acme Holdings Ltd lists the contact {INFO_EMAIL} [F1].",
        "Acme Holdings Ltd was incorporated on 2021-03-04 [F1].",
        "Acme Holdings Ltd was linked to Jane Q Example [F1,F2].",
        "The OFAC SDN list was screened, and Canada SEMA too [S1].",
        "A hash from the evidence such as rcpt_aaaaaaaaaa supports it [F1].",
    ],
)
def test_identifier_or_name_that_is_in_the_evidence_is_accepted(evidence: NarrativeEvidence, sentence: str) -> None:
    assert validate_analysis(_with(sentence), evidence) == []


def test_full_receipt_hash_from_the_evidence_is_accepted(evidence: NarrativeEvidence) -> None:
    import re

    digest = re.search(r"sha256=([0-9a-f]{64})", evidence.text)
    assert digest is not None
    assert validate_analysis(_with(f"The extract {digest.group(1)} supports it [F1]."), evidence) == []


# ------------------------------------------------------------------------------------- (d) forbidden methods


@pytest.mark.parametrize(
    "sentence",
    [
        "Pretext the registrar to release the file [G1].",
        "Hack into the account to read the messages [F3].",
        "Bypass the login of the portal [S1].",
        "Impersonate a client when calling the bank [G1].",
        "Contact the subject under a false name [G1].",
        "Call the subject posing as a supplier [G1].",
        "Use social engineering on the front desk [G1].",
        "Place a GPS tracker on the vehicle [G1].",
        "Log in to his account with the leaked password [F3].",
        "Use a fake profile to befriend the director [F3].",
        "Do not pretext anyone [G1].",
    ],
)
def test_forbidden_method_language_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "forbidden_method" in _codes(_with(sentence), evidence)


def test_lawful_next_steps_are_not_flagged(evidence: NarrativeEvidence) -> None:
    ok = _with("Interview the director with honest self-identification, or engage a licensed investigator [G1].")
    assert validate_analysis(ok, evidence) == []


# ------------------------------------------------------------------------------------- (e) labels and clearance


@pytest.mark.parametrize(
    "sentence",
    [
        "The GitHub account is confirmed as the subject's [F3].",
        "Jane Q Example is confirmed as a director [F2].",
        "The GitHub account is verified [F3].",
        "The GitHub account is probably the subject's [F3].",
        "A weak name match is confirmed [W1].",
        "The EU list result is confirmed [S1].",
    ],
)
def test_upgrading_a_label_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "label_upgrade" in _codes(_with(sentence), evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        "Acme Holdings Ltd is confirmed by three sources [F1].",
        "Jane Q Example is probable on two sources [F2].",
        "The GitHub account is not confirmed [F3].",
        "The GitHub account link is unconfirmed and a lead only [F3].",
    ],
)
def test_wording_that_matches_the_label_is_accepted(evidence: NarrativeEvidence, sentence: str) -> None:
    assert validate_analysis(_with(sentence), evidence) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "The subject is cleared of sanctions exposure [S1].",
        "The sanctions screening shows no risk [S1].",
        "The subject is clean [S1].",
        "This is an all clear on sanctions [S1].",
        "The subject is not sanctioned [S1].",
        "The subject is innocent of any listing [S1].",
        "It is safe to proceed with the deal [S1].",
        "There is no sanctions risk [S1].",
    ],
)
def test_clearance_wording_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "clearance" in _codes(_with(sentence), evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        "A no-hit result is not clearance [S1].",
        "The subject has not been cleared by this screening [S1].",
    ],
)
def test_negated_clearance_wording_is_accepted(evidence: NarrativeEvidence, sentence: str) -> None:
    assert validate_analysis(_with(sentence), evidence) == []


# ------------------------------------------------------------------------------------- layout and markup


def test_section_headings_are_the_four_of_the_contract() -> None:
    assert SECTION_HEADINGS == (
        "Connections", "Timeline", "What is not established", "Suggested next steps (lawful)",
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("### Timeline\n- 2021-03-04: Incorporated is the only dated fact supplied [F1].\n\n", ""),
        lambda t: t + "\n### Bonus\n- Extra [F1].\n",
        lambda t: "Here is my analysis.\n\n" + t,
        lambda t: t.replace("### Connections", "### Timeline", 1),
        lambda t: "",
    ],
)
def test_wrong_section_layout_is_rejected(evidence: NarrativeEvidence, mutate) -> None:  # type: ignore[no-untyped-def]
    assert "structure" in _codes(mutate(GOOD_ANALYSIS), evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        "See [the registry](https://example.org/company/00000001) [F1].",
        "Acme Holdings Ltd is <b>registered</b> [F1].",
        "Acme Holdings Ltd is `registered` [F1].",
        "![x](a.png) [F1].",
    ],
)
def test_markup_is_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert "markup" in _codes(_with(sentence), evidence)


def test_overlong_output_is_rejected(evidence: NarrativeEvidence) -> None:
    long_text = GOOD_ANALYSIS + "\n" + "- Acme Holdings Ltd is registered [F1].\n" * 400
    assert "too_long" in _codes(long_text, evidence)


def test_canonical_markdown_normalises_heading_level_and_blank_lines(evidence: NarrativeEvidence) -> None:
    messy = GOOD_ANALYSIS.replace("### ", "## ").replace("\n\n", "\n\n\n\n")
    assert validate_analysis(messy, evidence) == []
    rendered = canonical_markdown(messy)
    assert rendered.count("### ") == 4
    assert "\n\n\n" not in rendered
    assert rendered.startswith("### Connections")


@pytest.mark.parametrize(
    "sentence",
    [
        "The subject is cle\u200bared [S1].",  # zero-width space inside the word
        "The subject is cle\u0430red [S1].",  # Cyrillic a inside a Latin word
        "The subject is \uff43leared [S1].",  # full-width c
    ],
)
def test_obfuscated_clearance_wording_is_still_rejected(evidence: NarrativeEvidence, sentence: str) -> None:
    assert _codes(_with(sentence), evidence)


def test_abbreviation_and_initials_do_not_split_a_sentence(evidence: NarrativeEvidence) -> None:
    ok = _with("Obtain filed records, e.g. Articles of the company, from the registry [G1].")
    assert "uncited" not in _codes(ok, evidence)
