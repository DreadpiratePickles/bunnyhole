"""The Connections-only validator (``pi_narrative_validate``): pure, no network, no model.

The model writes one section, ``### Connections``: tagged bullets (tag first). Everything risky is code-built, so the
validator can be strict and structural. Sections: layout and tags, characters, bullet shape, evidence-derived tokens,
excluded topics, certainty and accusation words, advice and methods, the language gate, rendering, and the usability
gate (realistic outputs must pass).
"""

from __future__ import annotations

import re
from typing import List

import pytest
from pi_narrative_helpers import GOOD_ANALYSIS, narrative_result, wrap

from bunnyhole.engine.pi_narrative_input import NarrativeEvidence, build_evidence
from bunnyhole.engine.pi_narrative_validate import (
    HEADING_LINE,
    MAX_BULLETS,
    parse_bullets,
    render_connections,
    validate_analysis,
)


@pytest.fixture(scope="module")
def evidence() -> NarrativeEvidence:
    built = build_evidence(narrative_result())
    assert built is not None
    return built


def codes(text: str, evidence: NarrativeEvidence) -> List[str]:
    return sorted({v.code for v in validate_analysis(text, evidence)})


def bullet(text: str, tag: str = "[F1]") -> str:
    return wrap(f"- {tag} {text}")


def rejects(text: str, code: str, evidence: NarrativeEvidence) -> None:
    assert code in codes(text, evidence), (code, codes(text, evidence))


def accepts(text: str, evidence: NarrativeEvidence) -> None:
    found = [(v.code, v.detail) for v in validate_analysis(text, evidence)]
    assert found == [], found


def test_good_sample_is_accepted(evidence: NarrativeEvidence) -> None:
    accepts(GOOD_ANALYSIS, evidence)
    assert {"F1", "F2", "F3", "O1"} <= evidence.model_ids
    assert not ({"S1", "W1", "G1"} & evidence.model_ids) and {"S1", "W1", "G1"} <= evidence.known_ids


# ------------------------------------------------------------------------------------- layout and tags


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   \n\n",
        "- [F1] Acme Holdings Ltd is owned by Jane Q Example.\n",  # no heading
        "Here is my analysis.\n" + GOOD_ANALYSIS,  # preamble
        GOOD_ANALYSIS + "\nThis is my overall conclusion about Acme Holdings Ltd.\n",  # trailing text
        GOOD_ANALYSIS.replace("### Connections", "## Connections"),
        GOOD_ANALYSIS.replace("### Connections", "**Connections**"),
        "```markdown\n" + GOOD_ANALYSIS + "```\n",
        GOOD_ANALYSIS + "\n### Timeline\nNo dated facts were supplied.\n",
        GOOD_ANALYSIS + "\n## Bottom line\n- [F1] Acme Holdings Ltd is fine.\n",
        GOOD_ANALYSIS + "\n### What is not established\n- [F1] Acme Holdings Ltd is a lead.\n",
        "### Connections\n- [F1] Acme Holdings Ltd is owned by Jane Q Example.\n  and by nobody else here.\n",
        "### Connections\n1. [F1] Acme Holdings Ltd is owned by Jane Q Example.\n",
        "### Connections\n* [F1] Acme Holdings Ltd is owned by Jane Q Example.\n",
        "### Connections\n> [F1] Acme Holdings Ltd is owned by Jane Q Example.\n",
        "### Connections\n- ### Sanctions screening is complete [F1]\n",
        "### Connections\n- ----------\n",
        "### Connections\n- Acme Holdings Ltd is owned by Jane Q Example [F1].\n",  # tag last
        "### Connections\n- [F1]Acme Holdings Ltd is owned by Jane Q Example.\n",  # no space after the tag
    ],
)
def test_wrong_layout_is_rejected(text: str, evidence: NarrativeEvidence) -> None:
    assert codes(text, evidence), repr(text)


def test_crlf_and_typographic_quotes_are_normalised(evidence: NarrativeEvidence) -> None:
    accepts(GOOD_ANALYSIS.replace("\n", "\r\n"), evidence)
    accepts(bullet("Jane Q Example’s record is dated 2024-01-01 in the ownership edge."), evidence)


def test_none_means_no_connections(evidence: NarrativeEvidence) -> None:
    assert codes(f"{HEADING_LINE}\nNone.\n", evidence) == ["no_connections"]
    assert parse_bullets(f"{HEADING_LINE}\nNone.\n") == []


@pytest.mark.parametrize(
    "tag",
    ["[F9]", "[R1]", "[F 3]", "[f3]", "[F1][F2]", "[F1, F9]", "(F1)", "［F1］", "[F1,F2,F3,F1,F2]", "[ F1 ]", "[F1;F2]",
     "[S1]", "[W1]", "[G1]", "[F1,S1]", "[]"],
)
def test_bad_tags_are_rejected(tag: str, evidence: NarrativeEvidence) -> None:
    assert codes(wrap(f"- {tag} Acme Holdings Ltd is owned by Jane Q Example."), evidence), tag


def test_only_f_and_o_ids_of_the_prompt_are_citable(evidence: NarrativeEvidence) -> None:
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example.", "[S1]"), "citation", evidence)
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example.", "[G1]"), "citation", evidence)
    rejects(bullet("The GitHub account belongs to Jane Q Example.", "[G1]"), "citation", evidence)
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example.", "[F9]"), "unknown_id", evidence)
    accepts(bullet("Acme Holdings Ltd is owned by Jane Q Example.", "[F1, O1]"), evidence)


def test_bullet_shape_limits(evidence: NarrativeEvidence) -> None:
    ok = "- [F1,O1] Acme Holdings Ltd is owned by Jane Q Example."
    rejects(wrap(*([ok] * (MAX_BULLETS + 1))), "bullets", evidence)
    accepts(wrap(*([ok] * MAX_BULLETS)), evidence)
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example. " * 3, "[F1,O1]"), "bullets", evidence)
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example and " + "it is also described by gleif " * 20, "[F1,O1]"), "bullets", evidence)
    rejects(bullet("Acme."), "bullets", evidence)
    rejects(bullet("---."), "bullets", evidence)
    accepts(bullet("Acme Holdings Ltd is owned by Jane Q Example. It is also described by gleif.", "[F1,O1]"), evidence)
    accepts(bullet("Acme Holdings Ltd. is owned by Jane Q Example.", "[F1,O1]"), evidence)


def test_square_brackets_only_in_the_tag(evidence: NarrativeEvidence) -> None:
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example [see registry]."), "markup", evidence)
    rejects(bullet("Acme Holdings Ltd is owned by Jane Q Example [F2]."), "markup", evidence)


# ------------------------------------------------------------------------------------- characters


@pytest.mark.parametrize(
    "char",
    ["​", "‮", "‬", "﻿", " ", "\x07", "⁦", "­", "⠀", "͏", "️", "\t",
     "［", "］", "０", "٤", "`", "#", ">", "*", "|", "<", "~", "!", "?", "+", "=", "{", "}", "\\", "$",
     "а", "张", "א", "ก", "\U0001f600", "•"],
)
def test_characters_outside_the_allowlist_are_rejected(char: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(f"Acme Holdings{char} Ltd is owned by Jane Q Example."), "characters", evidence)


def test_accented_latin_letters_are_allowed_when_in_the_evidence() -> None:
    result = narrative_result()
    result["pi"]["findings"][0]["label"] = "Société Acme Ltd"
    evidence = build_evidence(result)
    assert evidence is not None
    accepts(bullet("Société Acme appears with Jane Q Example in the companies_house record."), evidence)


# ------------------------------------------------------------------------------------- evidence-derived tokens


@pytest.mark.parametrize(
    "sentence",
    [
        "Jane Q Example owns 75% of Acme Holdings Ltd.",
        "Jane Q Example owns 75 % of Acme Holdings Ltd.",
        "Jane Q Example owns 7 5 % of Acme Holdings Ltd.",
        "Jane Q Example owns 1 2 3 percent of Acme Holdings Ltd.",
        "Jane Q Example owns seventy five percent of Acme Holdings Ltd.",
        "Jane Q Example owns sixty percent of Acme Holdings Ltd.",
        "Jane Q Example owns half of Acme Holdings Ltd.",
        "Jane Q Example owns a dozen firms.",
        "Acme Holdings Ltd has three sources.",
        "Acme Holdings Ltd has 14 subsidiaries.",
        "Acme Holdings Ltd was formed in June.",
        "Acme Holdings Ltd was formed on 17 June.",
        "Acme Holdings Ltd was formed in 2019.",
        "Acme Holdings Ltd was formed in the spring.",
        "The host 203.0.113.5 appears in Acme Holdings Ltd records.",
        "The host ::1 appears in Acme Holdings Ltd records.",
        "The host fe80::1 appears in Acme Holdings Ltd records.",
        "The host dead:beef:cafe:babe appears in Acme Holdings Ltd records.",
        "The digest deadbeef appears in Acme Holdings Ltd records.",
        "The digest abc123 appears in Acme Holdings Ltd records.",
        "The handle @jqe appears in Acme Holdings Ltd records.",
        "The address jane@acme.example appears in Acme Holdings Ltd records.",
        "The site acme-evil.com appears in Acme Holdings Ltd records.",
        "The site xn--80ak6aa92e.com appears in Acme Holdings Ltd records.",
        "The address jane at acme dot com appears in Acme Holdings Ltd records.",
        "The address jane (at) acme (dot) com appears in Acme Holdings Ltd records.",
        "See javascript:alert(1) in Acme Holdings Ltd records.",
    ],
)
def test_specifics_must_come_from_the_evidence(sentence: str, evidence: NarrativeEvidence) -> None:
    assert codes(bullet(sentence), evidence), sentence


@pytest.mark.parametrize(
    "sentence",
    [
        "Jane Q Example appears with 60% in the edge for Acme Holdings Ltd.",
        "Acme Holdings Ltd has 3 sources.",
        "Acme Holdings Ltd is described by 3 sources.",
        "The ownership edge is dated 2024-01-01 and so falls in January 2024.",
        "The GitHub handle @janex is on GitHub.",
        "Jane Q Example and Acme Holdings Ltd come from companies_house.",
        "Acme Holdings is described by Companies House.",
        "The Ontario Business Registry and CanLII are not named in these records.",
    ],
)
def test_specifics_from_the_evidence_are_accepted(sentence: str, evidence: NarrativeEvidence) -> None:
    accepts(bullet(sentence), evidence)


def test_hash_prefix_of_an_evidence_digest_is_accepted(evidence: NarrativeEvidence) -> None:
    digest = re.search(r"sha256=([0-9a-f]{64})", evidence.text)
    assert digest is not None
    accepts(bullet(f"The extract {digest.group(1)[:12]} backs Acme Holdings Ltd."), evidence)
    rejects(bullet(f"The extract {digest.group(1)[:5]}ffff backs Acme Holdings Ltd."), "invented", evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        "Robert owns the company.",  # sentence-initial: no starter list, so an unknown capitalised word is rejected
        "Zephyr registered the shares.",
        "Obtain the registry extract.",
        "Robert's company holds shares.",
        "The company is controlled by Roberto Silva.",
        "Acme Holdings Ltd is a subsidiary of Globex Corporation.",
        "Acme Holdings Ltd is also known as Acme Trading.",
        "Jane Example and Acme Holdings Ltd are named together.",  # run not in evidence order
        "Example Jane and Acme Holdings Ltd are named together.",
        "Jane Q Example Jr owns Acme Holdings Ltd.",
        "Jane Q Example lives in Toronto.",
        "Jane Q Example is shown with Telegram.",
        "Acme Holdings Ltd appears in a Delaware record.",
    ],
)
def test_capitalised_words_must_be_in_the_evidence(sentence: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(sentence), "invented", evidence) if not sentence.startswith("Obtain") else rejects(
        bullet(sentence), "advice", evidence
    )


def test_function_words_may_start_a_sentence(evidence: NarrativeEvidence) -> None:
    accepts(bullet("Both records name Acme Holdings Ltd. This is how Jane Q Example is tied to it."), evidence)
    accepts(bullet("It is the tool companies_house that names Acme Holdings Ltd."), evidence)


def test_language_gate(evidence: NarrativeEvidence) -> None:
    rejects(bullet("La empresa pertenece a la persona segun el registro oficial de Acme Holdings Ltd."), "language", evidence)
    rejects(bullet("No hay sanciones contra el sujeto."), "language", evidence)


# ------------------------------------------------------------------------------------- excluded topics, certainty, methods


@pytest.mark.parametrize(
    "sentence",
    [
        "This clears the subject.",
        "Nothing concerning surfaced for Acme Holdings Ltd.",
        "Acme Holdings Ltd came back negative.",
        "No hits were returned on the lists for Acme Holdings Ltd.",
        "Acme Holdings Ltd is not sanctioned.",
        "Acme Holdings Ltd was screened and is fine.",
        "Acme Holdings Ltd has low risk.",
        "Acme Holdings Ltd is compliant.",
        "Acme Holdings Ltd is safe to deal with.",
        "Acme Holdings Ltd passed the checks.",
        "Acme Holdings Ltd is listed as a company.",
        "Acme Holdings Ltd is a close match for Jane Q Example.",
        "Acme Holdings Ltd was flagged for review.",
        "The result for Acme Holdings Ltd is empty.",
        "Acme Holdings Ltd is absent from other records.",
        "Acme Holdings Ltd is not on the other records.",
        "Acme Holdings Ltd has no concerns attached to it.",
        "Acme Holdings Ltd checks out.",
        "Jane Q Example can be ruled out.",
        "Jane Q Example is a PEP.",
        "Jane Q Example is a politically exposed person.",
        "Acme Holdings Ltd is OK.",
        "Acme Holdings Ltd is all good.",
    ],
)
def test_sanctions_screening_and_absence_talk_is_excluded(sentence: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(sentence), "topic", evidence)


@pytest.mark.parametrize(
    "sentence",
    [
        "Acme Holdings Ltd is confirmed by 3 sources.",
        "The GitHub account is verified.",
        "The link is established.",
        "The account is proven to be hers.",
        "The account is definitely hers.",
        "The account is certainly hers.",
        "The account is undoubtedly hers.",
        "The account is authenticated.",
        "No doubt, Jane Q Example is the owner.",
        "Without doubt the account is hers.",
        "Beyond doubt Jane Q Example owns Acme Holdings Ltd.",
        "Jane Q Example is the same person as the account holder.",
        "The GitHub account belongs to Jane Q Example.",
        "The GitHub account is the subject's own account.",
        "The account is solid and settled.",
        "The account appears to be valid.",
        "The account is genuine.",
        "The account is clearly hers.",
        "The account is surely hers.",
    ],
)
def test_label_and_certainty_words_are_rejected(sentence: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(sentence), "certainty", evidence)


@pytest.mark.parametrize(
    "word",
    ["fraud", "fraudster", "criminal", "crime", "money laundering", "illegal", "unlawful", "corrupt", "bribe", "scam",
     "terror links", "guilty", "dangerous", "shady", "suspicious", "evasion", "sham", "front company", "crook",
     "organised crime", "shell", "felon"],
)
def test_accusation_words_are_rejected_unless_in_the_cited_evidence(word: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(f"Jane Q Example is tied to {word} in these records.", "[F2]"), "accusation", evidence)


def test_accusation_word_that_is_in_the_cited_evidence_is_accepted() -> None:
    result = narrative_result()
    result["pi"]["findings"][0]["label"] = "Fraud Squad Ltd"
    evidence = build_evidence(result)
    assert evidence is not None
    assert validate_analysis(wrap("- [F1] Fraud Squad Ltd is described by 3 sources."), evidence) == []
    assert "accusation" in {v.code for v in validate_analysis(wrap("- [F2] Fraud Squad Ltd is tied to Jane Q Example."), evidence)}


@pytest.mark.parametrize(
    "sentence",
    [
        "Do not hack anything and stop with Acme Holdings Ltd.",
        "Obtain the registry extract for Acme Holdings Ltd.",
        "Verify his password by trying his old one.",
        "Obtain his phone records for Jane Q Example.",
        "Acme Holdings Ltd should be checked again.",
        "We recommend a registry search for Acme Holdings Ltd.",
        "A next step is a registry extract for Acme Holdings Ltd.",
        "Pretext the bank about Acme Holdings Ltd.",
        "Jane Q Example can be tracked with a GPS tracker.",
        "Interview the neighbour of Jane Q Example pretending to be a surveyor.",
        "Run Jane Q Example through a leaked database.",
        "Jane Q Example uses a fake profile.",
        "Check the mailbox of Jane Q Example.",
    ],
)
def test_advice_methods_and_instructions_are_rejected(sentence: str, evidence: NarrativeEvidence) -> None:
    assert codes(bullet(sentence), evidence), sentence
    assert {"advice", "invented", "topic"} & set(codes(bullet(sentence), evidence)) or codes(bullet(sentence), evidence)


@pytest.mark.parametrize("sentence", ["Obtain the registry extract for Acme Holdings Ltd.", "Do not hack anything and stop."])
def test_imperatives_and_methods_are_flagged_as_advice(sentence: str, evidence: NarrativeEvidence) -> None:
    rejects(bullet(sentence), "advice", evidence)


# ------------------------------------------------------------------------------------- rendering


def test_render_shows_the_codes_label_next_to_every_tag(evidence: NarrativeEvidence) -> None:
    rendered = render_connections(GOOD_ANALYSIS, dict(evidence.finding_labels))
    assert "- [F1 · confirmed, F2 · probable, O1] " in rendered
    assert "- [F3 · lead] " in rendered
    assert rendered.count("\n") == 1


def test_render_escapes_markdown_and_emits_plain_list_items_only(evidence: NarrativeEvidence) -> None:
    text = bullet("Acme Holdings Ltd (see: jane_q) appears with Jane Q Example & others @janex.")
    accepts(text, evidence)
    rendered = render_connections(text, dict(evidence.finding_labels))
    assert "\\(" in rendered and "\\)" in rendered and "\\_" in rendered and "\\&" in rendered
    assert all(line.startswith("- [F1 · confirmed] ") for line in rendered.splitlines())
    assert "\n#" not in rendered and "<" not in rendered and ">" not in rendered and "`" not in rendered


# ------------------------------------------------------------------------------------- the usability gate

REALISTIC = [
    # 1: ownership edge between two findings
    """### Connections
- [F1,F2,O1] Jane Q Example is recorded as the owner of Acme Holdings Ltd at 60% according to companies_house.
- [F3] The GitHub account @janex on GitHub rests on a single source and may be unrelated to the other findings.
""",
    # 2: shared registry source
    """### Connections
- [F1,F2] Both Acme Holdings Ltd and Jane Q Example are recorded by companies_house, which is how they are connected.
""",
    # 3: one entity, several sources
    """### Connections
- [F1] Acme Holdings Ltd is described by 3 sources, namely gleif, companies_house and sec_edgar.
""",
    # 4: ownership edge with its date
    """### Connections
- [O1] Acme Holdings Ltd is owned by Jane Q Example at 60%, as recorded by companies_house on 2024-01-01.
""",
    # 5: person with two sources and aging data
    """### Connections
- [F2] Jane Q Example appears in records from companies_house and wikidata, and the freshness of that data is aging.
""",
    # 6: finding and edge together
    """### Connections
- [F2,O1] Jane Q Example is both a finding with 2 sources and the parent in the ownership edge for Acme Holdings Ltd.
""",
    # 7: no recorded link between a handle and the company
    """### Connections
- [F1,F3] The GitHub account @janex on GitHub has no recorded link to Acme Holdings Ltd in this evidence.
""",
    # 8: single-source handle
    """### Connections
- [F3] The only source for @janex on GitHub is github, so it stays a single-source finding.
""",
    # 9: edge and registry record
    """### Connections
- [F1,O1] The ownership edge and the registry record both name Acme Holdings Ltd.
- [F2] Jane Q Example is the parent named in that edge.
""",
    # 10: different tools, no shared source (two findings that do not agree)
    """### Connections
- [F2,F3] Jane Q Example and the GitHub account @janex on GitHub come from different tools, companies_house and github, so they do not share a source.
""",
    # 11: findings that conflict in strength
    """### Connections
- [F1,F3] The evidence for Acme Holdings Ltd is far stronger than for @janex on GitHub, and no shared record ties them together.
""",
    # 12: a short two-sentence bullet
    """### Connections
- [F2,F1] Jane Q Example is a related party. Acme Holdings Ltd is the entity named in the findings.
""",
]


def test_realistic_outputs_pass_the_validator(evidence: NarrativeEvidence) -> None:
    failed = [(i + 1, [(v.code, v.detail) for v in validate_analysis(doc, evidence)]) for i, doc in enumerate(REALISTIC)]
    failed = [(i, problems) for i, problems in failed if problems]
    assert len(REALISTIC) >= 10
    assert len(REALISTIC) - len(failed) >= 0.9 * len(REALISTIC), failed


NATURAL_SENTENCES = [
    "Acme Holdings Ltd is supported by 3 sources, so it is the best-documented finding.",
    "Jane Q Example appears as a party to Acme Holdings Ltd, with 60% recorded by companies_house.",
    "Jane Q Example is a finding with 2 sources and aging freshness.",
    "The GitHub account @janex on GitHub is a single-source finding and may belong to a different person.",
    "Legal ownership is described from Acme Holdings Ltd to Jane Q Example.",
    "This would be consistent with a link between Jane Q Example and Acme Holdings Ltd.",
    "Acme Holdings Ltd and Jane Q Example are connected through the ownership edge.",
    "Both the registry record and the GLEIF record name Acme Holdings Ltd.",
    "Ownership data comes from companies_house and is dated 2024-01-01.",
    "Acme Holdings Ltd was reported by gleif, companies_house and sec_edgar.",
    "Jane Q Example is named in the ownership edge as the parent of Acme Holdings Ltd.",
    "The freshness of the Jane Q Example record is aging, which weakens the link.",
    "The GitHub account @janex on GitHub shares no tool with the Acme Holdings Ltd records.",
    "The record for Acme Holdings Ltd comes from 3 independent tools.",
    "Jane Q Example is linked to Acme Holdings Ltd only through the companies_house edge.",
    "The wikidata record is a second source for Jane Q Example.",
    "Acme Holdings Ltd appears in sec_edgar and in gleif.",
    "The ownership edge cites companies_house as its source.",
    "The edge for Acme Holdings Ltd is dated 2024-01-01 and shows 60%.",
    "The two records agree on the name Acme Holdings Ltd.",
    "Jane Q Example and the GitHub account are in separate records.",
    "The registry names Acme Holdings Ltd and Jane Q Example together.",
    "The third source for Acme Holdings Ltd is sec_edgar.",
    "Acme Holdings Ltd has fresh data from 3 tools.",
    "The GitHub account is the weakest finding here.",
    "The two strongest findings are Acme Holdings Ltd and Jane Q Example.",
    "Jane Q Example is a related party of Acme Holdings Ltd.",
    "The evidence ties Jane Q Example to Acme Holdings Ltd by ownership.",
    "No record ties the GitHub account to Acme Holdings Ltd.",
    "The ownership percentage of 60% comes from one edge.",
]


#: Natural wording that the validator rejects on purpose (the usability cost of the strict contract).
NATURAL_SLIPS = [
    "Both Acme Holdings Ltd and Jane Q Example are recorded by companies_house, and the two are connected.",
    "Acme Holdings Ltd is the subject of the findings.",
    "The registry confirms that Acme Holdings Ltd exists.",
    "Acme Holdings Ltd was listed by companies_house.",
    "Jane Q Example is a strong match for the owner of Acme Holdings Ltd.",
]


@pytest.mark.parametrize("sentence", NATURAL_SLIPS)
def test_known_natural_slips_are_rejected(sentence: str, evidence: NarrativeEvidence) -> None:
    assert codes(bullet(sentence, "[F1,F2]"), evidence)


def test_natural_connection_sentences_mostly_pass(evidence: NarrativeEvidence) -> None:
    failed = []
    for sentence in NATURAL_SENTENCES:
        problems = validate_analysis(bullet(sentence, "[F1,F2]"), evidence)
        if problems:
            failed.append((sentence, sorted({v.code for v in problems})))
    assert len(failed) <= 0.15 * len(NATURAL_SENTENCES), failed
