"""Round 3: compatibility forms, look-alike letters and split words must not slip past the word screens.

The validator rejects (never normalises-then-accepts) ligatures, small capitals, fullwidth and other compatibility
characters, limits letters to Basic Latin, Latin-1 and Latin Extended-A/B, runs every word screen on an accent-folded
copy, and runs them again on a squashed copy so punctuation-split words are caught. Pure: no network, no model.
"""

from __future__ import annotations

import copy
from typing import List

import pytest
from pi_narrative_helpers import narrative_result, wrap

from bunnyhole.engine.pi_narrative_checks import disallowed_character
from bunnyhole.engine.pi_narrative_input import NarrativeEvidence, build_evidence
from bunnyhole.engine.pi_narrative_validate import validate_analysis


@pytest.fixture(scope="module")
def evidence() -> NarrativeEvidence:
    built = build_evidence(narrative_result())
    assert built is not None
    return built


def codes(text: str, evidence: NarrativeEvidence) -> List[str]:
    return sorted({v.code for v in validate_analysis(text, evidence)})


def one(text: str, tag: str = "[F2]") -> str:
    return wrap(f"- {tag} {text}")


LIGATURE_TEXTS = [
    "Jane Q Example appears and is conﬁrmed by the companies_house record.",  # ﬁ
    "Jane Q Example appears and the record is veriﬁed by companies_house.",
    "Jane Q Example appears and the record is deﬁnitely about the officer.",
    "Jane Q Example appears and is ﬂagged in the companies_house record.",  # ﬂ
    "Jane Q Example appears and the ﬁne print is in the companies_house record.",
    "Jane Q Example appears and the record is unﬂagged in companies_house.",
    "Jane Q Example appears and the record is eﬆablished by companies_house.",  # ﬆ
    "Jane Q Example appears on a liﬆ in the companies_house record.",
    "Jane Q Example appears on a liﬆed record in companies_house.",
    "Jane Q Example appears and ﬆole from the companies_house record.",
    "Jane Q Example appears and the ﬃ record is in companies_house.",  # ﬃ
    "Jane Q Example appears and the oﬀ record is in companies_house.",  # ﬀ
    "Jane Q Example appears and the ﬅ record is in companies_house.",  # ﬅ
]
SMALL_CAP_TEXTS = [
    "Jane Q Example is under ꜱanctions according to the companies_house record.",  # ꜱ
    "Jane Q Example is the same as ʀᴏʙᴇʀᴛ ꜱᴍɪᴛʜ in the record.",
    "Jane Q Example is ｓanctions listed in the companies_house record.",  # fullwidth s
    "Jane Q Example is under sanctıons according to the companies_house record.",  # dotless i
    "Jane Q Example is under sanctɯons according to the companies_house record.",  # IPA
    "Jane Q Example is under ᴄᴇrtain terms in the companies_house record.",  # phonetic extensions
    "Jane Q Example is under ⱡⱡ terms in the companies_house record.",  # Latin Extended-C
    "Jane Q Example is under ꜱꜱ terms in the companies_house record.",  # Latin Extended-D
    "Jane Q Example is ˢanctions in the companies_house record.",  # modifier letter
    "Jane Q Example is ſanctions in the companies_house record.",  # long s
    "Jane Q Example is under ĳ terms in the companies_house record.",  # ij ligature (NFKC differs)
    "Jane Q Example is Ǉ in the companies_house record.",  # LJ digraph
]


@pytest.mark.parametrize("text", LIGATURE_TEXTS + SMALL_CAP_TEXTS)
def test_compatibility_and_lookalike_letters_are_rejected_as_characters(text: str, evidence: NarrativeEvidence) -> None:
    assert codes(one(text), evidence) == ["characters"]


@pytest.mark.parametrize("ch", ["\ufb01", "\ua731", "\u1d0f", "\uff53", "\u0131", "\u0237", "\u0138", "\u01dd", "\u00b5"])
def test_disallowed_character_reports_these(ch: str) -> None:
    assert disallowed_character(ch) == ch


@pytest.mark.parametrize("ch", ["a", "Z", "é", "Á", "ø", "Ł", "ć", "ș", "ß", "1", " "])
def test_basic_latin_latin1_and_extended_ab_letters_stay_allowed(ch: str) -> None:
    assert disallowed_character(ch) is None


@pytest.mark.parametrize("word", ["sánctions", "cónfirmed", "rísk", "clèar", "lïst", "sanctiøns",
                                  "łist", "fráud"])
def test_accented_lookalikes_of_screened_words_are_caught_by_the_folded_copy(word: str, evidence: NarrativeEvidence) -> None:
    found = codes(one(f"Jane Q Example appears and the record is {word} in companies_house."), evidence)
    assert found and "characters" not in found, (word, found)


def test_a_legitimately_accented_evidence_name_still_passes() -> None:
    result = copy.deepcopy(narrative_result())
    for node in result["nodes"]:
        if node["id"] == "person:jane":
            node["label"] = "José Álvarez"
    for finding in result["pi"]["findings"]:
        if finding["node_id"] == "person:jane":
            finding["label"] = "José Álvarez"
    built = build_evidence(result)
    assert built is not None
    text = one("José Álvarez appears in the companies_house record.", "[F2]")
    assert validate_analysis(text, built) == []
    # the unaccented spelling of an evidence name matches too (comparison is accent-folded), nothing else changes
    assert validate_analysis(one("Jose Alvarez appears in the companies_house record.", "[F2]"), built) == []
    assert validate_analysis(one("José Álvares appears in the companies_house record.", "[F2]"), built) != []


@pytest.mark.parametrize("word", ["sanc/tions", "s.a.n.c.t.i.o.n.s", "con-firmed", "o.f.a.c.", "s a n c t i o n s", "ri-sk",
                                  "sanc.tions", "cle_ar", "ver-ified", "fra-ud", "O F A C", "s-a-n-c-t-i-o-n-s"])
def test_punctuation_split_screened_words_are_rejected(word: str, evidence: NarrativeEvidence) -> None:
    found = codes(one(f"Jane Q Example appears and the record is {word} in companies_house."), evidence)
    assert found, word


@pytest.mark.parametrize("phrase", ["a cross-border record", "a co-founder entry", "a well-known tool", "a part-time role"])
def test_ordinary_hyphenated_words_still_pass(phrase: str, evidence: NarrativeEvidence) -> None:
    text = one(f"Jane Q Example appears with {phrase} in the companies_house record at Acme Holdings Ltd.")
    assert validate_analysis(text, evidence) == [], phrase


@pytest.mark.parametrize("filler", ["a-a-a-a-a-a-a-a-a-a-a-a", "a@a@a@a@a@a@a@a@a@a", "x.y.z.x.y.z.x.y.z.x.y.z",
                                    "- - - - - - - - - - - - - - -", "it it it it it it it it"])
def test_content_free_repetitive_bullets_are_rejected(filler: str, evidence: NarrativeEvidence) -> None:
    assert codes(one(filler), evidence), filler


def test_a_bullet_needs_three_distinct_words_of_three_letters(evidence: NarrativeEvidence) -> None:
    assert codes(one("Jane Jane Jane Jane Jane Jane"), evidence)
    assert codes(one("Jane Jane Jane Example Example Example"), evidence)
    assert validate_analysis(one("Jane Q Example appears in companies_house."), evidence) == []


def test_mostly_punctuation_bullet_is_rejected(evidence: NarrativeEvidence) -> None:
    text = one("Jane Q Example ... ... ... ... ... ... ... ... ... ... ... ... ... ...")
    assert codes(text, evidence)


def test_duplicate_ids_inside_one_tag_are_rejected(evidence: NarrativeEvidence) -> None:
    assert "duplicate_id" in codes(one("Jane Q Example appears in companies_house.", "[F2,F2]"), evidence)
    assert validate_analysis(one("Jane Q Example appears in companies_house.", "[F2,F1]"), evidence) == []


def test_a_url_path_on_an_evidence_domain_must_be_in_the_evidence_in_full(evidence: NarrativeEvidence) -> None:
    assert "invented" in codes(one("Jane Q Example appears at example.org/janex/evil in companies_house."), evidence)
    assert "invented" in codes(one("Jane Q Example appears at https://example.org/janex/evil in companies_house."), evidence)
    assert validate_analysis(one("Jane Q Example appears at example.org/officer/jane in companies_house."), evidence) == []
    assert validate_analysis(one("Jane Q Example appears at https://example.org/officer/jane in companies_house."), evidence) == []
