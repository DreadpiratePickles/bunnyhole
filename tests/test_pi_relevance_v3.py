"""Third quality pass on ``pi_relevance``: financial-line namesakes, affiliates, transliteration, registry prefixes.

Pure and offline. The examples are the false positives and misses a third verifier found in live Bombardier,
Rosneft and Boeing reports.
"""

from __future__ import annotations

import pytest

from bunnyhole.engine.pi_relevance import name_match_level
from bunnyhole.engine.pi_relevance import score_subject_relevance as score


def _rel(subject: str, label: str, **kw) -> str:
    return score(subject, label, **kw)[0]


# ---------------------------------------------------------------- R1: financial-line namesakes are never the subject


@pytest.mark.parametrize(
    ("subject", "label"),
    [
        ("Apple Inc", "Apple Bank"),
        ("Apple Inc", "Apple Trust Company"),
        ("Rosneft", "Rosneft Bank"),
        ("Shell plc", "Shell Bank"),
        ("Tesla Inc", "Tesla Bank"),
        ("Boeing Company", "Boeing Company Charitable Trust"),
        ("Boeing Company", "Employees Community Fund Of The Boeing Company"),
        ("Acme Corp", "Acme Insurance Ltd"),
    ],
)
def test_a_financial_line_namesake_is_flagged_never_subject(subject: str, label: str):
    rel, why = score(subject, label, tool="gleif_level1_level2_api")
    assert rel in {"related", "unrelated"}
    assert rel != "subject"
    assert "collision" in why or "affiliate" in why


def test_energy_and_mining_are_not_identity_neutral():
    assert _rel("Shell plc", "Shell Energy") == "related"  # a probable affiliate, not the subject itself
    assert _rel("Northern Lights", "Northern Lights Mining") == "related"


def test_legal_forms_are_still_stripped():
    for form in ("Inc", "Ltd", "LLC", "plc", "Corp", "AG", "SA", "GmbH", "PJSC", "OJSC", "Company", "Co"):
        assert _rel("Acme Widgets", f"Acme Widgets {form}") == "subject", form


def test_group_and_holdings_are_affiliates_not_the_subject():
    assert _rel("Acme Widgets", "Acme Widgets Group") == "related"
    assert _rel("Acme Widgets", "Acme Widgets Holdings Ltd") == "related"


# ---------------------------------------------------------------- R1: a hidden affiliate is related


def test_a_name_containing_the_whole_subject_plus_extra_words_is_a_probable_affiliate():
    rel, why = score("Gazprom", "Gazprom Neft", tool="gleif_level1_level2_api")
    assert rel == "related"
    assert "affiliate" in why or "subsidiary" in why


def test_extra_words_that_mark_a_different_business_keep_it_a_collision():
    rel, why = score("Bombardier Inc", "Bombardier Produits Récréatifs", tool="gleif_level1_level2_api")
    assert rel == "unrelated" and "possible name collision" in why


def test_a_long_tail_of_unfamiliar_words_is_a_collision_not_an_affiliate():
    rel, why = score("Acme", "Acme Alpha Beta Gamma Delta Society Place")
    assert rel == "unrelated" and "possible name collision" in why


# ---------------------------------------------------------------- R1: compounds, spaces, legal-form translations


def test_prefix_compound_names_are_recognised_as_related():
    rel, why = score("Citigroup", "Citibank")
    assert rel == "related"
    assert "citi" in why


def test_space_split_names_match_and_the_german_legal_form_is_translated():
    assert _rel("Volkswagen AG", "Volks Wagen Aktiengesellschaft") == "subject"
    assert _rel("Siemens AG", "Siemens Aktiengesellschaft") == "subject"


@pytest.mark.parametrize(
    "label",
    [
        "Acme Widgets Société Anonyme",
        "Acme Widgets Gesellschaft mit beschränkter Haftung",
        "Acme Widgets Aktieselskab",
        "Acme Widgets naamloze vennootschap",
        "Acme Widgets Sociedad Anónima",
        "Acme Widgets Aktiengesellschaft",
    ],
)
def test_long_form_legal_forms_are_removed(label: str):
    assert _rel("Acme Widgets", label) == "subject"


def test_cyrillic_legal_names_are_transliterated_and_their_legal_forms_removed():
    label = 'публичное акционерное общество "Нефтяная компания "Роснефть"'
    rel, _why = score("Rosneft", label, tool="gleif_level2_ultimate_parent")
    assert rel == "subject"
    assert _rel("Rosneft", "ПАО Роснефть") == "subject"
    assert _rel("Gazprom", "ПАО «Газпром»") == "subject"
    assert _rel("Rosneft", "ООО Роснефть Трейдинг") == "related"  # extra word: probable affiliate


# ---------------------------------------------------------------- R1: registry and source prefixes are not name tokens


@pytest.mark.parametrize(
    "label", ["Wikidata Q1141123: Rosneft", "🏛️ Wikidata Q1141123: Rosneft", "Wikidata Q1: Rosneft PJSC"]
)
def test_the_wikidata_prefix_and_qid_are_not_extra_name_tokens(label: str):
    assert _rel("Rosneft", label) == "subject"


def test_a_501c3_prefix_is_not_a_name_token_but_the_name_still_decides():
    assert _rel("Rosfest", "501(c)(3): Rosfest Inc (Sarasota, FL)") == "subject"
    assert _rel("Rosneft", "501(c)(3): Rosfest Inc (Sarasota, FL)") == "unrelated"


# ---------------------------------------------------------------- R1: news and forum nodes need whole words


def test_a_forum_post_with_a_lookalike_word_is_not_about_the_subject():
    rel, why = score(
        "Bombardier Inc", "HN (@hhs): Bombarding gamblers with offers greatly increase...", tool="hackernews_algolia_archive"
    )
    assert rel == "unrelated"
    assert "no name match" in why


def test_a_news_item_with_the_exact_word_is_related():
    assert _rel("Bombardier Inc", "Reuters: Bombardier talks with Boeing", tool="google_news_rss") == "related"


def test_a_news_item_with_a_spelling_variant_is_not_matched_fuzzily():
    assert _rel("Rosneft", "Rosnieft sanctioned", tool="google_news_rss") == "unrelated"


def test_a_cyrillic_headline_naming_the_subject_is_related():
    assert _rel("Rosneft", "АНТИКОР: Роснефть Drones attacked", tool="google_news_rss") == "related"


# ---------------------------------------------------------------- name_match_level (used for sanctions-list matching)


def test_match_level_exact_strong_affiliate_none():
    assert name_match_level("ROSNEFT TRADING S.A.", "Rosneft Trading S.A. (CH)") == "exact"
    assert name_match_level("PJSC Rosneft Oil Company", "Rosneft Deutschland GmbH (DE)") == "affiliate"
    assert name_match_level("Rosneft", "Rosneft Deutschland GmbH (DE)") == "affiliate"
    assert name_match_level("Rosneft", "Rosneft Bank") == "none"
    assert name_match_level("Hewlett Packard Financial Services", "Hewlett-Packard Co") == "strong"
    assert name_match_level("Rosneft", "") == "none"


def test_match_level_uses_other_names_the_node_carries():
    assert name_match_level("ROSNEFT", "Some Label", attributes={"legal_name": "Rosneft PJSC"}) == "exact"
