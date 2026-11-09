"""Tests for ``pi_relevance``: is a graph node about the subject, or noise? And ``name_match_level``.

Pure and offline. The examples are the real false positives and misses that verifiers found in live Bombardier,
Rosneft and Boeing reports: first pass (the verifier's exact examples, normalisation, aliases, weak overlap,
news/forum/token nodes, unknown states), then the third pass (financial-line namesakes, hidden affiliates,
compounds and legal-form translations, registry prefixes, whole-word news matches, ``name_match_level``).
"""

# Replaces: test_pi_relevance.py, test_pi_relevance_v3.py (consolidated 2026-11-09).

from __future__ import annotations

import pytest

from bunnyhole.engine.pi_relevance import name_match_level
from bunnyhole.engine.pi_relevance import score_subject_relevance as score

# ==============================================================================================================
# Subject relevance: verifier examples, normalisation, aliases, weak overlap, unknown states
# ==============================================================================================================


def _rel(subject: str, label: str, **kw) -> str:
    return score(subject, label, **kw)[0]


# ---------------------------------------------------------------- the exact examples from the verifier


def test_registry_or_sanctions_node_with_the_same_legal_name_is_the_subject():
    rel, why = score("Rosneft", "Rosneft PJSC", tool="gac_sema_sanctions")
    assert rel == "subject"
    assert why


def test_lookalike_nonprofit_is_unrelated():
    rel, why = score("Rosneft", "Rosfest Inc", tool="propublica_irs_990_api")
    assert rel == "unrelated"
    assert "rosfest" in why.lower() or "no name match" in why.lower()


def test_forum_post_with_no_name_match_is_unrelated():
    rel, why = score("Rosneft", "Why Agile Often Fails", tool="hackernews_algolia_archive")
    assert rel == "unrelated"
    assert "no name match" in why


def test_crypto_token_with_no_name_match_is_unrelated():
    assert _rel("Rosneft", "$ROBINCAT", tool="dexscreener_lp_forensics") == "unrelated"


def test_other_companys_filing_is_unrelated():
    assert _rel("Rosneft", "Pinnacle Airlines Corp", tool="sec_edgar_efts + edgartools") == "unrelated"


def test_wikidata_namesake_is_unrelated():
    assert _rel("Bombardier Inc", "Incentro", tool="wikidata") == "unrelated"


def test_division_or_regional_unit_of_the_subject_is_related():
    rel, why = score("Bombardier Inc", "Bombardier Transport Canada", tool="gleif_level1_level2_api")
    assert rel == "related"
    assert "affiliate" in why


def test_namesake_with_distinct_extra_words_is_flagged_as_a_possible_collision_not_dropped_silently():
    rel, why = score("Bombardier Inc", "Bombardier Produits Récréatifs", tool="gleif_level1_level2_api")
    assert rel == "unrelated"
    assert "possible name collision" in why
    assert "bombardier" in why


def test_the_same_namesake_is_related_when_an_ownership_edge_links_it():
    rel, why = score("Bombardier Inc", "Bombardier Produits Récréatifs", linked_by_edge=True)
    assert rel == "related"
    assert "edge" in why


# ---------------------------------------------------------------- name normalisation


@pytest.mark.parametrize(
    "label",
    ["Bombardier Inc.", "BOMBARDIER INC", "🏛️ Bombardier Inc (CA)", "Bombardier Incorporated", "The Bombardier Company"],
)
def test_legal_forms_case_emoji_and_jurisdiction_suffix_are_ignored(label: str):
    assert _rel("Bombardier Inc", label, tool="gleif_level1_level2_api") == "subject"


def test_accents_and_possessive_are_folded():
    assert _rel("Société Générale", "SOCIETE GENERALE SA", tool="gleif_level1_level2_api") == "subject"


def test_dotted_legal_form_abbreviations_are_stripped():
    assert _rel("Acme Widgets", "Acme Widgets S.A.") == "subject"
    assert _rel("Acme Widgets", "Acme Widgets N.V.") == "subject"


def test_transliteration_and_plural_tolerance():
    assert _rel("Rosneft", "Rosnieft") == "subject"  # one edit
    assert _rel("Rosneft", "Rosnefts") == "subject"
    assert _rel("Gazprom Neft", "Gazpromneft PJSC") == "subject"  # split vs joined spelling


def test_edit_distance_two_on_a_short_name_is_not_tolerated_and_is_called_a_lookalike():
    rel, why = score("Rosneft", "Rosfest")
    assert rel == "unrelated"
    assert "lookalike" in why


def test_identity_neutral_descriptors_do_not_change_identity():
    assert _rel("Rosneft", "Rosneft Oil Company") == "subject"
    assert _rel("Alaska Airlines", "Alaska Air Inc") == "subject"
    assert _rel("Alaska Airlines", "Alaska Air Group") == "related"  # a group is a parent or holding: affiliate


def test_single_letter_initials_are_ignored_for_person_names():
    assert _rel("Jane Smith", "Jane Q. Smith") == "subject"


# ---------------------------------------------------------------- aliases, acronyms, attributes


def test_acronym_label_matches_the_spelled_out_subject():
    assert _rel("International Business Machines", "IBM") == "subject"
    assert _rel("IBM", "International Business Machines Corp") == "subject"


def test_alias_in_attributes_makes_a_node_the_subject():
    rel, why = score(
        "Rosneft", "Public Joint Stock Company Oil Major", attributes={"aliases": ["Rosneft", "Rosneft Oil"]}
    )
    assert rel == "subject"
    assert "alias" in why


def test_match_query_attribute_is_not_evidence():
    # the agents record the query that found the node; that must never count as a name match
    assert _rel("Rosneft", "Rosfest Inc", attributes={"match_query": "Rosneft"}) == "unrelated"


def test_matched_name_and_legal_name_attributes_count():
    assert _rel("Rosneft", "Some Display Label", attributes={"legal_name": "Rosneft PJSC"}) == "subject"
    assert _rel("Rosneft", "Some Display Label", attributes={"matched_name": "Rosneft"}) == "subject"


# ---------------------------------------------------------------- weak overlap, partial, edges


def test_one_shared_generic_token_is_weak_overlap():
    rel, why = score("Pinnacle Airlines Corp", "Alaska Airlines Inc", tool="sec_edgar_efts + edgartools")
    assert rel == "unrelated"
    assert "weak name overlap" in why


def test_one_shared_token_of_a_multi_word_subject_is_weak_overlap():
    rel, why = score("Northern Lights Mining", "Northern Dynamics Holdings")
    assert rel == "unrelated"
    assert "weak name overlap" in why


def test_shortened_form_of_a_multi_word_subject_is_related_not_subject():
    rel, _ = score("Hewlett Packard Financial Services", "Hewlett-Packard Co")
    assert rel == "related"


def test_ownership_or_officer_edge_makes_an_otherwise_unmatched_node_related():
    rel, why = score("Rosneft", "Igor Sechin", linked_by_edge=True)
    assert rel == "related"
    assert "edge" in why


def test_an_edge_never_downgrades_a_strong_name_match():
    assert _rel("Rosneft", "Rosneft PJSC", linked_by_edge=True) == "subject"


# ---------------------------------------------------------------- news / forum / token nodes


def test_article_that_mentions_the_subject_is_related_not_the_subject():
    rel, why = score("Rosneft", "Rosneft sanctioned by the EU over oil trade", tool="google_news_rss + shingling_detector")
    assert rel == "related"
    assert "mention" in why


def test_article_with_exact_name_is_still_not_the_subject():
    assert _rel("Rosneft", "Rosneft", tool="google_news_rss + shingling_detector") == "related"


def test_token_that_carries_the_subject_name_is_related_not_subject():
    assert _rel("Rosneft", "ROSNEFT", tool="dexscreener_lp_forensics") == "related"


# ---------------------------------------------------------------- unknown states


def test_unknown_when_the_subject_or_label_is_unusable():
    assert score("", "Rosneft PJSC")[0] == "unknown"
    assert score("Rosneft", "")[0] == "unknown"
    assert score("Inc", "Rosneft")[0] == "unknown"  # nothing left after stripping legal forms


def test_identifier_nodes_are_unknown_unless_they_embed_the_name():
    assert score("Rosneft", "203.0.113.7", entity_type="IPHost")[0] == "unknown"
    assert score("Rosneft", "0x" + "ab" * 20, entity_type="CryptoWallet")[0] == "unknown"
    assert score("Rosneft", "12 Quiet Lane", entity_type="Location")[0] == "unknown"
    rel, why = score("Rosneft", "rosneft.ru", entity_type="Domain")
    assert rel == "related" and "embeds" in why


def test_reason_is_always_a_nonempty_string_and_relevance_is_in_the_literal_set():
    for label in ("Rosneft PJSC", "Rosfest", "", "$X", "ROSNEFT", "Pinnacle Airlines Corp"):
        rel, why = score("Rosneft", label)
        assert rel in {"subject", "related", "unrelated", "unknown"}
        assert isinstance(why, str) and why


# ==============================================================================================================
# Third pass: namesakes, affiliates, transliteration, registry prefixes, name_match_level
# ==============================================================================================================


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
