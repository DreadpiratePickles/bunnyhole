"""Tests for the PI stream identity-resolution module (pure, deterministic, no network)."""

from __future__ import annotations

import itertools

import pytest

from bunnyhole.engine.pi_identity import (
    COMMON_NAMES,
    IdentityMatch,
    MatchVerdict,
    PersonRecord,
    cluster_candidates,
    is_common_name,
    name_variants,
    score_same_person,
)

# ----------------------------------------------------------------------------------------------
# name_variants
# ----------------------------------------------------------------------------------------------


def test_name_variants_core_forms():
    variants = name_variants("William J. Smith")
    for expected in (
        "william j. smith",  # as given (lowercased)
        "william smith",
        "w smith",
        "w. smith",
        "william j smith",
        "william j. smith",
        "bill smith",
        "billy smith",
        "will smith",
        "bill j smith",
    ):
        assert expected in variants, expected


def test_name_variants_as_given_is_first_and_lowercase():
    variants = name_variants("ROBERT  Brown")
    assert variants[0] == "robert brown"
    assert all(v == v.lower() for v in variants)


def test_name_variants_are_deduplicated():
    variants = name_variants("Robert Brown")
    assert len(variants) == len(set(variants))
    assert "bob brown" in variants and "rob brown" in variants


def test_name_variants_hyphen_and_space_splits():
    variants = name_variants("Anna Smith-Jones")
    for expected in ("anna smith-jones", "anna smith jones", "anna smith", "anna jones"):
        assert expected in variants, expected


def test_name_variants_hyphenated_first_name():
    variants = name_variants("Mary-Ann Lee")
    for expected in ("mary-ann lee", "mary ann lee", "maryann lee", "mary lee"):
        assert expected in variants, expected


def test_name_variants_never_guesses_a_maiden_name():
    variants = name_variants("Jane Smith")
    assert variants  # sanity
    assert all(v.split()[-1] == "smith" for v in variants)


def test_name_variants_last_comma_first_is_reordered():
    assert "john smith" in name_variants("Smith, John")


def test_name_variants_single_token_and_empty():
    assert name_variants("Madonna") == ["madonna"]
    assert name_variants("") == []
    assert name_variants("   ") == []


def test_name_variants_nickname_map_breadth():
    assert {"liz smith", "beth smith", "betty smith"} <= set(name_variants("Elizabeth Smith"))
    assert {"mike jones", "mick jones"} <= set(name_variants("Michael Jones"))


# ----------------------------------------------------------------------------------------------
# COMMON_NAMES
# ----------------------------------------------------------------------------------------------


def test_common_names_table_is_real_sized_and_lowercase():
    assert len(COMMON_NAMES) >= 60
    assert all(n == n.lower() and n for n in COMMON_NAMES)
    assert {"smith", "john", "garcia", "maria"} <= COMMON_NAMES


def test_is_common_name_requires_both_parts_common():
    assert is_common_name("John Smith")
    assert is_common_name("J. Smith")
    assert not is_common_name("John Zacharopoulos")
    assert not is_common_name("Zbigniew Smith")
    assert not is_common_name("")


# ----------------------------------------------------------------------------------------------
# score_same_person: weights and bands
# ----------------------------------------------------------------------------------------------


def _rec(name: str = "Quentin Aldous Vance", **kw) -> PersonRecord:
    return PersonRecord(name=name, **kw)


def test_name_only_match_is_never_same_and_has_no_anchors():
    a = _rec("Quentin Vance", source="a")
    b = _rec("Quentin Vance", source="b")
    m = score_same_person(a, b, common_name=False)
    assert isinstance(m, IdentityMatch)
    assert m.verdict is MatchVerdict.DIFFERENT
    assert m.anchors == []
    assert m.score == pytest.approx(0.2)


@pytest.mark.parametrize("name", ["John Smith", "Quentin Vance", "J Smith", "Maria Garcia"])
def test_name_alone_never_yields_same_or_probable(name: str):
    m = score_same_person(_rec(name), _rec(name))
    assert m.verdict in (MatchVerdict.DIFFERENT, MatchVerdict.POSSIBLE)
    assert m.verdict is not MatchVerdict.SAME


def test_weights_are_applied_as_specified():
    base = {"common_name": False}
    name_only = score_same_person(_rec("Quentin Vance"), _rec("Quentin Vance"), **base).score
    assert name_only == pytest.approx(0.2)

    def with_attr(**kw) -> float:
        return score_same_person(_rec("Quentin Vance", **kw), _rec("Quentin Vance", **kw), **base).score

    assert with_attr(dob_year=1980) == pytest.approx(0.2 + 0.25)
    assert with_attr(addresses=["12 Oak St, Springfield"]) == pytest.approx(0.2 + 0.25)
    assert with_attr(phones=["415-555-0100"]) == pytest.approx(0.2 + 0.3)
    assert with_attr(emails=["q@example.org"]) == pytest.approx(0.2 + 0.3)
    assert with_attr(relatives=["Mary Vance"]) == pytest.approx(0.2 + 0.15)


def test_birth_year_within_one_scores_less_but_still_anchors():
    m = score_same_person(
        _rec("Quentin Vance", dob_year=1980), _rec("Quentin Vance", dob_year=1981), common_name=False
    )
    assert m.score == pytest.approx(0.2 + 0.15)
    assert "dob_year" in " ".join(m.anchors)


def test_name_variant_scores_less_than_exact():
    m = score_same_person(_rec("Bill Vance"), _rec("William Vance"), common_name=False)
    assert m.score == pytest.approx(0.12)
    m2 = score_same_person(_rec("J. Vance"), _rec("James Vance"), common_name=False)
    assert m2.score == pytest.approx(0.12)


def test_different_first_names_are_not_a_name_match():
    m = score_same_person(_rec("John Vance"), _rec("Jane Vance"), common_name=False)
    assert m.score == pytest.approx(0.0)


def test_same_band_needs_score_and_two_anchors():
    a = _rec("Quentin Vance", phones=["415-555-0100"], emails=["q@example.org"])
    b = _rec("Quentin Vance", phones=["(415) 555 0100"], emails=["Q@Example.org"])
    m = score_same_person(a, b, common_name=False)
    assert m.verdict is MatchVerdict.SAME
    assert set(m.anchors) == {"phone", "email"}
    assert m.score >= 0.8


def test_probable_band():
    a = _rec("Quentin Vance", phones=["415-555-0100"], addresses=["12 Oak Street"])
    b = _rec("Quentin Vance", phones=["415-555-0100"], addresses=["12 oak st."])
    m = score_same_person(a, b, common_name=False)
    assert m.verdict is MatchVerdict.PROBABLE
    assert m.score == pytest.approx(0.75)


def test_possible_band_single_anchor():
    a = _rec("Quentin Vance", phones=["415-555-0100"])
    b = _rec("Quentin Vance", phones=["415-555-0100"])
    m = score_same_person(a, b, common_name=False)
    assert m.verdict is MatchVerdict.POSSIBLE


def test_two_anchor_rule_holds_for_every_attribute_combination():
    attrs = {
        "dob_year": {"dob_year": 1980},
        "addresses": {"addresses": ["12 Oak St"]},
        "phones": {"phones": ["415-555-0100"]},
        "emails": {"emails": ["q@example.org"]},
        "relatives": {"relatives": ["Mary Vance"]},
    }
    for r in range(0, len(attrs) + 1):
        for combo in itertools.combinations(attrs, r):
            kw: dict = {}
            for key in combo:
                kw.update(attrs[key])
            m = score_same_person(_rec("Quentin Vance", **kw), _rec("Quentin Vance", **kw), common_name=False)
            if m.verdict is MatchVerdict.SAME:
                assert len(m.anchors) >= 2 and m.score >= 0.8, combo
            if m.verdict is MatchVerdict.PROBABLE:
                assert len(m.anchors) >= 1 and m.score >= 0.55, combo
            if not m.anchors:
                assert m.verdict is MatchVerdict.DIFFERENT, combo


def test_common_name_penalty_applies_only_without_anchors():
    a, b = _rec("John Smith"), _rec("John Smith")
    plain = score_same_person(a, b, common_name=False).score
    penalised = score_same_person(a, b, common_name=True).score
    assert plain == pytest.approx(0.2)
    assert penalised == pytest.approx(0.05)
    # with an anchor the penalty is not applied
    a2 = _rec("John Smith", addresses=["12 Oak St"])
    b2 = _rec("John Smith", addresses=["12 Oak St"])
    assert score_same_person(a2, b2, common_name=True).score == pytest.approx(
        score_same_person(a2, b2, common_name=False).score
    )


def test_common_name_is_autodetected_when_none():
    smith = score_same_person(_rec("John Smith"), _rec("John Smith"))
    rare = score_same_person(_rec("Quentin Vance"), _rec("Quentin Vance"))
    assert smith.score == pytest.approx(0.05)
    assert rare.score == pytest.approx(0.2)
    # explicit override beats auto-detection
    assert score_same_person(_rec("John Smith"), _rec("John Smith"), common_name=False).score == pytest.approx(0.2)


def test_score_never_negative():
    m = score_same_person(_rec("John Smith"), _rec("Zed Other"), common_name=True)
    assert m.score >= 0.0


# ----------------------------------------------------------------------------------------------
# Disqualifiers
# ----------------------------------------------------------------------------------------------

_STRONG = {"phones": ["415-555-0100"], "emails": ["q@example.org"], "addresses": ["12 Oak St"]}


def test_birth_years_more_than_five_apart_force_different():
    m = score_same_person(
        _rec("Quentin Vance", dob_year=1980, **_STRONG),
        _rec("Quentin Vance", dob_year=1990, **_STRONG),
        common_name=False,
    )
    assert m.verdict is MatchVerdict.DIFFERENT
    assert any("birth" in d for d in m.disqualifiers)


def test_birth_years_exactly_five_apart_is_not_disqualified():
    m = score_same_person(
        _rec("Quentin Vance", dob_year=1980, **_STRONG),
        _rec("Quentin Vance", dob_year=1985, **_STRONG),
        common_name=False,
    )
    assert m.disqualifiers == []
    assert m.verdict is MatchVerdict.SAME


def test_ages_more_than_five_apart_force_different():
    m = score_same_person(
        _rec("Quentin Vance", age=30, **_STRONG), _rec("Quentin Vance", age=41, **_STRONG), common_name=False
    )
    assert m.verdict is MatchVerdict.DIFFERENT
    assert any("age" in d for d in m.disqualifiers)


def test_ages_within_five_are_fine():
    m = score_same_person(
        _rec("Quentin Vance", age=30, **_STRONG), _rec("Quentin Vance", age=34, **_STRONG), common_name=False
    )
    assert m.disqualifiers == []


def test_deceased_versus_living_forces_different():
    m = score_same_person(
        _rec("Quentin Vance", deceased=True, **_STRONG),
        _rec("Quentin Vance", deceased=False, **_STRONG),
        common_name=False,
    )
    assert m.verdict is MatchVerdict.DIFFERENT
    assert any("deceased" in d for d in m.disqualifiers)


def test_both_deceased_is_not_a_disqualifier():
    m = score_same_person(
        _rec("Quentin Vance", deceased=True, **_STRONG),
        _rec("Quentin Vance", deceased=True, **_STRONG),
        common_name=False,
    )
    assert m.disqualifiers == []
    assert m.verdict is MatchVerdict.SAME


def test_conflicting_middle_initials_force_different():
    m = score_same_person(
        _rec("Quentin A Vance", **_STRONG), _rec("Quentin B Vance", **_STRONG), common_name=False
    )
    assert m.verdict is MatchVerdict.DIFFERENT
    assert any("middle" in d for d in m.disqualifiers)


def test_missing_or_compatible_middle_is_not_a_conflict():
    one_missing = score_same_person(_rec("Quentin Vance", **_STRONG), _rec("Quentin B Vance", **_STRONG))
    assert one_missing.disqualifiers == []
    initial_vs_full = score_same_person(
        _rec("Quentin A. Vance", **_STRONG), _rec("Quentin Aldous Vance", **_STRONG), common_name=False
    )
    assert initial_vs_full.disqualifiers == []
    assert initial_vs_full.verdict is MatchVerdict.SAME


def test_junior_versus_senior_forces_different():
    m = score_same_person(_rec("Quentin Vance Jr", **_STRONG), _rec("Quentin Vance Sr", **_STRONG), common_name=False)
    assert m.verdict is MatchVerdict.DIFFERENT
    assert any("jr" in d.lower() or "generation" in d.lower() for d in m.disqualifiers)


def test_non_matching_names_cap_the_verdict_below_probable():
    # Spouses/relatives share phone, address and email but are not the same person.
    m = score_same_person(_rec("Jane Vance", **_STRONG), _rec("John Vance", **_STRONG), common_name=False)
    assert m.verdict in (MatchVerdict.POSSIBLE, MatchVerdict.DIFFERENT)
    m2 = score_same_person(_rec("Mary Jones", **_STRONG), _rec("Mary Smith", **_STRONG), common_name=False)
    assert m2.verdict in (MatchVerdict.POSSIBLE, MatchVerdict.DIFFERENT)


def test_phone_and_address_normalisation():
    a = _rec("Quentin Vance", phones=["+1 (415) 555-0100"], addresses=["12 Oak Street, Apt 4"])
    b = _rec("Quentin Vance", phones=["415.555.0100"], addresses=["12 OAK ST APT 4"])
    m = score_same_person(a, b, common_name=False)
    assert set(m.anchors) == {"phone", "address"}


def test_different_apartments_do_not_overlap():
    a = _rec("Quentin Vance", addresses=["12 Oak St Apt 4"])
    b = _rec("Quentin Vance", addresses=["12 Oak St Apt 5"])
    assert score_same_person(a, b, common_name=False).anchors == []


def test_short_phone_fragments_are_ignored():
    a = _rec("Quentin Vance", phones=["555"])
    b = _rec("Quentin Vance", phones=["555"])
    assert score_same_person(a, b, common_name=False).anchors == []


def test_reasons_are_populated():
    m = score_same_person(_rec("Quentin Vance", phones=["415-555-0100"]), _rec("Quentin Vance", phones=["4155550100"]))
    assert m.reasons and any("phone" in r for r in m.reasons)


# ----------------------------------------------------------------------------------------------
# cluster_candidates
# ----------------------------------------------------------------------------------------------


def test_cluster_never_merges_on_name_alone():
    records = [_rec("John Smith"), _rec("John Smith"), _rec("John Smith")]
    assert cluster_candidates(records) == [[0], [1], [2]]


def test_cluster_merges_transitively():
    a = _rec("Quentin Vance", phones=["415-555-0100"], emails=["q@example.org"])
    b = _rec(
        "Quentin Vance", phones=["415-555-0100"], emails=["q@example.org"], addresses=["12 Oak St"], dob_year=1980
    )
    c = _rec("Quentin Vance", addresses=["12 Oak St"], dob_year=1980)
    d = _rec("Someone Else", phones=["999-555-0111"])
    # a~b (phone+email), b~c (address+dob), a vs c is name only
    assert score_same_person(a, c, common_name=False).verdict is MatchVerdict.DIFFERENT
    clusters = cluster_candidates([a, b, c, d])
    assert clusters == [[0, 1, 2], [3]]


def test_cluster_input_order_and_indices_are_stable():
    a = _rec("Quentin Vance", phones=["415-555-0100"], emails=["q@example.org"])
    other = _rec("Zed Nobody")
    b = _rec("Quentin Vance", phones=["415-555-0100"], emails=["q@example.org"])
    assert cluster_candidates([a, other, b]) == [[0, 2], [1]]


def test_cluster_empty_and_single():
    assert cluster_candidates([]) == []
    assert cluster_candidates([_rec("Quentin Vance")]) == [[0]]


def test_cluster_disqualified_pair_is_not_merged():
    a = _rec("Quentin Vance", dob_year=1950, **_STRONG)
    b = _rec("Quentin Vance", dob_year=1990, **_STRONG)
    assert cluster_candidates([a, b]) == [[0], [1]]
