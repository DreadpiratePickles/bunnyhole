"""Tests for the PI stream analysis module: coverage, freshness, contradictions, gaps and falsifiers.

All pure and deterministic: no network, no model calls.
"""

from __future__ import annotations

import pytest

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    Finding,
    FindingLabel,
    OwnershipBlock,
    SourceLogEntry,
)
from bunnyhole.engine.pi_analysis import (
    SOURCE_CLASSES,
    build_coverage,
    detect_contradictions,
    expected_source_classes,
    falsifiers_for,
    find_gaps,
    freshness_class,
)

NOW = "2026-11-09T12:00:00Z"


# ----------------------------------------------------------------------------------------------
# expected_source_classes
# ----------------------------------------------------------------------------------------------


def test_source_classes_are_the_twelve_spec_classes():
    assert SOURCE_CLASSES == (
        "court_dockets",
        "corporate_registry",
        "beneficial_ownership",
        "sanctions_pep",
        "regulatory_enforcement",
        "property_assets",
        "news_adverse_media",
        "social_osint",
        "domain_infrastructure",
        "crypto_onchain",
        "missing_persons",
        "vital_records",
    )


def test_asset_search_expects_asset_classes():
    got = set(expected_source_classes(CaseType.ASSET_SEARCH, True))
    assert {
        "corporate_registry",
        "beneficial_ownership",
        "sanctions_pep",
        "court_dockets",
        "property_assets",
        "crypto_onchain",
        "news_adverse_media",
    } <= got


def test_locate_expects_person_classes():
    assert set(expected_source_classes(CaseType.LOCATE, True)) == {
        "court_dockets",
        "corporate_registry",
        "social_osint",
        "vital_records",
        "news_adverse_media",
    }


def test_missing_person_expects_missing_person_classes():
    assert set(expected_source_classes(CaseType.MISSING_PERSON, True)) == {
        "missing_persons",
        "vital_records",
        "news_adverse_media",
        "social_osint",
    }


def test_due_diligence_expects_counterparty_classes():
    assert set(expected_source_classes(CaseType.DUE_DILIGENCE, False)) == {
        "corporate_registry",
        "beneficial_ownership",
        "sanctions_pep",
        "court_dockets",
        "regulatory_enforcement",
        "news_adverse_media",
    }


def test_fraud_screen_adds_enforcement_and_crypto():
    got = set(expected_source_classes(CaseType.FRAUD_SCREEN, False))
    assert {"regulatory_enforcement", "crypto_onchain"} <= got


def test_background_expects_identity_history_classes():
    assert set(expected_source_classes(CaseType.BACKGROUND, True)) == {
        "court_dockets",
        "sanctions_pep",
        "news_adverse_media",
        "corporate_registry",
    }


@pytest.mark.parametrize("case_type", list(CaseType))
def test_entity_subjects_drop_person_only_classes(case_type: CaseType):
    got = expected_source_classes(case_type, False)
    assert "vital_records" not in got
    assert "missing_persons" not in got


def test_entity_locate_keeps_remaining_classes():
    assert set(expected_source_classes(CaseType.LOCATE, False)) == {
        "court_dockets",
        "corporate_registry",
        "social_osint",
        "news_adverse_media",
    }


@pytest.mark.parametrize("case_type", [c for c in CaseType if c is not CaseType.ASSET_SEARCH])
def test_person_subjects_drop_domain_infrastructure_unless_asset_search(case_type: CaseType):
    assert "domain_infrastructure" not in expected_source_classes(case_type, True)


def test_asset_search_keeps_domain_infrastructure_for_persons():
    assert "domain_infrastructure" in expected_source_classes(CaseType.ASSET_SEARCH, True)


@pytest.mark.parametrize("case_type", list(CaseType))
@pytest.mark.parametrize("is_person", [True, False])
def test_expected_classes_are_known_unique_and_nonempty(case_type: CaseType, is_person: bool):
    got = expected_source_classes(case_type, is_person)
    assert got
    assert len(got) == len(set(got))
    assert set(got) <= set(SOURCE_CLASSES)


# ----------------------------------------------------------------------------------------------
# build_coverage
# ----------------------------------------------------------------------------------------------


def _entry(source: str, status: str, target: str = "acme") -> SourceLogEntry:
    return SourceLogEntry(source=source, target=target, status=status, at_utc=NOW)  # type: ignore[arg-type]


CLASS_MAP = {
    "courtlistener": "court_dockets",
    "pacer": "court_dockets",
    "gleif": "corporate_registry",
    "opensanctions": "sanctions_pep",
    "gdelt": "news_adverse_media",
}


def _rows(rows):
    return {r.source_class: r for r in rows}


def test_coverage_has_one_row_per_expected_class_in_order():
    rows = build_coverage(CaseType.LOCATE, True, [], CLASS_MAP)
    assert [r.source_class for r in rows] == expected_source_classes(CaseType.LOCATE, True)
    assert all(not r.searched and r.outcome == "not_searched" and r.sources == [] for r in rows)


def test_coverage_hit_marks_searched_with_hit_outcome():
    rows = _rows(build_coverage(CaseType.LOCATE, True, [_entry("courtlistener", "hit")], CLASS_MAP))
    row = rows["court_dockets"]
    assert row.searched is True
    assert row.outcome == "hit"
    assert row.sources == ["courtlistener"]


def test_coverage_negative_marks_searched_with_negative_outcome():
    rows = _rows(build_coverage(CaseType.LOCATE, True, [_entry("gleif", "negative")], CLASS_MAP))
    assert rows["corporate_registry"].searched is True
    assert rows["corporate_registry"].outcome == "negative"


@pytest.mark.parametrize("status", ["skipped", "error"])
def test_coverage_skipped_and_error_never_count_as_searched(status: str):
    rows = _rows(build_coverage(CaseType.LOCATE, True, [_entry("courtlistener", status)], CLASS_MAP))
    row = rows["court_dockets"]
    assert row.searched is False
    assert row.outcome == "not_searched"
    assert row.sources == []


def test_coverage_hit_beats_negative_regardless_of_order():
    for log in (
        [_entry("courtlistener", "negative"), _entry("pacer", "hit")],
        [_entry("pacer", "hit"), _entry("courtlistener", "negative")],
    ):
        row = _rows(build_coverage(CaseType.LOCATE, True, log, CLASS_MAP))["court_dockets"]
        assert row.outcome == "hit"
        assert sorted(row.sources) == ["courtlistener", "pacer"]


def test_coverage_skip_does_not_downgrade_a_negative():
    log = [_entry("courtlistener", "skipped"), _entry("pacer", "negative")]
    row = _rows(build_coverage(CaseType.LOCATE, True, log, CLASS_MAP))["court_dockets"]
    assert row.searched is True
    assert row.outcome == "negative"
    assert row.sources == ["pacer"]  # the skipped source did not search anything


def test_coverage_sources_deduped_preserving_first_seen_order():
    log = [
        _entry("pacer", "negative", "a"),
        _entry("courtlistener", "hit", "a"),
        _entry("pacer", "negative", "b"),
        _entry("courtlistener", "negative", "b"),
    ]
    row = _rows(build_coverage(CaseType.LOCATE, True, log, CLASS_MAP))["court_dockets"]
    assert row.sources == ["pacer", "courtlistener"]


def test_coverage_ignores_unmapped_sources_and_unexpected_classes():
    # opensanctions maps to sanctions_pep, which a locate case does not expect: no row for it
    log = [_entry("mystery_tool", "hit"), _entry("opensanctions", "hit")]
    rows = build_coverage(CaseType.LOCATE, True, log, CLASS_MAP)
    assert "sanctions_pep" not in {r.source_class for r in rows}
    assert all(not r.searched for r in rows)


# ----------------------------------------------------------------------------------------------
# freshness_class
# ----------------------------------------------------------------------------------------------


def test_freshness_address_exactly_12_months_is_fresh():
    assert freshness_class("2025-11-09", now_iso=NOW) == "fresh"
    assert freshness_class("2025-11-09T12:00:00Z", now_iso=NOW) == "fresh"


def test_freshness_address_just_over_12_months_is_aging():
    assert freshness_class("2025-11-08", now_iso=NOW) == "aging"
    assert freshness_class("2025-11-08T23:59:59Z", now_iso=NOW) == "aging"


def test_freshness_address_exactly_36_months_is_aging():
    assert freshness_class("2023-11-09", now_iso=NOW) == "aging"


def test_freshness_address_just_over_36_months_is_stale():
    assert freshness_class("2023-11-08", now_iso=NOW) == "stale"
    assert freshness_class("1999-01-01", now_iso=NOW) == "stale"


def test_freshness_registry_uses_24_and_60_month_cutoffs():
    assert freshness_class("2024-11-09", "registry", now_iso=NOW) == "fresh"
    assert freshness_class("2024-11-08", "registry", now_iso=NOW) == "aging"
    assert freshness_class("2021-11-09", "registry", now_iso=NOW) == "aging"
    assert freshness_class("2021-11-08", "registry", now_iso=NOW) == "stale"


def test_freshness_registry_differs_from_address_for_same_date():
    assert freshness_class("2025-01-01", "address", now_iso=NOW) == "aging"
    assert freshness_class("2025-01-01", "registry", now_iso=NOW) == "fresh"


def test_freshness_future_date_is_unknown():
    assert freshness_class("2027-01-01", now_iso=NOW) == "unknown"
    assert freshness_class("2026-11-10", now_iso=NOW) == "unknown"
    assert freshness_class("2026-11-09", now_iso=NOW) == "fresh"  # today is not the future


def test_freshness_month_end_clamping():
    # 2025-02-28 + 12 months clamps fine; 2024-02-29 + 12 months is 2025-02-28 (leap-day clamp)
    assert freshness_class("2024-02-29", now_iso="2025-02-28T00:00:00Z") == "fresh"
    assert freshness_class("2024-02-29", now_iso="2025-03-01T00:00:00Z") == "aging"


@pytest.mark.parametrize("bad", ["", "   ", "not a date", "2025-13-45", "yesterday", "2025/11/09x"])
def test_freshness_unknown_for_empty_or_unparseable(bad: str):
    assert freshness_class(bad, now_iso=NOW) == "unknown"


def test_freshness_unknown_for_non_string():
    assert freshness_class(None, now_iso=NOW) == "unknown"  # type: ignore[arg-type]


def test_freshness_unparseable_now_is_not_a_crash():
    assert freshness_class("2025-01-01", now_iso="garbage") == "unknown"


def test_freshness_unknown_kind_falls_back_to_address_cutoffs():
    assert freshness_class("2025-11-08", "something_else", now_iso=NOW) == "aging"


def test_freshness_defaults_to_real_now():
    assert freshness_class("2000-01-01") == "stale"
    assert freshness_class("2999-01-01") == "unknown"


# ----------------------------------------------------------------------------------------------
# detect_contradictions
# ----------------------------------------------------------------------------------------------


def _ev(ts, title, node="n1", **extra):
    return {"timestamp": ts, "title": title, "description": extra.pop("description", ""), "node_ids": [node], **extra}


def _kinds(found: list[Contradiction]) -> list[str]:
    return [c.kind for c in found]


def test_no_contradictions_on_clean_timeline():
    tl = [_ev("2020-01-01", "Incorporated"), _ev("2021-05-01", "Annual return filed")]
    assert detect_contradictions(tl) == []


def test_empty_timeline_has_no_contradictions():
    assert detect_contradictions([]) == []


def test_event_before_incorporation_is_flagged():
    tl = [_ev("2020-01-01", "Company incorporated"), _ev("2019-06-01", "Bank account opened")]
    found = detect_contradictions(tl)
    assert _kinds(found) == ["event_before_incorporation"]
    assert found[0].node_ids == ["n1"]
    assert "Bank account opened" in found[0].description


def test_event_on_incorporation_day_is_not_flagged_even_with_time_of_day():
    tl = [_ev("2020-01-01", "Incorporation"), _ev("2020-01-01T08:00:00Z", "Bank account opened")]
    assert detect_contradictions(tl) == []


def test_event_before_incorporation_only_applies_to_same_node():
    tl = [_ev("2020-01-01", "Incorporated", node="n1"), _ev("2019-01-01", "Something", node="n2")]
    assert detect_contradictions(tl) == []


def test_event_with_multiple_nodes_checked_against_each():
    tl = [
        _ev("2020-01-01", "Incorporated", node="n1"),
        _ev("2021-01-01", "Incorporated", node="n2"),
        {"timestamp": "2020-06-01", "title": "Joint venture signed", "description": "", "node_ids": ["n1", "n2"]},
    ]
    found = detect_contradictions(tl)
    assert _kinds(found) == ["event_before_incorporation"]
    assert found[0].node_ids == ["n2"]


def test_event_between_two_incorporation_dates_is_not_before_earliest():
    tl = [
        _ev("2020-01-01", "Incorporated"),
        _ev("2020-06-01", "Incorporation registered"),
        _ev("2020-03-01", "Bank account opened"),
    ]
    assert "event_before_incorporation" not in _kinds(detect_contradictions(tl))


def test_conflicting_incorporation_dates_over_30_days():
    tl = [_ev("2020-01-01", "Incorporated"), _ev("2020-02-01", "Date of incorporation (registry B)")]
    found = detect_contradictions(tl)
    assert _kinds(found) == ["conflicting_incorporation_dates"]
    assert found[0].node_ids == ["n1"]
    assert "2020-01-01" in found[0].description and "2020-02-01" in found[0].description


def test_incorporation_dates_exactly_30_days_apart_are_not_conflicting():
    tl = [_ev("2020-01-01", "Incorporated"), _ev("2020-01-31", "Incorporation")]
    assert detect_contradictions(tl) == []


def test_incorporation_dates_31_days_apart_are_conflicting():
    tl = [_ev("2020-01-01", "Incorporated"), _ev("2020-02-01", "Incorporation")]
    assert _kinds(detect_contradictions(tl)) == ["conflicting_incorporation_dates"]


def test_three_incorporation_dates_yield_one_conflict_per_node():
    tl = [
        _ev("2020-01-01", "Incorporated"),
        _ev("2020-06-01", "Incorporated"),
        _ev("2021-01-01", "Incorporated"),
    ]
    assert _kinds(detect_contradictions(tl)).count("conflicting_incorporation_dates") == 1


@pytest.mark.parametrize("terminal", ["Company dissolved", "Struck off the register", "Subject deceased"])
def test_event_after_terminal_event_is_flagged(terminal: str):
    tl = [_ev("2022-03-01", terminal), _ev("2023-01-01", "New filing submitted")]
    found = detect_contradictions(tl)
    assert _kinds(found) == ["event_after_end"]
    assert found[0].node_ids == ["n1"]
    assert "New filing submitted" in found[0].description


def test_event_on_terminal_day_is_not_flagged():
    tl = [_ev("2022-03-01", "Dissolved"), _ev("2022-03-01T09:30:00Z", "Final filing")]
    assert detect_contradictions(tl) == []


def test_terminal_event_itself_and_duplicates_are_not_flagged():
    tl = [_ev("2022-03-01", "Dissolved"), _ev("2022-04-01", "Struck off (gazette notice)")]
    assert detect_contradictions(tl) == []


def test_event_before_terminal_is_fine():
    tl = [_ev("2021-03-01", "Filing"), _ev("2022-03-01", "Dissolved")]
    assert detect_contradictions(tl) == []


def test_matching_is_case_insensitive():
    tl = [_ev("2022-03-01", "DISSOLVED"), _ev("2023-01-01", "late filing")]
    assert _kinds(detect_contradictions(tl)) == ["event_after_end"]


def test_mixed_date_only_and_full_iso_timestamps():
    tl = [_ev("2020-01-01T00:00:00Z", "Incorporated"), _ev("2019-12-31", "Bank account opened")]
    assert _kinds(detect_contradictions(tl)) == ["event_before_incorporation"]


def test_garbled_items_are_skipped_never_raise():
    tl = [
        _ev("2020-01-01", "Incorporated"),
        _ev("garbage", "Bank account opened"),
        _ev("", "Another"),
        _ev(None, "Another"),
        {"title": "no timestamp", "node_ids": ["n1"]},
        {"timestamp": "2019-01-01", "title": "Event", "node_ids": None},
        {"timestamp": "2019-01-01", "title": "Event", "node_ids": "n1"},
        "not a dict",
        None,
        42,
        {},
    ]
    assert detect_contradictions(tl) == []  # type: ignore[arg-type]


def test_untitled_dated_event_still_checked_with_readable_description():
    tl = [_ev("2020-01-01", "Incorporated"), {"timestamp": "2019-01-01", "title": None, "node_ids": ["n1"]}]
    found = detect_contradictions(tl)
    assert _kinds(found) == ["event_before_incorporation"]
    assert "untitled event" in found[0].description


def test_garbled_items_do_not_hide_real_contradictions():
    tl = [
        "junk",
        _ev("2020-01-01", "Incorporated"),
        _ev("not-a-date", "Incorporated"),
        _ev("2019-01-01", "Bank account opened"),
    ]
    assert _kinds(detect_contradictions(tl)) == ["event_before_incorporation"]  # type: ignore[arg-type]


def test_contradictions_are_deterministic_and_chronological_within_rule():
    tl = [
        _ev("2020-01-01", "Incorporated"),
        _ev("2019-06-01", "Event beta"),
        _ev("2019-02-01", "Event alpha"),
    ]
    first = detect_contradictions(tl)
    assert first == detect_contradictions(list(reversed(tl)))
    assert len(first) == 2
    assert "Event alpha" in first[0].description  # earliest offending event first
    assert "Event beta" in first[1].description


# ----------------------------------------------------------------------------------------------
# find_gaps
# ----------------------------------------------------------------------------------------------


def test_gaps_empty_timeline_reports_no_dated_evidence():
    gaps = find_gaps([])
    assert len(gaps) == 1
    assert "no dated evidence" in gaps[0].lower()


def test_gaps_all_unparseable_reports_no_dated_evidence():
    gaps = find_gaps([_ev("garbage", "x"), {"title": "y"}, "z"])  # type: ignore[list-item]
    assert len(gaps) == 1
    assert "no dated evidence" in gaps[0].lower()


def test_gap_exactly_365_days_is_not_a_gap():
    assert find_gaps([_ev("2020-01-01", "a"), _ev("2020-12-31", "b")]) == []  # 365 days (2020 is a leap year)


def test_gap_366_days_is_a_gap():
    gaps = find_gaps([_ev("2020-01-01", "a"), _ev("2021-01-01", "b")])  # 366 days
    assert len(gaps) == 1
    assert "n1" in gaps[0]
    assert "2020-01-01" in gaps[0] and "2021-01-01" in gaps[0]
    assert "366" in gaps[0]


def test_gap_custom_max_gap_days():
    tl = [_ev("2020-01-01", "a"), _ev("2020-02-01", "b")]  # 31 days
    assert find_gaps(tl, max_gap_days=31) == []
    assert len(find_gaps(tl, max_gap_days=30)) == 1


def test_gaps_are_per_node_not_across_nodes():
    tl = [_ev("2020-01-01", "a", node="n1"), _ev("2022-01-01", "b", node="n2")]
    assert find_gaps(tl) == []


def test_gaps_only_between_consecutive_events():
    tl = [_ev("2020-01-01", "a"), _ev("2020-06-01", "b"), _ev("2022-06-01", "c")]
    gaps = find_gaps(tl)
    assert len(gaps) == 1
    assert "2020-06-01" in gaps[0] and "2022-06-01" in gaps[0]


def test_gaps_input_order_does_not_matter():
    tl = [_ev("2022-06-01", "c"), _ev("2020-01-01", "a")]
    assert len(find_gaps(tl)) == 1


def test_gaps_skip_garbled_items_and_handle_mixed_formats():
    tl = [
        _ev("2020-01-01T10:00:00Z", "a"),
        _ev("garbage", "x"),
        {"timestamp": "2022-01-01", "title": "b", "node_ids": None},
        _ev("2022-03-01", "c"),
    ]
    gaps = find_gaps(tl)  # type: ignore[arg-type]
    assert len(gaps) == 1


def test_gaps_ordered_by_node_for_determinism():
    tl = [
        _ev("2020-01-01", "a", node="n2"),
        _ev("2023-01-01", "b", node="n2"),
        _ev("2020-01-01", "a", node="n1"),
        _ev("2023-01-01", "b", node="n1"),
    ]
    gaps = find_gaps(tl)
    assert len(gaps) == 2
    assert "n1" in gaps[0] and "n2" in gaps[1]


# ----------------------------------------------------------------------------------------------
# falsifiers_for
# ----------------------------------------------------------------------------------------------


def _finding(node: str, label: FindingLabel, count: int) -> Finding:
    return Finding(node_id=node, label=f"label {node}", finding_label=label, source_count=count)


@pytest.mark.parametrize("case_type", list(CaseType))
def test_each_case_type_has_at_least_two_base_falsifiers(case_type: CaseType):
    out = falsifiers_for(case_type, [], [], OwnershipBlock())
    assert len(out) >= 2
    assert all(isinstance(t, str) and t.strip() for t in out)
    assert len(out) == len(set(out))


def test_base_falsifiers_differ_by_case_type():
    sets = {c: tuple(falsifiers_for(c, [], [], OwnershipBlock())) for c in CaseType}
    assert len(set(sets.values())) == len(CaseType)


def test_one_falsifier_per_unresolved_ownership_node():
    base = falsifiers_for(CaseType.ASSET_SEARCH, [], [], OwnershipBlock())
    own = OwnershipBlock(unresolved=["shell_a", "shell_b"])
    out = falsifiers_for(CaseType.ASSET_SEARCH, [], [], own)
    assert len(out) == len(base) + 2
    assert any("shell_a" in t for t in out)
    assert any("shell_b" in t for t in out)


def test_one_falsifier_per_lead_only_finding_and_none_for_stronger_labels():
    base = falsifiers_for(CaseType.LOCATE, [], [], OwnershipBlock())
    findings = [
        _finding("p1", FindingLabel.LEAD, 1),
        _finding("p2", FindingLabel.PROBABLE, 2),
        _finding("p3", FindingLabel.CONFIRMED, 3),
        _finding("p4", FindingLabel.LEAD, 1),
    ]
    out = falsifiers_for(CaseType.LOCATE, findings, [], OwnershipBlock())
    assert len(out) == len(base) + 2
    assert any("label p1" in t for t in out)
    assert any("label p4" in t for t in out)
    assert not any("label p2" in t or "label p3" in t for t in out)


def test_one_falsifier_per_contradiction():
    base = falsifiers_for(CaseType.DUE_DILIGENCE, [], [], OwnershipBlock())
    contradictions = [
        Contradiction(kind="event_after_end", description="Filing after dissolution", node_ids=["n1"]),
        Contradiction(kind="conflicting_incorporation_dates", description="Two dates", node_ids=["n2"]),
    ]
    out = falsifiers_for(CaseType.DUE_DILIGENCE, [], contradictions, OwnershipBlock())
    assert len(out) == len(base) + 2
    assert any("Filing after dissolution" in t for t in out)
    assert any("Two dates" in t for t in out)


def test_falsifiers_combined_and_deterministic():
    findings = [_finding("p1", FindingLabel.LEAD, 1)]
    contradictions = [Contradiction(kind="k", description="d", node_ids=[])]
    own = OwnershipBlock(unresolved=["u1"])
    a = falsifiers_for(CaseType.FRAUD_SCREEN, findings, contradictions, own)
    b = falsifiers_for(CaseType.FRAUD_SCREEN, findings, contradictions, own)
    base = falsifiers_for(CaseType.FRAUD_SCREEN, [], [], OwnershipBlock())
    assert a == b
    assert len(a) == len(base) + 3
    assert a[: len(base)] == base  # base falsifiers first


# ----------------------------------------------------------------------------------------------
# D7b: coverage lists sources that were tried but not reached
# ----------------------------------------------------------------------------------------------


def test_coverage_skipped_and_error_sources_are_listed_as_skipped_not_searched():
    log = [_entry("courtlistener", "skipped"), _entry("pacer", "error")]
    row = _rows(build_coverage(CaseType.LOCATE, True, log, CLASS_MAP))["court_dockets"]
    assert row.searched is False
    assert row.outcome == "not_searched"
    assert row.sources == []
    assert row.skipped == ["courtlistener", "pacer"]


def test_coverage_partial_class_keeps_both_ran_and_skipped():
    log = [_entry("courtlistener", "skipped"), _entry("pacer", "negative")]
    row = _rows(build_coverage(CaseType.LOCATE, True, log, CLASS_MAP))["court_dockets"]
    assert row.searched is True and row.outcome == "negative"
    assert row.sources == ["pacer"]
    assert row.skipped == ["courtlistener"]


def test_coverage_skipped_deduped_and_only_for_mapped_expected_classes():
    log = [
        _entry("courtlistener", "skipped", "a"),
        _entry("courtlistener", "error", "b"),
        _entry("mystery_tool", "skipped"),
        _entry("opensanctions", "skipped"),  # sanctions_pep is not expected for a locate case
    ]
    rows = build_coverage(CaseType.LOCATE, True, log, CLASS_MAP)
    assert _rows(rows)["court_dockets"].skipped == ["courtlistener"]
    assert all(r.skipped == [] for r in rows if r.source_class != "court_dockets")


def test_coverage_sanctions_partial_list_example():
    class_map = {"canada_sema": "sanctions_pep", "opensanctions": "sanctions_pep"}
    log = [_entry("canada_sema", "negative"), _entry("opensanctions", "skipped")]
    row = _rows(build_coverage(CaseType.DUE_DILIGENCE, False, log, class_map))["sanctions_pep"]
    assert row.searched is True
    assert row.sources == ["canada_sema"] and row.skipped == ["opensanctions"]


def test_coverage_rows_without_skips_have_empty_skipped():
    row = _rows(build_coverage(CaseType.LOCATE, True, [_entry("courtlistener", "hit")], CLASS_MAP))["court_dockets"]
    assert row.skipped == []


# ----------------------------------------------------------------------------------------------
# D6: no duplicate falsifiers; quieter gaps
# ----------------------------------------------------------------------------------------------


def test_falsifiers_never_contain_duplicates():
    findings = [_finding("p1", FindingLabel.LEAD, 1)] * 5
    own = OwnershipBlock(unresolved=["u1", "u1", "u2"])
    contradictions = [Contradiction(kind="k", description="d", node_ids=["n"])] * 3
    out = falsifiers_for(CaseType.LOCATE, findings, contradictions, own)
    assert len(out) == len(set(out))
    assert sum("label p1" in t for t in out) == 1
    assert sum("u1" in t for t in out) == 1 and sum("u2" in t for t in out) == 1
    assert sum("Resolution of the contradiction" in t for t in out) == 1


def test_falsifiers_dedupe_keeps_first_seen_order():
    own = OwnershipBlock(unresolved=["b", "a", "b"])
    out = falsifiers_for(CaseType.ASSET_SEARCH, [], [], own)
    tail = out[-2:]
    assert "behind b" in tail[0] and "behind a" in tail[1]


def test_gaps_ignore_nodes_with_fewer_than_two_dated_events():
    tl = [_ev("2015-01-01", "only one", node="lonely"), _ev("2020-01-01", "a"), _ev("2023-01-01", "b")]
    gaps = find_gaps(tl)
    assert len(gaps) == 1 and "n1" in gaps[0]
    assert not any("lonely" in g for g in gaps)


def test_gaps_ignore_seed_anchor_nodes():
    tl = [
        _ev("2010-01-01", "a", node="seed:jet"),
        _ev("2020-01-01", "b", node="seed:jet"),
        _ev("2010-01-01", "a", node="profile:locked_target_root"),
        _ev("2020-01-01", "b", node="profile:locked_target_root"),
        _ev("2010-01-01", "a", node="seedco:real"),
        _ev("2020-01-01", "b", node="seedco:real"),
    ]
    gaps = find_gaps(tl)
    assert len(gaps) == 1 and "seedco:real" in gaps[0]


def test_gaps_only_seed_or_single_event_nodes_is_not_a_gap_line_per_node():
    tl = [_ev("2020-01-01", "a", node="seed:x"), _ev("2022-01-01", "b", node="seed:x")]
    gaps = find_gaps(tl)
    assert all("seed:x" not in g for g in gaps)
