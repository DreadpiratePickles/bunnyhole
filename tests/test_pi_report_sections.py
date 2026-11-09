"""Tests for the PI report builder (``build_pi_report``): structure and the contract of every section.

Sections: structure, findings and labels, escaping of untrusted text, the bottom line, the other sections, client
theory, notices, the next step (an action, not the header), ranking/caps/collapse, custody and coverage honesty, and
the identity and playbook sections. The entity due-diligence quality passes (sanctions-first bottom line, sanctions
honesty, Markdown hygiene) are in ``test_pi_report_bottom_line.py``.

Pure and deterministic: no network, no model calls. Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md
section 3.8.
"""

# Replaces: test_pi_report.py (consolidated 2026-11-09).

from __future__ import annotations

import re
from typing import Any, Dict, List

from pi_helpers import report_block, report_engagement
from pi_helpers import report_sections as _sections
from pi_helpers import unescaped_pipes as _unescaped_pipes

from bunnyhole.engine.pi import (
    NOTICES,
    CaseType,
    Contradiction,
    CoverageRow,
    Custodian,
    CustodyEntry,
    EscalationTrigger,
    FindingLabel,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    PlaybookProgress,
    SourceLogEntry,
)
from bunnyhole.engine.pi import Finding as _Finding
from bunnyhole.engine.pi_report import build_pi_report

HEADINGS = [
    "Bottom line",
    "Engagement & scope",
    "Entity profile",
    "Client theory vs. evidence",
    "Findings",
    "Sanctions screening",
    "Identity resolution",
    "Ownership chain",
    "What is NOT a link",
    "Contradictions and gaps",
    "What would change this conclusion",
    "Coverage and negatives",
    "Playbook progress",
    "Custodians and next steps",
    "Chain of custody",
    "Limitations & legal notices",
]
# Sections that carry content even for an empty block (the engagement always exists; notices always print).
ALWAYS_POPULATED = {"Engagement & scope", "Sanctions screening", "Limitations & legal notices"}
HASH_A = "a" * 63 + "1"
HASH_B = "b" * 63 + "2"
ABSENCE_SENTENCE = "Absence from the sources searched is not proof of absence."


def Finding(**fields: Any) -> _Finding:  # noqa: N802 - keeps the original call sites readable
    """Findings in this file are built as relevance "subject" (the PI report only lists subject/related rows)."""
    fields.setdefault("relevance", "subject")
    return _Finding(**fields)


_ENGAGEMENT_FIELDS = {
    "engagement_id": "pi_0123456789",
    "case_type": CaseType.DUE_DILIGENCE,
    "purpose": "Vet a counterparty before signing a supply contract",
    "created_at_utc": "2026-11-09T12:00:00+00:00",
}


def _engagement(**overrides: Any) -> PIEngagement:
    return report_engagement(_ENGAGEMENT_FIELDS, **overrides)


def _block(**overrides: Any) -> PIBlock:
    return report_block(_engagement, **overrides)


def _result(block: PIBlock | None = None, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(extra)
    if block is not None:
        result["pi"] = block.model_dump(mode="json")
    return result


def _h2_headings(markdown: str) -> List[str]:
    return re.findall(r"^## (.+)$", markdown, flags=re.MULTILINE)


def _full_block() -> PIBlock:
    return _block(
        engagement=_engagement(
            objective="Counterparty risk picture",
            client="Acme Counsel LLP",
            matter_ref="MSA-2026-114",
            jurisdiction="us",
            subject_is_person=False,
        ),
        identifier_warnings=["No second anchor was given for the entity"],
        prior_cases=[{"case_id": "case_77", "seed": "Zenith Holdings", "at": "2026-08-01"}],
        source_log=[
            SourceLogEntry(
                source="opensanctions", target="Zenith Holdings", status="hit", at_utc="2026-11-09T12:01:00+00:00"
            ),
            SourceLogEntry(
                source="courtlistener",
                target="Zenith Holdings",
                status="negative",
                detail="no dockets",
                at_utc="2026-11-09T12:02:00+00:00",
            ),
            SourceLogEntry(
                source="companies_house",
                target="Zenith Holdings",
                status="skipped",
                detail="COMPANIES_HOUSE_API_KEY not set",
                at_utc="2026-11-09T12:03:00+00:00",
            ),
            SourceLogEntry(
                source="cfpb",
                target="Zenith Holdings",
                status="error",
                detail="HTTP 500",
                at_utc="2026-11-09T12:04:00+00:00",
            ),
        ],
        findings=[
            Finding(node_id="lei:1", label="Zenith Holdings Ltd", finding_label=FindingLabel.CONFIRMED,
                    source_count=3, freshness="fresh"),
            Finding(node_id="person:2", label="Jane Director", finding_label=FindingLabel.PROBABLE,
                    source_count=2, freshness="aging"),
            Finding(node_id="addr:3", label="12 Quay Street", finding_label=FindingLabel.LEAD,
                    source_count=1, freshness="stale"),
        ],
        ownership=OwnershipBlock(
            levels_walked=2,
            edges=[
                OwnershipEdge(child="lei:1", parent="lei:9", pct=60.0, source="gleif", as_of="2026-01-01"),
                OwnershipEdge(child="lei:9", parent="person:7", pct=None, source="psc", as_of="2025-06-30"),
            ],
            blocked_by_50_rule=["lei:1"],
            unresolved=["lei:9"],
        ),
        false_link_flags=[{"node_id": "addr:3", "reason": "registered-agent address", "severity": "high"}],
        contradictions=[
            Contradiction(kind="incorporation_date", description="Two incorporation dates 2 years apart",
                          node_ids=["lei:1"])
        ],
        evidence_gaps=["No dated evidence between 2022 and 2025 for lei:1"],
        coverage=[
            CoverageRow(source_class="corporate_registry", searched=True, sources=["gleif"], outcome="hit"),
            CoverageRow(source_class="court_dockets", searched=True, sources=["courtlistener"], outcome="negative"),
            CoverageRow(source_class="property_assets", searched=False, sources=[], outcome="not_searched"),
        ],
        falsifiers=["A registry extract showing a different owner on the same date"],
        custodians=[
            Custodian(
                finding="company records",
                custodian="Delaware Division of Corporations",
                instrument="subpoena duces tecum",
                jurisdiction="us",
                note="needs counsel",
            )
        ],
        handoff_sheet=["Request via counsel: subpoena duces tecum to Delaware Division of Corporations"],
        custody=[
            CustodyEntry(receipt_id="rcpt_1", tool="gleif", url="https://api.gleif.org/x", sha256=HASH_A,
                         collected_at_utc="2026-11-09T12:01:00+00:00"),
            CustodyEntry(receipt_id="rcpt_2", tool="opensanctions", url="https://opensanctions.org/y",
                         sha256=HASH_B, collected_at_utc="2026-11-09T12:02:00+00:00"),
        ],
    )


def _full_result() -> Dict[str, Any]:
    return _result(
        _full_block(),
        seed_query="Zenith Holdings",
        nodes=[
            {"id": "lei:1", "label": "Zenith Holdings Ltd"},
            {"id": "lei:9", "label": "Zenith Parent SA"},
            {"id": "person:7", "label": "Ultimate Owner"},
        ],
        edges=[{"source_id": "lei:1", "target_id": "lei:9", "relation": "OWNED_BY"}],
        deep_research={"hypothesis": "Zenith is controlled by a sanctioned parent"},
        ach_assessment={
            "primary_question": "Who controls Zenith?",
            "winning_hypothesis": "H1: coordinated control",
            "h1_score": 4.5,
            "h2_score": 1.0,
            "h3_score": 0.5,
            "narrative_verdict": "Control by the parent is the best supported explanation.",
        },
    )


# ------------------------------------------------------------------ structure


def test_full_report_has_all_headings_in_order():
    report = build_pi_report(_full_result())
    assert _h2_headings(report) == HEADINGS


def test_full_report_renders_realistic_content():
    report = build_pi_report(_full_result())
    sections = _sections(report)
    assert "pi_0123456789" in sections["Engagement & scope"]
    assert "MSA-2026-114" in sections["Engagement & scope"]
    assert "Acme Counsel LLP" in sections["Engagement & scope"]
    assert "case_77" in sections["Engagement & scope"]
    assert "Jane Director" in sections["Findings"]
    assert "Zenith Parent SA" in sections["Ownership chain"]
    assert "registered-agent address" in sections["What is NOT a link"]
    assert "Two incorporation dates" in sections["Contradictions and gaps"]
    assert "No dated evidence between 2022 and 2025" in sections["Contradictions and gaps"]
    assert "different owner on the same date" in sections["What would change this conclusion"]
    assert "Delaware Division of Corporations" in sections["Custodians and next steps"]


def test_empty_block_renders_every_heading_with_none():
    report = build_pi_report(_result(_block()))
    assert _h2_headings(report) == HEADINGS
    sections = _sections(report)
    for heading in HEADINGS:
        if heading in ALWAYS_POPULATED:
            continue
        if heading == "Bottom line":
            continue
        assert sections[heading].startswith("None."), heading
    assert sections["Bottom line"]
    assert sections["Limitations & legal notices"]


def test_missing_pi_key_returns_short_report_without_raising():
    report = build_pi_report({"nodes": [], "edges": []})
    assert "No PI block" in report
    assert _h2_headings(report) == []


def test_invalid_pi_block_returns_short_report_without_raising():
    for bad in ({"bogus": 1}, "not a dict", None, 5):
        report = build_pi_report({"pi": bad})
        assert "No PI block" in report


def test_missing_nodes_edges_ach_still_renders():
    report = build_pi_report({"pi": _full_block().model_dump(mode="json")})
    assert _h2_headings(report) == HEADINGS
    assert "None." in _sections(report)["Client theory vs. evidence"]


# ------------------------------------------------------------------ findings and labels


def test_findings_table_has_columns_and_orders_confirmed_probable_lead():
    block = _block(
        findings=[
            Finding(node_id="n3", label="LeadOne", finding_label=FindingLabel.LEAD, source_count=1),
            Finding(node_id="n2", label="ProbableOne", finding_label=FindingLabel.PROBABLE, source_count=2),
            Finding(node_id="n1", label="ConfirmedOne", finding_label=FindingLabel.CONFIRMED, source_count=3),
        ]
    )
    findings = _sections(build_pi_report(_result(block)))["Findings"]
    assert "| Finding | Label | Sources | Freshness |" in findings
    assert findings.index("ConfirmedOne") < findings.index("ProbableOne") < findings.index("LeadOne")


def test_lead_only_report_never_uses_the_word_confirmed():
    block = _block(
        findings=[Finding(node_id="n1", label="Solo Hit", finding_label=FindingLabel.LEAD, source_count=1)]
    )
    report = build_pi_report(_result(block))
    assert "confirmed" not in report.lower()
    assert "lead" in _sections(report)["Findings"]
    assert "lead" in _sections(report)["Bottom line"]


def test_label_is_never_stronger_than_source_count():
    block = _block(
        findings=[Finding(node_id="n1", label="Overclaimed", finding_label=FindingLabel.CONFIRMED, source_count=1)]
    )
    sections = _sections(build_pi_report(_result(block)))
    row = next(line for line in sections["Findings"].splitlines() if "Overclaimed" in line)
    assert "| lead |" in row
    assert "| confirmed |" not in row


def test_a_lead_is_never_sorted_above_a_confirmed_finding_even_when_listed_first():
    block = _block(
        findings=[
            Finding(node_id="n1", label="AAA Lead", finding_label=FindingLabel.LEAD, source_count=1),
            Finding(node_id="n2", label="ZZZ Confirmed", finding_label=FindingLabel.CONFIRMED, source_count=4),
        ]
    )
    findings = _sections(build_pi_report(_result(block)))["Findings"]
    assert findings.index("ZZZ Confirmed") < findings.index("AAA Lead")


# ------------------------------------------------------------------ escaping and untrusted text


def test_pipe_characters_are_escaped_in_table_cells():
    block = _block(
        findings=[Finding(node_id="n1", label="Evil | Name", finding_label=FindingLabel.LEAD, source_count=1)]
    )
    findings = _sections(build_pi_report(_result(block)))["Findings"]
    row = next(line for line in findings.splitlines() if "Evil" in line)
    assert "Evil \\| Name" in row
    assert _unescaped_pipes(row) == 6  # 5 columns (Relevance added) -> 6 delimiters


def test_pipe_in_other_tables_is_escaped():
    block = _block(
        false_link_flags=[{"node_id": "a|b", "reason": "x|y", "severity": "low|high"}],
        custody=[CustodyEntry(receipt_id="r|1", tool="t|1", url="https://e.com/?a=1|2", sha256=HASH_A,
                              collected_at_utc="2026-11-09T12:00:00+00:00")],
        custodians=[Custodian(finding="f|1", custodian="c|1", instrument="i|1", jurisdiction="us", note="n|1")],
        coverage=[CoverageRow(source_class="c|1", searched=True, sources=["s|1"], outcome="hit")],
    )
    sections = _sections(build_pi_report(_result(block)))
    expected_columns = {
        "What is NOT a link": 3,
        "Chain of custody": 5,
        "Custodians and next steps": 5,
        "Coverage and negatives": 5,
    }
    for heading, columns in expected_columns.items():
        data_rows = [
            line
            for line in sections[heading].splitlines()
            if line.startswith("|") and ("\\|1" in line or "a\\|b" in line)
        ]
        assert data_rows, heading
        for row in data_rows:
            assert _unescaped_pipes(row) == columns + 1, (heading, row)


def test_newlines_in_untrusted_text_cannot_inject_headings():
    block = _block(
        findings=[
            Finding(node_id="n1", label="Name\n## Fake Heading\nmore", finding_label=FindingLabel.LEAD,
                    source_count=1)
        ],
        evidence_gaps=["gap\n## Another Fake"],
        engagement=_engagement(purpose="Vet a counterparty\n## Injected Purpose heading"),
    )
    report = build_pi_report(_result(block))
    assert _h2_headings(report) == HEADINGS


# ------------------------------------------------------------------ bottom line


def test_bottom_line_counts_labels_and_names_the_strongest_finding():
    bottom = _sections(build_pi_report(_full_result()))["Bottom line"]
    assert "3" in bottom
    assert "1 confirmed" in bottom
    assert "1 probable" in bottom
    assert "1 lead" in bottom
    assert "Zenith Holdings Ltd" in bottom


def test_bottom_line_is_at_most_six_labelled_bullets():
    # Requirement change (2026-11-09, final-verifier P3): the Bottom line is a short labelled list, not a paragraph
    # of 3 to 6 sentences; "at most 6 bullets" replaces the sentence count.
    bottom = _sections(build_pi_report(_full_result()))["Bottom line"]
    bullets = bottom.splitlines()
    assert 3 <= len(bullets) <= 6, bullets
    assert all(re.match(r"^- \*\*[^*]+:\*\* ", line) for line in bullets), bullets
    empty_bullets = _sections(build_pi_report(_result(_block())))["Bottom line"].splitlines()
    assert 3 <= len(empty_bullets) <= 6


def test_bottom_line_mentions_unresolved_ownership_node():
    block = _block(
        findings=[Finding(node_id="n1", label="Shellco", finding_label=FindingLabel.PROBABLE, source_count=2)],
        ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:UNRESOLVED-1"]),
    )
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "lei:UNRESOLVED-1" in bottom
    assert "unresolved" in bottom.lower()


def test_bottom_line_mentions_not_searched_class():
    block = _block(
        coverage=[CoverageRow(source_class="property_assets", searched=False, outcome="not_searched")],
    )
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "property_assets" in bottom
    assert "not searched" in bottom.lower()


def test_bottom_line_mentions_contradiction():
    block = _block(contradictions=[Contradiction(kind="dissolved_then_active", description="Event after dissolution")])
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "contradiction" in bottom.lower()
    assert "dissolved_then_active" in bottom


def test_bottom_line_flags_50_percent_rule():
    block = _block(ownership=OwnershipBlock(levels_walked=1, blocked_by_50_rule=["lei:BLOCKED"]))
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "50%" in bottom
    assert "lei:BLOCKED" in bottom


def test_bottom_line_without_50_percent_flags_does_not_mention_the_rule():
    bottom = _sections(build_pi_report(_result(_block())))["Bottom line"]
    assert "50%" not in bottom


def test_bottom_line_recommends_first_handoff_line():
    # A person subject keeps the handoff-line fallback; for an entity subject the next step is the primary registry
    # (final-verifier P4), so the engagement here is switched to a person.
    person = _full_block().model_copy(update={"engagement": _full_block().engagement.model_copy(
        update={"subject_is_person": True})})
    bottom = _sections(build_pi_report(_result(person)))["Bottom line"]
    assert "Request via counsel: subpoena duces tecum to Delaware Division of Corporations" in bottom


def test_bottom_line_says_no_escalation_when_no_custodians_or_handoff():
    bottom = _sections(build_pi_report(_result(_block())))["Bottom line"]
    assert "no escalation indicated" in bottom.lower()


def test_bottom_line_falls_back_to_custodian_when_no_handoff_lines():
    block = _block(
        custodians=[Custodian(finding="phone carrier", custodian="Carrier X", instrument="production order",
                              jurisdiction="ca-on")]
    )
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "Carrier X" in bottom
    assert "production order" in bottom
    assert "no escalation indicated" not in bottom.lower()


# ------------------------------------------------------------------ other sections


def test_ownership_section_shows_edges_levels_flags_and_unresolved():
    ownership = _sections(build_pi_report(_full_result()))["Ownership chain"]
    assert "Levels walked: 2" in ownership
    assert "| Child | Parent | Share | Source | As of |" in ownership
    assert "60" in ownership
    assert "unknown" in ownership  # pct None
    assert "50%" in ownership
    assert "Zenith Holdings Ltd" in ownership  # node id resolved to its label
    assert "lei:9" in ownership


def test_coverage_matrix_marks_not_searched_and_states_absence_caveat():
    coverage = _sections(build_pi_report(_full_result()))["Coverage and negatives"]
    row = next(line for line in coverage.splitlines() if "property_assets" in line)
    assert "NOT SEARCHED" in row
    assert ABSENCE_SENTENCE in coverage
    searched_row = next(line for line in coverage.splitlines() if "corporate_registry" in line)
    assert "NOT SEARCHED" not in searched_row


def test_absence_sentence_present_even_for_an_empty_block():
    assert ABSENCE_SENTENCE in _sections(build_pi_report(_result(_block())))["Coverage and negatives"]


def test_coverage_section_lists_negatives_skips_and_errors():
    coverage = _sections(build_pi_report(_full_result()))["Coverage and negatives"]
    assert "courtlistener" in coverage and "no dockets" in coverage
    assert "COMPANIES_HOUSE_API_KEY not set" in coverage
    assert "HTTP 500" in coverage


def test_custodians_section_has_table_and_handoff_lines():
    section = _sections(build_pi_report(_full_result()))["Custodians and next steps"]
    assert "Delaware Division of Corporations" in section
    assert "subpoena duces tecum" in section
    assert "- Request via counsel: subpoena duces tecum to Delaware Division of Corporations" in section


def test_handoff_lines_alone_still_render_under_custodians():
    block = _block(handoff_sheet=["Run through licensed database: jane@example.com"])
    section = _sections(build_pi_report(_result(block)))["Custodians and next steps"]
    assert "Run through licensed database: jane@example.com" in section
    assert not section.startswith("None.")


def test_custody_rows_show_full_64_char_hashes():
    custody = _sections(build_pi_report(_full_result()))["Chain of custody"]
    assert "| Receipt ID | Tool | URL | Receipt digest (SHA-256) | Collected (UTC) |" in custody
    assert HASH_A in custody and HASH_B in custody
    assert len(HASH_A) == 64
    row = next(line for line in custody.splitlines() if "rcpt_1" in line)
    assert "gleif" in row and "https://api.gleif.org/x" in row and "2026-11-09T12:01:00" in row


def test_falsifiers_are_listed():
    section = _sections(build_pi_report(_full_result()))["What would change this conclusion"]
    assert "A registry extract showing a different owner on the same date" in section


# ------------------------------------------------------------------ client theory


def test_client_theory_shows_hypothesis_and_ach_from_ach_assessment_key():
    theory = _sections(build_pi_report(_full_result()))["Client theory vs. evidence"]
    assert "Zenith is controlled by a sanctioned parent" in theory
    assert "H1: coordinated control" in theory
    assert "4.5" in theory
    assert "Control by the parent is the best supported explanation." in theory


def test_client_theory_reads_ach_from_the_short_key_and_top_level_hypothesis():
    result = _result(
        _block(),
        hypothesis="Owner is Jane",
        ach={"primary_question": "Who owns it?", "winning_hypothesis": "H2", "h1_score": 1, "h2_score": 3,
             "h3_score": 0},
    )
    theory = _sections(build_pi_report(result))["Client theory vs. evidence"]
    assert "Owner is Jane" in theory
    assert "Who owns it?" in theory
    assert "H2" in theory


def test_client_theory_without_hypothesis_or_ach_says_none():
    theory = _sections(build_pi_report(_result(_block())))["Client theory vs. evidence"]
    assert theory.startswith("None.")
    assert "no theory" in theory.lower()


# ------------------------------------------------------------------ notices


def test_notices_come_from_the_block_when_present():
    block = _block(notices=["Custom notice one", "Custom notice two"])
    notices = _sections(build_pi_report(_result(block)))["Limitations & legal notices"]
    assert "Custom notice one" in notices and "Custom notice two" in notices
    assert NOTICES[0] not in notices


def test_notices_fall_back_to_the_module_constant_when_empty():
    notices = _sections(build_pi_report(_result(_block())))["Limitations & legal notices"]
    for notice in NOTICES:
        assert notice in notices


# ------------------------------------------------------------------ D5: next step is an action, not the header


_HANDOFF_WITH_HEADER = [
    "Engagement pi_0123456789 (due_diligence); purpose as stated by the client: Vet a counterparty",
    "Matter reference: MSA-2026-114",
    "Jurisdiction: us",
    "Every identifier below comes from free public sources and is an unverified lead until confirmed.",
    "Bunnyhole output is not a consumer report and must not be used for eligibility decisions.",
    "Run through licensed database: jane@example.com (email; unverified lead)",
    "Request via counsel: subpoena duces tecum to Delaware Division of Corporations",
]


def test_bottom_line_next_step_skips_the_engagement_header_lines():
    block = _block(handoff_sheet=_HANDOFF_WITH_HEADER)
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    assert "**Next step:** Run through licensed database: jane@example.com" in bottom
    assert "**Next step:** Engagement" not in bottom
    assert "Matter reference" not in bottom


def test_bottom_line_next_step_accepts_field_verification_and_confirm_lines():
    for line in ("Field verification (public place only; licensed investigator): 1 Main St",
                 "Confirm with a primary source: x (y; unverified lead)"):
        block = _block(handoff_sheet=["Engagement pi_1 (locate); purpose: x", line])
        bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
        assert f"**Next step:** {line}" in bottom


def test_bottom_line_header_only_handoff_falls_back_to_custodian_then_none():
    header_only = _HANDOFF_WITH_HEADER[:5]
    custodian = Custodian(finding="phone carrier", custodian="Carrier X", instrument="production order",
                          jurisdiction="ca-on")
    with_custodian = _sections(build_pi_report(_result(_block(handoff_sheet=header_only, custodians=[custodian]))))
    assert "Carrier X" in with_custodian["Bottom line"]
    assert "**Next step:** Engagement" not in with_custodian["Bottom line"]
    without = _sections(build_pi_report(_result(_block(handoff_sheet=header_only))))["Bottom line"]
    assert "no escalation indicated" in without.lower()


# ------------------------------------------------------------------ D6: ranking, caps and collapse


def test_strongest_finding_is_not_chosen_alphabetically():
    block = _block(
        findings=[
            Finding(node_id="n1", label="Zulu Tram", finding_label=FindingLabel.LEAD, source_count=1),
            Finding(node_id="n2", label="Alpha Tram", finding_label=FindingLabel.LEAD, source_count=1),
        ]
    )
    bottom = _sections(build_pi_report(_result(block)))["Bottom line"]
    # Two findings tie at the top rank: no one is named (was: the first of the tie, "Zulu Tram").
    assert "no single strongest finding (2 tied at lead)" in bottom
    assert "Strongest finding: Zulu Tram" not in bottom


def test_findings_with_equal_label_rank_by_source_count_then_original_order():
    block = _block(
        findings=[
            Finding(node_id="n1", label="Second", finding_label=FindingLabel.CONFIRMED, source_count=3),
            Finding(node_id="n2", label="Zeta", finding_label=FindingLabel.CONFIRMED, source_count=5),
            Finding(node_id="n3", label="Alpha", finding_label=FindingLabel.CONFIRMED, source_count=3),
        ]
    )
    findings = _sections(build_pi_report(_result(block)))["Findings"]
    assert findings.index("Zeta") < findings.index("Second") < findings.index("Alpha")


def test_findings_table_is_capped_at_25_rows_with_an_omission_line():
    findings = [Finding(node_id=f"n{i}", label=f"Lead {i:02d}", finding_label=FindingLabel.LEAD, source_count=1)
                for i in range(30)]
    findings.append(Finding(node_id="top", label="Top Confirmed", finding_label=FindingLabel.CONFIRMED,
                            source_count=3))
    section = _sections(build_pi_report(_result(_block(findings=findings))))["Findings"]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ") and "Finding | Label" not in ln
            and "--- |" not in ln]
    assert len(rows) == 25
    assert "Top Confirmed" in section
    assert "6 further lead-only findings omitted here; they are in the JSON result" in section
    assert "Lead 23" in section and "Lead 24" not in section


def test_no_omission_line_when_findings_fit():
    findings = [Finding(node_id=f"n{i}", label=f"L{i}", finding_label=FindingLabel.LEAD, source_count=1)
                for i in range(25)]
    section = _sections(build_pi_report(_result(_block(findings=findings))))["Findings"]
    assert "omitted here" not in section


def test_omission_line_does_not_say_lead_only_when_stronger_findings_are_omitted():
    findings = [Finding(node_id=f"n{i}", label=f"P{i}", finding_label=FindingLabel.PROBABLE, source_count=2)
                for i in range(27)]
    section = _sections(build_pi_report(_result(_block(findings=findings))))["Findings"]
    assert "2 further findings omitted here; they are in the JSON result" in section
    assert "lead-only" not in section


def test_identical_falsifiers_collapse_with_a_count():
    text = "A second independent source that contradicts the lead 'Foo' (n1)."
    section = _sections(build_pi_report(_result(_block(falsifiers=[text] * 20 + ["Different one"]))))[
        "What would change this conclusion"
    ]
    lines = [ln for ln in section.splitlines() if ln.startswith("- ")]
    assert len(lines) == 2
    assert f"- {text} (x 20)" in lines
    assert "- Different one" in lines


def test_falsifier_list_is_capped_at_12_lines_plus_a_more_line():
    falsifiers = [f"Distinct statement {i}" for i in range(20)]
    section = _sections(build_pi_report(_result(_block(falsifiers=falsifiers))))["What would change this conclusion"]
    lines = [ln for ln in section.splitlines() if ln.startswith("- ")]
    assert len(lines) == 13
    assert lines[11] == "- Distinct statement 11"
    assert "8 more" in lines[12]
    assert "Distinct statement 12" not in section


# ------------------------------------------------------------------ D7: custody and coverage honesty


def test_custody_table_has_digest_caveat_sentence():
    custody = _sections(build_pi_report(_full_result()))["Chain of custody"]
    assert (
        "The digest covers the recorded extract (tool, URL, fact, snippet), not the full retrieved page; "
        "archive source pages (Wayback Save Page Now, ArchiveBox, SingleFile) for page-level preservation."
    ) in custody
    assert "| SHA-256 |" not in custody


def test_empty_custody_has_no_caveat_sentence():
    assert _sections(build_pi_report(_result(_block())))["Chain of custody"] == "None."


def _sanctions_partial_block() -> PIBlock:
    return _block(
        coverage=[
            CoverageRow(source_class="sanctions_pep", searched=True, sources=["canada_sema"],
                        skipped=["opensanctions"], outcome="negative"),
            CoverageRow(source_class="court_dockets", searched=False, sources=[], skipped=["courtlistener"],
                        outcome="not_searched"),
            CoverageRow(source_class="corporate_registry", searched=True, sources=["gleif"], outcome="hit"),
        ]
    )


def test_coverage_table_has_tried_not_reached_column():
    coverage = _sections(build_pi_report(_result(_sanctions_partial_block())))["Coverage and negatives"]
    assert "| Source class | Searched | Sources | Tried, not reached | Outcome |" in coverage
    row = next(ln for ln in coverage.splitlines() if ln.startswith("| sanctions_pep"))
    assert "canada_sema" in row and "opensanctions" in row
    skipped_only = next(ln for ln in coverage.splitlines() if ln.startswith("| court_dockets"))
    assert "courtlistener" in skipped_only and "NOT SEARCHED" in skipped_only


def test_skipped_only_class_is_still_not_searched_in_the_bottom_line():
    bottom = _sections(build_pi_report(_result(_sanctions_partial_block())))["Bottom line"]
    assert "court_dockets" in bottom and "not searched" in bottom.lower()


def test_partial_coverage_note_names_what_ran_and_what_was_skipped():
    block = _sanctions_partial_block()
    sections = _sections(build_pi_report(_result(block)))
    note = next(ln for ln in sections["Coverage and negatives"].splitlines() if "partial:" in ln)
    assert "sanctions_pep" in note and "canada_sema" in note and "opensanctions" in note
    assert "corporate_registry" not in note and "court_dockets" not in note
    assert "partial" in sections["Bottom line"].lower() and "opensanctions" in sections["Bottom line"]


def test_no_partial_note_when_nothing_was_skipped_alongside_a_search():
    coverage = _sections(build_pi_report(_full_result()))["Coverage and negatives"]
    assert "partial:" not in coverage


# ------------------------------------------------------------------ new sections: identity, playbook


def test_identity_resolution_renders_notes_after_findings():
    block = _block(identity_notes=["Two people named Jane Doe matched;\n## Fake | heading"])
    report = build_pi_report(_result(block))
    assert _h2_headings(report) == HEADINGS
    section = _sections(report)["Identity resolution"]
    assert "- Two people named Jane Doe matched; ## Fake | heading" in section
    assert report.index("## Findings") < report.index("## Identity resolution") < report.index("## Ownership chain")


def test_identity_resolution_empty_person_says_anchoring_unverified():
    section = _sections(build_pi_report(_result(_block())))["Identity resolution"]
    assert section.startswith("None.")
    assert "No identity-resolution notes; subject anchoring unverified." in section


def test_identity_resolution_empty_entity_is_just_none():
    block = _block(engagement=_engagement(subject_is_person=False))
    assert _sections(build_pi_report(_result(block)))["Identity resolution"] == "None."


def _playbook_block() -> PIBlock:
    return _block(
        done_when="Assets located and a custodian named\nfor each",
        playbook_progress=[
            PlaybookProgress(order=2, action="Search dockets", sources=["courtlistener"], status="partial",
                             evidence="one of two dockets reached"),
            PlaybookProgress(order=1, action="Registry lookup", sources=["gleif", "opencorporates"],
                             status="done", evidence="2 hits"),
            PlaybookProgress(order=3, action="Check vehicle registry | DMV", status="handoff",
                             evidence="needs licensed layer"),
            PlaybookProgress(order=4, action="Interview", status="not_run"),
        ],
        escalation_triggers=[
            EscalationTrigger(trigger="Subject is judgment-proof | claimed", fired=True, why="no assets found"),
            EscalationTrigger(trigger="Sanctions hit", fired=False),
        ],
    )


def test_playbook_progress_section_renders_done_when_steps_and_triggers():
    report = build_pi_report(_result(_playbook_block()))
    assert _h2_headings(report) == HEADINGS
    assert report.index("## Coverage and negatives") < report.index("## Playbook progress") < report.index(
        "## Custodians and next steps"
    )
    section = _sections(report)["Playbook progress"]
    assert "Done when (judged by a human, not by Bunnyhole): Assets located and a custodian named for each" in section
    assert "| Step | Action | Sources | Status | Evidence |" in section
    assert "| Trigger | Fired | Why |" in section
    for word in ("DONE", "PARTIAL", "NOT RUN", "NEEDS LICENSED LAYER"):
        assert f"| {word} |" in section
    assert section.index("Registry lookup") < section.index("Search dockets") < section.index("Interview")
    steps = [ln for ln in section.splitlines() if ln.startswith("| ") and "Registry" in ln][0]
    assert "gleif, opencorporates" in steps and "2 hits" in steps
    assert "Subject is judgment-proof \\| claimed" in section


def test_playbook_progress_pipes_in_untrusted_cells_keep_column_count():
    section = _sections(build_pi_report(_result(_playbook_block())))["Playbook progress"]
    for line in section.splitlines():
        if line.startswith("| ") and "DMV" in line:
            assert _unescaped_pipes(line) == 6
        if line.startswith("| ") and "judgment-proof" in line:
            assert _unescaped_pipes(line) == 4


def test_playbook_progress_empty_is_none():
    assert _sections(build_pi_report(_result(_block())))["Playbook progress"] == "None."
