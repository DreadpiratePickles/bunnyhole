"""Third quality pass on the PI report: attested purpose, soft graph matches, 50% rule honesty, quieter bottom line."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from bunnyhole.engine.pi import (
    CaseType,
    EscalationTrigger,
    Finding,
    FindingLabel,
    OwnershipBlock,
    OwnershipEdge,
    PIBlock,
    PIEngagement,
    SanctionsScreening,
)
from bunnyhole.engine.pi_report import build_pi_report

NOT_EVALUABLE = "50%-rule: not evaluable (ownership percentages unknown)"
GRAPH_HEADING = "Other graph entities that match a sanctions-list entry (soft)"


def _engagement(**overrides: Any) -> PIEngagement:
    fields: Dict[str, Any] = {
        "engagement_id": "pi_74e9482909",
        "case_type": CaseType.DUE_DILIGENCE,
        "purpose": "Counterparty due diligence ahead of a supply contract",
        "subject_is_person": False,
        "created_at_utc": "2026-11-09T07:48:55+00:00",
    }
    fields.update(overrides)
    return PIEngagement(**fields)


def _block(**overrides: Any) -> PIBlock:
    fields: Dict[str, Any] = {"engagement": _engagement()}
    fields.update(overrides)
    return PIBlock(**fields)


def _render(block: PIBlock) -> str:
    return build_pi_report({"pi": block.model_dump(mode="json")})


def _sections(markdown: str) -> Dict[str, str]:
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    return {parts[i].strip(): parts[i + 1].strip() for i in range(1, len(parts), 2)}


def _primary_hit() -> Dict[str, Any]:
    return {"list": "OFAC SDN", "name": "ROSNEFT TRADING S.A.", "match": "soft: verify on the primary list",
            "url": "https://sanctionssearch.ofac.treas.gov/", "node_id": "sanction:ofac:18299"}


def _graph_hit() -> Dict[str, Any]:
    return {"list": "OFAC SDN", "name": "Rosneft Trading S.A.", "match": "matches a sanctions-list entry (soft)",
            "url": "https://sanctionssearch.ofac.treas.gov/", "node_id": "lei:TRADING00000000000001",
            "graph_match": True, "matched_entry": "ROSNEFT TRADING S.A."}


def _screening(*hits: Dict[str, Any]) -> SanctionsScreening:
    return SanctionsScreening(status="partial", screened=["OFAC SDN"], not_screened=["OpenSanctions"], hits=list(hits))


def _edge(pct: Any) -> OwnershipEdge:
    return OwnershipEdge(child="lei:CHILD", parent="lei:PARENT", pct=pct)


# ---------------------------------------------------------------- attested purpose


def test_engagement_section_shows_the_attested_permissible_purpose_category():
    markdown = _render(_block(engagement=_engagement(purpose_category="counterparty_due_diligence")))
    assert "- **Attested permissible purpose:** counterparty_due_diligence" in _sections(markdown)["Engagement & scope"]


def test_engagement_section_says_not_attested_when_the_category_is_empty():
    markdown = _render(_block())
    assert "- **Attested permissible purpose:** (not attested)" in _sections(markdown)["Engagement & scope"]


# ---------------------------------------------------------------- 50% rule honesty


def test_ownership_section_says_the_50_rule_is_not_evaluable_when_no_percentage_is_known():
    ownership = OwnershipBlock(levels_walked=1, edges=[_edge(None)])
    section = _sections(_render(_block(ownership=ownership)))["Ownership chain"]
    assert NOT_EVALUABLE in section
    flags = section.split("**50%-rule flags (OFAC):**")[1].split("**Unresolved")[0]
    assert "None." not in flags


def test_ownership_section_still_says_none_when_percentages_are_known_and_nothing_is_blocked():
    ownership = OwnershipBlock(levels_walked=1, edges=[_edge(30.0)])
    section = _sections(_render(_block(ownership=ownership)))["Ownership chain"]
    assert NOT_EVALUABLE not in section
    assert "**50%-rule flags (OFAC):**\n- None." in section or "**50%-rule flags (OFAC):**\nNone." in section


def test_bottom_line_carries_the_not_evaluable_note_next_to_a_sanctions_hit():
    block = _block(sanctions=_screening(_primary_hit()), ownership=OwnershipBlock(levels_walked=1, edges=[_edge(None)]))
    assert NOT_EVALUABLE in _sections(_render(block))["Bottom line"]


def test_bottom_line_without_a_hit_does_not_add_the_note():
    block = _block(ownership=OwnershipBlock(levels_walked=1, edges=[_edge(None)]))
    assert NOT_EVALUABLE not in _sections(_render(block))["Bottom line"]


def test_the_escalation_text_is_shown_unchanged_in_the_playbook_table():
    trigger = EscalationTrigger(trigger="Sanctions hit", fired=False, why=f"not fired; {NOT_EVALUABLE}")
    assert NOT_EVALUABLE in _sections(_render(_block(escalation_triggers=[trigger])))["Playbook progress"]


# ---------------------------------------------------------------- soft graph matches


def test_sanctions_section_lists_other_graph_entities_that_match_a_listed_entry():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Sanctions screening"]
    assert GRAPH_HEADING in section
    tail = section.split(GRAPH_HEADING)[1]
    assert "Rosneft Trading S.A." in tail and "ROSNEFT TRADING S.A." in tail
    assert "lei:TRADING00000000000001" in tail
    assert "SOFT MATCH" in tail


def test_primary_hits_table_does_not_repeat_the_graph_matches():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Sanctions screening"]
    hits_part = section.split("**Hits:**")[1].split(GRAPH_HEADING)[0]
    assert "sanction:ofac:18299" not in hits_part  # the url column carries the list url, not the node id
    assert "Rosneft Trading S.A." not in hits_part.replace("ROSNEFT TRADING S.A.", "")


def test_the_graph_match_block_is_absent_without_graph_matches():
    section = _sections(_render(_block(sanctions=_screening(_primary_hit()))))["Sanctions screening"]
    assert GRAPH_HEADING not in section


def test_bottom_line_names_the_other_graph_matches_and_keeps_the_primary_hit_first():
    bottom = _sections(_render(_block(sanctions=_screening(_primary_hit(), _graph_hit()))))["Bottom line"]
    assert bottom.startswith("- **Sanctions:** soft name match to ROSNEFT TRADING S.A. on OFAC SDN")
    assert "1 other graph entity" in bottom and "Rosneft Trading S.A." in bottom


def test_graph_matches_alone_are_not_a_primary_hit():
    bottom = _sections(_render(_block(sanctions=_screening(_graph_hit()))))["Bottom line"]
    assert bottom.startswith("- **Sanctions:** partial")


# ---------------------------------------------------------------- findings untouched, no crash on odd rows


def test_a_finding_tagged_as_a_soft_listing_keeps_its_reason_in_the_findings_table():
    finding = Finding(
        node_id="lei:TRADING00000000000001", label="Rosneft Trading S.A. (CH)", finding_label=FindingLabel.LEAD,
        source_count=1, relevance="related",
        relevance_reason="extends the subject name with trading; matches a sanctions-list entry (soft): 'X'",
    )
    markdown = _render(_block(findings=[finding]))
    assert "matches a sanctions-list entry (soft)" in _sections(markdown)["Findings"]


def test_graph_match_rows_with_missing_fields_do_not_break_the_report():
    rows: List[Dict[str, Any]] = [{"graph_match": True}]
    markdown = _render(_block(sanctions=_screening(_primary_hit(), *rows)))
    assert "## Sanctions screening" in markdown


def test_node_names_in_the_bottom_line_drop_the_leading_emoji():
    block = _block(ownership=OwnershipBlock(levels_walked=1, unresolved=["lei:X1"]))
    markdown = build_pi_report({"pi": block.model_dump(mode="json"),
                                "nodes": [{"id": "lei:X1", "label": "\U0001f451 Acme Parent Ltd (RU)"}]})
    bottom = _sections(markdown)["Bottom line"]
    assert "Acme Parent Ltd (RU) (lei:X1)" in bottom and "\U0001f451" not in bottom
