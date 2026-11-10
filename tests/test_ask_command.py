"""CLI tests for ``bunnyhole ask`` with a recording fake orchestrator: no network, no LLM, no real ~/.bunnyhole.

The fake returns canned results shaped like the real orchestrator's (``nodes``, ``edges``, ``logs``,
``interconnections.targeted_paths``). The conftest network guard stays on for every test here: a live call fails the
test at teardown.
"""

from __future__ import annotations

import re
import sys
import types
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pi_helpers import isolate_cli
from pi_helpers import run_cli as _run

from bunnyhole.engine.ask_checklist import STATUS_NONE, STATUS_SIGNALS, STATUS_UNCHECKED, build_risk_checklist
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.pi import PIEngagement

PURPOSE = "vet a counterparty before signing a supply contract"
PI_FLAGS = ("--pi", "--purpose", PURPOSE, "--purpose-category", "counterparty_due_diligence", "--matter-ref", "MSA-2026-114")
CLOSING = "No hit is not clearance. This lists signals found in public sources; it is not a finding of wrongdoing."
FORBIDDEN = re.compile(r"\b(clean|safe|no risk|all clear)\b", re.I)


def _receipt(rid: str, tool: str, url: str) -> Dict[str, Any]:
    return {"receipt_id": rid, "tool": tool, "source_url": url, "admiralty_code": "B2"}


CONNECTION_RESULT: Dict[str, Any] = {
    "case_id": "bh_fake",
    "seed_query": "Acme Ltd <-> Globex Inc",
    "stats": {},
    "nodes": [
        {"id": "company:acme", "label": "Acme Ltd", "entity_type": "Organization", "receipts": []},
        {"id": "person:jd", "label": "John Doe [x]", "entity_type": "Person", "receipts": []},
        {"id": "company:globex", "label": "Globex Inc", "entity_type": "Organization", "receipts": []},
    ],
    "edges": [
        {
            "source_id": "person:jd", "target_id": "company:acme", "relation": "DIRECTOR_OF", "confidence": 0.9,
            "receipts": [_receipt("rcpt_aaa", "companies_house", "https://ch/a"), _receipt("rcpt_bbb", "gleif_level1_level2_api", "https://gleif/b")],
        },
        {
            "source_id": "person:jd", "target_id": "company:globex", "relation": "OFFICER_OF", "confidence": 0.7,
            "receipts": [_receipt("rcpt_ccc", "sec_edgar_efts + edgartools", "https://sec/c")],
        },
    ],
    "interconnections": {
        "targeted_paths": [
            {
                "node_ids": ["company:acme", "person:jd", "company:globex"], "hop_count": 2,
                "step_labels": ["Acme Ltd", "John Doe [x]", "Globex Inc"], "step_relations": [], "path_score": 1.2,
            }
        ]
    },
    "logs": [{"action": "COURTLISTENER_SKIP", "level": "warning", "detail": "token not set; court dockets not searched"}],
}
NO_CONNECTION_RESULT: Dict[str, Any] = {
    "case_id": "bh_fake", "nodes": [], "edges": [], "interconnections": {"targeted_paths": []},
    "logs": [
        {"action": "NEWS_TRAIL_SWEEP", "level": "info", "detail": "news"},
        {"action": "UK_PSC_SKIP", "level": "warning", "detail": "UK_COMPANIES_HOUSE_API_KEY not set"},
    ],
}
SIGNALS_RESULT: Dict[str, Any] = {
    "case_id": "bh_fake",
    "nodes": [
        {
            "id": "sanction:x", "label": "Acme Trading LLC (OpenSanctions)", "entity_type": "Organization",
            "risk_flags": ["OFAC_EU_UN_SANCTIONS_LIST_MATCH", "SOFT_NAME_MATCH_VERIFY"],
            "receipts": [_receipt("rcpt_s1", "opensanctions_yente", "https://os/x"), _receipt("rcpt_s2", "ofac_sdn", "https://ofac/x")],
        },
        {
            "id": "case:1", "label": "SEC v. Acme", "entity_type": "LegalCase",
            "risk_flags": ["FEDERAL_LITIGATION_RECORD", "REGULATORY_OR_FRAUD_DOCKET"],
            "receipts": [_receipt("rcpt_l1", "courtlistener_recap_v4", "https://cl/1")],
        },
        {
            "id": "addr:1", "label": "1 Registered Agent Way", "entity_type": "Location",
            "risk_flags": ["MASS_REGISTERED_AGENT_ADDRESS"], "receipts": [_receipt("rcpt_o1", "companies_house", "https://ch/o")],
        },
    ],
    "edges": [],
    "logs": [{"action": "SANCTIONS_PEP_SCAN", "level": "info", "detail": "scan"}, {"action": "NEWS_TRAIL_SWEEP", "level": "info", "detail": "n"}],
}
NO_SIGNALS_RESULT: Dict[str, Any] = {
    "case_id": "bh_fake", "nodes": [], "edges": [],
    "logs": [
        {"action": "SANCTIONS_PEP_SCAN", "level": "info", "detail": "scan"},
        {"action": "NEWS_TRAIL_SWEEP", "level": "info", "detail": "news"},
        {"action": "COURTLISTENER_RECAP_SEARCH", "level": "info", "detail": "dockets"},
        {"action": "CA_SANCTIONS_SKIP", "level": "warning", "detail": "Canadian sanctions list unavailable"},
    ],
}


class FakeAskOrchestrator:
    """Records constructor kwargs and calls; returns ``next_result``. Never touches the network."""

    instances: List["FakeAskOrchestrator"] = []
    next_result: Dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.calls: List[Any] = []
        self.graph = types.SimpleNamespace(export_markdown_dossier=lambda: "# dossier")
        type(self).instances.append(self)

    def _pi_start_case(self, seeds: List[Any]) -> None:
        self.calls.append(("pi_start_case", seeds))

    async def run_investigation(self) -> Dict[str, Any]:
        self.calls.append(("run_investigation",))
        return deepcopy(type(self).next_result)

    async def run_bidirectional_link_investigation(self, a: str, b: str) -> Dict[str, Any]:
        self.calls.append(("link", a, b))
        return deepcopy(type(self).next_result)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_cli(monkeypatch, FakeAskOrchestrator, stub_render=False)
    FakeAskOrchestrator.next_result = NO_SIGNALS_RESULT


def _ask(result: Dict[str, Any], *args: str) -> Any:
    FakeAskOrchestrator.next_result = result
    return _run("ask", *args)


# ------------------------------------------------------------------------------------------ connection


def test_connection_found_renders_chain_with_receipts_and_labels() -> None:
    res = _ask(CONNECTION_RESULT, "see if Acme Ltd is connected to Globex Inc")
    assert res.exit_code == 0, res.output
    assert FakeAskOrchestrator.instances[0].calls == [("link", "Acme Ltd", "Globex Inc")]
    out = res.output
    assert "Connection found between Acme Ltd and Globex Inc" in out
    assert "DIRECTOR_OF" in out and "OFFICER_OF" in out
    assert "rcpt_aaa, rcpt_bbb" in out and "rcpt_ccc" in out
    assert "confidence 0.90" in out and "confidence 0.70" in out
    assert "probable" in out and "lead" in out  # 2 independent sources and 1; no upgrade beyond the repo's rule
    assert "weakest hop is a lead" in out
    assert "John Doe [x]" in out  # bracketed text from a node label is shown literally, not read as markup
    assert "not proof of a relationship" in out
    assert "COURTLISTENER_SKIP" in out  # unavailable sources are listed


def test_no_connection_found_is_worded_as_absence_not_proof() -> None:
    res = _ask(NO_CONNECTION_RESULT, "any ties between Acme Ltd and Globex Inc")
    assert res.exit_code == 0, res.output
    flat = " ".join(res.output.split())
    assert "No connection found between Acme Ltd and Globex Inc in the sources searched; absence is not proof." in flat
    assert "not connected" not in flat.lower()
    assert "NEWS_TRAIL_SWEEP" in flat and "UK_PSC_SKIP" in flat  # searched / unavailable


# ------------------------------------------------------------------------------------------ company risk


def test_company_risk_with_signals_lists_checklist_and_closing_line() -> None:
    res = _ask(SIGNALS_RESULT, "see if Acme Ltd has anything shady going on")
    assert res.exit_code == 0, res.output
    flat = " ".join(res.output.split())
    inst = FakeAskOrchestrator.instances[0]
    assert inst.calls == [("run_investigation",)]
    assert inst.kwargs["profile"].persona is Persona.COMPLIANCE  # sanctions emphasis, same persona `trace` uses
    assert "engagement" not in inst.kwargs  # company-only questions need no PI mode
    assert "Sanctions and PEP screening: signals found" in flat
    assert "probable: Acme Trading LLC" in flat  # 2 independent receipts -> the repo's own label
    assert "rcpt_s1, rcpt_s2" in flat
    assert "name match only" in flat or "SOFT_NAME_MATCH_VERIFY" in flat
    assert "Litigation: signals found" in flat and "Ownership opacity and shell indicators: signals found" in flat
    assert "Leaked-data mentions: not checked or unavailable" in flat
    assert "NOT screened" in flat and "UK Sanctions List" in flat
    assert flat.rstrip().endswith(CLOSING)
    assert not FORBIDDEN.search(res.output)


def test_company_risk_with_no_signals_never_says_clean_or_safe() -> None:
    res = _ask(NO_SIGNALS_RESULT, "is Acme Ltd legit")
    assert res.exit_code == 0, res.output
    flat = " ".join(res.output.split())
    assert "Sanctions and PEP screening: nothing found in sources searched" in flat
    assert "Litigation: nothing found in sources searched" in flat
    assert "Registry status, officers and ownership: not checked or unavailable" in flat
    assert "Canadian sanctions list unavailable" in flat
    assert "Not a verdict" in flat
    assert flat.rstrip().endswith(CLOSING)
    assert not FORBIDDEN.search(res.output)


def test_risk_question_naming_a_person_runs_pi_link_and_shows_both() -> None:
    res = _ask(CONNECTION_RESULT, "see if Acme Ltd run by Jane Smith has anything shady going on", *PI_FLAGS)
    assert res.exit_code == 0, res.output
    inst = FakeAskOrchestrator.instances[0]
    assert ("link", "Acme Ltd", "Jane Smith") in inst.calls
    assert isinstance(inst.kwargs["engagement"], PIEngagement)
    assert "Sanctions and PEP screening" in res.output and "Connection between Acme Ltd and Jane Smith" in res.output


# ------------------------------------------------------------------------------------------ PI gates


def test_person_without_pi_flags_is_refused_and_nothing_runs() -> None:
    res = _ask(CONNECTION_RESULT, "see if Abdul Rehman Akingbola is connected to daliatech.ca")
    assert res.exit_code == 2
    assert "--purpose" in res.output  # the refusal `trace --pi` shows when the purpose is missing
    assert not FakeAskOrchestrator.instances


def test_person_with_purpose_but_no_matter_ref_is_refused_like_trace() -> None:
    args = ("see if Jane Smith is connected to Acme Ltd", "--purpose", PURPOSE, "--purpose-category", "counterparty_due_diligence")
    ask = _ask(CONNECTION_RESULT, *args)
    trace = _run("trace", "Jane Smith", "--pi", *args[1:])
    assert ask.exit_code == trace.exit_code == 2
    assert "--matter-ref" in ask.output and "--matter-ref" in trace.output
    assert not FakeAskOrchestrator.instances


def test_person_with_pi_flags_passes_the_same_gate_as_trace() -> None:
    res = _ask(CONNECTION_RESULT, "is Jane Smith linked to Acme Ltd", *PI_FLAGS)
    assert res.exit_code == 0, res.output
    inst = FakeAskOrchestrator.instances[0]
    engagement = inst.kwargs["engagement"]
    assert isinstance(engagement, PIEngagement) and engagement.subject_is_person
    assert engagement.matter_ref == "MSA-2026-114"
    assert inst.calls[0][0] == "pi_start_case" and inst.calls[0][1][0][1] == "Jane Smith"  # PI case opened on the person
    assert inst.calls[1] == ("link", "Jane Smith", "Acme Ltd")
    assert "PI SUMMARY" in res.output or "No PI block" in res.output


def test_eligibility_purpose_is_refused_for_a_person() -> None:
    res = _ask(
        CONNECTION_RESULT, "is Jane Smith linked to Acme Ltd", "--pi", "--purpose", "pre-employment screening of a candidate",
        "--purpose-category", "counterparty_due_diligence", "--matter-ref", "MSA-1",
    )
    assert res.exit_code == 2 and "FCRA" in res.output
    assert not FakeAskOrchestrator.instances


def test_pi_flags_without_pi_on_a_company_question_are_refused() -> None:
    res = _ask(SIGNALS_RESULT, "is Acme Ltd legit", "--purpose", PURPOSE)
    assert res.exit_code == 2 and "--pi" in res.output
    assert not FakeAskOrchestrator.instances


def test_company_with_pi_gets_an_entity_engagement_and_the_pi_persona() -> None:
    res = _ask(
        SIGNALS_RESULT, "is Acme Ltd legit", "--pi", "--purpose", PURPOSE, "--purpose-category", "counterparty_due_diligence"
    )
    assert res.exit_code == 0, res.output
    kwargs = FakeAskOrchestrator.instances[0].kwargs
    assert kwargs["engagement"].subject_is_person is False
    assert kwargs["profile"].persona is Persona.PRIVATE_INVESTIGATOR


def test_pi_report_reuses_the_existing_report_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: List[Dict[str, Any]] = []
    module = types.ModuleType("bunnyhole.engine.pi_report")
    module.build_pi_report = lambda result: seen.append(result) or "# STUB PI REPORT\n"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "bunnyhole.engine.pi_report", module)
    report = tmp_path / "pi.md"
    res = _ask(CONNECTION_RESULT, "is Jane Smith linked to Acme Ltd", *PI_FLAGS, "--pi-report", str(report), "--no-ai-analysis")
    assert res.exit_code == 0, res.output
    assert report.read_text() == "# STUB PI REPORT\n" and len(seen) == 1


# ------------------------------------------------------------------------------------------ output, unknown


def test_out_writes_the_markdown_answer(tmp_path: Path) -> None:
    target = tmp_path / "answer.md"
    res = _ask(SIGNALS_RESULT, "any red flags on Acme Ltd", "--out", str(target))
    assert res.exit_code == 0, res.output
    text = target.read_text(encoding="utf-8")
    assert text.startswith("# Signals found on")
    assert "## Sanctions and PEP screening: signals found" in text and CLOSING in text
    assert not FORBIDDEN.search(text)


def test_json_flag_writes_the_graph_json(tmp_path: Path) -> None:
    target = tmp_path / "graph.json"
    res = _ask(NO_SIGNALS_RESULT, "is Acme Ltd legit", "--json", str(target))
    assert res.exit_code == 0, res.output
    assert '"case_id": "bh_fake"' in target.read_text(encoding="utf-8")


def test_unknown_question_prints_help_and_exits_2() -> None:
    res = _ask(CONNECTION_RESULT, "what is the weather in Toronto")
    assert res.exit_code == 2
    flat = " ".join(res.output.split())
    assert "is X connected to Y" in flat and "bunnyhole trace" in flat
    assert not FakeAskOrchestrator.instances


# ------------------------------------------------------------------------------------------ checklist rules


def test_checklist_with_empty_result_reports_unchecked_never_nothing_found() -> None:
    rows = {r.key: r for r in build_risk_checklist({"nodes": [], "edges": [], "logs": []})}
    assert len(rows) == 7
    assert {r.status for r in rows.values()} == {STATUS_UNCHECKED}


def test_checklist_statuses_and_young_domain_signal() -> None:
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    young = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    result = {
        "nodes": [
            {"id": "domain:a.com", "label": "a.com", "entity_type": "Domain", "attributes": {"whois_created": young}, "receipts": []},
            {"id": "domain:b.com", "label": "b.com", "entity_type": "Domain", "attributes": {"whois_created": "2001-05-01"}, "receipts": []},
        ],
        "edges": [],
        "logs": [],
    }
    rows = {r.key: r for r in build_risk_checklist(result, now)}
    assert rows["domain"].status == STATUS_SIGNALS
    assert any("30_DAYS_AGO" in flag for s in rows["domain"].signals for flag in s.flags)
    assert any("not available in this version" in note for note in rows["domain"].notes)  # look-alikes: not checked
    assert rows["sanctions"].status == STATUS_UNCHECKED
    quiet = {r.key: r for r in build_risk_checklist({**result, "nodes": result["nodes"][1:]}, now)}
    assert quiet["domain"].status == STATUS_NONE


def test_a_skipped_sanctions_list_is_not_counted_as_screened() -> None:
    result = {"nodes": [], "edges": [], "logs": [
        {"action": "SANCTIONS_PEP_SCAN", "level": "info", "detail": "scan"},
        {"action": "SANCTIONS_PEP_SKIP", "level": "warning", "detail": "OpenSanctions needs access"},
    ]}
    row = build_risk_checklist(result)[0]
    assert row.status == STATUS_UNCHECKED
    assert any("OpenSanctions needs access" in n for n in row.notes)
