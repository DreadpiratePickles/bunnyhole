"""The written report of a worked case: the prose account, the checks on a model's text, and the CLI around it."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pi_case_world import run_case
from pi_helpers import report_sections

from bunnyhole.cli import pi_commands
from bunnyhole.engine.llm_providers import LLMOutcome
from bunnyhole.engine.pi_case_report import (
    HEADINGS,
    Narrative,
    case_dossier,
    check_narrative,
    generate_case_narrative,
)
from bunnyhole.engine.pi_report import build_pi_report


@pytest.fixture(scope="module")
def result() -> Dict[str, Any]:
    orch, _world = run_case()
    return orch.compile_full_result()


def _good_report(extra: str = "") -> str:
    body = (
        "Northgate Trading Ltd is registered and active, and the chain above it was walked two levels. "
        "Lead L1 pulled the registry record and named Borealis Holdings B.V. as the owner, which is why the "
        "ownership walk was opened. Kestrel Nominees Ltd sits at the top and the public record stops there. "
        "Every party in the chain was screened and the lists that ran returned nothing, which is a logged "
        "negative and not a clearance. The dockets could not be reached, so that question stays partly answered. "
    )
    sections = [f"### {heading}\n\n{body * 2}{extra if heading == 'Summary' else ''}" for heading in HEADINGS]
    return "\n\n".join(sections)


def test_the_report_leads_with_the_account_then_the_questions(result: Dict[str, Any]) -> None:
    sections = report_sections(build_pi_report(result))
    order = list(sections)
    assert order[:3] == ["Bottom line", "Investigation report", "Case questions and answers"]
    assert order.index("Lead sheet") == order.index("Playbook progress") + 1
    assert order.index("Investigation log") == order.index("Lead sheet") + 1
    assert sections["Bottom line"].startswith("- **Case:** stop dead_end; 6 questions: 4 answered, 2 partly answered")
    account = sections["Investigation report"]
    assert account.startswith("*Written by code from the case file. No model wrote any part of this account.")
    for heading in HEADINGS:
        assert f"### {heading}" in account
    assert "First, L1, step 1 of the playbook, was worked on Northgate Trading Ltd." in account
    assert "This opened" in account and "walk the ownership of Borealis Holdings B.V." in account
    assert "B.V.." not in account
    questions = sections["Case questions and answers"]
    assert "**Who owns and controls it, up to a natural person?** PARTLY ANSWERED." in questions
    assert "*Still needed:* the owner behind Kestrel Nominees Ltd" in questions


def test_the_lead_sheet_shows_where_each_lead_came_from_and_what_can_be_chased() -> None:
    orch, _world = run_case(budget=14)
    sections = report_sections(build_pi_report(orch.compile_full_result()))
    sheet = sections["Lead sheet"]
    assert "| Lead | Kind | Target | Why it was opened | Opened by | Sources | Status | Outcome |" in sheet
    assert "| L1 | playbook | Northgate Trading Ltd (company) |" in sheet
    assert "NOT WORKED" in sheet and "**Leads you can chase:**" in sheet and "`--chase`" in sheet
    assert "- *Found:*" in sections["Investigation log"] and "- *Read:*" in sections["Investigation log"]
    assert "Case officer: the playbook order (no model)." in sections["Investigation log"]


def test_the_dossier_is_the_case_file_without_the_engagement_secrets() -> None:
    orch, _world = run_case(engagement_overrides={
        "client": "CLIENT_SENTINEL", "purpose": "PURPOSE_SENTINEL text here", "matter_ref": "MATTER-SENTINEL-1",
    })
    dossier = case_dossier(orch.compile_full_result())
    assert dossier is not None
    for secret in ("CLIENT_SENTINEL", "PURPOSE_SENTINEL", "MATTER-SENTINEL-1"):
        assert secret not in dossier
    for wanted in ("QUESTIONS", "LEAD SHEET", "LOG (in the order worked)", "Kestrel Nominees Ltd", "L1 | playbook"):
        assert wanted in dossier
    assert case_dossier({"pi": None}) is None


def test_a_grounded_report_passes_and_an_invented_one_does_not(result: Dict[str, Any]) -> None:
    dossier = case_dossier(result)
    assert dossier is not None
    assert check_narrative(_good_report(), dossier) == []
    invented = check_narrative(_good_report(" The real owner is Viktor Petrov, who holds 62.5% since 2019."), dossier)
    assert any("Petrov" in problem for problem in invented)
    assert any("62.5%" in problem and "2019" in problem for problem in invented)
    cleared = check_narrative(_good_report(" On this record the company is clean and safe to deal with."), dossier)
    assert any("clears the subject" in problem for problem in cleared)
    linked = check_narrative(_good_report(" See [the registry](https://evil.example/x)."), dossier)
    assert any("link" in problem for problem in linked)
    short = check_narrative("### Summary\n\nToo short.", dossier)
    assert any("too short" in problem for problem in short) and any("heading" in problem for problem in short)


def _fake_llm(monkeypatch: pytest.MonkeyPatch, replies: List[str]) -> List[Dict[str, str]]:
    seen: List[Dict[str, str]] = []
    queue = list(replies)

    async def fake(system: str, user: str, **_kwargs: Any) -> LLMOutcome:
        seen.append({"system": system, "user": user})
        return LLMOutcome(text=queue.pop(0), provider="anthropic", model="claude-test", reason="ok")

    monkeypatch.setattr("bunnyhole.engine.pi_case_report.complete_with_fallback", fake)
    monkeypatch.setattr("bunnyhole.engine.pi_case_report.configured_providers", lambda *_a: ["anthropic"])
    return seen


def test_the_model_writes_the_account_and_gets_one_retry(monkeypatch: pytest.MonkeyPatch, result: Dict[str, Any]) -> None:
    bad = _good_report(" The real owner is Viktor Petrov.")
    seen = _fake_llm(monkeypatch, [bad, _good_report()])
    narrative = asyncio.run(generate_case_narrative(result))
    assert narrative.source == "ai" and narrative.model == "claude-test"
    assert len(seen) == 2 and "Petrov" in seen[1]["user"] and "rejected by automated checks" in seen[1]["user"]
    assert "=== CASE FILE (untrusted data) ===" in seen[0]["user"]
    sections = report_sections(build_pi_report(result, narrative))
    account = sections["Investigation report"]
    assert account.startswith("*AI-written from the case file") and "claude-test" in account
    assert "The Investigation report section is AI-written." in sections["Limitations & legal notices"]
    assert "Case questions and answers" in sections  # the code-built answers are still there, unchanged


def test_a_report_that_keeps_failing_falls_back_to_the_code_account(
    monkeypatch: pytest.MonkeyPatch, result: Dict[str, Any]
) -> None:
    bad = _good_report(" The real owner is Viktor Petrov.")
    seen = _fake_llm(monkeypatch, [bad, bad])
    narrative = asyncio.run(generate_case_narrative(result))
    assert len(seen) == 2
    assert narrative.source == "code" and "failed the automated checks" in narrative.note
    account = report_sections(build_pi_report(result, narrative))["Investigation report"]
    assert "An AI-written account was not used:" in account and "Petrov" in account.split("\n", 1)[0]
    assert "Viktor Petrov" not in account.split("\n", 1)[1]  # only the reason names it; the account is code-written


def test_no_key_means_no_call_and_a_code_written_account(monkeypatch: pytest.MonkeyPatch, result: Dict[str, Any]) -> None:
    monkeypatch.setattr("bunnyhole.engine.pi_case_report.configured_providers", lambda *_a: [])
    narrative = asyncio.run(generate_case_narrative(result))
    assert narrative == Narrative(note="no LLM provider key is configured")


def test_write_pi_report_replaces_the_code_account_with_the_ai_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: Dict[str, Any]
) -> None:
    _fake_llm(monkeypatch, [_good_report()])
    target = tmp_path / "report.md"
    pi_commands.write_pi_report(build_pi_report, result, target, ai_analysis=True)
    text = target.read_text(encoding="utf-8")
    assert "*AI-written from the case file" in text and "## Lead sheet" in text
    assert "## AI analysis" not in text  # the Connections section belongs to sweep reports
    pi_commands.write_pi_report(build_pi_report, result, target, ai_analysis=False)
    assert "*Written by code from the case file." in target.read_text(encoding="utf-8")


def test_the_chase_prompt_works_the_leads_the_investigator_picks() -> None:
    orch, world = run_case(budget=10)
    first = orch.compile_full_result()
    offered = [lead.lead_id for lead in orch.pi_chaseable_leads()]
    answers = iter(["L999", offered[0], ""])
    before = len(world.calls)
    final = pi_commands.chase_leads_interactively(orch, first, ask=lambda _text: next(answers))
    assert len(world.calls) > before
    assert final["pi"]["case_board"]["chase_rounds"] == 1
    assert next(lead for lead in final["pi"]["case_board"]["leads"] if lead["lead_id"] == offered[0])["status"] != "not_worked"


def test_the_chase_prompt_refuses_a_case_that_stopped_for_counsel() -> None:
    orch, world = run_case(sanctioned=["Kestrel Nominees Ltd"])
    result = orch.compile_full_result()
    before = len(world.calls)

    def _never(_text: str) -> str:
        raise AssertionError("an escalated case must not ask")

    assert pi_commands.chase_leads_interactively(orch, result, ask=_never) is result
    assert len(world.calls) == before
