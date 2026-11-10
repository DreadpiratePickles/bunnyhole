"""CLI wiring of the AI analysis: ``--pi-report`` adds it, ``--no-ai-analysis`` (the only new flag) removes it.

The repo had no existing LLM opt-out flag (the synthesizer is switched off only by having no provider key), so
``--no-ai-analysis`` is new. The analysis also stays off when no provider key is configured, exactly like the
synthesizer. The orchestrator and the LLM are fakes; no network.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Dict

import pytest
from pi_helpers import FakeOrchestrator, isolate_cli
from pi_helpers import run_cli as _run
from pi_narrative_helpers import GOOD_ANALYSIS, FakeLLM, narrative_result, outcome

from bunnyhole.cli import main as cli_main
from bunnyhole.engine import pi_narrative
from bunnyhole.engine.pi_report import build_pi_report

PURPOSE = "vet a counterparty before signing a supply contract"
PI_ARGS = ("--pi", "--purpose", PURPOSE, "--purpose-category", "counterparty_due_diligence",
           "--matter-ref", "MSA-2026-114")
HEADING = "## AI analysis (AI-written, not independently verified; not clearance)"


class NarrativeOrchestrator(FakeOrchestrator):
    """Returns a result with relevant findings, carrying the engagement the CLI built."""

    last_result: Dict[str, Any] = {}

    def _result(self) -> Dict[str, Any]:
        result = narrative_result()
        engagement = self.kwargs.get("engagement")
        if engagement is not None:
            result["pi"]["engagement"] = engagement.model_dump(mode="json")
        type(self).last_result = result
        return result


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_cli(monkeypatch, NarrativeOrchestrator, stub_render=True)
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSECRET-gemini-key")


@pytest.fixture
def fake_llm(monkeypatch: pytest.MonkeyPatch) -> FakeLLM:
    fake = FakeLLM(outcome(GOOD_ANALYSIS))
    monkeypatch.setattr(pi_narrative, "complete_with_fallback", fake)
    return fake


@pytest.mark.parametrize("command", [("trace", "acme.io"), ("intake", "--org", "Acme Holdings Ltd")])
def test_pi_report_gets_the_ai_section(tmp_path: Path, fake_llm: FakeLLM, command: tuple) -> None:
    out = tmp_path / "r.md"
    res = _run(*command, *PI_ARGS, "--pi-report", str(out))
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert HEADING in text
    assert text.index("## Bottom line") < text.index(HEADING)
    assert len(fake_llm.calls) == 1
    assert "AI analysis added" in res.output


@pytest.mark.parametrize("command", [("trace", "acme.io"), ("intake", "--org", "Acme Holdings Ltd")])
def test_no_ai_analysis_flag_writes_exactly_the_code_built_report(
    tmp_path: Path, fake_llm: FakeLLM, command: tuple
) -> None:
    out = tmp_path / "r.md"
    res = _run(*command, *PI_ARGS, "--pi-report", str(out), "--no-ai-analysis")
    assert res.exit_code == 0, res.output
    assert not fake_llm.calls
    assert out.read_text(encoding="utf-8") == build_pi_report(NarrativeOrchestrator.last_result)
    assert "AI analysis" in res.output  # the console says it was switched off


def test_without_a_provider_key_the_report_is_unchanged_and_no_call_is_made(
    tmp_path: Path, fake_llm: FakeLLM, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY")
    out = tmp_path / "r.md"
    res = _run("trace", "acme.io", *PI_ARGS, "--pi-report", str(out))
    assert res.exit_code == 0, res.output
    assert not fake_llm.calls
    assert out.read_text(encoding="utf-8") == build_pi_report(NarrativeOrchestrator.last_result)


def test_failed_analysis_leaves_the_report_and_adds_the_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = FakeLLM(outcome(GOOD_ANALYSIS.replace("[F1,F2,O1]", "[F9]", 1)))
    monkeypatch.setattr(pi_narrative, "complete_with_fallback", bad)
    out = tmp_path / "r.md"
    res = _run("trace", "acme.io", *PI_ARGS, "--pi-report", str(out))
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert text.startswith(build_pi_report(NarrativeOrchestrator.last_result))
    assert text.rstrip("\n").splitlines()[-1].startswith("AI analysis not included:")
    assert HEADING not in text
    assert len(bad.calls) == 2


def test_no_ai_analysis_needs_pi_report() -> None:
    res = _run("trace", "acme.io", *PI_ARGS, "--no-ai-analysis")
    assert res.exit_code == 2
    assert "--pi-report" in res.output
    assert not NarrativeOrchestrator.instances


def test_no_ai_analysis_without_pi_is_refused_like_every_pi_only_option() -> None:
    res = _run("trace", "acme.io", "--no-ai-analysis")
    assert res.exit_code == 2
    assert "--pi-report" in res.output


def test_menu_call_and_signatures_carry_the_new_flag() -> None:
    for command in (cli_main.trace_command, cli_main.intake_command):
        assert "no_ai_analysis" in inspect.signature(command).parameters
    assert "no_ai_analysis=False" in inspect.getsource(cli_main.menu_command)


def test_code_built_report_is_on_disk_even_if_the_analysis_is_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def interrupted(result: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(pi_narrative, "generate_ai_analysis", interrupted)
    out = tmp_path / "r.md"
    res = _run("trace", "acme.io", *PI_ARGS, "--pi-report", str(out))
    assert res.exit_code != 0
    assert out.read_text(encoding="utf-8") == build_pi_report(NarrativeOrchestrator.last_result)
