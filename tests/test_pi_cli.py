"""CLI tests for the PI stream: ``--pi`` flags on trace/intake and the ``bunnyhole pi`` reference sub-app.

No network and no real ~/.bunnyhole access: the orchestrator is a recording fake, the saved profile is
replaced by a default one, and ``bunnyhole.engine.pi_report`` is stubbed through ``sys.modules`` so these
tests pass whether or not the real report module has landed.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.personas import Persona
from bunnyhole.engine.pi import CaseType, PIBlock, PIEngagement
from bunnyhole.engine.pi_reference import playbook_for

PURPOSE = "vet a counterparty before signing a supply contract"
runner = CliRunner()
CATEGORY = ("--purpose-category", "counterparty_due_diligence")
PERSON_BASIS = (*CATEGORY, "--matter-ref", "MSA-2026-114")


class FakeOrchestrator:
    """Records constructor kwargs; returns a minimal result carrying a PI block when an engagement is set."""

    instances: List["FakeOrchestrator"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.graph = types.SimpleNamespace(export_markdown_dossier=lambda: "# dossier")
        FakeOrchestrator.instances.append(self)

    def _result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "case_id": "bh_fake01",
            "seed_query": self.kwargs.get("seed_query", ""),
            "stats": {"total_nodes": 0, "total_edges": 0, "total_receipts": 0, "cutout_brokers": 0},
            "ach_assessment": {},
            "deep_research": {"gear": "deep", "initial_breadth": 4, "max_depth": 3},
            "interconnections": {},
            "nodes": [],
        }
        engagement: Optional[PIEngagement] = self.kwargs.get("engagement")
        if engagement is not None:
            block = PIBlock(
                engagement=engagement,
                findings=[
                    {"node_id": "a", "label": "A", "finding_label": "confirmed", "source_count": 3},
                    {"node_id": "b", "label": "B", "finding_label": "lead", "source_count": 1},
                ],
                coverage=[
                    {"source_class": "court_dockets", "searched": True, "outcome": "negative"},
                    {"source_class": "crypto_onchain", "searched": False, "outcome": "not_searched"},
                ],
                custodians=[
                    {"finding": "bank", "custodian": "the bank", "instrument": "subpoena", "jurisdiction": "us"}
                ],
            )
            result["pi"] = block.model_dump(mode="json")
        return result

    async def run_investigation(self) -> Dict[str, Any]:
        return self._result()

    async def run_intake_investigation(self, packet: Any) -> Dict[str, Any]:
        self.packet = packet
        return self._result()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOrchestrator.instances = []
    monkeypatch.setattr(cli_main, "BunnyholeOrchestrator", FakeOrchestrator)
    monkeypatch.setattr(profile_mod, "load_profile", lambda *a, **k: profile_mod.InvestigatorProfile())
    wide = Console(width=240)
    monkeypatch.setattr(cli_main, "console", wide)
    monkeypatch.setattr(pi_commands, "console", wide)


@pytest.fixture
def stub_report(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    seen: List[Dict[str, Any]] = []
    module = types.ModuleType("bunnyhole.engine.pi_report")

    def build_pi_report(result: Dict[str, Any]) -> str:
        seen.append(result)
        return "# STUB PI REPORT\n"

    module.build_pi_report = build_pi_report  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "bunnyhole.engine.pi_report", module)
    return seen


def _run(*args: str) -> Any:
    return runner.invoke(cli_main.app, list(args))


# ------------------------------------------------------------------------------------------ the gates


def test_pi_without_purpose_exits_2() -> None:
    res = _run("trace", "acme.io", "--pi")
    assert res.exit_code == 2
    assert "--purpose" in res.output
    assert not FakeOrchestrator.instances


def test_eligibility_purpose_exits_2() -> None:
    res = _run("trace", "Jane Doe", "--pi", "--purpose", "pre-employment screening of a candidate")
    assert res.exit_code == 2
    assert "FCRA" in res.output
    assert not FakeOrchestrator.instances


def test_motive_purpose_for_person_exits_2() -> None:
    res = _run(
        "trace", "Jane Doe", "--pi", "--case-type", "background",
        "--purpose", "find out where my ex-girlfriend lives now",
    )
    assert res.exit_code == 2
    assert "former partner" in res.output
    assert not FakeOrchestrator.instances


def test_person_locate_without_matter_ref_exits_2_and_with_it_runs() -> None:
    args = (
        "trace", "Jane Doe", "--pi", "--case-type", "locate", "--purpose", "serve papers on a judgment debtor",
        "--purpose-category", "service_of_process",
    )
    res = _run(*args)
    assert res.exit_code == 2
    assert "--matter-ref" in res.output
    assert not FakeOrchestrator.instances

    ok = _run(*args, "--matter-ref", "2026-CV-1234")
    assert ok.exit_code == 0, ok.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].matter_ref == "2026-CV-1234"


def test_entity_subject_may_locate_without_matter_ref() -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", "--pi", "--case-type", "locate", "--subject-type", "entity",
        "--purpose", "locate the registered office of a judgment debtor company",
        "--purpose-category", "judgment_enforcement",
    )
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].subject_is_person is False


@pytest.mark.parametrize(
    "extra",
    [
        ("--purpose", PURPOSE),
        ("--case-type", "locate"),
        ("--client", "Acme LLP"),
        ("--matter-ref", "X-1"),
        ("--subject-type", "entity"),
        ("--pi-jurisdiction", "us"),
        ("--pi-report", "report.md"),
    ],
)
@pytest.mark.parametrize("command", ["trace", "intake"])
def test_pi_only_option_without_pi_exits_2(command: str, extra: tuple) -> None:
    base = ["trace", "acme.io"] if command == "trace" else ["intake", "--org", "Acme Ltd"]
    res = _run(*base, *extra)
    assert res.exit_code == 2
    assert "--pi" in res.output
    assert extra[0] in res.output
    assert not FakeOrchestrator.instances


# ----------------------------------------------------------------------------------- plumbing (happy)


def test_valid_trace_passes_engagement_and_persona_pi() -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", "--pi", "--case-type", "due_diligence", "--purpose", PURPOSE,
        "--client", "Acme LLP", "--matter-ref", "MSA-7", "--pi-jurisdiction", "ca-on", "--subject-type", "entity",
        *CATEGORY,
    )
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    engagement = kwargs["engagement"]
    assert isinstance(engagement, PIEngagement)
    assert engagement.case_type is CaseType.DUE_DILIGENCE
    assert engagement.purpose == PURPOSE
    assert engagement.objective == playbook_for(CaseType.DUE_DILIGENCE).objective
    assert (engagement.client, engagement.matter_ref, engagement.jurisdiction) == ("Acme LLP", "MSA-7", "ca-on")
    assert kwargs["profile"].persona is Persona.PRIVATE_INVESTIGATOR
    assert kwargs["gear"] is GearMode.DEEP and kwargs["max_depth"] == 3 and kwargs["initial_breadth"] == 4
    # compact PI summary rendered under the normal results
    assert "PI SUMMARY" in res.output
    assert "1 confirmed" in res.output and "1 lead" in res.output
    assert "crypto_onchain" in res.output
    assert "Custodians named: 1" in res.output


def test_case_type_defaults_to_due_diligence_and_explicit_flags_beat_persona_defaults() -> None:
    res = _run("trace", "acme.io", "--pi", "--purpose", PURPOSE, *CATEGORY, "--depth", "1", "--subject-type", "entity")
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert kwargs["engagement"].case_type is CaseType.DUE_DILIGENCE
    assert kwargs["max_depth"] == 1  # explicit flag wins
    assert kwargs["gear"] is GearMode.DEEP  # unset flag filled by the persona


def test_explicit_persona_wins_over_pi_implied_persona() -> None:
    res = _run("trace", "acme.io", "--pi", "--purpose", PURPOSE, *PERSON_BASIS, "--persona", "compliance")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["profile"].persona is Persona.COMPLIANCE


def test_trace_without_pi_is_unchanged() -> None:
    res = _run("trace", "acme.io")
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert "engagement" not in kwargs
    assert kwargs["profile"].persona is Persona.GENERALIST
    assert "PI SUMMARY" not in res.output


def test_trace_with_extra_selectors_forwards_pi_to_intake() -> None:
    res = _run("trace", "Acme Holdings Ltd", "--domain", "acme.io", "--pi", "--purpose", PURPOSE, *PERSON_BASIS)
    assert res.exit_code == 0, res.output
    inst = FakeOrchestrator.instances[0]
    assert hasattr(inst, "packet")
    assert inst.kwargs["engagement"].purpose == PURPOSE
    assert inst.kwargs["profile"].persona is Persona.PRIVATE_INVESTIGATOR


def test_intake_valid_pi_run() -> None:
    res = _run("intake", "--org", "Acme Holdings Ltd", "--pi", "--purpose", PURPOSE, *PERSON_BASIS, "--case-type", "fraud_screen")
    assert res.exit_code == 0, res.output
    inst = FakeOrchestrator.instances[0]
    assert inst.kwargs["engagement"].case_type is CaseType.FRAUD_SCREEN
    assert inst.kwargs["profile"].persona is Persona.PRIVATE_INVESTIGATOR


def test_intake_pi_gate_refuses() -> None:
    res = _run("intake", "--org", "Jane Doe", "--pi", "--purpose", "tenant screening for a rental application")
    assert res.exit_code == 2
    assert not FakeOrchestrator.instances


# ------------------------------------------------------------------------------------------ --pi-report


def test_pi_report_writes_file_with_stubbed_builder(tmp_path: Path, stub_report: List[Dict[str, Any]]) -> None:
    out = tmp_path / "pi_report.md"
    res = _run("trace", "acme.io", "--pi", "--purpose", PURPOSE, *PERSON_BASIS, "--pi-report", str(out))
    assert res.exit_code == 0, res.output
    assert out.read_text(encoding="utf-8") == "# STUB PI REPORT\n"
    assert stub_report and stub_report[0]["case_id"] == "bh_fake01"
    assert "Saved PI Report to" in res.output


def test_pi_report_fails_clearly_when_module_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "bunnyhole.engine.pi_report", None)  # forces ImportError
    out = tmp_path / "pi_report.md"
    res = _run("trace", "acme.io", "--pi", "--purpose", PURPOSE, *PERSON_BASIS, "--pi-report", str(out))
    assert res.exit_code == 1
    assert "pi_report" in res.output
    assert not out.exists()
    assert not FakeOrchestrator.instances  # fails before spending a run


# --------------------------------------------------------------------------------------- `bunnyhole pi`


def test_pi_guide() -> None:
    res = _run("pi", "guide")
    assert res.exit_code == 0, res.output
    assert "investigation cycle" in res.output.lower()
    assert "thirteen behaviours" in res.output.lower()


def test_pi_sources_filters() -> None:
    allr = _run("pi", "sources")
    assert allr.exit_code == 0, allr.output
    assert "OpenSanctions" in allr.output
    impl = _run("pi", "sources", "--implemented", "--case-type", "due_diligence")
    assert impl.exit_code == 0, impl.output
    assert "Free PI Sources" in impl.output
    uk = _run("pi", "sources", "--jurisdiction", "uk")
    assert uk.exit_code == 0 and "Companies House" in uk.output
    bad = _run("pi", "sources", "--case-type", "nonsense")
    assert bad.exit_code == 2


def test_pi_legal_with_disclaimer() -> None:
    res = _run("pi", "legal", "--jurisdiction", "ca-on")
    assert res.exit_code == 0, res.output
    assert "PSISA" in res.output or "Private Security" in res.output
    assert "Not legal advice" in res.output
    general = _run("pi", "legal")
    assert general.exit_code == 0 and "Not legal advice" in general.output


def test_pi_playbook_every_case_type_and_bad_value() -> None:
    for case_type in CaseType:
        res = _run("pi", "playbook", case_type.value)
        assert res.exit_code == 0, res.output
        assert "Objective" in res.output and "Escalate when" in res.output and "Pitfalls" in res.output
    bad = _run("pi", "playbook", "nonsense")
    assert bad.exit_code == 2
    for case_type in CaseType:
        assert case_type.value in bad.output


def test_pi_out_of_scope() -> None:
    res = _run("pi", "out-of-scope")
    assert res.exit_code == 0, res.output
    assert "TLOxp" in res.output
    assert "Unlawful methods" in res.output


def test_menu_trace_call_still_works_without_pi() -> None:
    """The interactive menu calls trace_command with explicit kwargs; the new options must default off."""
    import inspect

    params = inspect.signature(cli_main.trace_command).parameters
    for name in ("pi", "case_type", "purpose", "client", "matter_ref", "subject_type", "pi_jurisdiction", "pi_report"):
        assert name in params


# ------------------------------------------------------------------- hardening: --cred, subject-type, grammar


@pytest.mark.parametrize(
    "base",
    [
        ("trace", "acme.io"),
        ("trace", "Acme Holdings Ltd", "--domain", "acme.io"),
        ("intake", "--org", "Acme Holdings Ltd"),
    ],
)
def test_pi_mode_refuses_cred_with_exit_2(base: tuple) -> None:
    res = _run(*base, "--pi", "--purpose", PURPOSE, "--subject-type", "entity", "--cred", "a@b.co:hunter2")
    assert res.exit_code == 2
    assert "--cred" in res.output
    assert "credential" in res.output
    assert "hunter2" not in res.output
    assert not FakeOrchestrator.instances


def test_cred_short_flag_also_refused_in_pi_mode() -> None:
    res = _run("intake", "--org", "Acme Ltd", "--pi", "--purpose", PURPOSE, "-c", "a@b.co:pw")
    assert res.exit_code == 2
    assert not FakeOrchestrator.instances


def test_cred_still_works_without_pi() -> None:
    res = _run("intake", "--org", "Acme Ltd", "--cred", "a@b.co:pw")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].packet.credentials


ENTITY_LOCATE = ("--pi", "--case-type", "locate", "--subject-type", "entity")


def test_entity_declared_person_name_is_refused_on_trace() -> None:
    res = _run("trace", "Jane Doe", *ENTITY_LOCATE, "--purpose", "find where my ex-wife moved to recently")
    assert res.exit_code == 2
    assert "Jane Doe" in res.output
    assert "--subject-type person" in res.output
    assert "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


def test_entity_declared_person_name_is_refused_on_intake_org() -> None:
    res = _run(
        "intake", "--org", "Jane Doe", "--org", "Acme Ltd", "--pi", "--subject-type", "entity", "--purpose", PURPOSE
    )
    assert res.exit_code == 2
    assert "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


def test_entity_declared_person_name_is_refused_when_trace_forwards_to_intake() -> None:
    res = _run(
        "trace", "Jane Doe", "--domain", "acme.io", "--pi", "--subject-type", "entity", "--purpose", PURPOSE
    )
    assert res.exit_code == 2
    assert "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


def test_default_person_subject_type_hits_the_motive_gate() -> None:
    res = _run("trace", "Jane Doe", *ENTITY_LOCATE[:-2], "--purpose", "find where my ex-wife moved to recently")
    assert res.exit_code == 2  # default subject-type person: motive screen refuses
    assert "former partner" in res.output


def test_confirm_entity_overrides_the_name_check() -> None:
    res = _run("trace", "Jane Doe", *ENTITY_LOCATE, "--purpose", PURPOSE, *CATEGORY, "--confirm-entity")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].subject_is_person is False


def test_confirm_entity_works_on_intake_too() -> None:
    res = _run(
        "intake", "--org", "Jane Doe", "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY, "--confirm-entity"
    )
    assert res.exit_code == 0, res.output


@pytest.mark.parametrize(
    "seed", ["Bombardier Inc", "Acme Holdings Ltd", "Deutsche Bank", "Siemens AG", "acme.io", "Acme"]
)
def test_legitimate_entity_seeds_are_not_blocked(seed: str) -> None:
    res = _run("trace", seed, "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY)
    assert res.exit_code == 0, res.output


def test_person_subject_type_is_never_name_checked() -> None:
    res = _run("trace", "Jane Doe", "--pi", "--purpose", PURPOSE, *PERSON_BASIS)
    assert res.exit_code == 0, res.output


def test_confirm_entity_without_pi_exits_2() -> None:
    for base in (("trace", "acme.io"), ("intake", "--org", "Acme Ltd")):
        res = _run(*base, "--confirm-entity")
        assert res.exit_code == 2
        assert "--confirm-entity" in res.output and "--pi" in res.output


def test_pi_only_message_grammar_singular_and_plural() -> None:
    one = _run("trace", "acme.io", "--case-type", "locate")
    assert one.exit_code == 2
    assert "--case-type only applies to" in " ".join(one.output.split())
    many = _run("trace", "acme.io", "--case-type", "locate", "--client", "X")
    assert many.exit_code == 2
    assert "only apply to" in " ".join(many.output.split())
    assert "only applies to" not in " ".join(many.output.split())


def test_hardened_purpose_gates_reach_the_cli() -> None:
    res = _run("trace", "Jane Doe", "--pi", "--purpose", "check if this candidate is safe to hire")
    assert res.exit_code == 2 and "FCRA" in res.output
    res = _run("trace", "Jane Doe", "--pi", "--case-type", "background", "--purpose", "find where my ex moved")
    assert res.exit_code == 2 and "former partner" in res.output
    ok = _run("trace", "Acme Ltd", "--pi", "--subject-type", "entity", "--purpose", "fraud in hiring of subcontractor", *CATEGORY)
    assert ok.exit_code == 0, ok.output
