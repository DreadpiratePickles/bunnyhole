"""CLI flags for the PI casework loop. The orchestrator is the recording fake from the other PI CLI tests.

No network. Default ``--pi`` stays on the sweep: the new flags are passed only when the caller set them.
"""

from __future__ import annotations

import pytest
from pi_helpers import FakePIOrchestrator as FakeOrchestrator
from pi_helpers import isolate_cli
from pi_helpers import run_cli as _run

PURPOSE = "vet a counterparty before signing a supply contract"
CATEGORY = ("--purpose-category", "counterparty_due_diligence")
ENTITY = (
    "trace", "Acme Holdings Ltd", "--pi", "--case-type", "due_diligence",
    "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_cli(monkeypatch, FakeOrchestrator, stub_render=False)


@pytest.mark.parametrize("command", ["trace", "intake"])
@pytest.mark.parametrize(
    "extra",
    [
        ("--pi-loop", "casework"),
        ("--pi-budget", "40"),
    ],
)
def test_casework_flags_without_pi_exit_2(command: str, extra: tuple[str, str]) -> None:
    base = ["trace", "acme.io"] if command == "trace" else ["intake", "--org", "Acme Ltd"]
    res = _run(*base, *extra)
    assert res.exit_code == 2
    assert extra[0] in res.output
    assert "--pi" in res.output
    assert not FakeOrchestrator.instances


def test_bad_loop_exits_2() -> None:
    res = _run(*ENTITY, "--pi-loop", "deep")
    assert res.exit_code == 2
    assert "--pi-loop" in res.output
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize("budget", ["5", "401", "0"])
def test_budget_outside_10_to_400_exits_2(budget: str) -> None:
    res = _run(*ENTITY, "--pi-budget", budget)
    assert res.exit_code == 2
    assert "--pi-budget" in res.output
    assert not FakeOrchestrator.instances


def test_casework_flags_reach_the_orchestrator() -> None:
    res = _run(*ENTITY, "--pi-loop", "casework", "--pi-budget", "40")
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert kwargs["pi_loop"] == "casework"
    assert kwargs["pi_budget"] == 40
    assert kwargs["engagement"].subject_is_person is False


def test_default_pi_does_not_pass_a_loop_or_budget() -> None:
    res = _run(*ENTITY)
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert "pi_loop" not in kwargs
    assert "pi_budget" not in kwargs


def test_explicit_sweep_is_passed_through() -> None:
    res = _run(*ENTITY, "--pi-loop", "sweep")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["pi_loop"] == "sweep"


def test_intake_casework_flags_reach_the_orchestrator() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", "--pi", "--case-type", "due_diligence",
        "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY,
        "--pi-loop", "casework", "--pi-budget", "15",
    )
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert kwargs["pi_loop"] == "casework"
    assert kwargs["pi_budget"] == 15


def test_trace_with_an_extra_selector_still_forwards_the_flags() -> None:
    res = _run(*ENTITY, "--email", "ops@example.com", "--pi-loop", "casework", "--pi-budget", "12")
    assert res.exit_code == 0, res.output
    kwargs = FakeOrchestrator.instances[0].kwargs
    assert kwargs["pi_loop"] == "casework"
    assert kwargs["pi_budget"] == 12
    assert kwargs.get("intake_packet") is not None


def test_a_pi_engagement_works_the_case_file_unless_sweep_is_asked_for() -> None:
    from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
    from bunnyhole.engine.pi import CaseType, PIEngagement

    engagement = PIEngagement.model_construct(
        engagement_id="pi_default", case_type=CaseType.LOCATE, purpose=PURPOSE,
        purpose_category="service_of_process", subject_is_person=True, passive_only=True,
        matter_ref="CV-24-00123456", created_at_utc="2026-01-01T00:00:00+00:00",
    )
    assert BunnyholeOrchestrator("Jane Q Example", engagement=engagement)._use_pi_casework() is True
    assert BunnyholeOrchestrator("Jane Q Example", engagement=engagement, pi_loop="sweep")._use_pi_casework() is False
    assert BunnyholeOrchestrator("acme.io")._use_pi_casework() is False  # a plain trace never opens a case file


@pytest.mark.parametrize("command", ["trace", "intake"])
def test_chase_without_pi_exits_2(command: str) -> None:
    base = ["trace", "acme.io"] if command == "trace" else ["intake", "--org", "Acme Ltd"]
    res = _run(*base, "--chase")
    assert res.exit_code == 2
    assert "--chase" in res.output
    assert not FakeOrchestrator.instances


def test_chase_with_the_sweep_exits_2() -> None:
    res = _run(*ENTITY, "--pi-loop", "sweep", "--chase")
    assert res.exit_code == 2
    assert "lead sheet" in res.output
    assert not FakeOrchestrator.instances


def test_chase_on_a_result_without_a_case_file_says_so_and_carries_on() -> None:
    res = _run(*ENTITY, "--chase")
    assert res.exit_code == 0, res.output
    assert "no lead sheet to chase from" in res.output
