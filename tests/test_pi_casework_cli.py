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
