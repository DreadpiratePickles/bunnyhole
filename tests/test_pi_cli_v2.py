"""Second hardening pass on the CLI subject-type self-declaration check (``--subject-type entity``).

The subject type is self-declared, and declaring ``entity`` skips the person gates, so the CLI checks the seed, every
``--org`` and the email selectors for a clearly person-shaped name. The check stays conservative: entities such as
"Bombardier Inc", "Tesla", "Rosneft" and "Palantir Technologies" are accepted.
"""

from __future__ import annotations

import types
from typing import Any, Dict, List

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.pi import looks_like_natural_person_name, looks_like_person_email

PURPOSE = "vet a counterparty before signing a supply contract"
runner = CliRunner()
CATEGORY = ("--purpose-category", "counterparty_due_diligence")
PERSON_BASIS = (*CATEGORY, "--matter-ref", "MSA-2026-114")


class FakeOrchestrator:
    instances: List["FakeOrchestrator"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.graph = types.SimpleNamespace(export_markdown_dossier=lambda: "# dossier")
        FakeOrchestrator.instances.append(self)

    async def run_investigation(self) -> Dict[str, Any]:
        return {"case_id": "bh_fake", "stats": {}, "nodes": []}

    async def run_intake_investigation(self, packet: Any) -> Dict[str, Any]:
        self.packet = packet
        return {"case_id": "bh_fake", "stats": {}, "nodes": []}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeOrchestrator.instances = []
    monkeypatch.setattr(cli_main, "BunnyholeOrchestrator", FakeOrchestrator)
    monkeypatch.setattr(profile_mod, "load_profile", lambda *a, **k: profile_mod.InvestigatorProfile())
    monkeypatch.setattr(cli_main, "_render_investigation_results", lambda result: None)
    wide = Console(width=240)
    monkeypatch.setattr(cli_main, "console", wide)
    monkeypatch.setattr(pi_commands, "console", wide)


def _run(*args: str) -> Any:
    return runner.invoke(cli_main.app, list(args))


# ----------------------------------------------------------------------------- unit: name shapes

PERSON_NAMES = [
    "Jane Smith",
    "Smith, Jane",
    "Smith, Jane Marie",
    "Jane Marie Smith Jones",
    "Jane Smith, Esq.",
    "Jane Smith Jr.",
    "Dr. Jane Smith, PhD",
    "Jane Smith, MD",
    "Jane Smith (Toronto)",
    "Jane Smith 1980",
    "Jane Smith, b. 1980",
    "Ja​ne Smith",
    "Jane Smith",
    "Mr. John Q. Public",
    "Mary-Anne O'Brien",
]


@pytest.mark.parametrize("name", PERSON_NAMES)
def test_person_name_shapes_are_recognised(name: str) -> None:
    assert looks_like_natural_person_name(name) is True


ENTITY_NAMES = [
    "Bombardier Inc",
    "Tesla",
    "Rosneft",
    "Palantir Technologies",
    "Acme Holdings Ltd",
    "Acme, Inc.",
    "Smith & Sons",
    "Alpha Beta Gamma Delta",
    "Acme (Toronto)",
    "Acme 2024",
    "jane@example.com",
    "",
    "   ",
    "Deutsche Bank",
    "Esq",
]


@pytest.mark.parametrize("name", ENTITY_NAMES)
def test_entity_shapes_are_not_person_names(name: str) -> None:
    assert looks_like_natural_person_name(name) is False


@pytest.mark.parametrize(
    "email",
    ["jane.smith@gmail.com", "Jane_Smith@Yahoo.com", "john-doe@outlook.com", "jane.marie@acme.com"],
)
def test_first_last_email_local_parts_are_person_shaped(email: str) -> None:
    assert looks_like_person_email(email) is True


@pytest.mark.parametrize(
    "email",
    ["info@acme.com", "sales.team@acme.com", "jane@gmail.com", "a@b.co", "hr.office@acme.com", "x7.q@z.io",
     "support@gmail.com", "", "not-an-email", "jane.smith"],
)
def test_role_single_token_and_malformed_emails_are_not_person_shaped(email: str) -> None:
    assert looks_like_person_email(email) is False


# ----------------------------------------------------------------------------- CLI: refused

REFUSED_SEEDS = [
    "Smith, Jane",
    "Jane Marie Smith Jones",
    "Jane Smith, Esq.",
    "Jane Smith (Toronto)",
    "Jane Smith 1980",
    "Ja​ne Smith",
    "Dr. Jane Smith, PhD",
]


@pytest.mark.parametrize("seed", REFUSED_SEEDS)
def test_entity_declared_person_shaped_trace_seed_is_refused(seed: str) -> None:
    res = _run("trace", seed, "--pi", "--subject-type", "entity", "--purpose", PURPOSE)
    assert res.exit_code == 2, res.output
    assert "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize("seed", REFUSED_SEEDS)
def test_entity_declared_person_shaped_org_is_refused_on_intake(seed: str) -> None:
    res = _run("intake", "--org", seed, "--pi", "--subject-type", "entity", "--purpose", PURPOSE)
    assert res.exit_code == 2, res.output
    assert not FakeOrchestrator.instances


def test_every_org_is_checked_not_only_the_first() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", "--org", "Jane Smith", "--org", "Globex Corp",
        "--pi", "--subject-type", "entity", "--purpose", PURPOSE,
    )
    assert res.exit_code == 2, res.output
    assert "Jane Smith" in res.output and "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


def test_email_only_intake_with_a_person_shaped_address_is_refused() -> None:
    res = _run("intake", "--email", "jane.smith@gmail.com", "--pi", "--subject-type", "entity", "--purpose", PURPOSE)
    assert res.exit_code == 2, res.output
    assert "jane.smith@gmail.com" in res.output and "--confirm-entity" in res.output
    assert not FakeOrchestrator.instances


def test_free_mail_person_email_is_refused_even_next_to_an_org() -> None:
    res = _run(
        "intake", "--org", "Acme Ltd", "--email", "jane.smith@gmail.com",
        "--pi", "--subject-type", "entity", "--purpose", PURPOSE,
    )
    assert res.exit_code == 2, res.output


def test_trace_seed_that_is_a_person_email_is_refused() -> None:
    res = _run("trace", "jane.smith@gmail.com", "--pi", "--subject-type", "entity", "--purpose", PURPOSE)
    assert res.exit_code == 2, res.output


def test_trace_forwarding_to_intake_checks_the_seed() -> None:
    res = _run(
        "trace", "Smith, Jane", "--domain", "acme.io", "--pi", "--subject-type", "entity", "--purpose", PURPOSE
    )
    assert res.exit_code == 2, res.output


# ----------------------------------------------------------------------------- CLI: accepted

@pytest.mark.parametrize(
    "seed", ["Bombardier Inc", "Tesla", "Rosneft", "Palantir Technologies", "Alpha Beta Gamma Delta"]
)
def test_conservative_entity_seeds_are_accepted(seed: str) -> None:
    res = _run("trace", seed, "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY)
    assert res.exit_code == 0, res.output


def test_org_plus_corporate_email_and_domain_is_accepted() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", "--email", "jane.smith@acme.com", "--domain", "acme.com",
        "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY,
    )
    assert res.exit_code == 0, res.output


def test_role_email_only_intake_is_accepted() -> None:
    res = _run("intake", "--email", "info@acme.com", "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY)
    assert res.exit_code == 0, res.output


def test_confirm_entity_overrides_every_check() -> None:
    res = _run(
        "intake", "--org", "Acme Ltd", "--org", "Jane Smith", "--email", "jane.smith@gmail.com",
        "--pi", "--subject-type", "entity", "--purpose", PURPOSE, *CATEGORY, "--confirm-entity",
    )
    assert res.exit_code == 0, res.output


def test_person_subject_type_is_never_checked() -> None:
    res = _run("intake", "--org", "Jane Smith", "--email", "jane.smith@gmail.com", "--pi", "--purpose", PURPOSE, *PERSON_BASIS)
    assert res.exit_code == 0, res.output


# ----------------------------------------------------------------------------- CLI: gates v2 reach the CLI


def test_invalid_matter_ref_is_refused_at_the_cli() -> None:
    res = _run(
        "trace", "Jane Smith", "--pi", "--case-type", "locate", "--purpose", "serve papers on a judgment debtor",
        "--purpose-category", "service_of_process", "--matter-ref", "TBD",
    )
    assert res.exit_code == 2 and "matter reference" in " ".join(res.output.split()).lower()
    ok = _run(
        "trace", "Jane Smith", "--pi", "--case-type", "locate", "--purpose", "serve papers on a judgment debtor",
        "--purpose-category", "service_of_process", "--matter-ref", "23-CV-1182",
    )
    assert ok.exit_code == 0, ok.output


def test_entity_declared_pursuit_purpose_is_refused_at_the_cli() -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", "--pi", "--subject-type", "entity", "--case-type", "asset_search",
        "--purpose", "Find my ex-wife's current address, she blocked me",
    )
    assert res.exit_code == 2, res.output
    assert "law enforcement" in " ".join(res.output.split()).lower()
