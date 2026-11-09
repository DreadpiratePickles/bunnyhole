"""Fourth hardening pass on the CLI: credential-shaped text in --purpose/--client/--matter-ref is refused (exit 2),
never stored or echoed, and the ``--purpose-category`` help text lists the real person set from the code constant.

No network and no real ~/.bunnyhole access: the orchestrator is a recording fake and the saved profile is replaced
by a default one.
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any, Dict, List

import pytest
import typer.main
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.pi_types import PERSON_PURPOSE_CATEGORIES, PurposeCategory

PURPOSE = "vet a counterparty before signing a supply contract"
CATEGORY = "counterparty_due_diligence"
SECRET = "Zq7-secret"
runner = CliRunner()


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


def _flat(output: str) -> str:
    return " ".join(output.split())


def _base(command: str) -> List[str]:
    return ["trace", "Acme Holdings Ltd"] if command == "trace" else ["intake", "--org", "Acme Holdings Ltd"]


def _entity_args(purpose: str = PURPOSE) -> List[str]:
    return ["--pi", "--subject-type", "entity", "--purpose", purpose, "--purpose-category", CATEGORY]


SECRET_FIELDS = {
    "--purpose": ("--purpose", f"vet a counterparty before signing a supply contract password: {SECRET}"),
    "--client": ("--client", f"Northwind password: {SECRET}"),
    "--matter-ref": ("--matter-ref", f"MSA-2026-114 pw={SECRET}"),
}


@pytest.mark.parametrize("command", ["trace", "intake"])
@pytest.mark.parametrize("flag", sorted(SECRET_FIELDS))
def test_credential_shaped_text_in_purpose_client_or_matter_ref_exits_2_without_echoing_it(
    command: str, flag: str, tmp_path: Path
) -> None:
    report = tmp_path / "report.md"
    json_out = tmp_path / "out.json"
    args = [*_base(command), *_entity_args(), "--pi-report", str(report), "--json", str(json_out)]
    option, value = SECRET_FIELDS[flag]
    if option == "--purpose":
        args[args.index("--purpose") + 1] = value
    else:
        args += [option, value]
    res = _run(*args)
    assert res.exit_code == 2, res.output
    out = _flat(res.output)
    assert f"credential-shaped text found in {flag}" in out
    assert "remove it; credentials are not used in PI mode" in out
    assert SECRET not in res.output and "Zq7" not in res.output
    assert not FakeOrchestrator.instances
    assert not report.exists() and not json_out.exists()


@pytest.mark.parametrize(
    "shape", [f"bob@acme.com:{SECRET}", f"https://bob:{SECRET}@acme.com/", f'{{"password":"{SECRET}"}}']
)
def test_other_credential_shapes_in_the_client_field_are_refused_too(shape: str) -> None:
    res = _run(*_base("trace"), *_entity_args(), "--client", f"Northwind {shape}")
    assert res.exit_code == 2
    assert "credential-shaped text found in --client" in _flat(res.output)
    assert SECRET not in res.output


def test_a_clean_client_and_matter_ref_still_run_and_are_stored_verbatim() -> None:
    res = _run(
        *_base("intake"), *_entity_args(), "--client", "Northwind Procurement Ltd", "--matter-ref", "MSA-2026-114",
    )
    assert res.exit_code == 0, res.output
    engagement = FakeOrchestrator.instances[0].kwargs["engagement"]
    assert engagement.client == "Northwind Procurement Ltd" and engagement.matter_ref == "MSA-2026-114"


def test_the_refusal_also_comes_before_the_subject_type_check() -> None:
    res = _run(
        "trace", "Jane Doe", "--pi", "--subject-type", "entity", "--purpose", PURPOSE,
        "--purpose-category", CATEGORY, "--client", f"pw={SECRET}",
    )
    assert res.exit_code == 2
    assert "credential-shaped text found in --client" in _flat(res.output)


def test_resolve_pi_flags_refuses_directly_for_each_field() -> None:
    for field in ("purpose", "client", "matter_ref"):
        kwargs: Dict[str, Any] = {
            "pi": True, "case_type": None, "purpose": PURPOSE, "client": None, "matter_ref": None,
            "subject_type": pi_commands.SubjectType.ENTITY, "pi_jurisdiction": None, "pi_report": None,
            "persona": None, "purpose_category": CATEGORY,
        }
        kwargs[field] = f"{PURPOSE if field == 'purpose' else 'Northwind'} password: {SECRET}"
        with pytest.raises(Exception) as caught:
            pi_commands.resolve_pi_flags(**kwargs)
        assert getattr(caught.value, "exit_code", None) == 2


# --------------------------------------------------------------------------- D5. help text from the code constant


def _option_help(command: str, option: str) -> str:
    click_command = typer.main.get_command(cli_main.app)
    for param in click_command.commands[command].params:  # type: ignore[attr-defined]
        if param.name == option:
            return str(param.help)
    raise AssertionError(option)


@pytest.mark.parametrize("command", ["trace", "intake"])
def test_purpose_category_help_lists_every_category_and_every_person_category(command: str) -> None:
    text = _option_help(command, "purpose_category")
    for category in PurposeCategory:
        assert category.value in text
    person = [c.value for c in PurposeCategory if c in PERSON_PURPOSE_CATEGORIES]
    assert len(person) == 7
    sentence = text.split("A person subject is limited to")[1]
    assert all(value in sentence for value in person)
    assert not any(c.value in sentence for c in PurposeCategory if c not in PERSON_PURPOSE_CATEGORIES)
    assert "first six" not in text


def test_the_help_constant_is_derived_not_hand_typed() -> None:
    assert pi_commands.purpose_category_help() == pi_commands.PURPOSE_CATEGORY_HELP
    person = ", ".join(c.value for c in PurposeCategory if c in PERSON_PURPOSE_CATEGORIES)
    assert person in pi_commands.PURPOSE_CATEGORY_HELP


def test_acceptable_use_states_credentials_are_refused_or_dropped() -> None:
    text = (Path(__file__).resolve().parent.parent / "ACCEPTABLE_USE.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "credentials and credential-shaped text are refused or dropped" in flat
    assert "credential-shaped text in `--purpose`, `--client` and `--matter-ref`" in flat
    assert "credentials found in an intake dump or packet are dropped and scrubbed" in flat
    assert "credentials in intake packets and dumps are dropped," not in flat  # the old, inaccurate claim
