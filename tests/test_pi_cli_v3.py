"""Third hardening pass on the CLI: ``--purpose-category``, whole-run free-text screening and early credential scrub.

No network and no real ~/.bunnyhole access: the orchestrator is a recording fake and the saved profile is replaced
by a default one. The gates are a safety net, not a guarantee: the category is attested, not verified.
"""

from __future__ import annotations

import json
import re
import types
from typing import Any, Dict, List

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.pi import CaseType, PIEngagement, PurposeCategory

PURPOSE = "vet a counterparty before signing a supply contract"
ALL_CATEGORIES = [c.value for c in PurposeCategory]
runner = CliRunner()
SECRET = "Hunter2-secret-9z"


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


ENTITY = ("--pi", "--subject-type", "entity", "--purpose", PURPOSE)


# --------------------------------------------------------------------------- 1. --purpose-category


@pytest.mark.parametrize("command", ["trace", "intake"])
def test_missing_category_exits_2_listing_every_valid_value(command: str) -> None:
    base = ["trace", "Acme Holdings Ltd"] if command == "trace" else ["intake", "--org", "Acme Holdings Ltd"]
    res = _run(*base, *ENTITY)
    assert res.exit_code == 2
    out = _flat(res.output)
    assert "--purpose-category" in out and all(c in out for c in ALL_CATEGORIES)
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize("bad", ["employment", "tenancy", "credit", "insurance", "curiosity"])
def test_unknown_category_exits_2_listing_every_valid_value(bad: str) -> None:
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, "--purpose-category", bad)
    assert res.exit_code == 2
    out = _flat(res.output)
    assert bad in out and all(c in out for c in ALL_CATEGORIES)
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_every_category_runs_for_an_entity_and_is_stored_in_the_engagement(category: str) -> None:
    FakeOrchestrator.instances = []
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, "--purpose-category", category)
    assert res.exit_code == 0, res.output
    engagement = FakeOrchestrator.instances[0].kwargs["engagement"]
    assert isinstance(engagement, PIEngagement) and engagement.purpose_category == category


@pytest.mark.parametrize("category", ["regulatory_compliance_kyc", "journalism_public_interest"])
def test_person_subjects_cannot_use_the_entity_only_categories(category: str) -> None:
    res = _run(
        "trace", "Jane Doe", "--pi", "--purpose", PURPOSE, "--purpose-category", category,
        "--matter-ref", "MSA-2026-114",
    )
    assert res.exit_code == 2
    assert "private person" in _flat(res.output)
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize("category", ["judgment_enforcement", "service_of_process", "counterparty_due_diligence"])
def test_a_person_subject_needs_a_valid_matter_ref_under_every_person_category(category: str) -> None:
    args = ("trace", "Jane Doe", "--pi", "--case-type", "asset_search", "--purpose", PURPOSE,
            "--purpose-category", category)
    res = _run(*args)
    assert res.exit_code == 2 and "--matter-ref" in _flat(res.output)
    assert not FakeOrchestrator.instances
    bad = _run(*args, "--matter-ref", "TBD")
    assert bad.exit_code == 2 and "matter reference" in _flat(bad.output).lower()
    ok = _run(*args, "--matter-ref", "2026-CV-1234")
    assert ok.exit_code == 0, ok.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].purpose_category == category


def test_category_without_pi_exits_2_on_trace_and_intake() -> None:
    for base in (("trace", "acme.io"), ("intake", "--org", "Acme Ltd")):
        res = _run(*base, "--purpose-category", "asset_recovery")
        assert res.exit_code == 2
        out = _flat(res.output)
        assert "--purpose-category" in out and "--pi" in out
        assert not FakeOrchestrator.instances


def test_the_summary_panel_prints_the_attested_category(monkeypatch: pytest.MonkeyPatch) -> None:
    result = {
        "pi": {
            "engagement": {
                "engagement_id": "pi_0123456789", "case_type": "due_diligence", "matter_ref": "MSA-7",
                "purpose_category": "asset_recovery",
            }
        }
    }
    console = Console(width=240, record=True)
    monkeypatch.setattr(pi_commands, "console", console)
    pi_commands.render_pi_summary(result)
    assert "asset_recovery" in _flat(console.export_text())


def test_contradiction_between_category_and_purpose_text_is_refused_at_the_cli() -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", "--pi", "--subject-type", "entity",
        "--purpose", "Check a tenant before signing the lease",
        "--purpose-category", "litigation_support",
    )
    assert res.exit_code == 2
    out = _flat(res.output)
    assert "declared purpose contradicts the described use" in out and "FCRA" in out
    assert not FakeOrchestrator.instances


# --------------------------------------------------------------------------- 2. every free-text field is screened

CATEGORY = ("--purpose-category", "fraud_investigation")


@pytest.mark.parametrize("case_type", [c.value for c in CaseType])
def test_pursuit_wording_in_client_is_refused(case_type: str) -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", *ENTITY, *CATEGORY, "--case-type", case_type,
        "--client", "Find where my ex-girlfriend lives",
    )
    assert res.exit_code == 2
    assert "law enforcement" in _flat(res.output)
    assert not FakeOrchestrator.instances


def test_pursuit_wording_in_the_hypothesis_is_refused_on_trace_and_intake() -> None:
    hypothesis = "she blocked me everywhere, I want to locate her ex-girlfriend"
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, *CATEGORY, "--hypothesis", hypothesis)
    assert res.exit_code == 2
    res = _run("intake", "--org", "Acme Holdings Ltd", *ENTITY, *CATEGORY, "--hypothesis", hypothesis)
    assert res.exit_code == 2
    assert not FakeOrchestrator.instances


@pytest.mark.parametrize(
    "extra",
    [
        ("--dump", "Notes: she blocked me and changed her number"),
        ("--username", "doxx the guy who insulted me"),
        ("--exclude", "she-blocked-me-everywhere"),
        ("--matter-ref", "CV-24-00123456 she blocked me"),
        ("--org", "where my ex lives now"),
    ],
)
def test_pursuit_wording_in_any_other_field_is_refused(extra: tuple) -> None:
    res = _run("intake", "--org", "Acme Holdings Ltd", *ENTITY, *CATEGORY, *extra)
    assert res.exit_code == 2, res.output
    assert not FakeOrchestrator.instances


def test_eligibility_wording_in_another_field_is_refused() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", *ENTITY, *CATEGORY,
        "--hypothesis", "Tenant screening for a rental application",
    )
    assert res.exit_code == 2 and "FCRA" in _flat(res.output)
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, *CATEGORY, "--client", "Employee vetting for a finance position")
    assert res.exit_code == 2 and "FCRA" in _flat(res.output)
    assert not FakeOrchestrator.instances


def test_a_fake_matter_ref_no_longer_lifts_the_ex_partner_screen_on_non_locate_cases() -> None:
    res = _run(
        "trace", "Jane Doe", "--pi", "--case-type", "asset_search", "--purpose", "Asset search against my ex-wife",
        "--purpose-category", "fraud_investigation", "--matter-ref", "CV-24-00123456",
    )
    assert res.exit_code == 2 and "former-partner relationship" in _flat(res.output)
    ok = _run(
        "trace", "Jane Doe", "--pi", "--case-type", "asset_search", "--purpose", "Asset search against my ex-wife",
        "--purpose-category", "asset_recovery", "--matter-ref", "CV-24-00123456",
    )
    assert ok.exit_code == 0, ok.output


def test_clean_free_text_does_not_block_a_legitimate_intake() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", "--domain", "acme.example", "--email", "info@acme.example",
        "--hypothesis", "Funds moved through the parent company", "--client", "Northwind Procurement",
        *ENTITY, *CATEGORY, "--matter-ref", "MSA-2026-114",
    )
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].client == "Northwind Procurement"


# --------------------------------------------------------------------------- 3. credentials never reach the packet


def test_url_userinfo_in_the_dump_never_reaches_the_packet_in_pi_mode() -> None:
    dump = f"Check Acme at https://bob:{SECRET}@acme.com/login and also acme.io"
    res = _run("intake", "--dump", dump, *ENTITY, *CATEGORY)
    assert res.exit_code == 0, res.output
    packet = FakeOrchestrator.instances[0].kwargs["intake_packet"]
    blob = json.dumps(packet.model_dump(mode="json"))
    assert SECRET not in blob and "bob:" not in blob
    assert SECRET.lower() not in blob.lower()
    assert "acme.com" in blob  # the clean URL still yields the domain


def test_json_credentials_in_the_hypothesis_never_reach_the_packet_in_pi_mode() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", *ENTITY, *CATEGORY,
        "--hypothesis", f'config dump {{"password":"{SECRET}"}} shows the parent controls Acme',
    )
    assert res.exit_code == 0, res.output
    packet = FakeOrchestrator.instances[0].kwargs["intake_packet"]
    assert SECRET not in json.dumps(packet.model_dump(mode="json"))


def test_credentials_in_a_dump_are_still_parsed_without_pi() -> None:
    res = _run("intake", "--dump", "ceo@acme.com:hunter2pw", "--org", "Acme Ltd")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["intake_packet"].credentials


# --------------------------------------------------------------------------- 4. plumbing and help text


def test_menu_call_signature_has_the_new_option_and_it_defaults_off() -> None:
    import inspect

    for command in (cli_main.trace_command, cli_main.intake_command):
        assert "purpose_category" in inspect.signature(command).parameters


def test_help_text_describes_the_category_and_the_matter_ref_rule() -> None:
    for command in ("trace", "intake"):
        out = _flat(re.sub(r"[│╭╮╰╯─]", " ", _run(command, "--help").output))
        assert "--purpose-category" in out
        assert "judgment_enforcement" in out and "authorities_referral" in out
        assert "every person subject" in out.lower() or "every person" in out.lower()
