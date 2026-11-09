"""CLI input-hardening tests for the PI stream (the core ``--pi`` flag tests are in ``test_pi_cli.py``).

* Subject-type self-declaration: declaring ``--subject-type entity`` skips the person gates, so the CLI checks the
  seed, every ``--org`` and the email selectors for a clearly person-shaped name. The check stays conservative:
  entities such as "Bombardier Inc", "Tesla", "Rosneft" and "Palantir Technologies" are accepted.
* ``--purpose-category``, whole-run free-text screening and the early credential scrub (the category is attested,
  not verified).
* Credential-shaped text in ``--purpose``/``--client``/``--matter-ref`` is refused (exit 2), never stored or echoed,
  and the ``--purpose-category`` help text lists the real person set from the code constant.

No network and no real ~/.bunnyhole access: the orchestrator is a recording fake, the saved profile is replaced by a
default one and result rendering is silenced. The gates are a safety net, not a guarantee.
"""

# Replaces: test_pi_cli_v2.py, test_pi_cli_v3.py, test_pi_cli_v4.py (consolidated 2026-11-09).

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest
import typer.main
from pi_helpers import FakeOrchestrator, isolate_cli
from pi_helpers import run_cli as _run
from rich.console import Console

from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine.pi import CaseType, PIEngagement, looks_like_natural_person_name, looks_like_person_email
from bunnyhole.engine.pi_types import PERSON_PURPOSE_CATEGORIES, PurposeCategory

# ==============================================================================================================
# Shared setup: the recording fake orchestrator, default profile and silenced rendering
# ==============================================================================================================


PURPOSE = "vet a counterparty before signing a supply contract"
CATEGORY = ("--purpose-category", "counterparty_due_diligence")
PERSON_BASIS = (*CATEGORY, "--matter-ref", "MSA-2026-114")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_cli(monkeypatch, FakeOrchestrator)


# ==============================================================================================================
# Subject-type self-declaration (--subject-type entity): person-shaped names are refused
# ==============================================================================================================

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


# ----------------------------------------------------------------------------- CLI: the second-pass gates reach the CLI


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


# ==============================================================================================================
# --purpose-category, every free-text field screened, credentials never reach the packet
# ==============================================================================================================


ALL_CATEGORIES = [c.value for c in PurposeCategory]
PACKET_SECRET = "Hunter2-secret-9z"


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

FRAUD_CATEGORY = ("--purpose-category", "fraud_investigation")


@pytest.mark.parametrize("case_type", [c.value for c in CaseType])
def test_pursuit_wording_in_client_is_refused(case_type: str) -> None:
    res = _run(
        "trace", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY, "--case-type", case_type,
        "--client", "Find where my ex-girlfriend lives",
    )
    assert res.exit_code == 2
    assert "law enforcement" in _flat(res.output)
    assert not FakeOrchestrator.instances


def test_pursuit_wording_in_the_hypothesis_is_refused_on_trace_and_intake() -> None:
    hypothesis = "she blocked me everywhere, I want to locate her ex-girlfriend"
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY, "--hypothesis", hypothesis)
    assert res.exit_code == 2
    res = _run("intake", "--org", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY, "--hypothesis", hypothesis)
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
    res = _run("intake", "--org", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY, *extra)
    assert res.exit_code == 2, res.output
    assert not FakeOrchestrator.instances


def test_eligibility_wording_in_another_field_is_refused() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY,
        "--hypothesis", "Tenant screening for a rental application",
    )
    assert res.exit_code == 2 and "FCRA" in _flat(res.output)
    res = _run("trace", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY, "--client", "Employee vetting for a finance position")
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
        *ENTITY, *FRAUD_CATEGORY, "--matter-ref", "MSA-2026-114",
    )
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[0].kwargs["engagement"].client == "Northwind Procurement"


# --------------------------------------------------------------------------- 3. credentials never reach the packet


def test_url_userinfo_in_the_dump_never_reaches_the_packet_in_pi_mode() -> None:
    dump = f"Check Acme at https://bob:{PACKET_SECRET}@acme.com/login and also acme.io"
    res = _run("intake", "--dump", dump, *ENTITY, *FRAUD_CATEGORY)
    assert res.exit_code == 0, res.output
    packet = FakeOrchestrator.instances[0].kwargs["intake_packet"]
    blob = json.dumps(packet.model_dump(mode="json"))
    assert PACKET_SECRET not in blob and "bob:" not in blob
    assert PACKET_SECRET.lower() not in blob.lower()
    assert "acme.com" in blob  # the clean URL still yields the domain


def test_json_credentials_in_the_hypothesis_never_reach_the_packet_in_pi_mode() -> None:
    res = _run(
        "intake", "--org", "Acme Holdings Ltd", *ENTITY, *FRAUD_CATEGORY,
        "--hypothesis", f'config dump {{"password":"{PACKET_SECRET}"}} shows the parent controls Acme',
    )
    assert res.exit_code == 0, res.output
    packet = FakeOrchestrator.instances[0].kwargs["intake_packet"]
    assert PACKET_SECRET not in json.dumps(packet.model_dump(mode="json"))


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


# ==============================================================================================================
# Credential-shaped --purpose/--client/--matter-ref refused; help text from the code constant
# ==============================================================================================================


DUE_DILIGENCE_CATEGORY = "counterparty_due_diligence"
SECRET = "Zq7-secret"


def _base(command: str) -> List[str]:
    return ["trace", "Acme Holdings Ltd"] if command == "trace" else ["intake", "--org", "Acme Holdings Ltd"]


def _entity_args(purpose: str = PURPOSE) -> List[str]:
    return ["--pi", "--subject-type", "entity", "--purpose", purpose, "--purpose-category", DUE_DILIGENCE_CATEGORY]


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
        "--purpose-category", DUE_DILIGENCE_CATEGORY, "--client", f"pw={SECRET}",
    )
    assert res.exit_code == 2
    assert "credential-shaped text found in --client" in _flat(res.output)


def test_resolve_pi_flags_refuses_directly_for_each_field() -> None:
    for field in ("purpose", "client", "matter_ref"):
        kwargs: Dict[str, Any] = {
            "pi": True, "case_type": None, "purpose": PURPOSE, "client": None, "matter_ref": None,
            "subject_type": pi_commands.SubjectType.ENTITY, "pi_jurisdiction": None, "pi_report": None,
            "persona": None, "purpose_category": DUE_DILIGENCE_CATEGORY,
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
