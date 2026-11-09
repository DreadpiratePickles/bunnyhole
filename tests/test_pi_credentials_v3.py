"""Third hardening pass on PI credential scrubbing: URL userinfo, quoted-key JSON, more separators and keywords.

The scrubber is a heuristic safety net: it removes the shapes below and keeps ordinary text (emails alone, host:port,
times, "Note: ...", URLs without userinfo) unchanged. A secret in a shape it does not recognise can still pass.
"""

from __future__ import annotations

import json
from typing import List

import pytest

from bunnyhole.engine.intake import CaseIntakePacket
from bunnyhole.engine.pi_credentials import (
    REDACTED_CREDENTIAL,
    redact_value,
    scrub_credential_text,
    strip_packet_credentials,
)

SECRET = "Hunter2-secret-9z"


# --------------------------------------------------------------------------- 1. URL userinfo


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        (f"https://bob:{SECRET}@acme.com/login", "https://acme.com/login"),
        (f"http://bob:{SECRET}@acme.com", "http://acme.com"),
        (f"ftp://svc_user:{SECRET}@files.acme.com:2121/export.csv", "ftp://files.acme.com:2121/export.csv"),
        (f"postgres://admin:{SECRET}@db.acme.com:5432/prod", "postgres://db.acme.com:5432/prod"),
        ("https://bob:p@ss-w0rd-77@acme.com/login", "https://acme.com/login"),
        (f"https://:{SECRET}@acme.com/x", "https://acme.com/x"),
        ("https://ghp_1a2B3c4D5e6F7g8H9i@github.com/org/repo.git", "https://github.com/org/repo.git"),
    ],
)
def test_url_userinfo_is_removed_and_the_clean_url_survives(text: str, kept: str) -> None:
    clean, found = scrub_credential_text(f"See {text} for details")
    assert clean == f"See {kept} for details", clean
    assert found
    for leaked in (SECRET, "p@ss-w0rd-77", "ghp_1a2B3c4D5e6F7g8H9i", "bob:", "svc_user:", "admin:"):
        assert leaked not in clean


def test_url_userinfo_secret_is_redacted_everywhere_by_the_final_net() -> None:
    packet = CaseIntakePacket(
        raw_omni_text=f"Portal https://bob:{SECRET}@acme.com/login and a later mention of {SECRET} in notes",
        hypothesis="Acme Ltd",
    )
    clean, removed, redactions = strip_packet_credentials(packet)
    assert removed >= 1
    assert "bob:" not in clean.raw_omni_text and f":{SECRET}@" not in clean.raw_omni_text
    assert "https://acme.com/login" in clean.raw_omni_text
    result = {"urls": [f"https://keybase.io/{SECRET}", f"https://bob:{SECRET}@acme.com/x"], "note": f"pw {SECRET}"}
    scrubbed = json.dumps(redact_value(result, redactions))
    assert SECRET not in scrubbed
    assert "bob:" not in scrubbed


def test_redact_value_strips_userinfo_from_any_url_even_without_a_known_secret() -> None:
    scrubbed = redact_value({"u": "see https://carol:zq9-LL-pass@host.example/a?b=1 now"}, [])
    assert scrubbed == {"u": "see https://host.example/a?b=1 now"}


@pytest.mark.parametrize(
    "text",
    [
        "ssh://git@host.example:22/repo.git",
        "https://acme.com/login",
        "https://bob@acme.com/profile",
        "http://host.example:8080/path",
        "https://acme.com/mail?to=bob@acme.com",
        "mailto:ceo@acme.com",
    ],
)
def test_urls_without_credential_userinfo_are_untouched(text: str) -> None:
    clean, found = scrub_credential_text(f"Reference {text} noted")
    assert clean == f"Reference {text} noted"
    assert found == []


# --------------------------------------------------------------------------- 2. quoted-key JSON


@pytest.mark.parametrize(
    "text",
    [
        f'{{"password":"{SECRET}"}}',
        f'{{"pass":"{SECRET}"}}',
        f'{{"passwd": "{SECRET}"}}',
        f'{{"pwd":"{SECRET}"}}',
        f'{{"Password" : "{SECRET}"}}',
        f"{{'password': '{SECRET}'}}",
        f'{{"user":"bob","password":"{SECRET}","host":"acme.com"}}',
        f'{{"secret":"{SECRET}"}}',
        f'{{"token":"{SECRET}"}}',
        f'{{"api_key":"{SECRET}"}}',
        f'{{"apiKey":"{SECRET}"}}',
        f'{{"client_secret":"{SECRET}"}}',
        f'{{"db_password":"{SECRET}"}}',
        f'{{"login":"ceo@acme.com","password":"{SECRET}"}}',
        f'{{"passcode":"{SECRET}"}}',
        f'{{"Passwort":"{SECRET}"}}',
    ],
)
def test_json_style_credentials_are_scrubbed(text: str) -> None:
    clean, found = scrub_credential_text(f"payload {text} end")
    assert SECRET not in clean, clean
    assert REDACTED_CREDENTIAL in clean
    assert found
    assert clean.startswith("payload ") and clean.endswith(" end")


def test_json_scrub_keeps_the_other_fields() -> None:
    clean, _ = scrub_credential_text(f'{{"user":"bob","password":"{SECRET}","host":"acme.com"}}')
    assert '"user":"bob"' in clean and '"host":"acme.com"' in clean


@pytest.mark.parametrize(
    "text",
    [
        '{"password":""}',
        '{"password":null}',
        '{"token":"ETH"}',
        '{"token":"Bitcoin"}',
        '{"name":"Acme","host":"acme.com"}',
        '{"passenger":"Smith"}',
        '{"secretary":"Jane Smith"}',
    ],
)
def test_json_without_a_real_secret_is_untouched(text: str) -> None:
    clean, found = scrub_credential_text(f"payload {text} end")
    assert clean == f"payload {text} end"
    assert found == []


# --------------------------------------------------------------------------- 3. separators after email / handle


@pytest.mark.parametrize(
    "text",
    [
        f"ceo@acme.com - {SECRET}",
        f"ceo@acme.com / {SECRET}",
        f"ceo@acme.com/{SECRET}",
        f"ceo@acme.com => {SECRET}",
        f"ceo@acme.com=>{SECRET}",
        f"ceo@acme.com -> {SECRET}",
        f"ceo@acme.com = {SECRET}",
        f"ceo@acme.com={SECRET}",
        f"ceo@acme.com – {SECRET}",
        f'ceo@acme.com = "{SECRET}"',
        f"bob_smith={SECRET}",
        f"bob_smith => {SECRET}",
        f"@bobsmith = {SECRET}",
        f"api_key={SECRET}",
    ],
)
def test_more_separators_after_an_email_or_handle_are_scrubbed(text: str) -> None:
    clean, found = scrub_credential_text(f"Acme Holdings Ltd {text} please check")
    assert SECRET not in clean, clean
    assert REDACTED_CREDENTIAL in clean
    assert found
    assert clean.startswith("Acme Holdings Ltd") and clean.endswith("please check")


@pytest.mark.parametrize(
    "text",
    [
        "Jane Smith - jane@acme.com - CEO",
        "jane@acme.com - Jane Smith",
        "jane@acme.com / jane@acme.org",
        "jane@acme.com = jane@acme.org",
        "contact jane@acme.com - Director of Finance",
        "https://acme.com/path?user_id=abc&x=1",
        "https://acme.com/a?session_id=Xy12Zz98Qw",
        "width=100px height=20px",
        "version=2.0.1",
        "timeout_ms=3000",
        "host:8080 and 12:30 and Note: this is fine",
        "jane@acme.com",
        "wallet_address=0x52908400098527886E0F7030069857D2E4169EE7",
    ],
)
def test_ordinary_text_with_separators_is_untouched(text: str) -> None:
    clean, found = scrub_credential_text(f"Seen: {text} done")
    assert clean == f"Seen: {text} done", clean
    assert found == []


# --------------------------------------------------------------------------- 4. keywords in other languages


@pytest.mark.parametrize(
    "text",
    [
        f"Passwort: {SECRET}",
        f"Passwort={SECRET}",
        f"passwort {SECRET}",
        f"PASSWORT: {SECRET}",
        f"contraseña: {SECRET}",
        f"Contraseña = {SECRET}",
        f"la contraseña es {SECRET}",
        f"contrasena: {SECRET}",
        f"mdp: {SECRET}",
        f"mdp={SECRET}",
        f"mot de passe : {SECRET}",
        f"Mot de passe est {SECRET}",
        f"mot de passe: {SECRET}",
        f"passcode: {SECRET}",
        f"passcode {SECRET}",
        f"passphrase: {SECRET}",
        f"clave: {SECRET}",
        f"clave={SECRET}",
        f"ceo@acme.com {SECRET} Passwort",
        f"password => {SECRET}",
        f"password - {SECRET}",
        f"login ceo@acme.com contraseña {SECRET}",
    ],
)
def test_more_credential_keywords_are_scrubbed(text: str) -> None:
    clean, found = scrub_credential_text(f"Acme Holdings Ltd {text} please check")
    assert SECRET not in clean, clean
    assert REDACTED_CREDENTIAL in clean
    assert found
    assert clean.startswith("Acme Holdings Ltd") and clean.endswith("please check")


@pytest.mark.parametrize(
    "text",
    [
        "Passwort vergessen",
        "mot de passe oublié",
        "la contraseña del banco",
        "clave del contrato",
        "the passcode screen of the phone",
        "Passwort-Manager installed",
        "Note: contraseña reset ticket",
    ],
)
def test_keyword_mentions_without_a_secret_are_untouched(text: str) -> None:
    clean, found = scrub_credential_text(f"Seen: {text} done")
    assert clean == f"Seen: {text} done", clean
    assert found == []


# --------------------------------------------------------------------------- 5. the whole packet


def test_packet_text_fields_and_lists_are_scrubbed_for_the_new_shapes() -> None:
    selectors: List[str] = [f'{{"password":"{SECRET}"}}', f"ceo@acme.com - {SECRET}", f"https://bob:{SECRET}@acme.com/"]
    packet = CaseIntakePacket(
        hypothesis=f"portal https://bob:{SECRET}@acme.com/login, Passwort: {SECRET}",
        raw_omni_text="\n".join(selectors),
        organizations=["Acme Ltd", f"mdp={SECRET}"],
    )
    clean, removed, redactions = strip_packet_credentials(packet)
    assert removed >= 4
    blob = json.dumps(clean.model_dump(mode="json"))
    assert SECRET not in blob
    assert clean.organizations == ["Acme Ltd"]
    assert SECRET in "".join(redactions) or any(r == SECRET for r in redactions)
