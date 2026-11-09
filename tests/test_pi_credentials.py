"""Tests for PI credential scrubbing (``bunnyhole.engine.pi_credentials``).

The scrubber is a heuristic safety net: it removes the shapes below and keeps ordinary text (emails alone,
host:port, times, "Note: ...", URLs without userinfo) unchanged. A secret in a shape it does not recognise can still
pass; see the limits test.

Sections: delimiter, quoting and keyword shapes; URL userinfo, quoted-key JSON, separators and other-language
keywords; and bounded time on adversarial text (no quadratic/ReDoS behaviour: a pasted minified blob, long hex
string or hostile dump must never hang ``intake --dump`` in PI mode; the 2 s bound for 300 KB is deliberately
generous so a slow CI machine cannot flake it while a quadratic pattern still fails). The slowest timing tests
carry the ``slow`` marker (deselect with ``-m "not slow"``).
"""

# Replaces: test_pi_credentials_v2.py, test_pi_credentials_v3.py, test_pi_credentials_v4.py (consolidated 2026-11-09).

from __future__ import annotations

import json
import time
from typing import Callable, Dict, List

import pytest

from bunnyhole.engine.intake import CaseIntakePacket
from bunnyhole.engine.pi_credentials import (
    REDACTED_CREDENTIAL,
    redact_value,
    scrub_credential_text,
    scrub_credential_text_full,
    strip_packet_credentials,
)
from bunnyhole.engine.pi_identifiers import identifier_warnings, looks_like_natural_person_name

# ==============================================================================================================
# Delimiter, quoting and keyword shapes that leaked; packet level; false-positive guards
# ==============================================================================================================


SECRET = "Hunter2-secret-9z"

LEAKING_SHAPES = [
    f"bob_smith:{SECRET}",
    f"ceo@acme.com | {SECRET}",
    f"ceo@acme.com |{SECRET}",
    f"ceo@acme.com;{SECRET}",
    f"ceo@acme.com,{SECRET}",
    f"ceo@acme.com\t{SECRET}",
    f'ceo@acme.com:"{SECRET}"',
    f"ceo@acme.com:'{SECRET}'",
    f'ceo@acme.com;"{SECRET}"',
    f"ceo@acme.com {SECRET} password",
    f"password ceo@acme.com {SECRET}",
    f"cred: ceo@acme.com {SECRET}",
    f"password: {SECRET}",
    f"pw={SECRET}",
    f"pwd = {SECRET}",
    f"passwd:{SECRET}",
    f"the password is {SECRET}",
    f'password: "{SECRET}"',
    f"secret={SECRET}",
    f"user bob_smith password {SECRET}",
    f"ceo@acme.com: {SECRET}",
    f"ceo@acme.com:{SECRET}",  # the original shape still works
]


@pytest.mark.parametrize("text", LEAKING_SHAPES)
def test_every_leaking_shape_is_scrubbed_and_never_echoed(text: str) -> None:
    clean, found = scrub_credential_text(f"Acme Holdings Ltd {text} please check")
    assert SECRET not in clean, clean
    assert REDACTED_CREDENTIAL in clean
    assert found, "the removed token must be reported"
    assert clean.startswith("Acme Holdings Ltd") and clean.endswith("please check")


@pytest.mark.parametrize("secret", ["SECRET", "hunter2", "P@ssw0rd!", "x7Kq-9"])
@pytest.mark.parametrize("shape", ["ceo@acme.com | {s}", "ceo@acme.com;{s}", "bob_smith:{s}", "ceo@acme.com:\"{s}\""])
def test_other_secret_values_in_the_same_shapes(secret: str, shape: str) -> None:
    clean, _ = scrub_credential_text(shape.format(s=secret))
    assert secret not in clean


@pytest.mark.parametrize("text", LEAKING_SHAPES)
def test_removed_secret_is_added_to_the_redaction_list_for_the_result_net(text: str) -> None:
    _, _, redactions = strip_packet_credentials(CaseIntakePacket(raw_omni_text=text))
    result = {"url": f"https://x.example/?q={SECRET}", "note": text}
    assert SECRET not in str(redact_value(result, redactions))


# ----------------------------------------------------------------------------- packet-level

PACKET_FIELDS = ["emails", "usernames", "organizations", "orgs_or_names", "domains"]


@pytest.mark.parametrize("text", LEAKING_SHAPES)
def test_packet_text_fields_and_lists_are_scrubbed(text: str) -> None:
    packet = CaseIntakePacket(
        raw_omni_text=f"Acme Holdings Ltd {text} please",
        raw_omni_input=text,
        hypothesis=f"note {text} end",
        emails=[text, "keep@example.org"],
        usernames=[text],
        organizations=["Acme Holdings Ltd"],
    )
    clean, removed, redactions = strip_packet_credentials(packet)
    assert removed >= 1 and redactions
    dumped = str(clean.model_dump())
    assert SECRET not in dumped
    assert "keep@example.org" in clean.emails
    assert "Acme Holdings Ltd" in clean.organizations
    assert clean.credentials == []
    assert SECRET in str(packet.model_dump()), "the input packet is not mutated"


def test_packet_credentials_list_is_still_dropped() -> None:
    clean, removed, redactions = strip_packet_credentials(CaseIntakePacket(credentials=[f"ceo@acme.com:{SECRET}"]))
    assert clean.credentials == [] and removed == 1 and f"ceo@acme.com:{SECRET}" in redactions


# ----------------------------------------------------------------------------- false-positive guards

UNCHANGED: List[str] = [
    "ceo@acme.com",
    "Contact ceo@acme.com for details",
    "a@b.co, c@d.co and e@f.org",
    "a@b.co,c@d.co",
    "a@b.co;c@d.co",
    "a@b.co | c@d.co",
    "ceo@acme.com, Jane Smith, CFO",
    "| ceo@acme.com | Jane Smith | CFO |",
    "ceo@acme.com, ceo of Acme Holdings",
    "Reach ceo@acme.com or call +1 555 123 4567",
    "Server host:8080 and localhost:3000",
    "https://acme.example.com:8443/path?x=1",
    "Meeting at 12:30 and 9:45",
    "Note: something happened at the plant",
    "Re: supply contract",
    "mailto:ceo@acme.com",
    "version:2.0.1 built",
    "Pass the paperwork to counsel",
    "The password policy was reviewed by the auditor",
    "ssh://git@host.example:22/repo",
    "Timeline: 2024-01-05 filing",
    "Acme Holdings Ltd, Toronto; Ontario",
    "wallet 0x1234567890abcdef1234567890abcdef12345678",
]


@pytest.mark.parametrize("text", UNCHANGED)
def test_ordinary_text_is_unchanged(text: str) -> None:
    clean, found = scrub_credential_text(text)
    assert clean == text and found == []


def test_scrubbing_is_idempotent() -> None:
    once, _ = scrub_credential_text(f"x ceo@acme.com | {SECRET} y")
    twice, found = scrub_credential_text(once)
    assert once == twice and found == []


def test_redact_value_keeps_unrelated_result_text() -> None:
    value = {"a": ["https://acme.example.com:8443/x", "Note: ok", "12:30"], "b": "ceo@acme.com"}
    assert redact_value(value, []) == value


def test_short_secrets_are_not_redacted_globally_from_the_result() -> None:
    _, removed, redactions = strip_packet_credentials(CaseIntakePacket(raw_omni_text="note password: ab end"))
    assert removed == 1 and "ab" not in redactions  # too short to blank everywhere; the full token is still removed
    assert redact_value({"t": "a lab about cabs"}, redactions) == {"t": "a lab about cabs"}


# ==============================================================================================================
# URL userinfo, quoted-key JSON, separators after email/handle, other languages, whole packet
# ==============================================================================================================


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


# ==============================================================================================================
# Bounded time: no quadratic (ReDoS) behaviour on 300 KB of adversarial text
# ==============================================================================================================


SIZE = 300_000
LIMIT_S = 2.0


def _repeat(unit: str) -> str:
    return (unit * (SIZE // len(unit) + 1))[:SIZE]


ADVERSARIAL: Dict[str, str] = {
    "run_of_a": "a" * SIZE,
    "a_at": _repeat("a@"),
    "a_dot": _repeat("a."),
    "dotted_locals": _repeat("a.a@"),
    "password_eq_long_value": "password=" + "x" * (SIZE - 9),
    "password_eq_repeated": _repeat("password=x "),
    "password_colon_spaces": "password:" + " " * (SIZE - 9),
    "long_digits": "1" * SIZE,
    "unicode_lookalikes": "а" * SIZE,
    "spaced_dash": _repeat(" - "),
    "dots_dashes": _repeat(".-_"),
    "where_she": _repeat("where she "),
    "ex": _repeat("ex "),
    "email_colon_many": _repeat("a@b.co:xyz1 "),
    "email_colon_no_space_many": _repeat("a@b.co:"),
    "email_space_many": _repeat("a@b.co x "),
    "email_long_domain": "a@" + "b." * (SIZE // 2),
    "email_then_spaces": "a@b.co" + " " * (SIZE - 6),
    "json_many": _repeat('{"password":'),
    "json_pairs": _repeat('{"password":"Abc12345"} '),
    "url_userinfo": "http://" + "a:" * (SIZE // 2) + "@",
    "url_userinfo_many": _repeat("https://u:p4ss!word@h.example/ "),
    "quotes": '"' * SIZE,
    "keyword_many": _repeat("password "),
    "handles": _repeat("bob_smith:Zq7x9! "),
    "newlines": "\n" * SIZE,
}


def _seconds(fn: Callable[..., object], *args: object) -> float:
    started = time.perf_counter()
    fn(*args)
    return time.perf_counter() - started


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_scrubbing_300kb_of_adversarial_text_is_fast(name: str) -> None:
    text = ADVERSARIAL[name]
    assert len(text) >= SIZE
    assert _seconds(scrub_credential_text_full, text) < LIMIT_S, name


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_the_final_result_net_is_fast_on_adversarial_text(name: str) -> None:
    assert _seconds(redact_value, {"k": ADVERSARIAL[name]}, ["Hunter2-secret"]) < LIMIT_S, name


@pytest.mark.slow
@pytest.mark.parametrize("name", ["run_of_a", "a_dot", "password_eq_long_value", "email_colon_many", "json_pairs"])
def test_scrubbing_a_whole_packet_with_a_300kb_dump_is_fast(name: str) -> None:
    packet = CaseIntakePacket(raw_omni_text=ADVERSARIAL[name], hypothesis=ADVERSARIAL[name][:50_000])
    assert _seconds(strip_packet_credentials, packet) < LIMIT_S, name


@pytest.mark.parametrize("name", ["a_dot", "dotted_locals", "run_of_a"])
def test_name_and_email_shape_heuristics_are_fast_on_long_text(name: str) -> None:
    text = "(" * SIZE if name == "run_of_a" else ADVERSARIAL[name]
    assert _seconds(looks_like_natural_person_name, text) < LIMIT_S
    assert _seconds(identifier_warnings, {"organizations": [text]}, True) < LIMIT_S


def test_a_long_blob_before_a_real_credential_still_has_the_credential_removed() -> None:
    blob = "deadbeef" * 20_000
    clean, found = scrub_credential_text(f"{blob} ceo@acme.com:Hunter2-secret {blob}")
    assert "Hunter2-secret" not in clean and REDACTED_CREDENTIAL in clean
    assert found == ["ceo@acme.com:Hunter2-secret"]


def test_a_keyword_secret_after_a_long_blob_is_removed() -> None:
    clean, _ = scrub_credential_text("x" * 100_000 + " password: Zq7-secret9 " + "y" * 100_000)
    assert "Zq7-secret9" not in clean


@pytest.mark.parametrize(
    "text",
    [
        "bob.smith@acme.com:Hunter2-secret",
        "contact bob_smith+tag@acme.co.uk|Hunter2-secret",
        "ceo@acme.com password Zq7-secret9",
        "ceo@acme.com => Zq7-secret9",
        "  ceo@acme.com ;  Hunter2-secret",
    ],
)
def test_the_bounded_email_pattern_still_scrubs_every_ordinary_shape(text: str) -> None:
    clean, found = scrub_credential_text(text)
    assert found and "secret" not in clean.lower().replace("[credential removed]", "").replace("password", "")


def test_a_plain_email_and_a_list_of_emails_are_untouched() -> None:
    for text in ("Reach me at jane.smith@acme.com for details.", "a@b.co, Jane Smith and c@d.org"):
        assert scrub_credential_text(text) == (text, [])


def test_many_credentials_in_one_dump_are_all_removed_quickly() -> None:
    text = " ".join(f"user{i}@acme.com:Hunter{i}-secret" for i in range(8000))
    started = time.perf_counter()
    clean, found = scrub_credential_text(text)
    assert time.perf_counter() - started < LIMIT_S
    assert len(found) == 8000 and "Hunter" not in clean
