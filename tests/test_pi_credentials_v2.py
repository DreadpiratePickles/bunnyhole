"""Second hardening pass on PI credential scrubbing: delimiter, quoting and keyword shapes that leaked.

The scrubber is a heuristic safety net: it removes the shapes below and keeps ordinary text (emails alone, host:port,
times, "Note: ...") unchanged. A secret in a shape it does not recognise can still pass; see the limits test.
"""

from __future__ import annotations

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
