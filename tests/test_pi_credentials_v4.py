"""Fourth hardening pass on the PI credential scrubber: no quadratic (ReDoS) behaviour on adversarial text.

A pasted minified blob, a long hex string or a hostile dump must never hang ``intake --dump`` in PI mode. Every
timing bound here is deliberately generous (2 s for 300 KB; the real figure is a small fraction of that), so a slow
CI machine cannot flake them while a quadratic pattern (seconds to minutes on 300 KB) still fails.
"""

from __future__ import annotations

import time
from typing import Callable, Dict

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


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_scrubbing_300kb_of_adversarial_text_is_fast(name: str) -> None:
    text = ADVERSARIAL[name]
    assert len(text) >= SIZE
    assert _seconds(scrub_credential_text_full, text) < LIMIT_S, name


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_the_final_result_net_is_fast_on_adversarial_text(name: str) -> None:
    assert _seconds(redact_value, {"k": ADVERSARIAL[name]}, ["Hunter2-secret"]) < LIMIT_S, name


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
