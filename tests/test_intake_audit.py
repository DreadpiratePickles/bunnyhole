"""Audit regressions for the omni-text intake parser.

* Exclusion syntax: ``-x``, ``exclude:x``, ``ignore:x`` and ``-exclude:x`` / ``-ignore:x`` all parse to an
  exclusion of ``x`` and never leak ``x`` into the positive selectors (the README's own ``intake --dump`` example
  used ``-exclude:`` and got the scope inverted).
* ReDoS: every extractor is bounded, so long adversarial runs parse quickly (thresholds are generous; the
  pre-fix parser took several seconds on 30 KB).
* Malformed URLs (``http://a]b[c``) no longer raise ``ValueError`` out of the parser.
"""

from __future__ import annotations

import time
from typing import List

import pytest

from bunnyhole.engine.intake import SmartIntakeParser, interpret_command

# ----------------------------------------------------------------------------------------------- exclusions

EXCLUSION_TABLE = [
    ("acme.io founder@acme.io -exclude:unrelated.com", ["unrelated.com"]),
    ("acme.io -ignore:unrelated.com", ["unrelated.com"]),
    ("acme.io exclude:unrelated.com", ["unrelated.com"]),
    ("acme.io ignore:unrelated.com", ["unrelated.com"]),
    ("acme.io -unrelated.com", ["unrelated.com"]),
    ("acme.io EXCLUDE:unrelated.com", ["unrelated.com"]),
    ("acme.io -exclude:unrelated.com -ignore:other.io -third.org", ["unrelated.com", "other.io", "third.org"]),
    ("-exclude:unrelated.com acme.io", ["unrelated.com"]),
    ("acme.io\n-exclude:ignored-wallet.eth", ["ignored-wallet.eth"]),
]


@pytest.mark.parametrize(("text", "expected"), EXCLUSION_TABLE)
def test_every_exclusion_form_parses_to_the_excluded_value(text: str, expected: List[str]) -> None:
    pkt = SmartIntakeParser.parse_omni_text(text)
    assert pkt.exclusions == expected
    for value in expected:
        assert value not in pkt.domains_or_ips
        assert value not in pkt.domains
        assert value not in pkt.wallets
    assert "exclude" not in pkt.exclusions and "ignore" not in pkt.exclusions
    assert "acme.io" in pkt.domains_or_ips


def test_readme_dump_example_keeps_selectors_and_exclusion_apart() -> None:
    pkt = SmartIntakeParser.parse_omni_text("acme.io founder@acme.io -exclude:unrelated.com")
    assert pkt.exclusions == ["unrelated.com"]
    assert pkt.domains == ["acme.io"]
    assert pkt.emails == ["founder@acme.io"]


@pytest.mark.parametrize("text", ["acme-corp.io", "a-b-c.com founder@x-y.io", "bring-your-own.net"])
def test_hyphens_inside_a_token_are_not_exclusions(text: str) -> None:
    assert SmartIntakeParser.parse_omni_text(text).exclusions == []


# --------------------------------------------------------------------------------------------- malformed URL


@pytest.mark.parametrize("text", ["see http://a]b[c for details", "http://[::1 acme.io", "https://x]y acme.io"])
def test_malformed_url_is_skipped_not_raised(text: str) -> None:
    pkt = SmartIntakeParser.parse_omni_text(text)
    assert isinstance(pkt.domains_or_ips, list)
    cmd = interpret_command(text)
    assert cmd.packet is not None


def test_malformed_url_does_not_stop_other_selectors() -> None:
    pkt = SmartIntakeParser.parse_omni_text("http://a]b[c acme.io founder@acme.io")
    assert "acme.io" in pkt.domains_or_ips
    assert "founder@acme.io" in pkt.emails


def test_wellformed_url_still_yields_its_host() -> None:
    pkt = SmartIntakeParser.parse_omni_text("check https://Sub.Example.com/path?q=1 now")
    assert "sub.example.com" in pkt.domains_or_ips


# ------------------------------------------------------------------------------------------------ ReDoS

_SIZE = 100_000
ADVERSARIAL = {
    "ab-dot": "ab." * (_SIZE // 3),
    "a-at": "a@" * (_SIZE // 2),
    "a-colon": "a:" * (_SIZE // 2),
    "digits": "1" * _SIZE,
    "dots": "." * _SIZE,
    "spaces": " " * _SIZE,
    "unicode": "é" * _SIZE,
    "unicode-dot": "é." * (_SIZE // 2),
    "digit-dot": "1." * (_SIZE // 2),
    "a-dash": "a-" * (_SIZE // 2),
    "email-run": "a@b." * (_SIZE // 4),
    "email-colon": "a@b.c:" * (_SIZE // 6),
    "slash-run": "/a" * (_SIZE // 2),
    "http-run": "http://" * (_SIZE // 7),
    "plus-digits": "+1 " * (_SIZE // 3),
    "words": "word " * (_SIZE // 5),
    "dash-words": "-ab " * (_SIZE // 4),
}
_LIMIT_S = 1.0


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_parse_omni_text_is_bounded_on_adversarial_input(name: str) -> None:
    text = ADVERSARIAL[name]
    started = time.perf_counter()
    SmartIntakeParser.parse_omni_text(text)
    elapsed = time.perf_counter() - started
    assert elapsed < _LIMIT_S, f"{name}: parse_omni_text took {elapsed:.2f}s on {len(text)} chars"


@pytest.mark.parametrize("name", ["ab-dot", "email-run", "words", "digit-dot", "unicode"])
def test_interpret_command_is_bounded_on_adversarial_input(name: str) -> None:
    text = ADVERSARIAL[name]
    started = time.perf_counter()
    interpret_command(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 2 * _LIMIT_S, f"{name}: interpret_command took {elapsed:.2f}s on {len(text)} chars"


def test_bounded_regexes_still_extract_normal_selectors() -> None:
    pkt = SmartIntakeParser.parse_omni_text(
        "creds dev_ops@acme.io:Summer2025! mail first.last+tag@mail.sub.example.co.uk "
        "file ~/cases/leak_report.pdf and /tmp/a-b/board_minutes.DOCX ip 10.0.0.1"
    )
    assert "dev_ops@acme.io:Summer2025!" in pkt.credentials
    assert "first.last+tag@mail.sub.example.co.uk" in pkt.emails
    assert "~/cases/leak_report.pdf" in pkt.evidence_files
    assert "/tmp/a-b/board_minutes.DOCX" in pkt.evidence_files
    assert "10.0.0.1" in pkt.domains_or_ips
