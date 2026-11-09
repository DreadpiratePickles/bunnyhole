"""Engine audit M7: classify_seed_type must validate, not pattern-guess.

Covers the misclassifications called out in the audit (label:text as credential, IPv6, N26 as
aircraft, pure-digit bitcoin, invalid dotted-quad as ip, john.smith/node.js as domain) plus the
positives that must keep working.
"""

from __future__ import annotations

import pytest

from bunnyhole.engine.orchestrator import classify_seed_type, mask_credential

# (seed, expected lead_type)
_NEGATIVES = [
    ("Acme: Holdings Ltd", "company"),       # label: text, secret has spaces -> not a credential
    ("Re: Mueller report", "company"),       # label: text -> not a credential
    ("2001:db8::1", "ip"),                   # IPv6 literal -> ip, not credential
    ("::1", "ip"),                           # IPv6 loopback
    ("N26", "username"),                     # brand, not an aircraft tail
    ("999.999.999.999", "company"),          # impossible octets -> not ip, not phone
    ("john.smith", "company"),               # '.smith' is not a TLD
    ("node.js", "company"),                  # '.js' is not a TLD
    ("a1b2c3d4" * 8, "company"),             # 64-char hex hash -> not bitcoin
    ("1" + "2" * 30, "company"),             # 31 pure digits starting with 1 -> not bitcoin
]

_POSITIVES = [
    ("ceo@acme.com:hunter2", "credential"),
    ("bob_smith:S3cretValue", "credential"),
    ("0x" + "a" * 40, "wallet"),
    ("vitalik.eth", "wallet"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bitcoin"),  # the genesis P2PKH address
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bitcoin"),
    ("N628TS", "aircraft"),
    ("192.168.0.1", "ip"),
    ("founder@uniswap.org", "email"),
    ("example.com", "domain"),
    ("https://palantir.com/about", "domain"),
    ("sub.acme.co.uk", "domain"),
    ("@vbuterin", "username"),
    ("+1-415-555-0199", "phone"),
    ("Acme Holdings Ltd", "company"),
    ("report.pdf", "document"),
]


@pytest.mark.parametrize("seed,expected", _NEGATIVES)
def test_classify_rejects_misclassifications(seed: str, expected: str) -> None:
    assert classify_seed_type(seed)[0] == expected


@pytest.mark.parametrize("seed,expected", _POSITIVES)
def test_classify_accepts_known_positives(seed: str, expected: str) -> None:
    assert classify_seed_type(seed)[0] == expected


def test_mask_credential_keeps_identifier_hides_secret() -> None:
    assert mask_credential("ceo@acme.com:hunter2") == "ceo@acme.com:****"
    assert mask_credential("justasecret") == "****"
