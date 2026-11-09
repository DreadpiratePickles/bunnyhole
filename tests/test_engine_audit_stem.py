"""Engine audit M8: Unicode-aware entity-stem extraction + link_sleuth uses netutil's client."""

from __future__ import annotations

import inspect

import pytest

from bunnyhole.agents import link_sleuth
from bunnyhole.agents.link_sleuth import extract_entity_stem


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Müller GmbH", "müller"),       # legal form stripped, accented stem kept intact
        ("Zürich", "zürich"),
        ("Иванов Ltd", "иванов"),        # Cyrillic survives tokenisation
        ("Société Générale", "société"),
        ("Uniswap Labs Inc.", "uniswap"),  # ASCII positive still works
        ("https://palantir.com/about", "palantir"),
        ("First Global Capital Holdings LLC", ""),  # all stopwords -> empty
    ],
)
def test_extract_entity_stem_is_unicode_aware(name: str, expected: str) -> None:
    assert extract_entity_stem(name) == expected


def test_link_sleuth_uses_netutil_client_not_bare_httpx() -> None:
    # The cooccurrence probe must route through netutil.new_async_client (proxy/Tor aware), and the
    # module must no longer import httpx directly.
    src = inspect.getsource(link_sleuth)
    assert "new_async_client(" in src
    assert "httpx.AsyncClient(" not in src
