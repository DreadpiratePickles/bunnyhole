"""Tests for the opt-in HTTP response observer in ``bunnyhole.engine.netutil``.

The observer exists so the PI source log can tell "the source answered HTTP 401" from "the source ran and
found nothing" without editing any agent. It must be invisible when unset. All HTTP is mocked with respx.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional, Tuple

import httpx
import pytest
import respx

from bunnyhole.engine import netutil

Seen = List[Tuple[str, Optional[int], Optional[str]]]


@pytest.fixture(autouse=True)
def _reset_observer():
    netutil.set_response_observer(None)
    yield
    netutil.set_response_observer(None)


def _collect() -> Seen:
    seen: Seen = []
    netutil.set_response_observer(lambda url, status, error: seen.append((url, status, error)))
    return seen


def test_observer_defaults_to_none_and_leaves_httpx_untouched():
    original_send = httpx.AsyncClient.send
    assert netutil.get_response_observer() is None
    assert httpx.AsyncClient.send is original_send


def test_new_async_client_reports_status_and_url_for_each_response():
    seen = _collect()
    with respx.mock:
        respx.get("https://api.example.org/a").respond(200, json={})
        respx.get("https://api.example.org/b").respond(401)

        async def go() -> None:
            async with netutil.new_async_client() as client:
                await client.get("https://api.example.org/a")
                await client.get("https://api.example.org/b")

        asyncio.run(go())
    assert seen == [
        ("https://api.example.org/a", 200, None),
        ("https://api.example.org/b", 401, None),
    ]


def test_clients_built_directly_with_httpx_are_observed_too():
    """Most agents build httpx.AsyncClient directly (not through new_async_client); they must be seen."""
    seen = _collect()
    with respx.mock:
        respx.get("https://www.courtlistener.com/api/rest/v4/search/").respond(401)

        async def go() -> None:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.get("https://www.courtlistener.com/api/rest/v4/search/", params={"q": "acme"})

        asyncio.run(go())
    assert len(seen) == 1
    assert seen[0][1] == 401 and seen[0][2] is None
    assert seen[0][0].startswith("https://www.courtlistener.com/api/rest/v4/search/")


def test_transport_errors_are_reported_and_still_raised():
    seen = _collect()
    with respx.mock:
        respx.get("https://down.example.org/").mock(side_effect=httpx.ConnectError("refused"))

        async def go() -> None:
            async with netutil.new_async_client() as client:
                await client.get("https://down.example.org/")

        with pytest.raises(httpx.ConnectError):
            asyncio.run(go())
    assert seen == [("https://down.example.org/", None, "ConnectError")]


def test_error_text_never_carries_the_exception_message_or_query_secrets():
    seen = _collect()
    with respx.mock:
        respx.get("https://down.example.org/").mock(side_effect=httpx.ReadTimeout("secret-token-abc in message"))

        async def go() -> None:
            async with netutil.new_async_client() as client:
                await client.get("https://down.example.org/")

        with pytest.raises(httpx.ReadTimeout):
            asyncio.run(go())
    assert "secret-token-abc" not in repr(seen)


def test_clearing_the_observer_restores_httpx_exactly_and_stops_reporting():
    original_send = httpx.AsyncClient.send
    seen = _collect()
    assert httpx.AsyncClient.send is not original_send  # installed only while an observer is set
    netutil.set_response_observer(None)
    assert httpx.AsyncClient.send is original_send
    with respx.mock:
        respx.get("https://api.example.org/a").respond(200)

        async def go() -> None:
            async with netutil.new_async_client() as client:
                await client.get("https://api.example.org/a")

        asyncio.run(go())
    assert seen == []


def test_setting_the_observer_twice_does_not_stack_wrappers_or_double_report():
    seen = _collect()
    seen2: Seen = []
    netutil.set_response_observer(lambda url, status, error: seen2.append((url, status, error)))
    with respx.mock:
        respx.get("https://api.example.org/a").respond(200)

        async def go() -> None:
            async with netutil.new_async_client() as client:
                await client.get("https://api.example.org/a")

        asyncio.run(go())
    assert seen == []
    assert seen2 == [("https://api.example.org/a", 200, None)]


def test_a_raising_observer_never_breaks_the_request():
    def boom(url: str, status: Optional[int], error: Optional[str]) -> None:
        raise RuntimeError("observer bug")

    netutil.set_response_observer(boom)
    with respx.mock:
        respx.get("https://api.example.org/a").respond(200, json={"ok": True})

        async def go() -> dict:
            async with netutil.new_async_client() as client:
                return (await client.get("https://api.example.org/a")).json()

        assert asyncio.run(go()) == {"ok": True}


def test_observed_response_body_is_still_readable_and_redirects_work():
    seen = _collect()
    with respx.mock:
        respx.get("https://api.example.org/old").respond(302, headers={"Location": "https://api.example.org/new"})
        respx.get("https://api.example.org/new").respond(200, text="hello")

        async def go() -> str:
            async with netutil.new_async_client(follow_redirects=True) as client:
                return (await client.get("https://api.example.org/old")).text

        assert asyncio.run(go()) == "hello"
    assert seen and seen[-1][1] == 200


def test_proxy_and_header_behaviour_of_new_async_client_is_unchanged_when_observing():
    _collect()
    client = netutil.new_async_client(headers={"X-Test": "1"}, timeout=3.0)
    assert client.headers["X-Test"] == "1"
    assert client.timeout.read == 3.0
    asyncio.run(client.aclose())
