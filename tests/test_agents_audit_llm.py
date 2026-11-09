"""Audit regressions for LLM provider calls (council + synthesizer).

Requirements: keys only in headers (never URLs), every call through netutil.new_async_client (so --proxy/--tor
apply), model ids configurable by env with current defaults, failures logged as agent events (status code only,
never the key or the prompt) and an explicit fallback chain ending in the deterministic brief. No call at all when
no key is set. All HTTP is mocked with respx.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx
import pytest
import respx

from bunnyhole.engine import llm_providers, netutil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.llm_providers import complete_with_fallback
from bunnyhole.engine.models import DomainCategory, EntityType, EvidenceReceipt, GraphNode, SelectorStrength
from bunnyhole.engine.synthesizer import InvestigativeSynthesizer

KEYS = {
    "OPENROUTER_API_KEY": "sk-or-SECRET-openrouter-111",
    "GEMINI_API_KEY": "AIzaSECRET-gemini-222",
    "ANTHROPIC_API_KEY": "sk-ant-SECRET-anthropic-333",
    "OPENAI_API_KEY": "sk-SECRET-openai-444",
}
MODEL_ENV = ("BUNNYHOLE_ANTHROPIC_MODEL", "BUNNYHOLE_ANTHROPIC_FAST_MODEL", "BUNNYHOLE_OPENAI_MODEL",
             "BUNNYHOLE_GEMINI_MODEL")
PROMPT = "TOP-SECRET-CASE-EVIDENCE prompt body"

GEMINI_RE = r"https://generativelanguage\.googleapis\.com/v1beta/models/.*:generateContent"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in list(KEYS) + list(MODEL_ENV):
        monkeypatch.delenv(name, raising=False)
    netutil.set_default_proxy(None)
    yield
    netutil.set_default_proxy(None)


def _set_keys(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for name in names:
        monkeypatch.setenv(name, KEYS[name])


@pytest.fixture
def client_spy(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    built: List[Dict[str, Any]] = []
    real = llm_providers.new_async_client

    def spy(**kwargs: Any) -> httpx.AsyncClient:
        built.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(llm_providers, "new_async_client", spy)
    return built


def _ok_gemini() -> httpx.Response:
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "gemini says [R1]"}]}}]})


def _ok_anthropic() -> httpx.Response:
    return httpx.Response(200, json={"content": [{"type": "text", "text": "claude says [R1]"}]})


def _ok_openai(text: str = "openai says [R1]") -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


def _graph() -> InvestigationGraph:
    g = InvestigationGraph("llm-audit", "acme.io")
    rcpt = EvidenceReceipt(
        tool="crt_sh", domain=DomainCategory.OSINT, admiralty_code="A1", selector_strength=SelectorStrength.STRONG,
        source_url="https://crt.sh/?q=acme.io", extracted_fact="acme.io shares a TLS SAN with acme-pay.io",
        raw_snippet="san",
    )
    g.upsert_node(GraphNode(id="domain:acme.io", label="acme.io", entity_type=EntityType.DOMAIN,
                            domain=DomainCategory.OSINT, selector_strength=SelectorStrength.STRONG, receipts=[rcpt]))
    return g


# --- provider layer ----------------------------------------------------------------------------------------


def test_no_key_means_no_client_and_no_call(client_spy: List[Dict[str, Any]]) -> None:
    with respx.mock(assert_all_called=False) as router:
        anything = router.route().mock(return_value=httpx.Response(200))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert outcome.text is None
    assert outcome.reason == "no_provider_configured"
    assert outcome.attempts == []
    assert client_spy == []
    assert not anything.called


def test_keys_are_sent_only_in_headers_never_in_urls(monkeypatch: pytest.MonkeyPatch, client_spy: List[Any]) -> None:
    _set_keys(monkeypatch, *KEYS)
    with respx.mock(assert_all_called=True) as router:
        routes = {
            "openrouter": router.post(OPENROUTER_URL).mock(return_value=httpx.Response(500)),
            "gemini": router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(500)),
            "anthropic": router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(500)),
            "openai": router.post(OPENAI_URL).mock(return_value=httpx.Response(500)),
        }
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT, openrouter_model="openai/gpt-4o"))
    assert outcome.text is None and outcome.reason == "all_providers_failed"
    for route in routes.values():
        url = str(route.calls.last.request.url)
        for key in KEYS.values():
            assert key not in url
    assert routes["gemini"].calls.last.request.headers["x-goog-api-key"] == KEYS["GEMINI_API_KEY"]
    assert "key=" not in str(routes["gemini"].calls.last.request.url)
    assert routes["anthropic"].calls.last.request.headers["x-api-key"] == KEYS["ANTHROPIC_API_KEY"]
    assert routes["openai"].calls.last.request.headers["authorization"] == f"Bearer {KEYS['OPENAI_API_KEY']}"
    assert routes["openrouter"].calls.last.request.headers["authorization"] == f"Bearer {KEYS['OPENROUTER_API_KEY']}"
    assert len(client_spy) == 4


def test_every_provider_call_goes_through_new_async_client_and_honours_the_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    built: List[Dict[str, Any]] = []
    real = httpx.AsyncClient

    class Recording(real):  # type: ignore[misc,valid-type]
        def __init__(self, *a: Any, **k: Any) -> None:
            built.append(dict(k))
            super().__init__(*a, **k)

    monkeypatch.setattr(netutil.httpx, "AsyncClient", Recording)
    netutil.set_default_proxy("socks5h://127.0.0.1:9050")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=_ok_anthropic())
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert outcome.text == "claude says [R1]"
    assert built and built[-1]["proxy"] == "socks5h://127.0.0.1:9050"


def test_fallback_chain_moves_on_after_a_failure_and_records_why(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    graph = _graph()
    with respx.mock(assert_all_called=False) as router:
        router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(429))
        router.post(ANTHROPIC_URL).mock(side_effect=httpx.ConnectError("boom"))
        openai = router.post(OPENAI_URL).mock(return_value=_ok_openai())
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT, graph=graph, purpose="synthesis"))
    assert outcome.text == "openai says [R1]"
    assert outcome.provider == "openai"
    assert openai.called
    assert [(a.provider, a.status_code, a.error) for a in outcome.attempts] == [
        ("gemini", 429, "HTTP 429"),
        ("anthropic", None, "ConnectError"),
    ]
    events = [e for e in graph.logs if e.action == "LLM_PROVIDER_FAILED"]
    assert [e.target for e in events] == ["gemini", "anthropic"]
    assert "429" in events[0].detail
    for e in events:
        assert e.level == "warning"
        for key in KEYS.values():
            assert key not in e.detail
        assert PROMPT not in e.detail


def test_malformed_200_is_a_failure_not_a_silent_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={"content": []}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert outcome.text is None
    assert outcome.attempts[0].status_code == 200
    assert outcome.attempts[0].error == "EmptyOrMalformedResponse"


def test_model_defaults_and_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        route = router.post(ANTHROPIC_URL).mock(return_value=_ok_anthropic())
        asyncio.run(complete_with_fallback("sys", PROMPT))
        asyncio.run(complete_with_fallback("sys", PROMPT, fast=True))
        monkeypatch.setenv("BUNNYHOLE_ANTHROPIC_MODEL", "claude-custom-1")
        asyncio.run(complete_with_fallback("sys", PROMPT))
    import json

    models = [json.loads(c.request.content)["model"] for c in route.calls]
    assert models == ["claude-sonnet-5-5", "claude-haiku-5-5", "claude-custom-1"]

    monkeypatch.setenv("BUNNYHOLE_OPENAI_MODEL", "gpt-custom")
    monkeypatch.setenv("BUNNYHOLE_GEMINI_MODEL", "gemini-custom")
    assert llm_providers.openai_model() == "gpt-custom"
    assert llm_providers.gemini_model() == "gemini-custom"
    assert "claude-3-5-sonnet-latest" not in str(llm_providers.DEFAULT_MODELS)


def test_gemini_model_is_in_the_path_and_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY")
    monkeypatch.setenv("BUNNYHOLE_GEMINI_MODEL", "gemini-test-9")
    with respx.mock(assert_all_called=True) as router:
        route = router.post(url__regex=GEMINI_RE).mock(return_value=_ok_gemini())
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert route.calls.last.request.url.path == "/v1beta/models/gemini-test-9:generateContent"
    assert outcome.model == "gemini-test-9"


# --- synthesizer -------------------------------------------------------------------------------------------


def test_synthesizer_without_keys_makes_no_call_and_says_so(client_spy: List[Any]) -> None:
    synth = InvestigativeSynthesizer(_graph())
    res = asyncio.run(synth.synthesize_investigation([], {}, []))
    assert res["engine"] == "deterministic_evidence_synthesizer"
    assert res["llm_provider"] is None
    assert res["llm_fallback"]["reason"] == "no_provider_configured"
    assert client_spy == []


def test_synthesizer_falls_back_across_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY", "ANTHROPIC_API_KEY")
    synth = InvestigativeSynthesizer(_graph())
    with respx.mock(assert_all_called=True) as router:
        router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(403))
        router.post(ANTHROPIC_URL).mock(return_value=_ok_anthropic())
        res = asyncio.run(synth.synthesize_investigation([], {}, []))
    assert res["engine"] == "hybrid_llm_and_deterministic_synthesizer"
    assert res["llm_provider"] == "claude-sonnet-5-5"
    assert "claude says [R1]" in res["markdown_brief"]
    assert res["llm_fallback"]["failures"] == [
        {"provider": "gemini", "model": "gemini-2.5-flash", "status_code": 403, "error": "HTTP 403"}
    ]


def test_synthesizer_reports_every_failure_and_keeps_the_deterministic_brief(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    graph = _graph()
    synth = InvestigativeSynthesizer(graph)
    deterministic = synth.build_deterministic_brief([], {}, [])["markdown_brief"]
    with respx.mock(assert_all_called=True) as router:
        router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(500))
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(401))
        router.post(OPENAI_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        res = asyncio.run(synth.synthesize_investigation([], {}, []))
    assert res["engine"] == "deterministic_evidence_synthesizer"
    assert res["llm_provider"] is None
    assert res["llm_fallback"]["reason"] == "all_providers_failed"
    assert [(f["provider"], f["status_code"], f["error"]) for f in res["llm_fallback"]["failures"]] == [
        ("gemini", 500, "HTTP 500"), ("anthropic", 401, "HTTP 401"), ("openai", None, "ReadTimeout"),
    ]
    assert deterministic in res["markdown_brief"]
    assert "anthropic" in res["markdown_brief"].split("\n\n")[0]
    assert len([e for e in graph.logs if e.action == "LLM_PROVIDER_FAILED"]) == 3
