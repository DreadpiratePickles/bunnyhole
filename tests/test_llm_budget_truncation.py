"""LLM token budget, truncation handling, diagnosable errors, timeouts and receipt wording.

Regression for: a thinking model (claude-sonnet-5-5) spent a 700-token budget on its ``thinking`` block, left the
``text`` block empty/truncated, and the user saw only "EmptyOrMalformedResponse". Requirements covered here:

1. one shared token budget (25000, env override, bad value falls back), OpenRouter capped to a safe value;
2. a reply cut off by the token limit is a FAILED attempt per provider and falls through;
3. ``LLMAttempt.describe()`` carries HTTP status, stop reason and content block types, never key/prompt/body text;
4. synthesizer and council use the shared budget and a 120 s timeout;
5. the synthesizer brief says "unique" receipts and also gives the attachment count from the graph stat.

All HTTP is mocked with respx; no network, no real keys.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

import httpx
import pytest
import respx

from bunnyhole.engine import council as council_mod
from bunnyhole.engine import llm_providers, netutil
from bunnyhole.engine import synthesizer as synth_mod
from bunnyhole.engine.council import InvestigativeCouncil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.llm_providers import (
    DEFAULT_MAX_TOKENS,
    MAX_TOKENS_ENV,
    OPENROUTER_MAX_TOKENS_CAP,
    LLMAttempt,
    complete_with_fallback,
    llm_max_tokens,
)
from bunnyhole.engine.models import (
    ConfidenceTier,
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
)
from bunnyhole.engine.synthesizer import InvestigativeSynthesizer

KEYS = {
    "OPENROUTER_API_KEY": "sk-or-SECRET-openrouter-111",
    "GEMINI_API_KEY": "AIzaSECRET-gemini-222",
    "ANTHROPIC_API_KEY": "sk-ant-SECRET-anthropic-333",
    "OPENAI_API_KEY": "sk-SECRET-openai-444",
}
PROMPT = "TOP-SECRET-CASE-EVIDENCE prompt body"
BODY_SECRET = "SECRET-RESPONSE-BODY-TEXT-do-not-surface"

GEMINI_RE = r"https://generativelanguage\.googleapis\.com/v1beta/models/.*:generateContent"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in list(KEYS) + [MAX_TOKENS_ENV, "BUNNYHOLE_ANTHROPIC_MODEL", "BUNNYHOLE_OPENAI_MODEL",
                              "BUNNYHOLE_GEMINI_MODEL", "BUNNYHOLE_ANTHROPIC_FAST_MODEL"]:
        monkeypatch.delenv(name, raising=False)
    netutil.set_default_proxy(None)
    yield
    netutil.set_default_proxy(None)


def _set_keys(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    for name in names:
        monkeypatch.setenv(name, KEYS[name])


def _graph() -> InvestigationGraph:
    """Two unique receipts; the first is attached to a node, a second node and an edge (4 attachments)."""
    g = InvestigationGraph("llm-budget", "acme.io")
    r1 = EvidenceReceipt(tool="crt_sh", domain=DomainCategory.OSINT, admiralty_code="A1",
                         selector_strength=SelectorStrength.STRONG, source_url="https://crt.sh/?q=acme.io",
                         extracted_fact="acme.io shares a TLS SAN with acme-pay.io", raw_snippet="san")
    r2 = EvidenceReceipt(tool="gleif", domain=DomainCategory.FIAT, admiralty_code="B2",
                         selector_strength=SelectorStrength.STRONG, source_url="https://gleif.example/acme",
                         extracted_fact="Acme Ltd is owned by Acme Holdings", raw_snippet="lei")
    a = g.upsert_node(GraphNode(id="domain:acme.io", label="acme.io", entity_type=EntityType.DOMAIN,
                                domain=DomainCategory.OSINT, receipts=[r1]))
    b = g.upsert_node(GraphNode(id="domain:acme-pay.io", label="acme-pay.io", entity_type=EntityType.DOMAIN,
                                domain=DomainCategory.OSINT, receipts=[r1]))
    g.upsert_edge(GraphEdge(source_id=a.id, target_id=b.id, relation=RelationType.LINKED_IDENTITY,
                            domain=DomainCategory.OSINT, admiralty_code="A1", confidence=0.99,
                            tier=ConfidenceTier.VERIFIED, summary="shared SAN", receipts=[r1, r2]))
    return g


def _bodies(route: Any) -> List[Dict[str, Any]]:
    return [json.loads(c.request.content) for c in route.calls]


# --- 1. shared token budget -------------------------------------------------------------------------------


def test_default_budget_is_25000_and_env_is_named() -> None:
    assert DEFAULT_MAX_TOKENS == 25000
    assert MAX_TOKENS_ENV == "BUNNYHOLE_LLM_MAX_TOKENS"
    assert llm_max_tokens() == 25000


def test_env_override_sets_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MAX_TOKENS_ENV, " 12000 ")
    assert llm_max_tokens() == 12000


@pytest.mark.parametrize("bad", ["", "   ", "abc", "0", "-5", "1.5", "1e4", "NaN"])
def test_bad_env_value_falls_back_to_the_default(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv(MAX_TOKENS_ENV, bad)
    assert llm_max_tokens() == DEFAULT_MAX_TOKENS


def test_each_provider_receives_the_shared_budget_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        gem = router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(500))
        ant = router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(500))
        oai = router.post(OPENAI_URL).mock(return_value=httpx.Response(500))
        asyncio.run(complete_with_fallback("sys", PROMPT))
    assert _bodies(gem)[0]["generationConfig"]["maxOutputTokens"] == 25000
    assert _bodies(ant)[0]["max_tokens"] == 25000
    assert _bodies(oai)[0]["max_completion_tokens"] == 25000


def test_env_override_reaches_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    monkeypatch.setenv(MAX_TOKENS_ENV, "4321")
    with respx.mock(assert_all_called=True) as router:
        ant = router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(500))
        asyncio.run(complete_with_fallback("sys", PROMPT))
    assert _bodies(ant)[0]["max_tokens"] == 4321


def test_openrouter_is_capped_below_the_global_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    # claude-3.5-sonnet (a council seat) allows only 8192 output tokens; sending 25000 would be an HTTP 400.
    assert 0 < OPENROUTER_MAX_TOKENS_CAP <= 8192
    _set_keys(monkeypatch, "OPENROUTER_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        orr = router.post(OPENROUTER_URL).mock(return_value=httpx.Response(500))
        asyncio.run(complete_with_fallback("sys", PROMPT, openrouter_model="anthropic/claude-3.5-sonnet"))
    assert _bodies(orr)[0]["max_tokens"] == OPENROUTER_MAX_TOKENS_CAP


def test_openrouter_cap_never_raises_a_smaller_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "OPENROUTER_API_KEY")
    monkeypatch.setenv(MAX_TOKENS_ENV, "1000")
    with respx.mock(assert_all_called=True) as router:
        orr = router.post(OPENROUTER_URL).mock(return_value=httpx.Response(500))
        asyncio.run(complete_with_fallback("sys", PROMPT, openrouter_model="openai/gpt-4o"))
    assert _bodies(orr)[0]["max_tokens"] == 1000


def test_cap_applies_to_openrouter_only(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        orr = router.post(OPENROUTER_URL).mock(return_value=httpx.Response(500))
        ant = router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(500))
        asyncio.run(complete_with_fallback("sys", PROMPT, openrouter_model="openai/gpt-4o"))
    assert _bodies(orr)[0]["max_tokens"] == OPENROUTER_MAX_TOKENS_CAP
    assert _bodies(ant)[0]["max_tokens"] == 25000


# --- 2. truncation is a failure ---------------------------------------------------------------------------


def _truncated(provider: str) -> httpx.Response:
    if provider == "anthropic":
        return httpx.Response(200, json={"stop_reason": "max_tokens",
                                         "content": [{"type": "text", "text": "cut off mid sen"}]})
    if provider == "gemini":
        return httpx.Response(200, json={"candidates": [{"finishReason": "MAX_TOKENS",
                                                         "content": {"parts": [{"text": "cut off mid sen"}]}}]})
    return httpx.Response(200, json={"choices": [{"finish_reason": "length",
                                                  "message": {"content": "cut off mid sen"}}]})


EXPECTED_STOP = {"anthropic": "max_tokens", "gemini": "MAX_TOKENS", "openai": "length", "openrouter": "length"}
ROUTES = {
    "anthropic": ("ANTHROPIC_API_KEY", ANTHROPIC_URL),
    "openai": ("OPENAI_API_KEY", OPENAI_URL),
    "openrouter": ("OPENROUTER_API_KEY", OPENROUTER_URL),
}


@pytest.mark.parametrize("provider", ["anthropic", "gemini", "openai", "openrouter"])
def test_truncated_reply_is_a_failed_attempt(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    key_env = {"gemini": "GEMINI_API_KEY", **{k: v[0] for k, v in ROUTES.items()}}[provider]
    _set_keys(monkeypatch, key_env)
    with respx.mock(assert_all_called=True) as router:
        if provider == "gemini":
            router.post(url__regex=GEMINI_RE).mock(return_value=_truncated(provider))
        else:
            router.post(ROUTES[provider][1]).mock(return_value=_truncated(provider))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT, openrouter_model="openai/gpt-4o"))
    assert outcome.text is None
    assert outcome.reason == "all_providers_failed"
    (attempt,) = outcome.attempts
    assert attempt.provider == provider
    assert attempt.status_code == 200
    assert attempt.error == f"Truncated (stop_reason={EXPECTED_STOP[provider]})"
    assert "cut off" not in attempt.describe()


@pytest.mark.parametrize("provider", ["anthropic", "gemini", "openrouter"])
def test_truncated_reply_falls_through_to_the_next_provider(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    key_env = {"gemini": "GEMINI_API_KEY", **{k: v[0] for k, v in ROUTES.items()}}[provider]
    _set_keys(monkeypatch, key_env, "OPENAI_API_KEY")
    chain = ["openrouter", "gemini", "anthropic", "openai"]
    with respx.mock(assert_all_called=True) as router:
        if provider == "gemini":
            router.post(url__regex=GEMINI_RE).mock(return_value=_truncated(provider))
        else:
            router.post(ROUTES[provider][1]).mock(return_value=_truncated(provider))
        router.post(OPENAI_URL).mock(return_value=httpx.Response(
            200, json={"choices": [{"finish_reason": "stop", "message": {"content": "complete answer [R1]"}}]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT, providers=chain, openrouter_model="x/y"))
    assert outcome.text == "complete answer [R1]"
    assert outcome.provider == "openai"
    assert [a.provider for a in outcome.attempts] == [provider]
    assert outcome.attempts[0].error.startswith("Truncated")


def test_openai_stop_finish_reason_and_anthropic_end_turn_still_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": "end_turn",
            "content": [{"type": "thinking", "thinking": "..."}, {"type": "text", "text": "done [R1]"}]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert outcome.text == "done [R1]"
    assert outcome.attempts == []


def test_gemini_thought_part_is_not_returned_as_the_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "GEMINI_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(200, json={"candidates": [{
            "finishReason": "STOP",
            "content": {"parts": [{"text": "private reasoning", "thought": True}, {"text": "final [R1]"}]}}]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    assert outcome.text == "final [R1]"


# --- 3. diagnosable errors ----------------------------------------------------------------------------------


def test_thinking_only_truncation_reports_status_stop_reason_and_block_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact production failure: all of max_tokens went to a thinking block."""
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": BODY_SECRET}]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    (attempt,) = outcome.attempts
    text = attempt.describe()
    assert "200" in text
    assert "max_tokens" in text
    assert "['thinking']" in text
    assert "claude-sonnet-5-5" in text
    assert attempt.as_dict()["block_types"] == ["thinking"]
    assert attempt.as_dict()["stop_reason"] == "max_tokens"


def test_empty_non_truncated_reply_reports_stop_reason_and_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": "end_turn", "content": [{"type": "thinking", "thinking": BODY_SECRET}]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    (attempt,) = outcome.attempts
    assert attempt.error == "EmptyOrMalformedResponse"
    text = attempt.describe()
    assert "EmptyOrMalformedResponse" in text and "end_turn" in text and "['thinking']" in text and "200" in text


def test_http_error_describe_shows_status_once(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "OPENAI_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(OPENAI_URL).mock(return_value=httpx.Response(400, text=BODY_SECRET))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    text = outcome.attempts[0].describe()
    assert text == "openai (gpt-5-mini): HTTP 400"
    assert BODY_SECRET not in text


def test_transport_error_is_class_name_only() -> None:
    attempt = LLMAttempt("anthropic", "m", None, "ReadTimeout")
    assert attempt.describe() == "anthropic (m): ReadTimeout"


def test_untrusted_stop_reason_and_block_types_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    """Response-controlled strings must not smuggle text (or a key) into the user-visible message."""
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": f"weird {BODY_SECRET}",
            "content": [{"type": BODY_SECRET * 4}, {"type": 7}, "not-a-block"]}))
        outcome = asyncio.run(complete_with_fallback("sys", PROMPT))
    text = outcome.attempts[0].describe()
    assert BODY_SECRET not in text
    assert BODY_SECRET not in json.dumps(outcome.attempts[0].as_dict())


def test_no_key_prompt_or_body_text_in_describe_or_logged_events(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, *KEYS)
    graph = _graph()
    with respx.mock(assert_all_called=True) as router:
        router.post(OPENROUTER_URL).mock(return_value=httpx.Response(200, json={
            "choices": [{"finish_reason": "length", "message": {"content": BODY_SECRET}}]}))
        router.post(url__regex=GEMINI_RE).mock(return_value=httpx.Response(200, json={"candidates": [{
            "finishReason": "MAX_TOKENS", "content": {"parts": [{"text": BODY_SECRET}]}}]}))
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": BODY_SECRET}]}))
        router.post(OPENAI_URL).mock(return_value=httpx.Response(500, text=BODY_SECRET))
        outcome = asyncio.run(complete_with_fallback(
            "sys", PROMPT, openrouter_model="openai/gpt-4o", graph=graph, purpose="test"))
    assert len(outcome.attempts) == 4
    blobs = [a.describe() for a in outcome.attempts] + [json.dumps(outcome.failures())]
    blobs += [e.detail for e in graph.logs if e.action == "LLM_PROVIDER_FAILED"]
    assert len(blobs) == 4 + 1 + 4
    for blob in blobs:
        for secret in [*KEYS.values(), PROMPT, BODY_SECRET]:
            assert secret not in blob


# --- 4. synthesizer and council use the shared budget and a 120 s timeout -----------------------------------


def test_timeout_constants_are_120_seconds() -> None:
    assert synth_mod.SYNTHESIS_TIMEOUT_S == 120.0
    assert council_mod.COUNCIL_LLM_TIMEOUT_S == 120.0


def test_synthesizer_passes_shared_budget_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    captured: Dict[str, Any] = {}

    async def fake(system_prompt: str, user_prompt: str, **kwargs: Any) -> llm_providers.LLMOutcome:
        captured.update(kwargs)
        return llm_providers.LLMOutcome(text="x [R1]", provider="anthropic", model="m")

    monkeypatch.setattr(synth_mod, "complete_with_fallback", fake)
    asyncio.run(InvestigativeSynthesizer(_graph()).synthesize_investigation([], {}, []))
    assert captured["max_tokens"] == 25000
    assert captured["timeout"] == 120.0

    monkeypatch.setenv(MAX_TOKENS_ENV, "9000")
    asyncio.run(InvestigativeSynthesizer(_graph()).synthesize_investigation([], {}, []))
    assert captured["max_tokens"] == 9000


def test_council_passes_shared_budget_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: Dict[str, Any] = {}

    async def fake(system_prompt: str, user_prompt: str, **kwargs: Any) -> llm_providers.LLMOutcome:
        captured.update(kwargs)
        return llm_providers.LLMOutcome(reason="no_provider_configured")

    monkeypatch.setattr(council_mod, "complete_with_fallback", fake)
    council = InvestigativeCouncil(_graph())
    asyncio.run(council._query_llm_if_configured("sys", "user", "openai/gpt-4o"))
    assert captured["max_tokens"] == 25000
    assert captured["timeout"] == 120.0


def test_synthesizer_message_explains_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_keys(monkeypatch, "ANTHROPIC_API_KEY")
    with respx.mock(assert_all_called=True) as router:
        router.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={
            "stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": BODY_SECRET}]}))
        res = asyncio.run(InvestigativeSynthesizer(_graph()).synthesize_investigation([], {}, []))
    assert res["engine"] == "deterministic_evidence_synthesizer"
    head = res["markdown_brief"].split("\n\n")[0]
    assert "Truncated (stop_reason=max_tokens)" in head and "['thinking']" in head
    assert BODY_SECRET not in res["markdown_brief"]


# --- 5. receipt wording -------------------------------------------------------------------------------------


def test_brief_distinguishes_unique_receipts_from_attachments() -> None:
    graph = _graph()
    stats = graph.to_dict()["stats"]
    synth = InvestigativeSynthesizer(graph)
    unique = len(synth._collect_indexed_receipts())
    assert unique == 2
    assert stats["total_receipts"] == 4  # r1 on two nodes and an edge, r2 on the edge
    brief = synth.build_deterministic_brief([], {}, [])["markdown_brief"]
    assert f"{unique} unique SHA-256 receipts ({stats['total_receipts']} receipt attachments across nodes and edges)" in brief
    assert "cryptographic SHA-256 receipts" not in brief
