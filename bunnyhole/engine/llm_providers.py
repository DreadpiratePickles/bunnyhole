"""Optional LLM provider calls with an explicit, logged fallback chain.

Used by the council and the synthesizer to add narrative on top of their deterministic output. Rules:

- No key, no call: a provider is tried only when its key env var is set.
- Keys travel in headers only (Gemini ``x-goog-api-key``, Anthropic ``x-api-key``, OpenAI/OpenRouter bearer),
  never in a URL, so they cannot end up in proxy logs, response observers or error messages.
- Every request goes through :func:`bunnyhole.engine.netutil.new_async_client`, so case evidence in the prompt
  only leaves through the user's chosen ``--proxy`` / ``--tor`` route.
- Model ids come from env (``BUNNYHOLE_ANTHROPIC_MODEL``, ``BUNNYHOLE_ANTHROPIC_FAST_MODEL``,
  ``BUNNYHOLE_OPENAI_MODEL``, ``BUNNYHOLE_GEMINI_MODEL``) with current defaults.
- A failed provider is recorded (provider, model, HTTP status or exception class: never the key, the prompt or
  the response body), logged as a ``LLM_PROVIDER_FAILED`` agent event, and the next configured provider is
  tried. When all fail the caller keeps its deterministic output and reports why.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

import httpx

from bunnyhole.engine.models import DomainCategory
from bunnyhole.engine.netutil import new_async_client

DEFAULT_MODELS: Dict[str, str] = {
    "anthropic": "claude-sonnet-5-5",
    "anthropic_fast": "claude-haiku-5-5",
    "openai": "gpt-5-mini",
    "gemini": "gemini-2.5-flash",
}

KEY_ENV: Dict[str, str] = {
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

#: Default order: OpenRouter first (the council's per-seat models), then the direct providers.
PROVIDER_ORDER: Tuple[str, ...] = ("openrouter", "gemini", "anthropic", "openai")

ANTHROPIC_VERSION = "2023-06-01"
_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class _Logger(Protocol):
    def log(self, agent: DomainCategory, action: str, target: str, detail: str, receipt_count: int = 0,
            level: str = "info") -> Any: ...


def _env_model(env_name: str, default_key: str) -> str:
    return os.environ.get(env_name, "").strip() or DEFAULT_MODELS[default_key]


def anthropic_model(fast: bool = False) -> str:
    """Anthropic model id: ``BUNNYHOLE_ANTHROPIC_FAST_MODEL`` / ``BUNNYHOLE_ANTHROPIC_MODEL`` or the default."""
    if fast:
        return _env_model("BUNNYHOLE_ANTHROPIC_FAST_MODEL", "anthropic_fast")
    return _env_model("BUNNYHOLE_ANTHROPIC_MODEL", "anthropic")


def openai_model() -> str:
    return _env_model("BUNNYHOLE_OPENAI_MODEL", "openai")


def gemini_model() -> str:
    return _env_model("BUNNYHOLE_GEMINI_MODEL", "gemini")


def _key(provider: str) -> str:
    return os.environ.get(KEY_ENV[provider], "").strip()


def configured_providers(order: Sequence[str] = PROVIDER_ORDER) -> List[str]:
    """Providers in ``order`` whose API key is set."""
    return [p for p in order if _key(p)]


@dataclass
class LLMAttempt:
    """One failed provider call. ``error`` is ``HTTP <status>`` or an exception class name, never a message."""

    provider: str
    model: str
    status_code: Optional[int]
    error: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def describe(self) -> str:
        return f"{self.provider} ({self.model}): {self.error}"


@dataclass
class LLMOutcome:
    text: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    attempts: List[LLMAttempt] = field(default_factory=list)
    reason: str = "ok"  # ok | no_provider_configured | all_providers_failed

    def failures(self) -> List[Dict[str, Any]]:
        return [a.as_dict() for a in self.attempts]


class _EmptyResponse(Exception):
    """A 200 whose body did not contain the expected text."""


def _build_request(
    provider: str, system_prompt: str, user_prompt: str, model: str, max_tokens: int
) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    key = _key(provider)
    if provider == "gemini":
        return (
            f"{_GEMINI_BASE}/{model}:generateContent",
            {"x-goog-api-key": key, "content-type": "application/json"},
            {
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens},
            },
        )
    if provider == "anthropic":
        return (
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json"},
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
        )
    url = (
        "https://openrouter.ai/api/v1/chat/completions"
        if provider == "openrouter"
        else "https://api.openai.com/v1/chat/completions"
    )
    body: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
    }
    if provider == "openrouter":
        body.update(temperature=0.2, max_tokens=max_tokens)
    else:
        body["max_completion_tokens"] = max_tokens  # current OpenAI models reject max_tokens / custom temperature
    return url, {"authorization": f"Bearer {key}", "content-type": "application/json"}, body


def _extract_text(provider: str, payload: Any) -> str:
    try:
        if provider == "gemini":
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
        elif provider == "anthropic":
            text = next(b["text"] for b in payload["content"] if b.get("type", "text") == "text")
        else:
            text = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, StopIteration) as exc:
        raise _EmptyResponse from exc
    if not isinstance(text, str) or not text.strip():
        raise _EmptyResponse
    return text


def _model_for(provider: str, openrouter_model: Optional[str], fast: bool) -> str:
    if provider == "openrouter":
        return openrouter_model or ""
    if provider == "gemini":
        return gemini_model()
    if provider == "anthropic":
        return anthropic_model(fast)
    return openai_model()


async def complete_with_fallback(
    system_prompt: str,
    user_prompt: str,
    *,
    providers: Sequence[str] = PROVIDER_ORDER,
    openrouter_model: Optional[str] = None,
    fast: bool = False,
    max_tokens: int = 900,
    timeout: float = 20.0,
    graph: Optional[_Logger] = None,
    purpose: str = "llm",
) -> LLMOutcome:
    """Try each configured provider in ``providers`` order until one returns text.

    Returns an :class:`LLMOutcome`; ``reason`` is ``no_provider_configured`` (no key set: nothing was sent),
    ``all_providers_failed`` (every attempt is in ``attempts``) or ``ok``.
    """
    # OpenRouter needs an explicit OpenRouter model id (the council's per-seat models); without one it is skipped.
    chain = [p for p in configured_providers(providers) if p != "openrouter" or openrouter_model]
    if not chain:
        return LLMOutcome(reason="no_provider_configured")
    outcome = LLMOutcome(reason="all_providers_failed")
    for provider in chain:
        model = _model_for(provider, openrouter_model, fast)
        url, headers, body = _build_request(provider, system_prompt, user_prompt, model, max_tokens)
        status: Optional[int] = None
        try:
            async with new_async_client(timeout=timeout) as client:
                resp = await client.post(url, headers=headers, json=body)
            status = resp.status_code
            if status != 200:
                raise httpx.HTTPStatusError(f"HTTP {status}", request=resp.request, response=resp)
            text = _extract_text(provider, resp.json())
        except httpx.HTTPStatusError:
            attempt = LLMAttempt(provider, model, status, f"HTTP {status}")
        except (_EmptyResponse, ValueError):
            attempt = LLMAttempt(provider, model, status, "EmptyOrMalformedResponse")
        except Exception as exc:  # noqa: BLE001 - recorded and logged below; transport errors must not abort a case
            attempt = LLMAttempt(provider, model, status, type(exc).__name__)
        else:
            outcome.text, outcome.provider, outcome.model, outcome.reason = text, provider, model, "ok"
            return outcome
        outcome.attempts.append(attempt)
        if graph is not None:
            graph.log(
                DomainCategory.SKEPTIC,
                "LLM_PROVIDER_FAILED",
                provider,
                f"{purpose}: {attempt.describe()}; falling back"
                + (" to the next provider" if provider != chain[-1] else " to deterministic output"),
                level="warning",
            )
    return outcome
