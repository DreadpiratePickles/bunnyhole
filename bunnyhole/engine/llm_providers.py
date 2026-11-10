"""Optional LLM provider calls with an explicit, logged fallback chain.

Used by the council and the synthesizer to add narrative on top of their deterministic output. Rules:

- No key, no call: a provider is tried only when its key env var is set.
- Keys travel in headers only (Gemini ``x-goog-api-key``, Anthropic ``x-api-key``, OpenAI/OpenRouter bearer),
  never in a URL, so they cannot end up in proxy logs, response observers or error messages.
- Every request goes through :func:`bunnyhole.engine.netutil.new_async_client`, so case evidence in the prompt
  only leaves through the user's chosen ``--proxy`` / ``--tor`` route.
- Model ids come from env (``BUNNYHOLE_ANTHROPIC_MODEL``, ``BUNNYHOLE_ANTHROPIC_FAST_MODEL``,
  ``BUNNYHOLE_OPENAI_MODEL``, ``BUNNYHOLE_GEMINI_MODEL``) with current defaults.
- A failed provider is recorded (provider, model, HTTP status or exception class, and for empty/truncated replies
  the stop reason and content block types: never the key, the prompt or the response body), logged as a
  ``LLM_PROVIDER_FAILED`` agent event, and the next configured provider is tried. When all fail the caller keeps
  its deterministic output and reports why.
- A reply cut off by the token limit is a failure, not a success (a half sentence is not an answer).
- The output budget is one shared value (:func:`llm_max_tokens`): thinking models spend it on reasoning before the
  answer, so a small budget leaves an empty or truncated ``text`` block.
"""

from __future__ import annotations

import os
import re
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

#: Output-token budget shared by the synthesizer and the council. Thinking models (the default Anthropic model
#: among them) spend part of it on a ``thinking`` block, so a small value leaves no room for the answer.
DEFAULT_MAX_TOKENS = 25000
#: Env var overriding :data:`DEFAULT_MAX_TOKENS` (a positive integer; anything else is ignored).
MAX_TOKENS_ENV = "BUNNYHOLE_LLM_MAX_TOKENS"
#: Largest ``max_tokens`` sent through OpenRouter. OpenRouter routes the council's per-seat models, and some of
#: them cap output below the global budget (``anthropic/claude-3.5-sonnet`` allows 8192, ``openai/gpt-4o`` 16384);
#: a larger request is rejected with HTTP 400 and that seat would fail every time. 8000 sits under the tightest
#: known cap. The direct providers get the full budget.
OPENROUTER_MAX_TOKENS_CAP = 8000

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


def llm_max_tokens() -> int:
    """The shared output-token budget: ``BUNNYHOLE_LLM_MAX_TOKENS`` when a positive integer, else the default."""
    raw = os.environ.get(MAX_TOKENS_ENV, "").strip()
    if raw.isascii() and raw.isdigit() and int(raw) > 0:
        return int(raw)
    return DEFAULT_MAX_TOKENS


def _key(provider: str) -> str:
    return os.environ.get(KEY_ENV[provider], "").strip()


def configured_providers(order: Sequence[str] = PROVIDER_ORDER) -> List[str]:
    """Providers in ``order`` whose API key is set."""
    return [p for p in order if _key(p)]


@dataclass
class LLMAttempt:
    """One failed provider call. ``error`` is ``HTTP <status>``, an exception class name or a fixed phrase
    (``Truncated (...)``, ``EmptyOrMalformedResponse``), never a message from the response.

    ``stop_reason`` and ``block_types`` are set for empty or truncated replies. Both are sanitised (see
    :func:`_safe_token`) because they come from the response.
    """

    provider: str
    model: str
    status_code: Optional[int]
    error: str
    stop_reason: Optional[str] = None
    block_types: Optional[List[str]] = None

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for optional in ("stop_reason", "block_types"):
            if data[optional] is None:
                del data[optional]
        return data

    def describe(self) -> str:
        text = f"{self.provider} ({self.model}): {self.error}"
        details: List[str] = []
        if self.status_code is not None and f"HTTP {self.status_code}" not in self.error:
            details.append(f"HTTP {self.status_code}")
        if self.stop_reason and f"stop_reason={self.stop_reason}" not in self.error:
            details.append(f"stop_reason={self.stop_reason}")
        if self.block_types is not None:
            details.append(f"content_blocks={self.block_types!r}")
        return f"{text} [{', '.join(details)}]" if details else text


@dataclass
class LLMOutcome:
    text: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    attempts: List[LLMAttempt] = field(default_factory=list)
    reason: str = "ok"  # ok | no_provider_configured | all_providers_failed

    def failures(self) -> List[Dict[str, Any]]:
        return [a.as_dict() for a in self.attempts]


class _BadReply(Exception):
    """A 200 that is not a usable answer. Carries only sanitised diagnostics, never response text."""

    error = "EmptyOrMalformedResponse"

    def __init__(self, stop_reason: Optional[str] = None, block_types: Optional[List[str]] = None) -> None:
        super().__init__(self.error)
        self.stop_reason = stop_reason
        self.block_types = block_types


class _EmptyResponse(_BadReply):
    """The body did not contain the expected text."""


class _Truncated(_BadReply):
    """The provider stopped because the output-token limit was reached."""

    def __init__(self, stop_reason: str, block_types: Optional[List[str]] = None) -> None:
        super().__init__(stop_reason, block_types)
        self.error = f"Truncated (stop_reason={stop_reason})"


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
        body.update(temperature=0.2, max_tokens=min(max_tokens, OPENROUTER_MAX_TOKENS_CAP))
    else:
        body["max_completion_tokens"] = max_tokens  # current OpenAI models reject max_tokens / custom temperature
    return url, {"authorization": f"Bearer {key}", "content-type": "application/json"}, body


_SAFE_TOKEN = re.compile(r"[A-Za-z0-9_.\-]{1,40}")


def _safe_token(value: Any) -> str:
    """A short identifier from the response (stop reason, block type), or ``unrecognized``.

    The values are shown to the user, so only a short ``[A-Za-z0-9_.-]`` token passes; anything else could carry
    response text.
    """
    if isinstance(value, str) and _SAFE_TOKEN.fullmatch(value):
        return value
    return "unrecognized"


def _anthropic_blocks(payload: Any) -> List[Any]:
    blocks = payload.get("content") if isinstance(payload, dict) else None
    return blocks if isinstance(blocks, list) else []


def _extract_text(provider: str, payload: Any) -> str:
    """The answer text, or raise :class:`_Truncated` / :class:`_EmptyResponse` with safe diagnostics only."""
    stop_reason: Optional[str] = None
    block_types: Optional[List[str]] = None
    truncated = False
    try:
        if provider == "anthropic":
            raw_stop = payload.get("stop_reason")
            stop_reason = _safe_token(raw_stop) if raw_stop is not None else None
            truncated = raw_stop == "max_tokens"
            blocks = _anthropic_blocks(payload)
            block_types = [_safe_token(b.get("type")) if isinstance(b, dict) else "unrecognized" for b in blocks]
            text = next(b["text"] for b in blocks if isinstance(b, dict) and b.get("type", "text") == "text")
        elif provider == "gemini":
            candidate = payload["candidates"][0]
            raw_stop = candidate.get("finishReason")
            stop_reason = _safe_token(raw_stop) if raw_stop is not None else None
            truncated = raw_stop == "MAX_TOKENS"
            parts = candidate.get("content", {}).get("parts", [])
            block_types = [
                ("thought" if p.get("thought") else "text" if "text" in p else "other") if isinstance(p, dict)
                else "unrecognized"
                for p in parts
            ]
            text = next(p["text"] for p in parts if isinstance(p, dict) and not p.get("thought") and "text" in p)
        else:
            choice = payload["choices"][0]
            raw_stop = choice.get("finish_reason")
            stop_reason = _safe_token(raw_stop) if raw_stop is not None else None
            truncated = raw_stop == "length"
            text = choice["message"]["content"]
    except (KeyError, IndexError, TypeError, StopIteration, AttributeError) as exc:
        if truncated and stop_reason:
            raise _Truncated(stop_reason, block_types) from exc
        raise _EmptyResponse(stop_reason, block_types) from exc
    if truncated and stop_reason:
        raise _Truncated(stop_reason, block_types)
    if not isinstance(text, str) or not text.strip():
        raise _EmptyResponse(stop_reason, block_types)
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
    max_tokens: Optional[int] = None,
    timeout: float = 20.0,
    graph: Optional[_Logger] = None,
    purpose: str = "llm",
) -> LLMOutcome:
    """Try each configured provider in ``providers`` order until one returns text.

    Returns an :class:`LLMOutcome`; ``reason`` is ``no_provider_configured`` (no key set: nothing was sent),
    ``all_providers_failed`` (every attempt is in ``attempts``) or ``ok``. ``max_tokens`` defaults to the shared
    :func:`llm_max_tokens` budget (OpenRouter is additionally capped, see :data:`OPENROUTER_MAX_TOKENS_CAP`).
    A reply cut off by the token limit counts as a failed attempt.
    """
    budget = llm_max_tokens() if max_tokens is None else max_tokens
    # OpenRouter needs an explicit OpenRouter model id (the council's per-seat models); without one it is skipped.
    chain = [p for p in configured_providers(providers) if p != "openrouter" or openrouter_model]
    if not chain:
        return LLMOutcome(reason="no_provider_configured")
    outcome = LLMOutcome(reason="all_providers_failed")
    for provider in chain:
        model = _model_for(provider, openrouter_model, fast)
        url, headers, body = _build_request(provider, system_prompt, user_prompt, model, budget)
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
        except _BadReply as exc:
            attempt = LLMAttempt(provider, model, status, exc.error, exc.stop_reason, exc.block_types)
        except ValueError:  # resp.json() on a non-JSON 200
            attempt = LLMAttempt(provider, model, status, _BadReply.error)
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
