"""PI stream source-log recorder: one :class:`SourceLogEntry` per source call, plus the passive-mode blockers.

The recorder subscribes to the investigation graph, attributes each mutation and each HTTP outcome to the source
call running in the current ``ContextVar`` context, and classifies the call as hit, negative, skipped or error.
The blocker factories replace OSINT methods that are not passive (Holehe) or that touch breach contents.
No model calls; the only clock is the UTC timestamp stamped on each entry.
Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md sections 2 and 3.1.
"""

from __future__ import annotations

import contextvars
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Coroutine, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from bunnyhole.engine import netutil
from bunnyhole.engine.pi import SourceLogEntry

logger = logging.getLogger(__name__)


class _Probe:
    """What one recorded call produced, filled by the graph subscription and the HTTP observer while it runs."""

    __slots__ = ("new_nodes", "new_edges", "new_receipts", "skips", "http_ok", "http_failures")

    def __init__(self) -> None:
        self.new_nodes = 0
        self.new_edges = 0
        self.new_receipts = 0
        self.skips: List[str] = []
        self.http_ok = 0
        self.http_failures: List[Tuple[Optional[int], str, str]] = []  # (status or None, host, error class or "")

    @property
    def found_anything(self) -> bool:
        return bool(self.new_nodes or self.new_edges or self.new_receipts)


_CURRENT_PROBE: contextvars.ContextVar[Optional[_Probe]] = contextvars.ContextVar("pi_current_probe", default=None)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# HTTP statuses that mean "the source refused us" (no key, no access, rate limited): skipped, not a failure.
_AUTH_LIKE_STATUSES = frozenset({401, 403, 429})
_MAX_FAILURES_IN_DETAIL = 3


def _observe_http(url: str, status: Optional[int], error: Optional[str]) -> None:
    """netutil response observer: credit the HTTP outcome to the source call running in this context."""
    probe = _CURRENT_PROBE.get()
    if probe is None:
        return
    if error is None and status is not None and status < 400:
        probe.http_ok += 1
        return
    host = urlsplit(url).hostname or "unknown host"  # host only: query strings can carry the target's selectors
    probe.http_failures.append((status, host, error or ""))


_observer_refs = 0
_observer_owned = False


def _acquire_http_observer() -> None:
    """Register the observer while at least one recorded call is in flight (refcounted; never clobbers another)."""
    global _observer_refs, _observer_owned
    if _observer_refs == 0:
        _observer_owned = netutil.get_response_observer() is None
        if _observer_owned:
            netutil.set_response_observer(_observe_http)
    _observer_refs += 1


def _release_http_observer() -> None:
    global _observer_refs, _observer_owned
    _observer_refs = max(0, _observer_refs - 1)
    if _observer_refs == 0 and _observer_owned:
        if netutil.get_response_observer() is _observe_http:
            netutil.set_response_observer(None)
        _observer_owned = False


def _describe_failures(failures: Sequence[Tuple[Optional[int], str, str]]) -> str:
    unique: List[str] = []
    for status, host, error in failures:
        text = f"HTTP {status} from {host}" if status is not None else f"{error or 'transport error'} from {host}"
        if text not in unique:
            unique.append(text)
    more = len(unique) - _MAX_FAILURES_IN_DETAIL
    shown = "; ".join(unique[:_MAX_FAILURES_IN_DETAIL])
    return shown + (f"; +{more} more" if more > 0 else "")


class PIRunRecorder:
    """Records one :class:`SourceLogEntry` per source call, including negatives, skips and errors.

    Status rules for :meth:`run`: an exception is ``error`` (type and message kept, never re-raised);
    new graph nodes, edges or receipts are ``hit``; otherwise a new agent-log event whose action ends in
    ``_SKIP`` is ``skipped`` (detail from the event); otherwise ``negative``. A call that both adds nodes
    and logs a skip (a partial result) is a ``hit`` whose detail names the skip.

    Concurrency: the orchestrator runs leads and sources with ``asyncio.gather`` on one shared graph, so a
    before/after count of the graph would mix concurrent calls. Instead the recorder subscribes to the
    graph's synchronous mutation events and tags each event with the call that is running (a
    ``ContextVar``, which every asyncio task and its child tasks inherits), so attribution is exact
    without serialising the network calls. Limitations: (1) a receipt or node counts for the first call
    that emits it, so two sources that independently produce the identical receipt credit only the first;
    (2) agents that swallow their own exceptions and log them as INFO (for example ``GLEIF_INFO``) look
    like ``negative``, because only ``*_SKIP`` events and raised exceptions are distinguishable; (3) it
    sees only what the agents write to the graph, not what a source returned but the agent discarded;
    (4) the HTTP observer sees ``httpx.AsyncClient`` traffic only (not subprocess CLIs or sync clients), and
    redirect hops are not reported separately.
    """

    def __init__(self) -> None:
        self.entries: List[SourceLogEntry] = []
        self._attached: Dict[int, Any] = {}
        self._seen_nodes: Set[str] = set()
        self._seen_edges: Set[str] = set()
        self._seen_receipts: Set[str] = set()

    # -- graph subscription ------------------------------------------------------------------

    def _attach(self, graph: Any) -> None:
        if id(graph) in self._attached:
            return
        self._attached[id(graph)] = graph  # hold a reference so the id cannot be reused
        for node in list(graph.nodes.values()):
            self._seen_nodes.add(node.id)
            self._seen_receipts.update(r.receipt_id for r in node.receipts)
        for edge in list(graph.edges.values()):
            self._seen_edges.add(edge.id)
            self._seen_receipts.update(r.receipt_id for r in edge.receipts)
        graph.subscribe(self._on_event)

    def _on_event(self, event: Dict[str, Any]) -> None:
        kind = event.get("type")
        data = event.get("data") or {}
        probe = _CURRENT_PROBE.get()
        if kind in ("node_upsert", "edge_upsert"):
            seen = self._seen_nodes if kind == "node_upsert" else self._seen_edges
            ident = str(data.get("id") or "")
            if ident and ident not in seen:
                seen.add(ident)
                if probe is not None:
                    if kind == "node_upsert":
                        probe.new_nodes += 1
                    else:
                        probe.new_edges += 1
            for receipt in data.get("receipts") or []:
                receipt_id = str(receipt.get("receipt_id") or "") if isinstance(receipt, dict) else ""
                if receipt_id and receipt_id not in self._seen_receipts:
                    self._seen_receipts.add(receipt_id)
                    if probe is not None:
                        probe.new_receipts += 1
        elif kind == "agent_log" and probe is not None:
            if str(data.get("action") or "").endswith("_SKIP"):
                probe.skips.append(str(data.get("detail") or data.get("action")))

    # -- recording ---------------------------------------------------------------------------

    def _record(self, source: str, target: str, status: str, detail: str) -> None:
        self.entries.append(
            SourceLogEntry(
                source=source, target=target, status=status, detail=detail, at_utc=_now_utc()
            )
        )

    async def run(self, source: str, target: str, graph: Any, coro: Awaitable[Any]) -> Any:
        """Await ``coro`` and record the outcome. Returns the coroutine's result, or None after an error."""
        self._attach(graph)
        probe = _Probe()
        token = _CURRENT_PROBE.set(probe)
        _acquire_http_observer()
        try:
            result = await coro
        except Exception as exc:  # noqa: BLE001 - recorded as an 'error' entry, see class docstring
            logger.warning("PI source %s failed for %s: %s: %s", source, target, type(exc).__name__, exc)
            self._record(source, target, "error", f"{type(exc).__name__}: {exc}")
            return None
        finally:
            _release_http_observer()
            _CURRENT_PROBE.reset(token)
        status, detail = self._classify(probe)
        self._record(source, target, status, detail)
        return result

    @staticmethod
    def _classify(probe: _Probe) -> Tuple[str, str]:
        failures = probe.http_failures
        if probe.found_anything:
            detail = (
                f"{probe.new_nodes} new node(s), {probe.new_receipts} new receipt(s), {probe.new_edges} new edge(s)"
            )
            if probe.skips:
                detail += f"; partial: {probe.skips[0]}"
            if failures:
                detail += f"; partial failures: {_describe_failures(failures)}"
            return "hit", detail
        if failures:
            refused = all(status in _AUTH_LIKE_STATUSES for status, _, _ in failures)
            detail = _describe_failures(failures)
            if probe.skips:
                detail += f"; {'; '.join(probe.skips[:2])}"
            return ("skipped" if refused else "error"), detail
        if probe.skips:
            return "skipped", "; ".join(probe.skips[:3])
        detail = "ran; no new nodes or receipts"
        if probe.http_ok:
            detail += f" ({probe.http_ok} HTTP response(s) ok)"
        return "negative", detail

    def skip(self, source: str, target: str, detail: str) -> None:
        """Record a source that was not run on purpose (policy or passive-only rule)."""
        self._record(source, target, "skipped", detail)

    def error(self, source: str, target: str, detail: str) -> None:
        """Record a failure of something that is not a graph source call (for example the conflict check)."""
        self._record(source, target, "error", detail)

    def note(self, source: str, target: str, status: str, detail: str) -> None:
        """Record an entry with an explicit status (used by the conflict check)."""
        self._record(source, target, status, detail)


def make_holehe_blocker(recorder: PIRunRecorder) -> Callable[[str, str, int], Coroutine[Any, Any, None]]:
    """Replacement for ``OSINTAgent._run_local_arsenal_holehe`` in passive-only PI mode.

    Holehe probes sites' account-recovery and sign-up flows with the target's email address. That is
    not passive (it can trigger mail to the subject), so it is skipped and logged instead of run.
    """

    async def _blocked(clean_email: str, origin_node_id: str, hop_depth: int) -> None:
        recorder.skip(
            "holehe",
            clean_email,
            "Holehe probes account-recovery/sign-up flows with the email address; not passive, skipped in PI mode",
        )

    return _blocked


BREACH_SKIP_REASON = "breach/infostealer contents are not used in PI mode"
CREDENTIAL_SKIP_REASON = "credential/breach contents are not used in PI mode"


def make_breach_blocker(
    recorder: PIRunRecorder, source: str, *, target_arg: int = 0
) -> Callable[..., Awaitable[None]]:
    """Replacement for an ``OSINTAgent`` breach/infostealer method in PI mode (shadowed on the instance).

    ``investigate_hudsonrock_infostealer``, ``_scan_leakcheck``, ``_lookup_emailrep`` and
    ``investigate_credential_combo`` are also called from inside other OSINT methods
    (``investigate_email_pivots``, ``investigate_domain_infrastructure``, ``investigate_identity_and_handle``), so
    skipping them at the lead level is not enough. ``target_arg`` picks the positional argument recorded as the
    target; for the credential combo it must be the origin node id (index 1), never the secret in argument 0.
    """

    async def _blocked(*args: Any, **kwargs: Any) -> None:
        target = str(args[target_arg]) if len(args) > target_arg else ""
        recorder.skip(source, target, BREACH_SKIP_REASON if source != "credential_combo" else CREDENTIAL_SKIP_REASON)

    return _blocked


__all__ = [
    "BREACH_SKIP_REASON",
    "CREDENTIAL_SKIP_REASON",
    "PIRunRecorder",
    "make_breach_blocker",
    "make_holehe_blocker",
]
