"""FastAPI Backend & Interactive War-Room UI for Bunnyhole.

Security model (see docs/ and the audit tests in ``tests/test_api_security.py``):

* **No token configured** (the default): the server is loopback-only. Every request whose *peer address*
  is not loopback is refused with 403, and the ``Host`` header must be a loopback name (DNS-rebinding guard).
  A spoofed ``Host: localhost`` from a LAN peer therefore gets nothing.
* **Token configured** (``BUNNYHOLE_API_TOKEN``): every ``/api`` route, GETs included, requires the token in
  ``X-Bunnyhole-Token`` (or ``Authorization: Bearer``), compared in constant time. The token is never embedded
  in the served page; the War-Room asks the operator for it once and keeps it in ``sessionStorage``.
* Request bodies are capped (``BUNNYHOLE_API_MAX_BODY``, default 1 MiB) before any parsing; every request
  field has a length cap; CPU-bound parsing runs off the event loop; investigations share one bounded gate
  (concurrency + waiting queue) and a wall-clock timeout.
* Local evidence files (.pdf/.docx) are read over HTTP only from inside ``BUNNYHOLE_EVIDENCE_DIR``.
* ``POST /api/arsenal/install`` is off unless ``BUNNYHOLE_API_ALLOW_INSTALL=1`` and a token is configured.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import stat
from collections import OrderedDict
from html import escape as html_escape
from pathlib import Path
from typing import Annotated, Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple, TypeVar

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

import bunnyhole
from bunnyhole.engine.intake import AnchorMode, CaseIntakePacket, SmartIntakeParser
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator, classify_seed_type
from bunnyhole.engine.pi_credentials import scrub_credential_text

_T = TypeVar("_T")
_AUDIT = logging.getLogger("bunnyhole.api.audit")
_LOG = logging.getLogger("bunnyhole.api")

# --- Operational limits & safety knobs (override via environment) ---------------------------------
MAX_ACTIVE_CASES = int(os.environ.get("BUNNYHOLE_MAX_ACTIVE_CASES", "50"))
MAX_RAW_TEXT = int(os.environ.get("BUNNYHOLE_MAX_RAW_TEXT", "20000"))
MAX_SELECTORS = int(os.environ.get("BUNNYHOLE_MAX_SELECTORS", "64"))
MAX_CONCURRENT_INVESTIGATIONS = int(os.environ.get("BUNNYHOLE_MAX_CONCURRENT", "4"))
MAX_QUEUED_INVESTIGATIONS = int(os.environ.get("BUNNYHOLE_API_MAX_QUEUED", "16"))
MAX_SEED_CHARS = 2000
MAX_SELECTOR_CHARS = 512
MAX_PATH_CHARS = 1024
MAX_HYPOTHESIS_CHARS = 2000
MAX_TITLE_CHARS = 500
MAX_NODE_ID_CHARS = 500
MAX_CASE_ID_CHARS = 128
_DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_DEFAULT_INVESTIGATION_TIMEOUT_S = 15 * 60.0
_DEFAULT_MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
_RETRY_AFTER_S = "30"

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
_EVIDENCE_SUFFIXES = (".pdf", ".docx")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        _LOG.warning("Ignoring non-integer %s=%r; using %d", name, raw, default)
        return default
    return value if value > 0 else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        _LOG.warning("Ignoring non-numeric %s=%r; using %s", name, raw, default)
        return default
    return value if value > 0 else default


def _api_token() -> str:
    """The configured per-launch token, read per request so the CLI (and tests) control it via the env."""
    return os.environ.get("BUNNYHOLE_API_TOKEN", "").strip()


def _max_body_bytes() -> int:
    return _env_int("BUNNYHOLE_API_MAX_BODY", _DEFAULT_MAX_BODY_BYTES)


def _investigation_timeout_s() -> float:
    return _env_float("BUNNYHOLE_API_INVESTIGATION_TIMEOUT_S", _DEFAULT_INVESTIGATION_TIMEOUT_S)


def _max_evidence_bytes() -> int:
    return _env_int("BUNNYHOLE_API_MAX_EVIDENCE_BYTES", _DEFAULT_MAX_EVIDENCE_BYTES)


def _install_allowed() -> bool:
    return os.environ.get("BUNNYHOLE_API_ALLOW_INSTALL", "").strip() == "1" and bool(_api_token())


# --- Request guard: peer/Host check, token, body cap, security headers ----------------------------


def _is_loopback_peer(client: Optional[Tuple[str, int]]) -> bool:
    """True only for a loopback socket peer (127.0.0.0/8, ::1, IPv4-mapped loopback). Fails closed."""
    if not client:
        return False
    try:
        addr = ipaddress.ip_address(str(client[0]).strip("[]"))
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return bool(addr.is_loopback or (mapped is not None and mapped.is_loopback))


def _host_name(host_header: str) -> str:
    """The host part of a Host header, lower-cased; IPv6 literals keep their brackets."""
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _supplied_token(headers: Headers) -> str:
    supplied = headers.get("x-bunnyhole-token", "").strip()
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    return supplied


def _token_matches(supplied: str, expected: str) -> bool:
    """Constant-time token comparison (never ``==`` on secrets)."""
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"


def _war_room_csp(nonce: str) -> str:
    # Residual risk: the Tailwind Play CDN script is third-party, unpinned and has no SRI hash (it cannot be
    # vendored offline here). It is allowed by host only; a compromise of cdn.tailwindcss.com would be script
    # execution in this page. Inline scripts need the per-response nonce; inline event handlers are not used.
    # Tailwind injects <style> elements at runtime, so style-src keeps 'unsafe-inline' (no script execution).
    return (
        "default-src 'self'; "
        f"script-src 'nonce-{nonce}' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'"
    )


def _with_security_headers(send: Send) -> Send:
    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            headers = MutableHeaders(scope=message)
            headers["X-Content-Type-Options"] = "nosniff"
            headers["X-Frame-Options"] = "DENY"
            headers["Referrer-Policy"] = "no-referrer"
            headers["Cache-Control"] = "no-store"
            if "content-security-policy" not in headers:
                headers["Content-Security-Policy"] = _API_CSP
        await send(message)

    return wrapped


class SecurityGuardMiddleware:
    """Pure-ASGI outermost guard. Runs before routing, so it covers every route, present and future."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        send = _with_security_headers(send)
        path = scope.get("path", "")
        is_api = path == "/api" or path.startswith("/api/")
        headers = Headers(scope=scope)
        token = _api_token()

        if not token:
            # Loopback-only mode: the peer address decides (a Host header is attacker-controlled).
            if not _is_loopback_peer(scope.get("client")):
                await self._reject(scope, receive, send, 403, "Bunnyhole serves loopback clients only. Set "
                                   "BUNNYHOLE_API_TOKEN to allow remote clients.")
                return
            if _host_name(headers.get("host", "")) not in _LOOPBACK_HOSTS:
                await self._reject(scope, receive, send, 400, "Invalid host header")
                return
        elif is_api and not _token_matches(_supplied_token(headers), token):
            await self._reject(scope, receive, send, 401, "Missing or invalid API token",
                               {"WWW-Authenticate": 'Bearer realm="bunnyhole"'})
            return

        limit = _max_body_bytes()
        declared = headers.get("content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length")
                return
            if too_big:
                await self._reject(scope, receive, send, 413, f"Request body too large (max {limit} bytes)")
                return

        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > limit:
                await self._reject(scope, receive, send, 413, f"Request body too large (max {limit} bytes)")
                return
            more = bool(message.get("more_body", False))

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, status: int, detail: str,
                      headers: Optional[Dict[str, str]] = None) -> None:
        await JSONResponse({"detail": detail}, status_code=status, headers=headers)(scope, receive, send)


app = FastAPI(
    title="Bunnyhole Investigative Intelligence API",
    version=bunnyhole.__version__,
    description="Multi-Domain Investigative AI: Journalism, Forensic Accounting, Red Team OSINT, Link Sleuth & On-Chain Crypto",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(SecurityGuardMiddleware)  # added last = outermost


# --- Investigation gate: bounded concurrency + bounded waiting queue + wall-clock timeout ---------


class _InvestigationGate:
    """A semaphore with a bounded waiting queue. Re-binds itself if the running event loop changes."""

    def __init__(self, limit: int, max_waiting: int) -> None:
        self.limit = max(1, limit)
        self.max_waiting = max(0, max_waiting)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._sem: Optional[asyncio.Semaphore] = None
        self._waiting = 0

    def _semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._sem is None or self._loop is not loop:
            self._loop, self._sem, self._waiting = loop, asyncio.Semaphore(self.limit), 0
        return self._sem

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        sem = self._semaphore()
        if sem.locked() and self._waiting >= self.max_waiting:
            raise HTTPException(status_code=429, detail="Too many investigations queued; retry later",
                                headers={"Retry-After": _RETRY_AFTER_S})
        self._waiting += 1
        try:
            await sem.acquire()
        finally:
            self._waiting -= 1
        try:
            yield
        finally:
            sem.release()


_INVESTIGATION_GATE = _InvestigationGate(MAX_CONCURRENT_INVESTIGATIONS, MAX_QUEUED_INVESTIGATIONS)


async def _run_investigation(work: Callable[[], Awaitable[_T]]) -> _T:
    """Run ``work`` inside the shared gate, bounded (queue wait included) by the wall-clock timeout."""
    timeout_s = _investigation_timeout_s()

    async def gated() -> _T:
        async with _INVESTIGATION_GATE.slot():
            return await work()

    try:
        return await asyncio.wait_for(gated(), timeout=timeout_s)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail=f"Investigation exceeded the {timeout_s:g}s time limit "
                            "(BUNNYHOLE_API_INVESTIGATION_TIMEOUT_S)") from exc


async def _parse_off_loop(fn: Callable[..., _T], *args: Any) -> _T:
    """Run CPU-bound intake parsing in a worker thread; a parser ValueError becomes a clean 400."""
    try:
        return await asyncio.to_thread(fn, *args)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse the intake text: {exc}") from exc


# --- Local evidence policy (H2) --------------------------------------------------------------------


def _evidence_dir() -> Path:
    raw = os.environ.get("BUNNYHOLE_EVIDENCE_DIR", "").strip()
    if not raw:
        raise HTTPException(
            status_code=403,
            detail="Local evidence files (.pdf/.docx) are disabled over HTTP. Set BUNNYHOLE_EVIDENCE_DIR to a "
                   "directory of evidence files to allow reading files from inside it.",
        )
    try:
        base = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=403, detail="BUNNYHOLE_EVIDENCE_DIR does not exist") from exc
    if not base.is_dir():
        raise HTTPException(status_code=403, detail="BUNNYHOLE_EVIDENCE_DIR is not a directory")
    return base


def _require_evidence_allowed(raw_path: str) -> None:
    """Raise 403/400 unless ``raw_path`` is an absolute path to a regular .pdf/.docx inside the evidence dir."""
    base = _evidence_dir()
    shown = raw_path if len(raw_path) <= 200 else raw_path[:200] + "…"
    candidate = Path(raw_path.strip())
    if not candidate.is_absolute():
        raise HTTPException(status_code=400, detail=f"Evidence path must be absolute and inside "
                            f"BUNNYHOLE_EVIDENCE_DIR: {shown!r}")
    if ".." in candidate.parts:
        raise HTTPException(status_code=400, detail=f"Evidence path must not contain '..': {shown!r}")
    try:
        resolved = candidate.resolve(strict=True)
        st = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=f"Evidence file not found: {shown!r}") from exc
    if not resolved.is_relative_to(base):
        raise HTTPException(status_code=400, detail=f"Evidence path is outside BUNNYHOLE_EVIDENCE_DIR: {shown!r}")
    if resolved.suffix.lower() not in _EVIDENCE_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Evidence file must be .pdf or .docx: {shown!r}")
    if not stat.S_ISREG(st.st_mode):
        raise HTTPException(status_code=400, detail=f"Evidence path is not a regular file: {shown!r}")
    cap = _max_evidence_bytes()
    if st.st_size > cap:
        raise HTTPException(status_code=400, detail=f"Evidence file exceeds {cap} bytes: {shown!r}")


def _is_document_seed(value: str) -> bool:
    return classify_seed_type(value)[0] == "document"


def _document_leads(packet: CaseIntakePacket) -> List[str]:
    """Every value the orchestrator would open as a local document for this (normalized) packet."""
    tuples = packet.all_seed_tuples()
    docs = [v for lt, v in tuples if lt == "document"]
    if not tuples and packet.raw_omni_input and _is_document_seed(packet.raw_omni_input):
        docs.append(packet.raw_omni_input)
    return docs


def _strip_token(text: str, token: str) -> str:
    return re.sub(re.escape(token), " ", text, flags=re.IGNORECASE)


# --- Response hygiene: credentials (M4) and key previews (L1) -------------------------------------

_CREDENTIAL_KEYS = frozenset({"credentials"})
_SCRUBBED_TEXT_KEYS = frozenset({"raw_omni_text", "raw_omni_input", "seed_query", "title", "hypothesis"})
_MIN_SECRET_CHARS = 4


def _mask_credential(value: Any) -> str:
    text = str(value)
    return text.split(":", 1)[0] + ":***" if ":" in text else "***"


def _collect_credentials(obj: Any, found: List[str]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in _CREDENTIAL_KEYS and isinstance(value, list):
                found.extend(str(v) for v in value if isinstance(v, str) and v.strip())
            else:
                _collect_credentials(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _collect_credentials(item, found)


def _secret_replacements(credentials: List[str]) -> List[Tuple[str, str]]:
    pairs: Dict[str, str] = {}
    for cred in credentials:
        cred = cred.strip()
        if len(cred) >= _MIN_SECRET_CHARS:
            pairs[cred] = _mask_credential(cred)
        if ":" in cred:
            secret = cred.split(":", 1)[1].strip()
            if len(secret) >= _MIN_SECRET_CHARS:
                pairs.setdefault(secret, "***")
    return sorted(pairs.items(), key=lambda kv: len(kv[0]), reverse=True)


def _redact(obj: Any, replacements: List[Tuple[str, str]], key: Optional[str] = None) -> Any:
    if isinstance(obj, dict):
        return {k: _redact(v, replacements, k) for k, v in obj.items()}
    if isinstance(obj, list):
        if key in _CREDENTIAL_KEYS:
            return [_mask_credential(v) for v in obj]
        return [_redact(v, replacements) for v in obj]
    if isinstance(obj, str):
        for secret, masked in replacements:
            if secret in obj:
                obj = obj.replace(secret, masked)
        if key in _SCRUBBED_TEXT_KEYS:
            obj = scrub_credential_text(obj)[0]
        return obj
    return obj


def _safe_payload(result: Any, known_credentials: Optional[List[str]] = None) -> Any:
    """Last-line-of-defence credential masking for every investigation / case response.

    Masks every ``credentials`` list, replaces each known credential (and its secret half) anywhere in the
    payload (dossier Markdown included), and heuristically scrubs free-text fields that echo raw input.
    """
    payload = jsonable_encoder(result)
    found = list(known_credentials or [])
    _collect_credentials(payload, found)
    return _redact(payload, _secret_replacements(found))


def _credential_seeds(*values: str) -> List[str]:
    return [v for v in values if classify_seed_type(v)[0] == "credential"]


def _preview_secret(value: str) -> str:
    """At most the last 3 characters, and nothing at all for values under 12 characters."""
    if not value:
        return ""
    return "***" + value[-3:] if len(value) >= 12 else "***"


def _masked_key_statuses(statuses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for item in statuses:
        clean = dict(item)
        clean["masked_value"] = _preview_secret(os.environ.get(str(item.get("key", "")), "").strip())
        out.append(clean)
    return out


# Active investigation sessions in memory (bounded LRU; oldest cases are evicted).
ACTIVE_CASES: "OrderedDict[str, BunnyholeOrchestrator]" = OrderedDict()


def _register_case(orch: BunnyholeOrchestrator) -> None:
    """Store a case, evicting the least-recently-used once the cap is exceeded."""
    ACTIVE_CASES[orch.graph.case_id] = orch
    ACTIVE_CASES.move_to_end(orch.graph.case_id)
    while len(ACTIVE_CASES) > MAX_ACTIVE_CASES:
        ACTIVE_CASES.popitem(last=False)


# --- Request models (every string and list is bounded) ---------------------------------------------

_Selector = Annotated[str, Field(max_length=MAX_SELECTOR_CHARS)]
_SelectorList = Annotated[List[_Selector], Field(max_length=MAX_SELECTORS)]
_EvidencePath = Annotated[str, Field(max_length=MAX_PATH_CHARS)]
_CaseId = Annotated[str, Field(min_length=1, max_length=MAX_CASE_ID_CHARS)]
_NodeId = Annotated[str, Field(min_length=1, max_length=MAX_NODE_ID_CHARS)]
_Entity = Annotated[str, Field(min_length=1, max_length=MAX_SEED_CHARS)]


class TraceRequest(BaseModel):
    seed: _Entity
    gear: GearMode = GearMode.FAST
    depth: int = Field(2, ge=1, le=4)
    breadth: int = Field(4, ge=2, le=8)


class LinkRequest(BaseModel):
    entity_a: _Entity
    entity_b: _Entity
    gear: GearMode = GearMode.FAST


class ParseIntakeRequest(BaseModel):
    raw_text: str = Field(..., max_length=MAX_RAW_TEXT)


class IntakeRequest(BaseModel):
    """HTTP view of :class:`CaseIntakePacket` with a length cap on every field."""

    title: str = Field("", max_length=MAX_TITLE_CHARS)
    raw_omni_input: str = Field("", max_length=MAX_RAW_TEXT)
    raw_omni_text: str = Field("", max_length=MAX_RAW_TEXT)
    hypothesis: str = Field("", max_length=MAX_HYPOTHESIS_CHARS)
    anchor_mode: AnchorMode = AnchorMode.CONVERGENCE
    usernames: _SelectorList = Field(default_factory=list)
    emails: _SelectorList = Field(default_factory=list)
    phones: _SelectorList = Field(default_factory=list)
    credentials: _SelectorList = Field(default_factory=list)
    wallets: _SelectorList = Field(default_factory=list)
    domains_or_ips: _SelectorList = Field(default_factory=list)
    domains: _SelectorList = Field(default_factory=list)
    orgs_or_names: _SelectorList = Field(default_factory=list)
    organizations: _SelectorList = Field(default_factory=list)
    aircraft_tails: _SelectorList = Field(default_factory=list)
    evidence_files: Annotated[List[_EvidencePath], Field(max_length=MAX_SELECTORS)] = Field(default_factory=list)
    exclusions: _SelectorList = Field(default_factory=list)
    gear: GearMode = GearMode.FAST
    depth: int = Field(2, ge=1, le=4)
    breadth: int = Field(4, ge=1, le=8)

    def to_packet(self) -> CaseIntakePacket:
        return CaseIntakePacket(**self.model_dump())


class PivotRequest(BaseModel):
    case_id: _CaseId
    node_id: _NodeId
    seed_value: _Entity
    lead_type: Optional[str] = Field(None, max_length=32, pattern=r"^[a-z_]+$")


class CooccurrenceRequest(BaseModel):
    case_id: _CaseId
    node_a_id: _NodeId
    entity_a: _Entity
    node_b_id: _NodeId
    entity_b: _Entity


class SetKeyRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=128)
    value: str = Field(..., max_length=4096)


class InstallToolRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=64)


# --- Endpoints ---------------------------------------------------------------------------------------


@app.post("/api/parse-intake")
async def api_parse_intake(req: ParseIntakeRequest) -> Dict[str, Any]:
    """Auto-parse raw clipboard dumps / free-text notes into structured selectors & hypothesis.

    This is a stateless echo of the caller's own text (it fills the War-Room intake form), so the parsed
    credentials are returned to the same authenticated caller that just sent them; nothing is persisted.
    """
    packet = await _parse_off_loop(SmartIntakeParser.parse_omni_text, req.raw_text)
    return packet.model_dump(mode="json")


async def _prepare_intake(req: IntakeRequest) -> Tuple[CaseIntakePacket, List[Dict[str, str]]]:
    """Normalize the packet off-loop and apply the evidence policy.

    Explicit ``evidence_files`` that fail the policy fail the request (403/400). ``.pdf``/``.docx`` mentions
    the parser found inside the raw text are dropped (and reported) instead, and removed from the raw text so
    the orchestrator's own re-normalization cannot resurrect them. Finally the packet is re-normalized exactly
    as the orchestrator will, and every document lead it would open must pass the policy.
    """
    packet = req.to_packet()
    explicit = {p.strip().lower() for p in SmartIntakeParser.split_multi_values(packet.evidence_files)}
    normalized = await _parse_off_loop(SmartIntakeParser.normalize_packet, packet)

    rejected: List[Dict[str, str]] = []
    kept: List[str] = []
    raw = normalized.raw_omni_text
    for doc in normalized.evidence_files:
        try:
            _require_evidence_allowed(doc)
            kept.append(doc)
        except HTTPException as exc:
            if doc.strip().lower() in explicit:
                raise
            rejected.append({"path": doc, "reason": str(exc.detail)})
            raw = _strip_token(raw, doc)
    if rejected:
        raw = re.sub(r"\s+", " ", raw).strip()
        normalized = normalized.model_copy(update={"evidence_files": kept, "raw_omni_text": raw, "raw_omni_input": raw})

    final_view = await _parse_off_loop(SmartIntakeParser.normalize_packet, normalized)
    for doc in _document_leads(final_view):
        _require_evidence_allowed(doc)
    return normalized, rejected


@app.post("/api/intake")
async def api_intake(req: IntakeRequest) -> Dict[str, Any]:
    """Run a full Dual-Mode Case Intake & Multi-Selector Investigation (Hypothesis + Credentials/Selectors)."""
    normalized, rejected = await _prepare_intake(req)
    if normalized.total_selectors() > MAX_SELECTORS:
        raise HTTPException(status_code=413, detail=f"Too many selectors (max {MAX_SELECTORS})")

    async def work() -> Tuple[BunnyholeOrchestrator, Dict[str, Any]]:
        orch = BunnyholeOrchestrator(
            seed_query=normalized.summary_seed_label(),
            gear=normalized.gear,
            max_depth=normalized.depth,
            initial_breadth=normalized.breadth,
            intake_packet=normalized,
        )
        return orch, await orch.run_intake_investigation(normalized)

    orch, res = await _run_investigation(work)
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    if rejected:
        res["evidence_files_rejected"] = rejected
    return _safe_payload(res, list(normalized.credentials) + list(req.credentials))


@app.post("/api/trace")
async def api_trace(req: TraceRequest) -> Dict[str, Any]:
    if _is_document_seed(req.seed):
        _require_evidence_allowed(req.seed)

    async def work() -> Tuple[BunnyholeOrchestrator, Dict[str, Any]]:
        orch = BunnyholeOrchestrator(
            seed_query=req.seed,
            gear=req.gear,
            max_depth=req.depth,
            initial_breadth=req.breadth,
        )
        return orch, await orch.run_investigation()

    orch, res = await _run_investigation(work)
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return _safe_payload(res, _credential_seeds(req.seed))


@app.post("/api/link")
async def api_link(req: LinkRequest) -> Dict[str, Any]:
    for entity in (req.entity_a, req.entity_b):
        if _is_document_seed(entity):
            _require_evidence_allowed(entity)

    async def work() -> Tuple[BunnyholeOrchestrator, Dict[str, Any]]:
        orch = BunnyholeOrchestrator(
            seed_query=f"{req.entity_a} <-> {req.entity_b}",
            gear=req.gear,
            max_depth=2,
            initial_breadth=4,
        )
        return orch, await orch.run_bidirectional_link_investigation(req.entity_a, req.entity_b)

    orch, res = await _run_investigation(work)
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return _safe_payload(res, _credential_seeds(req.entity_a, req.entity_b))


@app.post("/api/pivot")
async def api_pivot(req: PivotRequest) -> Dict[str, Any]:
    """Click-to-Pivot on any existing node in the investigation graph!"""
    orch = ACTIVE_CASES.get(req.case_id)
    if not orch:
        raise HTTPException(status_code=404, detail="Case ID not found in active memory")
    ACTIVE_CASES.move_to_end(req.case_id)
    ltype = req.lead_type or classify_seed_type(req.seed_value)[0]
    if ltype == "document":
        _require_evidence_allowed(req.seed_value)
    node = orch.graph.nodes.get(req.node_id)
    hop = (node.hop_depth + 1) if node else 2

    async def work() -> Dict[str, Any]:
        await orch._execute_lead(ltype, req.seed_value, req.node_id, hop_depth=hop)
        orch._harvest_step_learnings_and_followups(current_hop=hop)
        orch.link_sleuth.break_dead_ends(current_hop=hop)
        return orch.compile_full_result()

    res = await _run_investigation(work)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return _safe_payload(res, _credential_seeds(req.seed_value))


@app.post("/api/verify-link")
async def api_verify_link(req: CooccurrenceRequest) -> Dict[str, Any]:
    """Verify a predicted Adamic-Adar missing link via live Joint Co-Occurrence search."""
    orch = ACTIVE_CASES.get(req.case_id)
    if not orch:
        raise HTTPException(status_code=404, detail="Case ID not found")

    async def work() -> Dict[str, Any]:
        await orch.link_sleuth.verify_interconnection_cooccurrence(
            req.entity_a, req.node_a_id, req.entity_b, req.node_b_id, hop_depth=2
        )
        return orch.compile_full_result()

    res = await _run_investigation(work)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return _safe_payload(res)


@app.get("/api/arsenal")
async def api_arsenal_status() -> Dict[str, Any]:
    """Return cross-platform OS profile, installed status of all 24 OSINT/forensic tools, and API key status."""
    from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager

    mgr = ArsenalManager()
    return {
        "platform": mgr.platform_info,
        "tools": mgr.check_arsenal_status(),
        "api_keys": _masked_key_statuses(mgr.get_api_keys_status()),
        "vault_paths": [str(BUNNYHOLE_ENV_FILE), str(LEGACY_OSINT_ENV_FILE)],
        "install_enabled": _install_allowed(),
    }


@app.post("/api/arsenal/install")
async def api_arsenal_install(req: InstallToolRequest, request: Request) -> Dict[str, Any]:
    """Install a catalog tool via uv/pipx/brew/apt/go. Off unless BUNNYHOLE_API_ALLOW_INSTALL=1 and a token."""
    from bunnyhole.arsenal.manager import ARSENAL_TOOLS_CATALOG, ArsenalManager

    peer = request.client.host if request.client else "?"
    if not _install_allowed():
        _AUDIT.warning("arsenal install refused (disabled): tool=%r peer=%s", req.tool_name, peer)
        raise HTTPException(
            status_code=403,
            detail="Tool installation over HTTP is disabled. It runs package managers (pip, go install, "
                   "sudo -n apt-get); use `bunnyhole arsenal install` locally, or set "
                   "BUNNYHOLE_API_ALLOW_INSTALL=1 together with BUNNYHOLE_API_TOKEN.",
        )
    catalog = {str(t["name"]).lower(): str(t["name"]) for t in ARSENAL_TOOLS_CATALOG}
    name = catalog.get(req.tool_name.strip().lower())
    if name is None:
        _AUDIT.warning("arsenal install refused (unknown tool): tool=%r peer=%s", req.tool_name, peer)
        raise HTTPException(status_code=400, detail="Unknown tool: only catalog tool names can be installed")

    _AUDIT.warning("arsenal install requested over HTTP: tool=%s peer=%s", name, peer)
    mgr = ArsenalManager()
    # install_tool runs blocking subprocesses; offload so the event loop stays responsive.
    res = await asyncio.to_thread(mgr.install_tool, name)
    _AUDIT.warning("arsenal install finished: tool=%s success=%s", name, bool(res.get("success")))
    return {
        "install_result": res,
        "tools": mgr.check_arsenal_status(),
    }


@app.post("/api/keys")
async def api_set_key(req: SetKeyRequest) -> Dict[str, Any]:
    """Persist a recognized API key to the local vault (~/.bunnyhole/api_keys.env, chmod 600)."""
    from bunnyhole.arsenal.manager import ArsenalManager

    mgr = ArsenalManager()
    try:
        mgr.set_api_key(req.key, req.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "api_keys": _masked_key_statuses(mgr.get_api_keys_status())}


@app.get("/api/cases")
async def api_list_cases(q: Annotated[Optional[str], Query(max_length=200)] = None) -> Dict[str, Any]:
    """List saved investigations in ~/.bunnyhole/cases.db or search historical entity memory."""
    from bunnyhole.engine.storage import CaseStore

    store = CaseStore()
    return _safe_payload({
        "cases": store.list_cases(limit=25),
        "entity_matches": store.search_entity_memory(q) if q else [],
    })


@app.get("/api/cases/{case_id}")
async def api_get_case(case_id: Annotated[str, PathParam(max_length=MAX_CASE_ID_CHARS)]) -> Dict[str, Any]:
    """Load a full saved investigation from ~/.bunnyhole/cases.db."""
    from bunnyhole.engine.storage import CaseStore

    store = CaseStore()
    data = store.get_case(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found in SQLite store")
    return _safe_payload(data)


@app.get("/api/research-files")
async def api_research_files() -> Dict[str, Any]:
    """Return the project's research dossiers (the bundled ``research/*.md`` tradecraft library)."""
    research_dir = Path(__file__).resolve().parents[2] / "research"
    files = []
    if research_dir.exists():
        for p in sorted(research_dir.glob("*.md")):
            try:
                content = p.read_text(encoding="utf-8")
            except OSError:
                continue
            files.append({"name": p.name, "size": p.stat().st_size, "content": content})
    return {"files": files}


WAR_ROOM_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>🐇🕳️ BUNNYHOLE // Autonomous Multi-Domain Intelligence War-Room</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background: #07090e; color: #e2e8f0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, monospace; overflow: hidden; }
    .glass { background: rgba(13, 18, 28, 0.88); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.16); }
    .neon-border { box-shadow: 0 0 20px rgba(139, 92, 246, 0.15); }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #07090e; }
    ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #38bdf8; }
  </style>
</head>
<body class="h-screen w-screen flex flex-col select-none">

  <!-- TOP COMMAND BAR -->
  <header class="glass h-16 px-4 flex items-center justify-between border-b border-slate-800 z-20 shrink-0">
    <div class="flex items-center gap-3">
      <div class="h-9 w-9 rounded-lg bg-gradient-to-br from-violet-600 via-fuchsia-600 to-cyan-500 flex items-center justify-center text-lg font-black shadow-lg">🐇</div>
      <div>
        <div class="flex items-center gap-2">
          <span class="font-black tracking-wider text-white text-base">BUNNYHOLE</span>
          <span class="text-[10px] px-2 py-0.5 rounded bg-violet-950/90 text-violet-300 border border-violet-700/50 font-mono">v__BUNNYHOLE_VERSION__ PALANTIR × ZACHXBT × BELLINGCAT ENGINE</span>
        </div>
        <p class="text-[11px] text-slate-400 font-mono">Journalism • Forensic Accounting • Red Team OSINT • Link Sleuth • On-Chain Crypto</p>
      </div>
    </div>

    <!-- MODE & SEARCH CONTROLS -->
    <div class="flex items-center gap-2 flex-1 max-w-5xl mx-4">
      <select id="modeSelect" class="bg-slate-900 text-xs font-mono text-cyan-300 border border-slate-700 rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-400">
        <option value="trace">🎯 Omni-Trace / Intake</option>
        <option value="link">🔗 Link Sleuth (A ↔ B)</option>
      </select>

      <div id="traceInputs" class="flex-1 flex items-center gap-1.5">
        <input id="seedInput" type="text" value="vitalik.eth" placeholder="Paste any seed OR messy case notes (hypothesis, @handles, emails, phones, email:pass, wallets, domains)..."
          class="w-full bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-violet-500" />
        <button id="autoTagBtn" title="Auto-extract hypothesis, credentials, emails, phones, wallets & domains into the Case Intake Drawer"
          class="px-2.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-amber-300 border border-amber-600/40 text-[11px] font-mono shrink-0">✨ Auto-Tag</button>
      </div>

      <div id="linkInputs" class="hidden flex-1 items-center gap-2">
        <input id="entityAInput" type="text" value="vitalik.eth" placeholder="Entity A (e.g. vitalik.eth or Coinbase)..."
          class="w-1/2 bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-amber-400" />
        <span class="text-amber-400 font-mono text-xs">↔</span>
        <input id="entityBInput" type="text" value="ethereum.org" placeholder="Entity B (e.g. ethereum.org or GitHub handle)..."
          class="w-1/2 bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-amber-400" />
      </div>

      <button id="drawerToggleBtn" class="px-2.5 py-2 rounded-lg bg-violet-950/90 hover:bg-violet-900 text-violet-200 border border-violet-600/60 text-xs font-mono shrink-0 flex items-center gap-1">
        <span>🗂️ Case Intake</span>
        <span id="intakeBadge" class="hidden px-1.5 py-0.2 rounded-full bg-fuchsia-600 text-white text-[10px]">0</span>
      </button>

      <select id="gearSelect" class="bg-slate-900 text-xs font-mono text-emerald-300 border border-slate-700 rounded-lg px-2 py-2">
        <option value="fast">⚡ Fast</option>
        <option value="deep">🔬 Deep</option>
      </select>

      <select id="depthSelect" class="bg-slate-900 text-xs font-mono text-slate-300 border border-slate-700 rounded-lg px-2 py-2" title="Recursive Depth">
        <option value="1">Depth 1</option>
        <option value="2" selected>Depth 2</option>
        <option value="3">Depth 3</option>
      </select>

      <button id="runBtn" class="bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-500 hover:to-cyan-500 text-white font-mono text-xs font-bold px-4 py-2 rounded-lg shadow-lg transition flex items-center gap-1.5 shrink-0">
        <span>🚀 HUNT</span>
      </button>
    </div>

    <!-- QUICK PRESETS -->
    <div class="flex items-center gap-1.5 text-[11px] font-mono">
      <span class="text-slate-500">Presets:</span>
      <button data-action="preset" data-preset="vitalik.eth" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-violet-300 border border-slate-800">⛓️ vitalik.eth</button>
      <button data-action="preset" data-preset="uniswap.org" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-800">🌐 uniswap.org</button>
      <button data-action="preset" data-preset="Coinbase" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-emerald-300 border border-slate-800">🏛️ Coinbase</button>
      <button data-action="preset" data-preset="N628TS" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-amber-300 border border-slate-800">✈️ Jet N628TS</button>
    </div>
  </header>

  <!-- EXPANDABLE DUAL-MODE CASE INTAKE & KNOWN CREDENTIALS LOCKER -->
  <section id="intakeDrawer" class="hidden glass border-b border-violet-800/60 px-5 py-3.5 z-20 shrink-0 text-xs font-mono space-y-3">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="text-violet-300 font-bold uppercase tracking-wider">🗂️ Dual-Mode Case Intake & Known Credentials Locker</span>
        <span class="text-[10px] text-slate-400">(Combine a Working Hypothesis with already-found usernames, emails, phone numbers, leaked credentials, wallets & files)</span>
      </div>
      <div class="flex items-center gap-2">
        <select id="anchorModeSelect" class="bg-slate-900 text-[11px] text-amber-300 border border-amber-700/60 rounded px-2.5 py-1">
          <option value="convergence">🕸️ Convergence Hunt (Prove IF & HOW clues connect)</option>
          <option value="locked_profile">🔒 Locked Target Profile (Confirmed Same Entity — Ground Truth)</option>
        </select>
        <button id="clearIntakeBtn" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">Clear</button>
        <button id="launchIntakeBtn" class="px-3 py-1 rounded bg-gradient-to-r from-fuchsia-600 to-cyan-600 hover:from-fuchsia-500 hover:to-cyan-500 text-white font-bold text-[11px]">🚀 Launch Multi-Selector Hunt</button>
      </div>
    </div>

    <!-- WORKING HYPOTHESIS BAR -->
    <div class="grid grid-cols-12 gap-3">
      <div class="col-span-8">
        <label class="block text-[10px] text-cyan-300 font-bold uppercase mb-1">🧠 Working Hypothesis / Investigative Question (Steers CIA ACH Matrix & +20 Lead Priority Boost)</label>
        <input id="intakeHypothesis" type="text" data-intake-field="1" placeholder="e.g. Prove whether @handle_x and dev@acme.io are the same operator laundering funds through 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045..."
          class="w-full bg-slate-950/95 text-white border border-slate-700 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-400" />
      </div>
      <div class="col-span-4">
        <label class="block text-[10px] text-rose-300 font-bold uppercase mb-1">🚫 Exclusions / Negative Scope (Comma-separated)</label>
        <input id="intakeExclusions" type="text" data-intake-field="1" placeholder="e.g. cloudflare.com, google.com, 0x000000..."
          class="w-full bg-slate-950/95 text-rose-200 border border-rose-900/60 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-rose-400" />
      </div>
    </div>

    <!-- 8 STRUCTURED CREDENTIAL & SELECTOR LOCKERS -->
    <div class="grid grid-cols-4 gap-2.5 text-[11px]">
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">👤 Usernames / @Handles</label>
        <input id="intakeUsernames" type="text" data-intake-field="1" placeholder="@vbuterin, vitalik..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">📧 Emails</label>
        <input id="intakeEmails" type="text" data-intake-field="1" placeholder="founder@domain.com, leak@..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">📱 Phone Numbers (E.164 / Intl)</label>
        <input id="intakePhones" type="text" data-intake-field="1" placeholder="+1-415-555-0199..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-amber-300 font-bold mb-1">🔑 Leaked Credentials (email:pass / hash)</label>
        <input id="intakeCredentials" type="text" data-intake-field="1" placeholder="user@corp.io:Hunter2025! (k-Anonymity SHA1)"
          class="w-full bg-slate-950 border border-amber-900/60 rounded px-2.5 py-1.5 text-amber-200" />
      </div>
      <div>
        <label class="block text-[10px] text-violet-300 font-bold mb-1">⛓️ Crypto Wallets / ENS / BTC</label>
        <input id="intakeWallets" type="text" data-intake-field="1" placeholder="vitalik.eth, 0xd8dA..., bc1q..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-cyan-300 font-bold mb-1">🌐 Domains & IP Addresses</label>
        <input id="intakeDomains" type="text" data-intake-field="1" placeholder="uniswap.org, 1.1.1.1..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-emerald-300 font-bold mb-1">🏛️ Orgs / Names / Tail Numbers</label>
        <input id="intakeOrgs" type="text" data-intake-field="1" placeholder="Coinbase, N628TS..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-fuchsia-300 font-bold mb-1">📄 Local Evidence (.pdf / .docx paths)</label>
        <input id="intakeFiles" type="text" data-intake-field="1" placeholder="Absolute paths inside BUNNYHOLE_EVIDENCE_DIR (off by default)"
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
    </div>
  </section>

  <!-- MAIN WORKSPACE -->
  <div class="flex-1 flex overflow-hidden relative">

    <!-- LEFT: INTERACTIVE FORCE GRAPH CANVAS -->
    <div class="flex-1 relative bg-[#05070b] overflow-hidden" id="canvasContainer">
      <canvas id="graphCanvas" class="w-full h-full cursor-grab active:cursor-grabbing"></canvas>

      <!-- LEGEND OVERLAY -->
      <div class="absolute top-3 left-3 glass rounded-lg p-2.5 text-[11px] font-mono space-y-1.5 pointer-events-none">
        <div class="text-slate-400 font-bold uppercase tracking-wider text-[10px]">Domain Color Key</div>
        <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block"></span><span>🗞️ Journalism / Dockets / Archives</span></div>
        <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block"></span><span>🏛️ Fiat / SEC / GLEIF / Offshore</span></div>
        <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block"></span><span>🕵️ Red Team OSINT / Infra / Breach</span></div>
        <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-violet-400 inline-block"></span><span>⛓️ On-Chain Crypto / DeFi / BTC</span></div>
        <div class="flex items-center gap-2"><span class="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span><span>✈️ Physical ADS-B / Maritime</span></div>
        <div class="flex items-center gap-2 pt-1 border-t border-slate-800"><span class="w-2.5 h-2.5 rounded-full border-2 border-yellow-300 inline-block"></span><span class="text-yellow-300">🔗 Cut-Out / Keystone Broker</span></div>
      </div>

      <!-- STATS HUD OVERLAY -->
      <div id="statsHud" class="absolute top-3 right-3 glass rounded-lg px-3 py-2 text-xs font-mono flex items-center gap-4">
        <div><span class="text-slate-400">Nodes:</span> <span id="statNodes" class="text-white font-bold">0</span></div>
        <div><span class="text-slate-400">Edges:</span> <span id="statEdges" class="text-white font-bold">0</span></div>
        <div><span class="text-slate-400">SHA-256 Receipts:</span> <span id="statReceipts" class="text-emerald-400 font-bold">0</span></div>
        <div><span class="text-slate-400">Keystone Brokers:</span> <span id="statBrokers" class="text-yellow-300 font-bold">0</span></div>
      </div>

      <!-- LOADING BANNER -->
      <div id="loadingOverlay" class="hidden absolute inset-0 bg-slate-950/75 backdrop-blur-sm flex flex-col items-center justify-center z-30">
        <div class="w-12 h-12 border-4 border-violet-500 border-t-transparent rounded-full animate-spin mb-3"></div>
        <div class="text-sm font-mono text-white font-bold" id="loadingTitle">Running Multi-Domain Recursive Deep-Research...</div>
        <div class="text-xs font-mono text-cyan-300 mt-1" id="loadingSub">Dispatching Journalist, Forensic Accountant, OSINT, On-Chain & Link Sleuth Agents</div>
      </div>
    </div>

    <!-- RIGHT: MULTI-TAB INTELLIGENCE INSPECTOR -->
    <aside class="w-[490px] glass border-l border-slate-800 flex flex-col z-10 shrink-0">
      <!-- TABS -->
      <div class="flex border-b border-slate-800 text-[10px] font-mono bg-slate-950/60">
        <button data-action="tab" data-tab="links" id="tabBtn-links" class="flex-1 py-2.5 px-1 border-b-2 border-cyan-400 text-cyan-300 font-bold">🔗 Links</button>
        <button data-action="tab" data-tab="node" id="tabBtn-node" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🧾 Node</button>
        <button data-action="tab" data-tab="council" id="tabBtn-council" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🏛️ Council</button>
        <button data-action="tab" data-tab="ach" id="tabBtn-ach" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">⚖️ ACH</button>
        <button data-action="tab" data-tab="dossier" id="tabBtn-dossier" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">📚 Dossier</button>
        <button data-action="tab" data-tab="arsenal" id="tabBtn-arsenal" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🛠️ Arsenal</button>
      </div>

      <!-- TAB 1: LINK SLEUTH & INTERCONNECTIONS -->
      <div id="tab-links" class="flex-1 overflow-y-auto p-3.5 space-y-4 text-xs font-mono">
        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div class="text-[11px] font-bold text-yellow-300 uppercase mb-1">🔗 Keystone Connectors & Cut-Out Brokers</div>
          <p class="text-[10px] text-slate-400 mb-2">Entities with highest Betweenness Centrality & Cross-Domain Shannon Entropy bridging separate worlds.</p>
          <div id="keystoneList" class="space-y-1.5 text-[11px] text-slate-300">Run an investigation to map keystone brokers.</div>
        </div>

        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div class="text-[11px] font-bold text-cyan-300 uppercase mb-1">🧭 Multi-Domain Interconnection Chains</div>
          <p class="text-[10px] text-slate-400 mb-2">Click any path to highlight the chain on the canvas.</p>
          <div id="pathsList" class="space-y-2 text-[11px]">No paths computed yet.</div>
        </div>

        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div class="text-[11px] font-bold text-fuchsia-300 uppercase mb-1">🧠 Adamic-Adar Predicted Missing Links (Triadic Closure)</div>
          <p class="text-[10px] text-slate-400 mb-2">Non-adjacent entities sharing rare intermediaries. Click 'Verify' to probe live co-occurrence.</p>
          <div id="predictedLinksList" class="space-y-2 text-[11px]">No predicted links yet.</div>
        </div>

        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div class="text-[11px] font-bold text-emerald-300 uppercase mb-1">🕸️ Louvain Syndicate Cells</div>
          <div id="syndicateList" class="space-y-2 text-[11px]">No syndicate clusters yet.</div>
        </div>
      </div>

      <!-- TAB 2: NODE & SHA-256 RECEIPTS INSPECTOR -->
      <div id="tab-node" class="hidden flex-1 overflow-y-auto p-3.5 space-y-3 text-xs font-mono">
        <div id="selectedNodePanel" class="text-slate-400 text-center py-10">Click any node on the graph canvas to inspect its attributes, SHA-256 Evidence Receipts, and dispatch a Click-to-Pivot sweep.</div>
      </div>

      <!-- TAB 3: KARPATHY 3-STAGE LLM COUNCIL -->
      <div id="tab-council" class="hidden flex-1 overflow-y-auto p-3.5 space-y-3 text-xs font-mono">
        <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-700/50">
          <div class="text-amber-300 font-bold text-[11px]">🏛️ Karpathy 3-Stage LLM Council Deliberation</div>
          <p class="text-[10px] text-slate-400 mt-0.5">Stage 1: 5 Specialist Seat Opinions → Stage 2: Deterministic evidence ranking (not peer review) → Stage 3: Chairman Verdict</p>
        </div>
        <div id="councilLeaderboard" class="space-y-1.5"></div>
        <div id="councilStage1List" class="space-y-1.5"></div>
        <div id="councilChairmanBox" class="p-2.5 rounded-lg bg-slate-950 border border-emerald-800/50 text-[10px] text-slate-200 whitespace-pre-wrap">Run an investigation to convene the 5-Seat Council.</div>
      </div>

      <!-- TAB 4: CIA ACH MATRIX -->
      <div id="tab-ach" class="hidden flex-1 overflow-y-auto p-3.5 space-y-3 text-xs font-mono">
        <div id="achSummaryBox" class="p-3 rounded-lg bg-slate-900 border border-violet-800/50 space-y-1">
          <div class="text-violet-300 font-bold">CIA Analysis of Competing Hypotheses (ACH)</div>
          <div id="achVerdictText" class="text-slate-300 text-[11px]">Run an investigation to evaluate competing hypotheses.</div>
        </div>
        <div id="achMatrixList" class="space-y-2"></div>
      </div>

      <!-- TAB 5: DOSSIER & RESEARCH LIBRARY -->
      <div id="tab-dossier" class="hidden flex-1 overflow-y-auto p-3.5 space-y-3 text-xs font-mono">
        <div class="flex items-center justify-between">
          <span class="font-bold text-emerald-300 uppercase">📑 Deep-Research Learnings & Dossier</span>
          <button id="exportDossierBtn" class="px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-[11px] font-bold">⬇ Export .MD</button>
        </div>
        <div id="learningsList" class="space-y-1.5 text-[11px] text-slate-300 bg-slate-900/80 p-2.5 rounded border border-slate-800 max-h-60 overflow-y-auto"></div>
        <div class="border-t border-slate-800 pt-2">
          <div class="font-bold text-cyan-300 uppercase mb-1.5">📚 Built-In Tradecraft Research Library (/Downloads/bunnyhole/research)</div>
          <div id="researchFilesList" class="space-y-1.5"></div>
        </div>
      </div>

      <!-- TAB 6: CROSS-PLATFORM ARSENAL & API KEYS VAULT -->
      <div id="tab-arsenal" class="hidden flex-1 overflow-y-auto p-3.5 space-y-3 text-xs font-mono">
        <div id="platformBanner" class="p-2.5 rounded-lg bg-slate-900 border border-cyan-800/50 text-[11px]"></div>
        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
          <div class="font-bold text-amber-300 uppercase text-[11px]">🔑 Unified API Keys Vault (~/.bunnyhole/api_keys.env)</div>
          <div class="flex gap-1.5">
            <input id="apiKeyNameInput" type="text" placeholder="KEY_NAME (e.g. SHODAN_API_KEY)" class="w-1/2 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[11px] text-white" />
            <input id="apiKeyValueInput" type="password" placeholder="API Key Value..." class="w-1/2 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[11px] text-white" />
            <button id="saveApiKeyBtn" class="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold text-[11px]">Save</button>
          </div>
          <div id="apiKeysList" class="space-y-1 max-h-48 overflow-y-auto pt-1"></div>
        </div>
        <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
          <div class="font-bold text-emerald-300 uppercase text-[11px]">🧰 OSINT & Red-Team Arsenal (Kali • Parrot • Debian • Arch • macOS)</div>
          <div id="arsenalToolsList" class="space-y-1.5"></div>
        </div>
      </div>
    </aside>
  </div>

  <!-- BOTTOM MASTER CHRONOLOGY TIMELINE -->
  <footer class="glass h-32 border-t border-slate-800 px-4 py-2 flex flex-col shrink-0 z-20">
    <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1.5">
      <span class="font-bold text-white">⏱️ MASTER MULTI-DOMAIN CHRONOLOGY ("WHO KNEW WHAT WHEN")</span>
      <span id="timelineCount">0 dated events</span>
    </div>
    <div id="timelineStrip" class="flex-1 flex items-center gap-3 overflow-x-auto pb-1 text-[11px] font-mono">
      <span class="text-slate-600">Dated events across Journalism, SEC Filings, Wayback Snapshots, and On-Chain Transfers will synchronize here...</span>
    </div>
  </footer>

<script>
// --- XSS defense: all OSINT data is attacker-influenced. Every value interpolated into HTML goes through
// esc(); no inline event handlers are used (they would bypass the CSP nonce); clicks are routed through
// data-* attributes and one delegated listener; hrefs go through safeUrl().
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function safeUrl(u) {
  try {
    const parsed = new URL(u, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.href;
  } catch (e) { /* fall through */ }
  return '#';
}
function byId(id) { return document.getElementById(id); }

// --- API token: NEVER embedded in this page. When the server asks for it (401), the operator types it once;
// it is kept in memory and sessionStorage (this tab only), never in persistent browser storage.
const TOKEN_KEY = 'bunnyhole.apiToken';
let memToken = '';
let tokenPrompt = null;
function currentToken() {
  if (memToken) return memToken;
  try { memToken = sessionStorage.getItem(TOKEN_KEY) || ''; } catch (e) { memToken = ''; }
  return memToken;
}
function rememberToken(t) {
  memToken = t;
  try { sessionStorage.setItem(TOKEN_KEY, t); } catch (e) { /* memory only */ }
}
function askForToken() {
  if (!tokenPrompt) {
    tokenPrompt = Promise.resolve().then(() => {
      const entered = window.prompt('This Bunnyhole server requires its API token (BUNNYHOLE_API_TOKEN). It is kept for this browser tab only.');
      tokenPrompt = null;
      if (entered && entered.trim()) { rememberToken(entered.trim()); return true; }
      return false;
    });
  }
  return tokenPrompt;
}
async function apiFetch(url, opts) {
  const base = opts || {};
  const send = () => {
    const headers = Object.assign({}, base.headers || {});
    const t = currentToken();
    if (t) headers['X-Bunnyhole-Token'] = t;
    return fetch(url, Object.assign({}, base, {headers, credentials: 'same-origin'}));
  };
  let resp = await send();
  if (resp.status === 401 && await askForToken()) resp = await send();
  return resp;
}
async function readJson(resp) {
  let data = null;
  try { data = await resp.json(); } catch (e) { data = null; }
  if (!resp.ok) {
    const detail = data && data.detail ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)) : '';
    throw new Error('HTTP ' + resp.status + (detail ? ': ' + detail : ''));
  }
  return data;
}
async function apiGet(url) { return readJson(await apiFetch(url)); }
async function apiPost(url, body) {
  return readJson(await apiFetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}));
}
function reportError(e) {
  console.error(e);
  window.alert('Bunnyhole request failed: ' + (e && e.message ? e.message : String(e)));
}

let currentCase = null;
let graphNodes = [];
let graphEdges = [];
let selectedNode = null;
let highlightedPathIds = new Set();
let pathRegistry = [];
let predictedRegistry = [];
let pivotSeed = '';

// Canvas Pan & Zoom State
const canvas = byId('graphCanvas');
const ctx = canvas.getContext('2d');
let camX = 0, camY = 0, camScale = 1.0;
let isDragging = false, dragStartX = 0, dragStartY = 0, draggedNode = null;

const DOMAIN_COLORS = {
  journalism: '#fbbf24',
  fiat: '#34d399',
  osint: '#38bdf8',
  onchain: '#a78bfa',
  physical: '#f43f5e',
  skeptic: '#e879f9'
};

function resizeCanvas() {
  const rect = byId('canvasContainer').getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = rect.height * window.devicePixelRatio;
  ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function toggleModeUI() {
  const mode = byId('modeSelect').value;
  byId('traceInputs').classList.toggle('hidden', mode !== 'trace');
  byId('linkInputs').classList.toggle('hidden', mode !== 'link');
  byId('linkInputs').classList.toggle('flex', mode === 'link');
}

function toggleIntakeDrawer(forceOpen) {
  const dr = byId('intakeDrawer');
  if (typeof forceOpen === 'boolean') {
    dr.classList.toggle('hidden', !forceOpen);
  } else {
    dr.classList.toggle('hidden');
  }
  setTimeout(resizeCanvas, 50);
}

function splitCsvInput(id) {
  const val = (byId(id).value || '').trim();
  if (!val) return [];
  return val.split(/[,;\n]+/).map(s => s.trim()).filter(Boolean);
}

const INTAKE_FIELDS = ['intakeUsernames','intakeEmails','intakePhones','intakeCredentials','intakeWallets','intakeDomains','intakeOrgs','intakeFiles'];

function updateIntakeBadge() {
  let total = 0;
  INTAKE_FIELDS.forEach(f => { total += splitCsvInput(f).length; });
  const badge = byId('intakeBadge');
  if (total > 0 || byId('intakeHypothesis').value.trim()) {
    badge.textContent = total || 'H';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
  return total;
}

function clearIntakeDrawer() {
  ['intakeHypothesis','intakeExclusions'].concat(INTAKE_FIELDS).forEach(id => { byId(id).value = ''; });
  updateIntakeBadge();
}

async function autoTagFromOmni() {
  const raw = byId('seedInput').value.trim();
  if (!raw) return;
  let pkt;
  try { pkt = await apiPost('/api/parse-intake', {raw_text: raw}); } catch (e) { reportError(e); return; }
  if (pkt.hypothesis) byId('intakeHypothesis').value = pkt.hypothesis;
  if ((pkt.usernames || []).length) byId('intakeUsernames').value = pkt.usernames.join(', ');
  if ((pkt.emails || []).length) byId('intakeEmails').value = pkt.emails.join(', ');
  if ((pkt.phones || []).length) byId('intakePhones').value = pkt.phones.join(', ');
  if ((pkt.credentials || []).length) byId('intakeCredentials').value = pkt.credentials.join(', ');
  if ((pkt.wallets || []).length) byId('intakeWallets').value = pkt.wallets.join(', ');
  if ((pkt.domains || []).length) byId('intakeDomains').value = pkt.domains.join(', ');
  const orgsAndTails = [...(pkt.organizations || []), ...(pkt.aircraft_tails || [])];
  if (orgsAndTails.length) byId('intakeOrgs').value = orgsAndTails.join(', ');
  if ((pkt.evidence_files || []).length) byId('intakeFiles').value = pkt.evidence_files.join(', ');
  if ((pkt.exclusions || []).length) byId('intakeExclusions').value = pkt.exclusions.join(', ');
  updateIntakeBadge();
  toggleIntakeDrawer(true);
}

function buildIntakePayload() {
  const gear = byId('gearSelect').value;
  const depth = parseInt(byId('depthSelect').value || '2', 10);
  return {
    hypothesis: byId('intakeHypothesis').value.trim(),
    anchor_mode: byId('anchorModeSelect').value,
    usernames: splitCsvInput('intakeUsernames'),
    emails: splitCsvInput('intakeEmails'),
    phones: splitCsvInput('intakePhones'),
    credentials: splitCsvInput('intakeCredentials'),
    wallets: splitCsvInput('intakeWallets'),
    domains: splitCsvInput('intakeDomains'),
    organizations: splitCsvInput('intakeOrgs'),
    evidence_files: splitCsvInput('intakeFiles'),
    exclusions: splitCsvInput('intakeExclusions'),
    gear,
    depth,
    breadth: 4
  };
}

function setLoading(title) {
  byId('loadingTitle').textContent = title;
  byId('loadingOverlay').classList.remove('hidden');
}
function clearLoading() { byId('loadingOverlay').classList.add('hidden'); }

async function runIntakeInvestigation() {
  const payload = buildIntakePayload();
  setLoading('Running Dual-Mode Case Intake (' + payload.anchor_mode.toUpperCase() + ')...');
  try {
    hydrateCase(await apiPost('/api/intake', payload));
  } catch (e) {
    reportError(e);
  } finally {
    clearLoading();
  }
}

function switchTab(tab) {
  ['links', 'node', 'council', 'ach', 'dossier', 'arsenal'].forEach(t => {
    byId('tab-' + t).classList.toggle('hidden', t !== tab);
    const btn = byId('tabBtn-' + t);
    if (t === tab) {
      btn.className = 'flex-1 py-2.5 px-1 border-b-2 border-cyan-400 text-cyan-300 font-bold';
    } else {
      btn.className = 'flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white';
    }
  });
  if (tab === 'arsenal') loadArsenalStatus();
}

function loadPreset(mode, val) {
  byId('modeSelect').value = mode;
  toggleModeUI();
  byId('seedInput').value = val;
  runInvestigation();
}

async function runInvestigation() {
  const mode = byId('modeSelect').value;
  const gear = byId('gearSelect').value;
  const depth = parseInt(byId('depthSelect').value || '2', 10);

  // If the investigator populated the Case Intake Drawer, route through /api/intake
  if (mode === 'trace' && updateIntakeBadge() > 0) {
    return runIntakeInvestigation();
  }

  try {
    let data;
    if (mode === 'trace') {
      const seed = byId('seedInput').value.trim();
      if (!seed) return;
      // If the user pasted a multi-token dump with spaces/colons, route through /api/intake with raw_omni_text
      if (seed.includes(' ') && (seed.includes('@') || seed.includes(':') || seed.includes('0x') || seed.includes('?'))) {
        setLoading('Smart-Parsing Multi-Selector Dump & Hunting...');
        data = await apiPost('/api/intake', {raw_omni_text: seed, gear, depth, breadth: 4});
      } else {
        setLoading("Tracing '" + seed + "' down the rabbit hole (" + gear.toUpperCase() + ' gear)...');
        data = await apiPost('/api/trace', {seed, gear, depth, breadth: 4});
      }
    } else {
      const entity_a = byId('entityAInput').value.trim();
      const entity_b = byId('entityBInput').value.trim();
      setLoading("Link Sleuth Bidirectional Hunt: '" + entity_a + "' ↔ '" + entity_b + "'...");
      data = await apiPost('/api/link', {entity_a, entity_b, gear});
    }
    hydrateCase(data);
  } catch (e) {
    reportError(e);
  } finally {
    clearLoading();
  }
}

async function pivotNode(nodeId, seedVal) {
  if (!currentCase) return;
  setLoading("Pivoting deeper on '" + seedVal + "'...");
  try {
    hydrateCase(await apiPost('/api/pivot', {case_id: currentCase.case_id, node_id: nodeId, seed_value: seedVal}));
  } catch (e) {
    reportError(e);
  } finally {
    clearLoading();
  }
}

async function verifyMissingLink(nodeAId, labelA, nodeBId, labelB) {
  if (!currentCase) return;
  setLoading('Link Sleuth Probing Co-Occurrence: ' + labelA + ' ↔ ' + labelB + '...');
  try {
    hydrateCase(await apiPost('/api/verify-link', {case_id: currentCase.case_id, node_a_id: nodeAId, entity_a: labelA, node_b_id: nodeBId, entity_b: labelB}));
  } catch (e) {
    reportError(e);
  } finally {
    clearLoading();
  }
}

function hydrateCase(data) {
  currentCase = data;
  highlightedPathIds.clear();
  const rect = byId('canvasContainer').getBoundingClientRect();
  const cx = rect.width / 2, cy = rect.height / 2;

  const existingPos = {};
  graphNodes.forEach(n => { existingPos[n.id] = {x: n.x, y: n.y}; });

  graphNodes = (data.nodes || []).map((n, i) => {
    const total = Math.max(1, data.nodes.length);
    const angle = (2 * Math.PI * i) / total;
    const radius = n.hop_depth === 0 ? (total > 1 ? 65 : 0) : (130 * n.hop_depth + (i % 3) * 35);
    return {
      ...n,
      label: String(n.label === undefined || n.label === null ? n.id : n.label),
      x: existingPos[n.id] ? existingPos[n.id].x : cx + Math.cos(angle) * radius,
      y: existingPos[n.id] ? existingPos[n.id].y : cy + Math.sin(angle) * radius,
      vx: 0,
      vy: 0
    };
  });
  graphEdges = data.edges || [];

  // Update Stats HUD
  const stats = data.stats || {};
  byId('statNodes').textContent = stats.total_nodes || 0;
  byId('statEdges').textContent = stats.total_edges || 0;
  byId('statReceipts').textContent = stats.total_receipts || 0;
  byId('statBrokers').textContent = stats.cutout_brokers || 0;

  renderLinkSleuthTab(data.interconnections || {});
  renderCouncilTab(data.council || {});
  renderACHTab(data.ach_assessment || {});
  renderDossierTab(data);
  renderTimeline(data.timeline || []);
}

function renderCouncilTab(council) {
  const agg = council.aggregate_rankings || [];
  byId('councilLeaderboard').innerHTML = agg.length ? `
    <div class="p-2 rounded bg-slate-900/90 border border-slate-800">
      <div class="text-[10px] font-bold text-cyan-300 uppercase mb-1">Stage 2 Deterministic evidence ranking (not peer review)</div>
      ${agg.map((r, i) => `
        <div class="flex justify-between text-[10px] py-0.5 border-b border-slate-800/50">
          <span class="text-white">#${esc(i + 1)} ${esc(r.member_name)} <span class="text-slate-500">(${esc(r.anonymous_label)})</span></span>
          <span class="text-amber-300 font-bold">Avg Rank ${esc(r.average_rank)}</span>
        </div>
      `).join('')}
    </div>
  ` : '';

  const s1 = council.stage1_opinions || [];
  byId('councilStage1List').innerHTML = s1.map(op => `
    <details class="p-2 rounded bg-slate-900/90 border border-slate-800">
      <summary class="cursor-pointer text-[10px] font-bold text-violet-300">${esc(op.member_name)} (Rigor: ${esc(op.evidentiary_rigor_score)})</summary>
      <pre class="mt-1.5 text-[10px] text-slate-300 whitespace-pre-wrap">${esc(op.response || '')}</pre>
    </details>
  `).join('');

  const s3 = (council.stage3_chairman_verdict || {}).verdict_markdown || '';
  if (s3) {
    byId('councilChairmanBox').textContent = s3;
  }
}

function highlightPath(nodeIds) {
  highlightedPathIds = new Set(nodeIds || []);
}

function registerPath(nodeIds) {
  pathRegistry.push(Array.isArray(nodeIds) ? nodeIds.map(String) : []);
  return pathRegistry.length - 1;
}

function renderLinkSleuthTab(inter) {
  pathRegistry = [];
  predictedRegistry = [];
  const ks = inter.keystone_brokers || [];
  byId('keystoneList').innerHTML = ks.length ? ks.map(k => `
    <div data-action="select-node" data-node-id="${esc(k.node_id)}" class="p-2 rounded bg-slate-950/90 border border-yellow-500/30 hover:border-yellow-400 cursor-pointer flex items-center justify-between">
      <div>
        <div class="font-bold text-yellow-300">${esc(k.label)}</div>
        <div class="text-[10px] text-slate-400">Bridges: ${esc((k.domains_bridged || []).join(' ↔ '))} | Entropy: ${esc(k.domain_entropy)}</div>
      </div>
      <span class="px-1.5 py-0.5 rounded bg-yellow-950 text-yellow-300 text-[10px]">CB ${esc(k.betweenness_centrality)}</span>
    </div>
  `).join('') : '<div class="text-slate-500">No multi-domain cut-out brokers detected yet.</div>';

  const paths = inter.targeted_paths || inter.cross_domain_paths || [];
  byId('pathsList').innerHTML = paths.length ? paths.map(p => `
    <div data-action="highlight-path" data-idx="${esc(registerPath(p.node_ids))}" class="p-2 rounded bg-slate-950/90 border border-slate-800 hover:border-cyan-400 cursor-pointer">
      <div class="flex justify-between text-[10px] text-cyan-300 mb-1">
        <span>${esc(p.hop_count)} Hops (${esc((p.domains_crossed || []).join(' → '))})</span>
        <span>Score: ${esc(p.path_score)}</span>
      </div>
      <div class="text-white text-[11px] leading-snug">${(p.step_labels || []).map(esc).join(' <span class="text-cyan-400">──►</span> ')}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No multi-hop paths found yet.</div>';

  const preds = inter.predicted_missing_links || [];
  predictedRegistry = preds;
  byId('predictedLinksList').innerHTML = preds.length ? preds.map((pr, idx) => `
    <div class="p-2 rounded bg-slate-950/90 border border-slate-800 space-y-1">
      <div class="flex items-center justify-between">
        <span class="text-fuchsia-300 font-bold text-[10px]">Adamic-Adar Score: ${esc(pr.adamic_adar_score)}</span>
        <button data-action="verify-link" data-idx="${esc(idx)}"
          class="px-2 py-0.5 rounded bg-fuchsia-900/80 hover:bg-fuchsia-700 text-white text-[10px]">🔍 Probe Link</button>
      </div>
      <div class="text-white">${esc(pr.node_a_label)} <span class="text-fuchsia-400">↔</span> ${esc(pr.node_b_label)}</div>
      <div class="text-[10px] text-slate-400">Shared Rare Intermediary: ${esc((pr.shared_intermediaries || []).join(', '))}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No unverified triadic closures remaining.</div>';

  const cells = inter.syndicate_cells || [];
  byId('syndicateList').innerHTML = cells.length ? cells.map(c => `
    <div data-action="highlight-path" data-idx="${esc(registerPath(c.member_ids))}" class="p-2 rounded bg-slate-950/90 border border-slate-800 hover:border-emerald-400 cursor-pointer">
      <div class="flex justify-between text-emerald-300 font-bold text-[10px]">
        <span>${esc(String(c.cell_id || '').toUpperCase())}: ${esc(c.lead_entity)}</span>
        <span>${esc(c.size)} Entities (Avg Smoke ${esc(c.avg_smoke_score)})</span>
      </div>
      <div class="text-[10px] text-slate-400 mt-1">${(c.member_labels || []).map(esc).join(' • ')}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No syndicate clusters yet.</div>';
}

function renderACHTab(ach) {
  byId('achVerdictText').innerHTML = `
    <div class="text-cyan-300 text-[10px] font-bold">${esc(ach.primary_question || '')}</div>
    <div class="text-emerald-300 font-bold mt-1">${esc(ach.winning_hypothesis || '')}</div>
    <div class="text-slate-300 mt-1">${esc(ach.narrative_verdict || '')}</div>
    <div class="flex gap-3 mt-2 text-[10px] text-slate-400">
      <span>H1 Support: <b class="text-white">${esc(ach.h1_score)}</b></span>
      <span>H2 Inconsistencies: <b class="text-rose-400">${esc(ach.inconsistency_count_h2)}</b></span>
    </div>
  `;
  const rows = ach.matrix_rows || [];
  byId('achMatrixList').innerHTML = rows.map(r => `
    <div class="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px]">
      <div class="flex justify-between text-[10px] mb-1">
        <span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">NATO ${esc(r.admiralty_code)} | ${esc(r.diagnosticity)}</span>
        <span class="text-slate-400">H1: <b class="text-emerald-400">${esc(r.h1_coordinated_control)}</b> | H2: <b class="text-rose-400">${esc(r.h2_coincidence_shared_vendor)}</b> | H3: <b>${esc(r.h3_false_flag_spoofing)}</b></span>
      </div>
      <div class="text-slate-200">${esc(r.evidence_summary)}</div>
    </div>
  `).join('');
}

function renderDossierTab(data) {
  const learnings = (data.deep_research || {}).learnings || [];
  const synthesis = (data.synthesis || {}).markdown_brief || '';
  const ccHits = data.cross_case_hits || [];
  byId('learningsList').innerHTML = `
    ${ccHits.length ? `<div class="p-2 mb-2 rounded bg-amber-950/80 border border-amber-600/50 text-amber-200 text-[10px]">
         <b>🗄️ Cross-Case Entity Memory Hits (${esc(ccHits.length)}):</b><br/>
         ${ccHits.map(h => `• <b>${esc(h.label)}</b> seen in ${(h.prior_cases || []).map(c => `${esc(c.case_id)} ('${esc(c.seed_query)}')`).join(', ')}`).join('<br/>')}
       </div>` : ''}
    ${synthesis ? `<pre class="text-[10px] text-emerald-200 whitespace-pre-wrap bg-slate-950/90 p-2.5 rounded border border-emerald-800/50 mb-2">${esc(synthesis)}</pre>` : ''}
    ${learnings.map(l => `<div class="py-1 border-b border-slate-800/60">• ${esc(l)}</div>`).join('')}
  `;
}

function renderTimeline(items) {
  byId('timelineCount').textContent = items.length + ' dated events';
  if (!items.length) return;
  byId('timelineStrip').innerHTML = items.map(t => `
    <div class="min-w-[250px] max-w-[280px] p-2 rounded-lg bg-slate-900/90 border border-slate-800 shrink-0 flex flex-col justify-between">
      <div class="flex items-center justify-between text-[10px]">
        <span class="text-cyan-300 font-bold">${esc(String(t.timestamp || '').slice(0, 16))}</span>
        <span class="px-1.5 py-0.2 rounded bg-slate-800 text-amber-300">${esc(t.admiralty_code)}</span>
      </div>
      <div class="text-white font-bold truncate mt-0.5" title="${esc(t.title)}">${esc(t.title)}</div>
      <div class="text-[10px] text-slate-400 truncate">${esc(t.description)}</div>
    </div>
  `).join('');
}

function selectNodeById(nid) {
  const n = graphNodes.find(x => x.id === nid);
  if (n) {
    selectedNode = n;
    switchTab('node');
    renderSelectedNode(n);
  }
}

function renderSelectedNode(n) {
  const cleanSeed = String(n.label).replace(/^[^\w@0x]+/, '').split('(')[0].trim();
  pivotSeed = cleanSeed;
  const rcpts = n.receipts || [];
  byId('selectedNodePanel').innerHTML = `
    <div class="text-left space-y-3">
      <div class="p-3 rounded-lg bg-slate-900 border border-slate-700 space-y-2">
        <div class="flex items-center justify-between">
          <span class="px-2 py-0.5 rounded bg-violet-950 text-violet-300 text-[10px] font-bold uppercase">${esc(n.entity_type)} • ${esc(n.domain)}</span>
          <span class="text-rose-400 font-bold">🔥 Smoke: ${esc(Math.round(Number(n.smoke_score) || 0))}/100</span>
        </div>
        <div class="text-sm font-bold text-white break-all">${esc(n.label)}</div>
        <div class="text-[10px] text-slate-400">ID: ${esc(n.id)} | Hop Depth: ${esc(n.hop_depth)} | Centrality: ${esc(n.betweenness_centrality || 0)}</div>
        <div class="flex flex-wrap gap-1 pt-1">
          ${(n.risk_flags || []).map(f => `<span class="px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/50 text-[10px]">${esc(f)}</span>`).join('')}
        </div>
        <button data-action="pivot" class="w-full mt-2 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 text-white font-bold text-xs shadow">
          ⚡ Click-to-Pivot: Dispatch Agents on '${esc(cleanSeed.slice(0, 26))}'
        </button>
      </div>

      <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div class="text-[10px] font-bold text-slate-400 uppercase mb-1">Structured Attributes</div>
        <pre class="text-[10px] text-cyan-200 overflow-x-auto whitespace-pre-wrap">${esc(JSON.stringify(n.attributes || {}, null, 2))}</pre>
      </div>

      <div class="space-y-2">
        <div class="text-[10px] font-bold text-emerald-300 uppercase">🧾 Immutable SHA-256 Evidence Receipts (${esc(rcpts.length)})</div>
        ${rcpts.map(r => `
          <div class="p-2.5 rounded-lg bg-slate-900/95 border border-emerald-900/50 space-y-1">
            <div class="flex justify-between text-[10px]">
              <span class="text-emerald-300 font-bold">${esc(r.tool)}</span>
              <span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 font-bold">NATO ${esc(r.admiralty_code)}</span>
            </div>
            <div class="text-white text-[11px]">${esc(r.extracted_fact)}</div>
            <div class="text-[10px] text-slate-400 break-all">Source: <a href="${esc(safeUrl(r.source_url))}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 underline">${esc(r.source_url)}</a></div>
            <div class="text-[9px] text-slate-500 font-mono break-all">SHA-256: ${esc(r.sha256_proof)}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function downloadDossier() {
  if (!currentCase || !currentCase.markdown_dossier) return;
  const blob = new Blob([currentCase.markdown_dossier], {type: 'text/markdown'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'bunnyhole_dossier_' + String(currentCase.case_id).replace(/[^\w.-]/g, '_') + '.md';
  a.click();
}

// Force-Directed Simulation & Canvas Render Loop
function stepPhysics() {
  const N = graphNodes.length;
  const nodeMap = {};
  graphNodes.forEach(n => { nodeMap[n.id] = n; });

  // Repulsion
  for (let i = 0; i < N; i++) {
    for (let j = i + 1; j < N; j++) {
      const a = graphNodes[i], b = graphNodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let distSq = dx * dx + dy * dy + 1;
      if (distSq < 36000) {
        let f = 2200 / distSq;
        a.vx -= dx * f * 0.04;
        a.vy -= dy * f * 0.04;
        b.vx += dx * f * 0.04;
        b.vy += dy * f * 0.04;
      }
    }
  }

  // Spring attraction along edges
  graphEdges.forEach(e => {
    const s = nodeMap[e.source_id], t = nodeMap[e.target_id];
    if (!s || !t) return;
    let dx = t.x - s.x, dy = t.y - s.y;
    let dist = Math.sqrt(dx * dx + dy * dy) || 1;
    let targetDist = 145;
    let f = (dist - targetDist) * 0.008;
    s.vx += (dx / dist) * f;
    s.vy += (dy / dist) * f;
    t.vx -= (dx / dist) * f;
    t.vy -= (dy / dist) * f;
  });

  graphNodes.forEach(n => {
    if (n === draggedNode) return;
    n.x += n.vx;
    n.y += n.vy;
    n.vx *= 0.78;
    n.vy *= 0.78;
  });
}

function drawGraph() {
  stepPhysics();
  const rect = byId('canvasContainer').getBoundingClientRect();
  ctx.clearRect(0, 0, rect.width, rect.height);

  ctx.save();
  ctx.translate(camX, camY);
  ctx.scale(camScale, camScale);

  const nodeMap = {};
  graphNodes.forEach(n => { nodeMap[n.id] = n; });

  // Draw Edges
  graphEdges.forEach(e => {
    const s = nodeMap[e.source_id], t = nodeMap[e.target_id];
    if (!s || !t) return;
    const isHighlighted = highlightedPathIds.has(s.id) && highlightedPathIds.has(t.id);
    ctx.beginPath();
    if (e.tier === 'HYPOTHESIS' || e.tier === 'CIRCUMSTANTIAL') {
      ctx.setLineDash([5, 5]);
    } else {
      ctx.setLineDash([]);
    }
    ctx.strokeStyle = isHighlighted ? '#facc15' : 'rgba(148, 163, 184, 0.35)';
    ctx.lineWidth = isHighlighted ? 2.8 : 1.3;
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
    ctx.stroke();

    // Edge Label (canvas text is never parsed as HTML)
    const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
    ctx.fillStyle = isHighlighted ? '#fef08a' : 'rgba(148, 163, 184, 0.75)';
    ctx.font = '9px monospace';
    ctx.fillText(String(e.relation) + ' [' + String(e.admiralty_code) + ']', mx + 4, my - 3);
  });
  ctx.setLineDash([]);

  // Draw Nodes
  graphNodes.forEach(n => {
    const r = n.hop_depth === 0 ? 18 : Math.max(10, Math.min(17, 8 + (n.smoke_score || 30) / 10));
    const color = DOMAIN_COLORS[n.domain] || '#38bdf8';
    const isSel = selectedNode && selectedNode.id === n.id;
    const isPath = highlightedPathIds.has(n.id);

    if (n.is_cutout_broker || isSel || isPath) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 5, 0, Math.PI * 2);
      ctx.strokeStyle = isSel ? '#ffffff' : '#facc15';
      ctx.lineWidth = 2.2;
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = '#0f172a';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.fillStyle = '#f8fafc';
    ctx.font = n.hop_depth === 0 ? 'bold 11px monospace' : '10px monospace';
    ctx.fillText(n.label.slice(0, 34), n.x + r + 5, n.y + 3);
  });

  ctx.restore();
  requestAnimationFrame(drawGraph);
}
requestAnimationFrame(drawGraph);

// Mouse Interaction on Canvas
canvas.addEventListener('mousedown', e => {
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left - camX) / camScale;
  const my = (e.clientY - rect.top - camY) / camScale;

  const hit = graphNodes.find(n => {
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx * dx + dy * dy) <= 18;
  });

  if (hit) {
    draggedNode = hit;
    selectedNode = hit;
    switchTab('node');
    renderSelectedNode(hit);
  } else {
    isDragging = true;
    dragStartX = e.clientX - camX;
    dragStartY = e.clientY - camY;
  }
});

window.addEventListener('mousemove', e => {
  if (draggedNode) {
    const rect = canvas.getBoundingClientRect();
    draggedNode.x = (e.clientX - rect.left - camX) / camScale;
    draggedNode.y = (e.clientY - rect.top - camY) / camScale;
  } else if (isDragging) {
    camX = e.clientX - dragStartX;
    camY = e.clientY - dragStartY;
  }
});

window.addEventListener('mouseup', () => {
  isDragging = false;
  draggedNode = null;
});

canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.1 : 0.9;
  camScale = Math.max(0.25, Math.min(3.5, camScale * factor));
});

async function loadResearchFiles() {
  try {
    const d = await apiGet('/api/research-files');
    byId('researchFilesList').innerHTML = (d.files || []).map(f => `
      <details class="bg-slate-900/90 border border-slate-800 rounded p-2">
        <summary class="cursor-pointer text-cyan-300 font-bold text-[11px]">${esc(f.name)} (${esc((Number(f.size) / 1024).toFixed(1))} KB)</summary>
        <pre class="mt-2 text-[10px] text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">${esc(f.content)}</pre>
      </details>
    `).join('');
  } catch (e) {
    console.error(e);
  }
}

async function loadArsenalStatus() {
  let d;
  try { d = await apiGet('/api/arsenal'); } catch (e) { reportError(e); return; }
  const p = d.platform || {};
  byId('platformBanner').innerHTML = `
    <div class="text-cyan-300 font-bold">OS Profile: ${esc(p.display_name)} (${esc(String(p.distro || '').toUpperCase())})</div>
    <div class="text-[10px] text-slate-400">Package Manager: ${esc(p.pkg_manager)} | Vault: ~/.bunnyhole/api_keys.env</div>
  `;
  byId('apiKeysList').innerHTML = (d.api_keys || []).map(k => `
    <div data-action="pick-key" data-key="${esc(k.key)}" class="flex items-center justify-between p-1.5 rounded bg-slate-950/80 border border-slate-800/80 hover:border-amber-500/50 cursor-pointer text-[10px]">
      <div>
        <span class="${esc(k.configured ? 'text-emerald-400' : 'text-slate-500')} font-bold">${esc(k.configured ? '●' : '○')} ${esc(k.key)}</span>
        <span class="text-slate-500 ml-1">(${esc(k.category)})</span>
      </div>
      <span class="text-cyan-300">${esc(k.masked_value || 'Not set')}</span>
    </div>
  `).join('');

  const installEnabled = !!d.install_enabled;
  byId('arsenalToolsList').innerHTML = (d.tools || []).map(t => `
    <div class="p-2 rounded bg-slate-950/90 border border-slate-800 flex items-center justify-between text-[10px]">
      <div>
        <div class="font-bold ${esc(t.installed ? 'text-emerald-300' : 'text-amber-300')}">${esc(t.installed ? '✔' : '○')} ${esc(t.name)} <span class="text-slate-500">(${esc(t.type)})</span></div>
        <div class="text-slate-400">${esc(t.description)}</div>
      </div>
      ${t.installed ? `<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300">READY</span>` : `<button data-action="install-tool" data-tool="${esc(t.name)}" class="px-2 py-1 rounded bg-cyan-800 hover:bg-cyan-600 text-white font-bold" title="${esc(installEnabled ? 'Install via package manager' : 'Disabled over HTTP: run bunnyhole arsenal install locally')}">Install</button>`}
    </div>
  `).join('');
}

async function saveApiKey() {
  const key = byId('apiKeyNameInput').value.trim();
  const value = byId('apiKeyValueInput').value.trim();
  if (!key) return;
  try {
    await apiPost('/api/keys', {key, value});
  } catch (e) {
    reportError(e);
  }
  byId('apiKeyValueInput').value = '';
  loadArsenalStatus();
}

async function installArsenalTool(toolName) {
  try {
    await apiPost('/api/arsenal/install', {tool_name: toolName});
  } catch (e) {
    reportError(e);
  }
  loadArsenalStatus();
}

// --- Event wiring (no inline handlers anywhere in the markup) ---
byId('modeSelect').addEventListener('change', toggleModeUI);
byId('autoTagBtn').addEventListener('click', autoTagFromOmni);
byId('drawerToggleBtn').addEventListener('click', () => toggleIntakeDrawer());
byId('runBtn').addEventListener('click', runInvestigation);
byId('clearIntakeBtn').addEventListener('click', clearIntakeDrawer);
byId('launchIntakeBtn').addEventListener('click', runIntakeInvestigation);
byId('exportDossierBtn').addEventListener('click', downloadDossier);
byId('saveApiKeyBtn').addEventListener('click', saveApiKey);
document.querySelectorAll('[data-intake-field]').forEach(el => el.addEventListener('input', updateIntakeBadge));

document.addEventListener('click', ev => {
  const el = ev.target && ev.target.closest ? ev.target.closest('[data-action]') : null;
  if (!el) return;
  const action = el.dataset.action;
  if (action === 'tab') switchTab(el.dataset.tab);
  else if (action === 'preset') loadPreset('trace', el.dataset.preset);
  else if (action === 'select-node') selectNodeById(el.dataset.nodeId);
  else if (action === 'highlight-path') highlightPath(pathRegistry[Number(el.dataset.idx)]);
  else if (action === 'verify-link') {
    const pr = predictedRegistry[Number(el.dataset.idx)];
    if (pr) verifyMissingLink(pr.node_a_id, pr.node_a_label, pr.node_b_id, pr.node_b_label);
  } else if (action === 'pivot') {
    if (selectedNode) pivotNode(selectedNode.id, pivotSeed);
  } else if (action === 'pick-key') byId('apiKeyNameInput').value = el.dataset.key || '';
  else if (action === 'install-tool') installArsenalTool(el.dataset.tool);
});

// Load built-in research library metadata on boot
loadResearchFiles();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def serve_war_room() -> HTMLResponse:
    """Serve the static War-Room shell. It never contains the API token or any case data.

    Every inline ``<script>`` gets a fresh per-response CSP nonce; the page asks for the token at runtime.
    """
    nonce = secrets.token_urlsafe(18)
    html = WAR_ROOM_HTML.replace("__BUNNYHOLE_VERSION__", html_escape(bunnyhole.__version__))
    html = html.replace("<script", f'<script nonce="{nonce}"')
    return HTMLResponse(content=html, headers={"Content-Security-Policy": _war_room_csp(nonce)})
