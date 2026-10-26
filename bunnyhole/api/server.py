"""FastAPI Backend & Interactive War-Room UI for Bunnyhole."""

from __future__ import annotations

import asyncio
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from bunnyhole.engine.intake import CaseIntakePacket, SmartIntakeParser
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator, classify_seed_type

# --- Operational limits & safety knobs (override via environment) ---------------------------------
MAX_ACTIVE_CASES = int(os.environ.get("BUNNYHOLE_MAX_ACTIVE_CASES", "50"))
MAX_RAW_TEXT = int(os.environ.get("BUNNYHOLE_MAX_RAW_TEXT", "20000"))
MAX_SELECTORS = int(os.environ.get("BUNNYHOLE_MAX_SELECTORS", "64"))
MAX_CONCURRENT_INVESTIGATIONS = int(os.environ.get("BUNNYHOLE_MAX_CONCURRENT", "4"))
# Optional bearer token: when BUNNYHOLE_API_TOKEN is set, mutating endpoints require it. The
# first-party War-Room UI reads it from the page it is served, so same-origin use is seamless.
API_TOKEN = os.environ.get("BUNNYHOLE_API_TOKEN", "").strip()

_INVESTIGATION_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)

app = FastAPI(
    title="Bunnyhole Investigative Intelligence API",
    version="0.2.0",
    description="Multi-Domain Investigative AI: Journalism, Forensic Accounting, Red Team OSINT, Link Sleuth & On-Chain Crypto",
)

# Block DNS-rebinding and remote Host spoofing: only loopback hostnames are served.
# Starlette strips the port before matching, so bare loopback hostnames cover localhost:PORT too.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    )
    return resp


async def require_token(authorization: str = Header(default=""), x_bunnyhole_token: str = Header(default="")) -> None:
    """Enforce the per-launch bearer token on mutating endpoints when one is configured."""
    if not API_TOKEN:
        return
    supplied = x_bunnyhole_token.strip()
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if supplied != API_TOKEN:
        raise HTTPException(status_code=401, detail="Missing or invalid API token")


# Active investigation sessions in memory (bounded LRU; oldest cases are evicted).
ACTIVE_CASES: "OrderedDict[str, BunnyholeOrchestrator]" = OrderedDict()


def _register_case(orch: BunnyholeOrchestrator) -> None:
    """Store a case, evicting the least-recently-used once the cap is exceeded."""
    ACTIVE_CASES[orch.graph.case_id] = orch
    ACTIVE_CASES.move_to_end(orch.graph.case_id)
    while len(ACTIVE_CASES) > MAX_ACTIVE_CASES:
        ACTIVE_CASES.popitem(last=False)


class TraceRequest(BaseModel):
    seed: str = Field(..., min_length=1, max_length=512)
    gear: GearMode = GearMode.FAST
    depth: int = Field(2, ge=1, le=4)
    breadth: int = Field(4, ge=2, le=8)


class LinkRequest(BaseModel):
    entity_a: str = Field(..., min_length=1, max_length=512)
    entity_b: str = Field(..., min_length=1, max_length=512)
    gear: GearMode = GearMode.FAST


class ParseIntakeRequest(BaseModel):
    raw_text: str = Field(..., max_length=MAX_RAW_TEXT)


class PivotRequest(BaseModel):
    case_id: str
    node_id: str
    seed_value: str
    lead_type: Optional[str] = None


class CooccurrenceRequest(BaseModel):
    case_id: str
    node_a_id: str
    entity_a: str
    node_b_id: str
    entity_b: str


@app.post("/api/parse-intake")
async def api_parse_intake(req: ParseIntakeRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Auto-parse raw clipboard dumps / free-text notes into structured selectors & hypothesis."""
    packet = SmartIntakeParser.parse_omni_text(req.raw_text)
    return packet.model_dump()


@app.post("/api/intake")
async def api_intake(packet: CaseIntakePacket, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Run a full Dual-Mode Case Intake & Multi-Selector Investigation (Hypothesis + Credentials/Selectors)."""
    normalized = SmartIntakeParser.normalize_packet(packet)
    if normalized.total_selectors() > MAX_SELECTORS:
        raise HTTPException(status_code=413, detail=f"Too many selectors (max {MAX_SELECTORS})")
    async with _INVESTIGATION_SEMAPHORE:
        orch = BunnyholeOrchestrator(
            seed_query=normalized.summary_seed_label(),
            gear=normalized.gear,
            max_depth=normalized.depth,
            initial_breadth=normalized.breadth,
            intake_packet=normalized,
        )
        res = await orch.run_intake_investigation(normalized)
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return res


@app.post("/api/trace")
async def api_trace(req: TraceRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    async with _INVESTIGATION_SEMAPHORE:
        orch = BunnyholeOrchestrator(
            seed_query=req.seed,
            gear=req.gear,
            max_depth=req.depth,
            initial_breadth=req.breadth,
        )
        res = await orch.run_investigation()
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return res


@app.post("/api/link")
async def api_link(req: LinkRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    async with _INVESTIGATION_SEMAPHORE:
        orch = BunnyholeOrchestrator(
            seed_query=f"{req.entity_a} <-> {req.entity_b}",
            gear=req.gear,
            max_depth=2,
            initial_breadth=4,
        )
        res = await orch.run_bidirectional_link_investigation(req.entity_a, req.entity_b)
    _register_case(orch)
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return res


@app.post("/api/pivot")
async def api_pivot(req: PivotRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Click-to-Pivot on any existing node in the investigation graph!"""
    orch = ACTIVE_CASES.get(req.case_id)
    if not orch:
        raise HTTPException(status_code=404, detail="Case ID not found in active memory")
    ACTIVE_CASES.move_to_end(req.case_id)
    ltype = req.lead_type or classify_seed_type(req.seed_value)[0]
    node = orch.graph.nodes.get(req.node_id)
    hop = (node.hop_depth + 1) if node else 2
    await orch._execute_lead(ltype, req.seed_value, req.node_id, hop_depth=hop)
    orch._harvest_step_learnings_and_followups(current_hop=hop)
    orch.link_sleuth.break_dead_ends(current_hop=hop)
    res = orch.compile_full_result()
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return res


@app.post("/api/verify-link")
async def api_verify_link(req: CooccurrenceRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Verify a predicted Adamic-Adar missing link via live Joint Co-Occurrence search."""
    orch = ACTIVE_CASES.get(req.case_id)
    if not orch:
        raise HTTPException(status_code=404, detail="Case ID not found")
    await orch.link_sleuth.verify_interconnection_cooccurrence(
        req.entity_a, req.node_a_id, req.entity_b, req.node_b_id, hop_depth=2
    )
    res = orch.compile_full_result()
    res["markdown_dossier"] = orch.graph.export_markdown_dossier()
    return res


class SetKeyRequest(BaseModel):
    key: str
    value: str


class InstallToolRequest(BaseModel):
    tool_name: str


@app.get("/api/arsenal")
async def api_arsenal_status() -> Dict[str, Any]:
    """Return cross-platform OS profile, installed status of all 24 OSINT/forensic tools, and API key status."""
    from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager

    mgr = ArsenalManager()
    return {
        "platform": mgr.platform_info,
        "tools": mgr.check_arsenal_status(),
        "api_keys": mgr.get_api_keys_status(),
        "vault_paths": [str(BUNNYHOLE_ENV_FILE), str(LEGACY_OSINT_ENV_FILE)],
    }


@app.post("/api/arsenal/install")
async def api_arsenal_install(req: InstallToolRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Install a tool via uv/pipx/brew/apt/go and return updated arsenal status."""
    from bunnyhole.arsenal.manager import ArsenalManager

    mgr = ArsenalManager()
    # install_tool runs blocking subprocesses; offload so the event loop stays responsive.
    res = await asyncio.to_thread(mgr.install_tool, req.tool_name)
    return {
        "install_result": res,
        "tools": mgr.check_arsenal_status(),
    }


@app.post("/api/keys")
async def api_set_key(req: SetKeyRequest, _: None = Depends(require_token)) -> Dict[str, Any]:
    """Persist a recognized API key to the local vault (~/.bunnyhole/api_keys.env, chmod 600)."""
    from bunnyhole.arsenal.manager import ArsenalManager

    mgr = ArsenalManager()
    try:
        mgr.set_api_key(req.key, req.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "api_keys": mgr.get_api_keys_status()}


@app.get("/api/cases")
async def api_list_cases(q: Optional[str] = None) -> Dict[str, Any]:
    """List saved investigations in ~/.bunnyhole/cases.db or search historical entity memory."""
    from bunnyhole.engine.storage import CaseStore

    store = CaseStore()
    return {
        "cases": store.list_cases(limit=25),
        "entity_matches": store.search_entity_memory(q) if q else [],
    }


@app.get("/api/cases/{case_id}")
async def api_get_case(case_id: str) -> Dict[str, Any]:
    """Load a full saved investigation from ~/.bunnyhole/cases.db."""
    from bunnyhole.engine.storage import CaseStore

    store = CaseStore()
    data = store.get_case(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found in SQLite store")
    return data


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
          <span class="text-[10px] px-2 py-0.5 rounded bg-violet-950/90 text-violet-300 border border-violet-700/50 font-mono">v0.2 PALANTIR × ZACHXBT × BELLINGCAT ENGINE</span>
        </div>
        <p class="text-[11px] text-slate-400 font-mono">Journalism • Forensic Accounting • Red Team OSINT • Link Sleuth • On-Chain Crypto</p>
      </div>
    </div>

    <!-- MODE & SEARCH CONTROLS -->
    <div class="flex items-center gap-2 flex-1 max-w-5xl mx-4">
      <select id="modeSelect" onchange="toggleModeUI()" class="bg-slate-900 text-xs font-mono text-cyan-300 border border-slate-700 rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-400">
        <option value="trace">🎯 Omni-Trace / Intake</option>
        <option value="link">🔗 Link Sleuth (A ↔ B)</option>
      </select>

      <div id="traceInputs" class="flex-1 flex items-center gap-1.5">
        <input id="seedInput" type="text" value="vitalik.eth" placeholder="Paste any seed OR messy case notes (hypothesis, @handles, emails, phones, email:pass, wallets, domains)..."
          class="w-full bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-violet-500" />
        <button onclick="autoTagFromOmni()" title="Auto-extract hypothesis, credentials, emails, phones, wallets & domains into the Case Intake Drawer"
          class="px-2.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-amber-300 border border-amber-600/40 text-[11px] font-mono shrink-0">✨ Auto-Tag</button>
      </div>

      <div id="linkInputs" class="hidden flex-1 items-center gap-2">
        <input id="entityAInput" type="text" value="vitalik.eth" placeholder="Entity A (e.g. vitalik.eth or Coinbase)..."
          class="w-1/2 bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-amber-400" />
        <span class="text-amber-400 font-mono text-xs">↔</span>
        <input id="entityBInput" type="text" value="ethereum.org" placeholder="Entity B (e.g. ethereum.org or GitHub handle)..."
          class="w-1/2 bg-slate-950/90 text-xs font-mono text-white border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-amber-400" />
      </div>

      <button id="drawerToggleBtn" onclick="toggleIntakeDrawer()" class="px-2.5 py-2 rounded-lg bg-violet-950/90 hover:bg-violet-900 text-violet-200 border border-violet-600/60 text-xs font-mono shrink-0 flex items-center gap-1">
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

      <button id="runBtn" onclick="runInvestigation()" class="bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-500 hover:to-cyan-500 text-white font-mono text-xs font-bold px-4 py-2 rounded-lg shadow-lg transition flex items-center gap-1.5 shrink-0">
        <span>🚀 HUNT</span>
      </button>
    </div>

    <!-- QUICK PRESETS -->
    <div class="flex items-center gap-1.5 text-[11px] font-mono">
      <span class="text-slate-500">Presets:</span>
      <button onclick="loadPreset('trace','vitalik.eth')" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-violet-300 border border-slate-800">⛓️ vitalik.eth</button>
      <button onclick="loadPreset('trace','uniswap.org')" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-800">🌐 uniswap.org</button>
      <button onclick="loadPreset('trace','Coinbase')" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-emerald-300 border border-slate-800">🏛️ Coinbase</button>
      <button onclick="loadPreset('trace','N628TS')" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-amber-300 border border-slate-800">✈️ Jet N628TS</button>
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
        <button onclick="clearIntakeDrawer()" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">Clear</button>
        <button onclick="runIntakeInvestigation()" class="px-3 py-1 rounded bg-gradient-to-r from-fuchsia-600 to-cyan-600 hover:from-fuchsia-500 hover:to-cyan-500 text-white font-bold text-[11px]">🚀 Launch Multi-Selector Hunt</button>
      </div>
    </div>

    <!-- WORKING HYPOTHESIS BAR -->
    <div class="grid grid-cols-12 gap-3">
      <div class="col-span-8">
        <label class="block text-[10px] text-cyan-300 font-bold uppercase mb-1">🧠 Working Hypothesis / Investigative Question (Steers CIA ACH Matrix & +20 Lead Priority Boost)</label>
        <input id="intakeHypothesis" type="text" oninput="updateIntakeBadge()" placeholder="e.g. Prove whether @handle_x and dev@acme.io are the same operator laundering funds through 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045..."
          class="w-full bg-slate-950/95 text-white border border-slate-700 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-400" />
      </div>
      <div class="col-span-4">
        <label class="block text-[10px] text-rose-300 font-bold uppercase mb-1">🚫 Exclusions / Negative Scope (Comma-separated)</label>
        <input id="intakeExclusions" type="text" oninput="updateIntakeBadge()" placeholder="e.g. cloudflare.com, google.com, 0x000000..."
          class="w-full bg-slate-950/95 text-rose-200 border border-rose-900/60 rounded px-3 py-1.5 text-xs focus:outline-none focus:border-rose-400" />
      </div>
    </div>

    <!-- 8 STRUCTURED CREDENTIAL & SELECTOR LOCKERS -->
    <div class="grid grid-cols-4 gap-2.5 text-[11px]">
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">👤 Usernames / @Handles</label>
        <input id="intakeUsernames" type="text" oninput="updateIntakeBadge()" placeholder="@vbuterin, vitalik..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">📧 Emails</label>
        <input id="intakeEmails" type="text" oninput="updateIntakeBadge()" placeholder="founder@domain.com, leak@..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-slate-300 font-bold mb-1">📱 Phone Numbers (E.164 / Intl)</label>
        <input id="intakePhones" type="text" oninput="updateIntakeBadge()" placeholder="+1-415-555-0199..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-amber-300 font-bold mb-1">🔑 Leaked Credentials (email:pass / hash)</label>
        <input id="intakeCredentials" type="text" oninput="updateIntakeBadge()" placeholder="user@corp.io:Hunter2025! (k-Anonymity SHA1)"
          class="w-full bg-slate-950 border border-amber-900/60 rounded px-2.5 py-1.5 text-amber-200" />
      </div>
      <div>
        <label class="block text-[10px] text-violet-300 font-bold mb-1">⛓️ Crypto Wallets / ENS / BTC</label>
        <input id="intakeWallets" type="text" oninput="updateIntakeBadge()" placeholder="vitalik.eth, 0xd8dA..., bc1q..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-cyan-300 font-bold mb-1">🌐 Domains & IP Addresses</label>
        <input id="intakeDomains" type="text" oninput="updateIntakeBadge()" placeholder="uniswap.org, 1.1.1.1..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-emerald-300 font-bold mb-1">🏛️ Orgs / Names / Tail Numbers</label>
        <input id="intakeOrgs" type="text" oninput="updateIntakeBadge()" placeholder="Coinbase, N628TS..."
          class="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white" />
      </div>
      <div>
        <label class="block text-[10px] text-fuchsia-300 font-bold mb-1">📄 Local Evidence (.pdf / .docx paths)</label>
        <input id="intakeFiles" type="text" oninput="updateIntakeBadge()" placeholder="/path/to/filing.pdf, /path/memo.docx"
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
        <button onclick="switchTab('links')" id="tabBtn-links" class="flex-1 py-2.5 px-1 border-b-2 border-cyan-400 text-cyan-300 font-bold">🔗 Links</button>
        <button onclick="switchTab('node')" id="tabBtn-node" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🧾 Node</button>
        <button onclick="switchTab('council')" id="tabBtn-council" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🏛️ Council</button>
        <button onclick="switchTab('ach')" id="tabBtn-ach" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">⚖️ ACH</button>
        <button onclick="switchTab('dossier')" id="tabBtn-dossier" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">📚 Dossier</button>
        <button onclick="switchTab('arsenal')" id="tabBtn-arsenal" class="flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white">🛠️ Arsenal</button>
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
          <p class="text-[10px] text-slate-400 mt-0.5">Stage 1: 5 Specialist Seat Opinions → Stage 2: Anonymized Peer Review (Response A..E) → Stage 3: Chairman Verdict</p>
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
          <button onclick="downloadDossier()" class="px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-[11px] font-bold">⬇ Export .MD</button>
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
            <button onclick="saveApiKey()" class="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold text-[11px]">Save</button>
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
// --- XSS defense: all OSINT data is attacker-influenced, so escape before inserting into HTML ---
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escAttr(v) { return esc(v); }
function safeUrl(u) {
  try {
    const parsed = new URL(u, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.href;
  } catch (e) { /* fall through */ }
  return '#';
}
function jsStr(v) { return esc(String(v === null || v === undefined ? '' : v).replace(/['"\\]/g, '')); }

// Optional per-launch API token (injected server-side; empty when auth is disabled).
const API_TOKEN = "__BUNNYHOLE_API_TOKEN__";
function jsonHeaders() {
  const h = {'Content-Type': 'application/json'};
  if (API_TOKEN) h['X-Bunnyhole-Token'] = API_TOKEN;
  return h;
}

let currentCase = null;
let graphNodes = [];
let graphEdges = [];
let selectedNode = null;
let highlightedPathIds = new Set();

// Canvas Pan & Zoom State
const canvas = document.getElementById('graphCanvas');
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
  const rect = document.getElementById('canvasContainer').getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = rect.height * window.devicePixelRatio;
  ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function toggleModeUI() {
  const mode = document.getElementById('modeSelect').value;
  document.getElementById('traceInputs').classList.toggle('hidden', mode !== 'trace');
  document.getElementById('linkInputs').classList.toggle('hidden', mode !== 'link');
  document.getElementById('linkInputs').classList.toggle('flex', mode === 'link');
}

function toggleIntakeDrawer(forceOpen) {
  const dr = document.getElementById('intakeDrawer');
  if (typeof forceOpen === 'boolean') {
    dr.classList.toggle('hidden', !forceOpen);
  } else {
    dr.classList.toggle('hidden');
  }
  setTimeout(resizeCanvas, 50);
}

function splitCsvInput(id) {
  const val = (document.getElementById(id).value || '').trim();
  if (!val) return [];
  return val.split(/[,;\n]+/).map(s => s.trim()).filter(Boolean);
}

function updateIntakeBadge() {
  const fields = ['intakeUsernames','intakeEmails','intakePhones','intakeCredentials','intakeWallets','intakeDomains','intakeOrgs','intakeFiles'];
  let total = 0;
  fields.forEach(f => { total += splitCsvInput(f).length; });
  const badge = document.getElementById('intakeBadge');
  if (total > 0 || document.getElementById('intakeHypothesis').value.trim()) {
    badge.innerText = total || 'H';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
  return total;
}

function clearIntakeDrawer() {
  ['intakeHypothesis','intakeExclusions','intakeUsernames','intakeEmails','intakePhones','intakeCredentials','intakeWallets','intakeDomains','intakeOrgs','intakeFiles'].forEach(id => {
    document.getElementById(id).value = '';
  });
  updateIntakeBadge();
}

async function autoTagFromOmni() {
  const raw = document.getElementById('seedInput').value.trim();
  if (!raw) return;
  const resp = await fetch('/api/parse-intake', {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({raw_text: raw})
  });
  const pkt = await resp.json();
  if (pkt.hypothesis) document.getElementById('intakeHypothesis').value = pkt.hypothesis;
  if ((pkt.usernames || []).length) document.getElementById('intakeUsernames').value = pkt.usernames.join(', ');
  if ((pkt.emails || []).length) document.getElementById('intakeEmails').value = pkt.emails.join(', ');
  if ((pkt.phones || []).length) document.getElementById('intakePhones').value = pkt.phones.join(', ');
  if ((pkt.credentials || []).length) document.getElementById('intakeCredentials').value = pkt.credentials.join(', ');
  if ((pkt.wallets || []).length) document.getElementById('intakeWallets').value = pkt.wallets.join(', ');
  if ((pkt.domains || []).length) document.getElementById('intakeDomains').value = pkt.domains.join(', ');
  const orgsAndTails = [...(pkt.organizations || []), ...(pkt.aircraft_tails || [])];
  if (orgsAndTails.length) document.getElementById('intakeOrgs').value = orgsAndTails.join(', ');
  if ((pkt.evidence_files || []).length) document.getElementById('intakeFiles').value = pkt.evidence_files.join(', ');
  if ((pkt.exclusions || []).length) document.getElementById('intakeExclusions').value = pkt.exclusions.join(', ');
  updateIntakeBadge();
  toggleIntakeDrawer(true);
}

function buildIntakePayload() {
  const gear = document.getElementById('gearSelect').value;
  const depth = parseInt(document.getElementById('depthSelect').value || '2', 10);
  return {
    hypothesis: document.getElementById('intakeHypothesis').value.trim(),
    anchor_mode: document.getElementById('anchorModeSelect').value,
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

async function runIntakeInvestigation() {
  const payload = buildIntakePayload();
  const overlay = document.getElementById('loadingOverlay');
  document.getElementById('loadingTitle').innerText = `Running Dual-Mode Case Intake (${payload.anchor_mode.toUpperCase()})...`;
  overlay.classList.remove('hidden');
  try {
    const resp = await fetch('/api/intake', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    hydrateCase(data);
  } finally {
    overlay.classList.add('hidden');
  }
}

function switchTab(tab) {
  ['links', 'node', 'council', 'ach', 'dossier', 'arsenal'].forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('hidden', t !== tab);
    const btn = document.getElementById('tabBtn-' + t);
    if (t === tab) {
      btn.className = 'flex-1 py-2.5 px-1 border-b-2 border-cyan-400 text-cyan-300 font-bold';
    } else {
      btn.className = 'flex-1 py-2.5 px-1 border-b-2 border-transparent text-slate-400 hover:text-white';
    }
  });
  if (tab === 'arsenal') loadArsenalStatus();
}

function loadPreset(mode, val) {
  document.getElementById('modeSelect').value = mode;
  toggleModeUI();
  document.getElementById('seedInput').value = val;
  runInvestigation();
}

async function runInvestigation() {
  const mode = document.getElementById('modeSelect').value;
  const gear = document.getElementById('gearSelect').value;
  const depth = parseInt(document.getElementById('depthSelect').value || '2', 10);

  // If the investigator populated the Case Intake Drawer, route through /api/intake
  if (mode === 'trace' && updateIntakeBadge() > 0) {
    return runIntakeInvestigation();
  }

  const overlay = document.getElementById('loadingOverlay');
  overlay.classList.remove('hidden');

  try {
    let resp;
    if (mode === 'trace') {
      const seed = document.getElementById('seedInput').value.trim();
      if (!seed) return;
      // If the user pasted a multi-token dump with spaces/colons, route through /api/intake with raw_omni_text
      if (seed.includes(' ') && (seed.includes('@') || seed.includes(':') || seed.includes('0x') || seed.includes('?'))) {
        document.getElementById('loadingTitle').innerText = `Smart-Parsing Multi-Selector Dump & Hunting...`;
        resp = await fetch('/api/intake', {
          method: 'POST',
          headers: jsonHeaders(),
          body: JSON.stringify({raw_omni_text: seed, gear, depth, breadth: 4})
        });
      } else {
        document.getElementById('loadingTitle').innerText = `Tracing '${seed}' down the rabbit hole (${gear.toUpperCase()} gear)...`;
        resp = await fetch('/api/trace', {
          method: 'POST',
          headers: jsonHeaders(),
          body: JSON.stringify({seed, gear, depth, breadth: 4})
        });
      }
    } else {
      const entity_a = document.getElementById('entityAInput').value.trim();
      const entity_b = document.getElementById('entityBInput').value.trim();
      document.getElementById('loadingTitle').innerText = `Link Sleuth Bidirectional Hunt: '${entity_a}' ↔ '${entity_b}'...`;
      resp = await fetch('/api/link', {
        method: 'POST',
        headers: jsonHeaders(),
        body: JSON.stringify({entity_a, entity_b, gear})
      });
    }
    const data = await resp.json();
    hydrateCase(data);
  } catch (e) {
    console.error(e);
  } finally {
    overlay.classList.add('hidden');
  }
}

async function pivotNode(nodeId, seedVal) {
  if (!currentCase) return;
  const overlay = document.getElementById('loadingOverlay');
  document.getElementById('loadingTitle').innerText = `Pivoting deeper on '${seedVal}'...`;
  overlay.classList.remove('hidden');
  try {
    const resp = await fetch('/api/pivot', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({case_id: currentCase.case_id, node_id: nodeId, seed_value: seedVal})
    });
    const data = await resp.json();
    hydrateCase(data);
  } finally {
    overlay.classList.add('hidden');
  }
}

async function verifyMissingLink(nodeAId, labelA, nodeBId, labelB) {
  if (!currentCase) return;
  const overlay = document.getElementById('loadingOverlay');
  document.getElementById('loadingTitle').innerText = `Link Sleuth Probing Co-Occurrence: ${labelA} ↔ ${labelB}...`;
  overlay.classList.remove('hidden');
  try {
    const resp = await fetch('/api/verify-link', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({case_id: currentCase.case_id, node_a_id: nodeAId, entity_a: labelA, node_b_id: nodeBId, entity_b: labelB})
    });
    const data = await resp.json();
    hydrateCase(data);
  } finally {
    overlay.classList.add('hidden');
  }
}

function hydrateCase(data) {
  currentCase = data;
  highlightedPathIds.clear();
  const rect = document.getElementById('canvasContainer').getBoundingClientRect();
  const cx = rect.width / 2, cy = rect.height / 2;

  const existingPos = {};
  graphNodes.forEach(n => { existingPos[n.id] = {x: n.x, y: n.y}; });

  graphNodes = (data.nodes || []).map((n, i) => {
    const total = Math.max(1, data.nodes.length);
    const angle = (2 * Math.PI * i) / total;
    const radius = n.hop_depth === 0 ? (total > 1 ? 65 : 0) : (130 * n.hop_depth + (i % 3) * 35);
    return {
      ...n,
      x: existingPos[n.id] ? existingPos[n.id].x : cx + Math.cos(angle) * radius,
      y: existingPos[n.id] ? existingPos[n.id].y : cy + Math.sin(angle) * radius,
      vx: 0,
      vy: 0
    };
  });
  graphEdges = data.edges || [];

  // Update Stats HUD
  document.getElementById('statNodes').innerText = data.stats.total_nodes;
  document.getElementById('statEdges').innerText = data.stats.total_edges;
  document.getElementById('statReceipts').innerText = data.stats.total_receipts;
  document.getElementById('statBrokers').innerText = data.stats.cutout_brokers;

  renderLinkSleuthTab(data.interconnections || {});
  renderCouncilTab(data.council || {});
  renderACHTab(data.ach_assessment || {});
  renderDossierTab(data);
  renderTimeline(data.timeline || []);
}

function renderCouncilTab(council) {
  const agg = council.aggregate_rankings || [];
  document.getElementById('councilLeaderboard').innerHTML = agg.length ? `
    <div class="p-2 rounded bg-slate-900/90 border border-slate-800">
      <div class="text-[10px] font-bold text-cyan-300 uppercase mb-1">Stage 2 Anonymized Peer Leaderboard</div>
      ${agg.map((r, i) => `
        <div class="flex justify-between text-[10px] py-0.5 border-b border-slate-800/50">
          <span class="text-white">#${i+1} ${r.member_name} <span class="text-slate-500">(${r.anonymous_label})</span></span>
          <span class="text-amber-300 font-bold">Avg Rank ${r.average_rank}</span>
        </div>
      `).join('')}
    </div>
  ` : '';

  const s1 = council.stage1_opinions || [];
  document.getElementById('councilStage1List').innerHTML = s1.map(op => `
    <details class="p-2 rounded bg-slate-900/90 border border-slate-800">
      <summary class="cursor-pointer text-[10px] font-bold text-violet-300">${esc(op.member_name)} (Rigor: ${esc(op.evidentiary_rigor_score)})</summary>
      <pre class="mt-1.5 text-[10px] text-slate-300 whitespace-pre-wrap">${esc(op.response || '')}</pre>
    </details>
  `).join('');

  const s3 = (council.stage3_chairman_verdict || {}).verdict_markdown || '';
  if (s3) {
    document.getElementById('councilChairmanBox').innerText = s3;
  }
}

function highlightPath(nodeIds) {
  highlightedPathIds = new Set(nodeIds);
}

function renderLinkSleuthTab(inter) {
  const ks = inter.keystone_brokers || [];
  document.getElementById('keystoneList').innerHTML = ks.length ? ks.map(k => `
    <div onclick="selectNodeById('${jsStr(k.node_id)}')" class="p-2 rounded bg-slate-950/90 border border-yellow-500/30 hover:border-yellow-400 cursor-pointer flex items-center justify-between">
      <div>
        <div class="font-bold text-yellow-300">${esc(k.label)}</div>
        <div class="text-[10px] text-slate-400">Bridges: ${esc((k.domains_bridged || []).join(' ↔ '))} | Entropy: ${esc(k.domain_entropy)}</div>
      </div>
      <span class="px-1.5 py-0.5 rounded bg-yellow-950 text-yellow-300 text-[10px]">CB ${esc(k.betweenness_centrality)}</span>
    </div>
  `).join('') : '<div class="text-slate-500">No multi-domain cut-out brokers detected yet.</div>';

  const paths = inter.targeted_paths || inter.cross_domain_paths || [];
  document.getElementById('pathsList').innerHTML = paths.length ? paths.map((p, idx) => `
    <div onclick='highlightPath(${JSON.stringify(p.node_ids || [])})' class="p-2 rounded bg-slate-950/90 border border-slate-800 hover:border-cyan-400 cursor-pointer">
      <div class="flex justify-between text-[10px] text-cyan-300 mb-1">
        <span>${esc(p.hop_count)} Hops (${esc((p.domains_crossed || []).join(' → '))})</span>
        <span>Score: ${esc(p.path_score)}</span>
      </div>
      <div class="text-white text-[11px] leading-snug">${(p.step_labels || []).map(esc).join(' <span class="text-cyan-400">──►</span> ')}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No multi-hop paths found yet.</div>';

  const preds = inter.predicted_missing_links || [];
  document.getElementById('predictedLinksList').innerHTML = preds.length ? preds.map(pr => `
    <div class="p-2 rounded bg-slate-950/90 border border-slate-800 space-y-1">
      <div class="flex items-center justify-between">
        <span class="text-fuchsia-300 font-bold text-[10px]">Adamic-Adar Score: ${esc(pr.adamic_adar_score)}</span>
        <button onclick="verifyMissingLink('${jsStr(pr.node_a_id)}', '${jsStr(pr.node_a_label)}', '${jsStr(pr.node_b_id)}', '${jsStr(pr.node_b_label)}')"
          class="px-2 py-0.5 rounded bg-fuchsia-900/80 hover:bg-fuchsia-700 text-white text-[10px]">🔍 Probe Link</button>
      </div>
      <div class="text-white">${esc(pr.node_a_label)} <span class="text-fuchsia-400">↔</span> ${esc(pr.node_b_label)}</div>
      <div class="text-[10px] text-slate-400">Shared Rare Intermediary: ${esc((pr.shared_intermediaries || []).join(', '))}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No unverified triadic closures remaining.</div>';

  const cells = inter.syndicate_cells || [];
  document.getElementById('syndicateList').innerHTML = cells.length ? cells.map(c => `
    <div onclick='highlightPath(${JSON.stringify(c.member_ids || [])})' class="p-2 rounded bg-slate-950/90 border border-slate-800 hover:border-emerald-400 cursor-pointer">
      <div class="flex justify-between text-emerald-300 font-bold text-[10px]">
        <span>${esc((c.cell_id || '').toUpperCase())}: ${esc(c.lead_entity)}</span>
        <span>${esc(c.size)} Entities (Avg Smoke ${esc(c.avg_smoke_score)})</span>
      </div>
      <div class="text-[10px] text-slate-400 mt-1">${(c.member_labels || []).map(esc).join(' • ')}</div>
    </div>
  `).join('') : '<div class="text-slate-500">No syndicate clusters yet.</div>';
}

function renderACHTab(ach) {
  document.getElementById('achVerdictText').innerHTML = `
    <div class="text-cyan-300 text-[10px] font-bold">${esc(ach.primary_question || '')}</div>
    <div class="text-emerald-300 font-bold mt-1">${esc(ach.winning_hypothesis || '')}</div>
    <div class="text-slate-300 mt-1">${esc(ach.narrative_verdict || '')}</div>
    <div class="flex gap-3 mt-2 text-[10px] text-slate-400">
      <span>H1 Support: <b class="text-white">${esc(ach.h1_score)}</b></span>
      <span>H2 Inconsistencies: <b class="text-rose-400">${esc(ach.inconsistency_count_h2)}</b></span>
    </div>
  `;
  const rows = ach.matrix_rows || [];
  document.getElementById('achMatrixList').innerHTML = rows.map(r => `
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
  const ccBanner = ccHits.length
    ? `<div class="p-2 mb-2 rounded bg-amber-950/80 border border-amber-600/50 text-amber-200 text-[10px]">
         <b>🗄️ Cross-Case Entity Memory Hits (${ccHits.length}):</b><br/>
         ${ccHits.map(h => `• <b>${esc(h.label)}</b> seen in ${(h.prior_cases || []).map(c => esc(c.case_id) + " ('" + esc(c.seed_query) + "')").join(', ')}`).join('<br/>')}
       </div>`
    : '';
  const synthHtml = synthesis
    ? `<pre class="text-[10px] text-emerald-200 whitespace-pre-wrap bg-slate-950/90 p-2.5 rounded border border-emerald-800/50 mb-2">${esc(synthesis)}</pre>`
    : '';
  document.getElementById('learningsList').innerHTML = ccBanner + synthHtml + learnings.map(l => `<div class="py-1 border-b border-slate-800/60">• ${esc(l)}</div>`).join('');
}

function renderTimeline(items) {
  document.getElementById('timelineCount').innerText = `${items.length} dated events`;
  if (!items.length) return;
  document.getElementById('timelineStrip').innerHTML = items.map(t => `
    <div class="min-w-[250px] max-w-[280px] p-2 rounded-lg bg-slate-900/90 border border-slate-800 shrink-0 flex flex-col justify-between">
      <div class="flex items-center justify-between text-[10px]">
        <span class="text-cyan-300 font-bold">${(t.timestamp || '').slice(0, 16)}</span>
        <span class="px-1.5 py-0.2 rounded bg-slate-800 text-amber-300">${t.admiralty_code}</span>
      </div>
      <div class="text-white font-bold truncate mt-0.5" title="${escAttr(t.title)}">${esc(t.title)}</div>
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
  const cleanSeed = n.label.replace(/^[^\w@0x]+/, '').split('(')[0].trim();
  const rcpts = n.receipts || [];
  document.getElementById('selectedNodePanel').innerHTML = `
    <div class="text-left space-y-3">
      <div class="p-3 rounded-lg bg-slate-900 border border-slate-700 space-y-2">
        <div class="flex items-center justify-between">
          <span class="px-2 py-0.5 rounded bg-violet-950 text-violet-300 text-[10px] font-bold uppercase">${esc(n.entity_type)} • ${esc(n.domain)}</span>
          <span class="text-rose-400 font-bold">🔥 Smoke: ${Math.round(n.smoke_score)}/100</span>
        </div>
        <div class="text-sm font-bold text-white break-all">${esc(n.label)}</div>
        <div class="text-[10px] text-slate-400">ID: ${esc(n.id)} | Hop Depth: ${esc(n.hop_depth)} | Centrality: ${esc(n.betweenness_centrality || 0)}</div>
        <div class="flex flex-wrap gap-1 pt-1">
          ${(n.risk_flags || []).map(f => `<span class="px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/50 text-[10px]">${esc(f)}</span>`).join('')}
        </div>
        <button onclick="pivotNode('${jsStr(n.id)}', '${jsStr(cleanSeed)}')" class="w-full mt-2 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 text-white font-bold text-xs shadow">
          ⚡ Click-to-Pivot: Dispatch Agents on '${esc(cleanSeed.slice(0, 26))}'
        </button>
      </div>

      <div class="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div class="text-[10px] font-bold text-slate-400 uppercase mb-1">Structured Attributes</div>
        <pre class="text-[10px] text-cyan-200 overflow-x-auto whitespace-pre-wrap">${esc(JSON.stringify(n.attributes || {}, null, 2))}</pre>
      </div>

      <div class="space-y-2">
        <div class="text-[10px] font-bold text-emerald-300 uppercase">🧾 Immutable SHA-256 Evidence Receipts (${rcpts.length})</div>
        ${rcpts.map(r => `
          <div class="p-2.5 rounded-lg bg-slate-900/95 border border-emerald-900/50 space-y-1">
            <div class="flex justify-between text-[10px]">
              <span class="text-emerald-300 font-bold">${esc(r.tool)}</span>
              <span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 font-bold">NATO ${esc(r.admiralty_code)}</span>
            </div>
            <div class="text-white text-[11px]">${esc(r.extracted_fact)}</div>
            <div class="text-[10px] text-slate-400 break-all">Source: <a href="${escAttr(safeUrl(r.source_url))}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 underline">${esc(r.source_url)}</a></div>
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
  a.download = `bunnyhole_dossier_${currentCase.case_id}.md`;
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
  const rect = document.getElementById('canvasContainer').getBoundingClientRect();
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

    // Edge Label
    const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
    ctx.fillStyle = isHighlighted ? '#fef08a' : 'rgba(148, 163, 184, 0.75)';
    ctx.font = '9px monospace';
    ctx.fillText(`${e.relation} [${e.admiralty_code}]`, mx + 4, my - 3);
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

// Load built-in research library metadata on boot
fetch('/api/research-files').then(r => r.json()).then(d => {
  const list = document.getElementById('researchFilesList');
  list.innerHTML = (d.files || []).map(f => `
    <details class="bg-slate-900/90 border border-slate-800 rounded p-2">
      <summary class="cursor-pointer text-cyan-300 font-bold text-[11px]">${esc(f.name)} (${(f.size/1024).toFixed(1)} KB)</summary>
      <pre class="mt-2 text-[10px] text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">${esc(f.content)}</pre>
    </details>
  `).join('');
});

async function loadArsenalStatus() {
  const r = await fetch('/api/arsenal');
  const d = await r.json();
  const p = d.platform || {};
  document.getElementById('platformBanner').innerHTML = `
    <div class="text-cyan-300 font-bold">OS Profile: ${p.display_name} (${(p.distro || '').toUpperCase()})</div>
    <div class="text-[10px] text-slate-400">Package Manager: ${p.pkg_manager} | Vault: ~/.bunnyhole/api_keys.env</div>
  `;
  const kList = document.getElementById('apiKeysList');
  kList.innerHTML = (d.api_keys || []).map(k => `
    <div onclick="document.getElementById('apiKeyNameInput').value='${k.key}'" class="flex items-center justify-between p-1.5 rounded bg-slate-950/80 border border-slate-800/80 hover:border-amber-500/50 cursor-pointer text-[10px]">
      <div>
        <span class="${k.configured ? 'text-emerald-400' : 'text-slate-500'} font-bold">${k.configured ? '●' : '○'} ${k.key}</span>
        <span class="text-slate-500 ml-1">(${k.category})</span>
      </div>
      <span class="text-cyan-300">${k.masked_value || 'Not set'}</span>
    </div>
  `).join('');

  const tList = document.getElementById('arsenalToolsList');
  tList.innerHTML = (d.tools || []).map(t => `
    <div class="p-2 rounded bg-slate-950/90 border border-slate-800 flex items-center justify-between text-[10px]">
      <div>
        <div class="font-bold ${t.installed ? 'text-emerald-300' : 'text-amber-300'}">${t.installed ? '✔' : '○'} ${t.name} <span class="text-slate-500">(${t.type})</span></div>
        <div class="text-slate-400">${t.description}</div>
      </div>
      ${t.installed
        ? `<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300">READY</span>`
        : `<button onclick="installArsenalTool('${t.name}')" class="px-2 py-1 rounded bg-cyan-800 hover:bg-cyan-600 text-white font-bold">Install</button>`}
    </div>
  `).join('');
}

async function saveApiKey() {
  const key = document.getElementById('apiKeyNameInput').value.trim();
  const value = document.getElementById('apiKeyValueInput').value.trim();
  if (!key) return;
  await fetch('/api/keys', {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({key, value})
  });
  document.getElementById('apiKeyValueInput').value = '';
  loadArsenalStatus();
}

async function installArsenalTool(toolName) {
  await fetch('/api/arsenal/install', {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({tool_name: toolName})
  });
  loadArsenalStatus();
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def serve_war_room() -> HTMLResponse:
    # Inject the optional API token into the first-party UI (JSON-escaped). Empty when auth is off.
    import json as _json

    token_literal = _json.dumps(API_TOKEN)[1:-1]  # value without surrounding quotes
    html = WAR_ROOM_HTML.replace("__BUNNYHOLE_API_TOKEN__", token_literal)
    return HTMLResponse(content=html)
