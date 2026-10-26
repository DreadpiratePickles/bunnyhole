# 🐇🕳️ Bunnyhole

**Autonomous Multi-Domain Investigative Intelligence Engine.**

Bunnyhole follows news & document trails like an investigative journalist (Bellingcat / ICIJ),
corporate shells & accounting anomalies like a forensic short-seller (Hindenburg / OCCRP),
infrastructure, breach & aviation/maritime recon like a red-teamer & SIGINT analyst, and
cross-chain fund flows like an on-chain forensic sleuth (ZachXBT / TRM) — then fuses every
finding into one **provenance-backed investigation graph** where each node and edge carries a
cryptographic `EvidenceReceipt`, a NATO Admiralty grade (`A1`–`F6`), and a Red-Cell skeptic review.

> ⚖️ **Lawful, ethical use only.** Bunnyhole aggregates open-source and public-record data for
> journalism, forensic research, threat intelligence, and due diligence. Read
> [`ACCEPTABLE_USE.md`](./ACCEPTABLE_USE.md) before using it. Findings are **leads, not verdicts** —
> the grading framework exists precisely because automated attribution produces false positives.

---

## Highlights

- **Lead → Pivot → Prove** recursive engine (breadth × depth, with dynamic tapering) across 6 specialist agents: Journalist, Accountant, OSINT, On-Chain, Link Sleuth, and the Red-Cell Skeptic.
- **Universal Investigation Graph** (OCCRP FollowTheMoney-compatible) with SHA-256 evidence receipts, NSA strong/soft selector chaining, betweenness-centrality cut-out detection, and a CIA ACH matrix.
- **Red-Cell guardrails** that downgrade known false-positive traps (mass registered-agent addresses, shared Cloudflare/Anycast CDN IPs, soft-to-soft links).
- **IC-aligned tradecraft:** every receipt is tagged **PAI vs CAI** (ODNI IC OSINT Strategy provenance taxonomy), and each dossier ends with a **CIA Key Assumptions Check** — the fragile assumptions the verdict rests on, because findings are leads, not verdicts.
- **Karpathy 3-stage LLM Council** for adversarial multi-model deliberation (optional; degrades to a deterministic council with no API key).
- **Cross-case entity memory** in local SQLite — entities seen in a prior case resurface automatically.
- **Two interfaces:** a Typer CLI and an interactive FastAPI "War-Room" web UI.
- **Keyless by default:** works against free/public endpoints; API keys only raise limits or add sources.

---

## Install

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
git clone <your-fork-url> bunnyhole && cd bunnyhole
uv sync                 # runtime deps
uv sync --extra dev     # + test/lint/type tooling
```

Optional external CLI tools (sherlock, subfinder, holehe, whois, …) enable DEEP-gear features:

```bash
bunnyhole doctor                       # health-check what's installed
python scripts/install_osint_tools.py  # cross-platform installer (Kali/Parrot/macOS)
```

## Quickstart

```bash
# Single-seed investigation (company, domain, wallet/ENS, @handle, email, or tail number)
uv run bunnyhole trace vitalik.eth
uv run bunnyhole trace example.com --gear deep --depth 3 --out dossier.md

# Multi-selector / hypothesis-driven intake (paste a messy dump; selectors are auto-parsed)
uv run bunnyhole intake "acme.io founder@acme.io 0x1234... -exclude:unrelated.com" \
  --hypothesis "Is acme.io controlled by the same operator as its token?"

# Meet-in-the-middle: how do two entities connect?
uv run bunnyhole link vitalik.eth ethereum.org

# 3-stage adversarial LLM council verdict over a seed
uv run bunnyhole council acme.io

# Aviation & document forensics
uv run bunnyhole jet N628TS
uv run bunnyhole doc-forensics ./leaked.pdf

# Saved cases & cross-case entity memory
uv run bunnyhole cases --search "0x1234"

# Full-screen War-Room TUI (live graph, tabbed inspector, streaming agent log)
uv run bunnyhole ui                      # or: bunnyhole ui vitalik.eth  /  bunnyhole tui
uv run bunnyhole menu                    # classic prompt-driven menu

# The War-Room, in a browser or on the web
uv run textual serve "bunnyhole ui"      # same TUI, served to a browser
uv run bunnyhole serve                   # the FastAPI web War-Room at http://127.0.0.1:8000
```

### The War-Room TUI

`bunnyhole ui` opens a full-screen terminal app (built on [Textual](https://textual.textualize.io/))
that mirrors the web War-Room: a seed/intake sidebar, a live entity table ranked by smoke score with
cut-out brokers flagged, a tabbed inspector (Node receipts, Links, Council, ACH, Dossier, Arsenal), a
timeline strip, and a streaming agent-telemetry log. It is keyboard- and mouse-driven: `enter` runs,
`tab` moves between panes, `/` focuses the seed, `p` pivots on the highlighted entity, `d` jumps to the
dossier, `q` quits. Because it is a Textual app, `textual serve "bunnyhole ui"` serves the exact same
interface to a web browser.

## Configuration (API keys)

Every key is **optional**. Copy [`.env.example`](./.env.example) and set the keys you have, either by
exporting them or via the vault:

```bash
uv run bunnyhole keys --set SHODAN_API_KEY=xxxx    # stored in ~/.bunnyhole/api_keys.env (chmod 600)
uv run bunnyhole keys                              # list configured keys (masked)
```

Keys cover breach/infostealer intel, infrastructure recon, identity/email, corporate registries,
on-chain explorers, and AI synthesis (OpenRouter / Anthropic / OpenAI / Gemini). Setting any one AI
key enables the LLM narrative synthesis and multi-model council.

## Web War-Room security

The FastAPI server is built for **local use** and ships with: loopback-only trusted-host enforcement
(blocks DNS rebinding), a strict Content-Security-Policy and security headers, output escaping of all
untrusted OSINT data, a bounded in-memory case store, and request-size/concurrency limits.

To expose it beyond `127.0.0.1`, set a token first — it is required on all mutating endpoints and
auto-injected into the first-party UI:

```bash
export BUNNYHOLE_API_TOKEN="$(openssl rand -hex 24)"
uv run bunnyhole serve --host 0.0.0.0   # warns and refuses to be unauthenticated
```

Never expose the server to an untrusted network: it stores API keys and case data locally.

## Testing & quality

```bash
uv run pytest             # test suite
uv run ruff check .       # lint
uv run mypy bunnyhole     # type check
```

## Architecture

```
bunnyhole/
├── engine/        # models, intake parser, orchestrator, graph, storage, synthesizer, council, netutil
├── agents/        # journalist, accountant, osint, onchain, link_sleuth specialists
├── api/           # FastAPI server + interactive War-Room UI
├── cli/           # Typer command-line interface
└── arsenal/       # cross-platform tool installer, health doctor, API-key vault
```

The flow: **intake** parses selectors & hypothesis → the **orchestrator** runs the recursive
breadth × depth loop, dispatching **agents** that write provenance-backed nodes/edges into the
**graph** → the **Link Sleuth** breaks dead ends and maps interconnections → the **skeptic** runs
network analytics (betweenness, ACH) → the **synthesizer** and **council** produce a citation-backed
dossier → **storage** persists the case and correlates cross-case entity memory.

## 📚 Tradecraft Research Library

The complete 9-volume intelligence & tradecraft specification lives in
[`research/00_INDEX.md`](./research/00_INDEX.md):

1. [Architecture Blueprint](./research/01_architecture_blueprint.md)
2. [Core 4 Pillars Tradecraft](./research/02_core_4_pillars_tradecraft.md)
3. [Physical OSINT — Aviation, Maritime, Supply Chain](./research/03_physical_osint_aviation_maritime_supply_chain.md)
4. [Breach, Telegram, Dark-Web Threat Intel](./research/04_breach_telegram_darkweb_threat_intel.md)
5. [Advanced DeFi — MEV, Bundlers, Mixer Demixing](./research/05_advanced_defi_mev_bundlers_mixer_demixing.md)
6. [Global Offshore Leaks, GLEIF, PSC, UCC-1](./research/06_global_offshore_leaks_gleif_psc_ucc1.md)
7. [Link Analysis & Dead-End Breaker](./research/07_link_analysis_dead_end_breaker_and_interconnections.md)
8. [Deep-Research Loop & Creative Endpoints](./research/08_deep_research_loop_and_creative_endpoints.md)
9. [LLM Council & Ultimate Architecture](./research/09_llm_council_and_ultimate_architecture.md)

## Project docs

- [`AUDIT.md`](./AUDIT.md) — security & code-quality audit, applied fixes, and prioritized backlog.
- [`ACCEPTABLE_USE.md`](./ACCEPTABLE_USE.md) — responsible-use policy.
- [`LICENSE`](./LICENSE) — MIT.
