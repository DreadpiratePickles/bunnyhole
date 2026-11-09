<div align="center">

# 🐇🕳️ Bunnyhole

**Point it at one clue. Get back a provenance-backed investigation graph.**

*Every node carries a receipt. Every verdict is a lead. The rabbit hole has guardrails.*

[![python](https://img.shields.io/badge/python-3.11+-blue)](#-install)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![keyless](https://img.shields.io/badge/keyless-by%20default-brightgreen)](#-configuration-api-keys)
[![tor](https://img.shields.io/badge/Tor-routable%20%7C%20onion%20search-purple)](#-going-dark-tor-proxies--anonsurf)
[![use](https://img.shields.io/badge/use-lawful%20%26%20ethical%20only-important)](ACCEPTABLE_USE.md)

</div>

---

A domain. A wallet. A shell company. An `@handle` scrawled in a leak. You have *one thread*,
and somewhere on the other end is the whole sweater.

**Bunnyhole pulls the thread.** It follows news & document trails like an investigative
journalist (Bellingcat / ICIJ), corporate shells & accounting anomalies like a forensic
short-seller (Hindenburg / OCCRP), infrastructure & breach recon like a red-teamer, and
cross-chain fund flows like an on-chain sleuth (ZachXBT / TRM) — then **fuses every finding into
one graph** where each node and edge carries a cryptographic `EvidenceReceipt`, a NATO Admiralty
grade (`A1`–`F6`), and a Red-Cell skeptic review that actively tries to prove the link *wrong*.

It is keyless by default, runs on free public endpoints, and will happily route the whole
operation through Tor. And because automated attribution lies with a straight face, **every
finding is a lead, not a verdict** — the grading framework exists precisely so you know which
ones to trust.

> ⚖️ **Lawful, ethical use only.** Bunnyhole aggregates open-source and public-record data for
> journalism, forensic research, threat intelligence, and due diligence. It investigates
> **known entities from public records — it is not a contact-scraper, and not for surveilling,
> doxxing, or stalking private individuals.** Read [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md)
> before you point it at anything.

---

## ⚡ The 60-second demo

Illustrative output (a live run needs network; a seed's real results vary):

```console
$ uv sync
$ uv run bunnyhole trace brightpeak-roofing.com

🐇🕳️  BUNNYHOLE INTELLIGENCE SUMMARY
   Seed: brightpeak-roofing.com   Gear: FAST (Breadth=4, Depth=2)
   Entities: 37   Edges: 52   SHA-256 Receipts: 61   Cut-Out Brokers: 2
   CIA ACH Verdict: H1 — Coordinated control (shared TLS SAN + reused GA tag)

🔥 Top Entities & Cross-Domain Cut-Out Brokers
   🧬 Google Analytics: G-8KD…   TRACKER   osint   smoke 55   ANALYTICS_TAG_SELECTOR
   🌐 staging.brightpeak-roofing.com          osint   smoke 58   SENSITIVE_STAGING_SUBDOMAIN
   🖥️ 203.0.113.9 (Ports: [22, 443])          osint   smoke 65   SENSITIVE_MANAGEMENT_PORTS_OPEN
   🧅 juhanurmihxlp77…onion                    osint   smoke 60   DARKWEB_ONION_MENTION

📚 every line above links back to a source you can click and a SHA-256 receipt you can verify.
```

One seed in. A sourced, graded, skeptic-reviewed map out. Reach for `--gear deep --depth 3` when
a lead earns the extra minutes.

## 🧭 What's actually happening down there

- **Lead → Pivot → Prove**, recursively. A breadth × depth engine with dynamic tapering drives six
  specialists: **Journalist**, **Accountant**, **OSINT**, **On-Chain**, **Link Sleuth**, and the
  **Red-Cell Skeptic** whose only job is to downgrade your favorite finding.
- **Universal Investigation Graph** (OCCRP FollowTheMoney-compatible): SHA-256 evidence receipts,
  NSA strong/soft selector chaining, betweenness-centrality cut-out detection, and a CIA ACH matrix.
- **Guardrails against the obvious traps:** mass registered-agent addresses, shared Cloudflare /
  Anycast CDN IPs, and soft-to-soft links get downgraded before they fool you.
- **IC-grade provenance:** every receipt is tagged **PAI vs CAI** (ODNI OSINT Strategy taxonomy),
  and every dossier ends with a **CIA Key Assumptions Check** — the fragile assumptions your verdict
  is quietly resting on.
- **Karpathy 3-stage LLM Council** for adversarial multi-model deliberation (optional; degrades to a
  deterministic council with no API key).
- **Cross-case memory** in local SQLite — an entity seen in a prior case resurfaces automatically.
- **Four ways in:** a Typer CLI, a full-screen Textual TUI, a FastAPI / browser "War-Room," and a
  Model-Context-Protocol (MCP) server so your own AI client can drive the same engine (see
  [The four surfaces](#-the-four-surfaces)).
- **Personas and a remembered profile:** pick a lens (journalist, compliance, threat-intel, ...), keep a
  watchlist, and every run is tuned and framed to match.
- **A private-investigator (`--pi`) stream:** purpose-gated, free-and-lawful-sources-only engagements
  that end in a bottom-line-up-front report (see [PI stream](#-private-investigator-pi-stream)).

## 📦 Install

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole
uv sync                 # runtime deps
uv sync --extra dev     # + test/lint/type tooling
uv run bunnyhole --help # list every command
```

Version 0.2.0. There is no install step beyond `uv sync`; every command below is run as
`uv run bunnyhole <command>` from the checkout. Nothing needs an API key to start (see
[Configuration](#-configuration-api-keys)).

Bunnyhole runs great on nothing but free public endpoints. Want the heavy DEEP-gear tools too?

```bash
uv run bunnyhole doctor                       # health-check the arsenal + your API keys
python scripts/install_osint_tools.py         # cross-platform installer (Kali / Parrot / macOS)
```

## 🎛️ Everyday commands

```bash
# Single-seed investigation (company, domain, wallet/ENS, @handle, email, or tail number)
uv run bunnyhole trace vitalik.eth
uv run bunnyhole trace example.com --gear deep --depth 3 --out dossier.md

# Hypothesis-driven intake: paste a messy dump (selectors are auto-parsed) or pass selectors as flags
uv run bunnyhole intake --dump "acme.io founder@acme.io 0x1234... -exclude:unrelated.com" \
  --hypothesis "Is acme.io run by the same operator as its token?"
uv run bunnyhole intake --domain acme.io --email founder@acme.io --wallet vitalik.eth --exclude unrelated.com

# Meet-in-the-middle: how do two entities connect?
uv run bunnyhole link vitalik.eth ethereum.org

# Dark-web: search the Tor index (Ahmia) for public mentions of a selector (keyless, no Tor needed)
uv run bunnyhole darkweb acme.io
uv run bunnyhole --tor darkweb acme.io --fetch-onion   # also fetch each hit's title through Tor

# 3-stage adversarial LLM council verdict over a seed
uv run bunnyhole council acme.io

# Aviation & document forensics
uv run bunnyhole jet N628TS
uv run bunnyhole doc-forensics ./leaked.pdf

# Saved cases & cross-case entity memory
uv run bunnyhole cases --search "0x1234"
uv run bunnyhole cases --load <case_id>

# Full-screen War-Room TUI, or the FastAPI War-Room in a browser
uv run bunnyhole ui
uv run bunnyhole serve                    # http://127.0.0.1:8000

# Run THIS instance as an MCP server for Claude Desktop / IDE copilots (see below)
uv run bunnyhole mcp --print-config       # prints the config snippet to paste into your client
uv run bunnyhole mcp                      # the server itself (your client launches this for you)
```

`--proxy` and `--tor` are **global** options: they go before the command
(`uv run bunnyhole --tor trace acme.io`), not after it, and not on `uv run`.

### Every command

| Command | What it does | Needs |
| --- | --- | --- |
| `trace <seed>` | Autonomous multi-domain investigation of one seed; Markdown dossier (`--out`) and graph JSON (`--json`). Also takes `--pi` (see below) | Network |
| `intake` | Case intake: a hypothesis plus any known selectors (`--dump`, `--domain`, `--email`, `--wallet`, `--org`, `--username`, `--phone`, `--doc`, `--exclude`) and an anchor mode. Also takes `--pi` | Network |
| `link <a> <b>` | Link Sleuth, bidirectional meet-in-the-middle: how do two entities connect? | Network |
| `jet <tail_or_hex>` | FAA N-Number to ICAO hex and back, plus ADS-B telemetry from adsb.lol | Network |
| `council <seed>` | 5-seat LLM Council (specialist briefs, anonymized peer review, chairman verdict) over a short trace | Network; an AI key for real model deliberation, deterministic council without one |
| `darkweb <query>` | Ahmia search of the Tor index for public mentions of a selector; `--fetch-onion` fetches titles | Network; `--fetch-onion` needs a Tor SOCKS listener |
| `anonsurf [action]` | Install and drive Parrot/Kali's system-wide Tor proxy: `status`, `start`, `stop`, `restart`, `change`, `install` | Linux, root |
| `doc-forensics <file>` | Word RSID revision fingerprints (`.docx`) or PDF `/Info` and XMP timezone metadata (`.pdf`) | Local file only |
| `arsenal` / `doctor` | Health-check the external tool arsenal and API keys; `--install <tool\|all>` installs missing tools (`doctor` is an alias) | Local |
| `personas` | List the investigator personas | Local |
| `profile` | View or edit your remembered profile: persona, watchlist, jurisdictions, default gear/depth/breadth, exclusions | Local |
| `cases` | List saved cases (`~/.bunnyhole/cases.db`), `--search` cross-case entity memory, `--load <case_id>` | Local |
| `keys` | List API keys (masked) or `--set KEY=VALUE` into the vault (`~/.bunnyhole/api_keys.env`) | Local |
| `ui` / `tui` | Full-screen Textual War-Room (optional seed argument to prefill; `tui` is an alias) | Local; running a case needs network |
| `menu` | Classic prompt-driven terminal command center | Local |
| `serve` | FastAPI War-Room and API (`--host`, `--port`; defaults `127.0.0.1:8000`) | Local; running a case needs network |
| `mcp` | MCP server over stdio; `--print-config` prints the client config snippet, `--no-uv` for a plain `bunnyhole mcp` entry | Local; tools need network to investigate |
| `pi guide \| sources \| legal \| playbook \| out-of-scope` | Offline private-investigator reference tables | Local |

### 🧩 The four surfaces

One engine, four front doors. They share the same case vault, key vault and profile.

- **CLI** (`trace`, `intake`, `link`, ...): scriptable, writes dossiers and graph JSON. The only surface
  that runs a `--pi` engagement.
- **TUI** (`ui` / `tui`): a seed/intake sidebar, live entity table, a tabbed inspector (Node, Links,
  Council, ACH, Dossier) and a streaming agent log. Keys: `enter`/`r` run, `/` focus the seed box, `d`
  dossier, `p` pivot, `ctrl+l` clear log, `q` quit. `textual serve` (browser delivery) is not installed
  by default; use `serve` for a browser.
- **API / War-Room** (`serve`): FastAPI server plus a browser UI (see
  [Web War-Room security](#-web-war-room-security)). Endpoints include `/api/trace`, `/api/intake`,
  `/api/link`, `/api/pivot`, `/api/arsenal`, `/api/keys` and `/api/cases`.
- **MCP** (`mcp`): your own AI client drives the engine as tools (next section).

### 🤖 Your own MCP server

Every install is its own **Model-Context-Protocol server** — point Claude Desktop or any MCP client
at it and the client drives *your* Bunnyhole instance as tools, keyless and optionally Tor-routed,
against your local case vault. It exposes 16 tools: `interpret` (plain language to a run plan, runs
nothing), `trace`, `intake`, `link`, `jet`, `darkweb`, `arsenal_status`, `list_cases`, `search_cases`,
`load_case`, `sanctions_screen`, `get_profile`, `set_persona`, `watchlist_add`, `watchlist_remove` and
`pi_reference` (read-only PI tables; no MCP tool runs a PI engagement). It runs on your machine over
stdio, with no hosting and no open port.

```bash
uv run bunnyhole mcp --print-config    # copy the JSON into claude_desktop_config.json, restart the client
```

Full setup, the tool list, and safety notes: **[docs/MCP_SERVER.md](docs/MCP_SERVER.md)**.

### 🧭 Make it yours (personas + profile)

Bunnyhole adapts to *how you investigate*. Pick an **investigator persona** that tunes gear, depth,
breadth, sources and framing, keep a **watchlist** of recurring targets that get flagged whenever they
resurface, and set standing jurisdictions and exclusions, all remembered in `~/.bunnyhole/profile.json`.

| Persona key | Lens | Default gear / depth / breadth |
| --- | --- | --- |
| `generalist` | Balanced, no bias | fast / 2 / 4 |
| `journalist` | Public-interest accountability, sourcing, provenance | fast / 2 / 5 |
| `compliance` | KYC/AML due diligence: UBO, sanctions/PEP, adverse media | deep / 3 / 4 |
| `threat_intel` | Infrastructure pivoting, breach exposure, attribution | fast / 2 / 6 |
| `crypto_tracer` | On-chain fund-flow tracing, bridges, off-ramps | deep / 3 / 5 |
| `pi` | Private-investigator lens; set automatically by `--pi` | deep / 3 / 4 |

```bash
uv run bunnyhole personas                                       # the lenses on offer
uv run bunnyhole profile --persona compliance --watch acme.io   # set yours
uv run bunnyhole profile                                        # view it
uv run bunnyhole trace acme.io --persona crypto_tracer          # one-off lens for a single run
```

Flags you pass on a run always win over the persona and profile. `compliance` and `crypto_tracer` lean on
**OpenSanctions sanctions/PEP screening**. Hits are authoritative listings but **soft name matches**:
leads to verify. Full details: **[docs/PERSONALIZATION.md](docs/PERSONALIZATION.md)**.

### 🕵️ Private-investigator (PI) stream

`--pi` turns a `trace` or `intake` into a private-investigator style engagement on the **free, lawful,
passive layer only**. It vets the purpose before anything is searched, labels each finding `confirmed` /
`probable` / `lead` by independent corroboration, logs every negative in a coverage matrix (sources that
ran vs. sources refused or failed), and writes a 16-section report that opens with a short labelled bottom
line and names who holds the records public data cannot reach and which legal instrument gets them. It is
a research tool, not a licence, and not legal advice. It is available on the CLI only.

**The legal filter, in two lines.** Free, lawful, passive sources only: no pretexting, tracker placement,
account access, contact with the subject, `--cred`, or breach/infostealer lookups, and no employment,
tenancy, credit or insurance decisions (there is no permissible-purpose category for them). A purpose is
required and gated: `--purpose` text, an attested `--purpose-category` (one of nine), a person subject
needs a person-eligible category plus a real-looking `--matter-ref`, and pursuit of a former partner or
someone avoiding the client is refused in every case type. Refusals exit with code 2 before any search.
The category is attested, not verified, and the phrase screens have incomplete recall; you remain
responsible for lawful use.

Three examples that pass the gates (a run needs network; each prints a PI SUMMARY and writes the report):

```bash
# 1. Entity due diligence (--subject-type defaults to person, so say entity for a company)
uv run bunnyhole trace "Acme Holdings Ltd" --pi --case-type due_diligence --subject-type entity \
  --purpose "Vet a counterparty before signing a supply contract" \
  --purpose-category counterparty_due_diligence \
  --pi-jurisdiction ca-on --pi-report acme_pi_report.md

# 2. Asset search on a judgment debtor, Ontario custodians
uv run bunnyhole intake --org "Acme Holdings Ltd" --domain acme.example \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" \
  --purpose-category judgment_enforcement \
  --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report asset_report.md

# 3. Person locate: needs a person-eligible category AND --matter-ref (omit it and the run exits 2)
uv run bunnyhole intake --org "Jane Q. Smith" --email jane@example.com \
  --pi --case-type locate --subject-type person \
  --purpose "Serve a statement of claim in an open action" --purpose-category service_of_process \
  --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report locate_report.md
```

Offline reference, no network and no keys: `uv run bunnyhole pi guide`, `pi sources`
(`--case-type`, `--jurisdiction`, `--implemented`), `pi legal --jurisdiction us|ca-on|general`,
`pi playbook <case-type>`, `pi out-of-scope`. Case types: `locate`, `background`, `asset_search`,
`due_diligence`, `fraud_screen`, `missing_person`.

**Sanctions screening is keyless.** In a `--pi` run Bunnyhole screens the official lists directly: Canada
SEMA (Global Affairs Canada), OFAC SDN, UN Consolidated and UK Sanctions List. Hits are soft name matches
to verify on the primary list, and no hit is not clearance. The EU Consolidated List is never automated,
so every report names it as not screened. OpenSanctions (a broader sanctions/PEP set) is optional: it needs
a self-hosted yente (`OPENSANCTIONS_API_URL`) or `OPENSANCTIONS_API_KEY`, and is listed as not screened
when absent. Outside `--pi`, the official-list screens do not run; OpenSanctions does, when configured
(also available as the MCP `sanctions_screen` tool).

Gates, flags, report anatomy, the legal filter and known limits: **[docs/PI_STREAM.md](docs/PI_STREAM.md)**.
Read the PI addendum in [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) first.

### The knobs worth knowing

| Option | What it does | When to reach for it |
| --- | --- | --- |
| `--gear fast` (default) | Quick scan of public APIs | First look at any lead |
| `--gear deep` | Adds slower, heavier CLI tools & sources | A lead that's earned the time |
| `--depth 1–4` | How many hops it follows out | Higher = wider net, slower |
| `--breadth 2–8` | Leads chased per hop | Higher = more thorough |
| `--out report.md` | Writes a Markdown dossier | Anything you want to keep/share |
| `--hypothesis "…"` | A question to steer ACH & priority | Qualifying a specific lead |
| `--persona <key>` | Run through an investigator persona lens | A one-off change of framing and defaults |
| `--proxy` / `--tor` (before the command) | Route all traffic through a proxy / Tor | Operating quietly (see below) |

## 🕵️ The Arsenal

Bunnyhole ships adaptive scrapers and API clients in-process, and orchestrates **40+ external
OSINT / forensics / red-team tools** when they're on your `PATH` — identity (`sherlock`, `maigret`,
`tookie-osint`, `ghunt`), email & phone (`holehe`, `h8mail`, `phoneinfoga`, `ignorant`),
infrastructure (`subfinder`, `amass`, `assetfinder`, `findomain`, `dnsx`, `dnsrecon`, `tlsx`,
`katana`, `httpx`, `nuclei`), recon frameworks (`spiderfoot`, `bbot`), infra intel CLIs (`shodan`,
`censys`), documents & metadata (`metagoofil`, `exiftool`), and the dark web (`tor`, `onionsearch`,
`anonsurf`).

```bash
uv run bunnyhole doctor                 # what's installed, what's missing, how to get it
uv run bunnyhole doctor --install all   # grab everything your platform can (non-root first)
```

Keyed sources light up automatically when a key is present and stay silent (keyless fallbacks) when
it isn't: **Censys** host/cert recon, **SecurityTrails** historical DNS, **Hunter.io** company email
footprint, and **LeakCheck** breach feeds all slot into the OSINT sweep the moment you add a key.

## 🧅 Going dark: Tor, proxies & anonsurf

Every outbound request in Bunnyhole flows through one proxy-aware client, so anonymizing the whole
engine is a single flag:

```bash
# Route everything through a local Tor SOCKS listener (socks5h → DNS resolves on Tor's side)
uv run bunnyhole --tor trace acme.io

# …or any proxy you like
uv run bunnyhole --proxy socks5h://127.0.0.1:9050 trace acme.io
export BUNNYHOLE_PROXY=http://127.0.0.1:8118      # standing default, no flag needed
export BUNNYHOLE_TOR_PROXY=socks5h://127.0.0.1:9060   # point --tor and .onion fetches at a non-default listener
```

`--tor` expects a Tor SOCKS listener to already be running (default `127.0.0.1:9050`); Bunnyhole does not
start Tor for you.

`darkweb --fetch-onion` reaches actual `.onion` services through the Tor SOCKS proxy (and *only*
`.onion` hosts — the onion path is locked so it can never become an SSRF foothold against your LAN).

On **Parrot / Kali**, Bunnyhole can also drive **anonsurf** — the system-wide Tor transparent proxy
— to anonymize *all* host traffic, not just its own:

```bash
uv run bunnyhole anonsurf install     # apt, or build from the official ParrotSec source
uv run bunnyhole anonsurf start       # route ALL host traffic through Tor (asks first; needs root)
uv run bunnyhole anonsurf change      # request a fresh Tor exit
uv run bunnyhole anonsurf stop        # restore normal networking
```

> anonsurf is Linux-only and rewrites iptables, so it's explicit and opt-in — **nothing reroutes
> your network without you typing the command.** On macOS/Windows, use `--tor` instead.

## 🔑 Configuration (API keys)

Every key is **optional**. Bunnyhole degrades gracefully to keyless public endpoints, and a keyed source
that has no key is logged as skipped rather than failing the run. Copy [`.env.example`](.env.example) and
set what you have, by exporting or via the vault:

```bash
uv run bunnyhole keys --set SHODAN_API_KEY=xxxx    # stored in ~/.bunnyhole/api_keys.env (chmod 600)
uv run bunnyhole keys                              # list configured keys (masked), with where to register
```

Keys cover AI synthesis (OpenRouter / Anthropic / OpenAI / Gemini: any one enables narrative synthesis,
OpenRouter powers the multi-model council), breach and infostealer intel, infrastructure recon, identity and
email, corporate registries (Companies House PSC, OpenSanctions, CourtListener, FEC) and on-chain
explorers. The registries matter for PI runs: without a Companies House key and a CourtListener token the
`beneficial_ownership` and `court_dockets` source classes are logged as not searched.

Which key unlocks what, where to register, and the free tiers: **[docs/QUICKSTART_CHEATSHEET.md](docs/QUICKSTART_CHEATSHEET.md)**.

## 🔒 Web War-Room security

The FastAPI server is built for **local use** and ships with loopback-only trusted-host enforcement
(blocks DNS rebinding), a strict Content-Security-Policy and security headers, output-escaping of all
untrusted OSINT data, a bounded in-memory case store, and request-size / concurrency limits.

Set a token to protect the mutating endpoints (it is also auto-injected into the first-party UI):

```bash
export BUNNYHOLE_API_TOKEN="$(openssl rand -hex 24)"
uv run bunnyhole serve
```

Binding a non-loopback `--host` prints a warning and, with no token set, says that mutating endpoints are
unauthenticated, but it still starts. The trusted-host allowlist is `localhost` / `127.0.0.1`, so keep it
on loopback (or behind your own authenticated proxy). Never expose it to an untrusted network: it stores
API keys and case data locally.

## ⚖️ Responsible use

Bunnyhole investigates **known entities from public records**. It is not for surveilling, doxxing, stalking
or profiling private individuals, and every finding is a lead to corroborate, not a verdict. The `--pi`
stream adds purpose gating and refuses eligibility (employment, tenancy, credit, insurance) work, but the
purpose category is attested rather than verified, so lawful use stays your responsibility. Read
[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) before pointing it at anything.

## 🧪 Testing & quality

```bash
uv sync --extra dev
uv run pytest -q -o addopts=""        # test suite (4054 tests, ~35 s, offline)
uv run ruff check bunnyhole tests     # lint
uv run mypy bunnyhole                 # type check
```

## 🏗️ Architecture

```
bunnyhole/
├── engine/        # models, intake parser, orchestrator, graph, storage, synthesizer, council, netutil
│                  #   personas + profile; pi_*.py: the PI stream (gates, purpose, identity, UBO walk, report)
├── agents/        # journalist, accountant, osint, onchain, link_sleuth specialists
│                  #   pi_sources + sanctions_lists: PI-only free sources and keyless official sanctions lists
├── arsenal/       # cross-platform tool installer, health doctor, anonsurf control, API-key vault
├── cli/           # Typer CLI (main.py) and the `pi` reference commands (pi_commands.py)
├── tui/           # Textual War-Room (`ui` / `tui`)
├── api/           # FastAPI server + browser War-Room UI (`serve`)
└── mcp/           # MCP server over stdio (`mcp`)
tests/             # ~4000 offline tests (pytest, respx)
docs/              # MCP_SERVER.md, PERSONALIZATION.md, PI_STREAM.md, QUICKSTART_CHEATSHEET.md, superpowers/specs
research/          # the tradecraft library (00_INDEX.md + 12 volumes)
scripts/           # install_osint_tools.py (cross-platform arsenal installer)
```

The flow: **intake** parses selectors & hypothesis → the **orchestrator** runs the recursive
breadth × depth loop, dispatching **agents** that write provenance-backed nodes/edges into the
**graph** → the **Link Sleuth** breaks dead ends and maps interconnections → the **Skeptic** runs
network analytics (betweenness, ACH) → the **synthesizer** and **council** produce a citation-backed
dossier → **storage** persists the case and correlates cross-case entity memory.

## 📚 Tradecraft research library

The complete 12-volume intelligence & tradecraft spec lives in
[`research/00_INDEX.md`](research/00_INDEX.md):

1. [Architecture Blueprint](research/01_architecture_blueprint.md)
2. [Core 4 Pillars Tradecraft](research/02_core_4_pillars_tradecraft.md)
3. [Physical OSINT — Aviation, Maritime, Supply Chain](research/03_physical_osint_aviation_maritime_supply_chain.md)
4. [Breach, Telegram, Dark-Web Threat Intel](research/04_breach_telegram_darkweb_threat_intel.md)
5. [Advanced DeFi — MEV, Bundlers, Mixer Demixing](research/05_advanced_defi_mev_bundlers_mixer_demixing.md)
6. [Global Offshore Leaks, GLEIF, PSC, UCC-1](research/06_global_offshore_leaks_gleif_psc_ucc1.md)
7. [Link Analysis & Dead-End Breaker](research/07_link_analysis_dead_end_breaker_and_interconnections.md)
8. [Deep-Research Loop & Creative Endpoints](research/08_deep_research_loop_and_creative_endpoints.md)
9. [LLM Council & Ultimate Architecture](research/09_llm_council_and_ultimate_architecture.md)
10. [Follow the Money: Public vs. Private Access](research/10_follow_the_money_access_public_vs_private.md)
11. [Market, Niche, Competitors & Expansion](research/11_market_niche_competitors_and_expansion.md)
12. [PI Methodology & Free Sources](research/12_pi_methodology_and_free_sources.md)

## 📄 Project docs

- [`docs/QUICKSTART_CHEATSHEET.md`](docs/QUICKSTART_CHEATSHEET.md) — quick start and API-key cheat sheet.
- [`CHEATSHEET.md`](CHEATSHEET.md) — the fast, practical lead & prospect-research guide.
- [`docs/PERSONALIZATION.md`](docs/PERSONALIZATION.md) — personas, the remembered profile, OpenSanctions screening.
- [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md) — your own MCP server: setup, tools, safety.
- [`docs/PI_STREAM.md`](docs/PI_STREAM.md) — the private-investigator (`--pi`) stream: gates, flags, report, legal filter, limits.
- [`docs/superpowers/specs/`](docs/superpowers/specs/) — design specs (the PI stream design).
- [`research/00_INDEX.md`](research/00_INDEX.md) — the tradecraft research library (above).
- [`AUDIT.md`](AUDIT.md) — security & code-quality audit, applied fixes, and prioritized backlog.
- [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) — responsible-use policy, including the PI addendum. Read it.
- [`LICENSE`](LICENSE) — MIT.

<div align="center">

**Findings are leads, not verdicts.** Corroborate before you publish, before you act, before you
believe your own graph.

</div>
