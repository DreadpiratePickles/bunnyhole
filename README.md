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
- **Two cockpits:** a Typer CLI and an interactive FastAPI / Textual "War-Room."

## 📦 Install

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole
uv sync                 # runtime deps
uv sync --extra dev     # + test/lint/type tooling
```

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

# Hypothesis-driven intake — paste a messy dump; selectors are auto-parsed
uv run bunnyhole intake "acme.io founder@acme.io 0x1234... -exclude:unrelated.com" \
  --hypothesis "Is acme.io run by the same operator as its token?"

# Meet-in-the-middle: how do two entities connect?
uv run bunnyhole link vitalik.eth ethereum.org

# Dark-web: search the Tor index (Ahmia) for public mentions of a selector — keyless, no Tor needed
uv run bunnyhole darkweb acme.io
uv run --tor bunnyhole darkweb acme.io --fetch-onion   # also fetch each hit's title through Tor

# 3-stage adversarial LLM council verdict over a seed
uv run bunnyhole council acme.io

# Aviation & document forensics
uv run bunnyhole jet N628TS
uv run bunnyhole doc-forensics ./leaked.pdf

# Saved cases & cross-case entity memory
uv run bunnyhole cases --search "0x1234"

# Full-screen War-Room TUI, or serve it to a browser / the web
uv run bunnyhole ui
uv run textual serve "bunnyhole ui"
uv run bunnyhole serve                    # FastAPI War-Room at http://127.0.0.1:8000
```

### The knobs worth knowing

| Option | What it does | When to reach for it |
| --- | --- | --- |
| `--gear fast` (default) | Quick scan of public APIs | First look at any lead |
| `--gear deep` | Adds slower, heavier CLI tools & sources | A lead that's earned the time |
| `--depth 1–4` | How many hops it follows out | Higher = wider net, slower |
| `--breadth 2–8` | Leads chased per hop | Higher = more thorough |
| `--out report.md` | Writes a Markdown dossier | Anything you want to keep/share |
| `--hypothesis "…"` | A question to steer ACH & priority | Qualifying a specific lead |
| `--proxy` / `--tor` | Route all traffic through a proxy / Tor | Operating quietly (see below) |

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
uv run --tor bunnyhole trace acme.io

# …or any proxy you like
uv run bunnyhole trace acme.io --proxy socks5h://127.0.0.1:9050
export BUNNYHOLE_PROXY=http://127.0.0.1:8118      # standing default, no flag needed
```

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

Every key is **optional** — Bunnyhole degrades gracefully to keyless public endpoints. Copy
[`.env.example`](.env.example) and set what you have, by exporting or via the vault:

```bash
uv run bunnyhole keys --set SHODAN_API_KEY=xxxx    # stored in ~/.bunnyhole/api_keys.env (chmod 600)
uv run bunnyhole keys                              # list configured keys (masked)
```

Keys cover breach/infostealer intel, infrastructure recon, identity/email, corporate registries,
on-chain explorers, and AI synthesis (OpenRouter / Anthropic / OpenAI / Gemini). Set any one AI key
to enable LLM narrative synthesis and the multi-model council.

## 🔒 Web War-Room security

The FastAPI server is built for **local use** and ships with loopback-only trusted-host enforcement
(blocks DNS rebinding), a strict Content-Security-Policy and security headers, output-escaping of all
untrusted OSINT data, a bounded in-memory case store, and request-size / concurrency limits.

To expose it beyond `127.0.0.1`, set a token first — required on all mutating endpoints and
auto-injected into the first-party UI:

```bash
export BUNNYHOLE_API_TOKEN="$(openssl rand -hex 24)"
uv run bunnyhole serve --host 0.0.0.0    # warns, and refuses to run unauthenticated
```

Never expose it to an untrusted network: it stores API keys and case data locally.

## 🧪 Testing & quality

```bash
uv run --extra dev pytest             # test suite
uv run --extra dev ruff check .       # lint
uv run --extra dev mypy bunnyhole     # type check
```

## 🏗️ Architecture

```
bunnyhole/
├── engine/        # models, intake parser, orchestrator, graph, storage, synthesizer, council, netutil
├── agents/        # journalist, accountant, osint, onchain, link_sleuth specialists
├── api/           # FastAPI server + interactive War-Room UI
├── cli/           # Typer command-line interface
└── arsenal/       # cross-platform tool installer, health doctor, anonsurf control, API-key vault
```

The flow: **intake** parses selectors & hypothesis → the **orchestrator** runs the recursive
breadth × depth loop, dispatching **agents** that write provenance-backed nodes/edges into the
**graph** → the **Link Sleuth** breaks dead ends and maps interconnections → the **Skeptic** runs
network analytics (betweenness, ACH) → the **synthesizer** and **council** produce a citation-backed
dossier → **storage** persists the case and correlates cross-case entity memory.

## 📚 Tradecraft research library

The complete 9-volume intelligence & tradecraft spec lives in
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

## 📄 Project docs

- [`CHEATSHEET.md`](CHEATSHEET.md) — the fast, practical lead & prospect-research guide.
- [`AUDIT.md`](AUDIT.md) — security & code-quality audit, applied fixes, and prioritized backlog.
- [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) — responsible-use policy. Read it.
- [`LICENSE`](LICENSE) — MIT.

<div align="center">

**Findings are leads, not verdicts.** Corroborate before you publish, before you act, before you
believe your own graph.

</div>
