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
uv sync --extra arsenal # + optional arsenal libraries: scrapling, trafilatura, waybackpy, edgartools, socid-extractor, holehe
uv run bunnyhole --help # list every command
```

`uv sync` removes extras you leave out, so name every extra you want in one command (for example
`uv sync --extra dev --extra arsenal`). The arsenal libraries are optional: `bunnyhole arsenal` only reports them.

`uv run bunnyhole --version` prints the version. There is no install step beyond `uv sync`; every command below is run as
`uv run bunnyhole <command>` from the checkout. Nothing needs an API key to start (see
[Configuration](#-configuration-api-keys)).

Bunnyhole runs great on nothing but free public endpoints. Want the heavy DEEP-gear tools too?

```bash
uv run bunnyhole doctor                              # health-check the arsenal + your API keys
uv run python scripts/install_osint_tools.py --check # non-destructive tool health check
uv run python scripts/install_osint_tools.py         # cross-platform installer (macOS; Linux without root: user-space tools only)
sudo python3 scripts/install_osint_tools.py          # Linux with root: adds apt / pacman / dnf packages
```

The installer script needs only the Python standard library, so `sudo python3` works on Linux; on macOS use
`uv run python` (there is no bare `python` there).

## 🎛️ Everyday commands

```bash
# Single-seed investigation (company, domain, wallet/ENS, @handle, email, or tail number)
uv run bunnyhole trace vitalik.eth
uv run bunnyhole trace example.com --gear deep --depth 3 --out dossier.md

# Hypothesis-driven intake: paste a messy dump (selectors are auto-parsed) or pass selectors as flags.
# In a dump, -unrelated.com, exclude:unrelated.com, ignore:unrelated.com and -exclude:unrelated.com all exclude it.
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
(`uv run bunnyhole --tor trace acme.io`), not after it, and not on `uv run`. `uv run bunnyhole --version`
prints the version; `uv run bunnyhole` with no command prints the help.

Input is validated, not clamped: `--depth` must be 1-4, `--breadth` 2-8, `--persona` one of the six keys
below (case-insensitive), `serve --port` 1-65535, and `jet` takes a US N-number or 6 hex digits. A bad value
exits 2 with the allowed range. `intake` with no selector at all (only `--hypothesis` or `--exclude`) exits 2
instead of running an empty case. Note that `-p` is `--phone` on `trace`/`intake` but `--port` on `serve`.

### Every command

| Command | What it does | Needs |
| --- | --- | --- |
| `trace <seed>` | Autonomous multi-domain investigation of one seed; Markdown dossier (`--out`) and graph JSON (`--json`). Also takes `--pi` (see below) | Network |
| `intake` | Case intake: a hypothesis plus at least one known selector (`--dump`, `--domain`, `--email`, `--wallet`, `--org`, `--username`, `--phone`, `--doc`), optional `--exclude`, and an anchor mode. Also takes `--pi` | Network |
| `ask "<question>"` | Plain-English front end: "see if X is connected to Y" runs `link`; "see if X has anything shady going on" runs a sanctions-emphasis trace and prints a fixed risk checklist. No model parses the question; naming a person applies the PI gates. See [`docs/ASK.md`](docs/ASK.md) | Network |
| `link <a> <b>` | Link Sleuth, bidirectional meet-in-the-middle: how do two entities connect? | Network |
| `jet <tail_or_hex>` | FAA N-Number to ICAO hex and back, plus ADS-B telemetry from adsb.lol | Network |
| `council <seed>` | 5-seat council (specialist briefs, deterministic evidence ranking (not peer review), chairman verdict) over a short trace | Network; an AI key for real model deliberation, deterministic council without one |
| `darkweb <query>` | Ahmia search of the Tor index for public mentions of a selector; `--fetch-onion` fetches titles | Network; `--fetch-onion` needs a Tor SOCKS listener |
| `anonsurf [action]` | Install and drive Parrot/Kali's system-wide Tor proxy: `status`, `start`, `stop`, `restart`, `change`, `install` | Linux, root |
| `doc-forensics <file>` | Word RSID revision fingerprints (`.docx`) or PDF `/Info` and XMP timezone metadata (`.pdf`); exits 1 on a missing, unreadable, unsupported or corrupt file | Local file only |
| `arsenal` / `doctor` | Health-check the external tool arsenal and API keys; `--install <tool\|all>` installs missing tools and exits 1 if an install fails (`doctor` is an alias) | Local |
| `personas` | List the investigator personas | Local |
| `profile` | View or edit your remembered profile: persona, watchlist, jurisdictions, default gear/depth/breadth, exclusions | Local |
| `cases` | List saved cases (`~/.bunnyhole/cases.db`), `--search` cross-case entity memory, `--load <case_id>` | Local |
| `keys` | List API keys (masked, with `SET (shell)` / `SET (vault)`) or `--set KEY=VALUE` into the vault (`~/.bunnyhole/api_keys.env`); `--set KEY=` clears it | Local |
| `ui` / `tui` | Full-screen Textual War-Room (optional seed argument to prefill; `tui` is an alias) | Local; running a case needs network |
| `menu` | Classic prompt-driven terminal command center | Local |
| `serve` | FastAPI War-Room and API (`--host`, `--port`; defaults `127.0.0.1:8000`). A non-loopback `--host` is refused unless `BUNNYHOLE_API_TOKEN` is set | Local; running a case needs network |
| `mcp` | MCP server over stdio; `--print-config` prints the client config snippet, `--no-uv` for a plain `bunnyhole mcp` entry | Local; tools need network to investigate |
| `pi guide \| sources \| legal \| playbook \| out-of-scope` | Offline private-investigator reference tables | Local |

### 🧩 The four surfaces

One engine, four front doors. They share the same case vault, key vault and profile.

- **CLI** (`trace`, `intake`, `link`, ...): scriptable, writes dossiers and graph JSON. The only surface
  that runs a `--pi` engagement.
- **TUI** (`ui` / `tui`): a seed/intake sidebar, live entity table, a tabbed inspector (Node, Links,
  Council, ACH, Dossier, Arsenal) and a streaming agent log. Keys: `enter`/`r` run, `/` focus the seed box, `d`
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
ran vs. sources refused or failed), and writes a report that opens with a short labelled bottom
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

**It works the case, it does not just search.** A `--pi` run turns the case type into the questions the
client's decision depends on, opens a lead sheet from the playbook, and works one lead at a time, letting each
result decide the next: the owner a registry names is walked to its own owner, every party in the chain is
screened, a conflict between records is pulled again, and anything that serves no question is written down
rather than chased. With a provider key (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY` or `OPENAI_API_KEY`) an AI case
officer runs that loop: it reads each result, opens leads of its own, and picks the next move, inside limits
code enforces (only names already in the evidence, only the fixed list of lawful sources, no waiving a
sanctions stop). The report leads with a detailed account in prose (AI-written and checked against the case
file when a key is set, code-written otherwise), answers each question, and carries the full lead sheet and
the investigator's log. Add `--chase` to pick leads off the sheet and keep going when the case stops.
`--pi-budget N` caps source calls (10–400); `--pi-loop sweep` runs the earlier single pass instead. See
[an example report](docs/examples/pi_case_report_example.md).

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

Bunnyhole ships adaptive scrapers and API clients in-process. Its arsenal catalog has **40 entries: 35
external OSINT / forensics / red-team CLI tools and 5 Python libraries** — identity (`sherlock`, `maigret`,
`tookie-osint`, `ghunt`), email & phone (`holehe`, `h8mail`, `phoneinfoga`, `ignorant`),
infrastructure (`subfinder`, `amass`, `assetfinder`, `findomain`, `dnsx`, `dnsrecon`, `tlsx`,
`katana`, `httpx`, `nuclei`), recon frameworks (`spiderfoot`, `bbot`), infra intel CLIs (`shodan`,
`censys`), documents & metadata (`metagoofil`, `exiftool`), and the dark web (`tor`, `onionsearch`,
`anonsurf`). The agents call five of them automatically when they are on your `PATH` (`whois`,
`subfinder`, `sherlock`, `holehe`, `ignorant`); the rest are checked and installed by `doctor` for your
own hands-on work.

```bash
uv run bunnyhole doctor                   # what's installed, what's missing, the exact install command
uv run bunnyhole doctor --install httpx   # one tool (httpx = ProjectDiscovery's httpx, catalog name httpx-pd)
uv run bunnyhole doctor --install all     # everything your platform can install (non-root first)
uv sync --extra arsenal                   # the optional Python libraries in one go (scrapling, trafilatura, ...)
```

The install hint `doctor` shows is exactly the command chain `--install` runs (`a || b` = try `a`, then
`b`): `uv tool install` / `pipx` for Python CLIs, `uv pip install` into the active environment for the
Python libraries, `brew` on macOS, `sudo -n apt-get` on Kali/Parrot/Debian, `sudo -n pacman` on Arch and
`sudo -n dnf` on Fedora for the packages they carry, and `go install` for Go tools. Where no installer
applies, the hint says `install manually` or `not available on <platform>` instead of guessing a package
name.

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
that has no key is logged as skipped rather than failing the run. [`.env.example`](.env.example) lists every
name the vault accepts plus the env-only `BUNNYHOLE_*` settings. **`.env` files are not loaded
automatically**: set a key with `keys --set` or export it in your shell.

```bash
uv run bunnyhole keys --set HUNTER_API_KEY=xxxx    # stored in ~/.bunnyhole/api_keys.env (chmod 600, atomic write)
uv run bunnyhole keys --set HUNTER_API_KEY=        # clear it
uv run bunnyhole keys                              # list keys (masked): SET (shell) / SET (vault) / EMPTY
```

- **The shell wins.** A variable already exported in your shell is never overridden by the vault; `keys`
  shows it as `SET (shell)`.
- **When the vault is read.** It is loaded into the process whenever the arsenal manager is built: at the
  start of every investigation (`trace`, `intake`, `link`, `council`, TUI / web / MCP runs), and by
  `darkweb`, `keys`, `doctor`, `menu`, the TUI Arsenal tab and the API / MCP arsenal endpoints. `jet`,
  `doc-forensics`, `cases`, `profile`, `personas` and `pi` do not read it.
- **Legacy file.** `~/.osint-apis/api_keys.env` (from older OSINT toolkits) is read and merged *under* the
  vault, but Bunnyhole never writes it. `keys --set` changes only the line for that key in the vault and
  keeps every other line and comment; a value with spaces or ` #` is stored quoted and read back exactly.
- **`$BUNNYHOLE_HOME`** relocates the vault, `cases.db` and `profile.json` (default `~/.bunnyhole`).
- **Reserved keys.** 13 keys are accepted and stored but **not read by any agent yet** (`keys` marks them
  `reserved: not used by any agent yet`): `HAVEIBEENPWNED_API_KEY`, `INTELX_API_KEY`,
  `BREACHDIRECTORY_API_KEY`, `HUDSONROCK_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
  `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`, `TELEGRAM_BOT_TOKEN`, `FEC_API_KEY`, `OPENCORPORATES_API_KEY`,
  `ETHERSCAN_API_KEY`, `HELIUS_API_KEY`. HudsonRock and Shodan are queried through their keyless endpoints.
- `COMPANIES_HOUSE_API_KEY` is accepted as an alias of `UK_COMPANIES_HOUSE_API_KEY`; `OPENSANCTIONS_API_URL`
  (a self-hosted yente base URL) can be stored in the vault too.

Keys cover AI synthesis (OpenRouter / Anthropic / OpenAI / Gemini: any one enables narrative synthesis,
OpenRouter powers the multi-model council), breach and infostealer intel, infrastructure recon, identity and
email, corporate registries (Companies House PSC, OpenSanctions, CourtListener, FEC) and on-chain
explorers. (FEC, OpenCorporates and the on-chain explorer keys are reserved, above.) The registries matter for PI runs: without a Companies House key and a CourtListener token the
`beneficial_ownership` and `court_dockets` source classes are logged as not searched.

Which key unlocks what, where to register, and the free tiers: **[docs/QUICKSTART_CHEATSHEET.md](docs/QUICKSTART_CHEATSHEET.md)**.

## 🔒 Web War-Room security

The FastAPI server is built for **local use** and ships with loopback-only trusted-host enforcement
(blocks DNS rebinding), a strict Content-Security-Policy and security headers, output-escaping of all
untrusted OSINT data, a bounded in-memory case store, and request-size / concurrency limits.

Set a token to protect the API:

```bash
export BUNNYHOLE_API_TOKEN="$(openssl rand -hex 24)"
uv run bunnyhole serve
```

`serve` on a loopback host (`127.0.0.1`, `localhost`, `::1`) starts without a token. **A non-loopback
`--host` is refused (exit 2) unless `BUNNYHOLE_API_TOKEN` is set in the environment**, and even then it
prints a warning. Keep it on loopback (or behind your own authenticated proxy). Never expose it to an
untrusted network: it stores API keys and case data locally.

## ⚖️ Responsible use

Bunnyhole investigates **known entities from public records**. It is not for surveilling, doxxing, stalking
or profiling private individuals, and every finding is a lead to corroborate, not a verdict. The `--pi`
stream adds purpose gating and refuses eligibility (employment, tenancy, credit, insurance) work, but the
purpose category is attested rather than verified, so lawful use stays your responsibility. Read
[`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) before pointing it at anything.

## 🧪 Testing & quality

```bash
uv sync --extra dev
uv run pytest -q -o addopts=""        # the full test suite (offline and hermetic, well under a minute)
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
tests/             # offline, hermetic tests (pytest, respx; no network, temp BUNNYHOLE_HOME)
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
- [`docs/ASK.md`](docs/ASK.md) — `bunnyhole ask`: plain-English connection and company-risk questions, what the answer says and never says.
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
