# Bunnyhole Quickstart Cheatsheet

One page for setup, API keys, every command, and the PI stream. Verified against the code and `--help`
output of this checkout (suite: 4,054 tests collected). Anything not verified is marked **unverified**.
Lead and prospect research for companies has its own sheet: [`../CHEATSHEET.md`](../CHEATSHEET.md).
Deeper docs: [`PI_STREAM.md`](PI_STREAM.md), [`PERSONALIZATION.md`](PERSONALIZATION.md), [`MCP_SERVER.md`](MCP_SERVER.md).

**Jump to:** [1 What it is](#1-what-it-is-and-is-not) | [2 macOS setup](#2-setup-on-macos) |
[3 ParrotOS / Kali Linux](#3-parrotos--kali-linux) | [4 API keys](#4-api-keys) | [5 Commands](#5-command-cheat-table) |
[6 Recipes](#6-recipes) | [7 PI stream](#7-the-pi-stream-in-one-page) | [8 Reading evidence](#8-reading-evidence) |
[9 Troubleshooting](#9-troubleshooting) | [10 Files and glossary](#10-files-and-glossary)

---

## 1. What it is and is not

| Is | Is not |
|---|---|
| A CLI (`bunnyhole`) that turns one clue (domain, email, @handle, wallet/ENS, company, tail number) into a graph of sourced findings | A people-search site, a contact scraper, or a consumer reporting agency |
| Keyless by default: free public endpoints work with no API keys; keys only add coverage | Fully keyless: court dockets, UK ownership and sanctions via OpenSanctions need a free key (section 4) |
| Surfaces: CLI, Textual TUI (`ui`), FastAPI web War-Room (`serve`), MCP server (`mcp`) | A licence, legal advice, or a verdict machine |
| Tor-routable with `--tor` / `--proxy` (with caveats, section 6) | Guaranteed anonymous: some agents ignore the proxy |

> **Legal and ethics box** (full text: [`../ACCEPTABLE_USE.md`](../ACCEPTABLE_USE.md))
> - Only investigate what you are **authorised** to investigate. No harassing, doxxing, stalking or profiling for discrimination.
> - Findings are **leads, not verdicts**. Corroborate before you publish or act.
> - Case data (and any credentials you type in) is stored unencrypted in `~/.bunnyhole/cases.db`. Protect and delete it per your obligations.
> - **Ontario:** acting as a private investigator for pay may require a licence under the Private Security and
>   Investigative Services Act, 2005 (PSISA). Whether it applies to you is yours to confirm: **verify with the
>   Ministry of the Solicitor General.** Bunnyhole is not a licence and gives no police powers.
> - Employment, tenancy, credit and insurance decisions are refused by the PI stream (FCRA-style); use a compliant screening provider.

---

## 2. Setup on macOS

Verified on this machine: macOS, Homebrew, `uv 0.12.6`, project venv on Python 3.11.16.

```bash
brew install uv git            # uv manages Python and the venv; git to clone
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole
uv sync                        # runtime deps (needs Python >= 3.11; uv fetches one if needed)
uv sync --extra dev            # optional: pytest, ruff, mypy, respx
uv run bunnyhole --help        # first-run check: lists all commands
uv run bunnyhole arsenal       # read-only health check: tools found and keys set
uv run pytest                  # optional; "-q" is already the default
```

- **Python:** `requires-python >= 3.11`; classifiers list 3.11 and 3.12. Pin one with `uv sync --python 3.12`.
- **Every command below is run from the repo folder** as `uv run bunnyhole ...`. (Or `source .venv/bin/activate` and drop `uv run`.)
- **SOCKS for Tor:** `httpx[socks]` is already a core dependency; `socksio` imports in the venv. There is **no separate SOCKS extra** (the only extra is `dev`).
- **Tor on macOS:** `brew install tor && brew services start tor` (documentation only, not run). Listener must be `127.0.0.1:9050`.
- **Optional arsenal tools** (deep scans; Bunnyhole degrades gracefully without them). On this Mac 9 of 40 catalog tools were detected:

```bash
uv run bunnyhole arsenal                      # status table (no changes)
uv run bunnyhole arsenal --install sherlock   # one tool by catalog name
uv run bunnyhole arsenal --install all        # every missing tool (slow, many installs)
```

`doctor` is an identical alias of `arsenal`. Installer order per tool (from `install_tool`): `uv tool install` / `pipx` / `pip`
first, then `brew` (macOS) or `apt` (Debian family), then `go install` (needs `go`). Names must match the catalog (`arsenal` lists them).

**What "keyless" means:** DNS, certificate transparency, GLEIF, SEC EDGAR, Wayback, Blockscout, adsb.lol, OFAC/UN/UK/Canada
sanctions lists, Ahmia and similar work with no account. **Still needs a key:** CourtListener dockets, UK Companies House
ownership, OpenSanctions, and the optional vendor and LLM APIs in section 4.

---

## 3. ParrotOS / Kali Linux

Both are Debian-based. The code detects them from `/etc/os-release` (`kali`, `parrot`, `ubuntu`/`debian` all use `apt`).

### 3.1 Prerequisites, clone, sync

```bash
sudo apt update && sudo apt install -y git curl pipx tor
pipx ensurepath                                        # then open a new shell
curl -LsSf https://astral.sh/uv/install.sh | sh        # official uv installer (documentation only, not run here)
python3 --version                                      # need >= 3.11
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole
uv sync                                                # includes SOCKS support (httpx[socks] is a core dependency)
uv run bunnyhole --help
uv run bunnyhole arsenal                               # shows detected OS "Distro Profile: KALI/PARROT", pkg manager apt
```

- **Wrong Python (older than 3.11, or too new for the wheels you need):** let uv supply its own.
  `uv python install 3.12 && uv sync --python 3.12`. (3.11 and 3.12 are the versions in the project classifiers; this repo's venv is 3.11.16.)
  Which Python each Kali/Parrot release ships: **unverified**; always check `python3 --version`.
- **Run Bunnyhole as your normal user, not root.** Keys and cases live under the invoking user's `~/.bunnyhole`; Bunnyhole already
  calls `sudo` itself only where needed (`anonsurf`, `apt-get` installs). Avoid `sudo python3 scripts/install_osint_tools.py`:
  its docstring suggests it, but it then runs pipx/go installs as root and may create the vault under root's home
  (**unverified**). Without root the script skips apt packages and installs user-space tools only (verified in its code).
  Preferred: `sudo apt install ...` yourself, then `uv run bunnyhole arsenal --install <name>`.
- Non-root `apt` installs use `sudo -n` (non-interactive): if sudo needs a password, the install fails. Run `sudo -v` first, or install the apt package by hand.

### 3.2 Which arsenal tools install how (from `ARSENAL_TOOLS_CATALOG`)

The catalog does **not** say any tool is preinstalled. `nmap`, `whois` and `dig` (package `dnsutils`) are commonly present on
Kali/Parrot (verify with `which nmap whois dig`); treat everything else as "check first".

| Install route (as coded) | Catalog tools |
|---|---|
| Already in Bunnyhole's venv (`uv sync`) | scrapling, trafilatura, edgartools, waybackpy, socid-extractor, holehe |
| `apt` package listed in catalog (tried after pipx where a pipx name also exists) | sherlock, theHarvester, dnstwist, subfinder, findomain, dnsrecon, metagoofil, amass, httpx-pd (`httpx-toolkit`), nuclei, whois, dig (`dnsutils`), nmap, exiftool (`libimage-exiftool-perl`), tor, anonsurf |
| `uv tool install` / `pipx` only | maigret, ignorant, h8mail, ghunt, phoneinfoga (**unverified** that a PyPI package of that name exists), tookie-osint, spiderfoot, bbot, shodan, censys, onionsearch |
| `go install` only (needs `go`, e.g. `sudo apt install golang-go`; binaries land in `~/go/bin`) | assetfinder, dnsx, tlsx, katana, mosint, waybackurls, gau |
| Hand-installed under `~/osint-tools/<tool-name>` | Counted as installed by `arsenal` if the folder exists. Bunnyhole **never clones into it** (verified by grep); you do that yourself. |

`arsenal` also searches `~/.local/bin`, `~/go/bin`, `~/bin`, `/usr/local/bin` besides `PATH`. Install hints shown by `arsenal`
for missing tools are the exact commands Bunnyhole would run. Whether each apt package exists in a given Kali/Parrot repo: **unverified**.

### 3.3 Tor (portable route, works on any OS)

```bash
sudo systemctl enable --now tor          # documentation only
systemctl status tor --no-pager
ss -ltn | grep 9050                      # Tor SOCKS listener should be on 127.0.0.1:9050
uv run bunnyhole --tor darkweb "example.com"                 # --tor goes BEFORE the command
uv run bunnyhole --tor darkweb "example.com" --fetch-onion    # also fetch .onion hits' titles via Tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip   # sanity check, needs network
```

- There is **no `bunnyhole tor` command** (`uv run bunnyhole tor` -> "No such command"). Tor is the `--tor` flag plus the `tor` daemon (arsenal tool name `tor`).
- `--tor` = `--proxy socks5h://127.0.0.1:9050` (`socks5h` keeps DNS on Tor's side). Different port: `export BUNNYHOLE_TOR_PROXY=socks5h://127.0.0.1:9150`. Standing proxy with no flag: `export BUNNYHOLE_PROXY=...`.
- `--tor` and `--proxy` are **global options placed before the subcommand**. `bunnyhole trace --proxy ...` is not valid (verified: `trace --help` has no `--proxy`).
- **Honest caveat (verified in code):** only clients built with `netutil.new_async_client` honour the proxy. These do **not**: the journalist agent (all
  HTTP calls), the on-chain agent, three of five accountant call sites, LLM council/synthesis calls, `dnspython` DNS lookups (system resolver),
  Scrapling fetches (**unverified** whether it inherits a proxy; none is passed) and the local CLI tools Bunnyhole shells out to (`whois`, `subfinder`,
  `dnstwist`, `sherlock`...). The PI-stream sources and most of the OSINT agent do honour it. Do not rely on `--tor` alone for anonymity.

### 3.4 AnonSurf vs Bunnyhole's `anonsurf` command

AnonSurf (Parrot's system-wide Tor transparent proxy) is the answer to the leaks above: it reroutes **all** host traffic through Tor with iptables.
`bunnyhole anonsurf` is only a thin wrapper:

```bash
uv run bunnyhole anonsurf status         # read-only; runs `anonsurf status`
uv run bunnyhole anonsurf install        # apt-get install -y anonsurf; fallback: git clone ParrotSec/anonsurf + `make install`
uv run bunnyhole anonsurf start          # asks to confirm, then `sudo anonsurf start`
uv run bunnyhole anonsurf start --yes    # skip the confirmation (-y)
uv run bunnyhole anonsurf change         # new Tor identity (no confirmation prompt)
uv run bunnyhole anonsurf stop           # confirm, then restore clearnet; or run `sudo anonsurf stop` directly
```

| Fact (verified in code) | Note |
|---|---|
| Linux only; needs root via `sudo` (it prompts on the terminal) | On macOS it prints a pointer to `--tor` and exits 1 (verified by running `anonsurf status`) |
| `start` and `stop` ask for confirmation unless `--yes`; `restart`, `change`, `install` do not | Unknown action -> exit 2 |
| Nothing ever starts it automatically | The status/error text says `anonsurf --install`; the real syntax is `anonsurf install` (code oddity) |

**It is a system-wide network change.** Every app (browser, SSH, updates, your logged-in accounts) goes through Tor until you stop it.
**Do not use it** over a remote SSH session (you can lose the connection; **unverified**), when you need a normal connection,
or while logged in to accounts that identify you. Check for DNS leaks yourself (use any DNS-leak test) because Bunnyhole cannot verify AnonSurf's
behaviour. Some sites block Tor exits, and some data sources' terms may restrict anonymised access: check each source's terms.
**Stop it:** `uv run bunnyhole anonsurf stop` or `sudo anonsurf stop`, then confirm with `anonsurf status`.

**proxychains alternative** (not verified with Bunnyhole): `proxychains4 -q uv run bunnyhole trace example.com`, with `socks5 127.0.0.1 9050`
in `/etc/proxychains4.conf` and `proxy_dns` enabled. Test for leaks before trusting it.

### 3.5 VM, live boot, persistence, updates

- **Snapshot the VM before** installing tools or starting AnonSurf so you can roll back.
- Keys and cases are plain-text files in `~/.bunnyhole/` (dir `0700`, `api_keys.env` `0600`, **not encrypted**), plus a **mirror copy** at `~/.osint-apis/api_keys.env`.
  On a **non-persistent live session they vanish at reboot**. Back up only to encrypted storage, for example
  `tar czf - ~/.bunnyhole ~/.osint-apis | gpg --symmetric -o bunnyhole_backup.tgz.gpg` (generic GnuPG usage, not a Bunnyhole feature). Wipe both files to remove a key everywhere.
- **Updates:** `sudo apt update && sudo apt upgrade`; `uv tool upgrade --all` (or `pipx upgrade-all`) for uv/pipx tools; `cd bunnyhole && git pull && uv sync`.
  Sanctions-list XML caches refresh on their own (24 h TTL, per `docs/PI_STREAM.md`).
- **Legal reminder:** Kali and Parrot ship offensive tools. Bunnyhole is **passive OSINT only**: no exploitation, no account access. The PI stream refuses eligibility
  decisions, former-partner pursuit and credential-shaped text (section 7). Do not point the arsenal's scanners (`nmap`, `nuclei`) at systems you are not authorised to test.

---

## 4. API keys

Every key is optional. `keys` lists all 30 names in the catalog (`API_KEYS_REGISTRY`). **"Read by code"** is my grep of `os.environ` use outside the catalog:
"no" means the key can be stored but **no agent currently reads it**.

### 4.1 Set these first (free, biggest payoff)

| Key | Unlocks | Sign up |
|---|---|---|
| `COURTLISTENER_API_TOKEN` | US federal dockets (RECAP). Without it the API returns 401 and `court_dockets` shows as not reached | https://www.courtlistener.com/help/api/rest/ |
| `UK_COMPANIES_HOUSE_API_KEY` | UK persons-with-significant-control (beneficial ownership) lookup. `COMPANIES_HOUSE_API_KEY` also works but **only as an exported env var** | https://developer.company-information.service.gov.uk/ |
| `OPENSANCTIONS_API_KEY` (hosted free tier; non-commercial per the source catalog) **or** `OPENSANCTIONS_API_URL` (self-hosted yente, keyless) | Sanctions/PEP screening. Without either: logged skip, sanctions status stays `partial` | https://www.opensanctions.org/api/ |
| `GITHUB_API_KEY` | GitHub rate limit 60 -> 5,000 req/hr | https://github.com/settings/tokens |

### 4.2 Full catalog

| Key | Category | Note from catalog | Read by code |
|---|---|---|---|
| `HAVEIBEENPWNED_API_KEY` | Breach | paid ($4.39/mo) | no |
| `LEAKCHECK_API_KEY` | Breach | free tier | yes (blocked in PI mode) |
| `INTELX_API_KEY` | Breach | free: 3 searches/day | no |
| `HUDSONROCK_API_KEY` | Breach | optional; Cavalier works keyless | no |
| `BREACHDIRECTORY_API_KEY` | Breach | free tier | no |
| `SHODAN_API_KEY` | Infra | free 100 credits/mo; InternetDB works keyless | no |
| `CENSYS_API_ID`, `CENSYS_API_SECRET` | Infra | free 250 queries/mo (set both) | yes |
| `SECURITYTRAILS_API_KEY` | Infra | historical DNS, 50/mo free | yes |
| `VIRUSTOTAL_API_KEY` | Infra | free 500 req/day | no |
| `URLSCAN_API_KEY` | Infra | free tier; public search keyless | yes (optional header) |
| `ABUSEIPDB_API_KEY` | Infra | free 1,000 checks/day | no |
| `ALIENVAULT_OTX_API_KEY` | Infra | free indicators | yes (optional header) |
| `GITHUB_API_KEY` | Social | rate-limit raise | yes |
| `HUNTER_API_KEY` | Social | free 25-50 searches/mo | yes |
| `EMAILREP_API_KEY` | Social | email reputation | yes (blocked in PI mode) |
| `IPINFO_TOKEN` | Social | free 50,000/mo | no |
| `NUMVERIFY_API_KEY` | Social | phone carrier/line type | yes |
| `TELEGRAM_BOT_TOKEN` | Social | optional Telegram recon | no |
| `FEC_API_KEY` | Corporate | free instant key (installer writes `DEMO_KEY`) | no |
| `OPENCORPORATES_API_KEY` | Corporate | registry search | no |
| `OPENSANCTIONS_API_KEY` | Corporate | see 4.1 | yes |
| `COURTLISTENER_API_TOKEN` | Corporate | see 4.1 | yes |
| `UK_COMPANIES_HOUSE_API_KEY` | Corporate | see 4.1 | yes |
| `ETHERSCAN_API_KEY` | On-chain | free 5 calls/sec; Blockscout keyless | no |
| `HELIUS_API_KEY` | On-chain | free Solana RPC | no |
| `OPENROUTER_API_KEY` | AI | powers the 3-stage LLM Council | yes |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | AI | optional narrative synthesis / council | yes |

> **Privacy:** with an AI key set, `council` and the synthesis step send receipt text from your case to that provider. Do not set these
> if the matter is confidential. Those calls also ignore `--tor`.

### 4.3 How to set, check, remove

```bash
uv run bunnyhole keys                                       # table: SET/EMPTY, masked value (verified)
uv run bunnyhole keys --set COURTLISTENER_API_TOKEN=xxxx    # -s works too; name is upper-cased
export COURTLISTENER_API_TOKEN=xxxx                         # alternative: shell env (current session only)
uv run bunnyhole keys --set COURTLISTENER_API_TOKEN=        # remove: empty value clears it (verified; still prints "Saved")
export OPENSANCTIONS_API_URL=http://localhost:9000          # env ONLY: not in the catalog, `keys --set` rejects it
```

- **Vault:** `~/.bunnyhole/api_keys.env` (dir `0700`, file `0600`, verified) **and** a synced copy `~/.osint-apis/api_keys.env`. Loaded into the environment at startup by every command.
- **Precedence:** a non-empty vault value overwrites the same variable exported in your shell.
- Only catalog names are accepted; anything else (for example `OPENSANCTIONS_API_URL`, `BUNNYHOLE_API_TOKEN`) raises `ValueError: Unknown or illegal API key name` (a traceback, verified).
- Yente on `localhost:8000` clashes with the default `serve` port 8000: use another port for one of them.
- `.env` files are **not** auto-loaded (no `load_dotenv` in the code, although `python-dotenv` is a dependency). `.env.example` is a template only, and omits `COURTLISTENER_API_TOKEN` and `OPENSANCTIONS_API_KEY`.
- Also settable from the `menu` (option 4) and the War-Room (`POST /api/keys`).

**What changes in a PI report once keys are set:** with the CourtListener token the `court_dockets` class is searched instead of "Tried, not reached"/`NOT SEARCHED`;
with the Companies House key `beneficial_ownership` gets UK PSC data (UK entities only); with OpenSanctions (key or yente) the sanctions status can move from `partial`
toward `lists_run` (all five automated lists; the EU list is never automated, so it is always named as not screened). A hit is always a soft name match.

---

## 5. Command cheat table

Global options (before the command): `--tor`, `--proxy URL` (schemes: http, https, socks5, socks5h, socks4; bad scheme -> exit 2).

| Command | Purpose | Flags that matter |
|---|---|---|
| `trace SEED` | Investigate one seed (company, domain, EVM/BTC wallet, ENS, @handle, email, tail number) | `-g fast\|deep`, `-d 1-4` (def 2), `-b 2-8` (def 4), `-H` hypothesis, `-u/-e/-p/-w/--domain/--doc/-x` extra selectors, `--persona`, `-o dossier.md`, `--json graph.json`, `--pi ...` |
| `intake` | Multi-selector case + hypothesis. **No positional argument** | `--dump "text"` (auto-extract), `-H`, repeatable `-u -e -p -w --domain --org --doc -x`, `--anchor-mode`, plus the `trace` flags |
| `link A B` | Meet-in-the-middle: how do two entities connect | `-g` |
| `jet TAIL_OR_HEX` | FAA N-number <-> ICAO hex + ADS-B (adsb.lol) | none |
| `council SEED` | 5-seat LLM council (needs an AI key for LLM output) | `-g`, `-d` (default 1) |
| `darkweb QUERY` | Ahmia dark-web index search; soft leads (C3) | `--fetch-onion` (needs Tor; pair with global `--tor`) |
| `doc-forensics FILE` | Word RSID or PDF /Info + XMP timezone metadata, local file | none |
| `arsenal` / `doctor` | Tool + key health; install tools | `-i NAME\|all` |
| `anonsurf [action]` | Parrot/Kali system Tor (Linux, sudo) | `status\|start\|stop\|restart\|change\|install`, `-y` |
| `personas` | List personas (marks your active one) | none |
| `profile` | View/edit remembered context | `--persona --name --watch --unwatch --clear-watch --jurisdiction -x -g -d -b --note` |
| `keys` | Show/set API keys | `-s KEY=VALUE` |
| `cases` | List last 25 cases / search / reload | `-q TEXT` search entity memory, `-l CASE_ID` re-display a case |
| `ui` / `tui` | Full-screen Textual War-Room (aliases) | optional `SEED` argument prefills |
| `menu` | Prompt-driven classic menu | none |
| `serve` | FastAPI web War-Room | `--host` (def 127.0.0.1), `-p/--port` (def 8000) |
| `mcp` | MCP server over stdio | `-c/--print-config`, `--no-uv` |
| `pi guide\|sources\|legal\|playbook\|out-of-scope` | Offline PI reference (no network, no keys) | `sources --case-type --jurisdiction --implemented`; `legal --jurisdiction us\|ca-on\|general`; `playbook CASE_TYPE` |

**Gear / depth / breadth in practice** (from `GearMode` and the orchestrator loop):

| Setting | Means |
|---|---|
| `fast` | Rapid APIs, DNS/CT, Scrapling HTTP fetch, Blockscout, GLEIF, EDGAR, Cavalier. Start here |
| `deep` | Adds Scrapling headless StealthyFetcher, Wayback diffing, PDF/DOCX RSID forensics, Holehe email sweep, 2-hop burner expansion. More requests, more noise, slower |
| `--depth` 1-4 | Extra pivot hops: the loop runs hops `2..depth`, so **depth 1 = seed only, no follow-up hops**. Out-of-range values are clamped |
| `--breadth` 2-8 | Leads pursued in parallel per hop. Higher = wider net, more requests against third parties |

Run times were **not measured**; expect minutes at deep/depth 3+. Persona defaults fill any of gear/depth/breadth you do not pass; flags you pass always win.

**Anchor modes** (`trace`/`intake --anchor-mode`): `convergence` (default) tests IF and HOW your clues connect; `locked_profile` treats them as one confirmed target.

**Personas** (`bunnyhole personas`, verified): `generalist` fast/d2/b4; `journalist` fast/d2/b5; `compliance` deep/d3/b4 + sanctions; `threat_intel` fast/d2/b6;
`crypto_tracer` deep/d3/b5 + sanctions; `pi` deep/d3/b4 + sanctions (auto-selected by `--pi`).

```bash
uv run bunnyhole profile --persona compliance --watch acme.io --jurisdiction CA --exclude unrelated.com --name "Your Name"
uv run bunnyhole trace acme.io --persona crypto_tracer       # one-off lens, profile unchanged
```
Watchlist hits show as `watchlist_hits` in results. Profile is `~/.bunnyhole/profile.json`.

**Cases:** every `trace`/`intake` run is saved automatically (`link`: **unverified**) to `~/.bunnyhole/cases.db`.
`cases` (list), `cases -q acme.io` (cross-case sightings), `cases -l bh_xxxxxxxx` (re-display summary; for files use `--out`/`--json` at run time).

**Exports:** `--out FILE.md` full dossier; `--json FILE.json` full graph (gains a `pi` key with `--pi`); `--pi-report FILE.md` PI report.

---

## 6. Recipes

Network commands below were not run for this sheet; syntax and gates were checked against `--help` and code.

```bash
# Quick traces
uv run bunnyhole trace example.com
uv run bunnyhole trace "@somehandle"
uv run bunnyhole trace someone@example.com
uv run bunnyhole trace vitalik.eth
uv run bunnyhole trace N628TS --out jet.md

# Multi-selector intake with a hypothesis, and a messy paste
uv run bunnyhole intake -H "Is acme.io run by the same operator as its token?" \
  --domain acme.io --wallet 0xABC... -e founder@acme.io -x unrelated.com --anchor-mode convergence
uv run bunnyhole intake --dump "paste notes with emails, domains and wallets here" --out case.md

# Link two entities
uv run bunnyhole link "Acme Holdings Ltd" acme.io --gear deep

# Dark web (keyless Ahmia) and Tor
uv run bunnyhole darkweb "acme.io"
uv run bunnyhole --tor darkweb "acme.io" --fetch-onion

# Sanctions check: no standalone CLI command. Use a PI run (below), or the MCP tool `sanctions_screen`.
```

**Company due diligence (PI stream).** `--purpose` (15+ chars) and `--purpose-category` are required; entity names need a legal form (`Ltd`, `Inc`, `LLC`) or `--confirm-entity`:

```bash
uv run bunnyhole trace "Acme Holdings Ltd" --pi --case-type due_diligence --subject-type entity \
  --purpose "Vet a counterparty before signing a supply contract" \
  --purpose-category counterparty_due_diligence --client "Your Client" \
  --pi-jurisdiction ca-on --pi-report acme_pi.md --json acme.json
```

**Asset search (Ontario custodians):**

```bash
uv run bunnyhole intake --org "Acme Holdings Ltd" --domain acme.example --pi --case-type asset_search \
  --subject-type entity --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" \
  --purpose-category judgment_enforcement --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report assets.md
```

**Locate a person (needs a matter reference, person-eligible category):**

```bash
uv run bunnyhole intake --org "Jane Q. Smith" --email jane@example.com --pi --case-type locate --subject-type person \
  --purpose "Serve a statement of claim in an open action" --purpose-category service_of_process \
  --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report locate.md
```

**TUI:** `uv run bunnyhole ui [seed]` (or `tui`). Type a seed or a plain-language question ("dig deep into acme.io, same operator as its token?").
Keys: `enter`/`r` run, `/` focus seed, `d` dossier tab, `p` pivot selected entity, `ctrl+l` clear log, `q` quit. Tabs: Node, Links, Council, ACH, Dossier, Arsenal.
The TUI has **no PI or persona controls** (verified by grep): use the CLI for `--pi`. Browser mode: `textual serve "bunnyhole ui"` (from `--help`; **unverified** here).

**Web War-Room / API:** `uv run bunnyhole serve` then open http://127.0.0.1:8000. Only loopback hostnames are served (Host-header check); CORS allows
`127.0.0.1:8000` and `localhost:8000` only. Binding a non-loopback `--host` prints a warning; set `BUNNYHOLE_API_TOKEN` first (mutating POST endpoints then need
`Authorization: Bearer ...` or `X-Bunnyhole-Token`; `GET /api/arsenal`, `/api/cases` stay open). Even so, a non-loopback `--host` is still rejected by the Host check
unless you front it with a proxy (**unverified**). Limits via env: `BUNNYHOLE_MAX_ACTIVE_CASES` (50), `BUNNYHOLE_MAX_CONCURRENT` (4), `BUNNYHOLE_MAX_SELECTORS` (64), `BUNNYHOLE_MAX_RAW_TEXT` (20000).

**MCP into Claude Desktop** (stdio, local only, no port):

```bash
uv run bunnyhole mcp --print-config        # prints the JSON; --no-uv for a plain `bunnyhole mcp` command
```
Merge the `bunnyhole` entry under `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), restart the client.
Tools (16, from `build_server`): `interpret`, `trace`, `intake`, `link`, `jet`, `darkweb`, `arsenal_status`, `list_cases`, `search_cases`, `load_case`,
`sanctions_screen`, `get_profile`, `set_persona`, `watchlist_add`, `watchlist_remove`, `pi_reference`. **No MCP tool runs a PI engagement**, so the purpose gates are CLI-only.
`docs/MCP_SERVER.md` suggests `uv run --tor bunnyhole mcp`; that is **wrong** (`--tor` is a bunnyhole option, not uv's): use `uv run bunnyhole --tor mcp` or set `BUNNYHOLE_PROXY`.

---

## 7. The PI stream in one page

Offline reference first: `uv run bunnyhole pi guide` (method, 13 behaviours, case types; verified), `pi legal --jurisdiction ca-on`, `pi playbook asset_search`, `pi sources --implemented`, `pi out-of-scope`.

**Required with `--pi` (on `trace` or `intake`):** `--purpose` (15+ chars), `--purpose-category`. **Person subject** (default `--subject-type person`) also needs `--matter-ref`
(format check only). PI flags without `--pi` are refused (verified: exit 2). Case types: `locate`, `background`, `asset_search`, `due_diligence` (default), `fraud_screen`, `missing_person`.

| `--purpose-category` (9) | Allowed for a person subject? |
|---|---|
| `judgment_enforcement`, `litigation_support`, `service_of_process`, `asset_recovery`, `fraud_investigation`, `counterparty_due_diligence`, `authorities_referral` | Yes (with a valid `--matter-ref`) |
| `regulatory_compliance_kyc`, `journalism_public_interest` | **Entities only** |

**Gates refuse (exit code 2, nothing is searched):** missing/short purpose or unknown category; person without matter reference; eligibility purposes (employment, tenancy,
credit, loan, insurance); former-partner and "someone avoiding me" wording (locate/background/missing_person for people; the pursuit screen applies to every case type);
credential-shaped text in purpose/client/matter-ref and any `--cred`; any free-text field over **150,000 characters** ("too long to screen"); a person-like name declared as an entity
without a legal form or `--confirm-entity`. Exit 2 = refused or invalid usage, not a crash. **If a legitimate purpose is refused, state it accurately in plain words or
consult counsel.** The screens are a safety net with known false refusals and gaps (see `PI_STREAM.md` section 4); the category is attested, not verified, and you stay responsible.

**Reading the report** (`--pi-report`, 16 sections): start with **Bottom line** (at most 6 bullets: Sanctions, Registry, Findings, Biggest gap, Not covered, Next step).

| Item | Meaning |
|---|---|
| `confirmed` / `probable` / `lead` | 3+ / 2 / 1 independent sources. Measures corroboration, not truth |
| `NOT SEARCHED` | No mapped source returned a hit or clean negative for that class: a task list, not a clean result |
| "Tried, not reached" | Source attempted but refused or failed (HTTP 401/403/429 -> `skipped`; other errors -> `error`), usually a missing key |
| Sanctions screening | Always a soft name match to verify on the primary list; "no hit" is not clearance; EU list never screened |
| Playbook progress | `DONE` / `PARTIAL` / `NOT RUN` / `NEEDS LICENSED LAYER`; "Done when" is your judgement |
| Chain of custody | SHA-256 of the **recorded extract** (tool, URL, fact, snippet), **not** of the web page |

**What to do next:** (1) verify each sanctions hit on the primary list (the report gives URLs; check the EU map by hand); (2) archive source pages yourself
(Wayback Save Page Now, ArchiveBox or SingleFile) because the digest is not a page hash; (3) set missing keys (section 4) and re-run the affected classes;
(4) hand the custodian/instrument sheet to a licensed investigator or counsel for anything non-public. Nothing is sent anywhere by Bunnyhole.

---

## 8. Reading evidence

- **Admiralty code** = source reliability `A`-`F` + information credibility `1`-`6`. `A1` completely reliable, confirmed; `B2` usually reliable, probably true (typical for list hits);
  `C3` fairly reliable, possibly true (typical dark-web lead); `E5`/`F6` unreliable or unjudgeable. Grades reflect the **source**, not confirmation.
- **Confidence tiers** (set by the Red-Cell Skeptic): `VERIFIED` (A1, A2, B1), `CORROBORATED` (B2, C1, C2), `CIRCUMSTANTIAL` (C3, D2, D3), `HYPOTHESIS` (D4, E5, F6).
- **Selector strength:** `STRONG` (wallet, LEI, email, ICAO hex: near-zero collision) vs `SOFT` (person name, shared CDN IP, registered agent: collision-prone).
- **`SOFT_NAME_MATCH_VERIFY`**: a name matched a list or registry entry. Two different people or firms can share a name; confirm with a second identifier.
- **Source class:** `PAI` free public data vs `CAI` commercial/paid-key products.
- **Lead:** an unverified pointer worth checking, not a finding. Also: cut-out brokers (nodes bridging domains), "smoke score", ACH verdict (competing-hypotheses ranking).
- Node types you will see: Person, Organization, ShellCompany, Domain, IPHost, Email, Phone, CryptoWallet, SmartContract, Filing, LegalCase, NewsArticle, TrackerID, Aircraft, Vessel, BreachRecord, OnionService.
  Edge types include OWNS, DIRECT_PARENT_OF, ULTIMATE_PARENT_OF, DIRECTOR_OF, OFFICER_OF, NOMINEE_FOR, SUBSIDIARY_OF, REGISTERED_AT, DONATED_TO, EMPLOYED_BY, FILED.

---

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Source shown as **skipped** after HTTP 401 | Missing/invalid key. CourtListener -> `COURTLISTENER_API_TOKEN`; OpenSanctions -> `OPENSANCTIONS_API_KEY` or `OPENSANCTIONS_API_URL`; Companies House PSC -> `UK_COMPANIES_HOUSE_API_KEY` |
| **403 / 429** shown as skipped | Refused or rate limited: wait, lower `--breadth`, add the key (GitHub, Censys...), or avoid Tor exits for that source |
| `keys --set` traceback "Unknown or illegal API key name" | Name not in the catalog (section 4). Env-only vars: export them in your shell |
| Key set but not used | 13 catalog keys are not read by any agent (table 4.2); also a vault value overrides your exported var |
| "too long to screen" / exit 2 | PI text over 150,000 characters: trim or split. Other exit-2 refusals: read the red panel; reword **accurately** or consult counsel |
| `--proxy` "No such option" after the subcommand | Global option: `bunnyhole --tor trace ...`, not `bunnyhole trace ... --tor` |
| `Invalid --proxy` | Scheme must be http, https, socks5, socks5h or socks4 |
| Tor not running / `.onion` fetch returns nothing | Start Tor, check `ss -ltn \| grep 9050` (Linux) or `lsof -iTCP:9050 -sTCP:LISTEN` (macOS); `--fetch-onion` silently degrades to no title when Tor or SOCKS is unavailable |
| SOCKS errors | `httpx[socks]` is core; run `uv sync` and `.venv/bin/python -c "import socksio"` |
| DNS leak while using `--tor` | `dnspython` uses the system resolver; use AnonSurf, a Tor-aware resolver setup, or accept the leak (section 3.3) |
| `permission denied` on the keys file | Vault is `0600` owned by the user who created it; do not mix `sudo` and normal runs. Fix owner: `sudo chown -R "$USER" ~/.bunnyhole ~/.osint-apis` |
| `arsenal --install` fails on apt | Needs non-interactive sudo (`sudo -n`): run `sudo -v` first or `sudo apt install <pkg>` by hand. Unknown name -> "Unknown tool" |
| Tool installed but still "MISSING" | Must be on `PATH` or in `~/.local/bin`, `~/go/bin`, `~/bin`, `/usr/local/bin`, `/opt/homebrew/bin` |
| Python version mismatch / build errors | `uv python install 3.12 && uv sync --python 3.12` |
| `anonsurf` says Linux-only | Expected on macOS; use `--tor` |
| Slow runs | Use `-g fast -d 1 -b 2`; deep gear and depth 3+ multiply requests |
| `serve` unreachable from another machine | Host-header check only allows localhost names (section 6) |
| Where are logs? | Bunnyhole writes **no log files** (no file handlers in code); output is the terminal plus `cases.db` and any `--out/--json/--pi-report` files |
| Reset profile | `rm ~/.bunnyhole/profile.json` (or `bunnyhole profile --persona generalist --clear-watch`); reset cases: delete `~/.bunnyhole/cases.db` |
| Run tests | `uv sync --extra dev && uv run pytest` (4,054 collected) |

---

## 10. Files and glossary

| Path | What |
|---|---|
| `~/.bunnyhole/api_keys.env` | Key vault (`0600`, dir `0700`, plain text) |
| `~/.osint-apis/api_keys.env` | Synced legacy mirror of the vault |
| `~/.bunnyhole/cases.db` | SQLite case store + cross-case entity memory |
| `~/.bunnyhole/profile.json` | Persona, watchlist, jurisdictions, defaults, note |
| `~/.bunnyhole/cache/sanctions/` | Downloaded OFAC/UN/UK sanctions XML (24 h TTL, stale fallback) |
| `~/osint-tools/<name>` | Optional hand-installed tools detected by `arsenal` |
| `docs/` | `PI_STREAM.md`, `PERSONALIZATION.md`, `MCP_SERVER.md`, `superpowers/specs/` design specs |
| `research/00_INDEX.md` | Index of the 13 research notes (architecture, tradecraft, PI methodology in `12_...`) |
| `CHEATSHEET.md`, `ACCEPTABLE_USE.md`, `README.md`, `.env.example` | Lead research sheet, use policy, overview, key template |

| Term | Meaning |
|---|---|
| Seed | The first clue you give `trace` |
| Selector | Any identifier used to pivot (email, wallet, handle, domain) |
| Gear | `fast` or `deep` source profile |
| Hop / depth | A round of following new leads from earlier findings |
| Receipt | SHA-256-hashed evidence record attached to every node/edge |
| Admiralty code | Source reliability (A-F) + credibility (1-6) |
| ACH | Analysis of Competing Hypotheses: ranks explanations of the evidence |
| Cut-out broker | A node bridging otherwise separate domains/clusters |
| PAI / CAI | Public vs commercially available information |
| PSC / UBO | Person with significant control (UK) / ultimate beneficial owner |
| Custodian | The party that holds a non-public record, and the legal instrument that reaches it |
