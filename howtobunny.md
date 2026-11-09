# How to run a private-investigator session with Bunnyhole

One document, in order, from a clean machine to a handed-off report. Every flag below was checked against
`uv run bunnyhole <command> --help` and the code of this checkout (Bunnyhole 0.2.0). Commands that need the
network or an API key say so on the line above them. Nothing here was run live: the offline commands were run
and their real output is shown; every PI example was pushed through the real CLI up to the point where the
investigation would start (see "How this was checked" at the end).

Read these once, they are short: `ACCEPTABLE_USE.md`, then `uv run bunnyhole pi guide`.

Placeholders are in `<ANGLE_BRACKETS>`. Replace every one before you press Enter (the shell treats a bare
`<...>` as a redirect). Commands assume you are in the repo folder and use `uv run bunnyhole ...`.

---

## 0. 60-second orientation

**What a session is.** One client matter, one case folder, one written purpose, then a series of Bunnyhole runs
(`intake` / `trace` / `link` / ...) that each write a report, a graph file and a case record, followed by a human
read, a pivot, verification on primary sources, and a handoff. Bunnyhole does the desk-research layer in
minutes; you do the judgment.

**The loop.**

```
scope  ->  collect  ->  corroborate  ->  verify  ->  report  ->  handoff
case      intake /     read labels:      primary      --pi-report   handoff sheet
sheet     trace --pi   confirmed /       lists,       + --json      to licensed
+ gates   (deep)       probable / lead   registries,  + shasum      investigator
                       pivot, repeat     archive                    or counsel
```

**The rules (non-negotiable).**

| Rule | What it means in practice |
|---|---|
| Lawful purpose | Every client run starts from a written purpose and one of nine permissible-purpose categories. Employment, tenancy, credit and insurance decisions are refused by design. |
| Passive only | Public sources and open APIs. No logins, no password resets, no contact with the subject, no pretexting. In `--pi` mode breach contents, credential lookups and Holehe-style sign-up probes are blocked. |
| Leads, not verdicts | A sanctions line is a soft name match until you verify it on the primary list. `lead` means one source. Absence from the sources searched is not proof of absence. |
| No licence implied | Bunnyhole is a research tool. It is not a licence, not a consumer reporting agency and not a lawyer. |
| Ontario | Acting as a private investigator for pay in Ontario may require a licence under the Private Security and Investigative Services Act, 2005 (PSISA). Whether it applies to you is yours to confirm: **verify with the Ministry of the Solicitor General.** The app's own legal table marks the PSISA facts as unconfirmed, and notes that Bunnyhole output feeding paid third-party work may fall inside the Act. |
| Not legal advice | Everything here, and everything Bunnyhole prints, is information. Check current law with counsel before relying on it. |

Offline reading before your first case (no network, no keys):

```bash
uv run bunnyhole pi guide                      # the method: cycle, 13 behaviours, six case types
uv run bunnyhole pi legal --jurisdiction ca-on # Ontario/Canada legal frame (PSISA, PIPEDA, Criminal Code s.184, s.264)
uv run bunnyhole pi out-of-scope               # what it refuses, and what to hand off
```

What you get: three reference screens rendered in the terminal. `pi legal --jurisdiction ca-on` lists general rules
(no pretexting, no hacking, no trespass, licence is not police power) and then PSISA, PIPEDA and the two Criminal
Code sections, each with a "Verify" column. Real output of `pi guide` (head):

```
Private-investigator method (Bunnyhole PI stream)
Bunnyhole runs the free, lawful, passive layer of an investigation the way an elite private investigator would.
It produces leads, not verdicts. It is information, not legal advice, and it is a research tool, not a licence.
The investigation cycle
 1 Intake and legal scoping ...   2 Desk research ...   3 Field verification (licensed): Not performed. ...
 4 Corroboration ...              5 Court-ready report ...
```

---

## 1. One-time setup, in order

### 1.1 Install (macOS)

```bash
brew install uv git                      # needs network. uv manages Python (>= 3.11) and the venv
git clone https://github.com/DreadpiratePickles/bunnyhole.git && cd bunnyhole   # skip if you already have the folder
uv sync                                  # needs network. Core dependencies
uv sync --extra arsenal                  # optional, needs network: scrapling, trafilatura, waybackpy, edgartools, socid-extractor, holehe
uv run bunnyhole --version
```

What you get: `bunnyhole 0.2.0` (real output). `--extra arsenal` is declared in `pyproject.toml`; Bunnyhole never
imports those libraries (it only probes for them), and of the whole arsenal catalog only `holehe` is actually
executed by an agent (and not in `--pi` mode). It is optional.

### 1.2 Health check and the arsenal tools that matter

```bash
uv run bunnyhole doctor                  # read-only table: OS, tools installed, keys set. `arsenal` is an identical alias
```

Real output (header panel, this Mac, temp key vault shortened):

```
Detected OS: macOS (26.5.2) [arm64] | Distro Profile: MACOS | Package Manager: brew
Tools Installed: 9/40 | API Keys Configured: 0/31
Key vault: <BUNNYHOLE_HOME>/api_keys.env  (legacy, read-only: ~/.osint-apis/api_keys.env)
```

Of the 40 catalog tools, the code calls only these as local programs: `whois`, `subfinder` (deep gear, domains),
`sherlock` (deep gear, usernames), `holehe` and `ignorant` (not in `--pi` mode). Install those; the rest of the
catalog is for you to run by hand.

```bash
# needs network
uv run bunnyhole doctor --install whois
uv run bunnyhole doctor --install subfinder     # go install: needs `go` (brew install go)
uv run bunnyhole doctor --install sherlock
uv run bunnyhole doctor --install all           # every missing catalog tool: slow, many installs, optional
```

What you get: for each tool, `Installed <tool> via: <command>` or `Could not auto-install ...` (exit 1 if any
install fails or the name is unknown). The hint column of `doctor` is exactly the command `--install` would run.
Without a tool Bunnyhole degrades silently: the lead simply returns less.

Optional, but set it: SEC EDGAR asks callers for a contact User-Agent.

```bash
export BUNNYHOLE_SEC_USER_AGENT="<YOUR_NAME> <YOUR_EMAIL>"
```

### 1.3 API keys: the free ones that change your results

Every key is optional. Exported shell variables always win over the vault. Keys are stored in
`~/.bunnyhole/api_keys.env` (folder `0700`, file `0600`, plain text, not encrypted). `.env` files are not loaded.

Set a key (clear it with an empty value):

```bash
uv run bunnyhole keys --set COURTLISTENER_API_TOKEN=<TOKEN>
uv run bunnyhole keys --set COURTLISTENER_API_TOKEN=            # clears it
uv run bunnyhole keys                                           # status table: SET (shell|vault|legacy) / EMPTY, masked value
```

Real output after setting a fake token in a temp vault: `Saved COURTLISTENER_API_TOKEN to <path>`, then the table
row `SET (vault) | COURTLISTENER_API_TOKEN | Corporate & Fiat | FAKE...567 | https://www.courtlistener.com/help/api/rest/ ...`.
A bad name exits 2 and prints the allowed names.

**Set these first, in this order** (all free tiers; each is read by code today):

| Priority | Key | What it unlocks | Sign up (from the registry) |
|---:|---|---|---|
| 1 | `COURTLISTENER_API_TOKEN` | US federal dockets (RECAP). Without it the call gets HTTP 401 and `court_dockets` shows as "Tried, not reached". | https://www.courtlistener.com/help/api/rest/ |
| 2 | `UK_COMPANIES_HOUSE_API_KEY` (alias `COMPANIES_HOUSE_API_KEY`, stored under the `UK_` name) | UK persons with significant control (beneficial ownership). UK entities only. | https://developer.company-information.service.gov.uk/ |
| 3 | `OPENSANCTIONS_API_KEY` **or** `OPENSANCTIONS_API_URL` | Consolidated sanctions and PEP screening. The URL form points at a self-hosted yente (keyless). Without either the status stays `partial` at best. The source catalog marks the hosted tier non-commercial: read OpenSanctions' terms before using it on paid work. | https://www.opensanctions.org/api/ and https://www.opensanctions.org/docs/yente/ |
| 4 | `GITHUB_API_KEY` | GitHub rate limit 60 to 5,000 requests/hour (handles, emails in commits). | https://github.com/settings/tokens |
| 5 | `CENSYS_API_ID` + `CENSYS_API_SECRET` (set both) | Host and certificate search, free 250 queries/month. | https://search.censys.io/ |
| 6 | `SECURITYTRAILS_API_KEY` | Historical DNS and the origin IP behind a CDN, 50/month free. | https://securitytrails.com/ |
| 7 | `HUNTER_API_KEY` | Domain email patterns, free 25 to 50 searches/month. | https://hunter.io/ |
| 8 | `URLSCAN_API_KEY`, `ALIENVAULT_OTX_API_KEY` | Optional headers that lift limits on keyless sources. | https://urlscan.io/ , https://otx.alienvault.com/ |
| 9 | `NUMVERIFY_API_KEY` | Phone carrier and line type (the registry does not state a price). | https://numverify.com/ |

Free-tier quotas are small (Censys 250, SecurityTrails 50, Hunter 25 to 50 per month): a depth 4 / breadth 8 run can
use a month of them. Save the keyed sources for the leads that matter.

**Read by code but not useful for client work.** `LEAKCHECK_API_KEY` and `EMAILREP_API_KEY` are read, but `--pi`
blocks those lookups. `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` power the
LLM council and the AI narrative: with one set, text from your case (receipts, names, selectors) is sent to that
provider. **Leave them empty for confidential matters.**

**Reserved: accepted and stored, but no agent reads them yet. Do not bother signing up.**
`HAVEIBEENPWNED_API_KEY`, `INTELX_API_KEY`, `HUDSONROCK_API_KEY`, `BREACHDIRECTORY_API_KEY`, `SHODAN_API_KEY`
(the keyless InternetDB is used), `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`, `TELEGRAM_BOT_TOKEN`,
`FEC_API_KEY`, `OPENCORPORATES_API_KEY`, `ETHERSCAN_API_KEY` (Blockscout is used keyless), `HELIUS_API_KEY`
(so there is no Solana support). `keys` marks each one `reserved: not used by any agent yet`.

What keyless already covers: DNS, certificate transparency (crt.sh), GLEIF, SEC EDGAR, Wayback, Blockscout and
mempool.space, adsb.lol, Google News, Wikidata, Shodan InternetDB, and the sanctions lists OFAC SDN, UN, UK and
Canada SEMA (the four lists screened keylessly, cached 24 h).

### 1.4 Tor and proxy

`--proxy` and `--tor` are **global flags and go before the command**. After the command they are an error.

```bash
uv run bunnyhole --tor intake --org "<COMPANY>" ...                  # = --proxy socks5h://127.0.0.1:9050
uv run bunnyhole --proxy socks5h://127.0.0.1:9050 trace <SEED>       # schemes: http, https, socks5, socks5h, socks4
export BUNNYHOLE_PROXY=socks5h://127.0.0.1:9050                      # standing proxy with no flag
export BUNNYHOLE_TOR_PROXY=socks5h://127.0.0.1:9150                  # Tor Browser's port instead of the daemon's 9050
```

macOS Tor daemon (not run here): `brew install tor && brew services start tor`, then
`lsof -iTCP:9050 -sTCP:LISTEN` should show a listener. A bad scheme exits 2 with `Invalid --proxy`.

**Honest caveat.** Traffic from the shared HTTP client is routed through the proxy (a repository test now guards that
no agent builds its own client, and LLM calls use it too). Not covered by `--proxy` / `--tor`: DNS lookups made with
`dnspython` (system resolver), and the local programs Bunnyhole launches (`whois`, `subfinder`, `sherlock`, `holehe`).
**Never rely on `--tor` alone for anonymity**. Also: domain traces fetch the subject's
own website (the OSINT agent fingerprints the site), so the subject's server can see a request unless you
route it; and every selector you type is sent to the public services queried. Tor does not hide a keyed
account from the service that issued the key, and some sources block Tor exits.

### 1.5 Kali / Parrot notes

```bash
sudo apt update && sudo apt install -y git curl pipx tor whois golang-go     # needs network
curl -LsSf https://astral.sh/uv/install.sh | sh                              # official uv installer
uv sync && uv run bunnyhole doctor                                           # run as your normal user, not root
sudo systemctl enable --now tor && ss -ltn | grep 9050                       # Tor listener on 127.0.0.1:9050
uv run bunnyhole anonsurf status                                             # Linux only; on macOS it exits 1 and points to --tor
```

- Run Bunnyhole as your normal user. Keys and cases live in the invoking user's `~/.bunnyhole`; the app calls `sudo`
  itself only for `anonsurf` and system-package installs (`sudo -n`, non-interactive: run `sudo -v` first).
- `anonsurf start` / `stop` ask for confirmation (`--yes` skips it) and reroute **all** host traffic through Tor. It is the
  fix for the leaks above, but never use it over SSH, and snapshot the VM first. Subcommands: `status`, `start`, `stop`,
  `restart`, `change` (new identity), `install`.
- A live-boot session loses `~/.bunnyhole` at reboot. Keep the case folder on encrypted storage.

---

## 2. Set your profile once

```bash
uv run bunnyhole personas                       # six lenses; the active one is marked
uv run bunnyhole profile --persona pi --name "<YOUR_NAME>" --jurisdiction ca-on
uv run bunnyhole profile                        # show it
```

Values from the real `personas` output, reformatted (the `pi` row is what `--pi` selects automatically):

| Key | Defaults (gear / depth / breadth) | Sanctions emphasis |
|---|---|---|
| `generalist` | fast / 2 / 4 | no |
| `journalist` | fast / 2 / 5 | no |
| `compliance` | deep / 3 / 4 | yes |
| `threat_intel` | fast / 2 / 6 | no |
| `crypto_tracer` | deep / 3 / 5 | yes |
| `pi` | deep / 3 / 4 | yes |

Profile flags (all verified from `profile --help`):

| Flag | Meaning |
|---|---|
| `--persona <key>` | Active lens. Case-insensitive; an unknown key exits 2 and lists the valid ones. |
| `--name <text>` | Display name used for attribution on dossiers. |
| `--watch <selector>` / `--unwatch <selector>` / `--clear-watch` | Recurring selectors. A hit shows as `watchlist_hits` in results. Repeatable. |
| `--jurisdiction <code>` | Standing jurisdictions of interest. **Replaces** the list; repeatable; stored upper-case. |
| `-x`, `--exclude <text>` | Standing default exclusions folded into **every** case. **Replaces** the list; repeatable. |
| `-g`, `-d`, `-b` | Standing gear / depth (1-4) / breadth (2-8) overrides. No flag clears one: delete `~/.bunnyhole/profile.json` to reset. |
| `--note <text>` | Free-text note. |

Two cautions. Put only matter-independent things in the standing exclusions (a noisy domain you never want), not a
client's namesake. And `profile.json` is plain text on disk, so do not put a client's name on the watchlist. A
persona only fills the gear/depth/breadth you did not pass; flags you pass always win.

---

## 3. Start every case the same way

Create a case folder and a case sheet **before** the first run. The case sheet is your written purpose, which is what
makes the queries lawful for a professional and not for a curious stranger.

```bash
export CASE=~/cases/<MATTER_REF>             # one folder per matter; re-run this export in each new terminal
mkdir -p "$CASE"/{reports,evidence,notes,logs}
```

Paste this into `$CASE/notes/case_sheet.md` and fill it in:

```markdown
# Case sheet: <MATTER_REF>
Opened (UTC): <run: date -u +%FT%TZ>

- Client / matter:            <CLIENT_NAME> / <ONE_LINE_MATTER>
- Instructing lawyer or authority: <NAME, CONTACT>
- Purpose (one honest sentence, 15+ characters, what decision or legal step this serves):
    <e.g. Identify attachable assets of a judgment debtor to enforce a judgment>
- Purpose category (pick ONE):
    judgment_enforcement | litigation_support | service_of_process | asset_recovery | fraud_investigation |
    counterparty_due_diligence | authorities_referral | regulatory_compliance_kyc* | journalism_public_interest*
    (* entity subjects only)
- Matter reference (real case no., contract no. or judgment ref; required for every person subject):
    <e.g. CV-24-00123456>
- Jurisdiction code for custodians and legal notes:  <ca-on | us | uk | ...>
- Subject type:               <person | entity>
- Case type:                  <locate | background | asset_search | due_diligence | fraud_screen | missing_person>
- Known identifiers (only what the client gave you, with source and date):
    names: <...>   emails: <...>   phones: <...>   usernames: <...>
    domains: <...>   wallets/ENS: <...>   aircraft N-numbers: <...>   registered numbers: <...>
    evidence files (in $CASE/evidence): <...>
- Working hypothesis (what you expect, so the report can test it):  <...>
- Competing hypothesis (what else could explain it):                <...>
- Exclusions (namesakes, noisy domains, terms to ignore):           <...>
- What would change my mind:                                        <...>
- Out of scope / must not do:                                       <...>
- Notes on lawful basis and retention (PIPEDA applies to personal data in commercial work): <...>
```

**The gates in six lines.** Each prints a red panel and exits with code 2 before anything is searched.

1. A missing or short (under 15 characters) `--purpose`, or a missing/unknown `--purpose-category`, is refused.
2. Eligibility decisions (employment, tenancy, credit, loan, insurance) are refused, by purpose text and by phrase screens over every free-text field (hypothesis, notes, selectors, file names).
3. A person subject needs one of seven categories **and** a `--matter-ref` (format-checked only: 5+ characters, a digit or a `v.`/`vs` pair, not a placeholder like `TBD`). `regulatory_compliance_kyc` and `journalism_public_interest` are entity-only.
4. Wordings about locating an ex-partner or someone avoiding the client (stalking pattern) are refused; the pursuit screen applies to every case type.
5. `--cred` and credential-shaped text in `--purpose`, `--client` or `--matter-ref` are refused; any single text over 150,000 characters is "too long to screen".
6. `--subject-type entity` with a person-like name ("Maple Leaf Roofing", no legal form) is refused unless you add a legal form (`Inc`, `Ltd`, `LLC`) or `--confirm-entity`.

**If you are refused:** read the panel, then state the matter *accurately* in plain words, or consult counsel. A
legitimate purpose can trip a phrase screen (known false refusals are listed in `docs/PI_STREAM.md` section 4):
rewording to say what the matter really is can clear it. **Never try to evade a gate** (synonyms, spacing, a false
category or a made-up matter reference). The category and reference are attested by you; Bunnyhole cannot verify
them, and you carry the responsibility. A reference that passes the format check but does not exist is a
misrepresentation to your own client file.

Real refusal, person locate without a matter reference (exit 2):

```
PI engagement refused
Investigating a private person under 'service_of_process' needs a matter reference: a case number, contract or
judgment reference that shows the legitimate matter. Add --matter-ref.
```

Before the first run, read the playbook for your case type (offline) so you know the done-when and the stop-ifs:

```bash
uv run bunnyhole pi playbook asset_search      # locate | background | asset_search | due_diligence | fraud_screen | missing_person
uv run bunnyhole pi sources --jurisdiction ca-on --case-type asset_search   # free source catalog; a tick means Bunnyhole queries it
uv run bunnyhole pi sources --implemented                                    # only what it queries today
```

**What Bunnyhole does not query for Ontario work** (do these by hand and write the results into your notes): the
Ontario Business Registry (https://www.ontario.ca/page/ontario-business-registry), Corporations Canada
(https://ised-isde.canada.ca/site/corporations-canada/en/node/269), CanLII (https://www.canlii.org/), OnLand
parcel registers (https://www.onland.ca/, free account), CRA charities listings, ICIJ Offshore Leaks
(https://offshoreleaks.icij.org/), Equasis for ships (https://www.equasis.org/, free account). It does query GLEIF,
the Canada SEMA sanctions list, OFAC, UN, UK, Google News, Wayback and Wikidata.

---

## 4. The maximum-depth commands, one per scenario

### Flags, settings and what they cost

| Flag (on `trace` and `intake` unless noted) | Meaning |
|---|---|
| `-g`, `--gear fast\|deep` | `deep` adds the local tools (subfinder on domains, sherlock on usernames) and an identity/handle sweep on the name stem of company and person leads. More requests, slower, noisier. |
| `-d`, `--depth 1-4` | Follow-up hops. The loop runs hops 2 to `depth`, so depth 1 is the seed only. Max 4. |
| `-b`, `--breadth 2-8` | Leads pursued in parallel per hop. Max 8. |
| `-H`, `--hypothesis` | Steers lead priority and the ACH ranking; appears in the report's *Client theory vs. evidence*. |
| `-u`, `-e`, `-p`, `-w`, `--domain`, `--doc`, `-x` | Extra selectors: username, email, phone, wallet/ENS, domain/IP, local `.pdf`/`.docx`, exclusion. `intake` also has `--org` (company, person name or N-number) and `--dump` (free text to auto-extract). All repeatable on `intake`. `-p` is `--phone` here (it is `--port` on `serve`). |
| `--anchor-mode convergence\|locked_profile` | `convergence` (default): treat the clues as unverified islands and test IF and HOW they connect. `locked_profile`: you have confirmed they are one target; link them to one root. |
| `--persona <key>` | One-off lens for this case. |
| `-o`, `--out <file>` | Full Markdown dossier. **Only available at run time.** |
| `--json <file>` | Full graph JSON (gains a `pi` key with `--pi`). |
| `--pi` | PI engagement: vets the purpose, persona `pi`, adds the PI block. Every flag below is an error without it. |
| `--case-type` | `locate`, `background`, `asset_search`, `due_diligence` (default), `fraud_screen`, `missing_person`. |
| `--purpose` | Required. One sentence, 15+ characters. |
| `--purpose-category` | Required. The nine values in section 3. |
| `--client` | Client name recorded in the engagement and report (free text, plain text on disk). |
| `--matter-ref` | Required for every person subject; optional but format-checked for an entity. |
| `--subject-type person\|entity` | Default `person`. |
| `--confirm-entity` | Override the person-like-name check for a real organisation. |
| `--pi-jurisdiction` | `ca-on`, `us`, `uk`, ... Picks the legal instrument named for each custodian. |
| `--pi-report <file>` | Bottom-line-up-front PI report (Markdown). |

**Trace versus intake.** `trace SEED` takes one positional seed. If you add any extra selector or `--hypothesis`
to `trace`, it silently becomes an `intake` whose free-text dump is your seed. The free-text parser treats a seed of
more than four words as a hypothesis, not a company. So **for a company with extra selectors, use
`intake --org "<COMPANY>"`.** `intake` has no positional argument and needs at least one selector (a hypothesis or
exclusion alone is not a seed).

**Settings: time, noise, cost.** Run times were not measured. The mechanics are: each hop pursues up to *breadth*
leads, so `deep` + depth 4 + breadth 8 is the widest, slowest and noisiest setting, issues the most requests against
third parties, burns free-tier quotas, and returns the most unrelated records (the report sets low-relevance ones
aside; the JSON keeps them). Start with depth 2 or 3 and breadth 4 to 6 on the first pass, read the report, then
spend the maximum on the leads that earned it. Cost is your time and your quotas: everything here is free or keyless.

| Setting | When to use |
|---|---|
| `fast`, depth 1, breadth 2 | A first look, or checking a single selector. |
| `deep`, depth 2 to 3, breadth 4 to 6 | The normal PI pass (the `pi` persona default is deep / 3 / 4). |
| `deep`, depth 4, breadth 8 | A final sweep once identity is settled and you have keys set. Expect noise and slow runs. |

**Always create the output folder first and always pass all three outputs** (`--pi-report`, `--json`, `--out`).
The files are written after the run, the dossier cannot be exported from a saved case later, and a missing folder
fails after the work is done. Use `NO_COLOR=1 COLUMNS=200 ... 2>&1 | tee "$CASE/logs/<RUN>.txt"` if you also want a
terminal transcript (standard shell, not run against a live case).

**Without `--pi`** no purpose is vetted, and breach/credential lookups and sign-up probes can run (`--cred` works).
That is not a mode for client work on private individuals. `link`, `jet`, `darkweb`, `doc-forensics` and `council` have no
PI gate at all: your case sheet is the control for them.

### (A) Company due diligence, including sanctions

Network. Keys that change the result: `OPENSANCTIONS_API_KEY`/`_URL` (sanctions status), `UK_COMPANIES_HOUSE_API_KEY`
(UK ownership), `COURTLISTENER_API_TOKEN` (US dockets).

```bash
uv run bunnyhole intake --org "<COMPANY_NAME_WITH_LEGAL_FORM>" --domain <COMPANY_DOMAIN> \
  --hypothesis "<WHAT_YOU_EXPECT, e.g. Is it a real operating company with clean ownership?>" \
  --exclude <NOISE_DOMAIN> --anchor-mode locked_profile \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type due_diligence --subject-type entity \
  --purpose "<e.g. Counterparty due diligence on a prospective supplier before signing a supply agreement>" \
  --purpose-category counterparty_due_diligence \
  --client "<CLIENT_NAME>" --matter-ref "<FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/01_company_pi.md" --json "$CASE/reports/01_company.json" --out "$CASE/reports/01_company_dossier.md"
```

What you get: a terminal summary (case ID, entities, edges, receipts, top entities, link paths, cross-case hits), a
PI SUMMARY panel (label counts, source classes not searched, custodians), and the three files. In the report, read
*Sanctions screening* first: with a key or yente the status can reach `lists_run`; without one it is `partial`
(OFAC, UN, UK and Canada SEMA screened, OpenSanctions not). The EU list is never automated: check
https://www.sanctionsmap.eu/ yourself. `locked_profile` is right only if you have confirmed the domain belongs to the
company; otherwise drop that flag (default `convergence`). Entity names need a legal form, or add `--confirm-entity`.
A KYC onboarding review is the same command with `--purpose-category regulatory_compliance_kyc` (entities only).

### (B) Asset search and beneficial-ownership walk for a company

Network. Same keys as (A); `COURTLISTENER_API_TOKEN` matters most for the US variant, Companies House for UK links.
`--org` takes company names and aircraft N-numbers, so related companies and a known aircraft go in the same run.

Ontario (`ca-on`):

```bash
uv run bunnyhole intake --org "<JUDGMENT_DEBTOR_COMPANY>" --org "<RELATED_COMPANY>" --org <KNOWN_N_NUMBER> \
  --domain <DEBTOR_DOMAIN> --wallet <KNOWN_WALLET_OR_ENS> \
  --hypothesis "<e.g. The debtor moved assets into related companies after the claim was issued>" \
  --exclude <NOISE_DOMAIN> --anchor-mode locked_profile \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" \
  --purpose-category judgment_enforcement \
  --client "<CLIENT_OR_LAW_FIRM>" --matter-ref "<COURT_FILE_NO, e.g. CV-24-00123456>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/02_assets_pi.md" --json "$CASE/reports/02_assets.json" --out "$CASE/reports/02_assets_dossier.md"
```

US variant (federal docket number as the reference, US custodians and instruments):

```bash
uv run bunnyhole intake --org "<JUDGMENT_DEBTOR_COMPANY>" --domain <DEBTOR_DOMAIN> \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" \
  --purpose-category judgment_enforcement --matter-ref "<DOCKET, e.g. 2:24-cv-01234>" --pi-jurisdiction us \
  --pi-report "$CASE/reports/02_assets_us_pi.md" --json "$CASE/reports/02_assets_us.json"
```

What you get: the *Ownership chain* (child, parent, share, source, as-of date, levels walked, 50%-rule flags, nodes
where the walk ended before a natural person), *What is NOT a link* (registered agents, nominees, shared hosting),
and *Custodians and next steps* naming who holds the records public data cannot reach (banks, exchanges, registrars)
and the instrument for the jurisdiction. Honest limits: the chain often ends at a registry record; Ontario land
(OnLand) and the Ontario/federal corporate registries are not queried, so pull them by hand; `property_assets` is
covered only by aircraft tracking; bank and exchange accounts are never visible. A quiet 50%-rule result is not
clearance (it needs ownership percentages, which come only from sources such as UK PSC bands).

### (C) Person locate for service of process or judgment enforcement (matter reference required)

Network. Person subjects are limited to seven categories and **always** need `--matter-ref`. Bunnyhole refuses
without one because the reference is what ties the search to a legitimate matter and gives you an audit trail; it is
format-checked only, so it must be a real file number you can produce to your client.

```bash
uv run bunnyhole intake --org "<SUBJECT_FULL_LEGAL_NAME>" --email <KNOWN_EMAIL> --phone "<+1-416-555-0100>" --username <KNOWN_HANDLE> \
  --hypothesis "<e.g. Subject is the same person named as the defendant in the open action>" \
  --exclude "<NAMESAKE_TO_IGNORE>" --anchor-mode locked_profile \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type locate --subject-type person \
  --purpose "Locate the defendant so that a statement of claim can be served in an open action" \
  --purpose-category service_of_process \
  --client "<LAW_FIRM>" --matter-ref "<COURT_FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/03_locate_pi.md" --json "$CASE/reports/03_locate.json"
```

For enforcing a judgment instead, change the purpose and use `--purpose-category judgment_enforcement`
(`"Locate the judgment debtor to enforce a monetary judgment"`). Refused if you omit `--matter-ref`, if you use
`regulatory_compliance_kyc` or `journalism_public_interest`, or if the text reads like an ex-partner or avoidance search.

What you get: leads and corroboration labels, an *Identity resolution* section ("N records named X are NOT established as
one person"), custodians, and a handoff sheet. What you do **not** get is a current address: that sits in
credit-header databases, which Bunnyhole will never use (section 7). A person needs a full name plus one more
anchor (email, phone, username, wallet, domain) or the report warns "subject anchoring unverified".

### (D) Fraud screen on an entity

Network. `fraud_investigation` is the category; a lookalike or clone domain goes in `--domain`.

```bash
uv run bunnyhole intake --org "<ENTITY_NAME_WITH_LEGAL_FORM>" --domain <SUSPECT_DOMAIN> \
  --hypothesis "<e.g. A cloned or shell company taking deposits for goods it does not supply>" \
  --exclude <REAL_COMPANY_DOMAIN> --gear deep --depth 4 --breadth 8 \
  --pi --case-type fraud_screen --subject-type entity \
  --purpose "Screen an entity suspected of taking deposits for goods it does not supply, for a fraud complaint" \
  --purpose-category fraud_investigation \
  --client "<CLIENT>" --matter-ref "<FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/04_fraud_pi.md" --json "$CASE/reports/04_fraud.json"
```

What you get: indicator-by-indicator findings (shell-company flags, enforcement and complaints, lookalike domains,
public ledgers); consumer-complaint claims (US CFPB) are marked unverified. *Playbook progress* shows which steps
ran, and the *Custodians* section names where funds would reach a bank or exchange (the point to escalate).

### (E) The single widest command: a multi-selector `intake`

This is the command that produces the most results: it seeds every selector type in one run and lets the hypothesis
steer the pivots. Network. Entity subject, no `--cred` (refused in `--pi`), email addresses at the company's own
domain (a consumer-mail `first.last@` address counts as a person and fails `--subject-type entity`).

```bash
uv run bunnyhole intake \
  --org "<ENTITY_NAME>" --org "<AFFILIATE_NAME>" --org <KNOWN_N_NUMBER> \
  --domain <DOMAIN_1> --domain <DOMAIN_2> \
  --email <ROLE_EMAIL_1> --email <ROLE_EMAIL_2> \
  --phone "<+1-416-555-0100>" --phone "<+1-905-555-0111>" \
  --username <HANDLE_1> --username @<HANDLE_2> \
  --wallet <0x_ADDRESS_OR_BTC_ADDRESS> --wallet <NAME.eth> \
  --doc "$CASE/evidence/<CONTRACT>.pdf" --doc "$CASE/evidence/<INVOICE>.docx" \
  --exclude <NOISE_DOMAIN> --exclude "<NAMESAKE_OR_TERM>" \
  --hypothesis "<e.g. The two companies share a controller and funds moved to the wallet>" \
  --anchor-mode convergence \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type fraud_screen --subject-type entity \
  --purpose "Screen a counterparty and its affiliates after non-delivery of goods, for a fraud complaint" \
  --purpose-category fraud_investigation \
  --client "<CLIENT>" --matter-ref "<FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/05_case_pi.md" --json "$CASE/reports/05_case.json" --out "$CASE/reports/05_case_dossier.md"
```

What you get: all leads fan out at hop 1 (company and sanctions sources, DNS and certificate transparency, Wayback,
Shodan InternetDB, GitHub and handle sweeps, wallet explorers, phone and aircraft lookups, local PDF/DOCX
forensics), then up to three more hops follow what turned up. With `convergence` the report tests whether the
islands connect (see *Link Sleuth* paths in the terminal and *Client theory vs. evidence*). Switch to
`locked_profile` once you have confirmed they are one target. Put the `--doc` files at the paths you give before you run
(a bad path is not checked by the gates); their contents are read by the engine but **not screened by the gates**, so keep
credential-bearing files out.

Person variant of the same idea (needs a person category and `--matter-ref`):

```bash
uv run bunnyhole intake --org "<SUBJECT_FULL_NAME>" --email <EMAIL> --phone "<PHONE>" --username <HANDLE> --wallet <WALLET_OR_ENS> \
  --doc "$CASE/evidence/<FILE>.pdf" --exclude "<NAMESAKE>" --anchor-mode locked_profile \
  --gear deep --depth 4 --breadth 8 \
  --pi --case-type background --subject-type person \
  --purpose "Confirm the identity of the defendant named in an open action and map her public corporate roles" \
  --purpose-category litigation_support --matter-ref "<COURT_FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/05_person_pi.md" --json "$CASE/reports/05_person.json"
```

Plain-text variant when you only have a messy note (no PI gates unless you add `--pi`): `intake --dump "<PASTE NOTES>" --out "$CASE/reports/dump.md"`
auto-extracts emails, domains, wallets, phones, handles, N-numbers, `-exclusion` tokens and a hypothesis.

### (F) Crypto wallet trace

Network. Keyless: Blockscout (EVM chains) and mempool.space (Bitcoin). No Solana (its key is reserved). Use the
`crypto_tracer` persona for the lens; the wallet owner is a person unless you know otherwise, so a person subject needs
the matter reference.

```bash
uv run bunnyhole trace <0x_ADDRESS_OR_BTC_ADDRESS_OR_NAME.eth> \
  --gear deep --depth 4 --breadth 8 --persona crypto_tracer \
  --pi --case-type fraud_screen --subject-type person \
  --purpose "Trace where misappropriated client funds went, for a fraud complaint" \
  --purpose-category fraud_investigation --matter-ref "<FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/06_wallet_pi.md" --json "$CASE/reports/06_wallet.json"
```

Without `--pi` (your own or public research, no client): `uv run bunnyhole trace <WALLET> --gear deep --depth 4 --breadth 8 --persona crypto_tracer --json "$CASE/reports/06_wallet.json"`.
What you get: counterparties, clusters, bridges, and exchange deposit addresses. An exchange deposit address is a
**custodian**: the report names the instrument (for Ontario, a Norwich Pharmacal or production order via counsel).
Wallet labels are not attribution.

### (G) Domain, infrastructure and threat-intel trace

Network. Keyless: DNS, crt.sh, Shodan InternetDB, Wayback, RIPEstat. Keys that add results: `CENSYS_API_ID`+`_SECRET`,
`SECURITYTRAILS_API_KEY`, `URLSCAN_API_KEY`, `ALIENVAULT_OTX_API_KEY`, `GITHUB_API_KEY`, `HUNTER_API_KEY`. Local
tools that add results in deep gear: `whois`, `subfinder`. This sends requests to the subject's own site.

```bash
uv run bunnyhole trace <SUSPECT_DOMAIN> --gear deep --depth 4 --breadth 8 --persona threat_intel \
  --out "$CASE/reports/07_domain_dossier.md" --json "$CASE/reports/07_domain.json"
```

For a client fraud matter (a lookalike domain used in invoice fraud) use the gated form:

```bash
uv run bunnyhole trace <SUSPECT_DOMAIN> --gear deep --depth 3 --breadth 6 \
  --pi --case-type fraud_screen --subject-type entity \
  --purpose "Screen a lookalike domain used to impersonate our client in invoice fraud" \
  --purpose-category fraud_investigation --matter-ref "<FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/07_domain_pi.md" --json "$CASE/reports/07_domain.json"
```

What you get: registrant and nameserver pivots, subdomains, certificate history, hosting neighbours (flagged as not a
link when it is a shared CDN), origin IP behind a CDN (needs SecurityTrails), leaked-secret and handle pivots. Shared
hosting is a soft selector: do not treat two sites on one IP as one operator.

### (H) How two entities connect: `link`

Network. Fixed at depth 2 and breadth 4; only `--gear` is available; no `--pi`.

```bash
uv run bunnyhole link "<ENTITY_A>" "<ENTITY_B>" --gear deep     # person, company, domain, wallet or handle
```

What you get: both sides expand simultaneously, then a co-occurrence test; the terminal shows multi-hop paths with
the domains they cross and Adamic-Adar predicted hidden connections via rare shared intermediaries. A predicted link
is a hypothesis to test, not a finding.

### (I) Aircraft and vessels

Network. `jet` takes a US N-number or a 6-hex-digit ICAO address; anything else exits 2 (Canadian `C-` registrations are
rejected). It reads no key. Verified offline: `N628TS` converts to ICAO `a835af`.

```bash
uv run bunnyhole jet <N_NUMBER_OR_ICAO_HEX>                 # e.g. N628TS or a835af
uv run bunnyhole intake --org <N_NUMBER> --gear deep --depth 2 --breadth 4 --json "$CASE/reports/08_aircraft.json"   # inside a case
```

What you get: a JSON panel titled with the N-number and its ICAO hex, holding the adsb.lol telemetry (live output not seen
here). Expect positions and movements, not the registered owner (unverified): look the owner up on the aircraft registry
yourself. **Vessels are not supported by any
command**: use Equasis by hand (free account, listed in `pi sources` as not queried).

### (J) Dark-web mentions: `darkweb` with Tor

Network. Keyless (Ahmia index). `--fetch-onion` also fetches each `.onion` hit's page title through Tor and needs a
running Tor listener; without one it degrades to no title. The global `--tor` goes before the command.

```bash
uv run bunnyhole --tor darkweb "<DOMAIN_OR_COMPANY_OR_EMAIL_OR_@HANDLE>" --fetch-onion
uv run bunnyhole darkweb "<SELECTOR>"                       # no Tor, index search only
```

What you get: a table of onion service, title and flags, and the line that hits are soft, low-confidence leads
(Admiralty C3): an indexed mention is not proof of a link. This command has no PI gate and does not read the case sheet:
search only selectors you are entitled to search.

### (K) Document metadata: `doc-forensics`

Offline, local file only; no network and no key. Exits 1 with a one-line message for a missing, unreadable, unsupported
or corrupt file. Copy the original into `$CASE/evidence` first and hash it (section 6): analyse the copy.

```bash
uv run bunnyhole doc-forensics "$CASE/evidence/<FILE>.pdf"     # or .docx
```

Real output for a PDF I generated for this guide (fake metadata):

```json
{ "type": ".pdf", "rsids": [],
  "metadata": { "/Producer": "Test Producer", "/Author": "Test Author",
                "/CreationDate": "D:20240101120000-05'00'", "/CreationDate_timezone": "UTC-05:00" },
  "anomalies": [ "Embedded PDF clock offset UTC-05:00 in /CreationDate" ] }
```

What you get: for `.pdf`, `/Info` and XMP fields plus any timezone offset embedded in the creation and modification
dates; for `.docx`, Word RSID revision fingerprints (`rsid_root`, up to 50 RSIDs, total revisions) read from
`word/settings.xml`, plus core authors. A timezone offset or author is a lead about where or how a file was made, not
about who. The same analysis runs inside `trace` / `intake` when you pass `--doc` (the DOCX/PDF forensics step).

### Optional: `council`, and the other surfaces

```bash
uv run bunnyhole council "<SEED>" --gear deep --depth 2     # needs an AI key (OPENROUTER_API_KEY) for LLM output; sends case text to the provider
uv run bunnyhole ui [<SEED>]                                # full-screen War-Room TUI (alias: tui). No PI or persona controls
uv run bunnyhole menu                                       # prompt-driven menu: trace, link, doctor, keys, jet, cases
uv run bunnyhole serve                                      # web War-Room at http://127.0.0.1:8000 (--host, --port/-p)
uv run bunnyhole mcp --print-config                         # JSON snippet to register Bunnyhole as an MCP server
```

`council` runs the investigation and prints the five specialist briefs and the chairman verdict (depth defaults to 1).
`serve` refuses a non-loopback `--host` (exit 2) unless `BUNNYHOLE_API_TOKEN` is set. The MCP server exposes one
read-only `pi_reference` tool and no tool that runs a PI engagement: **the purpose gates are CLI-only**, so run client
work from the CLI.

---

## 5. The follow-up loop: how a real investigator reaches depth

One run is a first pass. Depth comes from reading, then pivoting with what you learned.

### 5.1 Read the report top to bottom

Open `$CASE/reports/<RUN>_pi.md`. It has 16 sections in this order; read them in this order of attention:

| Section | What to take from it |
|---|---|
| **Bottom line** | At most six bullets: Sanctions, Registry, Findings, Biggest gap, Not covered, Next step. If the Next step is an escalation, stop and call counsel. |
| **Sanctions screening** | Status (`not_run`, `partial`, `lists_run`), lists screened, lists NOT screened with the reason, each hit as a "SOFT MATCH: verify on primary list". The EU list is always listed as not screened. |
| **Entity profile** | Legal name, LEI, status, registered address, parents, from GLEIF/Companies House when the registry record matches your subject. |
| **Engagement & scope** | Your purpose, category, matter ref, conflict-check result, identifier warnings. Confirm it says what you meant. |
| **Findings** | Each finding with label, source count, freshness (`fresh` up to 12 months, `aging` to 36, `stale`) and relevance (`subject`, `related`). Only the strongest 25 relevant rows show; the rest are in the JSON. |
| **Ownership chain** | Who owns whom, with shares and dates, and where the walk ended before a natural person. Every such end is a pivot or a custodian request. |
| **Identity resolution** | Same-name records that are not one person; probable same person on 2+ anchors. |
| **What is NOT a link** | Registered-agent addresses, nominees, shared hosting, common names. Do not chase these. |
| **Contradictions and gaps** | Conflicting records and long gaps in the timeline: each is a question to ask. |
| **What would change this conclusion** | The falsifiers. Go and look for them. |
| **Coverage and negatives** | See below. |
| **Playbook progress** | `DONE` / `PARTIAL` / `NOT RUN` / `NEEDS LICENSED LAYER` per step. "Done when" is your judgment, not Bunnyhole's. |
| **Custodians and next steps** | Who holds the non-public record, the legal instrument for your jurisdiction, and the handoff sheet. |
| **Chain of custody** | Receipt ID, tool, URL, collection time and a SHA-256 of the recorded extract (not of the page). |
| **Limitations & legal notices** | Standing notices. Keep them with the report. |

**`NOT SEARCHED` versus "Tried, not reached".** `NOT SEARCHED` means no mapped source returned a hit or a clean
negative for that source class: it is a task list, not a clean result. "Tried, not reached" means the source was
attempted but refused or failed (HTTP 401/403/429 logged as `skipped`, other errors as `error`), usually a missing
key. Fix the key (section 1.3) or do that class by hand, then say so in your notes.

**Labels.** `confirmed` is 3 or more independent sources, `probable` is 2, `lead` is 1. The count is the number of
independent tools (receipts sharing a URL host and path count once). It measures corroboration, not truth: two tools
reading one underlying record can still look independent.

**Admiralty codes** on receipts: source reliability `A` to `F` plus information credibility `1` to `6`. `A1` completely
reliable and confirmed; `B2` usually reliable, probably true (typical for list hits); `C3` fairly reliable, possibly
true (typical for a dark-web lead); `E5`/`F6` unreliable or unjudgeable. The grade describes the source, not
confirmation. Confidence tiers: `VERIFIED` (A1, A2, B1), `CORROBORATED` (B2, C1, C2), `CIRCUMSTANTIAL` (C3, D2, D3),
`HYPOTHESIS` (D4, E5, F6).

**Selector strength.** `STRONG` (wallet, LEI, email, ICAO hex) has near-zero collision. `SOFT` (a person name, a shared
CDN IP, a registered agent) is collision-prone. `SOFT_NAME_MATCH_VERIFY` means two people or firms can share the name:
confirm with a second identifier.

### 5.2 Pivot: re-run with the new selectors

Run 1 is the first pass; run 2 and 3 use what run 1 discovered. Write each new selector and where it came from in
the case sheet before you run it (it keeps the chain clean and gives the gates the right wording). Worked example for an
Ontario judgment-enforcement matter.

**Run 1: the company** (first pass, depth 3 / breadth 6 to read before spending the maximum):

```bash
uv run bunnyhole intake --org "<DEBTOR_COMPANY>" --domain <DEBTOR_DOMAIN> --gear deep --depth 3 --breadth 6 \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" --purpose-category judgment_enforcement \
  --client "<LAW_FIRM>" --matter-ref "<COURT_FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/10_company_pi.md" --json "$CASE/reports/10_company.json" --out "$CASE/reports/10_company.md"
```

Say the *Ownership chain* shows a sole officer, `<OFFICER_NAME>`, and their consulting company `<OFFICER_COMPANY>`.

**Run 2: the officer** (a new subject, now a person: person category, same matter ref, namesake excluded). An officer is not the
debtor: investigating a non-party individual is a legal question, so confirm the purpose with counsel first (the category
here is `litigation_support`):

```bash
uv run bunnyhole intake --org "<OFFICER_NAME>" --org "<OFFICER_COMPANY>" --exclude "<NAMESAKE_OF_OFFICER>" \
  --gear deep --depth 3 --breadth 6 \
  --pi --case-type asset_search --subject-type person \
  --purpose "Trace assets transferred by the judgment debtor to its sole officer after the claim was issued" \
  --purpose-category litigation_support --client "<LAW_FIRM>" --matter-ref "<COURT_FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/11_officer_pi.md" --json "$CASE/reports/11_officer.json"
```

**Run 3: a domain** found in run 1 or 2 (for example a payment or holding site):

```bash
uv run bunnyhole trace <DISCOVERED_DOMAIN> --gear deep --depth 3 --breadth 6 \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" --purpose-category judgment_enforcement \
  --matter-ref "<COURT_FILE_NO>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/12_domain_pi.md" --json "$CASE/reports/12_domain.json"
```

Then connect them, and test the hypothesis directly:

```bash
uv run bunnyhole link "<DEBTOR_COMPANY>" "<OFFICER_COMPANY>" --gear deep
```

What you get: each run ends with the conflict check against your earlier cases (in *Engagement & scope*) and a
*Cross-Case Entity Memory Hits* table in the terminal, so a name that appeared in run 1 is flagged in run 2.

### 5.3 Cases: list, search, reload

```bash
uv run bunnyhole cases                          # last 25 saved cases: ID, seed, gear, nodes, edges, receipts, created (UTC)
uv run bunnyhole cases --search "<ENTITY_SUBSTRING>"    # every sighting across all cases (-q)
uv run bunnyhole cases --load <CASE_ID>         # re-display a saved case in the terminal (-l)
```

`--load` re-displays the summary only. It does not rewrite your report or dossier, so keep the files from run time. An
empty `--search` or `--load` value exits 2; an unknown case ID exits 1. Every `trace` and `intake` run is saved
automatically; `link` shares the same save code (not verified against a live run). The store is `~/.bunnyhole/cases.db`,
**unencrypted**.

### 5.4 Cut noise with `--exclude`, then re-run only what changed

Put the namesake, the noisy domain or the term in `--exclude` (repeatable, accepts a domain, wallet or term) and re-run
the affected pivot, not the whole case. Standing exclusions belong in `profile --exclude` only if they are true for
every matter. Do not exclude something just because it is inconvenient: write the reason in the case notes.

---

## 6. Verify and preserve evidence

**Verify every sanctions hit on the primary list** (the report prints a URL per hit; these are the list owners):

| List | Primary source |
|---|---|
| OFAC SDN (US) | https://sanctionssearch.ofac.treas.gov/ |
| UN Security Council | https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list |
| UK Sanctions List | https://www.gov.uk/government/publications/the-uk-sanctions-list |
| Canada (SEMA, Global Affairs Canada) | https://www.international.gc.ca/world-monde/international_relations-relations_internationales/sanctions/consolidated-consolide.aspx?lang=eng |
| EU (never automated by Bunnyhole) | https://www.sanctionsmap.eu/ |
| FATF high-risk jurisdictions | https://www.fatf-gafi.org/en/countries/black-and-grey-lists.html |

Confirm corporate status and beneficial ownership on the primary registry (Ontario Business Registry, Corporations
Canada, Companies House, SEC EDGAR); use a second identifier (registration number, address, date of birth from a
document), never the name alone.

**Archive source pages yourself.** The report's SHA-256 covers the recorded extract, not the web page. Capture the page:

```bash
# needs network. Wayback Save Page Now: open this URL pattern in a browser (not run here)
#   https://web.archive.org/save/<FULL_URL_OF_THE_PAGE>
# alternatives: archive.today (https://archive.ph/), ArchiveBox (self-hosted), or your browser's "Save page as" for a local copy
```

**Hash your own files** (chain of custody on your side):

```bash
cd "$CASE" && shasum -a 256 reports/* evidence/* > notes/sha256_$(date -u +%Y%m%dT%H%M%SZ).txt    # macOS; on Kali use sha256sum
shasum -a 256 -c notes/sha256_<TIMESTAMP>.txt                                                      # re-check later
```

**Keep the graph.** The `--json` file is the full result (graph, receipts, the `pi` block, set-aside records). The
report shows only the relevant findings; the JSON keeps everything. **Export the dossier at run time** with `--out`:
there is no command to export one from a saved case afterward (the web War-Room has a download button for runs made
there, and it has no PI gates).

**Back up safely.** `~/.bunnyhole/api_keys.env` is `0600` plain text, and `cases.db` holds your case data
unencrypted. Back up only to encrypted storage, with no run in progress:

```bash
tar czf - ~/.bunnyhole "$CASE" | gpg --symmetric -o bunnyhole_backup_$(date -u +%Y%m%d).tgz.gpg    # generic GnuPG, not a Bunnyhole feature
```

To remove a key everywhere: `keys --set NAME=`, and delete it from the legacy `~/.osint-apis/api_keys.env` yourself (read
but never written). To reset the profile, delete `~/.bunnyhole/profile.json`. Delete case data when your retention
obligations end.

---

## 7. Handoff

**What to give a licensed investigator or counsel:**

1. `$CASE/reports/<RUN>_pi.md` for each run: start with *Bottom line*, then the handoff sheet in *Custodians and next steps*.
2. The `--json` files and the `sha256_*.txt` list, so they can confirm nothing changed.
3. The case sheet (purpose, category, matter ref, hypothesis, exclusions), your notes of what you verified by hand, and archive links.
4. A list of what was *not* searched (*Coverage and negatives*) and what you did manually (Ontario Business Registry, OnLand, CanLII).

**Custodians and legal instruments.** For each kind of finding (an exchange deposit address, a phone number, a
registered agent, an IP, a domain, an employer) the report names the holder and the instrument for your jurisdiction:
a subpoena or court order in the US; a Norwich Pharmacal order or production order via counsel in Ontario or the UK; an
MLAT or letter of request cross-border. For an entity subject the sheet points to primary sources (verify the sanctions
hit on the primary list; confirm status and ownership on the primary registry). Bunnyhole sends nothing anywhere.
A private-investigator licence confers no police powers: you cannot compel records.

**What Bunnyhole cannot do** (from `pi out-of-scope`; hand off to a licensed investigator or counsel):

| Cannot | Why |
|---|---|
| Credit-header and licensed people databases (TLOxp, Tracers, IRBsearch, idiCORE, Accurint, CLEAR, SkipSmasher, Delvepoint), credit bureaus, licence-plate-reader data | Licence, permissible purpose and audit required |
| Bank, exchange and phone-company records; phone pings and location data | Need a legal instrument (production order, subpoena); never obtainable by pretext |
| Eligibility screening (employment, tenancy, credit, insurance) | Consumer-report territory; use an FCRA-compliant screener (Checkr, Sterling) where it applies |
| Consumer people-search sites (Intelius, BeenVerified, Spokeo and similar) | Stale data and terms-of-service problems |
| Breach contents against individuals (DeHashed and similar); paid OSINT and enterprise ownership or crypto platforms (OSINT Industries, Orbis, Sayari, Dun & Bradstreet, Chainalysis, TRM, Elliptic) | Legally sensitive or outside the free layer |
| Field verification, interviews, surveillance | Needs a licensed investigator; never pretexting, trackers, recording, account access, sealed or medical records |

---

## 8. Cheat strip: the 12 commands of a typical day

Network except where noted. Replace placeholders first.

```bash
uv run bunnyhole keys                                                         # 1. offline: which keys are set (fix "EMPTY" ones that matter)
export CASE=~/cases/<MATTER_REF> && mkdir -p "$CASE"/{reports,evidence,notes,logs}   # 2. case folder; then fill notes/case_sheet.md
uv run bunnyhole pi playbook <CASE_TYPE>                                      # 3. offline: done-when, order of work, pitfalls
uv run bunnyhole pi legal --jurisdiction ca-on                                # 4. offline: legal frame (verify with counsel)
uv run bunnyhole intake --org "<SUBJECT>" --domain <DOMAIN> --gear deep --depth 3 --breadth 6 \
  --pi --case-type <CASE_TYPE> --subject-type <person|entity> --purpose "<PURPOSE>" --purpose-category <CATEGORY> \
  --client "<CLIENT>" --matter-ref "<REF>" --pi-jurisdiction ca-on \
  --pi-report "$CASE/reports/01_pi.md" --json "$CASE/reports/01.json" --out "$CASE/reports/01_dossier.md"   # 5. first pass
uv run bunnyhole cases                                                        # 6. offline: confirm it was saved, note the case ID
uv run bunnyhole cases --search "<NEW_SELECTOR>"                              # 7. offline: seen in an earlier matter?
uv run bunnyhole intake --org "<NEW_ENTITY>" --domain <NEW_DOMAIN> --exclude <NOISE> --gear deep --depth 4 --breadth 8 \
  --pi --case-type <CASE_TYPE> --subject-type <person|entity> --purpose "<PURPOSE>" --purpose-category <CATEGORY> \
  --matter-ref "<REF>" --pi-jurisdiction ca-on --pi-report "$CASE/reports/02_pi.md" --json "$CASE/reports/02.json"   # 8. pivot, widest
uv run bunnyhole link "<ENTITY_A>" "<ENTITY_B>" --gear deep                   # 9. how do two entities connect
uv run bunnyhole --tor darkweb "<SELECTOR>" --fetch-onion                     # 10. dark-web mentions (Tor listener running)
uv run bunnyhole doc-forensics "$CASE/evidence/<FILE>.pdf"                    # 11. offline: metadata of a document
cd "$CASE" && shasum -a 256 reports/* evidence/* > notes/sha256_$(date -u +%Y%m%dT%H%M%SZ).txt   # 12. offline: hash everything; then archive pages, verify sanctions hits, hand off
```

---

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| A source is `skipped` after HTTP 401 or 403 in the report or log | Missing or invalid key. CourtListener: `COURTLISTENER_API_TOKEN`. Sanctions/PEP: `OPENSANCTIONS_API_KEY` or `OPENSANCTIONS_API_URL`. UK ownership: `UK_COMPANIES_HOUSE_API_KEY`. 429 is a rate limit: wait, lower `--breadth`, or add the key (GitHub, Censys, ...). Check with `uv run bunnyhole keys`. |
| `court_dockets` or `beneficial_ownership` show `NOT SEARCHED` / "Tried, not reached" | The key is missing (above), or the source does not cover your jurisdiction (CourtListener is US federal, Companies House is UK only). For Ontario, search CanLII and the Ontario Business Registry by hand. |
| Exit code 2 with a red panel | A gate refused the engagement or a flag is invalid. Read the panel: missing `--purpose` / `--purpose-category`, person without `--matter-ref`, an eligibility or ex-partner wording, `--cred` with `--pi`, or a person-like entity name. Reword accurately or consult counsel; never evade. `Invalid value for '--depth'` means 1-4, `'--breadth'` means 2-8. |
| "too long to screen" | A single `--pi` text field over 150,000 characters. Trim it, or split it into separate runs. It never skips part of a field. |
| `No such option: --tor` / `--proxy` | They are global: `uv run bunnyhole --tor trace ...`, not `trace ... --tor`. `Invalid --proxy` means the scheme must be http, https, socks5, socks5h or socks4. |
| Slow or never-ending run | `deep` + depth 4 + breadth 8 is the heaviest setting; run times are unmeasured. Use depth 2 or 3, breadth 4, or `fast`. Free sources rate-limit, and local tools (subfinder, sherlock) add time. Ctrl-C and re-run narrower. |
| Tor not running, `.onion` titles empty, SOCKS errors | Start Tor (`brew services start tor` or `sudo systemctl enable --now tor`), check `lsof -iTCP:9050 -sTCP:LISTEN` (macOS) or `ss -ltn \| grep 9050` (Linux). `--fetch-onion` silently degrades to no title. `uv sync` re-installs SOCKS support (`httpx[socks]`). A different port: `export BUNNYHOLE_TOR_PROXY=...`. |
| Empty or thin results | Check that the name is spelled as registered (with the legal form), then add anchors: a domain, an email, a phone, a registration number. Raise depth or gear one step. Install `whois`, `subfinder`, `sherlock` for deep gear. Check *Coverage and negatives* for classes marked NOT SEARCHED. A name collision is also possible: add `--exclude`. A clean result on the searched sources is not proof of absence. |
| Where files live | Reports, JSON and dossiers: the paths you passed to `--pi-report`, `--json`, `--out` (create the folder first). Keys: `~/.bunnyhole/api_keys.env`. Cases: `~/.bunnyhole/cases.db`. Profile: `~/.bunnyhole/profile.json`. Sanctions cache: `~/.bunnyhole/cache/sanctions/` (24 h). All move with `export BUNNYHOLE_HOME=<DIR>`. Bunnyhole writes no log files. |
| `permission denied` on the key vault | The vault is `0600` and owned by whoever created it. Do not mix `sudo` and normal runs. Fix: `sudo chown -R "$USER" ~/.bunnyhole`. |
| A tool shows `MISSING` after installing | It must be on `PATH` or in `~/.local/bin`, `~/go/bin`, `~/bin`, `/usr/local/bin` or `/opt/homebrew/bin`. |

---

## How this was checked (and what is unverified)

**Run offline with `HOME` and `BUNNYHOLE_HOME` set to a temp folder:** `--version`; `--help` for the root command and every
command and subcommand (trace, intake, link, jet, council, darkweb, doc-forensics, anonsurf, arsenal, doctor, keys, personas,
profile, cases, ui, tui, menu, serve, mcp, pi and its five subcommands); `doctor`; `keys` and `keys --set` / clear with a fake
token; `personas`; `profile` with every edit flag; `pi guide`; `pi legal --jurisdiction ca-on`; `pi sources` (with and without
`--implemented`, `--jurisdiction ca-on`); `doc-forensics` on a generated PDF and DOCX and on a missing file; the N-number to
ICAO conversion of `jet`.

**Gate-checked without starting an investigation.** Each PI example was run through the real CLI (`bunnyhole.cli.main.app`)
with the orchestrator replaced by a stub that raises before any agent is built, so flags are parsed and the purpose gates
(`resolve_pi_flags`) are executed, but no network is touched. All examples in sections 4 and 5 and the cheat strip passed
(exit path "would start the investigation") with realistic substitute values: A (entity due diligence, and the KYC variant),
B (Ontario and US asset search), C (person locate, with matter ref; judgment-enforcement variant), D, E (entity and person
variants), F (PI person with `fraud_investigation` and `asset_recovery`, and non-PI), G (non-PI and PI), the three-run pivot flow,
`link`, `council`, and `intake --dump`. Negative cases behaved as documented (exit 2): person locate without `--matter-ref`,
an eligibility purpose, a missing `--purpose-category`, a person with `regulatory_compliance_kyc`, a PI flag without `--pi`,
`--cred` with `--pi`, a person-like entity name (cleared by `--confirm-entity`), `--depth 5`, `--breadth 1` and `9`, and `--tor`
after the command. Your real values can trip a phrase screen that mine did not.

**Unverified (needs network or a live run):** every live result and run time; the Wayback Save Page Now URL pattern; Tor
behaviour and the exact proxy coverage; that `link` runs are saved to `cases.db`; Ahmia, adsb.lol and all API responses; the
Ontario/Canadian legal items (marked unverified in the app's own catalog); OpenSanctions licence terms for paid work; the Kali/Parrot
package names; the `tee` transcript pattern.

**Inconsistencies noticed in the checkout.**
1. `trace SEED` with any extra selector reroutes into `intake` with the seed as a free-text dump (a seed over four words becomes a
   hypothesis, not a company); `trace --help` does not say so.
2. `--help` text for `trace` and `intake` still says "(can pass multiple)" only on `intake`; `trace` also accepts repeated
   `-u`, `-e`, `-p`, `-w`, `--domain`, `--doc` and `-x` (they are lists in the code).
