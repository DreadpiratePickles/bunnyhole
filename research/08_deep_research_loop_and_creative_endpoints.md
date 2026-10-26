# Module 8: `dzhng/deep-research` Recursive Engine & Round-2 Creative Tradecraft Arsenal

> **Purpose:** This module integrates the recursive **`breadth` $\times$ `depth` + accumulated `learnings` & `followUpQuestions` architecture** from [`dzhng/deep-research`](https://github.com/dzhng/deep-research) directly into Bunnyhole's orchestrator, and adds **12 high-leverage, zero-key "secret weapon" endpoints and creative investigative techniques** discovered in our second tradecraft sweep.

---

## 1. Fusing `dzhng/deep-research` into Bunnyhole's Orchestrator

The magic of [`dzhng/deep-research`](https://github.com/dzhng/deep-research) (by David Zhang) is that it replaces brittle, single-pass pipelines with a **Self-Refining Recursive Research Tree** controlled by two parameters—`breadth` and `depth`—and two evolving state accumulators—`learnings[]` and `visitedUrls[]`:

```mermaid
flowchart TD
    Seed["🎯 Initial Seed / Investigative Prompt"] --> Clarify["🔍 Phase 0: Pre-Flight Hypothesis & Angle Generator\n(Decomposes target into initial Breadth=B investigative angles across Journalism, Fiat, OSINT, On-Chain)"]
    
    Clarify --> Loop["🔄 Recursive Deep-Research Loop (depth = D..1, breadth = B)"]
    
    Loop --> Parallel["⚡ Concurrent Execution (asyncio.Semaphore)\nRun B parallel specialist queries + Link Sleuth lateral bypasses"]
    Parallel --> Extract["🧠 Extract Structured Learnings & Graph Receipts\n• New Entities & Edges (+ NATO Admiralty A1-F6 Receipts)\n• Distilled 'Learnings' (Key Facts & Anomalies)\n• 'Follow-Up Hypotheses' (What new questions did this evidence raise?)"]
    
    Extract --> Halve{"depth - 1 > 0 ?"}
    Halve -->|Yes: Narrow & Drill Deeper\nnew_breadth = ceil(breadth / 2)\ndepth = depth - 1| Loop
    Halve -->|No: Depth Reached| LinkSleuth["🔗 Final Link Sleuth & Red-Cell Skeptic Pass\n• Break remaining Dead Ends\n• Adamic-Adar Missing Link Prediction\n• CIA ACH Competing Hypotheses Matrix"]
    LinkSleuth --> Dossier["📑 Synthesize Publication-Grade Markdown Dossier + Interactive Graph"]
```

### How Bunnyhole Upgrades the `dzhng/deep-research` Loop for Intelligence Work
1. **Cumulative `learnings[]` Grounding:**
   * In `dzhng/deep-research`, every recursive step receives all previously extracted `learnings[]` so it never repeats a redundant search and instead formulates **compound follow-up queries** (e.g., if Depth 1 learns *"Domain X's historical DNS points to IP 185.x.x.x"* and *"SEC Form D for X lists John Doe in Miami"*, Depth 2 automatically generates targeted follow-up angles combining *"John Doe Miami LLC"* and *"185.x.x.x Shodan InternetDB + Passive DNS"*).
2. **Dynamic Breadth Tapering (`new_breadth = max(2, math.ceil(breadth / 2))`):**
   * At **Depth 1 (Broad Sweep):** Bunnyhole fans out wide (`breadth = 6`), sweeping all 4 core domains + physical/breach intel in parallel.
   * At **Depth 2 (Targeted Pivot):** Breadth tapers (`breadth = 3`), focusing exclusively on the highest-smoke anomalies, ABI path convergences, and follow-up questions discovered in Depth 1.
   * At **Depth 3+ (Surgical Rabbit-Hole):** Drills straight to the bottom of the highest-priority lead chain (e.g., walking a Mother Wallet 3 hops back or piercing an Ultimate Parent LEI chain).

---

## 2. Round-2 Creative Tradecraft: 12 "Secret Weapon" Zero-Key Endpoints

We identified **12 additional zero-key, high-signal endpoints and investigative methods** that bridge gaps other OSINT tools miss completely:

### 🕵️ Creative Infra, Passive DNS & Cryptographic Identity Pivots
| # | Tool / Endpoint | Access | What It Exposes & How Bunnyhole Uses It |
| :-: | :--- | :--- | :--- |
| **1** | **Shodan InternetDB**<br>`https://internetdb.shodan.io/{ip}` | **100% Free & Keyless** | Returns open `ports`, software `cpes`, reverse `hostnames`, `tags`, and known `vulns` (`CVEs`) for any IPv4 address instantaneously without a Shodan API key. |
| **2** | **Mnemonic Passive DNS (pDNS)**<br>`https://api.mnemonic.no/pdns/v3/{domain_or_ip}` | **100% Free & Keyless** (TLP:WHITE) | **Defeats Cloudflare Hiding:** Shows historical `A`/`AAAA`/`CNAME` resolutions from years ago *before* a target put their domain behind Cloudflare, plus every other domain that ever pointed to that origin IP! |
| **3** | **RIPEstat BGP & Routing History**<br>`https://stat.ripe.net/data/network-info/data.json?resource={ip}` | **100% Free & Keyless** | Reveals the exact BGP prefix, Autonomous System Number (ASN), network holder organization, and abuse contact for any IP or ASN globally. |
| **4** | **PeeringDB Physical Data Center API**<br>`https://www.peeringdb.com/api/net?asn={asn}` | **100% Free & Keyless** | Maps a virtual ASN to **physical data center buildings**, Internet Exchange Points (IXPs), and technical NOC contact emails. |
| **5** | **Keybase Cryptographic Proof Graph**<br>`https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}`<br>*(Also supports `?twitter=`, `?github=`, `?reddit=`, `?domain=`)* | **100% Free & Keyless** | **Cryptographic Identity Goldmine:** Tech founders, crypto devs, and security researchers who used Keybase published **cryptographically signed proofs** linking their GitHub, Twitter/X, Reddit, HackerNews, personal domains, **PGP Public Key bundles** (which contain raw email UIDs!), and BTC/Zcash addresses. One query unmasks the entire cross-platform identity graph with `Admiralty=A1` certainty! |

### 🗞️ Creative Narrative, Reputation Whitewashing, Lobbying & Academic Forensics
| # | Tool / Endpoint | Access | What It Exposes & How Bunnyhole Uses It |
| :-: | :--- | :--- | :--- |
| **6** | **Wikipedia Revision & "PR Whitewash / IP Leak" Forensics**<br>`https://en.wikipedia.org/w/api.php?action=query&prop=revisions...` | **100% Free & Keyless** | Inspects the edit history of a person's or company's Wikipedia page:<br>• **Catches Corporate Whitewashing:** Spots editors who deleted *"Controversies"*, *"SEC Investigation"*, or *"Founders"* sections.<br>• **Unmasks Anonymous IP Editors:** When an unlogged user edits Wikipedia, MediaWiki logs their **raw IP address** as the username! Bunnyhole pipes that IP straight into **RIPEstat + Shodan InternetDB** to see if the edit came from the target company's own office IP or a paid PR firm! |
| **7** | **U.S. Senate Lobbying Disclosure Act (LDA) API**<br>`https://lda.senate.gov/api/v1/filings/?client_name={name}` | **100% Free & Keyless** | Reveals every registered federal lobbying firm hired by a target corporation, the exact dollar amounts paid per quarter, the specific lobbyists (including former Congressional/SEC staffers), and the exact issues/agencies targeted. |
| **8** | **OpenAlex Scholarly & Grant Graph**<br>`https://api.openalex.org/authors?search={name}` & `/works?search={q}` | **100% Free & Keyless** | Searches 250M+ academic papers, patents, and research grants:<br>• Verifies whether a deep-tech/AI/biotech founder actually published the research they claim.<br>• Maps **Co-Author Networks**, university lab affiliations, `ORCID` identifiers, and federal/defense grant funders. |
| **9** | **HackerNews Algolia Historical Archive**<br>`https://hn.algolia.com/api/v1/search?query={query}` | **100% Free & Keyless** | Finds a startup's earliest *"Show HN"* launch posts (often posted under a founder's personal handle before rebranding), customer complaints, and former-employee whistleblowing comments. |

### ⛓️ Creative On-Chain Security, Bytecode & Web3 Identity Oracles
| # | Tool / Endpoint | Access | What It Exposes & How Bunnyhole Uses It |
| :-: | :--- | :--- | :--- |
| **10** | **GoPlus Web3 Security Oracle**<br>`https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses={addr}`<br>`/api/v1/address_security/{addr}` | **100% Free & Keyless** | Instant automated smart-contract & wallet forensics:<br>• **Token Audit:** Flags honeypots (`is_honeypot`), hidden mint functions (`is_mintable`), proxy contracts (`is_proxy`), transfer pausing, hidden owner privileges, creator address & balance %, and top LP holders.<br>• **Malicious Wallet Check:** Flags involvement in cybercrime, phishing, money laundering, mixers, or sanctions (`cybercrime`, `money_laundering`, `financial_crime`, `stealing_attack`). |
| **11** | **Sourcify 4Byte Selector Decoder & Verified Source Check**<br>`https://api.4byte.sourcify.dev/signature-database/v1/lookup?function={selector}` | **100% Free & Keyless** | Decodes raw 4-byte hexadecimal transaction method selectors (e.g., `0x3593564c` $\rightarrow$ `execute(bytes,bytes[],uint256)`) on unverified contracts so Bunnyhole knows what an exploiter or insider contract call actually did. |
| **12** | **ENSData Unified Web3 Identity Resolver**<br>`https://api.ensdata.net/{address_or_ens}` | **100% Free & Keyless** | Resolves `.eth` names and `0x` addresses in one shot—extracting primary ENS name, avatar image URL, and embedded on-chain text records (`twitter`, `github`, `email`, `url`, `description`, `discord`, `telegram`). |

---

## 3. Creative Cross-Domain "Combo Chains" Enabled by Round 2

Look at what happens when Bunnyhole chains these new tools together automatically:

1. **The "Wikipedia Whitewash $\rightarrow$ Corporate IP $\rightarrow$ Shodan" Combo:**
   * Bunnyhole pulls the Wikipedia revision history for `Target Corp` $\rightarrow$ spots an anonymous IP editor `198.51.100.42` deleting a paragraph about a lawsuit $\rightarrow$ pipes `198.51.100.42` into **RIPEstat** & **Shodan InternetDB** $\rightarrow$ discovers the IP belongs to a boutique crisis-PR firm in Washington D.C. $\rightarrow$ queries the **U.S. Senate LDA Lobbying API** and confirms `Target Corp` paid that exact firm \$180,000 in Q3!
2. **The "Cloudflare Bypass via Mnemonic Passive DNS $\rightarrow$ Shodan InternetDB" Combo:**
   * A scam domain `alpha-yield.io` sits behind Cloudflare (`104.21.x.x`) $\rightarrow$ Bunnyhole queries **Mnemonic Passive DNS** (`api.mnemonic.no/pdns/v3/alpha-yield.io`) $\rightarrow$ finds that for 3 days in 2024 before enabling Cloudflare, it pointed to `45.xx.xx.xx` $\rightarrow$ queries **Mnemonic pDNS** in reverse on `45.xx.xx.xx` and **Shodan InternetDB** $\rightarrow$ uncovers 4 other domains hosted on that same VPS and open SSH/Grafana ports!
3. **The "ENSData $\rightarrow$ Keybase Cryptographic Bundle $\rightarrow$ PGP Email $\rightarrow$ Holehe/HudsonRock" Combo:**
   * An on-chain wallet `0xabc...` resolves via **ENSData** to `cipherwolf.eth` with GitHub handle `cipherwolf` $\rightarrow$ Bunnyhole queries **Keybase Lookup API** (`?github=cipherwolf`) $\rightarrow$ Keybase returns a cryptographically signed proof linking Reddit, Twitter, a personal domain, and a **PGP public key** containing `Real Name <real.name@gmail.com>` $\rightarrow$ Bunnyhole pivots `Real Name` into **SEC Form D / FEC Donations / OpenAlex**!
