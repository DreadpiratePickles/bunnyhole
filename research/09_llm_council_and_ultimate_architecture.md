# 09. Karpathy `llm-council` Integration & The Ultimate Investigative Architecture

## 1. Why Single-Pass Investigative Synthesis Fails (And How `karpathy/llm-council` Solves It)

Our Principal Systems Reviewer stress-tested Bunnyhole across 6 critical dimensions and identified the #1 threat to any autonomous OSINT/investigative engine: **Apophenia & False-Positive Graph Explosion** (treating weak keyword or shared-infrastructure coincidences as hard attribution).

In `https://github.com/karpathy/llm-council`, Andrej Karpathy demonstrated a deceptively powerful 3-stage multi-agent deliberation protocol that eliminates single-model blind spots and sycophancy:

1. **Stage 1 — Parallel Independent First Opinions (`stage1_collect_responses`)**:
   Multiple council members independently examine the exact same problem without seeing each other's biases.
2. **Stage 2 — Anonymized Peer Critique & Forced Ranking (`stage2_collect_rankings`)**:
   Each council member's response is stripped of its identity and labeled `Response A`, `Response B`, `Response C`, etc. Every council member must critique all responses for factual accuracy, logical leaps, and blind spots, concluding with a strict machine-parsable `FINAL RANKING:` block. Aggregate rankings (`calculate_aggregate_rankings`) reveal which thesis survived adversarial peer review.
3. **Stage 3 — Chairman's Synthesis (`stage3_synthesize_final`)**:
   The Chairman model receives the original evidence, all Stage 1 specialist briefs, and all Stage 2 anonymized peer evaluations and rankings to compile the final authoritative verdict.

---

## 2. Adapting `llm-council` into Bunnyhole's **Adversarial Investigative Council**

Instead of generic chat personas, Bunnyhole instantiates a **5-Seat Investigative Council** where each seat represents a distinct intelligence discipline (backed by multi-model OpenRouter/LLM APIs when configured, and a deterministic evidentiary scoring engine when running zero-key):

| Seat | Council Persona | Primary Evidentiary Focus | What It Hunts |
| :--- | :--- | :--- | :--- |
| **Seat 1** | **Bellingcat Archival & Legal Lead** | `JOURNALISM` (`waybackpy`, `CourtListener`, `MediaWiki`, `RSID`) | Scrubbed `/team` pages, federal litigation dockets, anonymous Wikipedia IP edits, narrative laundering. |
| **Seat 2** | **Hindenburg Forensic Short-Seller** | `FIAT` & `PHYSICAL` (`SEC EDGAR`, `XBRL Beneish M-Score`, `GLEIF`, `adsb.lol`) | `M-Score > -1.78` earnings manipulation, Form 8-K auditor resignations (`Item 4.01`), offshore shells, corporate jets. |
| **Seat 3** | **NSA SIGINT & Infrastructure Analyst** | `OSINT` (`Shodan`, `RIPEstat`, `crt.sh`, `HudsonRock`, `GitHub`, `Sherlock`/`Holehe`) | Origin servers behind CDNs, infostealer logs, `.patch` commit author emails, cross-platform handle reuse. |
| **Seat 4** | **ZachXBT On-Chain & DeFi Sleuth** | `ONCHAIN` (`Blockscout`, `ENSData`, `GoPlus`, `Mempool.space`, `THORChain`) | Ascending (`sort=asc`) First-Funder Mother Wallets, THORChain cross-chain swap memos, Bitcoin CIOH & peel chains. |
| **Seat 5** | **Red-Cell Defense Counsel & Skeptic** | `SKEPTIC` (`ACH Matrix`, `Selector Quarantine`, `False-Positive Guardrails`) | **Attacks the other 4 seats.** Flags Registered Agent hubs, shared Cloudflare IPs, and uncorroborated `HYPOTHESIS` ticker/keyword leaps. |

---

## 3. Reviewer Triage Plan Hardening (Implemented Across the Engine)

Following the Principal Reviewer's 6-Dimension Critique, the following hard architectural fixes are enforced before the Council convenes:

1. **Strict Evidence Quarantine (`VERIFIED` vs. `CIRCUMSTANTIAL` vs. `HYPOTHESIS`)**:
   - Uncorroborated keyword searches (`DexScreener` token ticker matches without an exact contract address, `OpenAlex` / `HackerNews` keyword hits without author handle match) are automatically downgraded to `SelectorStrength.SOFT` (`admiralty_code="C3"`, `ConfidenceTier.HYPOTHESIS` / `CIRCUMSTANTIAL`).
   - Only `SelectorStrength.STRONG` (`A1`/`B1` cryptographic, corporate registry, or judicial records) can anchor primary attribution in Stage 3.
2. **True Genesis First-Funder Lineage (`sort=asc`)**:
   - `OnChainAgent.investigate_evm_address` queries chronological ascending transactions (`?module=account&action=txlist&address=...&page=1&offset=5&sort=asc`) so active wallets (>20 txs) trace their true Tx #0 Mother Wallet instead of the 20th most recent transaction.
3. **Live SEC XBRL Beneish M-Score Forensics**:
   - `AccountantAgent.investigate_sec_edgar` fetches `https://data.sec.gov/api/xbrl/companyfacts/CIK{cik.zfill(10)}.json` and computes the 8-variable Beneish M-Score directly from 10-K US-GAAP concepts.
4. **High-Entropy Stem Filtering (`extract_entity_stem`)**:
   - Expanded `CORPORATE_STOPWORDS` blocks generic English words (`first`, `apex`, `alpha`, `global`, `block`, `finance`, `capital`, `united`, etc.) from spawning false-positive cross-domain pivots.
5. **Sortable ISO-8601 UTC Master Chronology**:
   - `InvestigationGraph.normalize_iso_timestamp` normalizes RFC-2822 RSS dates, Unix epochs, and bare years into strict ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) before sorting.
