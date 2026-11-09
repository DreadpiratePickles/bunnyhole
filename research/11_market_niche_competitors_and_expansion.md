# 🐇🕳️ Vol. 11 — Market & Niche: Competitors, Buyers, and Where Bunnyhole Aims Next

> **Scope note.** Pricing in this space is overwhelmingly quote-on-request; figures below are
> third-party/aggregator estimates — directional, not list prices. Agent-performance and
> Admiralty-automation claims cited are largely unvalidated preprints — treat as directional.

Bunnyhole sits at an unusual intersection: the **recursive auto-pivoting of an OSINT scanner**, the
**provenance graph of an investigative-journalism platform**, and the **analytic-tradecraft layer of an
intelligence shop** — keyless, OSS, CLI/TUI-first. No single incumbent occupies that exact spot.

---

## 1. Landscape / direct competitors

**A. OSINT automation frameworks (closest technical cousins).**
- **SpiderFoot (OSS) / SpiderFoot HX (commercial):** nearest conceptual analog — one seed, 200+
  modules, auto-correlation; HX adds cloud orchestration, continuous monitoring/alerts, collaboration.
  *Not* FtM-graph-native; no Admiralty grading, no adversarial agent, no IC tradecraft.
- **BBOT:** best OSS exemplar of *recursive* OSINT (a finding auto-triggers the next module) — but
  scoped to attack-surface/infra only, not people/money/crypto.
- **Maltego:** the king of *visual link analysis*; GUI-first, transform-marketplace, analyst-driven
  (not autonomous); legacy Pro tiers withdrawn May 2024, ~€5k/user/yr per third-party listings.
- **Recon-ng / theHarvester:** the "unix tool" layer Bunnyhole *orchestrates*, not competes with.
- **Intelligence X / OSINT Industries / Lampyre / Shodan / Censys:** mostly data-source subscriptions
  Bunnyhole consumes, not orchestrators.

**B. Investigative-journalism / financial-crime graph platforms.**
- **OCCRP Aleph:** the FtM reference implementation and Bunnyhole's lineage. **Critical 2025 shift:**
  OCCRP is sunsetting open-source Aleph; successor **Aleph Pro (Dec 2025 rewrite) will NOT be open
  source** — leaving a vacancy in OSS FtM-native tooling Bunnyhole can occupy.
- **ICIJ Datashare (OSS):** document-set NER for leaks — complements, doesn't overlap.
- **OpenSanctions + nomenklatura, OpenCorporates:** FtM-native sanctions/PEP + registry data and a real
  entity-resolution matcher. **Data/matching layers Bunnyhole should ingest**, not compete with.
- **Sayari / Kharon / Linkurious / Moody's / LexisNexis:** enterprise DD/KYC/supply-chain,
  quote-on-request, five-to-six figures.

**C. Crypto on-chain forensics.** **Chainalysis / TRM / Elliptic** (enterprise AML/LE) vs. **Arkham /
Nansen / Breadcrumbs / MetaSleuth** (prosumer/retail). Bunnyhole folds on-chain into the *same* graph
as domains/handles/people — incumbents silo crypto.

**D. Link-analysis / i2 / Palantir.** **IBM i2 Analyst's Notebook** (~$7,160/yr est.) and **Palantir
Gotham/Foundry** (bespoke, gov/enterprise) — manual, analyst-driven. Bunnyhole automates the collection
and first-pass fusion they leave to the analyst, at zero license cost.

---

## 2. Users / buyers

| Segment | Core need | Pays for today | Bunnyhole fit |
|---|---|---|---|
| **Investigative journalists / newsroom data teams** | cheap, defensible, cross-border, audit trail | Aleph (free, closing), Datashare, Hunchly, Maltego Basic | **Strongest** — FtM-compat, receipts, keyless; fills closing-Aleph gap |
| **DD / KYC / AML compliance** | sanctions/PEP + UBO, auditable | Sayari, Moody's, LexisNexis, OpenSanctions | Partial — needs sanctions/PEP + registry integration to be credible |
| **Fraud / financial-crime investigators** | rapid entity+money tracing, cut-out detection | i2, Chainalysis | Good — betweenness "broker" + on-chain differentiated |
| **Threat-intel / CTI** | infra pivoting, breach, attribution | SpiderFoot HX, Shodan/Censys, Recorded Future | Strong — already orchestrates the CLIs |
| **Corporate investigations / asset-recovery lawyers** | hidden ownership, admissible provenance | Kroll-type firms, Sayari, i2 | Good — ACH + receipts map to litigation standards |
| **Red-teamers / pentesters** | attack-surface + people recon | BBOT, amass, Shodan | Native |

**Buying reality:** journalist/CTI/red-team segments have near-zero budget + high tool-fluency (ideal
for OSS adoption → community → reputation); compliance/DD/asset-recovery have real budget but demand
auditability, data coverage, and vendor accountability (the monetizable segment, gated on sanctions/
registry coverage + support).

---

## 3. What's genuinely differentiated (table-stakes vs. novel in OSS)

| Feature | Verdict |
|---|---|
| Recursive auto-pivot (breadth×depth) | **Table-stakes** (novel only in *multi-domain* breadth) |
| FtM-compatible provenance graph | **Valuable, semi-novel** — rare to *auto-emit* FtM from live recon; Aleph's closure widens the gap |
| **SHA-256 evidence receipts per node/edge** | **Genuinely novel in OSS** — chain-of-custody at the data-model level; even Maltego/i2 don't |
| **NATO Admiralty A1–F6 auto-grading** | **Novel but execution-risky** — raters conflate reliability vs. credibility; auto-scoring can launder an unconfirmed claim into "confirmed" |
| **Adversarial Red-Cell Skeptic agent** | **Most novel / most defensible** — directly answers the field's #1 critique (agents over-confirm under benign testing) |
| CIA ACH matrix | **Novel in OSS** |
| ODNI PAI-vs-CAI tagging | **Novel, niche** (matters to IC/gov/compliance) |
| Keyless + Tor-routable | **Differentiated for OSS/activist**; less relevant to enterprise |
| Betweenness cut-out detection | **Semi-novel** |
| Multi-model LLM council | **On-trend, commoditizing** |

**Durable moat:** the **tradecraft+provenance layer (receipts + Admiralty + Skeptic + ACH)** fused into
one OSS FtM graph. The Skeptic agent + evidence receipts are the two things no OSS competitor credibly has.

---

## 4. Trends (2024–2026)

- **Agentic investigation is the defining trend** — moving from concept to tooling, but **no community
  benchmark** exists and systems are tested mostly under benign conditions (documented over-confirmation).
  Bunnyhole's Skeptic + receipts are well-timed answers to the trust gap.
- **"Tool-grounded agents beat chatbots"** — the model reads *real tool output* rather than generating
  findings — exactly Bunnyhole's CLI-orchestration design.
- **MCP as the copilot interface** — MCP-native OSINT servers are appearing (e.g., OpenOSINT exposes
  tools to Claude; a DFIR paper argues MCP makes LLM forensics more auditable). A clear integration vector.
- **Entity resolution is the competitive battleground** — Linkurious+Senzing (2025), OpenSanctions
  LLM-matching benchmark, FtM 4.0 (Aug 2025).
- **Beneficial-ownership access whipsaw** — CJEU killed public EU UBO (2022); AMLD6/2024 restored via
  **"legitimate interest"** (journalists/CSOs presumed to qualify), phasing in 2025–2027.
- **Sanctions-screening / crypto-tracing demand rising fast** — crypto-compliance market ~$2–3.4B
  (2025), ~22% CAGR; Travel Rule the fastest-growing sub-segment.
- **Scrapeable surface tightening** — hiQ settled with LinkedIn despite its CFAA win; Clearview GDPR
  fines; California Delete Act **DROP** (one-click deletion, brokers poll every 45 days from Aug 2026)
  will shrink people-search data. **Assume less, and less-current, broker data going forward.**

---

## 5. Expansion opportunities (ranked by demand ÷ effort)

| Rank | Opportunity | Demand | Effort | Rationale |
|---|---|---|---|---|
| 1 | **Sanctions/PEP + OpenSanctions integration** | High | Low | OSS, FtM-native, free; instantly unlocks the compliance/DD buyer |
| 2 | **MCP server interface** (expose Bunnyhole to Claude/LLM copilots) | High | Low | On-trend, small build; becomes infra for the "investigation copilot" wave |
| 3 | **Corporate-registry graph + UBO-chain reconstruction** | High | Med | Rides the AMLD6 legitimate-interest reopening; Sayari/Aleph's core value |
| 4 | **Report/dossier export standards** (FtM export, court-ready PDF with receipts, ICD-203 confidence language) | High | Med | Monetizable; legal/compliance buyers need defensible output |
| 5 | **Cross-source entity resolution** (leaks + registries + chain via nomenklatura) | High | High | The industry's competitive frontier; nomenklatura is OSS + FtM-only |
| 6 | **Hosted collaborative mode** (multi-user, shared cases, change alerts) | Med-High | High | The obvious OSS→commercial path (SpiderFoot HX / Aleph Pro model) |
| 7 | **Maritime / aviation / trade-flow data** | Med | Med | Builds on the existing tail-number seed; sanctions-evasion & asset-recovery demand |
| 8 | **Benchmark & eval harness** | Med | Med | The field explicitly lacks one; reputation-defining, reinforces "defensible findings" |

---

## 6. Risks / constraints

- **Scraping ToS & CFAA** — public-data scraping isn't a CFAA crime (hiQ), but contract/ToS liability +
  fake-account bans remain live (the $500k settlement). Keep a conservative default posture + per-source toggles.
- **GDPR / personal data** — a public profile is still personal data; Clearview's repeat fines are the
  cautionary tale. Document lawful-basis guidance + data-minimization defaults.
- **Shrinking data-broker supply** — CA Delete Act/DROP + state registries will degrade people-search; don't over-index on broker data.
- **"Leads, not verdicts" — the attribution problem** — auto-Admiralty scoring risks laundering an
  unconfirmed claim into apparent "confirmation." Keep probability/confidence as *separate* fields,
  mandatory human-validation gating, and loud UX/docs — or the defensibility claim backfires. The
  Skeptic agent is the right mitigation; make it headline.
- **Dual-use / abuse** — keyless + Tor + autonomous recursion is a stalking vector; buyers/hosts expect
  abuse-mitigation posture, rate limits, and an acceptable-use stance (Bunnyhole has `ACCEPTABLE_USE.md`).
- **Buyer compliance expectations** — audit trails (have), vendor accountability/support, data-lineage,
  often on-prem/air-gap (the OSS/self-host model is an asset *if* paired with support/SLA).

---

## 7. Where Bunnyhole should aim next (ranked)

1. **Own the vacancy left by open-source Aleph's closure** — position as the OSS, FtM-native
   investigation graph for journalists now that OCCRP is going closed-source.
2. **Ship OpenSanctions sanctions/PEP screening first** — lowest-effort unlock of the budgeted
   compliance/DD segment; free, OSS, FtM-compatible.
3. **Expose an MCP server interface** — become the tool-grounded backend for the "investigation
   copilot" wave. *(SHIPPED — `bunnyhole mcp` runs a per-instance stdio MCP server; see
   `docs/MCP_SERVER.md`.)*
4. **Lead on the trust gap** — make the Red-Cell Skeptic + evidence receipts + separated
   probability/confidence the headline brand.
5. **Build UBO/corporate-registry chain reconstruction** tied to the AMLD6 legitimate-interest reopening.
6. **Court-/newsroom-ready dossier export** (FtM + receipts + ICD-203 confidence language) as the
   monetizable premium capability.
7. **Add cross-source entity resolution (nomenklatura)** across leaks + registries + chain.
8. **Expand seeds into maritime/aviation/trade-flow** — ride sanctions-evasion & asset-recovery demand.
9. **Publish an open OSINT-agent benchmark/eval harness** — the field lacks one.
10. **Define an OSS-core + hosted/supported-commercial path** — lead with the auditability/on-prem story
    enterprise buyers can't get from closed SaaS.
