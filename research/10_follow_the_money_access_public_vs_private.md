# 🐇🕳️ Vol. 10 — Following the Money: How It's Actually Done, and What's Public vs. Private

> **Scope & honesty note.** This volume maps how regulated institutions, FIUs, and lawyers trace
> money, and — crucially for Bunnyhole — **where the open-source line is**. Anything requiring legal
> authority or a regulated-institution seat is flagged **→ NOT OSINT-accessible**. Figures drawn from
> vendor/secondary sources are flagged as unverified; confirm against FATF, FinCEN, the EU Official
> Journal, SEC, and GLEIF primaries before using in shipped product copy.

Bunnyhole's honest ceiling: **reconstruct the public graph, score it, and produce a provenance-backed
referral package** that a lawyer or FIU can convert into compelled disclosure. It does not — and
cannot lawfully — reach the private layer. Designing to that line is a feature, not a limitation.

---

## 1. How bankers / compliance / FIUs follow money

A pipeline: **identify → monitor → report → share → investigate.** Almost none of its data is
OSINT-reachable; Bunnyhole must *understand* it to produce outputs useful to people who are inside it.

- **KYC / CDD / EDD** (FATF R.10, R.12). Identity at onboarding (CIP), risk-rated due diligence,
  enhanced diligence for PEPs/high-risk (source-of-funds / source-of-wealth). The account↔identity
  binding is private → **NOT OSINT-accessible**.
- **Transaction monitoring.** Rules + behavioral models flag structuring, rapid movement,
  round-tripping, peer-group outliers; alerts can trigger EDD. Runs on private ledger data → **NOT OSINT-accessible**.
- **SARs / STRs.** Filed to the national FIU on suspicion; no "tipping off." SAR *content* is
  FIU/LE-restricted → **NOT OSINT-accessible**. (Correction to a common myth: US BSA data isn't
  "LE-only" narrowly — FinCEN reports ~432 agencies with access running 2.3M+ searches in FY24, each
  gated by an MoU — but a developer/journalist is never on that list.)
- **§314(a) / §314(b) info-sharing** (US). Government→industry suspect-list searches, and voluntary
  institution↔institution sharing under a registered safe harbor. Neither discloses a SAR → **NOT OSINT-accessible**.
- **SWIFT / MT103 tracing.** The MT103 (single customer credit transfer) is the core artifact:
  `:50` ordering customer, `:59` beneficiary, and the bank chain `:52/:53/:54/:56/:57`. The bank-to-bank
  cover leg is **MT202 COV** (must repeat the real originator/beneficiary for screening). **ISO 20022
  migration:** MT103 → **pacs.008** (verify SWIFT's cutover schedule). SWIFT traffic is private →
  **NOT OSINT-accessible**; obtained via the bank, subpoena, or MLAT.
- **Correspondent banking chains.** Cross-border value moves through nested correspondent/respondent
  relationships — where the trail fragments across institutions and jurisdictions (the layering problem).
- **Beneficial-ownership tracing** (FATF R.24/R.25). Registry data + attestations + commercial DBs.
  The **public** side is Bunnyhole's turf (§3).
- **Travel Rule** (FATF R.16; baseline ~USD/EUR 1,000; US BSA $3,000 wire). Originator transmits
  originator+beneficiary data with the payment. **R.16 revised June 2025 — verify.**
- **Crypto Travel Rule (VASPs).** Extended to virtual assets (2019 INR.15 → R.16). Chronic issues:
  the **"sunrise issue"** (uneven rollout) and threshold divergence. VASP-held identity is private →
  **NOT OSINT-accessible** — but the **on-chain leg is public** (§3).
- **FIUs / Egmont.** National FIUs receive/analyze/disseminate SARs; cross-border via the **Egmont
  Group** (~170 FIUs) and EU **FIU.NET**. → **NOT OSINT-accessible**.

---

## 2. How lawyers follow money (litigation / asset recovery / forfeiture)

Lawyers cross the public/private line not by access but by **compelling disclosure through a court.**

- **US discovery & subpoenas** — civil discovery, third-party subpoenas, post-judgment discovery in
  aid of execution.
- **28 U.S.C. §1782** — a US federal court orders discovery held in its district *for use in a foreign
  proceeding*. Heavily used to pull US bank records to trace/freeze assets abroad; governed by *Intel v.
  AMD* factors; *ZF Automotive* (2022) largely closed it for private commercial arbitration (verify).
- **Norwich Pharmacal orders** (UK/common law) — compel a third party "mixed up in" wrongdoing to
  disclose info, classically to **identify an unknown wrongdoer**; can precede substantive proceedings;
  generally **not** available for foreign proceedings.
- **Bankers Trust orders** (UK) — the banking sibling: compel a **bank to disclose customer account
  info** to trace misappropriated funds; a recognized exception to banking confidentiality
  (*Stanford Asset Holdings v AfrAsia Bank* [2023] UKPC 35); increasingly used against crypto exchanges
  (*Fetch.ai v Persons Unknown* [2023] EWHC 2254).
- **Mareva / freezing injunctions (incl. worldwide — WFO)** — restrain dissipation pending judgment,
  often paired with asset-disclosure orders; foreign WFOs can be enforced locally.
- **MLATs / letters rogatory** — state-to-state evidence channels; strongest for *criminal* matters
  (~6–12 month lead times); letters rogatory the slower no-treaty fallback.
- **Asset-tracing firms** (Kroll, K2, forensic-accounting practices) — run the public layer at scale,
  then feed lawyers who convert leads into compelled disclosure. **This is Bunnyhole's commercial neighbor.**

**Net:** every step past the public layer is **court-gated** — find a hook in a strong-disclosure
jurisdiction (US §1782, English Norwich Pharmacal/Bankers Trust), obtain an order, enforce/transmit via
MLAT or local recognition.

---

## 3. Access map — PUBLIC vs PRIVATE

### PUBLIC / open (Bunnyhole's playing field)

- **Corporate registries.** **UK Companies House** — free, open API (~600 req/5 min), includes **PSC
  (people with significant control)** data — *but quality is weak* (~half of PSC data may be unreliable;
  ~20% name no individual). **EU BRIS / BORIS** (see CJEU caveat). US **Secretary of State** filings
  (50 states, uneven, mostly no UBO). **OpenCorporates** aggregates 140+ registries.
- **Securities filings.** **SEC EDGAR** — public full-text JSON search, no auth (descriptive
  User-Agent required), indexing **from 2001**; returns hits, fetch the doc yourself.
- **Legal-entity identifiers.** **GLEIF LEI** — full global repository, free, open, no key; the best
  clean cross-border entity join key. *(Bunnyhole already uses this — see Vol. 6.)*
- **Land/property registries, court records** — varies; US federal **PACER** (per-page paywall, public).
- **Sanctions lists (authoritative, fully public).** **OFAC SDN + Consolidated**, **EU Consolidated**,
  **UK OFSI**, **UN Security Council** lists.
- **PEP lists.** **No single official government PEP list** — PEP status is a commercial/aggregated
  determination; **OpenSanctions** is the leading open aggregator.
- **Leaks.** **ICIJ Offshore Leaks DB** (~810k entities), **OCCRP Aleph** (public + journalist-gated
  tiers), **OpenSanctions** (published in FtM, importable into Aleph). *(Bunnyhole already matches ICIJ
  — Vol. 6.)*
- **Crypto — public blockchains.** The one open *transaction* layer: every tx is readable. The private
  part is the **address→real-world-identity** binding that Chainalysis/Elliptic/TRM sell and Arkham
  partly crowd-sources. *(Bunnyhole's On-Chain pillar lives here — Vol. 2/5.)*

#### CJEU caveat on EU UBO registers (critical)
CJEU Joined Cases **C-37/20 & C-601/20** (22 Nov 2022) struck down **unrestricted public access** to
beneficial-ownership registers on privacy grounds. Consequence: **BORIS public access ended**; many
national registers suspended public access. The **6th AMLD / AMLR (2024)** replaces public access with
a **"legitimate interest"** regime — journalists & CSOs expected to qualify — phasing in ~2025–2027.
**Build the EU UBO strategy around "legitimate interest," not open scraping**, and verify per-country.

#### US beneficial-ownership caveat
The CTA's FinCEN BOI registry was **gutted for domestic use** (21 Mar 2025 interim final rule limits
reporting to foreign companies). BOI was never public anyway (authorized gov/FI users only). So **there
is effectively no public US federal UBO dataset** → **NOT OSINT-accessible** (verify post-2025 litigation).

### PRIVATE / restricted (court-gated or regulated-seat-only)
Bank account data & statements; SWIFT/MT103 traffic; SAR/STR content & FinCEN BSA data; credit-bureau
data; tax records; VASP-held customer identity; FIU intelligence. **None reachable without legal process
or a regulated-institution role.**

### The gap (state this plainly to users)
Journalists/OSINT investigators can fully work the **public layer**. Crossing into the private layer
requires **(a) a court order** (subpoena, §1782, Norwich Pharmacal/Bankers Trust, MLAT) or **(b) a
regulated-institution / LE seat.** Bunnyhole's job ends at a **referral package**.

---

## 4. The data sources & tools investigators chain together

| Layer | Real tools | Access | Notes |
|---|---|---|---|
| Corporate registries | **OpenCorporates**, **Companies House API**, **SEC EDGAR**, state SoS | Open / free-key | EDGAR full-text from 2001 |
| Entity ID | **GLEIF LEI** | Open, no key | Best cross-border join key |
| Beneficial ownership | **OpenOwnership (BODS)**, CH PSC | Open (quality-limited) | |
| Sanctions / PEP | **OpenSanctions** (FtM), OFAC/EU/UN/OFSI primaries | Open | consolidates + flags PEPs |
| Leaks | **ICIJ Offshore Leaks / Datashare**, **OCCRP Aleph** | Open tier + gated | Aleph speaks FtM |
| Commercial intel | **Sayari**, **Kharon**, **Moody's Orbis** (625M+ entities), **LexisNexis** | Paid / licensed | |
| Crypto analytics | **Chainalysis**, **Elliptic**, **TRM**, **Arkham**, explorers | Paid (Arkham has free tier) | |

> **Architectural recommendation:** the open ontology that stitches these together is **FollowTheMoney
> (FtM)** — OpenSanctions, Aleph, and ICIJ all speak it, and OpenSanctions open-sourced its matcher,
> **nomenklatura**. Bunnyhole's graph is already FtM-compatible (Vol. 1) — *lean in hard*; it inherits
> interoperability with the entire OCCRP/OpenSanctions/ICIJ ecosystem for free.

---

## 5. The hard parts / where it breaks down

- **Shell companies** — P.O.-box / corporate-service-provider addresses; one address shared by dozens.
- **Nominee directors/shareholders** — front persons; registry shows the nominee, not the UBO; red flag
  is one person directing many companies.
- **Bearer shares** — ownership = physical possession → near-total anonymity (many jurisdictions banned).
- **Offshore secrecy jurisdictions** — identity shielded by statute; CSP-mediated.
- **Layering** — rapid movement through many accounts/entities/jurisdictions.
- **Trade-based money laundering (TBML)** — fake/over/under-invoiced trade, phantom shipments. *(Vol. 3
  already covers customs-manifest anomaly detection.)*
- **Crypto mixers / chain-hopping** — Tornado Cash (OFAC-sanctioned Aug 2022; later litigated — verify),
  cross-chain bridges (RenBridge). *(Vol. 5 covers demixing tradecraft.)*
- **The "last mile" — public entity → real human.** The hardest, most valuable step. This is exactly
  where **entity resolution + graph analysis** earns its keep without ever touching private data.

---

## 6. What this means for Bunnyhole (public-data OSINT tool)

1. **The ceiling is the public layer, by law** — design to *end* at a referral package, never pretend
   to reach private data.
2. **Build on FollowTheMoney** — instant interoperability with OpenSanctions/Aleph/ICIJ (already started).
3. **Entity resolution is the product, not a feature** — join the same person/company across
   registries + leaks + sanctions + chain (probabilistic + deterministic, human-review merges).
4. **Unify on-chain and off-chain in one graph** — the one open *transaction* layer; mixers/bridges are
   the hard boundary, mark them as trail-breaks (don't fake continuity).
5. **Make provenance & access-class first-class** — tag every datum public / legitimate-interest /
   restricted. Bunnyhole already does PAI/CAI + SHA-256 receipts; add an **access-class** tag.
6. **UBO is the money shot and the weakest data** — reconstruct chains with confidence scores and honest
   dead-ends (CH PSC ~50% unreliable; no public US UBO post-2025).
7. **Encode jurisdictional access rules** — CJEU 2022 killed public EU UBO access; AMLR "legitimate
   interest" is the lawful path. A tool that *flags/refuses* unlawful-in-jurisdiction data classes is a
   compliance feature incumbents ignore.
8. **Use authoritative free primaries directly** — OFAC/EU/UN/OFSI, GLEIF (open), EDGAR (open, 2001+),
   Companies House (free key). Treat vendor coverage/pricing claims as marketing.
9. **PEP data has no official source** — rely on OpenSanctions; be explicit PEP status is an *inference*.
10. **Position against, and feed into, the paid incumbents** — win on transparency, provenance, FtM
    interoperability, and court-/FIU-ready referrals, not on out-accessing private data.

**Verification flags:** (a) revised FATF R.16 text & crypto thresholds (June 2025); (b) CTA interim rule
status post-2025; (c) per-country EU legitimate-interest UBO rules & AMLR Chapter IV timing; (d) Tornado
Cash sanctions status post-litigation; (e) SWIFT MT→ISO 20022 (pacs.008) cutover date.
