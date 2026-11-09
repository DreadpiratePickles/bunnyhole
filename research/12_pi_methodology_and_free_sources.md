# 12 — Private-Investigator Methodology and the Free, Lawful Source Layer

Distilled from the *PI Masterclass* field manual (Nov 2026) plus a follow-up web sweep for free sources
the manual missed. This file is the research basis for the `--pi` stream (see
`docs/superpowers/specs/2026-11-09-pi-stream-design.md`). Confidence flags: **V** = page/API opened or
called during research, **U** = from a search snippet or memory, not verified. Treat U rows as
"verify before relying".

## 1. The legal filter (what Bunnyhole will and will not do)

| Bunnyhole does (free, lawful, passive) | Bunnyhole does not (licence, credential or unlawful) |
|---|---|
| Free government / registry / court sources, open APIs | Credit-header databases: TLOxp, Tracers, IRBsearch, idiCORE, Accurint, CLEAR (need licence, permissible purpose, site audit) |
| Passive OSINT: no login, no password reset, no contact with the subject | License-plate-reader resale data |
| Public-record corporate and ownership walks, sanctions screening, the OFAC 50% rule | Scraping consumer people-search sites (ToS, accuracy) |
| Chain-of-custody evidence logging, SHA-256 receipts, court-style reports | Pretexting (GLBA crime), tracker placement, audio recording, account access, hacking |
| Naming the *custodian* of non-public records and the legal instrument that reaches it | Eligibility decisions (employment, housing, credit, insurance underwriting): FCRA-regulated, use an FCRA-compliant screener |
| Breach *exposure* signals already in Bunnyhole | Using breach *contents* against private individuals in PI mode (legally sensitive; skipped and logged) |

Ontario note (**U**, verify with the Ministry of the Solicitor General): under the Private Security and
Investigative Services Act, 2005, acting as a private investigator for pay generally needs a licence
(50-hour approved course, 60-question exam, digital licence renewing every two years, per the manual).
Bunnyhole output feeding paid third-party work may fall inside that. Bunnyhole is a research tool, not a licence.

## 2. How an elite PI actually works (doctrine encoded in the stream)

1. **Start from the decision, not the subject.** What will the client decide with the answer? That defines "done" and the stop rule.
2. **Vet the client and the purpose.** Motive screen (ex-partner locates, evasion of a protective order = walk away), a matter reference (case no., contract, judgment) for locates of private people, proportionality, conflict check against prior cases.
3. **Every input is wrong until corroborated**: the client's story, stale records, marketing data.
4. **Cheapest, highest-yield source first; stop when the objective is met.** Every pivot must justify itself.
5. **Identity resolution before inference.** Never merge two people on a name alone: two-anchor rule, common-name penalty, disqualifiers (age gap, deceased).
6. **Know what is *not* a link**: registered-agent addresses, virtual offices, nominee directors serving hundreds of entities, shared hosting, very common names.
7. **Corroborate across independent sources; label** confirmed (3+) / probable (2) / lead (1); decay stale data.
8. **Log every negative.** A coverage matrix shows what was and was not searched; absence from sources searched is not exculpatory.
9. **Chronology and contradictions.** Conflicts between records are leads; gaps are questions.
10. **Alternative hypotheses and falsifiers.** State what would change the conclusion.
11. **Find the custodian.** Where public data ends, name who holds the record and which legal tool (subpoena, production order, Norwich Pharmacal order, MLAT, licensed database, field surveillance in public) reaches it. That is the deliverable's "next step".
12. **Bottom line up front.** Conclusion, confidence, gaps, next steps with cost and legal gate, written to survive cross-examination.
13. **Stay passive; never tip off.** Chain of custody for everything.

## 3. Case-type playbooks (free layer)

| Case type | Objective ("done") | Order of work (cheapest and highest-yield first) |
|---|---|---|
| `locate` | A current address/contact confirmed by 2+ independent sources, or a documented dead end | Anchor identifiers → name variants → court/dockets → property/corporate officer filings → professional licences → social/OSINT footprint → hand off to licensed layer for credit-header confirmation |
| `background` | Identity confirmed, public-record history assembled (not for eligibility decisions) | Identity resolution → litigation → corporate roles → sanctions/PEP → adverse media → licences |
| `asset_search` | Map of assets held directly and through entities, with the owning chain to a human | Entity anchor → registry docs → officers (current and historical) → declared shareholders/PSC → nominees → 12-step UBO walk → sanctions 50% rule → property/UCC/liens/aircraft/vessels → crypto cash-out points → lifestyle vs declared income → custodians for process |
| `due_diligence` | Counterparty risk picture | Registry → UBO → sanctions/PEP → litigation/enforcement/complaints → adverse media → jurisdiction risk |
| `fraud_screen` | Pattern-of-conduct evidence and what is verifiable | Entity/person → enforcement and complaint databases → shell-company red flags → money trail → custodians |
| `missing_person` | Leads routed to the right authority | Identifier set → public missing/unidentified databases → obits/records → public-source footprint → **route to law enforcement**, never to the client |

## 4. The 12-step UBO workflow (from the manual, adapted from OSINT-BIBLE)

1 Anchor the entity (name, jurisdiction, registration number) · 2 Pull incorporation documents · 3 Current **and historical** directors/officers · 4 Declared shareholders · 5 Detect nominees, trusts, service providers · 6 Verify the physical persons · 7 Walk to the next ownership layer; repeat (max ~5 levels) · 8 Sanctions-check every node incl. the **OFAC 50% rule** · 9 Jurisdiction risk (FATF lists) · 10 Adverse media and litigation sweep · 11 Correlate crypto flows if applicable · 12 Document the chain: nodes, edges, %, dates, SHA-256 per document.

## 5. Source catalog additions found by the follow-up sweep

Verified by an API call this session: **CFPB complaints** (`consumerfinance.gov/data-research/consumer-complaints/search/api/v1/`, keyless JSON), **Wikidata** (`wikidata.org/w/api.php?action=wbsearchentities`, keyless), **Global Affairs Canada sanctions XML** (`international.gc.ca/world-monde/assets/office_docs/international_relations-relations_internationales/sanctions/sema-lmes.xml`, link found on the official page), **Companies House API** (`api.company-information.service.gov.uk`, returns 401 without a free API key, so it needs one).

| Name | URL | Gives a PI | Access | Caveats | Conf |
|---|---|---|---|---|---|
| CFPB Complaint Database | https://www.consumerfinance.gov/data-research/consumer-complaints/ | Complaints against US financial firms, pattern of conduct | keyless API | Narratives are unverified consumer claims | V |
| Wikidata | https://www.wikidata.org/ | Entity resolution, cross-registry IDs | keyless API | Community-edited, verify against primary | V |
| GAC Consolidated Canadian Autonomous Sanctions List | https://www.international.gc.ca/world-monde/international_relations-relations_internationales/sanctions/consolidated-consolide.aspx?lang=eng | SEMA / JVCFOA designations (XML) | keyless | "Administrative purposes only"; UN/OFSI lists separate | V |
| Companies House PSC (UK) | https://developer.company-information.service.gov.uk/ | Persons with Significant Control: public UBO register | free API key | Rate limited | V |
| Corporations Canada (federal) | https://ised-isde.canada.ca/site/corporations-canada/en/node/269 | Federal corporations, directors, open data CSV | keyless search; API terms unclear | Federal only; Ontario is separate | V (data page) |
| crt.sh | https://crt.sh/ | Certificate history, subdomains | keyless | Not an official API (already in Bunnyhole) | V |
| FINRA BrokerCheck | https://brokercheck.finra.org/ | Broker/adviser history, disclosures | keyless web | No API found | U |
| NMLS Consumer Access | https://www.nmlsconsumeraccess.org/ | Mortgage originator licences, discipline | keyless web | | U |
| FAA Aircraft Registry | https://registry.faa.gov/AircraftInquiry/ | N-number owner/registration | keyless web | Owner-privacy rules unchecked | U |
| FCC ULS | https://wireless.fcc.gov/uls | Radio licences, licensee | keyless | Mirrors lag | U |
| USCG PSIX | https://cgmix.uscg.mil/ | Documented US vessels | keyless | No liens shown | U |
| NSOPW | https://www.nsopw.gov/ | Public sex-offender registry search | keyless web | Privacy-sensitive; verify on the jurisdiction's own registry | V |
| BOP Inmate Locator | https://www.bop.gov/inmateloc/ | Federal custody status | keyless web | Federal only | V |
| Charley Project | https://charleyproject.org/ | Cold-case missing persons | keyless | Route matches to law enforcement | V |
| Doe Network | https://doenetwork.org/ | Missing/unidentified persons | keyless | Volunteer-run | U |
| FamilySearch / Find a Grave | https://www.familysearch.org/ · https://www.findagrave.com/ | Genealogy, burials | free account | Check terms before scraping | U |
| Chronicling America | https://www.loc.gov/collections/chronicling-america/ | Historic newspaper OCR | keyless (conflicting reports) | Page returned 403 | U |
| CRA Charities listings | https://apps.cra-arc.gc.ca/ebci/hacc/srch/pub/dsplyAdvncdSrch | Charity status, T3010 open data | keyless | | U |
| CIPO Trademarks | https://ised-isde.canada.ca/cipo/trademark-search | Canadian marks and owners | keyless | Registered/pending only | U |
| ABN Lookup (Australia) | https://abr.business.gov.au/Tools/WebServices | ABN, entity name, GST | free GUID | Thin fields | V |
| Open Ownership / BODS | https://standard.openownership.org/ | Beneficial-ownership data schema and datasets | free | Register reported retired | U |
| Overpass Turbo | https://overpass-turbo.eu/ | OSM feature queries for geolocation | keyless | Volunteer servers | U |
| Copernicus Browser | https://dataspace.copernicus.eu/ | Sentinel imagery, historical | free account | | U |
| InVID-WeVerify | https://weverify.eu/verification-plugin/ | Video/image verification plugin | free extension | | U |
| FotoForensics | https://fotoforensics.com/ | Error-level analysis | free | Uploads stored; not for legal work | U |
| ArchiveBox | https://archivebox.io/ | Self-hosted page capture (WARC, PDF) | open source | Licence unconfirmed; do not archive private sessions | U |
| OpenTimestamps | https://opentimestamps.org/ | Bitcoin-anchored existence proof | free client | Proves date, not authorship | V |
| Timesketch | https://github.com/google/timesketch | Forensic timeline analysis | Apache-2.0 | Heavy | V |
| Datashare (ICIJ) | https://github.com/ICIJ/datashare | Local document search and entity extraction | AGPL-3.0 | Heavy install | V |
| GIJN research tools | https://gijn.org/online-research-tools/ | Curated hub | free | | U |

Not selected: USPTO/PatentsView (status unclear), ASIC (no free official API found).

## 6. Methodology standards to cite

Berkeley Protocol on Digital Open Source Investigations (OHCHR/UC Berkeley, **U** on exact record) — documented, preserved, verifiable collection and reporting. ISO/IEC 27037:2012 (paid standard; summaries free) — identification, collection, acquisition and preservation of digital evidence with integrity. NATO Admiralty grading (already in Bunnyhole). ICD 203 analytic standards (already reflected in the ODNI PAI/CAI work). ACFE fraud-examination method (**U**).

## 7. Legal reference (verify before relying; not legal advice)

US: FCRA (consumer reports need permissible purpose; skip-trace ≠ consumer report), GLBA §6821 (pretexting is a federal crime), DPPA (DMV records, enumerated purposes), FDCPA/TCPA/HIPAA. Canada/Ontario: PSISA 2005 licensing; PIPEDA consent/legitimate-purpose; Criminal Code s.184 (interception) and s.264 (criminal harassment) **U**. Recording: one-party federal rule in the US but several states require all-party consent; GPS trackers on vehicles you do not own are unlawful in many jurisdictions.
