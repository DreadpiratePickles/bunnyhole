# PI Stream — design spec (2026-11-09)

Status: approved by Bobby in chat (design 2026-11-09; "assume the plan is approved" after research; upgraded
the brief to "think like an elite $500/hr private investigator"). Research basis:
`research/12_pi_methodology_and_free_sources.md`. Source manual: `~/Downloads/pI/privateeye/pi-masterclass.md`.

## 1. Outcome

`bunnyhole trace|intake --pi --case-type X --purpose "..."` runs an investigation the way an elite private
investigator would, on the **free, lawful, passive** layer only, and ends in a bottom-line-up-front report a
client or lawyer can act on. It scopes before it searches, refuses bad cases, resolves identity before
inferring links, knows what is *not* a link, labels confidence by independent corroboration, logs every
negative, finds contradictions and gaps, states what would change the conclusion, and names the custodian
and legal instrument for everything public data cannot reach.

Single pass (rulebook principle 17 loop check: no executable oracle needing 4+ rounds). Human gates
unchanged: nothing is sent, published, purchased or filed by this stream.

## 2. Doctrine → code (the elite-PI behaviours)

| # | Behaviour | Where |
|---|---|---|
| 1 | Start from the decision: objective + "done" definition per case type | `pi_reference.PLAYBOOKS`, report |
| 2 | Vet client/purpose: motive screen, forbidden eligibility purposes, matter-ref for person locates | `pi.py` |
| 3 | Conflict check against prior cases (`CaseStore.search_entity_memory`) | wiring |
| 4 | Cheapest/highest-yield first, explicit stop rules and escalation triggers | `pi_reference.PLAYBOOKS` |
| 5 | Identity resolution: name variants, same-person scoring, disqualifiers | `pi_identity.py` |
| 6 | False-link guards: registered agents, virtual offices, nominee frequency, common names | `pi_ubo.py` / `pi_analysis.py` |
| 7 | Confirmed(3+)/probable(2)/lead(1) labels, freshness decay | `pi.py`, `pi_analysis.py` |
| 8 | Log every negative; coverage matrix (searched / not searched) | `pi_analysis.py`, wiring |
| 9 | Timeline contradictions and evidence gaps | `pi_analysis.py` |
| 10 | "What would change my conclusion" falsifiers | `pi_analysis.py`, report |
| 11 | Custodian + legal instrument + licensed-layer handoff | `pi_escalation.py` |
| 12 | BLUF report with chain of custody | `pi_report.py` |
| 13 | Passive-only; skip breach-contents/credential leads, log the skip | wiring |

## 3. Modules (new files; one responsibility each)

All new Python is typed, `from __future__ import annotations`, pydantic v2 where it models data, line length
120, ruff-clean, no network in pure modules. Time is UTC-aware ISO strings.

### 3.1 `bunnyhole/engine/pi.py` — engagement, gates, labels, result schema

```python
class CaseType(str, Enum):  # values: "locate","background","asset_search","due_diligence","fraud_screen","missing_person"
class PIPurposeError(ValueError): ...   # raised by every gate; message is actionable and user-facing

class PIEngagement(BaseModel):
    engagement_id: str            # "pi_" + first 10 hex of sha256(created_at_utc|case_type|purpose)
    case_type: CaseType
    purpose: str                  # the client's written purpose; required, >= 15 chars after strip
    objective: str = ""           # filled from PLAYBOOKS by the caller; "the decision this serves"
    client: str = ""
    matter_ref: str = ""          # case no. / contract / judgment reference
    jurisdiction: str = ""        # e.g. "us", "ca-on", "uk"
    subject_is_person: bool = True
    passive_only: bool = True
    created_at_utc: str           # ISO UTC
    @classmethod
    def build(cls, case_type, purpose, *, client="", matter_ref="", jurisdiction="", subject_is_person=True) -> "PIEngagement"
        # runs validate_purpose + motive_screen + matter-ref rule, else raises PIPurposeError

FORBIDDEN_ELIGIBILITY_TERMS: tuple[str, ...]  # employment/hiring/tenant/rental/housing/credit/loan eligibility/insurance underwriting ...
MOTIVE_RED_FLAGS: tuple[str, ...]             # ex-girlfriend/ex-boyfriend/ex-wife/ex-husband/ex-partner/"blocked me"/"left me"/stalk/revenge/"protective order"/"restraining order"/"she moved"/"won't talk to me"/"get back at" ...

def validate_purpose(purpose: str) -> str                    # strip, length rule, FORBIDDEN_ELIGIBILITY_TERMS -> PIPurposeError pointing to an FCRA-compliant screener
def motive_screen(purpose: str, case_type: CaseType, subject_is_person: bool) -> None   # red flag + person + locate/background/missing_person -> PIPurposeError ("walk away" message)
def require_matter_ref(case_type, subject_is_person, matter_ref) -> None                # LOCATE of a natural person without matter_ref -> PIPurposeError
def identifier_warnings(selectors: dict[str, list[str]], subject_is_person: bool) -> list[str]
    # keys: usernames emails phones wallets domains organizations; person subject needs a full name (>=2 tokens) AND one more anchor; returns advisory strings, never raises

class FindingLabel(str, Enum): CONFIRMED="confirmed"; PROBABLE="probable"; LEAD="lead"
def label_finding(independent_source_count: int) -> FindingLabel      # >=3 confirmed, 2 probable, else lead
def count_independent_sources(receipts: list[dict]) -> int            # distinct (tool) values, but receipts sharing the same non-empty source_url host+path count once

NOTICES: tuple[str, ...]   # standing legal notices: not a consumer report / not for eligibility decisions; leads not verdicts; absence from searched sources is not proof; no licence implied; verify Ontario PSISA applicability
```

Result schema (pydantic models in `pi.py`, `PIBlock.model_dump(mode="json")` is what goes in `result["pi"]`):

```python
class SourceLogEntry(BaseModel): source: str; target: str; status: Literal["hit","negative","skipped","error"]; detail: str=""; at_utc: str
class Finding(BaseModel): node_id: str; label: str; finding_label: FindingLabel; source_count: int; freshness: str = "unknown"   # "fresh"|"aging"|"stale"|"unknown"
class OwnershipEdge(BaseModel): child: str; parent: str; pct: float | None; source: str; as_of: str = ""
class OwnershipBlock(BaseModel): levels_walked: int=0; edges: list[OwnershipEdge]=[]; blocked_by_50_rule: list[str]=[]; unresolved: list[str]=[]   # unresolved = nodes where the walk ended without reaching a natural person
class CustodyEntry(BaseModel): receipt_id: str; tool: str; url: str; sha256: str; collected_at_utc: str
class Contradiction(BaseModel): kind: str; description: str; node_ids: list[str]=[]
class CoverageRow(BaseModel): source_class: str; searched: bool; sources: list[str]=[]; outcome: str=""   # outcome: "hit"|"negative"|"not_searched"
class Custodian(BaseModel): finding: str; custodian: str; instrument: str; jurisdiction: str; note: str = ""
class PIBlock(BaseModel):
    engagement: PIEngagement
    identifier_warnings: list[str]=[]
    prior_cases: list[dict]=[]              # conflict check hits: {"case_id","seed","at"} from CaseStore
    source_log: list[SourceLogEntry]=[]
    findings: list[Finding]=[]
    ownership: OwnershipBlock = OwnershipBlock()
    false_link_flags: list[dict]=[]         # {"node_id","reason","severity"}
    contradictions: list[Contradiction]=[]
    evidence_gaps: list[str]=[]
    coverage: list[CoverageRow]=[]
    falsifiers: list[str]=[]                # "what would change my conclusion"
    custodians: list[Custodian]=[]
    handoff_sheet: list[str]=[]             # licensed-layer / counsel query sheet lines
    custody: list[CustodyEntry]=[]
    notices: list[str]=[]
```

### 3.2 `bunnyhole/engine/pi_identity.py` — identity resolution (pure)

```python
def name_variants(full_name: str) -> list[str]          # lowercase, deduped, includes: as-given, "first last", initials ("j smith", "j. smith"), first+middle-initial, hyphen/space splits, common nickname map (william/bill/billy/will, robert/bob/rob, elizabeth/liz/beth/betty, ...), no maiden-name guessing
class PersonRecord(BaseModel): name: str; dob_year: int | None=None; age: int | None=None; addresses: list[str]=[]; phones: list[str]=[]; emails: list[str]=[]; relatives: list[str]=[]; deceased: bool=False; source: str=""
class MatchVerdict(str, Enum): SAME="same"; PROBABLE="probable"; POSSIBLE="possible"; DIFFERENT="different"
class IdentityMatch(BaseModel): verdict: MatchVerdict; score: float; anchors: list[str]; disqualifiers: list[str]; reasons: list[str]
def score_same_person(a: PersonRecord, b: PersonRecord, *, common_name: bool | None = None) -> IdentityMatch
    # Weights: name match exact 0.2 / variant 0.12; birth year equal 0.25, within 1 -> 0.15; address overlap 0.25; phone overlap 0.3; email overlap 0.3; relative overlap 0.15.
    # Anchors = non-name attributes that matched. Two-anchor rule: SAME needs score>=0.8 AND >=2 anchors; PROBABLE >=0.55 and >=1 anchor; POSSIBLE >=0.3; else DIFFERENT.
    # Common-name penalty (-0.15, auto-detected from a small built-in set of very common surnames+given names when common_name is None) is applied when no anchor beyond name.
    # Disqualifiers force DIFFERENT: birth years differ by >5 (or ages differ by >5), one deceased and the other has an event after the death year given in reasons, conflicting middle initials (both present, different).
def cluster_candidates(records: list[PersonRecord]) -> list[list[int]]   # indices grouped by transitive PROBABLE-or-better matches; never merges on name alone
COMMON_NAMES: frozenset[str]
```

### 3.3 `bunnyhole/engine/pi_ubo.py` — ownership walk, 50% rule, false-link guards (pure; the network fetcher is injected)

```python
class OwnerLink(BaseModel): parent_id: str; parent_name: str; pct: float | None=None; is_natural_person: bool=False; source: str=""; as_of: str=""
Fetcher = Callable[[str], Awaitable[list[OwnerLink]]]
async def walk_ownership(start_id: str, fetch_owners: Fetcher, *, max_levels: int = 5) -> OwnershipBlock
    # BFS by layer, cycle guard (visited set), stops at natural persons or max_levels; nodes with no owners and not a person -> unresolved; fetch exceptions are recorded as unresolved with a reason (never swallowed silently, never raise).
def apply_50_percent_rule(edges: list[OwnershipEdge], listed_ids: set[str]) -> list[str]
    # OFAC fixpoint: an entity is blocked if (sum of pct of its blocked owners, direct) >= 50, where blocked owners = listed_ids plus already-blocked entities; iterate to a fixed point. pct None counts as 0 but is reported nowhere as blocked. Returns sorted node ids that are blocked by the rule (excluding the listed ones themselves).
REGISTERED_AGENT_ADDRESS_MARKERS: tuple[str, ...]   # e.g. "1209 orange st", "251 little falls", "2711 centerville", "8 the green", "1000 brickell", "registered agent", "c/o" ... (lowercase substrings)
def is_registered_agent_address(address: str) -> bool
def nominee_flags(officer_entity_counts: dict[str, int], threshold: int = 25) -> list[dict]   # officer name -> number of entities; >= threshold -> {"officer","entities","reason"}
def false_link_reason(shared_attribute_kind: str, value: str, *, entity_count: int | None = None) -> str | None
    # kinds: "address" (registered-agent/virtual-office -> reason), "officer" (nominee frequency), "ip"/"hosting" (shared hosting providers list), "name" (very common name). None = a real link candidate.
```

### 3.4 `bunnyhole/engine/pi_analysis.py` — coverage, timeline, freshness, falsifiers (pure)

```python
SOURCE_CLASSES: tuple[str, ...]   # "court_dockets","corporate_registry","beneficial_ownership","sanctions_pep","regulatory_enforcement","property_assets","news_adverse_media","social_osint","domain_infrastructure","crypto_onchain","missing_persons","vital_records"
def expected_source_classes(case_type: CaseType, subject_is_person: bool) -> list[str]
def build_coverage(case_type, subject_is_person, source_log: list[SourceLogEntry], source_class_map: dict[str, str]) -> list[CoverageRow]
    # one row per expected class: searched=True if any log entry whose source maps to the class has status hit/negative; outcome hit if any hit else negative; else not_searched. skipped/error never count as searched.
def freshness_class(as_of_iso: str, kind: str = "address", *, now_iso: str | None = None) -> str   # fresh <=12 months, aging <=36, stale beyond; "unknown" for empty/unparseable; kind "registry" uses 24/60 month cutoffs
def detect_contradictions(timeline: list[dict]) -> list[Contradiction]
    # items: {"timestamp","title","description","node_ids","kind"?}. Rules: an event dated before an entity's incorporation event on the same node ("incorporated"/"incorporation" in title); two incorporation dates for one node more than 30 days apart; an event after a node's "dissolved"/"struck off"/"deceased" event.
def find_gaps(timeline: list[dict], *, max_gap_days: int = 365) -> list[str]   # human-readable gaps between consecutive dated events on the same node; also "no dated evidence at all" when empty
def falsifiers_for(case_type: CaseType, findings: list[Finding], contradictions: list[Contradiction], ownership: OwnershipBlock) -> list[str]
    # deterministic text: per case type 2-4 base falsifiers ("a record showing a different registered owner at the same date", ...), plus one per unresolved ownership node, plus one per lead-only (single source) finding, plus one per contradiction.
```

### 3.5 `bunnyhole/engine/pi_escalation.py` — custodians and handoff (pure data + lookup)

```python
CUSTODIAN_RULES: list[dict]   # {"finding_kind","custodian","instruments": {"us": "...", "ca-on": "...", "uk": "...", "intl": "..."}, "note"}
def custodians_for(finding_kinds: set[str], jurisdiction: str) -> list[Custodian]
    # finding_kind vocabulary: "exchange_deposit_address","bank_account_indicated","registered_agent","company_records","phone_carrier","isp_ip_assignment","employer","vehicle_registry","land_title","social_platform_account","domain_registrant","vessel_aircraft_registry"
    # instruments by jurisdiction come from the manual: subpoena duces tecum / court order (us), Norwich Pharmacal order (ca-on, uk), production order via counsel, MLAT/Hague for cross-border, licensed database (credit header) confirmation by a licensed PI, public-place field verification by a licensed PI. Unknown jurisdiction falls back to "intl".
def handoff_sheet(engagement: PIEngagement, verified_identifiers: dict[str, list[str]], custodians: list[Custodian]) -> list[str]
    # plain lines a licensed investigator or lawyer can paste: "Run through licensed database: <identifier>", "Request via counsel: <instrument> to <custodian> for <finding>", "Field verification (public place only; licensed investigator): <address>". Never claims the data is verified beyond its label.
```

### 3.6 `bunnyhole/engine/pi_reference.py` — knowledge tables + lookups (pure data)

```python
class SourceEntry(BaseModel): name; url; what: str; access: Literal["keyless","free_account","free_api_key","open_source","free_noncommercial"]; jurisdiction: str; categories: list[str]; implemented: bool; caveats: str=""; verified: bool
SOURCES: list[SourceEntry]       # EVERY free source in research/12 section 5 plus every free source named in the masterclass sections 3-5 (PACER Case Locator, CourtListener/RECAP, UniCourt, Judyrecords, SEC EDGAR incl. Form D, OpenCorporates, SAM.gov, NamUs, SearchSystems.net, Black Book Online, OSINT Framework, Bellingcat toolkit, Awesome OSINT, voter rolls/licences/UCC/FAA/FCC, Companies House, GLEIF, Open Ownership, ICIJ Offshore Leaks, OCCRP Aleph, OpenSanctions, OFAC SDN/UN/EU/OFSI, LittleSis, Equasis, Etherscan/BscScan/Blockchain.com/Arkham/Breadcrumbs, CanLII, Ontario Business Registry, Teranet/OnLand, Wayback/archive.today, WiGLE, ADS-B Exchange, SunCalc, Mapillary, Google Earth, ExifTool, TinEye/Yandex/Google Lens, HaveIBeenPwned (membership check only), Shodan free tier, theHarvester, Sherlock, Maigret, Holehe, GHunt, PhoneInfoga, SpiderFoot, Maltego CE, Recon-ng). `implemented=True` only for sources Bunnyhole already queries or the new `pi_sources` agent queries; verify against the code.
OUT_OF_SCOPE: list[dict]         # {"name","why"}: TLOxp, Tracers, IRBsearch, idiCORE, Accurint, CLEAR, SkipSmasher, Delvepoint, Experian/Equifax, LPR data, consumer people-search sites, DeHashed contents for individuals, Orbis/Sayari/D&B, Chainalysis/TRM/Elliptic (enterprise) ... each with the reason (licence / permissible purpose / ToS / cost) and "hand off to a licensed investigator".
LEGAL_RULES: dict[str, list[dict]]   # keys "us","ca-on","general"; items {"rule","applies","practical","verify"}; us: FCRA, GLBA 6821, DPPA, FDCPA/TCPA/HIPAA, recording-consent states, GPS-tracker state laws; ca-on: PSISA 2005 (licensing, 50-hour course, 60-question exam, digital licence, 2-year renewal, "verify with the Ministry"), PIPEDA, Criminal Code s.184 and s.264 (verify); general: no pretexting, no hacking, no trespass, no impersonation of police, licence = no police powers.
UNLAWFUL_METHODS: tuple[str, ...]
CYCLE_STAGES: tuple[dict, ...]       # intake & legal scoping, desk research, field verification (licensed), corroboration, court-ready report
UBO_STEPS: tuple[dict, ...]          # the 12 steps with the primary tool each
class PlaybookStep(BaseModel): order:int; action:str; sources:list[str]; yield_level:Literal["high","medium","low"]; cost:Literal["free","free_key","handoff"]; legal_gate:str=""; stop_if:str=""
class Playbook(BaseModel): case_type: CaseType; objective: str; done_when: str; steps: list[PlaybookStep]; escalate_when: list[str]; pitfalls: list[str]; typical_hypotheses: list[str]
PLAYBOOKS: dict[CaseType, Playbook]   # all six, from research/12 section 3, with pitfalls and 2-3 competing hypotheses each (e.g. asset_search: assets held via nominee entities / dissipated or transferred / genuinely judgment-proof)
def sources_for(case_type: CaseType | None = None, jurisdiction: str | None = None, implemented_only: bool = False) -> list[SourceEntry]
def legal_for(jurisdiction: str) -> list[dict]       # "general" rules + the jurisdiction's; unknown jurisdiction -> general only
def playbook_for(case_type: CaseType | str) -> Playbook
def render_guide() -> str                             # markdown of CYCLE_STAGES + doctrine (the 13 behaviours in section 2) for `bunnyhole pi guide`
```

### 3.7 `bunnyhole/agents/pi_sources.py` — new network sources

```python
class PISourcesAgent:   # same constructor shape as AccountantAgent: __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST)
    async def investigate_companies_house_psc(self, company_name: str, origin_node_id: str, hop_depth: int) -> list[OwnerLink-like dicts]
        # needs COMPANIES_HOUSE_API_KEY (HTTP basic auth: key as username, empty password). No key -> log an agent skip "COMPANIES_HOUSE_API_KEY not set" and return []. Search /search/companies?q=, take top 3, fetch /company/{n}/persons-with-significant-control, add nodes/edges with receipts (Admiralty B2, name matches flagged soft). Never raise.
    async def screen_canadian_sanctions(self, query: str, origin_node_id: str, hop_depth: int) -> None
        # downloads the GAC SEMA XML once per process (cache on the class), parses entries, name-matches (normalized, token-subset) -> SOFT matches only, receipt tool "gac_sema_sanctions". Cap download at 10 MB. Parse with defusedxml-safe approach: use xml.etree with the DTD/entity features unavailable? -> use defusedxml if installed else refuse DTDs by rejecting payloads containing "<!DOCTYPE" / "<!ENTITY".
    async def investigate_cfpb_complaints(self, company: str, origin_node_id: str, hop_depth: int) -> None
        # keyless; search_term=<company>, size=5, no_aggs=true; summarise count + top issues; a hit is a pattern-of-conduct note, flagged "UNVERIFIED_CONSUMER_CLAIMS".
    async def investigate_wikidata_entity(self, query: str, origin_node_id: str, hop_depth: int) -> None
        # wbsearchentities, limit 3; descriptions only; records QID + URL; clearly "entity-resolution aid, verify against primary registry".
```
Use the repo's existing HTTP helper/`netutil` conventions (read `AccountantAgent.investigate_opensanctions` first and mirror its logging, timeout, error, receipt and Admiralty conventions; respect `--tor/--proxy`). Network errors are logged and returned as a clean negative/skip, never raised.

### 3.8 `bunnyhole/engine/pi_report.py` — the deliverable

```python
def build_pi_report(result: dict) -> str   # reads result["pi"] (PIBlock dict), result["nodes"], result["edges"], result.get("ach"), result.get("seed"); returns Markdown
```
Sections in order: **Bottom line** (3-6 sentences: what was established at which label, biggest gap, recommended next step — generated deterministically from findings/coverage/custodians, no model call) · **Engagement & scope** (id, case type, objective, purpose, matter ref, jurisdiction, passive-only, conflict-check result) · **Client theory vs. evidence** (the `--hypothesis`, ACH winner/scores if present, else "no theory supplied") · **Findings** (table: finding, label, sources, freshness; confirmed first) · **Ownership chain** (edges table, levels walked, 50%-rule flags, unresolved) · **What is NOT a link** (false-link flags) · **Contradictions and gaps** · **What would change this conclusion** · **Coverage and negatives** (matrix; "absence from searched sources is not proof") · **Custodians and next steps** (custodian, instrument, handoff sheet) · **Chain of custody** (receipt id, tool, URL, SHA-256, time) · **Limitations & legal notices**. Never states a label stronger than the data; empty sections say "none".

## 4. Wiring (modifies existing files; do not refactor them)

* `bunnyhole/engine/personas.py`: add `Persona.PRIVATE_INVESTIGATOR = "pi"`: display "Private Investigator (PI)", DEEP gear, depth 3, breadth 4, priority [FIAT, OSINT, JOURNALISM], `emphasize_sanctions=True`, framing "Elite-PI method: scope the decision, vet purpose, resolve identity before inferring links, corroborate across independent sources, log negatives, name the custodian for what public data cannot reach. Leads, not verdicts." Existing tests that assert 5 personas must be updated to 6 (that is an intentional requirement change).
* `bunnyhole/cli/main.py`: on `trace` and `intake` add `--pi` (bool), `--case-type` (CaseType, default `due_diligence`), `--purpose` (str), `--client`, `--matter-ref`, `--subject-type` (`person|entity`, default `person`), `--pi-report FILE`. `--pi` implies persona `pi` (still overridable through the existing precedence rules). `--pi` without `--purpose` or failing any gate exits with code 2 and a clear message (use `typer.BadParameter`/`typer.Exit(2)`). New sub-app `bunnyhole pi` with `guide`, `sources [--case-type] [--jurisdiction] [--implemented]`, `legal [--jurisdiction us|ca-on|general]`, `playbook CASE_TYPE`, `out-of-scope`. Follow the file's existing Rich output style.
* `bunnyhole/engine/orchestrator.py`: new optional `engagement: PIEngagement | None = None`. When set: run the conflict check first (`CaseStore().search_entity_memory` on the seed and selectors; failures are non-fatal and logged); in `_execute_lead` the company/person branch additionally runs `PISourcesAgent` sources (Companies House PSC, Canadian sanctions, CFPB, Wikidata) and, for person subjects, skips nothing else; `credential` leads are skipped with a logged reason ("credential/breach contents are not used in PI mode"); every dispatched source call is wrapped so a **SourceLogEntry** is recorded with status hit (new graph nodes or receipts appeared), negative (ran, nothing new), skipped (missing key/blocked/policy) or error (exception, stored as detail not swallowed); `compile_full_result` adds `result["pi"]` built from the pure modules (labels via `label_finding`/`count_independent_sources` over each node's receipts; ownership via `walk_ownership` seeded from GLEIF/PSC links and `apply_50_percent_rule` over OpenSanctions/GAC hits; coverage/contradictions/gaps/falsifiers/custodians/handoff via the pure modules; custody from every receipt). No behaviour change when `engagement` is None.
* `bunnyhole/mcp/server.py`: one read-only tool `pi_reference(kind: "guide"|"sources"|"legal"|"playbook"|"out_of_scope", case_type=None, jurisdiction=None)` returning JSON-serialisable data. No MCP tool runs a PI trace.
* Docs: `docs/PI_STREAM.md` (usage, doctrine, legal filter, flags, report anatomy, how to extend sources), README section, `ACCEPTABLE_USE.md` PI addendum, `research/00_INDEX.md` entry for file 12.

## 5. Tests (written first, failing for the right reason; no live network)

`tests/test_pi_core.py`, `test_pi_identity.py`, `test_pi_ubo.py`, `test_pi_analysis.py`, `test_pi_escalation_reference.py`, `test_pi_sources.py` (respx), `test_pi_report.py`, `test_pi_cli.py` (typer `CliRunner` with a fake orchestrator; asserts exit code 2 gates, flag plumbing, persona 5→6 update). Must cover, at minimum: purpose too short; every forbidden eligibility term refused; motive red flags refused for person subjects but allowed for entity subjects; locate of a person without matter-ref refused; label thresholds 0/1/2/3/4 sources; shared source URL counted once; same-person scoring bands incl. two-anchor rule, common-name penalty, deceased and birth-year disqualifiers; name variants; 50% rule direct, indirect (fixpoint), exactly-50, 49.9, `pct=None`, cycles; walk cap at 5 levels and fetch-exception becomes unresolved; registered-agent and nominee detection; coverage never counts skipped/error as searched; freshness cutoffs; timeline contradiction rules and gaps; falsifiers include one per unresolved node; custodian instruments differ by jurisdiction; every `SOURCES` entry has an https URL and an `access` that is not paid, no `OUT_OF_SCOPE` name appears in `SOURCES`, every playbook has ≥4 steps and ≥2 hypotheses; report contains all section headings, never labels a lead as confirmed, handles an empty block; sources agent returns a skip with no key and never raises on HTTP 500/timeout.

Verification commands: `uv run pytest -q` (whole suite, must stay green) and `uv run ruff check bunnyhole tests`.

## 6. Non-goals

No credentialled-database integration, no consumer people-search scraping, no pretexting/tracking/recording/account access, no automatic outbound contact, no model-judged scoring (all scoring deterministic), no changes to unrelated engine behaviour, no commits or pushes.
