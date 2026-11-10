# 🕵️ The PI stream: an elite-investigator method on the free, lawful, passive layer

`--pi` turns a `trace` or `intake` run into a private-investigator style engagement. It vets the purpose
before anything is searched, runs only free, lawful, passive sources, labels every finding by how many
independent sources support it, logs what was and was not searched, and ends in a bottom-line-up-front
report that names who holds the records public data cannot reach and which legal instrument gets them.

**Who it is for:** lawyers, paralegals, compliance and due-diligence staff, journalists and licensed
investigators who want a sourced first pass. **What it is not:** a licence, a consumer reporting agency, or
a replacement for a licensed investigator or counsel. Output is leads, not verdicts, and nothing here is
legal advice. Read [`ACCEPTABLE_USE.md`](../ACCEPTABLE_USE.md) first; it has a PI addendum.

Design spec: [`superpowers/specs/2026-11-09-pi-stream-design.md`](superpowers/specs/2026-11-09-pi-stream-design.md).
Research basis: [`research/12_pi_methodology_and_free_sources.md`](../research/12_pi_methodology_and_free_sources.md).

---

## 1. The doctrine: thirteen behaviours and where they show up

| # | Behaviour | How it shows up |
|---|---|---|
| 1 | Start from the decision, not the subject | `Objective` and `Purpose` in the report's *Engagement & scope*. The objective comes from the case-type playbook; `pi playbook` states the "done when". |
| 2 | Vet the client and purpose | A required, attested `--purpose-category` plus the gates in section 4 refuse with exit code 2 before any source runs; the category is shown in *Engagement & scope*. |
| 3 | Conflict check against prior cases | `Conflict check` line in *Engagement & scope*; the check is also a `conflict_check` row in the source log. |
| 4 | Cheapest, highest-yield first; stop rules | `pi playbook <type>` lists the order, stop-ifs and escalation triggers. The live run does not execute a playbook (it dispatches the existing lead agents), but the report's *Playbook progress* section scores each step against what actually ran. |
| 5 | Identity before inference | Advisory identifier warnings (a person needs a full name plus one more anchor), common-name flags under *What is NOT a link*, and the *Identity resolution* section: notes such as "N records named X are NOT established as one person" and "probable same person on anchors [...]", scored by the same-person scorer in `pi_identity.py`. The notes never merge graph nodes and do not use graph edges. |
| 6 | Know what is not a link | *What is NOT a link* table: registered-agent and virtual-office addresses, nominee officers, shared hosting and CDN IPs, very common names. |
| 7 | Label by independent corroboration; decay stale data | *Findings* table: `confirmed` (3+ sources), `probable` (2), `lead` (1), plus freshness and a relevance rating (`subject`, `related`; unrelated records are set aside in the report and kept in the JSON). |
| 8 | Log every negative | *Coverage and negatives*: every expected source class marked searched or `NOT SEARCHED`, a *Tried, not reached* column for sources that were refused or failed, and every negative, skip and error listed. |
| 9 | Chronology: contradictions and gaps | *Contradictions and gaps* section. |
| 10 | State what would change the conclusion | *What would change this conclusion*: base falsifiers per case type, plus one per unresolved ownership node, single-source lead and contradiction. |
| 11 | Find the custodian | *Custodians and next steps*: custodian and legal instrument per finding kind, and a handoff sheet to paste to a licensed investigator or counsel. For an entity subject the handoff points to primary sources (verify a sanctions hit on the primary list; confirm corporate status and beneficial ownership on the primary registry) instead of a licensed person database. |
| 12 | Bottom line up front, with chain of custody | *Bottom line* first; *Chain of custody* lists each receipt with a SHA-256 digest of the recorded extract (not of the retrieved page; archive pages separately). |
| 13 | Stay passive; skip breach contents | `--cred` is refused; credentials in intake packets or dumps are dropped and scrubbed; breach and infostealer lookups (Hudson Rock, LeakCheck, EmailRep) and Holehe-style probes are blocked and logged as `skipped`. No login, no contact with the subject. |

---

## 2. Quick start

Reference commands need no network and no keys:

```bash
uv run bunnyhole pi guide                      # the method: cycle, the 13 behaviours, case types
uv run bunnyhole pi sources                    # free source catalog (add --case-type, --jurisdiction, --implemented)
uv run bunnyhole pi legal --jurisdiction ca-on # legal frame: us | ca-on | general
uv run bunnyhole pi playbook asset_search      # order of work, stop-ifs, pitfalls, competing hypotheses
uv run bunnyhole pi out-of-scope               # what Bunnyhole will not do, and what to hand off
```

**Entity due diligence** (`--subject-type` defaults to `person`, so say `entity` for a company):

```bash
uv run bunnyhole trace "Acme Holdings Ltd" --pi --case-type due_diligence --subject-type entity \
  --purpose "Vet a counterparty before signing a supply contract" --purpose-category counterparty_due_diligence \
  --client "Northwind Procurement" --pi-jurisdiction ca-on --pi-report acme_pi_report.md
```

**Asset search** for a judgment debtor, Ontario custodians:

```bash
uv run bunnyhole intake --org "Acme Holdings Ltd" --domain acme.example \
  --pi --case-type asset_search --subject-type entity \
  --purpose "Identify attachable assets of a judgment debtor to enforce a judgment" \
  --purpose-category judgment_enforcement \
  --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report asset_report.md
```

**A person subject** needs a person-eligible `--purpose-category` AND a matter reference, whatever the case type.
Without `--matter-ref` the run exits 2 before any search:

```bash
uv run bunnyhole intake --org "Jane Q. Smith" --email jane@example.com \
  --pi --case-type locate --subject-type person \
  --purpose "Serve a statement of claim in an open action" --purpose-category service_of_process \
  --matter-ref "CV-24-00123456" --pi-jurisdiction ca-on --pi-report locate_report.md
```

`--pi` sets the persona to `pi` (deep gear, depth 3, breadth 4, sanctions screening emphasized) unless you
pass `--persona` or explicit gear/depth/breadth flags. The terminal ends with a short **PI SUMMARY** panel
(label counts, source classes not searched, custodians named); `--pi-report FILE` writes the full Markdown
report. `--out` and `--json` still write the usual dossier and graph JSON; the JSON gains a `pi` key.

With `--subject-type entity`, give the legal form in the name (`Ltd`, `Inc`, `LLC`) or add `--confirm-entity`;
a bare two- or three-word name such as "Maple Leaf Roofing" is refused as person-like (exit 2). `--cred` is refused.


### Worked example

A depth-1 fast run on a sanctioned company (Rosneft) and on one with no listing hit (Bombardier Inc). The
`--confirm-entity` flag is not needed here: a single-word name or a name with a legal form passes the seed check,
while "Maple Leaf Roofing" does not.

```bash
uv run bunnyhole trace "Rosneft" --pi --case-type due_diligence \
  --purpose "Counterparty due diligence ahead of a supply contract" \
  --purpose-category counterparty_due_diligence --subject-type entity \
  --gear fast --depth 1 --pi-report out.md --json out.json
```

Example output, soft matches, not a determination. Bottom line of the Rosneft report (trimmed):

> - **Sanctions:** soft name match to PJSC Rosneft Oil Company and 2 more on UK Sanctions List, OFAC SDN and 1 more; verify on the primary list before relying on it. 50%-rule: not evaluable (ownership percentages unknown).
> - **Registry:** публичное акционерное общество "Нефтяная компания "Роснефть", LEI 253400JT3MQWNDKMJE44, RU
> - **Findings:** 19 relevant (19 lead); no single strongest finding (19 tied at lead); 16 unrelated or low-relevance records were set aside (see JSON).
> - **Biggest gap:** ownership unresolved at the registry record (the walk ended before a natural person).
> - **Not covered:** sanctions lists NOT screened: OpenSanctions, EU Consolidated List; expected source classes not searched: beneficial_ownership, court_dockets.
> - **Next step:** escalate, trigger fired: A sanctions hit, 50% rule block or PEP link: refer to compliance counsel (sanctions/PEP listing on three names ...).

Bottom line of the Bombardier Inc report (trimmed):

> - **Sanctions:** partial; Screened: Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List; NOT screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
> - **Registry:** BOMBARDIER INC., LEI W7L3VLU8EHQY34Z36697, ACTIVE, CA-QC
> - **Findings:** 14 relevant (14 lead); no single strongest finding (14 tied at lead); 13 unrelated or low-relevance records were set aside (see JSON).
> - **Biggest gap:** ownership unresolved at BOMBARDIER INC. (CA-QC) (the walk ended before a natural person).
> - **Not covered:** expected source classes not searched: beneficial_ownership, court_dockets; partial coverage: corporate_registry (nonprofit_990s not reached).
> - **Next step:** No escalation indicated on the public record; to go further order the registry filings and corporate documents from the primary registry (Registraire des entreprises du Québec).

Read these as leads: every sanctions line is a name match to verify on the primary list, "19 lead" means each
finding rests on a single source, and an empty `beneficial_ownership` or `court_dockets` class in these runs means the Companies House key and the
CourtListener token were not set (both logged as skipped), not that nothing exists.

---

## 3. Flags (`trace` and `intake`)

| Flag | Default | Notes |
|---|---|---|
| `--pi` | off | Turns the stream on. Every flag below is an error (exit 2) without it. |
| `--case-type` | `due_diligence` | `locate`, `background`, `asset_search`, `due_diligence`, `fraud_screen`, `missing_person`. |
| `--purpose` | none | **Required with `--pi`.** At least 15 characters after trimming; passes the gates in section 4. |
| `--purpose-category` | none | **Required with `--pi`.** The attested permissible purpose, one of `judgment_enforcement`, `litigation_support`, `service_of_process`, `asset_recovery`, `fraud_investigation`, `counterparty_due_diligence`, `regulatory_compliance_kyc`, `journalism_public_interest`, `authorities_referral`. A missing or unknown value exits 2 and lists them. A person subject is limited to seven of the nine (every category except `regulatory_compliance_kyc` and `journalism_public_interest`) and always needs a valid `--matter-ref`. Stored in the engagement and shown in the report. There is deliberately no employment, tenancy, credit or insurance category. |
| `--client` | empty | Recorded in the engagement; free text. |
| `--matter-ref` | empty | Case number, contract or judgment reference. **Required for every person subject, under every category and case type**; optional for an entity, but if given it must look real (format check only, see section 4). |
| `--subject-type` | `person` | `person` or `entity`. Changes which gates and identifier warnings apply. With `entity`, a seed, any `--org` or a consumer-mail `first.last@` address that reads like a person is refused unless `--confirm-entity` is given. |
| `--confirm-entity` | off | Overrides the person-vs-entity check for a seed that reads like a person (for example "Maple Leaf Roofing", no legal form). Only meaningful with `--subject-type entity`; it overrides the check completely. |
| `--pi-jurisdiction` | empty | e.g. `us`, `ca-on`, `uk`. Picks the legal instrument named for each custodian; unknown or empty falls back to a generic cross-border route (MLAT, letter of request). |
| `--pi-report` | none | Path for the Markdown report. |

`--cred` is refused with `--pi` (exit 2). The usual `--gear`, `--depth`, `--breadth`, `--hypothesis`,
other selector flags work as before. `--proxy` and `--tor` are global flags and go before the command
(`bunnyhole --tor trace ...`). `--hypothesis` appears in the report's
*Client theory vs. evidence* section.

---

## 4. Gates: what is refused, and the honest limits

Each gate prints a red panel and exits with code 2. Nothing is searched.

| Gate | When it applies | Refuses | Why |
|---|---|---|---|
| Purpose required | `--pi` | No `--purpose`, or under 15 characters | A written purpose is what separates a professional inquiry from curiosity. |
| Permissible-purpose category (the allowlist) | `--pi`, every case type | A missing or unknown `--purpose-category`; for a **person** subject, `regulatory_compliance_kyc` and `journalism_public_interest`; and for a person every category without a valid `--matter-ref` | The structural gate: a phrase blocklist can never reach full recall, so the engagement must name one of nine permissible purposes. Employment, tenancy, credit and insurance decisions have no category and are refused by construction. The category is attested by the operator and cannot be verified. |
| Every free-text field | `--pi`, trace and intake | The eligibility, motive and pursuit screens below run over the concatenation of `--purpose`, `--client`, `--matter-ref`, `--hypothesis`, `--dump`, the seed and every `--org`, `--email`, `--domain`, `--username`, `--phone`, `--wallet`, `--exclude` and `--doc` value (long input in overlapping chunks) | Moving a wording into another field no longer bypasses a screen. Evidence file *contents* are not read here. |
| Text too long to screen | `--pi`, any free-text field | Any single text over 150,000 characters (`--purpose`, `--client`, notes, `--dump`, a selector): refused with "too long to screen safely". Fail-closed: Bunnyhole will not skip any part of a field. | An unscreened tail would be a bypass. Workaround: trim the text, or split it into separate runs. |
| Credential-shaped text in the engagement record | `--pi` | Credential-shaped text (`email:secret`, `password: x`, `pw=x` ...) in `--purpose`, `--client` or `--matter-ref`: exit 2, and the text is never echoed | These fields are stored in the engagement and printed in the report. Credentials found in an intake packet or `--dump` are instead dropped and scrubbed (see below). |
| Category contradicts the text | `--pi` | A declared category whose purpose text describes an eligibility decision (for example `litigation_support` plus "check a tenant") | The phrase screens stay as a cross-check on the attested category: "declared purpose contradicts the described use". |
| Eligibility purposes | Every case type and subject type | A purpose naming an employment, tenancy, credit, loan or insurance decision: a long list of phrases (`employment screening`, `pre-employment`, `job applicant`, `new hire`, `tenant screening`, `prospective tenant`, `credit application`, `creditworthiness`, `credit score`, `credit history`, `nanny`, `babysitter`, `insurance underwriting` ...), assessing verb plus role wordings in either order within about six words (`vet`, `screen`, `check`, `verify`, `underwrite`, `reference check`, `trustworthiness` next to `tenant`, `lodger`, `housekeeper`, `employee`, `borrower`, `policyholder`, `incoming CFO` ...), a few Spanish, French and German stems (`solicitante`, `inquilino`, `locataire`, `Bewerber`, `Mieter`, `Kredit...`) and a set of patterns (`whether to hire`, `safe to rent to`, `applicant`, `candidate`, `before leasing` ...). Bare `hiring` and `underwriting` are not on the list. `before onboarding` counts as an eligibility cue only next to a person role (`new employee`, `new hire`...), and is exempt under the `regulatory_compliance_kyc` category; the wording `onboarding as a ...` still refuses. | Eligibility decisions are FCRA-regulated consumer-report territory; use an FCRA-compliant screener. |
| Motive screen | Person subject **and** case type `locate`, `background` or `missing_person` | Former-partner and evasion wordings: `ex-` and `former` partner, wife, husband, girlfriend or boyfriend, `my ex`, `estranged`, `ghosted`, `blocked me`, `left me`, `broke up with me`, `stalk`, `revenge`, `protective order`, `restraining order`, `she moved`, `he moved`, `won't talk to me`, `avoiding me`, `changed her number`, `get back at`, and similar | Locating a former partner or someone avoiding the client is the stalking pattern. The refusal points to law enforcement or counsel. |
| Pursuit screen | **Every** case type and subject type, including `entity` | Wordings about pursuing someone who is avoiding the client: `blocked me`, `won't talk to me`, `deleted her accounts`, `where she lives`, `current address of my ex`, `changed her number` and similar | An entity subject is self-declared and can be a lie. |
| Former-partner relationship terms | Person subject on a **non-locate** case type (`asset_search`, `due_diligence`, `fraud_screen`) | `ex-wife`, `estranged husband`, `former spouse` and similar, unless the category is `asset_recovery` or `litigation_support` AND a valid `--matter-ref` is given. A reference alone no longer lifts the screen, and it never lifts the pursuit screen | A divorce, support or custody proceeding is a legitimate asset search; under any other category, or without a reference, it is refused. |
| Matter reference | Every **person** subject (required, any category and case type); any supplied reference (checked) | An empty `--matter-ref` for a person; a reference under 5 characters, a placeholder (`TBD`, `test`, `12345`, `abc`...), or one with neither a digit nor a `v.`/`vs` party pair | Format check only: nothing is looked up in any court or contract system, so a made-up reference such as `CV-2024-0001` passes. |
| Subject-type check | `--subject-type entity` | A seed, any `--org`, or a consumer-mail `first.last@` address that reads like a person: two or three words with no organisation word, `Last, First`, a four-word name with a common given name, with honorifics and suffixes ignored. A `first.last@` address at a non-consumer domain counts only for an email-only intake. | The subject type is self-declared, and declaring `entity` skips the person gates. Add a legal form (`Inc`, `Ltd`, `LLC`), use `--subject-type person`, or pass `--confirm-entity`. |
| Credentials | `--pi` | `--cred`; a seed that is only a credential | Breach and credential contents are not used in PI mode. |
| PI flags without `--pi` | Any run | `--case-type`, `--purpose`, `--purpose-category`, `--client`, `--matter-ref`, `--subject-type`, `--confirm-entity`, `--pi-jurisdiction` or `--pi-report` given without `--pi` | Never silently ignored. |

Text is normalised before matching (case, punctuation and hyphen spelling, full-width forms, zero-width
characters), and a second "skeleton" pass catches disguised spellings: homoglyphs (Cyrillic or Greek lookalikes),
leetspeak (`pre-3mployment`), spaced-out letters (`p r e - e m p l o y m e n t`), HTML and percent encoding,
and one typo on a curated set of high-risk phrases of 8 or more letters. A few non-hiring senses are
exempted: an acquisition, political or clinical "candidate"; a "patent", "permit", "visa" or "court" applicant,
or an "applicant company"; and trade or supplier credit.

**Breach and active-probe blocks in PI mode.** Credentials in intake packets or pasted dumps are dropped and
scrubbed before any parsing: `email:secret` tokens (including quoted ones), `user:pass`, email followed by a
separator (`|`, `;`, `,`, `-`, `/`, `=`, `=>`) and a secret, keyword forms (`password: x`, `pw=x`, `password is x`, also
`passcode`, `Passwort`, `contraseña`, `mdp`, `mot de passe`, `clave`), quoted-key JSON (`{"password":"x"}`, `pass`,
`pwd`, `secret`, `token`, `api_key`), URL userinfo (`https://bob:x@acme.com/` keeps `https://acme.com/`) and an email
plus secret near a password keyword. In an intake, the raw text and every field are scrubbed before the parser derives
selectors, so a password cannot become an "email" or a username. Nothing is derived from them, not even the email half; this is logged once as a skipped
`credentials` entry. Breach and infostealer lookups (Hudson Rock, LeakCheck, EmailRep, the credential combo)
are blocked everywhere they could run, and Holehe-style sign-up and account-recovery probes are blocked; each
is logged as `skipped`. The DexScreener token-name search is skipped for name-driven leads.

Identifier warnings are advisory only: a person subject without a full name or without one more anchor
(username, email, phone, wallet, domain) gets a warning in the report, not a refusal.

**Limits. These screens are a safety net, not a guarantee.**

*Known over-refusals* (a legitimate purpose that trips a gate):
- `candidate for takeover` (only the form `takeover candidate` is exempt), any "applicant" or "candidate" wording outside those exempted forms ("an applicant in a separate patent matter" is refused), `nanny` or `babysitter` even in a fraud matter, `credit score` or `credit history` even when enforcing a judgment, and lease wording such as `before leasing premises` in a landlord due-diligence purpose.
- `former partner` or `estranged` even for a law-firm partner or director, and `he moved` or `she moved` in an unrelated sense, on person locate and background engagements.
- A relationship term such as `ex-wife` on an asset search unless the category is `asset_recovery` or `litigation_support` AND a valid `--matter-ref` is given.
- An assessing verb near a person role: `vet`, `screen` or `due diligence` near `employee`, `borrower`, `intern` or `volunteer` ("screen the employees of the target against sanctions lists", "due diligence on the borrower entity"); `check`, `verify`, `review` or `confirm` near `tenant`, `lodger` or `occupant` ("check whether the tenant is the judgment debtor"); `new accountant` or `new engineer` with an assessing verb; `before onboarding` and `employment verification` even for a vendor or a judgment debtor's employer.
- Wordings about someone who ignores the client, applied to every case type and subject type: `ignored my emails`, `dodging my calls`, `keep tabs on`, `stalking` (except `stalking horse`), `where the tenant works`, `find his address` or `get her phone number`, `report me`, `dump me`.
- Spanish, French and German stems with a second meaning (`solicitante` of a patent, `Kreditkarte`, `candidat`).
- Any entity name with no legal form or organisation word (for example "Maple Leaf Roofing") or any `--org` that is a person's name, which needs a legal form or `--confirm-entity`.
- Rewording the purpose to say what the matter is can clear a false positive. It does not make a real eligibility or pursuit purpose acceptable.

*Known remaining bypasses:*
- **The phrase blocklists have incomplete recall.** The author of the vocabulary measured how many fresh eligibility and pursuit paraphrases were refused on first contact: not all of them, and the vocabulary was then extended to the misses, so recall on wordings nobody has tried yet is lower than that. Examples that still pass: `assess a worker before we put her on the crew`, `a bank wants to understand the finances of the person seeking a small business loan`, `get the home address of the referee who sent me off`. The category allowlist, not the phrase lists, is the structural gate.
- **The category is attested, not verified.** Lying in `--purpose-category` (for example `litigation_support` for a tenant check worded neutrally) passes the allowlist; only the phrase screens remain. The same holds for `--matter-ref` (format only) and for `--subject-type entity` with `--confirm-entity`, which skips the person-only rules (the narrower person categories and the person matter-reference requirement) while the eligibility and pursuit screens still apply.
- The free-text screens read the command line only. The contents of an evidence file named with `--doc`, and any text typed into the interactive menu after the run starts, are not screened.
- Homoglyphs outside the built-in map, and obfuscations the skeleton pass does not fold, pass.
- `--confirm-entity` overrides the subject-type check completely, and a false `--subject-type entity` then skips the person-only gates (the motive screen, the narrower person categories and the person matter-reference requirement); the pursuit screen and eligibility screen still apply.
- `--matter-ref` is format-only: any reference with a digit passes, whether or not the matter exists.
- Credential scrubbing misses a secret in a shape it does not recognise (for example a plain lowercase word after a comma with no keyword); keep credentials out of intake text.
- Bunnyhole cannot verify that the purpose is true or that the person typing is the client.

The operator remains responsible for lawful use. Do not use the stream for any purpose you would not state to
the subject's lawyer.

---

## 5. The legal filter

| In scope (free, lawful, passive) | Out of scope | Why |
|---|---|---|
| Government, registry and court sources; open APIs | Credit-header databases: TLOxp, Tracers, IRBsearch, idiCORE, Accurint, CLEAR, SkipSmasher, Delvepoint; credit bureaus (Experian, Equifax) | Licence, permissible purpose and site audit required. Hand off to a licensed investigator. |
| Passive OSINT: no login, no password reset, no contact | License-plate-reader data | Resold under permissible use via licensed platforms. |
| Public-record corporate and ownership walks, sanctions screening, the OFAC 50% rule | Consumer people-search sites (Intelius, BeenVerified, Spokeo and similar) | Stale data and terms-of-service breaches. |
| SHA-256 receipts and chain-of-custody logging | Pretexting, tracker placement, audio recording or interception, account access, hacking, phone pings, sealed or expunged records, medical records | Unlawful or legally sensitive by method; hiring someone who promises them exposes the client. |
| Naming the custodian of non-public records and the legal instrument that reaches it | Eligibility decisions (employment, housing, credit, insurance) | FCRA. Checkr and Sterling are listed as the FCRA-compliant route. |
| Breach *exposure* signals already in Bunnyhole | Breach *contents* against private individuals (DeHashed and similar) | Legally sensitive; skipped and logged in PI mode. |
| | Paid email/phone-to-account services; Orbis, Sayari, Dun & Bradstreet; Chainalysis, TRM, Elliptic | Paid enterprise tiers outside the free layer. |

Full lists and the jurisdiction rules: `bunnyhole pi out-of-scope` and `bunnyhole pi legal`. Ontario and
Canadian items (PSISA 2005 licensing, PIPEDA, Criminal Code s.184 and s.264) are marked unverified in the
catalog: verify with the Ministry of the Solicitor General and counsel.

---

## 6. Case-type playbooks

Reference material from `bunnyhole pi playbook <type>`. The live run uses only the objective; the order,
stop-ifs and escalation triggers guide the human.

| Case type | Done when | Order of work | Escalate when |
|---|---|---|---|
| `locate` | An address or contact has 2+ independent sources, each dated within 12 months, or a documented dead end | Anchors > dockets > property, officer and licence records > custody status > social footprint > age and corroborate > hand off for credit-header confirmation | Sources disagree and neither is fresh; evasion; any sign the client is a former partner (stop) |
| `background` | Identity resolved on 2+ anchors; each history element labelled; searched sources and negatives shown | Identity > litigation > corporate roles > sanctions/PEP > adverse media > licences > report with eligibility notice | Client wants it for an eligibility decision (stop); identity unresolved beyond a name |
| `asset_search` | Every asset has a named owner and a chain to a natural person or a documented unresolved node, with custodians for process | Entity and subject > registry documents > 12-step ownership walk > sanctions and 50% rule > property, liens > vessels, aircraft > crypto > lifestyle vs income > litigation > custodians | Bank or exchange account indicated; chain ends at a nominee or secrecy jurisdiction; cross-border; any sanctions hit |
| `due_diligence` | Registry, ownership, sanctions/PEP, litigation and enforcement, adverse media and jurisdiction risk each addressed | Registry > ownership walk > sanctions/PEP > litigation, enforcement, complaints > adverse media > jurisdiction risk | Sanctions hit, 50% rule block or PEP link; nominee chain; non-public records needed |
| `fraud_screen` | Each indicator labelled; consumer claims marked unverified; money trail reaches a custodian | Anchor > enforcement and complaints > shell-company red flags > lookalike domains > public ledgers > custodians | Funds reach a bank or KYC exchange; victims at ongoing risk; cloned entity |
| `missing_person` | Identifier set compiled, public databases searched, matches packaged for authority | Identifiers > missing and unidentified-persons databases > obits and records > public footprint > route to authority | Any possible match, any risk of harm: route to law enforcement, never to the client |

Each playbook also carries pitfalls and two to four competing hypotheses to keep open (for `asset_search`:
nominee holdings, dissipation or transfer, genuinely judgment-proof).

---

## 7. Report anatomy

`--pi-report` writes sixteen sections in this order (the list below is the heading list the code emits). Sections
with nothing to show say `None.`; where absence is worth stating it reads "None found in the evidence collected
(this is not proof that none exist)."

1. **Bottom line**: a short labelled list of at most six one-line bullets, each at most 220 characters, no model involved. Node ids are replaced by names, and a bullet that is too long is cut at a word boundary with an ellipsis. In order:
   - **Sanctions**: a hit leads and is always called a soft name match to verify on the primary list. Without a hit it gives the screening status (`not_run`, `partial` or `lists_run`), the lists screened, the lists NOT screened by name only (reasons are in the *Sanctions screening* section) and "no hit on a screened list is not clearance". It also carries `50%-rule: not evaluable (ownership percentages unknown)` next to a hit when the ownership edges have no percentages, and a note when other graph entities match a list entry. The EU Consolidated List is always named as not screened.
   - **Registry**: legal name, LEI, status, jurisdiction (and parents when they fit), only when a registry record matched the subject.
   - **Findings**: counts by label for the **relevant** findings only, the strongest finding, and how many unrelated or low-relevance records were set aside (see JSON). When several findings tie at the top it says "no single strongest finding (N tied at <label>)" rather than naming one.
   - **Biggest gap**: the single most important gap (contradiction, unresolved ownership, source classes not searched, partial coverage, evidence gap), with the other open items briefly.
   - **Not covered**: source classes not searched and partial coverage (and, when a sanctions hit takes the Sanctions bullet, the lists not screened).
   - **Next step**: for an entity due-diligence or background engagement, a fired sanctions, 50%-rule or nominee/secrecy trigger leads; otherwise any other fired trigger, but not the custodian-bearing one (it fires for every company); otherwise "No escalation indicated on the public record; to go further order the registry filings and corporate documents from the primary registry" with the registry named. For `asset_search`, `fraud_screen` and person subjects the escalation, custodian or production-order step remains the next step. Trigger reasons are trimmed.
2. **Engagement & scope**: ID (`pi_` plus 10 hex), case type, objective, purpose, the attested permissible purpose (`--purpose-category`; attested, not verified), client, matter reference, jurisdiction, subject type, seed, passive-only flag, conflict-check result, identifier warnings.
3. **Entity profile**: legal name, LEI, status, jurisdiction, registered address, parents and registry sources, built from registry nodes only (GLEIF, Companies House) that match the subject by name, by an alias the record carries, or by an LEI given as the seed. `None. No registry match for the subject.` otherwise.
4. **Client theory vs. evidence**: your `--hypothesis` and the ACH result if present, with a note when a sanctions hit sits beside an ACH that reports no anomalies (the ACH does not consider sanctions lists). A theory is a starting point, not proof.
5. **Findings**: finding, label, source count, freshness, relevance. Only `subject` and `related` findings are shown (a `related` row carries its reason). They are ranked by label, then source count (ties keep their original order), capped at 25 rows. Unrelated and unknown-relevance records are counted and left in the JSON result, except that up to five set-aside records whose titles mention a known related party (a parent or another entity in the ownership chain) are listed in a line `Set aside but possibly relevant (mentions a related party): ...`.
6. **Sanctions screening**: status, the lists screened, the lists NOT screened with the reason each was not reached, the hits (list, matched name, "SOFT MATCH: verify on primary list", URL), and a block *Other graph entities that match a sanctions-list entry (soft)* for entities the investigation found whose names match a listed entry. A name check is a lead, not a determination.
7. **Identity resolution**: notes on who the person records are. Same-name records that are not established as one person say so, with the reasons; two records agreeing on 2+ non-name anchors are noted as a probable same person; name collisions with namesake organisations are noted; a person subject with fewer than two anchors gets a standing "subject anchoring unverified" note. Candidates that matched only on a name and were not linked to a person subject appear as `Weak name match, not linked: ...` lines (see *Person subject: no linking on a name alone* below).
8. **Ownership chain**: child, parent, share, source, as-of date; levels walked; OFAC 50%-rule flags; nodes where the walk ended before a natural person.
9. **What is NOT a link**: flagged nodes with reason and severity. The subject's own registered-agent address is shown at severity `info` ("not evidence of a link"); another entity's shared agent address is `high`.
10. **Contradictions and gaps**: record conflicts and long gaps in the dated timeline. Gap lines are written only for `subject` and `related` nodes and use the node's name, not its id.
11. **What would change this conclusion**: the falsifiers, identical lines collapsed to `(x N)`, the per-lead lines merged into one summary, capped at 12.
12. **Coverage and negatives**: source-class matrix with a *Tried, not reached* column, partial-coverage notes, and every negative, skip and error.
13. **Playbook progress**: the case-type playbook's "Done when" (judged by a human, not by Bunnyhole), each step marked `DONE`, `PARTIAL`, `NOT RUN` or `NEEDS LICENSED LAYER` with evidence, and an escalation-triggers table (trigger, fired, why).
14. **Custodians and next steps**: custodian, instrument and jurisdiction per finding kind, and the handoff sheet.
15. **Chain of custody**: receipt ID, tool, URL, *Receipt digest (SHA-256)*, collection time. The digest covers the recorded extract (tool, URL, fact, snippet), **not the retrieved page**. For page-level preservation, archive the source pages yourself (Wayback Save Page Now, ArchiveBox, SingleFile).
16. **Limitations & legal notices**: standing notices (not a consumer report; leads not verdicts; absence is not proof; no licence implied; verify PSISA in Ontario), plus a note for each sanctions-list result that does not resemble the subject name and was not treated as a hit.

**Relevance.** Each finding is rated `subject`, `related`, `unrelated` or `unknown`, each with a stated reason. Names are compared after removing legal forms (including long, European and Cyrillic spellings), source prefixes such as `Wikidata Q123:` and accents, and after transliterating Cyrillic to Latin.
- `subject`: the name matches the subject's (small spelling tolerance on longer words, acronyms, aliases or an LEI the record carries).
- `related`: the name extends or shortens the subject's, or contains the whole subject name plus extra words (a probable affiliate), or an ownership or officer edge joins the node to a subject node. It means "worth reading", not "affiliation established".
- `unrelated`: no name match, or the extra words mark a different business, which is flagged as a possible name collision rather than dropped silently.
- `unknown`: nothing to compare, for example an IP address or wallet.

Financial-line and industry words (`bank`, `trust`, `fund`, `insurance`, `energy` ...) are not neutral, so "Apple Bank" is never "Apple Inc"; `oil`, `gas` and `petroleum` still are. News, forum and token nodes must carry every subject word as a whole word, with no spelling tolerance. The rating decides what the report shows; the JSON keeps everything.

**Person subject: no linking on a name alone.** With `--subject-type person` (the default) the name you give, through `intake --org "<full name>"` or as the `trace` seed, becomes a `Person` node (a name with a legal form such as `Ltd`, or an employer named next to it, stays an `Organization`; with `--subject-type entity` nothing changes). The name still goes to the registry, sanctions and news sources. Three rules keep a name search from linking the subject to someone else:

- **Name-derived account pivots.** A Keybase or GitHub user found by guessing a handle from a name token or an email local part (a handle you did not pass with `--username`) is attached to the subject graph only when the profile shows the subject's full name (a surname each, the surnames agree, the given names are compatible) AND one more anchor agrees: a domain you gave (the profile's site, a signed DNS proof or a commit address on it), an email you gave, a username you gave, or a company equal to your `--org` company or the label of your `--domain`. Otherwise it is recorded as a set-aside candidate. The local Sherlock sweep is not run for such a handle.
- **Sanctions and PEP entries** (Canada SEMA, OFAC SDN, UN, UK, OpenSanctions) become a graph node and edge when a listed name or alias is a compatible full name of ANY name you gave for the person, whatever its shape (a five-word name, "Jane Church", a name with a title or suffix). Names are compared with diacritics folded and case ignored, hyphen, space and comma as separators, and the same words in a different order (`Roe Jane` for `Jane Roe`) count as the same name. A match on given-name tokens only, or a different surname or a different spelling of it, is reported as `weak name match, not linked`; the receipts keep the "name match only; verify identifiers" wording for the entries that are linked. A one-word subject name links only an exact one-word match, flagged `WEAK_NAME_MATCH_SINGLE_WORD`. Every set-aside listing is also counted and its first three named in the report's Sanctions section and Bottom line (`weak name match, not linked; verify on the primary list`), so that section never reads as "no hit" without saying so; it is not clearance.
- **Analytics tables.** The interconnection paths, keystone brokers, predicted (Adamic-Adar) links and cut-out badges leave out a platform's own account (such as `@github`) in any PI run, and, with a person subject, every record the relevance scorer rates `unrelated` unless it hangs directly off a domain, email, username, phone, wallet or IP you supplied. The terminal summary skips the same nodes.

Set-aside candidates are not nodes or edges. They are kept in the JSON result under `set_aside_candidates` (label, tool, URL, reason, receipts) and named in the identity notes; excluded nodes stay in `nodes` and are listed under `set_aside_node_ids`. The ACH matrix still reads every edge in the graph.

**Reading the labels.** The count is the number of *independent* sources: distinct tools, with receipts that
share a URL host and path counted once. It measures corroboration, not truth.

| Label | Sources | Treat as |
|---|---|---|
| `confirmed` | 3 or more | Corroborated; still verify before acting on anything consequential |
| `probable` | 2 | Likely; seek a third source |
| `lead` | 1 | Unverified; do not rely on it |

Freshness: `fresh` is up to 12 months old, `aging` up to 36, `stale` beyond; registry records use 24 and 60
months; `unknown` when no date is recorded. The report never prints a label stronger than the source count supports.

**Coverage.** Each expected source class for the case type is `yes` or `NOT SEARCHED`. A class counts as
searched only when a mapped source returned a hit or a clean negative. The recorder also watches the HTTP
traffic of each source call: a source that got a 401, 403 or 429 is logged `skipped` (refused, for example no
key or rate limited), any other HTTP error or transport failure is logged `error`, and neither counts as
searched. Sources that were tried but not reached are listed in the *Tried, not reached* column, and a class
that was searched by one source while another failed carries a `partial` note. A source whose records are all about someone else is logged as `negative` with "records found but none about the subject" and does not count as a coverage hit. Read `NOT SEARCHED` as a task
list, not as a clean result.

**Playbook progress.** `DONE` means every automated source that step lists ran (hit or clean negative), not
that the topic is exhausted; it is rare by design. `PARTIAL` means some ran, `NOT RUN` means none did or the
step has no automated source, and `NEEDS LICENSED LAYER` marks steps that belong to a licensed investigator
or counsel. "Done when" is a human judgement.

**Custodians and handoff.** For finding kinds such as an exchange deposit address, a phone number, a
registered agent, an IP, a domain or an employer, the report names the holder and the instrument for the
engagement jurisdiction (for example a subpoena or court order in the US, a Norwich Pharmacal order in
Ontario or the UK, MLAT or letter of request cross-border). The handoff sheet turns that into lines a
licensed investigator or counsel can act on. For an entity subject the sheet gives action lines such as "Verify the sanctions hit on the primary list: <url>" (or the lists that were not screened) and "Confirm corporate status and beneficial ownership on the primary registry", rather than "Run through licensed database" for company addresses; person subjects and `locate` or `missing_person` cases still get the licensed-database and field-verification lines. Nothing is sent by Bunnyhole.

---

## 8. Free sources added by this stream

Queried only for company and person-name leads. The new sources use the proxy-aware client (`--tor`,
`--proxy` apply) and degrade to a logged skip or negative instead of raising.

| Source | Access | Gives you | Notes |
|---|---|---|---|
| Companies House PSC (UK) | Free API key | Persons with significant control; ownership bands feed the ownership walk | Key is read as `UK_COMPANIES_HOUSE_API_KEY` (the key-vault name; set it with `bunnyhole keys --set UK_COMPANIES_HOUSE_API_KEY=...`) or `COMPANIES_HOUSE_API_KEY` (accepted as an alias: exported, or `keys --set COMPANIES_HOUSE_API_KEY=...`, which stores it under the `UK_` name). Without a key the source logs a skip. Name matches are soft. |
| Canada SEMA, OFAC SDN, UN Security Council consolidated list, UK Sanctions List | Keyless | Name match against each official list | Soft name matches only, to verify on the primary list. OFAC, UN and UK are streamed XML with a 40 MB cap, a 24 h on-disk cache under the Bunnyhole config directory (`cache/sanctions/`) and a stale-cache fallback if a download fails; payloads with a DOCTYPE or ENTITY declaration are refused. SEMA is the older path: in-memory per process, 10 MB cap, up to 5 matches, no disk cache. |
| OpenSanctions | Optional (key or self-hosted yente) | Consolidated sanctions and PEP screening | Not part of a keyless run. See [PERSONALIZATION.md](PERSONALIZATION.md). |
| EU consolidated list | Not automated | Nothing | Never screened. Every report names it under NOT screened ("not automated, verify at the EU sanctions map") whatever the status, so check it manually. |
| CourtListener (RECAP dockets) | Free account token | Federal dockets | Set `COURTLISTENER_API_TOKEN` (`bunnyhole keys --set COURTLISTENER_API_TOKEN=...`). Unauthenticated calls return 401 and are logged `skipped`, so `court_dockets` shows as not reached. |
| CFPB consumer complaints | Keyless | Complaint count and top issues for a US financial firm | Consumer claims are unverified (`UNVERIFIED_CONSUMER_CLAIMS`). |
| Wikidata | Keyless | Entity-resolution aid: QID and description | Community-edited; verify against the primary registry. |

**Sanctions status.** `lists_run` means all five automated lists (SEMA, OpenSanctions, OFAC SDN, UN, UK) were
screened, `not_run` means none was, and anything else is `partial`. The EU list is never automated, so it is
named as not screened in every report, including a `lists_run` one. A keyless run has no OpenSanctions, so it
reads `partial` at best. A hit is always a soft name match; a list result whose name does not resemble the
subject is not counted as a hit and is noted under *Limitations & legal notices*. Other entities the
investigation found whose names match a sanctions-list entry are flagged "matches a sanctions-list entry (soft)"
and shown in a separate block in the *Sanctions screening* section; they are not the subject's own hits.

The full catalog (99 free sources, of which 25 are queried today as of this writing; the counts are derived from the catalog, so trust the command over this number, with access tier, caveats and a
verified flag) is `uv run bunnyhole pi sources`, or `pi_reference` over MCP. Rows not marked verified need
checking before reliance.

---

## 9. Adding a source

See `PISourcesAgent` in `bunnyhole/agents/pi_sources.py` and the list machinery in
`bunnyhole/agents/sanctions_lists.py`.

1. **Add the method** to `PISourcesAgent`, or to the agent that fits (a new sanctions list is a list spec in the list machinery, not a new download routine). Follow the conventions there: build the HTTP client with `netutil.new_async_client` (so `--tor` and `--proxy` apply), time out, never raise (log an agent event ending in `_SKIP` for a skip, `_INFO` for a clean negative), mark name matches `SelectorStrength.SOFT` with a `SOFT_NAME_MATCH_VERIFY` flag, give the receipt the source's Admiralty grade and the edge the weaker match grade.
2. **Dispatch it** in `BunnyholeOrchestrator._execute_lead` through `pi(<source_name>, value, coro)` so the call is logged as hit, negative, skipped or error.
3. **Map it to a source class** in `SOURCE_CLASS_MAP` in `bunnyhole/engine/pi_runtime.py` (`<source_name>` to one of the source classes in `pi_analysis`). Map only to the class it really searches. An unmapped source appears in the source log but never inflates coverage.
4. **Catalog it** with an entry in `pi_reference.SOURCES` (`implemented=True`, an https URL, an honest `access` tier and `caveats`). Do not mark `verified=True` unless you called it.
5. **Test it** with mocked HTTP (see `tests/test_pi_sources_registries.py` and `tests/test_pi_sources_sanctions.py`): no key gives a skip, HTTP 500 and timeout never raise, a hit adds a soft-flagged node.

---

## 10. Known limitations

- **Soft name matches.** Sanctions, PSC and Wikidata hits match on name and are flagged for verification. Two different people or companies can share a name.
- **Keyless runs are not fully screened.** OpenSanctions needs a key (or self-hosted yente) and the EU list is not automated, so a keyless sanctions status is `partial`, never `lists_run`, and the EU list is named as not screened even then. No hit on the lists screened is not clearance.
- **The 50% rule fires rarely and is often not evaluable.** It needs a percentage on an ownership edge. Percentages come only from ownership edges carrying a share midpoint (such as PSC bands); an edge with no percentage counts as zero and is never reported as blocked. When edges exist but none carries a percentage, the report says `50%-rule: not evaluable (ownership percentages unknown)` next to a sanctions hit instead of staying silent. A quiet result is not clearance.
- **Nominee and secrecy trigger.** The playbook trigger says the chain "ends at a nominee or secrecy jurisdiction", and it now fires only on evidence of that: a nominee flag, a nominee or secrecy risk flag, or a secrecy-jurisdiction parent. An unresolved chain alone (a listed company, a registry that stops) leaves the trigger off and the text says no nominee or secrecy evidence was found.
- **The HTTP observer sees only async `httpx` traffic.** Subprocess tools (the external OSINT CLIs) and sync HTTP clients are invisible to it, so their failures are not detected from the traffic. Redirect hops are not reported separately.
- **`--proxy` and `--tor` do not cover everything.** Every HTTP client is built through the shared factory (`netutil.new_async_client`, guarded by a test), so all Python HTTP traffic honours the proxy. Not covered: `dnspython` DNS lookups (system resolver) and the local programs Bunnyhole launches (`whois`, `subfinder`, `sherlock`, `holehe`). Do not rely on `--tor` alone for anonymity in PI runs.
- **Negatives are still partly inferred.** Some agents catch their own errors and log them as `*_INFO`, which the recorder cannot tell from "nothing found" unless the failure shows up in HTTP traffic. Any HTTP 404 on a call that produced no nodes is read as `error`, even when a 404 is the source's normal "no such record". Check the logged detail when a negative or error matters.
- **The relevance scorer is a name comparison.** Only Cyrillic is transliterated (with a simple scheme); other scripts such as Arabic and Chinese are not, and only aliases bridge them. A different organisation with the same whole name in a different industry (a namesake, "Delta" the airline and "Delta" the faucet maker) can score `subject`. The affiliate and different-business word lists are finite: an unlisted extra word is called a probable affiliate, and a real affiliate in a listed line (a bank) is flagged a possible collision. The legal-form phrase list covers common European and Cyrillic forms only. Articles, filings and tokens are judged by their titles alone. Unrelated filtering can hide a real affiliate that has no ownership or officer edge to the subject. The JSON keeps every record.
- **Entity profile picks by completeness.** When several registry records match the subject (by name, alias or LEI), the one with the most fields leads and the others fill blanks; that is not the same as the right record.
- **Identity notes are advisory.** They score Person records against each other on the attributes the sources recorded; they never merge graph nodes and do not use graph edges. Name-collision notes say a namesake exists, not that it is or is not the subject. A name alone is never treated as an identity.
- **The two-anchor rule is a name comparison.** A surname is the last word of a name, so a hyphenated surname matches a listing that shares one part of it (`Roe-Smith` and `Smith`), and a different spelling of a surname (`Roe`, `Rowe`) does not match. A legitimate account whose profile shows no name, or a different spelling of the name, is set aside; a set-aside candidate is a lead to check by hand, not a clearance. Only Keybase, GitHub and the sanctions lists above are gated this way; other name searches (news, dockets, registries) still enter the graph and are filtered by relevance only in the analytics tables. The terminal TUI (`bunnyhole/tui/app.py`) and the MCP server (`bunnyhole/mcp/server.py`) still rank every node, including the ones the analytics tables left out; only the CLI summary reads `set_aside_node_ids`. The ACH matrix reads every edge. A targeted `--source/--target` path to a set-aside node returns no path and says the endpoint was set aside as unanchored (`targeted_path_note`).
- **Conflict check is substring matching.** It searches the case vault's entity memory; short or common seeds can produce unrelated prior-case hits (minimum 3 characters).
- **Findings count tools, not truth.** A node's label reflects distinct sources, and two tools that read the same underlying record can still look independent if their URLs differ. The custody digest is of the recorded extract, not the page.
- **Coverage gaps by construction.** No source is mapped to `missing_persons` or `vital_records`, so a `missing_person` run always reports them `NOT SEARCHED`; `property_assets` is covered only by aircraft tracking, not land or lien registries; `court_dockets` needs a CourtListener token.
- **Attestations are not verified.** Lying in `--purpose-category` or passing `--confirm-entity` for a person passes the gates, `--matter-ref` is format-only, `--doc` contents are not screened, homoglyphs outside the built-in map pass, and the phrase blocklists have incomplete recall (section 4).
- **Playbooks are not executed.** The run uses the playbook objective, then scores progress afterwards. A `DONE` step is rare by design and still does not mean the topic is complete.
- **Companies House.** Unit tests use mocked responses. Unless you have run it with a real key, treat the parser as untested against the live API.
- **Ontario and Canada.** PSISA licensing, PIPEDA, Criminal Code s.184 and s.264 are marked unverified. Verify with the Ministry of the Solicitor General and counsel.
- **Single pass.** One run, one human gate. There is no loop and no oracle; corroborate before relying.

---

## MCP

The [MCP server](MCP_SERVER.md) exposes one read-only tool, `pi_reference` (`kind`: `guide`, `sources`,
`legal`, `playbook`, `out_of_scope`). No MCP tool runs a PI engagement, so the purpose gates are only
reachable from the CLI.

---

**Not legal advice.** This document and the output of the PI stream are research information. Laws vary by
place and change; verify current requirements with counsel before relying on any rule, and consult a lawyer
before investigating real subjects.
