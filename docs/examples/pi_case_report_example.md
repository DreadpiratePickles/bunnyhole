<!-- Generated offline by tests/pi_case_world.py: a scripted public record with invented companies. No network, no provider key, so the account is the code-written one. A run with a key replaces the Investigation report section with the AI-written account and adds the case officer's readings to the log. -->

# Bunnyhole PI report: Northgate Trading Ltd

## Bottom line

- **Case:** stop dead_end; 6 questions: 4 answered, 2 partly answered; not settled: ownership, litigation
- **Sanctions:** partial; Screened: Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List; NOT screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
- **Registry:** NORTHGATE TRADING LTD, LEI 213800NORTHGATE00001, ACTIVE, GB; parents: Borealis Holdings B.V.
- **Findings:** 4 relevant (4 lead); no single strongest finding (4 tied at lead).
- **Biggest gap:** ownership unresolved at Kestrel Nominees Ltd (CY) (lei:549300KESTREL0000003) (the walk ended before a natural person); also open: 1 more item.
- **Not covered:** expected source classes not searched: beneficial_ownership, court_dockets.

## Investigation report

*Written by code from the case file. No model wrote any part of this account.*

### Summary

This was a due diligence engagement on Northgate Trading Ltd. The objective was: Give the client a counterparty-risk picture: who the entity is, who owns it, whether it is sanctioned, and what litigation, enforcement, complaints and media say. The investigation worked 10 lead(s) with 28 source call(s) and stopped because every lead was worked and the free public record had nothing further to give. Of the 6 question(s) the engagement turns on: 4 answered, 2 partly answered. Nothing below is a clearance: a source that returned nothing is a logged negative, and a name match is a lead until identifiers are verified.

### How the investigation unfolded

The case opened with 5 lead(s) on the sheet: the playbook's order of work applied to what the client supplied. From there each result decided the next step. A lead was opened only when a record gave a reason for it, and each entry below says what that reason was. The sheet was worked in priority order by code; no model was involved.

First, L1, step 1 of the playbook, was worked on Northgate Trading Ltd. Confirm the entity in its registry and resolve its identity; use Wikidata only as an aid. 4 sources were run: Companies House, Wikidata, GLEIF and SEC EDGAR. GLEIF returned a record. Wikidata and SEC EDGAR returned nothing. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). 2 new record(s) came back, 2 about the subject or its chain: NORTHGATE TRADING LTD (GB) and Borealis Holdings B.V. (NL). The identity question moved from open to answered. Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001. The ownership question moved from open to partly answered. Corporate chain above the subject, 1 level(s) walked: Borealis Holdings B.V. The chain stops at Borealis Holdings B.V., with no owner behind it on the public record. The structure question moved from open to answered. Registered in GB; no secrecy-jurisdiction or nominee marker in the 1 chain node(s) walked. FATF list status is checked by hand. This opened L6 (walk the ownership of Borealis Holdings B.V.), L7 (screen Borealis Holdings B.V.) and L8 (find a second source for Borealis Holdings B.V.).

L2, step 2 of the playbook, was worked on Northgate Trading Ltd from records already on file (Companies House and GLEIF had run for an earlier lead), so it cost no new call. Walk beneficial ownership using the 12-step UBO workflow. GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). On those records the identity question is answered. Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001. On those records the ownership question is partly answered. Corporate chain above the subject, 1 level(s) walked: Borealis Holdings B.V. The chain stops at Borealis Holdings B.V., with no owner behind it on the public record. On those records the structure question is answered. Registered in GB; no secrecy-jurisdiction or nominee marker in the 1 chain node(s) walked. FATF list status is checked by hand.

L6 was walked upward on Borealis Holdings B.V. Borealis Holdings B.V. is named as an owner of NORTHGATE TRADING LTD. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. 2 sources were run: GLEIF and Companies House. GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). 1 new record(s) came back, 1 about the subject or its chain: Kestrel Nominees Ltd (CY). The ownership question is still partly answered, with more detail. Corporate chain above the subject, 2 level(s) walked: Borealis Holdings B.V. \> Kestrel Nominees Ltd. The chain stops at Kestrel Nominees Ltd, with no owner behind it on the public record. The structure question is still answered, with more detail. Yes: Kestrel Nominees Ltd is registered in CY. That is a reason to require the beneficial owner in writing, not a finding against the entity. This opened L9 (walk the ownership of Kestrel Nominees Ltd) and L10 (screen Kestrel Nominees Ltd).

L9 was walked upward on Kestrel Nominees Ltd. Kestrel Nominees Ltd is named as an owner of Borealis Holdings B.V. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. 2 sources were run: GLEIF and Companies House. GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). No new record came back. No owner is recorded above Kestrel Nominees Ltd in the sources reached. On the public record the chain stops here: the next step is the primary registry or the registered agent's file (see Custodians).

L3, step 3 of the playbook, was worked on Northgate Trading Ltd. Screen sanctions and PEP status for every node, including the OFAC 50% rule. 5 sources were run: OpenSanctions, the OFAC SDN list, the UN Consolidated List, the UK Sanctions List and the Canada SEMA list. The OFAC SDN list, the UN Consolidated List, the UK Sanctions List and the Canada SEMA list returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back. The sanctions question moved from open to partly answered. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 1 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.

L7 was screened on Borealis Holdings B.V. Borealis Holdings B.V. sits in the ownership chain above NORTHGATE TRADING LTD. Every node of the chain is screened, not only the subject. 5 sources were run: the Canada SEMA list, OpenSanctions, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List. The Canada SEMA list, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back. The sanctions question is still partly answered, with more detail. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 2 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.

L10 was screened on Kestrel Nominees Ltd. Kestrel Nominees Ltd sits in the ownership chain above Borealis Holdings B.V. Every node of the chain is screened, not only the subject. 5 sources were run: the Canada SEMA list, OpenSanctions, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List. The Canada SEMA list, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back. The sanctions question moved from partly answered to answered. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 3 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.

L4, step 4 of the playbook, was worked on Northgate Trading Ltd. Search litigation, enforcement and complaints. 2 sources were run: CourtListener dockets and the CFPB complaint database. SEC EDGAR and the CFPB complaint database returned nothing. CourtListener dockets could not be reached (COURTLISTENER_API_TOKEN not set; docket search skipped.). SEC EDGAR had already been pulled for an earlier lead. No new record came back. The litigation question moved from open to partly answered. Nothing about the subject in the CFPB complaint database. Absence from the sources searched is not proof of absence.

L5, step 5 of the playbook, was worked on Northgate Trading Ltd. Sweep adverse media and leaks for the entity and its principals. One source was run: the news search. The news search returned a record. 1 new record(s) came back, 1 about the subject or its chain: Northgate Trading Ltd wins Humber port logistics contract. The adverse media question moved from open to answered. 1 record(s) about the subject in the news search: Northgate Trading Ltd wins Humber port logistics contract. Each is a lead until a second independent source agrees.

Finally, L8 was checked against a second source on Borealis Holdings B.V. Borealis Holdings B.V. is named as owner by one source only. Look for it in a second, independent registry before relying on the link. 2 sources were run: SEC EDGAR and Wikidata. SEC EDGAR and Wikidata returned nothing. No new record came back. No second source names Borealis Holdings B.V., so the link still rests on a single source.

### What the record shows

**Is the subject a real registered entity, and what is its status?** This is answered. Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001.

**Who owns and controls it, up to a natural person?** This is partly answered. Corporate chain above the subject, 2 level(s) walked: Borealis Holdings B.V. \> Kestrel Nominees Ltd. The chain stops at Kestrel Nominees Ltd, with no owner behind it on the public record.

**Is the subject, or anyone in its ownership chain, on a sanctions or PEP list?** This is answered. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 3 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.

**Is there litigation, enforcement action or a complaint pattern?** This is partly answered. Nothing about the subject in the CFPB complaint database. Absence from the sources searched is not proof of absence.

**What does published coverage say about the subject?** This is answered. 1 record(s) about the subject in the news search: Northgate Trading Ltd wins Humber port logistics contract. Each is a lead until a second independent source agrees.

**Does a secrecy jurisdiction or a nominee arrangement sit in the structure?** This is answered. Yes: Kestrel Nominees Ltd is registered in CY. That is a reason to require the beneficial owner in writing, not a finding against the entity.

In all, 4 record(s) are about the subject or its chain (4 lead). A lead rests on one source, a probable finding on two, a confirmed finding on three or more independent sources. The Findings table in the annex lists each.

### What is not established

The question "Who owns and controls it, up to a natural person?" is partly answered. Still needed: the owner behind Kestrel Nominees Ltd: shareholder register or annual return from the primary registry, or the registered agent's file by legal process; not reached: Companies House (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.).

The question "Is the subject, or anyone in its ownership chain, on a sanctions or PEP list?" is answered. Still needed: manual check of OpenSanctions, EU Consolidated List.

The question "Is there litigation, enforcement action or a complaint pattern?" is partly answered. Still needed: not reached: CourtListener dockets (COURTLISTENER_API_TOKEN not set; docket search skipped.).


These explanations are still open, because the evidence neither supports nor rules them out: The counterparty is a legitimate operating business.; The counterparty is a shell or pass-through with nominee owners.; The counterparty is clean but carries sanctions or reputational exposure through an owner or affiliate..

What would change the conclusion: A registry or ownership filing naming a different beneficial owner or controller than the one found. A sanctions, enforcement or litigation record that was missed because it sits under a name variant or an affiliated entity. Evidence that the adverse items found concern a different entity with a similar name. A filing, register entry or disclosure naming the natural person or controller behind lei:549300KESTREL0000003, where the ownership walk ended without reaching one.

### Open leads and next steps

No lead is left on the sheet.

Where the public record ends, these hold the records and this is the instrument that reaches each: The company itself, and the registry that holds its filings (Ontario Business Registry document requests (public); production order or Norwich Pharmacal order via counsel for non-public registers, including any register of individuals with significant control). Counsel chooses the process.

Handoff: Engagement pi_case_world (due_diligence); purpose as stated by the client: Counterparty review before a supply contract. Jurisdiction: ca-on. Every identifier below comes from free public sources and is an unverified lead until a licensed investigator or counsel confirms it through lawful channels. Bunnyhole output is not a consumer report and must not be used for eligibility decisions.

## Case questions and answers

4 answered, 2 partly answered. A settled question is not a clearance.

1. **Is the subject a real registered entity, and what is its status?** ANSWERED.
   Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001.
2. **Who owns and controls it, up to a natural person?** PARTLY ANSWERED.
   Corporate chain above the subject, 2 level(s) walked: Borealis Holdings B.V. \> Kestrel Nominees Ltd. The chain stops at Kestrel Nominees Ltd, with no owner behind it on the public record.
   *Still needed:* the owner behind Kestrel Nominees Ltd: shareholder register or annual return from the primary registry, or the registered agent's file by legal process; not reached: Companies House (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.)
3. **Is the subject, or anyone in its ownership chain, on a sanctions or PEP list?** ANSWERED.
   No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 3 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
   *Still needed:* manual check of OpenSanctions, EU Consolidated List
4. **Is there litigation, enforcement action or a complaint pattern?** PARTLY ANSWERED.
   Nothing about the subject in the CFPB complaint database. Absence from the sources searched is not proof of absence.
   *Still needed:* not reached: CourtListener dockets (COURTLISTENER_API_TOKEN not set; docket search skipped.)
5. **What does published coverage say about the subject?** ANSWERED.
   1 record(s) about the subject in the news search: Northgate Trading Ltd wins Humber port logistics contract. Each is a lead until a second independent source agrees.
6. **Does a secrecy jurisdiction or a nominee arrangement sit in the structure?** ANSWERED.
   Yes: Kestrel Nominees Ltd is registered in CY. That is a reason to require the beneficial owner in writing, not a finding against the entity.

## Engagement & scope

- **Engagement ID:** `pi_case_world`
- **Case type:** due_diligence
- **Objective:** Give the client a counterparty-risk picture: who the entity is, who owns it, whether it is sanctioned, and what litigation, enforcement, complaints and media say.
- **Purpose:** Counterparty review before a supply contract.
- **Attested permissible purpose:** counterparty_due_diligence
- **Client:** not recorded
- **Matter reference:** not recorded
- **Jurisdiction:** ca-on
- **Subject:** entity
- **Seed:** Northgate Trading Ltd
- **Passive-only:** yes
- **Opened (UTC):** 2026-11-13T12:00:00+00:00
- **Conflict check:** 1 prior case matched: bh_prior (seed Northgate Trading Ltd, 2026-02-02)

## Entity profile

| Field | Value |
| --- | --- |
| Legal name | NORTHGATE TRADING LTD |
| LEI | 213800NORTHGATE00001 |
| Status | ACTIVE |
| Jurisdiction | GB |
| Registered address | 12 Dock Road, Hull, GB |
| Parents | Borealis Holdings B.V. |
| Registry sources | GLEIF: https://search.gleif.org/#/record/213800NORTHGATE00001 |

## Client theory vs. evidence

| Hypothesis | Status | For | Against | Score |
| --- | --- | --- | --- | --- |
| The counterparty is a legitimate operating business. | open | registry_active (registry status 'ACTIVE'); lei_issued (LEI '213800NORTHGATE00001') | none | 0.7 |
| The counterparty is a shell or pass-through with nominee owners. | open | chain_ends_at_nominee_or_secrecy (lei:549300KESTREL0000003) | none | 0.5 |
| The counterparty is clean but carries sanctions or reputational exposure through an owner or affiliate. | open | adverse_media_on_principal (article:northgate-trading-wins-port-contract) | none | 0.3 |

Scores come from the fixed signal table. A high score is not a clearance.

## Findings

| Finding | Label | Sources | Freshness | Relevance |
| --- | --- | --- | --- | --- |
| 🏛️ NORTHGATE TRADING LTD (GB) (lei:213800NORTHGATE00001) | lead | 1 | unknown | subject |
| 🏛️ Borealis Holdings B.V. (NL) (lei:724500BOREALIS000002) | lead | 1 | unknown | related: no name match: 'Borealis Holdings B.V. (NL)' shares no word with 'Northgate Trading Ltd'; linked to the subject by an ownership or officer edge |
| 🏛️ Kestrel Nominees Ltd (CY) (lei:549300KESTREL0000003) | lead | 1 | unknown | related: no name match: 'Kestrel Nominees Ltd (CY)' shares no word with 'Northgate Trading Ltd'; in the ownership chain above the subject |
| 📰 Northgate Trading Ltd wins Humber port logistics contract (article:northgate-trading-wins-port-contract) | lead | 1 | unknown | related: article or post 'Northgate Trading Ltd wins Humber port logistics contract' mentions the subject name |

Labels: lead = 1 source, needs corroboration before it is relied on.

## Sanctions screening

**Status:** partial (some lists ran and others were not reached; no hit on the screened lists is not clearance)

**Screened lists:**

| List |
| --- |
| Canada SEMA |
| OFAC SDN |
| UN Consolidated List |
| UK Sanctions List |

**NOT screened (tried and not reached, or never run):**

| List | Reason |
| --- | --- |
| OpenSanctions | skipped: OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped. |
| EU Consolidated List | not automated (verify at https://www.sanctionsmap.eu/) |

**Hits:**

No hit on the lists that ran. Lists not screened are not cleared.

A name match on a sanctions list is a lead, not a determination.

## Identity resolution

None.

## Ownership chain

Levels walked: 2

| Child | Parent | Share | Source | As of |
| --- | --- | --- | --- | --- |
| NORTHGATE TRADING LTD (GB) (lei:213800NORTHGATE00001) | Borealis Holdings B.V. (NL) (lei:724500BOREALIS000002) | unknown | https://search.gleif.org/#/record/724500BOREALIS000002 | unknown |
| Borealis Holdings B.V. (NL) (lei:724500BOREALIS000002) | Kestrel Nominees Ltd (CY) (lei:549300KESTREL0000003) | unknown | https://search.gleif.org/#/record/549300KESTREL0000003 | unknown |

**50%-rule flags (OFAC):**
- 50%-rule: not evaluable (ownership percentages unknown)

**Unresolved (walk ended before a natural person):**
- Kestrel Nominees Ltd (CY) (lei:549300KESTREL0000003)

## What is NOT a link

None. None found in the evidence collected (this is not proof that none exist).

## Contradictions and gaps

**Contradictions:**
None.

**Gaps:**
- No dated evidence at all: the timeline has no usable dated events.

## What would change this conclusion

- A registry or ownership filing naming a different beneficial owner or controller than the one found.
- A sanctions, enforcement or litigation record that was missed because it sits under a name variant or an affiliated entity.
- Evidence that the adverse items found concern a different entity with a similar name.
- A filing, register entry or disclosure naming the natural person or controller behind lei:549300KESTREL0000003, where the ownership walk ended without reaching one. — not attempted (no lead on the sheet covers it)
- A second independent source that contradicts, or corroborates, any of the 4 single-source leads, most relevant first: 'NORTHGATE TRADING LTD (GB)' (lei:213800NORTHGATE00001), 'Borealis Holdings B.V. (NL)' (lei:724500BOREALIS000002), 'Kestrel Nominees Ltd (CY)' (lei:549300KESTREL0000003), 'Northgate Trading Ltd wins Humber port logistics contract' (article:northgate-trading-wins-port-contract). — attempted (L6, worked; L8, negative; L9, worked)

## Coverage and negatives

| Source class | Searched | Sources | Tried, not reached | Outcome |
| --- | --- | --- | --- | --- |
| corporate_registry | yes | gleif, sec_edgar | none | hit |
| beneficial_ownership | NOT SEARCHED | none | uk_psc | NOT SEARCHED |
| sanctions_pep | yes | ofac_sdn, un_consolidated, uk_sanctions_list, ca_sanctions | opensanctions | negative |
| court_dockets | NOT SEARCHED | none | court_dockets | NOT SEARCHED |
| regulatory_enforcement | yes | cfpb_complaints | none | negative |
| news_adverse_media | yes | news_narrative | none | hit |

**Partial coverage (some sources ran, others were not reached):**

- sanctions_pep: partial: ofac_sdn, un_consolidated, uk_sanctions_list, ca_sanctions ran; opensanctions skipped or errored (not reached)

**Negatives, skips and errors logged:**

| Source | Target | Status | Detail |
| --- | --- | --- | --- |
| uk_psc | Northgate Trading Ltd | skipped | UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped. |
| wikidata | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| sec_edgar | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| uk_psc | Borealis Holdings B.V. | skipped | UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped. |
| uk_psc | Kestrel Nominees Ltd | skipped | UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped. |
| opensanctions | Northgate Trading Ltd | skipped | OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped. |
| ofac_sdn | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| un_consolidated | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| uk_sanctions_list | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| ca_sanctions | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| ca_sanctions | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |
| opensanctions | Borealis Holdings B.V. | skipped | OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped. |
| ofac_sdn | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |
| un_consolidated | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |
| uk_sanctions_list | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |
| ca_sanctions | Kestrel Nominees Ltd | negative | ran; no new nodes or receipts |
| opensanctions | Kestrel Nominees Ltd | skipped | OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped. |
| ofac_sdn | Kestrel Nominees Ltd | negative | ran; no new nodes or receipts |
| un_consolidated | Kestrel Nominees Ltd | negative | ran; no new nodes or receipts |
| uk_sanctions_list | Kestrel Nominees Ltd | negative | ran; no new nodes or receipts |
| court_dockets | Northgate Trading Ltd | skipped | COURTLISTENER_API_TOKEN not set; docket search skipped. |
| cfpb_complaints | Northgate Trading Ltd | negative | ran; no new nodes or receipts |
| sec_edgar | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |
| wikidata | Borealis Holdings B.V. | negative | ran; no new nodes or receipts |

Absence from the sources searched is not proof of absence.

## Playbook progress

Done when: not met (automated check) — every lead is worked and the free public record is exhausted (4 answered, 2 partly answered; not settled: ownership (partial), litigation (partial))

| Step | Action | Sources | Status | Evidence | Decision |
| --- | --- | --- | --- | --- | --- |
| 1 | Confirm the entity in its registry and resolve its identity; use Wikidata only as an aid. | OpenCorporates, Ontario Business Registry, Corporations Canada, Companies House, Wikidata | PARTIAL | ran: Wikidata (negative); did not run: Companies House (skipped: UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.); not automated: OpenCorporates, Ontario Business Registry, Corporations Canada | continue |
| 2 | Walk beneficial ownership using the 12-step UBO workflow. | Companies House PSC (UK), GLEIF LEI Search, Open Ownership / BODS, ICIJ Offshore Leaks | PARTIAL | ran: GLEIF LEI Search (hit); did not run: Companies House PSC (UK) (skipped: UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.); not automated: Open Ownership / BODS, ICIJ Offshore Leaks | continue |
| 3 | Screen sanctions and PEP status for every node, including the OFAC 50% rule. | OpenSanctions, OFAC Sanctions List Search, UN Security Council Consolidated List, EU Sanctions Map, UK OFSI Consolidated List, GAC Canadian Sanctions (SEMA) | PARTIAL | ran: OFAC Sanctions List Search (negative), UN Security Council Consolidated List (negative), UK OFSI Consolidated List (negative), GAC Canadian Sanctions (SEMA) (negative); did not run: OpenSanctions (skipped: OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.); not automated: EU Sanctions Map | continue |
| 4 | Search litigation, enforcement and complaints. | CourtListener / RECAP, PACER Case Locator, SEC EDGAR, SAM.gov, CFPB Consumer Complaints | PARTIAL | ran: SEC EDGAR (negative), CFPB Consumer Complaints (negative); did not run: CourtListener / RECAP (skipped: COURTLISTENER_API_TOKEN not set; docket search skipped.); not automated: PACER Case Locator, SAM.gov | continue |
| 5 | Sweep adverse media and leaks for the entity and its principals. | Google News, Wayback Machine, OCCRP Aleph | PARTIAL | ran: Google News (hit); not dispatched this run: Wayback Machine; not automated: OCCRP Aleph | continue |
| 6 | Assess jurisdiction risk against the FATF lists. | FATF High-Risk Jurisdictions | NOT RUN | not automated: FATF High-Risk Jurisdictions |  |

**Escalation triggers:**

| Trigger | Fired | Why |
| --- | --- | --- |
| A sanctions hit, 50% rule block or PEP link: refer to compliance counsel. | no | not fired on the lists screened (Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List); NOT screened: OpenSanctions (skipped: OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.); EU Consolidated List: not automated (verify at https://www.sanctionsmap.eu/); 50%-rule: not evaluable (ownership percentages unknown) |
| The ownership chain ends at a nominee or secrecy jurisdiction. | yes | 1 ownership node(s) unresolved: lei:549300KESTREL0000003; nominee or secrecy indicator: lei:549300KESTREL0000003: OFFSHORE_SECRECY_JURISDICTION_CY, lei:549300KESTREL0000003: ownership parent registered in secrecy jurisdiction CY |
| Non-public company records are needed: counsel for a production order. | yes | custodian-bearing finding(s): Non-public company records (share register, register of directors, minute book, accounts) |

## Lead sheet

10 lead(s): 9 worked, 1 negative.

| Lead | Kind | Target | Why it was opened | Opened by | Sources | Status | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| L1 | playbook | Northgate Trading Ltd (company) | Confirm the entity in its registry and resolve its identity; use Wikidata only as an aid. | intake | uk_psc, wikidata, gleif, sec_edgar | WORKED | uk_psc skipped (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC…); wikidata negative; gleif hit; sec_edgar negative |
| L2 | playbook | Northgate Trading Ltd (company) | Walk beneficial ownership using the 12-step UBO workflow. | intake | uk_psc, gleif | WORKED | uk_psc skipped (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC…); gleif hit |
| L3 | playbook | Northgate Trading Ltd (company) | Screen sanctions and PEP status for every node, including the OFAC 50% rule. | intake | opensanctions, ofac_sdn, un_consolidated, uk_sanctions_list, ca_sanctions | WORKED | opensanctions skipped (OpenSanctions needs access: set OPENSANCTIONS_API_KEY.…); ofac_sdn negative; un_consolidated negative; uk_sanctions_list negative; ca_sanctions negative |
| L4 | playbook | Northgate Trading Ltd (company) | Search litigation, enforcement and complaints. | intake | court_dockets, sec_edgar, cfpb_complaints | WORKED | sec_edgar negative; court_dockets skipped (COURTLISTENER_API_TOKEN not set; docket search skipped.); cfpb_complaints negative |
| L5 | playbook | Northgate Trading Ltd (company) | Sweep adverse media and leaks for the entity and its principals. | intake | news_narrative | WORKED | news_narrative hit |
| L6 | ownership | Borealis Holdings B.V. (company) | Borealis Holdings B.V. is named as an owner of NORTHGATE TRADING LTD. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. | L1 | gleif, uk_psc | WORKED | gleif hit; uk_psc skipped (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC…) |
| L7 | screen | Borealis Holdings B.V. (company) | Borealis Holdings B.V. sits in the ownership chain above NORTHGATE TRADING LTD. Every node of the chain is screened, not only the subject. | L1 | ca_sanctions, opensanctions, ofac_sdn, un_consolidated, uk_sanctions_list | WORKED | ca_sanctions negative; opensanctions skipped (OpenSanctions needs access: set OPENSANCTIONS_API_KEY.…); ofac_sdn negative; un_consolidated negative; uk_sanctions_list negative |
| L8 | corroborate | Borealis Holdings B.V. (company) | Borealis Holdings B.V. is named as owner by one source only. Look for it in a second, independent registry before relying on the link. | L1 | sec_edgar, wikidata | NEGATIVE | sec_edgar negative; wikidata negative |
| L9 | ownership | Kestrel Nominees Ltd (company) | Kestrel Nominees Ltd is named as an owner of Borealis Holdings B.V. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. | L6 | gleif, uk_psc | WORKED | gleif hit; uk_psc skipped (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC…) |
| L10 | screen | Kestrel Nominees Ltd (company) | Kestrel Nominees Ltd sits in the ownership chain above Borealis Holdings B.V. Every node of the chain is screened, not only the subject. | L6 | ca_sanctions, opensanctions, ofac_sdn, un_consolidated, uk_sanctions_list | WORKED | ca_sanctions negative; opensanctions skipped (OpenSanctions needs access: set OPENSANCTIONS_API_KEY.…); ofac_sdn negative; un_consolidated negative; uk_sanctions_list negative |

No lead is left to chase.

## Investigation log

**1. L1.** L1, step 1 of the playbook, was worked on Northgate Trading Ltd. Confirm the entity in its registry and resolve its identity; use Wikidata only as an aid. 4 sources were run: Companies House, Wikidata, GLEIF and SEC EDGAR.
- *Found:* GLEIF returned a record. Wikidata and SEC EDGAR returned nothing. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). 2 new record(s) came back, 2 about the subject or its chain: NORTHGATE TRADING LTD (GB) and Borealis Holdings B.V. (NL).
- *Read:* The identity question moved from open to answered. Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001. The ownership question moved from open to partly answered. Corporate chain above the subject, 1 level(s) walked: Borealis Holdings B.V. The chain stops at Borealis Holdings B.V., with no owner behind it on the public record. The structure question moved from open to answered. Registered in GB; no secrecy-jurisdiction or nominee marker in the 1 chain node(s) walked. FATF list status is checked by hand.
- *Next:* This opened L6 (walk the ownership of Borealis Holdings B.V.), L7 (screen Borealis Holdings B.V.) and L8 (find a second source for Borealis Holdings B.V.).

**2. L2.** L2, step 2 of the playbook, was worked on Northgate Trading Ltd from records already on file (Companies House and GLEIF had run for an earlier lead), so it cost no new call. Walk beneficial ownership using the 12-step UBO workflow.
- *Found:* GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.).
- *Read:* On those records the identity question is answered. Registered as NORTHGATE TRADING LTD, jurisdiction GB, status ACTIVE, LEI 213800NORTHGATE00001. On those records the ownership question is partly answered. Corporate chain above the subject, 1 level(s) walked: Borealis Holdings B.V. The chain stops at Borealis Holdings B.V., with no owner behind it on the public record. On those records the structure question is answered. Registered in GB; no secrecy-jurisdiction or nominee marker in the 1 chain node(s) walked. FATF list status is checked by hand.
- *Next:* No new lead.

**3. L6.** L6 was walked upward on Borealis Holdings B.V. Borealis Holdings B.V. is named as an owner of NORTHGATE TRADING LTD. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. 2 sources were run: GLEIF and Companies House.
- *Found:* GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). 1 new record(s) came back, 1 about the subject or its chain: Kestrel Nominees Ltd (CY).
- *Read:* The ownership question is still partly answered, with more detail. Corporate chain above the subject, 2 level(s) walked: Borealis Holdings B.V. \> Kestrel Nominees Ltd. The chain stops at Kestrel Nominees Ltd, with no owner behind it on the public record. The structure question is still answered, with more detail. Yes: Kestrel Nominees Ltd is registered in CY. That is a reason to require the beneficial owner in writing, not a finding against the entity.
- *Next:* This opened L9 (walk the ownership of Kestrel Nominees Ltd) and L10 (screen Kestrel Nominees Ltd).

**4. L9.** L9 was walked upward on Kestrel Nominees Ltd. Kestrel Nominees Ltd is named as an owner of Borealis Holdings B.V. Pull its registry record and find who owns it: the walk continues until a natural person or a documented stop. 2 sources were run: GLEIF and Companies House.
- *Found:* GLEIF returned a record. Companies House could not be reached (UK_COMPANIES_HOUSE_API_KEY not set; Companies House PSC lookup skipped.). No new record came back.
- *Read:* No owner is recorded above Kestrel Nominees Ltd in the sources reached. On the public record the chain stops here: the next step is the primary registry or the registered agent's file (see Custodians).
- *Next:* No new lead.

**5. L3.** L3, step 3 of the playbook, was worked on Northgate Trading Ltd. Screen sanctions and PEP status for every node, including the OFAC 50% rule. 5 sources were run: OpenSanctions, the OFAC SDN list, the UN Consolidated List, the UK Sanctions List and the Canada SEMA list.
- *Found:* The OFAC SDN list, the UN Consolidated List, the UK Sanctions List and the Canada SEMA list returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back.
- *Read:* The sanctions question moved from open to partly answered. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 1 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
- *Next:* No new lead.

**6. L7.** L7 was screened on Borealis Holdings B.V. Borealis Holdings B.V. sits in the ownership chain above NORTHGATE TRADING LTD. Every node of the chain is screened, not only the subject. 5 sources were run: the Canada SEMA list, OpenSanctions, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List.
- *Found:* The Canada SEMA list, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back.
- *Read:* The sanctions question is still partly answered, with more detail. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 2 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
- *Next:* No new lead.

**7. L10.** L10 was screened on Kestrel Nominees Ltd. Kestrel Nominees Ltd sits in the ownership chain above Borealis Holdings B.V. Every node of the chain is screened, not only the subject. 5 sources were run: the Canada SEMA list, OpenSanctions, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List.
- *Found:* The Canada SEMA list, the OFAC SDN list, the UN Consolidated List and the UK Sanctions List returned nothing. OpenSanctions could not be reached (OpenSanctions needs access: set OPENSANCTIONS_API_KEY. Sanctions/PEP screening skipped.). No new record came back.
- *Read:* The sanctions question moved from partly answered to answered. No match on Canada SEMA, OFAC SDN, UN Consolidated List, UK Sanctions List for 3 of 3 name(s) in scope. Not screened: OpenSanctions, EU Consolidated List. No hit on a screened list is not clearance.
- *Next:* No new lead.

**8. L4.** L4, step 4 of the playbook, was worked on Northgate Trading Ltd. Search litigation, enforcement and complaints. 2 sources were run: CourtListener dockets and the CFPB complaint database.
- *Found:* SEC EDGAR and the CFPB complaint database returned nothing. CourtListener dockets could not be reached (COURTLISTENER_API_TOKEN not set; docket search skipped.). SEC EDGAR had already been pulled for an earlier lead. No new record came back.
- *Read:* The litigation question moved from open to partly answered. Nothing about the subject in the CFPB complaint database. Absence from the sources searched is not proof of absence.
- *Next:* No new lead.

**9. L5.** L5, step 5 of the playbook, was worked on Northgate Trading Ltd. Sweep adverse media and leaks for the entity and its principals. One source was run: the news search.
- *Found:* The news search returned a record. 1 new record(s) came back, 1 about the subject or its chain: Northgate Trading Ltd wins Humber port logistics contract.
- *Read:* The adverse media question moved from open to answered. 1 record(s) about the subject in the news search: Northgate Trading Ltd wins Humber port logistics contract. Each is a lead until a second independent source agrees.
- *Next:* No new lead.

**10. L8.** L8 was checked against a second source on Borealis Holdings B.V. Borealis Holdings B.V. is named as owner by one source only. Look for it in a second, independent registry before relying on the link. 2 sources were run: SEC EDGAR and Wikidata.
- *Found:* SEC EDGAR and Wikidata returned nothing. No new record came back.
- *Read:* No second source names Borealis Holdings B.V., so the link still rests on a single source.
- *Next:* No new lead.

Stop: dead_end. every lead is worked and the free public record is exhausted (4 answered, 2 partly answered; not settled: ownership (partial), litigation (partial))
Case officer: the playbook order (no model). Source calls: 28 of 120.

## Custodians and next steps

| Finding | Custodian | Instrument | Jurisdiction | Note |
| --- | --- | --- | --- | --- |
| Non-public company records (share register, register of directors, minute book, accounts) | The company itself, and the registry that holds its filings | Ontario Business Registry document requests (public); production order or Norwich Pharmacal order via counsel for non-public registers, including any register of individuals with significant control | ca-on | Start with the public registry copy and hash it. Escalate only for what the registry does not hold. Verify current register access rules with counsel. |

**Handoff sheet (for a licensed investigator or counsel):**

- Engagement pi_case_world (due_diligence); purpose as stated by the client: Counterparty review before a supply contract.
- Jurisdiction: ca-on
- Every identifier below comes from free public sources and is an unverified lead until a licensed investigator or counsel confirms it through lawful channels.
- Bunnyhole output is not a consumer report and must not be used for eligibility decisions.
- Verify sanctions status on the primary list (OpenSanctions was not screened in this run): https://www.opensanctions.org/
- Verify sanctions status on the primary list (EU Sanctions Map was not screened in this run): https://www.sanctionsmap.eu/
- Confirm corporate status and beneficial ownership on the primary registry: Companies House (https://find-and-update.company-information.service.gov.uk/)
- Confirm with a primary source: 12 Dock Road, Hull, GB (address; unverified lead)
- Confirm with a primary source: Keizersgracht 100, Amsterdam, NL (address; unverified lead)
- Confirm with a primary source: 5 Makarios Avenue, Nicosia, CY (address; unverified lead)
- Confirm with a primary source: Northgate Trading Ltd (organization; unverified lead)
- Request via counsel: Ontario Business Registry document requests (public); production order or Norwich Pharmacal order via counsel for non-public registers, including any register of individuals with significant control to The company itself, and the registry that holds its filings for Non-public company records (share register, register of directors, minute book, accounts) (jurisdiction: ca-on)

## Chain of custody

| Receipt ID | Tool | URL | Receipt digest (SHA-256) | Collected (UTC) |
| --- | --- | --- | --- | --- |
| rcpt_a8a4368141 | bunnyhole_case_director | seed://Northgate Trading Ltd | `a8a4368141c148319ee93c888f154b72ba22d947871f3684512238db39d23f50` | 2026-11-13T12:00:00+00:00 |
| rcpt_790f003857 | gleif_level1_level2_api | https://search.gleif.org/#/record/213800NORTHGATE00001 | `790f00385765889d944f0822995a0da7334960909625b16c98bae76454a25e84` | 2026-11-13T12:00:00+00:00 |
| rcpt_0fb9e4e69e | gleif_level2_ultimate_parent | https://search.gleif.org/#/record/724500BOREALIS000002 | `0fb9e4e69e8dbd80af9940fb057f68b814ccce74fd6cd8b452153b7005205524` | 2026-11-13T12:00:00+00:00 |
| rcpt_2025234812 | gleif_level1_level2_api | https://search.gleif.org/#/record/724500BOREALIS000002 | `2025234812bfb687466767d961dd7cb70a34e62fbacb6c855392cd1132e9ca6c` | 2026-11-13T12:00:00+00:00 |
| rcpt_e3902da6ed | gleif_level2_ultimate_parent | https://search.gleif.org/#/record/549300KESTREL0000003 | `e3902da6ed2d309baecb4ac87e841075f6ec5440f259164827e33c0aa4342ffc` | 2026-11-13T12:00:00+00:00 |
| rcpt_7187c75898 | gleif_level1_level2_api | https://search.gleif.org/#/record/549300KESTREL0000003 | `7187c758989deb6bef10c2d379d5c2b5779d490447a7568f26ea5db3b0253fd4` | 2026-11-13T12:00:00+00:00 |
| rcpt_a7aca86d52 | google_news_rss | https://news.example.test/northgate-port-contract | `a7aca86d52f94c8b34e542ef794f18ebf6d7c005cc1cb1e308da7eaa295bf5a9` | 2026-11-13T12:00:00+00:00 |
| rcpt_f39040758e | gleif_level2_ultimate_parent | https://search.gleif.org/#/record/724500BOREALIS000002 | `f39040758e9b43d4535e9d56fedf521e158dc4c6b95470923b48c92dd196e2a9` | 2026-11-13T12:00:00+00:00 |
| rcpt_4039475cd4 | gleif_level2_ultimate_parent | https://search.gleif.org/#/record/549300KESTREL0000003 | `4039475cd411213080f3cb187f7899c7a05633b462994972ec3ed42df8fec20d` | 2026-11-13T12:00:00+00:00 |

The digest covers the recorded extract (tool, URL, fact, snippet), not the full retrieved page; archive source pages (Wayback Save Page Now, ArchiveBox, SingleFile) for page-level preservation.

## Limitations & legal notices

- This report is not a consumer report and must not be used for eligibility decisions about employment, tenancy, credit, loans or insurance (FCRA-regulated); use an FCRA-compliant screening provider for those.
- Findings are leads, not verdicts: each is labelled by how many independent sources support it, and records can be stale, mismatched or wrong.
- Absence from the sources searched is not proof of absence: the coverage matrix shows what was and was not searched.
- Bunnyhole is a research tool. It does not hold or imply a private investigator licence, grants no police powers, and does not replace a licensed investigator or counsel.
- Bunnyhole uses free, lawful, passive sources only: no pretexting, tracking, recording, account access or contact with the subject.
- In Ontario, verify with the Ministry of the Solicitor General whether the Private Security and Investigative Services Act, 2005 (PSISA) licensing applies if this work supports paid third-party investigation.
- Generated deterministically from the recorded data: no model scored, labelled or wrote any finding.
