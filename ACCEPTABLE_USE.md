# Responsible & Acceptable Use

Bunnyhole is an **investigative intelligence tool** intended for lawful, ethical work:
investigative journalism, forensic accounting and fraud research, threat intelligence,
corporate due diligence, and academic study. It aggregates **open-source and public-record
data** and attaches cryptographic provenance to every finding.

By using Bunnyhole you agree to:

- **Comply with all applicable laws** (computer-misuse, data-protection/GDPR/CCPA, anti-stalking,
  and the terms of service of every data source and API you query).
- **Only investigate what you are authorized to investigate.** Do not use Bunnyhole to harass,
  dox, stalk, or surveil private individuals, or to build profiles for discrimination.
- **Treat findings as leads, not verdicts.** Bunnyhole grades evidence (NATO Admiralty, Red-Cell
  Skeptic, ACH) precisely because automated attribution produces false positives. Corroborate
  before publishing or acting.
- **Handle sensitive data carefully.** Case data and any leaked credentials you input are stored
  locally in `~/.bunnyhole/cases.db`. Protect, minimize, and delete it per your obligations.

## Private-investigator (PI) stream addendum

The `--pi` stream (see [`docs/PI_STREAM.md`](docs/PI_STREAM.md)) is held to a stricter standard:

- **A purpose is recorded and gated.** `--pi` requires a written `--purpose` and an attested
  `--purpose-category` from a short list of permissible purposes, both stored in the engagement record and the
  report. A private person as subject needs a narrower category and a matter reference. Every free-text field
  of the command is screened (text too long to screen, over 150,000 characters, is refused rather than skipped). The category is attested, not verified: a false declaration passes the allowlist.
  The phrase screens that back it have incomplete recall, refuse some legitimate wordings and can be phrased
  around (a matter reference is only format-checked, and `--confirm-entity` overrides the person-vs-entity
  check). You remain responsible for lawful use. Do not reword a purpose to get past a screen when the real purpose is one
  it exists to stop.
- **No eligibility decisions.** Employment, tenancy, credit, loan and insurance decisions are refused
  (FCRA); no permissible-purpose category exists for them. Use an FCRA-compliant screening provider. PI output is not a consumer report.
- **Passive and lawful only.** No pretexting, tracker placement, audio recording or interception, account
  access or password resets, hacking, trespass, or contact with the subject. In PI mode credentials and
  credential-shaped text are refused or dropped: `--cred` is refused, as is credential-shaped text in `--purpose`,
  `--client` and `--matter-ref`; credentials found in an intake dump or packet are dropped and scrubbed. Breach and
  infostealer lookups and sign-up or account-recovery probes are blocked and logged.
- **Former partners are refused.** Pursuit of a former partner, or of someone avoiding the client, is refused
  in every case type and for entity subjects too. On locate, background and missing-person engagements a
  former-partner relationship is refused outright; on an asset search, due diligence or fraud screen of a
  person it is allowed only under an asset-recovery or litigation-support category with a real-looking matter
  reference (a divorce or support proceeding). If there
  is a protective order or a safety concern, go to law enforcement or counsel.
- **Leads, not verdicts.** Labels (`confirmed`, `probable`, `lead`) measure corroboration, not truth. A
  sanctions-list hit is a soft name match: verify it on the primary list, and note that a keyless run does not
  screen OpenSanctions, so no hit is not clearance. The EU list is never automated and is always named as not screened. Verify with primary records before you act,
  serve process, or publish.
- **Ontario and Canada.** Acting as a private investigator for pay in Ontario may require a licence under the
  Private Security and Investigative Services Act, 2005 (PSISA). Whether it applies to your use is for you to
  confirm: verify with the Ministry of the Solicitor General. Bunnyhole is a research tool; it is not a
  licence and confers no police powers.
- **Not legal advice.** Nothing in Bunnyhole or its documentation is legal advice; consult counsel.

The authors provide this software "as is" and are not responsible for misuse. If you cannot use
it lawfully and ethically, do not use it.
