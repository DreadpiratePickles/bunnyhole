"""PI stream: custodians of non-public records, the legal instrument that reaches them, and the handoff sheet.

Where free public data ends, an elite investigator does not guess: they name who holds the record and which
lawful tool reaches it (subpoena, production order, Norwich Pharmacal order, MLAT / Hague request, licensed
database confirmation, public-place field verification by a licensed investigator). This module is pure data
plus lookups. It never contacts anyone and never claims a lead is verified. It is information, not legal
advice: instruments vary by court and change over time, so counsel confirms the route.

Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.5.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

from bunnyhole.engine.pi import CaseType, Custodian, EntityProfile, OwnershipBlock, PIEngagement, SanctionsScreening

#: Jurisdiction keys carrying instrument text. Anything unrecognised falls back to "intl".
JURISDICTION_KEYS: tuple[str, ...] = ("us", "ca-on", "uk", "intl")

_LAWFUL_ONLY = (
    "Reachable only through lawful process or a consenting custodian; never by pretexting, impersonation or "
    "account access."
)

#: One rule per finding kind. ``instruments`` maps jurisdiction key -> the lawful route. ``note`` carries the
#: caution and the licensed-investigator route where one exists.
CUSTODIAN_RULES: List[dict] = [
    {
        "finding_kind": "exchange_deposit_address",
        "finding": "Deposit address at a KYC cryptocurrency exchange (the crypto cash-out point)",
        "custodian": "The exchange or custodial wallet provider that controls the deposit address",
        "instruments": {
            "us": "Subpoena duces tecum or court order served through counsel in a filed action, after a "
                  "preservation letter",
            "ca-on": "Norwich Pharmacal order from the Ontario Superior Court via counsel (production order if "
                     "police are engaged)",
            "uk": "Norwich Pharmacal order from the High Court via counsel, after a preservation request",
            "intl": "Letter of request, MLAT or Hague Evidence Convention request via counsel, plus the exchange's "
                    "own legal-process channel",
        },
        "note": "On-chain attribution is free and public, but the account holder's identity is only at the "
                "exchange. " + _LAWFUL_ONLY,
    },
    {
        "finding_kind": "bank_account_indicated",
        "finding": "Bank account indicated by a payment record, filing or court exhibit",
        "custodian": "The bank or payment institution holding the account",
        "instruments": {
            "us": "Subpoena duces tecum in a filed action, or post-judgment discovery and a writ of garnishment "
                  "served through counsel",
            "ca-on": "Examination of the judgment debtor in aid of execution, garnishment, or a Norwich "
                     "Pharmacal order via counsel",
            "uk": "Norwich Pharmacal or Bankers Trust order, or a third-party debt order after judgment, via "
                  "counsel",
            "intl": "Letter of request, MLAT or Hague Evidence Convention request via counsel; local enforcement "
                    "counsel in the bank's country",
        },
        "note": "Bank records are nonpublic financial information. Pretexting a bank is a federal crime in the "
                "US (GLBA s.6821). " + _LAWFUL_ONLY,
    },
    {
        "finding_kind": "registered_agent",
        "finding": "Registered agent or corporate-services provider named in a registry filing",
        "custodian": "The registered agent or company-formation provider that holds the client file",
        "instruments": {
            "us": "Subpoena duces tecum for the agent's client-identification and formation records, or a "
                  "court order",
            "ca-on": "Production or disclosure order via counsel, or a Norwich Pharmacal order to learn who "
                     "instructed the agent",
            "uk": "Norwich Pharmacal order via counsel (agents hold customer due-diligence records)",
            "intl": "Letter of request, MLAT or Hague request to the agent's home jurisdiction via counsel",
        },
        "note": "A registered-agent address is not evidence of a link between companies that share it. Expect "
                "the agent to assert confidentiality; counsel decides how to respond.",
    },
    {
        "finding_kind": "company_records",
        "finding": "Non-public company records (share register, register of directors, minute book, accounts)",
        "custodian": "The company itself, and the registry that holds its filings",
        "instruments": {
            "us": "Secretary of State certified copies (public); subpoena duces tecum to the company for books "
                  "and records; shareholder inspection rights if the client is a shareholder",
            "ca-on": "Ontario Business Registry document requests (public); production order or Norwich "
                     "Pharmacal order via counsel for non-public registers, including any register of "
                     "individuals with significant control",
            "uk": "Companies House filings and the PSC register (public); court order via counsel for "
                  "statutory registers that are not filed",
            "intl": "Certified extract from the foreign registry via local counsel; letter of request or Hague "
                    "request for non-public records",
        },
        "note": "Start with the public registry copy and hash it. Escalate only for what the registry does not "
                "hold. Verify current register access rules with counsel.",
    },
    {
        "finding_kind": "phone_carrier",
        "finding": "Subscriber and line records for a telephone number",
        "custodian": "The carrier, ISP or VoIP provider that assigns the number",
        "instruments": {
            "us": "Subpoena duces tecum or court order served through counsel (subscriber data only; the "
                  "Stored Communications Act limits content)",
            "ca-on": "Norwich Pharmacal order via counsel, or a production order if police are engaged",
            "uk": "Norwich Pharmacal order via counsel; communications data is otherwise available only to "
                  "public authorities",
            "intl": "MLAT or letter of request via counsel to the carrier's jurisdiction",
        },
        "note": "A licensed investigator may confirm line ownership or a current address from a licensed "
                "database, if a permissible purpose is documented. Cell-phone pings and SIM tricks are unlawful "
                "without legal basis. " + _LAWFUL_ONLY,
    },
    {
        "finding_kind": "isp_ip_assignment",
        "finding": "Subscriber behind an IP address at a point in time",
        "custodian": "The ISP that held the IP assignment (retention is limited, so act quickly)",
        "instruments": {
            "us": "Preservation letter, then a subpoena (including a John Doe subpoena in a filed action) or "
                  "court order",
            "ca-on": "Preservation letter, then a Norwich Pharmacal order via counsel (the usual route to "
                     "identify an anonymous online wrongdoer)",
            "uk": "Preservation letter, then a Norwich Pharmacal order via counsel",
            "intl": "MLAT or letter of request via counsel; the ISP's law-enforcement or legal-process channel",
        },
        "note": "Passive infrastructure data (DNS, certificates, hosting) is public; the person behind it is not. "
                "A shared hosting provider or VPN exit is not a link.",
    },
    {
        "finding_kind": "employer",
        "finding": "Subject's current employer and payroll records",
        "custodian": "The employer (payroll and HR records)",
        "instruments": {
            "us": "After judgment: writ of garnishment or wage-garnishment order; in a filed action: subpoena "
                  "duces tecum served through counsel",
            "ca-on": "After judgment: garnishment notice and examination of the debtor in aid of execution; "
                     "otherwise a production or Norwich Pharmacal order via counsel",
            "uk": "After judgment: attachment of earnings order via counsel; otherwise a Norwich Pharmacal "
                  "order",
            "intl": "Local enforcement counsel; letter of request or Hague Evidence Convention request",
        },
        "note": "A licensed investigator can confirm an employer through licensed-database confirmation plus "
                "public-place field verification, with a documented purpose. Never call the employer under a "
                "false pretext.",
    },
    {
        "finding_kind": "vehicle_registry",
        "finding": "Registered owner or keeper of a vehicle plate",
        "custodian": "The motor-vehicle licensing authority (DMV, Ministry of Transportation, DVLA)",
        "instruments": {
            "us": "Request under a DPPA permissible purpose (for example litigation use) through counsel or a "
                  "licensed investigator, or a subpoena",
            "ca-on": "Court order or a permitted-purpose request through counsel; plate-owner data is not public "
                     "(verify the current Ontario rules)",
            "uk": "DVLA keeper-data request showing reasonable cause, through counsel or a licensed "
                  "investigator (verify)",
            "intl": "Local licensing authority through local counsel in that jurisdiction",
        },
        "note": "Licence-plate-reader resale data is out of scope for Bunnyhole; a licensed investigator may "
                "query licensed databases under a documented permissible purpose. DPPA lists the permitted "
                "purposes.",
    },
    {
        "finding_kind": "land_title",
        "finding": "Land title, mortgage or lien on real property",
        "custodian": "The land registry (county recorder, OnLand/Teranet, HM Land Registry)",
        "instruments": {
            "us": "County recorder or register of deeds: public search and certified copies (no process needed "
                  "for recorded deeds); subpoena for non-recorded files",
            "ca-on": "OnLand parcel-register search and document copies (government fee applies); counsel for "
                     "anything sealed or unregistered",
            "uk": "HM Land Registry title register and plan (small fee; no process needed)",
            "intl": "Local land registry through local counsel; certified copy with apostille if used in court",
        },
        "note": "Property often sits in a holding company: trace the company, not just the address. Registry "
                "searches are cheap rather than free; confirm the fee first.",
    },
    {
        "finding_kind": "social_platform_account",
        "finding": "Subscriber and log data behind a social-platform or email account",
        "custodian": "The platform or email provider holding the account's subscriber and access logs",
        "instruments": {
            "us": "Subpoena duces tecum through the platform's legal-process portal (basic subscriber data "
                  "only; the Stored Communications Act bars content disclosure to civil litigants)",
            "ca-on": "Norwich Pharmacal order via counsel; platforms often answer only Canadian orders or MLAT "
                     "requests",
            "uk": "Norwich Pharmacal order via counsel; the platform's legal-requests channel",
            "intl": "MLAT or letter of request via counsel; the platform's legal-process guidelines",
        },
        "note": "Bunnyhole confirms that a handle exists on a platform, passively; it never logs in or resets a "
                "password. A matching username is a lead, not an identity. " + _LAWFUL_ONLY,
    },
    {
        "finding_kind": "domain_registrant",
        "finding": "True registrant behind a redacted or proxy-protected domain",
        "custodian": "The domain registrar, or the privacy/proxy service that fronts the registrant",
        "instruments": {
            "us": "Registrar disclosure request or a John Doe subpoena to the registrar through counsel; "
                  "UDRP/ACPA processes where they apply",
            "ca-on": "Norwich Pharmacal order to the registrar or privacy service via counsel; CIRA dispute "
                     "process for .ca (verify)",
            "uk": "Norwich Pharmacal order via counsel; Nominet dispute process for .uk (verify)",
            "intl": "ICANN registrar disclosure channel; letter of request via counsel",
        },
        "note": "Historical WHOIS, certificate and passive-DNS data are public and often show the registrant "
                "before redaction. Shared registrars and hosts are not links.",
    },
    {
        "finding_kind": "vessel_aircraft_registry",
        "finding": "Registered owner and manager or operator of a vessel or aircraft",
        "custodian": "The flag-state ship or aircraft registry, and the vessel or aircraft manager or operator",
        "instruments": {
            "us": "FAA aircraft registry and USCG vessel documentation (public); subpoena to the manager or "
                  "operator for charter, financing and insurance records",
            "ca-on": "Transport Canada civil aircraft and vessel registries (public); production order via "
                     "counsel for manager records",
            "uk": "UK CAA aircraft register and UK Ship Register (public); Norwich Pharmacal order for "
                  "non-public ownership information",
            "intl": "Flag-state registry request through local counsel; Equasis for the ship manager; MLAT for "
                    "non-public records",
        },
        "note": "The registered owner is often a single-asset shell: pivot to the manager or operator, then "
                "walk the ownership chain and screen every party.",
    },
]

_RULES_BY_KIND: Dict[str, dict] = {r["finding_kind"]: r for r in CUSTODIAN_RULES}


def resolve_jurisdiction(jurisdiction: str) -> str:
    """Map a free-form jurisdiction string onto ``us`` / ``ca-on`` / ``uk`` / ``intl`` (default ``intl``)."""
    key = (jurisdiction or "").strip().casefold()
    if key in JURISDICTION_KEYS:
        return key
    if key.startswith("us-"):
        return "us"
    if key in {"gb", "uk"} or key.startswith(("uk-", "gb-")):
        return "uk"
    return "intl"


def custodians_for(finding_kinds: Set[str], jurisdiction: str) -> List[Custodian]:
    """Return the custodian and lawful instrument for each known finding kind, in catalog order.

    Unknown kinds are ignored; an unrecognised jurisdiction falls back to ``intl``.
    """
    resolved = resolve_jurisdiction(jurisdiction)
    wanted = set(finding_kinds)
    out: List[Custodian] = []
    for rule in CUSTODIAN_RULES:
        if rule["finding_kind"] not in wanted:
            continue
        out.append(
            Custodian(
                finding=rule["finding"],
                custodian=rule["custodian"],
                instrument=rule["instruments"][resolved],
                jurisdiction=resolved,
                note=rule["note"],
            )
        )
    return out


# Handoff sheet -------------------------------------------------------------------------------------------

_LICENSED_DB_KINDS = ("names", "addresses", "phones", "emails")
_KIND_LABEL = {
    "names": "name",
    "addresses": "address",
    "phones": "phone",
    "emails": "email",
    "usernames": "username",
    "wallets": "wallet",
    "domains": "domain",
    "organizations": "organization",
}
_UNVERIFIED = "unverified lead"


def _clean_values(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for raw in values or []:
        value = str(raw).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


#: The OFAC 50% rule needs percentages; when the ownership edges carry none, the rule cannot be evaluated.
FIFTY_RULE_NOT_EVALUABLE = "50%-rule: not evaluable (ownership percentages unknown)"


def fifty_rule_not_evaluable(ownership: OwnershipBlock) -> bool:
    """True when ownership edges exist but none carries a percentage (derived from the block, no extra field)."""
    return bool(ownership.edges) and all(edge.pct is None for edge in ownership.edges)


#: Primary sanctions lists (the issuing authority, not an aggregator). Keys are the display names the sanctions
#: screening uses (``pi_notes.SANCTIONS_LISTS``); the EU list has no automated source and is always a manual check.
SANCTIONS_PRIMARY_URLS: Dict[str, str] = {
    "Canada SEMA": "https://www.international.gc.ca/world-monde/international_relations-relations_internationales/"
                   "sanctions/consolidated-consolide.aspx?lang=eng",
    "OpenSanctions": "https://www.opensanctions.org/",
    "OFAC SDN": "https://sanctionssearch.ofac.treas.gov/",
    "UN Consolidated List": "https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list",
    "UK Sanctions List": "https://www.gov.uk/government/publications/the-uk-sanctions-list",
    "EU Sanctions Map": "https://www.sanctionsmap.eu/",
}
_EU_LIST = "EU Sanctions Map"

#: Primary company registry by registration jurisdiction (GLEIF style codes such as ``CA-QC``, or ``us``, ``ca-on``).
_REGISTRIES: Dict[str, str] = {
    "gb": "Companies House (https://find-and-update.company-information.service.gov.uk/)",
    "ca-qc": "Registraire des entreprises du Québec (https://www.registreentreprises.gouv.qc.ca/)",
    "ca-on": "Ontario Business Registry (Ontario Ministry of Public and Business Service Delivery)",
    "ca": "Corporations Canada (federal) and the provincial registry of the head office",
    "ru": "the Russian unified state register of legal entities (EGRUL, https://egrul.nalog.ru/)",
}


def registry_for(jurisdiction: str) -> str:
    """The primary company registry to confirm status and ownership with, from a jurisdiction code. Never empty."""
    key = (jurisdiction or "").strip().casefold()
    if key in ("uk", "gb") or key.startswith(("uk-", "gb-")):
        return _REGISTRIES["gb"]
    if key in _REGISTRIES:
        return _REGISTRIES[key]
    if key.startswith("ca-"):
        return _REGISTRIES["ca"]
    if key == "us" or key.startswith("us-"):
        return "the state Secretary of State business registry of the state of incorporation (and SEC EDGAR if listed)"
    if key:
        return f"the company registry of the jurisdiction of incorporation ({jurisdiction.strip()})"
    return "the company registry of the jurisdiction of incorporation"


#: Short registry names for one-line use (the Bottom line); the full text with the URL is ``registry_for``.
_SHORT_REGISTRIES: Dict[str, str] = {
    "gb": "Companies House",
    "ca-qc": "Registraire des entreprises du Québec",
    "ca-on": "Ontario Business Registry",
    "ca": "Corporations Canada and the provincial head-office registry",
    "ru": "the Russian state register of legal entities (EGRUL)",
    "us": "the state Secretary of State business registry",
}


def registry_short_for(jurisdiction: str) -> str:
    """The primary company registry's short name for a jurisdiction code (same routing as ``registry_for``)."""
    key = (jurisdiction or "").strip().casefold()
    if key in ("uk", "gb") or key.startswith(("uk-", "gb-")):
        return _SHORT_REGISTRIES["gb"]
    if key in _SHORT_REGISTRIES:
        return _SHORT_REGISTRIES[key]
    if key.startswith("ca-"):
        return _SHORT_REGISTRIES["ca"]
    if key.startswith("us-"):
        return _SHORT_REGISTRIES["us"]
    if key:
        return f"the company registry of the jurisdiction of incorporation ({jurisdiction.strip()})"
    return "the company registry of the jurisdiction of incorporation"


def _screening_list_of(entry: str) -> str:
    """The sanctions-list display name an ``SanctionsScreening.not_screened`` entry starts with, or ``""``."""
    return next((name for name in SANCTIONS_PRIMARY_URLS if entry.startswith(name)), "")


def _entity_action_lines(
    sanctions: Optional[SanctionsScreening], entity_profile: Optional[EntityProfile], fallback_jurisdiction: str
) -> List[str]:
    """Next steps for an entity due diligence: verify sanctions on the primary list, confirm the registry record."""
    lines: List[str] = []
    if sanctions is not None:
        seen_lists: Set[str] = set()
        for hit in sanctions.hits:
            list_name = str(hit.get("list") or "")
            primary = SANCTIONS_PRIMARY_URLS.get(list_name) or str(hit.get("url") or "")
            if list_name in seen_lists:
                continue
            seen_lists.add(list_name)
            lines.append(
                f"Verify the sanctions hit on the primary list: {primary} ({list_name}: '{hit.get('name', '')}', "
                "soft name match; check identifiers, not just the name)"
            )
        if sanctions.status != "lists_run" or sanctions.hits:
            missing = [_screening_list_of(e) for e in sanctions.not_screened]
            for list_name in [m for m in missing if m] + [_EU_LIST]:
                if list_name in seen_lists:
                    continue
                seen_lists.add(list_name)
                lines.append(
                    f"Verify sanctions status on the primary list ({list_name} was not screened in this run): "
                    f"{SANCTIONS_PRIMARY_URLS[list_name]}"
                )
    jurisdiction = (entity_profile.jurisdiction if entity_profile else "") or fallback_jurisdiction
    lines.append(
        f"Confirm corporate status and beneficial ownership on the primary registry: {registry_for(jurisdiction)}"
    )
    return lines


def handoff_sheet(
    engagement: PIEngagement,
    verified_identifiers: Dict[str, List[str]],
    custodians: List[Custodian],
    *,
    sanctions: Optional[SanctionsScreening] = None,
    entity_profile: Optional[EntityProfile] = None,
) -> List[str]:
    """Plain lines a licensed investigator or lawyer can paste into their own workflow.

    ``verified_identifiers`` are identifiers Bunnyhole collected; each line labels them an unverified lead,
    because only the licensed layer or the custodian can confirm them. Blank values are skipped, duplicates
    collapse, and no line claims confirmation beyond what was supplied.

    "Run through licensed database" and "Field verification" lines are for people: they are emitted only for a
    person subject or a ``locate`` / ``missing_person`` case. For an entity (a company's address or name) they are
    replaced by "Confirm with a primary source" lines, plus action lines: verify a sanctions hit (or the lists that
    were not screened, when ``sanctions`` is given) on the primary list, and confirm corporate status and
    beneficial ownership on the primary registry for the jurisdiction in ``entity_profile``.
    """
    lines: List[str] = [
        f"Engagement {engagement.engagement_id} ({engagement.case_type.value}); purpose as stated by the client: "
        f"{engagement.purpose.strip()}"
    ]
    if engagement.matter_ref.strip():
        lines.append(f"Matter reference: {engagement.matter_ref.strip()}")
    if engagement.jurisdiction.strip():
        lines.append(f"Jurisdiction: {engagement.jurisdiction.strip()}")
    lines.append(
        "Every identifier below comes from free public sources and is an unverified lead until a licensed "
        "investigator or counsel confirms it through lawful channels."
    )
    lines.append("Bunnyhole output is not a consumer report and must not be used for eligibility decisions.")

    person_work = engagement.subject_is_person or engagement.case_type in (CaseType.LOCATE, CaseType.MISSING_PERSON)
    if not person_work:
        lines.extend(_entity_action_lines(sanctions, entity_profile, engagement.jurisdiction))

    ordered_kinds = [k for k in _LICENSED_DB_KINDS if k in verified_identifiers]
    ordered_kinds += [k for k in verified_identifiers if k not in _LICENSED_DB_KINDS]
    for kind in ordered_kinds:
        label = _KIND_LABEL.get(kind, kind.replace("_", " ").strip() or "identifier")
        for value in _clean_values(verified_identifiers[kind]):
            if kind in _LICENSED_DB_KINDS and person_work:
                lines.append(f"Run through licensed database: {value} ({label}; {_UNVERIFIED})")
            elif kind == "wallets":
                lines.append(
                    "Run through an enterprise chain-analytics provider via counsel or a licensed investigator: "
                    f"{value} ({label}; {_UNVERIFIED})"
                )
            else:
                lines.append(f"Confirm with a primary source: {value} ({label}; {_UNVERIFIED})")
            if kind == "addresses" and person_work:
                lines.append(f"Field verification (public place only; licensed investigator): {value}")

    for custodian in custodians:
        lines.append(
            f"Request via counsel: {custodian.instrument} to {custodian.custodian} for {custodian.finding} "
            f"(jurisdiction: {custodian.jurisdiction})"
        )
    return lines
