"""Solar BD Playbook: the structured knowledge base behind `bunnyhole solar`.

Everything here is *data* the planner and scout agent reason over:

- ``DECISION_ROLES``   – the buying unit for O&M / cleaning technology (roles, never private persons)
- ``BUYING_TRIGGERS``  – keyword rules that turn public news into dated propensity-to-buy signals
- ``ROUTE_CATALOG``    – every lawful route to a solar company's decision-makers, with how-to steps
- ``EVENTS``           – where O&M / asset-management people physically gather
- ``PROGRAMS``         – accelerators & corporate-innovation doors that bypass procurement
- ``ASSOCIATIONS``     – trade bodies with O&M committees
- ``WARM_INTRO_ORGS``  – investors, lenders, independent engineers, OEMs, O&M firms, sensor vendors
- ``INDIA_PLAYBOOK``   – the India entry manual (institutions, culture, compliance, calendar)
- ``GUERRILLA_TACTICS``– non-traditional tactics with legal/safety flags
- ``COMPLIANCE_RULES`` – outreach law by jurisdiction

Facts flagged ``verify`` are curated from public sources and should be re-checked before a
campaign; the long-form evidence lives in ``research/10_*`` – ``research/15_*``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple


class Region(str, Enum):
    GLOBAL = "global"
    INDIA = "india"
    US = "us"
    EU = "eu"
    MENA = "mena"
    APAC = "apac"
    LATAM = "latam"
    AFRICA = "africa"


class CompanyType(str, Enum):
    IPP = "ipp"            # Independent power producer / developer / asset owner
    UTILITY = "utility"    # Regulated or state utility with owned solar
    EPC = "epc"            # Engineering-procurement-construction contractor
    OM = "om"              # Third-party O&M / asset-services contractor
    CI = "ci"              # Commercial & industrial rooftop / open-access developer
    OEM = "oem"            # Module / tracker / inverter manufacturer
    FUND = "fund"          # Infrastructure investor owning platforms
    IE = "ie"              # Independent engineer / technical advisor
    UNKNOWN = "unknown"


class RouteCategory(str, Enum):
    IDENTIFY = "identify"          # Public sources that reveal who holds the role
    EVENT = "event"                # Conferences / summits
    ASSOCIATION = "association"    # Trade bodies
    WARM_INTRO = "warm_intro"      # Investors, lenders, IEs, OEMs, O&M partners
    PROGRAM = "program"            # Accelerators / innovation challenges
    MEDIA = "media"                # Trade press, podcasts, awards
    CREDIBILITY = "credibility"    # Studies, IE validation, standards
    DIRECT = "direct"              # Vendor portals, role mailboxes, LinkedIn, email, phone
    TENDER = "tender"              # Public procurement
    GUERRILLA = "guerrilla"        # Non-traditional, proof-first tactics


class CostTier(str, Enum):
    FREE = "free"
    LOW = "low"        # < USD 1k
    MID = "mid"        # USD 1k-15k
    HIGH = "high"      # > USD 15k


# --------------------------------------------------------------------------------------
# 1. Decision-making unit (roles, not people)
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class DecisionRole:
    role_id: str
    title_patterns: Tuple[str, ...]          # lower-case substrings that identify the role in public titles
    dmu_role: str                             # CHAMPION | DECIDER | APPROVER | GATEKEEPER | INFLUENCER
    company_types: Tuple[CompanyType, ...]
    cares_about: Tuple[str, ...]
    fears: Tuple[str, ...]
    pitch_angle: str
    first_touch: str                          # best first route to this role


DECISION_ROLES: Tuple[DecisionRole, ...] = (
    DecisionRole(
        "head_om", ("head of o&m", "head of operations and maintenance", "vp operations", "vice president o&m",
                    "director o&m", "director operations", "chief operating officer", "coo", "head - o&m", "om head"),
        "CHAMPION", (CompanyType.IPP, CompanyType.UTILITY, CompanyType.OM, CompanyType.CI),
        ("performance ratio (PR)", "availability", "OPEX per MW-year", "soiling ratio", "cleaning cycles", "water use", "labour headcount"),
        ("module micro-cracks / abrasion", "warranty voidance", "downtime during cleaning", "a vendor that disappears after the pilot"),
        "Recover 2-8% of lost yield at lower OPEX than manual cleaning, with a module-OEM compatibility letter in hand.",
        "om_practitioner_events",
    ),
    DecisionRole(
        "head_asset_mgmt", ("head of asset management", "vp asset management", "director asset management",
                            "chief asset officer", "asset manager", "head of performance"),
        "DECIDER", (CompanyType.IPP, CompanyType.FUND, CompanyType.UTILITY),
        ("P50 vs actual yield", "PPA performance / availability guarantees", "lender covenants & IE sign-off", "OPEX budget vs plan", "portfolio-wide standardisation"),
        ("independent-engineer pushback", "unbudgeted capex", "a pilot that cannot scale across the portfolio"),
        "Yield recovery that shows up in the P50 reconciliation and survives the IE; priced as OPEX, rolled out portfolio-wide.",
        "solar_asset_management_events",
    ),
    DecisionRole(
        "plant_manager", ("plant manager", "site manager", "plant head", "site head", "station manager", "cluster head"),
        "CHAMPION", (CompanyType.IPP, CompanyType.UTILITY, CompanyType.OM),
        ("cleaning frequency vs generation", "labour availability", "water tankers", "safety incidents", "breakage counts"),
        ("safety of unfamiliar equipment", "being blamed for a failed trial"),
        "Less manual cleaning, fewer tankers, no breakage, data they can show their boss. Offer a one-row, no-cost trial.",
        "one_row_demo",
    ),
    DecisionRole(
        "cto_innovation", ("chief technology officer", "cto", "chief innovation", "head of innovation", "head of technology",
                           "vp technology", "head of digital", "head of r&d", "chief engineering"),
        "INFLUENCER", (CompanyType.IPP, CompanyType.UTILITY, CompanyType.EPC, CompanyType.OEM),
        ("technology roadmap", "pilot data quality", "bankability of new tech", "digital O&M / monitoring integration"),
        ("vaporware", "lack of third-party test data"),
        "Independent test data (DNV/TUV/NREL/IIT) plus a structured pilot with pre-agreed success metrics.",
        "innovation_programs",
    ),
    DecisionRole(
        "procurement", ("head of procurement", "chief procurement", "procurement manager", "supply chain", "vendor development",
                        "purchase manager", "head purchase", "contracts manager", "sourcing"),
        "GATEKEEPER", tuple(CompanyType),
        ("approved-vendor-list onboarding", "price per MW", "payment terms", "compliance docs (GST, BIS, insurance, ISO)", "spares & service SLAs"),
        ("single-source risk", "a vendor without local service presence"),
        "Register on the vendor portal early; arrive with the compliance pack done so the champion never waits on paperwork.",
        "vendor_registration_portal",
    ),
    DecisionRole(
        "cfo", ("chief financial officer", "cfo", "finance director", "head of finance"),
        "APPROVER", (CompanyType.IPP, CompanyType.UTILITY, CompanyType.EPC, CompanyType.OM, CompanyType.CI),
        ("payback period", "capex vs opex treatment", "IRR uplift on the asset", "financing options"),
        ("capex that is not in the budget cycle",),
        "OPEX-neutral or performance-based pricing: the plant pays from recovered kWh, no new capex line.",
        "roi_one_pager",
    ),
    DecisionRole(
        "projects_epc", ("head of projects", "project director", "vp projects", "president projects", "chief projects officer",
                         "head of engineering", "design head"),
        "DECIDER", (CompanyType.EPC, CompanyType.IPP),
        ("bill-of-quantities inclusion", "commissioning schedule", "O&M handover baseline", "tracker/row compatibility"),
        ("anything that delays COD",),
        "Spec the system into new builds before COD so the O&M baseline is set with it installed.",
        "oem_partnerships",
    ),
    DecisionRole(
        "hse", ("head of hse", "ehs", "health safety", "safety head"),
        "GATEKEEPER", (CompanyType.IPP, CompanyType.UTILITY, CompanyType.OM, CompanyType.EPC),
        ("permit-to-work", "water & chemical use", "working at height / live DC"),
        ("an untested device on a live plant",),
        "Safety file first: method statement, risk assessment, chemical-free, no human on the array.",
        "vendor_registration_portal",
    ),
    DecisionRole(
        "promoter_md", ("managing director", "chairman", "founder", "promoter", "chief executive officer", "ceo", "group president"),
        "APPROVER", (CompanyType.IPP, CompanyType.EPC, CompanyType.CI, CompanyType.OM),
        ("group-level cost leadership", "reputation / ESG", "relationships"),
        ("embarrassment from a failed vendor",),
        "In India family-led groups the MD often signs anything new: get a trusted introducer and a reference from a peer group.",
        "warm_intro_investors",
    ),
    DecisionRole(
        "independent_engineer", ("independent engineer", "technical advisor", "lender's engineer", "owner's engineer"),
        "GATEKEEPER", (CompanyType.IE,),
        ("standards compliance (IEC 61215 / 62788 abrasion)", "module-OEM warranty letters", "field data"),
        ("approving something that later damages modules",),
        "Brief the IE before the client asks them; hand them the test reports and warranty letters.",
        "ie_validation",
    ),
)


# --------------------------------------------------------------------------------------
# 2. Buying triggers (public-news keyword rules -> dated propensity signals)
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class BuyingTrigger:
    trigger_id: str
    keywords: Tuple[str, ...]            # all lower-case; any match fires (regex allowed)
    weight: float                        # 0-40 heat contribution
    why: str
    pitch: str
    window_days: int = 120               # how long the signal stays "hot"


BUYING_TRIGGERS: Tuple[BuyingTrigger, ...] = (
    BuyingTrigger("COMPETITOR_CLEANING_ADOPTED",
                  ("robotic cleaning", "cleaning robot", "ecoppia", "waterless cleaning", "water-free cleaning", "solarcleano", "nomadd", "taypro", "airtouch", "bladeranger", "sun-x",
                   "leapting", "sunpure", "sol-bright", "solabot", "aegeus", "vayu solar", "amir robotics", "anti-soiling coating", "self-cleaning"),
                  32.0, "They already believe in automated cleaning; the sale is differentiation, not education.",
                  "Lead with a head-to-head on breakage, water, uptime and cost per MW vs the incumbent robot/coating."),
    BuyingTrigger("SOILING_AWARENESS",
                  ("soiling", "dust accumulation", "panel cleaning", "module cleaning", "dust storm", "cleaning cost", "cleaning cycle"),
                  28.0, "Soiling is being discussed publicly - the problem is already on the agenda.",
                  "Quote their own words back; offer a free soiling audit on the plant they named."),
    BuyingTrigger("WATER_CONSTRAINT",
                  ("water scarcity", "water shortage", "water restriction", "groundwater", "water ban", "water-stressed", "water stewardship", "water use"),
                  26.0, "Water is the hard constraint on manual cleaning in deserts; waterless/self-cleaning is the only path.",
                  "Litres saved per MW-year and the ESG/water-stewardship headline they can publish."),
    BuyingTrigger("YIELD_SHORTFALL",
                  ("underperform", "generation shortfall", "lower generation", "below p50", "performance ratio", "yield loss", "output fell", "weak generation"),
                  26.0, "Missed generation hurts PPA revenue and lender covenants; cheapest recovery is cleaning.",
                  "Yield-recovery guarantee tied to measured soiling ratio."),
    BuyingTrigger("NEW_PLANT_COMMISSIONED",
                  ("commissioned", "commissioning", "commercial operation", "cod ", "energised", "energized", "connected to the grid", "synchronised"),
                  22.0, "New plants set their O&M baseline in the first 6-12 months; vendors chosen then stay for the contract term.",
                  "Install before the first cleaning season so the O&M budget is written around you."),
    BuyingTrigger("OM_CONTRACT_CYCLE",
                  ("o&m contract", "operations and maintenance contract", "o&m agreement", "o&m partner", "o&m services", "asset management agreement"),
                  22.0, "O&M renewals are the moment scope and vendors get re-opened.",
                  "Offer to be written into the O&M scope, or partner with the bidding O&M contractor."),
    BuyingTrigger("INNOVATION_OPEN",
                  ("innovation", "startup", "accelerator", "pilot project", "pilot programme", "pilot program", "venture", "incubat", "hackathon", "challenge"),
                  24.0, "A public innovation posture means a door exists that bypasses procurement.",
                  "Apply through the program; it lands you in front of the CTO/innovation lead with a sponsor."),
    BuyingTrigger("EXEC_CHANGE",
                  ("appoints", "appointed", "names new", "joins as", "new chief", "new ceo", "new coo", "new cto", "new head of", "takes over as"),
                  16.0, "New leaders reset priorities in their first 90 days and are reachable before gatekeepers form.",
                  "Congratulate, then offer a quick win they can show in their first quarter."),
    BuyingTrigger("CAPITAL_EVENT",
                  ("raises", "funding round", "green bond", "refinanc", "ipo", "investment of", "equity investment", "financial close"),
                  15.0, "Fresh capital and refinancing create OPEX-optimisation mandates and IE reviews.",
                  "Frame as IRR uplift on the financed portfolio; brief the IE."),
    BuyingTrigger("PIPELINE_GROWTH",
                  ("letter of award", "loa", "wins bid", "ppa signed", "signs ppa", "awarded", "tender win", "bags", "secures", "gw pipeline"),
                  14.0, "Pipeline growth means more plants to specify and more O&M to budget.",
                  "Get into the EPC spec and the O&M plan of the newly awarded capacity."),
    BuyingTrigger("DUSTY_GEOGRAPHY",
                  ("rajasthan", "bhadla", "khavda", "jaisalmer", "jodhpur", "kutch", "bikaner", "pavagada", "gujarat", "saudi", "neom", "abu dhabi", "dubai", "atacama",
                   "nevada", "arizona", "mojave", "desert", "oman", "egypt", "morocco", "namibia", "sahara"),
                  14.0, "High-soiling climate: the ROI case is strongest where dust is worst.",
                  "Use regional soiling-loss data for that exact park in the first email."),
    BuyingTrigger("LABOUR_PRESSURE",
                  ("labour shortage", "labor shortage", "manpower", "wage", "workforce", "skilled labour", "skilled labor"),
                  14.0, "Manual cleaning is labour-bound; shortages push automation.",
                  "Headcount neutral cleaning; redeploy crews to higher-value O&M."),
    BuyingTrigger("MODULE_DAMAGE_SENSITIVITY",
                  ("micro-crack", "microcrack", "hail", "breakage", "cracked modules", "glass breakage", "warranty claim"),
                  12.0, "They are sensitive to module damage: a contact-free or low-abrasion method is a differentiator.",
                  "Abrasion test reports and OEM warranty-compatibility letters up front."),
    BuyingTrigger("ESG_REPORTING",
                  ("esg report", "sustainability report", "net zero", "water positive", "brsr", "csr"),
                  10.0, "ESG disclosure teams look for quantified water and emissions savings.",
                  "Deliver the water-saved and CO2-avoided numbers in their reporting format."),
    BuyingTrigger("PORTFOLIO_EXPANSION",
                  ("acquires", "acquisition", "acquired", "portfolio of", "adds", "expands", "takes over"),
                  10.0, "Portfolio integration triggers O&M standardisation reviews.",
                  "One standard across the acquired fleet; start with the dustiest site."),
    BuyingTrigger("DIGITAL_OM",
                  ("digital o&m", "ai monitoring", "drone inspection", "scada", "predictive maintenance", "digital twin", "remote monitoring"),
                  10.0, "They invest in O&M intelligence; a cleaning system with data integration fits the stack.",
                  "Expose soiling-ratio and cleaning logs to their monitoring platform via API."),
)

_TRIGGER_PATTERNS: List[Tuple[BuyingTrigger, re.Pattern[str]]] = [
    (t, re.compile("|".join(re.escape(k) if not any(ch in k for ch in ".*+?[]()") else k for k in t.keywords), re.IGNORECASE))
    for t in BUYING_TRIGGERS
]


def classify_buying_signals(text: str) -> List[BuyingTrigger]:
    """Return every BuyingTrigger whose keywords appear in text (deterministic, ordered by weight)."""
    hits = [t for t, pat in _TRIGGER_PATTERNS if pat.search(text or "")]
    return sorted(hits, key=lambda t: t.weight, reverse=True)


# Solar-specific news queries the scout runs per target (brand + angle). {c} is the company name.
NEWS_QUERY_ANGLES: Tuple[Tuple[str, str], ...] = (
    ("OM", '"{c}" solar "O&M" OR "operations and maintenance"'),
    ("SOILING", '"{c}" solar soiling OR "panel cleaning" OR "cleaning robot" OR waterless'),
    ("PLANTS", '"{c}" solar commissioned OR "commercial operation" OR MW'),
    ("LEADERS", '"{c}" appoints OR appointed OR "head of"'),
    ("CAPITAL", '"{c}" solar funding OR refinancing OR "green bond" OR tender OR "letter of award"'),
)


# --------------------------------------------------------------------------------------
# 3. Route catalog
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    route_id: str
    name: str
    category: RouteCategory
    reaches: Tuple[str, ...]                # role_ids from DECISION_ROLES
    cost: CostTier
    days_to_meeting: int                     # typical elapsed days to a real conversation
    effectiveness: int                       # 1-5 curated
    regions: Tuple[Region, ...]
    company_types: Tuple[CompanyType, ...]
    how_to: Tuple[str, ...]
    urls: Tuple[str, ...] = ()
    legal_note: str = ""
    probe_paths: Tuple[str, ...] = ()        # website paths the scout probes to confirm this route exists
    scan_keywords: Tuple[str, ...] = ()      # page keywords that confirm the route

    def applies(self, region: Region, ctype: CompanyType) -> bool:
        r_ok = Region.GLOBAL in self.regions or region in self.regions or region == Region.GLOBAL
        c_ok = (not self.company_types) or ctype in self.company_types or ctype == CompanyType.UNKNOWN
        return r_ok and c_ok


ALL_TYPES: Tuple[CompanyType, ...] = tuple(ct for ct in CompanyType if ct not in (CompanyType.UNKNOWN,))
BUYERS: Tuple[CompanyType, ...] = (CompanyType.IPP, CompanyType.UTILITY, CompanyType.OM, CompanyType.CI, CompanyType.EPC, CompanyType.FUND)

ROUTE_CATALOG: Tuple[Route, ...] = (
    # ---------------- IDENTIFY ----------------
    Route("leadership_page", "Corporate leadership / management page", RouteCategory.IDENTIFY,
          ("head_om", "head_asset_mgmt", "cto_innovation", "promoter_md"), CostTier.FREE, 1, 3, (Region.GLOBAL,), ALL_TYPES,
          ("Open /leadership, /management, /about/team, /board; note the exact titles used for operations, assets and technology.",
           "Map titles to the decision-making unit (champion / decider / gatekeeper) before any outreach.",
           "Cross-check against the latest annual report's management section for people the web page omits."),
          probe_paths=("/leadership", "/management", "/about-us/leadership", "/about/leadership", "/our-leadership", "/team", "/about-us/management",
                       "/leadership-team", "/about/management-team", "/board-of-directors", "/about-us/board-of-directors", "/management-team"),
          scan_keywords=("chief", "head of", "vice president", "director", "officer")),
    Route("annual_report_ir", "Annual report & investor presentations", RouteCategory.IDENTIFY,
          ("head_asset_mgmt", "cfo", "promoter_md"), CostTier.FREE, 1, 3, (Region.GLOBAL,), (CompanyType.IPP, CompanyType.UTILITY, CompanyType.EPC, CompanyType.OEM, CompanyType.FUND),
          ("Read the O&M / operations section: they state cleaning frequency, water, PR targets and the plants with generation shortfalls.",
           "Investor decks list the plant portfolio with MW and location - pick the dustiest sites for the ROI one-pager.",
           "The IR contact is a legitimate door for 'we have a question on your O&M disclosures'."),
          probe_paths=("/investors", "/investor-relations", "/investor", "/annual-report", "/investors/annual-reports", "/financials", "/investor-relations/annual-reports"),
          scan_keywords=("annual report", "investor presentation", "results")),
    Route("regulatory_filings", "Regulatory filings (SEC EDGAR / BSE-NSE / Companies House)", RouteCategory.IDENTIFY,
          ("head_asset_mgmt", "cfo"), CostTier.FREE, 2, 3, (Region.GLOBAL,), (CompanyType.IPP, CompanyType.UTILITY, CompanyType.OEM, CompanyType.EPC),
          ("US-listed: EDGAR full-text search for 'soiling' or 'panel cleaning' in 10-K risk factors - it names the issue and the officer who signs.",
           "India-listed: BSE/NSE corporate announcements and the Annual Report's Management Discussion for O&M cost commentary.",
           "UK/EU: Companies House officers & PSC; EU TED for public procurement of O&M scopes."),
          urls=("https://efts.sec.gov/LatestSearch/", "https://www.bseindia.com/corporates/ann.html", "https://find-and-update.company-information.service.gov.uk/")),
    Route("press_newsroom", "Company newsroom & press contact", RouteCategory.IDENTIFY,
          ("head_om", "cto_innovation", "promoter_md"), CostTier.FREE, 3, 2, (Region.GLOBAL,), ALL_TYPES,
          ("Press releases name the executives quoted on plant commissioning and O&M partnerships - those are the people who own the topic.",
           "The media mailbox is a lawful, monitored channel; use it to request the right contact for a technical partnership, not to pitch."),
          probe_paths=("/media", "/press", "/newsroom", "/news", "/media-centre", "/media-center", "/press-releases", "/news-and-media"),
          scan_keywords=("press", "media", "release")),
    Route("conference_speaker_lists", "Conference speaker & panel lists", RouteCategory.IDENTIFY,
          ("head_om", "head_asset_mgmt", "cto_innovation"), CostTier.FREE, 5, 4, (Region.GLOBAL,), BUYERS,
          ("Scan last year's agenda of Solar Asset Management, Intersolar, RE+, REI, Mercom and Solar Quarter events for the target company's speakers.",
           "A speaker has a public topic you can reference in a message, and will be at the next event - book the hallway meeting in advance.")),
    Route("linkedin_company_people", "LinkedIn company page & Sales Navigator (ToS-compliant)", RouteCategory.IDENTIFY,
          ("head_om", "head_asset_mgmt", "plant_manager", "procurement"), CostTier.LOW, 3, 4, (Region.GLOBAL,), ALL_TYPES,
          ("Use the company page's People tab / Sales Navigator title filters ('O&M', 'asset management', 'plant head') by hand - no scraping or automation.",
           "Engage on their posts for 2-3 weeks before a connection request; the request should reference a specific public post or plant.",
           "InMail only after a warm signal; keep a 3-touch cap."),
          urls=("https://www.linkedin.com/company/{slug}/people/",),
          legal_note="LinkedIn prohibits scraping and automation tools; manual use only."),
    Route("trade_press_interviews", "Trade-press interviews with O&M leaders", RouteCategory.IDENTIFY,
          ("head_om", "head_asset_mgmt"), CostTier.FREE, 3, 3, (Region.GLOBAL,), BUYERS,
          ("Search pv magazine, PV Tech, Solar Power World, Mercom India, Saur Energy and Solar Quarter for interviews with the company's O&M or asset heads.",
           "An interview gives you their stated priorities and a natural opener: 'you said X about soiling in Mercom last month'."),
          urls=("https://www.pv-magazine.com/", "https://www.pv-tech.org/", "https://www.mercomindia.com/", "https://www.saurenergy.com/", "https://solarquarter.com/")),
    Route("job_postings_signal", "Careers page & job boards as a buying signal", RouteCategory.IDENTIFY,
          ("head_om", "plant_manager"), CostTier.FREE, 2, 3, (Region.GLOBAL,), BUYERS,
          ("Openings for O&M engineers, cleaning supervisors, plant managers or 'asset performance' roles tell you where capacity is growing and who the hiring manager is.",
           "A post that mentions 'module cleaning' in the duties is a direct admission the cost centre exists."),
          probe_paths=("/careers", "/jobs", "/career", "/join-us", "/work-with-us", "/careers/openings"),
          scan_keywords=("o&m", "operations", "maintenance", "plant", "asset")),
    Route("gleif_corporate_tree", "GLEIF corporate tree -> the real decision centre", RouteCategory.IDENTIFY,
          ("head_asset_mgmt", "promoter_md"), CostTier.FREE, 1, 2, (Region.GLOBAL,), ALL_TYPES,
          ("Many 'companies' are SPVs; the LEI tree shows the platform or fund that actually buys O&M technology.",
           "Target the ultimate parent's asset-management team and reference the SPV's plant.")),
    Route("public_plant_registries", "Public plant registries -> dustiest sites first", RouteCategory.IDENTIFY,
          ("plant_manager", "head_om"), CostTier.FREE, 2, 3, (Region.GLOBAL,), BUYERS,
          ("India: MNRE/CEA/SECI project lists and state nodal agency lists; US: EIA-860 generator data; global: Global Energy Monitor Solar Power Tracker.",
           "Rank the company's plants by soiling climate and MW; the ROI one-pager is written for a named plant, not the company."),
          urls=("https://cea.nic.in/", "https://www.eia.gov/electricity/data/eia860/", "https://globalenergymonitor.org/projects/global-solar-power-tracker/")),

    # ---------------- DIRECT ----------------
    Route("vendor_registration_portal", "Supplier / vendor registration portal (AVL onboarding)", RouteCategory.DIRECT,
          ("procurement", "hse"), CostTier.FREE, 14, 3, (Region.GLOBAL,), BUYERS + (CompanyType.OEM,),
          ("Register before you pitch; AVL onboarding takes weeks and a champion cannot issue a PO to an unregistered vendor.",
           "Prepare the pack: company registration, tax IDs (GST/PAN in India), ISO certificates, insurance, HSE policy, bank letter, references.",
           "Use the portal ticket/helpdesk to ask which category code covers 'module cleaning equipment / O&M services'."),
          probe_paths=("/suppliers", "/supplier-registration", "/vendor-registration", "/vendors", "/procurement", "/supplier", "/vendor", "/partners",
                       "/tenders", "/become-a-supplier", "/supplier-portal", "/vendor-portal", "/e-procurement", "/eprocurement"),
          scan_keywords=("vendor", "supplier", "registration", "procurement", "tender")),
    Route("role_mailboxes", "Published role mailboxes (procurement@, info@, media@)", RouteCategory.DIRECT,
          ("procurement", "head_om"), CostTier.FREE, 7, 2, (Region.GLOBAL,), ALL_TYPES,
          ("Only use published functional mailboxes; ask to be routed to the O&M / asset-management owner for a technical evaluation.",
           "One short message, one concrete ask (a 20-minute technical call), one attachment (the 1-page ROI for a named plant)."),
          probe_paths=("/contact", "/contact-us", "/contactus", "/get-in-touch", "/reach-us"),
          scan_keywords=("@",)),
    Route("linkedin_personal_outreach", "Warm LinkedIn outreach to role-holders", RouteCategory.DIRECT,
          ("head_om", "head_asset_mgmt", "cto_innovation", "plant_manager"), CostTier.LOW, 10, 3, (Region.GLOBAL,), BUYERS,
          ("Sequence: comment on 2-3 of their posts -> connect with a note tied to a public fact -> share a plant-specific insight -> ask for 20 minutes.",
           "Never pitch in the connection note; never automate.",
           "In India, a LinkedIn connect followed by a referral from a mutual contact outperforms cold InMail."),
          legal_note="Manual only; respect LinkedIn ToS and regional data-protection law."),
    Route("email_sequence_b2b", "Compliant B2B email sequence", RouteCategory.DIRECT,
          ("head_om", "head_asset_mgmt", "procurement"), CostTier.LOW, 14, 2, (Region.GLOBAL,), BUYERS,
          ("Business-role addresses only, obtained from public corporate sources or stated email patterns; include identity, postal address and opt-out.",
           "3 touches over 3 weeks, each adding new value (plant ROI, test report, reference), then stop.",
           "US: CAN-SPAM. EU: legitimate-interest B2B is allowed in most states but Germany/Austria need prior consent for cold email. India: DPDP 2023 + reasonable B2B purpose; keep records of source and opt-outs."),
          legal_note="See COMPLIANCE_RULES; do not harvest personal emails."),
    Route("phone_switchboard", "Switchboard -> O&M department", RouteCategory.DIRECT,
          ("head_om", "plant_manager"), CostTier.FREE, 5, 2, (Region.GLOBAL,), BUYERS,
          ("Published corporate numbers only. Ask for the O&M or asset-management office, not a named person; request the right contact for a technical evaluation.",
           "India: TRAI telemarketing rules apply to promotional calls to numbers on DND - corporate landlines are the safe channel."),
          legal_note="TRAI TCCCPR-2018 in India; TCPA in the US for mobiles."),
    Route("whatsapp_business_india", "WhatsApp Business follow-up (India, after first contact)", RouteCategory.DIRECT,
          ("plant_manager", "head_om", "procurement"), CostTier.FREE, 3, 4, (Region.INDIA, Region.MENA), BUYERS,
          ("WhatsApp is the working channel for Indian site teams, but only after a meeting or an exchanged card - never as a cold first touch.",
           "Share short videos of the system working on a similar plant; respond same-day; move the deal to email for anything contractual."),
          legal_note="Consent-based; opt out immediately on request."),

    # ---------------- EVENTS ----------------
    Route("solar_asset_management_events", "Solar Asset Management (Solarplaza) NA / Europe / Asia", RouteCategory.EVENT,
          ("head_asset_mgmt", "head_om"), CostTier.MID, 30, 5, (Region.US, Region.EU, Region.APAC, Region.GLOBAL), BUYERS,
          ("The densest room of asset managers and O&M heads in the industry; attend as a delegate before you ever buy a booth.",
           "Pre-book 10 meetings via the event app; host a 6-person dinner the night before.")),
    Route("om_practitioner_events", "O&M-specific workshops & summits", RouteCategory.EVENT,
          ("head_om", "plant_manager"), CostTier.MID, 30, 5, (Region.GLOBAL,), BUYERS,
          ("Solar Quarter O&M summits (India), SolarPower Europe O&M & Asset Management events, PV ModuleTech, and regional O&M masterclasses.",
           "Sponsor a 20-minute technical slot with field data rather than a booth; practitioners come for data.")),
    Route("re_plus", "RE+ (North America)", RouteCategory.EVENT,
          ("head_om", "head_asset_mgmt", "cto_innovation"), CostTier.HIGH, 45, 4, (Region.US,), BUYERS + (CompanyType.OEM,),
          ("Largest NA show; the asset-owner track and the startup pavilion are where small vendors get O&M meetings.",
           "Apply for the startup competition for stage time; schedule meetings 6 weeks ahead."),
          urls=("https://www.re-plus.com/",)),
    Route("intersolar_europe", "Intersolar Europe / The smarter E (Munich)", RouteCategory.EVENT,
          ("head_om", "cto_innovation", "projects_epc"), CostTier.HIGH, 45, 4, (Region.EU, Region.MENA, Region.AFRICA), BUYERS + (CompanyType.OEM,),
          ("Enter the Intersolar Award / ees Award; shortlisted companies get stage and press coverage that opens European and MENA doors.",),
          urls=("https://www.intersolar.de/",)),
    Route("intersolar_india", "Intersolar India / The smarter E India (Gandhinagar)", RouteCategory.EVENT,
          ("head_om", "projects_epc", "procurement"), CostTier.MID, 45, 4, (Region.INDIA,), BUYERS + (CompanyType.OEM,),
          ("Co-located with the Gujarat ecosystem (Khavda is near); EPC and IPP project teams attend in force.",),
          urls=("https://www.intersolar.in/",)),
    Route("rei_expo_india", "Renewable Energy India (REI) Expo (Greater Noida)", RouteCategory.EVENT,
          ("head_om", "procurement", "projects_epc"), CostTier.MID, 45, 4, (Region.INDIA,), BUYERS + (CompanyType.OEM,),
          ("The largest Indian renewables show; delegate + hallway strategy beats a small booth for a first year.",),
          urls=("https://www.renewableenergyindiaexpo.com/",)),
    Route("mercom_solar_quarter_india_summits", "Mercom India Renewables Summit & Solar Quarter events/awards", RouteCategory.EVENT,
          ("head_om", "head_asset_mgmt", "promoter_md"), CostTier.MID, 30, 5, (Region.INDIA,), BUYERS,
          ("Smaller, senior rooms: IPP CXOs and O&M heads speak on panels; awards nights are where introductions happen.",
           "Pitch an O&M-track talk with Indian field data."),
          urls=("https://www.mercomindia.com/", "https://solarquarter.com/")),
    Route("wfes_mena", "World Future Energy Summit (Abu Dhabi) & Middle East Energy (Dubai)", RouteCategory.EVENT,
          ("head_om", "head_asset_mgmt", "procurement"), CostTier.HIGH, 45, 4, (Region.MENA,), BUYERS,
          ("Masdar, ACWA, EWEC, DEWA and AMEA teams attend; combine with MESIA membership and the Masdar / Saudi innovation programs.",),
          urls=("https://www.worldfutureenergysummit.com/", "https://www.middleeast-energy.com/")),
    Route("host_side_dinner", "Host your own side dinner / roundtable next to a major event", RouteCategory.EVENT,
          ("head_om", "head_asset_mgmt"), CostTier.LOW, 30, 5, (Region.GLOBAL,), BUYERS,
          ("6-10 practitioners, one topic ('soiling losses in 2026'), no pitch; you are the convener, which is worth more than a booth.",
           "Invite via speakers list + LinkedIn; confirm by phone; publish a 1-page summary afterwards and send to attendees.")),

    # ---------------- ASSOCIATIONS ----------------
    Route("solarpower_europe_om", "SolarPower Europe O&M & Asset Management workstream", RouteCategory.ASSOCIATION,
          ("head_om", "head_asset_mgmt"), CostTier.MID, 60, 4, (Region.EU, Region.MENA, Region.AFRICA), BUYERS,
          ("Membership gives a seat in the O&M Best Practice Guidelines working group where O&M heads of the big IPPs sit.",
           "Contribute a soiling / cleaning chapter; you become the reference."),
          urls=("https://www.solarpowereurope.org/",)),
    Route("seia", "SEIA (US) committees & regional chapters", RouteCategory.ASSOCIATION,
          ("head_om", "head_asset_mgmt"), CostTier.MID, 60, 3, (Region.US,), BUYERS,
          ("Join the O&M / asset-management working groups; present field data at member webinars.",),
          urls=("https://www.seia.org/",)),
    Route("nsefi_india", "NSEFI (National Solar Energy Federation of India)", RouteCategory.ASSOCIATION,
          ("head_om", "promoter_md", "projects_epc"), CostTier.LOW, 45, 4, (Region.INDIA,), BUYERS + (CompanyType.OEM,),
          ("The IPP federation; member meetings and policy consultations put you in the same room as promoters and O&M heads.",
           "Offer to present soiling-loss data for Rajasthan/Gujarat parks at an NSEFI O&M session."),
          urls=("https://nsefi.in/",)),
    Route("isa_alliance", "International Solar Alliance (HQ Gurugram) programmes", RouteCategory.ASSOCIATION,
          ("cto_innovation", "promoter_md"), CostTier.LOW, 60, 3, (Region.INDIA, Region.AFRICA, Region.GLOBAL), BUYERS,
          ("ISA runs technology showcases, startup programmes and member-country demonstration projects - a credibility door for India and Africa.",),
          urls=("https://isolaralliance.org/",)),
    Route("mesia_gcc", "MESIA (Middle East Solar Industry Association)", RouteCategory.ASSOCIATION,
          ("head_om", "procurement"), CostTier.MID, 45, 4, (Region.MENA,), BUYERS,
          ("GCC developers, EPCs and O&M firms; soiling is the headline O&M issue in the Gulf, so technical talks get accepted.",),
          urls=("https://www.mesia.com/",)),
    Route("cii_ficci_india", "CII / FICCI renewable-energy committees (India)", RouteCategory.ASSOCIATION,
          ("promoter_md", "projects_epc"), CostTier.MID, 60, 3, (Region.INDIA,), BUYERS + (CompanyType.OEM,),
          ("Industry-chamber energy committees are promoter-level rooms; a foreign vendor enters via an Indian partner's membership.",)),

    # ---------------- WARM INTRO ----------------
    Route("warm_intro_investors", "Infrastructure investors & platform owners", RouteCategory.WARM_INTRO,
          ("head_asset_mgmt", "promoter_md", "cfo"), CostTier.FREE, 30, 5, (Region.GLOBAL,), (CompanyType.IPP, CompanyType.FUND, CompanyType.CI),
          ("Funds (Brookfield, Actis, CIP, Macquarie, KKR, EQT, CDPQ, OTPP, GIC, Temasek, Masdar, Mubadala) push OPEX programs across every portfolio company.",
           "One asset-management partner at a fund can mandate a pilot across 5 platforms; pitch the fund's value-creation team, not the SPV.")),
    Route("warm_intro_lenders_dfi", "Lenders & DFIs (IFC, ADB, EIB, DFC, KfW; IREDA/PFC/REC in India)", RouteCategory.WARM_INTRO,
          ("head_asset_mgmt", "independent_engineer"), CostTier.FREE, 45, 3, (Region.GLOBAL,), (CompanyType.IPP, CompanyType.UTILITY),
          ("DFIs impose water-use and E&S conditions; a waterless cleaning method helps the borrower comply - ask the DFI's E&S or climate-tech teams for introductions.",)),
    Route("ie_validation", "Independent engineers as gatekeepers-turned-allies", RouteCategory.WARM_INTRO,
          ("independent_engineer", "head_asset_mgmt"), CostTier.MID, 60, 5, (Region.GLOBAL,), (CompanyType.IE, CompanyType.IPP, CompanyType.FUND),
          ("Commission a technology review from DNV, TUV Rheinland, UL Solutions, PI Berlin, Kiwa, Enertis, Black & Veatch or Leidos; a bankability letter removes the lender objection.",
           "Brief the IE's renewables practice lead; they are asked 'is this safe for modules?' by every client you pitch.")),
    Route("om_contractor_channel", "O&M contractors as channel partners", RouteCategory.WARM_INTRO,
          ("head_om", "procurement"), CostTier.LOW, 30, 5, (Region.GLOBAL,), (CompanyType.OM, CompanyType.EPC),
          ("Third-party O&M firms carry cleaning cost and risk on fixed-price contracts: your savings are their margin.",
           "Offer a reseller/service margin plus training; they bring you into every renewal they bid.")),
    Route("oem_partnerships", "Module / tracker / inverter OEM partnerships", RouteCategory.WARM_INTRO,
          ("projects_epc", "cto_innovation", "independent_engineer"), CostTier.LOW, 45, 4, (Region.GLOBAL,), (CompanyType.OEM, CompanyType.EPC, CompanyType.IPP),
          ("Get written warranty-compatibility statements from module OEMs (abrasion / coating compatibility) - buyers ask for these first.",
           "Tracker OEMs (Nextracker, Array, Arctech, Soltec, GameChange, PVH) bundle cleaning compatibility into their spec; co-market with them.")),
    Route("soiling_sensor_vendors", "Soiling-monitoring vendors as co-marketers", RouteCategory.WARM_INTRO,
          ("head_om", "head_asset_mgmt"), CostTier.LOW, 30, 4, (Region.GLOBAL,), BUYERS,
          ("DustIQ (Kipp & Zonen/OTT), Atonometrics, NRG Systems, Fracsun and similar sell the instruments that prove the problem you solve; joint webinars and shared leads.",)),
    Route("insurers_risk", "Renewables insurers & brokers", RouteCategory.WARM_INTRO,
          ("head_asset_mgmt", "cfo"), CostTier.LOW, 60, 2, (Region.GLOBAL,), (CompanyType.IPP, CompanyType.FUND),
          ("GCube, Munich Re, Swiss Re and Marsh renewables desks care about breakage and yield; a lower-risk cleaning method is a premium conversation.",)),

    # ---------------- PROGRAMS ----------------
    Route("innovation_programs", "Corporate accelerators & innovation challenges", RouteCategory.PROGRAM,
          ("cto_innovation", "head_om"), CostTier.FREE, 90, 5, (Region.GLOBAL,), BUYERS + (CompanyType.OEM,),
          ("Free Electrons (EDP + utilities), Shell GameChanger, Enel Innovation Hubs, Iberdrola PERSEO, EDF Pulse, ENGIE New Ventures, Equinor, Masdar, ACWA programmes; in India NTPC NETRA, Tata Power, ReNew and IIT incubators.",
           "A programme places you with an internal sponsor and a funded pilot - the shortest path from zero to a plant trial.")),

    # ---------------- MEDIA / CREDIBILITY ----------------
    Route("trade_press_pitch", "Trade press features (pv magazine, PV Tech, Mercom, Saur, Solar Quarter)", RouteCategory.MEDIA,
          ("head_om", "cto_innovation", "promoter_md"), CostTier.FREE, 30, 3, (Region.GLOBAL,), ALL_TYPES,
          ("Pitch data, not product: 'measured soiling losses at X plants in Rajasthan' gets printed; 'our product is great' does not.",
           "Every published piece becomes the attachment in your next outreach.")),
    Route("podcast_guesting", "Industry podcasts (SunCast, Solar Maverick, The Interchange, Watt It Takes, Indian solar podcasts)", RouteCategory.MEDIA,
          ("head_om", "cto_innovation"), CostTier.FREE, 45, 3, (Region.GLOBAL,), ALL_TYPES,
          ("Hosts are the best-connected people in the sector; one episode doubles as a warm intro engine to their past guests.",)),
    Route("awards_competitions", "Awards & startup competitions", RouteCategory.MEDIA,
          ("cto_innovation", "promoter_md"), CostTier.LOW, 90, 3, (Region.GLOBAL,), ALL_TYPES,
          ("Intersolar Award, RE+ startup competitions, Solar Quarter O&M awards, Mercom awards; judges are often the buyers.",)),
    Route("co_authored_study", "Co-authored field study with a research institute", RouteCategory.CREDIBILITY,
          ("cto_innovation", "independent_engineer", "head_asset_mgmt"), CostTier.MID, 120, 5, (Region.GLOBAL,), BUYERS,
          ("NREL, Fraunhofer ISE, IIT Bombay NCPRE, NISE, CSTEP, TERI, KAUST, QEERI, DEWA R&D, Masdar Institute run soiling test beds; a joint paper is the credibility most buyers ask for.",
           "Propose a 6-month side-by-side on an institute test bed; publish; cite in every pitch.")),
    Route("standards_test_reports", "Standards & third-party test reports", RouteCategory.CREDIBILITY,
          ("independent_engineer", "hse", "procurement"), CostTier.MID, 60, 4, (Region.GLOBAL,), BUYERS,
          ("Abrasion per IEC 62788-7-3:2022 (NREL methods) and module-specific tests (PI Berlin's standardised 3,100-cycle sand test; QEERI/DEWA desert studies); ARC-glass coating compatibility; IP rating; electrical safety near live DC; a documented no-contact or low-contact method.",
           "Module OEM positions buyers will quote: First Solar requires cleaning-system approval and excludes cleaning damage; JinkoSolar bans chemicals/abrasives; Ecoppia is certified for nine module brands - get your own letters.",
           "Put the test summary on page 2 of every proposal.")),

    # ---------------- TENDERS ----------------
    Route("india_public_tenders", "Indian public tenders (SECI, NTPC, SJVN, NHPC, state agencies, GeM)", RouteCategory.TENDER,
          ("procurement", "projects_epc"), CostTier.LOW, 60, 3, (Region.INDIA,), (CompanyType.UTILITY, CompanyType.EPC, CompanyType.OM),
          ("Register on GeM and CPPP; watch SECI/NTPC/SJVN/NHPC tender pages for 'O&M', 'module cleaning', 'robotic cleaning' scopes.",
           "Public utilities buy via tender only; the path is to be the subcontractor of the winning EPC/O&M bidder."),
          urls=("https://www.seci.co.in/tenders", "https://www.ntpctender.ntpc.co.in/", "https://gem.gov.in/", "https://eprocure.gov.in/eprocure/app")),
    Route("us_eu_mena_procurement", "SAM.gov / EU TED / GCC utility supplier portals", RouteCategory.TENDER,
          ("procurement",), CostTier.LOW, 60, 2, (Region.US, Region.EU, Region.MENA), (CompanyType.UTILITY,),
          ("Federal/state-owned plants (US DoD, BLM, EU municipal utilities, DEWA, EWEC, ACWA, Masdar supplier portals) publish O&M scopes; registration is free.",),
          urls=("https://sam.gov/", "https://ted.europa.eu/", "https://www.dewa.gov.ae/en/supplier")),

    # ---------------- GUERRILLA ----------------
    Route("free_soiling_audit", "Free soiling audit for a named plant", RouteCategory.GUERRILLA,
          ("plant_manager", "head_om"), CostTier.LOW, 14, 5, (Region.GLOBAL,), BUYERS,
          ("Using their public plant data (location, MW, COD) plus regional dust/precipitation data, estimate annual soiling loss and the recovery value; send it as a 1-page audit.",
           "Offer to validate on site with a portable soiling sensor for 30 days at no cost."),
          legal_note="Uses public data only; no site access without written permission."),
    Route("one_row_demo", "One-row, no-cost field demonstration", RouteCategory.GUERRILLA,
          ("plant_manager", "head_om"), CostTier.MID, 30, 5, (Region.GLOBAL,), BUYERS,
          ("Clean/treat one row (or one inverter block) with written permission; compare string-level output with an untreated control for 30-60 days.",
           "Hand the plant manager a report they can forward upward; the data does the selling."),
          legal_note="Permit-to-work, HSE sign-off and OEM compatibility letter before touching modules."),
    Route("regional_soiling_index", "Publish a regional soiling-loss index / map", RouteCategory.GUERRILLA,
          ("head_asset_mgmt", "head_om", "cto_innovation"), CostTier.LOW, 45, 4, (Region.GLOBAL,), BUYERS,
          ("Combine public plant lists with dust/aerosol and rainfall data to publish 'the 50 dustiest solar parks in India' (or the Gulf); every asset owner on the list will read it.",
           "Offer the per-plant detail privately to each owner.")),
    Route("roi_one_pager", "Per-plant physical ROI mailer to the O&M head", RouteCategory.GUERRILLA,
          ("head_om", "head_asset_mgmt", "cfo"), CostTier.LOW, 21, 4, (Region.US, Region.EU, Region.GLOBAL), BUYERS,
          ("A printed, plant-specific one-pager (their plant's name, MW, estimated loss, recovery) delivered to the corporate office, addressed to the role.",
           "Follow with one email a week later; physical mail gets opened where email does not."),
          legal_note="Address the role at the corporate address; no home addresses."),
    Route("video_prospecting", "60-second personalised video prospecting", RouteCategory.GUERRILLA,
          ("head_om", "cto_innovation"), CostTier.FREE, 14, 3, (Region.GLOBAL,), BUYERS,
          ("Screen-record their plant on a satellite map, overlay the estimated soiling loss, show 10 seconds of the system working; send via LinkedIn or email.",)),
    Route("local_om_roundtable", "Local practitioner roundtables near the big parks", RouteCategory.GUERRILLA,
          ("plant_manager", "head_om"), CostTier.LOW, 30, 5, (Region.INDIA, Region.MENA, Region.US), BUYERS,
          ("Jodhpur/Jaisalmer (Bhadla), Bhuj (Khavda), Bengaluru (Pavagada), Phoenix, Riyadh: a tea/dinner for 8 plant managers from different owners.",
           "Plant managers trade vendors by word of mouth; one good trial becomes five.")),
    Route("conference_demo_rig", "Portable demo rig at a hotel suite next to the venue", RouteCategory.GUERRILLA,
          ("head_om", "cto_innovation", "projects_epc"), CostTier.MID, 30, 4, (Region.GLOBAL,), BUYERS + (CompanyType.OEM,),
          ("Skip the booth: a working 2-module rig in a suite, 20-minute slots booked via LinkedIn and the event app.",)),
    Route("no_gain_no_fee_pilot", "Risk-reversal: no-yield-gain-no-fee pilot", RouteCategory.GUERRILLA,
          ("head_asset_mgmt", "cfo", "head_om"), CostTier.MID, 45, 5, (Region.GLOBAL,), BUYERS,
          ("Fee only on measured yield gain above an agreed soiling-ratio baseline, verified by the plant's own monitoring; it removes the CFO objection and forces a data-driven pilot design.",)),
    Route("plant_manager_community_india", "Opt-in plant-manager WhatsApp / Telegram community (India)", RouteCategory.GUERRILLA,
          ("plant_manager", "head_om"), CostTier.FREE, 60, 4, (Region.INDIA,), BUYERS,
          ("A moderated, vendor-neutral group sharing soiling data, dust-storm alerts and cleaning benchmarks; members join by invitation after events.",
           "Never pitch inside the group; the group makes you the convener."),
          legal_note="Opt-in only; comply with DPDP and group-consent norms."),
    Route("landmark_cleaning_stunt", "Permissioned landmark demonstration", RouteCategory.GUERRILLA,
          ("promoter_md", "head_om"), CostTier.MID, 60, 3, (Region.GLOBAL,), BUYERS + (CompanyType.CI,),
          ("Clean a visible rooftop (airport, university, temple, metro station) with permission and publish the before/after generation with the host's quote.",),
          legal_note="Written permission, HSE plan and host sign-off on publicity."),
    Route("drone_imagery_outreach", "Drone / satellite soiling imagery as an outreach hook", RouteCategory.GUERRILLA,
          ("head_om", "plant_manager"), CostTier.LOW, 21, 3, (Region.GLOBAL,), BUYERS,
          ("Satellite imagery (public) can show visible soiling bands; drone imagery only with the owner's permission and a licensed pilot (DGCA in India, FAA Part 107 in the US).",),
          legal_note="Never fly over a plant without permission; airspace and trespass rules apply."),
    Route("dirtiest_plant_challenge", "Public 'dirtiest plant' challenge (opt-in)", RouteCategory.GUERRILLA,
          ("head_om", "plant_manager"), CostTier.LOW, 60, 3, (Region.INDIA, Region.MENA, Region.US), BUYERS,
          ("Invite owners to nominate their worst-soiling site; the winner gets a free 90-day deployment with published results.",)),
)

ROUTES_BY_ID: Dict[str, Route] = {r.route_id: r for r in ROUTE_CATALOG}
ROLES_BY_ID: Dict[str, DecisionRole] = {r.role_id: r for r in DECISION_ROLES}


def routes_for(region: Region, ctype: CompanyType, categories: Optional[Sequence[RouteCategory]] = None) -> List[Route]:
    """Routes applicable to a target of this region & type, best first."""
    out = [r for r in ROUTE_CATALOG if r.applies(region, ctype) and (not categories or r.category in categories)]
    return sorted(out, key=lambda r: (r.effectiveness, -r.days_to_meeting), reverse=True)


def roles_for(ctype: CompanyType) -> List[DecisionRole]:
    return [r for r in DECISION_ROLES if ctype in r.company_types or ctype == CompanyType.UNKNOWN]


# --------------------------------------------------------------------------------------
# 4. Events, programmes, associations, warm-intro organisations
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class EventEntry:
    event_id: str
    name: str
    region: Region
    month: str                 # usual month(s); verify each year
    city: str
    audience: str
    url: str
    om_density: int            # 1-5 how concentrated the O&M / asset-management audience is
    scan_url: str = ""         # optional public page the scout greps for the target's name
    next_dates: str = ""       # last-known upcoming edition(s) at time of writing - verify before booking


EVENTS: Tuple[EventEntry, ...] = (
    EventEntry("sam_na", "Solarplaza Summit Asset Management North America", Region.US, "Apr", "San Diego", "asset managers, O&M heads, IEs, lenders - the densest O&M room in NA", "https://www.solarplaza.com/", 5, next_dates="6-7 Apr 2027 (San Diego)"),
    EventEntry("sam_eu", "Solarplaza Summit Asset Management Europe", Region.EU, "Oct", "Prague (recent editions)", "asset managers, O&M heads", "https://www.solarplaza.com/", 5, next_dates="Oct 2026 Prague (date TBC on organiser calendar)"),
    EventEntry("sam_asia", "Solarplaza Summit Asset Management Asia", Region.APAC, "varies", "Asia (rotates)", "asset managers, O&M heads", "https://www.solarplaza.com/", 5),
    EventEntry("sfi_europe", "Solar Finance & Investment Europe (Solar Media)", Region.EU, "Feb", "London", "owners, lenders, investors, asset-management functions", "https://www.solarenergyevents.com/", 4, next_dates="2-3 Feb 2027 (London)"),
    EventEntry("re_plus", "RE+", Region.US, "Sep-Nov", "Las Vegas / Anaheim (rotates)", "entire NA industry; asset-owner track; startup pavilion", "https://www.re-plus.com/", 3, next_dates="16-19 Nov 2026 (Las Vegas)"),
    EventEntry("cleanpower", "CLEANPOWER (American Clean Power)", Region.US, "May", "USA (rotates)", "US utility-scale owners/operators", "https://cleanpower.org/", 3, next_dates="24-27 May 2027 (Anaheim)"),
    EventEntry("intersolar_na", "Intersolar & Energy Storage North America", Region.US, "Feb", "San Diego", "installers, EPC, C&I", "https://www.intersolar.us/", 2, next_dates="8-11 Feb 2027 (San Diego)"),
    EventEntry("intersolar_eu", "Intersolar Europe / The smarter E Europe", Region.EU, "Jun", "Munich", "EPC, IPP, OEM; The smarter E AWARD (exhibitors only)", "https://www.intersolar.de/", 3, next_dates="8-10 Jun 2027 (Munich)"),
    EventEntry("spe_om", "SolarPower Europe O&M & Asset Management events / O&M Task Force", Region.EU, "varies", "Europe", "O&M heads, asset managers", "https://www.solarpowereurope.org/", 5),
    EventEntry("pv_moduletech", "PV ModuleTech / PV CellTech (PV Tech)", Region.GLOBAL, "Jun", "Napa, CA / varies", "module quality, bankability, IEs", "https://www.pv-tech.org/", 3, next_dates="PV ModuleTech USA 16-17 Jun 2026 (Napa)"),
    EventEntry("intersolar_india", "Intersolar India / The smarter E India", Region.INDIA, "Feb-Mar", "Gandhinagar", "Indian EPC/IPP project teams, OEMs (Khavda is nearby)", "https://www.intersolar.in/", 3, next_dates="9-11 Mar 2027 (Gandhinagar) - verify"),
    EventEntry("rei_expo", "Renewable Energy India (REI) Expo", Region.INDIA, "Oct-Nov", "Greater Noida", "largest Indian RE show (55k+ visitors); robot supply deals get signed on-site", "https://www.renewableenergyindiaexpo.com/", 3, next_dates="Nov 2027 (Greater Noida) - organiser lists Oct/Nov, verify"),
    EventEntry("india_energy_week", "India Energy Week", Region.INDIA, "Jan-Feb", "Kolkata (2027); Goa/Delhi previously", "ministerial & CXO level", "https://www.indiaenergyweek.com/", 2, next_dates="28-31 Jan 2027 (Kolkata)"),
    EventEntry("bharat_re_summit", "Bharat Renewable Energy Summit / Bharat Renewable Expo", Region.INDIA, "Nov / Jan", "New Delhi / Jaipur", "developers, EPC, Rajasthan Solar Association ecosystem", "https://nsefi.in/", 3, next_dates="2-5 Nov 2026 (Delhi); Bharat Renewable Expo 29-31 Jan 2027 (Jaipur) - verify"),
    EventEntry("mercom_india", "Mercom India Renewables Summit & Awards", Region.INDIA, "Jul", "New Delhi", "IPP CXOs, O&M heads, financiers", "https://www.mercomindia.com/", 4, next_dates="1-2 Jul 2026 (Delhi); 15-16 Jul 2027 (Delhi, venue TBC)"),
    EventEntry("solar_quarter_om", "Solar Quarter O&M / Asset Management summits & awards", Region.INDIA, "multiple", "India (multiple cities)", "O&M heads, plant managers", "https://solarquarter.com/", 5),
    EventEntry("solar_power_expo_mumbai", "Solar Power Expo", Region.INDIA, "May", "Mumbai", "installers, C&I, OEMs", "https://solarpowerexpo.in/", 2, next_dates="13-15 May 2027 (Mumbai) - verify"),
    EventEntry("wfes", "World Future Energy Summit (Abu Dhabi Sustainability Week)", Region.MENA, "Jan", "Abu Dhabi", "Masdar, EWEC, ACWA, AMEA, GCC utilities", "https://www.worldfutureenergysummit.com/", 3, next_dates="12-14 Jan 2027 (ADNEC)"),
    EventEntry("mee", "Middle East Energy", Region.MENA, "Apr-May", "Dubai (Expo City from 2027)", "GCC developers, EPCs, O&M", "https://www.middleeast-energy.com/", 3, next_dates="11-13 May 2027 (Expo City Dubai)"),
    EventEntry("ssl_ksa", "Solar & Storage Live KSA", Region.MENA, "Nov", "Riyadh", "Saudi developers, EPC, O&M (NEOM/Sudair ecosystem)", "https://www.terrapinn.com/", 3, next_dates="23-25 Nov 2026 (Riyadh)"),
    EventEntry("snec", "SNEC PV Power Expo", Region.APAC, "Jun", "Shanghai", "OEMs, Chinese EPC/IPP (manufacturer-dominated)", "https://www.snec.org.cn/", 2, next_dates="2-4 Jun 2027 (Shanghai)"),
)


@dataclass(frozen=True)
class ProgramEntry:
    program_id: str
    name: str
    owner: str
    region: Region
    url: str
    note: str


PROGRAMS: Tuple[ProgramEntry, ...] = (
    ProgramEntry("free_electrons", "Free Electrons", "EDP + utility consortium (CLP, E.ON, ESB, Hydro-Quebec, JERA, Origin...)", Region.GLOBAL, "https://www.freeelectrons.co/", "Utility-backed accelerator; applications typically Oct-Jan (2026 deadline was 31 Jan); EDP reports >60 pilots -> >10 commercial contracts (~1 in 6)."),
    ProgramEntry("shell_gamechanger", "Shell GameChanger / GCxN", "Shell", Region.GLOBAL, "https://www.shell.com/gamechanger", "Early-stage non-dilutive funding (GCxN up to ~$250k, referral-based); Shell owns solar via Sprng (India) and other platforms."),
    ProgramEntry("enel_innovation", "Enel Open Innovability", "Enel Green Power", Region.GLOBAL, "https://openinnovability.enel.com/", "Published challenges incl. a 2023 anti-soiling coating challenge; EGP tested SandStorm robots at its Catania lab then a 1 MW section of Totana - the model pilot path."),
    ProgramEntry("iberdrola_perseo", "Iberdrola PERSEO", "Iberdrola", Region.EU, "https://www.iberdrola.com/innovation/perseo", "Corporate VC + NewTech challenges; ran a dedicated PV-cleaning challenge (2019: >70 proposals, 25 countries, 4 winners, Iberdrola-funded pilots at Nunez de Balboa, 'official global supplier' status on success)."),
    ProgramEntry("edf_pulse", "EDF Pulse Ventures / EDF Pulse Startups", "EDF", Region.EU, "https://www.edf.fr/en/the-edf-group/inventing-the-future-of-energy/edf-pulse", "EDF Renewables incl. India and the US."),
    ProgramEntry("engie_new_ventures", "ENGIE New Ventures / ENGIE Factory", "ENGIE", Region.GLOBAL, "https://www.engie.com/en/innovation", "ENGIE solar in India, MENA, LATAM."),
    ProgramEntry("equinor_ventures", "Equinor Ventures", "Equinor", Region.EU, "https://www.equinor.com/energy/ventures", "Solar via Scatec stake and own projects."),
    ProgramEntry("masdar_programs", "Masdar innovation / WFES startup programmes", "Masdar", Region.MENA, "https://masdar.ae/", "Abu Dhabi; desert soiling is a core O&M theme."),
    ProgramEntry("acwa_innovation", "ACWA Power Innovation Days", "ACWA Power", Region.MENA, "https://www.acwapower.com/", "Largest GCC IPP; O&M via NOMAC; Innovation Days 2025 produced 7 partnership agreements from 968 ideas - robots are specified in Sudair/Al Shuaibah tenders."),
    ProgramEntry("aramco_waed", "Wa'ed Ventures", "Saudi Aramco", Region.MENA, "https://www.waed.net/", "Saudi startup fund; Aramco & SAPCO solar."),
    ProgramEntry("elemental", "Elemental Impact", "Elemental", Region.US, "https://elementalimpact.com/", "Project-funded climate deployments."),
    ProgramEntry("third_derivative", "Third Derivative", "RMI", Region.GLOBAL, "https://third-derivative.org/", "Corporate partners include utilities and IPPs."),
    ProgramEntry("powerhouse", "Powerhouse Ventures", "Powerhouse", Region.US, "https://www.powerhouse.fund/", "Digital energy; strong IPP network."),
    ProgramEntry("cleantech_open", "Cleantech Open", "Cleantech Open", Region.US, "https://www.cleantechopen.org/", "Accelerator with utility judges."),
    ProgramEntry("ntpc_netra", "NTPC Startup Grand Challenge / NETRA pilots", "NTPC", Region.INDIA, "https://www.ntpc.co.in/", "India's largest utility; Startup Grand Challenge via Startup India; NETRA pilots new tech; note NTPC O&M/cleaning tenders are often restricted to Class-I local suppliers."),
    ProgramEntry("tata_power_innovation", "Tata Power Pilot Accelerator (via Social Alpha)", "Tata Power", Region.INDIA, "https://www.tatapower.com/", "Pilot grants up to ~Rs 25 lakh; Tata Power Renewable & Tata Power Solar are early robotic-cleaning adopters (Taypro)."),
    ProgramEntry("renew_innovation", "ReNew innovation initiatives", "ReNew", Region.INDIA, "https://renew.com/", "Early robotic-cleaning adopter; verify current programme."),
    ProgramEntry("startup_india", "Startup India (DPIIT) / Invest India", "Govt of India", Region.INDIA, "https://www.startupindia.gov.in/", "DPIIT recognition unlocks GeM startup runway and MNRE challenges, but excludes foreign-owned subsidiaries - route via an Indian partner. MNRE's 2025 Rs 2.3 cr challenge (with NISE) was India-startup-only."),
    ProgramEntry("iit_incubators", "IIT Madras Incubation Cell / SINE IIT Bombay / IIT Delhi FITT", "IITs", Region.INDIA, "https://www.incubation.iitm.ac.in/", "Credibility + access to NCPRE/NISE test beds and corporate mentors."),
    ProgramEntry("isa_startups", "ISA SolarX / ISA startup challenges", "International Solar Alliance", Region.GLOBAL, "https://isolaralliance.org/", "Global showcase with member governments (verify current edition)."),
)


@dataclass(frozen=True)
class WarmIntroOrg:
    org_id: str
    name: str
    kind: str                 # investor | lender | ie | oem_module | oem_tracker | oem_inverter | om_contractor | sensor | insurer | research
    region: Region
    note: str


WARM_INTRO_ORGS: Tuple[WarmIntroOrg, ...] = (
    WarmIntroOrg("brookfield", "Brookfield Renewable", "investor", Region.GLOBAL, "Owns platforms in US/India (Evren)/Europe; portfolio-wide O&M programmes."),
    WarmIntroOrg("actis", "Actis", "investor", Region.GLOBAL, "Built Sprng (sold to Shell), BluPine (India); active in Africa/LatAm."),
    WarmIntroOrg("cip", "Copenhagen Infrastructure Partners", "investor", Region.GLOBAL, "Large solar+storage; India via Viviid/others (verify)."),
    WarmIntroOrg("macquarie", "Macquarie Asset Management", "investor", Region.GLOBAL, "Vibrant Energy (India), global platforms."),
    WarmIntroOrg("kkr", "KKR", "investor", Region.GLOBAL, "Serentica, Hero Future Energies stakes (India); global."),
    WarmIntroOrg("eqt", "EQT", "investor", Region.GLOBAL, "O2 Power (sold to JSW), European platforms."),
    WarmIntroOrg("cdpq_otpp_gic", "CDPQ / OTPP / GIC / Temasek", "investor", Region.GLOBAL, "Pension & sovereign owners of Indian and global platforms (Azure, Mahindra Susten, Greenko, Sembcorp)."),
    WarmIntroOrg("ifc", "IFC (World Bank Group)", "lender", Region.GLOBAL, "E&S water conditions; climate business teams."),
    WarmIntroOrg("adb", "Asian Development Bank", "lender", Region.APAC, "India & Asia project finance."),
    WarmIntroOrg("ireda_pfc_rec", "IREDA / PFC / REC", "lender", Region.INDIA, "Indian public lenders to IPPs."),
    WarmIntroOrg("dnv", "DNV", "ie", Region.GLOBAL, "Most common lender's engineer for solar."),
    WarmIntroOrg("tuv_rheinland", "TUV Rheinland", "ie", Region.GLOBAL, "Module & system testing; India labs."),
    WarmIntroOrg("ul_solutions", "UL Solutions", "ie", Region.GLOBAL, "Bankability & testing."),
    WarmIntroOrg("pi_berlin", "PI Berlin", "ie", Region.GLOBAL, "Module quality & field audits."),
    WarmIntroOrg("kiwa_pvel", "Kiwa PVEL", "ie", Region.US, "Module reliability scorecard."),
    WarmIntroOrg("enertis", "Enertis Applus+", "ie", Region.GLOBAL, "Technical advisory, Spain/LatAm/India."),
    WarmIntroOrg("black_veatch", "Black & Veatch", "ie", Region.US, "Owner's engineer."),
    WarmIntroOrg("first_solar", "First Solar", "oem_module", Region.GLOBAL, "Thin-film; specific cleaning compatibility guidance."),
    WarmIntroOrg("jinko_longi_trina_ja", "JinkoSolar / LONGi / Trina / JA Solar", "oem_module", Region.GLOBAL, "Warranty-compatibility letters for cleaning methods."),
    WarmIntroOrg("waaree_adani_tp_premier", "Waaree / Adani Solar / Tata Power Solar / Premier Energies", "oem_module", Region.INDIA, "Indian module makers (ALMM); compatibility letters for Indian buyers."),
    WarmIntroOrg("nextracker", "Nextracker", "oem_tracker", Region.GLOBAL, "Largest tracker OEM; acquired Amir Robotics (water-free robot, Mar 2025) and issues compatibility letters to third-party robots (e.g. KP Group, Apr 2025)."),
    WarmIntroOrg("array_technologies", "Array Technologies", "oem_tracker", Region.US, "Tracker OEM."),
    WarmIntroOrg("arctech_soltec_pvh_gamechange", "Arctech / Soltec / PVH / GameChange", "oem_tracker", Region.GLOBAL, "Tracker OEMs active in India/MENA/LatAm."),
    WarmIntroOrg("sungrow_huawei_sma", "Sungrow / Huawei / SMA", "oem_inverter", Region.GLOBAL, "Inverter monitoring platforms where soiling shows up."),
    WarmIntroOrg("solv_energy", "SOLV Energy", "om_contractor", Region.US, "Major US utility-scale O&M provider."),
    WarmIntroOrg("novasource", "NovaSource Power Services", "om_contractor", Region.GLOBAL, "~38 GW under O&M (Wood Mackenzie 2026) - largest third-party fleet."),
    WarmIntroOrg("baywa_re", "BayWa r.e. Operation Services", "om_contractor", Region.EU, "Large European O&M fleet."),
    WarmIntroOrg("mahindra_susten", "Mahindra Susten", "om_contractor", Region.INDIA, "Indian EPC & O&M (OTPP-backed)."),
    WarmIntroOrg("sterling_wilson_om", "Sterling & Wilson Renewable Energy (O&M)", "om_contractor", Region.INDIA, "Large Indian/MENA O&M fleet."),
    WarmIntroOrg("tata_power_solar_om", "Tata Power Solar (EPC & O&M)", "om_contractor", Region.INDIA, "Group O&M for Tata Power Renewable and third parties."),
    WarmIntroOrg("inox_mitarsh_jakson_inspire", "Inox Green / Mitarsh / Jakson Green / Inspire Clean Energy", "om_contractor", Region.INDIA, "Top Indian third-party O&M fleets (Mitarsh ~28 GWp, Jakson ~5 GWp); together with S&W they hold ~86% of contracted O&M - the reseller channel."),
    WarmIntroOrg("enerparc_refex", "Enerparc Energy India / Refex", "om_contractor", Region.INDIA, "Mid-size Indian O&M/EPC players."),
    WarmIntroOrg("nomac", "NOMAC (ACWA Power O&M)", "om_contractor", Region.MENA, "ACWA's O&M arm."),
    WarmIntroOrg("dustiq", "Kipp & Zonen / OTT HydroMet DustIQ", "sensor", Region.GLOBAL, "Soiling sensors."),
    WarmIntroOrg("atonometrics", "Atonometrics", "sensor", Region.US, "Soiling measurement systems."),
    WarmIntroOrg("fracsun", "Fracsun", "sensor", Region.US, "Soiling sensors & analytics."),
    WarmIntroOrg("gcube", "GCube Insurance", "insurer", Region.GLOBAL, "Renewables underwriter."),
    WarmIntroOrg("nrel", "NREL", "research", Region.US, "Soiling research and PV O&M best practices."),
    WarmIntroOrg("fraunhofer_ise", "Fraunhofer ISE", "research", Region.EU, "Soiling & coating testing."),
    WarmIntroOrg("iit_ncpre_nise", "IIT Bombay NCPRE / NISE / CSTEP / TERI", "research", Region.INDIA, "Indian soiling studies and test beds."),
    WarmIntroOrg("kaust_qeeri", "KAUST / QEERI / DEWA R&D / Masdar Institute", "research", Region.MENA, "Desert soiling test beds."),
)


# --------------------------------------------------------------------------------------
# 5. India playbook
# --------------------------------------------------------------------------------------

INDIA_PLAYBOOK: Dict[str, Any] = {
    "market_snapshot": [
        "India is the world's third-largest solar market: ~171 GW installed solar at 30 Sep 2026 (125.7 GW ground-mounted, 33.4 GW rooftop), a record 44.6 GW added in FY2025-26, a ~208 GW large-scale pipeline (Mercom, mid-2026), and a 500 GW non-fossil / 280 GW solar target for 2030 (verify latest MNRE/CEA monthly figure).",
        "Rajasthan (~44 GW) and Gujarat (~35 GW) lead; Khavda (Adani, 9.4 GW operational in 2026, heading to 30 GW by 2029) sees sandstorms that require cleaning several times a day, and AGEL has committed to waterless robots across its solar fleet; Bhadla is ~2.2 GW, Pavagada ~2 GW; a field study documents acute water scarcity at Bhadla (7-8 L per panel wash from canals/tubewells).",
        "Indian soiling rates cluster at 0.2-0.4%/day in peer-reviewed utility-scale studies (range 0.05-0.55%/day); manual wet cleaning uses 1-8 L/module/wash and competes with scarce groundwater; full O&M runs ~Rs 3.5-8 lakh/MW/yr with cleaning labour+water ~Rs 1-2 lakh/MW/yr; robotic cleaning is quoted at ~Rs 1.2-1.5 lakh/MW-DC/yr or ~Rs 0.20/module vs Rs 0.45-1.2/module manual (vendor/press figures - verify).",
        "Robotic waterless cleaning is deployed at multi-GW scale and the vendor table has turned over: Mercom's 2025 shipment leaderboard is Sol-Bright ~35%, Solabot ~12%, LEAPTING ~12%, Aegeus >11%, Vayu Solar >11% (Taypro led 2024 at 27.5%); LEAPTING holds >1 GW from ReNew, 1.2 GWp from Waaree RT and 2 GW from Adani; Airtouch (Israel, Noida factory) grew via ReNew, an Adani master supply agreement and Juniper repeat orders; Ecoppia's Indian wins are 2018-2020 vintage. Buyers are educated - the sale is differentiation, economics and breakage risk, not education.",
        "O&M is increasingly in-house at the large IPPs (Adani's ENOC runs ~1,100 O&M staff; ReNew, Tata Power, NTPC) and outsourced at mid-size owners; the top third-party O&M providers (Inox Green, Mitarsh ~28 GWp, Jakson Green ~5 GWp, Inspire Clean Energy, Sterling & Wilson ~12-13 GW) hold ~86% of contracted O&M; EPCs (Waaree RT, AMPIN) now buy robots directly for new builds.",
    ],
    "institutions": {
        "MNRE": "Ministry of New & Renewable Energy - policy, ALMM list, schemes.",
        "SECI": "Solar Energy Corporation of India - central tendering agency; O&M scopes appear in its tenders.",
        "NTPC / NTPC Green / SJVN / NHPC": "Public-sector generators that buy via tender; NTPC NETRA is the R&D arm.",
        "CEA": "Central Electricity Authority - monthly installed-capacity reports (plant lists).",
        "State nodal agencies": "GUVNL/GEDA (Gujarat), RUVNL/RREC (Rajasthan), MSEDCL/MEDA (Maharashtra), KREDL (Karnataka), TANGEDCO (TN), MPUVNL (MP).",
        "GeM": "Government e-Marketplace - mandatory channel for many public buyers; startup registration eases onboarding.",
        "BIS / MNRE quality control": "Module and inverter standards; cleaning equipment generally outside ALMM but check product-specific BIS requirements.",
        "CBIC": "Customs - basic customs duty and IGST on imported equipment; consider local assembly.",
        "DGCA": "Drone rules (Digital Sky) if imagery is part of the pitch.",
    },
    "entry_structures": [
        "Indian distributor / channel partner with O&M credentials (fastest, lowest control).",
        "Technology licence or contract manufacturing with an Indian OEM/EPC (Make-in-India optics, duty avoidance).",
        "Joint venture with an O&M contractor that already holds AVL status at the big IPPs.",
        "Wholly-owned Indian subsidiary (needed for GST invoicing, GeM, local service; required for serious scale).",
    ],
    "culture_and_norms": [
        "Relationship-first: a warm introduction from a peer, investor, IE or industry body beats any cold channel.",
        "Hierarchy matters: the plant manager champions, the Head O&M evaluates, the CXO/promoter signs; respect the chain and keep each level informed.",
        "Expect a demo request early and a 'pilot at your cost' ask; structure it as a measured trial with a conversion clause.",
        "Price anchoring to manual cleaning cost per MW-year is universal; lead with the all-in OPEX comparison, not technology.",
        "WhatsApp is the operational channel after first contact; phone over email for anything urgent; be punctual on follow-up.",
        "Local presence (service engineers, spares within days) is a qualifying criterion, not a nice-to-have.",
        "Payment terms are often long (60-90 days or milestone-based); retention clauses are common - price them in.",
    ],
    "calendar": [
        "Fiscal year April-March: O&M budgets are set Jan-Mar; pilots approved in Q1 (Apr-Jun) run through the dry season (practitioner inference - not independently sourced).",
        "Soiling season: October-May (post-monsoon dust, Rajasthan/Gujarat storms Mar-Jun); monsoon Jul-Sep partly self-cleans and slows field trials.",
        "Avoid launching outreach in the two weeks around Diwali (Oct/Nov) and Holi; Q4 (Jan-Mar) is budget-closing, good for next-year deals.",
        "Event anchors: Bharat RE Summit (2-5 Nov 2026, Delhi), India Energy Week (28-31 Jan 2027, Kolkata), Bharat Renewable Expo (29-31 Jan 2027, Jaipur), Intersolar India (9-11 Mar 2027, Gandhinagar), Mercom India (Jul 2027, Delhi), REI Expo (Nov 2027, Greater Noida), Solar Quarter O&M events (multiple) - verify dates.",
    ],
    "compliance_checklist": [
        "Indian entity or partner with GST registration and PAN; GeM seller registration; Startup India/DPIIT recognition if eligible.",
        "Product: CE/IEC test reports, IP rating, abrasion/compatibility reports. Cleaning robots sit outside ALMM (List-I modules, List-II cells); but a BIS Quality Control Order (DPIIT S.O. 1739(E), 6 Apr 2026) mandates ISI marking for >90 electrical appliance categories incl. vacuum/water-suction cleaning appliances from 1 Oct 2026 (small enterprises 1 Jan 2027, micro 1 Apr 2027) - check whether your device is captured.",
        "Imports: cleaning robots are typically classified under HS 8479.50 at 7.5% BCD + 10% SWS + 18% IGST (~27-28.5% landed); local assembly (Airtouch/Ecoppia precedent) avoids most of it. Coatings/chemicals carry their own HS codes and BIS rules.",
        "Public buyers: GeM requires an Indian entity (subsidiary or deemed-OEM distributor); NTPC's 2026 O&M/cleaning tenders were restricted to Class-I local suppliers (>=50% local content); MSMED Act caps payment to registered MSMEs at 45 days but >50% of Indian B2B receivables run >90 days overdue - price the working capital.",
        "Outreach: DPDP Act 2023 (Rules notified Nov 2025; full compliance 13 May 2027; no 'legitimate interest' basis, so named work emails need notice/consent discipline) and TRAI TCCCPR (2nd Amendment, Feb 2025: inferred consent abolished, mixed messages count as promotional, fines up to Rs 50,000 per violation for unregistered senders) - use corporate landlines, published role mailboxes, event follow-ups and consented WhatsApp.",
        "Site: permit-to-work, EHS induction, insurance (public liability), and a module-OEM compatibility letter before any trial.",
    ],
    "decision_escalation": [
        "Plant Manager / Cluster Head -> Head O&M -> President/Head Operations or CTO -> CEO/MD (promoter) -> Board for capex; opex-neutral pilots stop at Head O&M / President Operations.",
    ],
    "channel_partner_archetypes": [
        "Independent O&M companies with multi-GW fleets (service margin model).",
        "EPCs with captive O&M (spec into new builds + handover).",
        "Robotic-cleaning incumbents' service partners (if complementary, e.g. coating + robot).",
        "Soiling-sensor and monitoring resellers (data-led selling).",
    ],
}


# --------------------------------------------------------------------------------------
# 6. Guerrilla tactics & compliance rules
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Tactic:
    tactic_id: str
    name: str
    cost: CostTier
    risk: str           # LOW | MEDIUM | HIGH
    regions: Tuple[Region, ...]
    steps: Tuple[str, ...]
    legal: str = ""


GUERRILLA_TACTICS: Tuple[Tactic, ...] = (
    Tactic("proof_first_row", "Proof-first: one row, one month, one report", CostTier.MID, "LOW", (Region.GLOBAL,),
           ("Get written permission from the plant manager.", "Treat/clean one row; keep an adjacent control row.",
            "Pull string-level data for 30-60 days.", "Deliver a 2-page report the manager can forward upward."),
           "Permit-to-work and OEM compatibility letter required."),
    Tactic("soiling_audit_mailer", "Soiling audit mailer to the O&M head", CostTier.LOW, "LOW", (Region.GLOBAL,),
           ("Estimate per-plant loss from public plant data + regional dust/rain data.", "Print a 1-page audit addressed to the role.",
            "Follow up by email 7 days later referencing the audit."),
           "Corporate address only."),
    Tactic("dustiest_parks_report", "Publish 'the dustiest solar parks' report", CostTier.LOW, "LOW", (Region.INDIA, Region.MENA, Region.US),
           ("Rank public plants by soiling climate and MW.", "Offer private per-plant detail to each owner.", "Pitch the trade press on the ranking."),),
    Tactic("plant_manager_tea", "Plant-manager tea / dinner near the park", CostTier.LOW, "LOW", (Region.INDIA, Region.MENA),
           ("Invite 6-10 managers from different owners near Bhadla/Khavda/Pavagada.", "No pitch; discuss soiling benchmarks.", "Follow up individually with a trial offer."),),
    Tactic("suite_demo", "Hotel-suite demo rig next to the conference", CostTier.MID, "LOW", (Region.GLOBAL,),
           ("Working 2-module rig in a suite.", "Book 20-minute slots via the event app.", "Film testimonials with consent."),),
    Tactic("no_gain_no_fee", "No-yield-gain-no-fee pilot", CostTier.MID, "MEDIUM", (Region.GLOBAL,),
           ("Agree the soiling-ratio baseline and measurement method.", "Fee is a share of measured recovered kWh.", "Conversion clause to a multi-year contract."),
           "Define measurement in writing to avoid disputes."),
    Tactic("video_prospect", "Satellite-map video prospecting", CostTier.FREE, "LOW", (Region.GLOBAL,),
           ("Screen-record the plant on a public satellite map.", "Overlay the estimated loss.", "10 seconds of the system working; send via LinkedIn/email."),),
    Tactic("landmark_demo", "Permissioned landmark rooftop demonstration", CostTier.MID, "MEDIUM", (Region.GLOBAL,),
           ("Pick a visible rooftop (airport/university/temple).", "Written permission + HSE plan.", "Publish before/after generation with the host's quote."),
           "Host sign-off on publicity."),
    Tactic("drone_hook", "Drone imagery hook", CostTier.LOW, "HIGH", (Region.GLOBAL,),
           ("Only with owner permission and a licensed pilot.", "Thermal/visual soiling bands as the conversation opener."),
           "DGCA (India) / FAA Part 107 (US); never fly over a plant uninvited."),
    Tactic("opt_in_community", "Opt-in practitioner community", CostTier.FREE, "LOW", (Region.INDIA, Region.MENA),
           ("Moderated WhatsApp/Telegram group for plant managers.", "Share dust-storm alerts and benchmarks.", "Never pitch inside the group."),
           "Consent-based; DPDP."),
)


@dataclass(frozen=True)
class ComplianceRule:
    jurisdiction: str
    law: str
    rule: str


COMPLIANCE_RULES: Tuple[ComplianceRule, ...] = (
    ComplianceRule("US", "CAN-SPAM Act", "Commercial B2B email allowed without prior consent; must have accurate headers, a physical postal address, and a working opt-out honoured within 10 business days. TCPA governs calls/texts to mobiles."),
    ComplianceRule("EU", "GDPR + ePrivacy (national)", "B2B outreach to role-holders can rest on legitimate interest, but several states (e.g. Germany, Austria) require prior consent for cold email; always identify, give an opt-out, and keep a legitimate-interest assessment."),
    ComplianceRule("UK", "UK GDPR + PECR", "Corporate subscribers (company addresses) may be emailed without consent; sole traders/partnerships need consent; identify and offer opt-out."),
    ComplianceRule("India", "DPDP Act 2023 (Rules Nov 2025; full compliance 13 May 2027) + TRAI TCCCPR-2018 (2nd Amendment Feb 2025)", "DPDP has no legitimate-interest basis: named work emails are personal data needing notice and, from May 2027, consent discipline; TCCCPR abolished inferred consent, treats mixed messages as promotional and fines unregistered senders up to Rs 50,000/violation; corporate landlines, published role mailboxes, event follow-ups and consented WhatsApp are the safe channels."),
    ComplianceRule("Canada", "CASL", "Strict: implied consent only via existing business relationship or conspicuously published address with no 'no solicitation' notice."),
    ComplianceRule("GCC", "UAE PDPL / Saudi PDPL", "Saudi PDPL requires opt-in consent for direct marketing; UAE B2B treatment is contested and free zones (DIFC/ADGM) have their own regimes; use utility supplier portals (DEWA, EWEC, ACWA, Masdar) and MESIA events as the primary doors."),
    ComplianceRule("Platform", "LinkedIn User Agreement", "No scraping, bots or automation; manual use of Sales Navigator and InMail only."),
)


# --------------------------------------------------------------------------------------
# 7. Helpers
# --------------------------------------------------------------------------------------

_COUNTRY_TO_REGION: Dict[str, Region] = {
    "IN": Region.INDIA,
    "US": Region.US, "CA": Region.US,
    "GB": Region.EU, "DE": Region.EU, "FR": Region.EU, "ES": Region.EU, "IT": Region.EU, "PT": Region.EU, "NL": Region.EU, "DK": Region.EU,
    "NO": Region.EU, "SE": Region.EU, "LU": Region.EU, "IE": Region.EU, "PL": Region.EU, "GR": Region.EU, "CH": Region.EU, "AT": Region.EU, "BE": Region.EU,
    "AE": Region.MENA, "SA": Region.MENA, "QA": Region.MENA, "OM": Region.MENA, "KW": Region.MENA, "BH": Region.MENA, "EG": Region.MENA, "MA": Region.MENA,
    "JO": Region.MENA, "IL": Region.MENA, "TN": Region.MENA, "DZ": Region.MENA,
    "AU": Region.APAC, "JP": Region.APAC, "CN": Region.APAC, "SG": Region.APAC, "KR": Region.APAC, "VN": Region.APAC, "TH": Region.APAC, "PH": Region.APAC,
    "MY": Region.APAC, "ID": Region.APAC, "TW": Region.APAC,
    "CL": Region.LATAM, "BR": Region.LATAM, "MX": Region.LATAM, "AR": Region.LATAM, "CO": Region.LATAM, "PE": Region.LATAM,
    "ZA": Region.AFRICA, "KE": Region.AFRICA, "NG": Region.AFRICA, "NA": Region.AFRICA, "SN": Region.AFRICA, "GH": Region.AFRICA,
}


def region_for_country(country_code: str) -> Region:
    return _COUNTRY_TO_REGION.get((country_code or "").upper().strip(), Region.GLOBAL)


def parse_region(value: str) -> Region:
    v = (value or "").strip().lower()
    for r in Region:
        if r.value == v:
            return r
    return region_for_country(v)


def parse_company_type(value: str) -> CompanyType:
    v = (value or "").strip().lower()
    aliases = {"developer": "ipp", "asset owner": "ipp", "owner": "ipp", "o&m": "om", "o and m": "om", "contractor": "om",
               "investor": "fund", "c&i": "ci", "rooftop": "ci", "manufacturer": "oem", "engineer": "ie"}
    v = aliases.get(v, v)
    for ct in CompanyType:
        if ct.value == v:
            return ct
    return CompanyType.UNKNOWN


# Functional (role) mailbox prefixes the scout is allowed to record. Anything else is treated as
# potentially personal and is never stored - the engine finds routes, not people.
ROLE_MAILBOX_PREFIXES: Tuple[str, ...] = (
    "info", "contact", "contactus", "enquiry", "enquiries", "inquiry", "inquiries", "hello", "office",
    "procurement", "purchase", "purchasing", "vendor", "vendors", "vendorregistration", "supplier", "suppliers", "sourcing", "tenders", "tender",
    "media", "press", "pr", "communications", "corpcomm", "corporatecommunications",
    "investor", "investors", "ir", "investorrelations", "cs", "secretarial", "compliance",
    "careers", "career", "jobs", "hr", "recruitment", "talent",
    "sales", "business", "bd", "businessdevelopment", "partnerships", "partners", "partner", "innovation", "technology", "om", "operations", "support",
)


def is_role_mailbox(email: str) -> bool:
    """True only for functional mailboxes (procurement@, info@...). Personal-looking addresses are rejected."""
    local = (email or "").split("@")[0].lower().strip()
    local = re.sub(r"[._-]", "", local)
    if not local:
        return False
    if local in ROLE_MAILBOX_PREFIXES:
        return True
    # e.g. "vendor.registration", "india.sales", "sales-india", "investor_relations", "media.relations"
    return any(local.startswith(p) or local.endswith(p) for p in ("procurement", "vendor", "supplier", "tender", "investor", "media", "press", "careers", "sales", "partnership", "info", "contact", "enquir", "inquir", "innovation"))
