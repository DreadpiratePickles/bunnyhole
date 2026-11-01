"""Curated solar target universe for `bunnyhole solar sweep` / `targets`.

Each entry is a *company* (never a person) with its public web domain, type, HQ country and tags the
planner uses to pre-score heat. Domains are public corporate sites; a wrong or moved domain merely
yields 404s during the front-door probe. Tags:

  robotic_cleaning_adopter  – publicly reported robotic / waterless cleaning deployments (educated buyer)
  innovation_program        – runs a public accelerator / challenge / venture arm
  listed                    – publicly listed (annual report + filings route exists)
  dusty_fleet               – material capacity in high-soiling climates (Rajasthan/Gujarat/Gulf/Atacama/US-SW)
  in_house_om               – large in-house O&M organisation (champion sits inside)
  outsourced_om             – relies on third-party O&M (go via the contractor)
  public_tender             – buys via public tender (GeM / SAM.gov / TED)
  epc_om_channel            – EPC with captive O&M that specs new builds

The list is a starting point, not a verdict: `bunnyhole solar scout <any company>` works on anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from bunnyhole.solar.playbook import CompanyType, Region, region_for_country


@dataclass(frozen=True)
class SolarTarget:
    name: str
    domain: str
    ctype: CompanyType
    hq_country: str                      # ISO-3166 alpha-2
    tags: Tuple[str, ...] = ()
    note: str = ""
    parent: str = ""                     # ultimate owner / platform if different

    @property
    def region(self) -> Region:
        return region_for_country(self.hq_country)

    @property
    def slug(self) -> str:
        return self.domain.split(".")[0]


TARGET_UNIVERSE: Tuple[SolarTarget, ...] = (
    # ------------------------------------------------------------------ INDIA: IPPs / developers
    SolarTarget("Adani Green Energy", "adanigreenenergy.com", CompanyType.IPP, "IN",
                ("robotic_cleaning_adopter", "listed", "dusty_fleet", "in_house_om"),
                "Khavda (9.4 GW operational 2026 -> 30 GW), committed to waterless robots fleet-wide; ENOC in-house O&M; Airtouch & LEAPTING supplier.", "Adani Group"),
    SolarTarget("ReNew", "renew.com", CompanyType.IPP, "IN",
                ("robotic_cleaning_adopter", "listed", "dusty_fleet", "in_house_om", "innovation_program"),
                ">1 GW LEAPTING order (Anantapur, Bhadla); earlier Airtouch/Ecoppia; Nasdaq-listed."),
    SolarTarget("Tata Power Renewable Energy", "tatapower.com", CompanyType.IPP, "IN",
                ("robotic_cleaning_adopter", "listed", "innovation_program", "epc_om_channel"),
                "Group EPC/O&M via Tata Power Solar; Pilot Accelerator via Social Alpha; Taypro customer.", "Tata Group"),
    SolarTarget("NTPC Green Energy", "ntpcgreenenergy.com", CompanyType.UTILITY, "IN",
                ("listed", "public_tender", "dusty_fleet"),
                "PSU; buys via GeM/eProcure; NETRA pilots; Class-I local-supplier restrictions on O&M tenders.", "NTPC"),
    SolarTarget("Azure Power", "azurepower.com", CompanyType.IPP, "IN",
                ("robotic_cleaning_adopter", "dusty_fleet"), "Early Ecoppia adopter (450 MW); OMERS/CDPQ-backed."),
    SolarTarget("Avaada Group", "avaada.com", CompanyType.IPP, "IN", ("dusty_fleet", "robotic_cleaning_adopter"), "Large Rajasthan/MP portfolio; Taypro reference customer (vendor claim)."),
    SolarTarget("ACME Solar Holdings", "acme.in", CompanyType.IPP, "IN", ("listed", "dusty_fleet", "robotic_cleaning_adopter"), "Listed 2024; SVP & Head O&M role public (2026); Airtouch customer."),
    SolarTarget("JSW Energy / JSW Neo Energy", "jsw.in", CompanyType.IPP, "IN", ("listed", "dusty_fleet"), "Acquired O2 Power (2025); fast-growing RE arm.", "JSW Group"),
    SolarTarget("Sembcorp Green Infra", "sembcorp.com", CompanyType.IPP, "IN", ("dusty_fleet", "listed"), "Singapore-listed parent; multi-GW India fleet.", "Sembcorp Industries"),
    SolarTarget("Ayana Renewable Power", "ayanapower.com", CompanyType.IPP, "IN", ("dusty_fleet",), "Acquired by ONGC-NTPC Green JV (2025)."),
    SolarTarget("Sprng Energy", "sprng.com", CompanyType.IPP, "IN", ("dusty_fleet",), "Shell-owned (ex-Actis); Shell GameChanger link.", "Shell"),
    SolarTarget("Hero Future Energies", "herofutureenergies.com", CompanyType.IPP, "IN", ("robotic_cleaning_adopter", "dusty_fleet"), "KKR-backed; early robotic cleaning adopter.", "Hero Group / KKR"),
    SolarTarget("AMPIN Energy Transition", "ampin.com", CompanyType.IPP, "IN", ("dusty_fleet", "robotic_cleaning_adopter"), "Formerly Amp Energy India; buys robots directly for new builds."),
    SolarTarget("Juniper Green Energy", "junipergreenenergy.com", CompanyType.IPP, "IN", ("robotic_cleaning_adopter", "dusty_fleet"), "Repeat Airtouch orders (~3,000 robots); EVP Projects Solar role public."),
    SolarTarget("Vibrant Energy", "vibrantenergy.in", CompanyType.IPP, "IN", ("dusty_fleet",), "Macquarie-backed C&I/open-access developer.", "Macquarie"),
    SolarTarget("Serentica Renewables", "serenticaglobal.com", CompanyType.IPP, "IN", ("dusty_fleet",), "KKR-backed; round-the-clock RE for industrials.", "KKR / Sterlite"),
    SolarTarget("BluPine Energy", "blupineenergy.com", CompanyType.IPP, "IN", ("robotic_cleaning_adopter", "dusty_fleet"), "Actis-backed; 2,000-robot LEAPTING deal signed at REI 2026.", "Actis"),
    SolarTarget("Torrent Power", "torrentpower.com", CompanyType.UTILITY, "IN", ("listed",), "Gujarat utility with growing RE."),
    SolarTarget("SJVN Green Energy", "sjvn.nic.in", CompanyType.UTILITY, "IN", ("public_tender", "listed"), "PSU; tender-only.", "SJVN"),
    SolarTarget("NHPC", "nhpcindia.com", CompanyType.UTILITY, "IN", ("public_tender", "listed"), "PSU; solar parks via tender."),
    SolarTarget("Greenko Group", "greenkogroup.com", CompanyType.IPP, "IN", ("dusty_fleet",), "GIC/ADIA-backed; large hybrid fleet.", "GIC / ADIA"),
    SolarTarget("CleanMax", "cleanmax.com", CompanyType.CI, "IN", (), "C&I rooftop/open-access leader; Brookfield-backed.", "Brookfield"),
    SolarTarget("Fourth Partner Energy", "fourthpartner.co", CompanyType.CI, "IN", (), "C&I developer; IFC/ADB-backed."),
    SolarTarget("Amplus Solar", "amplussolar.com", CompanyType.CI, "IN", ("robotic_cleaning_adopter",), "Petronas-owned C&I developer; Airtouch customer.", "Petronas"),
    SolarTarget("SunSource Energy", "sunsource-energy.com", CompanyType.CI, "IN", (), "C&I developer; Shell-backed."),
    SolarTarget("Radiance Renewables", "radiancerenewables.com", CompanyType.CI, "IN", (), "NIIF-backed C&I platform."),
    SolarTarget("Evren (Brookfield India)", "brookfield.com", CompanyType.IPP, "IN", ("dusty_fleet",), "Brookfield's Indian RE platform.", "Brookfield"),
    # ------------------------------------------------------------------ INDIA: EPC / O&M / OEM
    SolarTarget("Sterling and Wilson Renewable Energy", "sterlingandwilsonre.com", CompanyType.EPC, "IN", ("listed", "epc_om_channel"), "~12-13 GW O&M fleet; India + MENA; Reliance-backed."),
    SolarTarget("Mahindra Susten", "mahindrasusten.com", CompanyType.EPC, "IN", ("epc_om_channel",), "EPC & O&M; OTPP-backed.", "Mahindra / OTPP"),
    SolarTarget("Waaree Renewable Technologies", "waareertl.com", CompanyType.EPC, "IN", ("listed", "epc_om_channel", "robotic_cleaning_adopter"), "1.2 GWp LEAPTING robot order; Waaree group OEM.", "Waaree Energies"),
    SolarTarget("Jakson Green", "jakson.com", CompanyType.OM, "IN", ("epc_om_channel",), "~5 GWp O&M; present at NTPC Bhadla."),
    SolarTarget("Inox Green Energy Services", "inoxgreen.com", CompanyType.OM, "IN", ("listed",), "Top Indian third-party O&M by fleet (2025)."),
    SolarTarget("Mitarsh", "mitarsh.com", CompanyType.OM, "IN", (), "~28 GWp O&M fleet (2025 ranking) - verify domain."),
    SolarTarget("Inspire Clean Energy", "inspirecleanenergy.com", CompanyType.OM, "IN", (), "Top-5 Indian O&M provider - verify domain."),
    SolarTarget("Rays Power Infra", "rayspowerinfra.com", CompanyType.EPC, "IN", ("epc_om_channel", "robotic_cleaning_adopter"), "EPC channel for Sol-Bright at NTPC 250 MW."),
    SolarTarget("KPI Green Energy", "kpigreenenergy.com", CompanyType.EPC, "IN", ("listed", "epc_om_channel"), "Gujarat EPC/IPP; Nextracker compatibility-letter precedent (KP Group)."),
    SolarTarget("Larsen & Toubro (Renewables EPC)", "larsentoubro.com", CompanyType.EPC, "IN", ("listed", "epc_om_channel"), "Utility-scale EPC in India and MENA."),
    SolarTarget("Adani Solar", "adanisolar.com", CompanyType.OEM, "IN", (), "Module OEM (ALMM); warranty-compatibility letters.", "Adani Group"),
    SolarTarget("Premier Energies", "premierenergies.com", CompanyType.OEM, "IN", ("listed",), "Module/cell OEM (ALMM)."),
    # ------------------------------------------------------------------ MENA
    SolarTarget("ACWA Power", "acwapower.com", CompanyType.IPP, "SA", ("listed", "dusty_fleet", "innovation_program", "in_house_om", "robotic_cleaning_adopter"), "Robots specified in Sudair 1.5 GW / Al Shuaibah 2.6 GW; O&M via NOMAC; Innovation Days."),
    SolarTarget("Masdar", "masdar.ae", CompanyType.IPP, "AE", ("dusty_fleet", "innovation_program"), "Abu Dhabi; hosts WFES; global portfolio."),
    SolarTarget("AMEA Power", "ameapower.com", CompanyType.IPP, "AE", ("dusty_fleet",), "Dubai-based; Egypt/Africa/GCC projects."),
    SolarTarget("EWEC", "ewec.ae", CompanyType.UTILITY, "AE", ("public_tender", "dusty_fleet"), "Abu Dhabi procurer; supplier portal."),
    SolarTarget("DEWA", "dewa.gov.ae", CompanyType.UTILITY, "AE", ("public_tender", "dusty_fleet"), "Dubai utility; R&D centre publishes soiling/robot studies; supplier registration."),
    SolarTarget("NOMAC", "nomac.com", CompanyType.OM, "SA", ("dusty_fleet",), "ACWA's O&M arm.", "ACWA Power"),
    SolarTarget("Saudi Aramco Power / SAPCO", "aramco.com", CompanyType.UTILITY, "SA", ("dusty_fleet", "innovation_program"), "Aramco solar; Wa'ed Ventures; NOMADD licence precedent."),
    # ------------------------------------------------------------------ US
    SolarTarget("NextEra Energy Resources", "nexteraenergyresources.com", CompanyType.IPP, "US", ("listed", "in_house_om", "dusty_fleet"), "Largest US renewables owner; in-house O&M."),
    SolarTarget("AES Clean Energy", "aes.com", CompanyType.IPP, "US", ("listed", "dusty_fleet", "robotic_cleaning_adopter"), "Ecoppia deployments in California (reported)."),
    SolarTarget("Lightsource bp", "lightsourcebp.com", CompanyType.IPP, "GB", ("dusty_fleet", "innovation_program"), "LOIs with EDS startup Sol Clarity; global fleet incl. US-SW."),
    SolarTarget("Brookfield Renewable", "brookfieldrenewable.com", CompanyType.FUND, "CA", ("listed",), "Owns platforms globally (incl. India Evren); portfolio OPEX programmes."),
    SolarTarget("Clearway Energy", "clearwayenergy.com", CompanyType.IPP, "US", ("listed", "dusty_fleet"), "Large California/Southwest fleet."),
    SolarTarget("Arevon Energy", "arevonenergy.com", CompanyType.IPP, "US", ("dusty_fleet",), "Southwest utility-scale owner (CalSTRS/APG-backed)."),
    SolarTarget("Intersect Power", "intersectpower.com", CompanyType.IPP, "US", ("dusty_fleet",), "Texas/California gigawatt projects."),
    SolarTarget("Silicon Ranch", "siliconranch.com", CompanyType.IPP, "US", (), "Shell-backed; in-house O&M culture."),
    SolarTarget("Invenergy", "invenergy.com", CompanyType.IPP, "US", ("in_house_om",), "Large private developer/owner."),
    SolarTarget("Cypress Creek Renewables", "ccrenew.com", CompanyType.IPP, "US", (), "Owner + O&M services arm."),
    SolarTarget("SOLV Energy", "solvenergy.com", CompanyType.OM, "US", (), "Major US utility-scale O&M provider (reseller channel)."),
    SolarTarget("NovaSource Power Services", "novasourcepower.com", CompanyType.OM, "US", (), "~38 GW under O&M globally (2026)."),
    SolarTarget("Nextracker", "nextracker.com", CompanyType.OEM, "US", ("listed", "innovation_program"), "Tracker OEM; owns Amir Robotics; issues cleaning compatibility letters."),
    SolarTarget("Array Technologies", "arraytechinc.com", CompanyType.OEM, "US", ("listed",), "Tracker OEM."),
    SolarTarget("First Solar", "firstsolar.com", CompanyType.OEM, "US", ("listed",), "Thin-film OEM; requires cleaning-system approval; excludes cleaning damage from warranty."),
    SolarTarget("Nexamp", "nexamp.com", CompanyType.CI, "US", ("innovation_program",), "Community solar; piloted Sol Clarity EDS."),
    # ------------------------------------------------------------------ EUROPE (global fleets)
    SolarTarget("Enel Green Power", "enelgreenpower.com", CompanyType.IPP, "IT", ("listed", "innovation_program", "dusty_fleet", "robotic_cleaning_adopter"), "Open Innovability challenges; SandStorm robot pilot path (Catania lab -> Totana 1 MW)."),
    SolarTarget("Iberdrola Renovables", "iberdrola.com", CompanyType.IPP, "ES", ("listed", "innovation_program", "dusty_fleet"), "PERSEO ran a dedicated PV-cleaning challenge; Nunez de Balboa pilots."),
    SolarTarget("EDF Renewables", "edf-re.com", CompanyType.IPP, "FR", ("innovation_program", "dusty_fleet"), "EDF Pulse; India/US/MENA fleets."),
    SolarTarget("ENGIE", "engie.com", CompanyType.IPP, "FR", ("listed", "innovation_program", "dusty_fleet", "robotic_cleaning_adopter"), "Ecoppia customer; LOIs with Sol Clarity; India, MENA, LatAm."),
    SolarTarget("EDP Renewables", "edpr.com", CompanyType.IPP, "ES", ("listed", "innovation_program"), "Free Electrons co-founder."),
    SolarTarget("TotalEnergies Renewables", "totalenergies.com", CompanyType.IPP, "FR", ("listed", "dusty_fleet"), "Global incl. India (Adani JV), MENA."),
    SolarTarget("RWE Renewables", "rwe.com", CompanyType.IPP, "DE", ("listed",), "US/EU fleets."),
    SolarTarget("Scatec", "scatec.com", CompanyType.IPP, "NO", ("listed", "dusty_fleet", "innovation_program"), "Africa/MENA/LatAm; LOI with Sol Clarity; Equinor stake."),
    SolarTarget("Voltalia", "voltalia.com", CompanyType.IPP, "FR", ("listed", "dusty_fleet"), "Brazil/Egypt/MENA."),
    SolarTarget("Zelestra", "zelestra.energy", CompanyType.IPP, "ES", ("dusty_fleet",), "Chile/Spain/US/India (ex-Solarpack)."),
    SolarTarget("Sonnedix", "sonnedix.com", CompanyType.IPP, "GB", ("dusty_fleet",), "Chile/Spain/Italy/Japan fleet."),
    SolarTarget("Encavis", "encavis.com", CompanyType.IPP, "DE", ("listed",), "European fleet; KKR take-private."),
    SolarTarget("BayWa r.e.", "baywa-re.com", CompanyType.OM, "DE", (), "Large European O&M services fleet (reseller channel)."),
    SolarTarget("Statkraft", "statkraft.com", CompanyType.IPP, "NO", ("dusty_fleet",), "India, Chile, Spain solar."),
    # ------------------------------------------------------------------ LATAM / APAC / AFRICA
    SolarTarget("Atlas Renewable Energy", "atlasrenewableenergy.com", CompanyType.IPP, "CL", ("dusty_fleet",), "Atacama (highest soiling on Earth) and Brazil/Mexico; GIP-owned."),
    SolarTarget("Mainstream Renewable Power", "mainstreamrp.com", CompanyType.IPP, "IE", ("dusty_fleet",), "Chile/South Africa; Aker-owned."),
    SolarTarget("Globeleq", "globeleq.com", CompanyType.IPP, "GB", ("dusty_fleet",), "Africa IPP (Kenya/Egypt/South Africa)."),
    SolarTarget("Enlight Renewable Energy", "enlightenergy.co.il", CompanyType.IPP, "IL", ("listed", "dusty_fleet", "robotic_cleaning_adopter"), "Airtouch's first customer; Israel/US/Europe."),
    SolarTarget("Sembcorp Industries", "sembcorp.com", CompanyType.IPP, "SG", ("listed",), "India + SE Asia.", ""),
)

TARGETS_BY_SLUG: Dict[str, SolarTarget] = {t.slug.lower(): t for t in TARGET_UNIVERSE}


_GENERIC_NAME_WORDS = {
    "energy", "energies", "solar", "power", "renewable", "renewables", "green", "limited", "ltd", "inc", "group", "holdings", "company", "co",
    "corp", "corporation", "plc", "llc", "pvt", "private", "india", "international", "global", "services", "infra", "infrastructure", "the", "and",
}


def find_target(query: str) -> Optional[SolarTarget]:
    """Resolve a name or domain to a curated target.

    Domains match only exactly (domain or slug). Names match when every *distinctive* word of the query
    (generic words like 'energy', 'solar', 'green' are ignored) appears in the target's name.
    """
    q = (query or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not q:
        return None
    for t in TARGET_UNIVERSE:
        if q in (t.domain.lower(), t.name.lower(), t.slug.lower()):
            return t
    if "." in q and " " not in q:
        return None  # a domain we do not curate: never fuzzy-match a domain onto a different company
    q_tokens = {w for w in re.split(r"[^a-z0-9&]+", q) if w} - _GENERIC_NAME_WORDS
    if not q_tokens:
        return None
    best: Tuple[int, Optional[SolarTarget]] = (0, None)
    for t in TARGET_UNIVERSE:
        n_tokens = {w for w in re.split(r"[^a-z0-9&]+", t.name.lower()) if w}
        if q_tokens <= n_tokens:
            # Prefer the most specific name (fewest extra distinctive words), e.g. "Tata Power Renewable" over a longer sibling.
            score = 100 * len(q_tokens) - len(n_tokens - _GENERIC_NAME_WORDS - q_tokens)
            if score > best[0]:
                best = (score, t)
    return best[1]


def filter_targets(region: Optional[Region] = None, ctype: Optional[CompanyType] = None, tag: Optional[str] = None) -> List[SolarTarget]:
    out: List[SolarTarget] = []
    for t in TARGET_UNIVERSE:
        if region and region != Region.GLOBAL and t.region != region:
            continue
        if ctype and ctype != CompanyType.UNKNOWN and t.ctype != ctype:
            continue
        if tag and tag not in t.tags:
            continue
        out.append(t)
    return out


def prior_heat(t: SolarTarget) -> float:
    """Pre-scan heat prior (0-40) from tags - the sweep uses it to order live scans."""
    w = {"robotic_cleaning_adopter": 14.0, "dusty_fleet": 10.0, "innovation_program": 8.0, "in_house_om": 5.0, "epc_om_channel": 4.0, "listed": 2.0, "public_tender": -3.0, "outsourced_om": -2.0}
    return max(0.0, min(40.0, sum(w.get(tag, 0.0) for tag in t.tags)))
