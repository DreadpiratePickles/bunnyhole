"""PI stream knowledge tables and lookups: sources, legal frame, doctrine, case-type playbooks, UBO workflow.

Pure data. No network, no I/O. Everything here is a reference an investigator reads before and after a trace:
which free and lawful sources exist, what Bunnyhole already queries, what is out of scope (licence,
credential or unlawful method), the legal frame, and how an elite private investigator sequences each case
type. It is information, not legal advice; the ``verify`` notes mark anything the research flagged as
unconfirmed.

The module is long because it is one cohesive reference catalog: each table has one reason to change (the
world's sources and laws), not several responsibilities.

Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.6. Research basis:
research/12_pi_methodology_and_free_sources.md. Source manual: the PI Masterclass field manual.
"""

from __future__ import annotations

import copy
from typing import Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, Field

from bunnyhole.engine.pi import CaseType

Access = Literal["keyless", "free_account", "free_api_key", "open_source", "free_noncommercial"]


class SourceEntry(BaseModel):
    name: str
    url: str
    what: str
    access: Access
    jurisdiction: str  # "us" | "ca" | "ca-on" | "uk" | "au" | "intl"
    categories: List[str]
    implemented: bool  # True only if Bunnyhole (or the pi_sources agent) already queries it
    caveats: str = ""
    verified: bool  # True only where research/12 marks the row V (page or API opened during research)


def _s(
    name: str,
    url: str,
    what: str,
    access: Access,
    jurisdiction: str,
    categories: List[str],
    *,
    implemented: bool = False,
    caveats: str = "",
    verified: bool = False,
) -> SourceEntry:
    return SourceEntry(
        name=name,
        url=url,
        what=what,
        access=access,
        jurisdiction=jurisdiction,
        categories=categories,
        implemented=implemented,
        caveats=caveats,
        verified=verified,
    )


_SEARCHSYSTEMS = "https://www.searchsystems.net/"

SOURCES: List[SourceEntry] = [
    # --- Courts and litigation --------------------------------------------------------------------------
    _s("PACER Case Locator", "https://pcl.uscourts.gov/", "Name search across US federal court cases and "
       "bankruptcies; filings name parties, counsel and addresses.", "free_account", "us", ["court_dockets"],
       caveats="Account required; per-page fees apply to documents (check the current fee schedule and any "
               "waiver). Federal courts only. Check CourtListener / RECAP before paying."),
    _s("CourtListener / RECAP", "https://www.courtlistener.com/", "Free mirror of PACER documents and dockets "
       "from the RECAP archive, plus opinions.", "free_account", "us", ["court_dockets"], implemented=True,
       caveats="API needs a free account token; unauthenticated calls return 401; set COURTLISTENER_API_TOKEN. "
               "Coverage depends on what users uploaded; absence is not proof of no case."),
    _s("UniCourt", "https://unicourt.com/", "State and federal docket aggregation with party and attorney "
       "search.", "free_account", "us", ["court_dockets"],
       caveats="Free tier is limited; premium features are paid and out of scope."),
    _s("Judyrecords", "https://www.judyrecords.com/", "Free nationwide search of US court case records across "
       "many states.", "keyless", "us", ["court_dockets"],
       caveats="Aggregated and uneven by county; confirm any hit at the court of record."),
    _s("CanLII", "https://www.canlii.org/", "Canadian court and tribunal decisions, statutes and "
       "regulations.", "keyless", "ca", ["court_dockets"],
       caveats="Published decisions only, not docket status; use provincial court portals for live files."),
    # --- Corporate registries and ownership -------------------------------------------------------------
    _s("OpenCorporates", "https://opencorporates.com/", "Largest open aggregator of company registries; the "
       "default first pivot for any company name.", "free_api_key", "intl", ["corporate_registry"],
       caveats="Web search is free; API access needs a key and bulk or commercial use is paid. Registry data "
               "can lag the source registry; confirm at the registry."),
    _s("SEC EDGAR", "https://www.sec.gov/edgar/search/", "US public-company filings, plus Form D private "
       "placements that name officers of otherwise opaque private companies.", "keyless", "us",
       ["corporate_registry", "regulatory_enforcement", "beneficial_ownership"], implemented=True,
       caveats="Officer names in Form D are self-reported; confirm against the registry."),
    _s("Companies House", "https://find-and-update.company-information.service.gov.uk/", "UK company filings, "
       "current and former officers, charges and accounts.", "free_api_key", "uk", ["corporate_registry"],
       caveats="Web search is keyless; the API needs a free key and is rate limited. Officer addresses are "
               "often service addresses."),
    _s("Companies House PSC (UK)", "https://developer.company-information.service.gov.uk/", "Persons with "
       "Significant Control: the UK's public beneficial-ownership register.", "free_api_key", "uk",
       ["beneficial_ownership", "corporate_registry"], implemented=True, verified=True,
       caveats="Needs a free API key (returns 401 without one); rate limited. Name matches are soft until "
               "confirmed by a second anchor."),
    _s("Corporations Canada", "https://ised-isde.canada.ca/site/corporations-canada/en/node/269", "Federal "
       "corporations, directors and an open-data CSV.", "keyless", "ca", ["corporate_registry"], verified=True,
       caveats="Federal corporations only; Ontario companies are in the Ontario Business Registry. API terms "
               "are unclear."),
    _s("Ontario Business Registry", "https://www.ontario.ca/page/ontario-business-registry", "Ontario "
       "corporate, business-name and limited-partnership records.", "keyless", "ca-on", ["corporate_registry"],
       caveats="Basic search is free; copies of documents carry a government fee."),
    _s("GLEIF LEI Search", "https://search.gleif.org/", "Legal Entity Identifier records and 'who owns whom' "
       "parent relationships for LEI-registered entities.", "keyless", "intl",
       ["beneficial_ownership", "corporate_registry"], implemented=True,
       caveats="Only entities that obtained an LEI appear; most small companies do not."),
    _s("Open Ownership / BODS", "https://standard.openownership.org/", "Beneficial-ownership data standard and "
       "datasets across jurisdictions.", "keyless", "intl", ["beneficial_ownership"],
       caveats="The register itself was reported retired (unconfirmed); treat as a schema and dataset "
               "source. Verify before relying."),
    _s("ICIJ Offshore Leaks", "https://offshoreleaks.icij.org/", "Panama, Paradise and Pandora Papers: "
       "officers, intermediaries and offshore entities.", "keyless", "intl",
       ["beneficial_ownership", "news_adverse_media"],
       caveats="A listing is not an allegation of wrongdoing; data is historical."),
    _s("OCCRP Aleph", "https://aleph.occrp.org/", "Cross-searchable archive of leaks, court records and "
       "registries.", "free_account", "intl", ["beneficial_ownership", "corporate_registry", "news_adverse_media"],
       caveats="Intended for journalists and researchers; read the terms before use."),
    _s("LittleSis", "https://littlesis.org/", "Relationship database of US power networks: boards, donors, "
       "officials.", "keyless", "us", ["beneficial_ownership", "news_adverse_media"],
       caveats="Community-curated; verify each link against a primary source."),
    _s("SAM.gov", "https://sam.gov/", "Entities doing business with the US government, plus debarment and "
       "exclusion records.", "keyless", "us", ["corporate_registry", "regulatory_enforcement"],
       caveats="Web search needs no key; the API needs a free key."),
    _s("ProPublica Nonprofit Explorer", "https://projects.propublica.org/nonprofits/", "IRS Form 990 data for US "
       "nonprofits: officers, compensation, finances.", "keyless", "us", ["corporate_registry"],
       implemented=True, caveats="Filings lag by one to two years."),
    _s("USAspending", "https://www.usaspending.gov/", "US federal contracts, grants and awards by recipient.",
       "keyless", "us", ["corporate_registry"], implemented=True,
       caveats="Recipient names are as filed; match to a registry entity before inferring a link."),
    _s("CRA Charities Listings", "https://apps.cra-arc.gc.ca/ebci/hacc/srch/pub/dsplyAdvncdSrch", "Canadian "
       "registered-charity status and T3010 open data.", "keyless", "ca", ["corporate_registry"],
       caveats="Not verified in research; verify before relying."),
    _s("CIPO Trademarks", "https://ised-isde.canada.ca/cipo/trademark-search", "Canadian trademark owners and "
       "agents.", "keyless", "ca", ["corporate_registry"],
       caveats="Registered and pending marks only; not verified in research."),
    _s("ABN Lookup", "https://abr.business.gov.au/Tools/WebServices", "Australian Business Number, entity name "
       "and GST status.", "free_api_key", "au", ["corporate_registry"], verified=True,
       caveats="Needs a free GUID; thin fields."),
    # --- Licences, regulators, enforcement --------------------------------------------------------------
    _s("FINRA BrokerCheck", "https://brokercheck.finra.org/", "US broker and adviser employment history and "
       "disclosures.", "keyless", "us", ["licences", "regulatory_enforcement"],
       caveats="Web only, no API found; not verified in research."),
    _s("NMLS Consumer Access", "https://www.nmlsconsumeraccess.org/", "US mortgage-originator licences and "
       "discipline.", "keyless", "us", ["licences", "regulatory_enforcement"],
       caveats="Not verified in research; verify before relying."),
    _s("CFPB Consumer Complaints", "https://www.consumerfinance.gov/data-research/consumer-complaints/",
       "Complaints against US financial firms: a pattern-of-conduct signal.", "keyless", "us",
       ["regulatory_enforcement"], implemented=True, verified=True,
       caveats="Narratives are unverified consumer claims; never present a complaint as a finding."),
    _s("State voter-registration records", _SEARCHSYSTEMS, "Voter-roll lookups where a state permits them: "
       "name, address, sometimes birth year.", "keyless", "us", ["licences", "vital_records"],
       caveats="Access and permitted use vary by state; many restrict commercial use. Use the state's own "
               "portal found through a directory, and check its terms."),
    _s("State professional-licence boards", _SEARCHSYSTEMS, "State licence lookups (trades, medicine, law, "
       "real estate) showing licensee name, status, discipline.", "keyless", "us", ["licences"],
       caveats="Each board is separate; use a directory to find it. Business address may be an office."),
    _s("State UCC filing search", _SEARCHSYSTEMS, "Secretary-of-State UCC filings: debtors, secured parties, "
       "pledged assets.", "keyless", "us", ["property_assets", "corporate_registry"],
       caveats="Per-state portals; some charge for copies."),
    # --- Property, vessels, aircraft, radio -------------------------------------------------------------
    _s("County recorders and registers of deeds", _SEARCHSYSTEMS, "Property deeds, mortgages, liens and "
       "foreclosures held at the county recorder, not in court dockets.", "keyless", "us", ["property_assets"],
       caveats="Each county is separate and some charge for copies; use a directory to find the portal."),
    _s("Teranet / OnLand", "https://www.onland.ca/", "Ontario land registry: parcel registers, ownership "
       "history, instruments.", "free_account", "ca-on", ["property_assets"],
       caveats="Registration is free but parcel registers and document copies carry government fees: "
               "'cheap', not free. Confirm the cost before searching."),
    _s("FAA Aircraft Registry", "https://registry.faa.gov/AircraftInquiry/", "US N-number registered owner and "
       "registration details.", "keyless", "us", ["property_assets"],
       caveats="Registered owner is often a trust or shell; owner-privacy rules unchecked. Not verified in "
               "research."),
    _s("USCG PSIX", "https://cgmix.uscg.mil/", "Documented US vessels: name, owner, hull data.", "keyless", "us",
       ["property_assets"], caveats="No liens shown. Not verified in research."),
    _s("Equasis", "https://www.equasis.org/", "Ship registry data: registered owner, ship manager, flag "
       "history.", "free_account", "intl", ["property_assets"],
       caveats="Free registration; the registered owner is usually a single-vessel shell, so pivot to the "
               "manager."),
    _s("FCC ULS", "https://wireless.fcc.gov/uls", "US radio licences and licensee names and addresses.",
       "keyless", "us", ["licences", "property_assets"], caveats="Mirrors lag; not verified in research."),
    _s("ADS-B Exchange", "https://www.adsbexchange.com/", "Unfiltered crowd-sourced aircraft tracking.",
       "keyless", "intl", ["property_assets"],
       caveats="Shows movements, not ownership; pair with the registry. Bunnyhole itself queries adsb.lol."),
    _s("adsb.lol", "https://adsb.lol/", "Open ADS-B aircraft position data used by Bunnyhole's aviation "
       "module.", "keyless", "intl", ["property_assets"], implemented=True,
       caveats="Positions only; resolve ownership through the national registry."),
    # --- Sanctions, PEP and jurisdiction risk -----------------------------------------------------------
    _s("OpenSanctions", "https://www.opensanctions.org/", "Deduplicated sanctions, PEP and watchlist graph with "
       "aliases and identifiers from hundreds of official lists.", "free_noncommercial", "intl",
       ["sanctions_pep"], implemented=True,
       caveats="needs OPENSANCTIONS_API_KEY or self-hosted yente; keyless calls return 401. Free for "
               "non-commercial use; commercial use needs a licence. A negative means absence from published "
               "lists, not innocence. Verify a hit on the primary list URL."),
    _s("OFAC Sanctions List Search", "https://sanctionssearch.ofac.treas.gov/", "US Treasury SDN and "
       "consolidated sanctions lists: the primary source for the 50 percent rule.", "keyless", "intl",
       ["sanctions_pep"], implemented=True, verified=True,
       caveats="Screened keyless from the official SDN XML (verified live 2026-11-09). Names only: a soft match "
               "needs identifiers to confirm."),
    _s("UN Security Council Consolidated List", "https://main.un.org/securitycouncil/en/content/"
       "un-sc-consolidated-list", "UN sanctions designations.", "keyless", "intl", ["sanctions_pep"],
       implemented=True, verified=True,
       caveats="Screened keyless from the official consolidated XML (verified live 2026-11-09). Separate from "
               "national lists; a soft name match needs identifiers to confirm."),
    _s("EU Sanctions Map", "https://www.sanctionsmap.eu/", "EU restrictive-measures regimes and designated "
       "persons.", "keyless", "intl", ["sanctions_pep"],
       caveats="Map view is keyless; the machine-readable consolidated list needs a free EU account."),
    _s("UK OFSI Consolidated List", "https://www.gov.uk/government/publications/the-uk-sanctions-list",
       "UK Sanctions List (FCDO), which replaced the OFSI consolidated list of financial-sanctions targets.",
       "keyless", "intl", ["sanctions_pep"], implemented=True, verified=True,
       caveats="Screened keyless from the official UK Sanctions List XML (FCDO; verified live 2026-11-09), which "
               "replaced the OFSI consolidated list format. UK designations only; a soft name match needs "
               "identifiers to confirm."),
    _s("GAC Canadian Sanctions (SEMA)", "https://www.international.gc.ca/world-monde/"
       "international_relations-relations_internationales/sanctions/consolidated-consolide.aspx?lang=eng",
       "Global Affairs Canada consolidated autonomous sanctions list (SEMA and JVCFOA), as XML.", "keyless",
       "ca", ["sanctions_pep"], implemented=True, verified=True,
       caveats="Published for administrative purposes only; UN and OFSI lists are separate. Matches are soft "
               "until identifiers agree."),
    _s("FATF High-Risk Jurisdictions", "https://www.fatf-gafi.org/en/countries/black-and-grey-lists.html",
       "FATF lists of jurisdictions under increased monitoring or subject to a call for action.", "keyless",
       "intl", ["jurisdiction_risk"], caveats="Lists change several times a year; check the date."),
    # --- News, archives, entity resolution --------------------------------------------------------------
    _s("Google News", "https://news.google.com/", "Adverse-media and news search used by Bunnyhole's news "
       "module.", "keyless", "intl", ["news_adverse_media"], implemented=True,
       caveats="Press coverage is a lead, not a finding; republished and syndicated stories are one source."),
    _s("Wayback Machine", "https://web.archive.org/", "Historical captures of web pages, plus a save-page "
       "function.", "keyless", "intl", ["evidence_preservation", "news_adverse_media"], implemented=True,
       caveats="Captures are incomplete; a missing capture is not proof a page never existed."),
    _s("archive.today", "https://archive.ph/", "On-demand snapshots of web pages that may vanish.", "keyless",
       "intl", ["evidence_preservation"],
       caveats="Not an authenticated capture and capture status can vary; keep your own timestamped copy too."),
    _s("Wikidata", "https://www.wikidata.org/", "Entity resolution and cross-registry identifiers.", "keyless",
       "intl", ["entity_resolution"], implemented=True, verified=True,
       caveats="Community-edited: an entity-resolution aid, verify against the primary registry."),
    # --- Missing persons, custody, vital records --------------------------------------------------------
    _s("NamUs", "https://namus.nij.ojp.gov/", "US national missing and unidentified persons system.", "keyless",
       "us", ["missing_persons"], caveats="Route any match to law enforcement, never to the client."),
    _s("Charley Project", "https://charleyproject.org/", "Cold-case missing persons.", "keyless", "us",
       ["missing_persons"], verified=True, caveats="Route matches to law enforcement."),
    _s("Doe Network", "https://doenetwork.org/", "Missing and unidentified persons.", "keyless", "intl",
       ["missing_persons"], caveats="Volunteer-run; not verified in research. Route matches to law enforcement."),
    _s("NSOPW", "https://www.nsopw.gov/", "Public sex-offender registry search across jurisdictions.", "keyless",
       "us", ["custody_registry"], verified=True,
       caveats="Privacy-sensitive; verify on the jurisdiction's own registry and never use it to harass."),
    _s("BOP Inmate Locator", "https://www.bop.gov/inmateloc/", "Federal custody status.", "keyless", "us",
       ["custody_registry"], verified=True, caveats="Federal only; state and local custody are separate."),
    _s("FamilySearch", "https://www.familysearch.org/", "Genealogy and civil-record indexes.", "free_account",
       "intl", ["vital_records"], caveats="Check terms before scraping; not verified in research."),
    _s("Find a Grave", "https://www.findagrave.com/", "Burial records and obituaries.", "keyless", "intl",
       ["vital_records"], caveats="User-submitted; check terms before scraping; not verified in research."),
    _s("Chronicling America", "https://www.loc.gov/collections/chronicling-america/", "Historic US newspaper "
       "OCR.", "keyless", "us", ["vital_records", "news_adverse_media"],
       caveats="Access reports conflict (page returned 403 in research); not verified."),
    # --- Social and identity OSINT tools ----------------------------------------------------------------
    _s("Sherlock", "https://github.com/sherlock-project/sherlock", "Username search across hundreds of social "
       "platforms.", "open_source", "intl", ["social_osint"], implemented=True,
       caveats="A matching username is a lead, not an identity; common handles collide."),
    _s("Maigret", "https://github.com/soxoj/maigret", "Username dossier across thousands of sites with "
       "profile metadata.", "open_source", "intl", ["social_osint"],
       caveats="Installable through the arsenal but not yet wired into a trace; false positives are common."),
    _s("Holehe", "https://github.com/megadose/holehe", "Checks which sites an email is registered on without "
       "alerting the owner.", "open_source", "intl", ["social_osint"], implemented=True,
       caveats="Probes sign-up and account-recovery flows with the email address (not strictly passive); never logs "
               "in. Not used in PI mode: Bunnyhole blocks and logs it there. Outside PI mode results are leads and "
               "can be stale or wrong."),
    _s("GHunt", "https://github.com/mxrch/GHunt", "Google-account footprint: public profile, Maps reviews, "
       "YouTube.", "open_source", "intl", ["social_osint"],
       caveats="Needs the investigator's own Google session, which conflicts with the passive no-login rule; "
               "not used by Bunnyhole in PI mode."),
    _s("PhoneInfoga", "https://github.com/sundowndev/phoneinfoga", "Phone number validation, carrier and line "
       "type, and footprint dorks.", "open_source", "intl", ["social_osint"],
       caveats="A reverse lookup corroborates a name you already have; it does not produce one."),
    _s("SpiderFoot", "https://github.com/smicallef/spiderfoot", "Automated OSINT scans with correlation rules.",
       "open_source", "intl", ["social_osint", "domain_infrastructure", "analysis"],
       caveats="Use passive modules only in PI mode; read raw output before trusting correlations."),
    _s("Maltego CE", "https://www.maltego.com/", "Graph-based link analysis and relationship mapping.",
       "free_noncommercial", "intl", ["analysis"],
       caveats="Community Edition is limited and for non-commercial use; paid editions are out of scope."),
    _s("Recon-ng", "https://github.com/lanmaster53/recon-ng", "Scriptable reconnaissance framework.",
       "open_source", "intl", ["social_osint", "domain_infrastructure"],
       caveats="Many modules need third-party keys; keep to passive modules."),
    _s("theHarvester", "https://github.com/laramies/theHarvester", "Passive email, subdomain and host "
       "discovery.", "open_source", "intl", ["domain_infrastructure", "social_osint"],
       caveats="Installable through the arsenal but not wired into a trace; found emails are leads."),
    _s("Hunter", "https://hunter.io/", "Domain email-pattern search and company email discovery.",
       "free_api_key", "intl", ["domain_infrastructure", "social_osint"], implemented=True,
       caveats="Small free quota; an inferred email address is a lead, not a verified contact."),
    # --- Infrastructure ---------------------------------------------------------------------------------
    _s("Shodan", "https://www.shodan.io/", "Internet-exposed devices and services for an organization.",
       "keyless", "intl", ["domain_infrastructure"], implemented=True,
       caveats="Bunnyhole uses the keyless InternetDB endpoint; the full free tier needs an account. Shared "
               "hosting is not a link."),
    _s("Censys", "https://search.censys.io/", "Internet-wide host and certificate search.", "free_api_key",
       "intl", ["domain_infrastructure"], implemented=True, caveats="Small monthly free quota."),
    _s("crt.sh", "https://crt.sh/", "Certificate Transparency history and subdomains.", "keyless", "intl",
       ["domain_infrastructure"], implemented=True, verified=True,
       caveats="Not an official API; may be slow or rate limited."),
    _s("urlscan.io", "https://urlscan.io/", "Public URL scans and page snapshots for a domain.", "keyless",
       "intl", ["domain_infrastructure"], implemented=True, caveats="Public scans may be submitted by anyone."),
    _s("HaveIBeenPwned", "https://haveibeenpwned.com/", "Breach membership check: whether an address appears in "
       "known breaches.", "keyless", "intl", ["breach_exposure"],
       caveats="Exposure signal only: PI mode never uses breach contents against private individuals. The "
               "email API is paid; use the web check."),
    # --- Crypto and on-chain ----------------------------------------------------------------------------
    _s("Etherscan", "https://etherscan.io/", "Ethereum address and transaction history.", "free_api_key", "intl",
       ["crypto_onchain"], caveats="Bunnyhole uses Blockscout keyless instead; free key limits apply."),
    _s("BscScan", "https://bscscan.com/", "BNB Chain address and transaction history.", "free_api_key", "intl",
       ["crypto_onchain"], caveats="Free key limits apply."),
    _s("Blockchain.com Explorer", "https://www.blockchain.com/explorer", "Bitcoin and other chain explorers.",
       "keyless", "intl", ["crypto_onchain"], caveats="Labels are not attribution."),
    _s("Blockscout", "https://www.blockscout.com/", "Open EVM explorer API used by Bunnyhole's on-chain "
       "module.", "keyless", "intl", ["crypto_onchain"], implemented=True,
       caveats="Entity labels are partial; a label is a lead."),
    _s("mempool.space", "https://mempool.space/", "Bitcoin mempool and UTXO explorer used by Bunnyhole.",
       "keyless", "intl", ["crypto_onchain"], implemented=True,
       caveats="Clustering heuristics are probabilistic, not proof of common control."),
    _s("Arkham Intelligence", "https://platform.arkhamintelligence.com/", "Entity-labelled wallets and exchange "
       "attribution.", "free_account", "intl", ["crypto_onchain"],
       caveats="Labels are the vendor's inference; confirm with the exchange through lawful process."),
    _s("Breadcrumbs", "https://www.breadcrumbs.app/", "Visual transaction-graph tracing.", "free_account",
       "intl", ["crypto_onchain", "analysis"], caveats="Free tier is limited; enterprise tools are out of scope."),
    # --- Images, geolocation, evidence tools ------------------------------------------------------------
    _s("ExifTool", "https://exiftool.org/", "Read camera model, timestamps and sometimes GPS from original "
       "image files.", "open_source", "intl", ["image_geo"],
       caveats="Social platforms strip EXIF on upload; only originals pay off."),
    _s("TinEye", "https://tineye.com/", "Reverse image search.", "keyless", "intl", ["image_geo"],
       caveats="A matching image shows where it appears, not who owns it."),
    _s("Yandex Images", "https://yandex.com/images/", "Reverse image search with strong face and place "
       "matching.", "keyless", "intl", ["image_geo"], caveats="Face-match hits are leads; do not name a person "
       "from one."),
    _s("Google Lens", "https://lens.google.com/", "Reverse image and visual search.", "keyless", "intl",
       ["image_geo"], caveats="Results are leads, not identification."),
    _s("WiGLE", "https://wigle.net/", "Crowd-sourced Wi-Fi network locations by BSSID.", "free_account", "intl",
       ["image_geo"], caveats="Location coverage varies."),
    _s("SunCalc", "https://www.suncalc.org/", "Sun position and shadow angle for time-of-day checks on photos.",
       "keyless", "intl", ["image_geo"], caveats="Supports, does not prove, a claimed time or place."),
    _s("Mapillary", "https://www.mapillary.com/", "Crowd-sourced street-level imagery.", "keyless", "intl",
       ["image_geo"], caveats="Coverage is uneven and imagery is dated."),
    _s("Google Earth", "https://earth.google.com/", "Satellite and historical imagery for place verification.",
       "keyless", "intl", ["image_geo"], caveats="Respect the imagery licence terms; check the capture date."),
    _s("Overpass Turbo", "https://overpass-turbo.eu/", "Query OpenStreetMap features to geolocate a place.",
       "keyless", "intl", ["image_geo"], caveats="Volunteer-run servers; not verified in research."),
    _s("Copernicus Browser", "https://dataspace.copernicus.eu/", "Sentinel satellite imagery, including "
       "historical scenes.", "free_account", "intl", ["image_geo"], caveats="Not verified in research."),
    _s("InVID-WeVerify", "https://weverify.eu/verification-plugin/", "Browser plugin for video and image "
       "verification.", "keyless", "intl", ["image_geo"], caveats="Free browser extension; not verified in "
       "research."),
    _s("FotoForensics", "https://fotoforensics.com/", "Error-level analysis of images.", "keyless", "intl",
       ["image_geo"], caveats="Uploads are stored by the service: do not use it for evidence in a live matter."),
    _s("ArchiveBox", "https://archivebox.io/", "Self-hosted capture of web pages (WARC, PDF, screenshots).",
       "open_source", "intl", ["evidence_preservation"],
       caveats="Licence unconfirmed; never archive private sessions. Not verified in research."),
    _s("OpenTimestamps", "https://opentimestamps.org/", "Bitcoin-anchored proof that a file existed at a time.",
       "open_source", "intl", ["evidence_preservation"], verified=True,
       caveats="Proves date, not authorship."),
    _s("Timesketch", "https://github.com/google/timesketch", "Collaborative forensic timeline analysis.",
       "open_source", "intl", ["analysis"], verified=True, caveats="Heavy to run."),
    _s("Datashare", "https://github.com/ICIJ/datashare", "Local document search and entity extraction.",
       "open_source", "intl", ["analysis"], verified=True, caveats="AGPL-3.0; heavy install."),
    # --- Meta-directories and frameworks ----------------------------------------------------------------
    _s("SearchSystems.net", "https://www.searchsystems.net/", "Directory of thousands of county, state and "
       "national public-record portals.", "keyless", "intl", ["meta_directory"],
       caveats="Free directory; its premium searches are paid and out of scope."),
    _s("Black Book Online", "https://www.blackbookonline.info/", "Directory of public-record portals.", "keyless",
       "intl", ["meta_directory"], caveats="Links go stale; confirm each portal."),
    _s("OSINT Framework", "https://osintframework.com/", "Tool tree organised by data type.", "keyless", "intl",
       ["meta_directory"], caveats="A launchpad, not a source."),
    _s("Bellingcat Online Investigation Toolkit", "https://bellingcat.gitbook.io/toolkit", "Curated "
       "investigation tools and guides.", "keyless", "intl", ["meta_directory"],
       caveats="Check each tool's terms and current status."),
    _s("Awesome OSINT", "https://github.com/jivoi/awesome-osint", "Maintained GitHub list of OSINT tools and "
       "resources.", "open_source", "intl", ["meta_directory"], caveats="A launchpad, not a source."),
    _s("GIJN Research Tools", "https://gijn.org/online-research-tools/", "Curated hub of investigative "
       "research tools.", "keyless", "intl", ["meta_directory"], caveats="Not verified in research."),
]


# Which source categories each case type draws on (used by sources_for).
_CASE_CATEGORIES: Dict[CaseType, frozenset[str]] = {
    CaseType.LOCATE: frozenset({
        "court_dockets", "property_assets", "corporate_registry", "licences", "social_osint", "vital_records",
        "custody_registry", "meta_directory", "evidence_preservation", "news_adverse_media",
    }),
    CaseType.BACKGROUND: frozenset({
        "court_dockets", "corporate_registry", "sanctions_pep", "news_adverse_media", "licences",
        "regulatory_enforcement", "social_osint", "entity_resolution", "meta_directory", "evidence_preservation",
        "custody_registry",
    }),
    CaseType.ASSET_SEARCH: frozenset({
        "corporate_registry", "beneficial_ownership", "sanctions_pep", "property_assets", "crypto_onchain",
        "court_dockets", "regulatory_enforcement", "news_adverse_media", "jurisdiction_risk", "entity_resolution",
        "analysis", "social_osint", "image_geo", "meta_directory", "evidence_preservation", "licences",
    }),
    CaseType.DUE_DILIGENCE: frozenset({
        "corporate_registry", "beneficial_ownership", "sanctions_pep", "court_dockets", "regulatory_enforcement",
        "news_adverse_media", "jurisdiction_risk", "entity_resolution", "domain_infrastructure", "meta_directory",
        "analysis", "licences", "breach_exposure",
    }),
    CaseType.FRAUD_SCREEN: frozenset({
        "regulatory_enforcement", "court_dockets", "corporate_registry", "beneficial_ownership", "sanctions_pep",
        "crypto_onchain", "news_adverse_media", "domain_infrastructure", "social_osint", "evidence_preservation",
        "entity_resolution", "breach_exposure", "jurisdiction_risk", "licences",
    }),
    CaseType.MISSING_PERSON: frozenset({
        "missing_persons", "vital_records", "social_osint", "news_adverse_media", "image_geo", "meta_directory",
        "custody_registry", "evidence_preservation",
    }),
}


# ----------------------------------------------------------------------------------------------------------
# Out of scope and unlawful
# ----------------------------------------------------------------------------------------------------------

_HANDOFF = "Hand off to a licensed investigator."
_LICENSED_DB_WHY = (
    "Credit-header and public-record reseller: needs a professional licence, a documented permissible purpose "
    "under FCRA/GLBA/DPPA and usually a site audit, and costs money. " + _HANDOFF
)
_PEOPLE_SEARCH_WHY = (
    "Consumer people-search site: resells marketing data that is often years stale, and scraping it breaks its "
    "terms of service. A hit is an unverified lead at best, and the output is not a consumer report. "
    + _HANDOFF
)
_ENTERPRISE_WHY = "Enterprise, paid-licence platform outside the free, lawful, passive layer. " + _HANDOFF
_UNLAWFUL_WHY = (
    "Unlawful or legally sensitive by method: no free lawful route exists, and hiring someone who promises it "
    "exposes the client to liability. " + _HANDOFF + " Only a lawful process (court order, subpoena) can reach it."
)


def _oos(name: str, category: str, why: str) -> dict:
    return {"name": name, "category": category, "why": why}


OUT_OF_SCOPE: List[dict] = [
    _oos("TLOxp", "licensed_database", _LICENSED_DB_WHY),
    _oos("Tracers", "licensed_database", _LICENSED_DB_WHY),
    _oos("IRBsearch", "licensed_database", _LICENSED_DB_WHY),
    _oos("idiCORE", "licensed_database", _LICENSED_DB_WHY),
    _oos("Accurint", "licensed_database", _LICENSED_DB_WHY),
    _oos("CLEAR", "licensed_database", _LICENSED_DB_WHY),
    _oos("SkipSmasher", "licensed_database", _LICENSED_DB_WHY),
    _oos("Delvepoint", "licensed_database", _LICENSED_DB_WHY),
    _oos("Experian", "licensed_database", "Credit-bureau data: credentialled, permissible purpose required, and "
         "FCRA-regulated for eligibility use. " + _HANDOFF),
    _oos("Equifax", "licensed_database", "Credit-bureau data: credentialled, permissible purpose required, and "
         "FCRA-regulated for eligibility use. " + _HANDOFF),
    _oos("License-plate-reader (LPR) data", "licensed_database", "Vehicle-sighting data resold under permissible "
         "use through licensed platforms; no lawful free equivalent. " + _HANDOFF),
    _oos("Checkr", "fcra_screener", "FCRA-compliant screening vendor: the correct route for employment, tenant, "
         "credit or insurance eligibility decisions, which Bunnyhole must not feed. " + _HANDOFF),
    _oos("Sterling", "fcra_screener", "FCRA-compliant screening vendor: the correct route for employment, tenant, "
         "credit or insurance eligibility decisions, which Bunnyhole must not feed. " + _HANDOFF),
    _oos("Intelius", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("BeenVerified", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("Spokeo", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("TruePeopleSearch", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("FastPeopleSearch", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("That'sThem", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("PeopleFinders", "consumer_site", _PEOPLE_SEARCH_WHY),
    _oos("DeHashed", "breach_contents", "Searchable breach contents (emails paired with passwords, names, phones): "
         "legally sensitive against private individuals, so PI mode skips and logs it. " + _HANDOFF),
    _oos("OSINT Industries", "paid_osint", "Paid email/phone-to-account discovery service. " + _HANDOFF),
    _oos("Social Links", "paid_osint", "Paid email/phone-to-account discovery service. " + _HANDOFF),
    _oos("Orbis", "enterprise_ownership", _ENTERPRISE_WHY),
    _oos("Sayari", "enterprise_ownership", _ENTERPRISE_WHY),
    _oos("Dun & Bradstreet", "enterprise_ownership", _ENTERPRISE_WHY),
    _oos("Chainalysis", "enterprise_crypto", _ENTERPRISE_WHY),
    _oos("TRM Labs", "enterprise_crypto", _ENTERPRISE_WHY),
    _oos("Elliptic", "enterprise_crypto", _ENTERPRISE_WHY),
    _oos("Pretexting and social engineering", "unlawful_method", "Impersonating anyone to extract bank, carrier, "
         "employer or other protected data is a federal crime for financial data (GLBA s.6821). " + _HANDOFF),
    _oos("GPS tracker placement", "unlawful_method", "Placing a tracker on a vehicle you do not own is unlawful in "
         "many jurisdictions and a felony in some US states. " + _HANDOFF),
    _oos("Audio recording and interception", "unlawful_method", "Recording or intercepting private communications "
         "without lawful consent is a crime in many jurisdictions (Criminal Code s.184 in Canada; verify). "
         + _HANDOFF),
    _oos("Account access, hacking and password resets", "unlawful_method", _UNLAWFUL_WHY),
    _oos("Phone pings and location data without legal basis", "unlawful_method", _UNLAWFUL_WHY),
    _oos("Sealed or expunged records", "unlawful_method", _UNLAWFUL_WHY),
    _oos("Medical records", "unlawful_method", "Protected under HIPAA: off-limits without legal process. " + _HANDOFF),
]

UNLAWFUL_METHODS: Tuple[str, ...] = (
    "Pretexting: impersonating a customer, official or other person to obtain bank, carrier, employer or other "
    "protected data (a federal crime for financial data under GLBA s.6821).",
    "Hacking or accessing accounts, resetting passwords, or logging in as the subject.",
    "Placing a GPS tracker on a vehicle you do not own without the owner's lawful consent.",
    "Recording or intercepting private communications without the consent the jurisdiction requires "
    "(one-party federally in the US, all-party in several states); wiretapping is a crime.",
    "Trespassing, or using long lenses to look into private homes.",
    "Impersonating police or implying police authority: a licence confers no police powers.",
    "Stalking or a course of conduct that causes fear (criminal harassment, Criminal Code s.264; verify).",
    "Accessing sealed or expunged records, or medical records without legal process (HIPAA).",
    "Obtaining cell-phone location pings, SSNs or live bank balances 'no questions asked': a marker of an "
    "unlawful method, and hiring that provider exposes the client to liability.",
    "Using a consumer report or investigative report for an eligibility decision (employment, housing, credit, "
    "insurance) outside FCRA rules.",
)


# ----------------------------------------------------------------------------------------------------------
# Legal frame (information, not legal advice)
# ----------------------------------------------------------------------------------------------------------


def _rule(rule: str, applies: str, practical: str, verify: str) -> dict:
    return {"rule": rule, "applies": applies, "practical": practical, "verify": verify}


_VERIFY_GENERIC = "Laws change and vary by place; confirm current requirements with counsel before relying."

LEGAL_RULES: Dict[str, List[dict]] = {
    "general": [
        _rule("No pretexting", "Any jurisdiction",
              "Never lie about who you are or why you ask to extract protected data; honest interviews are lawful, "
              "misrepresentation to obtain data is where interviewing becomes illegal pretexting.",
              _VERIFY_GENERIC),
        _rule("No hacking or account access", "Any jurisdiction",
              "Never log in as the subject, reset a password, or bypass access controls. Passive checks that never "
              "authenticate (a public-profile or username lookup) are the line. Probes of sign-up or "
              "account-recovery flows (Holehe-style) are not used in PI mode because they probe account-recovery "
              "flows (not strictly passive).", _VERIFY_GENERIC),
        _rule("No trespass", "Any jurisdiction",
              "Observe only from public places where there is no reasonable expectation of privacy.",
              _VERIFY_GENERIC),
        _rule("No impersonation of police; a licence is not police power", "Any jurisdiction",
              "A private-investigator licence confers no police powers: no wiretap, no arrest, no compelling "
              "records. Work with law enforcement, never as it.", _VERIFY_GENERIC),
        _rule("Document the purpose before any query", "Any jurisdiction",
              "A written purpose is what makes a query lawful for a professional and unlawful for a curious "
              "stranger; Bunnyhole refuses a trace without one.", _VERIFY_GENERIC),
        _rule("Client liability for an investigator's unlawful methods", "Any jurisdiction",
              "If an investigator you hired commits a crime to get information, you can face consequences. "
              "Anyone promising data no lawful method can produce is advertising an unlawful method.",
              _VERIFY_GENERIC),
        _rule("This is information, not legal advice", "Bunnyhole output and this catalog",
              "Bunnyhole is a research tool, not a licence and not a lawyer. Findings are leads, not verdicts, and "
              "nothing here establishes compliance with any statute.",
              "Consult a lawyer before investigating real subjects."),
    ],
    "us": [
        _rule("FCRA (15 U.S.C. s.1681)", "Consumer reports used for credit, employment, housing or insurance",
              "A permissible purpose is required. Skip-trace and investigative reports are not consumer reports "
              "and must not be used for eligibility decisions: hiring, tenancy, credit and underwriting go "
              "through an FCRA-compliant screener.",
              "Confirm the purpose is not an eligibility decision; ask counsel about borderline uses."),
        _rule("GLBA s.6821 (15 U.S.C. s.6821)", "Nonpublic financial information",
              "Pretexting is a federal crime with no exceptions: never impersonate anyone to get bank or "
              "financial data (penalties up to $500,000 and 10 years per the manual).",
              "Penalty figures come from the manual; verify against the statute."),
        _rule("DPPA (18 U.S.C. s.2721)", "Motor-vehicle (DMV) records",
              "Only enumerated permissible purposes apply, such as litigation or insurance claims; liquidated "
              "damages of $2,500 per violation per the manual.", "Verify the enumerated purposes and damages."),
        _rule("FDCPA", "Debt-collection contact conduct",
              "Do not harass third parties or contact them repeatedly about a debt.", _VERIFY_GENERIC),
        _rule("TCPA", "Calling and texting rules", "Respect calling restrictions; no repeated or automated "
              "contact.", _VERIFY_GENERIC),
        _rule("HIPAA", "Medical records", "Medical records are off-limits without legal process.",
              _VERIFY_GENERIC),
        _rule("Recording consent", "Audio recording of conversations",
              "Federal US law is one-party consent, but several states (for example California, Florida, "
              "Illinois, Pennsylvania and Washington) require all-party consent. Recording illegally destroys the "
              "evidence and can bring prosecution. Bunnyhole records nothing.",
              "Confirm the consent law of the specific state before anyone records."),
        _rule("GPS trackers on vehicles", "Placing a tracker on a vehicle you do not own",
              "US state law varies widely: Hawaii makes unauthorised tracking a Class C felony, and Michigan and "
              "North Dakota carve out narrow licensed-investigator exceptions. In the UK the professional body "
              "treats tracker data as intelligence only, never standalone evidence, deployable only as an aid to "
              "physical surveillance with a documented impact assessment. Bunnyhole places no trackers.",
              "State statutes change; confirm the current law in the specific state before any use."),
        _rule("Surveillance and stalking statutes", "Following and photographing a subject",
              "Public-place observation is lawful; trespass, telephoto views into homes and a course of conduct "
              "that amounts to stalking are not. Bunnyhole performs no surveillance.", _VERIFY_GENERIC),
        _rule("State investigator licensing", "Practising as a private investigator for pay",
              "Most states license PIs; Idaho, Mississippi and South Dakota do not, and Alaska and Wyoming "
              "regulate locally. Requirements often include experience or an apprenticeship, an exam, a bond and "
              "insurance.", "Check the specific state's licensing authority."),
    ],
    "ca-on": [
        _rule("Private Security and Investigative Services Act, 2005 (PSISA)",
              "Acting as a private investigator for pay in Ontario",
              "Licensed by the Ministry of the Solicitor General: age 18+, eligible to work in Canada, a recent "
              "Criminal Record and Judicial Matters Check, a 50-hour ministry-approved basic course, a "
              "60-question exam, then an application through ServiceOntario. Licences are digital-only and renew "
              "every two years. Bunnyhole output feeding paid third-party work may fall inside the Act; it is a "
              "research tool, not a licence.",
              "Verify with the Ministry of the Solicitor General (the research marks this unconfirmed): licensing "
              "facts and applicability change."),
        _rule("PIPEDA", "Personal information handled in commercial activity in Canada",
              "Consent and legitimate-purpose rules constrain personal-data work. Canada has no US-style "
              "credit-header resale ecosystem, so lean on court records, land titles, corporate registries and "
              "OSINT.", "Confirm with counsel which privacy statute governs the specific data and activity."),
        _rule("Criminal Code s.184 (interception of private communications)", "Recording or intercepting "
              "communications",
              "Intercepting a private communication without lawful consent is an offence; one party consenting "
              "is a different analysis from none consenting.",
              "Verify the current wording and consent rules with counsel (the research marks this unconfirmed)."),
        _rule("Criminal Code s.264 (criminal harassment)", "Repeated following, watching or contact that causes "
              "fear", "A course of conduct that makes a person fear for their safety is an offence. Surveillance "
              "must never become harassment.",
              "Verify the current wording with counsel (the research marks this unconfirmed)."),
    ],
}

# ----------------------------------------------------------------------------------------------------------
# Doctrine, cycle, UBO workflow
# ----------------------------------------------------------------------------------------------------------

DOCTRINE: Tuple[dict, ...] = (
    {"order": 1, "title": "Start from the decision, not the subject",
     "summary": "Ask what the client will decide with the answer. That defines 'done' and the stop rule."},
    {"order": 2, "title": "Vet the client and the purpose",
     "summary": "Screen the motive, refuse forbidden eligibility purposes, and require a matter reference for "
                "locates of private people. Walk away from ex-partner locates."},
    {"order": 3, "title": "Run the conflict check against prior cases",
     "summary": "Check the subject and selectors against earlier engagements before spending effort."},
    {"order": 4, "title": "Cheapest, highest-yield source first, with stop rules",
     "summary": "Order work by yield per cost, justify every pivot, and stop when the objective is met or an "
                "escalation trigger fires."},
    {"order": 5, "title": "Resolve identity before inferring links",
     "summary": "Never merge two people on a name alone: two-anchor rule, common-name penalty, disqualifiers "
                "such as an age gap or a death date."},
    {"order": 6, "title": "Know what is not a link",
     "summary": "Registered-agent addresses, virtual offices, nominee directors serving hundreds of entities, "
                "shared hosting and very common names are not evidence of a relationship."},
    {"order": 7, "title": "Label confidence by independent corroboration",
     "summary": "Confirmed needs three independent sources, probable two, lead one; decay stale data."},
    {"order": 8, "title": "Log every negative",
     "summary": "A coverage matrix shows what was and was not searched. Absence from searched sources is not "
                "proof of absence."},
    {"order": 9, "title": "Chase contradictions and gaps in the chronology",
     "summary": "Conflicts between records are leads; gaps are questions to ask."},
    {"order": 10, "title": "State what would change the conclusion",
     "summary": "Name the competing hypotheses and the evidence that would overturn the current view."},
    {"order": 11, "title": "Find the custodian where public data ends",
     "summary": "Name who holds the record and which lawful instrument reaches it: subpoena, production order, "
                "Norwich Pharmacal order, MLAT, licensed database or public-place field verification."},
    {"order": 12, "title": "Bottom line up front, with chain of custody",
     "summary": "Lead with the conclusion, its label, the biggest gap and the next step; every claim traces to "
                "a hashed receipt."},
    {"order": 13, "title": "Stay passive and skip breach contents",
     "summary": "No login, no password reset, no contact with the subject, no tipping off; breach contents "
                "against private individuals are skipped and logged."},
)

CYCLE_STAGES: Tuple[dict, ...] = (
    {"order": 1, "name": "Intake and legal scoping",
     "summary": "Write the client's purpose, confirm a permissible purpose, set the objective and the stop rule "
                "before touching any source.",
     "bunnyhole": "Engagement gates: purpose length, forbidden eligibility terms, motive screen, matter reference."},
    {"order": 2, "name": "Desk research",
     "summary": "Anchor the identity, then work cheapest and highest-yield sources first and log every "
                "negative.",
     "bunnyhole": "The trace itself: free, lawful, passive sources, with a coverage matrix."},
    {"order": 3, "name": "Field verification (licensed)",
     "summary": "Public-place observation and interviews confirm what records suggest. Requires a licensed "
                "investigator.",
     "bunnyhole": "Not performed. Bunnyhole writes the handoff sheet for the licensed investigator."},
    {"order": 4, "name": "Corroboration",
     "summary": "Nothing is fact until independent sources agree; reconcile contradictions and age stale "
                "data.",
     "bunnyhole": "Labels (confirmed / probable / lead), freshness, contradictions and evidence gaps."},
    {"order": 5, "name": "Court-ready report",
     "summary": "A chronological, plain-language report where every conclusion ties to documented facts and "
                "survives cross-examination.",
     "bunnyhole": "Bottom-line-up-front report with chain of custody and legal notices."},
)

UBO_STEPS: Tuple[dict, ...] = (
    {"step": 1, "action": "Anchor the entity: legal name, jurisdiction and registration number.",
     "tools": ["OpenCorporates", "Companies House", "Ontario Business Registry", "Corporations Canada"],
     "bunnyhole": "Seed the registry search and record the registry URL as a receipt."},
    {"step": 2, "action": "Pull the actual incorporation documents from the registry.",
     "tools": ["OCCRP Aleph", "Companies House", "Ontario Business Registry"],
     "bunnyhole": "Hash each downloaded document (SHA-256) into the chain of custody."},
    {"step": 3, "action": "List current and historical directors and officers.",
     "tools": ["OpenCorporates", "SEC EDGAR", "Companies House"],
     "bunnyhole": "Historical officers are leads for nominee detection."},
    {"step": 4, "action": "Identify declared shareholders and persons with significant control.",
     "tools": ["Open Ownership / BODS", "GLEIF LEI Search", "Companies House PSC (UK)"],
     "bunnyhole": "GLEIF parents and Companies House PSC feed the ownership walk."},
    {"step": 5, "action": "Detect nominees, trusts and service providers.",
     "tools": ["ICIJ Offshore Leaks", "OCCRP Aleph"],
     "bunnyhole": "Nominee-frequency and registered-agent flags mark what is not a link."},
    {"step": 6, "action": "Verify the physical persons behind the names.",
     "tools": ["LittleSis", "Wikidata"],
     "bunnyhole": "Identity resolution applies the two-anchor rule before merging any person."},
    {"step": 7, "action": "Walk up to the next ownership layer and repeat, to a maximum of about five levels.",
     "tools": ["Maltego CE"],
     "bunnyhole": "Breadth-first walk with a cycle guard; nodes that end before a person are listed as "
                  "unresolved."},
    {"step": 8, "action": "Sanctions-check every node, including the OFAC 50% rule for entities owned 50% or more "
                          "by a listed party.",
     "tools": ["OpenSanctions", "OFAC Sanctions List Search"],
     "bunnyhole": "Fixed-point 50% rule over the ownership edges; a hit is verified on the primary list."},
    {"step": 9, "action": "Check jurisdiction risk against the FATF high-risk and increased-monitoring lists.",
     "tools": ["FATF High-Risk Jurisdictions"], "bunnyhole": "Recorded as context, never as a finding."},
    {"step": 10, "action": "Sweep adverse media and litigation for every node.",
     "tools": ["OpenSanctions", "CourtListener / RECAP"],
     "bunnyhole": "Court and news hits are labelled by independent source count."},
    {"step": 11, "action": "Correlate crypto flows if applicable.",
     "tools": ["Arkham Intelligence", "Etherscan"],
     "bunnyhole": "Find the cash-out point; the exchange is where lawful process attaches a name."},
    {"step": 12, "action": "Document the final chain: nodes, edges, percentages, dates and a SHA-256 hash per "
                           "document.",
     "tools": ["Maltego CE"], "bunnyhole": "The ownership block plus the chain-of-custody table in the report."},
)


# ----------------------------------------------------------------------------------------------------------
# Playbooks
# ----------------------------------------------------------------------------------------------------------


class PlaybookStep(BaseModel):
    order: int
    action: str
    sources: List[str] = Field(default_factory=list)
    yield_level: Literal["high", "medium", "low"]
    cost: Literal["free", "free_key", "handoff"]
    legal_gate: str = ""
    stop_if: str = ""


class Playbook(BaseModel):
    case_type: CaseType
    objective: str
    done_when: str
    steps: List[PlaybookStep]
    escalate_when: List[str]
    pitfalls: List[str]
    typical_hypotheses: List[str]
    # escalate_when text (verbatim) -> machine key the runtime can evaluate from the result block (ESCALATION_KEYS).
    # Items without a key need human judgement and are reported as "not evaluated automatically".
    escalate_keys: Dict[str, str] = Field(default_factory=dict)


def _steps(rows: List[tuple]) -> List[PlaybookStep]:
    """Build ordered steps; each row is (action, sources, yield, cost, legal_gate, stop_if)."""
    return [
        PlaybookStep(order=i, action=a, sources=s, yield_level=y, cost=c, legal_gate=g, stop_if=stop)
        for i, (a, s, y, c, g, stop) in enumerate(rows, start=1)
    ]


_COURTS = ["PACER Case Locator", "CourtListener / RECAP", "Judyrecords", "UniCourt", "CanLII"]
_SANCTIONS = [
    "OpenSanctions", "OFAC Sanctions List Search", "UN Security Council Consolidated List", "EU Sanctions Map",
    "UK OFSI Consolidated List", "GAC Canadian Sanctions (SEMA)",
]
_REGISTRIES = ["OpenCorporates", "Ontario Business Registry", "Corporations Canada", "Companies House"]
_PASSIVE_GATE = "Passive only: no login, no password reset, no contact with the subject."
_FCRA_GATE = "Not for eligibility decisions (employment, housing, credit, insurance): FCRA applies."

_LOCATE = Playbook(
    case_type=CaseType.LOCATE,
    objective="Establish a current address or contact for a named person so the client can serve, enforce or "
              "reach them through lawful channels, or document a dead end.",
    done_when="A current address or contact is supported by two or more independent sources (probable) or three "
              "or more (confirmed), each dated within 12 months, or every expected source class is logged as "
              "searched and the dead end is documented.",
    steps=_steps([
        ("Anchor identifiers: full legal name plus one more anchor (prior address, approximate birth year or a "
         "relative); record the matter reference; generate name variants.", [], "high", "free",
         "Written purpose and a matter reference (case number, contract or judgment) on file; refuse ex-partner "
         "or protective-order locates.",
         "No full name plus a second anchor: stop and ask the client for one before searching."),
        ("Search court dockets and decisions for the subject and variants: filings carry addresses, service "
         "addresses and counsel.", _COURTS, "high", "free",
         "Public court records only; respect sealed and protected-address orders.",
         "Two independent filings under 12 months old agree on an address."),
        ("Check property, corporate-officer and licence records for the same name and anchors.",
         ["County recorders and registers of deeds", "Teranet / OnLand", "OpenCorporates",
          "Ontario Business Registry", "State professional-licence boards", "State UCC filing search"],
         "medium", "free_key",
         "Voter and licence data carry state use restrictions; check the permitted uses of each record.",
         "Results are for a different person (age, middle initial or city conflict): record as a negative."),
        ("Check custody status where an arrest or prison stay is plausible.", ["BOP Inmate Locator"], "low",
         "free", "Use only for a documented purpose; federal custody only.",
         "No custody record: log the negative and move on."),
        ("Map the passive social and OSINT footprint with usernames and emails derived from the anchors.",
         ["Sherlock", "Holehe", "Maigret", "Google News"], "medium", "free", _PASSIVE_GATE,
         "Hits rest on a common name or handle with no second anchor: keep them as leads and do not merge."),
        ("Age and corroborate every candidate address; archive volatile pages.", ["Wayback Machine"], "high",
         "free", "Preserve with timestamps; never alter a page.",
         "Two independent sources agree and neither is stale: stop searching and report."),
        ("Hand off for credit-header confirmation and, if needed, public-place field verification.",
         ["licensed credit-header database"], "high", "handoff",
         "Licensed investigator only, with a documented permissible purpose.",
         "Do not start field work until two independent sources agree on an address."),
    ]),
    escalate_when=[
        "Two sources disagree on the current address and neither is fresh.",
        "The subject appears to be evading service (frequent moves, mail drops).",
        "A confirmed address is needed for service or surveillance: hand off to a licensed investigator.",
        "Any sign the client is a former partner or the subject is a protected party: stop and walk away.",
    ],
    pitfalls=[
        "Stale marketing data: consumer-site addresses can be years out of date.",
        "A common name matches many people: never accept a hit on a name alone.",
        "Mail drops and registered-agent addresses look like homes but are not.",
        "Treating a consumer-site hit as fact: it is an unverified lead until corroborated.",
        "A relative's address is not the subject's address.",
    ],
    typical_hypotheses=[
        "The subject still lives at the last known address.",
        "The subject moved within the region and a recent filing shows the new address.",
        "The subject is deliberately evading (address churn, mail drops, no recent records).",
        "The hits belong to a different person with the same name.",
    ],
)

_BACKGROUND = Playbook(
    case_type=CaseType.BACKGROUND,
    objective="Confirm who the subject is and assemble their public-record history (litigation, corporate roles, "
              "sanctions and PEP status, adverse media, licences) for a purpose that is not an eligibility "
              "decision.",
    done_when="Identity is resolved on two or more anchors and each history element carries a label and its "
              "independent sources, with every searched source class logged including negatives.",
    steps=_steps([
        ("Resolve identity: name variants, two-anchor rule, disqualifiers such as an age gap or a death date.",
         [], "high", "free", _FCRA_GATE + " Refuse hiring, tenancy, credit or insurance purposes.",
         "Identity rests on a name alone: stop and request a second anchor."),
        ("Search litigation under the resolved identity.", _COURTS, "high", "free",
         "Public court records only; sealed and expunged records are off limits.",
         "A case matches the name but not the anchors: record as a negative for this person."),
        ("Pull corporate roles: current and historical directorships and filings.",
         ["OpenCorporates", "SEC EDGAR", "Ontario Business Registry", "Corporations Canada", "Companies House"],
         "medium", "free_key", "Public registries; a registered-agent address is not evidence of a link.",
         "Officer names are too common to tie to this person without a second anchor."),
        ("Screen sanctions and PEP status on the primary lists.", _SANCTIONS, "high", "free",
         "A negative means absence from lists, not innocence; verify any hit on the primary list.",
         "A hit does not match identifiers: log as a soft match and do not report it as a designation."),
        ("Sweep adverse media and archive what matters.", ["Google News", "Wayback Machine"], "medium", "free",
         "Press coverage is a lead; republished stories count as one source.",
         "Only syndicated copies of one story exist: label it a lead."),
        ("Check professional licences and regulatory records.",
         ["FINRA BrokerCheck", "NMLS Consumer Access", "State professional-licence boards"], "medium", "free",
         "Public licence lookups only.", "No licence record for this person: log the negative."),
        ("Assemble the report with its eligibility notice and the coverage matrix.", [], "high", "free",
         _FCRA_GATE, "Any reader intends an eligibility decision: stop and refer to an FCRA-compliant screener."),
    ]),
    escalate_when=[
        "The client wants the result for an employment, tenant, credit or insurance decision: stop and refer to "
        "an FCRA-compliant screener.",
        "Identity cannot be resolved beyond a name.",
        "Certified copies of court records are needed: counsel or a licensed investigator.",
        "A sanctions or PEP soft match needs confirming: escalate to compliance counsel.",
    ],
    pitfalls=[
        "A common name conflates two people: apply the two-anchor rule before merging.",
        "Absence from public records is not proof of a clean history (sealed and expunged records stay hidden).",
        "A consumer-site hit is an unverified lead, not a finding; stale marketing data misleads.",
        "Registered-agent addresses and shared officers are not links.",
    ],
    typical_hypotheses=[
        "The records belong to a different person with the same name.",
        "The subject's history is clean in public sources but differs in non-public ones.",
        "The subject uses a variant, former or abbreviated name that the first pass missed.",
    ],
)

_ASSET_SEARCH = Playbook(
    case_type=CaseType.ASSET_SEARCH,
    objective="Map the assets a subject holds directly and through entities, with the ownership chain traced to "
              "a living person, so counsel can choose the right legal process.",
    done_when="Every asset has a named legal owner and a traced chain to a natural person (or a documented "
              "unresolved node), a label, and a custodian for process; or every expected source class is logged "
              "as searched.",
    steps=_steps([
        ("Anchor the entity and the subject: legal name, jurisdiction, registration number.", _REGISTRIES
         + ["SEC EDGAR"], "high", "free_key", "Public registries; purpose and matter reference on file.",
         "The entity cannot be found in any searched registry: log negatives and ask the client for the "
         "registration number."),
        ("Pull registry documents and list current and historical officers.",
         ["Companies House", "OCCRP Aleph", "SEC EDGAR", "Ontario Business Registry"], "high", "free_key",
         "Public documents only; hash each (SHA-256).",
         "Officers are nominees serving many entities: flag and stop treating them as links."),
        ("Walk the ownership chain upward using the 12-step UBO workflow (see UBO_STEPS), to about five "
         "levels; flag nominees, trusts and registered-agent addresses as not links.",
         ["Companies House PSC (UK)", "GLEIF LEI Search", "Open Ownership / BODS", "ICIJ Offshore Leaks"],
         "high", "free_key", "Name matches stay soft until a second anchor agrees.",
         "The chain ends at a nominee, trust or secrecy jurisdiction: record the unresolved node."),
        ("Screen every node for sanctions, applying the OFAC 50% rule through the ownership percentages.",
         _SANCTIONS + ["FATF High-Risk Jurisdictions"], "high", "free",
         "A hit is verified on the primary list; a 50% rule block is a compliance matter for counsel.",
         "Any block or direct hit: stop and refer to compliance counsel."),
        ("Search real property, liens and secured debts: deeds, mortgages, UCC filings and bankruptcy "
         "dockets.", ["County recorders and registers of deeds", "Teranet / OnLand", "State UCC filing search",
                      "PACER Case Locator", "CourtListener / RECAP"], "high", "free",
         "Public records; registry fees are cheap, not free.",
         "Property sits in a holding company: trace the company, not the address."),
        ("Vessels and aircraft: look up the registered owner, then pivot to the ship or aircraft manager or "
         "operator, which is usually the accountable entity; trace both and screen every party.",
         ["Equasis", "FAA Aircraft Registry", "USCG PSIX", "ADS-B Exchange", "adsb.lol"], "medium", "free",
         "Registry data is public; movements are not ownership.",
         "The registered owner is a single-asset shell: record it and move to the manager."),
        ("Crypto: identify wallets from filings or reports and map counterparties to find the cash-out point, a "
         "deposit address at a KYC exchange.", ["Etherscan", "BscScan", "Blockchain.com Explorer", "Blockscout",
                                                "mempool.space", "Arkham Intelligence", "Breadcrumbs"],
         "medium", "free_key", "Ledger data is public; attribution labels are leads, not identity.",
         "A cash-out point is found: stop tracing and name the exchange as the custodian."),
        ("Compare visible lifestyle against declared income: luxury assets, travel and property signal hidden "
         "wealth. Treat every indicator as a lead.",
         ["Sherlock", "Google News", "Wayback Machine", "Google Earth", "Mapillary"], "low", "free",
         _PASSIVE_GATE, "Lifestyle evidence rests on one social post: keep it as a lead."),
        ("Sweep litigation, forfeiture and enforcement records for traced assets and wallets.",
         ["CourtListener / RECAP", "PACER Case Locator", "USAspending", "SAM.gov"], "medium", "free",
         "Public records only.", "Records name only the entity: tie to a person before reporting."),
        ("Name the custodian and legal instrument for every non-public hit: bank, exchange, registered agent.",
         ["counsel"], "high", "handoff",
         "Counsel decides the process; never pretext a bank or carrier.",
         "No lawful route exists for the data: report it as out of reach."),
    ]),
    escalate_when=[
        "A bank account, exchange deposit address or registered-agent file is indicated: counsel for a subpoena, "
        "production order or Norwich Pharmacal order.",
        "The chain ends at a nominee or secrecy jurisdiction.",
        "The work crosses borders: MLAT or Hague routes through counsel.",
        "Any sanctions hit or 50% rule block: stop and refer to compliance counsel.",
    ],
    pitfalls=[
        "Registered-agent addresses and shared officers are not ownership links.",
        "Nominee directors serving hundreds of entities hide the real owner; frequency is a flag, not a finding.",
        "Stale marketing data and consumer-site hits are unverified leads.",
        "A common name attached to an asset does not show it is the subject's.",
        "Registered owner is not beneficial owner: always walk to a person.",
    ],
    typical_hypotheses=[
        "Assets are held through nominee entities in other jurisdictions.",
        "Assets were dissipated or transferred before judgment.",
        "The subject is genuinely judgment-proof.",
    ],
)

_DUE_DILIGENCE = Playbook(
    case_type=CaseType.DUE_DILIGENCE,
    objective="Give the client a counterparty-risk picture: who the entity is, who owns it, whether it is "
              "sanctioned, and what litigation, enforcement, complaints and media say.",
    done_when="Registry identity, the ownership chain, sanctions and PEP results, litigation and enforcement, "
              "adverse media and jurisdiction risk are each labelled with sources, and unresolved ownership "
              "nodes are listed.",
    steps=_steps([
        ("Confirm the entity in its registry and resolve its identity; use Wikidata only as an aid.",
         _REGISTRIES + ["Wikidata"], "high", "free_key", "Public registries.",
         "Registry identity is ambiguous: ask the client for a registration number."),
        ("Walk beneficial ownership using the 12-step UBO workflow.", ["Companies House PSC (UK)",
                                                                      "GLEIF LEI Search",
                                                                      "Open Ownership / BODS",
                                                                      "ICIJ Offshore Leaks"],
         "high", "free_key", "Name matches stay soft until a second anchor agrees.",
         "The chain ends before a person: list the unresolved node."),
        ("Screen sanctions and PEP status for every node, including the OFAC 50% rule.", _SANCTIONS, "high",
         "free", "A negative is absence from lists, not innocence; verify any hit on the primary list.",
         "Any hit or block: stop and refer to compliance counsel."),
        ("Search litigation, enforcement and complaints.", ["CourtListener / RECAP", "PACER Case Locator",
                                                           "SEC EDGAR", "SAM.gov", "CFPB Consumer Complaints"],
         "medium", "free", "Consumer complaint narratives are unverified claims, never findings.",
         "Only complaints exist, with no case or order: report as a pattern-of-conduct note."),
        ("Sweep adverse media and leaks for the entity and its principals.", ["Google News", "Wayback Machine",
                                                                              "OCCRP Aleph"],
         "medium", "free", "Press coverage is a lead; syndicated copies count as one source.",
         "Only one story exists: label it a lead."),
        ("Assess jurisdiction risk against the FATF lists.", ["FATF High-Risk Jurisdictions"], "low", "free",
         "Context only; never treat a jurisdiction as a finding about the entity.",
         "The lists are older than three months: note the date."),
    ]),
    escalate_when=[
        "A sanctions hit, 50% rule block or PEP link: refer to compliance counsel.",
        "The ownership chain ends at a nominee or secrecy jurisdiction.",
        "Non-public company records are needed: counsel for a production order.",
    ],
    pitfalls=[
        "Stale registry data: an old filing may no longer describe the company.",
        "A common company name matches several entities: match on registration number.",
        "Registered-agent addresses and shared officers are not links.",
        "A consumer-site hit or a single complaint is an unverified lead.",
    ],
    typical_hypotheses=[
        "The counterparty is a legitimate operating business.",
        "The counterparty is a shell or pass-through with nominee owners.",
        "The counterparty is clean but carries sanctions or reputational exposure through an owner or affiliate.",
    ],
)

_FRAUD_SCREEN = Playbook(
    case_type=CaseType.FRAUD_SCREEN,
    objective="Find pattern-of-conduct evidence about a person or entity and state what is verifiable, so the "
              "client or counsel can decide on a complaint or formal investigation.",
    done_when="Each indicator is labelled with independent sources, consumer claims are marked unverified, the "
              "money trail reaches a custodian, and gaps are listed.",
    steps=_steps([
        ("Anchor the entity or person and resolve identity before linking anything.", _REGISTRIES, "high",
         "free_key", "Purpose and matter reference on file.",
         "Identity rests on a name alone: request a second anchor."),
        ("Search enforcement and complaint databases.", ["CFPB Consumer Complaints", "SEC EDGAR",
                                                         "CourtListener / RECAP", "FINRA BrokerCheck",
                                                         "NMLS Consumer Access"],
         "high", "free", "Complaint narratives are unverified consumer claims.",
         "Complaints only, no orders: report as a pattern, not a finding."),
        ("Check shell-company red flags: newly registered, no staff or website, secrecy jurisdiction, shared "
         "nominee directors, large flows with a thin paper trail.", ["Companies House", "OpenCorporates",
                                                                    "ICIJ Offshore Leaks", "Wayback Machine"],
         "medium", "free_key", "Public records; nominee frequency is a flag, not a finding.",
         "Red flags rest on one record: keep as a lead."),
        ("Inspect the domain and infrastructure for lookalikes, shared hosting and history.",
         ["crt.sh", "urlscan.io", "Shodan", "Wayback Machine"], "medium", "free", _PASSIVE_GATE,
         "Shared hosting or a common registrar: not a link."),
        ("Trace the money trail on public ledgers and screen counterparties.", ["Blockscout", "mempool.space",
                                                                              "Etherscan",
                                                                              "Arkham Intelligence",
                                                                              "OpenSanctions"],
         "medium", "free_key", "Ledger data is public; attribution labels are leads.",
         "A KYC exchange deposit address is found: name it as the custodian."),
        ("Name custodians and legal instruments for non-public records: banks, exchanges, registered agents, "
         "carriers.", ["counsel"], "high", "handoff", "Counsel decides the process; never pretext.",
         "No lawful route exists: report the data as out of reach."),
    ]),
    escalate_when=[
        "A funds trail reaches a bank or KYC exchange: counsel for a subpoena or Norwich Pharmacal order.",
        "Victims are at ongoing risk: report to law enforcement.",
        "A cloned entity or impersonation is suspected: counsel and the platform's abuse channel.",
    ],
    pitfalls=[
        "Consumer complaint narratives are unverified claims, not findings.",
        "Stale marketing data and consumer-site hits mislead.",
        "Registered-agent addresses and shared hosts are not links.",
        "A common name or company name matches innocent entities.",
    ],
    typical_hypotheses=[
        "A fraudulent operation (complaint pattern plus shell indicators).",
        "A poorly run but legitimate business.",
        "A cloned or impersonated entity (lookalike domain, borrowed identity).",
    ],
)

_MISSING_PERSON = Playbook(
    case_type=CaseType.MISSING_PERSON,
    objective="Compile public-source leads about a missing person and route them to the right authority, never "
              "to the client.",
    done_when="The identifier set is compiled, public missing and unidentified-persons databases are searched "
              "with negatives logged, and any match is packaged for law enforcement.",
    steps=_steps([
        ("Compile the identifier set: name variants, birth year, distinguishing features, last known place and "
         "date.", [], "high", "free",
         "Written purpose; walk away if the request looks like an evasion or a locate of a person who left on "
         "purpose.", "No full name plus a second anchor: ask for one."),
        ("Search public missing and unidentified-persons databases.", ["NamUs", "Charley Project", "Doe Network"],
         "high", "free", "Public databases only; do not post or publish.",
         "A plausible match: stop and route it to law enforcement."),
        ("Check obituaries, burial and civil records for a death or an unidentified burial.",
         ["Find a Grave", "FamilySearch", "Chronicling America"], "medium", "free",
         "Check each site's terms before scraping.", "A death record appears: route to law enforcement."),
        ("Map the passive public-source footprint for recent activity.", ["Sherlock", "Google News",
                                                                         "Wayback Machine"],
         "medium", "free", _PASSIVE_GATE, "Footprint rests on a common name: label as a lead."),
        ("Route every lead to law enforcement or the investigating agency, never to the client.",
         ["law enforcement"], "high", "handoff",
         "Do not contact the subject or family; leads go to the authority.",
         "Any sign of danger: contact law enforcement immediately."),
    ]),
    escalate_when=[
        "Any database match or possible match: route to law enforcement.",
        "Signs the person is at risk of harm.",
        "Remains or an unidentified burial may match: law enforcement and the medical examiner.",
    ],
    pitfalls=[
        "Stale or volunteer-run databases (the Doe Network) can be wrong: treat hits as leads.",
        "A common name matches many people.",
        "A consumer-site hit is an unverified lead; marketing data about a missing person is often stale.",
        "A missing-person framing can hide an evasion or an abusive ex-partner locate: apply the motive screen.",
        "Never publish findings or contact the person; matches go to law enforcement, never the client.",
    ],
    typical_hypotheses=[
        "A voluntarily absent adult who chose to leave.",
        "Missing involuntarily or at risk of harm.",
        "Deceased and unidentified: a match to unidentified remains.",
    ],
)

#: Machine keys for playbook escalation items. pi_runtime.ESCALATION_EVALUATORS must define exactly this set.
ESCALATION_KEYS: frozenset = frozenset({
    "contradiction",            # the timeline has any contradiction
    "custodian_finding",        # a finding kind that only a custodian can resolve was inferred
    "identity_unresolved",      # a person subject is not anchored, or same-name records are not established as one
    "no_corroborated_finding",  # a deep run produced no confirmed or probable finding
    "sanctions_or_50_rule",     # a sanctions/PEP listing node or an OFAC 50% rule block
    "unresolved_ownership",     # the ownership walk ended before reaching a natural person
})


def _key_escalations(playbook: Playbook, keys_by_index: Dict[int, str]) -> None:
    """Attach machine keys to escalate_when items by position (an IndexError at import means a stale index)."""
    playbook.escalate_keys = {playbook.escalate_when[i]: key for i, key in keys_by_index.items()}


_key_escalations(_LOCATE, {0: "contradiction", 2: "no_corroborated_finding"})
_key_escalations(_BACKGROUND, {1: "identity_unresolved", 3: "sanctions_or_50_rule"})
_key_escalations(_ASSET_SEARCH, {0: "custodian_finding", 1: "unresolved_ownership", 3: "sanctions_or_50_rule"})
_key_escalations(_DUE_DILIGENCE, {0: "sanctions_or_50_rule", 1: "unresolved_ownership", 2: "custodian_finding"})
_key_escalations(_FRAUD_SCREEN, {0: "custodian_finding"})
# _MISSING_PERSON stays unkeyed on purpose: no missing-persons source is automated, so no item can be evaluated.

PLAYBOOKS: Dict[CaseType, Playbook] = {
    CaseType.LOCATE: _LOCATE,
    CaseType.BACKGROUND: _BACKGROUND,
    CaseType.ASSET_SEARCH: _ASSET_SEARCH,
    CaseType.DUE_DILIGENCE: _DUE_DILIGENCE,
    CaseType.FRAUD_SCREEN: _FRAUD_SCREEN,
    CaseType.MISSING_PERSON: _MISSING_PERSON,
}


# ----------------------------------------------------------------------------------------------------------
# Lookups
# ----------------------------------------------------------------------------------------------------------


def _coerce_case_type(case_type: Union[CaseType, str]) -> CaseType:
    if isinstance(case_type, CaseType):
        return case_type
    key = str(case_type).strip().casefold()
    try:
        return CaseType(key)
    except ValueError:
        valid = ", ".join(c.value for c in CaseType)
        raise ValueError(f"unknown case type {case_type!r}; expected one of: {valid}") from None


def _jurisdiction_scope(jurisdiction: str) -> set[str]:
    key = jurisdiction.strip().casefold()
    if key.startswith("us-"):
        key = "us"
    elif key in {"gb"} or key.startswith(("uk-", "gb-")):
        key = "uk"
    scope = {key, "intl"}
    if key.startswith("ca-"):
        scope.add("ca")
    return scope


def sources_for(
    case_type: Optional[Union[CaseType, str]] = None,
    jurisdiction: Optional[str] = None,
    implemented_only: bool = False,
) -> List[SourceEntry]:
    """Return catalog sources, optionally filtered by case type, jurisdiction and implementation state.

    A jurisdiction filter keeps that jurisdiction's sources plus the global (``intl``) ones; a provincial code
    such as ``ca-on`` also keeps the federal (``ca``) sources. The returned list is a copy.
    """
    wanted_categories = _CASE_CATEGORIES[_coerce_case_type(case_type)] if case_type is not None else None
    scope = _jurisdiction_scope(jurisdiction) if jurisdiction and jurisdiction.strip() else None
    out: List[SourceEntry] = []
    for source in SOURCES:
        if implemented_only and not source.implemented:
            continue
        if scope is not None and source.jurisdiction not in scope:
            continue
        if wanted_categories is not None and not wanted_categories.intersection(source.categories):
            continue
        out.append(source.model_copy(deep=True))
    return out


def legal_for(jurisdiction: str) -> List[dict]:
    """General rules plus the jurisdiction's own (``us`` and ``ca-on``); unknown jurisdictions get general only."""
    key = (jurisdiction or "").strip().casefold()
    if key.startswith("us-"):
        key = "us"
    rules = copy.deepcopy(LEGAL_RULES["general"])
    if key in LEGAL_RULES and key != "general":
        rules += copy.deepcopy(LEGAL_RULES[key])
    return rules


def playbook_for(case_type: Union[CaseType, str]) -> Playbook:
    """The playbook for a case type given as an enum or its string value."""
    return PLAYBOOKS[_coerce_case_type(case_type)]


def render_guide() -> str:
    """Markdown guide: the investigation cycle, the thirteen behaviours and the case types."""
    lines: List[str] = [
        "# Private-investigator method (Bunnyhole PI stream)",
        "",
        "Bunnyhole runs the free, lawful, passive layer of an investigation the way an elite private "
        "investigator would. It produces leads, not verdicts. It is information, not legal advice, and it is a "
        "research tool, not a licence.",
        "",
        "## The investigation cycle",
        "",
    ]
    for stage in CYCLE_STAGES:
        lines.append(f"{stage['order']}. **{stage['name']}**: {stage['summary']} _In Bunnyhole:_ "
                     f"{stage['bunnyhole']}")
    lines += ["", "## The thirteen behaviours", ""]
    for item in DOCTRINE:
        lines.append(f"{item['order']}. **{item['title']}**: {item['summary']}")
    lines += ["", "## Case types", ""]
    for case_type, playbook in PLAYBOOKS.items():
        lines.append(f"- `{case_type.value}`: {playbook.objective}")
    lines += [
        "",
        "## Limits",
        "",
        "Nothing here is a consumer report or may drive an eligibility decision. Where public data ends, the "
        "report names the custodian and the lawful instrument; a licensed investigator or counsel takes it from "
        "there. This is not legal advice: verify current law with counsel.",
    ]
    return "\n".join(lines) + "\n"
