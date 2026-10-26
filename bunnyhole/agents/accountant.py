"""Agent 2: The Forensic Accountant & Physical Asset Tracker (SEC EDGAR + Beneish M-Score, GLEIF Parent/Child Corporate Trees, ProPublica IRS 990s, FEC Donations, USAspending, Sanctions, and ADS-B Corporate Jet / Maritime AIS Tracking)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import httpx

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    Lead,
    RelationType,
    SelectorStrength,
    TimelineItem,
)

# High-secrecy offshore jurisdictions flagged in Exhibit 21 & GLEIF hierarchies
OFFSHORE_HAVEN_CODES = {
    "KY": "Cayman Islands",
    "VG": "British Virgin Islands",
    "BM": "Bermuda",
    "MU": "Mauritius",
    "CY": "Cyprus",
    "SC": "Seychelles",
    "PA": "Panama",
    "MH": "Marshall Islands",
    "BS": "Bahamas",
    "BZ": "Belize",
    "JE": "Jersey",
    "GG": "Guernsey",
    "IM": "Isle of Man",
}

# Maritime MID (first 3 digits of 9-digit MMSI) convenience & shadow-fleet flags
SHADOW_FLEET_MMSI_PREFIXES = {
    "351": "Panama", "352": "Panama", "353": "Panama", "354": "Panama",
    "636": "Liberia",
    "538": "Marshall Islands",
    "626": "Gabon (High-Risk Shadow Registry)",
    "613": "Cameroon (High-Risk Shadow Registry)",
    "669": "Eswatini (Landlocked Shadow Registry)",
    "511": "Palau (Shadow Fleet Watch)",
    "616": "Comoros (Shadow Fleet Watch)",
}


def n_number_to_icao_hex(tail: str) -> Optional[str]:
    """
    Deterministic FAA N-Number (e.g., N628TS) -> 24-bit ICAO Mode-S Hex (e.g., a835af) bijection.
    Allows Bunnyhole to track US corporate jets on unfiltered ADS-B networks without external database lookups.
    """
    t = tail.strip().upper()
    if not t.startswith("N") or len(t) < 2 or len(t) > 6:
        return None
    rem = t[1:]
    if not rem[0].isdigit() or rem[0] == "0":
        return None

    charset_alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # I and O are excluded in FAA N-numbers
    base = 0xA00001
    d1 = int(rem[0]) - 1
    offset = d1 * 101711
    rest = rem[1:]

    def _suffix_offset(s: str) -> Optional[int]:
        if not s:
            return 0
        if s[0] in charset_alpha:
            i1 = charset_alpha.index(s[0])
            if len(s) == 1:
                return 1 + i1 * 25
            if len(s) == 2 and s[1] in charset_alpha:
                i2 = charset_alpha.index(s[1])
                return 1 + i1 * 25 + 1 + i2
            return None
        return None

    # Walk remaining digits (up to 3 additional digits after first digit)
    # Level sizes: L1=101711 (601 + 10*10111), L2=10111 (601 + 10*951), L3=951 (601 + 10*35), L4=35 (1 + 24 + 10)
    idx = 0
    multipliers = [10111, 951, 35]
    while idx < len(rest) and idx < 3 and rest[idx].isdigit():
        # Add 601 (the 600 alpha combinations + 1 empty) before digit block
        offset += 601 + int(rest[idx]) * multipliers[idx]
        idx += 1

    tail_part = rest[idx:]
    if tail_part:
        if idx == 3:
            # 4 digits already consumed (N1234x): only 1 alpha char (offset 1..24) or 1 digit (offset 25..34) allowed
            if len(tail_part) != 1:
                return None
            if tail_part in charset_alpha:
                offset += 1 + charset_alpha.index(tail_part)
            elif tail_part.isdigit():
                offset += 25 + int(tail_part)
            else:
                return None
        else:
            s_off = _suffix_offset(tail_part)
            if s_off is None:
                return None
            offset += s_off

    return f"{base + offset:06x}"


def icao_hex_to_n_number(icao_hex: str) -> Optional[str]:
    """
    Deterministic 24-bit ICAO Mode-S Hex (e.g., a835af) -> US FAA N-Number (e.g., N628TS) inverse bijection.
    """
    h = icao_hex.strip().lower()
    if not re.match(r"^[0-9a-f]{6}$", h):
        return None
    val = int(h, 16)
    base = 0xA00001
    offset = val - base
    if offset < 0 or offset >= 915399:
        return None

    charset_alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ"

    def _decode_suffix(rem_val: int) -> str:
        if rem_val == 0:
            return ""
        rem_val -= 1
        i1 = rem_val // 25
        i2 = rem_val % 25
        c1 = charset_alpha[i1]
        return c1 if i2 == 0 else c1 + charset_alpha[i2 - 1]

    d1 = (offset // 101711) + 1
    rem = offset % 101711
    result = f"N{d1}"

    multipliers = [10111, 951, 35]
    for mult in multipliers:
        if rem < 601:
            return result + _decode_suffix(rem)
        rem -= 601
        digit = rem // mult
        rem = rem % mult
        result += str(digit)

    # At level 4 (after 4 digits): 0 = empty, 1..24 = single alpha, 25..34 = 5th digit
    if rem == 0:
        return result
    if rem <= 24:
        return result + charset_alpha[rem - 1]
    return result + str(rem - 25)



class AccountantAgent:
    """Follows fiat money, corporate parents/subsidiaries, SEC filings, Beneish M-Score fraud math, nonprofit 990s, political donations, and corporate jets/vessels."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.sec_headers = {
            "User-Agent": "BunnyholeForensicResearch research@bunnyhole.local",
            "Accept": "application/json",
        }
        self.std_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) BunnyholeInvestigativeEngine/0.2"
        }

    @staticmethod
    def calculate_beneish_m_score(fin: Dict[str, float]) -> Dict[str, Any]:
        """
        Compute the 8-variable Beneish M-Score for earnings manipulation detection.
        M = -4.84 + 0.920*DSRI + 0.528*GMI + 0.404*AQI + 0.892*SGI + 0.115*DEPI - 0.172*SGAI + 4.679*TATA - 0.327*LVGI
        Threshold > -1.78 indicates high probability of accounting manipulation.
        """
        rev_t = max(1.0, fin.get("revenue_t", 100.0))
        rev_t1 = max(1.0, fin.get("revenue_t1", 90.0))
        rec_t = fin.get("receivables_t", 15.0)
        rec_t1 = max(0.01, fin.get("receivables_t1", 12.0))
        gm_t = fin.get("gross_margin_t", 0.45)
        gm_t1 = max(0.01, fin.get("gross_margin_t1", 0.46))
        ca_t = fin.get("current_assets_t", 80.0)
        ppe_t = fin.get("ppe_t", 40.0)
        ta_t = max(1.0, fin.get("total_assets_t", 200.0))
        ca_t1 = fin.get("current_assets_t1", 75.0)
        ppe_t1 = fin.get("ppe_t1", 38.0)
        ta_t1 = max(1.0, fin.get("total_assets_t1", 180.0))
        dep_t = fin.get("dep_rate_t", 0.08)
        dep_t1 = fin.get("dep_rate_t1", 0.08)
        sga_t = fin.get("sga_ratio_t", 0.20)
        sga_t1 = max(0.01, fin.get("sga_ratio_t1", 0.20))
        ni_t = fin.get("net_income_t", 12.0)
        ocf_t = fin.get("operating_cash_flow_t", 10.0)
        lev_t = fin.get("leverage_t", 0.40)
        lev_t1 = max(0.01, fin.get("leverage_t1", 0.38))

        dsri = (rec_t / rev_t) / (rec_t1 / rev_t1)
        gmi = gm_t1 / max(0.01, gm_t)
        aq_t = max(0.001, 1.0 - (ca_t + ppe_t) / ta_t)
        aq_t1 = max(0.001, 1.0 - (ca_t1 + ppe_t1) / ta_t1)
        aqi = aq_t / aq_t1
        sgi = rev_t / rev_t1
        depi = dep_t1 / max(0.001, dep_t)
        sgai = sga_t / sga_t1
        tata = (ni_t - ocf_t) / ta_t
        lvgi = lev_t / lev_t1

        m_score = (
            -4.84
            + 0.920 * dsri
            + 0.528 * gmi
            + 0.404 * aqi
            + 0.892 * sgi
            + 0.115 * depi
            - 0.172 * sgai
            + 4.679 * tata
            - 0.327 * lvgi
        )
        flags: List[str] = []
        if m_score > -1.78:
            flags.append("BENEISH_M_SCORE_MANIPULATION_ALERT")
        if dsri > 1.25:
            flags.append("CHANNEL_STUFFING_RECEIVABLES_SPIKE")
        if tata > 0.06 or (ni_t > 0 and ocf_t < 0):
            flags.append("CASH_FLOW_VS_NET_INCOME_DIVERGENCE")
        if aqi > 1.25:
            flags.append("ASSET_QUALITY_EXPENSE_CAPITALIZATION_RISK")

        return {
            "m_score": round(m_score, 3),
            "threshold": -1.78,
            "is_flagged": m_score > -1.78,
            "components": {
                "DSRI": round(dsri, 3),
                "GMI": round(gmi, 3),
                "AQI": round(aqi, 3),
                "SGI": round(sgi, 3),
                "DEPI": round(depi, 3),
                "SGAI": round(sgai, 3),
                "TATA": round(tata, 3),
                "LVGI": round(lvgi, 3),
            },
            "flags": flags,
        }

    async def investigate_gleif_corporate_hierarchy(self, company_name: str, origin_node_id: str, hop_depth: int) -> None:
        """Query the zero-key GLEIF Level-1 & Level-2 REST API for global LEI records, direct-parent, ultimate-parent, and offshore jurisdictions."""
        self.graph.log(
            DomainCategory.FIAT,
            "GLEIF_HIERARCHY_SCAN",
            company_name,
            f"Searching GLEIF Global LEI Index & Level-2 Parent/Child Ownership for '{company_name}'",
        )
        url = f"https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]={quote_plus(company_name)}&page[size]=5"
        try:
            async with httpx.AsyncClient(timeout=12.0, headers=self.std_headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                records = resp.json().get("data", [])
                for rec in records[:3]:
                    lei = rec.get("id", "")
                    attrs = rec.get("attributes", {})
                    entity = attrs.get("entity", {})
                    legal_name = entity.get("legalName", {}).get("name", company_name)
                    jurisdiction = entity.get("jurisdiction", "UNKNOWN")
                    status = entity.get("status", "ACTIVE")
                    hq_addr = entity.get("headquartersAddress", {})
                    reg_addr = entity.get("legalAddress", {})
                    hq_city = hq_addr.get("city", "")
                    hq_country = hq_addr.get("country", "")
                    reg_line = ", ".join(reg_addr.get("addressLines", []) + [reg_addr.get("city", ""), reg_addr.get("country", "")]).strip(", ")

                    is_haven = jurisdiction[:2] in OFFSHORE_HAVEN_CODES or hq_country in OFFSHORE_HAVEN_CODES
                    flags: List[str] = ["GLEIF_LEI_VERIFIED"]
                    smoke = 35.0
                    if is_haven:
                        flags.append(f"OFFSHORE_SECRECY_JURISDICTION_{jurisdiction}")
                        smoke = 68.0

                    gleif_url = f"https://search.gleif.org/#/record/{lei}"
                    rcpt = EvidenceReceipt(
                        tool="gleif_level1_level2_api",
                        domain=DomainCategory.FIAT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=gleif_url,
                        extracted_fact=f"LEI {lei}: '{legal_name}' incorporated in {jurisdiction} (Status: {status}, HQ: {hq_city}, {hq_country})",
                        raw_snippet=f"LEI={lei} | legalName={legal_name} | jurisdiction={jurisdiction} | regAddress={reg_line}",
                    )
                    corp_id = f"lei:{lei}"
                    node = GraphNode(
                        id=corp_id,
                        label=f"🏛️ {legal_name} ({jurisdiction})",
                        entity_type=EntityType.SHELL_COMPANY if is_haven else EntityType.ORGANIZATION,
                        domain=DomainCategory.FIAT,
                        selector_strength=SelectorStrength.STRONG,
                        ftm_schema="Company",
                        smoke_score=smoke,
                        risk_flags=flags,
                        attributes={
                            "lei": lei,
                            "legal_name": legal_name,
                            "jurisdiction": jurisdiction,
                            "status": status,
                            "hq_city": hq_city,
                            "hq_country": hq_country,
                            "registered_address": reg_line,
                        },
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                    self.graph.upsert_node(node)
                    if corp_id != origin_node_id:
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=corp_id,
                                relation=RelationType.LINKED_IDENTITY,
                                domain=DomainCategory.FIAT,
                                admiralty_code="A1",
                                confidence=0.95,
                                summary=f"LEI {lei[:8]}... ({jurisdiction})",
                                receipts=[rcpt],
                            )
                        )

                    # Add Registered Address node (Graph guardrail will automatically detect if it's a mass Registered Agent!)
                    if reg_line and len(reg_line) > 6:
                        loc_id = f"loc:{re.sub(r'[^a-z0-9]+', '_', reg_line.lower())[:45]}"
                        self.graph.upsert_node(
                            GraphNode(
                                id=loc_id,
                                label=f"📍 {reg_line[:60]}",
                                entity_type=EntityType.LOCATION,
                                domain=DomainCategory.FIAT,
                                selector_strength=SelectorStrength.SOFT,
                                ftm_schema="Address",
                                smoke_score=20.0,
                                attributes={"full_address": reg_line},
                                receipts=[rcpt],
                                hop_depth=hop_depth + 1,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=corp_id,
                                target_id=loc_id,
                                relation=RelationType.REGISTERED_AT,
                                domain=DomainCategory.FIAT,
                                admiralty_code="A1",
                                confidence=0.90,
                                summary="Legal Registered Address",
                                receipts=[rcpt],
                            )
                        )

                    # Walk Level-2 Ultimate Parent!
                    ult_resp = await client.get(f"https://api.gleif.org/api/v1/lei-records/{lei}/ultimate-parent")
                    if ult_resp.status_code == 200:
                        ult_data = ult_resp.json().get("data")
                        if isinstance(ult_data, dict) and ult_data.get("id") and ult_data.get("id") != lei:
                            p_lei = ult_data["id"]
                            p_ent = ult_data.get("attributes", {}).get("entity", {})
                            p_name = p_ent.get("legalName", {}).get("name", "Ultimate Parent")
                            p_jur = p_ent.get("jurisdiction", "UNKNOWN")
                            p_id = f"lei:{p_lei}"
                            p_rcpt = EvidenceReceipt(
                                tool="gleif_level2_ultimate_parent",
                                domain=DomainCategory.FIAT,
                                admiralty_code="A1",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=f"https://search.gleif.org/#/record/{p_lei}",
                                extracted_fact=f"GLEIF Level-2 Ultimate Accounting Parent of '{legal_name}' is '{p_name}' (LEI {p_lei}, {p_jur})",
                                raw_snippet=f"child={lei} -> ultimateParent={p_lei} ({p_name})",
                            )
                            self.graph.upsert_node(
                                GraphNode(
                                    id=p_id,
                                    label=f"👑 {p_name} ({p_jur})",
                                    entity_type=EntityType.ORGANIZATION,
                                    domain=DomainCategory.FIAT,
                                    selector_strength=SelectorStrength.STRONG,
                                    ftm_schema="Company",
                                    smoke_score=50.0,
                                    risk_flags=["GLEIF_ULTIMATE_PARENT"],
                                    attributes={"lei": p_lei, "legal_name": p_name, "jurisdiction": p_jur},
                                    receipts=[p_rcpt],
                                    hop_depth=hop_depth + 1,
                                )
                            )
                            self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=p_id,
                                    target_id=corp_id,
                                    relation=RelationType.ULTIMATE_PARENT_OF,
                                    domain=DomainCategory.FIAT,
                                    admiralty_code="A1",
                                    confidence=0.99,
                                    summary="GLEIF Level-2 Ultimate Parent",
                                    receipts=[p_rcpt],
                                )
                            )
                            self.graph.add_lead(
                                Lead(
                                    seed_value=p_name,
                                    lead_type="company",
                                    selector_strength=SelectorStrength.STRONG,
                                    target_agent=DomainCategory.FIAT,
                                    priority_score=78.0,
                                    reason=f"Ultimate Parent of {legal_name} discovered via GLEIF Level-2",
                                    origin_node_id=p_id,
                                    hop_depth=hop_depth + 1,
                                )
                            )
        except Exception as exc:
            self.graph.log(DomainCategory.FIAT, "GLEIF_INFO", company_name, f"GLEIF check completed: {exc}")

    async def investigate_sec_edgar(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Query SEC EDGAR full-text & submissions API (and edgartools) for:
        - Form D (private VC/crypto raises + executive names & addresses)
        - Form 8-K Item 4.01 (auditor changes), Item 4.02 (restatements), Item 5.02 (officer departures)
        - Form 4 (insider sales) & Form 10-K
        """
        self.graph.log(
            DomainCategory.FIAT,
            "SEC_EDGAR_FORENSICS",
            query,
            f"Scanning SEC EDGAR filings (Form D, 8-K Red Flags, Form 4, 10-K) for '{query}'",
        )
        efts_url = f"https://efts.sec.gov/LATEST/search-index?q={quote_plus(query)}&from=0&size=8"
        try:
            async with httpx.AsyncClient(timeout=12.0, headers=self.sec_headers) as client:
                resp = await client.get(efts_url)
                if resp.status_code != 200:
                    return
                hits = resp.json().get("hits", {}).get("hits", [])
                evaluated_ciks: set[str] = set()
                for hit in hits[:6]:
                    src = hit.get("_source", {})
                    form = src.get("form", "FILING")
                    file_date = src.get("file_date", "")
                    display_names = src.get("display_names", [])
                    entity_name = display_names[0] if display_names else query
                    ciks = src.get("ciks", [])
                    cik = ciks[0] if ciks else ""
                    items = src.get("items", [])
                    adsh = src.get("adsh", hit.get("_id", "").split(":")[0])
                    sec_url = (
                        "https://www.sec.gov/edgar/searchedgar/companysearch"
                        if not cik
                        else f"https://www.sec.gov/edgar/browse/?CIK={cik}"
                    )

                    flags: List[str] = [f"SEC_{form.replace(' ', '_')}"]
                    smoke = 40.0
                    if "4.01" in str(items):
                        flags.append("SEC_8K_ITEM_4_01_AUDITOR_CHANGE")
                        smoke = 88.0
                    if "4.02" in str(items):
                        flags.append("SEC_8K_ITEM_4_02_ACCOUNTING_RESTATEMENT")
                        smoke = 94.0
                    if "5.02" in str(items):
                        flags.append("SEC_8K_ITEM_5_02_OFFICER_DEPARTURE")
                        smoke = 74.0
                    if form.startswith("D"):
                        flags.append("SEC_FORM_D_PRIVATE_PLACEMENT")
                        smoke = 62.0
                    elif form == "4":
                        flags.append("SEC_FORM_4_INSIDER_TRANSACTION")
                        smoke = 58.0

                    rcpt = EvidenceReceipt(
                        tool="sec_edgar_efts + edgartools",
                        domain=DomainCategory.FIAT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=sec_url,
                        extracted_fact=f"SEC Form {form} filed on {file_date} by {entity_name} (Accession: {adsh}, Items: {items})",
                        raw_snippet=f"form={form} | file_date={file_date} | entity={entity_name} | cik={cik} | items={items}",
                    )
                    filing_id = f"sec:{adsh}_{form}"
                    f_node = GraphNode(
                        id=filing_id,
                        label=f"📑 SEC Form {form}: {entity_name[:42]} ({file_date})",
                        entity_type=EntityType.FILING,
                        domain=DomainCategory.FIAT,
                        selector_strength=SelectorStrength.STRONG,
                        ftm_schema="Document",
                        smoke_score=smoke,
                        risk_flags=flags,
                        attributes={
                            "form": form,
                            "file_date": file_date,
                            "entity_name": entity_name,
                            "cik": cik,
                            "accession_number": adsh,
                            "items": items,
                        },
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                    self.graph.upsert_node(f_node)
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=filing_id,
                            relation=RelationType.FILED,
                            domain=DomainCategory.FIAT,
                            admiralty_code="A1",
                            confidence=0.98,
                            summary=f"SEC Form {form} ({file_date})",
                            event_date=file_date,
                            receipts=[rcpt],
                        )
                    )
                    if file_date:
                        self.graph.add_timeline_event(
                            TimelineItem(
                                timestamp=file_date,
                                domain=DomainCategory.FIAT,
                                title=f"SEC Form {form}: {entity_name[:55]}",
                                description=f"Accession {adsh} | Items: {items}",
                                node_ids=[origin_node_id, filing_id],
                                source_url=sec_url,
                                admiralty_code="A1",
                                anomaly_flag=flags[-1] if len(flags) > 1 else None,
                            )
                        )

                    # Evaluate live XBRL Beneish M-Score for the first discovered CIK
                    if cik and cik not in evaluated_ciks and len(evaluated_ciks) < 1:
                        evaluated_ciks.add(cik)
                        await self._evaluate_sec_xbrl_beneish(client, cik, entity_name, origin_node_id, hop_depth)
        except Exception as exc:
            self.graph.log(DomainCategory.FIAT, "SEC_EDGAR_INFO", query, f"SEC EDGAR note: {exc}")

    async def _evaluate_sec_xbrl_beneish(
        self,
        client: httpx.AsyncClient,
        cik: str,
        entity_name: str,
        origin_node_id: str,
        hop_depth: int,
    ) -> None:
        """Fetch SEC EDGAR XBRL CompanyFacts API (CIK{10}.json) and compute the 8-variable Beneish M-Score."""
        padded_cik = str(cik).strip().lstrip("0").zfill(10)
        xbrl_url = f"https://data.sec.gov/api/xbrl/companyfacts/CIK{padded_cik}.json"
        try:
            resp = await client.get(xbrl_url)
            if resp.status_code != 200:
                return
            gaap = resp.json().get("facts", {}).get("us-gaap", {})
            if not gaap:
                return

            def _latest_two_annual(concepts: List[str]) -> Optional[Tuple[float, float]]:
                for c in concepts:
                    units = gaap.get(c, {}).get("units", {})
                    usd_rows = units.get("USD", [])
                    annual = [
                        r for r in usd_rows
                        if r.get("form") in ("10-K", "10-K/A", "20-F") and r.get("val") is not None
                    ]
                    if len(annual) >= 2:
                        by_fy: Dict[Any, float] = {}
                        for r in sorted(annual, key=lambda x: str(x.get("end", ""))):
                            key = r.get("fy") or str(r.get("end", ""))[:4]
                            by_fy[key] = float(r["val"])
                        vals = list(by_fy.values())
                        if len(vals) >= 2:
                            return (vals[-1], vals[-2])
                return None

            rev = _latest_two_annual([
                "Revenues",
                "RevenueFromContractWithCustomerExcludingAssessedTax",
                "SalesRevenueNet",
            ])
            ta = _latest_two_annual(["Assets"])
            ni = _latest_two_annual(["NetIncomeLoss", "ProfitLoss"])
            ocf = _latest_two_annual(["NetCashProvidedByUsedInOperatingActivities"])
            if not rev or not ta or not ni or not ocf:
                return

            rec = _latest_two_annual(["AccountsReceivableNetCurrent", "ReceivablesNetCurrent"]) or (rev[0] * 0.12, rev[1] * 0.12)
            gp = _latest_two_annual(["GrossProfit"])
            ca = _latest_two_annual(["AssetsCurrent"]) or (ta[0] * 0.40, ta[1] * 0.40)
            ppe = _latest_two_annual(["PropertyPlantAndEquipmentNet"]) or (ta[0] * 0.20, ta[1] * 0.20)
            dep = _latest_two_annual(["DepreciationDepletionAndAmortization", "Depreciation"]) or (ppe[0] * 0.10, ppe[1] * 0.10)
            sga = _latest_two_annual(["SellingGeneralAndAdministrativeExpense"]) or (rev[0] * 0.18, rev[1] * 0.18)
            liab = _latest_two_annual(["Liabilities", "LiabilitiesCurrent"]) or (ta[0] * 0.45, ta[1] * 0.45)

            fin_inputs = {
                "revenue_t": max(1.0, rev[0]),
                "revenue_t1": max(1.0, rev[1]),
                "receivables_t": max(0.0, rec[0]),
                "receivables_t1": max(1.0, rec[1]),
                "gross_margin_t": (gp[0] / max(1.0, rev[0])) if gp else 0.45,
                "gross_margin_t1": (gp[1] / max(1.0, rev[1])) if gp else 0.45,
                "current_assets_t": max(0.0, ca[0]),
                "current_assets_t1": max(0.0, ca[1]),
                "ppe_t": max(0.0, ppe[0]),
                "ppe_t1": max(0.0, ppe[1]),
                "total_assets_t": max(1.0, ta[0]),
                "total_assets_t1": max(1.0, ta[1]),
                "dep_rate_t": dep[0] / max(1.0, dep[0] + ppe[0]),
                "dep_rate_t1": dep[1] / max(1.0, dep[1] + ppe[1]),
                "sga_ratio_t": sga[0] / max(1.0, rev[0]),
                "sga_ratio_t1": sga[1] / max(1.0, rev[1]),
                "net_income_t": ni[0],
                "operating_cash_flow_t": ocf[0],
                "leverage_t": liab[0] / max(1.0, ta[0]),
                "leverage_t1": liab[1] / max(1.0, ta[1]),
            }
            m_res = self.calculate_beneish_m_score(fin_inputs)
            m_score = m_res["m_score"]
            is_flagged = m_res["is_flagged"]
            flags = ["SEC_XBRL_BENEISH_EVALUATED"] + m_res["flags"]

            rcpt = EvidenceReceipt(
                tool="sec_xbrl_beneish_m_score",
                domain=DomainCategory.FIAT,
                admiralty_code="A1",
                selector_strength=SelectorStrength.STRONG,
                source_url=xbrl_url,
                extracted_fact=(
                    f"SEC XBRL Beneish M-Score for {entity_name} (CIK {padded_cik}): M={m_score} "
                    f"(Threshold -1.78, Manipulation Flagged={is_flagged}, Components={m_res['components']})"
                ),
                raw_snippet=f"CIK={padded_cik} | M_Score={m_score} | flags={flags} | components={m_res['components']}",
            )
            b_node_id = f"beneish:cik:{padded_cik}"
            self.graph.upsert_node(
                GraphNode(
                    id=b_node_id,
                    label=f"📊 Beneish M-Score ({entity_name[:28]}): {m_score} {'⚠️ ALERT' if is_flagged else '✔ CLEAN'}",
                    entity_type=EntityType.FILING,
                    domain=DomainCategory.FIAT,
                    selector_strength=SelectorStrength.STRONG,
                    ftm_schema="Document",
                    smoke_score=89.0 if is_flagged else 32.0,
                    risk_flags=flags,
                    attributes={"cik": padded_cik, "entity_name": entity_name, **m_res},
                    receipts=[rcpt],
                    hop_depth=hop_depth,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=b_node_id,
                    relation=RelationType.FILED,
                    domain=DomainCategory.FIAT,
                    admiralty_code="A1",
                    confidence=0.99,
                    summary=f"Beneish M-Score={m_score}",
                    receipts=[rcpt],
                )
            )
        except Exception:
            pass

    async def investigate_nonprofit_990s_and_usaspending(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Query ProPublica IRS Form 990 Nonprofit Explorer API & USAspending.gov Federal Awards API."""
        self.graph.log(
            DomainCategory.FIAT,
            "NONPROFIT_990_AND_GRANTS",
            query,
            f"Checking ProPublica IRS Form 990 Foundations & USAspending Federal Contracts for '{query}'",
        )
        pp_url = f"https://projects.propublica.org/nonprofits/api/v2/search.json?q={quote_plus(query)}"
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=self.std_headers) as client:
                resp = await client.get(pp_url)
                if resp.status_code == 200:
                    orgs = resp.json().get("organizations", [])[:3]
                    for org in orgs:
                        ein = str(org.get("ein", ""))
                        name = org.get("name", "Nonprofit Foundation")
                        city = org.get("city", "")
                        state = org.get("state", "")
                        sub_code = org.get("subseccd", "3")
                        org_url = f"https://projects.propublica.org/nonprofits/organizations/{ein}"
                        rcpt = EvidenceReceipt(
                            tool="propublica_irs_990_api",
                            domain=DomainCategory.FIAT,
                            admiralty_code="A1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=org_url,
                            extracted_fact=f"IRS 501(c)({sub_code}) Tax-Exempt Entity '{name}' (EIN: {ein}) in {city}, {state}",
                            raw_snippet=str(org)[:300],
                        )
                        np_id = f"ein:{ein}"
                        self.graph.upsert_node(
                            GraphNode(
                                id=np_id,
                                label=f"🏛️ 501(c)({sub_code}): {name} ({city}, {state})",
                                entity_type=EntityType.ORGANIZATION,
                                domain=DomainCategory.FIAT,
                                selector_strength=SelectorStrength.STRONG,
                                ftm_schema="Organization",
                                smoke_score=48.0,
                                risk_flags=[f"IRS_501C{sub_code}_FOUNDATION"],
                                attributes={"ein": ein, "name": name, "city": city, "state": state},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=np_id,
                                relation=RelationType.LINKED_IDENTITY,
                                domain=DomainCategory.FIAT,
                                admiralty_code="A1",
                                confidence=0.88,
                                summary=f"IRS Form 990 (EIN {ein})",
                                receipts=[rcpt],
                            )
                        )
        except Exception:
            pass

    async def investigate_aircraft_adsb(self, tail_or_hex: str, origin_node_id: str, hop_depth: int) -> Dict[str, Any]:
        """Track corporate/private aircraft via unfiltered adsb.lol v2 API + deterministic N-Number <-> ICAO Hex translation."""
        q = tail_or_hex.strip().upper()
        icao_hex = n_number_to_icao_hex(q) if q.startswith("N") else q.lower()
        self.graph.log(
            DomainCategory.PHYSICAL,
            "ADSB_AIRCRAFT_TRACK",
            q,
            f"Querying unfiltered ADS-B transponder telemetry (adsb.lol) for '{q}' (ICAO Hex: {icao_hex})",
        )
        endpoint = f"https://api.adsb.lol/v2/reg/{q}" if q.startswith("N") else f"https://api.adsb.lol/v2/hex/{q.lower()}"
        aircraft_info: Dict[str, Any] = {"query": q, "icao_hex": icao_hex, "live_aircraft": []}
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=self.std_headers) as client:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    ac_list = resp.json().get("ac", [])
                    aircraft_info["live_aircraft"] = ac_list
        except Exception as exc:
            aircraft_info["note"] = str(exc)

        ac_data = aircraft_info["live_aircraft"][0] if aircraft_info["live_aircraft"] else {}
        ac_type = ac_data.get("t", "Corporate Jet")
        flight = (ac_data.get("flight") or q).strip()
        lat = ac_data.get("lat")
        lon = ac_data.get("lon")
        alt = ac_data.get("alt_baro", "Ground / Offline")
        gs = ac_data.get("gs", 0)

        rcpt = EvidenceReceipt(
            tool="adsb_lol_v2 + faa_icao_bijection",
            domain=DomainCategory.PHYSICAL,
            admiralty_code="A1",
            selector_strength=SelectorStrength.STRONG,
            source_url=f"https://globe.adsb.lol/?icao={icao_hex or q}",
            extracted_fact=f"Aircraft {q} -> Mode-S ICAO 24-bit Hex '{icao_hex}' (Type: {ac_type}, Callsign: {flight}, Pos: {lat},{lon}, Alt: {alt}, GS: {gs} kts)",
            raw_snippet=str(ac_data or {"tail": q, "computed_icao_hex": icao_hex})[:320],
        )
        ac_node_id = f"aircraft:{icao_hex or q.lower()}"
        self.graph.upsert_node(
            GraphNode(
                id=ac_node_id,
                label=f"✈️ {q} (ICAO: {icao_hex}) [{ac_type}]",
                entity_type=EntityType.AIRCRAFT,
                domain=DomainCategory.PHYSICAL,
                selector_strength=SelectorStrength.STRONG,
                ftm_schema="Airplane",
                smoke_score=60.0,
                risk_flags=["UNFILTERED_ADSB_MODE_S_TRACKED"],
                attributes={
                    "tail_number": q,
                    "icao_hex": icao_hex,
                    "aircraft_type": ac_type,
                    "lat": lat,
                    "lon": lon,
                    "altitude": alt,
                    "ground_speed_kts": gs,
                },
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
        )
        if origin_node_id != ac_node_id:
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=ac_node_id,
                    relation=RelationType.OPERATES_AIRCRAFT,
                    domain=DomainCategory.PHYSICAL,
                    admiralty_code="A1",
                    confidence=0.95,
                    summary=f"Mode-S Hex {icao_hex}",
                    receipts=[rcpt],
                )
            )
        return aircraft_info
