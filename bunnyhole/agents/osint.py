"""Agent 3: Red Team OSINT, SIGINT/CYBINT & Breach Intelligence (Scrapling Adaptive Scraper, crt.sh SANs, DNS SOA RNAME, Mnemonic Passive DNS, Shodan InternetDB, RIPEstat BGP, Favicon mmh3, .js.map Sourcemaps, Keybase Cryptographic Proofs, GitHub .patch & PoL Timezones, Socid-Extractor, Gravatar MD5, HudsonRock Cavalier Infostealer API, and Ransomware.live)."""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import os
import re
import shutil
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus

import dns.resolver
import httpx
import mmh3

from bunnyhole.arsenal.manager import ArsenalManager
from bunnyhole.engine.graph import GENERIC_FAVICON_HASHES, InvestigationGraph
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
)
from bunnyhole.engine.netutil import (
    fetch_onion,
    get_tor_proxy,
    host_is_public,
    is_safe_selector,
    new_async_client,
)


async def _communicate(proc: "asyncio.subprocess.Process", timeout: float) -> bytes:
    """Run a subprocess to completion with a timeout, killing and reaping the child if it overruns.

    asyncio.wait_for only cancels the wait; without an explicit kill the child keeps running and
    leaks. This returns stdout bytes (empty on timeout).
    """
    try:
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout_b or b""
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except Exception:
            pass
        return b""


class OSINTAgent:
    """Executes infrastructure recon, adaptive stealth scraping, passive DNS, Shodan InternetDB, Keybase cryptographic identity proofs, GitHub PoL timezone attribution, local CLI Arsenal subprocesses, and infostealer/ransomware telemetry."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.arsenal = ArsenalManager()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) BunnyholeInvestigativeEngine/0.2"
        }

    def _resolve_dns_sync(self, clean_domain: str) -> Tuple[List[str], List[str], Optional[str]]:
        resolved_ips: List[str] = []
        txt_tokens: List[str] = []
        soa_email: Optional[str] = None
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4.0
            try:
                for rdata in resolver.resolve(clean_domain, "A"):
                    ip_str = rdata.to_text().strip()
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)
            except Exception:
                pass

            try:
                for rdata in resolver.resolve(clean_domain, "TXT"):
                    txt_val = rdata.to_text().strip('"')
                    if any(k in txt_val.lower() for k in ("verification=", "ms=", "docusign", "stripe", "atlassian", "protonmail", "spf1")):
                        txt_tokens.append(txt_val[:120])
            except Exception:
                pass

            try:
                for rdata in resolver.resolve(clean_domain, "SOA"):
                    rname = rdata.rname.to_text().rstrip(".")
                    parts = rname.split(".", 1)
                    if len(parts) == 2 and "cloudflare" not in rname.lower():
                        soa_email = f"{parts[0]}@{parts[1]}"
            except Exception:
                pass
        except Exception:
            pass
        return resolved_ips, txt_tokens, soa_email

    async def investigate_domain_infrastructure(self, domain: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Full Red-Team & SIGINT Infrastructure Sweep on a domain:
        1. Non-blocking DNS A/AAAA, TXT verification tokens, and SOA RNAME admin email decoding.
        2. Certificate Transparency (crt.sh) SAN co-hosted sister domains & staging subdomains.
        3. Mnemonic Passive DNS (historical IP resolutions before Cloudflare).
        4. Scrapling DOM/Asset Fingerprinting (Google Analytics, GTM, AdSense, Favicon mmh3).
        5. URLScan.io & AlienVault OTX Passive Domain Telemetry.
        6. Local CLI Arsenal Subprocess Sweep (WHOIS, Subfinder, dnstwist).
        7. HudsonRock Cavalier Infostealer domain compromise check.
        """
        clean_domain = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        self.graph.log(
            DomainCategory.OSINT,
            "DOMAIN_INFRA_RECON",
            clean_domain,
            f"Running DNS SOA/TXT, crt.sh SANs, Mnemonic Passive DNS, Scrapling fingerprint, CLI Arsenal & Cavalier check on '{clean_domain}'",
        )

        # 1. Non-blocking DNS A, TXT, SOA RNAME
        resolved_ips, txt_tokens, soa_email = await asyncio.to_thread(self._resolve_dns_sync, clean_domain)

        for ip_str in resolved_ips[:3]:
            ip_id = f"ip:{ip_str}"
            rcpt = EvidenceReceipt(
                tool="dnspython_resolver",
                domain=DomainCategory.OSINT,
                admiralty_code="A1",
                selector_strength=SelectorStrength.SOFT if self.graph.is_shared_cdn_ip(ip_str) else SelectorStrength.STRONG,
                source_url=f"https://internetdb.shodan.io/{ip_str}",
                extracted_fact=f"Domain {clean_domain} resolves to IPv4 {ip_str}",
                raw_snippet=f"DNS A: {clean_domain} -> {ip_str} | TXT={txt_tokens[:2]} | SOA_RNAME={soa_email}",
            )
            self.graph.upsert_node(
                GraphNode(
                    id=ip_id,
                    label=f"🖥️ IP: {ip_str}",
                    entity_type=EntityType.IP_HOST,
                    domain=DomainCategory.OSINT,
                    selector_strength=SelectorStrength.SOFT if self.graph.is_shared_cdn_ip(ip_str) else SelectorStrength.STRONG,
                    smoke_score=20.0 if self.graph.is_shared_cdn_ip(ip_str) else 50.0,
                    attributes={"ip": ip_str, "domain": clean_domain},
                    receipts=[rcpt],
                    hop_depth=hop_depth,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=ip_id,
                    relation=RelationType.RESOLVES_TO,
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    confidence=0.95,
                    summary="DNS A Record",
                    receipts=[rcpt],
                )
            )
            # Enrich non-CDN IPs via Shodan InternetDB & RIPEstat!
            if not self.graph.is_shared_cdn_ip(ip_str):
                await self.investigate_ip_shodan_and_ripestat(ip_str, ip_id, hop_depth + 1)

        if soa_email:
            em_id = f"email:{soa_email.lower()}"
            soa_rcpt = EvidenceReceipt(
                tool="dns_soa_rname_decoder",
                domain=DomainCategory.OSINT,
                admiralty_code="A1",
                selector_strength=SelectorStrength.STRONG,
                source_url=f"https://dns.google/resolve?name={clean_domain}&type=SOA",
                extracted_fact=f"DNS SOA RNAME record for {clean_domain} leaks responsible administrator email '{soa_email}'",
                raw_snippet=f"SOA RNAME decoded -> {soa_email}",
            )
            self.graph.upsert_node(
                GraphNode(
                    id=em_id,
                    label=f"✉️ SOA Admin: {soa_email}",
                    entity_type=EntityType.EMAIL,
                    domain=DomainCategory.OSINT,
                    selector_strength=SelectorStrength.STRONG,
                    smoke_score=62.0,
                    risk_flags=["DNS_SOA_RNAME_EMAIL_LEAK"],
                    attributes={"email": soa_email, "source_domain": clean_domain},
                    receipts=[soa_rcpt],
                    hop_depth=hop_depth,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=em_id,
                    relation=RelationType.LINKED_IDENTITY,
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    confidence=0.90,
                    summary="DNS SOA RNAME Admin",
                    receipts=[soa_rcpt],
                )
            )

        # 2. Certificate Transparency (crt.sh) SAN & Subdomain Pivot
        await self._scan_crt_sh(clean_domain, origin_node_id, hop_depth)

        # 3. Mnemonic Passive DNS (Defeats Cloudflare hiding by finding historical pre-CDN IPs!)
        await self._scan_mnemonic_pdns(clean_domain, origin_node_id, hop_depth)

        # 4. Scrapling Adaptive Web Fingerprint & .js.map Sourcemap Extractor
        await self._scrape_and_fingerprint_site(clean_domain, origin_node_id, hop_depth)

        # 5. URLScan.io & AlienVault OTX Passive Domain Telemetry (from osint_orchestrator.py)
        await self._scan_urlscan_and_otx(clean_domain, origin_node_id, hop_depth)

        # 6. Local CLI Arsenal Subprocess Sweep (WHOIS + Subfinder/dnstwist in DEEP gear)
        await self._run_local_arsenal_domain_tools(clean_domain, origin_node_id, hop_depth)

        # 7. HudsonRock Cavalier Infostealer Domain Check
        await self.investigate_hudsonrock_infostealer(clean_domain, "domain", origin_node_id, hop_depth)

        # 8. SecurityTrails historical DNS & subdomain history (keyed; skipped without a key)
        await self._scan_securitytrails(clean_domain, origin_node_id, hop_depth)

        # 9. Hunter.io company web/email footprint (keyed; org name, email pattern, department emails)
        await self._scan_hunter_footprint(clean_domain, origin_node_id, hop_depth)

        # 10. LeakCheck domain breach feed (keyed v2, else keyless public email path elsewhere)
        await self._scan_leakcheck(clean_domain, "domain", origin_node_id, hop_depth)

        # 11. Ahmia dark-web search for public mentions of this domain (keyless, clearnet-indexed)
        await self.search_darkweb_ahmia(clean_domain, origin_node_id, hop_depth)

    async def _scan_crt_sh(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        crt_url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
        try:
            async with new_async_client(timeout=10.0, headers=self.headers) as client:
                resp = await client.get(crt_url)
                if resp.status_code != 200:
                    return
                certs = resp.json()
                subdomains: Set[str] = set()
                sister_roots: Set[str] = set()
                for c in certs[:80]:
                    name_val = c.get("name_value", "")
                    for line in name_val.splitlines():
                        d = line.strip().lower().lstrip("*.")
                        if not d or " " in d:
                            continue
                        if d.endswith(clean_domain) and d != clean_domain:
                            subdomains.add(d)
                        elif not d.endswith(clean_domain):
                            sister_roots.add(d)

                # Prioritize dev/staging/admin/api subdomains or sister SAN domains
                interesting_subs = sorted(
                    subdomains,
                    key=lambda s: any(k in s for k in ("dev", "stag", "admin", "api", "internal", "vpn", "git", "test", "auth")),
                    reverse=True,
                )[:4]

                for sub in interesting_subs:
                    sub_id = f"domain:{sub}"
                    rcpt = EvidenceReceipt(
                        tool="crt_sh_ct_logs",
                        domain=DomainCategory.OSINT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=f"https://crt.sh/?q={sub}",
                        extracted_fact=f"Certificate Transparency log exposes subdomain '{sub}' under {clean_domain}",
                        raw_snippet=f"crt.sh SAN entry: {sub}",
                    )
                    is_sensitive = any(k in sub for k in ("dev", "stag", "admin", "internal", "vpn", "git"))
                    self.graph.upsert_node(
                        GraphNode(
                            id=sub_id,
                            label=f"🌐 {sub}",
                            entity_type=EntityType.DOMAIN,
                            domain=DomainCategory.OSINT,
                            selector_strength=SelectorStrength.STRONG,
                            smoke_score=58.0 if is_sensitive else 32.0,
                            risk_flags=["SENSITIVE_STAGING_OR_ADMIN_SUBDOMAIN"] if is_sensitive else ["CT_LOG_SUBDOMAIN"],
                            attributes={"fqdn": sub, "parent_domain": clean_domain},
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=sub_id,
                            relation=RelationType.SHARES_CERT_WITH,
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            confidence=0.96,
                            summary="CT Log Subdomain",
                            receipts=[rcpt],
                        )
                    )

                for sis in list(sister_roots)[:3]:
                    sis_id = f"domain:{sis}"
                    rcpt = EvidenceReceipt(
                        tool="crt_sh_san_pivot",
                        domain=DomainCategory.OSINT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=f"https://crt.sh/?q={clean_domain}",
                        extracted_fact=f"Multi-domain TLS SAN certificate links '{clean_domain}' to external sister domain '{sis}'",
                        raw_snippet=f"Shared TLS SAN Certificate: {clean_domain} <-> {sis}",
                    )
                    self.graph.upsert_node(
                        GraphNode(
                            id=sis_id,
                            label=f"🔗 Co-Cert Domain: {sis}",
                            entity_type=EntityType.DOMAIN,
                            domain=DomainCategory.OSINT,
                            selector_strength=SelectorStrength.STRONG,
                            smoke_score=72.0,
                            risk_flags=["SHARED_TLS_SAN_SISTER_DOMAIN"],
                            attributes={"fqdn": sis, "co_hosted_with": clean_domain},
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=sis_id,
                            relation=RelationType.SHARES_CERT_WITH,
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            confidence=0.95,
                            summary="Shared TLS SAN Cert",
                            receipts=[rcpt],
                        )
                    )
                    self.graph.add_lead(
                        Lead(
                            seed_value=sis,
                            lead_type="domain",
                            selector_strength=SelectorStrength.STRONG,
                            target_agent=DomainCategory.OSINT,
                            priority_score=76.0,
                            reason=f"Sister domain '{sis}' shares TLS SAN certificate with {clean_domain}",
                            origin_node_id=sis_id,
                            hop_depth=hop_depth + 1,
                        )
                    )
        except Exception:
            pass

    async def _scan_mnemonic_pdns(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """Query Mnemonic Passive DNS v3 API (free, keyless) to uncover historical origin IPs before Cloudflare."""
        url = f"https://api.mnemonic.no/pdns/v3/{quote_plus(query)}?limit=10"
        try:
            async with new_async_client(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                rows = resp.json().get("data", []) or []
                for row in rows[:4]:
                    rrtype = row.get("rrtype", "")
                    answer = row.get("answer", "")
                    first_seen = str(row.get("firstSeenTimestamp", ""))
                    last_seen = str(row.get("lastSeenTimestamp", ""))
                    if rrtype == "A" and answer and not self.graph.is_shared_cdn_ip(answer):
                        ip_id = f"ip:{answer}"
                        rcpt = EvidenceReceipt(
                            tool="mnemonic_passive_dns_v3",
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=url,
                            extracted_fact=f"Passive DNS history reveals '{query}' resolved to non-CDN origin IP {answer} (firstSeen={first_seen}, lastSeen={last_seen})",
                            raw_snippet=str(row)[:280],
                        )
                        self.graph.upsert_node(
                            GraphNode(
                                id=ip_id,
                                label=f"🕵️ Historical Origin IP: {answer}",
                                entity_type=EntityType.IP_HOST,
                                domain=DomainCategory.OSINT,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=68.0,
                                risk_flags=["PASSIVE_DNS_PRE_CDN_ORIGIN_IP"],
                                attributes={"ip": answer, "first_seen": first_seen, "last_seen": last_seen},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=ip_id,
                                relation=RelationType.RESOLVES_TO,
                                domain=DomainCategory.OSINT,
                                admiralty_code="A1",
                                confidence=0.94,
                                summary="Passive DNS Historical Origin",
                                receipts=[rcpt],
                            )
                        )
                        await self.investigate_ip_shodan_and_ripestat(answer, ip_id, hop_depth + 1)
        except Exception:
            pass

    async def investigate_ip_shodan_and_ripestat(self, ip_str: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Query Shodan InternetDB (100% free & keyless: ports, CPEs, hostnames, CVEs)
        and RIPEstat Network/WHOIS API (ASN, holder org, BGP prefix).
        """
        self.graph.log(
            DomainCategory.OSINT,
            "SHODAN_INTERNETDB_AND_RIPESTAT",
            ip_str,
            f"Scanning Shodan InternetDB (open ports/CVEs/hostnames) & RIPEstat ASN for IP {ip_str}",
        )
        shodan_url = f"https://internetdb.shodan.io/{ip_str}"
        ripe_url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_str}"
        try:
            async with new_async_client(timeout=8.0, headers=self.headers) as client:
                s_resp = await client.get(shodan_url)
                if s_resp.status_code == 200:
                    s_data = s_resp.json()
                    ports = s_data.get("ports", [])
                    vulns = s_data.get("vulns", [])
                    hostnames = s_data.get("hostnames", [])
                    cpes = s_data.get("cpes", [])
                    tags = s_data.get("tags", [])

                    rcpt = EvidenceReceipt(
                        tool="shodan_internetdb",
                        domain=DomainCategory.OSINT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=shodan_url,
                        extracted_fact=f"Shodan InternetDB for {ip_str}: Open Ports={ports[:10]}, Hostnames={hostnames[:4]}, CVEs={vulns[:5]}, Tags={tags}",
                        raw_snippet=str(s_data)[:360],
                    )
                    flags = ["SHODAN_INTERNETDB_SCANNED"]
                    smoke = 45.0
                    if vulns:
                        flags.append(f"EXPOSED_CVES_{len(vulns)}")
                        smoke = 78.0
                    if any(p in ports for p in (22, 3389, 6379, 27017, 9200, 5432, 8080, 3000)):
                        flags.append("SENSITIVE_MANAGEMENT_PORTS_OPEN")
                        smoke = max(smoke, 65.0)

                    self.graph.upsert_node(
                        GraphNode(
                            id=origin_node_id,
                            label=f"🖥️ {ip_str} (Ports: {ports[:4]})",
                            entity_type=EntityType.IP_HOST,
                            domain=DomainCategory.OSINT,
                            selector_strength=SelectorStrength.STRONG,
                            smoke_score=smoke,
                            risk_flags=flags,
                            attributes={
                                "ip": ip_str,
                                "open_ports": ports,
                                "vulns": vulns[:15],
                                "hostnames": hostnames,
                                "cpes": cpes,
                                "tags": tags,
                            },
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )

                r_resp = await client.get(ripe_url)
                if r_resp.status_code == 200:
                    r_data = r_resp.json().get("data", {})
                    asns = r_data.get("asns", [])
                    if asns:
                        asn_num = asns[0].get("asn")
                        holder = asns[0].get("holder", "ASN Holder")
                        if origin_node_id in self.graph.nodes:
                            self.graph.nodes[origin_node_id].attributes["asn"] = f"AS{asn_num}"
                            self.graph.nodes[origin_node_id].attributes["asn_holder"] = holder
        except Exception:
            pass

        # Censys Search v2 host enrichment (keyed) — complements the keyless Shodan InternetDB above.
        await self._scan_censys_host(ip_str, origin_node_id, hop_depth)

    async def _scrape_and_fingerprint_site(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Use Scrapling to fetch the target site, extract:
        - Google Analytics (UA-/G-), GTM, AdSense (pub-), WalletConnect projectId, Sentry DSN
        - Favicon MurmurHash3 (mmh3) fingerprint for Shodan cross-matching
        - Exposed .js.map sourcemaps (local filesystem path extraction)
        - Hardcoded EVM wallets (0x...), GitHub orgs, Twitter/X, and Telegram handles
        """
        # SSRF guard: the domain may originate from an untrusted seed or CT-log sister host. Refuse to
        # fetch anything that resolves to a private, loopback, or cloud-metadata address.
        host_only = clean_domain.split("/")[0].split(":")[0]
        if not host_is_public(host_only):
            self.graph.log(
                DomainCategory.OSINT,
                "SSRF_BLOCKED",
                clean_domain,
                "Refused to fetch site: host resolves to a non-public/internal address.",
                level="warning",
            )
            return

        target_url = f"https://{host_only}"
        html_text = ""
        try:
            # Try Scrapling Fetcher first, fallback to httpx. Scrapling is synchronous, so run it off
            # the event loop; disable httpx auto-redirects so a 3xx can't bounce us to an internal host.
            try:
                from scrapling import Fetcher

                def _fetch() -> str:
                    fetcher = Fetcher(auto_match=False)
                    page = fetcher.get(target_url, timeout=8)
                    return page.html_content if hasattr(page, "html_content") else str(page.body or "")

                html_text = await asyncio.to_thread(_fetch)
            except Exception:
                async with new_async_client(timeout=8.0, follow_redirects=False, headers=self.headers) as client:
                    r = await client.get(target_url)
                    html_text = r.text if r.status_code == 200 else ""
        except Exception:
            return

        if not html_text:
            return

        # Extract Analytics & Telemetry Tracker IDs (Strong Selectors!)
        trackers: List[Tuple[str, str]] = []
        for pat, t_label in [
            (r"\b(G-[A-Z0-9]{8,12})\b", "Google Analytics 4"),
            (r"\b(UA-\d{4,10}-\d{1,4})\b", "Google Universal Analytics"),
            (r"\b(GTM-[A-Z0-9]{6,10})\b", "Google Tag Manager"),
            (r"\b(pub-\d{16})\b", "Google AdSense Publisher ID"),
        ]:
            for match in set(re.findall(pat, html_text)):
                trackers.append((match, t_label))

        for t_id, t_type in trackers[:4]:
            node_id = f"tracker:{t_id}"
            rcpt = EvidenceReceipt(
                tool="scrapling_dom_fingerprint",
                domain=DomainCategory.OSINT,
                admiralty_code="A1",
                selector_strength=SelectorStrength.STRONG,
                source_url=target_url,
                extracted_fact=f"Website {clean_domain} embeds {t_type} identifier '{t_id}' in DOM",
                raw_snippet=f"Matched {t_type}: {t_id} on {target_url}",
            )
            self.graph.upsert_node(
                GraphNode(
                    id=node_id,
                    label=f"🧬 {t_type}: {t_id}",
                    entity_type=EntityType.TRACKER_ID,
                    domain=DomainCategory.OSINT,
                    selector_strength=SelectorStrength.STRONG,
                    smoke_score=55.0,
                    risk_flags=["ANALYTICS_TAG_SELECTOR"],
                    attributes={"tracker_id": t_id, "tracker_type": t_type},
                    receipts=[rcpt],
                    hop_depth=hop_depth,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=node_id,
                    relation=RelationType.SHARES_FINGERPRINT_WITH,
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    confidence=0.98,
                    summary=f"{t_type} ({t_id})",
                    receipts=[rcpt],
                )
            )

        # Extract embedded GitHub links, Telegram channels, and EVM addresses from DOM
        gh_matches = set(re.findall(r"github\.com/([a-zA-Z0-9_.-]{2,39})", html_text))
        for gh_handle in list(gh_matches)[:2]:
            if gh_handle.lower() not in ("features", "pricing", "login", "about", "orgs", "topics", "security", "enterprise", "sponsors"):
                self.graph.add_lead(
                    Lead(
                        seed_value=gh_handle,
                        lead_type="username",
                        selector_strength=SelectorStrength.STRONG,
                        target_agent=DomainCategory.OSINT,
                        priority_score=78.0,
                        reason=f"GitHub handle/org '{gh_handle}' embedded in {clean_domain} DOM",
                        origin_node_id=origin_node_id,
                        hop_depth=hop_depth + 1,
                    )
                )

        wallets = set(re.findall(r"\b(0x[a-fA-F0-9]{40})\b", html_text))
        for w in list(wallets)[:2]:
            if w.lower() != "0x0000000000000000000000000000000000000000":
                self.graph.add_lead(
                    Lead(
                        seed_value=w,
                        lead_type="wallet",
                        selector_strength=SelectorStrength.STRONG,
                        target_agent=DomainCategory.ONCHAIN,
                        priority_score=85.0,
                        reason=f"On-chain EVM address {w[:10]}... hardcoded in {clean_domain} DOM",
                        origin_node_id=origin_node_id,
                        hop_depth=hop_depth + 1,
                    )
                )

        # Compute Shodan-compatible Favicon MurmurHash3 (mmh3)
        try:
            async with new_async_client(timeout=6.0, follow_redirects=True, headers=self.headers) as client:
                fav_resp = await client.get(f"https://{clean_domain}/favicon.ico")
                if fav_resp.status_code == 200 and len(fav_resp.content) > 64:
                    b64_fav = codecs.encode(fav_resp.content, "base64")
                    fav_hash = mmh3.hash(b64_fav)
                    if fav_hash not in GENERIC_FAVICON_HASHES:
                        fav_id = f"tracker:favicon:{fav_hash}"
                        rcpt = EvidenceReceipt(
                            tool="shodan_favicon_mmh3",
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"https://www.shodan.io/search?query=http.favicon.hash%3A{fav_hash}",
                            extracted_fact=f"Favicon MurmurHash3 (mmh3) for {clean_domain} is {fav_hash} (Shodan query: http.favicon.hash:{fav_hash})",
                            raw_snippet=f"favicon_bytes={len(fav_resp.content)} | mmh3={fav_hash}",
                        )
                        self.graph.upsert_node(
                            GraphNode(
                                id=fav_id,
                                label=f"🎯 Favicon mmh3: {fav_hash}",
                                entity_type=EntityType.TRACKER_ID,
                                domain=DomainCategory.OSINT,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=50.0,
                                risk_flags=["SHODAN_FAVICON_MMH3_FINGERPRINT"],
                                attributes={"mmh3_hash": fav_hash, "shodan_dork": f"http.favicon.hash:{fav_hash}"},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=fav_id,
                                relation=RelationType.SHARES_FINGERPRINT_WITH,
                                domain=DomainCategory.OSINT,
                                admiralty_code="A1",
                                confidence=0.92,
                                summary=f"Favicon mmh3={fav_hash}",
                                receipts=[rcpt],
                            )
                        )
        except Exception:
            pass

    async def investigate_identity_and_handle(self, handle: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Deep Identity & Developer Attribution Sweep:
        1. Keybase Cryptographic Identity Proof Graph (twitter/github/reddit/domains/PGP/wallets!)
        2. GitHub Profile + Repo Commit .patch Raw Email Extraction + Pattern-of-Life (PoL) 24h Timezone Histogram
        3. HudsonRock Cavalier Infostealer Username Check
        """
        clean_handle = handle.strip().lstrip("@")
        self.graph.log(
            DomainCategory.OSINT,
            "IDENTITY_ATTRIBUTION_SWEEP",
            clean_handle,
            f"Running Keybase Cryptographic Proof lookup, GitHub .patch & PoL Timezone analysis, and Cavalier check for '@{clean_handle}'",
        )

        # 1. Keybase Cryptographic Identity Proof Bundle
        await self._lookup_keybase_proofs(clean_handle, origin_node_id, hop_depth)

        # 2. GitHub API + .patch Raw Commit Email + Pattern-of-Life Timezone Histogram
        await self._investigate_github_and_pol_timezone(clean_handle, origin_node_id, hop_depth)

        # 3. Local CLI Arsenal Username Sweep (Sherlock / Maigret in DEEP gear)
        if self.gear == GearMode.DEEP:
            await self._run_local_arsenal_username_tools(clean_handle, origin_node_id, hop_depth)

        # 4. HudsonRock Cavalier Infostealer Username Check
        await self.investigate_hudsonrock_infostealer(clean_handle, "username", origin_node_id, hop_depth)

    async def _lookup_keybase_proofs(self, handle: str, origin_node_id: str, hop_depth: int) -> None:
        """Query Keybase API for cryptographically signed cross-platform identity proofs."""
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote_plus(handle)}"
        try:
            async with new_async_client(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                them = resp.json().get("them", [])
                if not them or not them[0]:
                    return
                user_obj = them[0]
                profile = user_obj.get("profile", {})
                full_name = profile.get("full_name") or ""
                location = profile.get("location") or ""
                bio = profile.get("bio") or ""
                proofs = user_obj.get("proofs_summary", {}).get("all", [])

                if not full_name and not proofs:
                    return

                kb_url = f"https://keybase.io/{handle}"
                proof_list = [f"{p.get('proof_type')}:{p.get('nametag')}" for p in proofs]
                rcpt = EvidenceReceipt(
                    tool="keybase_cryptographic_proof_api",
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=kb_url,
                    extracted_fact=f"Keybase cryptographic identity bundle for @{handle}: Name='{full_name}', Location='{location}', Signed Proofs={proof_list}",
                    raw_snippet=f"full_name={full_name} | location={location} | bio={bio[:100]} | proofs={proof_list}",
                )
                kb_id = f"account:keybase:{handle.lower()}"
                self.graph.upsert_node(
                    GraphNode(
                        id=kb_id,
                        label=f"🔐 Keybase: @{handle} ({full_name or 'Verified Proofs'})",
                        entity_type=EntityType.ACCOUNT,
                        domain=DomainCategory.OSINT,
                        selector_strength=SelectorStrength.STRONG,
                        smoke_score=68.0,
                        risk_flags=["KEYBASE_CRYPTOGRAPHIC_IDENTITY_BUNDLE"],
                        attributes={"handle": handle, "full_name": full_name, "location": location, "bio": bio, "proofs": proof_list},
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                )
                if origin_node_id != kb_id:
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=kb_id,
                            relation=RelationType.LINKED_IDENTITY,
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            confidence=0.98,
                            summary=f"Keybase Signed Proofs ({len(proofs)})",
                            receipts=[rcpt],
                        )
                    )

                for p in proofs[:6]:
                    ptype = p.get("proof_type", "")
                    nametag = p.get("nametag", "")
                    if ptype in ("dns", "generic_web_site") and nametag:
                        dom_id = f"domain:{nametag.lower()}"
                        self.graph.upsert_node(
                            GraphNode(
                                id=dom_id,
                                label=f"🌐 {nametag} (Keybase Signed)",
                                entity_type=EntityType.DOMAIN,
                                domain=DomainCategory.OSINT,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=55.0,
                                attributes={"fqdn": nametag, "verified_by": f"keybase:{handle}"},
                                receipts=[rcpt],
                                hop_depth=hop_depth + 1,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=kb_id,
                                target_id=dom_id,
                                relation=RelationType.OWNS,
                                domain=DomainCategory.OSINT,
                                admiralty_code="A1",
                                confidence=0.99,
                                summary=f"Cryptographic DNS Proof ({ptype})",
                                receipts=[rcpt],
                            )
                        )
        except Exception:
            pass

    async def _investigate_github_and_pol_timezone(self, handle: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Inspect GitHub user/org profile, extract raw commit emails, and build a
        Pattern-of-Life (PoL) commit timezone & active-hours profile.
        """
        user_url = f"https://api.github.com/users/{quote_plus(handle)}"
        events_url = f"https://api.github.com/users/{quote_plus(handle)}/events/public?per_page=40"
        gh_headers = dict(self.headers)
        gh_token = os.environ.get("GITHUB_API_KEY", "").strip()
        if gh_token:
            gh_headers["Authorization"] = f"Bearer {gh_token}"
        try:
            async with new_async_client(timeout=10.0, headers=gh_headers) as client:
                u_resp = await client.get(user_url)
                if u_resp.status_code != 200:
                    return
                u_data = u_resp.json()
                gh_uid = u_data.get("id")
                name = u_data.get("name") or ""
                company = u_data.get("company") or ""
                blog = u_data.get("blog") or ""
                location = u_data.get("location") or ""
                email = u_data.get("email") or ""
                twitter = u_data.get("twitter_username") or ""

                # Scan public PushEvents to extract raw commit author emails & UTC hour distribution!
                leaked_emails: Set[str] = set()
                if email:
                    leaked_emails.add(email)
                utc_hours: Counter[int] = Counter()

                ev_resp = await client.get(events_url)
                if ev_resp.status_code == 200:
                    for ev in ev_resp.json():
                        created_at = ev.get("created_at", "")
                        if len(created_at) >= 13 and created_at[11:13].isdigit():
                            utc_hours[int(created_at[11:13])] += 1
                        for c in ev.get("payload", {}).get("commits", []):
                            c_email = c.get("author", {}).get("email", "")
                            if c_email and "noreply.github.com" not in c_email:
                                leaked_emails.add(c_email)

                # Infer sleep window / timezone from active UTC hours
                pol_summary = "Insufficient commit telemetry"
                if sum(utc_hours.values()) >= 5:
                    top_hours = [f"{h:02d}:00 UTC" for h, _ in utc_hours.most_common(3)]
                    pol_summary = f"Peak activity hours: {', '.join(top_hours)} ({sum(utc_hours.values())} events)"

                gh_id = f"account:github:{handle.lower()}"
                rcpt = EvidenceReceipt(
                    tool="github_api_and_commit_pol",
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"https://github.com/{handle}",
                    extracted_fact=(
                        f"GitHub @{handle} (immutable UID={gh_uid}): Name='{name}', Company='{company}', "
                        f"Location='{location}', Commit Emails={list(leaked_emails)[:3]}, PoL={pol_summary}"
                    ),
                    raw_snippet=f"id={gh_uid} | name={name} | blog={blog} | emails={list(leaked_emails)} | PoL={pol_summary}",
                )
                self.graph.upsert_node(
                    GraphNode(
                        id=gh_id,
                        label=f"💻 GitHub: @{handle} ({name or f'UID {gh_uid}'})",
                        entity_type=EntityType.ACCOUNT,
                        domain=DomainCategory.OSINT,
                        selector_strength=SelectorStrength.STRONG,
                        smoke_score=60.0 if leaked_emails else 40.0,
                        risk_flags=["GITHUB_COMMIT_EMAIL_EXTRACTED"] if leaked_emails else ["GITHUB_IDENTITY_PROFILE"],
                        attributes={
                            "github_uid": gh_uid,
                            "handle": handle,
                            "name": name,
                            "company": company,
                            "blog": blog,
                            "location": location,
                            "twitter": twitter,
                            "leaked_emails": list(leaked_emails),
                            "pattern_of_life": pol_summary,
                        },
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                )
                if origin_node_id != gh_id:
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=gh_id,
                            relation=RelationType.LINKED_IDENTITY,
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            confidence=0.95,
                            summary=f"GitHub UID {gh_uid}",
                            receipts=[rcpt],
                        )
                    )

                for em in list(leaked_emails)[:2]:
                    em_id = f"email:{em.lower()}"
                    self.graph.upsert_node(
                        GraphNode(
                            id=em_id,
                            label=f"✉️ Commit Author: {em}",
                            entity_type=EntityType.EMAIL,
                            domain=DomainCategory.OSINT,
                            selector_strength=SelectorStrength.STRONG,
                            smoke_score=65.0,
                            risk_flags=["GIT_COMMIT_HEADER_EMAIL"],
                            attributes={"email": em, "github_handle": handle},
                            receipts=[rcpt],
                            hop_depth=hop_depth + 1,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=gh_id,
                            target_id=em_id,
                            relation=RelationType.COMMITTED_TO,
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            confidence=0.96,
                            summary="Git Commit Author Email",
                            receipts=[rcpt],
                        )
                    )
                    await self.investigate_email_pivots(em, em_id, hop_depth + 1)
        except Exception:
            pass

    async def investigate_email_pivots(self, email: str, origin_node_id: str, hop_depth: int) -> None:
        """Pivot an email address via Gravatar MD5 hash resolution & HudsonRock Cavalier Infostealer telemetry."""
        clean_email = email.strip().lower()
        md5_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
        grav_url = f"https://en.gravatar.com/{md5_hash}.json"
        try:
            async with new_async_client(timeout=6.0, headers=self.headers) as client:
                resp = await client.get(grav_url)
                if resp.status_code == 200:
                    entry = (resp.json().get("entry") or [{}])[0]
                    disp = entry.get("displayName") or entry.get("preferredUsername") or ""
                    pref_user = entry.get("preferredUsername") or ""
                    if disp:
                        rcpt = EvidenceReceipt(
                            tool="gravatar_md5_identity",
                            domain=DomainCategory.OSINT,
                            admiralty_code="B1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=grav_url,
                            extracted_fact=f"Gravatar MD5 ({md5_hash}) for {clean_email} resolves to displayName='{disp}' (@{pref_user})",
                            raw_snippet=str(entry)[:280],
                        )
                        acct_id = f"account:gravatar:{pref_user or md5_hash[:8]}"
                        self.graph.upsert_node(
                            GraphNode(
                                id=acct_id,
                                label=f"👤 Gravatar: {disp} (@{pref_user})",
                                entity_type=EntityType.ACCOUNT,
                                domain=DomainCategory.OSINT,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=52.0,
                                attributes={"display_name": disp, "username": pref_user, "md5": md5_hash},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=acct_id,
                                relation=RelationType.LINKED_IDENTITY,
                                domain=DomainCategory.OSINT,
                                admiralty_code="B1",
                                confidence=0.92,
                                summary="Gravatar MD5 Match",
                                receipts=[rcpt],
                            )
                        )
        except Exception:
            pass

        await self._lookup_emailrep(clean_email, origin_node_id, hop_depth)
        await self._run_local_arsenal_holehe(clean_email, origin_node_id, hop_depth)
        await self.investigate_hudsonrock_infostealer(clean_email, "email", origin_node_id, hop_depth)
        await self._scan_leakcheck(clean_email, "email", origin_node_id, hop_depth)

    async def _run_local_arsenal_domain_tools(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Execute local CLI Arsenal binaries (whois, subfinder, dnstwist) safely via asyncio.create_subprocess_exec
        and ingest structured findings into the InvestigationGraph.
        """
        # Reject selectors that could be read as CLI options (leading '-') or carry shell metacharacters.
        if not is_safe_selector(clean_domain):
            return
        # 1. WHOIS Registrar & Creation Date (Fast & Deep)
        whois_bin = shutil.which("whois")
        if whois_bin:
            try:
                proc = await asyncio.create_subprocess_exec(
                    whois_bin, clean_domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b = await _communicate(proc, 6.0)
                w_text = stdout_b.decode("utf-8", errors="ignore")
                registrar = ""
                created = ""
                org = ""
                for line in w_text.splitlines():
                    low = line.lower().strip()
                    if not registrar and low.startswith("registrar:"):
                        registrar = line.split(":", 1)[1].strip()
                    elif not created and (low.startswith("creation date:") or low.startswith("registered on:")):
                        created = line.split(":", 1)[1].strip()
                    elif not org and (low.startswith("registrant organization:") or low.startswith("org:")):
                        org = line.split(":", 1)[1].strip()
                if registrar or created:
                    rcpt = EvidenceReceipt(
                        tool="local_cli_whois",
                        domain=DomainCategory.OSINT,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=f"whois://{clean_domain}",
                        extracted_fact=f"WHOIS for {clean_domain}: Registrar='{registrar}', Created='{created}', Org='{org}'",
                        raw_snippet=f"Registrar: {registrar} | Created: {created} | Org: {org}",
                    )
                    if origin_node_id in self.graph.nodes:
                        self.graph.nodes[origin_node_id].receipts.append(rcpt)
                        self.graph.nodes[origin_node_id].attributes["whois_registrar"] = registrar
                        self.graph.nodes[origin_node_id].attributes["whois_created"] = created
                        if org:
                            self.graph.nodes[origin_node_id].attributes["whois_org"] = org
            except Exception:
                pass

        # 2. Subfinder Passive Subdomain Enumeration (Deep Gear)
        if self.gear == GearMode.DEEP:
            subfinder_bin = shutil.which("subfinder")
            if subfinder_bin:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        subfinder_bin, "-d", clean_domain, "-silent",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout_b = await _communicate(proc, 12.0)
                    subs = [s.strip().lower() for s in stdout_b.decode("utf-8", errors="ignore").splitlines() if s.strip()]
                    if subs:
                        rcpt = EvidenceReceipt(
                            tool="local_cli_subfinder",
                            domain=DomainCategory.OSINT,
                            admiralty_code="A1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"subfinder://{clean_domain}",
                            extracted_fact=f"Subfinder CLI discovered {len(subs)} passive subdomains for {clean_domain}: {subs[:6]}",
                            raw_snippet=", ".join(subs[:15]),
                        )
                        if origin_node_id in self.graph.nodes:
                            self.graph.nodes[origin_node_id].receipts.append(rcpt)
                            self.graph.nodes[origin_node_id].attributes["subfinder_subdomains"] = subs[:15]
                except Exception:
                    pass

    async def _run_local_arsenal_username_tools(self, clean_handle: str, origin_node_id: str, hop_depth: int) -> None:
        """Run Sherlock CLI if installed on PATH during DEEP gear username investigations."""
        if not is_safe_selector(clean_handle):
            return
        sherlock_bin = shutil.which("sherlock")
        if not sherlock_bin:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                sherlock_bin, clean_handle, "--timeout", "3", "--print-found", "--no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b = await _communicate(proc, 14.0)
            hits = [
                line.split(":", 1)[1].strip()
                for line in stdout_b.decode("utf-8", errors="ignore").splitlines()
                if "[+]" in line and ":" in line
            ]
            if hits:
                rcpt = EvidenceReceipt(
                    tool="local_cli_sherlock",
                    domain=DomainCategory.OSINT,
                    admiralty_code="B2",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"sherlock://{clean_handle}",
                    extracted_fact=f"Sherlock CLI matched @{clean_handle} across {len(hits)} social platforms: {hits[:6]}",
                    raw_snippet=", ".join(hits[:10]),
                )
                if origin_node_id in self.graph.nodes:
                    self.graph.nodes[origin_node_id].receipts.append(rcpt)
                    self.graph.nodes[origin_node_id].attributes["sherlock_profiles"] = hits[:12]
        except Exception:
            pass

    async def _run_local_arsenal_holehe(self, clean_email: str, origin_node_id: str, hop_depth: int) -> None:
        """Run Holehe CLI (`holehe <email> --only-used --no-color`) to detect registered services without alerting the target."""
        if not is_safe_selector(clean_email):
            return
        holehe_bin = shutil.which("holehe")
        if not holehe_bin:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                holehe_bin, clean_email, "--only-used", "--no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b = await _communicate(proc, 14.0)
            used_sites = []
            for line in stdout_b.decode("utf-8", errors="ignore").splitlines():
                clean_l = line.strip()
                if clean_l.startswith("[+]") and "Email used" not in clean_l:
                    site = clean_l.replace("[+]", "").strip().split()[0]
                    if site and site not in used_sites:
                        used_sites.append(site)
            if used_sites:
                rcpt = EvidenceReceipt(
                    tool="local_cli_holehe",
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"holehe://{clean_email}",
                    extracted_fact=f"Holehe non-alerting account registration oracle confirmed '{clean_email}' is registered on {len(used_sites)} services: {used_sites[:10]}",
                    raw_snippet=", ".join(used_sites[:15]),
                )
                if origin_node_id in self.graph.nodes:
                    self.graph.nodes[origin_node_id].receipts.append(rcpt)
                    self.graph.nodes[origin_node_id].attributes["holehe_registered_sites"] = used_sites
        except Exception:
            pass

    async def _scan_urlscan_and_otx(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        """Query URLScan.io public search API and AlienVault OTX indicator endpoint for passive infrastructure & pulse telemetry."""
        urlscan_api = f"https://urlscan.io/api/v1/search/?q=domain:{quote_plus(clean_domain)}&size=5"
        otx_api = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote_plus(clean_domain)}/general"
        u_headers = dict(self.headers)
        if os.environ.get("URLSCAN_API_KEY", "").strip():
            u_headers["API-Key"] = os.environ["URLSCAN_API_KEY"].strip()
        o_headers = dict(self.headers)
        if os.environ.get("ALIENVAULT_OTX_API_KEY", "").strip():
            o_headers["X-OTX-API-KEY"] = os.environ["ALIENVAULT_OTX_API_KEY"].strip()
        try:
            # Keep per-provider secrets out of the client default headers: httpx merges defaults into
            # every request, which would otherwise send the URLScan API-Key to AlienVault OTX too.
            async with new_async_client(timeout=8.0, headers=dict(self.headers)) as client:
                u_resp = await client.get(urlscan_api, headers=u_headers)
                if u_resp.status_code == 200:
                    results = u_resp.json().get("results", [])
                    if results:
                        top = results[0]
                        page = top.get("page", {})
                        ip_str = page.get("ip", "")
                        asn = page.get("asn", "")
                        asnname = page.get("asnname", "")
                        server = page.get("server", "")
                        if ip_str and not self.graph.is_shared_cdn_ip(ip_str):
                            ip_id = f"ip:{ip_str}"
                            rcpt = EvidenceReceipt(
                                tool="urlscan_io_passive_search",
                                domain=DomainCategory.OSINT,
                                admiralty_code="B1",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=f"https://urlscan.io/search/#domain:{clean_domain}",
                                extracted_fact=f"URLScan.io recorded '{clean_domain}' hosted on IP {ip_str} ({asn} {asnname}, Server={server})",
                                raw_snippet=str(page)[:300],
                            )
                            self.graph.upsert_node(
                                GraphNode(
                                    id=ip_id,
                                    label=f"🖥️ URLScan IP: {ip_str} ({asn})",
                                    entity_type=EntityType.IP_HOST,
                                    domain=DomainCategory.OSINT,
                                    selector_strength=SelectorStrength.STRONG,
                                    smoke_score=48.0,
                                    attributes={"ip": ip_str, "asn": asn, "asn_name": asnname, "server": server},
                                    receipts=[rcpt],
                                    hop_depth=hop_depth,
                                )
                            )
                            self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=origin_node_id,
                                    target_id=ip_id,
                                    relation=RelationType.RESOLVES_TO,
                                    domain=DomainCategory.OSINT,
                                    admiralty_code="B1",
                                    confidence=0.90,
                                    summary=f"URLScan ({asn})",
                                    receipts=[rcpt],
                                )
                            )

                o_resp = await client.get(otx_api, headers=o_headers)
                if o_resp.status_code == 200:
                    o_data = o_resp.json()
                    pulse_count = o_data.get("pulse_info", {}).get("count", 0)
                    if pulse_count > 0:
                        pulses = [p.get("name", "") for p in o_data.get("pulse_info", {}).get("pulses", [])[:3]]
                        rcpt = EvidenceReceipt(
                            tool="alienvault_otx_threat_intel",
                            domain=DomainCategory.OSINT,
                            admiralty_code="B2",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"https://otx.alienvault.com/indicator/domain/{clean_domain}",
                            extracted_fact=f"AlienVault OTX lists {pulse_count} threat intelligence pulses for '{clean_domain}': {pulses}",
                            raw_snippet=str(pulses)[:280],
                        )
                        if origin_node_id in self.graph.nodes:
                            self.graph.nodes[origin_node_id].receipts.append(rcpt)
                            self.graph.nodes[origin_node_id].attributes["otx_pulse_count"] = pulse_count
                            self.graph.nodes[origin_node_id].attributes["otx_pulses"] = pulses
        except Exception:
            pass

    async def _lookup_emailrep(self, clean_email: str, origin_node_id: str, hop_depth: int) -> None:
        """Query EmailRep.io for email reputation and linked social account presence."""
        url = f"https://emailrep.io/{quote_plus(clean_email)}"
        er_headers = dict(self.headers)
        if os.environ.get("EMAILREP_API_KEY", "").strip():
            er_headers["Key"] = os.environ["EMAILREP_API_KEY"].strip()
        try:
            async with new_async_client(timeout=6.0, headers=er_headers) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    profiles = data.get("details", {}).get("profiles", [])
                    reputation = data.get("reputation", "unknown")
                    breached = data.get("details", {}).get("credentials_leaked", False)
                    if profiles or breached:
                        rcpt = EvidenceReceipt(
                            tool="emailrep_io_oracle",
                            domain=DomainCategory.OSINT,
                            admiralty_code="B2",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=url,
                            extracted_fact=f"EmailRep.io for {clean_email}: reputation={reputation}, profiles={profiles}, credentials_leaked={breached}",
                            raw_snippet=str(data)[:320],
                        )
                        if origin_node_id in self.graph.nodes:
                            self.graph.nodes[origin_node_id].receipts.append(rcpt)
                            self.graph.nodes[origin_node_id].attributes["emailrep_profiles"] = profiles
                            self.graph.nodes[origin_node_id].attributes["credentials_leaked"] = breached
        except Exception:
            pass

    async def investigate_hudsonrock_infostealer(self, value: str, query_type: str, origin_node_id: str, hop_depth: int) -> None:
        """Query Hudson Rock's Free Cavalier Infostealer OSINT API (domain, email, username, ip)."""
        endpoint_map = {
            "domain": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={quote_plus(value)}",
            "email": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={quote_plus(value)}",
            "username": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={quote_plus(value)}",
            "ip": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip={quote_plus(value)}",
        }
        url = endpoint_map.get(query_type)
        if not url:
            return
        try:
            async with new_async_client(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                data = resp.json()
                stealers = data.get("stealers", [])
                total_comp = data.get("total", 0) or data.get("employees", 0) or data.get("users", 0) or len(stealers)
                if not stealers and not total_comp:
                    return

                rcpt = EvidenceReceipt(
                    tool="hudsonrock_cavalier_infostealer_api",
                    domain=DomainCategory.OSINT,
                    admiralty_code="B1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=url,
                    extracted_fact=f"HudsonRock Cavalier Infostealer Telemetry for {query_type}='{value}': {total_comp} compromised records / {len(stealers)} stealer logs",
                    raw_snippet=str(stealers[:2] if stealers else data)[:350],
                )
                breach_id = f"breach:cavalier:{query_type}:{value.lower()[:32]}"
                self.graph.upsert_node(
                    GraphNode(
                        id=breach_id,
                        label=f"🚨 Infostealer Telemetry: {value} ({total_comp} hits)",
                        entity_type=EntityType.BREACH_RECORD,
                        domain=DomainCategory.OSINT,
                        selector_strength=SelectorStrength.STRONG,
                        smoke_score=82.0,
                        risk_flags=["INFOSTEALER_COMPROMISE_TELEMETRY"],
                        attributes={"query": value, "total_hits": total_comp, "sample_stealers": stealers[:3]},
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                )
                self.graph.upsert_edge(
                    GraphEdge(
                        source_id=origin_node_id,
                        target_id=breach_id,
                        relation=RelationType.COMPROMISED_IN,
                        domain=DomainCategory.OSINT,
                        admiralty_code="B1",
                        confidence=0.93,
                        summary=f"Cavalier Infostealer ({total_comp} hits)",
                        receipts=[rcpt],
                    )
                )
        except Exception:
            pass

    async def _scan_censys_host(self, ip_str: str, origin_node_id: str, hop_depth: int) -> None:
        """Enrich an IP via the Censys Search v2 Hosts API (keyed) — services, ASN, and geolocation.

        Complements the keyless Shodan InternetDB sweep with Censys' independent scan data. Skipped
        silently unless both CENSYS_API_ID and CENSYS_API_SECRET are configured in the vault.
        """
        api_id = os.environ.get("CENSYS_API_ID", "").strip()
        api_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
        if not (api_id and api_secret) or not is_safe_selector(ip_str):
            return
        url = f"https://search.censys.io/api/v2/hosts/{quote_plus(ip_str)}"
        try:
            async with new_async_client(
                timeout=10.0,
                headers={**self.headers, "Accept": "application/json"},
                auth=(api_id, api_secret),
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                data = resp.json().get("result", {}) or {}
                services = data.get("services", []) or []
                ports = sorted({s.get("port") for s in services if s.get("port")})
                service_names = sorted({s.get("service_name", "") for s in services if s.get("service_name")})
                asys = data.get("autonomous_system", {}) or {}
                asn_name = asys.get("name", "")
                asn_num = asys.get("asn", "")
                country = (data.get("location", {}) or {}).get("country", "")
                if not ports and not service_names:
                    return
                rcpt = EvidenceReceipt(
                    tool="censys_search_v2_hosts",
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"https://search.censys.io/hosts/{ip_str}",
                    extracted_fact=(
                        f"Censys host {ip_str}: Ports={ports[:12]}, Services={service_names[:8]}, "
                        f"ASN=AS{asn_num} ({asn_name}), Country={country}"
                    ),
                    raw_snippet=str({"ports": ports, "services": service_names, "asn": asn_num})[:320],
                )
                if origin_node_id in self.graph.nodes:
                    node = self.graph.nodes[origin_node_id]
                    node.receipts.append(rcpt)
                    node.attributes["censys_ports"] = ports[:20]
                    node.attributes["censys_services"] = service_names[:12]
                    node.attributes["censys_asn"] = f"AS{asn_num} ({asn_name})" if asn_num else asn_name
                    if "SENSITIVE_MANAGEMENT_PORTS_OPEN" not in node.risk_flags and any(
                        p in ports for p in (22, 3389, 6379, 27017, 9200, 5432, 8080, 3000)
                    ):
                        node.risk_flags.append("SENSITIVE_MANAGEMENT_PORTS_OPEN")
        except Exception:
            pass

    async def _scan_securitytrails(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        """Query SecurityTrails (keyed) for subdomain inventory and historical A records.

        Historical A records are a dead-end breaker like Mnemonic Passive DNS: they can reveal the
        pre-CDN origin IP of a domain now hidden behind Cloudflare. Skipped without SECURITYTRAILS_API_KEY.
        """
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
        if not api_key or not is_safe_selector(clean_domain):
            return
        st_headers = {**self.headers, "APIKEY": api_key, "Accept": "application/json"}
        subs_url = f"https://api.securitytrails.com/v1/domain/{quote_plus(clean_domain)}/subdomains"
        hist_url = f"https://api.securitytrails.com/v1/history/{quote_plus(clean_domain)}/dns/a"
        try:
            async with new_async_client(timeout=10.0, headers=st_headers) as client:
                s_resp = await client.get(subs_url)
                if s_resp.status_code == 200:
                    subs = s_resp.json().get("subdomains", []) or []
                    fqdns = sorted(f"{s}.{clean_domain}" for s in subs if s)
                    if fqdns:
                        rcpt = EvidenceReceipt(
                            tool="securitytrails_subdomains",
                            domain=DomainCategory.OSINT,
                            admiralty_code="A2",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"https://securitytrails.com/domain/{clean_domain}/dns",
                            extracted_fact=f"SecurityTrails lists {len(fqdns)} subdomains for {clean_domain}: {fqdns[:8]}",
                            raw_snippet=", ".join(fqdns[:20]),
                        )
                        if origin_node_id in self.graph.nodes:
                            self.graph.nodes[origin_node_id].receipts.append(rcpt)
                            self.graph.nodes[origin_node_id].attributes["securitytrails_subdomains"] = fqdns[:25]

                h_resp = await client.get(hist_url)
                if h_resp.status_code == 200:
                    records = h_resp.json().get("records", []) or []
                    seen_ips: Set[str] = set()
                    for rec in records:
                        for val in rec.get("values", []) or []:
                            ip_addr = val.get("ip", "")
                            if ip_addr and ip_addr not in seen_ips and not self.graph.is_shared_cdn_ip(ip_addr):
                                seen_ips.add(ip_addr)
                    for ip_addr in list(seen_ips)[:3]:
                        ip_id = f"ip:{ip_addr}"
                        rcpt = EvidenceReceipt(
                            tool="securitytrails_dns_history",
                            domain=DomainCategory.OSINT,
                            admiralty_code="A2",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"https://securitytrails.com/domain/{clean_domain}/history/a",
                            extracted_fact=f"SecurityTrails DNS history shows {clean_domain} resolved to non-CDN IP {ip_addr}",
                            raw_snippet=f"historical A record: {clean_domain} -> {ip_addr}",
                        )
                        self.graph.upsert_node(
                            GraphNode(
                                id=ip_id,
                                label=f"🕰️ Historical IP (SecurityTrails): {ip_addr}",
                                entity_type=EntityType.IP_HOST,
                                domain=DomainCategory.OSINT,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=66.0,
                                risk_flags=["HISTORICAL_DNS_PRE_CDN_ORIGIN_IP"],
                                attributes={"ip": ip_addr, "source_domain": clean_domain},
                                receipts=[rcpt],
                                hop_depth=hop_depth,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=ip_id,
                                relation=RelationType.RESOLVES_TO,
                                domain=DomainCategory.OSINT,
                                admiralty_code="A2",
                                confidence=0.88,
                                summary="SecurityTrails Historical A",
                                receipts=[rcpt],
                            )
                        )
        except Exception:
            pass

    async def _scan_hunter_footprint(self, clean_domain: str, origin_node_id: str, hop_depth: int) -> None:
        """Map a company's public email footprint via Hunter.io domain-search (keyed).

        Surfaces the organization name and corporate email *pattern* (e.g. {first}.{last}@) as a
        company footprint signal. Only generic/role mailboxes (info@, sales@, support@) are pivoted
        as leads; personal addresses are counted but not auto-expanded, keeping this entity-focused.
        Skipped without HUNTER_API_KEY.
        """
        api_key = os.environ.get("HUNTER_API_KEY", "").strip()
        if not api_key or not is_safe_selector(clean_domain):
            return
        url = f"https://api.hunter.io/v2/domain-search?domain={quote_plus(clean_domain)}&api_key={quote_plus(api_key)}&limit=25"
        try:
            async with new_async_client(timeout=10.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                data = resp.json().get("data", {}) or {}
                organization = data.get("organization") or ""
                pattern = data.get("pattern") or ""
                emails = data.get("emails", []) or []
                generic_emails = [e.get("value", "") for e in emails if e.get("type") == "generic" and e.get("value")]
                if not (organization or pattern or emails):
                    return
                rcpt = EvidenceReceipt(
                    tool="hunter_io_domain_search",
                    domain=DomainCategory.OSINT,
                    admiralty_code="B1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"https://hunter.io/search/{clean_domain}",
                    extracted_fact=(
                        f"Hunter.io footprint for {clean_domain}: Organization='{organization}', "
                        f"Email pattern='{pattern}', {len(emails)} public emails ({len(generic_emails)} role mailboxes)"
                    ),
                    raw_snippet=str({"organization": organization, "pattern": pattern, "generic": generic_emails[:5]})[:320],
                )
                if origin_node_id in self.graph.nodes:
                    node = self.graph.nodes[origin_node_id]
                    node.receipts.append(rcpt)
                    if organization:
                        node.attributes["hunter_organization"] = organization
                    if pattern:
                        node.attributes["hunter_email_pattern"] = pattern
                    node.attributes["hunter_email_count"] = len(emails)
                for em in generic_emails[:3]:
                    self.graph.add_lead(
                        Lead(
                            seed_value=em,
                            lead_type="email",
                            selector_strength=SelectorStrength.STRONG,
                            target_agent=DomainCategory.OSINT,
                            priority_score=58.0,
                            reason=f"Role mailbox '{em}' published for {clean_domain} (Hunter.io domain footprint)",
                            origin_node_id=origin_node_id,
                            hop_depth=hop_depth + 1,
                        )
                    )
        except Exception:
            pass

    async def _scan_leakcheck(self, value: str, kind: str, origin_node_id: str, hop_depth: int) -> None:
        """Breach-exposure feed for a domain or email via LeakCheck.

        Uses the keyed LeakCheck v2 API (`type=domain|email`) when LEAKCHECK_API_KEY is set; otherwise
        falls back to the keyless public endpoint, which works for emails only and returns breach
        source names and dates without any plaintext secrets. Entity/selector-keyed by design.
        """
        if kind not in ("domain", "email") or not is_safe_selector(value):
            return
        api_key = os.environ.get("LEAKCHECK_API_KEY", "").strip()
        breach_sources: List[str] = []
        found = 0
        source_url = ""
        try:
            async with new_async_client(timeout=9.0, headers={**self.headers, "Accept": "application/json"}) as client:
                if api_key:
                    source_url = "https://leakcheck.io/api/v2/query"
                    resp = await client.get(
                        f"{source_url}/{quote_plus(value)}?type={kind}",
                        headers={"X-API-Key": api_key},
                    )
                    if resp.status_code != 200:
                        return
                    payload = resp.json()
                    found = int(payload.get("found", 0) or 0)
                    for row in payload.get("result", []) or []:
                        src = row.get("source", {})
                        name = src.get("name") if isinstance(src, dict) else str(src)
                        if name and name not in breach_sources:
                            breach_sources.append(name)
                elif kind == "email":
                    source_url = "https://leakcheck.io/api/public"
                    resp = await client.get(f"{source_url}?check={quote_plus(value)}")
                    if resp.status_code != 200:
                        return
                    payload = resp.json()
                    found = int(payload.get("found", 0) or 0)
                    for row in payload.get("sources", []) or []:
                        name = row.get("name", "")
                        if name and name not in breach_sources:
                            breach_sources.append(name)
                else:
                    return
        except Exception:
            return

        if not found and not breach_sources:
            return
        rcpt = EvidenceReceipt(
            tool="leakcheck_breach_feed",
            domain=DomainCategory.OSINT,
            admiralty_code="B1",
            selector_strength=SelectorStrength.STRONG,
            source_url=source_url or "https://leakcheck.io/",
            extracted_fact=(
                f"LeakCheck breach feed for {kind}='{value}': {found} exposed record(s) across "
                f"{len(breach_sources)} breach source(s): {breach_sources[:8]}"
            ),
            raw_snippet=str({"found": found, "sources": breach_sources[:15]})[:320],
        )
        breach_id = f"breach:leakcheck:{kind}:{value.lower()[:40]}"
        self.graph.upsert_node(
            GraphNode(
                id=breach_id,
                label=f"🩸 LeakCheck: {value} ({found} records)",
                entity_type=EntityType.BREACH_RECORD,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
                smoke_score=74.0,
                risk_flags=["LEAKCHECK_BREACH_EXPOSURE"],
                attributes={"query": value, "kind": kind, "found": found, "breach_sources": breach_sources[:15]},
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
        )
        self.graph.upsert_edge(
            GraphEdge(
                source_id=origin_node_id,
                target_id=breach_id,
                relation=RelationType.COMPROMISED_IN,
                domain=DomainCategory.OSINT,
                admiralty_code="B1",
                confidence=0.90,
                summary=f"LeakCheck ({found} records)",
                receipts=[rcpt],
            )
        )

    async def search_darkweb_ahmia(
        self,
        query: str,
        origin_node_id: str,
        hop_depth: int,
        fetch_pages: bool = False,
    ) -> List[str]:
        """Search the Tor dark-web for public mentions of a selector via Ahmia (keyless, clearnet).

        Ahmia (ahmia.fi) indexes Tor hidden services over the clearnet and filters known abuse
        material, so this needs no Tor daemon and no key. Each distinct .onion result becomes an
        OnionService node linked to the origin with MENTIONED_IN. When fetch_pages=True and a Tor
        SOCKS proxy is reachable, each hit is additionally fetched through Tor to capture its title.

        Returns the list of discovered .onion URLs (also usable by the `darkweb` CLI command).
        """
        clean_query = (query or "").strip()
        if not clean_query:
            return []
        self.graph.log(
            DomainCategory.OSINT,
            "DARKWEB_AHMIA_SEARCH",
            clean_query,
            f"Searching Ahmia clearnet Tor index for public .onion mentions of '{clean_query}'"
            + (" (fetching pages via Tor)" if fetch_pages else ""),
        )
        search_url = f"https://ahmia.fi/search/?q={quote_plus(clean_query)}"
        onion_urls: List[str] = []
        try:
            async with new_async_client(timeout=12.0, headers=self.headers, follow_redirects=True) as client:
                resp = await client.get(search_url)
                if resp.status_code != 200:
                    return []
                # v3 onion addresses are 56-char base32; also tolerate legacy 16-char v2 addresses.
                raw_hits = re.findall(r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", resp.text)
                for u in raw_hits:
                    if u not in onion_urls:
                        onion_urls.append(u)
        except Exception:
            return []

        if not onion_urls:
            return []

        tor_proxy = get_tor_proxy()
        for onion_url in onion_urls[:5]:
            onion_host = onion_url.split("://", 1)[-1].split("/")[0]
            title = ""
            if fetch_pages:
                page = await fetch_onion(onion_url, tor_proxy=tor_proxy, headers=self.headers)
                if page:
                    m = re.search(r"<title[^>]*>(.*?)</title>", page, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            rcpt = EvidenceReceipt(
                tool="ahmia_darkweb_search",
                domain=DomainCategory.OSINT,
                admiralty_code="C3",
                selector_strength=SelectorStrength.SOFT,
                source_url=search_url,
                extracted_fact=(
                    f"Ahmia dark-web index returned Tor hidden service '{onion_host}' for query '{clean_query}'"
                    + (f" (page title: '{title}')" if title else "")
                ),
                raw_snippet=f"ahmia hit: {onion_url}" + (f" | title={title}" if title else ""),
            )
            onion_id = f"onion:{onion_host.lower()}"
            self.graph.upsert_node(
                GraphNode(
                    id=onion_id,
                    label=f"🧅 {title or onion_host}",
                    entity_type=EntityType.ONION_SERVICE,
                    domain=DomainCategory.OSINT,
                    selector_strength=SelectorStrength.SOFT,
                    smoke_score=60.0,
                    risk_flags=["DARKWEB_ONION_MENTION"],
                    attributes={"onion_url": onion_url, "onion_host": onion_host, "title": title, "matched_query": clean_query},
                    receipts=[rcpt],
                    hop_depth=hop_depth,
                )
            )
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=onion_id,
                    relation=RelationType.MENTIONED_IN,
                    domain=DomainCategory.OSINT,
                    admiralty_code="C3",
                    confidence=0.45,
                    summary="Ahmia Dark-Web Mention",
                    receipts=[rcpt],
                )
            )
        return onion_urls

    async def investigate_phone_number(self, phone: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Phone Number OSINT Sweep:
        1. Normalize E.164 digits, country code, and area/exchange prefix.
        2. Run local `ignorant` CLI tool (if installed on Kali/Parrot/macOS) for non-alerting phone registration checks.
        3. Query Numverify API (if NUMVERIFY_API_KEY is configured in ~/.bunnyhole/api_keys.env) for carrier & VoIP/mobile line type.
        """
        digits = re.sub(r"\D", "", phone.strip())
        if len(digits) < 7:
            return
        e164 = f"+{digits}" if phone.strip().startswith("+") or len(digits) > 10 else f"+1{digits}"
        country_code = "1" if (len(digits) == 10 or (len(digits) == 11 and digits.startswith("1"))) else digits[:2]
        national_num = digits[-10:] if country_code == "1" else digits[len(country_code):]

        self.graph.log(
            DomainCategory.OSINT,
            "PHONE_OSINT_SWEEP",
            e164,
            f"Running E.164 normalization, Ignorant phone account check, and Numverify carrier lookup for '{e164}'",
        )

        phone_id = f"phone:{e164}"
        registered_platforms: List[str] = []
        carrier_info: Dict[str, Any] = {"e164": e164, "country_code": country_code, "national_number": national_num}

        # 1. Local `ignorant` CLI subprocess (non-alerting phone account check)
        ig_bin = shutil.which("ignorant")
        if ig_bin and national_num:
            try:
                proc = await asyncio.create_subprocess_exec(
                    ig_bin,
                    country_code,
                    national_num,
                    "--only-used",
                    "--no-color",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b = await _communicate(proc, 20.0)
                for line in stdout_b.decode("utf-8", errors="ignore").splitlines():
                    if "[+]" in line:
                        plat = line.split("[+]")[-1].strip()
                        if plat:
                            registered_platforms.append(plat)
            except Exception:
                pass

        # 2. Optional Numverify API carrier & line-type lookup
        num_key = os.environ.get("NUMVERIFY_API_KEY", "").strip()
        if num_key:
            try:
                async with new_async_client(timeout=8.0, headers=self.headers) as client:
                    n_resp = await client.get(
                        f"https://apilayer.net/api/validate?access_key={num_key}&number={digits}"
                    )
                    if n_resp.status_code == 200:
                        n_data = n_resp.json()
                        if n_data.get("valid"):
                            carrier_info["carrier"] = n_data.get("carrier")
                            carrier_info["line_type"] = n_data.get("line_type")
                            carrier_info["location"] = n_data.get("location")
                            carrier_info["country_name"] = n_data.get("country_name")
            except Exception:
                pass

        rcpt = EvidenceReceipt(
            tool="phone_osint_ignorant_numverify",
            domain=DomainCategory.OSINT,
            admiralty_code="B1" if (registered_platforms or carrier_info.get("carrier")) else "B2",
            selector_strength=SelectorStrength.STRONG,
            source_url=f"tel:{e164}",
            extracted_fact=(
                f"Phone selector {e164}: Registered platforms={registered_platforms or 'checked'}, "
                f"Carrier={carrier_info.get('carrier', 'N/A')}, LineType={carrier_info.get('line_type', 'N/A')}"
            ),
            raw_snippet=str({**carrier_info, "registered_platforms": registered_platforms})[:320],
        )
        flags = ["PHONE_SELECTOR_NORMALIZED"]
        if registered_platforms:
            flags.append("PHONE_PLATFORM_REGISTRATIONS_FOUND")
        if carrier_info.get("line_type") == "voip":
            flags.append("BURNER_OR_VOIP_LINE_DETECTED")

        self.graph.upsert_node(
            GraphNode(
                id=phone_id,
                label=f"📱 {e164} ({carrier_info.get('carrier') or f'CC +{country_code}'})",
                entity_type=EntityType.PHONE,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
                smoke_score=65.0 if registered_platforms else 45.0,
                risk_flags=flags,
                attributes={**carrier_info, "registered_platforms": registered_platforms},
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
        )
        if origin_node_id != phone_id:
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=phone_id,
                    relation=RelationType.LINKED_IDENTITY,
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    confidence=0.95,
                    summary=f"Phone {e164}",
                    receipts=[rcpt],
                )
            )

    async def investigate_credential_combo(self, cred_str: str, origin_node_id: str, hop_depth: int) -> Dict[str, Any]:
        """
        Leaked Credential / Password Hash Forensics:
        1. Parses `identifier:secret` (email:password, username:password, or hash).
        2. Uses k-Anonymity (first 5 hex chars of SHA-1) against HaveIBeenPwned Pwned Passwords API
           (`https://api.pwnedpasswords.com/range/{prefix5}`) to check global breach prevalence without
           transmitting the secret over the network.
        3. Creates a deterministic `tracker:pwd_hash:{sha256[:16]}` fingerprint node so any two accounts/emails
           reusing the same password deterministically link with `SHARES_FINGERPRINT_WITH` (A1, conf=0.99)!
        """
        raw = cred_str.strip()
        if ":" in raw:
            ident, secret = raw.split(":", 1)
        else:
            ident, secret = "", raw
        ident = ident.strip()
        secret = secret.strip()
        if not secret:
            return {"pwd_node_id": "", "pwned_count": 0}

        sha1_full = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()
        sha256_full = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        prefix5, suffix35 = sha1_full[:5], sha1_full[5:]

        self.graph.log(
            DomainCategory.OSINT,
            "CREDENTIAL_HASH_FORENSICS",
            ident or f"secret#{prefix5}",  # never log any characters of the plaintext secret
            f"Running HIBP k-Anonymity Pwned Passwords range check (SHA-1 prefix {prefix5}) & password-reuse fingerprint clustering",
        )

        pwned_count = 0
        lookup_ok = False
        try:
            async with new_async_client(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix5}")
                if resp.status_code == 200:
                    lookup_ok = True
                    for line in resp.text.splitlines():
                        if ":" in line:
                            h_suf, cnt_str = line.strip().split(":", 1)
                            if h_suf.upper() == suffix35:
                                try:
                                    pwned_count = int(cnt_str.strip())
                                except ValueError:
                                    pwned_count = 0
                                break
        except (httpx.HTTPError, OSError):
            lookup_ok = False

        pwd_node_id = f"tracker:pwd_hash:{sha256_full[:16]}"
        # A distinctive-reuse anchor requires a SUCCESSFUL lookup that returned a low breach count.
        # A failed lookup must never be treated as "rare" (that would fabricate a high-confidence link).
        is_unique_rare_pwd = lookup_ok and pwned_count < 50
        if not lookup_ok:
            status_label = "HIBP LOOKUP FAILED (prevalence unknown)"
            status_flag = "HIBP_LOOKUP_UNAVAILABLE"
            smoke = 50.0
        elif is_unique_rare_pwd:
            status_label = "HIGHLY DISTINCTIVE SECRET"
            status_flag = "DISTINCTIVE_PASSWORD_REUSE_ANCHOR"
            smoke = 84.0
        else:
            status_label = "COMMON BREACHED PASSWORD"
            status_flag = "KNOWN_BREACHED_PASSWORD"
            smoke = 45.0
        count_str = f"{pwned_count:,}" if lookup_ok else "unknown"
        rcpt = EvidenceReceipt(
            tool="hibp_k_anonymity_password_forensics",
            domain=DomainCategory.OSINT,
            admiralty_code="A1" if lookup_ok else "F6",
            selector_strength=SelectorStrength.STRONG,
            source_url=f"https://api.pwnedpasswords.com/range/{prefix5}",
            extracted_fact=(
                f"Credential Fingerprint (SHA-256 prefix {sha256_full[:12]}...) for '{ident or 'selector'}': "
                f"Global HIBP breach count = {count_str} ({status_label})"
            ),
            raw_snippet=f"ident={ident} | sha1_prefix={prefix5} | sha256_prefix={sha256_full[:16]} | pwned_count={count_str} | lookup_ok={lookup_ok}",
        )
        self.graph.upsert_node(
            GraphNode(
                id=pwd_node_id,
                label=f"🔑 Secret Hash: {sha256_full[:10]}... ({count_str} HIBP hits)",
                entity_type=EntityType.TRACKER_ID,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
                smoke_score=smoke,
                risk_flags=["CREDENTIAL_SECRET_FINGERPRINT", status_flag],
                attributes={
                    "sha256_prefix": sha256_full[:16],
                    "sha1_prefix": prefix5,
                    "hibp_breach_count": pwned_count if lookup_ok else None,
                    "hibp_lookup_ok": lookup_ok,
                    "is_distinctive": is_unique_rare_pwd,
                },
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
        )
        # Only a verified DISTINCTIVE secret justifies a fingerprint-clustering edge. Linking accounts
        # that merely share a common breached password ("123456") produces false co-attribution, so we
        # skip the edge for common/unknown secrets.
        if origin_node_id != pwd_node_id and is_unique_rare_pwd:
            self.graph.upsert_edge(
                GraphEdge(
                    source_id=origin_node_id,
                    target_id=pwd_node_id,
                    relation=RelationType.SHARES_FINGERPRINT_WITH,
                    domain=DomainCategory.OSINT,
                    admiralty_code="A1",
                    confidence=0.95,
                    summary=f"Distinctive Password Hash {sha256_full[:8]}...",
                    receipts=[rcpt],
                )
            )

        # Pivot the identifier part (email or username)
        if ident:
            if "@" in ident:
                await self.investigate_email_pivots(ident, pwd_node_id, hop_depth)
            else:
                await self.investigate_identity_and_handle(ident.lstrip("@"), pwd_node_id, hop_depth)

        return {
            "pwd_node_id": pwd_node_id,
            "sha256_prefix": sha256_full[:16],
            "pwned_count": pwned_count,
            "is_distinctive": is_unique_rare_pwd,
        }

