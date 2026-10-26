"""Agent 6: The Pathfinder / Link Sleuth (Dead-End Classification & Lateral Bypass Matrix, Adamic-Adar Missing Link Prediction, Joint Co-Occurrence Verification, Multi-Domain Pathfinding, Domain Entropy Keystone Broker Detection, and Louvain Syndicate Clustering)."""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import httpx
import networkx as nx

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    Lead,
    RelationType,
    SelectorStrength,
)

CORPORATE_STOPWORDS = {
    "inc", "llc", "ltd", "limited", "corp", "corporation", "company", "co",
    "holdings", "holding", "group", "global", "international", "capital",
    "ventures", "management", "partners", "partner", "lp", "llp", "plc", "sa", "ag",
    "gmbh", "bv", "nv", "foundation", "trust", "labs", "lab", "protocol", "network",
    "networks", "technologies", "technology", "tech", "systems", "system", "solutions",
    "services", "service", "the", "and", "for", "with", "from",
    # Common generic corporate/financial prefixes that cause false-positive stem collisions
    "first", "apex", "alpha", "beta", "omega", "prime", "united", "national",
    "american", "pacific", "atlantic", "digital", "crypto", "block", "blockchain",
    "chain", "token", "coin", "swap", "finance", "financial", "fintech", "defi",
    "asset", "assets", "investment", "investments", "investor", "investors",
    "advisors", "advisor", "advisory", "equity", "equities", "fund", "funds",
    "bank", "banking", "bancorp", "credit", "commerce", "commercial", "trade",
    "trading", "market", "markets", "exchange", "energy", "power", "solar",
    "real", "estate", "realty", "properties", "property", "medical", "health",
    "healthcare", "bio", "biotech", "pharma", "therapeutics", "media", "news",
    "press", "world", "worldwide", "north", "south", "east", "west", "central",
    "standard", "general", "universal", "premier", "supreme", "summit", "pinnacle",
    "horizon", "vanguard", "pioneer", "alliance", "union", "federation", "association",
    "institute", "center", "centre", "research", "science", "sciences", "scientific",
    "data", "cloud", "cyber", "security", "smart", "next", "future", "modern",
    "new", "old", "blue", "red", "green", "black", "white", "gold", "golden",
    "silver", "star", "sun", "moon", "earth", "sky", "one", "two", "three",
    "four", "five", "six", "seven", "eight", "nine", "ten", "core", "base",
    "meta", "omni", "nova", "nexus", "vertex", "matrix", "vector", "pulse",
    "wave", "spark", "edge", "peak", "crest", "bridge", "gate", "link", "node",
    "hub", "spot", "zone", "sphere", "realm", "works", "studio", "studios",
    "interactive", "enterprises", "enterprise", "industries", "industrial",
    "logistics", "transport", "shipping", "aviation", "air", "airlines", "jet",
    "motors", "auto", "automotive", "foods", "retail", "brands", "brand",
    "consulting", "consultants", "associates", "agency", "syndicate", "paper", "article", "docket", "case", "form", "sec", "deploy", "deployer",
    "contract", "wallet", "mother", "funder", "wayback", "wiki", "history",
}


def extract_entity_stem(name: str) -> str:
    """
    Extract a high-entropy distinctive stem token from a corporate, domain, or project name for orthogonal pivoting.
    Returns '' if the name consists solely of generic dictionary/corporate stopwords, preventing combinatorial graph explosion.
    """
    cleaned = re.sub(r"^[^\w]+", "", name.lower())
    cleaned = re.sub(r"^https?://(www\.)?", "", cleaned)
    cleaned = re.sub(r"^(https?|www)\b[\W_]*", "", cleaned)
    cleaned = re.sub(r"\.(com|org|io|fi|xyz|net|co|ai|eth|gg|app).*$", "", cleaned)
    tokens = [
        t for t in re.findall(r"[a-z0-9]{4,}", cleaned)
        if t not in CORPORATE_STOPWORDS and not t.isdigit()
    ]
    return tokens[0] if tokens else ""


class LinkSleuthAgent:
    """
    Dedicated interconnection & dead-end breaking specialist:
    1. Diagnoses stalled dead-end leaf nodes and injects orthogonal lateral bypass leads.
    2. Predicts hidden relationships via Adamic-Adar Triadic Closure over rare shared intermediaries.
    3. Runs live Joint Co-Occurrence searches ("Entity A" AND "Entity B") to verify why two nodes link.
    4. Computes Cross-Domain Paths, Domain-Entropy Keystone Brokers, and Louvain Syndicate Communities.
    """

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) BunnyholeInvestigativeEngine/0.2"
        }

    def break_dead_ends(self, current_hop: int) -> List[Lead]:
        """
        Scan the graph for Dead-End Leaf Nodes (degree <= 1) and generate Lateral Bypass Leads
        that flank around the wall via a different investigative domain.
        """
        if len(self.graph.nodes) < 2:
            return []

        undirected = nx.Graph(self.graph.nx_graph.to_undirected())
        injected_leads: List[Lead] = []

        for node_id, node in list(self.graph.nodes.items()):
            deg = undirected.degree(node_id) if node_id in undirected else 0
            if deg > 1 or node.hop_depth == 0:
                continue
            if "MASS_REGISTERED_AGENT_ADDRESS" in node.risk_flags or "SHARED_ANYCAST_CDN_IP" in node.risk_flags:
                continue

            # Classify Dead-End Wall Type & Execute Lateral Bypass Playbook
            raw_label = re.sub(r"^[^\w@0x]+", "", node.label).strip()
            stem = extract_entity_stem(raw_label)
            if not stem or len(stem) < 4:
                continue

            # Wall Type 1: Opaque Shell Company / Corporate Entity -> Pivot distinctive stem to OSINT (GitHub/Domain)
            if node.entity_type in (EntityType.SHELL_COMPANY, EntityType.ORGANIZATION):
                lead_osint = self.graph.add_lead(
                    Lead(
                        seed_value=stem,
                        lead_type="username",
                        selector_strength=SelectorStrength.SOFT,
                        target_agent=DomainCategory.OSINT,
                        priority_score=64.0,
                        reason=f"[DEAD-END BYPASS] Opaque corporate leaf '{node.label[:38]}' -> Flanking via high-entropy stem '{stem}' in GitHub/Keybase OSINT",
                        origin_node_id=node_id,
                        hop_depth=current_hop + 1,
                    )
                )
                injected_leads.append(lead_osint)

            # Wall Type 2: Redacted Domain -> Pivot distinctive stem to Corporate/SEC & News
            elif node.entity_type == EntityType.DOMAIN:
                lead_fiat = self.graph.add_lead(
                    Lead(
                        seed_value=stem,
                        lead_type="company",
                        selector_strength=SelectorStrength.SOFT,
                        target_agent=DomainCategory.FIAT,
                        priority_score=62.0,
                        reason=f"[DEAD-END BYPASS] Redacted domain leaf '{node.label}' -> Flanking via high-entropy stem '{stem}' in GLEIF/SEC EDGAR",
                        origin_node_id=node_id,
                        hop_depth=current_hop + 1,
                    )
                )
                injected_leads.append(lead_fiat)

            # Wall Type 3: Stalled Account / Handle -> Pivot to On-Chain ENS (.eth) hypothesis
            elif node.entity_type == EntityType.ACCOUNT:
                ens_candidate = f"{stem}.eth"
                lead_chain = self.graph.add_lead(
                    Lead(
                        seed_value=ens_candidate,
                        lead_type="wallet",
                        selector_strength=SelectorStrength.SOFT,
                        target_agent=DomainCategory.ONCHAIN,
                        priority_score=66.0,
                        reason=f"[DEAD-END BYPASS] Handle leaf '{node.label}' -> Testing ENS hypothesis '{ens_candidate}'",
                        origin_node_id=node_id,
                        hop_depth=current_hop + 1,
                    )
                )
                injected_leads.append(lead_chain)

        if injected_leads:
            self.graph.log(
                DomainCategory.SKEPTIC,
                "DEAD_END_BREAKER_FLANK",
                f"{len(injected_leads)} stalled leaves",
                f"Link Sleuth diagnosed dead-end leaf nodes and injected {len(injected_leads)} orthogonal lateral bypass pivots",
                level="discovery",
            )
        return injected_leads

    def predict_missing_links_adamic_adar(self) -> List[Dict[str, Any]]:
        """
        Compute Adamic-Adar Triadic Closure over non-adjacent node pairs (u, v) at distance 2:
        AA(u, v) = sum_{z in N(u) intersect N(v)} 1 / ln(max(2, deg(z)))
        Excludes noise intermediaries (Registered Agents & Anycast CDNs).
        """
        simple_g = nx.Graph()
        for u, v, data in self.graph.nx_graph.edges(data=True):
            u_node = self.graph.nodes.get(u)
            v_node = self.graph.nodes.get(v)
            if not u_node or not v_node:
                continue
            if "MASS_REGISTERED_AGENT_ADDRESS" in u_node.risk_flags or "MASS_REGISTERED_AGENT_ADDRESS" in v_node.risk_flags:
                continue
            if "SHARED_ANYCAST_CDN_IP" in u_node.risk_flags or "SHARED_ANYCAST_CDN_IP" in v_node.risk_flags:
                continue
            simple_g.add_edge(u, v)

        predictions: List[Dict[str, Any]] = []
        nodes_list = list(simple_g.nodes())
        for i in range(len(nodes_list)):
            for j in range(i + 1, len(nodes_list)):
                u, v = nodes_list[i], nodes_list[j]
                if simple_g.has_edge(u, v):
                    continue
                common = list(nx.common_neighbors(simple_g, u, v))
                if not common:
                    continue
                aa_score = sum(1.0 / math.log(max(2, simple_g.degree(z))) for z in common)
                u_node = self.graph.nodes[u]
                v_node = self.graph.nodes[v]
                # Boost score if u and v sit in different domains (Cross-Domain Triadic Closure!)
                cross_domain_bonus = 1.35 if u_node.domain != v_node.domain else 1.0
                final_score = round(aa_score * cross_domain_bonus, 3)
                shared_labels = [self.graph.nodes[z].label for z in common if z in self.graph.nodes]
                predictions.append({
                    "node_a_id": u,
                    "node_a_label": u_node.label,
                    "node_a_domain": u_node.domain.value,
                    "node_b_id": v,
                    "node_b_label": v_node.label,
                    "node_b_domain": v_node.domain.value,
                    "adamic_adar_score": final_score,
                    "shared_intermediaries": shared_labels,
                    "is_cross_domain": u_node.domain != v_node.domain,
                })

        predictions.sort(key=lambda x: (x["is_cross_domain"], x["adamic_adar_score"]), reverse=True)
        return predictions[:12]

    async def verify_interconnection_cooccurrence(
        self,
        entity_a: str,
        node_a_id: str,
        entity_b: str,
        node_b_id: str,
        hop_depth: int,
    ) -> Optional[GraphEdge]:
        """
        Actively investigate HOW two entities link by running a Joint Co-Occurrence Query:
        '"{entity_a}" "{entity_b}"' across Google News RSS & CourtListener federal dockets.
        """
        clean_a = re.sub(r"^[^\w@0x]+", "", entity_a).split("(")[0].strip()[:35]
        clean_b = re.sub(r"^[^\w@0x]+", "", entity_b).split("(")[0].strip()[:35]
        if not clean_a or not clean_b or clean_a.lower() == clean_b.lower():
            return None

        joint_query = f'"{clean_a}" "{clean_b}"'
        self.graph.log(
            DomainCategory.SKEPTIC,
            "LINK_COOCCURRENCE_PROBE",
            f"{clean_a} <-> {clean_b}",
            f"Link Sleuth probing direct co-occurrence evidence for {joint_query}",
        )
        rss_url = f"https://news.google.com/rss/search?q={quote_plus(joint_query)}&hl=en-US&gl=US&ceid=US:en"
        cl_url = f"https://www.courtlistener.com/api/rest/v4/search/?q={quote_plus(joint_query)}&type=r"
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers=self.headers) as client:
                # 1. Check CourtListener Federal Dockets first (A1/A2 Judicial Record)
                try:
                    cl_resp = await client.get(cl_url)
                    if cl_resp.status_code == 200:
                        cl_results = cl_resp.json().get("results", [])
                        if cl_results:
                            top_docket = cl_results[0]
                            c_name = top_docket.get("caseName") or top_docket.get("case_name") or "Federal Docket"
                            d_num = top_docket.get("docketNumber") or top_docket.get("docket_number") or "N/A"
                            d_date = top_docket.get("dateFiled") or top_docket.get("date_filed") or ""
                            d_url = "https://www.courtlistener.com" + (top_docket.get("absolute_url") or "")
                            rcpt = EvidenceReceipt(
                                tool="link_sleuth_courtlistener_cooccurrence",
                                domain=DomainCategory.SKEPTIC,
                                admiralty_code="A1",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=d_url,
                                extracted_fact=f"Federal Docket Co-Occurrence ({d_date}): '{clean_a}' and '{clean_b}' co-appear in '{c_name}' ({d_num})",
                                raw_snippet=f"Query={joint_query} | Case='{c_name}' | Docket={d_num}",
                            )
                            return self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=node_a_id,
                                    target_id=node_b_id,
                                    relation=RelationType.LITIGATED_IN,
                                    domain=DomainCategory.SKEPTIC,
                                    admiralty_code="A1",
                                    confidence=0.94,
                                    summary=f"Co-litigated in {c_name[:38]}...",
                                    event_date=d_date,
                                    receipts=[rcpt],
                                )
                            )
                except Exception:
                    pass

                # 2. Check Google News RSS Co-Occurrence
                resp = await client.get(rss_url)
                if resp.status_code == 200 and resp.text:
                    root = ET.fromstring(resp.text)
                    item = root.find(".//item")
                    if item is not None:
                        title = (item.findtext("title") or "").strip()
                        link = (item.findtext("link") or "").strip()
                        pub_date = (item.findtext("pubDate") or "").strip()
                        if title and link:
                            rcpt = EvidenceReceipt(
                                tool="link_sleuth_cooccurrence_verifier",
                                domain=DomainCategory.SKEPTIC,
                                admiralty_code="B2",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=link,
                                extracted_fact=f"Joint Co-Occurrence Verified ({pub_date}): '{clean_a}' and '{clean_b}' co-appear in '{title}'",
                                raw_snippet=f"Query={joint_query} | Hit='{title}' | URL={link}",
                            )
                            edge = self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=node_a_id,
                                    target_id=node_b_id,
                                    relation=RelationType.LINKED_IDENTITY,
                                    domain=DomainCategory.SKEPTIC,
                                    admiralty_code="B2",
                                    confidence=0.86,
                                    summary=f"Co-occurrence: {title[:42]}...",
                                    event_date=pub_date,
                                    receipts=[rcpt],
                                )
                            )
                            return edge
        except Exception:
            pass
        return None

    def find_interconnection_paths(
        self,
        source_query: Optional[str] = None,
        target_query: Optional[str] = None,
        max_hops: int = 6,
    ) -> List[Dict[str, Any]]:
        """
        Find and score multi-domain paths connecting entities in the graph ("Six Degrees of Bunnyhole").
        If source_query and target_query are omitted, automatically finds paths between the highest-smoke entities across different domains!
        """
        simple_g = nx.Graph(self.graph.nx_graph.to_undirected())
        if len(simple_g.nodes) < 2:
            return []

        def _match_node(q: str) -> Optional[str]:
            ql = q.lower().strip()
            for nid, n in self.graph.nodes.items():
                if ql in nid.lower() or ql in n.label.lower():
                    return nid
            return None

        pairs_to_check: List[Tuple[str, str]] = []
        if source_query and target_query:
            u = _match_node(source_query)
            v = _match_node(target_query)
            if u and v and u != v:
                pairs_to_check.append((u, v))
        else:
            # Automatically pick top high-smoke nodes from distinct domains to show how the web interconnects
            high_nodes = sorted(
                [
                    n for n in self.graph.nodes.values()
                    if "MASS_REGISTERED_AGENT_ADDRESS" not in n.risk_flags
                    and "SHARED_ANYCAST_CDN_IP" not in n.risk_flags
                ],
                key=lambda x: (x.is_cutout_broker, x.smoke_score, x.hop_depth),
                reverse=True,
            )[:10]
            for i in range(len(high_nodes)):
                for j in range(i + 1, len(high_nodes)):
                    if high_nodes[i].domain != high_nodes[j].domain or high_nodes[i].hop_depth != high_nodes[j].hop_depth:
                        pairs_to_check.append((high_nodes[i].id, high_nodes[j].id))

        discovered_paths: List[Dict[str, Any]] = []
        for u, v in pairs_to_check[:12]:
            if not nx.has_path(simple_g, u, v):
                continue
            try:
                for path in list(nx.all_simple_paths(simple_g, u, v, cutoff=max_hops))[:3]:
                    domains_in_path = {self.graph.nodes[nid].domain.value for nid in path if nid in self.graph.nodes}
                    step_labels = [self.graph.nodes[nid].label for nid in path if nid in self.graph.nodes]
                    edge_confs: List[float] = []
                    step_relations: List[str] = []
                    for k in range(len(path) - 1):
                        a, b = path[k], path[k + 1]
                        # Find matching directed edge in self.edges
                        matched_e = next(
                            (
                                e for e in self.graph.edges.values()
                                if (e.source_id == a and e.target_id == b) or (e.source_id == b and e.target_id == a)
                            ),
                            None,
                        )
                        if matched_e:
                            edge_confs.append(matched_e.confidence)
                            step_relations.append(f"{matched_e.relation.value} [{matched_e.admiralty_code}]")
                        else:
                            edge_confs.append(0.75)
                            step_relations.append("LINKED")

                    geom_mean = (math.prod(edge_confs) ** (1.0 / max(1, len(edge_confs)))) if edge_confs else 0.75
                    path_score = round(geom_mean * (1.0 + 0.15 * len(domains_in_path)), 3)
                    discovered_paths.append({
                        "from_id": u,
                        "from_label": self.graph.nodes[u].label,
                        "to_id": v,
                        "to_label": self.graph.nodes[v].label,
                        "hop_count": len(path) - 1,
                        "domains_crossed": list(domains_in_path),
                        "path_score": path_score,
                        "node_ids": path,
                        "step_labels": step_labels,
                        "step_relations": step_relations,
                    })
            except Exception:
                continue

        discovered_paths.sort(key=lambda x: (len(x["domains_crossed"]), x["path_score"]), reverse=True)
        return discovered_paths[:10]

    def analyze_interconnected_web(self) -> Dict[str, Any]:
        """
        Comprehensive interconnection synthesis:
        1. Domain-Entropy Keystone Connectors (nodes that bridge multiple investigative domains)
        2. Louvain / Greedy Modularity Syndicate Communities (clusters of tightly interconnected actors)
        3. Adamic-Adar Predicted Missing Links
        4. Top Cross-Domain Interconnection Paths
        """
        simple_g = nx.Graph(self.graph.nx_graph.to_undirected())
        keystone_brokers: List[Dict[str, Any]] = []

        for nid, node in self.graph.nodes.items():
            if nid not in simple_g or simple_g.degree(nid) < 2:
                continue
            if "MASS_REGISTERED_AGENT_ADDRESS" in node.risk_flags or "SHARED_ANYCAST_CDN_IP" in node.risk_flags:
                continue

            nbr_domains = [
                self.graph.nodes[nbr].domain.value
                for nbr in simple_g.neighbors(nid)
                if nbr in self.graph.nodes
            ]
            counts = Counter(nbr_domains)
            tot = len(nbr_domains)
            # Shannon Domain Entropy H_dom(v)
            entropy = -sum((c / tot) * math.log(c / tot) for c in counts.values()) if tot > 0 else 0.0
            if len(counts) >= 2 or node.betweenness_centrality >= 0.10:
                keystone_brokers.append({
                    "node_id": nid,
                    "label": node.label,
                    "entity_type": node.entity_type.value,
                    "primary_domain": node.domain.value,
                    "degree": tot,
                    "betweenness_centrality": node.betweenness_centrality,
                    "domain_entropy": round(entropy, 3),
                    "domains_bridged": list(counts.keys()),
                    "smoke_score": node.smoke_score,
                })

        keystone_brokers.sort(
            key=lambda x: (len(x["domains_bridged"]), x["domain_entropy"], x["betweenness_centrality"]),
            reverse=True,
        )

        # Greedy Modularity Syndicate Communities
        syndicate_cells: List[Dict[str, Any]] = []
        if len(simple_g.nodes) >= 3 and len(simple_g.edges) >= 2:
            try:
                communities = nx.community.greedy_modularity_communities(simple_g)
                for idx, comm in enumerate(communities[:6]):
                    members = [self.graph.nodes[m] for m in comm if m in self.graph.nodes]
                    if len(members) < 2:
                        continue
                    members.sort(key=lambda m: m.smoke_score, reverse=True)
                    syndicate_cells.append({
                        "cell_id": f"cell_{idx + 1}",
                        "size": len(members),
                        "lead_entity": members[0].label,
                        "avg_smoke_score": round(sum(m.smoke_score for m in members) / len(members), 1),
                        "domains": list({m.domain.value for m in members}),
                        "member_labels": [m.label for m in members[:8]],
                        "member_ids": [m.id for m in members],
                    })
            except Exception:
                pass

        return {
            "keystone_brokers": keystone_brokers[:10],
            "syndicate_cells": syndicate_cells,
            "predicted_missing_links": self.predict_missing_links_adamic_adar(),
            "cross_domain_paths": self.find_interconnection_paths(),
        }
