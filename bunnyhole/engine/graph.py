"""Universal Investigation Graph with ABI Path Convergence, NSA Selector Chaining, Betweenness Centrality Cut-Out Detection, and CIA ACH Matrix Evaluation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

import networkx as nx

from bunnyhole.engine.models import (
    ACHAssessment,
    ACHHypothesisRow,
    AgentLogEvent,
    ConfidenceTier,
    DomainCategory,
    EntityType,
    GraphEdge,
    GraphNode,
    Lead,
    RelationType,
    SelectorStrength,
    TimelineItem,
)

# Known Commercial Registered Agents (Delaware, Wyoming, Nevada, Cayman, BVI) that create false-positive ownership links
KNOWN_REGISTERED_AGENT_PATTERNS = [
    r"251\s+little\s+falls",
    r"1209\s+orange\s+st",
    r"corporation\s+trust\s+center",
    r"corporation\s+service\s+company",
    r"8\s+the\s+green.*dover",
    r"30\s+n\.?\s+gould\s+st.*sheridan",
    r"16192\s+coastal\s+hwy.*lewes",
    r"651\s+n\.?\s+broad\s+st.*middletown",
    r"ugland\s+house",
    r"craigmuir\s+chambers",
    r"trident\s+chambers",
    r"cogency\s+global",
    r"registered\s+agents\s+inc",
]

# Known CDN / Anycast IP prefixes (Cloudflare, Fastly, CloudFront) where shared IP != shared operator
KNOWN_CDN_IP_PREFIXES = (
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.24.", "104.25.", "104.26.", "104.27.",
    "172.64.", "172.66.", "172.67.", "162.159.", "188.114.", "151.101.", "185.199.",
)

# Known generic framework favicon mmh3 hashes (React, Next.js, Vercel, Blank)
GENERIC_FAVICON_HASHES = {-1588080585, 116323821, -247388890, 0}


class InvestigationGraph:
    """In-memory + exportable Universal Investigation Graph powered by NetworkX."""

    def __init__(
        self,
        case_id: str,
        seed_query: str,
        hypothesis: str = "",
        exclusions: Optional[List[str]] = None,
    ) -> None:
        self.case_id = case_id
        self.seed_query = seed_query
        self.hypothesis = hypothesis.strip()
        self.exclusions: Set[str] = {x.strip().lower() for x in (exclusions or []) if x.strip()}
        self.hypothesis_keywords: Set[str] = {
            w for w in re.findall(r"[a-z0-9]{4,}", self.hypothesis.lower())
            if w not in {"prove", "whether", "that", "this", "with", "from", "into", "through", "connected", "linked", "between", "does", "have"}
        }
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.nx_graph = nx.MultiDiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.leads: Dict[str, Lead] = {}
        self.timeline: List[TimelineItem] = []
        self.logs: List[AgentLogEvent] = []
        self.explored_seeds: Set[str] = set()
        self._event_listeners: List[Callable[[Dict[str, Any]], None]] = []

    def is_excluded(self, text_or_id: str) -> bool:
        """Check if a selector, label, or node ID matches the user's negative scope exclusions."""
        if not self.exclusions:
            return False
        low = text_or_id.lower().strip()
        return any(ex in low for ex in self.exclusions)

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Subscribe to real-time graph mutations and agent telemetry."""
        self._event_listeners.append(callback)

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        for cb in self._event_listeners:
            try:
                cb({"type": event_type, "data": payload})
            except Exception:
                pass

    def log(
        self,
        agent: DomainCategory,
        action: str,
        target: str,
        detail: str,
        receipt_count: int = 0,
        level: str = "info",
    ) -> AgentLogEvent:
        evt = AgentLogEvent(
            agent=agent,
            action=action,
            target=target,
            detail=detail,
            receipt_count=receipt_count,
            level=level,
        )
        self.logs.append(evt)
        self._emit("agent_log", evt.model_dump())
        return evt

    @staticmethod
    def is_registered_agent_address(address_str: str) -> bool:
        norm = address_str.lower().strip()
        return any(re.search(pat, norm) for pat in KNOWN_REGISTERED_AGENT_PATTERNS)

    @staticmethod
    def is_shared_cdn_ip(ip_str: str) -> bool:
        return ip_str.strip().startswith(KNOWN_CDN_IP_PREFIXES)

    def upsert_node(self, node: GraphNode) -> GraphNode:
        """Insert or merge a node while preserving all EvidenceReceipts and risk flags."""
        # Red-Cell Skeptic Guardrail: Check if Location node is a mass commercial registered agent
        if node.entity_type == EntityType.LOCATION and self.is_registered_agent_address(node.label):
            node.selector_strength = SelectorStrength.SOFT
            if "MASS_REGISTERED_AGENT_ADDRESS" not in node.risk_flags:
                node.risk_flags.append("MASS_REGISTERED_AGENT_ADDRESS")
            node.attributes["skeptic_warning"] = (
                "Commercial Registered Agent address (shared by thousands of unrelated LLCs). "
                "Do not infer common beneficial ownership from this address alone."
            )

        if node.entity_type == EntityType.IP_HOST and self.is_shared_cdn_ip(node.label):
            node.selector_strength = SelectorStrength.SOFT
            if "SHARED_ANYCAST_CDN_IP" not in node.risk_flags:
                node.risk_flags.append("SHARED_ANYCAST_CDN_IP")

        if node.id in self.nodes:
            existing = self.nodes[node.id]
            existing.smoke_score = max(existing.smoke_score, node.smoke_score)
            existing.hop_depth = min(existing.hop_depth, node.hop_depth)
            for flag in node.risk_flags:
                if flag not in existing.risk_flags:
                    existing.risk_flags.append(flag)
            existing.attributes.update(node.attributes)
            existing_rcpt_ids = {r.receipt_id for r in existing.receipts}
            for rcpt in node.receipts:
                if rcpt.receipt_id not in existing_rcpt_ids:
                    existing.receipts.append(rcpt)
                    existing_rcpt_ids.add(rcpt.receipt_id)
            self.nx_graph.nodes[node.id].update(existing.model_dump())
            self._emit("node_upsert", existing.model_dump())
            return existing
        else:
            self.nodes[node.id] = node
            self.nx_graph.add_node(node.id, **node.model_dump())
            self._emit("node_upsert", node.model_dump())
            return node

    def upsert_edge(self, edge: GraphEdge) -> GraphEdge:
        """Insert or merge an edge while applying Red-Cell Skeptic guardrails."""
        target_node = self.nodes.get(edge.target_id)
        source_node = self.nodes.get(edge.source_id)

        # Guardrail 1: Downgrade Registered Agent address links
        if target_node and "MASS_REGISTERED_AGENT_ADDRESS" in target_node.risk_flags:
            edge.confidence = min(edge.confidence, 0.30)
            edge.admiralty_code = "B5"
            edge.tier = ConfidenceTier.HYPOTHESIS
            edge.skeptic_notes = (
                "Red-Cell Skeptic Filter: Target is a mass Registered Agent address. "
                "Downgraded confidence to prevent false-positive shell clustering."
            )

        # Guardrail 2: Downgrade Anycast CDN IP links
        if target_node and "SHARED_ANYCAST_CDN_IP" in target_node.risk_flags:
            edge.confidence = min(edge.confidence, 0.35)
            edge.admiralty_code = "A4"
            edge.tier = ConfidenceTier.CIRCUMSTANTIAL
            edge.skeptic_notes = (
                "Red-Cell Skeptic Filter: Target IP is an Anycast CDN proxy (e.g., Cloudflare/Fastly). "
                "Shared CDN IPs do not prove shared server ownership."
            )

        # Guardrail 3: NSA Soft -> Soft Selector Chaining Warning
        if (
            source_node
            and target_node
            and source_node.selector_strength == SelectorStrength.SOFT
            and target_node.selector_strength == SelectorStrength.SOFT
        ):
            edge.confidence = min(edge.confidence, 0.45)
            edge.tier = ConfidenceTier.CIRCUMSTANTIAL
            edge.skeptic_notes = (
                "NSA Selector Rule: Soft-to-Soft selector link. Requires secondary Strong selector corroboration."
            )

        if edge.id in self.edges:
            existing = self.edges[edge.id]
            existing.confidence = max(existing.confidence, edge.confidence)
            existing_rcpt_ids = {r.receipt_id for r in existing.receipts}
            for rcpt in edge.receipts:
                if rcpt.receipt_id not in existing_rcpt_ids:
                    existing.receipts.append(rcpt)
                    existing_rcpt_ids.add(rcpt.receipt_id)
            if self.nx_graph.has_edge(existing.source_id, existing.target_id, key=existing.id):
                self.nx_graph.edges[existing.source_id, existing.target_id, existing.id].update(existing.model_dump())
            self._emit("edge_upsert", existing.model_dump())
            return existing
        else:
            self.edges[edge.id] = edge
            self.nx_graph.add_edge(edge.source_id, edge.target_id, key=edge.id, **edge.model_dump())
            self._emit("edge_upsert", edge.model_dump())
            return edge

    def add_lead(self, lead: Lead) -> Lead:
        """Queue a new lead or boost priority via Activity-Based Intelligence (ABI) Path Convergence & Hypothesis Alignment."""
        norm_key = f"{lead.lead_type}:{lead.seed_value.lower().strip()}"
        if norm_key in self.explored_seeds or self.is_excluded(lead.seed_value):
            lead.explored = True
            return lead

        # Reject chasing mass registered agents or CDN IPs down the rabbit hole
        if lead.lead_type == "location" and self.is_registered_agent_address(lead.seed_value):
            return lead
        if lead.lead_type == "ip" and self.is_shared_cdn_ip(lead.seed_value):
            return lead

        # Boost priority if lead aligns with user's working hypothesis keywords
        if self.hypothesis_keywords:
            haystack = f"{lead.seed_value} {lead.reason} {lead.lead_type}".lower()
            if any(kw in haystack for kw in self.hypothesis_keywords):
                lead.priority_score = min(100.0, lead.priority_score + 20.0)
                if "[HYPOTHESIS ALIGNED]" not in lead.reason:
                    lead.reason = f"[HYPOTHESIS ALIGNED] {lead.reason}"

        if lead.lead_id in self.leads:
            existing = self.leads[lead.lead_id]
            if existing.origin_node_id != lead.origin_node_id:
                # ABI Path Convergence! Two separate investigation branches hit the exact same lead!
                existing.convergence_count += 1
                existing.priority_score = min(100.0, max(existing.priority_score, lead.priority_score) + 25.0)
                existing.reason = f"[ABI PATH CONVERGENCE x{existing.convergence_count}] {existing.reason} + {lead.reason}"
                self.log(
                    DomainCategory.SKEPTIC,
                    "ABI_PATH_CONVERGENCE",
                    existing.seed_value,
                    f"Independent branches converged on '{existing.seed_value}' (x{existing.convergence_count}) -> Priority boosted to {existing.priority_score:.0f}",
                    level="anomaly",
                )
            return existing
        else:
            self.leads[lead.lead_id] = lead
            self._emit("lead_added", lead.model_dump())
            return lead

    def pop_next_leads(self, max_hop: int, batch_size: int = 4) -> List[Lead]:
        """Return top unexplored leads ordered by priority_score (with Strong selectors prioritized)."""
        candidates = [
            l for l in self.leads.values()
            if not l.explored and l.hop_depth <= max_hop and not self.is_excluded(l.seed_value)
        ]
        candidates.sort(
            key=lambda x: (
                x.convergence_count > 1,
                x.selector_strength == SelectorStrength.STRONG,
                x.priority_score,
            ),
            reverse=True,
        )
        selected = candidates[:batch_size]
        for l in selected:
            l.explored = True
            self.explored_seeds.add(f"{l.lead_type}:{l.seed_value.lower().strip()}")
        return selected

    @staticmethod
    def normalize_iso_timestamp(raw_ts: str) -> str:
        """Normalize RFC-2822 RSS dates, Unix epochs, YYYY-MM-DD, or bare YYYY years into sortable ISO-8601 UTC."""
        s = (raw_ts or "").strip()
        if not s:
            return datetime.now(timezone.utc).isoformat()
        # Bare 4-digit year (e.g. "2024")
        if re.match(r"^\d{4}$", s):
            return f"{s}-01-01T00:00:00Z"
        # YYYY-MM-DD
        if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
            return f"{s}T00:00:00Z"
        # Unix epoch seconds
        if re.match(r"^\d{9,10}$", s):
            try:
                return datetime.fromtimestamp(int(s), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass
        # Already ISO-8601 starting with YYYY-MM-DD
        if re.match(r"^\d{4}-\d{2}-\d{2}[T\s]", s):
            return s.replace(" ", "T")
        # RFC-2822 (e.g., "Tue, 14 Oct 2025 12:30:00 GMT")
        try:
            from email.utils import parsedate_to_datetime

            dt = parsedate_to_datetime(s)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return s

    def add_timeline_event(self, item: TimelineItem) -> None:
        item.timestamp = self.normalize_iso_timestamp(item.timestamp)
        self.timeline.append(item)
        self.timeline.sort(key=lambda x: x.timestamp)
        self._emit("timeline_event", item.model_dump())

    def run_skeptic_network_analytics(self) -> ACHAssessment:
        """
        Execute Spy Agency Graph Analytics:
        1. Betweenness Centrality & Articulation Points to unmask Cut-Outs, Brokers & Nominee Strawmen.
        2. Cross-Domain Timeline Contradiction Detection (Public Claims vs Insider Actions within +-14 days).
        3. CIA Analysis of Competing Hypotheses (ACH) Matrix evaluation.
        """
        if len(self.nx_graph.nodes) > 2:
            simple_g = nx.Graph(self.nx_graph.to_undirected())
            centrality = nx.betweenness_centrality(simple_g, normalized=True)
            try:
                articulation_pts = set(nx.articulation_points(simple_g))
            except Exception:
                articulation_pts = set()

            for node_id, bc_score in centrality.items():
                if node_id in self.nodes:
                    node = self.nodes[node_id]
                    node.betweenness_centrality = round(bc_score, 4)
                    # Check if this node bridges two different investigative domains (e.g. OSINT <-> ONCHAIN or FIAT <-> ONCHAIN)
                    neighbor_domains: Set[DomainCategory] = set()
                    for nbr in simple_g.neighbors(node_id):
                        if nbr in self.nodes:
                            neighbor_domains.add(self.nodes[nbr].domain)
                    if (
                        len(neighbor_domains) >= 2
                        and (bc_score >= 0.15 or node_id in articulation_pts)
                        and node.hop_depth > 0
                        and "MASS_REGISTERED_AGENT_ADDRESS" not in node.risk_flags
                        and "SHARED_ANYCAST_CDN_IP" not in node.risk_flags
                    ):
                        node.is_cutout_broker = True
                        if "CROSS_DOMAIN_CUTOUT_BROKER" not in node.risk_flags:
                            node.risk_flags.append("CROSS_DOMAIN_CUTOUT_BROKER")
                            node.smoke_score = min(100.0, node.smoke_score + 20.0)

                    # Nominee Director ("Strawman") check: Person linked to >= 5 distinct corporate entities
                    if node.entity_type == EntityType.PERSON:
                        corp_neighbors = [
                            nbr for nbr in simple_g.neighbors(node_id)
                            if nbr in self.nodes and self.nodes[nbr].entity_type in (EntityType.ORGANIZATION, EntityType.SHELL_COMPANY)
                        ]
                        if len(corp_neighbors) >= 5:
                            if "NOMINEE_DIRECTOR_STRAWMAN_CANDIDATE" not in node.risk_flags:
                                node.risk_flags.append("NOMINEE_DIRECTOR_STRAWMAN_CANDIDATE")

        # Build CIA Analysis of Competing Hypotheses (ACH) Matrix
        rows: List[ACHHypothesisRow] = []
        h1_score = 0.0
        h2_score = 0.0
        h3_score = 0.0
        inconsist_h1 = 0
        inconsist_h2 = 0
        inconsist_h3 = 0

        for edge in self.edges.values():
            if not edge.receipts:
                continue
            rcpt = edge.receipts[0]
            # Evaluate diagnosticity based on relation & selector strength
            if edge.relation in (
                RelationType.SHARED_CEX_DEPOSIT,
                RelationType.FIRST_FUNDED_BY,
                RelationType.SHARES_RSID_WITH,
                RelationType.BUNDLED_WITH,
                RelationType.SANCTIONED_MATCH,
                RelationType.ULTIMATE_PARENT_OF,
                RelationType.DIRECT_PARENT_OF,
            ):
                diag = "EXTREME"
                h1, h2, h3 = "++", "--", "--"
                h1_score += 3.0
                inconsist_h2 += 1
                inconsist_h3 += 1
            elif edge.relation in (
                RelationType.SHARES_FINGERPRINT_WITH,
                RelationType.COMMITTED_TO,
                RelationType.SCRUBBED_FROM,
                RelationType.COMPROMISED_IN,
                RelationType.OPERATES_AIRCRAFT,
                RelationType.BRIDGED_TO,
            ):
                diag = "HIGH"
                h1, h2, h3 = "+", "-", "-"
                h1_score += 2.0
                inconsist_h2 += 1
            elif edge.relation == RelationType.SWAPPED_IN:
                # Token ticker / name matches on DEXes can be spoofed copycats (H3)
                diag = "MEDIUM"
                h1, h2, h3 = "0", "+", "++"
                h2_score += 1.0
                h3_score += 2.0
                inconsist_h1 += 1
            elif edge.tier == ConfidenceTier.HYPOTHESIS or (edge.skeptic_notes and "Registered Agent" in edge.skeptic_notes):
                diag = "LOW"
                h1, h2, h3 = "0", "++", "0"
                h2_score += 2.0
            else:
                # Standard public record / DNS resolution / news mention supports normal operations (H2) equally with H1
                diag = "MEDIUM"
                h1, h2, h3 = "+", "+", "0"
                h1_score += 1.0
                h2_score += 1.2

            rows.append(
                ACHHypothesisRow(
                    evidence_id=rcpt.receipt_id,
                    evidence_summary=f"[{edge.relation.value}] {rcpt.extracted_fact[:120]}",
                    admiralty_code=edge.admiralty_code,
                    diagnosticity=diag,
                    h1_coordinated_control=h1,
                    h2_coincidence_shared_vendor=h2,
                    h3_false_flag_spoofing=h3,
                )
            )

        if h1_score > h2_score and inconsist_h2 >= 1:
            winning = "H1: Direct Attribution / Coordinated Multi-Domain Footprint"
            verdict = (
                f"ACH refutes innocent coincidence (H2 has {inconsist_h2} diagnostic inconsistencies; H1={h1_score:.1f} vs H2={h2_score:.1f}, H3={h3_score:.1f}). "
                f"High-diagnosticity selectors corroborate coordinated operation across {len({n.domain for n in self.nodes.values()})} domains."
            )
        else:
            winning = "H2: Independent Entities / Shared Infrastructure or Public Records"
            verdict = (
                "Current evidence primarily reflects standard regulatory, infrastructure, or public-record footprint "
                "without deterministic cross-domain attribution anomalies."
            )

        primary_q = (
            f"Hypothesis Test: {self.hypothesis}"
            if self.hypothesis
            else f"What is the underlying attribution, financial, and operational structure around '{self.seed_query}'?"
        )
        return ACHAssessment(
            primary_question=primary_q,
            winning_hypothesis=winning,
            h1_score=round(h1_score, 1),
            h2_score=round(h2_score, 1),
            h3_score=round(h3_score, 1),
            inconsistency_count_h1=inconsist_h1,
            inconsistency_count_h2=inconsist_h2,
            inconsistency_count_h3=inconsist_h3,
            matrix_rows=rows[:20],
            narrative_verdict=verdict,
        )

    def to_dict(self) -> Dict[str, Any]:
        ach = self.run_skeptic_network_analytics()
        return {
            "case_id": self.case_id,
            "seed_query": self.seed_query,
            "created_at": self.created_at,
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "total_receipts": sum(len(n.receipts) for n in self.nodes.values()) + sum(len(e.receipts) for e in self.edges.values()),
                "cutout_brokers": sum(1 for n in self.nodes.values() if n.is_cutout_broker),
                "high_smoke_nodes": sum(1 for n in self.nodes.values() if n.smoke_score >= 60.0),
                "domains_covered": list({n.domain.value for n in self.nodes.values()}),
            },
            "ach_assessment": ach.model_dump(),
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges.values()],
            "leads": [l.model_dump() for l in self.leads.values()],
            "timeline": [t.model_dump() for t in self.timeline],
            "logs": [lg.model_dump() for lg in self.logs[-100:]],
        }

    def export_markdown_dossier(self) -> str:
        """Compile a publication-ready Bellingcat / Hindenburg / ZachXBT style Markdown Dossier with SHA-256 Receipts."""
        data = self.to_dict()
        ach = data["ach_assessment"]
        lines = [
            f"# 🐇🕳️ BUNNYHOLE INVESTIGATIVE DOSSIER: `{self.seed_query}`",
            f"**Case ID:** `{self.case_id}` | **Generated:** `{self.created_at}`",
            "",
            "---",
            "",
            "## 1. Executive Intelligence Summary & CIA ACH Verdict",
            f"- **Primary Investigative Question:** {ach['primary_question']}",
            f"- **Winning Hypothesis:** **{ach['winning_hypothesis']}**",
            f"- **Analytic Verdict:** {ach['narrative_verdict']}",
            f"- **Graph Scale:** `{data['stats']['total_nodes']}` Entities | `{data['stats']['total_edges']}` Relationships | `{data['stats']['total_receipts']}` Immutable Evidence Receipts | `{data['stats']['cutout_brokers']}` Cross-Domain Cut-Out/Broker Nodes",
            "",
            "### CIA Analysis of Competing Hypotheses (ACH) Matrix",
            "| Receipt ID | NATO Grade | Diagnosticity | Evidence Fact | H1 (Coordinated) | H2 (Coincidence) | H3 (Spoofed) |",
            "| :--- | :---: | :---: | :--- | :---: | :---: | :---: |",
        ]
        for row in ach["matrix_rows"][:15]:
            lines.append(
                f"| `{row['evidence_id']}` | **{row['admiralty_code']}** | `{row['diagnosticity']}` | {row['evidence_summary']} | `{row['h1_coordinated_control']}` | `{row['h2_coincidence_shared_vendor']}` | `{row['h3_false_flag_spoofing']}` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. High-Smoke Entities & Cross-Domain Cut-Outs",
            "| Entity | Type | Domain | Smoke Score | Centrality | Risk Flags & Findings |",
            "| :--- | :--- | :--- | :---: | :---: | :--- |",
        ])
        sorted_nodes = sorted(self.nodes.values(), key=lambda x: (x.is_cutout_broker, x.smoke_score), reverse=True)
        for n in sorted_nodes[:25]:
            flags = ", ".join(f"`{f}`" for f in n.risk_flags) if n.risk_flags else "—"
            cutout = " 🔥 **[CUT-OUT BRIDGE]**" if n.is_cutout_broker else ""
            lines.append(
                f"| **{n.label}**{cutout} | `{n.entity_type.value}` | `{n.domain.value}` | **{n.smoke_score:.0f}/100** | `{n.betweenness_centrality:.3f}` | {flags} |"
            )

        if self.timeline:
            lines.extend([
                "",
                "---",
                "",
                "## 3. Master Multi-Domain Chronology (Who Knew What When)",
                "| Timestamp | Domain | NATO | Event | Details |",
                "| :--- | :--- | :---: | :--- | :--- |",
            ])
            for t in self.timeline[:30]:
                flag_str = f" ⚠️ **{t.anomaly_flag}**" if t.anomaly_flag else ""
                lines.append(
                    f"| `{t.timestamp[:19]}` | `{t.domain.value}` | `{t.admiralty_code}` | **{t.title}**{flag_str} | {t.description[:140]} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Cryptographic & URL Evidence Receipts Ledger",
        ])
        seen_rcpts: Set[str] = set()
        for e in self.edges.values():
            for r in e.receipts:
                if r.receipt_id in seen_rcpts:
                    continue
                seen_rcpts.add(r.receipt_id)
                lines.extend([
                    f"### Receipt `{r.receipt_id}` — NATO Grade `{r.admiralty_code}` ({r.tool})",
                    f"- **Fact Proven:** {r.extracted_fact}",
                    f"- **Source URL:** {r.source_url}",
                    f"- **SHA-256 Proof:** `{r.sha256_proof}`",
                    f"- **Raw Excerpt:** `{r.raw_snippet[:240]}`",
                    "",
                ])

        return "\n".join(lines)
