"""Universal Investigation Graph with ABI Path Convergence, NSA Selector Chaining, Betweenness Centrality Cut-Out Detection, and CIA ACH Matrix Evaluation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Set

import networkx as nx

from bunnyhole.engine.models import (
    ACHAssessment,
    ACHHypothesisRow,
    AgentLogEvent,
    AssumptionFragility,
    ConfidenceTier,
    DomainCategory,
    EntityType,
    GraphEdge,
    GraphNode,
    KeyAssumption,
    Lead,
    RelationType,
    SelectorStrength,
    TimelineItem,
    selector_token_match,
)

if TYPE_CHECKING:
    from bunnyhole.engine.pi_anchoring import AnchorVerdict, SubjectAnchors

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
        # PI stream, person subject only (None everywhere else, which leaves every behaviour below unchanged):
        # the investigator's anchors for the two-anchor rule, name-only candidates that were NOT linked, and the node
        # ids the analytics tables (paths, keystone brokers, predicted links, cut-outs) must not run through.
        self.pi_subject: Optional["SubjectAnchors"] = None
        self.set_aside_candidates: List[Dict[str, Any]] = []
        self.analytics_excluded_ids: Set[str] = set()

    def is_excluded(self, text_or_id: str) -> bool:
        """Check if a selector, label, or node ID matches the user's negative scope exclusions.

        Matches on token/label boundaries (domains by exact host or subdomain suffix, wallets/handles
        exactly, names by whole word), so a short exclusion like 'ab' no longer blocks 'cabinet.com'.
        """
        if not self.exclusions:
            return False
        low = text_or_id.lower().strip()
        return any(selector_token_match(ex, low) for ex in self.exclusions)

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

    def set_aside_candidate(
        self,
        agent: DomainCategory,
        kind: str,
        label: str,
        tool: str,
        source_url: str,
        verdict: "AnchorVerdict",
        receipts: Sequence[Any] = (),
    ) -> None:
        """Record a name-only candidate that was NOT linked to the subject (PI person subject).

        It is not a node and not an edge, so no analytics table can run through it; it stays in the JSON result
        (``set_aside_candidates``), is named in the identity notes, and is logged.
        """
        from bunnyhole.engine.pi_anchoring import candidate_record

        record = candidate_record(kind, label, tool, source_url, verdict, receipts)
        if any(r["tool"] == tool and r["label"] == label for r in self.set_aside_candidates):
            return
        self.set_aside_candidates.append(record)
        self.log(agent, "NAME_ONLY_MATCH_SET_ASIDE", label, record["reason"])

    def analysis_graph(self) -> "nx.Graph[Any]":
        """Undirected simple graph for the analytics tables: ``analytics_excluded_ids`` are left out."""
        simple_g = nx.Graph(self.nx_graph.to_undirected())
        simple_g.remove_nodes_from([n for n in self.analytics_excluded_ids if n in simple_g])
        return simple_g

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

    @staticmethod
    def _tier_for_confidence(confidence: float) -> ConfidenceTier:
        """Map a confidence score onto its tier (same thresholds as GraphEdge.model_post_init)."""
        if confidence >= 0.90:
            return ConfidenceTier.VERIFIED
        if confidence >= 0.65:
            return ConfidenceTier.CORROBORATED
        if confidence >= 0.35:
            return ConfidenceTier.CIRCUMSTANTIAL
        return ConfidenceTier.HYPOTHESIS

    @staticmethod
    def _append_note(existing: Optional[str], note: str) -> str:
        """Append a skeptic note without overwriting or duplicating an existing one."""
        if not existing:
            return note
        if note in existing:
            return existing
        return f"{existing} | {note}"

    def _apply_edge_guardrails(self, edge: GraphEdge) -> GraphEdge:
        """Apply the Red-Cell Skeptic guardrails to ``edge`` from the CURRENT node flags.

        Caps are idempotent (``min`` on confidence, weakest tier wins) and notes append rather than
        overwrite, so this runs both on insert and on a final normalisation pass — making the result
        independent of the order edges and their nodes were inserted.
        """
        target_node = self.nodes.get(edge.target_id)
        source_node = self.nodes.get(edge.source_id)
        tier_rank = {
            ConfidenceTier.VERIFIED: 3,
            ConfidenceTier.CORROBORATED: 2,
            ConfidenceTier.CIRCUMSTANTIAL: 1,
            ConfidenceTier.HYPOTHESIS: 0,
        }

        def cap_tier(tier: ConfidenceTier) -> None:
            if tier_rank[tier] < tier_rank[edge.tier]:
                edge.tier = tier

        # Guardrail 1: Downgrade Registered Agent address links
        if target_node and "MASS_REGISTERED_AGENT_ADDRESS" in target_node.risk_flags:
            edge.confidence = min(edge.confidence, 0.30)
            edge.admiralty_code = "B5"
            cap_tier(ConfidenceTier.HYPOTHESIS)
            edge.skeptic_notes = self._append_note(
                edge.skeptic_notes,
                "Red-Cell Skeptic Filter: Target is a mass Registered Agent address. "
                "Downgraded confidence to prevent false-positive shell clustering.",
            )

        # Guardrail 2: Downgrade Anycast CDN IP links
        if target_node and "SHARED_ANYCAST_CDN_IP" in target_node.risk_flags:
            edge.confidence = min(edge.confidence, 0.35)
            edge.admiralty_code = "A4"
            cap_tier(ConfidenceTier.CIRCUMSTANTIAL)
            edge.skeptic_notes = self._append_note(
                edge.skeptic_notes,
                "Red-Cell Skeptic Filter: Target IP is an Anycast CDN proxy (e.g., Cloudflare/Fastly). "
                "Shared CDN IPs do not prove shared server ownership.",
            )

        # Guardrail 3: NSA Soft -> Soft Selector Chaining Warning
        if (
            source_node
            and target_node
            and source_node.selector_strength == SelectorStrength.SOFT
            and target_node.selector_strength == SelectorStrength.SOFT
        ):
            edge.confidence = min(edge.confidence, 0.45)
            cap_tier(ConfidenceTier.CIRCUMSTANTIAL)
            edge.skeptic_notes = self._append_note(
                edge.skeptic_notes,
                "NSA Selector Rule: Soft-to-Soft selector link. Requires secondary Strong selector corroboration.",
            )
        return edge

    def normalize_edges(self) -> None:
        """Re-apply every guardrail to every edge against the final node state.

        This makes edge confidences/tiers independent of insertion order: an edge inserted before
        its target node was flagged (registered agent / CDN) is still downgraded here.
        """
        for edge in self.edges.values():
            self._apply_edge_guardrails(edge)
            if self.nx_graph.has_edge(edge.source_id, edge.target_id, key=edge.id):
                self.nx_graph.edges[edge.source_id, edge.target_id, edge.id].update(edge.model_dump())

    @staticmethod
    def _min_date(*dates: Optional[str]) -> Optional[str]:
        vals = [d for d in dates if d]
        return min(vals) if vals else None

    @staticmethod
    def _max_date(*dates: Optional[str]) -> Optional[str]:
        vals = [d for d in dates if d]
        return max(vals) if vals else None

    def upsert_edge(self, edge: GraphEdge) -> GraphEdge:
        """Insert or merge an edge while applying Red-Cell Skeptic guardrails.

        A merge KEEPS data instead of discarding it: amounts are summed, event dates widened to an
        earliest/latest span, the strongest admiralty grade kept, distinct summaries concatenated,
        and every contributor's receipts retained. Re-merging the SAME observation (no new receipts)
        is idempotent and does not double-count the amount or the merged_count.
        """
        self._apply_edge_guardrails(edge)
        if edge.event_date_earliest is None:
            edge.event_date_earliest = edge.event_date
        if edge.event_date_latest is None:
            edge.event_date_latest = edge.event_date

        if edge.id in self.edges:
            existing = self.edges[edge.id]
            existing_rcpt_ids = {r.receipt_id for r in existing.receipts}
            new_receipts = [r for r in edge.receipts if r.receipt_id not in existing_rcpt_ids]
            # A contribution counts only when it brings at least one receipt not already seen, OR the
            # incoming edge carries no receipts at all (nothing to dedup on). Same-event re-merges
            # (all receipts already present) are idempotent.
            is_new_contribution = bool(new_receipts) or not edge.receipts
            for rcpt in new_receipts:
                existing.receipts.append(rcpt)
                existing_rcpt_ids.add(rcpt.receipt_id)

            existing.confidence = max(existing.confidence, edge.confidence)
            # Strongest admiralty grade (A1 < B5 lexicographically = stronger) unless a guardrail pinned it.
            existing.admiralty_code = min(existing.admiralty_code, edge.admiralty_code)
            existing.tier = self._tier_for_confidence(existing.confidence)
            self._apply_edge_guardrails(existing)  # re-cap after confidence/tier recompute
            existing.event_date_earliest = self._min_date(existing.event_date_earliest, edge.event_date_earliest)
            existing.event_date_latest = self._max_date(existing.event_date_latest, edge.event_date_latest)

            if is_new_contribution:
                existing.merged_count += 1
                if edge.amount_usd is not None:
                    existing.amount_usd = (existing.amount_usd or 0.0) + edge.amount_usd
                if edge.summary and edge.summary not in existing.summary:
                    merged_summary = f"{existing.summary} | {edge.summary}" if existing.summary else edge.summary
                    existing.summary = merged_summary[:600]  # bounded

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
    def normalize_iso_timestamp_full(raw_ts: str) -> tuple[Optional[str], Optional[str]]:
        """Normalize any supported timestamp into UTC ISO-8601 ``...Z``.

        Returns ``(iso_or_None, anomaly_flag_or_None)``. Supported: bare year, ``YYYY-MM-DD``,
        Unix epoch seconds (9-10 digits) and milliseconds (13 digits), full ISO-8601 with a ``Z`` or
        numeric offset (converted to UTC), and RFC-2822 (``-0000`` / missing zone read as UTC, not
        local). An empty string defaults to now (flagged); anything unparseable or an impossible date
        (``2025-13-45``) returns ``(None, flag)`` and never raises.
        """
        from email.utils import parsedate_to_datetime

        def to_utc_z(dt: datetime) -> str:
            if dt.tzinfo is None:  # RFC-2822 '-0000' / naive: treat as UTC, never shift by local zone
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        s = (raw_ts or "").strip()
        if not s:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "EMPTY_TIMESTAMP_DEFAULTED_TO_NOW"
        if re.match(r"^\d{4}$", s):
            return f"{s}-01-01T00:00:00Z", None
        if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
            try:
                datetime.strptime(s, "%Y-%m-%d")  # reject impossible dates (2025-13-45)
            except ValueError:
                return None, "INVALID_TIMESTAMP"
            return f"{s}T00:00:00Z", None
        if re.match(r"^\d{13}$", s):  # epoch milliseconds
            try:
                return to_utc_z(datetime.fromtimestamp(int(s) / 1000, tz=timezone.utc)), None
            except (ValueError, OverflowError, OSError):
                return None, "INVALID_TIMESTAMP"
        if re.match(r"^\d{9,10}$", s):  # epoch seconds
            try:
                return to_utc_z(datetime.fromtimestamp(int(s), tz=timezone.utc)), None
            except (ValueError, OverflowError, OSError):
                return None, "INVALID_TIMESTAMP"
        if re.match(r"^\d{4}-\d{2}-\d{2}[T\s]", s):  # ISO-8601 with time (any offset incl. +02:00 / Z)
            try:
                iso = s.replace(" ", "T").replace("Z", "+00:00")
                return to_utc_z(datetime.fromisoformat(iso)), None
            except ValueError:
                return None, "INVALID_TIMESTAMP"
        try:  # RFC-2822 (e.g., "Tue, 14 Oct 2025 12:30:00 GMT" / "... -0000")
            return to_utc_z(parsedate_to_datetime(s)), None
        except (ValueError, TypeError):
            return None, "UNPARSEABLE_TIMESTAMP"

    @classmethod
    def normalize_iso_timestamp(cls, raw_ts: str) -> str:
        """Back-compatible string form: the normalized UTC ISO-8601 timestamp, or the raw input when
        it could not be parsed (so a value is always returned and never crashes)."""
        iso, _flag = cls.normalize_iso_timestamp_full(raw_ts)
        return iso if iso is not None else (raw_ts or "").strip()

    def add_timeline_event(self, item: TimelineItem) -> None:
        iso, flag = self.normalize_iso_timestamp_full(item.timestamp)
        item.timestamp = iso if iso is not None else ""
        if flag and not item.anomaly_flag:
            item.anomaly_flag = flag
        self.timeline.append(item)
        self.timeline.sort(key=lambda x: x.timestamp or "")
        self._emit("timeline_event", item.model_dump())

    def run_skeptic_network_analytics(self) -> ACHAssessment:
        """
        Execute Spy Agency Graph Analytics:
        1. Betweenness Centrality & Articulation Points to unmask Cut-Outs, Brokers & Nominee Strawmen.
        2. Cross-Domain Timeline Contradiction Detection (Public Claims vs Insider Actions within +-14 days).
        3. CIA Analysis of Competing Hypotheses (ACH) Matrix evaluation.
        """
        # Final guardrail normalisation: downgrade every edge from the final node state before the ACH
        # reads it, so a downgraded (CDN / registered-agent / soft-soft) edge cannot score as HIGH.
        self.normalize_edges()
        for excluded_id in self.analytics_excluded_ids:  # a set-aside node is never a cut-out broker
            if excluded_id in self.nodes:
                self.nodes[excluded_id].is_cutout_broker = False
        if len(self.nx_graph.nodes) > 2:
            simple_g = self.analysis_graph()
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
            # A guardrail-downgraded edge (CDN / registered agent / soft-soft) has had its confidence
            # capped below 0.5: read that downgrade FIRST, so a SHARES_FINGERPRINT_WITH edge to a CDN
            # IP supports the coincidence hypothesis (H2), not coordinated control (H1).
            if edge.confidence < 0.5:
                diag = "LOW"
                h1, h2, h3 = "0", "++", "0"
                h2_score += 2.0
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
                continue
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
            key_assumptions=self.run_key_assumptions_check(
                winning, h1_score, h2_score, h3_score
            ),
        )

    def run_key_assumptions_check(
        self,
        winning_hypothesis: str,
        h1_score: float,
        h2_score: float,
        h3_score: float,
    ) -> List[KeyAssumption]:
        """CIA Key Assumptions Check (Structured Analytic Technique).

        Surfaces the working assumptions the winning hypothesis rests on and rates how
        fragile each one is, deterministically, from the graph's own evidence profile.
        This operationalizes 'findings are leads, not verdicts': the reader sees exactly
        which assumptions, if wrong, would overturn the lead.
        """
        edges = list(self.edges.values())
        nodes = list(self.nodes.values())
        all_receipts = [r for n in nodes for r in n.receipts] + [
            r for e in edges for r in e.receipts
        ]

        pivot_nodes = [n for n in nodes if n.hop_depth > 0] or nodes
        soft_pivots = sum(1 for n in pivot_nodes if n.selector_strength == SelectorStrength.SOFT)
        soft_frac = soft_pivots / len(pivot_nodes) if pivot_nodes else 0.0

        low_grade = sum(1 for r in all_receipts if r.admiralty_code[:1] in ("D", "E", "F"))
        low_grade_frac = low_grade / len(all_receipts) if all_receipts else 0.0

        verified_edges = sum(1 for e in edges if e.tier == ConfidenceTier.VERIFIED)
        hypothesis_edges = sum(1 for e in edges if e.tier == ConfidenceTier.HYPOTHESIS)
        cutouts = sum(1 for n in nodes if n.is_cutout_broker)
        ach_margin = abs(h1_score - h2_score)
        attribution_claim = winning_hypothesis.startswith("H1")

        def level(fragile: bool, supported: bool) -> AssumptionFragility:
            if fragile:
                return AssumptionFragility.FRAGILE
            return AssumptionFragility.SUPPORTED if supported else AssumptionFragility.SOLID

        assumptions: List[KeyAssumption] = []

        # 1. Selector uniqueness — the backbone of all attribution.
        assumptions.append(
            KeyAssumption(
                assumption="STRONG selectors (wallet, LEI, CIK, RSID, ICAO hex, email) each resolve to a single real-world operator.",
                rationale="Contact-chaining treats STRONG selectors as near-zero-collision identities when fusing nodes across domains.",
                fragility=level(soft_frac >= 0.5, soft_frac >= 0.25),
                if_wrong="If SOFT selectors are carrying the attribution, fused identities may collapse into distinct people/entities and the chain breaks.",
                supporting_signal=f"{soft_pivots}/{len(pivot_nodes)} pivot nodes rely on SOFT selectors ({soft_frac:.0%}).",
            )
        )

        # 2. Source reliability grading reflects reality.
        assumptions.append(
            KeyAssumption(
                assumption="Assigned NATO Admiralty reliability grades accurately reflect each source's trustworthiness.",
                rationale="Confidence tiers and the ACH weighting inherit directly from per-receipt Admiralty codes.",
                fragility=level(low_grade_frac >= 0.33, low_grade_frac >= 0.1),
                if_wrong="If low-grade (D/E/F) sources are over-trusted, corroboration is illusory and the verdict is overstated.",
                supporting_signal=f"{low_grade}/{len(all_receipts)} receipts are graded D/E/F ({low_grade_frac:.0%}).",
            )
        )

        # 3. Shared infrastructure is not mistaken for coordination.
        assumptions.append(
            KeyAssumption(
                assumption="Shared-infrastructure links (CDN IPs, registered agents, mass hosts) were correctly down-weighted, not read as attribution.",
                rationale="Red-Cell guards flag known false-positive traps so coincidental co-location does not inflate smoke scores.",
                fragility=level(False, cutouts == 0 and attribution_claim),
                if_wrong="If a flagged hub is in fact a benign shared service, any attribution routed through it is a false positive.",
                supporting_signal=f"{cutouts} cross-domain cut-out broker(s) flagged by betweenness analysis.",
            )
        )

        # 4. Temporal authenticity — dates are genuine.
        assumptions.append(
            KeyAssumption(
                assumption="Timestamps, filing dates, and on-chain/transponder times are authentic and not backdated or spoofed.",
                rationale="Timeline contradiction detection and event ordering assume the recorded times are truthful.",
                fragility=AssumptionFragility.SUPPORTED,
                if_wrong="Backdated filings or spoofed memos/transponder times would invert cause-and-effect in the narrative.",
                supporting_signal="Not independently verifiable from open sources; assumed absent contrary evidence.",
            )
        )

        # 5. Completeness — the unexplored frontier hides no disconfirming fact.
        thin_attribution = attribution_claim and (verified_edges < 2 or ach_margin < 2.0)
        assumptions.append(
            KeyAssumption(
                assumption="No disconfirming evidence is hiding in unexplored leads; what was collected is representative.",
                rationale="The verdict is drawn from the traversed subgraph, not an exhaustive census of the open-source space.",
                fragility=level(thin_attribution, hypothesis_edges > verified_edges),
                if_wrong="A single strong disconfirming source left unexplored could flip the ACH winner.",
                supporting_signal=f"{verified_edges} VERIFIED vs {hypothesis_edges} HYPOTHESIS-tier edges; ACH margin |H1-H2|={ach_margin:.1f}.",
            )
        )

        return assumptions

    def to_dict(self) -> Dict[str, Any]:
        ach = self.run_skeptic_network_analytics()
        out = self._to_dict(ach)
        if self.set_aside_candidates:
            out["set_aside_candidates"] = list(self.set_aside_candidates)
        return out

    def _to_dict(self, ach: ACHAssessment) -> Dict[str, Any]:
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

    @staticmethod
    def _md_cell(text: Any) -> str:
        """Escape a value for a Markdown table cell: pipes and newlines would otherwise break the row."""
        return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

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

        # CIA Key Assumptions Check — the assumptions the verdict rests on (leads, not verdicts)
        key_assumptions = ach.get("key_assumptions") or []
        if key_assumptions:
            _frag_icon = {"FRAGILE": "🔴", "SUPPORTED": "🟡", "SOLID": "🟢"}

            def _frag(ka: Dict[str, Any]) -> str:
                return getattr(ka["fragility"], "value", ka["fragility"])

            fragile_n = sum(1 for ka in key_assumptions if _frag(ka) == "FRAGILE")
            lines.extend([
                "",
                "### CIA Key Assumptions Check",
                f"_The verdict above holds only while these assumptions hold. **{fragile_n}** rated 🔴 FRAGILE — findings are leads, not verdicts._",
                "",
                "| | Fragility | Working Assumption | If Wrong | Signal |",
                "| :---: | :---: | :--- | :--- | :--- |",
            ])
            for ka in key_assumptions:
                frag = _frag(ka)
                icon = _frag_icon.get(frag, "🟡")
                lines.append(
                    f"| {icon} | `{frag}` | {ka['assumption']} | {ka['if_wrong']} | {ka['supporting_signal']} |"
                )

        # ODNI PAI/CAI source-provenance catalog
        all_rcpts = [r for n in self.nodes.values() for r in n.receipts] + [
            r for e in self.edges.values() for r in e.receipts
        ]
        pai_n = sum(1 for r in all_rcpts if (r.source_class.value if r.source_class else "PAI") == "PAI")
        cai_n = len(all_rcpts) - pai_n
        cai_srcs = sorted({r.tool for r in all_rcpts if r.source_class and r.source_class.value == "CAI"})
        lines.extend([
            "",
            "### Source Provenance — PAI vs CAI (ODNI IC OSINT Strategy)",
            f"- **PAI (Publicly Available Information):** `{pai_n}` receipts — keyless public web, registries, blockchains, transponders.",
            f"- **CAI (Commercially Available Information):** `{cai_n}` receipts"
            + (f" via `{', '.join(cai_srcs)}`." if cai_srcs else " — none; this dossier rests entirely on public data."),
        ])

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
            flags = ", ".join(f"`{self._md_cell(f)}`" for f in n.risk_flags) if n.risk_flags else "—"
            cutout = " 🔥 **[CUT-OUT BRIDGE]**" if n.is_cutout_broker else ""
            lines.append(
                f"| **{self._md_cell(n.label)}**{cutout} | `{n.entity_type.value}` | `{n.domain.value}` | **{n.smoke_score:.0f}/100** | `{n.betweenness_centrality:.3f}` | {flags} |"
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
                    f"| `{t.timestamp[:19]}` | `{t.domain.value}` | `{t.admiralty_code}` | "
                    f"**{self._md_cell(t.title)}**{flag_str} | {self._md_cell(t.description[:140])} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Cryptographic & URL Evidence Receipts Ledger",
        ])
        seen_rcpts: Set[str] = set()
        # Both edge AND node receipts belong in the ledger — node receipts (seed anchors, cross-case
        # memory hits, sanctions screens) were previously omitted, so their proofs never appeared.
        receipt_sources = [r for e in self.edges.values() for r in e.receipts] + [
            r for n in self.nodes.values() for r in n.receipts
        ]
        for r in receipt_sources:
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
