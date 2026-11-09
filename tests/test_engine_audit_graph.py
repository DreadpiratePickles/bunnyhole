"""Engine audit M5 + M6: edge merges keep data; guardrails are insertion-order independent."""

from __future__ import annotations

import itertools

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    ConfidenceTier,
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
)


def _rcpt(fact: str) -> EvidenceReceipt:
    return EvidenceReceipt(tool="onchain", domain=DomainCategory.ONCHAIN, source_url=f"https://x/{fact}", extracted_fact=fact)


def _wallets(g: InvestigationGraph) -> None:
    g.upsert_node(GraphNode(id="w:a", label="A", entity_type=EntityType.CRYPTO_WALLET, domain=DomainCategory.ONCHAIN))
    g.upsert_node(GraphNode(id="w:b", label="B", entity_type=EntityType.CRYPTO_WALLET, domain=DomainCategory.ONCHAIN))


def _transfer(amount: float, date: str, fact: str) -> GraphEdge:
    return GraphEdge(source_id="w:a", target_id="w:b", relation=RelationType.TRANSFERRED_TO,
                     domain=DomainCategory.ONCHAIN, admiralty_code="A1", confidence=0.95,
                     amount_usd=amount, event_date=date, summary=f"xfer {amount}", receipts=[_rcpt(fact)])


# ---- M5: data-preserving merge -----------------------------------------------------------------


def test_merge_aggregates_amount_dates_summary_and_receipts() -> None:
    g = InvestigationGraph("c", "q")
    _wallets(g)
    g.upsert_edge(_transfer(100.0, "2024-01-10", "t1"))
    edge = g.upsert_edge(_transfer(900.0, "2024-03-02", "t2"))
    assert edge.amount_usd == 1000.0
    assert edge.merged_count == 2
    assert edge.event_date_earliest == "2024-01-10"
    assert edge.event_date_latest == "2024-03-02"
    assert len(edge.receipts) == 2
    assert "xfer 100.0" in edge.summary and "xfer 900.0" in edge.summary


def test_remerge_of_same_event_is_idempotent() -> None:
    g = InvestigationGraph("c", "q")
    _wallets(g)
    same = _transfer(100.0, "2024-01-10", "t1")
    g.upsert_edge(same)
    g.upsert_edge(same)  # identical receipt id -> no double count
    edge = g.edges[same.id]
    assert edge.amount_usd == 100.0
    assert edge.merged_count == 1
    assert len(edge.receipts) == 1


# ---- M6: order-independent guardrails ----------------------------------------------------------


def _build_cdn_fingerprint_graph(edge_before_node: bool) -> InvestigationGraph:
    """A SHARES_FINGERPRINT_WITH edge to a CDN IP; optionally the edge is inserted before the IP node
    exists, to exercise the order-dependence the audit flagged."""
    g = InvestigationGraph("c", "q")
    g.upsert_node(GraphNode(id="dom:acme", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT))
    cdn = GraphNode(id="ip:cdn", label="104.16.0.1", entity_type=EntityType.IP_HOST, domain=DomainCategory.OSINT)
    edge = GraphEdge(source_id="dom:acme", target_id="ip:cdn", relation=RelationType.SHARES_FINGERPRINT_WITH,
                     domain=DomainCategory.OSINT, admiralty_code="A1", confidence=0.9,
                     receipts=[EvidenceReceipt(tool="shodan", domain=DomainCategory.OSINT, source_url="https://s", extracted_fact="same favicon")])
    if edge_before_node:
        g.upsert_edge(edge)
        g.upsert_node(cdn)
    else:
        g.upsert_node(cdn)
        g.upsert_edge(edge)
    return g


def test_guardrails_are_independent_of_insertion_order() -> None:
    confs = []
    tiers = []
    for edge_first in (True, False):
        g = _build_cdn_fingerprint_graph(edge_first)
        g.normalize_edges()
        e = g.edges[next(iter(g.edges))]
        confs.append(round(e.confidence, 3))
        tiers.append(e.tier)
    # Both orderings converge on the same downgraded confidence/tier.
    assert confs[0] == confs[1] <= 0.35
    assert tiers[0] == tiers[1] == ConfidenceTier.CIRCUMSTANTIAL


def test_downgraded_fingerprint_edge_does_not_score_h1_high() -> None:
    # Even inserted before its CDN node, the downgraded edge must not let H1 win on this evidence.
    g = _build_cdn_fingerprint_graph(edge_before_node=True)
    ach = g.run_skeptic_network_analytics()
    row = next(r for r in ach.matrix_rows if "SHARES_FINGERPRINT_WITH" in r.evidence_summary)
    assert row.diagnosticity == "LOW"
    assert row.h2_coincidence_shared_vendor == "++"


def test_guardrail_notes_append_not_overwrite() -> None:
    # A soft-to-soft link onto a registered-agent target must keep BOTH notes.
    g = InvestigationGraph("c", "q")
    g.upsert_node(GraphNode(id="p:soft", label="John", entity_type=EntityType.PERSON, domain=DomainCategory.OSINT, selector_strength=SelectorStrength.SOFT))
    g.upsert_node(GraphNode(id="loc:csc", label="251 Little Falls Drive, Wilmington, DE", entity_type=EntityType.LOCATION, domain=DomainCategory.FIAT, selector_strength=SelectorStrength.SOFT))
    edge = g.upsert_edge(GraphEdge(source_id="p:soft", target_id="loc:csc", relation=RelationType.REGISTERED_AT, domain=DomainCategory.FIAT, confidence=0.9))
    assert "Registered Agent" in (edge.skeptic_notes or "")
    assert "Soft-to-Soft" in (edge.skeptic_notes or "")


def test_final_edge_confidences_stable_under_shuffled_insertion() -> None:
    # Property-style: shuffle insertion order of a small fixture; final confidences/tiers are identical.
    def run(order) -> dict:
        g = InvestigationGraph("c", "q")
        nodes = {
            "dom:acme": GraphNode(id="dom:acme", label="acme.io", entity_type=EntityType.DOMAIN, domain=DomainCategory.OSINT),
            "ip:cdn": GraphNode(id="ip:cdn", label="104.16.0.1", entity_type=EntityType.IP_HOST, domain=DomainCategory.OSINT),
            "loc:csc": GraphNode(id="loc:csc", label="251 Little Falls Drive, Wilmington, DE", entity_type=EntityType.LOCATION, domain=DomainCategory.FIAT),
        }
        edges = [
            GraphEdge(source_id="dom:acme", target_id="ip:cdn", relation=RelationType.RESOLVES_TO, domain=DomainCategory.OSINT, admiralty_code="A1", confidence=0.9),
            GraphEdge(source_id="dom:acme", target_id="loc:csc", relation=RelationType.REGISTERED_AT, domain=DomainCategory.FIAT, admiralty_code="A1", confidence=0.9),
        ]
        items = list(nodes.values()) + edges
        for idx in order:
            item = items[idx]
            if isinstance(item, GraphNode):
                g.upsert_node(item)
            else:
                g.upsert_edge(item)
        g.normalize_edges()
        return {eid: (round(e.confidence, 3), e.tier.value) for eid, e in g.edges.items()}

    baseline = run(range(5))
    for perm in itertools.islice(itertools.permutations(range(5)), 12):
        assert run(perm) == baseline
