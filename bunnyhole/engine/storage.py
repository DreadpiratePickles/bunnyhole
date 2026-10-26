"""Persistent SQLite Case Store & Cross-Case Entity Memory (~/.bunnyhole/cases.db)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bunnyhole.arsenal.manager import BUNNYHOLE_CONFIG_DIR
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EvidenceReceipt, SelectorStrength

CASES_DB_PATH = BUNNYHOLE_CONFIG_DIR / "cases.db"


class CaseStore:
    """
    SQLite-backed persistence layer for Bunnyhole investigations and Cross-Case Entity Memory.
    Whenever an entity (wallet, domain, IP, corporate LEI, email, handle) discovered in Case B
    was previously recorded in Case A, CaseStore flags a CROSS_CASE_ENTITY_HIT and links both cases.
    """

    def __init__(self, db_path: Path = CASES_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    seed_query TEXT NOT NULL,
                    gear TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    total_nodes INTEGER DEFAULT 0,
                    total_edges INTEGER DEFAULT 0,
                    total_receipts INTEGER DEFAULT 0,
                    winning_hypothesis TEXT DEFAULT '',
                    result_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entity_sightings (
                    entity_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    seed_query TEXT NOT NULL,
                    label TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    smoke_score REAL DEFAULT 0.0,
                    sighted_at TEXT NOT NULL,
                    PRIMARY KEY (entity_id, case_id)
                );

                CREATE INDEX IF NOT EXISTS idx_entity_sightings_id ON entity_sightings(entity_id);
                CREATE INDEX IF NOT EXISTS idx_cases_seed ON cases(seed_query);
                """
            )

    def correlate_cross_case_entities(self, graph: InvestigationGraph) -> List[Dict[str, Any]]:
        """
        Check if any entity in the current InvestigationGraph was previously seen in earlier cases
        with a DIFFERENT seed_query. Enriches matching nodes with a CROSS_CASE_ENTITY_HIT flag & receipt.
        """
        hits: List[Dict[str, Any]] = []
        if not graph.nodes:
            return hits

        with self._connect() as conn:
            for node_id, node in list(graph.nodes.items()):
                if node_id.startswith("seed:"):
                    continue
                rows = conn.execute(
                    """
                    SELECT case_id, seed_query, label, smoke_score, sighted_at
                    FROM entity_sightings
                    WHERE entity_id = ? AND case_id != ?
                    ORDER BY sighted_at DESC
                    LIMIT 5
                    """,
                    (node_id, graph.case_id),
                ).fetchall()

                if not rows:
                    continue

                prior_cases = [
                    {
                        "case_id": r["case_id"],
                        "seed_query": r["seed_query"],
                        "sighted_at": r["sighted_at"],
                        "prior_smoke_score": r["smoke_score"],
                    }
                    for r in rows
                ]
                # Check if at least one prior case had a different seed query (true cross-case correlation!)
                distinct_seeds = {r["seed_query"] for r in rows if r["seed_query"].lower() != graph.seed_query.lower()}
                prior_summary = ", ".join(f"{r['case_id']} ('{r['seed_query']}')" for r in rows[:3])

                if "CROSS_CASE_ENTITY_HIT" not in node.risk_flags:
                    node.risk_flags.append("CROSS_CASE_ENTITY_HIT")
                if distinct_seeds:
                    node.smoke_score = min(100.0, node.smoke_score + 18.0)

                rcpt = EvidenceReceipt(
                    tool="sqlite_cross_case_memory",
                    domain=DomainCategory.SKEPTIC,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"sqlite:///{self.db_path}#entity={node_id}",
                    extracted_fact=f"Cross-Case Memory Hit: '{node.label}' ({node_id}) was previously recorded in {len(rows)} historical investigation(s): {prior_summary}",
                    raw_snippet=json.dumps(prior_cases)[:360],
                )
                node.receipts.append(rcpt)
                node.attributes["prior_case_sightings"] = prior_cases

                hits.append(
                    {
                        "entity_id": node_id,
                        "label": node.label,
                        "entity_type": node.entity_type.value,
                        "domain": node.domain.value,
                        "current_case_id": graph.case_id,
                        "prior_cases": prior_cases,
                        "distinct_seed_overlap": bool(distinct_seeds),
                    }
                )
        return hits

    def save_case(self, graph: InvestigationGraph, full_result: Dict[str, Any]) -> None:
        """Persist the full case JSON and index all entity sightings in ~/.bunnyhole/cases.db."""
        now_iso = datetime.now(timezone.utc).isoformat()
        stats = full_result.get("stats", {})
        ach = full_result.get("ach_assessment", {})
        gear = full_result.get("deep_research", {}).get("gear", "fast")

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cases (
                    case_id, seed_query, gear, created_at,
                    total_nodes, total_edges, total_receipts,
                    winning_hypothesis, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    graph.case_id,
                    graph.seed_query,
                    gear,
                    now_iso,
                    stats.get("total_nodes", len(graph.nodes)),
                    stats.get("total_edges", len(graph.edges)),
                    stats.get("total_receipts", 0),
                    ach.get("winning_hypothesis", ""),
                    json.dumps(full_result),
                ),
            )

            for node_id, node in graph.nodes.items():
                if node_id.startswith("seed:"):
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO entity_sightings (
                        entity_id, case_id, seed_query, label,
                        entity_type, domain, smoke_score, sighted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        graph.case_id,
                        graph.seed_query,
                        node.label,
                        node.entity_type.value,
                        node.domain.value,
                        float(node.smoke_score),
                        now_iso,
                    ),
                )

    def list_cases(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Return metadata for recent saved investigations."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT case_id, seed_query, gear, created_at,
                       total_nodes, total_edges, total_receipts, winning_hypothesis
                FROM cases
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Load a saved investigation's full JSON payload by case_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if not row:
                return None
            return json.loads(row["result_json"])

    def search_entity_memory(self, query: str, limit: int = 25) -> List[Dict[str, Any]]:
        """Search across all historical entity sightings by ID or label substring."""
        q = f"%{query.strip()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT entity_id, label, entity_type, domain, smoke_score, case_id, seed_query, sighted_at
                FROM entity_sightings
                WHERE entity_id LIKE ? OR label LIKE ?
                ORDER BY smoke_score DESC, sighted_at DESC
                LIMIT ?
                """,
                (q, q, limit),
            ).fetchall()
            return [dict(r) for r in rows]
