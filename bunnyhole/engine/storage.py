"""Persistent SQLite Case Store & Cross-Case Entity Memory (~/.bunnyhole/cases.db)."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bunnyhole.arsenal.manager import BUNNYHOLE_CONFIG_DIR
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EvidenceReceipt, SelectorStrength
from bunnyhole.engine.pi_credentials import scrub_credential_text

logger = logging.getLogger(__name__)

CASES_DB_PATH = BUNNYHOLE_CONFIG_DIR / "cases.db"

# Current on-disk schema version, stored in SQLite's PRAGMA user_version. Bump it and add a branch
# to _migrate() for any backward-incompatible change to the tables below.
SCHEMA_VERSION = 1


def _escape_like(term: str) -> str:
    r"""Escape LIKE wildcards (``%``, ``_``) and the escape char (``\``) so a literal search term
    is matched literally. Used with ``LIKE ? ESCAPE '\'``."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class CaseStore:
    """
    SQLite-backed persistence layer for Bunnyhole investigations and Cross-Case Entity Memory.
    Whenever an entity (wallet, domain, IP, corporate LEI, email, handle) discovered in Case B
    was previously recorded in Case A, CaseStore flags a CROSS_CASE_ENTITY_HIT and links both cases.
    """

    #: Set on a store that could not open a database; persistence is a no-op and callers report it.
    persist_error: Optional[str] = None

    def __init__(self, db_path: Path = CASES_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.db_path.exists()
        self._init_schema()
        if not existed:
            # A freshly created case DB is secured 0600 (same posture as the keys vault / profile).
            try:
                self.db_path.chmod(0o600)
            except OSError:  # pragma: no cover - best-effort on platforms without chmod semantics
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
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
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Advance the DB from its stored PRAGMA user_version to SCHEMA_VERSION.

        A small, explicit migration hook: existing databases (user_version 0) are tagged with the
        current version in place, their tables being created-if-not-exists above. Future breaking
        changes add a branch here keyed on the version read back.
        """
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version < SCHEMA_VERSION:
            # No destructive change between 0 and 1; the CREATE TABLE IF NOT EXISTS above is the whole
            # migration. Record the new version so later migrations have a floor to build on.
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def correlate_cross_case_entities(
        self, graph: InvestigationGraph, *, include_seed_text: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Check if any entity in the current InvestigationGraph was previously seen in earlier cases
        with a DIFFERENT seed_query. Enriches matching nodes with a CROSS_CASE_ENTITY_HIT flag & receipt.

        Idempotent: the cross-case receipt has a stable id derived from the entity and the set of prior
        case ids, so re-running never duplicates it nor re-bumps the smoke score.

        ``include_seed_text`` is True for ordinary runs (prior seed queries are shown). It is set False
        under a PI engagement, where another case's seed query is a different client's subject: then
        only ``case <id>`` is emitted, never the other seed text.
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
                        "seed_query": r["seed_query"] if include_seed_text else "",
                        "sighted_at": r["sighted_at"],
                        "prior_smoke_score": r["smoke_score"],
                    }
                    for r in rows
                ]
                # Check if at least one prior case had a different seed query (true cross-case correlation!)
                distinct_seeds = {r["seed_query"] for r in rows if r["seed_query"].lower() != graph.seed_query.lower()}
                if include_seed_text:
                    prior_summary = ", ".join(f"{r['case_id']} ('{r['seed_query']}')" for r in rows[:3])
                else:
                    prior_summary = ", ".join(f"case {r['case_id']}" for r in rows[:3])

                # Stable receipt id per (entity, set of prior case ids): skip if already present so a
                # second correlation pass does not duplicate the receipt or re-add the smoke bump.
                case_key = ",".join(sorted({r["case_id"] for r in rows}))
                stable_id = f"rcpt_xcase_{hashlib.sha256(f'{node_id}|{case_key}'.encode()).hexdigest()[:10]}"
                if any(r.receipt_id == stable_id for r in node.receipts):
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
                    continue

                if "CROSS_CASE_ENTITY_HIT" not in node.risk_flags:
                    node.risk_flags.append("CROSS_CASE_ENTITY_HIT")
                if distinct_seeds:
                    node.smoke_score = min(100.0, node.smoke_score + 18.0)

                rcpt = EvidenceReceipt(
                    receipt_id=stable_id,
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

        # Persistence-boundary net: no credential-shaped token (`email:secret`) is written to disk,
        # even if one reached this far. The caller already masks/scrubs; this is the last line.
        seed_query = scrub_credential_text(graph.seed_query)[0]
        result_json = scrub_credential_text(json.dumps(full_result))[0]

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
                    seed_query,
                    gear,
                    now_iso,
                    stats.get("total_nodes", len(graph.nodes)),
                    stats.get("total_edges", len(graph.edges)),
                    stats.get("total_receipts", 0),
                    ach.get("winning_hypothesis", ""),
                    result_json,
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
                        scrub_credential_text(node_id)[0],
                        graph.case_id,
                        seed_query,
                        scrub_credential_text(node.label)[0],
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
        q = f"%{_escape_like(query.strip())}%"
        with self._connect() as conn:
            rows = conn.execute(
                r"""
                SELECT entity_id, label, entity_type, domain, smoke_score, case_id, seed_query, sighted_at
                FROM entity_sightings
                WHERE entity_id LIKE ? ESCAPE '\' OR label LIKE ? ESCAPE '\'
                ORDER BY smoke_score DESC, sighted_at DESC
                LIMIT ?
                """,
                (q, q, limit),
            ).fetchall()
            return [dict(r) for r in rows]


class NullCaseStore:
    """A no-op stand-in used when the case DB cannot be opened (corrupt beyond recovery, or a
    read-only HOME). Persistence is optional, so the investigation proceeds; ``persist_error``
    tells the caller to surface the reason in the result."""

    def __init__(self, persist_error: str) -> None:
        self.persist_error = persist_error
        self.db_path: Optional[Path] = None

    def correlate_cross_case_entities(
        self, graph: InvestigationGraph, *, include_seed_text: bool = True
    ) -> List[Dict[str, Any]]:
        return []

    def save_case(self, graph: InvestigationGraph, full_result: Dict[str, Any]) -> None:
        return None

    def list_cases(self, limit: int = 30) -> List[Dict[str, Any]]:
        return []

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        return None

    def search_entity_memory(self, query: str, limit: int = 25) -> List[Dict[str, Any]]:
        return []


def build_case_store(db_path: Path = CASES_DB_PATH) -> "CaseStore | NullCaseStore":
    """Construct a CaseStore defensively. Persistence is optional, so failure is never fatal.

    * A corrupt ``cases.db`` (``sqlite3.DatabaseError``) is moved aside as
      ``cases.db.corrupt-<ts>`` (never deleted) and a fresh DB is started, with a logged warning.
    * A read-only / unwritable HOME (``OSError``/``PermissionError``) yields a :class:`NullCaseStore`
      that disables persistence and carries the reason for the caller to report.
    """
    try:
        return CaseStore(db_path)
    except sqlite3.DatabaseError as exc:
        try:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            moved = db_path.with_name(f"{db_path.name}.corrupt-{ts}")
            db_path.rename(moved)
            for sidecar in (f"{db_path.name}-wal", f"{db_path.name}-shm"):
                side = db_path.with_name(sidecar)
                if side.exists():
                    side.unlink()
            logger.warning("Corrupt case DB moved aside to %s and recreated: %s", moved, exc)
            return CaseStore(db_path)
        except (OSError, sqlite3.DatabaseError) as exc2:
            logger.warning("Case DB unavailable after corruption recovery: %s", exc2)
            return NullCaseStore(f"case DB unavailable (corrupt, recovery failed): {type(exc2).__name__}")
    except (OSError, PermissionError) as exc:
        logger.warning("Case DB unavailable, persistence disabled: %s", exc)
        return NullCaseStore(f"case DB unavailable (persistence disabled): {type(exc).__name__}")
