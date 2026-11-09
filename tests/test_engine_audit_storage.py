"""Engine audit M3 + M12: defensive, secured, migratable storage and idempotent cross-case memory."""

from __future__ import annotations

import stat

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode
from bunnyhole.engine.storage import SCHEMA_VERSION, CaseStore, NullCaseStore, build_case_store


def _graph_with_entity(case_id: str, seed: str, entity_id: str = "lei:acme") -> InvestigationGraph:
    g = InvestigationGraph(case_id, seed)
    g.upsert_node(GraphNode(id=entity_id, label="Acme LEI", entity_type=EntityType.ORGANIZATION, domain=DomainCategory.FIAT, hop_depth=1))
    return g


# ---- M3: file mode, WAL, user_version, LIKE escaping, corruption/read-only handling ------------


def test_new_db_is_created_0600_with_wal_and_user_version(tmp_path) -> None:
    db = tmp_path / "cases.db"
    store = CaseStore(db)
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    with store._connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == SCHEMA_VERSION


def test_search_escapes_like_wildcards(tmp_path) -> None:
    store = CaseStore(tmp_path / "cases.db")
    g = InvestigationGraph("bh_1", "Discount Corp")
    g.upsert_node(GraphNode(id="lei:discount", label="Discount_Corp 50% Ltd",
                            entity_type=EntityType.ORGANIZATION, domain=DomainCategory.FIAT, hop_depth=1))
    store.save_case(g, g.to_dict())
    # A literal '%'/'_' must match literally, not act as a wildcard.
    assert store.search_entity_memory("50%")  # the literal row is found
    assert store.search_entity_memory("Discount%Ltd") == []  # '%' escaped -> no wildcard match


def test_corrupt_db_is_moved_aside_and_recreated(tmp_path) -> None:
    db = tmp_path / "cases.db"
    db.write_bytes(b"this is not a sqlite database at all")
    store = build_case_store(db)
    assert isinstance(store, CaseStore)
    # original moved aside (never deleted), fresh DB usable
    assert list(tmp_path.glob("cases.db.corrupt-*"))
    assert store.list_cases() == []


def test_readonly_home_yields_null_store_with_reason(tmp_path, monkeypatch) -> None:
    db = tmp_path / "cases.db"

    def boom(self, *a, **k):
        raise PermissionError("read-only fs")

    monkeypatch.setattr(CaseStore, "__init__", boom)
    store = build_case_store(db)
    assert isinstance(store, NullCaseStore)
    assert store.persist_error and "persistence disabled" in store.persist_error
    # no-op surface keeps an investigation running
    assert store.correlate_cross_case_entities(_graph_with_entity("x", "y")) == []
    store.save_case(_graph_with_entity("x", "y"), {})


def test_existing_db_still_works_and_keeps_rows(tmp_path) -> None:
    db = tmp_path / "cases.db"
    g1 = _graph_with_entity("bh_old", "Old Seed")
    CaseStore(db).save_case(g1, g1.to_dict())
    # Re-open (migration path over an existing DB) and confirm the row survived.
    store = build_case_store(db)
    assert isinstance(store, CaseStore)
    assert store.get_case("bh_old") is not None


# ---- M12: idempotent cross-case correlation + PI seed-text suppression -------------------------


def test_correlate_is_idempotent_no_double_smoke_or_duplicate_receipt(tmp_path) -> None:
    store = CaseStore(tmp_path / "cases.db")
    prior = _graph_with_entity("bh_prior", "Prior Subject")
    store.save_case(prior, prior.to_dict())

    current = _graph_with_entity("bh_curr", "Different Subject")
    node = current.nodes["lei:acme"]
    base_smoke = node.smoke_score

    store.correlate_cross_case_entities(current)
    after_first_smoke = node.smoke_score
    after_first_receipts = len(node.receipts)
    assert after_first_smoke == base_smoke + 18.0

    store.correlate_cross_case_entities(current)  # second pass must change nothing
    assert node.smoke_score == after_first_smoke
    assert len(node.receipts) == after_first_receipts


def test_correlate_without_seed_text_hides_other_case_subject(tmp_path) -> None:
    store = CaseStore(tmp_path / "cases.db")
    prior = _graph_with_entity("bh_prior", "SECRET CLIENT NAME")
    store.save_case(prior, prior.to_dict())

    current = _graph_with_entity("bh_curr", "Different Subject")
    hits = store.correlate_cross_case_entities(current, include_seed_text=False)
    assert hits
    node = current.nodes["lei:acme"]
    rcpt = next(r for r in node.receipts if r.tool == "sqlite_cross_case_memory")
    assert "SECRET CLIENT NAME" not in rcpt.extracted_fact
    assert "SECRET CLIENT NAME" not in rcpt.raw_snippet
    assert "bh_prior" in rcpt.extracted_fact  # the case id is still referenced
