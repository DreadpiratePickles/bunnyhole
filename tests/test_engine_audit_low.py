"""Engine audit LOW: timestamps, token matching, atomic profile I/O, dossier escaping/node receipts."""

from __future__ import annotations

import stat

from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GraphNode,
    selector_token_match,
)
from bunnyhole.engine.profile import InvestigatorProfile, load_profile, match_watchlist, save_profile

# ---- timestamp normalisation -------------------------------------------------------------------


def test_timestamps_normalise_to_utc_z_or_flagged_none() -> None:
    f = InvestigationGraph.normalize_iso_timestamp_full
    assert f("Tue, 14 Oct 2025 12:30:00 -0000") == ("2025-10-14T12:30:00Z", None)  # -0000 = UTC, not local
    assert f("Tue, 14 Oct 2025 12:30:00 GMT") == ("2025-10-14T12:30:00Z", None)
    assert f("2025-10-14T12:30:00+02:00") == ("2025-10-14T10:30:00Z", None)        # offset folded to UTC
    assert f("1700000000000")[0].endswith("Z") and f("1700000000000")[1] is None   # 13-digit epoch ms
    iso, flag = f("")
    assert iso.endswith("Z") and flag == "EMPTY_TIMESTAMP_DEFAULTED_TO_NOW"
    assert f("2025-13-45") == (None, "INVALID_TIMESTAMP")                            # impossible date
    assert f("+02:00 bad") == (None, "UNPARSEABLE_TIMESTAMP")


def test_normalize_iso_timestamp_never_raises_and_returns_str() -> None:
    assert InvestigationGraph.normalize_iso_timestamp("garbage !!!") == "garbage !!!"
    assert InvestigationGraph.normalize_iso_timestamp("2021").startswith("2021-01-01")


# ---- token-boundary matching (is_excluded + match_watchlist) -----------------------------------


def test_selector_token_match_rules() -> None:
    assert not selector_token_match("ab", "cabinet.com")      # substring no longer matches
    assert selector_token_match("acme.io", "x.acme.io")       # subdomain on dot boundary
    assert selector_token_match("acme.io", "acme.io")         # exact host
    assert not selector_token_match("acme.io", "notacme.io")  # not a boundary
    assert selector_token_match("0xABC", "wallet:0xabc")      # wallet exact, case-insensitive
    assert not selector_token_match("acme", "acmecorp")       # name whole-word only


def test_is_excluded_is_token_aware() -> None:
    g = InvestigationGraph("c", "q", exclusions=["cloudflare.com", "ab"])
    assert g.is_excluded("sub.cloudflare.com")
    assert not g.is_excluded("cabinet.com")  # 'ab' must not block it


def test_match_watchlist_is_token_aware() -> None:
    nodes = [
        {"id": "domain:x.acme.io", "label": "x.acme.io", "domain": "osint", "smoke_score": 20},
        {"id": "domain:cabinet.com", "label": "cabinet.com", "domain": "osint", "smoke_score": 10},
    ]
    hits = match_watchlist(nodes, ["acme.io", "ab"])
    assert {h["node_id"] for h in hits} == {"domain:x.acme.io"}


# ---- atomic profile write + corrupt backup -----------------------------------------------------


def test_profile_save_is_atomic_and_secured(tmp_path) -> None:
    path = tmp_path / "profile.json"
    save_profile(InvestigatorProfile(display_name="Nat"), path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob("profile.json.tmp-*"))  # no temp file left behind
    assert load_profile(path=path).display_name == "Nat"


def test_corrupt_profile_is_backed_up_then_defaulted(tmp_path, monkeypatch) -> None:
    path = tmp_path / "profile.json"
    path.write_text("{ not json at all", encoding="utf-8")
    monkeypatch.setattr(profile_mod, "logger", profile_mod.logging.getLogger("silent"))
    loaded = load_profile(path=path)
    assert loaded.persona == profile_mod.Persona.GENERALIST
    assert list(tmp_path.glob("profile.json.bad-*"))  # corrupt file preserved, not overwritten
    assert not path.exists()  # moved aside


# ---- dossier: escape table cells + include node receipts ---------------------------------------


def test_dossier_escapes_pipes_and_includes_node_receipts() -> None:
    g = InvestigationGraph("c", "q")
    node_rcpt = EvidenceReceipt(tool="seed_anchor", domain=DomainCategory.OSINT,
                                source_url="https://node-only", extracted_fact="NODE_ONLY_PROOF_XYZ")
    g.upsert_node(GraphNode(
        id="org:pipe", label="Evil | Corp\nNewline", entity_type=EntityType.ORGANIZATION,
        domain=DomainCategory.FIAT, smoke_score=70.0, receipts=[node_rcpt],
    ))
    dossier = g.export_markdown_dossier()
    assert "Evil \\| Corp" in dossier       # pipe escaped so the table row is not broken
    assert "Evil | Corp\nNewline" not in dossier  # raw newline/pipe not emitted in the cell
    assert "NODE_ONLY_PROOF_XYZ" in dossier  # node receipts now appear in the ledger
