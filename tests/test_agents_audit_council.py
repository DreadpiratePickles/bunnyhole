"""Audit regressions for the investigative council.

Stage 2 is a deterministic evidence-rubric ranking (it never consulted an LLM): it must be labelled as such, not
as anonymized peer review, and the per-reviewer ``(idx % 3) * 1.2`` / self-bonus fudges are gone, so every seat's
ballot follows the one documented rule. LLM calls go through llm_providers (mocked with respx here).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List

import httpx
import pytest
import respx

from bunnyhole.agents.link_sleuth import LinkSleuthAgent
from bunnyhole.engine import llm_providers
from bunnyhole.engine.council import InvestigativeCouncil, deterministic_rubric_score
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

KEY_VARS = ("OPENROUTER_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
ANTHROPIC_KEY = "sk-ant-SECRET-council-999"


@pytest.fixture(autouse=True)
def _no_keys(monkeypatch: pytest.MonkeyPatch):
    for name in KEY_VARS:
        monkeypatch.delenv(name, raising=False)


def _graph() -> InvestigationGraph:
    g = InvestigationGraph("council_audit", "vitalik.eth")
    rcpt = EvidenceReceipt(
        tool="ensdata_web3_identity_resolver", domain=DomainCategory.ONCHAIN, admiralty_code="A1",
        selector_strength=SelectorStrength.STRONG, source_url="https://api.ensdata.net/vitalik.eth",
        extracted_fact="ENS vitalik.eth resolves to 0xd8da6bf26964af9d7eed9e03e53415d37aa96045", raw_snippet="ens",
    )
    a = g.upsert_node(GraphNode(id="seed:vitalik", label="vitalik.eth", entity_type=EntityType.CRYPTO_WALLET,
                                domain=DomainCategory.ONCHAIN, selector_strength=SelectorStrength.STRONG,
                                receipts=[rcpt]))
    b = g.upsert_node(GraphNode(id="account:github:vbuterin", label="GitHub @vbuterin", entity_type=EntityType.ACCOUNT,
                                domain=DomainCategory.OSINT, selector_strength=SelectorStrength.STRONG,
                                receipts=[rcpt]))
    g.upsert_edge(GraphEdge(source_id=a.id, target_id=b.id, relation=RelationType.LINKED_IDENTITY,
                            domain=DomainCategory.ONCHAIN, admiralty_code="A1", confidence=0.99,
                            tier=ConfidenceTier.VERIFIED, summary="ENS github record", receipts=[rcpt]))
    return g


def _run(graph: InvestigationGraph) -> Dict[str, Any]:
    inter = LinkSleuthAgent(graph).analyze_interconnected_web()
    return asyncio.run(InvestigativeCouncil(graph).run_full_council(inter, []))


def test_stage2_is_labelled_deterministic_not_peer_review() -> None:
    res = _run(_graph())
    assert res["stage2_method"] == "deterministic_evidence_rubric"
    assert "not peer review" in res["stage2_label"]
    md = res["stage3_chairman_verdict"]["verdict_markdown"]
    assert "not peer review" in md
    assert "Peer-Review Leaderboard" not in md and "Peer-Ranked" not in md
    for ballot in res["stage2_peer_rankings"]:
        assert ballot["method"] == "deterministic_evidence_rubric"
        assert ballot["ranking"].startswith("DETERMINISTIC EVIDENCE-RUBRIC RANKING")
        assert "PEER EVALUATION" not in ballot["ranking"]


def test_every_ballot_follows_the_documented_rule_without_fudge() -> None:
    res = _run(_graph())
    stage1 = res["stage1_opinions"]
    labels = list(res["label_to_member"])
    scores = {lbl: deterministic_rubric_score(s1) for lbl, s1 in zip(labels, stage1)}
    for s1, lbl in zip(stage1, labels):
        cites = len(re.findall(r"\[R\d+\]", s1["response"]))
        assert scores[lbl] == pytest.approx(s1["evidentiary_rigor_score"] + min(15.0, cites * 3.0))
    expected = sorted(labels, key=lambda lbl: -scores[lbl])  # stable: ties keep label order
    ballots = [b["parsed_ranking"] for b in res["stage2_peer_rankings"]]
    assert len(ballots) == 5
    assert all(b == expected for b in ballots)
    assert [a["anonymous_label"] for a in res["aggregate_rankings"]] == expected


def test_no_llm_call_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_k: Any) -> Any:
        raise AssertionError("no provider call may be made without a key")

    monkeypatch.setattr(llm_providers, "new_async_client", boom)
    res = _run(_graph())
    assert all(s["mode"] == "deterministic_specialist_seat" for s in res["stage1_opinions"])
    assert res["stage3_chairman_verdict"]["chairman_model"] == "deterministic_council_chairman"
    assert res["llm_status"] == {"configured_providers": [], "failures": []}


def test_llm_failures_are_logged_reported_and_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    graph = _graph()
    with respx.mock(assert_all_called=True) as router:
        route = router.post("https://api.anthropic.com/v1/messages").mock(return_value=httpx.Response(401))
        res = _run(graph)
    assert route.call_count == 6  # 5 seats + chairman
    for call in route.calls:
        assert ANTHROPIC_KEY not in str(call.request.url)
    assert all(s["mode"] == "deterministic_specialist_seat" for s in res["stage1_opinions"])
    assert all(s["llm_failures"][0]["status_code"] == 401 for s in res["stage1_opinions"])
    stage3 = res["stage3_chairman_verdict"]
    assert stage3["chairman_model"] == "deterministic_council_chairman"
    assert stage3["llm_failures"] == [
        {"provider": "anthropic", "model": "claude-sonnet-5-5", "status_code": 401, "error": "HTTP 401"}
    ]
    assert res["llm_status"]["configured_providers"] == ["anthropic"]
    assert len(res["llm_status"]["failures"]) == 6
    events = [e for e in graph.logs if e.action == "LLM_PROVIDER_FAILED"]
    assert len(events) == 6
    assert all(ANTHROPIC_KEY not in e.detail for e in events)


def test_seats_use_the_fast_model_and_chairman_the_main_model(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    with respx.mock(assert_all_called=True) as router:
        route = router.post("https://api.anthropic.com/v1/messages").mock(
            return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "brief [R1]"}]})
        )
        res = _run(_graph())
    models: List[str] = [json.loads(c.request.content)["model"] for c in route.calls]
    assert sorted(models) == ["claude-haiku-5-5"] * 5 + ["claude-sonnet-5-5"]
    assert all(s["mode"] == "llm_council_api" for s in res["stage1_opinions"])
    assert res["stage3_chairman_verdict"]["chairman_model"] == "llm_council_chairman"
