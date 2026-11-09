"""Audit regressions for the accountant agent: Beneish M-score honesty, ADS-B URL quoting, SEC user agent.

The Beneish M-score must only be computed from filed numbers: no imputed defaults, no NaN/negative revenue,
no zero denominators. A score that cannot be computed is reported as ``not_computable`` with the missing inputs
and never becomes an A1 "manipulation flagged" receipt. All HTTP is mocked with respx.
"""

from __future__ import annotations

import asyncio
import math
from typing import Any, Dict, Optional

import httpx
import pytest
import respx

from bunnyhole.agents import accountant as accountant_module
from bunnyhole.agents.accountant import (
    BENEISH_REQUIRED_INPUTS,
    AccountantAgent,
    beneish_m_score_from_indices,
)
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.netutil import new_async_client

COMPLETE: Dict[str, float] = {
    "revenue_t": 110.0,
    "revenue_t1": 100.0,
    "receivables_t": 11.0,
    "receivables_t1": 10.5,
    "gross_margin_t": 0.48,
    "gross_margin_t1": 0.48,
    "current_assets_t": 90.0,
    "current_assets_t1": 85.0,
    "ppe_t": 50.0,
    "ppe_t1": 48.0,
    "total_assets_t": 200.0,
    "total_assets_t1": 190.0,
    "dep_rate_t": 0.08,
    "dep_rate_t1": 0.08,
    "sga_ratio_t": 0.20,
    "sga_ratio_t1": 0.20,
    "net_income_t": 15.0,
    "operating_cash_flow_t": 18.0,
    "leverage_t": 0.40,
    "leverage_t1": 0.38,
}

# Beneish (1999), "The Detection of Earnings Manipulation", Financial Analysts Journal, Table 2: sample means of the
# eight indices for manipulators and non-manipulators.
MANIPULATOR_MEANS = {"DSRI": 1.465, "GMI": 1.193, "AQI": 1.254, "SGI": 1.607,
                     "DEPI": 1.077, "SGAI": 1.041, "TATA": 0.031, "LVGI": 1.111}
NON_MANIPULATOR_MEANS = {"DSRI": 1.031, "GMI": 1.014, "AQI": 1.039, "SGI": 1.134,
                         "DEPI": 1.001, "SGAI": 1.054, "TATA": 0.018, "LVGI": 1.037}


def _hand_m_score(f: Dict[str, float]) -> float:
    """Independent re-derivation of the 8-variable model from raw inputs."""
    dsri = (f["receivables_t"] / f["revenue_t"]) / (f["receivables_t1"] / f["revenue_t1"])
    gmi = f["gross_margin_t1"] / f["gross_margin_t"]
    aqi = (1 - (f["current_assets_t"] + f["ppe_t"]) / f["total_assets_t"]) / (
        1 - (f["current_assets_t1"] + f["ppe_t1"]) / f["total_assets_t1"]
    )
    sgi = f["revenue_t"] / f["revenue_t1"]
    depi = f["dep_rate_t1"] / f["dep_rate_t"]
    sgai = f["sga_ratio_t"] / f["sga_ratio_t1"]
    tata = (f["net_income_t"] - f["operating_cash_flow_t"]) / f["total_assets_t"]
    lvgi = f["leverage_t"] / f["leverage_t1"]
    return (-4.84 + 0.920 * dsri + 0.528 * gmi + 0.404 * aqi + 0.892 * sgi + 0.115 * depi
            - 0.172 * sgai + 4.679 * tata - 0.327 * lvgi)


# --- pure calculator ---------------------------------------------------------------------------------------


def test_published_beneish_1999_mean_indices_reproduce_the_model() -> None:
    manip = beneish_m_score_from_indices(MANIPULATOR_MEANS)
    clean = beneish_m_score_from_indices(NON_MANIPULATOR_MEANS)
    assert manip == pytest.approx(-1.196, abs=1e-3)
    assert clean == pytest.approx(-2.246, abs=1e-3)
    assert manip > -1.78 > clean


def test_empty_inputs_are_not_computable_and_never_flagged() -> None:
    res = AccountantAgent.calculate_beneish_m_score({})
    assert res["status"] == "not_computable"
    assert res["m_score"] is None
    assert res["is_flagged"] is False
    assert res["flags"] == []
    assert sorted(res["missing_inputs"]) == sorted(BENEISH_REQUIRED_INPUTS)


def test_partial_inputs_list_exactly_what_is_missing() -> None:
    partial = {k: v for k, v in COMPLETE.items() if k not in ("dep_rate_t", "sga_ratio_t1", "leverage_t")}
    res = AccountantAgent.calculate_beneish_m_score(partial)
    assert res["status"] == "not_computable"
    assert sorted(res["missing_inputs"]) == ["dep_rate_t", "leverage_t", "sga_ratio_t1"]
    assert res["is_flagged"] is False and res["m_score"] is None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -5.0, 0.0])
def test_nan_infinite_negative_or_zero_revenue_is_not_computable(bad: float) -> None:
    res = AccountantAgent.calculate_beneish_m_score({**COMPLETE, "revenue_t": bad})
    assert res["status"] == "not_computable"
    assert "revenue_t" in res["invalid_inputs"]
    assert res["is_flagged"] is False and res["m_score"] is None


@pytest.mark.parametrize("key", ["receivables_t1", "gross_margin_t", "dep_rate_t", "sga_ratio_t1", "leverage_t1",
                                 "total_assets_t"])
def test_zero_denominators_are_not_computable(key: str) -> None:
    res = AccountantAgent.calculate_beneish_m_score({**COMPLETE, key: 0.0})
    assert res["status"] == "not_computable"
    assert key in res["invalid_inputs"]


def test_asset_quality_denominator_must_be_positive() -> None:
    # current assets + PP&E >= total assets in t-1 makes AQ(t-1) <= 0, so AQI is undefined.
    res = AccountantAgent.calculate_beneish_m_score({**COMPLETE, "current_assets_t1": 150.0})
    assert res["status"] == "not_computable"
    assert "asset_quality_t1" in res["invalid_inputs"]


def test_non_numeric_input_is_invalid_not_a_crash() -> None:
    res = AccountantAgent.calculate_beneish_m_score({**COMPLETE, "net_income_t": "12"})  # type: ignore[dict-item]
    assert res["status"] == "not_computable"
    assert "net_income_t" in res["invalid_inputs"]


def test_complete_inputs_match_an_independent_derivation() -> None:
    res = AccountantAgent.calculate_beneish_m_score(COMPLETE)
    assert res["status"] == "computed"
    assert res["missing_inputs"] == [] and res["invalid_inputs"] == []
    assert res["m_score"] == pytest.approx(round(_hand_m_score(COMPLETE), 3))
    assert math.isfinite(res["m_score"])
    assert res["is_flagged"] is False


# --- SEC XBRL integration ----------------------------------------------------------------------------------

CIK = "320193"
XBRL_URL = "https://data.sec.gov/api/xbrl/companyfacts/CIK0000320193.json"


def _concept(v_t: float, v_t1: float) -> Dict[str, Any]:
    return {"units": {"USD": [
        {"form": "10-K", "fy": 2023, "end": "2023-12-31", "val": v_t1},
        {"form": "10-K", "fy": 2024, "end": "2024-12-31", "val": v_t},
    ]}}


MINIMAL_FACTS = {
    "Revenues": _concept(220.0, 100.0),
    "Assets": _concept(300.0, 180.0),
    "NetIncomeLoss": _concept(45.0, 10.0),
    "NetCashProvidedByUsedInOperatingActivities": _concept(-15.0, 5.0),
}

FULL_FACTS = {
    **MINIMAL_FACTS,
    "AccountsReceivableNetCurrent": _concept(95.0, 15.0),
    "GrossProfit": _concept(55.0, 50.0),
    "AssetsCurrent": _concept(60.0, 80.0),
    "PropertyPlantAndEquipmentNet": _concept(20.0, 40.0),
    "DepreciationDepletionAndAmortization": _concept(4.0, 6.0),
    "SellingGeneralAndAdministrativeExpense": _concept(40.0, 20.0),
    "Liabilities": _concept(150.0, 80.0),
}


def _run_xbrl(facts: Optional[Dict[str, Any]]) -> InvestigationGraph:
    graph = InvestigationGraph("beneish", "Acme")
    agent = AccountantAgent(graph)

    async def go() -> None:
        async with new_async_client(timeout=5.0) as client:
            await agent._evaluate_sec_xbrl_beneish(client, CIK, "ACME CORP", "org:acme", 1)

    with respx.mock(assert_all_called=False) as router:
        router.get(XBRL_URL).mock(return_value=httpx.Response(200, json={"facts": {"us-gaap": facts or {}}}))
        asyncio.run(go())
    return graph


def test_xbrl_with_missing_inputs_creates_no_flag_and_no_a1_score_receipt() -> None:
    graph = _run_xbrl(MINIMAL_FACTS)
    beneish_nodes = [n for n in graph.nodes.values() if n.id.startswith("beneish:")]
    for node in beneish_nodes:
        assert not any("MANIPULATION" in f for f in node.risk_flags)
        assert node.smoke_score < 50
        assert node.attributes.get("status") == "not_computable"
        for rcpt in node.receipts:
            assert rcpt.admiralty_code != "A1"
            assert "Manipulation Flagged" not in rcpt.extracted_fact
    notes = [e for e in graph.logs if e.action == "BENEISH_NOT_COMPUTABLE"]
    assert notes, [e.action for e in graph.logs]
    assert "receivables" in notes[0].detail.lower()


def test_xbrl_with_complete_filed_inputs_computes_and_flags() -> None:
    graph = _run_xbrl(FULL_FACTS)
    node = graph.nodes["beneish:cik:0000320193"]
    assert node.attributes["status"] == "computed"
    expected = {
        "revenue_t": 220.0, "revenue_t1": 100.0, "receivables_t": 95.0, "receivables_t1": 15.0,
        "gross_margin_t": 55.0 / 220.0, "gross_margin_t1": 50.0 / 100.0,
        "current_assets_t": 60.0, "current_assets_t1": 80.0, "ppe_t": 20.0, "ppe_t1": 40.0,
        "total_assets_t": 300.0, "total_assets_t1": 180.0,
        "dep_rate_t": 4.0 / (4.0 + 20.0), "dep_rate_t1": 6.0 / (6.0 + 40.0),
        "sga_ratio_t": 40.0 / 220.0, "sga_ratio_t1": 20.0 / 100.0,
        "net_income_t": 45.0, "operating_cash_flow_t": -15.0,
        "leverage_t": 150.0 / 300.0, "leverage_t1": 80.0 / 180.0,
    }
    assert node.attributes["m_score"] == pytest.approx(round(_hand_m_score(expected), 3))
    assert node.attributes["is_flagged"] is True
    assert "BENEISH_M_SCORE_MANIPULATION_ALERT" in node.risk_flags


def test_xbrl_with_no_gaap_facts_creates_nothing() -> None:
    graph = _run_xbrl(None)
    assert not [n for n in graph.nodes.values() if n.id.startswith("beneish:")]


# --- ADS-B URL quoting, SEC user agent, docstring honesty ----------------------------------------------------


@pytest.mark.parametrize(
    "tail,raw_path",
    [("N1/../v2/all", b"/v2/reg/N1%2F..%2FV2%2FALL"), ("N1?x=1", b"/v2/reg/N1%3FX%3D1"), ("N628TS", b"/v2/reg/N628TS")],
)
def test_adsb_query_is_path_quoted(tail: str, raw_path: bytes) -> None:
    graph = InvestigationGraph("adsb", tail)
    agent = AccountantAgent(graph)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith="https://api.adsb.lol/").mock(return_value=httpx.Response(200, json={"ac": []}))
        asyncio.run(agent.investigate_aircraft_adsb(tail, "case:root", 1))
    assert route.call_count == 1
    assert route.calls.last.request.url.raw_path == raw_path


def test_sec_user_agent_default_and_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUNNYHOLE_SEC_USER_AGENT", raising=False)
    agent = AccountantAgent(InvestigationGraph("ua", "x"))
    assert agent.sec_headers["User-Agent"] == "Bunnyhole research (+https://github.com/DreadpiratePickles/bunnyhole)"
    monkeypatch.setenv("BUNNYHOLE_SEC_USER_AGENT", "Jane Analyst jane@example.org")
    agent = AccountantAgent(InvestigationGraph("ua", "x"))
    assert agent.sec_headers["User-Agent"] == "Jane Analyst jane@example.org"


def test_accountant_docs_do_not_claim_unimplemented_fec_lookups() -> None:
    text = (accountant_module.__doc__ or "") + (AccountantAgent.__doc__ or "")
    assert "FEC" not in text and "political donations" not in text.lower()
