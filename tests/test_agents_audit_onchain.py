"""Audit regressions for the on-chain agent: GoPlus flags must not be dropped, one entity has one wallet node id.

All HTTP is mocked with respx; nothing reaches the network.
"""

from __future__ import annotations

import asyncio
import re

import httpx
import respx

from bunnyhole.agents.onchain import OnChainAgent
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.ids import canonical_wallet_id, legacy_seed_wallet_ids, resolve_wallet_node_id
from bunnyhole.engine.models import DomainCategory, EntityType, GraphNode, SelectorStrength

ADDR = "0xAbCdEf0123456789abcdef0123456789ABCDEF01"
ADDR_LOW = ADDR.lower()
BTC = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


def _seed(graph: InvestigationGraph, node_id: str, raw: str) -> None:
    graph.upsert_node(
        GraphNode(
            id=node_id,
            label=f"seed {raw}",
            entity_type=EntityType.CRYPTO_WALLET,
            domain=DomainCategory.ONCHAIN,
            selector_strength=SelectorStrength.STRONG,
            risk_flags=["PRIMARY_INVESTIGATION_ANCHOR"],
            attributes={"raw_seed": raw},
        )
    )


def _mock_evm_404s(router: respx.MockRouter) -> None:
    router.get(url__regex=r"https://api\.ensdata\.net/.*").mock(return_value=httpx.Response(404))
    router.get(url__regex=r"https://eth\.blockscout\.com/.*").mock(return_value=httpx.Response(404))


def _goplus_cybercrime(router: respx.MockRouter) -> respx.Route:
    return router.get(url__regex=r"https://api\.gopluslabs\.io/api/v1/address_security/.*").mock(
        return_value=httpx.Response(200, json={"code": 1, "result": {"cybercrime": "1", "phishing_activities": "0"}})
    )


# --- ids canonicaliser -------------------------------------------------------------------------------------


def test_canonical_wallet_id_evm_lowercases_and_accepts_chain_aliases() -> None:
    assert canonical_wallet_id("eth", ADDR) == f"wallet:eth:{ADDR_LOW}"
    assert canonical_wallet_id("evm", ADDR) == f"wallet:eth:{ADDR_LOW}"
    assert canonical_wallet_id("wallet", f"  {ADDR} ") == f"wallet:eth:{ADDR_LOW}"


def test_canonical_wallet_id_bitcoin_keeps_base58_case_and_lowercases_bech32() -> None:
    assert canonical_wallet_id("btc", BTC.upper()) == f"wallet:btc:{BTC}"
    assert canonical_wallet_id("bitcoin", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT") == "wallet:btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT"


def test_canonical_wallet_id_rejects_unknown_chain_and_empty_address() -> None:
    for chain, addr in (("sol", ADDR), ("eth", ""), ("eth", "   ")):
        try:
            canonical_wallet_id(chain, addr)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {chain!r}/{addr!r}")


def test_legacy_seed_ids_match_the_orchestrator_seed_format() -> None:
    assert f"wallet:{ADDR_LOW}" in legacy_seed_wallet_ids("eth", ADDR)
    long_btc = "bc1q" + "a" * 58
    assert f"bitcoin:{long_btc[:48]}" in legacy_seed_wallet_ids("btc", long_btc)


def test_resolve_wallet_node_id_prefers_canonical_then_existing_alias() -> None:
    g = InvestigationGraph("ids", ADDR)
    assert resolve_wallet_node_id(g, "eth", ADDR) == f"wallet:eth:{ADDR_LOW}"
    _seed(g, f"wallet:{ADDR_LOW}", ADDR)
    assert resolve_wallet_node_id(g, "eth", ADDR) == f"wallet:{ADDR_LOW}"
    _seed(g, f"wallet:eth:{ADDR_LOW}", ADDR)
    assert resolve_wallet_node_id(g, "eth", ADDR) == f"wallet:eth:{ADDR_LOW}"


# --- H2: GoPlus flag dropped because the node did not exist yet ----------------------------------------------


def test_goplus_flag_is_kept_when_no_other_source_created_the_wallet_node() -> None:
    g = InvestigationGraph("goplus", ADDR)
    agent = OnChainAgent(g)
    with respx.mock(assert_all_called=False) as router:
        _mock_evm_404s(router)
        route = _goplus_cybercrime(router)
        asyncio.run(agent.investigate_evm_address(ADDR, "case:root", 1))
    assert route.called
    flagged = [n for n in g.nodes.values() if "GOPLUS_CYBERCRIME" in n.risk_flags]
    assert len(flagged) == 1, [n.id for n in g.nodes.values()]
    node = flagged[0]
    assert node.id == f"wallet:eth:{ADDR_LOW}"
    assert node.smoke_score >= 92.0
    assert any(r.tool == "goplus_web3_security_oracle" for r in node.receipts)
    assert "GOPLUS_PHISHING_ACTIVITIES" not in node.risk_flags


def test_goplus_flag_lands_on_the_seed_node_not_a_duplicate() -> None:
    g = InvestigationGraph("goplus-seed", ADDR)
    seed_id = f"wallet:{ADDR_LOW}"  # legacy id the orchestrator gave a 0x seed (persisted cases still carry it)
    _seed(g, seed_id, ADDR)
    agent = OnChainAgent(g)
    with respx.mock(assert_all_called=False) as router:
        _mock_evm_404s(router)
        _goplus_cybercrime(router)
        asyncio.run(agent.investigate_evm_address(ADDR, seed_id, 1))
    wallet_nodes = [n for n in g.nodes.values() if n.entity_type == EntityType.CRYPTO_WALLET]
    assert [n.id for n in wallet_nodes] == [seed_id]
    assert "GOPLUS_CYBERCRIME" in g.nodes[seed_id].risk_flags
    assert "PRIMARY_INVESTIGATION_ANCHOR" in g.nodes[seed_id].risk_flags


def test_evm_seed_and_blockscout_findings_share_one_node() -> None:
    g = InvestigationGraph("one-node", ADDR)
    seed_id = f"wallet:{ADDR_LOW}"
    _seed(g, seed_id, ADDR)
    agent = OnChainAgent(g)
    info = {"is_contract": False, "public_tags": [{"label": "Exchange"}]}
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://api\.ensdata\.net/.*").mock(return_value=httpx.Response(404))
        router.get(url__regex=r"https://api\.gopluslabs\.io/.*").mock(return_value=httpx.Response(200, json={"result": {}}))
        router.get(f"https://eth.blockscout.com/api/v2/addresses/{ADDR_LOW}").mock(return_value=httpx.Response(200, json=info))
        router.get(url__regex=r"https://eth\.blockscout\.com/api.*").mock(return_value=httpx.Response(404))
        asyncio.run(agent.investigate_evm_address(ADDR, seed_id, 1))
    assert f"wallet:eth:{ADDR_LOW}" not in g.nodes
    assert "Exchange" in g.nodes[seed_id].risk_flags
    assert any(r.tool == "blockscout_v2_evm_inspector" for r in g.nodes[seed_id].receipts)


def test_bitcoin_seed_and_mempool_findings_share_one_node() -> None:
    g = InvestigationGraph("btc-one-node", BTC)
    seed_id = f"bitcoin:{BTC}"
    _seed(g, seed_id, BTC)
    agent = OnChainAgent(g)
    stats = {"chain_stats": {"funded_txo_sum": 150_000_000, "spent_txo_sum": 50_000_000, "tx_count": 3}}
    with respx.mock(assert_all_called=False) as router:
        router.get(f"https://mempool.space/api/address/{BTC}").mock(return_value=httpx.Response(200, json=stats))
        router.get(f"https://mempool.space/api/address/{BTC}/txs").mock(return_value=httpx.Response(200, json=[]))
        asyncio.run(agent.investigate_bitcoin_utxo(BTC, seed_id, 1))
    assert f"wallet:btc:{BTC}" not in g.nodes
    assert g.nodes[seed_id].attributes["tx_count"] == 3


def test_bitcoin_without_seed_uses_canonical_id() -> None:
    g = InvestigationGraph("btc-canonical", BTC)
    agent = OnChainAgent(g)
    stats = {"chain_stats": {"funded_txo_sum": 1, "spent_txo_sum": 0, "tx_count": 1}}
    with respx.mock(assert_all_called=False) as router:
        router.get(f"https://mempool.space/api/address/{BTC}").mock(return_value=httpx.Response(200, json=stats))
        router.get(f"https://mempool.space/api/address/{BTC}/txs").mock(return_value=httpx.Response(200, json=[]))
        asyncio.run(agent.investigate_bitcoin_utxo(BTC, "case:root", 1))
    assert canonical_wallet_id("btc", BTC) in g.nodes


def test_onchain_docs_do_not_advertise_solana() -> None:
    import bunnyhole.agents.onchain as onchain_mod

    text = (onchain_mod.__doc__ or "") + (OnChainAgent.__doc__ or "")
    assert not re.search(r"solana", text, re.IGNORECASE)
