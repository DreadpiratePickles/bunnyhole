"""A wallet seeded by the case director and the on-chain agent's findings about it are ONE graph node.

The seed node id comes from ``engine.ids.canonical_wallet_id`` (``wallet:eth:<0x lower>`` / ``wallet:btc:<addr>``),
the id the on-chain agent uses. All HTTP is mocked with respx; nothing reaches the network.
"""

from __future__ import annotations

import asyncio

import httpx
import respx

from bunnyhole.engine.models import EntityType
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator

ADDR = "0xAbCdEf0123456789abcdef0123456789ABCDEF01"
ADDR_LOW = ADDR.lower()
BTC = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
# taproot address longer than the old 48-character seed-id truncation
BTC_TAPROOT = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"


def _wallet_ids(orch: BunnyholeOrchestrator) -> list[str]:
    return sorted(n.id for n in orch.graph.nodes.values() if n.entity_type == EntityType.CRYPTO_WALLET)


def test_evm_seed_uses_the_canonical_wallet_id() -> None:
    orch = BunnyholeOrchestrator(seed_query=ADDR)
    lead_type, node = orch._create_seed_node(ADDR)
    assert lead_type == "wallet"
    assert node.id == f"wallet:eth:{ADDR_LOW}"


def test_bitcoin_seed_uses_the_canonical_wallet_id_untruncated() -> None:
    orch = BunnyholeOrchestrator(seed_query=BTC_TAPROOT)
    lead_type, node = orch._create_seed_node(BTC_TAPROOT)
    assert lead_type == "bitcoin"
    assert node.id == f"wallet:btc:{BTC_TAPROOT}"


def test_non_wallet_seed_ids_are_unchanged() -> None:
    orch = BunnyholeOrchestrator(seed_query="acme.io")
    lead_type, node = orch._create_seed_node("https://Acme.io/about")
    assert lead_type == "domain"
    assert node.id == "domain:acme.io"


def test_evm_seed_and_onchain_findings_share_one_node() -> None:
    orch = BunnyholeOrchestrator(seed_query=ADDR)
    _, seed = orch._create_seed_node(ADDR)
    info = {"is_contract": False, "public_tags": [{"label": "Exchange"}]}
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r"https://api\.ensdata\.net/.*").mock(return_value=httpx.Response(404))
        router.get(url__regex=r"https://api\.gopluslabs\.io/.*").mock(
            return_value=httpx.Response(200, json={"code": 1, "result": {"cybercrime": "1"}})
        )
        router.get(f"https://eth.blockscout.com/api/v2/addresses/{ADDR_LOW}").mock(
            return_value=httpx.Response(200, json=info)
        )
        router.get(url__regex=r"https://eth\.blockscout\.com/api.*").mock(return_value=httpx.Response(404))
        asyncio.run(orch.onchain.investigate_evm_address(ADDR, seed.id, 1))
    assert _wallet_ids(orch) == [seed.id]
    node = orch.graph.nodes[seed.id]
    assert "PRIMARY_INVESTIGATION_ANCHOR" in node.risk_flags
    assert "GOPLUS_CYBERCRIME" in node.risk_flags
    assert any(r.tool == "blockscout_v2_evm_inspector" for r in node.receipts)


def test_bitcoin_seed_and_onchain_findings_share_one_node() -> None:
    orch = BunnyholeOrchestrator(seed_query=BTC)
    _, seed = orch._create_seed_node(BTC)
    stats = {"chain_stats": {"funded_txo_sum": 150_000_000, "spent_txo_sum": 50_000_000, "tx_count": 3}}
    with respx.mock(assert_all_called=False) as router:
        router.get(f"https://mempool.space/api/address/{BTC}").mock(return_value=httpx.Response(200, json=stats))
        router.get(f"https://mempool.space/api/address/{BTC}/txs").mock(return_value=httpx.Response(200, json=[]))
        asyncio.run(orch.onchain.investigate_bitcoin_utxo(BTC, seed.id, 1))
    assert _wallet_ids(orch) == [seed.id]
    assert orch.graph.nodes[seed.id].attributes["tx_count"] == 3
    assert "PRIMARY_INVESTIGATION_ANCHOR" in orch.graph.nodes[seed.id].risk_flags
