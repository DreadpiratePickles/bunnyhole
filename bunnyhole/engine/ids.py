"""Canonical graph node ids for entities that more than one component creates.

A wallet seeded by the case director and the same wallet found by the on-chain agent must be one node. The
canonical id is ``wallet:<chain>:<address>`` (``wallet:eth:0x...`` / ``wallet:btc:bc1...``), the form the agents
have always used. The case director historically created seeds as ``wallet:0x...`` and ``bitcoin:bc1...``; those
legacy ids are still recognised so findings merge into an existing seed instead of creating a duplicate.
"""

from __future__ import annotations

from typing import List, Protocol

_CHAIN_ALIASES = {
    "eth": "eth",
    "evm": "eth",
    "ethereum": "eth",
    "wallet": "eth",  # the orchestrator's lead type for 0x addresses and ENS names
    "btc": "btc",
    "bitcoin": "btc",
}

# Lead types the case director gives each chain (the prefix of its legacy seed ids).
_LEGACY_SEED_PREFIX = {"eth": "wallet", "btc": "bitcoin"}

# The case director truncates the seed value to this many characters when building a seed id.
_LEGACY_SEED_VALUE_LIMIT = 48


class _HasNodes(Protocol):
    nodes: dict


def normalize_chain(chain: str) -> str:
    """Return the canonical chain code ('eth' or 'btc'); raise ValueError for an unsupported chain."""
    key = (chain or "").strip().lower()
    if key not in _CHAIN_ALIASES:
        raise ValueError(f"Unsupported wallet chain {chain!r}; supported: eth (EVM), btc")
    return _CHAIN_ALIASES[key]


def normalize_wallet_address(chain: str, address: str) -> str:
    """Normalise an address for comparison: EVM hex and bech32 lower-cased, base58 (case-significant) kept."""
    code = normalize_chain(chain)
    addr = (address or "").strip()
    if not addr:
        raise ValueError("Wallet address is empty")
    if code == "eth":
        return addr.lower()
    if addr.lower().startswith(("bc1", "tb1", "bcrt1")):
        return addr.lower()  # bech32 is case-insensitive (and must not be mixed-case)
    return addr  # base58 legacy / P2SH: case carries information


def canonical_wallet_id(chain: str, address: str) -> str:
    """The one node id for a wallet: ``wallet:eth:<0x lower>`` or ``wallet:btc:<address>``."""
    code = normalize_chain(chain)
    return f"wallet:{code}:{normalize_wallet_address(code, address)}"


def legacy_seed_wallet_ids(chain: str, address: str) -> List[str]:
    """Ids the case director gave this wallet as a seed before it used :func:`canonical_wallet_id`."""
    code = normalize_chain(chain)
    raw = (address or "").strip()
    if not raw:
        return []
    value = raw.lower().replace(" ", "_")[:_LEGACY_SEED_VALUE_LIMIT]
    return [f"{_LEGACY_SEED_PREFIX[code]}:{value}"]


def resolve_wallet_node_id(graph: _HasNodes, chain: str, address: str) -> str:
    """Return the id of the node that already represents this wallet, else the canonical id.

    The canonical id wins when it exists; otherwise a legacy seed id that is already in the graph is reused so the
    agent enriches the seed instead of creating a second node for the same address.
    """
    canonical = canonical_wallet_id(chain, address)
    if canonical in graph.nodes:
        return canonical
    for legacy in legacy_seed_wallet_ids(chain, address):
        if legacy in graph.nodes:
            return legacy
    return canonical
