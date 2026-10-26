"""Agent 4: On-Chain Crypto Sleuth (Blockscout Multi-Chain EVM, First-Funder Mother Wallet Gas Tree, CEX Deposit Sweep Clustering, THORChain Calldata Memo Decoder, ENSData Identity Resolver, GoPlus Security Oracle, DexScreener LP Forensics, and Bitcoin Mempool.space CIOH + Peel Chains)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import httpx

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.models import (
    ConfidenceTier,
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    Lead,
    RelationType,
    SelectorStrength,
)

# Known CEX Omnibus Hot Wallets & Mixers for Deposit Sweep Clustering & Attribution
KNOWN_EVM_LABELS: Dict[str, str] = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet 14",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance Hot Wallet 16",
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance Hot Wallet 15",
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase 10",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase 2",
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX Hot Wallet",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH Pool",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH Pool",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
}


class OnChainAgent:
    """Traces EVM, Bitcoin, and Solana wallets, Mother Wallet gas trees, CEX Deposit Sweep clusters, THORChain memos, and DeFi liquidity anomalies."""

    def __init__(self, graph: InvestigationGraph, gear: GearMode = GearMode.FAST) -> None:
        self.graph = graph
        self.gear = gear
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) BunnyholeInvestigativeEngine/0.2"
        }

    @staticmethod
    def decode_thorchain_memo_from_hex(input_hex: str) -> Optional[Dict[str, str]]:
        """
        Deterministically decode THORChain cross-chain swap memo from EVM transaction calldata.
        Example memo embedded in hex: '=:BTC.BTC:bc1qxyz123...:0/1/0:t:0'
        """
        if not input_hex or len(input_hex) < 10:
            return None
        clean_hex = input_hex[2:] if input_hex.startswith("0x") else input_hex
        try:
            raw_bytes = bytes.fromhex(clean_hex)
            ascii_str = raw_bytes.decode("latin-1", errors="ignore")
            m = re.search(r"(=:|SWAP:)([A-Z0-9.\-]+):([a-zA-Z0-9]{26,64})", ascii_str)
            if m:
                return {
                    "action": m.group(1),
                    "target_asset": m.group(2),
                    "destination_address": m.group(3),
                    "full_memo": m.group(0),
                }
        except Exception:
            pass
        return None

    async def investigate_evm_address(self, address_or_ens: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Full ZachXBT-style EVM forensic sweep:
        1. ENSData Unified Web3 Identity Resolution (.eth -> address, Twitter/GitHub/email text records)
        2. GoPlus Web3 Address & Token Security Audit (cybercrime, phishing, mixer, honeypot flags)
        3. Blockscout REST API v2 Address Info & Transactions
        4. Heuristic 1: First-Funder ('Mother Wallet' / Gas Station) Lineage
        5. Heuristic 2: CEX Deposit Sweep Address Detection
        6. Heuristic 3: THORChain Cross-Chain Calldata Memo Decoding
        """
        target = address_or_ens.strip()
        self.graph.log(
            DomainCategory.ONCHAIN,
            "EVM_FORENSIC_SWEEP",
            target,
            f"Running ENSData resolution, GoPlus security audit, Blockscout v2 tx graph & First-Funder trace on '{target}'",
        )

        resolved_address = target if target.startswith("0x") and len(target) == 42 else ""
        ens_name = target if target.endswith(".eth") else ""

        # 1. ENSData Unified Web3 Profile Resolution
        try:
            async with httpx.AsyncClient(timeout=8.0, headers=self.headers) as client:
                ens_resp = await client.get(f"https://api.ensdata.net/{quote_plus(target)}")
                if ens_resp.status_code == 200:
                    ens_data = ens_resp.json()
                    if ens_data.get("address"):
                        resolved_address = ens_data["address"]
                    if ens_data.get("ens"):
                        ens_name = ens_data["ens"]

                    wallet_id = f"wallet:eth:{(resolved_address or target).lower()}"
                    rcpt = EvidenceReceipt(
                        tool="ensdata_web3_identity_resolver",
                        domain=DomainCategory.ONCHAIN,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=f"https://api.ensdata.net/{quote_plus(target)}",
                        extracted_fact=f"ENS Identity Resolution: {ens_name or target} <-> {resolved_address} | twitter={ens_data.get('twitter')} | github={ens_data.get('github')} | email={ens_data.get('email')}",
                        raw_snippet=str(ens_data)[:340],
                    )
                    self.graph.upsert_node(
                        GraphNode(
                            id=wallet_id,
                            label=f"⛓️ {ens_name} ({resolved_address[:10]}...)" if ens_name else f"⛓️ {resolved_address[:14]}...",
                            entity_type=EntityType.CRYPTO_WALLET,
                            domain=DomainCategory.ONCHAIN,
                            selector_strength=SelectorStrength.STRONG,
                            ftm_schema="CryptoWallet",
                            smoke_score=45.0,
                            risk_flags=["ENS_DOXXED_PROFILE"] if (ens_data.get("twitter") or ens_data.get("github") or ens_data.get("email")) else ["ENS_RESOLVED"],
                            attributes={
                                "address": resolved_address,
                                "ens": ens_name,
                                "twitter": ens_data.get("twitter"),
                                "github": ens_data.get("github"),
                                "email": ens_data.get("email"),
                                "url": ens_data.get("url"),
                            },
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    if origin_node_id != wallet_id:
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=origin_node_id,
                                target_id=wallet_id,
                                relation=RelationType.LINKED_IDENTITY,
                                domain=DomainCategory.ONCHAIN,
                                admiralty_code="A1",
                                confidence=0.99,
                                summary=f"ENS {ens_name or resolved_address[:10]}",
                                receipts=[rcpt],
                            )
                        )
                    origin_node_id = wallet_id

                    # Pivot any linked GitHub / Twitter handle or email into OSINT Agent!
                    for social_key in ("github", "twitter"):
                        handle_val = ens_data.get(social_key)
                        if handle_val:
                            self.graph.add_lead(
                                Lead(
                                    seed_value=str(handle_val).lstrip("@"),
                                    lead_type="username",
                                    selector_strength=SelectorStrength.STRONG,
                                    target_agent=DomainCategory.OSINT,
                                    priority_score=88.0,
                                    reason=f"ENS text record '{social_key}' on {ens_name or resolved_address} links to @{handle_val}",
                                    origin_node_id=wallet_id,
                                    hop_depth=hop_depth + 1,
                                )
                            )
        except Exception:
            pass

        if not resolved_address or not resolved_address.startswith("0x"):
            return

        addr_low = resolved_address.lower()
        wallet_id = f"wallet:eth:{addr_low}"

        # 2. GoPlus Malicious Address Security Oracle
        await self._check_goplus_security(addr_low, wallet_id, hop_depth)

        # 3. Blockscout REST API v2 Address Info & Transactions
        bs_base = "https://eth.blockscout.com/api/v2"
        try:
            async with httpx.AsyncClient(timeout=12.0, headers=self.headers) as client:
                info_resp = await client.get(f"{bs_base}/addresses/{addr_low}")
                if info_resp.status_code == 200:
                    info = info_resp.json()
                    is_contract = info.get("is_contract", False)
                    creator_addr = (info.get("creator_address_hash") or "").lower()
                    creation_tx = info.get("creation_tx_hash") or ""
                    ens_domain = info.get("ens_domain_name") or ens_name
                    pub_tags = [t.get("label") for t in (info.get("public_tags") or []) if t.get("label")]

                    rcpt = EvidenceReceipt(
                        tool="blockscout_v2_evm_inspector",
                        domain=DomainCategory.ONCHAIN,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=f"https://eth.blockscout.com/address/{addr_low}",
                        extracted_fact=f"EVM Address {addr_low}: is_contract={is_contract}, creator={creator_addr}, ens={ens_domain}, tags={pub_tags}",
                        raw_snippet=str(info)[:350],
                    )
                    self.graph.upsert_node(
                        GraphNode(
                            id=wallet_id,
                            label=f"📜 Contract: {ens_domain or addr_low[:12]}..." if is_contract else f"⛓️ {ens_domain or addr_low[:14]}...",
                            entity_type=EntityType.SMART_CONTRACT if is_contract else EntityType.CRYPTO_WALLET,
                            domain=DomainCategory.ONCHAIN,
                            selector_strength=SelectorStrength.STRONG,
                            smoke_score=50.0,
                            risk_flags=pub_tags,
                            attributes={
                                "address": addr_low,
                                "is_contract": is_contract,
                                "creator_address": creator_addr,
                                "creation_tx": creation_tx,
                                "public_tags": pub_tags,
                            },
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )

                    # If it's a Smart Contract, link & pivot to the Deployer Wallet!
                    if is_contract and creator_addr:
                        dep_id = f"wallet:eth:{creator_addr}"
                        self.graph.upsert_node(
                            GraphNode(
                                id=dep_id,
                                label=f"🛠️ Deployer: {creator_addr[:14]}...",
                                entity_type=EntityType.CRYPTO_WALLET,
                                domain=DomainCategory.ONCHAIN,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=68.0,
                                risk_flags=["SMART_CONTRACT_DEPLOYER"],
                                attributes={"address": creator_addr, "deployed_contract": addr_low},
                                receipts=[rcpt],
                                hop_depth=hop_depth + 1,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=wallet_id,
                                target_id=dep_id,
                                relation=RelationType.DEPLOYED_BY,
                                domain=DomainCategory.ONCHAIN,
                                admiralty_code="A1",
                                confidence=1.0,
                                summary=f"Deployed in tx {creation_tx[:10]}...",
                                receipts=[rcpt],
                            )
                        )
                        self.graph.add_lead(
                            Lead(
                                seed_value=creator_addr,
                                lead_type="wallet",
                                selector_strength=SelectorStrength.STRONG,
                                target_agent=DomainCategory.ONCHAIN,
                                priority_score=84.0,
                                reason=f"Contract Deployer of {addr_low[:10]}... -> Trace First-Funder Mother Wallet",
                                origin_node_id=dep_id,
                                hop_depth=hop_depth + 1,
                            )
                        )

                # Fetch transactions to trace First-Funder, Counterparties, CEX Sweeps, and THORChain Memos
                tx_resp = await client.get(f"{bs_base}/addresses/{addr_low}/transactions")
                if tx_resp.status_code == 200:
                    tx_items = tx_resp.json().get("items", [])
                    incoming_funders: List[Dict[str, Any]] = []
                    for tx in tx_items[:20]:
                        tx_hash = tx.get("hash", "")
                        ts = tx.get("timestamp", "")
                        from_obj = tx.get("from") or {}
                        to_obj = tx.get("to") or {}
                        from_addr = (from_obj.get("hash") or "").lower()
                        to_addr = (to_obj.get("hash") or "").lower()
                        from_name = from_obj.get("name") or from_obj.get("ens_domain_name") or KNOWN_EVM_LABELS.get(from_addr, "")
                        to_name = to_obj.get("name") or to_obj.get("ens_domain_name") or KNOWN_EVM_LABELS.get(to_addr, "")
                        val_wei = int(tx.get("value") or "0")
                        val_eth = val_wei / 1e18
                        raw_input = tx.get("raw_input") or ""

                        # Check Heuristic 3: THORChain Cross-Chain Memo Decoding!
                        thor_memo = self.decode_thorchain_memo_from_hex(raw_input)
                        if thor_memo:
                            dest_btc = thor_memo["destination_address"]
                            btc_id = f"wallet:btc:{dest_btc}"
                            t_rcpt = EvidenceReceipt(
                                tool="thorchain_calldata_memo_decoder",
                                domain=DomainCategory.ONCHAIN,
                                admiralty_code="A1",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=f"https://eth.blockscout.com/tx/{tx_hash}",
                                extracted_fact=f"THORChain cross-chain swap memo in tx {tx_hash[:12]}... deterministically routes to {thor_memo['target_asset']} address '{dest_btc}'",
                                raw_snippet=f"memo={thor_memo['full_memo']} | value_eth={val_eth:.4f}",
                            )
                            self.graph.upsert_node(
                                GraphNode(
                                    id=btc_id,
                                    label=f"₿ Cross-Chain Dest: {dest_btc[:14]}...",
                                    entity_type=EntityType.CRYPTO_WALLET,
                                    domain=DomainCategory.ONCHAIN,
                                    selector_strength=SelectorStrength.STRONG,
                                    smoke_score=88.0,
                                    risk_flags=["THORCHAIN_CROSS_CHAIN_HOP_DESTINATION"],
                                    attributes={"address": dest_btc, "asset": thor_memo["target_asset"], "source_evm_tx": tx_hash},
                                    receipts=[t_rcpt],
                                    hop_depth=hop_depth + 1,
                                )
                            )
                            self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=wallet_id,
                                    target_id=btc_id,
                                    relation=RelationType.BRIDGED_TO,
                                    domain=DomainCategory.ONCHAIN,
                                    admiralty_code="A1",
                                    confidence=1.0,
                                    summary=f"THORChain Memo -> {dest_btc[:10]}...",
                                    event_date=ts,
                                    receipts=[t_rcpt],
                                )
                            )
                            if dest_btc.startswith(("bc1", "1", "3")):
                                self.graph.add_lead(
                                    Lead(
                                        seed_value=dest_btc,
                                        lead_type="bitcoin",
                                        selector_strength=SelectorStrength.STRONG,
                                        target_agent=DomainCategory.ONCHAIN,
                                        priority_score=92.0,
                                        reason=f"Cross-chain BTC destination decoded from THORChain calldata memo in {tx_hash[:10]}",
                                        origin_node_id=btc_id,
                                        hop_depth=hop_depth + 1,
                                    )
                                )

                        if to_addr == addr_low and from_addr and from_addr != addr_low and val_eth > 0:
                            incoming_funders.append({"from": from_addr, "name": from_name, "eth": val_eth, "tx": tx_hash, "ts": ts})

                        # Track major outgoing flows or mixer/CEX interactions
                        if from_addr == addr_low and to_addr and (val_eth >= 0.1 or to_addr in KNOWN_EVM_LABELS):
                            cp_id = f"wallet:eth:{to_addr}"
                            label_str = to_name or f"{to_addr[:12]}..."
                            is_mixer = "tornado" in label_str.lower()
                            is_cex = any(k in label_str.lower() for k in ("binance", "coinbase", "okx", "kraken", "bybit"))
                            rcpt = EvidenceReceipt(
                                tool="blockscout_v2_tx_tracer",
                                domain=DomainCategory.ONCHAIN,
                                admiralty_code="A1",
                                selector_strength=SelectorStrength.STRONG,
                                source_url=f"https://eth.blockscout.com/tx/{tx_hash}",
                                extracted_fact=f"Transferred {val_eth:.4f} ETH from {addr_low[:10]}... to {label_str} ({to_addr}) at {ts}",
                                raw_snippet=f"tx={tx_hash} | from={addr_low} | to={to_addr} ({label_str}) | eth={val_eth:.4f}",
                            )
                            flags = []
                            if is_mixer:
                                flags.append("PRIVACY_MIXER_INTERACTION")
                            if is_cex:
                                flags.append("CEX_HOT_WALLET_SWEEP")
                            self.graph.upsert_node(
                                GraphNode(
                                    id=cp_id,
                                    label=f"🌪️ {label_str}" if is_mixer else (f"🏦 {label_str}" if is_cex else f"⛓️ {label_str}"),
                                    entity_type=EntityType.CRYPTO_WALLET,
                                    domain=DomainCategory.ONCHAIN,
                                    selector_strength=SelectorStrength.STRONG,
                                    smoke_score=85.0 if is_mixer else (60.0 if is_cex else 42.0),
                                    risk_flags=flags,
                                    attributes={"address": to_addr, "label": label_str},
                                    receipts=[rcpt],
                                    hop_depth=hop_depth + 1,
                                )
                            )
                            self.graph.upsert_edge(
                                GraphEdge(
                                    source_id=wallet_id,
                                    target_id=cp_id,
                                    relation=RelationType.TRANSFERRED_TO,
                                    domain=DomainCategory.ONCHAIN,
                                    admiralty_code="A1",
                                    confidence=1.0,
                                    summary=f"Sent {val_eth:.3f} ETH",
                                    event_date=ts,
                                    receipts=[rcpt],
                                )
                            )

                    # Heuristic 1: Link Earliest Chronological Incoming Gas Funder ('Mother Wallet') via sort=asc
                    first_f: Optional[Dict[str, Any]] = None
                    try:
                        asc_url = (
                            f"https://eth.blockscout.com/api?module=account&action=txlist"
                            f"&address={addr_low}&page=1&offset=5&sort=asc"
                        )
                        asc_resp = await client.get(asc_url)
                        if asc_resp.status_code == 200:
                            asc_items = asc_resp.json().get("result", [])
                            if isinstance(asc_items, list):
                                for atx in asc_items:
                                    afrom = (atx.get("from") or "").lower()
                                    ato = (atx.get("to") or "").lower()
                                    aval = int(atx.get("value") or "0") / 1e18
                                    if ato == addr_low and afrom and afrom != addr_low and aval > 0:
                                        first_f = {
                                            "from": afrom,
                                            "name": KNOWN_EVM_LABELS.get(afrom, ""),
                                            "eth": aval,
                                            "tx": atx.get("hash", ""),
                                            "ts": atx.get("timeStamp", ""),
                                        }
                                        break
                    except Exception:
                        pass

                    # Only fall back to page-1 v2 list if the entire wallet has < 20 txs (so page 1 reaches genesis)
                    if not first_f and incoming_funders and len(tx_items) < 20:
                        first_f = incoming_funders[-1]

                    if first_f:
                        f_addr = first_f["from"]
                        f_name = first_f["name"] or f"{f_addr[:12]}..."
                        f_id = f"wallet:eth:{f_addr}"
                        f_rcpt = EvidenceReceipt(
                            tool="first_funder_gas_lineage (sort=asc)",
                            domain=DomainCategory.ONCHAIN,
                            admiralty_code="A1",
                            selector_strength=SelectorStrength.STRONG,
                            source_url=f"https://eth.blockscout.com/tx/{first_f['tx']}",
                            extracted_fact=f"First-Funder Gas Lineage (Genesis Incoming Tx): {f_name} ({f_addr}) funded {addr_low} with {first_f['eth']:.4f} ETH in tx {first_f['tx'][:12]}...",
                            raw_snippet=str(first_f),
                        )
                        self.graph.upsert_node(
                            GraphNode(
                                id=f_id,
                                label=f"⛽ Mother Funder: {f_name}",
                                entity_type=EntityType.CRYPTO_WALLET,
                                domain=DomainCategory.ONCHAIN,
                                selector_strength=SelectorStrength.STRONG,
                                smoke_score=72.0,
                                risk_flags=["MOTHER_WALLET_GAS_FUNDER"],
                                attributes={"address": f_addr, "label": f_name},
                                receipts=[f_rcpt],
                                hop_depth=hop_depth + 1,
                            )
                        )
                        self.graph.upsert_edge(
                            GraphEdge(
                                source_id=wallet_id,
                                target_id=f_id,
                                relation=RelationType.FIRST_FUNDED_BY,
                                domain=DomainCategory.ONCHAIN,
                                admiralty_code="A1",
                                confidence=0.98,
                                summary=f"Funded {first_f['eth']:.3f} ETH",
                                event_date=str(first_f["ts"]),
                                receipts=[f_rcpt],
                            )
                        )
        except Exception as exc:
            self.graph.log(DomainCategory.ONCHAIN, "EVM_SWEEP_NOTE", addr_low, f"Blockscout query note: {exc}")

    async def _check_goplus_security(self, addr_low: str, wallet_id: str, hop_depth: int) -> None:
        """Query GoPlus Security Oracle for malicious address flags (cybercrime, money laundering, phishing, mixer, sanctions)."""
        url = f"https://api.gopluslabs.io/api/v1/address_security/{addr_low}?chain_id=1"
        try:
            async with httpx.AsyncClient(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                res = resp.json().get("result") or {}
                triggered = [
                    k.upper()
                    for k, v in res.items()
                    if str(v) == "1" and k not in ("data_source",)
                ]
                if triggered:
                    rcpt = EvidenceReceipt(
                        tool="goplus_web3_security_oracle",
                        domain=DomainCategory.ONCHAIN,
                        admiralty_code="A1",
                        selector_strength=SelectorStrength.STRONG,
                        source_url=url,
                        extracted_fact=f"GoPlus Security Alert on {addr_low}: Flagged for {triggered}",
                        raw_snippet=str(res)[:320],
                    )
                    if wallet_id in self.graph.nodes:
                        node = self.graph.nodes[wallet_id]
                        node.smoke_score = max(node.smoke_score, 92.0)
                        for f in triggered:
                            flag = f"GOPLUS_{f}"
                            if flag not in node.risk_flags:
                                node.risk_flags.append(flag)
                        node.receipts.append(rcpt)
        except Exception:
            pass

    async def investigate_dexscreener_tokens(self, query: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Search DexScreener API for tokens, LP liquidity concentration, and thin-liquidity manipulation traps.
        Red-Cell Guardrail: Unless `query` is an exact contract address (0x...), ticker/keyword matches
        are quarantined to ConfidenceTier.HYPOTHESIS (SelectorStrength.SOFT, C3) to prevent spoofed meme-token pollution.
        """
        clean_q = query.strip()
        is_exact_contract = bool(re.match(r"^0x[a-fA-F0-9]{40}$", clean_q))
        if not is_exact_contract and len(clean_q) < 4:
            return
        url = f"https://api.dexscreener.com/latest/dex/search?q={quote_plus(clean_q)}"
        try:
            async with httpx.AsyncClient(timeout=8.0, headers=self.headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return
                pairs = resp.json().get("pairs", [])[:2]
                for p in pairs:
                    chain_id = p.get("chainId", "eth")
                    dex_id = p.get("dexId", "dex")
                    base_tok = p.get("baseToken", {})
                    tok_addr = base_tok.get("address", "")
                    tok_sym = base_tok.get("symbol", "")
                    tok_name = base_tok.get("name", "")
                    liq_usd = float((p.get("liquidity") or {}).get("usd") or 0.0)
                    fdv = float(p.get("fdv") or 0.0)
                    pair_url = p.get("url") or f"https://dexscreener.com/{chain_id}/{tok_addr}"

                    flags = [f"DEX_{dex_id.upper()}_{chain_id.upper()}"]
                    if not is_exact_contract:
                        flags.append("UNCORROBORATED_TICKER_HYPOTHESIS")
                    smoke = 40.0 if is_exact_contract else 28.0
                    # Flag thin-liquidity FDV manipulation trap (Liquidity < 2% of FDV when FDV > $1M)
                    if fdv > 1_000_000 and liq_usd > 0 and (liq_usd / fdv) < 0.02:
                        flags.append("THIN_LIQUIDITY_FDV_MANIPULATION_TRAP")
                        smoke = 82.0 if is_exact_contract else 55.0

                    sel_strength = SelectorStrength.STRONG if is_exact_contract else SelectorStrength.SOFT
                    adm_code = "B1" if is_exact_contract else "C3"
                    edge_tier = ConfidenceTier.VERIFIED if is_exact_contract else ConfidenceTier.HYPOTHESIS
                    edge_conf = 0.90 if is_exact_contract else 0.42

                    rcpt = EvidenceReceipt(
                        tool="dexscreener_lp_forensics",
                        domain=DomainCategory.ONCHAIN,
                        admiralty_code=adm_code,
                        selector_strength=sel_strength,
                        source_url=pair_url,
                        extracted_fact=f"Token ${tok_sym} ({tok_name} on {chain_id}/{dex_id}): FDV=${fdv:,.0f}, Liquidity=${liq_usd:,.0f}, Contract={tok_addr}",
                        raw_snippet=f"symbol={tok_sym} | contract={tok_addr} | fdv={fdv} | liquidity_usd={liq_usd} | exact_contract_match={is_exact_contract}",
                    )
                    tok_id = f"token:{chain_id}:{tok_addr.lower()}"
                    self.graph.upsert_node(
                        GraphNode(
                            id=tok_id,
                            label=f"🪙 ${tok_sym} ({chain_id}): FDV ${fdv:,.0f} / Liq ${liq_usd:,.0f}",
                            entity_type=EntityType.TOKEN,
                            domain=DomainCategory.ONCHAIN,
                            selector_strength=sel_strength,
                            smoke_score=smoke,
                            risk_flags=flags,
                            attributes={
                                "symbol": tok_sym,
                                "name": tok_name,
                                "chain": chain_id,
                                "contract_address": tok_addr,
                                "fdv_usd": fdv,
                                "liquidity_usd": liq_usd,
                                "is_uncorroborated_ticker_match": not is_exact_contract,
                            },
                            receipts=[rcpt],
                            hop_depth=hop_depth,
                        )
                    )
                    self.graph.upsert_edge(
                        GraphEdge(
                            source_id=origin_node_id,
                            target_id=tok_id,
                            relation=RelationType.SWAPPED_IN,
                            domain=DomainCategory.ONCHAIN,
                            admiralty_code=adm_code,
                            confidence=edge_conf,
                            tier=edge_tier,
                            summary=f"${tok_sym} on {dex_id} ({'Exact' if is_exact_contract else 'Ticker Hypothesis'})",
                            amount_usd=liq_usd,
                            skeptic_notes=(
                                None
                                if is_exact_contract
                                else "Red-Cell Quarantine: Matched by ticker/keyword only. Anyone can deploy a spoofed ERC-20/SPL token; verify contract deployer before attributing."
                            ),
                            receipts=[rcpt],
                        )
                    )
        except Exception:
            pass

    async def investigate_bitcoin_utxo(self, btc_address: str, origin_node_id: str, hop_depth: int) -> None:
        """
        Bitcoin UTXO Forensics via keyless Mempool.space REST API:
        1. Common Input Ownership Heuristic (CIOH) co-spent input clustering
        2. Peel Chain Detection (80%+ fractional change output + small peel output)
        """
        addr = btc_address.strip()
        self.graph.log(
            DomainCategory.ONCHAIN,
            "BITCOIN_UTXO_FORENSICS",
            addr,
            f"Running Mempool.space UTXO Common-Input-Ownership (CIOH) & Peel Chain analysis on '{addr}'",
        )
        base_url = f"https://mempool.space/api/address/{addr}"
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=self.headers) as client:
                resp = await client.get(base_url)
                if resp.status_code != 200:
                    return
                stats = resp.json().get("chain_stats", {})
                funded_sats = stats.get("funded_txo_sum", 0)
                spent_sats = stats.get("spent_txo_sum", 0)
                tx_count = stats.get("tx_count", 0)
                bal_btc = (funded_sats - spent_sats) / 1e8

                btc_id = f"wallet:btc:{addr}"
                rcpt = EvidenceReceipt(
                    tool="mempool_space_utxo_forensics",
                    domain=DomainCategory.ONCHAIN,
                    admiralty_code="A1",
                    selector_strength=SelectorStrength.STRONG,
                    source_url=f"https://mempool.space/address/{addr}",
                    extracted_fact=f"Bitcoin Address {addr}: Total Received={funded_sats/1e8:.4f} BTC, Current Balance={bal_btc:.4f} BTC across {tx_count} txs",
                    raw_snippet=str(stats)[:300],
                )
                self.graph.upsert_node(
                    GraphNode(
                        id=btc_id,
                        label=f"₿ {addr[:14]}... ({funded_sats/1e8:.2f} BTC rx)",
                        entity_type=EntityType.CRYPTO_WALLET,
                        domain=DomainCategory.ONCHAIN,
                        selector_strength=SelectorStrength.STRONG,
                        smoke_score=55.0,
                        risk_flags=["BITCOIN_UTXO_CLUSTERED"],
                        attributes={"address": addr, "total_received_btc": funded_sats / 1e8, "balance_btc": bal_btc, "tx_count": tx_count},
                        receipts=[rcpt],
                        hop_depth=hop_depth,
                    )
                )

                tx_resp = await client.get(f"{base_url}/txs")
                if tx_resp.status_code == 200:
                    txs = tx_resp.json()[:6]
                    for tx in txs:
                        txid = tx.get("txid", "")
                        vins = tx.get("vin", [])
                        vouts = tx.get("vout", [])
                        # Coinbase inputs have prevout == null; guard so mining txs don't raise and
                        # abort the whole Bitcoin analysis.
                        in_addrs = [
                            (v.get("prevout") or {}).get("scriptpubkey_address")
                            for v in vins
                            if (v.get("prevout") or {}).get("scriptpubkey_address")
                        ]
                        # CIOH: If addr is one of multiple inputs, all co-inputs belong to the same entity!
                        if addr in in_addrs and len(set(in_addrs)) > 1 and len(set(in_addrs)) <= 8:
                            for co_addr in set(in_addrs):
                                if co_addr and co_addr != addr:
                                    co_id = f"wallet:btc:{co_addr}"
                                    c_rcpt = EvidenceReceipt(
                                        tool="cioh_common_input_heuristic",
                                        domain=DomainCategory.ONCHAIN,
                                        admiralty_code="A1",
                                        selector_strength=SelectorStrength.STRONG,
                                        source_url=f"https://mempool.space/tx/{txid}",
                                        extracted_fact=f"Common Input Ownership Heuristic (CIOH): {addr} and {co_addr} co-signed inputs in tx {txid[:12]}...",
                                        raw_snippet=f"txid={txid} | co_inputs={list(set(in_addrs))[:5]}",
                                    )
                                    self.graph.upsert_node(
                                        GraphNode(
                                            id=co_id,
                                            label=f"₿ CIOH Co-Signer: {co_addr[:14]}...",
                                            entity_type=EntityType.CRYPTO_WALLET,
                                            domain=DomainCategory.ONCHAIN,
                                            selector_strength=SelectorStrength.STRONG,
                                            smoke_score=64.0,
                                            risk_flags=["CIOH_CO_SPENT_WALLET"],
                                            attributes={"address": co_addr, "cioh_tx": txid},
                                            receipts=[c_rcpt],
                                            hop_depth=hop_depth + 1,
                                        )
                                    )
                                    self.graph.upsert_edge(
                                        GraphEdge(
                                            source_id=btc_id,
                                            target_id=co_id,
                                            relation=RelationType.LINKED_IDENTITY,
                                            domain=DomainCategory.ONCHAIN,
                                            admiralty_code="A1",
                                            confidence=0.96,
                                            summary="CIOH Co-Signed Inputs",
                                            receipts=[c_rcpt],
                                        )
                                    )

                        # Peel Chain Detection: 2 outputs where one output > 80% of total value
                        if addr in in_addrs and len(vouts) == 2:
                            v0 = vouts[0].get("value", 0)
                            v1 = vouts[1].get("value", 0)
                            tot = v0 + v1
                            if tot > 100_000:
                                larger = vouts[0] if v0 >= v1 else vouts[1]
                                ratio = larger.get("value", 0) / tot
                                change_addr = larger.get("scriptpubkey_address")
                                if ratio >= 0.80 and change_addr and change_addr != addr:
                                    ch_id = f"wallet:btc:{change_addr}"
                                    p_rcpt = EvidenceReceipt(
                                        tool="bitcoin_peel_chain_detector",
                                        domain=DomainCategory.ONCHAIN,
                                        admiralty_code="A2",
                                        selector_strength=SelectorStrength.STRONG,
                                        source_url=f"https://mempool.space/tx/{txid}",
                                        extracted_fact=f"Peel Chain Step in tx {txid[:12]}...: {ratio*100:.1f}% change ({larger.get('value',0)/1e8:.4f} BTC) routed to {change_addr}",
                                        raw_snippet=f"txid={txid} | peel_ratio={ratio:.3f} | change_addr={change_addr}",
                                    )
                                    self.graph.upsert_node(
                                        GraphNode(
                                            id=ch_id,
                                            label=f"🍌 Peel Change ({ratio*100:.0f}%): {change_addr[:14]}...",
                                            entity_type=EntityType.CRYPTO_WALLET,
                                            domain=DomainCategory.ONCHAIN,
                                            selector_strength=SelectorStrength.STRONG,
                                            smoke_score=75.0,
                                            risk_flags=["PEEL_CHAIN_CONTINUATION_ADDRESS"],
                                            attributes={"address": change_addr, "peel_ratio": round(ratio, 3)},
                                            receipts=[p_rcpt],
                                            hop_depth=hop_depth + 1,
                                        )
                                    )
                                    self.graph.upsert_edge(
                                        GraphEdge(
                                            source_id=btc_id,
                                            target_id=ch_id,
                                            relation=RelationType.TRANSFERRED_TO,
                                            domain=DomainCategory.ONCHAIN,
                                            admiralty_code="A2",
                                            confidence=0.89,
                                            summary=f"Peel Chain ({ratio*100:.0f}% change)",
                                            receipts=[p_rcpt],
                                        )
                                    )
        except Exception:
            pass
