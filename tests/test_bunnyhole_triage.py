"""Ground-Truth Unit Test Suite for Bunnyhole (Reviewer Triage Plan + Karpathy 3-Stage LLM Council)."""

from __future__ import annotations

import asyncio
import unittest

from bunnyhole.agents.accountant import (
    AccountantAgent,
    icao_hex_to_n_number,
    n_number_to_icao_hex,
)
from bunnyhole.agents.link_sleuth import LinkSleuthAgent, extract_entity_stem
from bunnyhole.agents.onchain import OnChainAgent
from bunnyhole.engine.council import (
    InvestigativeCouncil,
    parse_ranking_from_text,
)
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
    TimelineItem,
)


class TestBunnyholeTriageAndCouncil(unittest.TestCase):
    def test_faa_n_number_icao_hex_bijection(self) -> None:
        """Verify deterministic FAA Tail N-Number <-> 24-bit ICAO Mode-S Hex round-trip & invalid suffix rejection."""
        cases = {
            "N1": "a00001",
            "N628TS": "a835af",
            "N99999": "adf7c7",
        }
        for tail, expected_hex in cases.items():
            computed_hex = n_number_to_icao_hex(tail)
            self.assertEqual(computed_hex, expected_hex)
            self.assertEqual(icao_hex_to_n_number(expected_hex), tail)

        # Reject invalid FAA tail where digits follow alpha suffix
        self.assertIsNone(n_number_to_icao_hex("N12A3"))
        self.assertIsNone(n_number_to_icao_hex("N0123"))

    def test_beneish_m_score_forensic_math(self) -> None:
        """Verify 8-variable Beneish M-Score flags earnings manipulation (> -1.78) and passes clean baselines."""
        clean = AccountantAgent.calculate_beneish_m_score({
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
            "net_income_t": 15.0,
            "operating_cash_flow_t": 18.0,
        })
        self.assertFalse(clean["is_flagged"])
        self.assertLess(clean["m_score"], -1.78)

        manipulated = AccountantAgent.calculate_beneish_m_score({
            "revenue_t": 220.0,
            "revenue_t1": 100.0,
            "receivables_t": 95.0,
            "receivables_t1": 15.0,
            "gross_margin_t": 0.25,
            "gross_margin_t1": 0.50,
            "current_assets_t": 60.0,
            "current_assets_t1": 80.0,
            "ppe_t": 20.0,
            "ppe_t1": 40.0,
            "total_assets_t": 300.0,
            "total_assets_t1": 180.0,
            "net_income_t": 45.0,
            "operating_cash_flow_t": -15.0,
        })
        self.assertTrue(manipulated["is_flagged"])
        self.assertIn("BENEISH_M_SCORE_MANIPULATION_ALERT", manipulated["flags"])
        self.assertIn("CHANNEL_STUFFING_RECEIVABLES_SPIKE", manipulated["flags"])
        self.assertIn("CASH_FLOW_VS_NET_INCOME_DIVERGENCE", manipulated["flags"])

    def test_extract_entity_stem_stopword_filtering(self) -> None:
        """Ensure generic corporate/dictionary prefixes do not spawn false-positive stems."""
        self.assertEqual(extract_entity_stem("First Global Capital Holdings LLC"), "")
        self.assertEqual(extract_entity_stem("Apex Digital Block Ventures Inc."), "")
        self.assertEqual(extract_entity_stem("Uniswap Labs Inc."), "uniswap")
        self.assertEqual(extract_entity_stem("https://palantir.com/about"), "palantir")

    def test_graph_guardrails_and_iso8601_timeline(self) -> None:
        """Verify Registered Agent downgrade, Anycast CDN downgrade, and ISO-8601 timeline normalization."""
        g = InvestigationGraph("test_case", "Acme")
        corp = g.upsert_node(
            GraphNode(
                id="corp:acme",
                label="Acme Corp",
                entity_type=EntityType.ORGANIZATION,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.STRONG,
            )
        )
        reg_agent = g.upsert_node(
            GraphNode(
                id="loc:csc",
                label="📍 251 Little Falls Drive, Wilmington, DE",
                entity_type=EntityType.LOCATION,
                domain=DomainCategory.FIAT,
                selector_strength=SelectorStrength.STRONG,
            )
        )
        self.assertIn("MASS_REGISTERED_AGENT_ADDRESS", reg_agent.risk_flags)

        edge = g.upsert_edge(
            GraphEdge(
                source_id=corp.id,
                target_id=reg_agent.id,
                relation=RelationType.REGISTERED_AT,
                domain=DomainCategory.FIAT,
                admiralty_code="A1",
                confidence=0.95,
            )
        )
        self.assertEqual(edge.tier, ConfidenceTier.HYPOTHESIS)
        self.assertLessEqual(edge.confidence, 0.30)
        self.assertEqual(edge.admiralty_code, "B5")

        # Timeline normalization across RFC-2822, bare year, and ISO-8601
        g.add_timeline_event(
            TimelineItem(
                timestamp="Tue, 14 Oct 2025 12:30:00 GMT",
                domain=DomainCategory.JOURNALISM,
                title="Event 2025",
                description="RFC-2822 date",
            )
        )
        g.add_timeline_event(
            TimelineItem(
                timestamp="2021",
                domain=DomainCategory.JOURNALISM,
                title="Event 2021",
                description="Bare year",
            )
        )
        self.assertEqual(g.timeline[0].title, "Event 2021")
        self.assertTrue(g.timeline[0].timestamp.startswith("2021-01-01"))
        self.assertTrue(g.timeline[1].timestamp.startswith("2025-10-14"))

    def test_thorchain_memo_decoder(self) -> None:
        """Verify deterministic THORChain cross-chain calldata memo extraction."""
        memo_ascii = "=:BTC.BTC:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh:0/1/0"
        hex_payload = "0x" + memo_ascii.encode("ascii").hex()
        decoded = OnChainAgent.decode_thorchain_memo_from_hex(hex_payload)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["target_asset"], "BTC.BTC")
        self.assertEqual(decoded["destination_address"], "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")

    def test_karpathy_llm_council_three_stages(self) -> None:
        """Verify Stage 1 opinions, Stage 2 anonymized peer rankings, and Stage 3 Chairman verdict."""
        g = InvestigationGraph("council_test", "vitalik.eth")
        rcpt = EvidenceReceipt(
            tool="ensdata_web3_identity_resolver",
            domain=DomainCategory.ONCHAIN,
            admiralty_code="A1",
            selector_strength=SelectorStrength.STRONG,
            source_url="https://api.ensdata.net/vitalik.eth",
            extracted_fact="ENS vitalik.eth resolves to 0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
            raw_snippet="ens=vitalik.eth",
        )
        n1 = g.upsert_node(
            GraphNode(
                id="seed:vitalik",
                label="🎯 vitalik.eth",
                entity_type=EntityType.CRYPTO_WALLET,
                domain=DomainCategory.ONCHAIN,
                selector_strength=SelectorStrength.STRONG,
                receipts=[rcpt],
            )
        )
        n2 = g.upsert_node(
            GraphNode(
                id="account:github:vbuterin",
                label="👤 GitHub: @vbuterin",
                entity_type=EntityType.ACCOUNT,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
                receipts=[rcpt],
            )
        )
        g.upsert_edge(
            GraphEdge(
                source_id=n1.id,
                target_id=n2.id,
                relation=RelationType.LINKED_IDENTITY,
                domain=DomainCategory.ONCHAIN,
                admiralty_code="A1",
                confidence=0.99,
                tier=ConfidenceTier.VERIFIED,
                summary="ENS github record -> @vbuterin",
                receipts=[rcpt],
            )
        )

        sleuth = LinkSleuthAgent(g)
        inter = sleuth.analyze_interconnected_web()
        council = InvestigativeCouncil(g)
        res = asyncio.run(council.run_full_council(inter, []))

        self.assertEqual(len(res["stage1_opinions"]), 5)
        self.assertEqual(len(res["stage2_peer_rankings"]), 5)
        self.assertEqual(len(res["aggregate_rankings"]), 5)
        self.assertIn("Response A", res["label_to_member"])
        self.assertIn("verdict_markdown", res["stage3_chairman_verdict"])
        self.assertGreaterEqual(res["stage3_chairman_verdict"]["verified_facts_count"], 1)

        # Also test parse_ranking_from_text directly
        sample_ballot = "Analysis...\n\nFINAL RANKING:\n1. Response C\n2. Response A\n3. Response B"
        self.assertEqual(parse_ranking_from_text(sample_ballot), ["Response C", "Response A", "Response B"])

    def test_smart_intake_parser_omni_text(self) -> None:
        """Verify SmartIntakeParser extracts hypothesis, credentials, emails, phones, handles, wallets, domains, tails, files & exclusions."""
        from bunnyhole.engine.intake import SmartIntakeParser

        raw_dump = (
            "Hypothesis: Prove whether @vbuterin and founder@uniswap.org are connected to jet N628TS\n"
            "Found creds: dev_ops@acme.io:Summer2025! and backup@acme.io:Summer2025!\n"
            "Phone: +1-415-555-0199 Wallet: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 and vitalik.eth\n"
            "Docs: /tmp/leak_report.pdf /tmp/board_minutes.docx -cloudflare.com"
        )
        pkt = SmartIntakeParser.parse_omni_text(raw_dump)
        self.assertIn("Prove whether", pkt.hypothesis)
        self.assertIn("@vbuterin", pkt.usernames)
        self.assertIn("founder@uniswap.org", pkt.emails)
        self.assertEqual(len(pkt.credentials), 2)
        self.assertIn("dev_ops@acme.io:Summer2025!", pkt.credentials)
        self.assertTrue(any("4155550199" in p for p in pkt.phones))
        self.assertIn("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", pkt.wallets)
        self.assertIn("vitalik.eth", pkt.wallets)
        self.assertIn("N628TS", pkt.aircraft_tails)
        self.assertIn("/tmp/leak_report.pdf", pkt.evidence_files)
        self.assertIn("/tmp/board_minutes.docx", pkt.evidence_files)
        self.assertIn("cloudflare.com", pkt.exclusions)

    def test_credential_password_reuse_clustering_and_exclusions(self) -> None:
        """Verify two accounts sharing a leaked password deterministically link via a shared password hash node, and exclusions block leads."""
        from bunnyhole.agents.osint import OSINTAgent
        from bunnyhole.engine.models import Lead

        g = InvestigationGraph(
            "cred_case",
            "credential_cluster",
            hypothesis="Investigate whether shadow_admin and ceo@offshore-shell.io share infrastructure",
            exclusions=["cloudflare.com", "ignored-wallet.eth"],
        )
        # Verify negative scope exclusion blocks excluded leads and boosts hypothesis-matching leads
        self.assertTrue(g.is_excluded("sub.cloudflare.com"))
        l_blocked = g.add_lead(
            Lead(
                lead_id="lead:blocked",
                lead_type="domain",
                seed_value="sub.cloudflare.com",
                target_agent=DomainCategory.OSINT,
                priority_score=90.0,
                reason="CDN domain",
                origin_node_id="seed",
                hop_depth=1,
            )
        )
        self.assertTrue(l_blocked.explored)
        self.assertEqual(len(g.leads), 0)

        l_aligned = g.add_lead(
            Lead(
                lead_id="lead:aligned",
                lead_type="domain",
                seed_value="offshore-shell.io",
                target_agent=DomainCategory.FIAT,
                priority_score=50.0,
                reason="Check corporate shell",
                origin_node_id="seed",
                hop_depth=1,
            )
        )
        self.assertEqual(len(g.leads), 1)
        # Priority should be boosted by +20.0 because 'offshore-shell.io' appears in the hypothesis
        self.assertGreaterEqual(l_aligned.priority_score, 70.0)

        g.upsert_node(
            GraphNode(
                id="seed:1",
                label="Seed 1",
                entity_type=EntityType.ACCOUNT,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
            )
        )
        g.upsert_node(
            GraphNode(
                id="seed:2",
                label="Seed 2",
                entity_type=EntityType.ACCOUNT,
                domain=DomainCategory.OSINT,
                selector_strength=SelectorStrength.STRONG,
            )
        )
        osint = OSINTAgent(g)
        r1 = asyncio.run(osint.investigate_credential_combo("alice@corp-a.io:UltraSecretPass99!", "seed:1", hop_depth=0))
        r2 = asyncio.run(osint.investigate_credential_combo("bob_anon@proton.me:UltraSecretPass99!", "seed:2", hop_depth=0))
        self.assertEqual(r1["pwd_node_id"], r2["pwd_node_id"])
        self.assertIn(r1["pwd_node_id"], g.nodes)
        # Both accounts must connect to the exact same deterministic password fingerprint node
        pwd_neighbors = list(g.nx_graph.to_undirected().neighbors(r1["pwd_node_id"]))
        self.assertGreaterEqual(len(pwd_neighbors), 2)


if __name__ == "__main__":
    unittest.main()

