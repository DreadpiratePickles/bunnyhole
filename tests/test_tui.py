"""Headless smoke tests for the Textual War-Room TUI (no network)."""

from __future__ import annotations

import asyncio
import unittest

from bunnyhole.tui.app import BunnyholeTUI, EngineEvent

FAKE_RESULT = {
    "stats": {"total_nodes": 2, "total_edges": 1, "total_receipts": 3, "cutout_brokers": 1},
    "nodes": [
        {
            "id": "wallet:eth:0xabc",
            "label": "0xabc",
            "entity_type": "CryptoWallet",
            "domain": "onchain",
            "smoke_score": 72.0,
            "is_cutout_broker": True,
            "betweenness_centrality": 0.2,
            "risk_flags": ["GOPLUS_cybercrime"],
            "hop_depth": 1,
            "attributes": {"raw_seed": "0xabc"},
            "receipts": [
                {"admiralty_code": "A1", "tool": "blockscout", "extracted_fact": "funded gitcoin.eth", "source_url": "https://x"}
            ],
        },
        {
            "id": "domain:acme.com",
            "label": "acme.com",
            "entity_type": "Domain",
            "domain": "osint",
            "smoke_score": 40.0,
            "is_cutout_broker": False,
            "betweenness_centrality": 0.0,
            "risk_flags": [],
            "hop_depth": 1,
            "attributes": {},
            "receipts": [],
        },
    ],
    "edges": [],
    "ach_assessment": {
        "primary_question": "Q",
        "winning_hypothesis": "H1",
        "narrative_verdict": "v",
        "h1_score": 3,
        "h2_score": 1,
        "h3_score": 0,
        "matrix_rows": [],
    },
    "council": {"stage3_chairman_verdict": {"verdict_markdown": "## Verdict"}},
    "interconnections": {
        "keystone_brokers": [{"label": "0xabc", "domains_bridged": ["onchain", "fiat"], "betweenness_centrality": 0.2}],
        "cross_domain_paths": [{"hop_count": 2, "step_labels": ["a", "b"]}],
        "predicted_missing_links": [],
    },
    "timeline": [{"timestamp": "2022-01-01", "title": "tx", "anomaly_flag": None}],
    "markdown_dossier": "# Dossier",
}


class TuiComposeTest(unittest.TestCase):
    def test_compose_populate_and_log(self) -> None:
        async def scenario() -> None:
            app = BunnyholeTUI(initial_seed="vitalik.eth")
            async with app.run_test(size=(120, 40)) as pilot:
                for sel in ("#statsbar", "#seed", "#entities", "#tabs", "#log", "#timeline"):
                    self.assertTrue(app.query(sel), f"missing {sel}")

                app._populate(FAKE_RESULT)
                await pilot.pause()
                self.assertEqual(app.query_one("#entities").row_count, 2)

                # the live-log relay handler must not raise on a telemetry event
                app.post_message(
                    EngineEvent({"type": "agent_log", "data": {"agent": "onchain", "action": "FIRST_FUNDER", "target": "0xabc", "detail": "traced", "level": "discovery"}})
                )
                await pilot.pause()

                # tabs switch without error
                app.query_one("#tabs").active = "tab-dossier"
                await pilot.pause()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
