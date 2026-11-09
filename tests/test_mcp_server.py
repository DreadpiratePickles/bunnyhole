"""Tests for the packaged per-instance Bunnyhole MCP server (`bunnyhole mcp`).

The MCP server exposes Bunnyhole's investigation engine to any Model-Context-Protocol
client (Claude Desktop, IDE copilots, …) over stdio. These tests exercise the tool layer
*without* the stdio transport and *without* network access: the heavy orchestrator is
replaced by a recording fake, so we verify wiring, argument translation, and the
token-friendly result shaping rather than running real investigations.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any, Dict, Optional

from bunnyhole.engine.intake import CaseIntakePacket
from bunnyhole.engine.models import GearMode
from bunnyhole.mcp import server as mcp_server

ADDR_A = "0x" + "a" * 40

# The tools every MCP client should see from a stock Bunnyhole instance.
EXPECTED_TOOLS = {
    "interpret",
    "trace",
    "intake",
    "link",
    "jet",
    "darkweb",
    "arsenal_status",
    "list_cases",
    "search_cases",
    "load_case",
}


def _synthetic_full_result() -> Dict[str, Any]:
    """A full orchestrator result dict with deliberately bulky receipts to shrink away."""
    bulky_receipt = {"raw_snippet": "x" * 4000, "sha256": "d" * 64}
    return {
        "case_id": "bh_test01",
        "seed_query": "acme.io",
        "created_at": "2026-10-31T00:00:00Z",
        "stats": {
            "total_nodes": 2,
            "total_edges": 1,
            "total_receipts": 8,
            "cutout_brokers": 1,
            "high_smoke_nodes": 1,
            "domains_covered": ["osint", "onchain"],
        },
        "ach_assessment": {
            "winning_hypothesis": "H2: common operator",
            "narrative_verdict": "Strong circumstantial convergence, not yet confirmed.",
        },
        "nodes": [
            {
                "id": "domain:acme.io",
                "label": "Acme Labs",
                "entity_type": "Domain",
                "domain": "osint",
                "smoke_score": 82.0,
                "betweenness_centrality": 0.51,
                "is_cutout_broker": True,
                "risk_flags": ["SHELL", "NOMINEE", "FRESH_WALLET", "EXTRA_FLAG"],
                "receipts": [bulky_receipt, bulky_receipt],
            },
            {
                "id": "wallet:" + ADDR_A,
                "label": ADDR_A,
                "entity_type": "Wallet",
                "domain": "onchain",
                "smoke_score": 40.0,
                "betweenness_centrality": 0.0,
                "is_cutout_broker": False,
                "risk_flags": [],
                "receipts": [bulky_receipt],
            },
        ],
        "edges": [{"source_id": "domain:acme.io", "target_id": "wallet:" + ADDR_A, "receipts": [bulky_receipt]}],
        "interconnections": {
            "targeted_paths": [
                {
                    "hop_count": 2,
                    "path_score": 0.91,
                    "domains_crossed": ["osint", "onchain"],
                    "step_labels": ["Acme Labs", "Broker LLC", ADDR_A],
                }
            ],
            "predicted_missing_links": [
                {
                    "node_a_label": "Acme Labs",
                    "node_a_domain": "osint",
                    "node_b_label": ADDR_A,
                    "node_b_domain": "onchain",
                    "adamic_adar_score": 1.44,
                    "shared_intermediaries": ["Broker LLC", "shared-ns.example"],
                }
            ],
        },
        "cross_case_hits": [
            {
                "label": "Acme Labs",
                "entity_id": "domain:acme.io",
                "prior_cases": [{"case_id": "bh_old99", "seed_query": "brightpeak"}],
            }
        ],
        "synthesis": {"markdown_brief": "## Brief\nAcme Labs links to the wallet via a broker."},
        "council": {"stage3_chairman_verdict": {"verdict_markdown": "## Verdict\nLeads, not proof."}},
        "deep_research": {
            "gear": "deep",
            "max_depth": 3,
            "initial_breadth": 6,
            "learnings": ["Learning one [A1]", "Learning two [C3]"],
        },
    }


class _FakeGraph:
    def export_markdown_dossier(self) -> str:
        return "# DOSSIER\n" + ("line\n" * 50)


class _FakeOrchestrator:
    """Records constructor kwargs and which run method was called; returns a canned result."""

    last_instance: Optional["_FakeOrchestrator"] = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.called: Optional[str] = None
        self.called_with: Any = None
        self.graph = _FakeGraph()
        _FakeOrchestrator.last_instance = self

    async def run_investigation(self) -> Dict[str, Any]:
        self.called = "run_investigation"
        return _synthetic_full_result()

    async def run_intake_investigation(self, packet: CaseIntakePacket) -> Dict[str, Any]:
        self.called = "run_intake_investigation"
        self.called_with = packet
        return _synthetic_full_result()

    async def run_bidirectional_link_investigation(self, a: str, b: str) -> Dict[str, Any]:
        self.called = "run_bidirectional_link_investigation"
        self.called_with = (a, b)
        return _synthetic_full_result()


class BuildServerTest(unittest.TestCase):
    def test_server_registers_expected_tools(self) -> None:
        server = mcp_server.build_server()
        names = {t.name for t in asyncio.run(server.list_tools())}
        missing = EXPECTED_TOOLS - names
        self.assertFalse(missing, f"MCP server missing tools: {missing}")

    def test_every_tool_has_a_description(self) -> None:
        server = mcp_server.build_server()
        for t in asyncio.run(server.list_tools()):
            self.assertTrue((t.description or "").strip(), f"tool {t.name} has no description")


class CompactResultTest(unittest.TestCase):
    def test_compact_drops_bulky_receipts_and_keeps_signal(self) -> None:
        full = _synthetic_full_result()
        compact = mcp_server._compact_result(full)

        blob = json.dumps(compact)
        self.assertNotIn("x" * 100, blob, "bulky receipt snippets must not survive into the compact result")
        self.assertLess(len(blob), len(json.dumps(full)))

        self.assertEqual(compact["case_id"], "bh_test01")
        self.assertEqual(compact["verdict"]["winning_hypothesis"], "H2: common operator")

        top = compact["top_entities"][0]
        self.assertEqual(top["label"], "Acme Labs")  # cut-out broker + highest smoke ranks first
        self.assertTrue(top["is_cutout_broker"])
        self.assertLessEqual(len(top["risk_flags"]), 3)

        self.assertEqual(compact["interconnection_paths"][0]["chain"], ["Acme Labs", "Broker LLC", ADDR_A])
        self.assertEqual(compact["predicted_links"][0]["adamic_adar_score"], 1.44)
        self.assertIn("Acme Labs links", compact["synthesis_brief"])
        self.assertIn("Leads, not proof", compact["council_verdict"])
        self.assertEqual(len(compact["learnings"]), 2)

    def test_compact_tolerates_missing_sections(self) -> None:
        compact = mcp_server._compact_result({"case_id": "bh_x", "seed_query": "s"})
        self.assertEqual(compact["case_id"], "bh_x")
        self.assertEqual(compact["top_entities"], [])
        self.assertEqual(compact["interconnection_paths"], [])


class InterpretToolTest(unittest.TestCase):
    def test_interpret_actionable(self) -> None:
        out = mcp_server.interpret_tool("take a quick look at acme.io")
        self.assertTrue(out["is_actionable"])
        self.assertTrue(out["understanding"])
        self.assertIn("acme.io", out["seeds"])
        self.assertEqual(out["gear"], "fast")
        self.assertEqual(out["depth"], 1)

    def test_interpret_non_actionable(self) -> None:
        out = mcp_server.interpret_tool("take a quick look")
        self.assertFalse(out["is_actionable"])
        self.assertTrue(out["understanding"])
        self.assertEqual(out["seeds"], [])


class RunToolWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = mcp_server.BunnyholeOrchestrator
        mcp_server.BunnyholeOrchestrator = _FakeOrchestrator  # type: ignore[assignment,misc]
        _FakeOrchestrator.last_instance = None

    def tearDown(self) -> None:
        mcp_server.BunnyholeOrchestrator = self._orig  # type: ignore[assignment,misc]

    def test_trace_wires_orchestrator_and_compacts(self) -> None:
        out = asyncio.run(mcp_server.trace_tool(seed="acme.io", gear="deep", depth=3, breadth=6, hypothesis="same op?"))
        inst = _FakeOrchestrator.last_instance
        assert inst is not None
        self.assertEqual(inst.called, "run_investigation")
        self.assertEqual(inst.kwargs["seed_query"], "acme.io")
        self.assertEqual(inst.kwargs["gear"], GearMode.DEEP)
        self.assertEqual(inst.kwargs["max_depth"], 3)
        self.assertEqual(inst.kwargs["initial_breadth"], 6)
        self.assertEqual(inst.kwargs["hypothesis"], "same op?")
        # result is compacted, and the dossier is attached
        self.assertEqual(out["case_id"], "bh_test01")
        self.assertIn("DOSSIER", out["dossier_markdown"])

    def test_intake_builds_normalized_packet(self) -> None:
        out = asyncio.run(
            mcp_server.intake_tool(
                hypothesis="all one operator",
                domains=["acme.io"],
                wallets=[ADDR_A],
                anchor_mode="locked_profile",
                gear="deep",
                depth=2,
                breadth=4,
            )
        )
        inst = _FakeOrchestrator.last_instance
        assert inst is not None
        self.assertEqual(inst.called, "run_intake_investigation")
        packet = inst.called_with
        self.assertIsInstance(packet, CaseIntakePacket)
        self.assertEqual(out["case_id"], "bh_test01")

    def test_link_wires_bidirectional(self) -> None:
        asyncio.run(mcp_server.link_tool(entity_a="acme.io", entity_b=ADDR_A, gear="fast"))
        inst = _FakeOrchestrator.last_instance
        assert inst is not None
        self.assertEqual(inst.called, "run_bidirectional_link_investigation")
        self.assertEqual(inst.called_with, ("acme.io", ADDR_A))

    def test_bad_gear_string_is_rejected_clearly(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(mcp_server.trace_tool(seed="acme.io", gear="turbo"))


class ProfileToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self._orig_path = mcp_server._profile.PROFILE_PATH
        mcp_server._profile.PROFILE_PATH = __import__("pathlib").Path(self._tmp.name) / "profile.json"

    def tearDown(self) -> None:
        mcp_server._profile.PROFILE_PATH = self._orig_path
        self._tmp.cleanup()

    def test_new_tools_are_registered(self) -> None:
        names = {t.name for t in asyncio.run(mcp_server.build_server().list_tools())}
        for t in ("sanctions_screen", "get_profile", "set_persona", "watchlist_add", "watchlist_remove"):
            self.assertIn(t, names)

    def test_get_profile_defaults_to_generalist(self) -> None:
        out = mcp_server.get_profile_tool()
        self.assertEqual(out["persona"], "generalist")
        self.assertIn("available_personas", out)
        self.assertEqual(out["watchlist"], [])

    def test_set_persona_and_watchlist_persist(self) -> None:
        out = mcp_server.set_persona_tool("compliance")
        self.assertEqual(out["persona"], "compliance")
        self.assertTrue(out["emphasize_sanctions"])
        self.assertEqual(out["effective_run_defaults"]["gear"], "deep")
        mcp_server.watchlist_add_tool(["acme.io", "acme.io", "0xabc"])
        reloaded = mcp_server.get_profile_tool()
        self.assertEqual(reloaded["persona"], "compliance")  # survived a reload from disk
        self.assertEqual(reloaded["watchlist"], ["acme.io", "0xabc"])
        mcp_server.watchlist_remove_tool(["acme.io"])
        self.assertEqual(mcp_server.get_profile_tool()["watchlist"], ["0xabc"])

    def test_bad_persona_falls_back_to_generalist(self) -> None:
        self.assertEqual(mcp_server.set_persona_tool("wizard")["persona"], "generalist")


class PIReferenceToolTest(unittest.TestCase):
    """The read-only PI reference tool: static tables only, never raises, never runs a trace."""

    def test_registered_and_no_pi_trace_tool(self) -> None:
        names = {t.name for t in asyncio.run(mcp_server.build_server().list_tools())}
        self.assertIn("pi_reference", names)
        self.assertFalse({n for n in names if "pi" in n.split("_") and n != "pi_reference"})

    def test_guide(self) -> None:
        out = mcp_server.pi_reference_tool("guide")
        self.assertNotIn("error", out)
        self.assertIn("Private-investigator method", out["markdown"])
        json.dumps(out)

    def test_sources_filters(self) -> None:
        everything = mcp_server.pi_reference_tool("sources")
        implemented = mcp_server.pi_reference_tool("sources", case_type="due_diligence", jurisdiction="us")
        self.assertGreater(everything["count"], 0)
        self.assertEqual(everything["count"], len(everything["sources"]))
        self.assertLessEqual(implemented["count"], everything["count"])
        self.assertIn("access", everything["sources"][0])
        json.dumps(everything)

    def test_legal_defaults_to_general_and_carries_disclaimer(self) -> None:
        out = mcp_server.pi_reference_tool("legal")
        self.assertEqual(out["jurisdiction"], "general")
        self.assertTrue(out["rules"])
        self.assertIn("not legal advice", out["disclaimer"].lower())
        ca = mcp_server.pi_reference_tool("legal", jurisdiction="ca-on")
        self.assertGreater(len(ca["rules"]), len(out["rules"]))

    def test_playbook(self) -> None:
        out = mcp_server.pi_reference_tool("playbook", case_type="asset_search")
        self.assertEqual(out["playbook"]["case_type"], "asset_search")
        self.assertGreaterEqual(len(out["playbook"]["steps"]), 4)
        json.dumps(out)

    def test_out_of_scope(self) -> None:
        out = mcp_server.pi_reference_tool("out_of_scope")
        self.assertIn("TLOxp", {e["name"] for e in out["out_of_scope"]})
        self.assertTrue(out["unlawful_methods"])

    def test_bad_inputs_return_error_dicts_never_raise(self) -> None:
        for kwargs in (
            {"kind": "trace"},
            {"kind": ""},
            {"kind": "playbook"},
            {"kind": "playbook", "case_type": "nonsense"},
            {"kind": "sources", "case_type": "nonsense"},
        ):
            out = mcp_server.pi_reference_tool(**kwargs)
            self.assertIn("error", out, kwargs)
            self.assertTrue(out["error"])


class ClientConfigTest(unittest.TestCase):
    def test_config_is_valid_json_with_bunnyhole_entry(self) -> None:
        cfg = mcp_server.client_config(directory="/home/u/bunnyhole")
        blob = json.dumps(cfg)  # must round-trip
        self.assertIn("mcpServers", cfg)
        entry = cfg["mcpServers"]["bunnyhole"]
        self.assertIn("command", entry)
        self.assertIn("mcp", entry["args"])
        self.assertIn("bunnyhole", blob)


if __name__ == "__main__":
    unittest.main()
