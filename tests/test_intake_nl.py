"""Tests for the natural-language command interpreter (plain-language TUI/CLI intake).

`interpret_command` turns a plain-English instruction ("take a quick look at acme.io",
"dig 3 levels into example.com and 0x…, same operator?") into a ready-to-run
`InterpretedCommand`: a populated `CaseIntakePacket` with gear / depth / breadth / anchor
inferred from the language, plus a human-readable `understanding` and `notes`.
"""

from __future__ import annotations

import unittest

from bunnyhole.engine.intake import AnchorMode, interpret_command
from bunnyhole.engine.models import GearMode

ADDR_A = "0x" + "a" * 40
ADDR_B = "0x" + "b" * 40


class InterpretCommandTest(unittest.TestCase):
    def test_bare_seed_uses_defaults(self) -> None:
        cmd = interpret_command("acme.io")
        self.assertTrue(cmd.is_actionable)
        self.assertIn("acme.io", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.gear, GearMode.FAST)
        self.assertEqual(cmd.packet.depth, 2)
        self.assertEqual(cmd.packet.breadth, 4)
        self.assertEqual(cmd.packet.anchor_mode, AnchorMode.CONVERGENCE)
        self.assertTrue(cmd.understanding)

    def test_deep_cue_sets_deep_gear_and_depth(self) -> None:
        cmd = interpret_command("vitalik.eth go deep")
        self.assertIn("vitalik.eth", cmd.packet.wallets)
        self.assertEqual(cmd.packet.gear, GearMode.DEEP)
        self.assertEqual(cmd.packet.depth, 3)  # "deep" with no explicit number implies 3
        # the control phrase must not survive as a bogus company/username selector
        self.assertNotIn("go deep", [o.lower() for o in cmd.packet.orgs_or_names])
        self.assertEqual(len(cmd.packet.all_seed_tuples()), 1)

    def test_quick_cue_sets_fast_and_shallow(self) -> None:
        cmd = interpret_command("take a quick look at acme.io")
        self.assertIn("acme.io", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.gear, GearMode.FAST)
        self.assertEqual(cmd.packet.depth, 1)
        self.assertEqual(len(cmd.packet.all_seed_tuples()), 1)

    def test_command_phrasing_does_not_become_hypothesis(self) -> None:
        # "take a quick look at X" is a scan of X, not a hypothesis about it.
        cmd = interpret_command("take a quick look at brightpeak-roofing.com")
        self.assertIn("brightpeak-roofing.com", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.hypothesis, "")
        self.assertEqual(len(cmd.packet.all_seed_tuples()), 1)

    def test_explicit_depth_and_breadth(self) -> None:
        cmd = interpret_command("example.com depth 4 breadth 6")
        self.assertIn("example.com", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.depth, 4)
        self.assertEqual(cmd.packet.breadth, 6)
        self.assertEqual(cmd.packet.gear, GearMode.DEEP)  # depth>=3 implies heavier gear

    def test_dig_n_levels(self) -> None:
        cmd = interpret_command("dig 3 levels into example.com")
        self.assertIn("example.com", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.depth, 3)
        self.assertEqual(cmd.packet.gear, GearMode.DEEP)
        self.assertEqual(len(cmd.packet.all_seed_tuples()), 1)

    def test_wide_net_raises_breadth(self) -> None:
        cmd = interpret_command("cast a wide net on acme.io")
        self.assertIn("acme.io", cmd.packet.domains_or_ips)
        self.assertGreaterEqual(cmd.packet.breadth, 6)

    def test_question_with_same_operator_is_convergence(self) -> None:
        cmd = interpret_command(f"is acme.io run by the same operator as {ADDR_A}? go deep")
        self.assertIn("acme.io", cmd.packet.domains_or_ips)
        self.assertIn(ADDR_A, cmd.packet.wallets)
        self.assertEqual(cmd.packet.anchor_mode, AnchorMode.CONVERGENCE)
        self.assertEqual(cmd.packet.gear, GearMode.DEEP)
        self.assertTrue(cmd.packet.hypothesis)
        self.assertIn("operator", cmd.packet.hypothesis.lower())

    def test_asserted_same_person_is_locked_profile(self) -> None:
        cmd = interpret_command(
            f"these wallets all belong to the same person {ADDR_A} {ADDR_B}, map their footprint"
        )
        self.assertEqual(cmd.packet.anchor_mode, AnchorMode.LOCKED_PROFILE)
        self.assertIn(ADDR_A, cmd.packet.wallets)
        self.assertIn(ADDR_B, cmd.packet.wallets)

    def test_pure_command_is_not_actionable(self) -> None:
        cmd = interpret_command("take a quick look")
        self.assertFalse(cmd.is_actionable)
        self.assertEqual(cmd.packet.total_selectors(), 0)
        self.assertFalse(cmd.packet.hypothesis)
        self.assertTrue(cmd.understanding)  # still explains what it understood / why nothing ran

    def test_control_word_inside_domain_is_preserved(self) -> None:
        # "deep" / "quick" as substrings of a real selector must not be stripped.
        cmd = interpret_command("look into deepmind.com quickly")
        self.assertIn("deepmind.com", cmd.packet.domains_or_ips)
        self.assertEqual(cmd.packet.gear, GearMode.FAST)  # "quickly" -> fast


if __name__ == "__main__":
    unittest.main()
