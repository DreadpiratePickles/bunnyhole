"""Every surface names council Stage 2 honestly: a deterministic evidence ranking, never an (anonymized) peer review.

Stage 2 is ``engine.council.deterministic_rubric_score``; no LLM ranks the seats (STAGE2_LABEL).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bunnyhole.engine.council import STAGE2_LABEL

REPO = Path(__file__).resolve().parent.parent
SURFACES = ["bunnyhole/api/server.py", "bunnyhole/cli/main.py", "bunnyhole/tui/app.py", "bunnyhole/mcp/server.py",
            "README.md", "CHEATSHEET.md", "docs/QUICKSTART_CHEATSHEET.md"]
_PEER_CLAIM = re.compile(r"anonymi[sz]ed\s+peer|peer\s+review(?!\))|peer\s+rank", re.IGNORECASE)


@pytest.mark.parametrize("rel", SURFACES)
def test_no_surface_claims_a_peer_review(rel: str) -> None:
    path = REPO / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    hits = [f"{rel}:{n}: {line.strip()[:120]}" for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if _PEER_CLAIM.search(line) and "not peer review" not in line.lower()]
    assert hits == []


def test_cli_and_web_ui_use_the_council_stage2_label() -> None:
    for rel in ("bunnyhole/api/server.py", "bunnyhole/cli/main.py"):
        assert STAGE2_LABEL.lower() in (REPO / rel).read_text(encoding="utf-8").lower(), rel
