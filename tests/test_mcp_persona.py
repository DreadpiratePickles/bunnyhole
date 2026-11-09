"""``set_persona`` over MCP: an unknown persona is a clean error listing the valid keys, and nothing is saved.

Hermetic: the profile lives in ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bunnyhole.engine.personas import persona_keys
from bunnyhole.mcp import server as mcp_server


@pytest.fixture(autouse=True)
def _isolated_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "profile.json"
    monkeypatch.setattr(mcp_server._profile, "PROFILE_PATH", path)
    return path


def test_unknown_persona_returns_an_error_listing_valid_keys(tmp_path: Path) -> None:
    out = mcp_server.set_persona_tool("wizard")
    assert "wizard" in out["error"]
    assert out["valid_personas"] == persona_keys()
    for key in persona_keys():
        assert key in out["error"]
    assert "persona" not in out  # no profile payload pretending the change was applied


def test_unknown_persona_does_not_overwrite_the_saved_persona(tmp_path: Path) -> None:
    assert mcp_server.set_persona_tool("compliance")["persona"] == "compliance"
    mcp_server.set_persona_tool("wizard")
    assert mcp_server.get_profile_tool()["persona"] == "compliance"


def test_unknown_persona_on_a_fresh_profile_writes_nothing(_isolated_profile: Path) -> None:
    mcp_server.set_persona_tool("not-a-persona")
    assert not _isolated_profile.exists()


@pytest.mark.parametrize("value", ["journalist", "  Crypto_Tracer ", "PI"])
def test_valid_persona_is_case_and_space_insensitive(value: str) -> None:
    out = mcp_server.set_persona_tool(value)
    assert "error" not in out
    assert out["persona"] == value.strip().lower()
