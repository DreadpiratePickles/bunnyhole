"""Packaged per-instance Model-Context-Protocol (MCP) server for Bunnyhole.

Every Bunnyhole install can expose its own investigation engine to any MCP client
(Claude Desktop, IDE copilots, agent runtimes) over stdio via ``bunnyhole mcp``.
See :mod:`bunnyhole.mcp.server` and ``docs/MCP_SERVER.md``.
"""

from __future__ import annotations

from bunnyhole.mcp.server import build_server, client_config, run_stdio

__all__ = ["build_server", "client_config", "run_stdio"]
