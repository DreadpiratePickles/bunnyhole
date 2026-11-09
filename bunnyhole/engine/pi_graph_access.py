"""Plain-dict access helpers shared by the PI runtime modules.

``graph.to_dict()`` holds enum members while hand-built dicts hold strings, so every reader goes through
these tolerant accessors. Pure functions; no I/O.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping

_INTERNAL_TOOL_PREFIXES = ("bunnyhole_", "sqlite_")
_ADDRESS_ATTRS = ("full_address", "registered_address", "address", "address_snippet")


def _val(value: Any) -> Any:
    return getattr(value, "value", value)


def _dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    dump = getattr(obj, "model_dump", None)
    return dump() if callable(dump) else {}


def _receipts(item: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [_dict(r) for r in (item.get("receipts") or []) if _dict(r)]


def _is_external(receipt: Mapping[str, Any]) -> bool:
    tool = str(receipt.get("tool") or "")
    return bool(tool) and not tool.startswith(_INTERNAL_TOOL_PREFIXES)


def _clean_label(label: str) -> str:
    """Drop the decorative emoji/punctuation prefix the agents put on labels."""
    return re.sub(r"^[^\w]+", "", label or "").strip()
