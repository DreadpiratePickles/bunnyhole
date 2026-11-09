"""Guard: every outbound HTTP client is built by ``netutil.new_async_client`` so --proxy / --tor route all of it.

A bare ``httpx.AsyncClient(...)`` (or ``httpx.Client``, or a module-level ``httpx.get/post/...``) ignores the user's
proxy/Tor choice, so case selectors and evidence would leave over the direct connection. The only sanctioned
exception is ``bunnyhole/engine/netutil.py`` itself (the factory, and ``fetch_onion`` which pins the Tor proxy
explicitly). Parsed with ``ast`` so comments, docstrings and type annotations (``client: httpx.AsyncClient``) do not
count; import aliases (``import httpx as hx``, ``from httpx import AsyncClient as AC``) do.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

import bunnyhole

PACKAGE_ROOT = Path(bunnyhole.__file__).resolve().parent
ALLOWED = {PACKAGE_ROOT / "engine" / "netutil.py"}
_BARE_NAMES = {"AsyncClient", "Client", "get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}


def _bare_client_lines(source: str, filename: str) -> List[int]:
    tree = ast.parse(source, filename=filename)
    httpx_modules = {"httpx"}
    direct_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            httpx_modules.update(a.asname or a.name for a in node.names if a.name == "httpx")
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            direct_names.update(a.asname or a.name for a in node.names if a.name in _BARE_NAMES)
    lines: List[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        via_module = (
            isinstance(func, ast.Attribute)
            and func.attr in _BARE_NAMES
            and isinstance(func.value, ast.Name)
            and func.value.id in httpx_modules
        )
        via_alias = isinstance(func, ast.Name) and func.id in direct_names
        if via_module or via_alias:
            lines.append(node.lineno)
    return sorted(lines)


def test_no_bare_httpx_clients_outside_netutil() -> None:
    offenders: List[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path in ALLOWED:
            continue
        for line in _bare_client_lines(path.read_text(encoding="utf-8"), str(path)):
            offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{line}")
    assert offenders == [], "build clients with netutil.new_async_client(...) instead: " + ", ".join(offenders)


def test_the_guard_detects_every_bare_form_and_ignores_annotations_and_docstrings() -> None:
    sample = (
        "import httpx\n"
        "import httpx as hx\n"
        "from httpx import AsyncClient as AC\n"
        "def f(c: httpx.AsyncClient) -> None:\n"
        "    '''httpx.AsyncClient( in a docstring'''\n"
        "    httpx.AsyncClient(timeout=1)\n"
        "    hx.AsyncClient()\n"
        "    AC()\n"
        "    httpx.get('https://example.com')\n"
        "    isinstance(c, httpx.AsyncClient)  # not a call of the client\n"
    )
    assert _bare_client_lines(sample, "sample.py") == [6, 7, 8, 9]
