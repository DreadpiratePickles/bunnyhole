"""Repository hygiene: things a stranger cloning the repo would trip over.

Fast, offline, and ast/regex based. Covers packaging (version single-sourced, ``python -m bunnyhole``), package
layout, accidental personal paths, Markdown links, the one-HTTP-client-factory rule, and the test network guard.
"""

from __future__ import annotations

import ast
import importlib.metadata
import os
import re
import socket
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import List, Set

import pytest
from conftest import NetworkAccessBlocked, pop_blocked_attempts

import bunnyhole

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "bunnyhole"


def _tracked_files(*roots: str) -> List[Path]:
    """Tracked + new-but-not-ignored files under ``roots``; falls back to a walk outside a git checkout."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", *roots],
            cwd=REPO, capture_output=True, text=True, check=True, timeout=30,
        ).stdout
        return [REPO / line for line in out.splitlines() if line and (REPO / line).is_file()]
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        files: List[Path] = []
        for root in roots:
            files.extend(p for p in (REPO / root).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
        return files


# ---------------------------------------------------------------------------------------------------------------
# (a) every outbound HTTP client is built by engine/netutil.new_async_client (proxy/Tor routing, SSRF policy)
# ---------------------------------------------------------------------------------------------------------------


def _direct_async_client_calls() -> List[str]:
    hits: List[str] = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "netutil.py" and path.parent.name == "engine":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if name == "AsyncClient":
                hits.append(f"{path.relative_to(REPO)}:{node.lineno}")
    return hits


def test_no_direct_httpx_async_client_outside_netutil() -> None:
    assert _direct_async_client_calls() == []


# ---------------------------------------------------------------------------------------------------------------
# (a2) CI gates: ruff, mypy and the tests all block a merge (none is continue-on-error)
# ---------------------------------------------------------------------------------------------------------------


def _ci_steps() -> List[dict]:
    steps: List[dict] = []
    current: dict = {}
    for line in (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*-\s+name:\s*(.+)$", line)
        if m:
            current = {"name": m.group(1).strip(), "body": []}
            steps.append(current)
        elif current:
            current["body"].append(line)
    return steps


def test_ci_mypy_ruff_and_tests_are_blocking() -> None:
    gates = {"mypy bunnyhole": False, "ruff check": False, "pytest": False}
    for step in _ci_steps():
        body = "\n".join(step["body"])
        for command in gates:
            if f"run: uv run --locked {command}" in body:
                gates[command] = True
                assert "continue-on-error" not in body, f"CI step {step['name']!r} must block"
                assert "|| true" not in body, f"CI step {step['name']!r} must block"
    assert gates == dict.fromkeys(gates, True)


# ---------------------------------------------------------------------------------------------------------------
# (b) package layout
# ---------------------------------------------------------------------------------------------------------------


def test_every_top_level_subpackage_has_an_init() -> None:
    missing = [
        d.name
        for d in sorted(PKG.iterdir())
        if d.is_dir() and d.name != "__pycache__" and not d.name.startswith(".") and any(d.rglob("*.py"))
        and not (d / "__init__.py").is_file()
    ]
    assert missing == []


# ---------------------------------------------------------------------------------------------------------------
# (c) python -m bunnyhole
# ---------------------------------------------------------------------------------------------------------------


def test_python_dash_m_bunnyhole_help_exits_zero() -> None:
    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb"}
    proc = subprocess.run(
        [sys.executable, "-m", "bunnyhole", "--help"], cwd=REPO, env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "Usage" in proc.stdout and "bunnyhole" in proc.stdout


# ---------------------------------------------------------------------------------------------------------------
# (d) the version is single-sourced from bunnyhole/__init__.py
# ---------------------------------------------------------------------------------------------------------------


def test_version_is_single_sourced_from_the_package() -> None:
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    project = meta["project"]
    assert "version" not in project, "pyproject must not hard-code the version"
    assert "version" in project.get("dynamic", [])
    assert meta["tool"]["hatch"]["version"]["path"] == "bunnyhole/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-]?\w+)?", bunnyhole.__version__)


def test_installed_metadata_matches_package_version() -> None:
    try:
        installed = importlib.metadata.version("bunnyhole")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("bunnyhole is not installed in this environment")
    assert installed == bunnyhole.__version__


# ---------------------------------------------------------------------------------------------------------------
# (e) no developer home-directory paths leak into the package or the tests
# ---------------------------------------------------------------------------------------------------------------

# Built from parts so this file does not match itself.
_HOME_PATH = re.compile("/" + r"(?:Users|home)/([A-Za-z0-9._-]+)/")
# Obviously fictional sample owners used in docs/tests (research/ is out of scope: it holds documented samples).
_FICTIONAL_OWNERS = {"u", "user", "you", "username", "example", "name"}


def test_no_absolute_home_paths_in_package_or_tests() -> None:
    leaks: List[str] = []
    for path in _tracked_files("bunnyhole", "tests"):
        if path.suffix in {".pyc", ".png", ".jpg", ".gif", ".ico", ".db", ".sqlite"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _HOME_PATH.finditer(line):
                if m.group(1).lower() not in _FICTIONAL_OWNERS:
                    leaks.append(f"{path.relative_to(REPO)}:{lineno}: {m.group(0)}")
    assert leaks == []


# ---------------------------------------------------------------------------------------------------------------
# (f) relative links in README / docs / top-level Markdown resolve
# ---------------------------------------------------------------------------------------------------------------

_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_FENCE = re.compile(r"^\s*(```|~~~)")
_EXTERNAL = ("http://", "https://", "mailto:", "tel:", "ftp://", "data:")


def _markdown_files() -> List[Path]:
    files = sorted(REPO.glob("*.md"))
    files += sorted((REPO / "docs").rglob("*.md")) if (REPO / "docs").is_dir() else []
    return files


def _relative_links(md: Path) -> List[tuple]:
    links = []
    in_fence = False
    for lineno, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        line = re.sub(r"`[^`]*`", "", line)  # inline code is not a link
        for target in _LINK.findall(line):
            if target.startswith(_EXTERNAL) or target.startswith("#"):
                continue
            links.append((lineno, target))
    return links


def test_markdown_relative_links_resolve() -> None:
    broken: List[str] = []
    for md in _markdown_files():
        for lineno, target in _relative_links(md):
            path_part = target.split("#", 1)[0].split("?", 1)[0]
            if not path_part:
                continue
            resolved = (REPO / path_part.lstrip("/")) if path_part.startswith("/") else (md.parent / path_part)
            if not resolved.exists():
                broken.append(f"{md.relative_to(REPO)}:{lineno} -> {target}")
    assert broken == []


def test_markdown_link_checker_detects_a_broken_link(tmp_path: Path) -> None:
    md = tmp_path / "x.md"
    md.write_text("[ok](https://e.x)\n[a](#anchor)\n`[no](code.md)`\n```\n[no](fenced.md)\n```\n[bad](missing.md#s)\n")
    assert _relative_links(md) == [(7, "missing.md#s")]


# ---------------------------------------------------------------------------------------------------------------
# the hermetic-test network guard itself (tests/conftest.py)
# ---------------------------------------------------------------------------------------------------------------


def test_guard_blocks_a_public_tcp_connect() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(NetworkAccessBlocked):
            sock.connect(("203.0.113.10", 443))  # TEST-NET-3, never routable
    finally:
        sock.close()
    assert len(pop_blocked_attempts()) == 1


def test_guard_blocks_create_connection_and_public_dns() -> None:
    with pytest.raises(NetworkAccessBlocked):
        socket.create_connection(("198.51.100.7", 80), timeout=0.1)
    with pytest.raises(NetworkAccessBlocked):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(NetworkAccessBlocked):
        socket.gethostbyname("example.org")
    assert len(pop_blocked_attempts()) == 3


def test_guard_blocks_network_subprocesses_but_not_plain_ones() -> None:
    with pytest.raises(NetworkAccessBlocked):
        subprocess.run(["curl", "https://example.com"], capture_output=True)
    with pytest.raises(NetworkAccessBlocked):
        subprocess.run("uv tool install sherlock-project", shell=True, capture_output=True)
    with pytest.raises(NetworkAccessBlocked):
        subprocess.run([sys.executable, "-m", "pip", "install", "x"], capture_output=True)
    assert len(pop_blocked_attempts()) == 3
    ok = subprocess.run([sys.executable, "-c", "print(1)"], capture_output=True, text=True, timeout=60)
    assert ok.stdout.strip() == "1"


def test_guard_allows_loopback_and_numeric_lookups() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname(), timeout=2)
    client.close()
    server.close()
    assert socket.getaddrinfo("127.0.0.1", 80)
    assert socket.getaddrinfo("localhost", 80)
    assert pop_blocked_attempts() == []


@pytest.mark.network
def test_network_marker_is_skipped_unless_opted_in() -> None:
    """Runs only with BUNNYHOLE_TEST_NETWORK=1; then the guard is lifted for this test."""
    assert os.environ.get("BUNNYHOLE_TEST_NETWORK") == "1"
    socket.getaddrinfo("example.com", 443)


def test_network_marker_is_registered(pytestconfig: pytest.Config) -> None:
    markers: Set[str] = {m.split(":", 1)[0].strip() for m in pytestconfig.getini("markers")}
    assert "network" in markers
