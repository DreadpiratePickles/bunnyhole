"""CLI audit regressions: exit codes, input validation and help, without network or real ~/.bunnyhole access.

The orchestrator is a recording fake, the saved profile is a default in-memory one (``save_profile`` is a
recorder), ``uvicorn.run`` and the ADS-B agent are stubbed.
"""

from __future__ import annotations

import os
import types
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest
from rich.console import Console
from typer.testing import CliRunner

import bunnyhole
from bunnyhole.cli import main as cli_main
from bunnyhole.cli import pi_commands
from bunnyhole.engine import profile as profile_mod
from bunnyhole.engine.personas import Persona, persona_keys

runner = CliRunner()


class FakeOrchestrator:
    instances: List["FakeOrchestrator"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.graph = types.SimpleNamespace(export_markdown_dossier=lambda: "# dossier")
        FakeOrchestrator.instances.append(self)

    def _result(self) -> Dict[str, Any]:
        return {
            "case_id": "bh_fake01",
            "seed_query": self.kwargs.get("seed_query", ""),
            "stats": {},
            "ach_assessment": {},
            "deep_research": {},
            "interconnections": {},
            "nodes": [],
        }

    async def run_investigation(self) -> Dict[str, Any]:
        return self._result()

    async def run_intake_investigation(self, packet: Any) -> Dict[str, Any]:
        self.packet = packet
        return self._result()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    FakeOrchestrator.instances = []
    saved: List[Any] = []
    monkeypatch.setattr(cli_main, "BunnyholeOrchestrator", FakeOrchestrator)
    monkeypatch.setattr(profile_mod, "load_profile", lambda *a, **k: profile_mod.InvestigatorProfile())
    monkeypatch.setattr(profile_mod, "save_profile", lambda prof, *a, **k: saved.append(prof))
    wide = Console(width=300)
    monkeypatch.setattr(cli_main, "console", wide)
    monkeypatch.setattr(pi_commands, "console", wide)

    def _no_server(*a: Any, **k: Any) -> None:
        raise AssertionError("uvicorn.run must not be reached in this test")

    monkeypatch.setattr(cli_main.uvicorn, "run", _no_server)
    return saved


def _run(*args: str) -> Any:
    return runner.invoke(cli_main.app, list(args))


def _clean(res: Any) -> None:
    assert "Traceback" not in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit), repr(res.exception)


# ------------------------------------------------------------------------------------- intake selectors


@pytest.mark.parametrize(
    "args",
    [
        ("intake",),
        ("intake", "--hypothesis", "is anything connected?"),
        ("intake", "--exclude", "cloudflare.com"),
        ("intake", "--dump", "   "),
    ],
)
def test_intake_without_any_selector_exits_2(args: tuple) -> None:
    res = _run(*args)
    assert res.exit_code == 2, res.output
    assert "selector" in res.output.lower()
    assert FakeOrchestrator.instances == []
    _clean(res)


def test_intake_with_a_selector_still_runs() -> None:
    res = _run("intake", "--domain", "acme.io")
    assert res.exit_code == 0, res.output
    assert len(FakeOrchestrator.instances) == 1


def test_intake_pi_refusals_still_come_first() -> None:
    res = _run("intake", "--pi")
    assert res.exit_code == 2
    assert "purpose" in res.output.lower()


# ------------------------------------------------------------------------------------------- personas


@pytest.mark.parametrize("cmd", [("trace", "acme.io"), ("intake", "--domain", "acme.io"), ("profile",)])
def test_unknown_persona_is_rejected_with_the_valid_keys(cmd: tuple, _isolated: List[Any]) -> None:
    res = _run(*cmd, "--persona", "bogus")
    assert res.exit_code == 2, res.output
    for key in persona_keys():
        assert key in res.output
    assert FakeOrchestrator.instances == []
    assert _isolated == []  # profile not saved
    assert "Saved profile" not in res.output


def test_persona_is_case_insensitive(_isolated: List[Any]) -> None:
    res = _run("profile", "--persona", "COMPLIANCE")
    assert res.exit_code == 0, res.output
    assert _isolated and _isolated[-1].persona is Persona.COMPLIANCE
    res = _run("trace", "acme.io", "--persona", "Crypto_Tracer")
    assert res.exit_code == 0, res.output
    assert FakeOrchestrator.instances[-1].kwargs["profile"].persona is Persona.CRYPTO_TRACER


# --------------------------------------------------------------------------------------- depth/breadth


@pytest.mark.parametrize(
    "args",
    [
        ("trace", "acme.io", "--depth", "0"),
        ("trace", "acme.io", "--depth", "5"),
        ("trace", "acme.io", "--breadth", "1"),
        ("trace", "acme.io", "--breadth", "9"),
        ("intake", "--domain", "acme.io", "--depth", "9"),
        ("intake", "--domain", "acme.io", "--breadth", "0"),
        ("profile", "--depth", "7"),
        ("profile", "--breadth", "20"),
        ("council", "acme.io", "--depth", "5"),
        ("serve", "--port", "0"),
        ("serve", "--port", "70000"),
    ],
)
def test_out_of_range_numbers_are_rejected(args: tuple, _isolated: List[Any]) -> None:
    res = _run(*args)
    assert res.exit_code == 2, res.output
    assert FakeOrchestrator.instances == []
    assert _isolated == []


def test_in_range_depth_and_breadth_pass_through() -> None:
    res = _run("trace", "acme.io", "--depth", "4", "--breadth", "8")
    assert res.exit_code == 0, res.output
    kw = FakeOrchestrator.instances[0].kwargs
    assert kw["max_depth"] == 4 and kw["initial_breadth"] == 8


# ------------------------------------------------------------------------------------- help & version


def test_bare_bunnyhole_prints_help() -> None:
    res = _run()
    assert "Usage" in res.output
    assert "Missing command" not in res.output
    assert "trace" in res.output


def test_version_flag_prints_the_package_version() -> None:
    res = _run("--version")
    assert res.exit_code == 0, res.output
    assert bunnyhole.__version__ in res.output


def test_dash_p_meaning_is_documented_in_help() -> None:
    assert "--port" in _run("trace", "--help").output
    assert "--phone" in _run("serve", "--help").output


# ---------------------------------------------------------------------------------------------- jet


class FakeAccountant:
    calls: List[str] = []

    def __init__(self, graph: Any) -> None:
        pass

    async def investigate_aircraft_adsb(self, q: str, origin: str, hop_depth: int) -> Dict[str, Any]:
        FakeAccountant.calls.append(q)
        return {"query": q, "live_aircraft": []}


@pytest.fixture
def fake_accountant(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    FakeAccountant.calls = []
    monkeypatch.setattr(cli_main, "AccountantAgent", FakeAccountant)
    return FakeAccountant.calls


@pytest.mark.parametrize("value", ["zzz", "N0123", "12345", "a835afz", "", "N", "../etc"])
def test_jet_rejects_malformed_input(value: str, fake_accountant: List[str]) -> None:
    res = _run("jet", value)
    assert res.exit_code == 2, res.output
    assert fake_accountant == []
    assert "N628TS" in res.output  # the error shows a valid example
    _clean(res)


@pytest.mark.parametrize(("value", "hex_"), [("N628TS", "a835af"), ("n628ts", "a835af"), ("A835AF", "a835af")])
def test_jet_title_shows_the_real_icao_hex(value: str, hex_: str, fake_accountant: List[str]) -> None:
    res = _run("jet", value)
    assert res.exit_code == 0, res.output
    assert f"ICAO Hex: {hex_}" in res.output
    assert "ICAO Hex: None" not in res.output


# -------------------------------------------------------------------------------------------- cases


@pytest.mark.parametrize("args", [("cases", "--search", ""), ("cases", "--search", "  "), ("cases", "--load", "")])
def test_cases_empty_search_or_load_is_an_error(args: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    from bunnyhole.engine import storage

    class _Store:
        def __init__(self) -> None:
            pass

        def list_cases(self, limit: int = 25) -> List[Any]:
            raise AssertionError("must not fall through to the list")

    monkeypatch.setattr(storage, "CaseStore", _Store)
    res = _run(*args)
    assert res.exit_code == 2, res.output
    _clean(res)


# ---------------------------------------------------------------------------------------------- pi


def test_pi_sources_unknown_jurisdiction_warns() -> None:
    res = _run("pi", "sources", "--jurisdiction", "zz")
    assert res.exit_code == 0
    assert "No jurisdiction-specific sources for zz" in res.output


def test_pi_sources_known_jurisdiction_does_not_warn() -> None:
    res = _run("pi", "sources", "--jurisdiction", "ca-on")
    assert "No jurisdiction-specific" not in res.output


def test_pi_jurisdiction_hint_lists_are_identical() -> None:
    sources_help = _run("pi", "sources", "--help").output
    legal_help = _run("pi", "legal", "--help").output
    hint = pi_commands.PI_JURISDICTION_HINT
    flat = lambda text: " ".join(text.replace("│", " ").split())  # noqa: E731
    assert flat(hint) in flat(sources_help)
    assert flat(hint) in flat(legal_help)


# ------------------------------------------------------------------------------------- doc-forensics


def _docx(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/settings.xml", '<w:settings><w:rsidRoot w:val="00A1B2C3"/></w:settings>')
        zf.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>Jane</dc:creator></cp:coreProperties>")
    return path


def test_doc_forensics_valid_docx_exits_0(tmp_path: Path) -> None:
    res = _run("doc-forensics", str(_docx(tmp_path / "ok.docx")))
    assert res.exit_code == 0, res.output
    assert "00A1B2C3" in res.output


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("missing.docx", None),
        ("corrupt.docx", b"not a zip"),
        ("garbage.pdf", b"garbage"),
        ("notes.txt", b"plain text"),
        ("noext", b"x"),
    ],
)
def test_doc_forensics_errors_exit_1_cleanly(tmp_path: Path, name: str, content: Any) -> None:
    path = tmp_path / name
    if content is not None:
        path.write_bytes(content)
    res = _run("doc-forensics", str(path))
    assert res.exit_code == 1, res.output
    assert '"error"' not in res.output
    assert "incorrect startxref" not in res.output
    assert "parsing for Object Streams" not in res.output
    _clean(res)


def test_doc_forensics_recoverable_pdf_prints_no_library_noise(tmp_path: Path) -> None:
    # pypdf recovers this file (bad startxref pointer) and logs its repair steps; none of that may reach the user.
    path = tmp_path / "damaged.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\nstartxref\n999\n%%EOF")
    res = _run("doc-forensics", str(path))
    assert res.exit_code == 0, res.output
    assert "incorrect startxref" not in res.output
    assert "parsing for Object Streams" not in res.output
    _clean(res)


@pytest.mark.parametrize("value", ["", "   "])
def test_doc_forensics_empty_path_exits_1(value: str) -> None:
    res = _run("doc-forensics", value)
    assert res.exit_code == 1, res.output
    _clean(res)


def test_doc_forensics_directory_exits_1(tmp_path: Path) -> None:
    folder = tmp_path / "folder.docx"
    folder.mkdir()
    res = _run("doc-forensics", str(folder))
    assert res.exit_code == 1, res.output
    _clean(res)


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read a chmod-000 file")
def test_doc_forensics_unreadable_file_exits_1(tmp_path: Path) -> None:
    path = _docx(tmp_path / "locked.docx")
    path.chmod(0)
    try:
        res = _run("doc-forensics", str(path))
    finally:
        path.chmod(0o600)
    assert res.exit_code == 1, res.output
    _clean(res)


# ------------------------------------------------------------------------------------------------ serve


@pytest.fixture
def uvicorn_calls(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(cli_main.uvicorn, "run", lambda *a, **k: calls.append(k))
    monkeypatch.delenv("BUNNYHOLE_API_TOKEN", raising=False)
    return calls


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com"])
def test_serve_refuses_non_loopback_without_token(host: str, uvicorn_calls: List[Dict[str, Any]]) -> None:
    res = _run("serve", "--host", host)
    assert res.exit_code == 2, res.output
    assert "BUNNYHOLE_API_TOKEN" in res.output
    assert uvicorn_calls == []


def test_serve_non_loopback_with_token_starts(
    uvicorn_calls: List[Dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", "s3cret-token")
    res = _run("serve", "--host", "0.0.0.0", "--port", "8123")
    assert res.exit_code == 0, res.output
    assert uvicorn_calls and uvicorn_calls[0]["host"] == "0.0.0.0" and uvicorn_calls[0]["port"] == 8123
    assert "s3cret-token" not in res.output


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.2"])
def test_serve_loopback_needs_no_token(host: str, uvicorn_calls: List[Dict[str, Any]]) -> None:
    res = _run("serve", "--host", host)
    assert res.exit_code == 0, res.output
    assert uvicorn_calls and uvicorn_calls[0]["host"] == host


# ------------------------------------------------------------------------------------------------- menu


def test_menu_offers_depth_1_to_4(monkeypatch: pytest.MonkeyPatch) -> None:
    from rich import prompt as rich_prompt

    seen: List[Any] = []
    answers = iter(["1", "acme.io", "fast", "4", "0"])

    def _ask(cls: Any, question: str, *a: Any, **k: Any) -> str:
        seen.append((question, k.get("choices")))
        return next(answers)

    monkeypatch.setattr(rich_prompt.Prompt, "ask", classmethod(_ask))
    res = _run("menu")
    assert res.exit_code == 0, res.output
    depth_prompt = next(c for q, c in seen if "depth" in q.lower())
    assert depth_prompt == ["1", "2", "3", "4"]
    assert FakeOrchestrator.instances[-1].kwargs["max_depth"] == 4
