"""Security and robustness tests for the FastAPI War-Room server (``bunnyhole.api.server``).

Hermetic: every investigation goes through :class:`FakeOrchestrator`; nothing opens a non-loopback socket.
Covers the audit findings C1 (token leak / Host spoof), H1 (body + field limits, event loop), H2 (local
evidence files), H4 (install endpoint), H5 (DOM XSS + CSP), M3 (investigation gate), M4 (credentials in
responses), L1 (key previews) and the version metadata.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import bunnyhole
from bunnyhole.api import server
from bunnyhole.engine.intake import CaseIntakePacket, SmartIntakeParser

LOOPBACK_PEER = ("127.0.0.1", 50000)
LAN_PEER = ("192.168.1.5", 12345)
BASE_URL = "http://localhost:8000"
TOKEN = "unit-test-token-0123456789abcdef"
HOSTILE_IDS = ["email:'),alert(1),('", 'username:"><img src=x onerror=alert(1)>']

_ENV_VARS = (
    "BUNNYHOLE_API_TOKEN",
    "BUNNYHOLE_EVIDENCE_DIR",
    "BUNNYHOLE_API_ALLOW_INSTALL",
    "BUNNYHOLE_API_MAX_BODY",
    "BUNNYHOLE_API_INVESTIGATION_TIMEOUT_S",
    "BUNNYHOLE_API_MAX_EVIDENCE_BYTES",
)


# --------------------------------------------------------------------------------------------------
# Fakes and fixtures
# --------------------------------------------------------------------------------------------------


class FakeGraph:
    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.nodes: Dict[str, Any] = {}

    def export_markdown_dossier(self) -> str:
        return "# Dossier\n"


class FakeSleuth:
    def __init__(self, owner: "FakeOrchestrator") -> None:
        self.owner = owner

    async def verify_interconnection_cooccurrence(self, *args: Any, **kwargs: Any) -> None:
        FakeOrchestrator.calls.append(("verify", args))
        await self.owner._maybe_sleep()

    def break_dead_ends(self, current_hop: int) -> None:
        return None


class FakeOrchestrator:
    """Records how the API drives the engine; never touches the network."""

    calls: List[Tuple[Any, ...]] = []
    delay_s: float = 0.0
    counter: int = 0
    extra_result: Dict[str, Any] = {}

    def __init__(self, seed_query: str = "", gear: Any = None, max_depth: int = 2, initial_breadth: int = 4,
                 intake_packet: Optional[CaseIntakePacket] = None, **_: Any) -> None:
        FakeOrchestrator.counter += 1
        self.seed_query = seed_query
        self.intake_packet = intake_packet
        self.graph = FakeGraph(f"bh_fake{FakeOrchestrator.counter:04d}")
        self.link_sleuth = FakeSleuth(self)
        FakeOrchestrator.calls.append(("init", seed_query))

    async def _maybe_sleep(self) -> None:
        if FakeOrchestrator.delay_s:
            await asyncio.sleep(FakeOrchestrator.delay_s)

    def compile_full_result(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "case_id": self.graph.case_id,
            "seed_query": self.seed_query,
            "nodes": [],
            "edges": [],
            "stats": {"total_nodes": 0, "total_edges": 0, "total_receipts": 0, "cutout_brokers": 0},
        }
        if self.intake_packet is not None:
            res["intake_packet"] = self.intake_packet
        res.update(FakeOrchestrator.extra_result)
        return res

    async def run_investigation(self) -> Dict[str, Any]:
        FakeOrchestrator.calls.append(("trace", self.seed_query))
        await self._maybe_sleep()
        return self.compile_full_result()

    async def run_intake_investigation(self, packet: CaseIntakePacket) -> Dict[str, Any]:
        FakeOrchestrator.calls.append(("intake", packet))
        await self._maybe_sleep()
        return self.compile_full_result()

    async def run_bidirectional_link_investigation(self, a: str, b: str) -> Dict[str, Any]:
        FakeOrchestrator.calls.append(("link", a, b))
        await self._maybe_sleep()
        return self.compile_full_result()

    async def _execute_lead(self, lead_type: str, value: str, origin: str, hop_depth: int) -> None:
        FakeOrchestrator.calls.append(("lead", lead_type, value))
        await self._maybe_sleep()

    def _harvest_step_learnings_and_followups(self, current_hop: int) -> None:
        return None


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from bunnyhole.arsenal import manager

    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    def never_install(self: Any, tool_name: str) -> Dict[str, Any]:
        raise AssertionError(f"a test reached the real package-manager install for {tool_name!r}")

    # Never run a real package manager or write the key vault from this suite (tests override where needed).
    monkeypatch.setattr(manager.ArsenalManager, "install_tool", never_install)
    monkeypatch.setattr(manager.ArsenalManager, "set_api_key", lambda self, k, v: None)
    monkeypatch.setattr(manager.ArsenalManager, "check_arsenal_status", lambda self: [])
    FakeOrchestrator.calls = []
    FakeOrchestrator.delay_s = 0.0
    FakeOrchestrator.extra_result = {}
    monkeypatch.setattr(server, "BunnyholeOrchestrator", FakeOrchestrator)
    server.ACTIVE_CASES.clear()
    yield
    server.ACTIVE_CASES.clear()


def make_client(peer: Tuple[str, int] = LOOPBACK_PEER, base_url: str = BASE_URL) -> TestClient:
    return TestClient(server.app, base_url=base_url, client=peer, raise_server_exceptions=False)


def auth(token: str = TOKEN) -> Dict[str, str]:
    return {"X-Bunnyhole-Token": token}


def intake_packets() -> List[CaseIntakePacket]:
    return [c[1] for c in FakeOrchestrator.calls if c[0] == "intake"]


# --------------------------------------------------------------------------------------------------
# C1: the token is never served; it guards every /api route; loopback-only without a token
# --------------------------------------------------------------------------------------------------


def test_root_html_never_contains_configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    resp = make_client().get("/")
    assert resp.status_code == 200
    assert TOKEN not in resp.text
    assert all(TOKEN not in v for v in resp.headers.values())
    assert "__BUNNYHOLE_API_TOKEN__" not in server.WAR_ROOM_HTML


GET_ROUTES = ["/api/arsenal", "/api/cases", "/api/cases/bh_missing", "/api/research-files"]
POST_ROUTES = [
    ("/api/parse-intake", {"raw_text": "acme.io"}),
    ("/api/intake", {"domains": ["acme.io"]}),
    ("/api/trace", {"seed": "acme.io"}),
    ("/api/link", {"entity_a": "a.io", "entity_b": "b.io"}),
    ("/api/pivot", {"case_id": "x", "node_id": "n", "seed_value": "acme.io"}),
    ("/api/verify-link", {"case_id": "x", "node_a_id": "a", "entity_a": "a", "node_b_id": "b", "entity_b": "b"}),
    ("/api/keys", {"key": "SHODAN_API_KEY", "value": "v"}),
    ("/api/arsenal/install", {"tool_name": "sherlock"}),
]


@pytest.mark.parametrize("path", GET_ROUTES)
def test_token_required_on_every_api_get(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    client = make_client()
    assert client.get(path).status_code == 401
    assert client.get(path, headers=auth("wrong-token")).status_code == 401
    assert client.get(path, headers=auth()).status_code != 401


@pytest.mark.parametrize(("path", "body"), POST_ROUTES)
def test_token_required_on_every_api_post(monkeypatch: pytest.MonkeyPatch, path: str, body: Dict[str, Any]) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    client = make_client()
    assert client.post(path, json=body).status_code == 401
    assert client.post(path, json=body, headers=auth("nope")).status_code == 401
    assert client.post(path, json=body, headers=auth()).status_code != 401


def test_bearer_authorization_header_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    resp = make_client().get("/api/research-files", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


def test_token_comparison_uses_hmac_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    calls: List[Tuple[Any, Any]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(server.hmac, "compare_digest", spy)
    assert make_client().get("/api/research-files", headers=auth()).status_code == 200
    assert calls, "token check must go through hmac.compare_digest"


def test_host_spoof_from_lan_peer_is_rejected_without_token() -> None:
    client = make_client(peer=LAN_PEER)
    for path in ("/", "/api/cases", "/api/research-files"):
        resp = client.get(path, headers={"Host": "localhost"})
        assert resp.status_code == 403, path
    resp = client.post("/api/keys", json={"key": "SHODAN_API_KEY", "value": "x"}, headers={"Host": "127.0.0.1"})
    assert resp.status_code == 403


def test_lan_peer_with_valid_token_is_served(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    client = make_client(peer=LAN_PEER, base_url="http://192.168.1.10:8000")
    assert client.get("/api/research-files", headers=auth()).status_code == 200
    assert client.get("/api/research-files").status_code == 401
    assert client.get("/").status_code == 200  # the static shell carries no secrets


def test_dns_rebinding_host_is_rejected_from_loopback_peer() -> None:
    resp = make_client().get("/api/cases", headers={"Host": "evil.example.com"})
    assert resp.status_code == 400


@pytest.mark.parametrize("peer_host", ["::1", "::ffff:127.0.0.1", "127.0.0.2"])
def test_loopback_peers_are_allowed_without_token(peer_host: str) -> None:
    assert make_client(peer=(peer_host, 1)).get("/api/research-files").status_code == 200


def test_ipv6_loopback_host_header_is_trusted() -> None:
    client = make_client(peer=("::1", 4321), base_url="http://[::1]:8000")
    assert client.get("/").status_code == 200
    assert client.get("/api/research-files").status_code == 200


def test_war_room_asks_for_token_and_keeps_it_out_of_local_storage() -> None:
    html = server.WAR_ROOM_HTML
    assert "X-Bunnyhole-Token" in html
    assert "sessionStorage" in html
    assert "localStorage" not in html
    assert "prompt(" in html


# --------------------------------------------------------------------------------------------------
# H1: body-size limit, field limits, parsing off the event loop, investigation timeout
# --------------------------------------------------------------------------------------------------


def test_oversize_body_is_rejected_with_413_by_content_length() -> None:
    big = json.dumps({"raw_omni_text": "a" * (2 * 1024 * 1024)})
    resp = make_client().post("/api/intake", content=big, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413
    assert not FakeOrchestrator.calls


def test_oversize_streamed_body_is_rejected_with_413() -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"raw_omni_text": "'
        for _ in range(40):
            yield b"a" * 65536
        yield b'"}'

    resp = make_client().post("/api/intake", content=chunks(), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413
    assert not FakeOrchestrator.calls


def test_max_body_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_MAX_BODY", "64")
    resp = make_client().post("/api/trace", json={"seed": "x" * 100})
    assert resp.status_code == 413


@pytest.mark.parametrize(
    "body",
    [
        {"raw_omni_text": "a" * 20001},
        {"raw_omni_input": "a" * 20001},
        {"hypothesis": "h" * 2001},
        {"usernames": [f"user{i}" for i in range(65)]},
        {"emails": ["e" * 513]},
        {"credentials": ["c" * 513]},
        {"evidence_files": ["/x" * 600]},
        {"title": "t" * 501},
        {"depth": 9},
        {"breadth": 99},
    ],
)
def test_intake_field_limits_return_422(body: Dict[str, Any]) -> None:
    resp = make_client().post("/api/intake", json=body)
    assert resp.status_code == 422, resp.text
    assert not FakeOrchestrator.calls


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/trace", {"seed": "s" * 2001}),
        ("/api/link", {"entity_a": "a" * 2001, "entity_b": "b"}),
        ("/api/parse-intake", {"raw_text": "r" * 20001}),
        ("/api/pivot", {"case_id": "c", "node_id": "n" * 501, "seed_value": "acme.io"}),
        ("/api/pivot", {"case_id": "c", "node_id": "n", "seed_value": "s" * 2001}),
        ("/api/pivot", {"case_id": "c" * 129, "node_id": "n", "seed_value": "acme.io"}),
        ("/api/verify-link", {"case_id": "c", "node_a_id": "a" * 501, "entity_a": "a", "node_b_id": "b", "entity_b": "b"}),
        ("/api/keys", {"key": "K" * 129, "value": "v"}),
        ("/api/keys", {"key": "SHODAN_API_KEY", "value": "v" * 4097}),
        ("/api/arsenal/install", {"tool_name": "t" * 65}),
    ],
)
def test_request_model_field_limits_return_422(path: str, body: Dict[str, Any]) -> None:
    assert make_client().post(path, json=body).status_code == 422


def test_cases_query_and_case_id_are_bounded() -> None:
    client = make_client()
    assert client.get("/api/cases", params={"q": "q" * 201}).status_code == 422
    assert client.get("/api/cases/" + "c" * 129).status_code == 422


@pytest.mark.parametrize(
    ("path", "body"),
    [("/api/parse-intake", {"raw_text": "acme.io"}), ("/api/intake", {"raw_omni_text": "acme.io"})],
)
def test_intake_parsing_does_not_block_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, path: str, body: Dict[str, Any]
) -> None:
    started = threading.Event()
    release = threading.Event()
    real = SmartIntakeParser.parse_omni_text.__func__  # type: ignore[attr-defined]

    def slow_parse(cls: Any, raw_text: str) -> CaseIntakePacket:
        started.set()
        release.wait(timeout=5)
        return real(cls, raw_text)

    monkeypatch.setattr(SmartIntakeParser, "parse_omni_text", classmethod(slow_parse))
    with make_client() as client:
        results: Dict[str, int] = {}
        worker = threading.Thread(target=lambda: results.update(slow=client.post(path, json=body).status_code))
        worker.start()
        try:
            assert started.wait(timeout=5), "the slow parse never started"
            t0 = time.monotonic()
            fast = client.get("/api/research-files")
            elapsed = time.monotonic() - t0
            released_before_answer = release.is_set()
        finally:
            release.set()
            worker.join(timeout=10)
    assert fast.status_code == 200
    assert not released_before_answer
    assert elapsed < 2.0, f"a concurrent GET waited {elapsed:.2f}s behind CPU-bound parsing"
    assert results.get("slow") == 200


@pytest.mark.parametrize(
    ("path", "body"),
    [("/api/parse-intake", {"raw_text": "see http://a]b[c"}), ("/api/intake", {"raw_omni_text": "see http://a]b[c"})],
)
def test_parser_value_error_becomes_400(monkeypatch: pytest.MonkeyPatch, path: str, body: Dict[str, Any]) -> None:
    def broken(cls: Any, raw_text: str) -> CaseIntakePacket:
        raise ValueError("Invalid IPv6 URL")

    monkeypatch.setattr(SmartIntakeParser, "parse_omni_text", classmethod(broken))
    resp = make_client().post(path, json=body)
    assert resp.status_code == 400
    assert "parse" in resp.json()["detail"].lower()


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/trace", {"seed": "acme.io"}),
        ("/api/intake", {"domains": ["acme.io"]}),
        ("/api/link", {"entity_a": "a.io", "entity_b": "b.io"}),
    ],
)
def test_investigation_wall_clock_timeout_returns_504(
    monkeypatch: pytest.MonkeyPatch, path: str, body: Dict[str, Any]
) -> None:
    monkeypatch.setenv("BUNNYHOLE_API_INVESTIGATION_TIMEOUT_S", "0.05")
    FakeOrchestrator.delay_s = 2.0
    t0 = time.monotonic()
    resp = make_client().post(path, json=body)
    assert resp.status_code == 504
    assert time.monotonic() - t0 < 1.5


def test_pivot_and_verify_link_are_bounded_by_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_client()
    case_id = client.post("/api/trace", json={"seed": "acme.io"}).json()["case_id"]
    monkeypatch.setenv("BUNNYHOLE_API_INVESTIGATION_TIMEOUT_S", "0.05")
    FakeOrchestrator.delay_s = 2.0
    pivot = client.post("/api/pivot", json={"case_id": case_id, "node_id": "n", "seed_value": "acme.io"})
    verify = client.post(
        "/api/verify-link",
        json={"case_id": case_id, "node_a_id": "a", "entity_a": "a", "node_b_id": "b", "entity_b": "b"},
    )
    assert pivot.status_code == 504
    assert verify.status_code == 504


# --------------------------------------------------------------------------------------------------
# H2: local evidence files over HTTP
# --------------------------------------------------------------------------------------------------


@pytest.fixture()
def evidence_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "filing.pdf").write_bytes(b"%PDF-1.4 test")
    monkeypatch.setenv("BUNNYHOLE_EVIDENCE_DIR", str(root))
    return root


def test_evidence_files_rejected_when_no_evidence_dir(tmp_path: Path) -> None:
    doc = tmp_path / "secret.pdf"
    doc.write_bytes(b"%PDF")
    resp = make_client().post("/api/intake", json={"domains": ["acme.io"], "evidence_files": [str(doc)]})
    assert resp.status_code == 403
    assert "BUNNYHOLE_EVIDENCE_DIR" in resp.json()["detail"]
    assert not intake_packets()


def test_raw_text_document_mentions_are_dropped_not_read(tmp_path: Path) -> None:
    doc = tmp_path / "leak.pdf"
    doc.write_bytes(b"%PDF")
    resp = make_client().post("/api/intake", json={"raw_omni_text": f"acme.io see {doc} for context"})
    assert resp.status_code == 200, resp.text
    packet = intake_packets()[0]
    assert packet.evidence_files == []
    assert str(doc) not in packet.raw_omni_text
    # the orchestrator re-normalizes the packet; the dropped path must not come back
    assert SmartIntakeParser.normalize_packet(packet).evidence_files == []
    assert resp.json()["evidence_files_rejected"][0]["path"] == str(doc)


def test_evidence_inside_dir_is_accepted(evidence_dir: Path) -> None:
    doc = evidence_dir / "filing.pdf"
    resp = make_client().post("/api/intake", json={"domains": ["acme.io"], "evidence_files": [str(doc)]})
    assert resp.status_code == 200, resp.text
    assert intake_packets()[0].evidence_files == [str(doc)]


def test_evidence_outside_dir_is_rejected(evidence_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF")
    resp = make_client().post("/api/intake", json={"evidence_files": [str(outside)]})
    assert resp.status_code == 400
    assert "outside" in resp.json()["detail"].lower()
    assert not intake_packets()


def test_evidence_dotdot_is_rejected(evidence_dir: Path, tmp_path: Path) -> None:
    (tmp_path / "outside.pdf").write_bytes(b"%PDF")
    sneaky = f"{evidence_dir}/../outside.pdf"
    resp = make_client().post("/api/intake", json={"evidence_files": [sneaky]})
    assert resp.status_code == 400
    assert not intake_packets()


def test_evidence_symlink_escape_is_rejected(evidence_dir: Path, tmp_path: Path) -> None:
    target = tmp_path / "private.pdf"
    target.write_bytes(b"%PDF")
    link = evidence_dir / "innocent.pdf"
    link.symlink_to(target)
    resp = make_client().post("/api/intake", json={"evidence_files": [str(link)]})
    assert resp.status_code == 400
    assert not intake_packets()


def test_evidence_relative_path_is_rejected(evidence_dir: Path) -> None:
    resp = make_client().post("/api/intake", json={"evidence_files": ["filing.pdf"]})
    assert resp.status_code == 400
    assert "absolute" in resp.json()["detail"].lower()


def test_evidence_non_regular_and_oversize_files_are_rejected(
    evidence_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (evidence_dir / "folder.pdf").mkdir()
    client = make_client()
    assert client.post("/api/intake", json={"evidence_files": [str(evidence_dir / "folder.pdf")]}).status_code == 400
    assert client.post("/api/intake", json={"evidence_files": [str(evidence_dir / "missing.pdf")]}).status_code == 400
    monkeypatch.setenv("BUNNYHOLE_API_MAX_EVIDENCE_BYTES", "4")
    assert client.post("/api/intake", json={"evidence_files": [str(evidence_dir / "filing.pdf")]}).status_code == 400
    assert not intake_packets()


def test_pivot_document_lead_follows_the_evidence_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_client()
    case_id = client.post("/api/trace", json={"seed": "acme.io"}).json()["case_id"]
    outside = tmp_path / "x.pdf"
    outside.write_bytes(b"%PDF")
    explicit = {"case_id": case_id, "node_id": "n", "seed_value": str(outside), "lead_type": "document"}
    inferred = {"case_id": case_id, "node_id": "n", "seed_value": str(outside)}
    assert client.post("/api/pivot", json=explicit).status_code == 403
    assert client.post("/api/pivot", json=inferred).status_code == 403
    assert not [c for c in FakeOrchestrator.calls if c[0] == "lead"]

    root = tmp_path / "ev"
    root.mkdir()
    (root / "ok.docx").write_bytes(b"PK")
    monkeypatch.setenv("BUNNYHOLE_EVIDENCE_DIR", str(root))
    assert client.post("/api/pivot", json=explicit).status_code == 400
    ok = dict(explicit, seed_value=str(root / "ok.docx"))
    assert client.post("/api/pivot", json=ok).status_code == 200
    assert ("lead", "document", str(root / "ok.docx")) in FakeOrchestrator.calls


@pytest.mark.parametrize(
    ("path", "body"),
    [("/api/trace", {"seed": "/etc/private.pdf"}), ("/api/link", {"entity_a": "/etc/a.docx", "entity_b": "b.io"})],
)
def test_trace_and_link_document_seeds_follow_the_evidence_policy(path: str, body: Dict[str, Any]) -> None:
    resp = make_client().post(path, json=body)
    assert resp.status_code == 403
    assert not [c for c in FakeOrchestrator.calls if c[0] in ("trace", "link")]


# --------------------------------------------------------------------------------------------------
# H4: arsenal install endpoint
# --------------------------------------------------------------------------------------------------


class _InstallRecorder:
    def __init__(self) -> None:
        self.installed: List[str] = []

    def patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from bunnyhole.arsenal import manager

        rec = self

        def fake_install(self: Any, tool_name: str) -> Dict[str, Any]:
            rec.installed.append(tool_name)
            return {"success": True, "tool": tool_name}

        monkeypatch.setattr(manager.ArsenalManager, "install_tool", fake_install)
        monkeypatch.setattr(manager.ArsenalManager, "check_arsenal_status", lambda self: [])


def test_install_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _InstallRecorder()
    rec.patch(monkeypatch)
    resp = make_client().post("/api/arsenal/install", json={"tool_name": "sherlock"})
    assert resp.status_code == 403
    assert "BUNNYHOLE_API_ALLOW_INSTALL" in resp.json()["detail"]
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    assert make_client().post("/api/arsenal/install", json={"tool_name": "sherlock"}, headers=auth()).status_code == 403
    assert rec.installed == []


def test_install_flag_without_token_is_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _InstallRecorder()
    rec.patch(monkeypatch)
    monkeypatch.setenv("BUNNYHOLE_API_ALLOW_INSTALL", "1")
    assert make_client().post("/api/arsenal/install", json={"tool_name": "sherlock"}).status_code == 403
    assert rec.installed == []


def test_install_enabled_accepts_catalog_names_only_and_audits(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from bunnyhole.arsenal.manager import ARSENAL_TOOLS_CATALOG

    rec = _InstallRecorder()
    rec.patch(monkeypatch)
    monkeypatch.setenv("BUNNYHOLE_API_ALLOW_INSTALL", "1")
    monkeypatch.setenv("BUNNYHOLE_API_TOKEN", TOKEN)
    client = make_client()
    bad = client.post("/api/arsenal/install", json={"tool_name": "evil; rm -rf ~"}, headers=auth())
    assert bad.status_code == 400
    name = ARSENAL_TOOLS_CATALOG[0]["name"]
    with caplog.at_level(logging.INFO, logger="bunnyhole.api.audit"):
        ok = client.post("/api/arsenal/install", json={"tool_name": name}, headers=auth())
    assert ok.status_code == 200
    assert rec.installed == [name]
    assert any("install" in r.getMessage() and name in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------------------------------
# H5: DOM XSS hardening, CSP nonce, security headers
# --------------------------------------------------------------------------------------------------


def _script_source() -> str:
    m = re.search(r"<script>(.*?)</script>", server.WAR_ROOM_HTML, flags=re.S)
    assert m, "inline War-Room script not found"
    return m.group(1)


def _skip_string(src: str, i: int) -> int:
    quote, j = src[i], i + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == quote:
            return j + 1
        j += 1
    raise AssertionError(f"unterminated string at {i}")


def _regex_allowed(src: str, i: int) -> bool:
    j = i - 1
    while j >= 0 and src[j] in " \t\n":
        j -= 1
    return j < 0 or src[j] in "(,=:[!&|?{};"


def _skip_regex(src: str, i: int) -> int:
    j, in_class = i + 1, False
    while j < len(src):
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < len(src) and src[j].isalpha():
                j += 1
            return j
        j += 1
    raise AssertionError(f"unterminated regex at {i}")


def _read_template(src: str, i: int, exprs: List[str]) -> int:
    j = i + 1
    while j < len(src):
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1
        if c == "$" and src[j + 1] == "{":
            k = _read_code(src, j + 2, exprs, stop="}")
            exprs.append(src[j + 2:k].strip())
            j = k + 1
            continue
        j += 1
    raise AssertionError(f"unterminated template at {i}")


def _read_code(src: str, i: int, exprs: List[str], stop: Optional[str] = None) -> int:
    depth, j = 0, i
    while j < len(src):
        c = src[j]
        nxt = src[j + 1] if j + 1 < len(src) else ""
        if c in "'\"":
            j = _skip_string(src, j)
            continue
        if c == "`":
            j = _read_template(src, j, exprs)
            continue
        if c == "/" and nxt == "/":
            j = src.index("\n", j)
            continue
        if c == "/" and nxt == "*":
            j = src.index("*/", j) + 2
            continue
        if c == "/" and _regex_allowed(src, j):
            j = _skip_regex(src, j)
            continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            if depth == 0 and stop == c:
                return j
            depth -= 1
        elif c == ";" and depth == 0 and stop == ";":
            return j
        j += 1
    return j


def _skeleton(src: str) -> str:
    """Collapse every string literal to S and template literal to T (top level only)."""
    out: List[str] = []
    j = 0
    while j < len(src):
        c = src[j]
        if c in "'\"":
            j = _skip_string(src, j)
            out.append("S")
        elif c == "`":
            j = _read_template(src, j, [])
            out.append("T")
        else:
            out.append(c)
            j += 1
    return re.sub(r"\s+", " ", "".join(out)).strip()


def _whole_call(expr: str, fn: str) -> bool:
    if not expr.startswith(fn + "("):
        return False
    return _read_code(expr, len(fn) + 1, [], stop=")") == len(expr) - 1


_LIST = r"\(?[\w.]+(?: \|\| \[\])?\)?"
_SAFE_SHAPES = [
    re.compile(rf"^{_LIST}\.map\(esc\)\.join\(S\)$"),
    re.compile(rf"^{_LIST}\.map\(\(?\w+(?:, ?\w+)?\)? => T\)\.join\(S\)$"),
    re.compile(r"^[\w.!]+(?: [<>=!]+ \w+)? \? (?:T|S) : (?:T|S)$"),
]
_INNER_HTML_SHAPES = [
    re.compile(r"^(?:T|S)$"),
    re.compile(rf"^{_LIST}\.map\(\(?\w+(?:, ?\w+)?\)? => T\)\.join\(S\)$"),
    re.compile(rf"^[\w.!]+ \? (?:T|S|{_LIST}\.map\(\(?\w+(?:, ?\w+)?\)? => T\)\.join\(S\)) : (?:T|S)$"),
]


def test_war_room_has_no_inline_event_handlers_or_js_urls() -> None:
    html = server.WAR_ROOM_HTML
    assert not re.findall(r"\son[a-z]+\s*=", html), "inline on*= handlers bypass the CSP nonce and invite XSS"
    assert "javascript:" not in html.lower()
    for sink in ("insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function"):
        assert sink not in html, sink


def test_every_html_template_interpolation_is_escaped() -> None:
    src = _script_source()
    exprs: List[str] = []
    _read_code(src, 0, exprs)
    assert len(exprs) > 40, "scanner found suspiciously few interpolations"
    unsafe = [
        e for e in exprs
        if not (_whole_call(e, "esc") or any(p.match(_skeleton(e)) for p in _SAFE_SHAPES))
    ]
    assert not unsafe, f"unescaped interpolations: {unsafe}"


def test_every_inner_html_assignment_is_a_template() -> None:
    src = _script_source()
    sinks = [m.end() for m in re.finditer(r"\.innerHTML\s*=", src)]
    assert sinks
    bad = []
    for start in sinks:
        end = _read_code(src, start, [], stop=";")
        rhs = _skeleton(src[start:end])
        if not any(p.match(rhs) for p in _INNER_HTML_SHAPES):
            bad.append(rhs)
    assert not bad, f"innerHTML built outside an escaped template: {bad}"


def test_hrefs_go_through_safe_url() -> None:
    for m in re.finditer(r'href="\$\{', server.WAR_ROOM_HTML):
        assert server.WAR_ROOM_HTML[m.end():].startswith("esc(safeUrl("), "href interpolation without safeUrl"


def test_csp_uses_a_fresh_script_nonce_per_response() -> None:
    client = make_client()
    nonces = []
    for _ in range(2):
        resp = client.get("/")
        csp = resp.headers["content-security-policy"]
        script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src"))
        assert "'unsafe-inline'" not in script_src
        nonce = re.search(r"'nonce-([^']+)'", script_src).group(1)  # type: ignore[union-attr]
        tags = re.findall(r"<script\b[^>]*>", resp.text)
        assert tags and all(f'nonce="{nonce}"' in t for t in tags)
        assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp and "base-uri 'none'" in csp
        nonces.append(nonce)
    assert nonces[0] != nonces[1]


def test_hostile_node_ids_never_reach_server_html(monkeypatch: pytest.MonkeyPatch) -> None:
    hostile_nodes = [{"id": h, "label": h, "hop_depth": 1} for h in HOSTILE_IDS]
    FakeOrchestrator.extra_result = {
        "nodes": hostile_nodes,
        "interconnections": {"targeted_paths": [{"node_ids": HOSTILE_IDS, "step_labels": HOSTILE_IDS}]},
    }
    client = make_client()
    resp = client.post("/api/trace", json={"seed": "acme.io"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["x-content-type-options"] == "nosniff"
    page = client.get("/").text
    for h in HOSTILE_IDS:
        assert h not in page
    assert "alert(1)" not in page


@pytest.mark.parametrize(
    ("method", "path", "kwargs", "peer"),
    [
        ("get", "/api/research-files", {}, LOOPBACK_PEER),
        ("get", "/api/cases", {}, LAN_PEER),  # 403 from the guard
        ("post", "/api/trace", {"content": b"x" * (2 * 1024 * 1024)}, LOOPBACK_PEER),  # 413 from the guard
        ("post", "/api/trace", {"json": {"seed": ""}}, LOOPBACK_PEER),  # 422
    ],
)
def test_api_responses_carry_security_headers(method: str, path: str, kwargs: Dict[str, Any], peer: Tuple[str, int]) -> None:
    resp = getattr(make_client(peer=peer), method)(path, **kwargs)
    h = resp.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store"
    assert "content-security-policy" in h


# --------------------------------------------------------------------------------------------------
# M3: one bounded investigation gate for every investigation endpoint
# --------------------------------------------------------------------------------------------------


def test_investigation_gate_bounds_the_waiting_queue() -> None:
    async def scenario() -> None:
        gate = server._InvestigationGate(limit=1, max_waiting=1)
        hold = asyncio.Event()

        async def occupant() -> None:
            async with gate.slot():
                await hold.wait()

        first = asyncio.create_task(occupant())
        await asyncio.sleep(0)
        second = asyncio.create_task(occupant())
        await asyncio.sleep(0)
        with pytest.raises(HTTPException) as info:
            async with gate.slot():
                pass
        assert info.value.status_code == 429
        assert info.value.headers and "Retry-After" in info.value.headers
        hold.set()
        await asyncio.gather(first, second)
        async with gate.slot():  # capacity is released afterwards
            pass

    asyncio.run(scenario())


def test_investigation_gate_survives_a_new_event_loop() -> None:
    gate = server._InvestigationGate(limit=1, max_waiting=1)

    async def use() -> None:
        async with gate.slot():
            await asyncio.sleep(0)

    asyncio.run(use())
    asyncio.run(use())


class _RecordingGate:
    def __init__(self) -> None:
        self.entered = 0

    def slot(self) -> Any:
        gate = self

        class _Ctx:
            async def __aenter__(self) -> None:
                gate.entered += 1

            async def __aexit__(self, *exc: Any) -> None:
                return None

        return _Ctx()


class _FullGate:
    def slot(self) -> Any:
        raise HTTPException(status_code=429, detail="busy", headers={"Retry-After": "30"})


def test_every_investigation_endpoint_uses_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    client = make_client()
    case_id = client.post("/api/trace", json={"seed": "acme.io"}).json()["case_id"]
    gate = _RecordingGate()
    monkeypatch.setattr(server, "_INVESTIGATION_GATE", gate)
    for path, body in [
        ("/api/trace", {"seed": "acme.io"}),
        ("/api/intake", {"domains": ["acme.io"]}),
        ("/api/link", {"entity_a": "a.io", "entity_b": "b.io"}),
        ("/api/pivot", {"case_id": case_id, "node_id": "n", "seed_value": "acme.io"}),
        ("/api/verify-link", {"case_id": case_id, "node_a_id": "a", "entity_a": "a", "node_b_id": "b", "entity_b": "b"}),
    ]:
        before = gate.entered
        assert client.post(path, json=body).status_code == 200, path
        assert gate.entered == before + 1, path


def test_full_queue_returns_429_with_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_INVESTIGATION_GATE", _FullGate())
    resp = make_client().post("/api/trace", json={"seed": "acme.io"})
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "30"


# --------------------------------------------------------------------------------------------------
# M4 / L1: no plaintext credentials or key material in responses
# --------------------------------------------------------------------------------------------------


def test_intake_response_never_contains_plaintext_credentials() -> None:
    secret = "Hunter2025!xyz"
    resp = make_client().post(
        "/api/intake",
        json={"credentials": [f"bob@corp.io:{secret}"], "raw_omni_text": f"check bob@corp.io:{secret} please"},
    )
    assert resp.status_code == 200, resp.text
    assert secret not in resp.text
    assert resp.json()["intake_packet"]["credentials"] == ["bob@corp.io:***"]


def test_trace_of_a_credential_seed_does_not_echo_the_secret() -> None:
    secret = "S3cretPassw0rd"
    resp = make_client().post("/api/trace", json={"seed": f"bob@corp.io:{secret}"})
    assert resp.status_code == 200
    assert secret not in resp.text


def test_saved_case_reads_mask_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from bunnyhole.engine import storage

    secret = "TopSecret123!"
    case = {
        "case_id": "bh_saved",
        "seed_query": f"bob@corp.io:{secret}",
        "intake_packet": {"credentials": [f"bob@corp.io:{secret}"], "raw_omni_text": f"bob@corp.io:{secret}"},
        "markdown_dossier": f"leaked bob@corp.io:{secret} here",
    }
    monkeypatch.setattr(storage.CaseStore, "get_case", lambda self, cid: case)
    monkeypatch.setattr(storage.CaseStore, "list_cases", lambda self, limit=25: [{"case_id": "bh_saved", "seed_query": case["seed_query"]}])
    client = make_client()
    one = client.get("/api/cases/bh_saved")
    many = client.get("/api/cases")
    assert one.status_code == 200 and many.status_code == 200
    assert secret not in one.text
    assert secret not in many.text
    assert one.json()["intake_packet"]["credentials"] == ["bob@corp.io:***"]


def test_api_key_previews_show_at_most_the_last_three_chars(monkeypatch: pytest.MonkeyPatch) -> None:
    from bunnyhole.arsenal import manager

    long_val, short_val = "ABCDEFGHIJKLMNOPQRS", "SHORTKEY1"
    monkeypatch.setenv("SHODAN_API_KEY", long_val)
    monkeypatch.setenv("INTELX_API_KEY", short_val)
    statuses = [
        {"key": "SHODAN_API_KEY", "category": "c", "configured": True, "masked_value": long_val[:4] + "..." + long_val[-3:]},
        {"key": "INTELX_API_KEY", "category": "c", "configured": True, "masked_value": short_val[:4] + "..."},
        {"key": "LEAKCHECK_API_KEY", "category": "c", "configured": False, "masked_value": ""},
    ]
    monkeypatch.delenv("LEAKCHECK_API_KEY", raising=False)
    monkeypatch.setattr(manager.ArsenalManager, "get_api_keys_status", lambda self: [dict(s) for s in statuses])
    monkeypatch.setattr(manager.ArsenalManager, "check_arsenal_status", lambda self: [])
    monkeypatch.setattr(manager.ArsenalManager, "set_api_key", lambda self, k, v: None)
    client = make_client()
    for resp in (client.get("/api/arsenal"), client.post("/api/keys", json={"key": "SHODAN_API_KEY", "value": long_val})):
        assert resp.status_code == 200
        keys = {k["key"]: k["masked_value"] for k in resp.json()["api_keys"]}
        assert keys["SHODAN_API_KEY"].endswith("QRS")
        assert "ABCD" not in keys["SHODAN_API_KEY"] and "PQRS" not in keys["SHODAN_API_KEY"]
        assert not any(ch in keys["INTELX_API_KEY"] for ch in "SHORTKEY1")
        assert keys["LEAKCHECK_API_KEY"] == ""


def test_version_metadata_comes_from_the_package() -> None:
    assert server.app.version == bunnyhole.__version__
    source = Path(server.__file__).read_text(encoding="utf-8")
    assert not re.search(r'version="\d+\.\d+\.\d+"', source), "hard-coded version string in api/server.py"
