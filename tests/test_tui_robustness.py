"""Robustness tests for the Textual War-Room (``bunnyhole.tui.app``), driven headless with ``run_test``.

Untrusted strings (node labels, timeline titles, engine errors, the user's own text, dossier links) must never
be parsed as Rich/Textual markup or open a non-web URL, and background workers must survive the UI being torn
down underneath them (the old ``#arsenalbody`` flake) without leaking engine subscribers.
"""

from __future__ import annotations

import asyncio
import copy
import threading
from typing import Any, Callable, Dict, List

import pytest
from rich.text import Text
from textual.widgets import DataTable, Markdown, RichLog, Static

from bunnyhole.arsenal import manager as arsenal_manager
from bunnyhole.tui import app as tui_app
from bunnyhole.tui.app import BunnyholeTUI, RunFailed

HOSTILE = [
    "[/x]",
    "[bold red]x",
    "[link=file:///etc/passwd]click[/link]",
    "[@click=app.quit]boom[/]",
    "L" * 5000,
]

BASE_RESULT: Dict[str, Any] = {
    "stats": {"total_nodes": 1, "total_edges": 0, "total_receipts": 1, "cutout_brokers": 1},
    "nodes": [
        {
            "id": "domain:acme.com",
            "label": "acme.com",
            "entity_type": "Domain",
            "domain": "osint",
            "smoke_score": 40.0,
            "is_cutout_broker": True,
            "betweenness_centrality": 0.1,
            "risk_flags": ["FLAG"],
            "hop_depth": 1,
            "attributes": {},
            "receipts": [{"admiralty_code": "A1", "tool": "t", "extracted_fact": "f", "source_url": "https://x"}],
        }
    ],
    "edges": [],
    "ach_assessment": {"primary_question": "Q", "winning_hypothesis": "H1", "narrative_verdict": "v", "matrix_rows": []},
    "council": {"stage3_chairman_verdict": {"verdict_markdown": "## Verdict"}},
    "interconnections": {"keystone_brokers": [], "cross_domain_paths": [], "predicted_missing_links": []},
    "timeline": [{"timestamp": "2022-01-01", "title": "tx", "anomaly_flag": None}],
    "markdown_dossier": "# Dossier",
}


def _hostile_result(text: str) -> Dict[str, Any]:
    res = copy.deepcopy(BASE_RESULT)
    node = res["nodes"][0]
    node.update(label=text, entity_type=text, domain=text, risk_flags=[text])
    res["timeline"][0]["title"] = text
    res["interconnections"]["keystone_brokers"] = [{"label": text, "domains_bridged": [text]}]
    res["interconnections"]["cross_domain_paths"] = [{"hop_count": 1, "step_labels": [text, text]}]
    res["ach_assessment"]["matrix_rows"] = [{"admiralty_code": text, "diagnosticity": text, "evidence_summary": text}]
    return res


def _log_text(app: BunnyholeTUI) -> str:
    return "\n".join(strip.text for strip in app.query_one("#log", RichLog).lines)


def run(scenario: Callable[[], Any]) -> None:
    asyncio.run(scenario())


@pytest.fixture()
def quiet_arsenal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(arsenal_manager.ArsenalManager, "check_arsenal_status", lambda self: [])
    monkeypatch.setattr(arsenal_manager.ArsenalManager, "get_api_keys_status", lambda self: [])


# --------------------------------------------------------------------------------------------------
# M6: markup injection
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("text", HOSTILE)
def test_hostile_labels_render_as_literal_text(text: str, quiet_arsenal: None) -> None:
    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            app._populate(_hostile_result(text))
            await pilot.pause()
            table = app.query_one("#entities", DataTable)
            assert table.row_count == 1
            cell = table.get_row_at(0)[0]
            assert isinstance(cell, Text)
            assert text[:100] in cell.plain
            assert not any(span.style and getattr(span.style, "link", None) for span in cell.spans if not isinstance(span.style, str))
            timeline = app.query_one("#timeline", Static)
            assert "TIMELINE" in str(timeline.render())

    run(scenario)


@pytest.mark.parametrize("text", HOSTILE[:4])
def test_run_failed_errors_are_written_literally(text: str, quiet_arsenal: None) -> None:
    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            app.post_message(RunFailed(f"ValueError: {text}"))
            await pilot.pause()
            await pilot.pause()
            assert text in _log_text(app)
            assert app._investigation_running is False
            assert app.is_running  # Textual's own message-pump state is untouched

    run(scenario)


@pytest.mark.parametrize("text", ["[/x] acme.io", "[/x]", "[link=file:///etc/passwd]acme.io[/link]"])
def test_user_text_with_markup_does_not_crash_interpretation(text: str, quiet_arsenal: None) -> None:
    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            app._resolve_run(text)
            await pilot.pause()
            await pilot.pause()

    run(scenario)


def test_pivot_log_line_escapes_the_seed(quiet_arsenal: None, monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            res = copy.deepcopy(BASE_RESULT)
            res["nodes"][0]["attributes"] = {"raw_seed": "[/x]"}
            app._populate(res)
            await pilot.pause()
            app._orchestrator = object()  # type: ignore[assignment]
            monkeypatch.setattr(app, "_pivot_worker", lambda *a: None)
            app._pivot_selected()
            await pilot.pause()
            assert "[/x]" in _log_text(app)

    run(scenario)


def test_run_action_starts_an_investigation(quiet_arsenal: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """The app's busy flag must not collide with Textual's internal ``MessagePump._running`` (always True)."""
    launched: List[Any] = []

    async def scenario() -> None:
        app = BunnyholeTUI()
        monkeypatch.setattr(app, "_run_worker", lambda *a: launched.append(a))
        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one("#seed").value = "acme.io"  # type: ignore[attr-defined]
            app._start_run()
            await pilot.pause()
            assert app._investigation_running is True
            app.post_message(RunFailed("stop"))
            await pilot.pause()
            assert app._investigation_running is False
            assert app.is_running

    run(scenario)
    assert len(launched) == 1


def test_parser_value_error_is_reported_not_raised(quiet_arsenal: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(text: str) -> Any:
        raise ValueError("Invalid IPv6 URL")

    monkeypatch.setattr(tui_app, "interpret_command", broken)

    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            assert app._resolve_run("see http://a]b[c") is None
            await pilot.pause()
            assert "Invalid IPv6 URL" in _log_text(app)

    run(scenario)


def test_seed_input_is_length_capped(quiet_arsenal: None) -> None:
    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)):
            from textual.widgets import Input

            assert 0 < app.query_one("#seed", Input).max_length <= 20000

    run(scenario)


@pytest.mark.parametrize("widget_id", ["#dossierbody", "#councilbody"])
def test_markdown_links_open_only_web_urls(widget_id: str, quiet_arsenal: None, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: List[str] = []

    async def scenario() -> None:
        app = BunnyholeTUI()
        monkeypatch.setattr(app, "open_url", lambda url, **kw: opened.append(url))
        async with app.run_test(size=(120, 40)) as pilot:
            md = app.query_one(widget_id, Markdown)
            for href in ("file:///etc/passwd", "javascript:alert(1)", "/Applications/Calculator.app", "https://example.org/a"):
                md.post_message(Markdown.LinkClicked(md, href))
            await pilot.pause()
            await pilot.pause()

    run(scenario)
    assert opened == ["https://example.org/a"]


# --------------------------------------------------------------------------------------------------
# M6: worker lifecycle (the #arsenalbody flake) and subscriber leak
# --------------------------------------------------------------------------------------------------


class _BlockingArsenal:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        gate = self

        def slow_status(self_: Any) -> List[Dict[str, Any]]:
            gate.entered.set()
            gate.release.wait(timeout=10)
            return [{"name": "[/x]", "installed": True}]

        monkeypatch.setattr(arsenal_manager.ArsenalManager, "check_arsenal_status", slow_status)
        monkeypatch.setattr(
            arsenal_manager.ArsenalManager, "get_api_keys_status", lambda self: [{"key": "[/x]", "configured": True}]
        )


def test_arsenal_load_tolerates_its_widget_being_removed_mid_load(monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = _BlockingArsenal(monkeypatch)

    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            assert await asyncio.to_thread(blocker.entered.wait, 10)
            await app.query_one("#arsenalbody", Static).remove()
            blocker.release.set()
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.pause()
            assert app.is_running

    run(scenario)


def test_arsenal_load_after_app_exit_neither_raises_nor_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = _BlockingArsenal(monkeypatch)
    thread_errors: List[BaseException] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: thread_errors.append(args.exc_value))
    before = set(threading.enumerate())

    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)):
            assert await asyncio.to_thread(blocker.entered.wait, 10)
            # finish loading only once the app is already shutting down
            threading.Timer(0.3, blocker.release.set).start()

    run(scenario)
    blocker.release.set()
    for t in set(threading.enumerate()) - before:
        t.join(timeout=5)
        assert not t.is_alive(), f"worker thread {t.name} hung after the app exited"
    assert not thread_errors


def test_arsenal_panel_escapes_tool_and_key_names(monkeypatch: pytest.MonkeyPatch) -> None:
    blocker = _BlockingArsenal(monkeypatch)
    blocker.release.set()

    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.pause()
            assert "[/x]" in str(app.query_one("#arsenalbody", Static).render())

    run(scenario)


class _FakeGraph:
    def __init__(self) -> None:
        self._event_listeners: List[Callable[[Dict[str, Any]], None]] = []

    def subscribe(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._event_listeners.append(cb)

    def export_markdown_dossier(self) -> str:
        return "# d"


class _FakeSleuth:
    def break_dead_ends(self, current_hop: int) -> None:
        return None


class _FakeOrch:
    def __init__(self, fail: bool = False) -> None:
        self.graph = _FakeGraph()
        self.link_sleuth = _FakeSleuth()
        self.fail = fail

    async def _execute_lead(self, *args: Any, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("lead blew up [/x]")

    def _harvest_step_learnings_and_followups(self, current_hop: int) -> None:
        return None

    def compile_full_result(self) -> Dict[str, Any]:
        return copy.deepcopy(BASE_RESULT)


@pytest.mark.parametrize("fail", [False, True])
def test_pivot_worker_unsubscribes_its_callback(fail: bool, quiet_arsenal: None) -> None:
    orch = _FakeOrch(fail=fail)

    async def scenario() -> None:
        app = BunnyholeTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            app._orchestrator = orch  # type: ignore[assignment]
            for _ in range(3):
                app._pivot_worker("domain:acme.com", "acme.com", 2)
                await app.workers.wait_for_complete()
                await pilot.pause()
            assert orch.graph._event_listeners == []

    run(scenario)
