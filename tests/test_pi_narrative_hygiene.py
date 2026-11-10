"""Round 3: no stderr or log leak of an unexpected exception."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from pi_narrative_helpers import narrative_result

from bunnyhole.cli import pi_commands
from bunnyhole.engine import pi_narrative
from bunnyhole.engine.pi_narrative import generate_ai_analysis

SECRET = "boom secret AIzaSECRET-in-an-exception"


@pytest.fixture(autouse=True)
def _key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSECRET-gemini-key")


def test_an_unexpected_exception_is_logged_by_class_name_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    async def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(pi_narrative, "complete_with_fallback", explode)
    with caplog.at_level(logging.DEBUG):
        analysis = asyncio.run(generate_ai_analysis(narrative_result()))
    assert analysis.status == "omitted" and analysis.reason == "internal error (RuntimeError)"
    ours = [r for r in caplog.records if r.name == pi_narrative.logger.name]
    assert ours, "the failure must still be logged"
    for record in ours:
        assert record.exc_info is None and record.exc_text is None
        assert "AIzaSECRET" not in record.getMessage() and "boom" not in record.getMessage()
        assert "RuntimeError" in record.getMessage()
    captured = capsys.readouterr()
    assert "AIzaSECRET" not in captured.err + captured.out and "Traceback" not in captured.err


def test_the_source_never_logs_with_exc_info() -> None:
    import inspect

    source = inspect.getsource(pi_narrative)
    assert "exc_info=" not in source


def test_a_single_link_file_is_still_replaced_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    real = os.replace
    monkeypatch.setattr(pi_commands.os, "replace", lambda a, b: (calls.append(b), real(a, b))[1])
    report = tmp_path / "r.md"
    report.write_text("old", encoding="utf-8")
    pi_commands._write_report_text(report, "new\n")
    assert len(calls) == 1 and report.read_text(encoding="utf-8") == "new\n"
