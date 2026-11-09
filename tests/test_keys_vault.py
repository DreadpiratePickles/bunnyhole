"""The API-key vault never destroys data, writes atomically, round-trips awkward values, lets the shell win,
rejects unknown names cleanly, and is honest about keys no agent reads yet.

Every test runs against a temp primary vault and a fake legacy file (monkeypatched module constants), and
restores ``os.environ`` afterwards, so nothing here touches ~/.bunnyhole, ~/.osint-apis or other tests.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Dict, Iterator, Tuple

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.arsenal import manager
from bunnyhole.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

ALL_NAMES = sorted(manager.ALLOWED_KEY_NAMES | set(manager.KEY_ALIASES))


@pytest.fixture
def vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Tuple[Path, Path]]:
    saved_env: Dict[str, str] = dict(os.environ)
    primary = tmp_path / "home" / "api_keys.env"
    legacy = tmp_path / "legacy" / "api_keys.env"
    monkeypatch.setattr(manager, "BUNNYHOLE_CONFIG_DIR", primary.parent)
    monkeypatch.setattr(manager, "BUNNYHOLE_ENV_FILE", primary)
    monkeypatch.setattr(manager, "LEGACY_OSINT_ENV_FILE", legacy)
    monkeypatch.setattr(manager, "_VAULT_INJECTED", {})
    for name in ALL_NAMES:
        os.environ.pop(name, None)
    monkeypatch.setattr(cli_main, "console", Console(width=400))
    try:
        yield primary, legacy
    finally:
        os.environ.clear()
        os.environ.update(saved_env)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


LEGACY_TEXT = (
    "# my old osint toolkit keys\n"
    "SHODAN_API_KEY=legacyshodan123\n"
    "IPGEOLOCATION_API_KEY=unrelated-tool-key\n"
    "export SOMETHING_ELSE=keepme\n"
)


# ------------------------------------------------------------------------------------ data preservation


def test_set_never_writes_or_blanks_the_legacy_vault(vault: Tuple[Path, Path]) -> None:
    primary, legacy = vault
    _write(legacy, LEGACY_TEXT)
    before = legacy.read_bytes()
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "hunter-value-1")
    assert legacy.read_bytes() == before
    assert "HUNTER_API_KEY=hunter-value-1" in primary.read_text(encoding="utf-8")


def test_legacy_values_are_merged_under_the_primary_vault(vault: Tuple[Path, Path]) -> None:
    primary, legacy = vault
    _write(legacy, LEGACY_TEXT + "HUNTER_API_KEY=legacy-hunter\n")
    _write(primary, "HUNTER_API_KEY=primary-hunter\n")
    manager.ArsenalManager()
    assert os.environ["SHODAN_API_KEY"] == "legacyshodan123"
    assert os.environ["HUNTER_API_KEY"] == "primary-hunter"
    assert "IPGEOLOCATION_API_KEY" not in os.environ  # not an allowed name: never exported


def test_set_preserves_unrelated_lines_and_comments_in_the_primary_vault(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    original = (
        "# hand-written header\n"
        "\n"
        "GITHUB_API_KEY=ghp_existing   # my personal token\n"
        "SOME_OTHER_TOOL=keep-this\n"
        "# trailing note\n"
    )
    _write(primary, original)
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "h1")
    text = primary.read_text(encoding="utf-8")
    for line in (
        "# hand-written header",
        "GITHUB_API_KEY=ghp_existing   # my personal token",
        "SOME_OTHER_TOOL=keep-this",
        "# trailing note",
    ):
        assert line in text
    assert text.count("HUNTER_API_KEY=") == 1


def test_set_replaces_an_existing_entry_in_place(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    _write(
        primary, "# head\nHUNTER_API_KEY=old   # https://hunter.io/\nGITHUB_API_KEY=g\nHUNTER_API_KEY=older-duplicate\n"
    )
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "new")
    lines = primary.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# head"
    assert lines[1].startswith("HUNTER_API_KEY=new")
    assert "https://hunter.io/" in lines[1]
    assert sum(1 for ln in lines if ln.startswith("HUNTER_API_KEY=")) == 1
    assert "GITHUB_API_KEY=g" in lines


def test_primary_write_is_atomic_0600_and_leaves_no_temp_files(
    vault: Tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    primary, _ = vault
    replaced = []
    synced = []
    real_replace, real_fsync = os.replace, os.fsync
    monkeypatch.setattr(
        manager.os, "replace", lambda a, b: (replaced.append((Path(a), Path(b))), real_replace(a, b))[1]
    )
    monkeypatch.setattr(manager.os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "v")
    assert replaced and replaced[-1][1] == primary and replaced[-1][0].parent == primary.parent
    assert synced
    assert stat.S_IMODE(primary.stat().st_mode) == 0o600
    assert sorted(p.name for p in primary.parent.iterdir()) == ["api_keys.env"]


@pytest.mark.parametrize(
    "value",
    ["abc #def", "with space", 'quo"te', "back\\slash", "trailing#hash", "  padded  ", "a=b=c", "x'y", "$HOME"],
)
def test_awkward_values_round_trip_exactly(vault: Tuple[Path, Path], value: str) -> None:
    primary, _ = vault
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", value)
    os.environ.pop("HUNTER_API_KEY", None)
    manager._VAULT_INJECTED.clear()
    manager.ArsenalManager()
    assert os.environ["HUNTER_API_KEY"] == value.strip()


def test_values_with_hash_or_space_are_written_quoted(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "abc #def")
    assert 'HUNTER_API_KEY="abc #def"' in primary.read_text(encoding="utf-8")


def test_old_format_unquoted_lines_with_inline_comments_still_load(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    _write(primary, "HUNTER_API_KEY=tok#en1                               # https://hunter.io/ (Free)\n")
    manager.ArsenalManager()
    assert os.environ["HUNTER_API_KEY"] == "tok#en1"


# ------------------------------------------------------------------------------------- shell precedence


def test_shell_export_wins_over_the_vault(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    _write(primary, "HUNTER_API_KEY=from-vault\n")
    os.environ["HUNTER_API_KEY"] = "from-shell"
    mgr = manager.ArsenalManager()
    assert os.environ["HUNTER_API_KEY"] == "from-shell"
    status = {s["key"]: s for s in mgr.get_api_keys_status()}
    assert status["HUNTER_API_KEY"]["source"] == "shell"


def test_status_reports_vault_source(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    _write(primary, "GITHUB_API_KEY=ghp_abcdefghijk\n")
    status = {s["key"]: s for s in manager.ArsenalManager().get_api_keys_status()}
    assert status["GITHUB_API_KEY"]["configured"] is True
    assert status["GITHUB_API_KEY"]["source"] == "vault"
    assert status["HUNTER_API_KEY"]["source"] == ""


def test_set_while_shell_exports_the_key_keeps_the_shell_value_and_says_so(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    os.environ["HUNTER_API_KEY"] = "from-shell"
    result = manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "from-set")
    assert result["shadowed_by_shell"] is True
    assert os.environ["HUNTER_API_KEY"] == "from-shell"
    assert "HUNTER_API_KEY=from-set" in primary.read_text(encoding="utf-8")


def test_clearing_removes_the_value_and_masks_the_legacy_copy(vault: Tuple[Path, Path]) -> None:
    primary, legacy = vault
    _write(legacy, "SHODAN_API_KEY=legacyshodan123\n")
    mgr = manager.ArsenalManager()
    assert os.environ["SHODAN_API_KEY"] == "legacyshodan123"
    result = mgr.set_api_key("SHODAN_API_KEY", "")
    assert result["action"] == "cleared"
    assert "SHODAN_API_KEY" not in os.environ
    status = {s["key"]: s for s in mgr.get_api_keys_status()}
    assert status["SHODAN_API_KEY"]["configured"] is False
    assert legacy.read_text(encoding="utf-8") == "SHODAN_API_KEY=legacyshodan123\n"


# --------------------------------------------------------------------------------------- name handling


def test_unknown_name_raises_a_value_error_listing_allowed_names(vault: Tuple[Path, Path]) -> None:
    with pytest.raises(ValueError) as info:
        manager.ArsenalManager().set_api_key("FOO", "bar")
    assert "HUNTER_API_KEY" in str(info.value)


def test_companies_house_alias_is_accepted_and_stored_under_the_canonical_name(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    manager.ArsenalManager().set_api_key("companies_house_api_key", "chkey")
    text = primary.read_text(encoding="utf-8")
    assert "UK_COMPANIES_HOUSE_API_KEY=chkey" in text
    assert not re.search(r"^COMPANIES_HOUSE_API_KEY=", text, flags=re.MULTILINE)
    assert os.environ["UK_COMPANIES_HOUSE_API_KEY"] == "chkey"


def test_alias_exported_in_the_shell_counts_as_configured(vault: Tuple[Path, Path]) -> None:
    os.environ["COMPANIES_HOUSE_API_KEY"] = "shell-ch-key"
    status = {s["key"]: s for s in manager.ArsenalManager().get_api_keys_status()}
    assert status["UK_COMPANIES_HOUSE_API_KEY"]["configured"] is True
    assert status["UK_COMPANIES_HOUSE_API_KEY"]["source"] == "shell"


@pytest.mark.parametrize(
    "name", ["OPENSANCTIONS_API_URL", "OPENSANCTIONS_API_KEY", "COURTLISTENER_API_TOKEN", "UK_COMPANIES_HOUSE_API_KEY"]
)
def test_env_vars_the_code_reads_are_in_the_catalog(name: str) -> None:
    assert name in manager.ALLOWED_KEY_NAMES


def test_newline_in_value_is_rejected(vault: Tuple[Path, Path]) -> None:
    with pytest.raises(ValueError):
        manager.ArsenalManager().set_api_key("HUNTER_API_KEY", "a\nPATH=/evil")


# ------------------------------------------------------------------------------------ reserved honesty

RESERVED = {
    "HAVEIBEENPWNED_API_KEY",
    "INTELX_API_KEY",
    "BREACHDIRECTORY_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "IPINFO_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "FEC_API_KEY",
    "OPENCORPORATES_API_KEY",
    "ETHERSCAN_API_KEY",
    "HELIUS_API_KEY",
    "HUDSONROCK_API_KEY",
    "SHODAN_API_KEY",
}


def test_reserved_keys_are_marked_and_kept() -> None:
    assert RESERVED <= manager.ALLOWED_KEY_NAMES
    assert manager.RESERVED_KEY_NAMES == RESERVED


def test_reserved_keys_are_really_unread_by_the_package() -> None:
    sources = [p for p in (REPO_ROOT / "bunnyhole").rglob("*.py") if p.name != "manager.py"]
    blob = "\n".join(p.read_text(encoding="utf-8") for p in sources)
    for name in RESERVED:
        read = re.search(rf"(environ\.get\(|getenv\(|environ\[)\s*[\"']{name}[\"']", blob)
        assert read is None, f"{name} is now read by the package: drop its reserved status"


def test_status_rows_carry_the_reserved_flag(vault: Tuple[Path, Path]) -> None:
    rows = {s["key"]: s for s in manager.ArsenalManager().get_api_keys_status()}
    assert rows["FEC_API_KEY"]["reserved"] is True
    assert rows["HUNTER_API_KEY"]["reserved"] is False


# ------------------------------------------------------------------------------------------------- CLI


def test_keys_set_unknown_name_exits_2_with_allowed_names_and_no_traceback(vault: Tuple[Path, Path]) -> None:
    for arg in ("FOO=bar", "=x"):
        res = runner.invoke(cli_main.app, ["keys", "--set", arg])
        assert res.exit_code == 2, res.output
        assert "HUNTER_API_KEY" in res.output
        assert "Traceback" not in res.output
        assert res.exception is None or isinstance(res.exception, SystemExit)


def test_keys_set_without_equals_exits_2(vault: Tuple[Path, Path]) -> None:
    res = runner.invoke(cli_main.app, ["keys", "--set", "HUNTER_API_KEY"])
    assert res.exit_code == 2


def test_keys_set_and_clear_messages(vault: Tuple[Path, Path]) -> None:
    primary, legacy = vault
    res = runner.invoke(cli_main.app, ["keys", "--set", "HUNTER_API_KEY=abc12345678"])
    assert res.exit_code == 0, res.output
    assert "Saved HUNTER_API_KEY" in res.output
    assert str(legacy) not in res.output.split("Saved", 1)[1].splitlines()[0]
    res = runner.invoke(cli_main.app, ["keys", "--set", "HUNTER_API_KEY="])
    assert res.exit_code == 0, res.output
    assert "Cleared HUNTER_API_KEY" in res.output
    assert "Saved" not in res.output


def test_keys_table_shows_source_and_reserved(vault: Tuple[Path, Path]) -> None:
    primary, _ = vault
    _write(primary, "GITHUB_API_KEY=ghp_abcdefghijk\n")
    os.environ["HUNTER_API_KEY"] = "shell-hunter-123"
    res = runner.invoke(cli_main.app, ["keys"])
    assert res.exit_code == 0, res.output
    assert "SET (vault)" in res.output
    assert "SET (shell)" in res.output
    assert "reserved: not used by any agent yet" in res.output


def test_keys_set_reports_shell_shadowing(vault: Tuple[Path, Path]) -> None:
    os.environ["HUNTER_API_KEY"] = "from-shell"
    res = runner.invoke(cli_main.app, ["keys", "--set", "HUNTER_API_KEY=from-set"])
    assert res.exit_code == 0
    assert "shell" in res.output.lower()


def test_menu_option_4_unknown_key_returns_to_prompt(vault: Tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["4", "FOO", "0"])
    from rich import prompt as rich_prompt

    monkeypatch.setattr(rich_prompt.Prompt, "ask", classmethod(lambda cls, *a, **k: next(answers)))
    res = runner.invoke(cli_main.app, ["menu"])
    assert res.exit_code == 0, res.output
    assert "Traceback" not in res.output
    assert "HUNTER_API_KEY" in res.output


# ------------------------------------------------------------------------------------------ .env.example


def test_env_example_lists_every_accepted_key_and_is_honest_about_loading() -> None:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    for name in ALL_NAMES:
        assert re.search(rf"^#?\s*{name}=", text, flags=re.MULTILINE), f"{name} missing from .env.example"
    for name in ("BUNNYHOLE_HOME", "BUNNYHOLE_PROXY", "BUNNYHOLE_TOR_PROXY", "BUNNYHOLE_API_TOKEN"):
        assert name in text
    assert "NOT loaded automatically" in text
    assert "bunnyhole keys --set" in text


def test_env_example_documents_every_bunnyhole_env_var_the_package_reads() -> None:
    blob = "\n".join(p.read_text(encoding="utf-8") for p in (REPO_ROOT / "bunnyhole").rglob("*.py"))
    read = set(re.findall(r"[\"'](BUNNYHOLE_[A-Z0-9_]*[A-Z0-9])[\"']", blob))
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    missing = sorted(name for name in read if name not in text)
    assert missing == [], f"document these env vars in .env.example: {missing}"
