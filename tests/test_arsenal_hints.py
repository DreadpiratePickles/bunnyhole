"""Arsenal install hints are honest and identical to what the installer runs; nothing here runs an installer.

Platform data and PATH lookups are monkeypatched; ``subprocess.run`` is replaced by a recorder, so the tests are
hermetic and never install anything.
"""

from __future__ import annotations

import shlex
import sys
from typing import Any, Dict, List, Optional, Set

import pytest
from rich.console import Console
from typer.testing import CliRunner

from bunnyhole.arsenal import manager
from bunnyhole.cli import main as cli_main

runner = CliRunner()

PLATFORMS: Dict[str, Dict[str, str]] = {
    "macos": {"os": "macos", "distro": "macos", "display_name": "macOS (15.0) [arm64]", "pkg_manager": "brew"},
    "kali": {"os": "linux", "distro": "kali", "display_name": "Kali Linux [x86_64]", "pkg_manager": "apt"},
    "debian": {"os": "linux", "distro": "debian", "display_name": "Debian/Ubuntu Linux [x86_64]", "pkg_manager": "apt"},
    "arch": {"os": "linux", "distro": "arch", "display_name": "Arch Linux [x86_64]", "pkg_manager": "pacman"},
    "fedora": {"os": "linux", "distro": "fedora", "display_name": "Fedora/RHEL Linux [x86_64]", "pkg_manager": "dnf"},
    "unknown": {"os": "freebsd", "distro": "unknown", "display_name": "freebsd [amd64]", "pkg_manager": "pipx"},
}
ALL_BINS = {"uv", "pipx", "brew", "go", "sudo", "apt-get", "pacman", "dnf"}


class Recorder:
    def __init__(self, succeed: bool = False) -> None:
        self.calls: List[List[str]] = []
        self.succeed = succeed

    def __call__(self, argv: Any, *args: Any, **kwargs: Any) -> Any:
        assert isinstance(argv, list), "installers must run with an argv list, never a shell string"
        assert not kwargs.get("shell"), "installers must not use a shell"
        self.calls.append(list(argv))

        class _Res:
            returncode = 0 if self.succeed else 1
            stdout = "ok" if self.succeed else ""
            stderr = "" if self.succeed else "simulated failure"

        return _Res()


def _manager(
    monkeypatch: pytest.MonkeyPatch, platform_key: str, bins: Set[str], recorder: Optional[Recorder] = None
) -> manager.ArsenalManager:
    monkeypatch.setattr(manager, "OSINT_TOOLS_GIT_DIR", manager.BUNNYHOLE_CONFIG_DIR / "no-such-osint-tools")
    monkeypatch.setattr(manager, "LEGACY_OSINT_ENV_FILE", manager.BUNNYHOLE_CONFIG_DIR / "no-such-legacy.env")
    monkeypatch.setattr(manager, "detect_platform_profile", lambda: dict(PLATFORMS[platform_key]))
    monkeypatch.setattr(manager.shutil, "which", lambda name, *a, **k: f"/fake/bin/{name}" if name in bins else None)
    monkeypatch.setattr(manager.subprocess, "run", recorder or Recorder())
    return manager.ArsenalManager()


@pytest.mark.parametrize("platform_key", sorted(PLATFORMS))
@pytest.mark.parametrize(
    "bins",
    [ALL_BINS, {"uv"}, set(), {"go", "brew"}, {"pipx", "sudo", "apt-get"}],
    ids=["all", "uv", "none", "go+brew", "pipx+apt"],
)
def test_hint_is_exactly_what_the_installer_runs(
    monkeypatch: pytest.MonkeyPatch, platform_key: str, bins: Set[str]
) -> None:
    rec = Recorder(succeed=False)
    mgr = _manager(monkeypatch, platform_key, bins, rec)
    for tool in manager.ARSENAL_TOOLS_CATALOG:
        rec.calls.clear()
        hint = mgr.get_install_command_for_tool(tool)
        res = mgr.install_tool(tool["name"])
        assert res["success"] is False
        if rec.calls:
            assert hint == " || ".join(shlex.join(c) for c in rec.calls), tool["name"]
        else:
            assert hint.lower().startswith(("install manually", "not available")), (tool["name"], hint)
            assert res["error"] == hint


@pytest.mark.parametrize("platform_key", sorted(PLATFORMS))
def test_no_invented_pip_package_names(monkeypatch: pytest.MonkeyPatch, platform_key: str) -> None:
    mgr = _manager(monkeypatch, platform_key, ALL_BINS)
    for row in mgr.check_arsenal_status():
        hint = row["install_hint"]
        assert not hint.startswith("pip install"), (row["name"], hint)
        if row["type"] == "sys_cli":
            assert "pip install" not in hint, (row["name"], hint)


def test_anonsurf_on_macos_is_honestly_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = _manager(monkeypatch, "macos", ALL_BINS)
    tool = next(t for t in manager.ARSENAL_TOOLS_CATALOG if t["name"] == "anonsurf")
    hint = mgr.get_install_command_for_tool(tool)
    assert hint.startswith("not available on macos")


def test_go_tool_without_go_says_install_manually(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = _manager(monkeypatch, "macos", {"uv"})
    tool = next(t for t in manager.ARSENAL_TOOLS_CATALOG if t["name"] == "waybackurls")
    hint = mgr.get_install_command_for_tool(tool)
    assert hint.startswith("install manually")
    assert "go install github.com/tomnomnom/waybackurls@latest" in hint


@pytest.mark.parametrize(
    ("platform_key", "tool", "expected"),
    [
        ("arch", "nmap", "sudo -n pacman -S --noconfirm nmap"),
        ("arch", "dig", "sudo -n pacman -S --noconfirm bind"),
        ("fedora", "exiftool", "sudo -n dnf install -y perl-Image-ExifTool"),
        ("fedora", "dig", "sudo -n dnf install -y bind-utils"),
        ("kali", "exiftool", "sudo -n apt-get install -y libimage-exiftool-perl"),
        ("macos", "dig", "brew install bind"),
    ],
)
def test_native_package_manager_hints(
    monkeypatch: pytest.MonkeyPatch, platform_key: str, tool: str, expected: str
) -> None:
    mgr = _manager(monkeypatch, platform_key, ALL_BINS)
    entry = next(t for t in manager.ARSENAL_TOOLS_CATALOG if t["name"] == tool)
    assert mgr.get_install_command_for_tool(entry) == expected


def test_python_lib_installs_into_the_active_env_with_uv(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = Recorder(succeed=True)
    mgr = _manager(monkeypatch, "macos", {"uv"}, rec)
    res = mgr.install_tool("scrapling")
    assert res["success"] is True
    assert rec.calls == [["uv", "pip", "install", "--python", sys.executable, "scrapling"]]


def test_install_all_covers_python_libs(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = _manager(monkeypatch, "macos", {"uv"})
    tool = next(t for t in manager.ARSENAL_TOOLS_CATALOG if t["type"] == "python_lib")
    assert "No compatible installer" not in mgr.get_install_command_for_tool(tool)
    assert mgr.get_install_command_for_tool(tool).startswith("uv pip install")


def test_httpx_alias_resolves_to_the_projectdiscovery_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = Recorder(succeed=True)
    mgr = _manager(monkeypatch, "macos", {"brew"}, rec)
    res = mgr.install_tool("httpx")
    assert res["success"] is True
    assert rec.calls == [["brew", "install", "httpx"]]
    assert res["tool"] == "httpx-pd"


def test_unknown_tool_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = _manager(monkeypatch, "macos", ALL_BINS)
    res = mgr.install_tool("nonexistent")
    assert res["success"] is False
    assert "Unknown tool" in res["error"]


def test_ghunt_description_typo_fixed() -> None:
    ghunt = next(t for t in manager.ARSENAL_TOOLS_CATALOG if t["name"] == "ghunt")
    assert "OSINTrecon" not in ghunt["desc"]


def test_anonsurf_missing_binary_message_names_the_real_subcommand(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manager.platform, "system", lambda: "Linux")
    monkeypatch.setattr(manager.shutil, "which", lambda name, *a, **k: None)
    ctl = manager.AnonsurfController()
    for res in (ctl.status(), ctl.start()):
        assert "bunnyhole anonsurf install" in res["error"]
        assert "--install" not in res["error"]


# ------------------------------------------------------------------------------------------------- CLI


@pytest.fixture
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "console", Console(width=400))


def test_cli_install_unknown_tool_exits_1(monkeypatch: pytest.MonkeyPatch, wide_console: None) -> None:
    _manager(monkeypatch, "macos", ALL_BINS)
    res = runner.invoke(cli_main.app, ["arsenal", "--install", "nonexistent"])
    assert res.exit_code == 1, res.output
    assert "Unknown tool" in res.output


def test_cli_failed_install_exits_1(monkeypatch: pytest.MonkeyPatch, wide_console: None) -> None:
    _manager(monkeypatch, "macos", ALL_BINS, Recorder(succeed=False))
    res = runner.invoke(cli_main.app, ["doctor", "--install", "sherlock"])
    assert res.exit_code == 1, res.output


def test_cli_doctor_shows_platform_brackets_and_full_hints(monkeypatch: pytest.MonkeyPatch, wide_console: None) -> None:
    _manager(monkeypatch, "macos", {"go"})
    monkeypatch.setattr(manager.importlib.util, "find_spec", lambda name, *a, **k: None)
    res = runner.invoke(cli_main.app, ["doctor"])
    assert res.exit_code == 0, res.output
    assert "[arm64]" in res.output
    assert "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" in res.output
