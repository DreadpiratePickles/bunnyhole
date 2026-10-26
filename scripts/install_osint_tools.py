#!/usr/bin/env python3
"""
Bunnyhole & OSINT Arsenal Cross-Platform Installer v3.0
Supports:
  - Kali Linux (apt + pipx/uv + go)
  - Parrot Security OS (apt + pipx/uv + go)
  - Debian / Ubuntu Linux (apt + pipx/uv + go)
  - Arch / BlackArch / Manjaro Linux (pacman + pipx/uv + go)
  - Fedora / RHEL (dnf + pipx/uv + go)
  - macOS (Homebrew + uv/pipx + go, no root required)

Usage:
  python3 scripts/install_osint_tools.py --check          # Non-destructive health check & API vault setup
  sudo python3 scripts/install_osint_tools.py             # Full install on Linux (Kali/Parrot/Debian/Arch/Fedora)
  python3 scripts/install_osint_tools.py                  # Full install on macOS (Homebrew + uv/pipx)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


def run_cmd(cmd: str, shell: bool = True, check: bool = False):
    """Run a shell command and return output."""
    print(f"{BLUE}[RUN]{RESET} {cmd}")
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, check=check)
        if result.returncode != 0 and result.stderr:
            print(f"{YELLOW}[WARN]{RESET} {result.stderr.strip()[:240]}")
        return result
    except Exception as exc:
        print(f"{RED}[ERROR]{RESET} {exc}")
        return None


def detect_distro() -> str:
    """Detect Linux distribution (kali, parrot, debian, arch, fedora) or macOS."""
    if platform.system().lower() == "darwin":
        return "macos"
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", encoding="utf-8", errors="ignore") as f:
            content = f.read().lower()
            if "kali" in content:
                return "kali"
            if "parrot" in content:
                return "parrot"
            if "ubuntu" in content or "debian" in content:
                return "debian"
            if "arch" in content or "blackarch" in content or "manjaro" in content:
                return "arch"
            if "fedora" in content or "rhel" in content or "centos" in content:
                return "fedora"
    return "unknown"


def install_system_deps(distro: str) -> None:
    """Install system-level dependencies across Debian/Kali/Parrot, Arch, Fedora, and macOS."""
    print(f"\n{GREEN}=== Installing System Dependencies ({distro}) ==={RESET}")

    if distro == "macos":
        if not shutil.which("brew"):
            print(f"{YELLOW}[WARN]{RESET} Homebrew not found on macOS. Skipping brew system packages.")
            return
        brew_deps = ["git", "python", "curl", "wget", "whois", "bind", "jq", "tor", "node", "go", "exiftool", "pipx"]
        run_cmd(f"brew install {' '.join(brew_deps)}", check=False)
        return

    linux_deps = [
        "git", "python3", "python3-pip", "python3-venv", "curl", "wget",
        "whois", "dnsutils", "jq", "tor", "nodejs", "npm", "golang-go",
        "libxml2-dev", "libxslt1-dev", "zlib1g-dev", "libffi-dev", "libssl-dev",
    ]

    if distro in ["debian", "kali", "parrot"]:
        run_cmd("apt-get update -y", check=False)
        run_cmd(f"apt-get install -y {' '.join(linux_deps)} pipx libimage-exiftool-perl", check=False)
    elif distro == "arch":
        arch_deps = [
            "git", "python", "python-pip", "python-pipx", "curl", "wget",
            "whois", "bind", "jq", "tor", "nodejs", "npm", "go", "perl-image-exiftool",
        ]
        run_cmd("pacman -Syu --noconfirm", check=False)
        run_cmd(f"pacman -S --noconfirm {' '.join(arch_deps)}", check=False)
    elif distro == "fedora":
        run_cmd("dnf install -y git python3 python3-pip pipx curl wget whois bind-utils jq tor nodejs npm golang perl-Image-ExifTool", check=False)

    print(f"{GREEN}[OK]{RESET} System dependencies installed.")


def install_pipx_tools() -> None:
    """Install isolated Python OSINT CLI tools via uv tool or pipx."""
    print(f"\n{GREEN}=== Installing Python OSINT CLI Tools (uv / pipx) ==={RESET}")

    pipx_tools = [
        "sherlock-project",      # Username search across 400+ sites
        "maigret",               # Deep username investigation (2500+ sites)
        "holehe",                # Email-to-registered-accounts
        "user-scanner",          # Email + username scanner
        "theHarvester",          # Email/subdomain harvester
        "waybackpy",             # Wayback Machine interface
        "exifread",              # EXIF metadata reader
        "dnstwist",              # Domain lookalike / typo-squatting detection
        "sublist3r",             # Subdomain enumeration
        "h8mail",                # Breach email hunting
        "ignorant",              # Phone number registration check
        "ghunt",                 # Google account OSINT
    ]

    runner = "uv tool install" if shutil.which("uv") else "pipx install"
    for tool in pipx_tools:
        print(f"{BLUE}[INSTALL]{RESET} {tool} (via {runner})")
        run_cmd(f"{runner} {tool}", check=False)

    print(f"{GREEN}[OK]{RESET} Python OSINT CLI tools installed.")


def install_distro_osint_packages(distro: str) -> None:
    """Install OSINT tools directly packaged in Kali, Parrot, Debian, Arch, Fedora, or Homebrew."""
    print(f"\n{GREEN}=== Installing Native Package Manager OSINT Tools ({distro}) ==={RESET}")

    if distro in ["debian", "kali", "parrot"]:
        pkg_tools = [
            "sherlock", "theharvester", "recon-ng", "amass",
            "sublist3r", "dnsrecon", "fierce", "whois", "dnsutils", "libimage-exiftool-perl",
        ]
        run_cmd(f"apt-get install -y {' '.join(pkg_tools)}", check=False)
    elif distro == "arch":
        pkg_tools = ["whois", "bind", "perl-image-exiftool"]
        run_cmd(f"pacman -S --noconfirm {' '.join(pkg_tools)}", check=False)
    elif distro == "macos" and shutil.which("brew"):
        pkg_tools = ["sherlock", "theharvester", "dnstwist", "subfinder", "amass", "httpx", "whois", "exiftool"]
        run_cmd(f"brew install {' '.join(pkg_tools)}", check=False)

    print(f"{GREEN}[OK]{RESET} Package manager OSINT tools installed.")


def install_go_tools() -> None:
    """Install Go-based passive discovery & archive OSINT tools."""
    if not shutil.which("go"):
        print(f"{YELLOW}[SKIP]{RESET} Go compiler not found on PATH; skipping go install step.")
        return

    print(f"\n{GREEN}=== Installing Go-based OSINT Tools ==={RESET}")
    go_tools = [
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/tomnomnom/assetfinder@latest",
        "github.com/tomnomnom/waybackurls@latest",
        "github.com/tomnomnom/anew@latest",
        "github.com/lc/gau/v2/cmd/gau@latest",
    ]
    for tool in go_tools:
        print(f"{BLUE}[GO]{RESET} {tool}")
        run_cmd(f"go install {tool}", check=False)

    print(f"{GREEN}[OK]{RESET} Go OSINT tools installed.")


def setup_api_keys() -> None:
    """Ensure API key vaults exist at both ~/.bunnyhole/api_keys.env and ~/.osint-apis/api_keys.env."""
    print(f"\n{GREEN}=== Setting Up Unified API Keys Vault ==={RESET}")
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))
    try:
        from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager
        mgr = ArsenalManager()
        if not BUNNYHOLE_ENV_FILE.exists():
            mgr.set_api_key("FEC_API_KEY", "DEMO_KEY")
        print(f"{GREEN}[OK]{RESET} Unified API vault ready at:")
        print(f"  • {BUNNYHOLE_ENV_FILE}")
        print(f"  • {LEGACY_OSINT_ENV_FILE}")
    except Exception as exc:
        print(f"{YELLOW}[WARN]{RESET} Fallback API template setup: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bunnyhole Cross-Platform OSINT Arsenal Installer")
    parser.add_argument("--check", action="store_true", help="Only run non-destructive system & tool health check")
    args = parser.parse_args()

    distro = detect_distro()
    print(f"{CYAN}╔══════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║       🐇🕳️ BUNNYHOLE CROSS-PLATFORM OSINT ARSENAL INSTALLER       ║{RESET}")
    print(f"{CYAN}║   Supports: Kali • Parrot OS • Debian • Arch • Fedora • macOS   ║{RESET}")
    print(f"{CYAN}╚══════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"{BLUE}[INFO]{RESET} Detected Platform: {distro.upper()}")

    if args.check:
        # Keep --check genuinely non-destructive: report tool health without creating the vault.
        project_root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(project_root))
        from bunnyhole.arsenal.manager import ArsenalManager
        mgr = ArsenalManager()
        tools = mgr.check_arsenal_status()
        installed = sum(1 for t in tools if t["installed"])
        print(f"{GREEN}[HEALTH]{RESET} {installed}/{len(tools)} Arsenal tools currently available on this machine.")
        for t in tools:
            badge = f"{GREEN}✔{RESET}" if t["installed"] else f"{YELLOW}○{RESET}"
            print(f"  {badge} {t['name']:<16} ({t['location']})")
        return

    setup_api_keys()

    # os.geteuid() does not exist on Windows; guard it so the installer degrades gracefully there.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if distro != "macos" and not is_root:
        print(f"{YELLOW}[NOTE]{RESET} Running without root on Linux: skipping apt/pacman/dnf system packages and installing user-space tools via uv/pipx/go.")
    else:
        install_system_deps(distro)
        install_distro_osint_packages(distro)

    install_pipx_tools()
    install_go_tools()
    print(f"\n{GREEN}✔ Bunnyhole Arsenal setup complete! Run 'bunnyhole doctor' or 'bunnyhole tui' to manage tools & API keys.{RESET}")


if __name__ == "__main__":
    main()
