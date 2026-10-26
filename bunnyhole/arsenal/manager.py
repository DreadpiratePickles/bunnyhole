"""Cross-Platform OSINT Arsenal Installer, Health Doctor & API Key Vault Manager for Kali Linux, Parrot OS, and macOS."""

from __future__ import annotations

import importlib.util
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

BUNNYHOLE_CONFIG_DIR = Path.home() / ".bunnyhole"
BUNNYHOLE_ENV_FILE = BUNNYHOLE_CONFIG_DIR / "api_keys.env"
LEGACY_OSINT_ENV_FILE = Path.home() / ".osint-apis" / "api_keys.env"
OSINT_TOOLS_GIT_DIR = Path.home() / "osint-tools"

# Comprehensive API Keys Registry across all Bunnyhole Pillars (Breach, Infra, Identity, Fiat, On-Chain, AI)
API_KEYS_REGISTRY: List[Dict[str, str]] = [
    # Breach & Leak Databases
    {"key": "HAVEIBEENPWNED_API_KEY", "category": "Breach & Leaks", "url": "https://haveibeenpwned.com/API/Key", "note": "Account breach lookup ($4.39/mo)"},
    {"key": "LEAKCHECK_API_KEY", "category": "Breach & Leaks", "url": "https://leakcheck.io/", "note": "Free tier available"},
    {"key": "INTELX_API_KEY", "category": "Breach & Leaks", "url": "https://intelx.io/", "note": "Free tier: 3 searches/day"},
    {"key": "HUDSONROCK_API_KEY", "category": "Breach & Leaks", "url": "https://www.hudsonrock.com/free-api-key", "note": "Optional (Cavalier OSINT works keyless)"},
    {"key": "BREACHDIRECTORY_API_KEY", "category": "Breach & Leaks", "url": "https://breachdirectory.com/api_documentation", "note": "Free tier"},
    # Infrastructure & Network
    {"key": "SHODAN_API_KEY", "category": "Infrastructure & Recon", "url": "https://account.shodan.io/", "note": "Free 100 credits/mo (InternetDB works keyless)"},
    {"key": "CENSYS_API_ID", "category": "Infrastructure & Recon", "url": "https://search.censys.io/", "note": "Free 250 queries/mo"},
    {"key": "CENSYS_API_SECRET", "category": "Infrastructure & Recon", "url": "https://search.censys.io/", "note": "Paired with CENSYS_API_ID"},
    {"key": "SECURITYTRAILS_API_KEY", "category": "Infrastructure & Recon", "url": "https://securitytrails.com/", "note": "Historical DNS & subdomains (50/mo free)"},
    {"key": "VIRUSTOTAL_API_KEY", "category": "Infrastructure & Recon", "url": "https://www.virustotal.com/gui/my-apikey", "note": "Free: 500 req/day (Domains, IPs, Hashes)"},
    {"key": "URLSCAN_API_KEY", "category": "Infrastructure & Recon", "url": "https://urlscan.io/", "note": "Free tier (Public search works keyless)"},
    {"key": "ABUSEIPDB_API_KEY", "category": "Infrastructure & Recon", "url": "https://www.abuseipdb.com/", "note": "Free: 1,000 IP checks/day"},
    {"key": "ALIENVAULT_OTX_API_KEY", "category": "Infrastructure & Recon", "url": "https://otx.alienvault.com/", "note": "Free Threat Intel indicators"},
    # Social, Identity & Email
    {"key": "GITHUB_API_KEY", "category": "Social & Identity", "url": "https://github.com/settings/tokens", "note": "Raises GitHub rate limit from 60 -> 5,000 req/hr"},
    {"key": "HUNTER_API_KEY", "category": "Social & Identity", "url": "https://hunter.io/", "note": "Free: 25-50 domain email searches/mo"},
    {"key": "EMAILREP_API_KEY", "category": "Social & Identity", "url": "https://emailrep.io/", "note": "Email reputation & social profile correlation"},
    {"key": "IPINFO_TOKEN", "category": "Social & Identity", "url": "https://ipinfo.io/", "note": "Free: 50,000 IP geolocation/ASN lookups/mo"},
    {"key": "NUMVERIFY_API_KEY", "category": "Social & Identity", "url": "https://numverify.com/", "note": "Phone carrier & line-type validation"},
    {"key": "TELEGRAM_BOT_TOKEN", "category": "Social & Identity", "url": "https://t.me/BotFather", "note": "Optional Telegram channel/fwd_from recon"},
    # Corporate, Fiat & On-Chain
    {"key": "FEC_API_KEY", "category": "Corporate & Fiat", "url": "https://api.open.fec.gov/developers/", "note": "Free instant key (DEMO_KEY used by default)"},
    {"key": "OPENCORPORATES_API_KEY", "category": "Corporate & Fiat", "url": "https://opencorporates.com/", "note": "Global company registry search"},
    {"key": "UK_COMPANIES_HOUSE_API_KEY", "category": "Corporate & Fiat", "url": "https://developer.company-information.service.gov.uk/", "note": "Free UK PSC beneficial owner lookup"},
    {"key": "ETHERSCAN_API_KEY", "category": "On-Chain Crypto", "url": "https://etherscan.io/apis", "note": "Free 5 calls/sec (Blockscout v2 works keyless)"},
    {"key": "HELIUS_API_KEY", "category": "On-Chain Crypto", "url": "https://www.helius.dev/", "note": "Free Solana deep RPC & Jito bundle history"},
    # AI & Deep Research Synthesis + Karpathy llm-council
    {"key": "OPENROUTER_API_KEY", "category": "AI Synthesis", "url": "https://openrouter.ai/keys", "note": "Powers Karpathy 3-Stage LLM Council (GPT-4o, Claude, Gemini, Grok, DeepSeek)"},
    {"key": "OPENAI_API_KEY", "category": "AI Synthesis", "url": "https://platform.openai.com/", "note": "Optional LLM synthesis"},
    {"key": "ANTHROPIC_API_KEY", "category": "AI Synthesis", "url": "https://console.anthropic.com/", "note": "Optional Claude synthesis"},
    {"key": "GEMINI_API_KEY", "category": "AI Synthesis", "url": "https://aistudio.google.com/", "note": "Optional Gemini synthesis"},
]

# Allow-list of persistable/loadable key names, derived from the registry. Any name not in this
# set is rejected, so a caller can never inject process-controlling variables (PATH, LD_PRELOAD,
# PYTHONPATH, HTTPS_PROXY, ...) into the vault file or os.environ via set_api_key / the API.
ALLOWED_KEY_NAMES: frozenset[str] = frozenset(item["key"] for item in API_KEYS_REGISTRY)

# A legal environment variable name, as a second-layer guard.
_VALID_KEY_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _strip_inline_comment(raw_value: str) -> str:
    """Strip a trailing ' # ...' vault comment without truncating a value that itself contains '#'."""
    # The vault writer appends comments as ' # <url> (<note>)' (space before #). Only split on that
    # delimiter so a token like 'abc#def' survives intact.
    cut = raw_value.split(" #", 1)[0]
    return cut.strip().strip('"').strip("'")


def _secure_write(path: Path, content: str) -> None:
    """Atomically write a secret file with 0600 permissions inside a 0700 parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=".env")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


# Catalog of OSINT, Red-Team, Financial & Forensics Tools across Kali Linux, Parrot OS, and macOS
ARSENAL_TOOLS_CATALOG: List[Dict[str, Any]] = [
    # Core Python Libraries (Built into Bunnyhole venv)
    {"name": "scrapling", "type": "python_lib", "module": "scrapling", "pkg": "scrapling", "desc": "Adaptive stealth scraper & Cloudflare Turnstile bypass"},
    {"name": "trafilatura", "type": "python_lib", "module": "trafilatura", "pkg": "trafilatura", "desc": "Journalistic article & metadata extractor"},
    {"name": "edgartools", "type": "python_lib", "module": "edgar", "pkg": "edgartools", "desc": "SEC EDGAR XBRL, Form D, Form 4, 10-K forensic parser"},
    {"name": "waybackpy", "type": "python_lib", "module": "waybackpy", "pkg": "waybackpy", "desc": "Internet Archive CDX & Save API client"},
    {"name": "socid-extractor", "type": "python_lib", "module": "socid_extractor", "pkg": "socid-extractor", "desc": "Maigret profile metadata & UID parser"},
    {"name": "holehe", "type": "cli_or_py", "binary": "holehe", "module": "holehe", "pipx": "holehe", "desc": "Non-alerting email account registration check (120+ sites)"},
    # Identity & Username CLI Tools
    {"name": "sherlock", "type": "cli", "binary": "sherlock", "pipx": "sherlock-project", "apt": "sherlock", "brew": "sherlock", "desc": "Username hunt across 400+ social platforms"},
    {"name": "maigret", "type": "cli", "binary": "maigret", "pipx": "maigret", "desc": "Deep username dossier builder across 2,500+ sites"},
    {"name": "ignorant", "type": "cli", "binary": "ignorant", "pipx": "ignorant", "desc": "Phone number account registration check (Snapchat, Instagram, Amazon)"},
    {"name": "h8mail", "type": "cli", "binary": "h8mail", "pipx": "h8mail", "desc": "Email breach hunting & credential correlation"},
    {"name": "ghunt", "type": "cli", "binary": "ghunt", "pipx": "ghunt", "desc": "Google account OSINTrecon"},
    # Domain, DNS & Network Recon Tools
    {"name": "theHarvester", "type": "cli", "binary": "theHarvester", "pipx": "theHarvester", "apt": "theharvester", "brew": "theharvester", "desc": "Email, subdomain, and employee name harvester"},
    {"name": "dnstwist", "type": "cli", "binary": "dnstwist", "pipx": "dnstwist", "apt": "dnstwist", "brew": "dnstwist", "desc": "Domain lookalike & typosquatting permutation scanner"},
    {"name": "subfinder", "type": "go_cli", "binary": "subfinder", "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "apt": "subfinder", "brew": "subfinder", "desc": "Fast passive subdomain discovery (ProjectDiscovery)"},
    {"name": "amass", "type": "go_cli", "binary": "amass", "go_pkg": "github.com/owasp-amass/amass/v4/...@master", "apt": "amass", "brew": "amass", "desc": "In-depth attack surface mapping & ASN discovery"},
    {"name": "httpx-pd", "type": "go_cli", "binary": "httpx", "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest", "apt": "httpx-toolkit", "brew": "httpx", "desc": "Fast HTTP probing, tech stack & TLS fingerprinter"},
    {"name": "nuclei", "type": "go_cli", "binary": "nuclei", "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "apt": "nuclei", "brew": "nuclei", "desc": "Template-based vulnerability & misconfiguration scanner"},
    {"name": "waybackurls", "type": "go_cli", "binary": "waybackurls", "go_pkg": "github.com/tomnomnom/waybackurls@latest", "desc": "Fetch all historical URLs known to the Wayback Machine"},
    {"name": "gau", "type": "go_cli", "binary": "gau", "go_pkg": "github.com/lc/gau/v2/cmd/gau@latest", "desc": "GetAllUrls from AlienVault OTX, Wayback, and CommonCrawl"},
    # System Utilities (Pre-installed or via apt/brew on Kali, Parrot, macOS)
    {"name": "whois", "type": "sys_cli", "binary": "whois", "apt": "whois", "brew": "whois", "desc": "Domain & IP registration WHOIS client"},
    {"name": "dig", "type": "sys_cli", "binary": "dig", "apt": "dnsutils", "brew": "bind", "desc": "DNS record interrogation utility"},
    {"name": "nmap", "type": "sys_cli", "binary": "nmap", "apt": "nmap", "brew": "nmap", "desc": "Network exploration and service/port scanner"},
    {"name": "exiftool", "type": "sys_cli", "binary": "exiftool", "apt": "libimage-exiftool-perl", "brew": "exiftool", "desc": "Read/write meta information in PDF, image, and media files"},
    {"name": "tor", "type": "sys_cli", "binary": "tor", "apt": "tor", "brew": "tor", "desc": "Anonymity onion routing daemon for dark-web OSINT"},
]


def detect_platform_profile() -> Dict[str, str]:
    """
    Detect exact OS platform:
    - 'kali' (Kali Linux)
    - 'parrot' (Parrot Security OS)
    - 'macos' (Darwin / macOS with Homebrew)
    - 'debian' (Debian / Ubuntu)
    - 'arch' (Arch / BlackArch)
    - 'fedora' (Fedora / RHEL)
    """
    sys_name = platform.system().lower()
    machine = platform.machine()
    if sys_name == "darwin":
        has_brew = shutil.which("brew") is not None
        return {
            "os": "macos",
            "distro": "macos",
            "display_name": f"macOS ({platform.mac_ver()[0]}) [{machine}]",
            "pkg_manager": "brew" if has_brew else "uv/pipx",
        }

    if os.path.exists("/etc/os-release"):
        try:
            content = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").lower()
            if "kali" in content:
                return {"os": "linux", "distro": "kali", "display_name": f"Kali Linux [{machine}]", "pkg_manager": "apt"}
            if "parrot" in content:
                return {"os": "linux", "distro": "parrot", "display_name": f"Parrot Security OS [{machine}]", "pkg_manager": "apt"}
            if "ubuntu" in content or "debian" in content:
                return {"os": "linux", "distro": "debian", "display_name": f"Debian/Ubuntu Linux [{machine}]", "pkg_manager": "apt"}
            if "arch" in content or "blackarch" in content or "manjaro" in content:
                return {"os": "linux", "distro": "arch", "display_name": f"Arch Linux [{machine}]", "pkg_manager": "pacman"}
            if "fedora" in content or "rhel" in content or "centos" in content:
                return {"os": "linux", "distro": "fedora", "display_name": f"Fedora/RHEL Linux [{machine}]", "pkg_manager": "dnf"}
        except Exception:
            pass

    return {"os": sys_name, "distro": "unknown", "display_name": f"{sys_name} [{machine}]", "pkg_manager": "pipx"}


class ArsenalManager:
    """Manages OSINT tool detection, cross-platform installation (Kali/Parrot/macOS), and API Key Vault."""

    def __init__(self) -> None:
        BUNNYHOLE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(BUNNYHOLE_CONFIG_DIR, 0o700)
        except OSError:
            pass
        self.platform_info = detect_platform_profile()
        self.load_api_keys_into_env()

    def load_api_keys_into_env(self) -> Dict[str, str]:
        """Load recognized API keys from the vault file(s) into os.environ.

        Only names present in ALLOWED_KEY_NAMES are loaded, so a tampered or legacy vault file can
        never inject process-controlling variables (PATH, LD_PRELOAD, PYTHONPATH, ...) into the
        environment. Unknown names are ignored rather than exported.
        """
        loaded: Dict[str, str] = {}
        for env_path in (LEGACY_OSINT_ENV_FILE, BUNNYHOLE_ENV_FILE):
            if not env_path.exists():
                continue
            try:
                raw = env_path.read_text(encoding="utf-8")
            except OSError:
                continue
            for line in raw.splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#") or "=" not in clean:
                    continue
                k, v = clean.split("=", 1)
                k = k.strip()
                v = _strip_inline_comment(v)
                if k in ALLOWED_KEY_NAMES and v:
                    os.environ[k] = v
                    loaded[k] = v
        return loaded

    def get_api_keys_status(self) -> List[Dict[str, Any]]:
        """Return all supported API keys with configured status and masked preview."""
        self.load_api_keys_into_env()
        status_list: List[Dict[str, Any]] = []
        for item in API_KEYS_REGISTRY:
            k = item["key"]
            val = os.environ.get(k, "").strip()
            masked = f"{val[:4]}...{val[-3:]}" if len(val) > 8 else ("***" if val else "")
            status_list.append({
                "key": k,
                "category": item["category"],
                "url": item["url"],
                "note": item["note"],
                "configured": bool(val),
                "masked_value": masked,
            })
        return status_list

    def set_api_key(self, key_name: str, key_value: str) -> None:
        """Persist a recognized API key into the vault file(s) with 0600 permissions.

        Raises ValueError for any name that is not a known Bunnyhole key, which prevents arbitrary
        environment-variable injection through this method and the ``POST /api/keys`` endpoint.
        """
        k = key_name.strip().upper()
        v = key_value.strip()
        if k not in ALLOWED_KEY_NAMES or not _VALID_KEY_NAME.match(k):
            raise ValueError(f"Unknown or illegal API key name: {key_name!r}")
        if "\n" in v or "\r" in v:
            raise ValueError("API key value must not contain newlines")

        if v:
            os.environ[k] = v
        elif k in os.environ:
            del os.environ[k]

        # Read only values already persisted in the vault; never fall back to the live process
        # environment, which would silently write unrelated exported secrets to disk.
        existing_map: Dict[str, str] = {}
        if BUNNYHOLE_ENV_FILE.exists():
            try:
                for line in BUNNYHOLE_ENV_FILE.read_text(encoding="utf-8").splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        ek, ev = line.split("=", 1)
                        ek = ek.strip()
                        if ek in ALLOWED_KEY_NAMES:
                            existing_map[ek] = _strip_inline_comment(ev)
            except OSError:
                pass

        existing_map[k] = v

        lines = [
            "# Bunnyhole Unified API Keys Vault (chmod 600)",
            "# Compatible with Kali Linux, Parrot OS, and macOS",
            "",
        ]
        for reg in API_KEYS_REGISTRY:
            rk = reg["key"]
            rv = existing_map.get(rk, "")
            lines.append(f"{rk}={rv:<36} # {reg['url']} ({reg['note']})")

        content = "\n".join(lines) + "\n"
        _secure_write(BUNNYHOLE_ENV_FILE, content)

        # Also sync to the legacy ~/.osint-apis/api_keys.env location with the same 0600 protection.
        try:
            _secure_write(LEGACY_OSINT_ENV_FILE, content)
        except OSError:
            pass

    def check_arsenal_status(self) -> List[Dict[str, Any]]:
        """Check which OSINT & forensic tools are currently installed on this Kali / Parrot / macOS system."""
        extra_paths = [
            str(Path.home() / ".local" / "bin"),
            str(Path.home() / "go" / "bin"),
            str(Path.home() / "bin"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
        ]
        search_path = os.pathsep.join(extra_paths + [os.environ.get("PATH", "")])

        results: List[Dict[str, Any]] = []
        for tool in ARSENAL_TOOLS_CATALOG:
            installed = False
            location = ""
            if tool.get("module"):
                spec = importlib.util.find_spec(tool["module"])
                if spec is not None:
                    installed = True
                    location = f"python:{tool['module']}"
            if not installed and tool.get("binary"):
                bin_path = shutil.which(tool["binary"], path=search_path)
                if bin_path:
                    installed = True
                    location = bin_path
                else:
                    # Check ~/osint-tools/<name>
                    git_candidate = OSINT_TOOLS_GIT_DIR / tool["name"]
                    if git_candidate.exists():
                        installed = True
                        location = str(git_candidate)

            results.append({
                "name": tool["name"],
                "type": tool["type"],
                "installed": installed,
                "location": location or "Not installed",
                "description": tool["desc"],
                "install_hint": self.get_install_command_for_tool(tool),
            })
        return results

    def get_install_command_for_tool(self, tool: Dict[str, Any]) -> str:
        distro = self.platform_info["distro"]
        if tool["type"] == "python_lib":
            return f"uv pip install {tool['pkg']}"
        if distro in ("kali", "parrot", "debian") and tool.get("apt"):
            return f"sudo apt install -y {tool['apt']}"
        if distro == "macos" and tool.get("brew"):
            return f"brew install {tool['brew']}"
        if tool.get("pipx"):
            return f"uv tool install {tool['pipx']} || pipx install {tool['pipx']}"
        if tool.get("go_pkg"):
            return f"go install {tool['go_pkg']}"
        return f"pip install {tool['name']}"

    def install_tool(self, tool_name: str) -> Dict[str, Any]:
        """Install a single tool by name using the safest non-root package manager available on macOS / Kali / Parrot."""
        target = next((t for t in ARSENAL_TOOLS_CATALOG if t["name"].lower() == tool_name.lower()), None)
        if not target:
            return {"success": False, "tool": tool_name, "error": f"Unknown tool '{tool_name}'"}

        distro = self.platform_info["distro"]
        cmds: List[str] = []

        # Prefer uv tool / pipx first for Python CLIs so root isn't required
        if target.get("pipx"):
            if shutil.which("uv"):
                cmds.append(f"uv tool install {target['pipx']}")
            if shutil.which("pipx"):
                cmds.append(f"pipx install {target['pipx']}")
            cmds.append(f"{sys.executable} -m pip install {target['pipx']}")

        if distro == "macos" and target.get("brew") and shutil.which("brew"):
            cmds.append(f"brew install {target['brew']}")
        elif distro in ("kali", "parrot", "debian") and target.get("apt"):
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0
            sudo_prefix = "" if is_root else "sudo -n "
            cmds.append(f"{sudo_prefix}apt-get install -y {target['apt']}")

        if target.get("go_pkg") and shutil.which("go"):
            cmds.append(f"go install {target['go_pkg']}")

        last_err = "No compatible installer found on PATH"
        for cmd in cmds:
            try:
                res = subprocess.run(shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    return {"success": True, "tool": tool_name, "command": cmd, "stdout": res.stdout[-400:]}
                last_err = (res.stderr or res.stdout)[-300:]
            except Exception as exc:
                last_err = str(exc)

        return {"success": False, "tool": tool_name, "error": last_err}
