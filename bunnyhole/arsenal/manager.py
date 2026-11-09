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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# BUNNYHOLE_HOME relocates all state (keys vault, cases.db, profile, caches); the test suite sets it to a temp dir.
BUNNYHOLE_CONFIG_DIR = Path(os.environ.get("BUNNYHOLE_HOME") or (Path.home() / ".bunnyhole"))
BUNNYHOLE_ENV_FILE = BUNNYHOLE_CONFIG_DIR / "api_keys.env"
LEGACY_OSINT_ENV_FILE = Path.home() / ".osint-apis" / "api_keys.env"
OSINT_TOOLS_GIT_DIR = Path.home() / "osint-tools"

RESERVED_STATUS = "reserved"
RESERVED_LABEL = "reserved: not used by any agent yet"

# Comprehensive API Keys Registry across all Bunnyhole Pillars (Breach, Infra, Identity, Fiat, On-Chain, AI).
# ``"status": "reserved"`` marks a key the vault accepts (so it can be stored for future use) but that no
# Bunnyhole agent reads yet; ``keys``, the README and the cheatsheet say so. Remove the marker in the same
# change that makes an agent read the key (tests/test_keys_vault.py checks the package for reads).
API_KEYS_REGISTRY: List[Dict[str, str]] = [
    # Breach & Leak Databases
    {"key": "HAVEIBEENPWNED_API_KEY", "category": "Breach & Leaks", "url": "https://haveibeenpwned.com/API/Key", "note": "Account breach lookup ($4.39/mo)", "status": RESERVED_STATUS},
    {"key": "LEAKCHECK_API_KEY", "category": "Breach & Leaks", "url": "https://leakcheck.io/", "note": "Free tier available"},
    {"key": "INTELX_API_KEY", "category": "Breach & Leaks", "url": "https://intelx.io/", "note": "Free tier: 3 searches/day", "status": RESERVED_STATUS},
    {"key": "HUDSONROCK_API_KEY", "category": "Breach & Leaks", "url": "https://www.hudsonrock.com/free-api-key", "note": "Not needed: the keyless Cavalier OSINT endpoints are what Bunnyhole queries", "status": RESERVED_STATUS},
    {"key": "BREACHDIRECTORY_API_KEY", "category": "Breach & Leaks", "url": "https://breachdirectory.com/api_documentation", "note": "Free tier", "status": RESERVED_STATUS},
    # Infrastructure & Network
    {"key": "SHODAN_API_KEY", "category": "Infrastructure & Recon", "url": "https://account.shodan.io/", "note": "Not needed: Bunnyhole queries the keyless Shodan InternetDB", "status": RESERVED_STATUS},
    {"key": "CENSYS_API_ID", "category": "Infrastructure & Recon", "url": "https://search.censys.io/", "note": "Free 250 queries/mo"},
    {"key": "CENSYS_API_SECRET", "category": "Infrastructure & Recon", "url": "https://search.censys.io/", "note": "Paired with CENSYS_API_ID"},
    {"key": "SECURITYTRAILS_API_KEY", "category": "Infrastructure & Recon", "url": "https://securitytrails.com/", "note": "Historical DNS & subdomains (50/mo free)"},
    {"key": "VIRUSTOTAL_API_KEY", "category": "Infrastructure & Recon", "url": "https://www.virustotal.com/gui/my-apikey", "note": "Free: 500 req/day (Domains, IPs, Hashes)", "status": RESERVED_STATUS},
    {"key": "URLSCAN_API_KEY", "category": "Infrastructure & Recon", "url": "https://urlscan.io/", "note": "Free tier (Public search works keyless)"},
    {"key": "ABUSEIPDB_API_KEY", "category": "Infrastructure & Recon", "url": "https://www.abuseipdb.com/", "note": "Free: 1,000 IP checks/day", "status": RESERVED_STATUS},
    {"key": "ALIENVAULT_OTX_API_KEY", "category": "Infrastructure & Recon", "url": "https://otx.alienvault.com/", "note": "Free Threat Intel indicators"},
    # Social, Identity & Email
    {"key": "GITHUB_API_KEY", "category": "Social & Identity", "url": "https://github.com/settings/tokens", "note": "Raises GitHub rate limit from 60 -> 5,000 req/hr"},
    {"key": "HUNTER_API_KEY", "category": "Social & Identity", "url": "https://hunter.io/", "note": "Free: 25-50 domain email searches/mo"},
    {"key": "EMAILREP_API_KEY", "category": "Social & Identity", "url": "https://emailrep.io/", "note": "Email reputation & social profile correlation"},
    {"key": "IPINFO_TOKEN", "category": "Social & Identity", "url": "https://ipinfo.io/", "note": "Free: 50,000 IP geolocation/ASN lookups/mo", "status": RESERVED_STATUS},
    {"key": "NUMVERIFY_API_KEY", "category": "Social & Identity", "url": "https://numverify.com/", "note": "Phone carrier & line-type validation"},
    {"key": "TELEGRAM_BOT_TOKEN", "category": "Social & Identity", "url": "https://t.me/BotFather", "note": "Optional Telegram channel/fwd_from recon", "status": RESERVED_STATUS},
    # Corporate, Fiat & On-Chain
    {"key": "FEC_API_KEY", "category": "Corporate & Fiat", "url": "https://api.open.fec.gov/developers/", "note": "Free instant key", "status": RESERVED_STATUS},
    {"key": "OPENCORPORATES_API_KEY", "category": "Corporate & Fiat", "url": "https://opencorporates.com/", "note": "Global company registry search", "status": RESERVED_STATUS},
    {"key": "OPENSANCTIONS_API_KEY", "category": "Corporate & Fiat", "url": "https://www.opensanctions.org/api/", "note": "Sanctions/PEP screening — keyless via self-hosted yente (OPENSANCTIONS_API_URL); hosted free tier needs a key"},
    {"key": "OPENSANCTIONS_API_URL", "category": "Corporate & Fiat", "url": "https://www.opensanctions.org/docs/yente/", "note": "Base URL of a self-hosted yente (keyless); default https://api.opensanctions.org. A URL, not a secret"},
    {"key": "COURTLISTENER_API_TOKEN", "category": "Corporate & Fiat", "url": "https://www.courtlistener.com/help/api/rest/", "note": "Free account token; unauthenticated API returns 401"},
    {"key": "UK_COMPANIES_HOUSE_API_KEY", "category": "Corporate & Fiat", "url": "https://developer.company-information.service.gov.uk/", "note": "Free UK PSC beneficial owner lookup (alias: COMPANIES_HOUSE_API_KEY)"},
    {"key": "ETHERSCAN_API_KEY", "category": "On-Chain Crypto", "url": "https://etherscan.io/apis", "note": "Free 5 calls/sec (Blockscout v2 works keyless)", "status": RESERVED_STATUS},
    {"key": "HELIUS_API_KEY", "category": "On-Chain Crypto", "url": "https://www.helius.dev/", "note": "Free Solana deep RPC & Jito bundle history", "status": RESERVED_STATUS},
    # AI & Deep Research Synthesis + Karpathy llm-council
    {"key": "OPENROUTER_API_KEY", "category": "AI Synthesis", "url": "https://openrouter.ai/keys", "note": "LLM text for council Stage 1 seats and Stage 3 chairman (GPT-4o, Claude, Gemini, Grok, DeepSeek); Stage 2 ranking is deterministic"},
    {"key": "OPENAI_API_KEY", "category": "AI Synthesis", "url": "https://platform.openai.com/", "note": "Optional LLM synthesis"},
    {"key": "ANTHROPIC_API_KEY", "category": "AI Synthesis", "url": "https://console.anthropic.com/", "note": "Optional Claude synthesis"},
    {"key": "GEMINI_API_KEY", "category": "AI Synthesis", "url": "https://aistudio.google.com/", "note": "Optional Gemini synthesis"},
]

# Allow-list of persistable/loadable key names, derived from the registry. Any name not in this
# set is rejected, so a caller can never inject process-controlling variables (PATH, LD_PRELOAD,
# PYTHONPATH, HTTPS_PROXY, ...) into the vault file or os.environ via set_api_key / the API.
ALLOWED_KEY_NAMES: frozenset[str] = frozenset(item["key"] for item in API_KEYS_REGISTRY)

# Alternative names the code also reads, mapped to the canonical registry name the vault stores.
KEY_ALIASES: Dict[str, str] = {"COMPANIES_HOUSE_API_KEY": "UK_COMPANIES_HOUSE_API_KEY"}

RESERVED_KEY_NAMES: frozenset[str] = frozenset(
    item["key"] for item in API_KEYS_REGISTRY if item.get("status") == RESERVED_STATUS
)

# A legal environment variable name, as a second-layer guard.
_VALID_KEY_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")

# Unquoted vault values are limited to this charset; anything else (spaces, '#', quotes, '$', ...) is
# written double-quoted so it reads back exactly.
_SAFE_UNQUOTED_VALUE = re.compile(r"^[A-Za-z0-9_\-.:/+=@%~,]*$")

# Names this process exported FROM a vault file, with the value it exported. Anything else in os.environ
# came from the shell (or the parent process), and the shell always wins over the vault.
_VAULT_INJECTED: Dict[str, str] = {}


class UnknownKeyError(ValueError):
    """An API-key name the vault does not accept. ``str()`` lists the accepted names."""

    def __init__(self, key_name: str) -> None:
        self.key_name = key_name
        super().__init__(f"Unknown or illegal API key name: {key_name!r}. Allowed: {', '.join(accepted_key_names())}")


def accepted_key_names() -> List[str]:
    """Every name ``set_api_key`` accepts (registry keys plus aliases), sorted."""
    return sorted(ALLOWED_KEY_NAMES | set(KEY_ALIASES))


def canonical_key_name(key_name: str) -> str:
    """Normalize ``key_name`` (case-insensitive, alias-aware) to its registry name, or raise UnknownKeyError."""
    k = (key_name or "").strip().upper()
    k = KEY_ALIASES.get(k, k)
    if k not in ALLOWED_KEY_NAMES or not _VALID_KEY_NAME.match(k):
        raise UnknownKeyError(key_name)
    return k


def _names_for(canonical: str) -> List[str]:
    """The canonical name followed by every alias of it."""
    return [canonical, *(alias for alias, target in KEY_ALIASES.items() if target == canonical)]


def _strip_inline_comment(raw_value: str) -> str:
    """Strip a trailing ' # ...' vault comment without truncating a value that itself contains '#'."""
    return _split_value(raw_value)[0]


def _split_value(raw_value: str) -> Tuple[str, str]:
    """Split the right-hand side of ``KEY=...`` into ``(value, trailing_comment)``.

    A double-quoted value supports ``\\"`` and ``\\\\`` escapes; a single-quoted value is literal. An unquoted
    value ends at the first ``' #'`` (space before '#', which is what the vault writer appends), so a token
    like ``abc#def`` survives intact. ``trailing_comment`` keeps its leading whitespace and '#'.
    """
    stripped = raw_value.lstrip()
    if stripped[:1] == '"':
        out: List[str] = []
        i = 1
        while i < len(stripped):
            ch = stripped[i]
            if ch == "\\" and i + 1 < len(stripped) and stripped[i + 1] in '"\\':
                out.append(stripped[i + 1])
                i += 2
                continue
            if ch == '"':
                return "".join(out), stripped[i + 1:]
            out.append(ch)
            i += 1
        return stripped[1:].strip(), ""  # unterminated quote: best effort, keep the text
    if stripped[:1] == "'":
        end = stripped.find("'", 1)
        if end != -1:
            return stripped[1:end], stripped[end + 1:]
        return stripped[1:].strip(), ""
    value, sep, comment = raw_value.partition(" #")
    return value.strip(), (f" #{comment}" if sep else "")


def _parse_env_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Parse one vault line into ``(NAME, value, trailing_comment)``, or None for blanks/comments/garbage."""
    clean = line.strip()
    if not clean or clean.startswith("#") or "=" not in clean:
        return None
    if clean.startswith("export "):
        clean = clean[len("export "):].lstrip()
    name, _, rhs = clean.partition("=")
    name = name.strip()
    if not _VALID_KEY_NAME.match(name):
        return None
    value, comment = _split_value(rhs)
    return name, value, comment


def _format_env_value(value: str) -> str:
    """Render ``value`` for the vault so ``_split_value`` reads back exactly the same string."""
    if _SAFE_UNQUOTED_VALUE.match(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _read_vault_file(path: Path) -> Dict[str, str]:
    """Canonical ``{NAME: value}`` for the recognized names in ``path`` (last assignment wins; blanks kept)."""
    found: Dict[str, str] = {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:  # missing or unreadable vault: no keys from it (keyless endpoints still work)
        return found
    for line in raw.splitlines():
        parsed = _parse_env_line(line)
        if parsed is None:
            continue
        name, value, _ = parsed
        name = KEY_ALIASES.get(name, name)
        if name in ALLOWED_KEY_NAMES:
            found[name] = value
    return found


def _secure_write(path: Path, content: str) -> None:
    """Atomically write a secret file: temp file in the same dir, fsync, 0600, os.replace (0700 parent)."""
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
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


VAULT_HEADER = (
    "# Bunnyhole API Keys Vault (chmod 600). Edit with `bunnyhole keys --set NAME=VALUE`.\n"
    "# Exported shell variables always win over values here. Unrecognized lines are left untouched.\n"
)


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
    {"name": "ghunt", "type": "cli", "binary": "ghunt", "pipx": "ghunt", "desc": "Google account OSINT recon"},
    {"name": "phoneinfoga", "type": "cli", "binary": "phoneinfoga", "pipx": "phoneinfoga", "desc": "Phone number OSINT: carrier, line type, footprint & reputation scanners"},
    {"name": "tookie-osint", "type": "cli", "binary": "tookie-osint", "pipx": "tookie-osint", "desc": "Username enumeration across social platforms (Sherlock-class)"},
    # OSINT Automation Frameworks
    {"name": "spiderfoot", "type": "cli", "binary": "sf", "pipx": "spiderfoot", "desc": "Automated OSINT framework correlating domains, IPs, emails & breaches"},
    # Domain, DNS & Network Recon Tools
    {"name": "theHarvester", "type": "cli", "binary": "theHarvester", "pipx": "theHarvester", "apt": "theharvester", "brew": "theharvester", "desc": "Email, subdomain, and employee name harvester"},
    {"name": "dnstwist", "type": "cli", "binary": "dnstwist", "pipx": "dnstwist", "apt": "dnstwist", "brew": "dnstwist", "desc": "Domain lookalike & typosquatting permutation scanner"},
    {"name": "subfinder", "type": "go_cli", "binary": "subfinder", "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "apt": "subfinder", "brew": "subfinder", "desc": "Fast passive subdomain discovery (ProjectDiscovery)"},
    {"name": "assetfinder", "type": "go_cli", "binary": "assetfinder", "go_pkg": "github.com/tomnomnom/assetfinder@latest", "desc": "Find domains & subdomains via CT, VirusTotal & other passive sources"},
    {"name": "findomain", "type": "sys_cli", "binary": "findomain", "apt": "findomain", "brew": "findomain", "desc": "Fast passive subdomain enumeration via Certificate Transparency logs"},
    {"name": "dnsx", "type": "go_cli", "binary": "dnsx", "go_pkg": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "desc": "Fast multipurpose DNS toolkit: resolve, bruteforce & probe records"},
    {"name": "dnsrecon", "type": "cli", "binary": "dnsrecon", "pipx": "dnsrecon", "apt": "dnsrecon", "desc": "DNS enumeration: records, zone transfers, SRV, brute & zone walks"},
    {"name": "tlsx", "type": "go_cli", "binary": "tlsx", "go_pkg": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "brew": "tlsx", "desc": "TLS/SSL cert grabber: SANs, CN, JARM & certificate metadata recon"},
    {"name": "katana", "type": "go_cli", "binary": "katana", "go_pkg": "github.com/projectdiscovery/katana/cmd/katana@latest", "brew": "katana", "desc": "Fast web crawler mapping endpoints, JS & assets (ProjectDiscovery)"},
    {"name": "mosint", "type": "go_cli", "binary": "mosint", "go_pkg": "github.com/alpkeskin/mosint/v3/cmd/mosint@latest", "desc": "Automated email OSINT: breaches, related domains, pastes & social"},
    {"name": "bbot", "type": "cli", "binary": "bbot", "pipx": "bbot", "desc": "Recursive OSINT framework: subdomains, ports, certs & web recon"},
    {"name": "shodan", "type": "cli_or_py", "binary": "shodan", "module": "shodan", "pipx": "shodan", "desc": "Shodan CLI: search exposed hosts, services, ports & banners"},
    {"name": "censys", "type": "cli_or_py", "binary": "censys", "module": "censys", "pipx": "censys", "desc": "Censys CLI: search internet hosts & certificates by attribute"},
    {"name": "metagoofil", "type": "sys_cli", "binary": "metagoofil", "apt": "metagoofil", "desc": "Harvest public documents & surface author/metadata leaks for a domain"},
    {"name": "onionsearch", "type": "cli", "binary": "onionsearch", "pipx": "onionsearch", "desc": "Scrape .onion URLs across multiple Tor search engines (via Tor)"},
    {"name": "amass", "type": "go_cli", "binary": "amass", "go_pkg": "github.com/owasp-amass/amass/v4/...@master", "apt": "amass", "brew": "amass", "desc": "In-depth attack surface mapping & ASN discovery"},
    {"name": "httpx-pd", "type": "go_cli", "binary": "httpx", "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest", "apt": "httpx-toolkit", "brew": "httpx", "desc": "Fast HTTP probing, tech stack & TLS fingerprinter"},
    {"name": "nuclei", "type": "go_cli", "binary": "nuclei", "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "apt": "nuclei", "brew": "nuclei", "desc": "Template-based vulnerability & misconfiguration scanner"},
    {"name": "waybackurls", "type": "go_cli", "binary": "waybackurls", "go_pkg": "github.com/tomnomnom/waybackurls@latest", "desc": "Fetch all historical URLs known to the Wayback Machine"},
    {"name": "gau", "type": "go_cli", "binary": "gau", "go_pkg": "github.com/lc/gau/v2/cmd/gau@latest", "desc": "GetAllUrls from AlienVault OTX, Wayback, and CommonCrawl"},
    # System Utilities (Pre-installed or via apt/brew on Kali, Parrot, macOS)
    {"name": "whois", "type": "sys_cli", "binary": "whois", "apt": "whois", "brew": "whois", "pacman": "whois", "dnf": "whois", "desc": "Domain & IP registration WHOIS client"},
    {"name": "dig", "type": "sys_cli", "binary": "dig", "apt": "dnsutils", "brew": "bind", "pacman": "bind", "dnf": "bind-utils", "desc": "DNS record interrogation utility"},
    {"name": "nmap", "type": "sys_cli", "binary": "nmap", "apt": "nmap", "brew": "nmap", "pacman": "nmap", "dnf": "nmap", "desc": "Network exploration and service/port scanner"},
    {"name": "exiftool", "type": "sys_cli", "binary": "exiftool", "apt": "libimage-exiftool-perl", "brew": "exiftool", "pacman": "perl-image-exiftool", "dnf": "perl-Image-ExifTool", "desc": "Read/write meta information in PDF, image, and media files"},
    {"name": "tor", "type": "sys_cli", "binary": "tor", "apt": "tor", "brew": "tor", "pacman": "tor", "dnf": "tor", "desc": "Anonymity onion routing daemon for dark-web OSINT"},
    {"name": "anonsurf", "type": "sys_cli", "binary": "anonsurf", "apt": "anonsurf", "desc": "Parrot/Kali system-wide Tor transparent proxy (Linux-only, needs root)"},
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


APT_DISTROS = ("kali", "parrot", "debian")

# Names users type that differ from the catalog entry (README calls ProjectDiscovery's httpx just "httpx").
TOOL_ALIASES: Dict[str, str] = {"httpx": "httpx-pd"}


def resolve_tool(tool_name: str) -> Optional[Dict[str, Any]]:
    """The catalog entry for ``tool_name`` (case-insensitive, alias-aware), or None."""
    wanted = (tool_name or "").strip().lower()
    wanted = TOOL_ALIASES.get(wanted, wanted)
    return next((t for t in ARSENAL_TOOLS_CATALOG if t["name"].lower() == wanted), None)


@dataclass(frozen=True)
class InstallPlan:
    """What installing one tool means on this platform.

    ``commands`` are tried in order until one exits 0 (argv lists, no shell). ``unavailable`` lists installers
    that would apply but whose program is not on PATH (e.g. ``go install ...`` without go). With no commands,
    ``hint`` says honestly how to proceed instead of inventing a package name.
    """

    commands: Tuple[Tuple[str, ...], ...]
    unavailable: Tuple[str, ...]
    distro: str

    @property
    def hint(self) -> str:
        if self.commands:
            return " || ".join(shlex.join(c) for c in self.commands)
        if self.unavailable:
            return f"install manually: {'; or '.join(self.unavailable)}"
        return f"not available on {self.distro}: install manually"


def _privileged(argv: List[str]) -> Optional[List[str]]:
    """``argv`` as root: unchanged when already root, prefixed with non-interactive ``sudo -n`` when sudo exists."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return argv
    if shutil.which("sudo"):
        return ["sudo", "-n", *argv]
    return None


def build_install_plan(tool: Dict[str, Any], distro: str) -> InstallPlan:
    """Build the ordered installer list for ``tool`` on ``distro``. Hints and installs both come from here.

    Order: user-space Python installers first (no root), then the native package manager, then ``go install``.
    """
    commands: List[List[str]] = []
    unavailable: List[str] = []

    def _want(program: str, argv: List[str], needs_root: bool = False) -> None:
        if not shutil.which(program):
            unavailable.append(f"{shlex.join(argv)} ({program} not on PATH)")
            return
        if needs_root:
            elevated = _privileged(argv)
            if elevated is None:
                unavailable.append(f"{shlex.join(argv)} (needs root; sudo not on PATH)")
                return
            argv = elevated
        commands.append(argv)

    if tool["type"] == "python_lib":
        # Into the interpreter running Bunnyhole, so the library is importable by it.
        _want("uv", ["uv", "pip", "install", "--python", sys.executable, tool["pkg"]])
    if tool.get("pipx"):
        has_uv, has_pipx = bool(shutil.which("uv")), bool(shutil.which("pipx"))
        if has_uv:
            commands.append(["uv", "tool", "install", tool["pipx"]])
        if has_pipx:
            commands.append(["pipx", "install", tool["pipx"]])
        if not (has_uv or has_pipx):
            unavailable.append(f"uv tool install {tool['pipx']} (uv or pipx not on PATH)")
    if distro == "macos" and tool.get("brew"):
        _want("brew", ["brew", "install", tool["brew"]])
    elif distro in APT_DISTROS and tool.get("apt"):
        _want("apt-get", ["apt-get", "install", "-y", tool["apt"]], needs_root=True)
    elif distro == "arch" and tool.get("pacman"):
        _want("pacman", ["pacman", "-S", "--noconfirm", tool["pacman"]], needs_root=True)
    elif distro == "fedora" and tool.get("dnf"):
        _want("dnf", ["dnf", "install", "-y", tool["dnf"]], needs_root=True)
    if tool.get("go_pkg"):
        _want("go", ["go", "install", tool["go_pkg"]])
    return InstallPlan(commands=tuple(tuple(c) for c in commands), unavailable=tuple(unavailable), distro=distro)


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

    @staticmethod
    def _vault_values() -> Dict[str, Tuple[str, str]]:
        """Merged vault view ``{NAME: (value, source)}``: the read-only legacy file under the primary vault.

        A name the primary vault lists (even with a blank value, which is how ``keys --set NAME=`` clears it)
        overrides the legacy file. ``source`` is ``"vault"`` (primary) or ``"legacy"``.
        """
        merged: Dict[str, Tuple[str, str]] = {k: (v, "legacy") for k, v in _read_vault_file(LEGACY_OSINT_ENV_FILE).items()}
        merged.update({k: (v, "vault") for k, v in _read_vault_file(BUNNYHOLE_ENV_FILE).items()})
        return merged

    @staticmethod
    def _shell_value(name: str) -> str:
        """The value of ``name`` (or an alias of it) exported by the shell, i.e. not injected from a vault."""
        for candidate in _names_for(name):
            current = os.environ.get(candidate, "").strip()
            if current and _VAULT_INJECTED.get(candidate) != os.environ.get(candidate):
                return current
        return ""

    def load_api_keys_into_env(self) -> Dict[str, str]:
        """Export recognized vault keys into os.environ, without ever overriding the shell.

        Only names present in ALLOWED_KEY_NAMES (or an alias) are loaded, so a tampered or legacy vault file
        can never inject process-controlling variables (PATH, LD_PRELOAD, PYTHONPATH, ...) into the
        environment. A variable the shell already exports wins over the vault. A value this process exported
        earlier and that has since been cleared from the vault is withdrawn again. Returns what was exported.
        """
        loaded: Dict[str, str] = {}
        merged = self._vault_values()
        for name in ALLOWED_KEY_NAMES:
            value, _source = merged.get(name, ("", ""))
            if self._shell_value(name):
                continue  # the shell wins
            if value:
                os.environ[name] = value
                _VAULT_INJECTED[name] = value
                loaded[name] = value
            elif name in _VAULT_INJECTED:
                if os.environ.get(name) == _VAULT_INJECTED[name]:
                    del os.environ[name]
                del _VAULT_INJECTED[name]
        return loaded

    def get_api_keys_status(self) -> List[Dict[str, Any]]:
        """Return all supported API keys with configured status, where the value comes from and a masked preview.

        ``source`` is ``"shell"`` (exported in the environment; wins), ``"vault"`` (primary vault),
        ``"legacy"`` (read-only legacy file) or ``""`` (not set). ``reserved`` is True for a key no agent reads yet.
        """
        self.load_api_keys_into_env()
        merged = self._vault_values()
        status_list: List[Dict[str, Any]] = []
        for item in API_KEYS_REGISTRY:
            k = item["key"]
            shell_val = self._shell_value(k)
            vault_val, vault_source = merged.get(k, ("", ""))
            val = shell_val or vault_val
            source = "shell" if shell_val else (vault_source if vault_val else "")
            masked = f"{val[:4]}...{val[-3:]}" if len(val) > 8 else ("***" if val else "")
            reserved = item.get("status") == RESERVED_STATUS
            status_list.append({
                "key": k,
                "category": item["category"],
                "url": item["url"],
                "note": item["note"],
                "configured": bool(val),
                "masked_value": masked,
                "source": source,
                "reserved": reserved,
                "status": RESERVED_STATUS if reserved else "active",
            })
        return status_list

    def set_api_key(self, key_name: str, key_value: str) -> Dict[str, Any]:
        """Persist (or, with an empty value, clear) a recognized API key in the primary vault.

        Raises :class:`UnknownKeyError` (a ValueError listing the accepted names) for any name that is not a
        known Bunnyhole key or alias, which prevents arbitrary environment-variable injection through this
        method and the ``POST /api/keys`` endpoint; raises ValueError for a value containing a newline.

        Only the primary vault is written, atomically, and only the line(s) for this key change: comments,
        blank lines and unrelated assignments are kept verbatim. The legacy ~/.osint-apis file is read-only
        input and is never written. A key the shell already exports keeps its shell value in this process.

        Returns ``{"key", "action": "saved" | "cleared", "path", "shadowed_by_shell"}``.
        """
        k = canonical_key_name(key_name)
        v = key_value.strip()
        if "\n" in v or "\r" in v:
            raise ValueError("API key value must not contain newlines")

        new_line = f"{k}={_format_env_value(v)}"
        names = set(_names_for(k))
        try:
            existing = BUNNYHOLE_ENV_FILE.read_text(encoding="utf-8")
        except FileNotFoundError:
            existing = VAULT_HEADER
        out_lines: List[str] = []
        replaced = False
        for line in existing.splitlines():
            parsed = _parse_env_line(line)
            if parsed is None or parsed[0] not in names:
                out_lines.append(line)
                continue
            if not replaced:
                out_lines.append(new_line + parsed[2])  # keep the line's trailing comment
                replaced = True
            # later duplicates of this key are superseded by the new value and dropped
        if not replaced:
            out_lines.append(new_line)
        _secure_write(BUNNYHOLE_ENV_FILE, "\n".join(out_lines) + "\n")

        shadowed = bool(self._shell_value(k))
        if not shadowed:
            if v:
                os.environ[k] = v
                _VAULT_INJECTED[k] = v
            else:
                os.environ.pop(k, None)
                _VAULT_INJECTED.pop(k, None)
        return {"key": k, "action": "saved" if v else "cleared", "path": str(BUNNYHOLE_ENV_FILE), "shadowed_by_shell": shadowed}

    def ensure_vault_file(self) -> bool:
        """Create an empty primary vault (header only, 0600) if none exists. Returns True when one was created."""
        if BUNNYHOLE_ENV_FILE.exists():
            return False
        _secure_write(BUNNYHOLE_ENV_FILE, VAULT_HEADER)
        return True

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

    def install_plan(self, tool: Dict[str, Any]) -> InstallPlan:
        """The installer commands for ``tool`` on this platform: the single source for hints AND installs."""
        return build_install_plan(tool, self.platform_info["distro"])

    def get_install_command_for_tool(self, tool: Dict[str, Any]) -> str:
        """Human-readable install hint, exactly the command chain :meth:`install_tool` would run."""
        return self.install_plan(tool).hint

    def install_tool(self, tool_name: str) -> Dict[str, Any]:
        """Install one catalog tool (name or alias, case-insensitive) by running its :meth:`install_plan` in order.

        Returns ``{"success": True, "tool", "command", "stdout"}`` on the first command that exits 0, else
        ``{"success": False, "tool", "error"}`` (an unknown name, no installer for this platform, or the last
        failure). Commands run as argv lists, never through a shell.
        """
        target = resolve_tool(tool_name)
        if not target:
            known = ", ".join(sorted(t["name"] for t in ARSENAL_TOOLS_CATALOG))
            return {"success": False, "tool": tool_name, "error": f"Unknown tool '{tool_name}'. Known tools: {known}"}

        plan = self.install_plan(target)
        if not plan.commands:
            return {"success": False, "tool": target["name"], "error": plan.hint}

        last_err = "all installers failed"
        for argv in plan.commands:
            try:
                res = subprocess.run(list(argv), shell=False, capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    return {"success": True, "tool": target["name"], "command": shlex.join(argv), "stdout": (res.stdout or "")[-400:]}
                last_err = ((res.stderr or res.stdout) or f"exit code {res.returncode}")[-300:]
            except Exception as exc:
                last_err = str(exc)

        return {"success": False, "tool": target["name"], "error": last_err}


class AnonsurfController:
    """Install and control anonsurf — Parrot/Kali's system-wide Tor transparent proxy.

    anonsurf routes *all* of the host's traffic through Tor by rewriting iptables, which anonymizes
    the operator's clearnet OSINT traffic (not a target's). It is therefore deliberately explicit and
    opt-in: nothing here is ever called automatically. It is Linux-only (Parrot/Kali/Debian) and every
    state change needs root, so start/stop/install run under sudo and inherit the terminal so sudo can
    prompt. On macOS/Windows these refuse with a pointer to the portable `--tor` SOCKS route instead.
    """

    REPO_URL = "https://github.com/ParrotSec/anonsurf"

    def __init__(self) -> None:
        self.is_linux = platform.system().lower() == "linux"

    def is_available(self) -> bool:
        """True if the anonsurf binary is on PATH."""
        return shutil.which("anonsurf") is not None

    def _is_root(self) -> bool:
        geteuid = getattr(os, "geteuid", None)  # absent on Windows
        return callable(geteuid) and geteuid() == 0

    def _sudo_prefix(self) -> List[str]:
        return [] if self._is_root() else (["sudo"] if shutil.which("sudo") else [])

    def _not_linux_result(self, action: str) -> Dict[str, Any]:
        return {
            "success": False,
            "action": action,
            "error": (
                "anonsurf is Linux-only (Parrot/Kali/Debian). On this platform, route Bunnyhole "
                "through Tor with the portable SOCKS proxy instead: start `tor`, then run any command "
                "with `--tor` (or `--proxy socks5h://127.0.0.1:9050`)."
            ),
        }

    def status(self) -> Dict[str, Any]:
        """Return anonsurf's current state (`anonsurf status`), without changing anything."""
        if not self.is_linux:
            return self._not_linux_result("status")
        if not self.is_available():
            return {"success": False, "action": "status", "error": "anonsurf is not installed (try `bunnyhole anonsurf install`)."}
        try:
            res = subprocess.run(["anonsurf", "status"], capture_output=True, text=True, timeout=30)
            return {"success": res.returncode == 0, "action": "status", "output": (res.stdout or res.stderr).strip()[-600:]}
        except Exception as exc:
            return {"success": False, "action": "status", "error": str(exc)}

    def _run_state_change(self, action: str) -> Dict[str, Any]:
        """Run `anonsurf start|stop|restart|change` under sudo, inheriting the terminal for the prompt."""
        if not self.is_linux:
            return self._not_linux_result(action)
        if not self.is_available():
            return {"success": False, "action": action, "error": "anonsurf is not installed (try `bunnyhole anonsurf install`)."}
        cmd = self._sudo_prefix() + ["anonsurf", action]
        if not self._is_root() and not self._sudo_prefix():
            return {"success": False, "action": action, "error": f"'{action}' needs root and sudo was not found on PATH."}
        try:
            # No capture: anonsurf needs to write iptables and sudo must be able to prompt on the tty.
            res = subprocess.run(cmd, timeout=120)
            return {"success": res.returncode == 0, "action": action, "command": " ".join(cmd)}
        except Exception as exc:
            return {"success": False, "action": action, "error": str(exc)}

    def start(self) -> Dict[str, Any]:
        """Route all host traffic through Tor (`sudo anonsurf start`). Explicit, operator-initiated only."""
        return self._run_state_change("start")

    def stop(self) -> Dict[str, Any]:
        """Restore the host's normal (clearnet) networking (`sudo anonsurf stop`)."""
        return self._run_state_change("stop")

    def restart(self) -> Dict[str, Any]:
        """Restart the anonsurf Tor transparent proxy."""
        return self._run_state_change("restart")

    def change_identity(self) -> Dict[str, Any]:
        """Request a fresh Tor circuit / exit IP (`sudo anonsurf change`)."""
        return self._run_state_change("change")

    def install(self) -> Dict[str, Any]:
        """Install anonsurf: apt first, else clone and build from the official ParrotSec repo.

        Linux + root (via sudo) only. Operator-initiated; never called automatically.
        """
        if not self.is_linux:
            return self._not_linux_result("install")
        if self.is_available():
            return {"success": True, "action": "install", "note": "anonsurf already installed."}
        sudo = self._sudo_prefix()
        if not self._is_root() and not sudo:
            return {"success": False, "action": "install", "error": "Installing anonsurf needs root and sudo was not found on PATH."}

        # 1. Preferred: distro package (Parrot ships it; Kali via its repos).
        try:
            res = subprocess.run(sudo + ["apt-get", "install", "-y", "anonsurf"], timeout=300)
            if res.returncode == 0 and shutil.which("anonsurf"):
                return {"success": True, "action": "install", "method": "apt", "command": "apt-get install -y anonsurf"}
        except Exception:
            pass

        # 2. Fallback: build from the official ParrotSec/anonsurf source.
        if not shutil.which("git"):
            return {"success": False, "action": "install", "error": "apt install failed and git is unavailable for the source fallback."}
        clone_dir = tempfile.mkdtemp(prefix="anonsurf_src_")
        try:
            clone = subprocess.run(["git", "clone", "--depth", "1", self.REPO_URL, clone_dir], capture_output=True, text=True, timeout=180)
            if clone.returncode != 0:
                return {"success": False, "action": "install", "error": f"git clone failed: {(clone.stderr or '')[-200:]}"}
            # ParrotSec/anonsurf installs via `make install`.
            build = subprocess.run(sudo + ["make", "install"], cwd=clone_dir, timeout=300)
            if build.returncode == 0 and shutil.which("anonsurf"):
                return {"success": True, "action": "install", "method": "source", "command": f"git clone {self.REPO_URL} && sudo make install"}
            return {"success": False, "action": "install", "error": "Source build completed but the anonsurf binary is not on PATH."}
        except Exception as exc:
            return {"success": False, "action": "install", "error": str(exc)}
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)
