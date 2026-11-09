"""Test-suite isolation: never touch the developer's real ~/.bunnyhole, and never touch the network.

1. BUNNYHOLE_HOME (and HOME) are read when ``bunnyhole.arsenal.manager`` is first imported, so they must be set
   here, at conftest import time, before any test module (or the package) is imported. Both point into one temp
   dir, so no test reads the developer's real ~/.bunnyhole, ~/.osint-apis vault or ~/osint-tools.

2. Network guard (installed for the whole session). Every test runs hermetically. These raise
   ``NetworkAccessBlocked`` AND fail the test at teardown, even when the code under test swallows the exception
   (many OSINT adapters catch broad errors and degrade quietly, which would otherwise hide a live call):

   - a socket to a non-loopback address: ``socket.socket.connect``/``connect_ex``, ``socket.create_connection``
     and UDP ``sendto`` (this covers asyncio, httpx/anyio and dnspython);
   - a lookup of a public hostname: ``socket.getaddrinfo``/``gethostbyname[_ex]`` (live DNS is network use, and
     behaves differently offline);
   - a subprocess that is a network tool: any binary from the arsenal catalog (holehe, sherlock, ...), git,
     curl, Tor tooling, package managers, remote ``git`` commands, and ``uv``/``pip`` installs. A child process is invisible to the
     socket guard, so it is blocked by name.

   Loopback (127.0.0.0/8, ::1, ``localhost``) and AF_UNIX stay allowed, so local servers, asyncio self-pipes and
   FastAPI's TestClient work. respx mocks at the httpx transport layer, before any socket is opened, so
   respx-mocked calls are unaffected.

   Mock outbound HTTP with respx (``with respx.mock: respx.get(url).mock(return_value=httpx.Response(...))``)
   or monkeypatch the adapter / tool runner. Do not loosen the guard to make a test pass.

3. Opt-out for a deliberate live test: mark it ``@pytest.mark.network``. Such tests are SKIPPED unless
   ``BUNNYHOLE_TEST_NETWORK=1`` is set in the environment; when it is set, the guard is lifted for those tests
   only. CI never sets it.

4. Shared helpers (``tests/pi_helpers.py``) are imported as ``import pi_helpers`` in both pytest import modes.
   The default (prepend) mode puts this directory on ``sys.path``; ``--import-mode=importlib`` does not, so it is
   appended here. There is deliberately no ``tests`` package: a dependency (waybackpy) installs its own top-level
   ``tests`` package into site-packages, which would shadow it. ``conftest`` is also registered under its plain
   name so ``from conftest import ...`` resolves to this already-loaded module in both modes (never a second copy
   with its own temp home and violation list).

5. Marker ``slow``: the bounded-time tests on 300 KB adversarial inputs (seconds in total). They run by default;
   deselect them for a quick loop with ``-m "not slow"``.
"""

from __future__ import annotations

import atexit
import ipaddress
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Any, FrozenSet, List

import pytest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.append(_TESTS_DIR)
sys.modules.setdefault("conftest", sys.modules[__name__])

_TEST_HOME = tempfile.mkdtemp(prefix="bunnyhole-test-home-")
os.environ["BUNNYHOLE_HOME"] = _TEST_HOME
# HOME too: arsenal/manager.py reads the legacy vault ~/.osint-apis/api_keys.env (real API keys on a developer
# machine), ~/osint-tools and ~/.local/bin, ~/go/bin, ~/bin via Path.home(). Point them at an empty temp home so
# a developer's own keys and tools never change test outcomes (and the suite runs with HOME unwritable).
_TEST_USER_HOME = os.path.join(_TEST_HOME, "user-home")
os.makedirs(_TEST_USER_HOME, exist_ok=True)
os.environ["HOME"] = _TEST_USER_HOME
os.environ["USERPROFILE"] = _TEST_USER_HOME
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)

NETWORK_ENV_VAR = "BUNNYHOLE_TEST_NETWORK"


class NetworkAccessBlocked(RuntimeError):
    """Raised when a test tries to reach the network. Deliberately not an OSError subclass, so
    ``except OSError`` / httpx error mapping cannot quietly turn it into a "lookup failed" path."""


_guard_state: dict = {"enabled": True}
_violations: List[str] = []

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto
_real_create_connection = socket.create_connection
_real_getaddrinfo = socket.getaddrinfo
_real_gethostbyname = socket.gethostbyname
_real_gethostbyname_ex = socket.gethostbyname_ex
_real_popen_init = subprocess.Popen.__init__

_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

# Executables that always talk to the network. The arsenal catalog's binaries are added lazily (see below).
_NETWORK_BINARIES: FrozenSet[str] = frozenset({
    "curl", "wget", "ssh", "scp", "rsync", "nc", "ncat", "nmap", "dig", "nslookup", "host", "whois",
    "tor", "torsocks", "torify", "proxychains", "proxychains4", "anonsurf",
    "pipx", "apt", "apt-get", "brew", "go", "npm", "npx", "cargo", "gem",
})
# Executables that hit the network only for some sub-commands (installs, fetches).
_NETWORK_SUBCOMMANDS = {"git": {"clone", "fetch", "pull", "push", "ls-remote", "submodule"},
                        "uv": {"add", "sync", "lock", "tool", "pip", "build", "publish", "self"},
                        "pip": {"install", "download"}, "pip3": {"install", "download"}}


def pop_blocked_attempts() -> List[str]:
    """Return and clear the attempts recorded so far in this test (for tests of the guard itself)."""
    out = list(_violations)
    _violations.clear()
    return out


def _normalise_host(host: Any) -> str:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    return str(host).strip("[]").split("%", 1)[0].lower()


def _is_local_address(address: Any) -> bool:
    """True for AF_UNIX paths and loopback (host, port[, ...]) tuples."""
    if isinstance(address, (str, bytes)):  # AF_UNIX path (str/bytes); abstract namespace on Linux
        return True
    if not isinstance(address, tuple) or not address:
        return False
    host = _normalise_host(address[0])
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_local_host_lookup(host: Any) -> bool:
    """True when resolving ``host`` cannot leave the machine: None/'' (bind), IP literals, loopback names."""
    if host is None:
        return True
    host = _normalise_host(host)
    if not host or host in _LOOPBACK_NAMES:
        return True
    try:
        ipaddress.ip_address(host)
        return True  # numeric: no DNS query is made
    except ValueError:
        return False


def _block(what: str) -> None:
    msg = (
        f"Network access blocked in tests: {what}. Mock it with respx or monkeypatch the adapter; "
        f"for a deliberate live test use @pytest.mark.network and {NETWORK_ENV_VAR}=1."
    )
    _violations.append(msg)
    raise NetworkAccessBlocked(msg)


def _check(address: Any, how: str) -> None:
    if _guard_state["enabled"] and not _is_local_address(address):
        _block(f"{how} to {address!r}")


def _check_lookup(host: Any, how: str) -> None:
    if _guard_state["enabled"] and not _is_local_host_lookup(host):
        _block(f"{how} of {host!r}")


def _guarded_connect(self: socket.socket, address: Any) -> None:
    _check(address, "socket.connect")
    return _real_connect(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    _check(address, "socket.connect_ex")
    return _real_connect_ex(self, address)


def _guarded_sendto(self: socket.socket, data: Any, *args: Any) -> int:
    if args:  # sendto(data, address) or sendto(data, flags, address)
        _check(args[-1], "socket.sendto")
    return _real_sendto(self, data, *args)  # type: ignore[arg-type]


def _guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
    _check(address, "socket.create_connection")
    return _real_create_connection(address, *args, **kwargs)


def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    _check_lookup(host, "DNS lookup (socket.getaddrinfo)")
    return _real_getaddrinfo(host, *args, **kwargs)


def _guarded_gethostbyname(host: str) -> str:
    _check_lookup(host, "DNS lookup (socket.gethostbyname)")
    return _real_gethostbyname(host)


def _guarded_gethostbyname_ex(host: str) -> Any:
    _check_lookup(host, "DNS lookup (socket.gethostbyname_ex)")
    return _real_gethostbyname_ex(host)


_catalog_binaries: dict = {}


def _arsenal_binaries() -> FrozenSet[str]:
    """Binaries of the arsenal catalog (read lazily so a broken import never breaks collection)."""
    if "names" not in _catalog_binaries:
        try:
            from bunnyhole.arsenal.manager import ARSENAL_TOOLS_CATALOG

            names = {str(t["binary"]).lower() for t in ARSENAL_TOOLS_CATALOG if t.get("binary")}
        except Exception:  # noqa: BLE001 - fall back to the static list only
            names = set()
        _catalog_binaries["names"] = frozenset(names)
    return _catalog_binaries["names"]


def _argv(args: Any, shell: bool) -> List[str]:
    if isinstance(args, (str, bytes, os.PathLike)):
        text = os.fsdecode(args)
        if not shell:
            return [text]
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()
    return [os.fsdecode(a) for a in args]


def _is_network_command(argv: List[str]) -> bool:
    if not argv:
        return False
    exe = os.path.basename(argv[0]).lower()
    if exe in _NETWORK_BINARIES or exe in _arsenal_binaries():
        return True
    if exe in _NETWORK_SUBCOMMANDS and len(argv) > 1 and argv[1].lower() in _NETWORK_SUBCOMMANDS[exe]:
        return True
    # python -m pip install ...
    if exe.startswith("python") and argv[1:3] == ["-m", "pip"] and len(argv) > 3:
        return argv[3].lower() in _NETWORK_SUBCOMMANDS["pip"]
    return False


def _guarded_popen_init(self: subprocess.Popen, args: Any, *a: Any, **kw: Any) -> None:
    if _guard_state["enabled"]:
        argv = _argv(args, bool(kw.get("shell", False)))
        if _is_network_command(argv):
            _block(f"subprocess {' '.join(argv)[:160]!r} (a network tool)")
    _real_popen_init(self, args, *a, **kw)


def _install_network_guard() -> None:
    socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = _guarded_sendto  # type: ignore[method-assign,assignment]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
    socket.gethostbyname = _guarded_gethostbyname  # type: ignore[assignment]
    socket.gethostbyname_ex = _guarded_gethostbyname_ex  # type: ignore[assignment]
    subprocess.Popen.__init__ = _guarded_popen_init  # type: ignore[method-assign,assignment]


def _uninstall_network_guard() -> None:
    socket.socket.connect = _real_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _real_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = _real_sendto  # type: ignore[method-assign]
    socket.create_connection = _real_create_connection
    socket.getaddrinfo = _real_getaddrinfo
    socket.gethostbyname = _real_gethostbyname
    socket.gethostbyname_ex = _real_gethostbyname_ex
    subprocess.Popen.__init__ = _real_popen_init  # type: ignore[method-assign]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"network: test makes a deliberate live network call; skipped unless {NETWORK_ENV_VAR}=1",
    )
    config.addinivalue_line(
        "markers",
        'slow: bounded-time test on large adversarial input (runs by default; deselect with -m "not slow")',
    )
    _install_network_guard()


def pytest_unconfigure(config: pytest.Config) -> None:
    _uninstall_network_guard()


def _network_opt_in() -> bool:
    return os.environ.get(NETWORK_ENV_VAR, "").strip() == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    if _network_opt_in():
        return
    skip = pytest.mark.skip(reason=f"live network test: set {NETWORK_ENV_VAR}=1 to run")
    for item in items:
        if item.get_closest_marker("network") is not None:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _hermetic_network(request: pytest.FixtureRequest):
    """Per-test: lift the guard only for opted-in network tests; fail any test that tried the network."""
    allow = request.node.get_closest_marker("network") is not None and _network_opt_in()
    _guard_state["enabled"] = not allow
    start = len(_violations)
    try:
        yield
    finally:
        _guard_state["enabled"] = True
    attempts = _violations[start:]
    del _violations[start:]
    if attempts:
        pytest.fail(
            f"{len(attempts)} blocked network attempt(s) (possibly swallowed by the code under test):\n"
            + "\n".join(dict.fromkeys(attempts)),
            pytrace=False,
        )
