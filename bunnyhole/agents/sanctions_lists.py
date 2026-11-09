"""Official sanctions lists (GAC SEMA, OFAC SDN, UN consolidated, UK Sanctions List): download, cache, parse, match.

Pure module-level machinery split out of ``pi_sources`` (no agent state, no graph, no receipts). The agent in
``pi_sources`` owns every graph node, edge, receipt and log line and calls in here; everything it needs from its
own module namespace (cache directory, size cap, clock, HTTP client factory, log callbacks) is passed in through
a :class:`SanctionsEnv` resolved at call time, so patching those names on ``pi_sources`` keeps working.

What lives here:

* streamed download with a size cap and a DTD/ENTITY/NUL refusal, manual redirect handling (https only, host
  allow-list), an on-disk cache (atomic rename, 0o600 temp file, TTL), per-process index caches, a failure
  backoff and one asyncio lock per (list, event loop);
* the per-list XML parsers (OFAC SDN, UN, UK, and the bilingual GAC SEMA file) and the compact name index;
* the shared name-matching helpers (:func:`normalize_name_tokens`, :func:`names_match`).
"""

from __future__ import annotations

import asyncio
import codecs
import os
import re
import sys
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Tuple

import httpx

SEMA_XML_URL = (
    "https://www.international.gc.ca/world-monde/assets/office_docs/"
    "international_relations-relations_internationales/sanctions/sema-lmes.xml"
)
SEMA_PAGE_URL = (
    "https://www.international.gc.ca/world-monde/international_relations-relations_internationales/"
    "sanctions/consolidated-consolide.aspx?lang=eng"
)

OFAC_SDN_XML_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
OFAC_SDN_PAGE_URL = "https://sanctionssearch.ofac.treas.gov/"
UN_CONSOLIDATED_XML_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
UN_CONSOLIDATED_PAGE_URL = "https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list"
UK_SANCTIONS_XML_URL = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.xml"
UK_SANCTIONS_PAGE_URL = "https://www.gov.uk/government/publications/the-uk-sanctions-list"

MAX_SANCTIONS_LIST_BYTES = 40 * 1024 * 1024  # per-list download cap, enforced while streaming (live: 2-30 MB)
SANCTIONS_LIST_TIMEOUT_S = 60.0
SANCTIONS_CACHE_TTL_S = 24 * 3600  # an on-disk list younger than this is used without a download
SANCTIONS_RETRY_AFTER_S = 300.0  # after a failed download, do not hammer the host again for this long
_SANCTIONS_MAX_REDIRECTS = 3
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DTD_OVERLAP_CHARS = 16  # longer than "<!doctype": a declaration split across two chunks is still seen

MAX_SEMA_BYTES = 10 * 1024 * 1024  # hard cap on the sanctions download (the live file is ~3 MB)

# Tokens that carry no identity (legal forms, honorifics): dropped before name comparison.
_NAME_NOISE_TOKENS = frozenset(
    {
        "ltd", "limited", "llc", "inc", "incorporated", "plc", "corp", "corporation", "co", "company",
        "llp", "lp", "sa", "ag", "gmbh", "jsc", "ojsc", "pjsc", "ooo", "bv", "nv", "the",
    }
)  # fmt: skip

# The GAC SEMA file uses bilingual element names. Verified against the live file on 2026-11-09.
_SEMA_COUNTRY = "Country-Pays"
_SEMA_LAST_NAME = "LastName-NomDeFamille"
_SEMA_GIVEN_NAME = "GivenName-Prenom"
_SEMA_ENTITY = "EntityOrShip-EntiteOuNavire"
_SEMA_ALIASES = "Aliases-Alias"
_SEMA_DOB = "DateOfBirthOrShipBuildDate-DateDeNaissanceOuDateDeConstructionDuNavire"
_SEMA_SCHEDULE = "Schedule-Annexe"
_SEMA_ITEM = "Item-NumeroDarticle"
_SEMA_LISTED = "DateOfListing-DateDinscription"
_SEMA_IMO = "ShipIMONumber-NumeroOMIDuNavire"
_SEMA_SHIP_TYPE = "TitleOrShipType-TitreOuTypeDeNavire"


class _SourceSkip(Exception):
    """A source could not run (access, HTTP status, payload). Caught inside the agent and logged."""


# ----------------------------------------------------------------------------------------------
# Name matching (shared with the agent's CFPB and SEMA screens)
# ----------------------------------------------------------------------------------------------


def normalize_name_tokens(name: str) -> FrozenSet[str]:
    """Lowercase, accent-stripped word tokens of a name with legal-form noise removed.

    If removing noise would empty the name (e.g. ``"The Company"``), the unfiltered tokens are kept.
    """
    folded = unicodedata.normalize("NFKD", name or "")
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch)).lower()
    tokens = re.findall(r"\w+", folded)
    core = [t for t in tokens if t not in _NAME_NOISE_TOKENS]
    return frozenset(core or tokens)


def _token_sets_match(q: FrozenSet[str], c: FrozenSet[str], *, allow_single_token: bool = False) -> bool:
    """The :func:`names_match` rule on two already-normalised token sets (shared with the sanctions index)."""
    if not q or not c:
        return False
    if q == c:
        return True
    min_size = 1 if allow_single_token else 2
    if len(q) >= min_size and q <= c:
        return True
    return len(c) >= 2 and c <= q


def names_match(query: str, candidate: str, *, allow_single_token: bool = False) -> bool:
    """Token-subset name match (normalised, order-free, accent- and punctuation-insensitive).

    True when the query's tokens are all in the candidate's (or the candidate's all in the query's),
    with at least two tokens on the contained side, or when the two token sets are identical. A lone
    shared token ("Smith") is never a match unless the whole name is that token or the caller opts in
    with ``allow_single_token`` (used where the candidate is a long company name and the query is a
    short brand).
    """
    return _token_sets_match(
        normalize_name_tokens(query), normalize_name_tokens(candidate), allow_single_token=allow_single_token
    )


# ----------------------------------------------------------------------------------------------
# GAC SEMA (Canada): parse, download, match
# ----------------------------------------------------------------------------------------------


def _parse_sema_records(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse the GAC SEMA XML into plain dicts. Caller must already have refused DTD/entity payloads."""
    root = ET.fromstring(xml_bytes)
    records: List[Dict[str, Any]] = []
    for rec in root.iter("record"):
        fields = {child.tag: (child.text or "").strip() for child in rec}
        given, last = fields.get(_SEMA_GIVEN_NAME, ""), fields.get(_SEMA_LAST_NAME, "")
        entity = fields.get(_SEMA_ENTITY, "")
        if given or last:
            kind, primary = "person", " ".join(part for part in (given, last) if part)
        elif entity:
            is_ship = bool(fields.get(_SEMA_IMO) or fields.get(_SEMA_SHIP_TYPE))
            kind, primary = ("ship" if is_ship else "entity"), entity
        else:
            continue
        aliases = [a.strip() for a in fields.get(_SEMA_ALIASES, "").split(";") if a.strip()]
        records.append(
            {
                "kind": kind,
                "name": primary,
                "aliases": aliases,
                "country": fields.get(_SEMA_COUNTRY, ""),
                "schedule": fields.get(_SEMA_SCHEDULE, ""),
                "item": fields.get(_SEMA_ITEM, ""),
                "listed": fields.get(_SEMA_LISTED, ""),
                "dob_or_build": fields.get(_SEMA_DOB, ""),
                "imo": fields.get(_SEMA_IMO, ""),
            }
        )
    return records


def _reject_dtd(payload: bytes) -> None:
    """Refuse payloads that could carry an XML entity-expansion attack or hide one in another encoding."""
    if b"\x00" in payload:
        raise _SourceSkip("payload contains NUL bytes (non-UTF-8 encoding can hide a DOCTYPE); refused")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _SourceSkip("payload is not valid UTF-8; refused") from exc
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise _SourceSkip("payload contains a DOCTYPE/ENTITY declaration (XML entity-expansion defence); refused")


async def download_sema_xml(
    client_factory: Callable[..., Any], std_headers: Dict[str, str], max_bytes: int
) -> bytes:
    """Download the whole SEMA file into memory, aborting past ``max_bytes`` (declared or streamed)."""
    headers = dict(std_headers)
    headers["Accept"] = "application/xml, text/xml"
    async with (
        client_factory(timeout=30.0, headers=headers) as client,
        client.stream("GET", SEMA_XML_URL) as resp,
    ):
        if resp.status_code != 200:
            raise _SourceSkip(f"HTTP {resp.status_code}")
        declared = resp.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise _SourceSkip("declared size exceeds the 10 MB download cap")
        buffer = bytearray()
        async for chunk in resp.aiter_bytes():
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                raise _SourceSkip("download exceeded the 10 MB cap and was aborted")
        return bytes(buffer)


def find_sema_matches(records: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """SEMA records whose name or an alias name-matches ``query``, each with a ``matched_name`` key added."""
    matches: List[Dict[str, Any]] = []
    for rec in records:
        via = next((n for n in [rec["name"], *rec["aliases"]] if names_match(query, n)), None)
        if via is not None:
            matches.append({**rec, "matched_name": via})
    return matches


# ----------------------------------------------------------------------------------------------
# Official sanctions lists (OFAC SDN, UN Security Council consolidated, UK Sanctions List): stream-parsed
# ----------------------------------------------------------------------------------------------


def _monotonic_s() -> float:
    return time.monotonic()


def _iso_utc(epoch_s: float) -> str:
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_cap(cap_bytes: int) -> str:
    return f"{cap_bytes // (1024 * 1024)} MB" if cap_bytes >= 1024 * 1024 else f"{cap_bytes} bytes"


def sanctions_cache_path(config_dir: Any, source: str) -> Path:
    """Where the downloaded XML of one list is cached: ``<config dir>/cache/sanctions/<source>.xml``."""
    return Path(config_dir) / "cache" / "sanctions" / f"{source}.xml"


class _SanctionsRecord(NamedTuple):
    """One listed party, reduced to what screening needs. ``names`` is (display name, tokens), primary first."""

    list_id: str
    kind: str  # person | entity | ship | aircraft
    programs: Tuple[str, ...]
    listed: str
    names: Tuple[Tuple[str, FrozenSet[str]], ...]
    extra: str = ""


@dataclass(frozen=True)
class _SanctionsListSpec:
    source: str  # receipt tool name, cache file stem, orchestrator source name
    label: str
    prefix: str  # agent-log action prefix
    id_prefix: str  # graph node id: sanction:<id_prefix>:<list id>
    xml_url: str
    page_url: str
    program_label: str
    record_tags: FrozenSet[str]
    parse: Callable[[ET.Element], Optional[_SanctionsRecord]]
    # OFAC and the UN answer 302 to signed object storage. Redirects are followed by hand, https only, and only
    # to the list's own host or a host with one of these suffixes; any other target is refused unvisited.
    redirect_host_suffixes: Tuple[str, ...] = ()


@dataclass
class _LoadedSanctionsIndex:
    records: List[_SanctionsRecord]
    expires_at: float  # monotonic seconds
    stale_note: str = ""  # set when the index was built from an expired cache because the refresh failed


def _local(tag: Any) -> str:
    return tag.rpartition("}")[2] if isinstance(tag, str) else ""


def _text(elem: ET.Element) -> str:
    return " ".join((elem.text or "").split())


def _build_names(candidates: Iterable[str]) -> Tuple[Tuple[str, FrozenSet[str]], ...]:
    """Display names with interned token sets, dropping blanks and name variants that tokenise identically."""
    out: List[Tuple[str, FrozenSet[str]]] = []
    seen: set = set()
    for raw in candidates:
        name = " ".join((raw or "").split())
        if not name:
            continue
        tokens = frozenset(sys.intern(t) for t in normalize_name_tokens(name))
        if tokens and tokens not in seen:
            seen.add(tokens)
            out.append((name, tokens))
    return tuple(out)


def _parse_ofac_entry(entry: ET.Element) -> Optional[_SanctionsRecord]:
    """``<sdnEntry>`` (namespaced): uid, firstName/lastName (lastName is the whole name of an entity), sdnType,
    programList/program, akaList/aka (own firstName/lastName)."""
    uid = sdn_type = first = last = ""
    programs: List[str] = []
    akas: List[str] = []
    for child in entry:
        tag = _local(child.tag)
        if tag == "uid":
            uid = _text(child)
        elif tag == "firstName":
            first = _text(child)
        elif tag == "lastName":
            last = _text(child)
        elif tag == "sdnType":
            sdn_type = _text(child)
        elif tag == "programList":
            programs = [p for p in (_text(item) for item in child) if p]
        elif tag == "akaList":
            for aka in child:
                parts = {_local(part.tag): _text(part) for part in aka}
                akas.append(" ".join(p for p in (parts.get("firstName", ""), parts.get("lastName", "")) if p))
    names = _build_names([" ".join(p for p in (first, last) if p), *akas])
    if not names:
        return None
    kind = {"individual": "person", "vessel": "ship", "aircraft": "aircraft"}.get(sdn_type.lower(), "entity")
    return _SanctionsRecord(uid or names[0][0], kind, tuple(programs), "", names, sdn_type)


_UN_NAME_PARTS = ("FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME")


def _parse_un_entry(rec: ET.Element) -> Optional[_SanctionsRecord]:
    """``<INDIVIDUAL>`` / ``<ENTITY>``: FIRST..FOURTH_NAME (an entity's whole name is in FIRST_NAME), DATAID,
    REFERENCE_NUMBER, UN_LIST_TYPE, LISTED_ON, *_ALIAS/ALIAS_NAME, NAME_ORIGINAL_SCRIPT."""
    fields: Dict[str, str] = {}
    aliases: List[str] = []
    for child in rec:
        tag = _local(child.tag)
        if tag.endswith("_ALIAS"):
            aliases.extend(_text(sub) for sub in child if _local(sub.tag) == "ALIAS_NAME")
        else:
            fields.setdefault(tag, _text(child))
    primary = " ".join(fields[p] for p in _UN_NAME_PARTS if fields.get(p))
    names = _build_names([primary, *aliases, fields.get("NAME_ORIGINAL_SCRIPT", "")])
    if not names:
        return None
    list_type = fields.get("UN_LIST_TYPE", "")
    kind = "person" if _local(rec.tag) == "INDIVIDUAL" else "entity"
    list_id = fields.get("REFERENCE_NUMBER") or fields.get("DATAID") or names[0][0]
    return _SanctionsRecord(list_id, kind, (list_type,) if list_type else (), fields.get("LISTED_ON", ""), names)


_UK_FIELDS = frozenset(
    {"UniqueID", "RegimeName", "DateDesignated", "IndividualEntityShip", "UNReferenceNumber", "DesignationSource"}
)


def _parse_uk_designation(des: ET.Element) -> Optional[_SanctionsRecord]:
    """``<Designation>``: UniqueID, RegimeName, DateDesignated, IndividualEntityShip, UNReferenceNumber,
    Names/Name (Name1..Name6 joined; NameType 'Primary Name' or an alias type), NonLatinNames."""
    fields: Dict[str, str] = {}
    primary: List[str] = []
    others: List[str] = []
    for child in des:
        tag = _local(child.tag)
        if tag == "Names":
            for name in child:
                parts = [(_local(p.tag), _text(p)) for p in name]
                joined = " ".join(v for t, v in parts if t.startswith("Name") and t != "NameType" and v)
                kind = next((v for t, v in parts if t == "NameType"), "").lower()
                (primary if kind == "primary name" else others).append(joined)
        elif tag == "NonLatinNames":
            others.extend(_text(p) for n in child for p in n)
        elif tag in _UK_FIELDS:
            fields.setdefault(tag, _text(child))
    names = _build_names([*primary, *others])
    if not names:
        return None
    kind = {"individual": "person", "ship": "ship"}.get(fields.get("IndividualEntityShip", "").lower(), "entity")
    regime = fields.get("RegimeName", "")
    extra = "; ".join(
        f"{label} {fields[key]}"
        for label, key in (("UN ref", "UNReferenceNumber"), ("source", "DesignationSource"))
        if fields.get(key)
    )
    return _SanctionsRecord(
        fields.get("UniqueID") or names[0][0], kind, (regime,) if regime else (), fields.get("DateDesignated", ""),
        names, extra,
    )  # fmt: skip


_SANCTIONS_LISTS: Dict[str, _SanctionsListSpec] = {
    spec.source: spec
    for spec in (
        _SanctionsListSpec(
            "ofac_sdn", "OFAC SDN list (US Treasury)", "OFAC_SDN", "ofac", OFAC_SDN_XML_URL, OFAC_SDN_PAGE_URL,
            "programs", frozenset({"sdnEntry"}), _parse_ofac_entry, (".amazonaws.com",),
        ),
        _SanctionsListSpec(
            "un_consolidated", "UN Security Council consolidated list", "UN_CONSOLIDATED", "un",
            UN_CONSOLIDATED_XML_URL, UN_CONSOLIDATED_PAGE_URL, "committee list type",
            frozenset({"INDIVIDUAL", "ENTITY"}), _parse_un_entry, (".blob.core.windows.net",),
        ),
        _SanctionsListSpec(
            "uk_sanctions_list", "UK Sanctions List (FCDO)", "UK_SANCTIONS", "uk", UK_SANCTIONS_XML_URL,
            UK_SANCTIONS_PAGE_URL, "regime", frozenset({"Designation"}), _parse_uk_designation,
        ),
    )
}  # fmt: skip


class _XmlStreamGuard:
    """Refuses DOCTYPE/ENTITY declarations, NUL bytes and non-UTF-8 text, chunk by chunk, across chunk borders."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._tail = ""

    def feed(self, chunk: bytes) -> None:
        if b"\x00" in chunk:
            raise _SourceSkip("payload contains NUL bytes (non-UTF-8 encoding can hide a DOCTYPE); refused")
        try:
            text = self._decoder.decode(chunk)
        except UnicodeDecodeError as exc:
            raise _SourceSkip("payload is not valid UTF-8; refused") from exc
        window = (self._tail + text).lower()
        if "<!doctype" in window or "<!entity" in window:
            raise _SourceSkip("payload contains a DOCTYPE/ENTITY declaration (XML entity-expansion defence); refused")
        self._tail = window[-_DTD_OVERLAP_CHARS:]

    def finish(self) -> None:
        try:
            self._decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise _SourceSkip("payload ends inside a multi-byte character; refused") from exc


def _index_xml_file(spec: _SanctionsListSpec, path: Path, *, guard: bool) -> List[_SanctionsRecord]:
    """Stream-parse one list into the compact name index (runs in a worker thread).

    ``guard=True`` first re-checks the whole file with the same DTD/NUL/UTF-8 refusal the download applies
    (used for a file read back from the cache). Each processed record element is cleared, so memory holds
    the name index and one record at a time, not the document.
    """
    if guard:
        checker = _XmlStreamGuard()
        with open(path, "rb") as raw:
            while chunk := raw.read(1 << 20):
                checker.feed(chunk)
        checker.finish()
    records: List[_SanctionsRecord] = []
    with open(path, "rb") as fh:
        for _event, elem in ET.iterparse(fh, events=("end",)):
            if _local(elem.tag) in spec.record_tags:
                record = spec.parse(elem)
                if record is not None:
                    records.append(record)
                elem.clear()
    if not records:
        raise _SourceSkip("the list contained no records")
    return records


def _cache_age_s(path: Path) -> Optional[float]:
    try:
        return max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        return None


def find_sanctions_matches(
    records: List[_SanctionsRecord], query: str
) -> List[Tuple[bool, _SanctionsRecord, str]]:
    """Records with a name that matches ``query`` as (is_inexact, record, matched display name), exact first."""
    q_tokens = normalize_name_tokens(query)
    matches: List[Tuple[bool, _SanctionsRecord, str]] = []
    for rec in records:
        for display, tokens in rec.names:
            if _token_sets_match(q_tokens, tokens):
                matches.append((q_tokens != tokens, rec, display))
                break
    matches.sort(key=lambda m: m[0])  # exact name matches first; stable otherwise
    return matches


# ----------------------------------------------------------------------------------------------
# Per-process state (shared by every PISourcesAgent; the agent aliases these dicts as class attributes)
# ----------------------------------------------------------------------------------------------

# Keyed by list source name: parsed name index, time of the last failed download (monotonic seconds), and one
# asyncio lock per (list, event loop).
_SANCTIONS_INDEXES: Dict[str, _LoadedSanctionsIndex] = {}
_SANCTIONS_FAILED_AT: Dict[str, float] = {}
_SANCTIONS_LOCKS: Dict[Tuple[str, int], asyncio.Lock] = {}


def reset_sanctions_process_index(source: Optional[str] = None) -> None:
    """Forget the in-memory name index of one list (or all), keeping failure state and the disk cache."""
    for key in [source] if source else list(_SANCTIONS_INDEXES):
        _SANCTIONS_INDEXES.pop(key, None)


def reset_sanctions_source(source: str) -> None:
    """Forget the in-memory index, the recorded failure and the locks of one list (disk cache kept)."""
    _SANCTIONS_INDEXES.pop(source, None)
    _SANCTIONS_FAILED_AT.pop(source, None)
    for key in [k for k in _SANCTIONS_LOCKS if k[0] == source]:
        _SANCTIONS_LOCKS.pop(key, None)


def reset_all_sanctions_sources() -> None:
    """Reset all three official-list caches (in-memory only)."""
    for source in _SANCTIONS_LISTS:
        reset_sanctions_source(source)


# ----------------------------------------------------------------------------------------------
# Load: process cache -> fresh disk cache -> download -> stale disk cache
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SanctionsEnv:
    """What the loader needs from its caller, resolved per call so the caller's own names stay patchable."""

    log: Callable[..., None]  # (action, target, detail, *, level="info")
    skip: Callable[[str, str, str], None]  # (action, target, reason): a warning-level log
    config_dir: Any  # root of the cache directory tree
    max_list_bytes: int
    monotonic_s: Callable[[], float]
    client_factory: Callable[..., Any]  # netutil.new_async_client
    std_headers: Dict[str, str]


def _sanctions_lock(source: str) -> asyncio.Lock:
    """One lock per (list, running event loop): concurrent screens of one list share one download."""
    return _SANCTIONS_LOCKS.setdefault((source, id(asyncio.get_running_loop())), asyncio.Lock())


async def load_sanctions_index(
    spec: _SanctionsListSpec, target: str, env: SanctionsEnv
) -> Optional[_LoadedSanctionsIndex]:
    """Return the name index of one list (process cache, then fresh disk cache, then download, then stale
    disk cache), or None after logging a skip. Never raises."""
    async with _sanctions_lock(spec.source):
        now = env.monotonic_s()
        loaded = _SANCTIONS_INDEXES.get(spec.source)
        if loaded is not None and now < loaded.expires_at:
            return loaded
        path = sanctions_cache_path(env.config_dir, spec.source)
        age_s = _cache_age_s(path)
        cache_usable = age_s is not None
        if age_s is not None and age_s < SANCTIONS_CACHE_TTL_S:
            records = await _index_cached_file(spec, path, target, env)
            if records is not None:
                env.log(
                    f"{spec.prefix}_INFO", target,
                    f"Loaded {spec.label} from the on-disk cache (downloaded {_iso_utc(time.time() - age_s)})",
                )  # fmt: skip
                return _remember_sanctions_index(spec, records, now + SANCTIONS_CACHE_TTL_S - age_s)
            cache_usable = False
        failed_at = _SANCTIONS_FAILED_AT.get(spec.source)
        if failed_at is not None and now - failed_at < SANCTIONS_RETRY_AFTER_S:
            reason = "download failed recently; not retrying yet"
        else:
            try:
                records = await _download_and_index(spec, path, target, env)
            except Exception as exc:
                _SANCTIONS_FAILED_AT[spec.source] = now
                reason = str(exc) if isinstance(exc, _SourceSkip) else f"{type(exc).__name__}: {exc}"
            else:
                _SANCTIONS_FAILED_AT.pop(spec.source, None)
                return _remember_sanctions_index(spec, records, now + SANCTIONS_CACHE_TTL_S)
        if cache_usable and age_s is not None:
            records = await _index_cached_file(spec, path, target, env)
            if records is not None:
                note = f"{reason}; using cached list from {_iso_utc(time.time() - age_s)}"
                return _remember_sanctions_index(spec, records, now + SANCTIONS_RETRY_AFTER_S, note)
        env.skip(f"{spec.prefix}_SKIP", target, f"{spec.label} unavailable: {reason}")
        return None


def _remember_sanctions_index(
    spec: _SanctionsListSpec, records: List[_SanctionsRecord], expires_at: float, stale_note: str = ""
) -> _LoadedSanctionsIndex:
    loaded = _LoadedSanctionsIndex(records, expires_at, stale_note)
    _SANCTIONS_INDEXES[spec.source] = loaded
    return loaded


async def _index_cached_file(
    spec: _SanctionsListSpec, path: Path, target: str, env: SanctionsEnv
) -> Optional[List[_SanctionsRecord]]:
    """Parse a cached list (re-checked for DTD/NUL first), or log why it cannot be used and return None."""
    try:
        return await asyncio.to_thread(_index_xml_file, spec, path, guard=True)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, _SourceSkip) else f"{type(exc).__name__}: {exc}"
        env.log(f"{spec.prefix}_INFO", target, f"Ignoring unusable cache file for {spec.label}: {reason}", level="warning")
        return None


def _open_sanctions_temp_file(
    spec: _SanctionsListSpec, final_path: Path, target: str, env: SanctionsEnv
) -> Tuple[Path, bool]:
    """A private (0o600) temp file next to the cache entry, or in the system temp dir if the cache dir
    cannot be created. Returns (path, is_cacheable)."""
    try:
        final_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(dir=final_path.parent, prefix=f".{spec.source}-", suffix=".part")
        cacheable = True
    except OSError as exc:
        env.log(
            f"{spec.prefix}_INFO", target,
            f"Sanctions cache directory unavailable ({type(exc).__name__}); downloading to a temporary file without caching",
            level="warning",
        )  # fmt: skip
        fd, name = tempfile.mkstemp(prefix=f"bunnyhole-{spec.source}-", suffix=".xml")
        cacheable = False
    os.close(fd)
    return Path(name), cacheable


async def _download_and_index(
    spec: _SanctionsListSpec, final_path: Path, target: str, env: SanctionsEnv
) -> List[_SanctionsRecord]:
    """Stream one list to a temp file (size cap and DTD guard applied per chunk), index it, then move it
    into the cache with an atomic rename. A failed download or parse leaves no file behind."""
    temp_path, cacheable = _open_sanctions_temp_file(spec, final_path, target, env)
    try:
        await _download_sanctions_to(spec, temp_path, env)
        records = await asyncio.to_thread(_index_xml_file, spec, temp_path, guard=False)
        if cacheable:
            try:
                os.replace(temp_path, final_path)
            except OSError as exc:
                env.log(
                    f"{spec.prefix}_INFO", target,
                    f"Could not write the list cache ({type(exc).__name__}); continuing without it",
                    level="warning",
                )  # fmt: skip
        return records
    finally:
        temp_path.unlink(missing_ok=True)


def _redirect_target(spec: _SanctionsListSpec, current_url: str, location: str) -> str:
    """Resolve a Location header and return it only if it stays on https and on an allowed host."""
    if not location.strip():
        raise _SourceSkip("redirect without a Location header; refused")
    try:
        target = httpx.URL(current_url).join(location.strip())
    except httpx.InvalidURL as exc:
        raise _SourceSkip("redirect to an invalid URL; refused") from exc
    host = (target.host or "").lower()
    own_host = (httpx.URL(spec.xml_url).host or "").lower()
    if target.scheme != "https":
        raise _SourceSkip(f"redirect to a non-https URL ({target.scheme or 'none'}) refused")
    suffixes = spec.redirect_host_suffixes
    if host != own_host and not (suffixes and host.endswith(suffixes)):
        raise _SourceSkip(f"redirect to host {host or 'unknown'} is not allow-listed; refused")
    return str(target)


async def _download_sanctions_to(spec: _SanctionsListSpec, dest: Path, env: SanctionsEnv) -> None:
    headers = dict(env.std_headers)
    headers["Accept"] = "application/xml, text/xml"
    async with env.client_factory(timeout=SANCTIONS_LIST_TIMEOUT_S, headers=headers) as client:
        url = spec.xml_url
        for _hop in range(_SANCTIONS_MAX_REDIRECTS + 1):
            async with client.stream("GET", url) as resp:
                if resp.status_code in _REDIRECT_STATUSES:
                    url = _redirect_target(spec, url, resp.headers.get("location", ""))
                    continue
                await _stream_sanctions_body(resp, dest, env.max_list_bytes)
                return
    raise _SourceSkip("too many redirects")


async def _stream_sanctions_body(resp: httpx.Response, dest: Path, cap: int) -> None:
    """Write the response body to ``dest``, enforcing the size cap and the DTD/NUL guard on every chunk."""
    if resp.status_code != 200:
        raise _SourceSkip(f"HTTP {resp.status_code}")
    declared = resp.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > cap:
        raise _SourceSkip(f"declared size exceeds the {_format_cap(cap)} download cap")
    guard = _XmlStreamGuard()
    received = 0
    with open(dest, "wb") as out:
        async for chunk in resp.aiter_bytes():
            received += len(chunk)
            if received > cap:
                raise _SourceSkip(f"download exceeded the {_format_cap(cap)} cap and was aborted")
            guard.feed(chunk)
            out.write(chunk)
    guard.finish()
