"""PI stream ownership walk, OFAC 50% rule and false-link guards.

Pure logic: the network fetcher that resolves "who owns this entity?" is injected, so this module is
fully testable offline. Everything here encodes the investigator's second rule: *know what is not a
link*. A shared registered-agent address, a nominee officer on hundreds of entities, a shared
hosting provider or a very common name is not evidence of a relationship.
See docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.3.
"""

from __future__ import annotations

import logging
import re
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel

from bunnyhole.engine.pi import OwnershipBlock, OwnershipEdge
from bunnyhole.engine.pi_identity import is_common_name

logger = logging.getLogger(__name__)

DEFAULT_MAX_LEVELS = 5
OFAC_BLOCKING_THRESHOLD_PCT = 50.0
DEFAULT_NOMINEE_THRESHOLD = 25
SHARED_ENTITY_COUNT_THRESHOLD = 25  # an address or IP tied to this many entities/domains is shared infrastructure

# ----------------------------------------------------------------------------------------------
# Ownership walk
# ----------------------------------------------------------------------------------------------


class OwnerLink(BaseModel):
    """One ownership relationship as returned by a fetcher: ``parent`` owns the node that was queried."""

    parent_id: str
    parent_name: str
    pct: Optional[float] = None
    is_natural_person: bool = False
    source: str = ""
    as_of: str = ""


Fetcher = Callable[[str], Awaitable[List[OwnerLink]]]

_UNRESOLVED_SUFFIX = re.compile(r"\s+\((?:fetch failed|max_levels reached|circular ownership)[^)]*\)$")
_REASON_NO_OWNERS = ""  # plain id: the registry returned no owners for a non-person node
_REASON_MAX_LEVELS = "max_levels reached"
_REASON_CIRCULAR = "circular ownership, no natural person reached"


def unresolved_node_id(entry: str) -> str:
    """Strip the reason suffix from an ``OwnershipBlock.unresolved`` entry, returning the bare node id.

    ``walk_ownership`` records *why* a node is unresolved inside the string, in one of the forms
    ``"<id>"`` (no owners found), ``"<id> (fetch failed: <ExcType>: <message>)"``,
    ``"<id> (max_levels reached)"`` or ``"<id> (circular ownership, no natural person reached)"``.
    """
    return _UNRESOLVED_SUFFIX.sub("", entry)


async def walk_ownership(
    start_id: str, fetch_owners: Fetcher, *, max_levels: int = DEFAULT_MAX_LEVELS
) -> OwnershipBlock:
    """Walk ownership upward from ``start_id`` one layer at a time (breadth-first).

    * ``fetch_owners(node_id)`` returns the owners of that node; it is called at most once per node.
    * Natural persons end a branch and are never fetched. A visited set guards against cycles.
    * ``levels_walked`` is the depth of the deepest ownership edge discovered (start node = level 0).
    * Non-person nodes the walk could not take further are listed in ``unresolved`` with the reason
      embedded in the string (see :func:`unresolved_node_id`): no owners returned, fetch failure,
      ``max_levels`` reached, or a closed ownership loop that never reaches a natural person.
    * A fetcher exception never propagates and is never swallowed silently: it is logged at WARNING
      and recorded as an unresolved entry carrying the exception type and message.
    * ``blocked_by_50_rule`` is left empty here; run :func:`apply_50_percent_rule` on the edges.
    """
    edges: Dict[Tuple[str, str], OwnershipEdge] = {}
    unresolved: Dict[str, str] = {}  # node id -> reason ("" = plain)
    person_ids: Set[str] = set()
    visited: Set[str] = {start_id}
    frontier: List[str] = [start_id]
    levels_walked = 0

    for level in range(1, max_levels + 1):
        if not frontier:
            break
        next_frontier: List[str] = []
        for node_id in frontier:
            try:
                owners = await fetch_owners(node_id)
            except Exception as exc:  # noqa: BLE001 - recorded, logged, never raised (see docstring)
                reason = f"fetch failed: {type(exc).__name__}: {exc}"
                logger.warning("ownership fetch failed for %s: %s: %s", node_id, type(exc).__name__, exc)
                unresolved.setdefault(node_id, reason)
                continue
            if not owners:
                unresolved.setdefault(node_id, _REASON_NO_OWNERS)
                continue
            for owner in owners:
                key = (node_id, owner.parent_id)
                if key not in edges:
                    edges[key] = OwnershipEdge(
                        child=node_id, parent=owner.parent_id, pct=owner.pct, source=owner.source, as_of=owner.as_of
                    )
                    levels_walked = max(levels_walked, level)
                if owner.is_natural_person:
                    person_ids.add(owner.parent_id)
                    continue
                if owner.parent_id not in visited:
                    visited.add(owner.parent_id)
                    next_frontier.append(owner.parent_id)
        frontier = next_frontier

    for node_id in frontier:  # discovered but not expanded because the level cap was reached
        unresolved.setdefault(node_id, _REASON_MAX_LEVELS)

    _flag_closed_loops(edges, person_ids, unresolved)

    return OwnershipBlock(
        levels_walked=levels_walked,
        edges=list(edges.values()),
        blocked_by_50_rule=[],
        unresolved=[f"{nid} ({reason})" if reason else nid for nid, reason in unresolved.items()],
    )


def _flag_closed_loops(
    edges: Dict[Tuple[str, str], OwnershipEdge], person_ids: Set[str], unresolved: Dict[str, str]
) -> None:
    """Report nodes that can reach neither a natural person nor an already-reported dead end.

    That only happens inside a closed ownership loop (A owns B owns A), which a pure visited-set walk
    would otherwise end silently with nothing unresolved.
    """
    reaches_terminal: Set[str] = set(person_ids) | set(unresolved)
    changed = True
    while changed:
        changed = False
        for (child, parent), _edge in edges.items():
            if child not in reaches_terminal and parent in reaches_terminal:
                reaches_terminal.add(child)
                changed = True
    nodes = {child for child, _ in edges} | {parent for _, parent in edges}
    for node_id in sorted(nodes - reaches_terminal - person_ids):
        unresolved.setdefault(node_id, _REASON_CIRCULAR)


# ----------------------------------------------------------------------------------------------
# OFAC 50 percent rule
# ----------------------------------------------------------------------------------------------


def apply_50_percent_rule(edges: List[OwnershipEdge], listed_ids: Set[str]) -> List[str]:
    """Return the sorted ids of entities blocked by the OFAC 50% rule, excluding ``listed_ids`` themselves.

    An entity is blocked when the summed ownership held by blocked owners (the listed ids plus entities
    already blocked by this rule) is at least 50%. Iterates to a fixed point, so a blocked parent blocks
    its own majority-owned subsidiary. ``pct=None`` counts as 0. Duplicate (child, parent) edges, for
    example the same stake reported by two sources, count once at the highest reported percentage.
    """
    stake: Dict[Tuple[str, str], float] = {}
    for edge in edges:
        pct = max(0.0, edge.pct) if edge.pct is not None else 0.0
        key = (edge.child, edge.parent)
        stake[key] = max(stake.get(key, 0.0), pct)

    by_child: Dict[str, List[Tuple[str, float]]] = {}
    for (child, parent), pct in stake.items():
        by_child.setdefault(child, []).append((parent, pct))

    blocked: Set[str] = set(listed_ids)
    changed = True
    while changed:
        changed = False
        for child, owners in by_child.items():
            if child in blocked:
                continue
            held = sum(pct for parent, pct in owners if parent in blocked)
            if round(held, 6) >= OFAC_BLOCKING_THRESHOLD_PCT:
                blocked.add(child)
                changed = True
    return sorted(blocked - set(listed_ids))


# ----------------------------------------------------------------------------------------------
# False-link guards
# ----------------------------------------------------------------------------------------------

# Lowercase fragments of well-known registered-agent, mass-registration and virtual-office addresses,
# plus generic wording. Matched after normalisation (punctuation -> spaces) with a leading word
# boundary, so "1209 orange st" matches "1209 Orange Street" but "8 the green" does not match
# "18 The Green". These show up as the "shared address" of thousands of unrelated companies.
REGISTERED_AGENT_ADDRESS_MARKERS: Tuple[str, ...] = (
    # Delaware
    "1209 orange st", "251 little falls", "2711 centerville", "8 the green", "874 walker rd",
    "3500 s dupont hwy", "16192 coastal hwy", "1521 concord pike", "2140 s dupont hwy", "1013 centre rd",
    # Wyoming / Nevada
    "30 n gould st", "1712 pioneer ave", "5830 e 2nd st", "1309 coffeen ave", "401 ryland st",
    "2360 corporate cir", "3773 howard hughes pkwy",
    # Florida virtual office
    "1000 brickell",
    # London mass-registration addresses
    "20 22 wenlock rd", "71 75 shelton st", "27 old gloucester st", "128 city rd", "167 169 great portland st",
    "kemp house",
    # Offshore registered-office buildings
    "ugland house", "trident chambers", "craigmuir chambers", "wickhams cay",
    # Generic wording
    "registered agent", "registered office", "national registered agents", "corporation trust center",
    "virtual office", "mail forwarding", "c/o",
)  # fmt: skip

# Providers whose address/IP/ASN is shared by huge numbers of unrelated customers. Matched on word boundaries.
HOSTING_PROVIDER_MARKERS: Tuple[str, ...] = (
    "cloudflare", "godaddy", "amazon", "amazonaws", "aws", "namecheap", "wix", "squarespace",
    "google cloud", "googleusercontent", "microsoft azure", "azure", "digitalocean", "ovh", "hetzner",
    "linode", "akamai", "fastly", "hostgator", "bluehost", "siteground", "hostinger", "ionos",
    "shopify", "weebly", "automattic", "wordpress", "vercel", "netlify", "github", "heroku",
    "rackspace", "dreamhost", "liquid web", "contabo", "vultr", "oracle cloud",
)  # fmt: skip


def _normalise_for_match(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9/]+", " ", text.lower()).split())


_REGISTERED_AGENT_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(r"(?<![a-z0-9])" + re.escape(_normalise_for_match(marker)))
    for marker in REGISTERED_AGENT_ADDRESS_MARKERS
)
_HOSTING_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = tuple(
    (marker, re.compile(r"(?<![a-z0-9])" + re.escape(marker) + r"(?![a-z0-9])")) for marker in HOSTING_PROVIDER_MARKERS
)


def is_registered_agent_address(address: str) -> bool:
    """True when the address contains a known registered-agent / virtual-office / mass-registration marker."""
    text = _normalise_for_match(address)
    return bool(text) and any(p.search(text) for p in _REGISTERED_AGENT_PATTERNS)


def nominee_flags(officer_entity_counts: Dict[str, int], threshold: int = DEFAULT_NOMINEE_THRESHOLD) -> List[dict]:
    """Flag officers appearing on ``threshold`` or more entities: professional nominees, not real links.

    Sorted by entity count descending, then officer name.
    """
    flagged = [
        {
            "officer": officer,
            "entities": count,
            "reason": (
                f"appears as an officer of {count} entities (>= {threshold}): likely a professional nominee or "
                "formation agent, not evidence of a real relationship between those entities"
            ),
        }
        for officer, count in officer_entity_counts.items()
        if count >= threshold
    ]
    return sorted(flagged, key=lambda f: (-f["entities"], f["officer"]))


def _hosting_provider(value: str) -> Optional[str]:
    text = value.lower()
    for marker, pattern in _HOSTING_PATTERNS:
        if pattern.search(text):
            return marker
    return None


def false_link_reason(shared_attribute_kind: str, value: str, *, entity_count: Optional[int] = None) -> Optional[str]:
    """Explain why a shared attribute is NOT evidence of a link, or return None for a real link candidate.

    ``shared_attribute_kind`` (case-insensitive): ``address``, ``officer``, ``ip`` / ``hosting`` or ``name``.
    ``entity_count`` is how many entities/domains share the value, when known. An unknown kind has no
    known false-link pattern and so also returns None.
    """
    kind = shared_attribute_kind.strip().lower()
    many = entity_count is not None and entity_count >= SHARED_ENTITY_COUNT_THRESHOLD

    if kind == "address":
        if is_registered_agent_address(value):
            return "registered-agent / virtual-office / mass-registration address shared by unrelated companies"
        if many:
            return f"address is shared by {entity_count} entities: shared infrastructure, not a relationship"
        return None
    if kind == "officer":
        if many:
            return f"officer serves {entity_count} entities: likely a professional nominee or formation agent"
        if "nominee" in value.lower():
            return "officer name indicates a nominee service"
        return None
    if kind in ("ip", "hosting"):
        provider = _hosting_provider(value)
        if provider is not None:
            return f"shared hosting / CDN provider ({provider}): thousands of unrelated sites share it"
        if many:
            return f"IP/hosting value is shared by {entity_count} domains: shared hosting, not a relationship"
        return None
    if kind == "name":
        if is_common_name(value):
            return "very common name: a name match alone does not identify the same person"
        return None
    return None
