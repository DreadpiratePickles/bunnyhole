"""The case file: what an investigator keeps while working a case.

Three things, all built by code from the evidence, none of them a verdict:

* **Questions** (:func:`open_questions`, :func:`answer_questions`): the client's decision turned into the
  questions it depends on. A case is finished when each is answered or shown to be out of reach on the free
  public record, not when every source has been called.
* **The lead sheet** (:func:`plan_leads`, :func:`develop_leads`): every line of inquiry, why it was opened, what
  opened it, and how it ended. The first leads are the playbook's order of work applied to what the client
  supplied. Every later lead is a pivot off something a lead actually returned: the next owner up the chain, a
  controlling person to screen, a wallet a filing named.
* **The log** (:func:`write_note`): one entry per lead worked. What was done and why, what came back, what it
  means for the questions, what it opened.

Pure: no I/O, no clock, no network. Every function returns new models and leaves its inputs unchanged.

Scope rules an investigator follows and this module enforces when it develops leads:

* A lead is opened only when it serves a question on the board. Nothing is chased because it is there.
* Every node of an ownership chain is screened. Those leads are ``mandatory``: neither a quiet streak nor a
  model's stop request skips them.
* A person found inside an entity case (an owner, a controller) gets the role-relevant checks only: sanctions,
  PEP and adverse media. Their accounts, handles and contact points are not touched.
* A nominee or a registered-agent address is set aside in writing, not followed.
* A handle found on a company's website belongs to a person, so an entity case sets it aside.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple, cast

from bunnyhole.engine.pi import (
    CaseBoard,
    CaseLead,
    CaseNote,
    CaseQuestion,
    CaseTask,
    CaseType,
    Finding,
    LeadKind,
    LeadStatus,
    PIBlock,
    PIEngagement,
    SourceLogEntry,
)
from bunnyhole.engine.pi_dispatch import PI_DISPATCH, source_name, sources_for
from bunnyhole.engine.pi_notes import PLAYBOOK_SOURCE_MAP, SANCTIONS_LISTS
from bunnyhole.engine.pi_reference import Playbook, PlaybookStep
from bunnyhole.engine.pi_report_common import _undecorated
from bunnyhole.engine.pi_runtime import SECRECY_JURISDICTION_CODES, SOURCE_CLASS_MAP

SUGGESTED_NOTE = "Outside this engagement's questions, so not worked. Available to chase."
CHASEABLE = ("suggested", "not_worked", "not_reached")
CHASE_PRIORITY = 95.0
MAX_CHAIN_DEPTH = 5
MAX_DOMAIN_PIVOTS = 3
MAX_WALLET_PIVOTS = 4
MAX_HANDLE_PIVOTS = 2
MAX_CORROBORATIONS = 3
QUIET_STREAK_LIMIT = 3
OFFERED_LEADS = 5

_NAME_TYPES = ("company", "person")
_SETTLED = ("answered", "out_of_reach")
_RAN = ("hit", "negative")
_JURISDICTION_SUFFIX = re.compile(r"\s*\([A-Za-z]{2}(?:-[A-Za-z0-9]+)?\)\s*$")

#: Recorder names of the sanctions and PEP lists, in screening order.
SANCTION_SOURCES: Tuple[str, ...] = tuple(recorder for _display, recorder, _tool in SANCTIONS_LISTS)
#: The four official keyless lists. All four must have run on a name before it counts as screened.
_OFFICIAL_LISTS: Tuple[str, ...] = tuple(r for r in SANCTION_SOURCES if r != "opensanctions")
_OFFICIAL_DISPLAY: Tuple[str, ...] = tuple(d for d, r, _t in SANCTIONS_LISTS if r != "opensanctions")

#: What a client-supplied selector is run through when no playbook step already covers it.
SELECTOR_SOURCES: Dict[str, Tuple[str, ...]] = {
    "domain": ("osint_domain", "wayback"),
    "email": ("email_pivots",),
    "username": ("osint_identity", "hackernews"),
    "phone": ("phone_lookup",),
    "wallet": ("onchain_evm",),
    "bitcoin": ("onchain_bitcoin",),
    "ip": ("ip_shodan_ripestat",),
    "aircraft": ("aircraft_adsb",),
}

#: Sources Bunnyhole runs for a playbook step whose own source list names a registry it cannot query.
#: (case type, step order) -> recorder names, tried in this order after the step's mapped sources.
STEP_EXTRA_SOURCES: Dict[Tuple[CaseType, int], Tuple[str, ...]] = {
    (CaseType.DUE_DILIGENCE, 1): ("gleif", "sec_edgar"),
    (CaseType.ASSET_SEARCH, 1): ("gleif", "wikidata"),
    (CaseType.FRAUD_SCREEN, 1): ("gleif", "wikidata"),
    (CaseType.LOCATE, 3): ("sec_edgar", "wikidata"),
    (CaseType.LOCATE, 5): ("openalex",),
    (CaseType.BACKGROUND, 3): ("wikidata",),
    (CaseType.BACKGROUND, 5): ("openalex",),
}

#: Source classes no automated source reaches, and who or what does.
MANUAL_ROUTES: Dict[str, str] = {
    "missing_persons": "NamUs, the Charley Project and the Doe Network are searched by hand; any possible match "
                       "goes to law enforcement, never to the client",
    "vital_records": "obituaries, vital-statistics offices and custody locators (BOP Inmate Locator) are checked "
                     "by hand",
    "property_assets": "land titles, liens and UCC filings are ordered from the county recorder or land registry "
                       "(Teranet / OnLand in Ontario)",
    "licences": "FINRA BrokerCheck, NMLS Consumer Access and the professional-licence boards are checked by hand",
}


def norm(text: str) -> str:
    """Case-folded, single-spaced text: the key two spellings of one target share."""
    return " ".join(str(text or "").casefold().split())


# ----------------------------------------------------------------------------------------------
# What the case file reads from the graph
# ----------------------------------------------------------------------------------------------


class Subject(NamedTuple):
    """One thing the client supplied: a name or a selector, and the graph node that anchors it."""

    target_type: str
    value: str
    node_id: str


@dataclass(frozen=True)
class GraphView:
    """Plain-dict view of the graph: node labels, types and the pivots the source agents queued."""

    nodes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    leads: Tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def from_graph(cls, graph_dict: Mapping[str, Any], leads: Iterable[Mapping[str, Any]] = ()) -> "GraphView":
        nodes = {str(n.get("id")): n for n in graph_dict.get("nodes") or [] if isinstance(n, Mapping)}
        return cls(nodes=nodes, leads=tuple(lead for lead in leads if isinstance(lead, Mapping)))

    def name(self, node_id: str) -> str:
        """The searchable name of a node: its legal name, else its label without decoration or jurisdiction."""
        node = self.nodes.get(node_id)
        if node is None:
            return node_id
        attrs = node.get("attributes") or {}
        legal = str(attrs.get("legal_name") or "").strip() if isinstance(attrs, Mapping) else ""
        if legal:
            return legal
        label = _undecorated(str(node.get("label") or node_id)).strip()
        return _JURISDICTION_SUFFIX.sub("", label).strip() or node_id

    def entity_type(self, node_id: str) -> str:
        node = self.nodes.get(node_id) or {}
        raw = node.get("entity_type")
        return str(getattr(raw, "value", raw) or "")

    def is_person(self, node_id: str) -> bool:
        return self.entity_type(node_id) == "Person"


def subjects_from_roots(roots: Sequence[Tuple[str, str, Any]]) -> List[Subject]:
    """Client-supplied names and selectors, in the order given. Credentials and documents are never subjects."""
    subjects: List[Subject] = []
    seen: Set[Tuple[str, str]] = set()
    for lead_type, value, node in roots:
        clean = str(value or "").strip()
        if not clean or lead_type in ("credential", "document"):
            continue
        attributes = getattr(node, "attributes", None) or {}
        target_type = lead_type
        if lead_type == "company" and str(attributes.get("seed_type") or "") == "person":
            target_type = "person"
        key = (target_type, norm(clean))
        if key in seen:
            continue
        seen.add(key)
        subjects.append(Subject(target_type, clean, str(getattr(node, "id", "") or "")))
    return subjects


# ----------------------------------------------------------------------------------------------
# Reading the source log
# ----------------------------------------------------------------------------------------------


class _ClassState(NamedTuple):
    state: str  # hit | negative | not_reached | not_run | not_automated
    ran: Tuple[str, ...]
    unreached: Tuple[Tuple[str, str], ...]  # (source, why it was not reached)


_AUTOMATED_CLASSES = frozenset(SOURCE_CLASS_MAP[source] for source in PI_DISPATCH if source in SOURCE_CLASS_MAP)


def class_state(log: Sequence[SourceLogEntry], source_class: str) -> _ClassState:
    """What happened to one source class: a hit, a clean negative, tried and not reached, or never run."""
    if source_class not in _AUTOMATED_CLASSES:
        return _ClassState("not_automated", (), ())
    ran: Dict[str, str] = {}
    unreached: Dict[str, str] = {}
    for entry in log:
        if SOURCE_CLASS_MAP.get(entry.source) != source_class:
            continue
        if entry.status in _RAN:
            if ran.get(entry.source) != "hit":
                ran[entry.source] = entry.status
        elif entry.source not in unreached:
            unreached[entry.source] = entry.detail or entry.status
    missed = tuple((source, why) for source, why in unreached.items() if source not in ran)
    if ran:
        return _ClassState("hit" if "hit" in ran.values() else "negative", tuple(ran), missed)
    if missed:
        return _ClassState("not_reached", (), missed)
    return _ClassState("not_run", (), ())


def _short(text: str, limit: int = 90) -> str:
    flat = " ".join(str(text).split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def _unreached_text(states: Sequence[_ClassState]) -> str:
    parts = [f"{source_name(source)} ({_short(why)})" for state in states for source, why in state.unreached]
    return "not reached: " + "; ".join(dict.fromkeys(parts)) if parts else ""


def _and(items: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    items = [item for item in items if item]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _sources(names: Iterable[str]) -> str:
    return _and(list(dict.fromkeys(source_name(name) for name in names)))


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _end(text: str) -> str:
    """``text`` ending in exactly one full stop (a name such as ``Borealis Holdings B.V.`` already has one)."""
    return text if text.endswith((".", "!", "?")) else text + "."


def _join(parts: Iterable[str]) -> str:
    return "; ".join(part for part in parts if part)


def _named(items: Sequence[str], limit: int = 3) -> str:
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return shown + (f" and {extra} more" if extra > 0 else "")


def _relevant(block: PIBlock, prefixes: Tuple[str, ...]) -> List[Finding]:
    return [
        f for f in block.findings
        if f.relevance in ("subject", "related") and (not prefixes or f.node_id.startswith(prefixes))
    ]


# ----------------------------------------------------------------------------------------------
# The ownership chain above the subject
# ----------------------------------------------------------------------------------------------


class ChainLink(NamedTuple):
    child: str
    parent: str
    depth: int  # 1 = the subject's own owner


def subject_node_ids(block: PIBlock, subjects: Sequence[Subject]) -> Set[str]:
    """The client's anchors plus every record the relevance scorer rates as the subject itself."""
    ids = {subject.node_id for subject in subjects if subject.node_id}
    ids |= {finding.node_id for finding in block.findings if finding.relevance == "subject"}
    return ids


def ownership_chain(block: PIBlock, subjects: Sequence[Subject]) -> List[ChainLink]:
    """Ownership edges reachable upward from the subject, nearest first. Namesakes' chains are left out."""
    depth: Dict[str, int] = dict.fromkeys(subject_node_ids(block, subjects), 0)
    links: List[ChainLink] = []
    seen: Set[Tuple[str, str]] = set()
    changed = True
    while changed:
        changed = False
        for edge in block.ownership.edges:
            if edge.child not in depth or (edge.child, edge.parent) in seen:
                continue
            level = depth[edge.child] + 1
            if level > MAX_CHAIN_DEPTH:
                continue
            seen.add((edge.child, edge.parent))
            links.append(ChainLink(edge.child, edge.parent, level))
            if edge.parent not in depth:
                depth[edge.parent] = level
                changed = True
    return sorted(links, key=lambda link: link.depth)


def _chain_parents(chain: Sequence[ChainLink]) -> List[str]:
    return list(dict.fromkeys(link.parent for link in chain))


def screened_names(log: Sequence[SourceLogEntry]) -> Set[str]:
    """Names every official list has run on (hit or clean negative)."""
    ran: Dict[str, Set[str]] = {}
    for entry in log:
        if entry.source in _OFFICIAL_LISTS and entry.status in _RAN:
            ran.setdefault(norm(entry.target), set()).add(entry.source)
    return {name for name, lists in ran.items() if lists >= set(_OFFICIAL_LISTS)}


# ----------------------------------------------------------------------------------------------
# Questions
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Ctx:
    block: PIBlock
    view: GraphView
    subjects: Tuple[Subject, ...]
    selectors: Mapping[str, Sequence[str]]
    chain: Tuple[ChainLink, ...]


class _Verdict(NamedTuple):
    status: str
    answer: str
    basis: Tuple[str, ...] = ()
    missing: str = ""


@dataclass(frozen=True)
class QuestionSpec:
    key: str
    text: str
    evaluator: str
    classes: Tuple[str, ...] = ()
    prefixes: Tuple[str, ...] = ()
    manual: str = ""


def _eval_identity_entity(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    profile = ctx.block.entity_profile
    registry = class_state(ctx.block.source_log, "corporate_registry")
    if profile is not None and profile.legal_name.strip():
        parts = [f"Registered as {profile.legal_name.strip()}"]
        if profile.jurisdiction.strip():
            parts.append(f"jurisdiction {profile.jurisdiction.strip()}")
        if profile.status.strip():
            parts.append(f"status {profile.status.strip()}")
        if profile.lei.strip():
            parts.append(f"LEI {profile.lei.strip()}")
        answer = ", ".join(parts) + "."
        basis = tuple(profile.sources) or registry.ran
        if profile.status.strip():
            return _Verdict("answered", answer, basis)
        return _Verdict("partial", answer, basis, "registry status: confirm on the primary registry")
    if registry.state in _RAN:
        return _Verdict(
            "partial",
            f"No registry record matched the name in the registries searched ({_sources(registry.ran)}). "
            "That is not proof the entity does not exist.",
            registry.ran,
            _join(["a registration number or the incorporating jurisdiction from the client, then the primary "
                   "registry", _unreached_text([registry])]),
        )
    return _Verdict("open", "", (), _unreached_text([registry]) or "the registries have not been searched yet")


_ANCHOR_KINDS = ("emails", "usernames", "phones", "domains", "wallets")


def _eval_identity_person(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    names = [str(n) for n in ctx.selectors.get("names") or [] if str(n).strip()]
    anchors = [kind for kind in _ANCHOR_KINDS if ctx.selectors.get(kind)]
    notes = len(ctx.block.identity_notes)
    tail = f" {notes} identity note(s) are in the Identity resolution section." if notes else ""
    if names and anchors:
        return _Verdict(
            "answered",
            f"Working identity: {names[0]} plus {len(anchors)} further anchor kind(s) ({', '.join(anchors)}). "
            f"A record that matches the name alone stays a lead (two-anchor rule).{tail}",
            tuple(anchors),
        )
    if names:
        return _Verdict(
            "partial",
            f"Name only ({names[0]}). Every record below is a name match, not an identification.{tail}",
            (),
            "a second anchor from the client: birth year, a prior address, an employer, an email or a username",
        )
    return _Verdict(
        "partial",
        f"No full name on file; the selectors supplied are the only anchors ({', '.join(anchors) or 'none'}).{tail}",
        tuple(anchors),
        "the subject's full legal name from the client",
    )


def _eval_ownership(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    log = ctx.block.source_log
    states = [class_state(log, "beneficial_ownership"), class_state(log, "corporate_registry")]
    ran = tuple(dict.fromkeys(source for state in states for source in state.ran))
    unreached = _unreached_text(states)
    if ctx.chain:
        parents = _chain_parents(ctx.chain)
        children = {link.child for link in ctx.chain}
        people = [parent for parent in parents if ctx.view.is_person(parent)]
        companies = [parent for parent in parents if not ctx.view.is_person(parent)]
        open_tops = [parent for parent in companies if parent not in children]
        levels = max(link.depth for link in ctx.chain)
        parts: List[str] = []
        if people:
            parts.append(
                f"Named as controlling person(s): {_named([ctx.view.name(p) for p in people])} (a registry "
                "declaration: verify identifiers before relying on it)."
            )
        if companies:
            parts.append(_end(
                f"Corporate chain above the subject, {levels} level(s) walked: "
                + " > ".join(ctx.view.name(parent) for parent in companies[:5])
            ))
        if not open_tops:
            return _Verdict("answered", " ".join(parts), tuple(parents))
        stops = _named([ctx.view.name(p) for p in open_tops])
        parts.append(f"The chain stops at {stops}, with no owner behind it on the public record.")
        return _Verdict(
            "partial",
            " ".join(parts),
            tuple(parents),
            _join([
                f"the owner behind {stops}: shareholder register or annual return from the primary registry, or "
                "the registered agent's file by legal process",
                unreached,
            ]),
        )
    if any(state.state in _RAN for state in states):
        return _Verdict(
            "partial",
            f"No parent or controlling person is named in the registries searched ({_sources(ran)}).",
            ran,
            _join(["the shareholder register or annual return from the primary registry", unreached]),
        )
    return _Verdict("open", "", (), unreached or "the ownership sources have not been searched yet")


def _eval_sanctions(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    sanctions = ctx.block.sanctions
    hits = [hit for hit in sanctions.hits if isinstance(hit, Mapping)]
    blocked = list(ctx.block.ownership.blocked_by_50_rule)
    not_screened = [str(item).split(" (", 1)[0].split(":", 1)[0] for item in sanctions.not_screened]
    if hits or blocked:
        named = [f"{hit.get('name') or '?'} ({hit.get('list') or 'list'})" for hit in hits]
        parts = []
        if named:
            parts.append(f"Soft name match: {_named(named)}")
        if blocked:
            parts.append(f"OFAC 50% rule block on {_named([ctx.view.name(b) for b in blocked])}")
        return _Verdict(
            "answered",
            "; ".join(parts) + ". A name match is a lead: verify on the primary list and refer to compliance "
            "counsel before dealing.",
            tuple(str(hit.get("node_id") or "") for hit in hits if hit.get("node_id")),
        )
    if sanctions.status == "not_run":
        reasons = "; ".join(_short(str(item)) for item in sanctions.not_screened[:4])
        return _Verdict("open", "", (), f"no list has been screened yet ({reasons})" if reasons else "")
    screened = screened_names(ctx.block.source_log)
    names = [subject.value for subject in ctx.subjects if subject.target_type in _NAME_TYPES]
    names += [ctx.view.name(parent) for parent in _chain_parents(ctx.chain)]
    names = list(dict.fromkeys(name for name in names if name))
    unscreened = [name for name in names if norm(name) not in screened]
    weak = len(sanctions.weak_matches)
    answer = (
        f"No match on {', '.join(sanctions.screened)} for {len(names) - len(unscreened)} of {len(names)} name(s) "
        f"in scope. Not screened: {', '.join(not_screened) or 'none'}. No hit on a screened list is not clearance."
    )
    if weak:
        answer += f" {weak} weak name match(es) were set aside, not linked: check them by hand."
    official = set(sanctions.screened) >= set(_OFFICIAL_DISPLAY)
    if official and not unscreened:
        return _Verdict("answered", answer, tuple(sanctions.screened), f"manual check of {', '.join(not_screened)}")
    missing = []
    if unscreened:
        missing.append(f"not yet screened on every official list: {_named(unscreened)}")
    if not official:
        missing.append("official lists not reached: " + ", ".join(d for d in _OFFICIAL_DISPLAY if d not in sanctions.screened))
    return _Verdict("partial", answer, tuple(sanctions.screened), _join(missing))


def _eval_classes(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    """A question a set of source classes answers: what they returned about the subject, or a logged negative."""
    log = ctx.block.source_log
    states = [class_state(log, source_class) for source_class in spec.classes]
    automated = [state for state in states if state.state != "not_automated"]
    if not automated:
        return _Verdict("out_of_reach", "No free, lawful, passive source reaches this.", (), spec.manual)
    ran = tuple(dict.fromkeys(source for state in automated for source in state.ran))
    found = _relevant(ctx.block, spec.prefixes)
    if found:
        text = (
            f"{len(found)} record(s) about the subject in {_sources(ran) or 'the sources run'}: "
            f"{_named([_undecorated(f.label) for f in found])}. Each is a lead until a second independent source agrees."
        )
    else:
        text = (
            f"Nothing about the subject in {_sources(ran)}. Absence from the sources searched is not proof of "
            "absence."
        )
    gaps = _join([
        _unreached_text(automated),
        "not searched: " + ", ".join(c for c, s in zip(spec.classes, states) if s.state == "not_run")
        if any(s.state == "not_run" for s in states) else "",
        spec.manual,
    ])
    if all(state.state in _RAN for state in automated):
        return _Verdict("answered", text, tuple(f.node_id for f in found) or ran, spec.manual)
    if any(state.state in _RAN for state in automated):
        return _Verdict("partial", text, tuple(f.node_id for f in found) or ran, gaps)
    return _Verdict("open", "", (), gaps or "the sources for this have not been searched yet")


def _secrecy_code(jurisdiction: str) -> str:
    head = jurisdiction.strip().split(None, 1)[0].split("-", 1)[0] if jurisdiction.strip() else ""
    return head.upper() if len(head) == 2 and head.isalpha() else ""


def _structure_markers(ctx: _Ctx) -> List[str]:
    markers: List[str] = []
    profile = ctx.block.entity_profile
    if profile is not None and _secrecy_code(profile.jurisdiction) in SECRECY_JURISDICTION_CODES:
        markers.append(f"the subject is registered in {profile.jurisdiction}")
    in_scope = {link.parent for link in ctx.chain} | subject_node_ids(ctx.block, ctx.subjects)
    for flag in ctx.block.false_link_flags:
        reason = str(flag.get("reason") or "")
        node_id = str(flag.get("node_id") or "")
        if node_id and node_id not in in_scope:
            continue
        if "nominee" in reason.casefold() or "secrecy" in reason.casefold():
            markers.append(f"{ctx.view.name(node_id)}: {_short(reason, 70)}")
    for parent in _chain_parents(ctx.chain):
        attrs = (ctx.view.nodes.get(parent) or {}).get("attributes") or {}
        code = _secrecy_code(str(attrs.get("jurisdiction") or "")) if isinstance(attrs, Mapping) else ""
        if code in SECRECY_JURISDICTION_CODES:
            markers.append(f"{ctx.view.name(parent)} is registered in {code}")
    return list(dict.fromkeys(markers))


def _eval_structure(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    markers = _structure_markers(ctx)
    profile = ctx.block.entity_profile
    if markers:
        return _Verdict(
            "answered",
            f"Yes: {_named(markers)}. That is a reason to require the beneficial owner in writing, not a "
            "finding against the entity.",
            (),
        )
    if profile is not None and profile.jurisdiction.strip():
        return _Verdict(
            "answered",
            f"Registered in {profile.jurisdiction.strip()}; no secrecy-jurisdiction or nominee marker in the "
            f"{len(_chain_parents(ctx.chain))} chain node(s) walked. FATF list status is checked by hand.",
            tuple(profile.sources),
            "the current FATF high-risk and monitored lists (manual)",
        )
    registry = class_state(ctx.block.source_log, "corporate_registry")
    if registry.state in _RAN:
        return _Verdict(
            "partial", "No jurisdiction is recorded for the subject in the registries searched.", registry.ran,
            "the incorporating jurisdiction from the client or the primary registry",
        )
    return _Verdict("open", "", (), _unreached_text([registry]) or "the registries have not been searched yet")


_ASSET_PREFIXES = ("aircraft:", "wallet:")


def _eval_assets(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    assets = [f for f in ctx.block.findings if f.relevance != "unrelated" and f.node_id.startswith(_ASSET_PREFIXES)]
    log = ctx.block.source_log
    states = [class_state(log, source_class) for source_class in spec.classes]
    manual = MANUAL_ROUTES["property_assets"]
    if assets:
        return _Verdict(
            "partial",
            f"{len(assets)} asset record(s) on the public record: {_named([_undecorated(a.label) for a in assets])}. "
            "A registered owner is not a beneficial owner: tie each to the subject before relying on it.",
            tuple(a.node_id for a in assets),
            manual,
        )
    pending = [s for s in ctx.subjects if s.target_type in ("wallet", "bitcoin", "aircraft")]
    if pending and not any(state.state in _RAN for state in states):
        return _Verdict("open", "", (), _unreached_text(states) or "the asset identifiers supplied have not been run yet")
    return _Verdict(
        "out_of_reach",
        "No asset surfaced on the free layer. Land, lien, vehicle and bank records are not open data here.",
        (),
        manual + "; bank and brokerage records need legal process (see Custodians)",
    )


def _eval_custodians(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    custodians = ctx.block.custodians
    if custodians:
        named = [f"{c.custodian} ({c.instrument})" for c in custodians]
        return _Verdict(
            "answered",
            f"{len(custodians)} custodian(s) named with the instrument that reaches each: {_named(named)}. "
            "Counsel chooses the process; nothing is sent by Bunnyhole.",
            (),
        )
    return _Verdict(
        "out_of_reach",
        "No finding yet points at a record holder (no bank, exchange, registered agent, carrier or registrar "
        "surfaced).",
        (),
        "an account, wallet, phone or domain identifier from the client would name a custodian",
    )


def _eval_shell(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    markers = _structure_markers(ctx)
    for flag in ctx.block.false_link_flags:
        reason = str(flag.get("reason") or "")
        if "registered-agent" in reason.casefold() or "registered agent" in reason.casefold():
            markers.append(_short(reason, 70))
    log = ctx.block.source_log
    states = [class_state(log, source_class) for source_class in spec.classes]
    ran = tuple(dict.fromkeys(source for state in states for source in state.ran))
    if markers:
        return _Verdict(
            "answered",
            f"Shell-company markers present: {_named(list(dict.fromkeys(markers)))}. Each is a flag to explain, "
            "not a finding of fraud.",
            ran,
        )
    if any(state.state in _RAN for state in states):
        status = "answered" if all(state.state in _RAN for state in states) else "partial"
        return _Verdict(
            status,
            f"No nominee, secrecy-jurisdiction or agent-only-address marker in the records pulled ({_sources(ran)}).",
            ran,
            _unreached_text(states) if status == "partial" else "",
        )
    return _Verdict("open", "", (), _unreached_text(states) or "the registries have not been searched yet")


def _eval_clone(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    domains = [s for s in ctx.subjects if s.target_type == "domain"]
    lookalikes = [
        f for f in ctx.block.findings
        if "lookalike" in f.label.casefold() or "typosquat" in f.label.casefold()
        or (f.node_id.startswith("domain:") and "similar" in f.label.casefold())
    ]
    mismatches = [c for c in ctx.block.contradictions if "registry" in f"{c.kind} {c.description}".casefold()]
    if lookalikes or mismatches:
        named = [_undecorated(f.label) for f in lookalikes] + [c.description or c.kind for c in mismatches]
        return _Verdict(
            "answered",
            f"Possible imitation: {_named(named)}. Report it to counsel and the platform's abuse channel.",
            tuple(f.node_id for f in lookalikes),
        )
    if not domains:
        return _Verdict(
            "out_of_reach",
            "No website is on file, so there is nothing to compare a lookalike against.",
            (),
            "the website or email domain the victims dealt with, from the client",
        )
    state = class_state(ctx.block.source_log, "domain_infrastructure")
    if state.state in _RAN:
        return _Verdict(
            "answered",
            f"No lookalike domain or registry mismatch in what {_sources(state.ran)} returned for "
            f"{_named([d.value for d in domains])}.",
            state.ran,
        )
    return _Verdict("open", "", (), _unreached_text([state]) or "the domain has not been examined yet")


def _eval_money(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    wallets = [s for s in ctx.subjects if s.target_type in ("wallet", "bitcoin")]
    exchanges = [
        c for c in ctx.block.custodians
        if any(word in f"{c.finding} {c.custodian} {c.note}".casefold() for word in ("exchange", "cash-out", "cash out"))
    ]
    if exchanges:
        return _Verdict(
            "answered",
            f"The trail reaches {_named([c.custodian for c in exchanges])}; the instrument is "
            f"{exchanges[0].instrument}. Tracing stops at the custodian.",
            (),
        )
    state = class_state(ctx.block.source_log, "crypto_onchain")
    if not wallets and state.state not in _RAN:
        return _Verdict(
            "out_of_reach",
            "No wallet or account identifier is on file, so there is no public ledger to follow.",
            (),
            "payment details from the client (wallet address, IBAN, processor reference); bank records need legal "
            "process",
        )
    if state.state in _RAN:
        return _Verdict(
            "partial",
            f"Public ledgers were read ({_sources(state.ran)}); no cash-out point at a regulated exchange was "
            "identified.",
            state.ran,
            "attribution of the counterparty addresses (a licensed blockchain-analytics provider)",
        )
    return _Verdict("open", "", (), _unreached_text([state]) or "the wallet has not been traced yet")


def _eval_address(ctx: _Ctx, spec: QuestionSpec) -> _Verdict:
    handoff = (
        "confirmation through a licensed credit-header database, then verification in a public place by a "
        "licensed investigator (handoff sheet)"
    )
    addresses = _relevant(ctx.block, ("loc:",))
    if addresses:
        shown = [f"{_undecorated(a.label)} ({a.freshness}, {a.finding_label.value})" for a in addresses]
        return _Verdict(
            "partial",
            f"{len(addresses)} address lead(s) on the public record: {_named(shown)}. None is confirmed as current; "
            "a registered-agent or relative's address is not the subject's.",
            tuple(a.node_id for a in addresses),
            handoff,
        )
    states = [class_state(ctx.block.source_log, source_class) for source_class in spec.classes]
    if any(state.state in _RAN for state in states):
        return _Verdict(
            "out_of_reach", "No address surfaced in the free public record searched.", (), handoff,
        )
    return _Verdict("open", "", (), _unreached_text(states) or "the public record has not been searched yet")


_EVALUATORS: Dict[str, Callable[[_Ctx, QuestionSpec], _Verdict]] = {
    "identity_entity": _eval_identity_entity,
    "identity_person": _eval_identity_person,
    "ownership": _eval_ownership,
    "sanctions": _eval_sanctions,
    "classes": _eval_classes,
    "structure": _eval_structure,
    "assets": _eval_assets,
    "custodians": _eval_custodians,
    "shell": _eval_shell,
    "clone": _eval_clone,
    "money": _eval_money,
    "address": _eval_address,
}

_Q_IDENTITY_ENTITY = QuestionSpec(
    "identity", "Is the subject a real registered entity, and what is its status?", "identity_entity",
    ("corporate_registry",),
)
_Q_IDENTITY_PERSON = QuestionSpec(
    "identity", "Is the subject identified on more than a name?", "identity_person",
)
_Q_OWNERSHIP = QuestionSpec(
    "ownership", "Who owns and controls it, up to a natural person?", "ownership",
    ("beneficial_ownership", "corporate_registry"),
)
_Q_SANCTIONS = QuestionSpec(
    "sanctions", "Is the subject, or anyone in its ownership chain, on a sanctions or PEP list?", "sanctions",
    ("sanctions_pep",),
)
_Q_LITIGATION = QuestionSpec(
    "litigation", "Is there litigation, enforcement action or a complaint pattern?", "classes",
    ("court_dockets", "regulatory_enforcement"), ("docket:", "cfpb:"),
)
_Q_COURTS = QuestionSpec(
    "courts", "Do court records name the subject?", "classes", ("court_dockets",), ("docket:",),
)
_Q_MEDIA = QuestionSpec(
    "adverse_media", "What does published coverage say about the subject?", "classes",
    ("news_adverse_media",), ("article:", "archive:"),
)
_Q_STRUCTURE = QuestionSpec(
    "structure", "Does a secrecy jurisdiction or a nominee arrangement sit in the structure?", "structure",
    ("corporate_registry", "beneficial_ownership"),
)
_Q_ROLES = QuestionSpec(
    "roles", "Which companies does the subject hold, direct or file for?", "classes",
    ("corporate_registry",), ("sec:", "lei:", "company:", "psc:"),
)
_Q_ASSETS = QuestionSpec(
    "assets", "What assets are visible on the public record?", "assets",
    ("property_assets", "crypto_onchain"),
)
_Q_CUSTODIANS = QuestionSpec(
    "custodians", "Who holds the non-public records, and which legal instrument reaches them?", "custodians",
)
_Q_FOOTPRINT = QuestionSpec(
    "footprint", "What public footprint is tied to the selectors supplied?", "classes",
    ("social_osint",), ("account:", "email:", "phone:", "hn:", "openalex:"),
)

_ENTITY_QUESTIONS: Dict[CaseType, Tuple[QuestionSpec, ...]] = {
    CaseType.DUE_DILIGENCE: (
        _Q_IDENTITY_ENTITY, _Q_OWNERSHIP, _Q_SANCTIONS, _Q_LITIGATION, _Q_MEDIA, _Q_STRUCTURE,
    ),
    CaseType.ASSET_SEARCH: (
        _Q_IDENTITY_ENTITY, _Q_OWNERSHIP, _Q_ASSETS, _Q_SANCTIONS,
        QuestionSpec("litigation", "Do the dockets show liens, judgments, bankruptcies or forfeiture actions?",
                     "classes", ("court_dockets",), ("docket:",)),
        _Q_CUSTODIANS,
    ),
    CaseType.FRAUD_SCREEN: (
        QuestionSpec("identity", "Is the entity what it claims to be on the registry?", "identity_entity",
                     ("corporate_registry",)),
        QuestionSpec("complaints", "Is there a pattern of complaints, enforcement or litigation?", "classes",
                     ("regulatory_enforcement", "court_dockets"), ("cfpb:", "docket:")),
        QuestionSpec("shell", "Does it show shell-company markers (nominees, an agent-only address, a secrecy "
                     "jurisdiction)?", "shell", ("corporate_registry", "beneficial_ownership")),
        QuestionSpec("clone", "Is someone imitating it, or is it imitating someone (lookalike domain, registry "
                     "mismatch)?", "clone", ("domain_infrastructure",)),
        _Q_SANCTIONS,
        QuestionSpec("money", "Where does the money trail reach a regulated custodian?", "money",
                     ("crypto_onchain",)),
    ),
}

_PERSON_QUESTIONS: Dict[CaseType, Tuple[QuestionSpec, ...]] = {
    CaseType.LOCATE: (
        _Q_IDENTITY_PERSON,
        QuestionSpec("address", "What current address or contact does the public record support?", "address",
                     ("court_dockets", "corporate_registry", "social_osint")),
        _Q_COURTS,
        _Q_FOOTPRINT,
        QuestionSpec("status", "Is there any sign the subject has died or is in custody?", "classes",
                     ("vital_records",), (), MANUAL_ROUTES["vital_records"]),
    ),
    CaseType.BACKGROUND: (
        _Q_IDENTITY_PERSON, _Q_COURTS, _Q_ROLES,
        QuestionSpec("sanctions", "Is the subject on a sanctions or PEP list?", "sanctions", ("sanctions_pep",)),
        _Q_MEDIA,
        QuestionSpec("licences", "What professional licences and disciplinary records exist?", "classes",
                     ("licences",), (), MANUAL_ROUTES["licences"]),
    ),
    CaseType.MISSING_PERSON: (
        QuestionSpec("identity", "Is the identifier set complete enough to match a record?", "identity_person"),
        QuestionSpec("databases", "Do the public missing and unidentified-persons databases hold a possible match?",
                     "classes", ("missing_persons",), (), MANUAL_ROUTES["missing_persons"]),
        QuestionSpec("status", "Do obituaries, burial or custody records show the subject?", "classes",
                     ("vital_records",), (), MANUAL_ROUTES["vital_records"]),
        _Q_MEDIA, _Q_FOOTPRINT,
    ),
    CaseType.ASSET_SEARCH: (
        _Q_IDENTITY_PERSON, _Q_ROLES, _Q_ASSETS,
        QuestionSpec("sanctions", "Does a sanctions listing block dealing with the subject?", "sanctions",
                     ("sanctions_pep",)),
        QuestionSpec("litigation", "Do the dockets show liens, judgments, bankruptcies or forfeiture actions?",
                     "classes", ("court_dockets",), ("docket:",)),
        _Q_CUSTODIANS,
    ),
    CaseType.DUE_DILIGENCE: (
        _Q_IDENTITY_PERSON, _Q_ROLES,
        QuestionSpec("sanctions", "Is the subject on a sanctions or PEP list?", "sanctions", ("sanctions_pep",)),
        _Q_LITIGATION, _Q_MEDIA,
    ),
    CaseType.FRAUD_SCREEN: (
        _Q_IDENTITY_PERSON,
        QuestionSpec("complaints", "Is there a pattern of complaints, enforcement or litigation?", "classes",
                     ("regulatory_enforcement", "court_dockets"), ("cfpb:", "docket:")),
        QuestionSpec("sanctions", "Is the subject on a sanctions or PEP list?", "sanctions", ("sanctions_pep",)),
        _Q_MEDIA,
        QuestionSpec("money", "Where does the money trail reach a regulated custodian?", "money",
                     ("crypto_onchain",)),
    ),
}

_ENTITY_FALLBACK: Tuple[QuestionSpec, ...] = (_Q_IDENTITY_ENTITY, _Q_SANCTIONS, _Q_LITIGATION, _Q_MEDIA)


def question_specs(case_type: CaseType, subject_is_person: bool) -> Tuple[QuestionSpec, ...]:
    """The questions a case of this type turns on, in the order a report answers them."""
    if subject_is_person:
        return _PERSON_QUESTIONS.get(case_type, _PERSON_QUESTIONS[CaseType.BACKGROUND])
    return _ENTITY_QUESTIONS.get(case_type, _ENTITY_FALLBACK)


def open_questions(case_type: CaseType, subject_is_person: bool) -> List[CaseQuestion]:
    return [CaseQuestion(key=spec.key, text=spec.text) for spec in question_specs(case_type, subject_is_person)]


def answer_questions(
    questions: Sequence[CaseQuestion],
    block: PIBlock,
    view: GraphView,
    subjects: Sequence[Subject],
    selectors: Mapping[str, Sequence[str]],
) -> Tuple[List[CaseQuestion], List[str]]:
    """Re-read every question against the evidence as it stands. Returns the questions and the keys that moved."""
    specs = {spec.key: spec for spec in question_specs(block.engagement.case_type, block.engagement.subject_is_person)}
    ctx = _Ctx(block, view, tuple(subjects), selectors, tuple(ownership_chain(block, subjects)))
    updated: List[CaseQuestion] = []
    changed: List[str] = []
    for question in questions:
        spec = specs.get(question.key)
        if spec is None:
            updated.append(question)
            continue
        verdict = _EVALUATORS[spec.evaluator](ctx, spec)
        fresh = question.model_copy(update={
            "status": verdict.status, "answer": verdict.answer,
            "basis": [item for item in verdict.basis if item], "missing": verdict.missing,
        })
        if fresh.status != question.status or fresh.answer != question.answer:
            changed.append(question.key)
        updated.append(fresh)
    return updated, changed


def questions_settled(questions: Sequence[CaseQuestion]) -> bool:
    """Every question is answered or documented as out of reach. An empty board is not settled."""
    return bool(questions) and all(question.status in _SETTLED for question in questions)


def question_tally(questions: Sequence[CaseQuestion]) -> str:
    counts: Dict[str, int] = {}
    for question in questions:
        counts[question.status] = counts.get(question.status, 0) + 1
    order = (("answered", "answered"), ("partial", "partly answered"), ("out_of_reach", "out of reach"), ("open", "open"))
    return ", ".join(f"{counts[key]} {label}" for key, label in order if counts.get(key)) or "no questions"


# ----------------------------------------------------------------------------------------------
# The lead sheet
# ----------------------------------------------------------------------------------------------


def _questions_for(sources: Sequence[str], specs: Sequence[QuestionSpec]) -> List[str]:
    classes = {SOURCE_CLASS_MAP.get(source) for source in sources}
    return [spec.key for spec in specs if classes & set(spec.classes)]


_LeadKey = Tuple[str, str, str, Optional[int]]


def _lead_key(lead: CaseLead) -> _LeadKey:
    return (lead.kind, lead.target_type, norm(lead.target), lead.step_order)


class _Sheet:
    """Leads being added to a board: numbers them, drops repeats and sources that already ran or are planned."""

    def __init__(self, existing: Sequence[CaseLead], done: Set[Tuple[str, str]], specs: Sequence[QuestionSpec]) -> None:
        self.existing = list(existing)
        self._count = len(existing)
        self._keys = {_lead_key(lead) for lead in existing}
        self._planned = {
            (source, norm(lead.target)) for lead in existing if lead.status == "open" for source in lead.sources
        } | set(done)
        self._specs = specs
        self.added: List[CaseLead] = []

    def add(
        self, kind: str, target_type: str, target: str, why: str, sources: Sequence[str], *,
        priority: float, opened_by: str = "intake", node_id: str = "", depth: int = 0,
        step_order: Optional[int] = None, mandatory: bool = False, questions: Optional[Sequence[str]] = None,
        keep_done_sources: bool = False, status: str = "open", outcome: str = "",
    ) -> Optional[CaseLead]:
        """Add a lead unless it repeats one. Returns ``None`` when nothing new would run and nothing is recorded."""
        key: _LeadKey = (kind, target_type, norm(target), step_order)
        if not target.strip() or key in self._keys:
            return None
        runnable = sources_for(target_type, list(sources))
        if not keep_done_sources:
            runnable = [source for source in runnable if (source, norm(target)) not in self._planned]
        if status == "open" and not runnable:
            return None
        serves = list(questions) if questions is not None else _questions_for(runnable, self._specs)
        if status == "open" and not serves and kind != "playbook":
            # Nothing on the board needs it, so it is not worked. It stays on the sheet for the investigator.
            status, outcome = "suggested", SUGGESTED_NOTE
        self._count += 1
        lead = CaseLead(
            lead_id=f"L{self._count}", kind=cast(LeadKind, kind), target=target.strip(), target_type=target_type,
            node_id=node_id, why=why, opened_by=opened_by, questions=serves, sources=runnable, priority=priority,
            depth=depth, step_order=step_order, mandatory=mandatory, status=cast(LeadStatus, status),
            outcome=outcome,
        )
        self._keys.add(key)
        if status == "open":
            self._planned |= {(source, norm(target)) for source in runnable}
        self.added.append(lead)
        return lead


def step_recorders(playbook: Playbook, step: PlaybookStep) -> List[str]:
    """Recorder names a playbook step maps to, then the extras for that step. Unmapped sources give nothing."""
    names: List[str] = []
    for listed in step.sources:
        for recorder in PLAYBOOK_SOURCE_MAP.get(listed) or ():
            if recorder not in names:
                names.append(recorder)
    for recorder in STEP_EXTRA_SOURCES.get((playbook.case_type, step.order), ()):
        if recorder not in names:
            names.append(recorder)
    return names


def plan_leads(
    playbook: Playbook, subjects: Sequence[Subject], engagement: PIEngagement
) -> Tuple[List[CaseLead], List[Tuple[str, str]]]:
    """The opening lead sheet: the playbook's order of work applied to what the client supplied.

    Each playbook step becomes one lead per subject it has a source for. A source only runs on the kind of target
    it is built for, so a domain tool never receives a name. A later step may list a source an earlier step already
    pulled: that lead costs nothing and is read from the records on file. Selectors no step covers get a lead of
    their own. Returns the leads and the ``(source, target)`` pairs the playbook names but casework must not run
    (the caller logs them as skipped).
    """
    specs = question_specs(engagement.case_type, engagement.subject_is_person)
    sheet = _Sheet([], set(), specs)
    blocked: List[Tuple[str, str]] = []
    for step in playbook.steps:
        if step.cost == "handoff":
            continue
        recorders = step_recorders(playbook, step)
        for recorder in recorders:
            if recorder not in PI_DISPATCH and subjects and all(recorder != name for name, _target in blocked):
                blocked.append((recorder, subjects[0].value))
        for subject in subjects:
            sheet.add(
                "playbook", subject.target_type, subject.value, _short(step.action, 220), recorders,
                priority=90.0 - 4.0 * step.order, node_id=subject.node_id, step_order=step.order, mandatory=True,
                keep_done_sources=True,
            )
    if any(spec.key == "sanctions" for spec in specs):
        # The engagement asks whether the subject is listed. A playbook step may name one list only; the subject
        # is screened on every list casework can reach, before any of its owners are.
        screen_at = _stage_priority(sheet.added, SANCTION_SOURCES, 76.0) - 0.2
        for subject in subjects:
            if subject.target_type in _NAME_TYPES:
                sheet.add(
                    "screen", subject.target_type, subject.value,
                    "The engagement asks whether the subject is on a sanctions or PEP list: screen the name on "
                    "every official list, not only the one the playbook step names.",
                    SANCTION_SOURCES, priority=screen_at, node_id=subject.node_id, mandatory=True,
                )
    for subject in subjects:
        extra = SELECTOR_SOURCES.get(subject.target_type, ())
        sheet.add(
            "selector", subject.target_type, subject.value,
            f"The client supplied this {subject.target_type}: establish what it is attached to before relying on it.",
            extra, priority=70.0, node_id=subject.node_id, mandatory=True,
        )
        local = subject.value.split("@", 1)[0].strip() if subject.target_type == "email" else ""
        supplied = {norm(s.value) for s in subjects if s.target_type == "username"}
        if engagement.subject_is_person and len(local) >= 3 and norm(local) not in supplied:
            sheet.add(
                "pivot", "username", local,
                f"Handle guessed from the local part of {subject.value}. It is a guess: an account is attached only "
                "when a second anchor agrees (two-anchor rule).",
                ("osint_identity",), priority=44.0, node_id=subject.node_id, depth=1,
            )
    return sheet.added, blocked


def _flagged_not_a_link(block: PIBlock, node_id: str) -> str:
    for flag in block.false_link_flags:
        if str(flag.get("node_id") or "") != node_id:
            continue
        reason = str(flag.get("reason") or "")
        if "nominee" in reason.casefold():
            return reason
    return ""


def _count_kind(leads: Iterable[CaseLead], kind: str, target_type: str) -> int:
    return sum(1 for lead in leads if lead.kind == kind and lead.target_type == target_type)


def _stage_priority(leads: Sequence[CaseLead], sources: Iterable[str], default: float) -> float:
    """Priority of the playbook stage that runs ``sources``: a pivot is worked right after its own stage.

    The subject is always handled first. Its owners are walked after the subject's ownership step and screened
    after the subject's own screening, never before.
    """
    wanted = set(sources)
    stages = [lead.priority for lead in leads if lead.kind == "playbook" and wanted & set(lead.sources)]
    return min(stages) if stages else default


def develop_leads(
    board: CaseBoard,
    block: PIBlock,
    view: GraphView,
    subjects: Sequence[Subject],
    done: Set[Tuple[str, str]],
    *,
    opened_by: str,
) -> List[CaseLead]:
    """New leads the evidence now supports. Called after every lead is worked; repeats are never re-opened.

    In order: the next owner up the chain (walk it, and screen it), controlling persons (screen only), records
    that contradict each other (pull the registry again), single-source owners (a second registry), and the pivots
    the source agents queued off the subject's own selectors (wallets, sister domains, handles).
    """
    engagement = block.engagement
    specs = question_specs(engagement.case_type, engagement.subject_is_person)
    keys = {spec.key for spec in specs}
    sheet = _Sheet(board.leads, done, specs)
    chain = ownership_chain(block, subjects)
    in_scope = subject_node_ids(block, subjects) | {link.parent for link in chain}
    media = ["news_narrative"] if "adverse_media" in keys else []
    walk_at = _stage_priority(board.leads, ("uk_psc", "gleif"), 80.0) - 0.5
    screen_at = _stage_priority(board.leads, SANCTION_SOURCES, 76.0) - 0.5

    if "sanctions" in keys or "ownership" in keys:
        for link in chain:
            name = view.name(link.parent)
            child = view.name(link.child)
            not_a_link = _flagged_not_a_link(block, link.parent)
            if not_a_link:
                sheet.add(
                    "screen", "person" if view.is_person(link.parent) else "company", name,
                    _end(f"{name} is named above {child}"), (), priority=0.0, opened_by=opened_by, node_id=link.parent,
                    depth=link.depth, status="set_aside",
                    outcome=f"Not a link: {_short(not_a_link, 120)}. A nominee is not a beneficial owner.",
                )
                continue
            if view.is_person(link.parent):
                sheet.add(
                    "screen", "person", name,
                    f"{name} is named as a controlling person of {_end(child)} Screen the name against the sanctions "
                    "and PEP lists" + (" and read the coverage" if media else "") + ". Role-relevant checks only: "
                    "this person is not the subject.",
                    [*SANCTION_SOURCES, *media], priority=screen_at - 0.1 * link.depth, opened_by=opened_by,
                    node_id=link.parent, depth=link.depth, mandatory=True,
                )
                continue
            if "ownership" in keys:
                sheet.add(
                    "ownership", "company", name,
                    f"{name} is named as an owner of {_end(child)} Pull its registry record and find who owns it: the "
                    "walk continues until a natural person or a documented stop.",
                    ("gleif", "uk_psc"), priority=walk_at - 0.1 * link.depth, opened_by=opened_by,
                    node_id=link.parent, depth=link.depth,
                )
            sheet.add(
                "screen", "company", name,
                f"{name} sits in the ownership chain above {_end(child)} Every node of the chain is screened, not only "
                "the subject.",
                SANCTION_SOURCES, priority=screen_at - 0.1 * link.depth, opened_by=opened_by, node_id=link.parent,
                depth=link.depth, mandatory=True,
            )

    for contradiction in block.contradictions:
        node_id = next((n for n in contradiction.node_ids if n in in_scope), "")
        if not node_id:
            continue
        if node_id.startswith("lei:"):
            sources: Tuple[str, ...] = ("gleif",)
        elif node_id.startswith(("company:", "psc:")):
            sources = ("uk_psc",)
        else:
            sources = ("sec_edgar", "gleif")
        sheet.add(
            "contradiction", "company", view.name(node_id),
            f"Two records disagree ({_short(contradiction.description or contradiction.kind, 110)}). Pull the registry "
            "again to see which is current: a conflict between records is a lead, not noise.",
            sources, priority=66.0, opened_by=opened_by, node_id=node_id,
        )

    if "ownership" in keys:
        single = {f.node_id for f in block.findings if f.source_count <= 1}
        for link in chain:
            if _count_kind([*board.leads, *sheet.added], "corroborate", "company") >= MAX_CORROBORATIONS:
                break
            if link.depth != 1 or link.parent not in single or view.is_person(link.parent):
                continue
            name = view.name(link.parent)
            sheet.add(
                "corroborate", "company", name,
                f"{name} is named as owner by one source only. Look for it in a second, independent registry "
                "before relying on the link.",
                ("sec_edgar", "wikidata"), priority=55.0, opened_by=opened_by, node_id=link.parent, depth=1,
                questions=["ownership"],
            )

    _adopt_agent_pivots(sheet, board, block, view, subjects, in_scope, opened_by)
    return sheet.added


def _adopt_agent_pivots(
    sheet: _Sheet, board: CaseBoard, block: PIBlock, view: GraphView, subjects: Sequence[Subject],
    in_scope: Set[str], opened_by: str,
) -> None:
    """Pivots the source agents queued, kept only when they hang off the subject.

    One that serves a question on the board is opened. One that does not is written down as ``suggested``: a real
    lead, outside what the client asked, that the investigator may choose to chase.
    """
    anchors = {subject.node_id: subject for subject in subjects if subject.node_id}
    for raw in view.leads:
        if raw.get("explored"):
            continue
        lead_type = str(raw.get("lead_type") or "")
        value = str(raw.get("seed_value") or "").strip()
        origin = str(raw.get("origin_node_id") or "")
        reason = _short(str(raw.get("reason") or ""), 140)
        if not value or "[DEAD-END BYPASS]" in reason:
            continue  # a guessed stem is not evidence of anything
        current = [*board.leads, *sheet.added]
        if lead_type in ("wallet", "bitcoin") and origin in in_scope:
            if _count_kind(current, "pivot", lead_type) < MAX_WALLET_PIVOTS:
                sheet.add(
                    "pivot", lead_type, value, f"{reason}. Follow it to a cash-out point, then stop.",
                    SELECTOR_SOURCES[lead_type], priority=60.0, opened_by=opened_by, depth=1,
                )
        elif lead_type == "domain" and origin in anchors:
            if _count_kind(current, "pivot", "domain") < MAX_DOMAIN_PIVOTS:
                sheet.add(
                    "pivot", "domain", value,
                    f"{reason}. A shared certificate is a lead to common control, and shared hosting is not a link: "
                    "check what the domain is before relying on it.",
                    SELECTOR_SOURCES["domain"], priority=48.0, opened_by=opened_by, depth=1,
                )
        elif lead_type == "company" and origin in in_scope and norm(value) not in {norm(view.name(n)) for n in in_scope}:
            sheet.add(
                "pivot", "company", value, f"{reason}. A related company the registry record named.",
                ("gleif", "uk_psc", *SANCTION_SOURCES), priority=58.0, opened_by=opened_by, node_id=origin, depth=1,
                questions=[],
            )
        elif lead_type == "username" and origin in anchors:
            if not block.engagement.subject_is_person:
                sheet.add(
                    "pivot", "username", value, f"{reason}.", (), priority=0.0, opened_by=opened_by,
                    status="set_aside",
                    outcome="Set aside: a personal handle found on the company's site belongs to a person, and "
                            "this engagement is about the entity.",
                )
            elif _count_kind(current, "pivot", "username") < MAX_HANDLE_PIVOTS + 1:
                sheet.add(
                    "pivot", "username", value,
                    f"{reason}. Attached to the subject only if a second anchor agrees.",
                    ("osint_identity",), priority=46.0, opened_by=opened_by, depth=1,
                )


# ----------------------------------------------------------------------------------------------
# Working the sheet
# ----------------------------------------------------------------------------------------------


def _lead_number(lead: CaseLead) -> int:
    digits = "".join(ch for ch in lead.lead_id if ch.isdigit())
    return int(digits) if digits else 0


def open_leads(board: CaseBoard) -> List[CaseLead]:
    """Open leads, the one to work next first: highest priority, then the order they were opened."""
    leads = [lead for lead in board.leads if lead.status == "open"]
    return sorted(leads, key=lambda lead: (-lead.priority, _lead_number(lead)))


def lead_tasks(lead: CaseLead, done: Set[Tuple[str, str]]) -> List[CaseTask]:
    """One task per source of the lead that has not already run on its target."""
    return [
        CaseTask(
            task_id=f"{lead.lead_id}:{source}", origin=lead.kind, step_order=lead.step_order, source=source,
            target=lead.target, why=lead.why,
        )
        for source in lead.sources
        if (source, norm(lead.target)) not in done
    ]


def lead_offer(lead: CaseLead) -> CaseTask:
    """A lead as the guide sees it: the id it may choose, what would run, on what, and why."""
    return CaseTask(
        task_id=lead.lead_id, origin=lead.kind, step_order=lead.step_order,
        source=", ".join(lead.sources) or "records on file", target=lead.target, why=lead.why,
    )


def replace_lead(board: CaseBoard, lead: CaseLead) -> CaseBoard:
    return board.model_copy(update={
        "leads": [lead if item.lead_id == lead.lead_id else item for item in board.leads]
    })


def retire_unneeded(board: CaseBoard) -> CaseBoard:
    """Close optional leads whose questions are all settled: the objective is met, the pivot no longer pays.

    A lead the case officer opened is left alone: it was a decision about this case, not a rule firing.
    """
    settled = {question.key for question in board.questions if question.status in _SETTLED}
    leads: List[CaseLead] = []
    for lead in board.leads:
        optional = lead.status == "open" and not lead.mandatory and "case officer" not in lead.opened_by
        if optional and lead.questions and set(lead.questions) <= settled:
            lead = lead.model_copy(update={
                "status": "not_worked",
                "outcome": "Not needed: the question it serves is already settled.",
            })
        leads.append(lead)
    return board.model_copy(update={"leads": leads})


def close_remaining(board: CaseBoard, reason: str, *, keep_mandatory: bool = False) -> CaseBoard:
    """Mark every open lead as not worked, with the reason. ``keep_mandatory`` leaves the mandatory ones open."""
    leads = [
        lead.model_copy(update={"status": "not_worked", "outcome": reason})
        if lead.status == "open" and not (keep_mandatory and lead.mandatory) else lead
        for lead in board.leads
    ]
    return board.model_copy(update={"leads": leads})


def _entries_for(lead: CaseLead, log: Sequence[SourceLogEntry]) -> Dict[str, SourceLogEntry]:
    latest: Dict[str, SourceLogEntry] = {}
    target = norm(lead.target)
    for entry in log:
        if entry.source in lead.sources and norm(entry.target) == target:
            latest[entry.source] = entry
    return latest


def settle_lead(lead: CaseLead, log: Sequence[SourceLogEntry], *, relevant_new: int, moved: bool) -> CaseLead:
    """Close a worked lead from what its sources returned.

    ``worked``: it produced a record about the subject or moved a question. ``negative``: its sources ran clean
    and found nothing (a logged negative). ``not_reached``: every source was refused or failed, so nothing was
    searched.
    """
    entries = _entries_for(lead, log)
    statuses = [entry.status for entry in entries.values()]
    parts = [
        f"{source} {entry.status}" + (f" ({_short(entry.detail, 60)})" if entry.status in ("skipped", "error") and entry.detail else "")
        for source, entry in entries.items()
    ]
    if relevant_new or moved or "hit" in statuses:
        status = "worked"
    elif "negative" in statuses:
        status = "negative"
    else:
        status = "not_reached"
    return lead.model_copy(update={
        "status": cast(LeadStatus, status), "outcome": "; ".join(parts) or "no source returned a result",
    })


def _question_title(key: str) -> str:
    return key.replace("_", " ").capitalize()


_STATUS_PROSE: Dict[str, str] = {
    "open": "open", "partial": "partly answered", "answered": "answered", "out_of_reach": "out of reach",
}
_QUIET_READS: Dict[str, str] = {
    "ownership": "No owner is recorded above {target} in the sources reached. On the public record the chain "
                 "stops here: the next step is the primary registry or the registered agent's file (see Custodians).",
    "screen": "No list entry matched {target} on the lists that ran. That is a logged negative, not a clearance.",
    "corroborate": "No second source names {target}, so the link still rests on a single source.",
    "contradiction": "The registry returned nothing that settles the conflict. It stays open as a contradiction.",
}
_QUIET_DEFAULT = "Nothing about the subject came back. Logged as a negative, not as a clearance."
_NOT_REACHED_READ = (
    "No source could be reached, so nothing was searched. This is a gap in coverage, not a negative result."
)


_KIND_VERBS: Dict[str, str] = {
    "playbook": "worked",
    "selector": "examined",
    "ownership": "walked upward",
    "screen": "screened",
    "corroborate": "checked against a second source",
    "contradiction": "pulled again from the registry",
    "pivot": "followed",
}
_OPENED_PHRASES: Dict[str, str] = {
    "ownership": "walk the ownership of {target}",
    "screen": "screen {target}",
    "corroborate": "find a second source for {target}",
    "contradiction": "settle the conflicting records on {target}",
    "pivot": "follow {target}",
    "selector": "examine {target}",
    "playbook": "work {target}",
}


def _found_prose(lead: CaseLead, entries: Mapping[str, SourceLogEntry], ran_now: Set[str], any_ran: bool) -> str:
    """What each source returned, in sentences: records, nothing, or not reached and why."""
    hits = [source for source, entry in entries.items() if entry.status == "hit"]
    negatives = [source for source, entry in entries.items() if entry.status == "negative"]
    missed = [(source, entry) for source, entry in entries.items() if entry.status in ("skipped", "error")]
    earlier = [source for source in entries if any_ran and source not in ran_now]
    parts: List[str] = []
    if hits:
        parts.append(f"{_cap(_sources(hits))} returned {'a record' if len(hits) == 1 else 'records'}.")
    if negatives:
        parts.append(f"{_cap(_sources(negatives))} returned nothing.")
    for source, entry in missed:
        why = f" ({_short(entry.detail, 110)})" if entry.detail else ""
        parts.append(f"{_cap(source_name(source))} could not be reached{why}.")
    if earlier:
        parts.append(f"{_cap(_sources(earlier))} had already been pulled for an earlier lead.")
    return " ".join(parts) or "No source returned a result."


def write_note(
    seq: int,
    lead: CaseLead,
    *,
    ran: Sequence[CaseTask],
    log: Sequence[SourceLogEntry],
    new_relevant: Sequence[Finding],
    new_total: int,
    before: Sequence[CaseQuestion],
    after: Sequence[CaseQuestion],
    hypotheses_changed: Sequence[Tuple[str, str]],
    opened: Sequence[CaseLead],
    counsel: str = "",
) -> CaseNote:
    """One log entry, in the order an investigator writes it: did, found, read, next. Plain sentences."""
    step = f", step {lead.step_order} of the playbook," if lead.step_order is not None else ""
    ran_now = {task.source for task in ran}
    verb = _KIND_VERBS.get(lead.kind, "worked")
    why = _end(lead.why.rstrip()) if lead.why.strip() else ""
    if ran:
        count = "One source was" if len(ran) == 1 else f"{len(ran)} sources were"
        did = (
            f"{lead.lead_id}{step} was {verb} on {_end(lead.target)} {why} "
            f"{count} run: {_sources(task.source for task in ran)}."
        )
    else:
        did = (
            f"{lead.lead_id}{step} was {verb} on {lead.target} from records already on file "
            f"({_sources(lead.sources) or 'none'} had run for an earlier lead), so it cost no new call. {why}"
        )
    entries = _entries_for(lead, log)
    found = _found_prose(lead, entries, ran_now, bool(ran))
    if ran:
        if not new_total:
            found += " No new record came back."
        elif not new_relevant:
            found += f" {new_total} new record(s) came back, none about the subject or its chain."
        else:
            found += (
                f" {new_total} new record(s) came back, {len(new_relevant)} about the subject or its chain: "
                f"{_and([_undecorated(f.label) for f in new_relevant][:4])}."
            )
    prior = {question.key: question for question in before}
    reads: List[str] = []
    for question in after:
        old = prior.get(question.key)
        if old is None or (old.status == question.status and old.answer == question.answer):
            continue
        if old.status != question.status:
            moved = f"moved from {_STATUS_PROSE.get(old.status, old.status)} to {_STATUS_PROSE.get(question.status, question.status)}"
        else:
            moved = f"is still {_STATUS_PROSE.get(question.status, question.status)}, with more detail"
        reads.append(f"The {_question_title(question.key).lower()} question {moved}. {question.answer or _cap(question.missing)}")
    reads += [f"The hypothesis '{_short(text, 90)}' is now {status.replace('_', ' ')}." for text, status in hypotheses_changed]
    if not reads and not ran:
        # A step read from records already on file: say where its questions stand on those records.
        reads = [
            f"On those records the {_question_title(q.key).lower()} question is {_STATUS_PROSE.get(q.status, q.status)}. "
            f"{q.answer or _cap(q.missing)}"
            for q in after if q.key in lead.questions and (q.answer or q.missing)
        ]
    if reads:
        read = " ".join(reads)
    elif lead.status == "not_reached":
        read = _NOT_REACHED_READ
    else:
        read = _QUIET_READS.get(lead.kind, _QUIET_DEFAULT).format(target=lead.target)
    worked_next = [
        f"{item.lead_id} ({_OPENED_PHRASES.get(item.kind, 'work {target}').format(target=item.target)})"
        for item in opened if item.status == "open"
    ]
    aside = [f"{item.lead_id} ({item.target}: {_short(item.outcome, 90)})" for item in opened if item.status == "set_aside"]
    noted = [f"{item.lead_id} ({item.target_type}: {item.target})" for item in opened if item.status == "suggested"]
    parts = []
    if worked_next:
        parts.append("This opened " + _and(worked_next) + ".")
    if aside:
        parts.append("Set aside: " + "; ".join(aside) + ".")
    if noted:
        parts.append("Noted for the investigator, outside the questions asked: " + _and(noted) + ".")
    return CaseNote(
        seq=seq, lead_id=lead.lead_id, did=did, found=found, read=read,
        next=" ".join(parts) or "No new lead.", counsel=counsel,
    )


# ----------------------------------------------------------------------------------------------
# Chasing leads after the case stops
# ----------------------------------------------------------------------------------------------


def chaseable_leads(board: CaseBoard) -> List[CaseLead]:
    """Leads the investigator may reopen: suggested, not worked, or never reached. Set-aside leads are not.

    A lead set aside as a nominee, as a personal handle inside an entity case, or on the client's instruction
    stays set aside: those were decisions about scope, not about time.
    """
    return [lead for lead in board.leads if lead.status in CHASEABLE and lead.sources]


def reopen_leads(board: CaseBoard, lead_ids: Sequence[str]) -> Tuple[CaseBoard, List[CaseLead], List[str]]:
    """Reopen the named leads at the front of the sheet. Returns the board, the reopened leads and refusals."""
    wanted = {str(lead_id).strip().upper() for lead_id in lead_ids if str(lead_id).strip()}
    allowed = {lead.lead_id.upper(): lead for lead in chaseable_leads(board)}
    known = {lead.lead_id.upper(): lead for lead in board.leads}
    refused: List[str] = []
    for lead_id in sorted(wanted):
        if lead_id in allowed:
            continue
        lead = known.get(lead_id)
        if lead is None:
            refused.append(f"{lead_id}: no such lead on the sheet")
        elif lead.status == "set_aside":
            refused.append(f"{lead_id}: set aside on scope grounds, not available to chase")
        else:
            refused.append(f"{lead_id}: already {lead.status.replace('_', ' ')}")
    reopened: List[CaseLead] = []
    leads: List[CaseLead] = []
    for lead in board.leads:
        if lead.lead_id.upper() in wanted and lead.lead_id.upper() in allowed:
            lead = lead.model_copy(update={
                "status": "open", "mandatory": True, "priority": CHASE_PRIORITY,
                "outcome": "Reopened at the investigator's direction.",
            })
            reopened.append(lead)
        leads.append(lead)
    return board.model_copy(update={"leads": leads}), reopened, refused


# ----------------------------------------------------------------------------------------------
# Leads the AI case officer proposes
# ----------------------------------------------------------------------------------------------

MAX_PROPOSALS_PER_TURN = 3
MAX_OFFICER_LEADS = 12
OFFICER_PRIORITY = 62.0
_PERSON_IN_ENTITY_CASE = (*SANCTION_SOURCES, "news_narrative")
_NODE_TARGET_TYPES: Dict[str, str] = {
    "Person": "person", "Organization": "company", "ShellCompany": "company", "Domain": "domain",
}


class Target(NamedTuple):
    """Something in the evidence a lead may be opened on. The type comes from the record, never from a model."""

    name: str
    target_type: str
    node_id: str
    is_subject: bool


def known_targets(block: PIBlock, view: GraphView, subjects: Sequence[Subject]) -> Dict[str, Target]:
    """Names a lead may target: the client's own selectors, records about the subject, and its ownership chain.

    Nothing else can be a target. A name a model produces that is not in this map is refused, so a model cannot
    point the investigation at someone the evidence never named.
    """
    targets: Dict[str, Target] = {}
    for subject in subjects:
        targets.setdefault(norm(subject.value), Target(subject.value, subject.target_type, subject.node_id, True))
    in_chain = {link.parent for link in ownership_chain(block, subjects)}
    for finding in block.findings:
        if finding.relevance not in ("subject", "related") and finding.node_id not in in_chain:
            continue
        entity = view.entity_type(finding.node_id)
        target_type = _NODE_TARGET_TYPES.get(entity)
        if finding.node_id.startswith("wallet:"):
            target_type = "bitcoin" if finding.node_id.startswith("wallet:btc:") else "wallet"
        if target_type is None or finding.node_id.startswith(("sanction:", "article:", "sec:", "docket:")):
            continue
        name = view.name(finding.node_id)
        if finding.node_id.startswith("wallet:"):
            name = finding.node_id.rsplit(":", 1)[-1]
        targets.setdefault(norm(name), Target(name, target_type, finding.node_id, finding.relevance == "subject"))
    return targets


class Proposal(NamedTuple):
    target: str
    sources: Tuple[str, ...]
    why: str


def admit_proposals(
    board: CaseBoard,
    proposals: Sequence[Proposal],
    block: PIBlock,
    view: GraphView,
    subjects: Sequence[Subject],
    done: Set[Tuple[str, str]],
    *,
    opened_by: str,
) -> Tuple[List[CaseLead], List[str]]:
    """Turn a case officer's proposed leads into leads, or refuse them with a reason.

    The officer chooses the target and the sources. Code decides whether that is allowed: the target must be in
    the evidence, each source must be one casework may run and must fit the kind of target, a person who is not
    the subject gets the role-relevant checks only, and a person subject's case never opens a lead on another
    person. A proposal that serves no question on the board is recorded as ``suggested``, not worked.
    """
    engagement = block.engagement
    specs = question_specs(engagement.case_type, engagement.subject_is_person)
    sheet = _Sheet(board.leads, done, specs)
    targets = known_targets(block, view, subjects)
    officer_leads = sum(1 for lead in board.leads if "case officer" in lead.opened_by)
    refused: List[str] = []
    for proposal in list(proposals)[:MAX_PROPOSALS_PER_TURN]:
        label = _short(proposal.target, 60)
        target = targets.get(norm(proposal.target))
        if target is None:
            refused.append(f"'{label}': not a name in the evidence")
            continue
        if officer_leads + len(sheet.added) >= MAX_OFFICER_LEADS:
            refused.append(f"'{label}': the case officer's lead allowance is used up")
            continue
        wanted = [source for source in proposal.sources if source in PI_DISPATCH]
        if target.target_type == "person" and not target.is_subject:
            if engagement.subject_is_person:
                refused.append(f"'{label}': another person is outside this engagement")
                continue
            wanted = [source for source in wanted if source in _PERSON_IN_ENTITY_CASE]
        if not sources_for(target.target_type, wanted):
            refused.append(f"'{label}': none of the sources named may run on a {target.target_type}")
            continue
        lead = sheet.add(
            "pivot", target.target_type, target.name, _short(proposal.why, 240) or "Opened by the case officer.",
            wanted, priority=OFFICER_PRIORITY, opened_by=f"{opened_by} (case officer)", node_id=target.node_id,
            depth=1,
        )
        if lead is None:
            refused.append(f"'{label}': those sources already ran on it, or the lead is already on the sheet")
    return sheet.added, refused


def set_aside_leads(board: CaseBoard, reasons: Mapping[str, str]) -> Tuple[CaseBoard, List[str]]:
    """Set aside the open, optional leads a case officer named. A mandatory lead cannot be set aside."""
    wanted = {str(key).strip().upper(): _short(str(value), 160) for key, value in reasons.items()}
    done: List[str] = []
    leads: List[CaseLead] = []
    for lead in board.leads:
        reason = wanted.get(lead.lead_id.upper())
        if reason is not None and lead.status == "open" and not lead.mandatory:
            lead = lead.model_copy(update={
                "status": "set_aside",
                "outcome": f"Set aside by the case officer: {reason or 'no reason given'}",
            })
            done.append(lead.lead_id)
        leads.append(lead)
    return board.model_copy(update={"leads": leads}), done


def lead_tally(leads: Sequence[CaseLead]) -> str:
    counts: Dict[str, int] = {}
    for lead in leads:
        counts[lead.status] = counts.get(lead.status, 0) + 1
    order = (
        ("worked", "worked"), ("negative", "negative"), ("not_reached", "not reached"),
        ("set_aside", "set aside"), ("not_worked", "not worked"), ("suggested", "suggested"), ("open", "open"),
    )
    return ", ".join(f"{counts[key]} {label}" for key, label in order if counts.get(key)) or "no leads"


def stop_summary(board: CaseBoard) -> str:
    """Where the case stands, for the stop line: the question tally and the questions still not settled."""
    unsettled = [f"{question.key} ({question.status})" for question in board.questions if question.status not in _SETTLED]
    text = question_tally(board.questions)
    if unsettled:
        text += "; not settled: " + ", ".join(unsettled)
    return text


__all__ = [
    "CHASEABLE",
    "MANUAL_ROUTES",
    "MAX_CHAIN_DEPTH",
    "MAX_OFFICER_LEADS",
    "MAX_PROPOSALS_PER_TURN",
    "Proposal",
    "Target",
    "admit_proposals",
    "chaseable_leads",
    "known_targets",
    "reopen_leads",
    "set_aside_leads",
    "OFFERED_LEADS",
    "QUIET_STREAK_LIMIT",
    "SANCTION_SOURCES",
    "SELECTOR_SOURCES",
    "STEP_EXTRA_SOURCES",
    "ChainLink",
    "GraphView",
    "QuestionSpec",
    "Subject",
    "answer_questions",
    "class_state",
    "close_remaining",
    "develop_leads",
    "lead_offer",
    "lead_tally",
    "lead_tasks",
    "norm",
    "open_leads",
    "open_questions",
    "ownership_chain",
    "plan_leads",
    "question_specs",
    "question_tally",
    "questions_settled",
    "replace_lead",
    "retire_unneeded",
    "screened_names",
    "settle_lead",
    "step_recorders",
    "stop_summary",
    "subject_node_ids",
    "subjects_from_roots",
    "write_note",
]
