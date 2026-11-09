"""PI stream analysis notes: identity-resolution notes, playbook progress and escalation triggers.

Everything here is a deterministic function over plain dicts (``graph.to_dict()`` shape), the source log and a
playbook from ``pi_reference``. Nodes are never merged and nothing claims more than the anchors support.
Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md section 4.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from bunnyhole.engine.pi import (
    Contradiction,
    Custodian,
    EscalationTrigger,
    Finding,
    FindingLabel,
    OwnershipBlock,
    PlaybookProgress,
    SanctionsScreening,
    SourceLogEntry,
)
from bunnyhole.engine.pi_escalation import FIFTY_RULE_NOT_EVALUABLE, SANCTIONS_PRIMARY_URLS, fifty_rule_not_evaluable
from bunnyhole.engine.pi_graph_access import (
    _ADDRESS_ATTRS,
    _clean_label,
    _is_external,
    _receipts,
    _val,
)
from bunnyhole.engine.pi_identity import MatchVerdict, PersonRecord, name_variants, score_same_person
from bunnyhole.engine.pi_reference import Playbook
from bunnyhole.engine.pi_relevance import name_match_level
from bunnyhole.engine.pi_ubo import unresolved_node_id

# ----------------------------------------------------------------------------------------------
# U1: identity resolution notes (deterministic; nodes are never merged)
# ----------------------------------------------------------------------------------------------

MAX_IDENTITY_NOTES = 12
MAX_RECORDS_PER_NAME_GROUP = 40
SUBJECT_NOT_ANCHORED_NOTE = (
    "subject not anchored: name alone is not an identity. Fewer than two identifiers (name, username, email, "
    "phone, wallet, domain) came with the request, so any same-name record below is a lead, not this person."
)
_DOB_KEYS = ("dob_year", "birth_year", "date_of_birth", "date_of_birth_or_build", "dob", "birth_date", "born")
_DEATH_KEYS = ("date_of_death", "death_date", "died")
_COUNTRY_KEYS = ("countries", "country", "country_of_residence")
_PERSON_ADDRESS_KEYS = _ADDRESS_ATTRS + ("addresses",)
_ANCHOR_SELECTOR_KEYS = ("names", "usernames", "emails", "phones", "wallets", "domains")
_YEAR = re.compile(r"\b(1[89]\d\d|20[0-2]\d)\b")


def _as_text_list(value: Any) -> List[str]:
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple, set)) else [value]
    return [str(item).strip() for item in items if item is not None and str(item).strip()]


def _birth_year(attrs: Mapping[str, Any]) -> Optional[int]:
    for key in _DOB_KEYS:
        for text in _as_text_list(attrs.get(key)):
            match = _YEAR.search(text)
            if match:
                return int(match.group(1))
    return None


def _countries(attrs: Mapping[str, Any]) -> Set[str]:
    return {text.upper() for key in _COUNTRY_KEYS for text in _as_text_list(attrs.get(key))}


def _is_subject_anchor(node: Mapping[str, Any]) -> bool:
    """The seed/subject node: it has receipts but none from an external source."""
    receipts = _receipts(node)
    return bool(receipts) and not any(_is_external(r) for r in receipts)


def _person_records(
    nodes: Sequence[Mapping[str, Any]], selectors: Mapping[str, Sequence[str]], subject_is_person: bool
) -> List[Tuple[PersonRecord, Set[str], str]]:
    """``(record, countries, node_id)`` for every Person node that carries a usable name, in graph order."""
    out: List[Tuple[PersonRecord, Set[str], str]] = []
    for node in nodes:
        node_id = str(node.get("id"))
        if str(_val(node.get("entity_type"))) != "Person":
            continue
        if node_id.startswith("profile:") or "USER_CONFIRMED_TARGET_BUNDLE" in (node.get("risk_flags") or []):
            continue
        attrs = node.get("attributes") or {}
        name = _clean_label(str(attrs.get("caption") or node.get("label") or ""))
        if not name_variants(name):
            continue
        age = attrs.get("age")
        emails = _as_text_list(attrs.get("email")) + _as_text_list(attrs.get("emails"))
        phones = _as_text_list(attrs.get("phone")) + _as_text_list(attrs.get("phones"))
        if subject_is_person and _is_subject_anchor(node):  # the subject's own record carries the intake anchors
            emails += list(selectors.get("emails") or [])
            phones += list(selectors.get("phones") or [])
        receipts = _receipts(node)
        out.append(
            (
                PersonRecord(
                    name=name,
                    dob_year=_birth_year(attrs),
                    age=int(age) if isinstance(age, (int, float)) and not isinstance(age, bool) else None,
                    addresses=[a for key in _PERSON_ADDRESS_KEYS for a in _as_text_list(attrs.get(key))],
                    phones=phones,
                    emails=emails,
                    deceased=bool(attrs.get("deceased")) or any(attrs.get(k) for k in _DEATH_KEYS),
                    source=str(receipts[0].get("tool") or "") if receipts else "",
                ),
                _countries(attrs),
                node_id,
            )
        )
    return out


def _find_root(parent: Dict[int, int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]
        i = parent[i]
    return i


def _union(parent: Dict[int, int], a: int, b: int) -> None:
    root_a, root_b = _find_root(parent, a), _find_root(parent, b)
    if root_a != root_b:
        parent[max(root_a, root_b)] = min(root_a, root_b)


def _name_groups(records: Sequence[PersonRecord]) -> List[List[int]]:
    """Group record indices whose names are the same or variants of each other (nickname, initial, hyphen)."""
    variants = [name_variants(r.name) for r in records]
    parent = {i: i for i in range(len(records))}
    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            if variants[j][0] in variants[i] or variants[i][0] in variants[j]:
                _union(parent, i, j)
    groups: Dict[int, List[int]] = {}
    for i in range(len(records)):
        groups.setdefault(_find_root(parent, i), []).append(i)
    return [groups[root] for root in sorted(groups)]


def _why_not_same(match: Any) -> str:
    if match.disqualifiers:
        return "; ".join(match.disqualifiers)
    if match.anchors:
        return f"anchors [{', '.join(match.anchors)}] too weak to merge (score {match.score:.2f})"
    return "name only, no corroborating anchor"


def identity_notes_for(
    nodes: Sequence[Mapping[str, Any]], selectors: Mapping[str, Sequence[str]], subject_is_person: bool
) -> List[str]:
    """Notes on who the Person nodes are. Never merges anything and never claims more than the anchors support.

    * a standing note when the subject is a person but the intake carried fewer than two anchors;
    * ``N records named X are NOT established as one person`` where same-name records score only possible or
      different (with the reasons: a name alone is never an identity);
    * ``records A and B: probable same person on anchors [...]`` where two or more non-name anchors agree.
    """
    notes: List[str] = []
    if subject_is_person:
        anchors = {
            str(v).strip().lower()
            for key in _ANCHOR_SELECTOR_KEYS
            for v in (selectors.get(key) or [])
            if str(v).strip()
        }
        if len(anchors) < 2:
            notes.append(SUBJECT_NOT_ANCHORED_NOTE)

    triples = _person_records(nodes, selectors, subject_is_person)
    records = [t[0] for t in triples]
    countries = [t[1] for t in triples]
    for group in _name_groups(records):
        if len(group) < 2:
            continue
        compared = group[:MAX_RECORDS_PER_NAME_GROUP]
        probable: List[str] = []
        parent = {i: i for i in compared}
        weak: List[Tuple[int, int, Any]] = []
        for a_pos, i in enumerate(compared):
            for j in compared[a_pos + 1 :]:
                match = score_same_person(records[i], records[j])
                if match.verdict in (MatchVerdict.SAME, MatchVerdict.PROBABLE):
                    _union(parent, i, j)
                    wording = (
                        "same person (verdict same)" if match.verdict is MatchVerdict.SAME else "probable same person"
                    )
                    probable.append(
                        f"records '{records[i].name}' ({records[i].source or 'no source'}) and '{records[j].name}' "
                        f"({records[j].source or 'no source'}): {wording} on anchors [{', '.join(match.anchors)}] "
                        f"(score {match.score:.2f}); still two records, not merged"
                    )
                else:
                    weak.append((i, j, match))
        not_established = [(i, j, m) for i, j, m in weak if _find_root(parent, i) != _find_root(parent, j)]
        if not_established:
            examples: List[str] = []
            for i, j, match in not_established[:2]:
                text = f"'{records[i].name}' vs '{records[j].name}': {match.verdict.value}: {_why_not_same(match)}"
                if countries[i] and countries[j] and not (countries[i] & countries[j]):
                    text += f"; countries differ ({'/'.join(sorted(countries[i]))} vs {'/'.join(sorted(countries[j]))})"
                examples.append(text)
            more = len(not_established) - len(examples)
            notes.append(
                f"{len(group)} records named '{records[group[0]].name}' are NOT established as one person "
                f"({len(not_established)} pair(s) possible/different; " + "; ".join(examples)
                + (f"; +{more} more" if more > 0 else "") + ")"
            )
        notes.extend(probable[:3])

    if len(notes) > MAX_IDENTITY_NOTES:
        omitted = len(notes) - (MAX_IDENTITY_NOTES - 1)
        notes = notes[: MAX_IDENTITY_NOTES - 1] + [f"+{omitted} more identity note(s) omitted"]
    return notes


# ----------------------------------------------------------------------------------------------
# U2: playbook progress and escalation triggers
# ----------------------------------------------------------------------------------------------

#: Playbook source name (``pi_reference.SOURCES``) -> the recorder source name(s) that really query it.
#: Deliberately small and explicit: a name that is not listed (or that no agent queries) is reported as not
#: automated, never guessed (the EU Sanctions Map has no source, so a step that lists it can never be ``done``). ``Holehe`` maps to the blocker's log name so the step shows it as skipped.
PLAYBOOK_SOURCE_MAP: Dict[str, Tuple[str, ...]] = {
    "CourtListener / RECAP": ("court_dockets",),
    "GLEIF LEI Search": ("gleif",),
    "OpenSanctions": ("opensanctions",),
    "GAC Canadian Sanctions (SEMA)": ("ca_sanctions",),
    "OFAC Sanctions List Search": ("ofac_sdn",),
    "UN Security Council Consolidated List": ("un_consolidated",),
    "UK OFSI Consolidated List": ("uk_sanctions_list",),
    "Companies House": ("uk_psc",),
    "Companies House PSC (UK)": ("uk_psc",),
    "SEC EDGAR": ("sec_edgar",),
    "CFPB Consumer Complaints": ("cfpb_complaints",),
    "Wikidata": ("wikidata",),
    "Wayback Machine": ("wayback",),
    "Google News": ("news_narrative",),
    "USAspending": ("nonprofit_990s",),
    "crt.sh": ("osint_domain",),
    "urlscan.io": ("osint_domain",),
    "Shodan": ("ip_shodan_ripestat",),
    "Blockscout": ("onchain_evm",),
    "mempool.space": ("onchain_bitcoin",),
    "adsb.lol": ("aircraft_adsb",),
    "Holehe": ("holehe",),
}


def playbook_progress_for(playbook: Playbook, source_log: Sequence[SourceLogEntry]) -> List[PlaybookProgress]:
    """One :class:`PlaybookProgress` per playbook step, computed only from what the source log says ran.

    ``done`` = every source the step lists is mapped to a recorder source that ran (hit or negative); ``partial`` =
    at least one ran; ``not_run`` = none did (skipped, errored, unmapped and not-dispatched sources never count);
    ``handoff`` = the step belongs to the licensed layer or counsel. A ``done`` step still means "the automated
    sources ran", not that the investigation of that topic is complete.
    """
    ran: Dict[str, str] = {}
    failed: Dict[str, Tuple[str, str]] = {}
    for entry in source_log:
        if entry.status in ("hit", "negative"):
            if ran.get(entry.source) != "hit":
                ran[entry.source] = entry.status
        elif entry.source not in failed:
            failed[entry.source] = (entry.status, entry.detail)

    progress: List[PlaybookProgress] = []
    for step in playbook.steps:
        if step.cost == "handoff":
            progress.append(
                PlaybookProgress(
                    order=step.order, action=step.action, sources=list(step.sources), status="handoff",
                    evidence="needs the licensed layer or counsel; see the handoff sheet (Bunnyhole does not run it)",
                )
            )
            continue
        if not step.sources:
            progress.append(
                PlaybookProgress(
                    order=step.order, action=step.action, sources=[], status="not_run",
                    evidence="no automated source for this step (manual or gating step)",
                )
            )
            continue
        did: List[str] = []
        trouble: List[str] = []
        idle: List[str] = []
        unautomated: List[str] = []
        for name in step.sources:
            recorder_names = PLAYBOOK_SOURCE_MAP.get(name)
            if not recorder_names:
                unautomated.append(name)
                continue
            hits = [ran[r] for r in recorder_names if r in ran]
            if hits:
                did.append(f"{name} ({'hit' if 'hit' in hits else 'negative'})")
                continue
            problems = [failed[r] for r in recorder_names if r in failed]
            if problems:
                status, detail = problems[0]
                trouble.append(f"{name} ({status}: {detail})" if detail else f"{name} ({status})")
            else:
                idle.append(name)
        parts: List[str] = []
        if did:
            parts.append("ran: " + ", ".join(did))
        if trouble:
            parts.append("did not run: " + ", ".join(trouble))
        if idle:
            parts.append("not dispatched this run: " + ", ".join(idle))
        if unautomated:
            parts.append("not automated: " + ", ".join(unautomated))
        status_value = "not_run" if not did else ("done" if len(did) == len(step.sources) else "partial")
        progress.append(
            PlaybookProgress(
                order=step.order, action=step.action, sources=list(step.sources),
                status=status_value, evidence="; ".join(parts),
            )
        )
    return progress


# ----------------------------------------------------------------------------------------------
# Sanctions screening: what actually ran, and what it found
# ----------------------------------------------------------------------------------------------

#: (display name, recorder source name, receipt tool prefix). All five must be screened for ``lists_run``.
SANCTIONS_LISTS: Tuple[Tuple[str, str, str], ...] = (
    ("Canada SEMA", "ca_sanctions", "gac_sema_sanctions"),
    ("OpenSanctions", "opensanctions", "opensanctions_yente"),
    ("OFAC SDN", "ofac_sdn", "ofac_sdn"),
    ("UN Consolidated List", "un_consolidated", "un_consolidated"),
    ("UK Sanctions List", "uk_sanctions_list", "uk_sanctions_list"),
)
SOFT_MATCH_NOTE = "soft: verify on the primary list"
#: The EU consolidated list has no automated source, so it is named as NOT screened in every run, including a
#: ``lists_run`` one (``lists_run`` still means the five automated lists above all ran).
EU_LIST_NOT_SCREENED = "EU Consolidated List: not automated (verify at https://www.sanctionsmap.eu/)"


def _list_status(source_log: Sequence[SourceLogEntry], recorder_name: str) -> Tuple[bool, str]:
    """``(screened, reason it was not)``. Screened means a hit or negative entry exists for the source."""
    entries = [e for e in source_log if e.source == recorder_name]
    if any(e.status in ("hit", "negative") for e in entries):
        return True, ""
    failures = [e for e in entries if e.status in ("skipped", "error")]
    if failures:
        last = failures[-1]
        return False, f"{last.status}: {last.detail}" if last.detail else last.status
    return False, "not run this session"


def sanctions_screening_for(
    source_log: Sequence[SourceLogEntry],
    nodes: Sequence[Mapping[str, Any]],
    relevance_by_node: Optional[Mapping[str, str]] = None,
) -> Tuple[SanctionsScreening, List[str]]:
    """Which sanctions lists ran, which did not (with the reason), and the soft hits on nodes the lists produced.

    ``status`` is ``lists_run`` only when all five lists were screened, ``not_run`` when none was, else
    ``partial``. The EU consolidated list is never automated, so ``not_screened`` always ends with it
    (``EU_LIST_NOT_SCREENED``), whatever the status. A hit is always a soft name match. A listed node whose name does not resemble the subject
    (``relevance_by_node`` says ``unrelated``) is not a hit; it is returned in the second value as a note so the
    report can show it instead of dropping it silently.
    """
    screened: List[str] = []
    not_screened: List[str] = []
    for display, recorder_name, _tool in SANCTIONS_LISTS:
        ok, reason = _list_status(source_log, recorder_name)
        if ok:
            screened.append(display)
        else:
            not_screened.append(f"{display} ({reason})")
    status = "lists_run" if not not_screened else ("not_run" if not screened else "partial")
    not_screened.append(EU_LIST_NOT_SCREENED)

    hits: List[Dict[str, Any]] = []
    ignored: List[str] = []
    seen: Set[str] = set()
    relevance = relevance_by_node or {}
    for node in nodes:
        node_id = str(node.get("id"))
        for receipt in _receipts(node):
            tool = str(receipt.get("tool") or "")
            list_name = next((d for d, _r, prefix in SANCTIONS_LISTS if tool.startswith(prefix)), "")
            if not list_name or node_id in seen:
                continue
            seen.add(node_id)
            name = _clean_label(str(node.get("label") or node_id))
            if relevance.get(node_id) == "unrelated":
                ignored.append(
                    f"Sanctions-list result '{name}' ({list_name}) does not resemble the subject name and is not "
                    "treated as a hit; check manually if the subject may use another name"
                )
                continue
            hits.append(
                {"list": list_name, "name": name, "match": SOFT_MATCH_NOTE,
                 "url": str(receipt.get("source_url") or SANCTIONS_PRIMARY_URLS.get(list_name, "")),
                 "node_id": node_id, "relevance": relevance.get(node_id, "unknown")}
            )
    return (
        SanctionsScreening(status=status, screened=screened, not_screened=not_screened, hits=hits),
        ignored,
    )


# ----------------------------------------------------------------------------------------------
# Soft sanctions matches inside the graph (a listed name that another graph entity carries)
# ----------------------------------------------------------------------------------------------

SOFT_LISTED_TAG = "matches a sanctions-list entry (soft)"
_NON_ENTITY_ID_PREFIXES = ("sanction:", "sec:", "hn:", "article:", "openalex:", "wikidata:", "beneish:", "loc:")
_ENTITY_TYPES = frozenset({"Organization", "ShellCompany", "Person"})
_ALIAS_ATTRIBUTES = ("aliases", "alias", "aka", "also_known_as")
_SNIPPET_ALIASES = re.compile(r"aliases=(\[[^\]]*\])")
_IGNORED_ALIASES = frozenset({"cyrillic", "latin", "arabic", "chinese", "japanese", "korean"})
_MIN_ALIAS_CHARS = 5
_STRONG_LEVELS = ("exact", "strong")


@dataclass(frozen=True)
class SoftListMatch:
    """A graph entity whose name matches a sanctions-list entry (the entry's name or one of its aliases)."""

    node_id: str
    label: str
    entry: str  # the listed name it matches
    list_name: str
    url: str


def _entry_names(node: Mapping[str, Any], name: str) -> List[str]:
    """The listed name plus the aliases the listing node carries (attributes, or ``aliases=[...]`` in a snippet)."""
    aliases: List[str] = []
    attrs = node.get("attributes") or {}
    for key in _ALIAS_ATTRIBUTES:
        aliases += _as_text_list(attrs.get(key))
    for receipt in _receipts(node):
        found = _SNIPPET_ALIASES.search(str(receipt.get("raw_snippet") or ""))
        if found is None:
            continue
        try:
            parsed = ast.literal_eval(found.group(1))
        except (ValueError, SyntaxError):
            continue
        aliases += [str(item).strip() for item in parsed if isinstance(item, str)]
    usable = [a for a in aliases if len(a) >= _MIN_ALIAS_CHARS and a.lower() not in _IGNORED_ALIASES]
    return list(dict.fromkeys(([name] if name else []) + usable))


def soft_listed_matches(nodes: Sequence[Mapping[str, Any]], sanctions: SanctionsScreening) -> List[SoftListMatch]:
    """Graph entities (other than the listing nodes) that match a sanctions hit's name or alias at exact or strong level.

    A listing found for the seed rarely sits inside the ownership graph (it is a ``sanction:*`` node), so the 50% rule
    could never fire; this matches each hit name against every organisation or person node by name. Only ``exact``
    (the same name after legal forms, accents, transliteration) and ``strong`` (a shortened form) count: a name that
    merely contains the listed name ("Rosneft Deutschland" for "Rosneft") or sits in a different line of business
    ("Rosneft Bank") is not matched. The seed anchor, document nodes (filings, articles, Wikidata) and addresses are
    skipped. Every match is a SOFT name match: verify on the primary list.
    """
    hits = [h for h in sanctions.hits if isinstance(h, Mapping) and not h.get("graph_match")]
    if not hits:
        return []
    by_id = {str(n.get("id")): n for n in nodes}
    hit_ids = {str(h.get("node_id")) for h in hits}
    entries: List[Tuple[str, str, str, bool]] = []  # (name, list, url, is a person listing)
    for hit in hits:
        node = by_id.get(str(hit.get("node_id")), {})
        is_person = str(_val(node.get("entity_type"))) == "Person"
        for name in _entry_names(node, str(hit.get("name") or "")):
            entries.append((name, str(hit.get("list") or ""), str(hit.get("url") or ""), is_person))

    matches: List[SoftListMatch] = []
    for node in nodes:
        node_id = str(node.get("id"))
        if (
            node_id in hit_ids
            or _is_subject_anchor(node)
            or node_id.startswith(_NON_ENTITY_ID_PREFIXES)
            or str(_val(node.get("entity_type"))) not in _ENTITY_TYPES
        ):
            continue
        label = _clean_label(str(node.get("label") or node_id))
        node_is_person = str(_val(node.get("entity_type"))) == "Person"
        for name, list_name, url, is_person in entries:
            if is_person != node_is_person:  # a person listing never marks an organisation, and the reverse
                continue
            if name_match_level(name, label, attributes=node.get("attributes") or {}) in _STRONG_LEVELS:
                matches.append(SoftListMatch(node_id=node_id, label=label, entry=name, list_name=list_name, url=url))
                break
    return matches


def soft_match_hit(match: SoftListMatch) -> Dict[str, Any]:
    """The ``SanctionsScreening.hits`` row for a soft match found in the graph (flagged ``graph_match``)."""
    return {
        "list": match.list_name, "name": match.label, "match": f"{SOFT_LISTED_TAG}: '{match.entry}'",
        "url": match.url, "node_id": match.node_id, "graph_match": True, "matched_entry": match.entry,
    }


def soft_match_note(match: SoftListMatch) -> str:
    return (
        f"Graph entity '{match.label}' ({match.node_id}) {SOFT_LISTED_TAG}: '{match.entry}' on {match.list_name}; "
        "a name match only, verify identifiers on the primary list"
    )


@dataclass
class _EscalationContext:
    findings: Sequence[Finding]
    ownership: OwnershipBlock
    custodians: Sequence[Custodian]
    contradictions: Sequence[Contradiction]
    identity_notes: Sequence[str]
    listed_ids: Sequence[str]
    deep_run: bool
    subject_is_person: bool
    sanctions: SanctionsScreening = field(default_factory=SanctionsScreening)
    ownership_flags: Sequence[str] = ()  # nominee / secrecy-jurisdiction evidence found on nodes of the subject's chain
    public_listed_ids: Sequence[str] = ()  # nodes that are publicly listed registrants (dispersed shareholders)
    details: Dict[str, Any] = field(default_factory=dict)


def _preview(items: Sequence[str], limit: int = 3) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _eval_unresolved_ownership(ctx: _EscalationContext) -> Tuple[bool, str]:
    """The playbook text says "ends at a nominee or secrecy jurisdiction": it fires ONLY on such evidence.

    An unresolved walk by itself (a listed company, a registry that stops, a missing record) is not that: the trigger
    stays off and says "ownership walk unresolved (no nominee or secrecy-jurisdiction evidence)" with the nodes.
    Evidence is a nominee false-link flag, a nominee or secrecy risk flag, or a secrecy-jurisdiction parent.
    """
    if not ctx.ownership.unresolved:
        return False, "no unresolved ownership node recorded"
    nodes = [unresolved_node_id(u) for u in ctx.ownership.unresolved]
    if ctx.ownership_flags:
        return True, (
            f"{len(nodes)} ownership node(s) unresolved: {_preview(nodes)}; nominee or secrecy indicator: "
            f"{_preview(list(ctx.ownership_flags))}"
        )
    listed = set(ctx.public_listed_ids)
    if all(node in listed for node in nodes):
        return False, (
            "not evaluated automatically: the ownership walk ended at publicly listed registrant(s) "
            f"({_preview(nodes)}), whose shareholders are dispersed; that is not by itself a nominee or "
            "secrecy-jurisdiction indicator"
        )
    return False, (
        f"ownership walk unresolved (no nominee or secrecy-jurisdiction evidence): {len(nodes)} node(s) "
        f"({_preview(nodes)}) where the walk ended; an open chain is not by itself a nominee or secrecy finding"
    )


def _coverage_sentence(sanctions: SanctionsScreening) -> str:
    screened = ", ".join(sanctions.screened) or "none"
    missing = "; ".join(sanctions.not_screened) or "none"
    return f"lists screened ({screened}); NOT screened: {missing}"


def _eval_sanctions_or_50_rule(ctx: _EscalationContext) -> Tuple[bool, str]:
    """Fires on a listing or a 50% rule block. "No listing" is claimed only when all five lists were screened.

    When ownership edges exist but carry no percentage the rule cannot be evaluated; the text says so instead of
    leaving the reader to assume "no block".
    """
    sanctions = ctx.sanctions
    unevaluable = fifty_rule_not_evaluable(ctx.ownership) and not ctx.ownership.blocked_by_50_rule
    parts: List[str] = []
    if ctx.listed_ids:
        parts.append(
            f"sanctions/PEP listing on {_preview(list(ctx.listed_ids))} (soft name match: verify on the primary list)"
        )
    if ctx.ownership.blocked_by_50_rule:
        parts.append(f"50% rule block on {_preview(ctx.ownership.blocked_by_50_rule)}")
    note = f"; {FIFTY_RULE_NOT_EVALUABLE}" if unevaluable else ""
    if parts:
        if unevaluable:
            parts.append(FIFTY_RULE_NOT_EVALUABLE)
        if sanctions.status != "lists_run":
            parts.append(f"screening was incomplete: {_coverage_sentence(sanctions)}")
        return True, "; ".join(parts)
    if sanctions.status == "lists_run":
        return False, (
            f"no sanctions/PEP listing or 50% rule block found on the lists screened ({', '.join(sanctions.screened)}); "
            f"NOT screened: {'; '.join(sanctions.not_screened) or EU_LIST_NOT_SCREENED}; check the EU list manually{note}"
        )
    if sanctions.status == "partial":
        screened = ", ".join(sanctions.screened) or "none"
        return False, (
            f"not fired on the lists screened ({screened}); NOT screened: {'; '.join(sanctions.not_screened)}{note}"
        )
    return False, (
        "not evaluated: no sanctions list was screened in this run; "
        f"NOT screened: {'; '.join(sanctions.not_screened) or 'all lists'}{note}"
    )


def _eval_custodian_finding(ctx: _EscalationContext) -> Tuple[bool, str]:
    if ctx.custodians:
        return True, f"custodian-bearing finding(s): {_preview([c.finding for c in ctx.custodians])}"
    return False, "no finding that only a custodian can resolve"


def _eval_no_corroborated_finding(ctx: _EscalationContext) -> Tuple[bool, str]:
    if not ctx.deep_run:
        return False, "not a deep run: not evaluated against a shallow sweep"
    corroborated = [f for f in ctx.findings if f.finding_label in (FindingLabel.CONFIRMED, FindingLabel.PROBABLE)]
    if corroborated:
        return False, f"{len(corroborated)} confirmed or probable finding(s)"
    return True, f"deep run produced no confirmed or probable finding ({len(ctx.findings)} lead-only finding(s))"


def _eval_contradiction(ctx: _EscalationContext) -> Tuple[bool, str]:
    if ctx.contradictions:
        return True, f"{len(ctx.contradictions)} contradiction(s): {_preview([c.kind for c in ctx.contradictions])}"
    return False, "no contradiction detected in the timeline"


def _eval_identity_unresolved(ctx: _EscalationContext) -> Tuple[bool, str]:
    if not ctx.subject_is_person:
        return False, "subject is an entity: person identity resolution does not apply"
    for note in ctx.identity_notes:
        if note.startswith("subject not anchored") or "NOT established" in note:
            return True, note
    return False, "subject anchored on two or more identifiers and no unresolved same-name collision"


#: Machine key -> evaluator. Must define exactly ``pi_reference.ESCALATION_KEYS`` (a test enforces it).
ESCALATION_EVALUATORS: Dict[str, Callable[[_EscalationContext], Tuple[bool, str]]] = {
    "contradiction": _eval_contradiction,
    "custodian_finding": _eval_custodian_finding,
    "identity_unresolved": _eval_identity_unresolved,
    "no_corroborated_finding": _eval_no_corroborated_finding,
    "sanctions_or_50_rule": _eval_sanctions_or_50_rule,
    "unresolved_ownership": _eval_unresolved_ownership,
}


def escalation_triggers_for(playbook: Playbook, ctx: _EscalationContext) -> List[EscalationTrigger]:
    """One trigger per ``escalate_when`` item; items without an evaluable key are never reported as fired."""
    triggers: List[EscalationTrigger] = []
    for text in playbook.escalate_when:
        evaluator = ESCALATION_EVALUATORS.get(playbook.escalate_keys.get(text, ""))
        if evaluator is None:
            triggers.append(EscalationTrigger(trigger=text, fired=False, why="not evaluated automatically"))
            continue
        fired, why = evaluator(ctx)
        triggers.append(EscalationTrigger(trigger=text, fired=fired, why=why))
    return triggers


__all__ = [
    "EU_LIST_NOT_SCREENED",
    "SANCTIONS_LISTS",
    "SOFT_LISTED_TAG",
    "SoftListMatch",
    "ESCALATION_EVALUATORS",
    "MAX_IDENTITY_NOTES",
    "MAX_RECORDS_PER_NAME_GROUP",
    "PLAYBOOK_SOURCE_MAP",
    "SUBJECT_NOT_ANCHORED_NOTE",
    "escalation_triggers_for",
    "identity_notes_for",
    "playbook_progress_for",
    "sanctions_screening_for",
    "soft_listed_matches",
    "soft_match_hit",
    "soft_match_note",
]
