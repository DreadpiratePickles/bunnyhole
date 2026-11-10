"""Evidence input of the PI report's AI analysis: a minimal, id-tagged text block, plus structured gap data.

The rule: send ONLY what the code-built report itself prints, in the same words and fields. Nothing is read from a
receipt's ``extracted_fact`` or ``raw_snippet``, nor from node attributes or timeline items (no titles, no dates):
the report does not print those and they carry third-party data. The model writes connection bullets only, so the
prompt carries only what a connection needs:

- ``F1..`` findings, in the report's own ranking (confirmed first), with the label the CODE computed, and for each
  its receipts as the *Chain of custody* table prints them (receipt id, tool, URL, SHA-256);
- ``O1..`` ownership edges as the *Ownership chain* table prints them.

Everything else (sanctions screening ``S``, set-aside matches ``W``, coverage and gaps ``G``, where the ownership walk
stopped) is NOT in the prompt. It is kept as structured :class:`GapItem` records and rendered by code
(``pi_narrative_sections``) in fixed wording. Not sent: the client name, matter reference, purpose text, receipt
extracts, raw snippets, node attributes, timeline items, sanctions or coverage data, unrelated records, API keys.
Every value is collapsed to one line and stripped of control characters, so a hostile string cannot open a new
evidence line or forge an id. ``NarrativeEvidence.values`` lists every data string that was sent, so a test can prove
each one is printed by the report. Pure: no network, no model.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from pydantic import ValidationError

from bunnyhole.engine.pi import PIBlock
from bunnyhole.engine.pi_graph_access import _is_external, _receipts
from bunnyhole.engine.pi_narrative_lexicon import JURISDICTION_WORDS
from bunnyhole.engine.pi_report_common import (
    _distinct,
    _graph_matches,
    _is_searched,
    _primary_hits,
    _ranked_findings,
    _relevant,
    _undecorated,
    _weak_matches,
    truncate_words,
)

MAX_FINDINGS = 25
MAX_RECEIPTS_PER_FINDING = 3
MAX_LIST_ENTRIES = 12
MAX_ITEMS_PER_KIND = 8
MAX_WEAK_MATCHES = 3  # the Sanctions section prints three, then "+N more"
MAX_OWNERSHIP_EDGES = 15
MAX_COVERAGE_ROWS = 12
MAX_NOTES = 5
_NAME_CHARS = 120
_URL_CHARS = 200
_NOTE_CHARS = 300  # identity notes, contradictions and chronology gaps: whole up to here, cut at a word beyond

# Gap kinds: what a code-rendered "not established" line and its next step are keyed by.
STANDING_LIMITS = "standing_limits"
SANCTIONS_STATUS = "sanctions_status"
SANCTIONS_POSSIBLE = "sanctions_possible"
SET_ASIDE = "set_aside"
NOT_SEARCHED = "not_searched"
SEARCHED = "searched"
IDENTITY_NOTE = "identity_note"
CONTRADICTION = "contradiction"
CHRONOLOGY_GAP = "chronology_gap"
OWNERSHIP_WALK = "ownership_walk"
LEAD_ONLY = "lead_only"


class KeyEntry(NamedTuple):
    """What one id stands for, written by code: shown in the report's citation key."""

    description: str
    receipt_ids: Tuple[str, ...]


class GapItem(NamedTuple):
    """One thing the report does not establish, as structured data. ``names`` are printed-report strings."""

    item_id: str
    kind: str
    label: str
    names: Tuple[str, ...] = ()


@dataclass(frozen=True)
class NarrativeEvidence:
    """The evidence text sent to the model plus everything the validator, the audit tests and the report need."""

    text: str  # the prompt data block: case header, findings (F), ownership edges (O)
    key: Mapping[str, KeyEntry]  # every id (F, O, S, W, G) -> description, for the citation key
    finding_labels: Mapping[str, str]  # F id -> confirmed | probable | lead, as computed by the code
    lines: Mapping[str, str]  # id -> its prompt line(s), for the per-id checks of the validator
    model_ids: FrozenSet[str]  # the ids the model may cite: the F and O ids that are in the prompt
    gaps: Tuple[GapItem, ...]  # structured gaps, rendered by code
    values: Tuple[str, ...]  # every data string sent; each must be printed by the report
    extra_words: FrozenSet[str]  # vocabulary the validator accepts that is not itself sent (jurisdiction words)
    names: FrozenSet[str] = frozenset()  # printed names of the findings and of the ownership edges' parties

    @property
    def known_ids(self) -> FrozenSet[str]:
        return frozenset(self.key)

    @property
    def digest(self) -> str:
        """A short content hash, used to make the data-block delimiter specific to this evidence."""
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:12]


def clean(value: Any, limit: int) -> str:
    """One line of inert text: control and format characters become spaces, whitespace collapses, cut at ``limit``."""
    raw = str(value if value is not None else "")
    spaced = "".join(" " if ch.isspace() or unicodedata.category(ch).startswith("C") else ch for ch in raw)
    return truncate_words(re.sub(r"\s+", " ", spaced).strip(), limit)


def _unescaped(text: Any) -> str:
    """Report text without the Markdown backslash escapes ``_inline`` adds (so it can be compared with a value)."""
    return str(text).replace("\\", "")


def _split_list_reason(entry: str) -> Tuple[str, str]:
    """``X: reason`` or ``X (reason)`` into (list, reason), as the report's Sanctions table splits it.

    Mirrors ``pi_report._split_reason`` (not imported: that module is a large builder and tests stub it).
    """
    colon = re.match(r"^(?P<list>[^:()]+?)\s*:\s*(?P<reason>.+)$", entry)
    if colon is not None:
        return colon.group("list"), colon.group("reason")
    paren = re.match(r"^(?P<list>[^:()]+?)\s*\(\s*(?P<reason>.+?)\)?$", entry)
    if paren is None:
        return entry, "not recorded"
    return paren.group("list"), paren.group("reason")


def _unique(items: Sequence[Any], limit: int, chars: int = 100) -> List[str]:
    return list(dict.fromkeys(text for text in (clean(i, chars) for i in items) if text))[:limit]


class _Builder:
    """Collects prompt lines, the key, the structured gaps and the audit values, handing out ids per family."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.key: Dict[str, KeyEntry] = {}
        self.by_id: Dict[str, str] = {}
        self.model_ids: List[str] = []
        self.gaps: List[GapItem] = []
        self.values: List[str] = []
        self.names: List[str] = []
        self._counts: Dict[str, int] = {}

    def heading(self, title: str) -> None:
        self.lines += ["", f"-- {title} --"]

    def _next(self, family: str) -> str:
        self._counts[family] = self._counts.get(family, 0) + 1
        return f"{family}{self._counts[family]}"

    def add(
        self, family: str, line: str, description: str, receipt_ids: Tuple[str, ...] = (), values: Sequence[str] = ()
    ) -> str:
        """An id that is in the prompt (the model may cite it)."""
        item_id = self._next(family)
        self.lines.append(f"[{item_id}] {line}")
        self.by_id[item_id] = line
        self.model_ids.append(item_id)
        self.key[item_id] = KeyEntry(clean(description, 160), receipt_ids)
        self.values += [v for v in values if v]
        return item_id

    def extend(self, item_id: str, line: str, values: Sequence[str] = ()) -> None:
        self.lines.append(line)
        self.by_id[item_id] += " " + line
        self.values += [v for v in values if v]

    def raw(self, line: str, values: Sequence[str] = ()) -> None:
        self.lines.append(line)
        self.values += [v for v in values if v]

    def gap(self, family: str, kind: str, label: str, description: str, names: Sequence[str] = ()) -> str:
        """An id that is NOT in the prompt: a structured gap that code renders."""
        item_id = self._next(family)
        self.key[item_id] = KeyEntry(clean(description, 160), ())
        self.gaps.append(GapItem(item_id, kind, clean(label, _NOTE_CHARS), tuple(clean(n, 160) for n in names)))
        return item_id


def _node_index(result: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    nodes = result.get("nodes")
    index: Dict[str, Mapping[str, Any]] = {}
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, Mapping) and node.get("id"):
                index[str(node["id"])] = node
    return index


def _name_of(node_id: str, index: Mapping[str, Mapping[str, Any]]) -> str:
    node = index.get(node_id)
    label = _undecorated(node.get("label")) if node and node.get("label") else node_id
    return clean(label, _NAME_CHARS)


def _printed_receipts(node: Mapping[str, Any], custody: Mapping[str, Any]) -> List[Any]:
    """The node's external receipts that the Chain of custody table prints (its entry, not the receipt)."""
    seen: set = set()
    entries: List[Any] = []
    for receipt in _receipts(node):
        rid = str(receipt.get("receipt_id") or "")
        if rid and rid not in seen and rid in custody and _is_external(receipt):
            seen.add(rid)
            entries.append(custody[rid])
    return entries[:MAX_RECEIPTS_PER_FINDING]


def _add_findings(
    builder: _Builder, shown: Sequence[Tuple[Any, Any]], index: Mapping[str, Mapping[str, Any]], block: PIBlock
) -> Dict[str, str]:
    """Findings as F ids. Returns F id -> label value."""
    builder.heading("FINDINGS (the label is computed by code and rendered next to every citation)")
    custody = {entry.receipt_id: entry for entry in block.custody}
    labels: Dict[str, str] = {}
    for finding, label in shown:
        entries = _printed_receipts(index.get(finding.node_id, {}), custody)
        name = clean(_undecorated(finding.label), _NAME_CHARS)
        freshness, relevance = clean(finding.freshness, 20), clean(finding.relevance, 20)
        line = (
            f"label={label.value} | sources={finding.source_count} | freshness={freshness} | "
            f"relevance={relevance} | name: {name}"
        )
        receipt_ids = tuple(clean(e.receipt_id, 40) for e in entries)
        item_id = builder.add(
            "F", line, f"{name} ({label.value}, {finding.source_count} source(s))", receipt_ids,
            values=(name, label.value, freshness, relevance),
        )
        labels[item_id] = label.value
        builder.names.append(name)
        if label.value == "lead":
            builder.gaps.append(GapItem(item_id, LEAD_ONLY, name))
        for entry in entries:
            tool, url = clean(entry.tool, 40), clean(entry.url, _URL_CHARS)
            sha = entry.sha256.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", entry.sha256 or "") else ""
            parts = [f"receipt {clean(entry.receipt_id, 40)}", f"tool={tool}", f"url={url}"]
            if sha:
                parts.append(f"sha256={sha}")
            builder.extend(item_id, "    - " + " | ".join(parts), (clean(entry.receipt_id, 40), tool, url, sha))
    return labels


def _record_sanctions(builder: _Builder, block: PIBlock) -> None:
    """Sanctions facts as structured gaps (not in the prompt)."""
    sanctions = block.sanctions
    missed: List[str] = []
    for entry in _distinct(sanctions.not_screened)[:MAX_LIST_ENTRIES]:
        name, reason = (clean(_unescaped(part), 100) for part in _split_list_reason(entry))
        missed.append(f"{name}: {reason}")
    screened = _unique([_unescaped(s) for s in _distinct(sanctions.screened)], MAX_LIST_ENTRIES)
    builder.gap(
        "S", SANCTIONS_STATUS, sanctions.status, "sanctions screening status and the lists screened or not",
        [f"screened: {'; '.join(screened) or 'none'}", *missed],
    )
    for hit in _primary_hits(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(hit.get("name") or hit.get("match"), _NAME_CHARS)
        builder.gap("S", SANCTIONS_POSSIBLE, name, f"possible sanctions-list match (soft): {name}", [name])
    for match in _graph_matches(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(match.get("name") or match.get("node_id"), _NAME_CHARS)
        builder.gap("S", SANCTIONS_POSSIBLE, name, f"graph entity matches a sanctions-list entry (soft): {name}", [name])
    for candidate in _weak_matches(sanctions)[:MAX_WEAK_MATCHES]:
        name = clean(candidate.get("name"), _NAME_CHARS)
        builder.gap("W", SET_ASIDE, name, f"weak name match set aside, not a finding: {name}", [name])


def _record_coverage_and_gaps(builder: _Builder, block: PIBlock) -> None:
    builder.gap("G", STANDING_LIMITS, "standing limits", "standing limits of this tool (what was not checked)")
    for row in block.coverage[:MAX_COVERAGE_ROWS]:
        source_class = clean(row.source_class, 60)
        if not _is_searched(row):
            builder.gap("G", NOT_SEARCHED, source_class, f"source class {source_class}: not searched")
        else:
            outcome = clean(row.outcome, 20) or "unknown"
            builder.gap("G", SEARCHED, source_class, f"source class {source_class}: searched, outcome {outcome}",
                        [outcome])
    for note in _unique([_unescaped(n) for n in _distinct(block.identity_notes)], MAX_NOTES, _NOTE_CHARS):
        builder.gap("G", IDENTITY_NOTE, note, f"identity note: {note}")
    for item in block.contradictions[:MAX_NOTES]:
        text = f"{clean(item.kind, 40)}: {clean(item.description, 200)}"
        builder.gap("G", CONTRADICTION, text, f"contradiction ({text})")
    for gap in _unique([_unescaped(g) for g in _distinct(block.evidence_gaps)], MAX_NOTES, _NOTE_CHARS):
        builder.gap("G", CHRONOLOGY_GAP, gap, f"chronology gap: {gap}")


def _add_ownership(builder: _Builder, block: PIBlock, index: Mapping[str, Mapping[str, Any]]) -> None:
    walk = block.ownership
    if not (walk.edges or walk.unresolved or walk.blocked_by_50_rule or walk.levels_walked):
        return
    if walk.edges:
        builder.heading("OWNERSHIP EDGES (legal ownership walked by the code)")
    for edge in walk.edges[:MAX_OWNERSHIP_EDGES]:
        pct = f"{edge.pct:g}%" if edge.pct is not None else "unknown"
        child, parent = _name_of(edge.child, index), _name_of(edge.parent, index)
        source, as_of = clean(edge.source, 40) or "unknown", clean(edge.as_of, 20) or "unknown"
        builder.names += [child, parent]
        builder.add(
            "O", f"{child} is owned by {parent} | pct={pct} | source={source} | as_of={as_of}",
            f"ownership edge: {child} owned by {parent}", values=(child, parent, pct, source, as_of),
        )
    stops = _unique([_name_of(n, index) for n in walk.unresolved], MAX_NOTES)
    blocked = _unique([_name_of(n, index) for n in walk.blocked_by_50_rule], MAX_NOTES)
    builder.gap("O", OWNERSHIP_WALK, str(walk.levels_walked), "where the ownership walk stopped",
                [*stops, *(f"blocked: {b}" for b in blocked)])


def _jurisdiction_words(jurisdiction: str) -> FrozenSet[str]:
    return frozenset(JURISDICTION_WORDS.get(jurisdiction.lower().split("-")[0], ()))


def build_evidence(result: Mapping[str, Any]) -> Optional[NarrativeEvidence]:
    """The evidence for ``result``, or ``None`` when there is no valid PI block or no relevant finding.

    The finding population is the report's own Findings table: records about the subject (relevance ``subject`` or
    ``related``), ranked confirmed first, at most :data:`MAX_FINDINGS`. With none of those there is nothing to connect,
    so no analysis is attempted (and no call is made).
    """
    data: Mapping[str, Any] = result if isinstance(result, Mapping) else {}
    try:
        block = PIBlock.model_validate(data.get("pi"))
    except ValidationError:
        return None
    shown = _relevant(_ranked_findings(block.findings))[:MAX_FINDINGS]
    if not shown:
        return None
    index = _node_index(data)
    engagement = block.engagement
    seed = clean(data.get("seed") or data.get("seed_query") or engagement.engagement_id, _NAME_CHARS)
    case_type, purpose = clean(engagement.case_type.value, 40), clean(engagement.purpose_category, 60)
    builder = _Builder()
    builder.heading("CASE")
    builder.raw(f"SUBJECT: {seed}", (seed,))
    builder.raw(f"SUBJECT_KIND: {'person' if engagement.subject_is_person else 'entity'}")
    builder.raw(f"CASE_TYPE: {case_type}", (case_type,))
    builder.raw(f"PURPOSE_CATEGORY: {purpose or 'not recorded'}", (purpose,))
    if engagement.jurisdiction:
        jurisdiction = clean(engagement.jurisdiction, 40)
        builder.raw(f"JURISDICTION: {jurisdiction}", (jurisdiction,))
    labels = _add_findings(builder, shown, index, block)
    _add_ownership(builder, block, index)
    _record_sanctions(builder, block)
    _record_coverage_and_gaps(builder, block)
    return NarrativeEvidence(
        text="\n".join(builder.lines).strip("\n"),
        key=dict(builder.key),
        finding_labels=labels,
        lines=dict(builder.by_id),
        model_ids=frozenset(builder.model_ids),
        gaps=tuple(builder.gaps),
        values=tuple(builder.values),
        extra_words=_jurisdiction_words(engagement.jurisdiction),
        names=frozenset(n for n in builder.names if n),
    )
