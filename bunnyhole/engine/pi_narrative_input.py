"""Evidence input of the PI report's AI analysis: one deterministic, minimal, id-tagged text block.

The rule: send ONLY what the code-built report itself prints, in the same words and fields. Nothing is read from a
receipt's ``extracted_fact`` or ``raw_snippet`` and nothing from node attributes or timeline titles, because the
report does not print those and they carry third-party data (names, birth years, emails, display names). Each
evidence line carries a stable id so the model can cite it and the validator can check the citation:

- ``F1..`` findings, in the report's own ranking (confirmed first), with the label the CODE computed, and for each
  its receipts as the *Chain of custody* table prints them (receipt id, tool, URL, SHA-256);
- ``S1..`` sanctions screening (status, lists screened, lists NOT screened, possible hits);
- ``W1..`` weak name matches that were set aside (name and URL, as the Sanctions section prints them);
- ``G1..`` coverage and gaps (standing limits, source classes searched or not, identity notes, contradictions);
- ``O1..`` ownership edges and where the walk stopped;
- dated events: the date and the finding ids it belongs to, never the event's title.

Not sent: the client name, matter reference, purpose text, receipt extracts, raw snippets, node attributes, event
titles, unrelated records, API keys. Every value is collapsed to one line and stripped of control characters, so a
hostile string cannot open a new evidence line or forge an id. ``NarrativeEvidence.values`` lists every data string
that was sent, so a test can prove each one is printed by the report. Pure: no network, no model.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from pydantic import ValidationError

from bunnyhole.engine.pi import CoverageRow, PIBlock
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
MAX_DATED_EVENTS = 15
MAX_OWNERSHIP_EDGES = 15
MAX_COVERAGE_ROWS = 12
MAX_NOTES = 5
_NAME_CHARS = 120
_URL_CHARS = 200

STANDING_LIMITS = (
    "standing limits of this tool: free public passive sources only. NOT checked: licensed or paid investigator "
    "databases, paid records, field work and interviews. Court dockets and registries were consulted only as the "
    "coverage lines below say."
)


class KeyEntry(NamedTuple):
    """What one id stands for, written by code: shown in the report's citation key."""

    description: str
    receipt_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NarrativeEvidence:
    """The evidence text sent to the model plus everything the validator, the audit tests and the key need."""

    text: str
    key: Mapping[str, KeyEntry]
    finding_labels: Mapping[str, str]  # F id -> confirmed | probable | lead, as computed by the code
    lines: Mapping[str, str]  # id -> its evidence line(s), for the per-id checks of the validator
    values: Tuple[str, ...]  # every data string sent; each must be printed by the report
    date_values: Tuple[str, ...]  # event dates (the one thing sent that the report does not print)
    extra_words: FrozenSet[str]  # vocabulary the validator accepts that is not itself sent (jurisdiction words)

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
    """Collects evidence lines, the key and the audit values, handing out ids per family in order."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.key: Dict[str, KeyEntry] = {}
        self.by_id: Dict[str, str] = {}
        self.values: List[str] = []
        self._counts: Dict[str, int] = {}

    def heading(self, title: str) -> None:
        self.lines += ["", f"-- {title} --"]

    def add(
        self, family: str, line: str, description: str, receipt_ids: Tuple[str, ...] = (), values: Sequence[str] = ()
    ) -> str:
        self._counts[family] = self._counts.get(family, 0) + 1
        item_id = f"{family}{self._counts[family]}"
        self.lines.append(f"[{item_id}] {line}")
        self.by_id[item_id] = line
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


def _printed_receipts(
    node: Mapping[str, Any], custody: Mapping[str, Any]
) -> List[Any]:
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
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Findings as F ids. Returns (node id -> F id, F id -> label value)."""
    builder.heading("FINDINGS (the label is computed by code; never change or upgrade it)")
    custody = {entry.receipt_id: entry for entry in block.custody}
    node_to_f: Dict[str, str] = {}
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
        node_to_f[finding.node_id] = item_id
        labels[item_id] = label.value
        for entry in entries:
            tool, url = clean(entry.tool, 40), clean(entry.url, _URL_CHARS)
            digest = entry.sha256.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", entry.sha256 or "") else ""
            parts = [f"receipt {clean(entry.receipt_id, 40)}", f"tool={tool}", f"url={url}"]
            if digest:
                parts.append(f"sha256={digest}")
            builder.extend(item_id, "    - " + " | ".join(parts), (clean(entry.receipt_id, 40), tool, url, digest))
    return node_to_f, labels


def _add_sanctions(builder: _Builder, block: PIBlock) -> None:
    sanctions = block.sanctions
    builder.heading("SANCTIONS SCREENING")
    screened = _unique([_unescaped(s) for s in _distinct(sanctions.screened)], MAX_LIST_ENTRIES) or ["none"]
    missed: List[str] = []
    missed_values: List[str] = []
    for entry in _distinct(sanctions.not_screened)[:MAX_LIST_ENTRIES]:
        name, reason = (clean(_unescaped(part), 100) for part in _split_list_reason(entry))
        missed.append(f"{name}: {reason}")
        missed_values += [name, reason]
    builder.add(
        "S",
        f"status={sanctions.status} | lists screened: {'; '.join(screened)} | "
        f"lists NOT screened or not reached: {'; '.join(missed) or 'none recorded'}",
        "sanctions screening status and the lists screened or not screened",
        values=[sanctions.status, *(s for s in screened if s != "none"), *missed_values],
    )
    for hit in _primary_hits(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(hit.get("name") or hit.get("match"), _NAME_CHARS)
        listing, url = clean(hit.get("list"), 60), clean(hit.get("url"), _URL_CHARS)
        builder.add(
            "S",
            f"possible list match, SOFT and unverified (verify on the primary list) | list={listing} | name={name}"
            f" | url={url}",
            f"possible sanctions-list match (soft): {name}", values=(listing, name, url),
        )
    for match in _graph_matches(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(match.get("name") or match.get("node_id"), _NAME_CHARS)
        entry_name, listing = clean(match.get("matched_entry"), _NAME_CHARS), clean(match.get("list"), 60)
        builder.add(
            "S",
            f"another graph entity's name matches a listed entry, SOFT and unverified | entity={name} | "
            f"entry={entry_name} | list={listing}",
            f"graph entity matches a sanctions-list entry (soft): {name}", values=(name, entry_name, listing),
        )
    weak = _weak_matches(sanctions)[:MAX_WEAK_MATCHES]
    if weak:
        builder.heading("SET-ASIDE NAME MATCHES (weak, NOT linked to the subject; not findings)")
        for candidate in weak:
            name, url = clean(candidate.get("name"), _NAME_CHARS), clean(candidate.get("url"), _URL_CHARS)
            builder.add(
                "W", f"weak name match, set aside and NOT linked | name={name} | url={url}",
                f"weak name match set aside, not a finding: {name}", values=(name, url),
            )


def _coverage_line(row: CoverageRow) -> Tuple[str, List[str]]:
    source_class = clean(row.source_class, 60)
    if not _is_searched(row):
        return f"source class {source_class}: NOT searched", [source_class]
    ran = _unique(row.sources, 6, 40)
    outcome = clean(row.outcome, 20) or "unknown"
    text = f"source class {source_class}: searched, outcome={outcome}; sources that ran: {', '.join(ran) or 'none named'}"
    values = [source_class, outcome, *ran]
    if row.skipped:
        skipped = _unique(row.skipped, 6, 40)
        text += f"; tried but NOT reached: {', '.join(skipped)}"
        values += skipped
    return text, values


def _add_gaps(builder: _Builder, block: PIBlock) -> None:
    builder.heading("COVERAGE AND GAPS")
    builder.add("G", STANDING_LIMITS, "standing limits of this tool (what was not checked)")
    for row in block.coverage[:MAX_COVERAGE_ROWS]:
        text, values = _coverage_line(row)
        builder.add("G", text, text, values=values)
    for note in _unique([_unescaped(n) for n in _distinct(block.identity_notes)], MAX_NOTES, 200):
        builder.add("G", f"identity note: {note}", f"identity note: {note}", values=(note,))
    for item in block.contradictions[:MAX_NOTES]:
        kind, description = clean(item.kind, 40), clean(item.description, 200)
        builder.add("G", f"contradiction ({kind}): {description}", f"contradiction ({kind}): {description}",
                    values=(kind, description))
    for gap in _unique([_unescaped(g) for g in _distinct(block.evidence_gaps)], MAX_NOTES, 200):
        builder.add("G", f"chronology gap: {gap}", f"chronology gap: {gap}", values=(gap,))


def _add_ownership(builder: _Builder, block: PIBlock, index: Mapping[str, Mapping[str, Any]]) -> None:
    walk = block.ownership
    if not (walk.edges or walk.unresolved or walk.blocked_by_50_rule or walk.levels_walked):
        return
    builder.heading("OWNERSHIP (legal ownership walked by the code; verify on the registry)")
    for edge in walk.edges[:MAX_OWNERSHIP_EDGES]:
        pct = f"{edge.pct:g}%" if edge.pct is not None else "unknown"
        child, parent = _name_of(edge.child, index), _name_of(edge.parent, index)
        source, as_of = clean(edge.source, 40) or "unknown", clean(edge.as_of, 20) or "unknown"
        builder.add(
            "O", f"{child} is owned by {parent} | pct={pct} | source={source} | as_of={as_of}",
            f"ownership edge: {child} owned by {parent}", values=(child, parent, pct, source, as_of),
        )
    stops = _unique([_name_of(n, index) for n in walk.unresolved], MAX_NOTES)
    blocked = _unique([_name_of(n, index) for n in walk.blocked_by_50_rule], MAX_NOTES)
    summary = f"ownership walk: levels walked={walk.levels_walked}"
    summary += f" | stopped before a natural person at: {'; '.join(stops)}" if stops else ""
    summary += f" | blocked by the 50% rule at: {'; '.join(blocked)}" if blocked else ""
    builder.add("O", summary, "where the ownership walk stopped", values=[*stops, *blocked])


def _add_dated_events(
    builder: _Builder, result: Mapping[str, Any], node_to_f: Mapping[str, str]
) -> List[str]:
    """Event dates with the finding ids they belong to. Never the event's title or description."""
    timeline = result.get("timeline")
    events: List[Tuple[str, str]] = []
    for item in timeline if isinstance(timeline, list) else []:
        if not isinstance(item, Mapping):
            continue
        stamp = clean(item.get("timestamp"), 30)
        cited = list(dict.fromkeys(node_to_f[str(n)] for n in item.get("node_ids") or [] if str(n) in node_to_f))
        if re.fullmatch(r"\d{4}(?:-\d{2}(?:-\d{2})?)?[0-9T:.+\-Z]*", stamp) and cited:
            events.append((stamp, ",".join(cited)))
    if not events:
        return []
    builder.heading("DATED EVENTS (a date from the source; cite the finding ids on its line)")
    shown = sorted(events)[:MAX_DATED_EVENTS]
    for stamp, cite_ids in shown:
        builder.raw(f"date={stamp} | cite={cite_ids}")
    return [stamp for stamp, _ids in shown]


def _jurisdiction_words(jurisdiction: str) -> FrozenSet[str]:
    return frozenset(JURISDICTION_WORDS.get(jurisdiction.lower().split("-")[0], ()))


def build_evidence(result: Mapping[str, Any]) -> Optional[NarrativeEvidence]:
    """The evidence block for ``result``, or ``None`` when there is no valid PI block or no relevant finding.

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
    node_to_f, labels = _add_findings(builder, shown, index, block)
    _add_sanctions(builder, block)
    _add_gaps(builder, block)
    _add_ownership(builder, block, index)
    dates = _add_dated_events(builder, data, node_to_f)
    return NarrativeEvidence(
        text="\n".join(builder.lines).strip("\n"),
        key=dict(builder.key),
        finding_labels=labels,
        lines=dict(builder.by_id),
        values=tuple(builder.values),
        date_values=tuple(dates),
        extra_words=_jurisdiction_words(engagement.jurisdiction),
    )
