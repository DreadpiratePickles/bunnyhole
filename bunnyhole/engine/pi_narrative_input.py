"""Evidence input of the PI report's AI analysis: one deterministic, minimal, id-tagged text block.

Built only from the structured data the code-built report already prints (``result["pi"]``, the node receipts the
findings stand on, and the timeline), never from raw page bodies. Each evidence line carries a stable id so the model
can cite it and the validator can check the citation:

- ``F1..`` findings, in the report's own ranking (confirmed first), with the label the CODE computed;
- ``S1..`` sanctions screening (status, lists screened, lists NOT screened, possible hits);
- ``W1..`` weak name matches that were set aside (disclosed as set aside, not as findings);
- ``G1..`` coverage and gaps (standing limits, source classes searched or not, identity notes, contradictions);
- ``O1..`` ownership edges and where the walk stopped.

What is deliberately NOT included: the client name, the matter reference, the purpose free text, ``raw_snippet``
page extracts, unrelated records, API keys. Every value is collapsed to one line and stripped of control
characters, so a hostile string cannot open a new evidence line or forge an id. Pure: no network, no model.
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
from bunnyhole.engine.pi_report_common import (
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
MAX_DATED_EVENTS = 15
MAX_OWNERSHIP_EDGES = 15
MAX_COVERAGE_ROWS = 12
MAX_NOTES = 5
_NAME_CHARS = 120
_FACT_CHARS = 200
_URL_CHARS = 200
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

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
    """The evidence text sent to the model plus everything the validator and the report key need."""

    text: str
    key: Mapping[str, KeyEntry]
    finding_labels: Mapping[str, str]  # F id -> confirmed | probable | lead, as computed by the code

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


def _unique(items: Sequence[Any], limit: int, chars: int = 100) -> List[str]:
    return list(dict.fromkeys(text for text in (clean(i, chars) for i in items) if text))[:limit]


class _Builder:
    """Collects evidence lines and the key, handing out ids per family in order."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.key: Dict[str, KeyEntry] = {}
        self._counts: Dict[str, int] = {}

    def heading(self, title: str) -> None:
        self.lines += ["", f"-- {title} --"]

    def add(self, family: str, line: str, description: str, receipt_ids: Tuple[str, ...] = ()) -> str:
        self._counts[family] = self._counts.get(family, 0) + 1
        item_id = f"{family}{self._counts[family]}"
        self.lines.append(f"[{item_id}] {line}")
        self.key[item_id] = KeyEntry(clean(description, 160), receipt_ids)
        return item_id

    def raw(self, line: str) -> None:
        self.lines.append(line)


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


def _add_findings(
    builder: _Builder, shown: Sequence[Tuple[Any, Any]], index: Mapping[str, Mapping[str, Any]]
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Findings as F ids. Returns (F id -> node id, F id -> label value)."""
    builder.heading("FINDINGS (the label is computed by code; never change or upgrade it)")
    node_to_f: Dict[str, str] = {}
    labels: Dict[str, str] = {}
    for finding, label in shown:
        seen: set = set()
        receipts: List[Mapping[str, Any]] = []
        for candidate in _receipts(index.get(finding.node_id, {})):
            rid = str(candidate.get("receipt_id") or "")
            if rid and rid not in seen and _is_external(candidate):
                seen.add(rid)
                receipts.append(candidate)
        receipts = receipts[:MAX_RECEIPTS_PER_FINDING]
        name = clean(_undecorated(finding.label), _NAME_CHARS)
        line = (
            f"label={label.value} | sources={finding.source_count} | freshness={clean(finding.freshness, 20)} | "
            f"relevance={clean(finding.relevance, 20)} | name: {name}"
        )
        receipt_ids = tuple(clean(r.get("receipt_id"), 40) for r in receipts)
        item_id = builder.add("F", line, f"{name} ({label.value}, {finding.source_count} source(s))", receipt_ids)
        node_to_f[finding.node_id] = item_id
        labels[item_id] = label.value
        for receipt in receipts:
            digest = str(receipt.get("sha256_proof") or "")
            parts = [
                f"receipt {clean(receipt.get('receipt_id'), 40)}",
                f"tool={clean(receipt.get('tool'), 40)}",
                f"url={clean(receipt.get('source_url'), _URL_CHARS)}",
            ]
            if _SHA256_RE.match(digest):
                parts.append(f"sha256={digest.lower()}")
            parts.append(f"fact: {clean(receipt.get('extracted_fact'), _FACT_CHARS)}")
            builder.raw("    - " + " | ".join(parts))
    return node_to_f, labels


def _add_sanctions(builder: _Builder, block: PIBlock) -> None:
    sanctions = block.sanctions
    builder.heading("SANCTIONS SCREENING")
    screened = _unique(sanctions.screened, MAX_LIST_ENTRIES) or ["none"]
    missed = _unique(sanctions.not_screened, MAX_LIST_ENTRIES) or ["none recorded"]
    builder.add(
        "S",
        f"status={sanctions.status} | lists screened: {'; '.join(screened)} | "
        f"lists NOT screened or not reached: {'; '.join(missed)}",
        "sanctions screening status and the lists screened or not screened",
    )
    for hit in _primary_hits(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(hit.get("name") or hit.get("match"), _NAME_CHARS)
        builder.add(
            "S",
            f"possible list match, SOFT and unverified (verify on the primary list) | list={clean(hit.get('list'), 60)}"
            f" | name={name} | url={clean(hit.get('url'), _URL_CHARS)}",
            f"possible sanctions-list match (soft): {name}",
        )
    for match in _graph_matches(sanctions)[:MAX_ITEMS_PER_KIND]:
        name = clean(match.get("name") or match.get("node_id"), _NAME_CHARS)
        builder.add(
            "S",
            f"another graph entity's name matches a listed entry, SOFT and unverified | entity={name} | "
            f"entry={clean(match.get('matched_entry'), _NAME_CHARS)} | list={clean(match.get('list'), 60)}",
            f"graph entity matches a sanctions-list entry (soft): {name}",
        )
    weak = _weak_matches(sanctions)[:MAX_ITEMS_PER_KIND]
    if weak:
        builder.heading("SET-ASIDE NAME MATCHES (weak, NOT linked to the subject; not findings)")
        for entry in weak:
            name = clean(entry.get("name"), _NAME_CHARS)
            builder.add(
                "W",
                f"weak name match, set aside and NOT linked | name={name} | reason={clean(entry.get('reason'), 120)}"
                f" | url={clean(entry.get('url'), _URL_CHARS)}",
                f"weak name match set aside, not a finding: {name}",
            )


def _coverage_text(row: CoverageRow) -> str:
    source_class = clean(row.source_class, 60)
    if not _is_searched(row):
        return f"source class {source_class}: NOT searched"
    ran = ", ".join(_unique(row.sources, 6, 40)) or "none named"
    text = f"source class {source_class}: searched, outcome={clean(row.outcome, 20) or 'unknown'}; sources that ran: {ran}"
    if row.skipped:
        text += f"; tried but NOT reached: {', '.join(_unique(row.skipped, 6, 40))}"
    return text


def _add_gaps(builder: _Builder, block: PIBlock) -> None:
    builder.heading("COVERAGE AND GAPS")
    builder.add("G", STANDING_LIMITS, "standing limits of this tool (what was not checked)")
    for row in block.coverage[:MAX_COVERAGE_ROWS]:
        text = _coverage_text(row)
        builder.add("G", text, text)
    for note in _unique(block.identity_notes, MAX_NOTES, 200):
        builder.add("G", f"identity note: {note}", f"identity note: {note}")
    for item in block.contradictions[:MAX_NOTES]:
        text = f"contradiction ({clean(item.kind, 40)}): {clean(item.description, 200)}"
        builder.add("G", text, text)
    for gap in _unique(block.evidence_gaps, MAX_NOTES, 200):
        builder.add("G", f"chronology gap: {gap}", f"chronology gap: {gap}")


def _add_ownership(builder: _Builder, block: PIBlock, index: Mapping[str, Mapping[str, Any]]) -> None:
    walk = block.ownership
    if not (walk.edges or walk.unresolved or walk.blocked_by_50_rule or walk.levels_walked):
        return
    builder.heading("OWNERSHIP (legal ownership walked by the code; verify on the registry)")
    for edge in walk.edges[:MAX_OWNERSHIP_EDGES]:
        pct = f"{edge.pct:g}%" if edge.pct is not None else "unknown"
        child, parent = _name_of(edge.child, index), _name_of(edge.parent, index)
        builder.add(
            "O",
            f"{child} is owned by {parent} | pct={pct} | source={clean(edge.source, 40) or 'not recorded'} | "
            f"as_of={clean(edge.as_of, 20) or 'not recorded'}",
            f"ownership edge: {child} owned by {parent}",
        )
    stops = _unique([_name_of(n, index) for n in walk.unresolved], MAX_NOTES)
    blocked = _unique([_name_of(n, index) for n in walk.blocked_by_50_rule], MAX_NOTES)
    summary = f"ownership walk: levels walked={walk.levels_walked}"
    summary += f" | stopped before a natural person at: {'; '.join(stops)}" if stops else ""
    summary += f" | blocked by the 50% rule at: {'; '.join(blocked)}" if blocked else ""
    builder.add("O", summary, "where the ownership walk stopped")


def _add_dated_events(builder: _Builder, result: Mapping[str, Any], node_to_f: Mapping[str, str]) -> None:
    timeline = result.get("timeline")
    events: List[Tuple[str, str, str]] = []
    for item in timeline if isinstance(timeline, list) else []:
        if not isinstance(item, Mapping):
            continue
        stamp = clean(item.get("timestamp"), 30)
        cited = list(dict.fromkeys(node_to_f[str(n)] for n in item.get("node_ids") or [] if str(n) in node_to_f))
        if stamp and any(ch.isdigit() for ch in stamp) and cited:
            events.append((stamp, ",".join(cited), clean(item.get("title"), 100)))
    if not events:
        return
    builder.heading("DATED EVENTS (each is dated in the source; cite the finding ids on its line)")
    for stamp, cite_ids, title in sorted(events)[:MAX_DATED_EVENTS]:
        builder.raw(f"date={stamp} | cite={cite_ids} | title: {title}")


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
    builder = _Builder()
    builder.heading("CASE")
    builder.raw(f"SUBJECT: {seed}")
    builder.raw(f"SUBJECT_KIND: {'person' if engagement.subject_is_person else 'entity'}")
    builder.raw(f"CASE_TYPE: {clean(engagement.case_type.value, 40)}")
    builder.raw(f"PURPOSE_CATEGORY: {clean(engagement.purpose_category, 60) or 'not recorded'}")
    if engagement.jurisdiction:
        builder.raw(f"JURISDICTION: {clean(engagement.jurisdiction, 40)}")
    node_to_f, labels = _add_findings(builder, shown, index)
    _add_sanctions(builder, block)
    _add_gaps(builder, block)
    _add_ownership(builder, block, index)
    _add_dated_events(builder, data, node_to_f)
    text = "\n".join(builder.lines).strip("\n")
    return NarrativeEvidence(text=text, key=dict(builder.key), finding_labels=labels)
