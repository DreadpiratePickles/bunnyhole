"""Shared helpers of the PI report modules (``pi_report`` and ``pi_report_bottom``).

Pure and deterministic. All untrusted text is made inert here (see ``_inline``) and never interpreted; the
finding-ranking helpers decide which findings are about the subject and at which label they may be shown.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from bunnyhole.engine.pi import CoverageRow, Finding, FindingLabel, PIBlock, SanctionsScreening, label_finding

_LABEL_RANK: Dict[FindingLabel, int] = {FindingLabel.CONFIRMED: 0, FindingLabel.PROBABLE: 1, FindingLabel.LEAD: 2}
_LABELS_STRONGEST_FIRST: Tuple[FindingLabel, ...] = (FindingLabel.CONFIRMED, FindingLabel.PROBABLE, FindingLabel.LEAD)
_MAX_NAMED = 3
_SHOWN_RELEVANCE: Tuple[str, ...] = ("subject", "related")
ELLIPSIS = "…"


class _Raw(str):
    """Text that has already been made inert by ``_inline`` (or is authored here), so a table cell must not escape
    it a second time. Concatenating loses the type, so a value built from several parts is wrapped again."""


_MD_ESCAPES = {"\\": "\\\\", "[": "\\[", "]": "\\]", "`": "\\`", "<": "\\<", ">": "\\>"}


def _inline(value: Any) -> str:
    """Untrusted text as inert one-line Markdown.

    All whitespace (including newlines) is collapsed to single spaces so the text cannot open a heading or a table
    row. Backslash, square brackets, backticks and angle brackets are backslash-escaped, so a link, an image, a
    code span or an HTML tag cannot form (a literal backslash is escaped first so it cannot cancel an escape).
    """
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    text = "".join(_MD_ESCAPES.get(ch, ch) for ch in text)
    return _Raw("\\" + text if text.startswith("#") else text)


def _plural(count: int, singular: str, plural: str = "") -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _sentence(text: str) -> str:
    return text.rstrip(" .") + "."


def _named(items: Sequence[str], limit: int = _MAX_NAMED) -> str:
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return shown + (f" and {extra} more" if extra > 0 else "")


def truncate_words(text: str, limit: int) -> str:
    """``text`` cut at a word boundary to at most ``limit`` characters, ending in an ellipsis when it was cut.

    Never cuts inside a word (and so never inside a Markdown escape, which has no space in it). A single word longer
    than ``limit`` is kept whole, then shortened with the ellipsis only as a last resort.
    """
    if len(text) <= limit:
        return text
    room = max(limit - 1, 1)
    head = text[:room]
    if not text[room].isspace():  # the cut falls inside a word: back up to the previous space
        head = head.rsplit(" ", 1)[0] if " " in head else ""
    head = head.rstrip(" ,;:-(")
    if not head:  # one unbroken word: keep as much of it as fits, never ending on a lone backslash
        head = text[:room].rstrip("\\")
    return head + ELLIPSIS


def _undecorated(label: Any) -> str:
    """The label without the leading emoji or symbol the agents prefix to it (the text itself is untouched)."""
    text = str(label)
    start = 0
    while start < len(text) and (unicodedata.category(text[start]) in ("So", "Sk", "Mn", "Cf") or text[start].isspace()):
        start += 1
    return text[start:] or text


def _distinct(items: Iterable[Any]) -> List[str]:
    """Non-empty inline texts, first-seen order, without duplicates."""
    return list(dict.fromkeys(text for text in (_inline(i) for i in items) if text))


def _effective_label(finding: Finding) -> FindingLabel:
    """The weaker of the recorded label and the label the source count supports."""
    supported = label_finding(finding.source_count)
    return max(finding.finding_label, supported, key=lambda label: _LABEL_RANK[label])


def _ranked_findings(findings: Sequence[Finding]) -> List[Tuple[Finding, FindingLabel]]:
    pairs = [(f, _effective_label(f)) for f in findings]
    # sorted() is stable: ties keep their original order, never alphabetical.
    return sorted(pairs, key=lambda p: (_LABEL_RANK[p[1]], -p[0].source_count))


Ranked = Sequence[Tuple[Finding, FindingLabel]]


def _relevant(ranked: Ranked) -> List[Tuple[Finding, FindingLabel]]:
    """Findings about the subject (relevance subject or related); everything else is set aside."""
    return [(f, lab) for f, lab in ranked if f.relevance in _SHOWN_RELEVANCE]


def _is_searched(row: CoverageRow) -> bool:
    return row.searched and row.outcome != "not_searched"


def _partial_rows(block: PIBlock) -> List[CoverageRow]:
    """Coverage rows where some source ran and another was tried but not reached."""
    return [row for row in block.coverage if _is_searched(row) and row.sources and row.skipped]


def _partial_text(row: CoverageRow) -> str:
    ran = ", ".join(_inline(s) for s in row.sources)
    missed = ", ".join(_inline(s) for s in row.skipped)
    return f"partial: {ran} ran; {missed} skipped or errored (not reached)"


def _primary_hits(sanctions: SanctionsScreening) -> List[Mapping[str, Any]]:
    """Hits the sanctions screening itself produced (not the graph entities matched against them)."""
    return [h for h in sanctions.hits if isinstance(h, Mapping) and not h.get("graph_match")]


def _weak_matches(sanctions: SanctionsScreening) -> List[Mapping[str, Any]]:
    """List entries that matched on a name only and were not linked to the subject (``set_aside_candidates``)."""
    return [w for w in sanctions.weak_matches if isinstance(w, Mapping)]


def _graph_matches(sanctions: SanctionsScreening) -> List[Mapping[str, Any]]:
    """Other graph entities whose name matches a sanctions-list entry (soft), flagged ``graph_match``."""
    return [h for h in sanctions.hits if isinstance(h, Mapping) and h.get("graph_match")]
