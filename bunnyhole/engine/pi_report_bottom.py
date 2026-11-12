"""The PI report's Bottom line: a short labelled list (at most six one-line bullets, each at most 220 characters).

    - **Sanctions:** ...      what the screening found and which lists did NOT run (the EU list always)
    - **Registry:** ...       the subject's registry profile (only when a registry record matched)
    - **Findings:** ...       how many findings are about the subject, the strongest one, what was set aside
    - **Biggest gap:** ...    the single most important gap
    - **Not covered:** ...    expected source classes not searched, partial coverage
    - **Next step:** ...      the recommended next step

Pure and deterministic. Every string from the result is untrusted data: it is made inert (``_inline``) and never
interpreted. Node ids are replaced by human labels (looked up in the nodes, the findings, the registry profile and the
sanctions hits); a registry identifier (LEI, company, CIK) keeps its id next to the label, any other id with no label is
shortened. A bullet that is too long is cut at a word boundary and ends in an ellipsis, never mid-word.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from bunnyhole.engine.pi import CaseType, EntityProfile, EscalationTrigger, FindingLabel, PIBlock, SanctionsScreening
from bunnyhole.engine.pi_escalation import FIFTY_RULE_NOT_EVALUABLE, fifty_rule_not_evaluable, registry_short_for
from bunnyhole.engine.pi_reference import playbook_for
from bunnyhole.engine.pi_report_common import (
    _LABELS_STRONGEST_FIRST,
    _MD_ESCAPES,
    ELLIPSIS,
    Ranked,
    _distinct,
    _graph_matches,
    _inline,
    _is_searched,
    _named,
    _partial_rows,
    _plural,
    _primary_hits,
    _relevant,
    _sentence,
    _undecorated,
    _weak_matches,
    truncate_words,
)

MAX_BULLET_CHARS = 220
_MAX_LABEL_CHARS = 48
_MAX_ID_CHARS = 24
_MAX_WHY_LABEL_CHARS = 26
_REGISTRY_ID_PREFIXES = ("lei:", "company:", "psc:", "cik:")
_REGISTRY_ID_WITH_LABEL_MAX = 30
_ID_PREFIXES = (
    "lei", "company", "psc", "cik", "sanction", "sec", "hn", "article", "openalex", "wikidata", "beneish", "loc", "ein",
    "seed", "profile", "selector",
)
_ID_PATTERN = r"(?:%s):[^\s,;()]+" % "|".join(_ID_PREFIXES)
_ACTION_PREFIXES: Tuple[str, ...] = (
    "run through", "request", "field verification", "confirm with", "confirm corporate status", "verify", "obtain",
    "serve", "subpoena", "submit", "retain",
)
#: Triggers that always lead the next step (escalation keys of ``pi_reference``): a sanctions/50%-rule/PEP link or a
#: nominee / secrecy-jurisdiction chain.
_LEADING_TRIGGER_KEYS = frozenset({"sanctions_or_50_rule", "unresolved_ownership"})
_CUSTODIAN_TRIGGER_KEY = "custodian_finding"
_ENTITY_DILIGENCE_CASES = frozenset({CaseType.DUE_DILIGENCE, CaseType.BACKGROUND})
NO_ESCALATION = "No escalation indicated."
NO_ESCALATION_ENTITY = (
    "No escalation indicated on the public record; to go further order the registry filings and corporate documents "
    "from the primary registry"
)


# --------------------------------------------------------------------------- text

_WHITESPACE = re.compile(r"\s+")


def _escape(text: str) -> str:
    """Inert text that keeps its edge spaces (a piece of a longer line)."""
    return "".join(_MD_ESCAPES.get(ch, ch) for ch in _WHITESPACE.sub(" ", text))


class _Labels:
    """Node id -> human label, from the nodes, the registry profile, the findings and the sanctions hits."""

    def __init__(self, block: PIBlock, names: Mapping[str, str]) -> None:
        self._labels: Dict[str, str] = {}
        profile = block.entity_profile
        if profile is not None and profile.lei.strip() and profile.legal_name.strip():
            self._labels[f"lei:{profile.lei.strip()}"] = str(_inline(profile.legal_name))
        for finding in block.findings:
            if finding.node_id and finding.label.strip():
                self._labels.setdefault(finding.node_id, str(_inline(_undecorated(finding.label))))
        for hit in block.sanctions.hits:
            if isinstance(hit, Mapping) and hit.get("node_id") and hit.get("name"):
                self._labels.setdefault(str(hit["node_id"]), str(_inline(hit["name"])))
        self._labels.update({str(k): str(v) for k, v in names.items()})
        known = sorted((k for k in self._labels if k), key=len, reverse=True)
        pattern = "|".join([re.escape(k) for k in known] + [_ID_PATTERN])
        self._id_re = re.compile(pattern)

    def label(self, node_id: str, max_chars: int = _MAX_LABEL_CHARS, with_id: bool = True) -> str:
        """The label for an id: ``label`` (plus ``(id)`` for a short registry identifier), else a shortened id."""
        label = self._labels.get(node_id, "")
        clean_id = str(_inline(node_id))
        if not label or label == clean_id:
            raw = str(node_id)
            return str(_inline(raw if len(raw) <= _MAX_ID_CHARS else raw[: _MAX_ID_CHARS - 1] + ELLIPSIS))
        shown = truncate_words(label, max_chars)
        if with_id and node_id.startswith(_REGISTRY_ID_PREFIXES) and len(clean_id) <= _REGISTRY_ID_WITH_LABEL_MAX:
            return f"{shown} ({clean_id})"
        return shown

    def humanize(self, text: Any, max_label: int = _MAX_LABEL_CHARS, with_id: bool = True) -> str:
        """Untrusted text, inert, with every node id replaced by its label (or a shortened id)."""
        raw = str(text if text is not None else "")
        out: List[str] = []
        last = 0
        for match in self._id_re.finditer(raw):
            out.append(_escape(raw[last:match.start()]))
            out.append(self.label(match.group(0), max_label, with_id))
            last = match.end()
        out.append(_escape(raw[last:]))
        return _WHITESPACE.sub(" ", "".join(out)).strip()


def _bullet(label: str, text: str) -> str:
    """``- **Label:** text`` on one line, the text cut at a word boundary so the whole line fits the limit."""
    prefix = f"- **{label}:** "
    return prefix + truncate_words(text, MAX_BULLET_CHARS - len(prefix))


def _budget(label: str) -> int:
    return MAX_BULLET_CHARS - len(f"- **{label}:** ")


def _first_fitting(label: str, candidates: Sequence[str]) -> str:
    """The first candidate that fits the bullet; the last one, cut at a word boundary, when none does."""
    room = _budget(label)
    return next((c for c in candidates if len(c) <= room), candidates[-1])


# --------------------------------------------------------------------------- sanctions


def _list_names_only(entries: Iterable[str]) -> str:
    """List names without the per-list reason (reasons live in the Sanctions screening section)."""
    names = []
    for entry in _distinct(entries):
        match = re.match(r"^\s*([^:()]+?)\s*(?::|\()", str(entry))
        names.append((match.group(1) if match else str(entry)).strip())
    return ", ".join(_distinct(names))


def _graph_match_clause(sanctions: SanctionsScreening, labels: _Labels) -> str:
    matches = _graph_matches(sanctions)
    if not matches:
        return ""
    names = _distinct(labels.humanize(h.get("name") or h.get("node_id") or "an unnamed entity") for h in matches)
    count = len(matches)
    return (
        f"{_plural(count, 'other graph entity', 'other graph entities')} "
        f"{'matches' if count == 1 else 'match'} a list entry (soft): {_named(names, 1)}"
    )


def _weak_match_clauses(sanctions: SanctionsScreening) -> Tuple[str, str]:
    """The weak-name-match clause, long and short (``("", "")`` when there is none)."""
    count = len(_weak_matches(sanctions))
    if not count:
        return "", ""
    short = f"{_plural(count, 'weak name match', 'weak name matches')}, not linked"
    return f"{short} (verify on the primary list)", short


def _flag_clause(block: PIBlock, labels: _Labels) -> str:
    blocked = [labels.label(node) for node in block.ownership.blocked_by_50_rule]
    if not blocked:
        # next to a sanctions hit, say when the 50% rule could not be checked (no percentages) rather than stay silent
        if _primary_hits(block.sanctions) and fifty_rule_not_evaluable(block.ownership):
            return FIFTY_RULE_NOT_EVALUABLE
        return ""
    return f"OFAC 50% rule: {_plural(len(blocked), 'entity', 'entities')} blocked via ownership ({_named(blocked, 1)})"


def _hit_sentence(
    hits: Sequence[Mapping[str, Any]], labels: _Labels, max_names: int, max_lists: int, name_chars: int
) -> str:
    names = _distinct(
        truncate_words(
            labels.humanize(h.get("name") or h.get("match") or h.get("node_id") or "an unnamed entry"), name_chars
        )
        for h in hits
    )
    lists = _distinct(h.get("list") or "an unnamed list" for h in hits)
    return (
        f"soft name match to {_named(names, max_names)} on {_named(lists, max_lists)}; "
        "verify on the primary list before relying on it."
    )


#: (names shown, lists shown, characters per name): most detail first; the bullet takes the first that fits.
_HIT_DETAIL_LEVELS: Tuple[Tuple[int, int, int], ...] = (
    (3, 3, 60), (2, 3, 60), (2, 2, 40), (1, 2, 40), (1, 1, 40), (1, 1, 24),
)


_NOT_CLEARANCE = "No hit on a screened list is not clearance."
_NOT_CLEARANCE_SHORT = "No hit is not clearance."


def _weak_match_candidates(
    sanctions: SanctionsScreening, missing: str, others: Sequence[str], weak_long: str, weak_short: str
) -> List[str]:
    """Bullet texts for a no-hit run with a weak name match, most informative first.

    Every one keeps the not-clearance closing: when the 220-character cap bites, the weak clause is shortened, the
    other clauses are dropped, then the not-screened list becomes a count, but the closing is never cut.
    """
    screened = ", ".join(_distinct(sanctions.screened)) or "none"
    compact = f"{len(_distinct(sanctions.not_screened)) or 'all'} lists (see Sanctions screening)"
    out: List[str] = []
    for missing_text in (missing, compact):
        base = f"{sanctions.status}; Screened: {screened}; NOT screened: {missing_text}."
        for kept in range(len(others), -1, -1):
            for weak in (weak_long, weak_short):
                tail = _sentence("; ".join([weak, *others[:kept]]))
                out += [f"{base} {tail} {_NOT_CLEARANCE}", f"{base} {tail} {_NOT_CLEARANCE_SHORT}"]
    return out


def _sanctions_bullet(block: PIBlock, labels: _Labels) -> str:
    """A hit always leads and is always a soft match; a partial run never reads as clear. Without a hit the lists that
    did not run (the EU list always) are named here; with a hit they are named in the Not covered bullet, which keeps this
    one short enough for the 50% rule and graph-match clauses. Names shrink before those clauses are dropped."""
    sanctions = block.sanctions
    hits = _primary_hits(sanctions)
    missing = _list_names_only(sanctions.not_screened)
    if not missing:
        missing = "all lists (screening did not run)" if sanctions.status == "not_run" else "none recorded"
    weak_long, weak_short = _weak_match_clauses(sanctions)
    others = [clause for clause in (_flag_clause(block, labels), _graph_match_clause(sanctions, labels)) if clause]
    extras = ([weak_long] if weak_long else []) + others
    if not hits and weak_long:
        return _bullet("Sanctions", _first_fitting("Sanctions", _weak_match_candidates(sanctions, missing, others, weak_long, weak_short)))
    candidates: List[str] = []
    for kept in range(len(extras), -1, -1):
        tail = "; ".join(extras[:kept])
        if hits:
            for max_names, max_lists, name_chars in _HIT_DETAIL_LEVELS:
                text = _hit_sentence(hits, labels, max_names, max_lists, name_chars)
                candidates.append(f"{text} {_sentence(tail)}" if tail else text)
        else:
            screened = ", ".join(_distinct(sanctions.screened)) or "none"
            base = f"{sanctions.status}; Screened: {screened}; NOT screened: {missing}."
            base = f"{base} {_sentence(tail)}" if tail else base
            candidates += [f"{base} No hit on a screened list is not clearance.", base]
    return _bullet("Sanctions", _first_fitting("Sanctions", candidates))


# --------------------------------------------------------------------------- registry, findings, gap, coverage


def _registry_bullet(profile: Optional[EntityProfile]) -> str:
    if profile is None:
        return ""
    lei = f"LEI {_inline(profile.lei)}" if _inline(profile.lei) else ""
    parts = [_inline(profile.legal_name), lei, _inline(profile.status), _inline(profile.jurisdiction)]
    base = ", ".join(part for part in parts if part)
    if not base:
        return ""
    parents = _distinct(profile.parents)
    candidates = [f"{base}; parents: {'; '.join(parents)}"] if parents else []
    candidates.append(base)
    return _bullet("Registry", _first_fitting("Registry", candidates))


def _strongest_clause(relevant: Ranked, max_name: int, hedge: str) -> str:
    """Name the top-ranked finding only when it is alone at the top rank (label, then source count)."""
    top, label = relevant[0]
    key = (label, top.source_count)
    tied = sum(1 for f, lab in relevant if (lab, f.source_count) == key)
    if tied > 1:
        return f"no single strongest finding ({tied} tied at {label.value})"
    note = hedge if label is FindingLabel.LEAD else ""
    name = truncate_words(str(_inline(_undecorated(top.label))), max_name)
    return f"Strongest finding: {name}, labelled {label.value} on {_plural(top.source_count, 'source')}{note}"


def _findings_bullet(ranked: Ranked) -> str:
    relevant = _relevant(ranked)
    set_aside = len(ranked) - len(relevant)
    aside = (
        f"{_plural(set_aside, 'unrelated or low-relevance record')} "
        f"{'was' if set_aside == 1 else 'were'} set aside (see JSON)"
    ) if set_aside else ""
    if not ranked:
        return _bullet("Findings", "No findings were established.")
    if not relevant:
        return _bullet("Findings", _sentence("; ".join(["No finding is rated subject or related"] + ([aside] if aside else []))))
    parts = [
        f"{sum(1 for _, lab in relevant if lab is label)} {label.value}"
        for label in _LABELS_STRONGEST_FIRST
        if any(lab is label for _, lab in relevant)
    ]
    head = f"{len(relevant)} relevant ({', '.join(parts)})"
    hedges = (" (a lead, not established; corroborate before relying on it)", " (a lead, not established)")
    candidates = [
        _sentence("; ".join(c for c in (head, _strongest_clause(relevant, max_name, hedge), aside) if c))
        for max_name in (60, 40, 24)
        for hedge in hedges
    ]
    candidates.append(_sentence("; ".join(c for c in (head, aside) if c)))
    return _bullet("Findings", _first_fitting("Findings", candidates))


def _partial_summary(row_class: str, skipped: Sequence[str]) -> str:
    return f"{_inline(row_class)} ({', '.join(_inline(s) for s in skipped)} not reached)"


def _lists_in_not_covered(block: PIBlock) -> bool:
    """True when the sanctions lists that did not run are named in the Not covered bullet (a primary hit was found,
    so the Sanctions bullet is kept for the hit); otherwise the Sanctions bullet names them."""
    return bool(_primary_hits(block.sanctions))


def _coverage_gaps(block: PIBlock) -> Tuple[str, str, str]:
    """``(sanctions lists NOT screened, classes not searched, partial coverage)``; any may be empty.

    The sanctions class is left out of the partial coverage when the screening block already names the lists that did
    not run (it would only repeat them)."""
    missing = _list_names_only(block.sanctions.not_screened)
    lists = f"sanctions lists NOT screened: {missing}" if missing and _lists_in_not_covered(block) else ""
    not_searched = [str(_inline(row.source_class)) for row in block.coverage if not _is_searched(row)]
    partial = [
        _partial_summary(row.source_class, row.skipped)
        for row in _partial_rows(block)
        if not (row.source_class == "sanctions_pep" and block.sanctions.not_screened)
    ]
    return (
        lists,
        f"expected source classes not searched: {_named(not_searched)}" if not_searched else "",
        f"partial coverage: {_named(partial)}" if partial else "",
    )


class _GapItem(NamedTuple):
    full: str
    short: str  # the form used under "also open"
    in_not_covered: bool  # also stated in the Not covered bullet, so not repeated under "also open"


def _gap_items(block: PIBlock, labels: _Labels) -> List[_GapItem]:
    """Gaps in priority order: contradiction, unresolved ownership, source classes not searched, partial coverage,
    evidence gap. Coverage gaps are repeated in the Not covered bullet, so they are not listed again as "also open"."""
    unresolved = [labels.label(node) for node in block.ownership.unresolved]
    gaps = [labels.humanize(g).rstrip(" .") for g in block.evidence_gaps]
    _lists, not_searched, partial = _coverage_gaps(block)
    items: List[_GapItem] = []
    if block.contradictions:
        first = block.contradictions[0]
        text = f"a contradiction between records ({_inline(first.kind)}: {labels.humanize(first.description)})"
        items.append(_GapItem(text, f"a contradiction ({_inline(first.kind)})", False))
        if len(block.contradictions) > 1:
            more = _plural(len(block.contradictions) - 1, "further contradiction")
            items.append(_GapItem(more, more, False))
    if unresolved:
        short = f"ownership unresolved at {_named(unresolved)}"
        items.append(_GapItem(f"{short} (the walk ended before a natural person)", short, False))
    if not_searched:
        items.append(_GapItem(not_searched, not_searched, True))
    if partial:
        items.append(_GapItem(partial, partial, True))
    if gaps:
        items.append(_GapItem(f"evidence gap: {_named(gaps)}", f"evidence gap: {_named(gaps, 1)}", False))
    return items


def _gap_bullet(block: PIBlock, labels: _Labels) -> str:
    items = _gap_items(block, labels)
    if not items:
        return _bullet(
            "Biggest gap",
            "No gaps were recorded in the structured analysis, but absence from the sources searched is not proof.",
        )
    first, rest = items[0], [item.short for item in items[1:] if not item.in_not_covered]
    candidates = []
    if rest:
        candidates.append(_sentence(f"{first.full}; also open: {'; '.join(rest)}"))
        candidates.append(_sentence(f"{first.full}; also open: {_plural(len(rest), 'more item')}"))
    candidates.append(_sentence(first.full))
    return _bullet("Biggest gap", _first_fitting("Biggest gap", candidates))


def _not_covered_bullet(block: PIBlock) -> str:
    parts = [part for part in _coverage_gaps(block) if part]
    if not parts:
        return ""
    return _bullet("Not covered", _sentence("; ".join(parts)))


# --------------------------------------------------------------------------- next step


def _is_action_line(line: str) -> bool:
    """A handoff line that tells someone to do something (not an engagement header or context line)."""
    return str(_inline(line)).lower().startswith(_ACTION_PREFIXES)


def _short_registry(jurisdiction: str, room: int) -> str:
    """The primary registry's short name for a jurisdiction, cut to ``room`` characters at a word boundary."""
    return truncate_words(str(_inline(registry_short_for(jurisdiction))).strip(), max(room, 12))


def _escalate_text(first: EscalationTrigger, further: int, labels: _Labels) -> str:
    room = _budget("Next step")
    head = f"escalate, trigger fired: {labels.humanize(first.trigger).rstrip(' .')}"
    more = f" ({_plural(further, 'further fired trigger')})" if further else ""
    why = labels.humanize(first.why, max_label=_MAX_WHY_LABEL_CHARS, with_id=False)
    room_for_why = room - len(head) - len(more) - len(" ()") - len(".")
    if why and room_for_why >= 20:
        return _sentence(f"{head} ({truncate_words(why, room_for_why)}){more}")
    return _sentence(truncate_words(head, room - len(more) - 1) + more)


def _entity_next_step(block: PIBlock, labels: _Labels) -> str:
    """Due diligence / background of an entity: sanctions, 50%-rule and nominee triggers lead, then any fired trigger but
    the custodian-bearing one (it fires for every company: its records are always non-public), then the registry."""
    keys = playbook_for(block.engagement.case_type).escalate_keys
    fired = [t for t in block.escalation_triggers if t.fired]
    leading = [t for t in fired if keys.get(t.trigger) in _LEADING_TRIGGER_KEYS]
    other = [t for t in fired if t not in leading and keys.get(t.trigger) != _CUSTODIAN_TRIGGER_KEY]
    chosen = leading + other
    if chosen:
        return _escalate_text(chosen[0], len(chosen) - 1, labels)
    jurisdiction = (block.entity_profile.jurisdiction if block.entity_profile else "") or block.engagement.jurisdiction
    tail = ")."
    head = f"{NO_ESCALATION_ENTITY} ("
    room = _budget("Next step") - len(head) - len(tail)
    return f"{head}{_short_registry(jurisdiction, room)}{tail}"


def _next_step_bullet(block: PIBlock, labels: _Labels) -> str:
    engagement = block.engagement
    if not engagement.subject_is_person and engagement.case_type in _ENTITY_DILIGENCE_CASES:
        return _bullet("Next step", _entity_next_step(block, labels))
    fired = [t for t in block.escalation_triggers if t.fired]
    if fired:
        return _bullet("Next step", _escalate_text(fired[0], len(fired) - 1, labels))
    action = next((line for line in block.handoff_sheet if _is_action_line(line)), None)
    if action is not None:
        return _bullet("Next step", _sentence(labels.humanize(action)))
    if block.custodians:
        c = block.custodians[0]
        return _bullet(
            "Next step",
            _sentence(
                f"request via counsel, {_inline(c.instrument)} to {_inline(c.custodian)} for {_inline(c.finding)}"
            ),
        )
    return _bullet("Next step", NO_ESCALATION)


# --------------------------------------------------------------------------- entry point


def _case_bullet(block: PIBlock) -> str:
    """Stop reason plus the leading supported hypothesis. Absent when the run has no case board."""
    board = getattr(block, "case_board", None)
    reason = getattr(getattr(board, "stop_reason", None), "value", getattr(board, "stop_reason", None))
    if board is None or not reason:
        return ""
    hypotheses = list(getattr(board, "hypotheses", []) or [])
    supported = [
        item for item in hypotheses
        if str(getattr(getattr(item, "status", ""), "value", getattr(item, "status", ""))) == "supported"
    ]
    if supported:
        best = max(supported, key=lambda item: float(getattr(item, "score", 0) or 0))
        text = f"stop {reason}; leading read: {getattr(best, 'text', '')} (score {float(getattr(best, 'score', 0) or 0):g})"
    else:
        open_keys = [
            str(getattr(item, "key", "")) for item in hypotheses
            if str(getattr(getattr(item, "status", ""), "value", getattr(item, "status", ""))) in ("open", "weakened")
        ]
        shown = ", ".join(key for key in open_keys if key) or "none"
        text = f"stop {reason}; no hypothesis supported; open questions: {shown}"
    return _bullet("Case", text)


def bottom_line_lines(block: PIBlock, ranked: Ranked, names: Mapping[str, str]) -> List[str]:
    """The Bottom line bullets, sanctions first: at most six one-line ``- **Label:** text`` entries.

    A casework board with a stop reason adds a Case bullet in front and the list is cut back to six.
    A sweep block is unchanged.
    """
    labels = _Labels(block, names)
    bullets = [
        _sanctions_bullet(block, labels),
        _registry_bullet(block.entity_profile),
        _findings_bullet(ranked),
        _gap_bullet(block, labels),
        _not_covered_bullet(block),
        _next_step_bullet(block, labels),
    ]
    kept = [bullet for bullet in bullets if bullet]
    case_line = _case_bullet(block)
    if case_line:
        return [case_line, *kept][:6]
    return kept


__all__ = ["MAX_BULLET_CHARS", "NO_ESCALATION", "NO_ESCALATION_ENTITY", "bottom_line_lines"]
