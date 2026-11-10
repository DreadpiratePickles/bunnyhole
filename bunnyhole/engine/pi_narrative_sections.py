"""Code-built sections of the AI analysis: "What is not established" and "Suggested next steps (lawful)".

No model output goes into these sections. Each line is fixed wording keyed by the kind of gap (see ``GapItem`` in
``pi_narrative_input``), filled only with strings the report itself prints, escaped, and tagged with its id. So the
classes of misstatement that a free-text model could make here (an unlawful step, a clearance sentence, a misdated
event) cannot occur. The lawful-action menu below is the whole vocabulary of next steps; every step starts with a verb
from :data:`NEXT_STEP_VERBS` (a test enforces it). Model-written next steps could later be added behind this same
closed menu (the model picking menu keys, never writing the step), but they are not today.
"""

from __future__ import annotations

from typing import Callable, Dict, FrozenSet, List, Sequence, Tuple

from bunnyhole.engine.pi_narrative_input import (
    CHRONOLOGY_GAP,
    CONTRADICTION,
    IDENTITY_NOTE,
    LEAD_ONLY,
    NOT_SEARCHED,
    OWNERSHIP_WALK,
    SANCTIONS_POSSIBLE,
    SANCTIONS_STATUS,
    SEARCHED,
    SET_ASIDE,
    STANDING_LIMITS,
    GapItem,
)
from bunnyhole.engine.pi_narrative_validate import escape_markdown

MAX_LINES = 24
#: More lead-only findings than this collapse into one line that lists their ids (one line each below this).
COLLAPSE_LEADS_ABOVE = 5
#: Kinds whose lines are never dropped, in the order they are written. Everything else follows, lead-only last.
CRITICAL_KINDS: Tuple[str, ...] = (SANCTIONS_STATUS, SANCTIONS_POSSIBLE, STANDING_LIMITS, OWNERSHIP_WALK, SET_ASIDE)
_OTHER_KINDS: Tuple[str, ...] = (CONTRADICTION, IDENTITY_NOTE, CHRONOLOGY_GAP, NOT_SEARCHED, SEARCHED, LEAD_ONLY)
_OMITTED_LINE = "- {n} further lines omitted; see the full code-built report above."
#: Every next step starts with one of these verbs: an action on records or a lawful request, never an event.
NEXT_STEP_VERBS: FrozenSet[str] = frozenset(
    {"Obtain", "Request", "Verify", "Review", "Search", "Check", "Screen", "Compare", "Archive", "Record", "Engage",
     "Seek", "Corroborate"}
)

_SCREENED_PREFIX = "screened: "
_BLOCKED_PREFIX = "blocked: "
_COURT = "Engage a licensed investigator or a lawyer to search court records for the subject."
_BY_SOURCE_CLASS: Dict[str, str] = {
    "court_dockets": _COURT,
    "corporate_registry": "Obtain the corporate registry extract for the subject entity from the registry of the jurisdiction.",
    "beneficial_ownership": "Request the filed ownership and officer records from the registry of the jurisdiction.",
    "sanctions_pep": "Screen the sanctions and PEP lists on their primary sources.",
    "news_adverse_media": "Search public news archives for the subject and record the sources searched.",
    "property_assets": "Search the land and property registries of the jurisdiction.",
}
_ARCHIVE_STEP = "Archive the cited source pages (for example with Save Page Now) before they change."
_LEGAL_PROCESS_STEP = (
    "Engage a licensed investigator or a lawyer for court records beyond the public portals searched, and for bank "
    "and telephone records, which only legal process can reach."
)


def _e(text: str) -> str:
    return escape_markdown(text)


def _missed_lists(item: GapItem) -> List[str]:
    return [n for n in item.names if not n.startswith(_SCREENED_PREFIX)]


def _stops(item: GapItem) -> Tuple[List[str], List[str]]:
    stops = [n for n in item.names if not n.startswith(_BLOCKED_PREFIX)]
    blocked = [n[len(_BLOCKED_PREFIX):] for n in item.names if n.startswith(_BLOCKED_PREFIX)]
    return stops, blocked


# --------------------------------------------------------------------------------------- what is not established


def _sanctions_status_line(item: GapItem) -> str:
    if item.label == "not_run":
        return "No sanctions list was screened; this is not a clear result."
    missed = _missed_lists(item)
    if missed:
        listed = "; ".join(_e(m) for m in missed)
        return (
            f"These sanctions lists were not screened or not reached: {listed}. "
            "A no-hit result on the lists that ran is not clearance."
        )
    return "A no-hit result on the sanctions lists screened is not clearance."


def _ownership_line(item: GapItem) -> str:
    stops, blocked = _stops(item)
    text = f"The ownership walk covered {_e(item.label)} level(s)."
    if stops:
        text += (
            f" It stopped before a natural person at: {'; '.join(_e(s) for s in stops)}, "
            "so beneficial ownership is not established."
        )
    else:
        text += " Legal ownership edges do not by themselves establish beneficial ownership."
    if blocked:
        text += f" The 50% rule applies at: {'; '.join(_e(b) for b in blocked)}."
    return text


_SEARCHED_BY_OUTCOME: Dict[str, str] = {
    "hit": "returned records; the records are cited above.",
    "positive": "returned records; the records are cited above.",
    "negative": "returned nothing; absence from this source is not proof of absence.",
    "empty": "returned nothing; absence from this source is not proof of absence.",
}


def _searched_outcome(outcome: str) -> str:
    """Fixed wording for what a searched source class returned (an unknown or unavailable outcome: not checked)."""
    return _SEARCHED_BY_OUTCOME.get(outcome.strip().lower(), "could not be checked.")


_NOT_ESTABLISHED: Dict[str, Callable[[GapItem], str]] = {
    STANDING_LIMITS: lambda g: (
        "This tool uses free public passive sources only; licensed or paid investigator databases, paid records, "
        "field work and interviews were not used."
    ),
    SANCTIONS_STATUS: _sanctions_status_line,
    SANCTIONS_POSSIBLE: lambda g: (
        f"{_e(g.label)} is a possible, soft name match on a sanctions list; it is unverified until checked on the "
        "primary list."
    ),
    SET_ASIDE: lambda g: (
        f"{_e(g.label)} is a weak name match that was set aside; it is not linked to the subject and is not a finding."
    ),
    NOT_SEARCHED: lambda g: f"Source class {_e(g.label)} was not searched.",
    SEARCHED: lambda g: f"Source class {_e(g.label)} {_searched_outcome(g.names[0] if g.names else '')}",
    IDENTITY_NOTE: lambda g: f"Identity note from the program: {_e(g.label)}",
    CONTRADICTION: lambda g: f"Contradiction recorded by the program: {_e(g.label)}",
    CHRONOLOGY_GAP: lambda g: f"Chronology gap recorded by the program: {_e(g.label)}",
    OWNERSHIP_WALK: _ownership_line,
    LEAD_ONLY: lambda g: (
        f"{_e(g.label)} rests on a single source and is a lead only; it needs a second independent source."
    ),
}


def _prioritised(gaps: Sequence[GapItem]) -> List[GapItem]:
    """``gaps`` with the critical kinds first (in :data:`CRITICAL_KINDS` order), then the others, lead-only last."""
    rank = {kind: i for i, kind in enumerate((*CRITICAL_KINDS, *_OTHER_KINDS))}
    return sorted((g for g in gaps if g.kind in rank), key=lambda g: rank[g.kind])


def _ids(items: Sequence[GapItem]) -> str:
    return ", ".join(g.item_id for g in items)


def _capped(critical: List[str], others: List[str]) -> List[str]:
    """Every critical line, then as many other lines as fit; an explicit line says how many were dropped."""
    kept = others[: max(0, MAX_LINES - len(critical))]
    dropped = len(others) - len(kept)
    return [*critical, *kept, *([_OMITTED_LINE.format(n=dropped)] if dropped else [])]


def not_established_lines(gaps: Sequence[GapItem]) -> List[str]:
    """Fixed-wording "not established" lines, each tagged with its id.

    Critical lines first and never dropped; many lead-only findings become one line listing their ids; anything else
    that does not fit is replaced by an explicit omission line.
    """
    ordered = [g for g in _prioritised(gaps) if g.kind in _NOT_ESTABLISHED]
    leads = [g for g in ordered if g.kind == LEAD_ONLY]
    collapse = len(leads) > COLLAPSE_LEADS_ABOVE
    critical = [f"- {_NOT_ESTABLISHED[g.kind](g)} [{g.item_id}]" for g in ordered if g.kind in CRITICAL_KINDS]
    others = [f"- {_NOT_ESTABLISHED[g.kind](g)} [{g.item_id}]" for g in ordered
              if g.kind not in CRITICAL_KINDS and not (collapse and g.kind == LEAD_ONLY)]
    if collapse:
        others.append(
            f"- {len(leads)} findings each rest on a single source and are leads only; each needs a second "
            f"independent source. [{_ids(leads)}]"
        )
    return _capped(critical, others)


# --------------------------------------------------------------------------------------- next steps


def _status_step(item: GapItem) -> str:
    missed = _missed_lists(item)
    if missed:
        return f"Screen the sanctions lists that were not reached ({'; '.join(_e(m) for m in missed)}) on their primary sources."
    if item.label != "lists_run":
        return "Screen the sanctions lists again on their primary sources."
    return ""


def _not_searched_step(item: GapItem) -> str:
    return _BY_SOURCE_CLASS.get(
        item.label,
        f"Search source class {_e(item.label)} through a licensed investigator or a lawyer where public sources do not reach it.",
    )


_NEXT_STEPS: Dict[str, Callable[[GapItem], str]] = {
    STANDING_LIMITS: lambda g: _LEGAL_PROCESS_STEP,
    SANCTIONS_STATUS: _status_step,
    SANCTIONS_POSSIBLE: lambda g: f"Verify the possible match for {_e(g.label)} on the primary list.",
    SET_ASIDE: lambda g: (
        f"Seek a second anchor (a shared domain, email, username or company) before treating {_e(g.label)} as related."
    ),
    NOT_SEARCHED: _not_searched_step,
    SEARCHED: lambda g: (
        f"Record the date, terms and sources of the {_e(g.label)} search so that it can be repeated or challenged."
    ),
    IDENTITY_NOTE: lambda g: (
        "Compare a second identifier (date of birth, address, company) before treating records as one person; "
        "if an interview would help, interview openly, identifying yourself and stating the purpose."
    ),
    CONTRADICTION: lambda g: "Obtain the primary record behind each side of the contradiction and compare their dates.",
    CHRONOLOGY_GAP: lambda g: "Obtain dated primary records for the period that the gap covers.",
    OWNERSHIP_WALK: lambda g: (
        "Obtain the shareholder register or the filed ownership records from the registry to continue the walk to a "
        "natural person, and verify the percentage chain."
    ),
    LEAD_ONLY: lambda g: f"Seek a second independent source for {_e(g.label)}.",
}


def next_step_lines(gaps: Sequence[GapItem]) -> List[str]:
    """Fixed-menu lawful next steps, each tagged with the id of the gap it answers (duplicates are merged).

    Same order and limits as :func:`not_established_lines`: critical steps first, never dropped; many lead-only steps
    become one line listing the ids; an explicit omission line replaces anything else that does not fit.
    """
    ordered = _prioritised(gaps)
    leads = [g for g in ordered if g.kind == LEAD_ONLY]
    collapse = len(leads) > COLLAPSE_LEADS_ABOVE
    critical: Dict[str, str] = {}
    others: Dict[str, str] = {}
    for gap in ordered:
        build = _NEXT_STEPS.get(gap.kind)
        step = build(gap) if build else ""
        if not step or (collapse and gap.kind == LEAD_ONLY):
            continue
        bucket = critical if gap.kind in CRITICAL_KINDS else others
        if step not in critical and step not in others:
            bucket[step] = gap.item_id
    limits = next((g.item_id for g in ordered if g.kind == STANDING_LIMITS), "")
    if limits and _ARCHIVE_STEP not in critical:
        critical[_ARCHIVE_STEP] = limits
    lines_others = [f"- {step} [{item_id}]" for step, item_id in others.items()]
    if collapse:
        lines_others.append(f"- Seek a second independent source for each lead-only finding. [{_ids(leads)}]")
    return _capped([f"- {step} [{item_id}]" for step, item_id in critical.items()], lines_others)
