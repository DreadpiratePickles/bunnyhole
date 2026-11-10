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
    "Engage a licensed investigator or a lawyer for records that only legal process can reach "
    "(court records, bank and telephone records)."
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
    SEARCHED: lambda g: (
        f"Source class {_e(g.label)} was searched with outcome {_e(g.names[0] if g.names else 'unknown')}; "
        "absence from the sources searched is not proof of absence."
    ),
    IDENTITY_NOTE: lambda g: f"Identity note from the program: {_e(g.label)}",
    CONTRADICTION: lambda g: f"Contradiction recorded by the program: {_e(g.label)}",
    CHRONOLOGY_GAP: lambda g: f"Chronology gap recorded by the program: {_e(g.label)}",
    OWNERSHIP_WALK: _ownership_line,
    LEAD_ONLY: lambda g: (
        f"{_e(g.label)} rests on a single source and is a lead only; it needs a second independent source."
    ),
}


def not_established_lines(gaps: Sequence[GapItem]) -> List[str]:
    """Fixed-wording "not established" lines, each tagged with its id."""
    lines = [f"- {_NOT_ESTABLISHED[g.kind](g)} [{g.item_id}]" for g in gaps if g.kind in _NOT_ESTABLISHED]
    return lines[:MAX_LINES]


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
    """Fixed-menu lawful next steps, each tagged with the id of the gap it answers (duplicates are merged)."""
    seen: Dict[str, str] = {}
    for gap in gaps:
        build = _NEXT_STEPS.get(gap.kind)
        step = build(gap) if build else ""
        if step and step not in seen:
            seen[step] = gap.item_id
    limits = next((g.item_id for g in gaps if g.kind == STANDING_LIMITS), "")
    if limits and _ARCHIVE_STEP not in seen:
        seen[_ARCHIVE_STEP] = limits
    return [f"- {step} [{item_id}]" for step, item_id in seen.items()][:MAX_LINES]
