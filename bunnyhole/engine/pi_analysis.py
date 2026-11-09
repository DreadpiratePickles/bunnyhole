"""PI stream analysis: coverage matrix, freshness decay, timeline contradictions/gaps and falsifiers.

Pure and deterministic: no network, no model calls, no clock except the injectable ``now_iso``.
Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.4.
"""

from __future__ import annotations

import calendar
import re
from datetime import date, datetime, timezone
from typing import Any, Collection, Dict, List, Mapping, Optional, Sequence, Tuple

from bunnyhole.engine.pi import (
    CaseType,
    Contradiction,
    CoverageRow,
    Finding,
    FindingLabel,
    OwnershipBlock,
    SourceLogEntry,
)
from bunnyhole.engine.pi_graph_access import _is_external, _receipts
from bunnyhole.engine.pi_ubo import unresolved_node_id

SOURCE_CLASSES: Tuple[str, ...] = (
    "court_dockets",
    "corporate_registry",
    "beneficial_ownership",
    "sanctions_pep",
    "regulatory_enforcement",
    "property_assets",
    "news_adverse_media",
    "social_osint",
    "domain_infrastructure",
    "crypto_onchain",
    "missing_persons",
    "vital_records",
)

# Expected source classes per case type, in the order an investigator would work them.
_EXPECTED_BY_CASE: Dict[CaseType, Tuple[str, ...]] = {
    CaseType.ASSET_SEARCH: (
        "corporate_registry",
        "beneficial_ownership",
        "sanctions_pep",
        "court_dockets",
        "property_assets",
        "crypto_onchain",
        "news_adverse_media",
        "domain_infrastructure",
    ),
    CaseType.LOCATE: (
        "court_dockets",
        "corporate_registry",
        "social_osint",
        "vital_records",
        "news_adverse_media",
    ),
    CaseType.MISSING_PERSON: (
        "missing_persons",
        "vital_records",
        "news_adverse_media",
        "social_osint",
    ),
    CaseType.DUE_DILIGENCE: (
        "corporate_registry",
        "beneficial_ownership",
        "sanctions_pep",
        "court_dockets",
        "regulatory_enforcement",
        "news_adverse_media",
    ),
    CaseType.FRAUD_SCREEN: (
        "corporate_registry",
        "sanctions_pep",
        "court_dockets",
        "regulatory_enforcement",
        "news_adverse_media",
        "crypto_onchain",
    ),
    CaseType.BACKGROUND: (
        "court_dockets",
        "sanctions_pep",
        "news_adverse_media",
        "corporate_registry",
    ),
}

_PERSON_ONLY_CLASSES = frozenset({"vital_records", "missing_persons"})

# (fresh cutoff, aging cutoff) in months, by kind of record.
_FRESHNESS_MONTHS: Dict[str, Tuple[int, int]] = {
    "address": (12, 36),
    "registry": (24, 60),
}

_INCORPORATION_MARKERS: Tuple[str, ...] = ("incorporated", "incorporation")
_TERMINAL_MARKERS: Tuple[str, ...] = ("dissolved", "struck off", "deceased")
_INCORPORATION_CONFLICT_DAYS = 30
# Nodes that anchor the investigation rather than carry evidence ("seed:jet", "profile:locked_target_root").
_SEED_ANCHOR_ID = re.compile(r"^(seed|profile)[:_\-]", re.IGNORECASE)
_MIN_EVENTS_FOR_GAP = 2


# ----------------------------------------------------------------------------------------------
# Coverage
# ----------------------------------------------------------------------------------------------


def expected_source_classes(case_type: CaseType, subject_is_person: bool) -> List[str]:
    """Source classes an investigator is expected to have searched for this case and subject type."""
    classes = list(_EXPECTED_BY_CASE[case_type])
    if not subject_is_person:
        classes = [c for c in classes if c not in _PERSON_ONLY_CLASSES]
    elif case_type is not CaseType.ASSET_SEARCH:
        classes = [c for c in classes if c != "domain_infrastructure"]
    return classes


def build_coverage(
    case_type: CaseType,
    subject_is_person: bool,
    source_log: List[SourceLogEntry],
    source_class_map: Dict[str, str],
) -> List[CoverageRow]:
    """One row per expected class. Only ``hit``/``negative`` entries count as searched; ``hit`` beats ``negative``.

    ``skipped`` and ``error`` entries never count as searched; their sources are listed in ``CoverageRow.skipped``
    (tried but not reached) so a reader can see what did not run. A class with only skipped sources stays
    ``searched=False`` with outcome ``not_searched``.
    """
    rows: List[CoverageRow] = []
    for source_class in expected_source_classes(case_type, subject_is_person):
        sources: List[str] = []
        skipped: List[str] = []
        any_hit = False
        for entry in source_log:
            if source_class_map.get(entry.source) != source_class:
                continue
            if entry.status in ("skipped", "error"):
                if entry.source not in skipped:
                    skipped.append(entry.source)
                continue
            if entry.status not in ("hit", "negative"):
                continue
            if entry.source not in sources:
                sources.append(entry.source)
            any_hit = any_hit or entry.status == "hit"
        if not sources:
            rows.append(
                CoverageRow(
                    source_class=source_class, searched=False, sources=[], skipped=skipped, outcome="not_searched"
                )
            )
        else:
            outcome = "hit" if any_hit else "negative"
            rows.append(
                CoverageRow(
                    source_class=source_class, searched=True, sources=sources, skipped=skipped, outcome=outcome
                )
            )
    return rows


NO_SUBJECT_RECORDS_DETAIL = "records found but none about the subject"
_ABOUT_THE_SUBJECT = ("subject", "related")


def downgrade_unrelated_hits(
    source_log: List[SourceLogEntry],
    nodes: Sequence[Mapping[str, Any]],
    relevance_by_node: Mapping[str, str],
    receipt_tool_prefixes: Mapping[str, Tuple[str, ...]],
) -> List[SourceLogEntry]:
    """Copy of the source log where a ``hit`` that produced no record about the subject is ``negative``.

    A source "hit" for coverage only when at least one node it added is rated ``subject`` or ``related``. The nodes a
    source added are those carrying an external receipt whose tool starts with one of the source's entries in
    ``receipt_tool_prefixes`` (recorder source name -> receipt tool name prefixes). A hit whose source is not in the
    map, or that added no matching node, is left as recorded: nothing is guessed. A downgraded entry keeps its original
    detail after ``NO_SUBJECT_RECORDS_DETAIL``; the status enum is unchanged.
    """
    out: List[SourceLogEntry] = []
    for entry in source_log:
        prefixes = receipt_tool_prefixes.get(entry.source)
        if entry.status != "hit" or not prefixes:
            out.append(entry)
            continue
        added = [
            str(node.get("id")) for node in nodes
            if any(_is_external(r) and str(r.get("tool") or "").startswith(prefixes) for r in _receipts(node))
        ]
        about_subject = any(relevance_by_node.get(node_id, "subject") in _ABOUT_THE_SUBJECT for node_id in added)
        if not added or about_subject:
            out.append(entry)
            continue
        detail = f"{NO_SUBJECT_RECORDS_DETAIL} ({entry.detail})" if entry.detail else NO_SUBJECT_RECORDS_DETAIL
        out.append(entry.model_copy(update={"status": "negative", "detail": detail}))
    return out


# ----------------------------------------------------------------------------------------------
# Freshness
# ----------------------------------------------------------------------------------------------


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse a date-only or ISO timestamp (``Z`` accepted) to an aware UTC datetime; None if unusable."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _add_months(moment: date, months: int) -> date:
    index = moment.year * 12 + (moment.month - 1) + months
    year, month = divmod(index, 12)
    month += 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def freshness_class(as_of_iso: str, kind: str = "address", *, now_iso: Optional[str] = None) -> str:
    """Classify data age: ``fresh``, ``aging``, ``stale`` or ``unknown`` (empty, unparseable or future input).

    ``kind`` "address" uses 12/36-month cutoffs, "registry" 24/60 (unknown kinds use the address cutoffs).
    Age is measured in whole calendar days (UTC): a cutoff is inclusive, so a record exactly 12 months old is
    still fresh, whatever the time of day.
    """
    as_of = _parse_timestamp(as_of_iso)
    if as_of is None:
        return "unknown"
    now = datetime.now(timezone.utc) if now_iso is None else _parse_timestamp(now_iso)
    if now is None:
        return "unknown"
    fresh_months, aging_months = _FRESHNESS_MONTHS.get(kind, _FRESHNESS_MONTHS["address"])
    as_of_day, today = as_of.date(), now.date()
    if as_of_day > today:
        return "unknown"  # a date in the future is a data error, never "fresh"
    if today <= _add_months(as_of_day, fresh_months):
        return "fresh"
    if today <= _add_months(as_of_day, aging_months):
        return "aging"
    return "stale"


# ----------------------------------------------------------------------------------------------
# Timeline: contradictions and gaps
# ----------------------------------------------------------------------------------------------

_Event = Tuple[date, str]  # (calendar date UTC, title)


def _events_by_node(
    timeline: List[Dict[str, Any]], drop_events_about: Collection[str] = ()
) -> Dict[str, List[_Event]]:
    """Group usable dated events by node id, each node's events sorted by (date, title).

    Items that are not dicts, lack a parseable timestamp, or lack a list of node ids are skipped. An item that names
    other nodes besides the one being grouped, all of them in ``drop_events_about``, is skipped for that node: a
    filing of another entity attached to the seed node is not dated evidence about the seed.
    """
    dropped = set(drop_events_about)
    by_node: Dict[str, List[_Event]] = {}
    for item in timeline:
        if not isinstance(item, dict):
            continue
        parsed = _parse_timestamp(item.get("timestamp"))
        node_ids = item.get("node_ids")
        if parsed is None or not isinstance(node_ids, list):
            continue
        raw_title = item.get("title")
        title = raw_title.strip() if isinstance(raw_title, str) else ""
        event: _Event = (parsed.date(), title)
        names = [n for n in node_ids if isinstance(n, str) and n]
        for node_id in names:
            peers = [n for n in names if n != node_id]
            if peers and all(p in dropped for p in peers):
                continue
            by_node.setdefault(node_id, []).append(event)
    for events in by_node.values():
        events.sort()
    return by_node


def _quote(title: str) -> str:
    return f"'{title}'" if title else "An untitled event"


def _has_marker(title: str, markers: Tuple[str, ...]) -> bool:
    lowered = title.lower()
    return any(marker in lowered for marker in markers)


def detect_contradictions(timeline: List[Dict[str, Any]]) -> List[Contradiction]:
    """Find timeline contradictions per node (calendar-date comparison, so mixed timestamp formats are safe).

    Rules: an event dated before the node's earliest incorporation; two incorporation dates more than 30 days
    apart; an event after the node's earliest dissolved/struck off/deceased event.
    """
    found: List[Contradiction] = []
    for node_id, events in sorted(_events_by_node(timeline).items()):
        incorporations = [e for e in events if _has_marker(e[1], _INCORPORATION_MARKERS)]
        terminals = [e for e in events if _has_marker(e[1], _TERMINAL_MARKERS)]

        if incorporations:
            earliest = incorporations[0]
            for event in events:
                if event in incorporations or event[0] >= earliest[0]:
                    continue
                found.append(
                    Contradiction(
                        kind="event_before_incorporation",
                        description=(
                            f"{_quote(event[1])} is dated {event[0].isoformat()}, before {node_id} was incorporated "
                            f"({earliest[0].isoformat()})."
                        ),
                        node_ids=[node_id],
                    )
                )
            latest = incorporations[-1]
            if (latest[0] - earliest[0]).days > _INCORPORATION_CONFLICT_DAYS:
                found.append(
                    Contradiction(
                        kind="conflicting_incorporation_dates",
                        description=(
                            f"{node_id} has incorporation dates {earliest[0].isoformat()} and "
                            f"{latest[0].isoformat()}, more than {_INCORPORATION_CONFLICT_DAYS} days apart."
                        ),
                        node_ids=[node_id],
                    )
                )

        if terminals:
            first_end = terminals[0]
            for event in events:
                if event in terminals or event[0] <= first_end[0]:
                    continue
                found.append(
                    Contradiction(
                        kind="event_after_end",
                        description=(
                            f"{_quote(event[1])} is dated {event[0].isoformat()}, after {node_id} was recorded as "
                            f"'{first_end[1]}' ({first_end[0].isoformat()})."
                        ),
                        node_ids=[node_id],
                    )
                )
    return found


def find_gaps(
    timeline: List[Dict[str, Any]],
    *,
    max_gap_days: int = 365,
    skip_node_ids: Collection[str] = (),
    drop_events_about: Collection[str] = (),
    node_labels: Optional[Mapping[str, str]] = None,
) -> List[str]:
    """Human-readable evidence gaps: consecutive dated events on one node more than ``max_gap_days`` apart.

    Seed-anchor nodes (ids such as ``seed:...`` or ``profile:...``) and nodes with fewer than two dated events
    are ignored: a gap needs two dates. ``skip_node_ids`` (nodes judged unrelated to the subject) are ignored too.
    ``drop_events_about`` removes events whose other nodes are all in that set (a filing of another entity attached
    to the subject). ``node_labels`` maps a node id to the name printed in the line (the id is the fallback).
    When no usable dated event remains, a single "no dated evidence at all" line is returned, unless events existed
    and were only skipped as unrelated (then there is nothing to report about the subject, and the list is empty).
    """
    skipped = set(skip_node_ids)
    labels = node_labels or {}
    all_nodes = {
        node_id: events
        for node_id, events in _events_by_node(timeline).items()
        if not _SEED_ANCHOR_ID.match(node_id)
    }
    by_node = {
        node_id: events
        for node_id, events in _events_by_node(timeline, drop_events_about).items()
        if node_id not in skipped and not _SEED_ANCHOR_ID.match(node_id)
    }
    if not by_node:
        return [] if all_nodes else ["No dated evidence at all: the timeline has no usable dated events."]
    gaps: List[str] = []
    for node_id, events in sorted(by_node.items()):
        if len(events) < _MIN_EVENTS_FOR_GAP:
            continue
        shown = labels.get(node_id) or node_id
        for previous, current in zip(events, events[1:]):
            days = (current[0] - previous[0]).days
            if days > max_gap_days:
                gaps.append(
                    f"{shown}: no dated evidence between {previous[0].isoformat()} and "
                    f"{current[0].isoformat()} ({days} days)."
                )
    return gaps


# ----------------------------------------------------------------------------------------------
# Falsifiers
# ----------------------------------------------------------------------------------------------

_BASE_FALSIFIERS: Dict[CaseType, Tuple[str, ...]] = {
    CaseType.LOCATE: (
        "A current record (court filing, utility, licence or registry entry) placing the subject at a different "
        "address than the one reported.",
        "Evidence that the matched identity is a different person who shares the name (conflicting date of birth, "
        "middle initial or relatives).",
        "A dated record showing the subject has moved since the newest address found.",
    ),
    CaseType.BACKGROUND: (
        "A record that attaches the same name to a different date of birth or life history, showing the "
        "records describe more than one person.",
        "A court or registry record contradicting the reported history, such as a dismissed case, a sealed or "
        "expunged entry, or an entity the subject never held a role in.",
        "A primary-source document (not an aggregator) that disagrees with the secondary sources relied on.",
    ),
    CaseType.ASSET_SEARCH: (
        "A record showing a different registered owner of the asset at the same date.",
        "Evidence that the asset was transferred, encumbered by a lien or sold before the judgment or claim date.",
        "A filing showing a nominee, trustee or lender holds the beneficial interest rather than the named owner.",
        "Evidence that the subject is genuinely judgment-proof (no assets in any searched jurisdiction).",
    ),
    CaseType.DUE_DILIGENCE: (
        "A registry or ownership filing naming a different beneficial owner or controller than the one found.",
        "A sanctions, enforcement or litigation record that was missed because it sits under a name variant or "
        "an affiliated entity.",
        "Evidence that the adverse items found concern a different entity with a similar name.",
    ),
    CaseType.FRAUD_SCREEN: (
        "Evidence that the complaints or enforcement items found concern a different entity with a similar name.",
        "A documented resolution (refund, settlement, dismissal) showing the pattern of conduct has ended.",
        "A legitimate explanation for the shell-company indicators, such as a registered agent address or a "
        "service provider shared with many unrelated companies.",
    ),
    CaseType.MISSING_PERSON: (
        "A record of the person being found, such as a dated contact with an agency, an obituary or a "
        "death registration.",
        "Evidence that the public-source footprint belongs to a different person with the same name.",
        "An authority or law-enforcement report that supersedes the open-source picture.",
    ),
}


_RELEVANCE_ORDER = {"subject": 0, "related": 1, "unknown": 2, "unrelated": 3}
_MAX_NAMED_LEADS = 5


def _plain_label(label: str) -> str:
    """The label without the decorative emoji or punctuation prefix the agents put on it."""
    return re.sub(r"^[^\w]+", "", label).strip() or label


def _collapsed_lead_statement(leads: List[Finding]) -> str:
    ranked = sorted(leads, key=lambda f: _RELEVANCE_ORDER.get(f.relevance, 2))  # stable: graph order within a rank
    named = ", ".join(f"'{_plain_label(f.label)}' ({f.node_id})" for f in ranked[:_MAX_NAMED_LEADS])
    more = len(ranked) - _MAX_NAMED_LEADS
    return (
        f"A second independent source that contradicts, or corroborates, any of the {len(ranked)} single-source "
        f"leads, most relevant first: {named}" + (f" (+{more} more)." if more > 0 else ".")
    )


def falsifiers_for(
    case_type: CaseType,
    findings: List[Finding],
    contradictions: List[Contradiction],
    ownership: OwnershipBlock,
    *,
    collapse_leads_above: int = 2,
    unrelated_node_ids: Collection[str] = (),
) -> List[str]:
    """What would change the conclusion: base statements per case type, then per gap, lead and contradiction.

    Single-source leads each get a line while there are at most ``collapse_leads_above`` of them; beyond that they
    collapse into ONE line naming up to five (most relevant first) and the count (the assembly passes ``1``, so a
    report never repeats one near-identical line per lead). Leads whose ``relevance`` is ``unrelated`` are skipped,
    as are unresolved ownership nodes and contradictions driven only by ``unrelated_node_ids``. One line is kept per
    remaining unresolved node and per contradiction. Identical statements are emitted once (first-seen order).
    """
    unrelated = set(unrelated_node_ids)
    statements: List[str] = list(_BASE_FALSIFIERS[case_type])
    for entry in ownership.unresolved:
        if unresolved_node_id(entry) in unrelated:
            continue
        statements.append(
            f"A filing, register entry or disclosure naming the natural person or controller behind {entry}, "
            "where the ownership walk ended without reaching one."
        )
    leads = [
        f for f in findings
        if f.finding_label is FindingLabel.LEAD and f.relevance != "unrelated" and f.node_id not in unrelated
    ]
    unique_leads = list({f.node_id: f for f in leads}.values())
    if len(unique_leads) > collapse_leads_above:
        statements.append(_collapsed_lead_statement(unique_leads))
    else:
        for finding in leads:
            statements.append(
                f"A second independent source that contradicts, or corroborates, the single-source lead "
                f"'{finding.label}' ({finding.node_id})."
            )
    for contradiction in contradictions:
        if contradiction.node_ids and all(n in unrelated for n in contradiction.node_ids):
            continue
        statements.append(
            f"Resolution of the contradiction ({contradiction.kind}): {contradiction.description} "
            "Which record is correct would change the timeline."
        )
    return list(dict.fromkeys(statements))
