"""The fixed company-risk checklist for ``bunnyhole ask``, built by deterministic code from a finished result.

Input is the result dict the orchestrator already returns (``nodes``, ``edges``, ``logs``). Nothing here calls a model
or the network, and nothing upgrades a finding label: the confirmed / probable / lead label of a signal is
``label_finding(count_independent_sources(receipts))``, the same rule the PI report uses (3+, 2, 1 independent source).

A check is ``signals found`` only when the graph carries a signal flag for it, ``nothing found in sources searched``
only when the run shows the source ran, and ``not checked or unavailable`` otherwise. A check with no data source in
this version says so and is never reported as clear.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from bunnyhole.engine.pi import count_independent_sources, label_finding

STATUS_SIGNALS = "signals found"
STATUS_NONE = "nothing found in sources searched"
STATUS_UNCHECKED = "not checked or unavailable"

CLOSING_LINE = "No hit is not clearance. This lists signals found in public sources; it is not a finding of wrongdoing."

_MAX_SIGNALS_PER_CHECK = 8
_MAX_RECEIPTS_PER_SIGNAL = 4
_YOUNG_DOMAIN_DAYS = 365

# Sanctions lists the engine can screen: log-action prefix -> (display name, receipt tool that proves the list ran).
SANCTIONS_LISTS: Dict[str, Tuple[str, str]] = {
    "SANCTIONS_PEP": ("OpenSanctions (OFAC/EU/UN/UK OFSI sanctions, PEP lists, watchlists)", "opensanctions_yente"),
    "OFAC_SDN": ("OFAC SDN list (US Treasury)", "ofac_sdn"),
    "UN_CONSOLIDATED": ("UN Security Council consolidated list", "un_consolidated"),
    "UK_SANCTIONS": ("UK Sanctions List (FCDO)", "uk_sanctions_list"),
    "CA_SANCTIONS": ("Canada consolidated autonomous sanctions list (SEMA)", "gac_sema_sanctions"),
}
_SANCTION_FLAGS = frozenset({"OFAC_EU_UN_SANCTIONS_LIST_MATCH", "POLITICALLY_EXPOSED_PERSON_PEP"})
_LITIGATION_FLAGS = frozenset({"FEDERAL_LITIGATION_RECORD", "REGULATORY_OR_FRAUD_DOCKET", "LITIGATION_MENTION"})
_ADVERSE_NEWS_FLAGS = frozenset(
    {
        "REGULATORY_SCRUTINY", "SUBPOENA_REPORTED", "FRAUD_ALLEGATION", "EXPLOIT_OR_BREACH", "INSOLVENCY_SIGNAL",
        "SANCTIONS_MENTION", "SHORT_REPORT_TARGET", "NARRATIVE_SYNDICATION_CLUSTER",
    }
)
_OPACITY_FLAGS = frozenset(
    {"MASS_REGISTERED_AGENT_ADDRESS", "NOMINEE_DIRECTOR_STRAWMAN_CANDIDATE", "CROSS_DOMAIN_CUTOUT_BROKER"}
)
_REGISTRY_TOOL_HINTS = ("companies_house", "gleif", "edgar", "opencorporates")
_LEAK_TOOL_HINTS = ("leakcheck", "hudsonrock", "hibp")
_OWNERSHIP_RELATIONS = frozenset(
    {"DIRECTOR_OF", "OFFICER_OF", "OWNS", "DIRECT_PARENT_OF", "ULTIMATE_PARENT_OF", "SUBSIDIARY_OF", "NOMINEE_FOR"}
)


@dataclass(frozen=True)
class Signal:
    """One graph node that raised a signal, with its receipt ids and the repo's own label (never upgraded)."""

    node_id: str
    label: str
    flags: Tuple[str, ...]
    receipt_ids: Tuple[str, ...]
    finding_label: str


@dataclass(frozen=True)
class CheckRow:
    key: str
    title: str
    status: str
    signals: Tuple[Signal, ...] = ()
    notes: Tuple[str, ...] = ()


def _val(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _nodes(result: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    return [n for n in (result.get("nodes") or []) if isinstance(n, Mapping)]


def _logs(result: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    return [x for x in (result.get("logs") or []) if isinstance(x, Mapping)]


def _flags(node: Mapping[str, Any]) -> Set[str]:
    return {str(f) for f in (node.get("risk_flags") or [])}


def _receipts(node: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    return [r for r in (node.get("receipts") or []) if isinstance(r, Mapping)]


def _tools(node: Mapping[str, Any]) -> Set[str]:
    return {str(r.get("tool") or "").lower() for r in _receipts(node)}


def _any_tool(result: Mapping[str, Any], hints: Iterable[str]) -> bool:
    return any(h in tool for n in _nodes(result) for tool in _tools(n) for h in hints)


def _signal(node: Mapping[str, Any], flags: Iterable[str]) -> Signal:
    receipts = _receipts(node)
    count = count_independent_sources([dict(r) for r in receipts])
    return Signal(
        node_id=str(node.get("id") or ""),
        label=str(node.get("label") or node.get("id") or "?"),
        flags=tuple(sorted(flags)),
        receipt_ids=tuple(str(r.get("receipt_id")) for r in receipts if r.get("receipt_id"))[:_MAX_RECEIPTS_PER_SIGNAL],
        finding_label=label_finding(count).value,
    )


def _signals(result: Mapping[str, Any], wanted: frozenset[str], types: Optional[Set[str]] = None) -> Tuple[Signal, ...]:
    found = []
    for node in _nodes(result):
        hit = _flags(node) & wanted
        if hit and (types is None or _val(node.get("entity_type")) in types):
            found.append(_signal(node, hit))
    return tuple(found[:_MAX_SIGNALS_PER_CHECK])


def _reasons(result: Mapping[str, Any], *actions: str) -> List[str]:
    """Why a source was skipped, from warning-level log events (``<ACTION>: <detail>``)."""
    return [f"{x.get('action')}: {str(x.get('detail') or '')[:160]}" for x in _logs(result) if x.get("action") in actions]


def _status(signals: Sequence[Signal], ran: bool) -> str:
    return STATUS_SIGNALS if signals else (STATUS_NONE if ran else STATUS_UNCHECKED)


def check_sanctions(result: Mapping[str, Any]) -> CheckRow:
    actions = {str(x.get("action")) for x in _logs(result)}
    signals = _signals(result, _SANCTION_FLAGS)
    proof_tools = {t for n in _nodes(result) for t in _tools(n)}
    screened: List[str] = []
    missing: List[str] = []
    for prefix, (name, tool) in SANCTIONS_LISTS.items():
        ran = f"{prefix}_SCAN" in actions and f"{prefix}_SKIP" not in actions
        (screened if ran or tool in proof_tools else missing).append(name)
    notes = [f"Screened: {'; '.join(screened) or 'none recorded in the run log'}."]
    notes.append(
        f"NOT screened (or not confirmed in the run log, which keeps the last 100 events): {'; '.join(missing) or 'none of the known lists'}; "
        "plus any list this version does not carry (other national lists, private watchlists)."
    )
    notes += [f"Skipped: {r}" for r in _reasons(result, *(f"{p}_SKIP" for p in SANCTIONS_LISTS))]
    if signals:
        notes.append("A listing is a name match only (SOFT_NAME_MATCH_VERIFY): verify identifiers before relying on it.")
    return CheckRow("sanctions", "Sanctions and PEP screening", _status(signals, bool(screened)), signals, tuple(notes))


def _registry_ran(result: Mapping[str, Any]) -> bool:
    has_links = any(_val(e.get("relation")) in _OWNERSHIP_RELATIONS for e in (result.get("edges") or []))
    return _any_tool(result, _REGISTRY_TOOL_HINTS) or has_links


def _ownership_notes(result: Mapping[str, Any]) -> List[str]:
    labels = {str(n.get("id")): str(n.get("label")) for n in _nodes(result)}
    notes = []
    for edge in result.get("edges") or []:
        relation = _val(edge.get("relation"))
        if relation in _OWNERSHIP_RELATIONS:
            ids = ", ".join(str(r.get("receipt_id")) for r in (edge.get("receipts") or [])[:3] if r.get("receipt_id"))
            who, what = labels.get(str(edge.get("source_id")), "?"), labels.get(str(edge.get("target_id")), "?")
            notes.append(f"{who} -{relation}-> {what}" + (f" (receipts: {ids})" if ids else " (no receipt recorded)"))
    return notes[:10]


def check_registry(result: Mapping[str, Any]) -> CheckRow:
    ran = _registry_ran(result)
    notes: List[str] = []
    if ran:
        notes.append("Registry, identifier and officer/ownership records retrieved are listed for context; they are not signals by themselves.")
        notes += _ownership_notes(result) or ["No officer or ownership links in the graph."]
    notes += [f"Skipped: {r}" for r in _reasons(result, "UK_PSC_SKIP", "GLEIF_ENRICH_SKIP")]
    return CheckRow("registry", "Registry status, officers and ownership", _status((), ran), (), tuple(notes))


def check_litigation(result: Mapping[str, Any]) -> CheckRow:
    signals = _signals(result, _LITIGATION_FLAGS)
    actions = {str(x.get("action")) for x in _logs(result)}
    ran = "COURTLISTENER_RECAP_SEARCH" in actions and "COURTLISTENER_SKIP" not in actions or _any_tool(result, ("courtlistener",))
    notes = ["Covers CourtListener US federal dockets only; state, provincial and foreign courts were not searched."]
    notes += [f"Skipped: {r}" for r in _reasons(result, "COURTLISTENER_SKIP")]
    return CheckRow("litigation", "Litigation", _status(signals, bool(ran)), signals, tuple(notes))


def check_adverse_media(result: Mapping[str, Any]) -> CheckRow:
    signals = _signals(result, _ADVERSE_NEWS_FLAGS, {"NewsArticle"}) + _signals(result, frozenset({"ADVERSE_MEDIA_CRIME_TOPIC"}))
    swept = any(x.get("action") == "NEWS_TRAIL_SWEEP" for x in _logs(result)) or any(
        _val(n.get("entity_type")) == "NewsArticle" for n in _nodes(result)
    )
    notes = ["News flags come from headline keyword matching, not from reading the articles: open each source."]
    return CheckRow("adverse_media", "Adverse media", _status(signals[:_MAX_SIGNALS_PER_CHECK], swept), signals[:_MAX_SIGNALS_PER_CHECK], tuple(notes))


def _parse_date(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    for fmt, size in (("%Y-%m-%d", 10), ("%d-%b-%Y", 11), ("%Y.%m.%d", 10), ("%d.%m.%Y", 10), ("%Y/%m/%d", 10)):
        try:
            return datetime.strptime(text[:size], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_domain(result: Mapping[str, Any], now: Optional[datetime] = None) -> CheckRow:
    now = now or datetime.now(timezone.utc)
    signals: List[Signal] = []
    notes: List[str] = []
    dated = 0
    for node in _nodes(result):
        created = str((node.get("attributes") or {}).get("whois_created") or "")
        if _val(node.get("entity_type")) != "Domain" or not created:
            continue
        dated += 1
        when = _parse_date(created)
        if when is None:
            notes.append(f"{node.get('label')}: registration date '{created[:40]}' could not be read.")
        elif (now - when).days < _YOUNG_DOMAIN_DAYS:
            signals.append(_signal(node, {f"DOMAIN_REGISTERED_{(now - when).days}_DAYS_AGO"}))
        else:
            notes.append(f"{node.get('label')}: registered {created[:10]} ({(now - when).days} days ago).")
    notes.append("Look-alike domain detection is not available in this version: not checked.")
    return CheckRow("domain", "Domain age and look-alike domains", _status(signals, dated > 0), tuple(signals), tuple(notes))


def check_leaks(result: Mapping[str, Any]) -> CheckRow:
    signals = _signals(result, frozenset({"LEAKCHECK_BREACH_EXPOSURE"})) + tuple(
        _signal(n, _flags(n) or {"BREACH_RECORD"}) for n in _nodes(result) if _val(n.get("entity_type")) == "BreachRecord"
    )
    ran = bool(signals) or _any_tool(result, _LEAK_TOOL_HINTS)
    notes = ["A breach source that ran and found nothing leaves no record in this version, so absence here cannot be confirmed."]
    return CheckRow("leaks", "Leaked-data mentions", _status(signals[:_MAX_SIGNALS_PER_CHECK], ran), signals[:_MAX_SIGNALS_PER_CHECK], tuple(notes))


def check_opacity(result: Mapping[str, Any]) -> CheckRow:
    signals = list(_signals(result, _OPACITY_FLAGS))
    seen = {s.node_id for s in signals}
    for node in _nodes(result):
        if node.get("id") not in seen and (_val(node.get("entity_type")) == "ShellCompany" or node.get("is_cutout_broker")):
            signals.append(_signal(node, _flags(node) | {"SHELL_OR_CUTOUT_INDICATOR"}))
    notes = ["Indicators are structural (registered-agent address, nominee pattern, cut-out position), not proof of a shell."]
    return CheckRow("opacity", "Ownership opacity and shell indicators", _status(signals[:_MAX_SIGNALS_PER_CHECK], _registry_ran(result)), tuple(signals[:_MAX_SIGNALS_PER_CHECK]), tuple(notes))


def build_risk_checklist(result: Mapping[str, Any], now: Optional[datetime] = None) -> List[CheckRow]:
    """The seven fixed checks, in a fixed order, from the finished result."""
    return [
        check_sanctions(result),
        check_registry(result),
        check_litigation(result),
        check_adverse_media(result),
        check_domain(result, now),
        check_leaks(result),
        check_opacity(result),
    ]


def risk_headline(subject: str, rows: Sequence[CheckRow]) -> str:
    hit = sum(r.status == STATUS_SIGNALS for r in rows)
    unchecked = sum(r.status == STATUS_UNCHECKED for r in rows)
    ran = len(rows) - unchecked
    if hit:
        return f"Signals found on {hit} of {len(rows)} checks for {subject}. Each is a lead to verify, not a conclusion."
    return (
        f"No signals found for {subject} in the sources searched ({ran} of {len(rows)} checks ran; "
        f"{unchecked} not checked or unavailable). Not a verdict."
    )
