"""PI report builder: turns ``result["pi"]`` (a PIBlock dict) into a bottom-line-up-front Markdown report.

Pure and deterministic: no network, no model call. Every node label, finding name, purpose and other string in
the result is untrusted data. It is printed (whitespace collapsed so it cannot start a new heading or row;
backslashes, brackets, backticks and angle brackets escaped so no link, code span or HTML can form; pipes escaped
inside tables) and never interpreted. A finding is never shown at a label stronger than its source count
supports. Spec: docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.8.

Input keys read from ``result`` (all but ``pi`` optional): ``nodes`` (id to label lookup), ``seed_query`` or
``seed``, ``hypothesis`` or ``deep_research.hypothesis``, and the ACH assessment under ``ach`` or, as
``InvestigationGraph.to_dict`` emits it, ``ach_assessment``. ``edges`` is accepted but not used: the ownership
chain comes from ``pi.ownership``, which is the PI-grade walk.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import ValidationError

from bunnyhole.engine.pi import NOTICES, Finding, FindingLabel, PIBlock
from bunnyhole.engine.pi_escalation import FIFTY_RULE_NOT_EVALUABLE, fifty_rule_not_evaluable
from bunnyhole.engine.pi_report_bottom import bottom_line_lines
from bunnyhole.engine.pi_report_common import (
    _LABELS_STRONGEST_FIRST,
    Ranked,
    _distinct,
    _graph_matches,
    _inline,
    _is_searched,
    _partial_rows,
    _partial_text,
    _plural,
    _primary_hits,
    _ranked_findings,
    _Raw,
    _relevant,
    _undecorated,
    truncate_words,
)

ABSENCE_CAVEAT = "Absence from the sources searched is not proof of absence."
NOT_SEARCHED = "NOT SEARCHED"
_NOT_RECORDED = "not recorded"

_LABEL_MEANING: Dict[FindingLabel, str] = {
    FindingLabel.CONFIRMED: "3 or more independent sources",
    FindingLabel.PROBABLE: "2 independent sources",
    FindingLabel.LEAD: "1 source, needs corroboration before it is relied on",
}
_MAX_FINDING_ROWS = 25
_MAX_FALSIFIER_LINES = 12
_MAX_LEAD_NAMES = 5
_SHOWN_RELEVANCE: Tuple[str, ...] = ("subject", "related")
_NO_ANOMALY_RE = re.compile(r"\b(?:no|without)\b[^.]{0,80}anomal", re.IGNORECASE)
_LEAD_FALSIFIER_RE = re.compile(
    r"^(?P<head>A second independent source that contradicts, or corroborates, the single-source lead )"
    r"'(?P<name>.*)' \((?P<node>[^()]*)\)\.?$"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PLAYBOOK_STATUS: Dict[str, str] = {
    "done": "DONE",
    "partial": "PARTIAL",
    "not_run": "NOT RUN",
    "handoff": "NEEDS LICENSED LAYER",
}
GRAPH_MATCH_HEADING = "Other graph entities that match a sanctions-list entry (soft)"
NAME_MATCH_CAVEAT = "A name match on a sanctions list is a lead, not a determination."
ACH_SANCTIONS_NOTE = (
    "Note: sanctions screening returned a soft hit; the ACH assessment does not consider sanctions lists."
)
_SANCTIONS_STATUS_TEXT: Dict[str, str] = {
    "not_run": "no sanctions list was screened; this is not a clear result",
    "partial": "some lists ran and others were not reached; no hit on the screened lists is not clearance",
    "lists_run": "every list attempted ran; a name check only, not clearance",
}
DIGEST_CAVEAT = (
    "The digest covers the recorded extract (tool, URL, fact, snippet), not the full retrieved page; archive "
    "source pages (Wayback Save Page Now, ArchiveBox, SingleFile) for page-level preservation."
)


# --------------------------------------------------------------------------- text helpers


def _cell(value: Any) -> str:
    """Untrusted text safe inside a Markdown table cell: inert, one line, pipes escaped."""
    text = str(value) if isinstance(value, _Raw) else str(_inline(value))
    return text.replace("|", "\\|")


def _or_not_recorded(value: Any) -> str:
    return _inline(value) or _NOT_RECORDED


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    lines.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return lines


def _score(value: Any) -> str:
    return f"{value:g}" if isinstance(value, (int, float)) and not isinstance(value, bool) else _inline(value)


# --------------------------------------------------------------------------- input normalisation


def _node_names(result: Mapping[str, Any]) -> Dict[str, str]:
    nodes = result.get("nodes")
    names: Dict[str, str] = {}
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, Mapping) and node.get("id") and node.get("label"):
                names[str(node["id"])] = _inline(_undecorated(node["label"]))
    return names


def _name(node_id: str, names: Mapping[str, str]) -> str:
    """``label (id)`` when the id is a known node, else the id as given."""
    label = names.get(node_id)
    clean_id = _inline(node_id)
    return _Raw(f"{label} ({clean_id})" if label and label != clean_id else clean_id)


def _ach(result: Mapping[str, Any]) -> Dict[str, Any]:
    """The ACH assessment under ``ach`` or ``ach_assessment``; empty when absent or blank."""
    for key in ("ach", "ach_assessment"):
        raw = result.get(key)
        dump = getattr(raw, "model_dump", None)
        if callable(dump):
            raw = dump()
        if isinstance(raw, Mapping) and any(raw.get(k) for k in ("primary_question", "winning_hypothesis")):
            return dict(raw)
    return {}


def _hypothesis(result: Mapping[str, Any]) -> str:
    deep = result.get("deep_research")
    nested = deep.get("hypothesis") if isinstance(deep, Mapping) else ""
    return _inline(result.get("hypothesis") or nested)


# --------------------------------------------------------------------------- sections


def _engagement_section(block: PIBlock, result: Mapping[str, Any]) -> List[str]:
    e = block.engagement
    seed = _inline(result.get("seed") or result.get("seed_query"))
    lines = [
        f"- **Engagement ID:** `{_inline(e.engagement_id).replace(chr(96), chr(39))}`",
        f"- **Case type:** {e.case_type.value}",
        f"- **Objective:** {_or_not_recorded(e.objective)}",
        f"- **Purpose:** {_or_not_recorded(e.purpose)}",
        f"- **Attested permissible purpose:** {_inline(e.purpose_category) or '(not attested)'}",
        f"- **Client:** {_or_not_recorded(e.client)}",
        f"- **Matter reference:** {_or_not_recorded(e.matter_ref)}",
        f"- **Jurisdiction:** {_or_not_recorded(e.jurisdiction)}",
        f"- **Subject:** {'natural person' if e.subject_is_person else 'entity'}",
        f"- **Seed:** {seed or _NOT_RECORDED}",
        f"- **Passive-only:** {'yes' if e.passive_only else 'NO (active methods were permitted)'}",
        f"- **Opened (UTC):** {_or_not_recorded(e.created_at_utc)}",
    ]
    if block.prior_cases:
        hits = "; ".join(
            f"{_inline(c.get('case_id', '?'))} (seed {_inline(c.get('seed', '?'))}, {_inline(c.get('at', '?'))})"
            for c in block.prior_cases
        )
        lines.append(f"- **Conflict check:** {_plural(len(block.prior_cases), 'prior case')} matched: {hits}")
    else:
        lines.append("- **Conflict check:** no prior cases matched.")
    if block.identifier_warnings:
        lines.append("- **Identifier warnings:**")
        lines.extend(f"  - {_inline(w)}" for w in block.identifier_warnings)
    return lines


def _entity_profile_section(block: PIBlock) -> List[str]:
    profile = block.entity_profile
    if profile is None:
        return ["None. No registry match for the subject."]
    rows = [
        ["Legal name", _or_not_recorded(profile.legal_name)],
        ["LEI", _or_not_recorded(profile.lei)],
        ["Status", _or_not_recorded(profile.status)],
        ["Jurisdiction", _or_not_recorded(profile.jurisdiction)],
        ["Registered address", _or_not_recorded(profile.registered_address)],
        ["Parents", _Raw(", ".join(_distinct(profile.parents)) or _NOT_RECORDED)],
        ["Registry sources", _Raw(", ".join(_distinct(profile.sources)) or _NOT_RECORDED)],
    ]
    return _table(["Field", "Value"], rows)


def _says_no_anomalies(ach: Mapping[str, Any]) -> bool:
    """True when the ACH text reports no (or no deterministic) anomalies; the ACH itself is never edited."""
    text = f"{ach.get('narrative_verdict') or ''} {ach.get('winning_hypothesis') or ''}"
    return bool(_NO_ANOMALY_RE.search(text))


def _theory_section(result: Mapping[str, Any], block: PIBlock) -> List[str]:
    sanctions_hit = bool(_primary_hits(block.sanctions))
    hypothesis, ach = _hypothesis(result), _ach(result)
    if not hypothesis and not ach:
        return ["None. No theory was supplied and no ACH assessment is available."]
    lines: List[str] = []
    if hypothesis:
        lines.append(f"- **Client theory:** {hypothesis}")
    else:
        lines.append("- **Client theory:** none supplied.")
    if ach:
        lines.append(f"- **Question tested (ACH):** {_or_not_recorded(ach.get('primary_question'))}")
        lines.append(f"- **Best-supported hypothesis:** {_or_not_recorded(ach.get('winning_hypothesis'))}")
        lines.append(
            f"- **ACH scores:** H1 {_score(ach.get('h1_score', 0))} / H2 {_score(ach.get('h2_score', 0))} / "
            f"H3 {_score(ach.get('h3_score', 0))}"
        )
        if ach.get("narrative_verdict"):
            lines.append(f"- **Analytic verdict:** {_inline(ach['narrative_verdict'])}")
        if sanctions_hit and _says_no_anomalies(ach):
            lines.append(f"- {ACH_SANCTIONS_NOTE}")
    else:
        lines.append("- **ACH:** no assessment was available to test the theory.")
    lines.append("")
    lines.append(
        "The theory is a starting point. A structured comparison is not proof; only the labelled findings "
        "below count as evidence."
    )
    return lines


def _relevance_cell(finding: Finding) -> str:
    reason = _inline(finding.relevance_reason)
    if finding.relevance == "related":
        return _Raw(f"related: {reason}" if reason else "related")
    return finding.relevance


_LEGAL_NOISE = frozenset({
    "inc", "ltd", "llc", "plc", "gmbh", "sa", "ag", "nv", "bv", "co", "corp", "corporation", "company", "limited",
    "pjsc", "ojsc", "oao", "pao", "jsc", "the", "of", "and",
})
_JURISDICTION_TAG = re.compile(r"\s*\([A-Za-z]{2}(?:-[A-Za-z0-9]+)?\)\s*")
_REGISTRY_NODE_PREFIXES = ("lei:", "company:", "psc:", "cik:")
_MAX_POSSIBLY_RELEVANT = 5
_MAX_TITLE_CHARS = 90
_SHORT_NAME_CHARS = 3
POSSIBLY_RELEVANT_HEADING = "Set aside but possibly relevant (mentions a related party):"


def _name_tokens(text: str) -> List[str]:
    """Words of a name or title, without legal forms and jurisdiction tags (case kept; compared casefolded)."""
    words = re.findall(r"\w+", _JURISDICTION_TAG.sub(" ", text))
    return [w for w in words if w.casefold() not in _LEGAL_NOISE]


def _mentions(title_tokens: Sequence[str], name_tokens: Sequence[str]) -> bool:
    """True when ``name_tokens`` appear as consecutive whole words in the title. A name of one short word (a ticker such
    as ``BP``) must also match in case, so ``Bpmn`` or ``bp`` is not a mention."""
    if not name_tokens:
        return False
    short = len(name_tokens) == 1 and len(name_tokens[0]) <= _SHORT_NAME_CHARS
    fold = (lambda w: w) if short else str.casefold
    want = [fold(w) for w in name_tokens]
    have = [fold(w) for w in title_tokens]
    return any(have[i:i + len(want)] == want for i in range(len(have) - len(want) + 1))


def _related_parties(block: PIBlock, names: Mapping[str, str]) -> List[str]:
    """Names of known related parties: the registry profile's parents, the ownership chain's other entities, and the
    registry records found related to the subject. The subject itself is not one."""
    profile = block.entity_profile
    own = {profile.legal_name.casefold()} if profile and profile.legal_name else set()
    by_id = {f.node_id: f for f in block.findings}
    subject_ids = {f.node_id for f in block.findings if f.relevance == "subject"}
    found: List[str] = [p for p in (profile.parents if profile else []) if not p.startswith("Reporting exception")]
    for edge in block.ownership.edges:
        for node_id in (edge.child, edge.parent):
            if node_id in subject_ids:
                continue
            label = names.get(node_id) or (by_id[node_id].label if node_id in by_id else "")
            found.append(_undecorated(label))
    found += [
        _undecorated(f.label) for f in block.findings
        if f.relevance == "related" and f.node_id.startswith(_REGISTRY_NODE_PREFIXES)
    ]
    cleaned = [re.sub(r"\s+", " ", str(n)).strip() for n in found]
    return list(dict.fromkeys(n for n in cleaned if n and n.casefold() not in own and _name_tokens(n)))


def _possibly_relevant_line(block: PIBlock, names: Mapping[str, str]) -> str:
    """Titles of set-aside records that mention (by whole words) a known related party; empty when none do."""
    parties = [(party, _name_tokens(party)) for party in _related_parties(block, names)]
    items: List[str] = []
    for finding in block.findings:
        if finding.relevance in _SHOWN_RELEVANCE:
            continue
        title_tokens = _name_tokens(_undecorated(finding.label))
        party = next((p for p, tokens in parties if _mentions(title_tokens, tokens)), "")
        if party:
            title = truncate_words(str(_inline(_undecorated(finding.label))), _MAX_TITLE_CHARS)
            items.append(f"{title} (mentions {_inline(party)})")
        if len(items) == _MAX_POSSIBLY_RELEVANT:
            break
    return f"{POSSIBLY_RELEVANT_HEADING} " + "; ".join(items) if items else ""


def _findings_section(ranked: Ranked, block: PIBlock, names: Mapping[str, str]) -> List[str]:
    relevant = _relevant(ranked)
    omitted_records = len(ranked) - len(relevant)
    lines: List[str] = []
    if not relevant:
        lines.append("None.")
    else:
        rows = []
        for finding, label in relevant[:_MAX_FINDING_ROWS]:
            node = _inline(finding.node_id)
            name = _inline(finding.label)
            shown = name if node == name or not node else f"{name} ({node})"
            rows.append(
                [_Raw(shown), label.value, finding.source_count, _inline(finding.freshness) or "unknown",
                 _relevance_cell(finding)]
            )
        lines = _table(["Finding", "Label", "Sources", "Freshness", "Relevance"], rows)
        omitted = relevant[_MAX_FINDING_ROWS:]
        if omitted:
            kind = "lead-only findings" if all(lab is FindingLabel.LEAD for _, lab in omitted) else "findings"
            lines += ["", f"{len(omitted)} further {kind} omitted here; they are in the JSON result."]
    if omitted_records:
        lines += [
            "",
            f"{_plural(omitted_records, 'record')} of unrelated or unknown relevance omitted here; "
            "they are in the JSON result.",
        ]
        possibly_relevant = _possibly_relevant_line(block, names)
        if possibly_relevant:
            lines += ["", possibly_relevant]
    if relevant:
        present = [lab for lab in _LABELS_STRONGEST_FIRST if any(x is lab for _, x in relevant)]
        lines += ["", "Labels: " + "; ".join(f"{lab.value} = {_LABEL_MEANING[lab]}" for lab in present) + "."]
        downgraded = sum(1 for f, lab in relevant if lab is not f.finding_label)
        if downgraded:
            lines.append(
                f"{_plural(downgraded, 'finding')} had a recorded label stronger than its source count supports "
                "and is shown at the supported label."
            )
    return lines


def _split_reason(entry: str) -> Tuple[_Raw, _Raw]:
    """``X: reason`` or ``X (reason)`` into (list, reason); the whole text and ``not recorded`` otherwise.

    A reason that follows a colon is kept whole (it may end in a closing bracket of its own); only the bracket that
    opens the ``X (reason)`` form is stripped from the end.
    """
    text = str(entry)  # already made inert by _distinct
    colon = re.match(r"^(?P<list>[^:()]+?)\s*:\s*(?P<reason>.+)$", text)
    if colon is not None:
        return _Raw(colon.group("list")), _Raw(colon.group("reason"))
    match = re.match(r"^(?P<list>[^:()]+?)\s*\(\s*(?P<reason>.+?)\)?$", text)
    if match is None:
        return _Raw(text), _Raw(_NOT_RECORDED)
    return _Raw(match.group("list")), _Raw(match.group("reason"))


def _sanctions_section(block: PIBlock) -> List[str]:
    sanctions = block.sanctions
    status_text = _SANCTIONS_STATUS_TEXT.get(sanctions.status, "")
    lines = [f"**Status:** {sanctions.status} ({status_text})", ""]
    lines += ["**Screened lists:**", ""]
    lines += _table(["List"], [[name] for name in _distinct(sanctions.screened)]) if sanctions.screened else ["None."]
    lines += ["", "**NOT screened (tried and not reached, or never run):**", ""]
    if sanctions.not_screened:
        lines += _table(["List", "Reason"], [_split_reason(n) for n in _distinct(sanctions.not_screened)])
    else:
        lines.append("None recorded.")
    lines += ["", "**Hits:**", ""]
    hits = _primary_hits(sanctions)
    if hits:
        rows = [
            [h.get("list", ""), h.get("name") or h.get("match") or "", "SOFT MATCH: verify on primary list",
             h.get("url", "")]
            for h in hits
        ]
        lines += _table(["List", "Matched name", "Status", "URL"], rows)
    elif sanctions.status == "lists_run":
        lines.append("No hit on the lists screened. This is a name check, not clearance.")
    else:
        lines.append("No hit on the lists that ran. Lists not screened are not cleared.")
    graph_matches = _graph_matches(sanctions)
    if graph_matches:
        lines += ["", f"**{GRAPH_MATCH_HEADING}:**", ""]
        rows = [
            [h.get("name") or h.get("node_id") or "", h.get("node_id", ""), h.get("matched_entry") or "",
             h.get("list", ""), "SOFT MATCH: verify on primary list"]
            for h in graph_matches
        ]
        lines += _table(["Graph entity", "Node", "Matches listed entry", "List", "Status"], rows)
    lines += ["", NAME_MATCH_CAVEAT]
    return lines


def _identity_section(block: PIBlock) -> List[str]:
    if block.identity_notes:
        return [f"- {_inline(n)}" for n in block.identity_notes]
    if block.engagement.subject_is_person:
        return ["None. No identity-resolution notes; subject anchoring unverified."]
    return ["None."]


def _falsifier_lines(block: PIBlock) -> List[str]:
    """Falsifier texts with identical lines counted ``(x N)`` and the per-lead lines merged into one summary.

    Lines that differ only by the lead name ("A second independent source ... single-source lead 'X' (id)") are
    replaced, at the position of the first of them, by one line naming up to five leads (leads on subject or
    related findings first) and the count. A single such line is left as it is.
    """
    relevant_nodes = {_inline(f.node_id) for f in block.findings if f.relevance in _SHOWN_RELEVANCE}
    counts: Dict[str, int] = {}
    lead_names: List[Tuple[bool, str]] = []
    lead_lines: List[str] = []
    lead_head = ""
    lead_slot: Optional[str] = None
    for text in block.falsifiers:
        raw = re.sub(r"\s+", " ", str(text)).strip()
        match = _LEAD_FALSIFIER_RE.match(raw)
        if match is not None:
            lead_head = _inline(match.group("head")).rstrip()
            lead_lines.append(_inline(raw))
            lead_names.append((_inline(match.group("node")) not in relevant_nodes, _inline(match.group("name"))))
            if lead_slot is None:
                lead_slot = "\0lead"
                counts[lead_slot] = 1
            continue
        clean = _inline(text)
        if clean:
            counts[clean] = counts.get(clean, 0) + 1
    lines: List[str] = []
    for text, n in counts.items():
        if text == lead_slot:
            lines.append(_lead_summary(lead_head, lead_names, lead_lines))
        else:
            lines.append(f"{text}" + (f" (x {n})" if n > 1 else ""))
    return lines


def _lead_summary(head: str, names: List[Tuple[bool, str]], lines: List[str]) -> str:
    unique = list(dict.fromkeys(names))
    if len(unique) == 1:  # one lead (possibly repeated): keep the original line
        return lines[0] + (f" (x {len(lines)})" if len(lines) > 1 else "")
    ordered = [name for _, name in sorted(unique, key=lambda pair: pair[0])]  # relevant leads first (stable)
    shown = ", ".join(f"'{name}'" for name in ordered[:_MAX_LEAD_NAMES])
    extra = len(ordered) - _MAX_LEAD_NAMES
    tail = f" and {extra} more" if extra > 0 else ""
    return (
        head.replace("single-source lead", f"{len(ordered)} single-source leads")
        + f" (for example {shown}{tail}); the full list is in the JSON result."
    )


def _falsifiers_section(block: PIBlock) -> List[str]:
    """Falsifier lines, repeats collapsed (see ``_falsifier_lines``), capped with a ``<n> more`` line."""
    items = _falsifier_lines(block)
    if not items:
        return ["None."]
    lines = [f"- {text}" for text in items[:_MAX_FALSIFIER_LINES]]
    if len(items) > _MAX_FALSIFIER_LINES:
        lines.append(f"- {len(items) - _MAX_FALSIFIER_LINES} more (see the JSON result)")
    return lines


def _playbook_section(block: PIBlock) -> List[str]:
    if not (block.done_when.strip() or block.playbook_progress or block.escalation_triggers):
        return ["None."]
    lines: List[str] = []
    if block.done_when.strip():
        lines.append(f"Done when (judged by a human, not by Bunnyhole): {_inline(block.done_when)}")
    if block.playbook_progress:
        steps = sorted(block.playbook_progress, key=lambda s: s.order)
        rows = [
            [s.order, s.action, _Raw(", ".join(_inline(x) for x in s.sources) or "none"),
             _PLAYBOOK_STATUS.get(s.status, _inline(s.status).upper()), s.evidence]
            for s in steps
        ]
        lines += ([""] if lines else []) + _table(["Step", "Action", "Sources", "Status", "Evidence"], rows)
    if block.escalation_triggers:
        rows = [[t.trigger, "yes" if t.fired else "no", t.why] for t in block.escalation_triggers]
        lines += ([""] if lines else []) + ["**Escalation triggers:**", ""]
        lines += _table(["Trigger", "Fired", "Why"], rows)
    return lines


def _ownership_section(block: PIBlock, names: Mapping[str, str]) -> List[str]:
    o = block.ownership
    if not (o.edges or o.blocked_by_50_rule or o.unresolved or o.levels_walked):
        return ["None."]
    lines = [f"Levels walked: {o.levels_walked}", ""]
    if o.edges:
        rows = [
            [
                _name(e.child, names),
                _name(e.parent, names),
                "unknown" if e.pct is None else f"{e.pct:g}%",
                _inline(e.source) or "unknown",
                _inline(e.as_of) or "unknown",
            ]
            for e in o.edges
        ]
        lines += _table(["Child", "Parent", "Share", "Source", "As of"], rows)
    else:
        lines.append("No ownership edges were recorded.")
    lines += ["", "**50%-rule flags (OFAC):**"]
    if o.blocked_by_50_rule:
        lines += [f"- {_name(n, names)}" for n in o.blocked_by_50_rule]
    else:
        lines.append(f"- {FIFTY_RULE_NOT_EVALUABLE}" if fifty_rule_not_evaluable(o) else "None.")
    lines += ["", "**Unresolved (walk ended before a natural person):**"]
    lines += [f"- {_name(n, names)}" for n in o.unresolved] or ["None."]
    return lines


NONE_FOUND = "None found in the evidence collected (this is not proof that none exist)."


def _false_link_section(block: PIBlock, names: Mapping[str, str]) -> List[str]:
    if not block.false_link_flags:
        return [f"None. {NONE_FOUND}"]
    rows = [
        [_name(str(f.get("node_id", "")), names), f.get("reason", ""), f.get("severity", "")]
        for f in block.false_link_flags
    ]
    return _table(["Node", "Reason", "Severity"], rows)


def _contradictions_section(block: PIBlock, names: Mapping[str, str]) -> List[str]:
    if not block.contradictions and not block.evidence_gaps:
        return [f"None. {NONE_FOUND}"]
    lines = ["**Contradictions:**"]
    for c in block.contradictions:
        nodes = ", ".join(_name(n, names) for n in c.node_ids)
        lines.append(f"- {_inline(c.kind)}: {_inline(c.description)}" + (f" ({nodes})" if nodes else ""))
    if not block.contradictions:
        lines.append("None.")
    lines += ["", "**Gaps:**"]
    lines += [f"- {_inline(g)}" for g in block.evidence_gaps] or ["None."]
    return lines


def _coverage_section(block: PIBlock) -> List[str]:
    lines: List[str] = []
    if block.coverage:
        rows = [
            [
                row.source_class,
                "yes" if _is_searched(row) else NOT_SEARCHED,
                _Raw(", ".join(_inline(s) for s in row.sources) or "none"),
                _Raw(", ".join(_inline(s) for s in row.skipped) or "none"),
                (row.outcome or "unknown") if _is_searched(row) else NOT_SEARCHED,
            ]
            for row in block.coverage
        ]
        lines += _table(["Source class", "Searched", "Sources", "Tried, not reached", "Outcome"], rows)
        partial = _partial_rows(block)
        if partial:
            lines += ["", "**Partial coverage (some sources ran, others were not reached):**", ""]
            lines += [f"- {_inline(row.source_class)}: {_partial_text(row)}" for row in partial]
    negatives = [e for e in block.source_log if e.status != "hit"]
    if negatives:
        rows = [[e.source, e.target, e.status, e.detail] for e in negatives]
        lines += ([""] if lines else []) + ["**Negatives, skips and errors logged:**", ""]
        lines += _table(["Source", "Target", "Status", "Detail"], rows)
    if not lines:
        lines = ["None."]
    return lines + ["", ABSENCE_CAVEAT]


def _custodians_section(block: PIBlock) -> List[str]:
    if not block.custodians and not block.handoff_sheet:
        return ["None."]
    lines: List[str] = []
    if block.custodians:
        rows = [[c.finding, c.custodian, c.instrument, c.jurisdiction, c.note] for c in block.custodians]
        lines += _table(["Finding", "Custodian", "Instrument", "Jurisdiction", "Note"], rows)
    if block.handoff_sheet:
        lines += ([""] if lines else []) + ["**Handoff sheet (for a licensed investigator or counsel):**", ""]
        lines += [f"- {_inline(line)}" for line in block.handoff_sheet]
    return lines


def _digest_cell(sha256: str) -> str:
    """A well-formed hex digest in a code span; anything else is untrusted text and is escaped."""
    digest = sha256.strip()
    return _Raw(f"`{digest}`") if _SHA256_RE.match(digest) else _inline(sha256)


def _custody_section(block: PIBlock) -> List[str]:
    if not block.custody:
        return ["None."]
    rows = [
        [c.receipt_id, c.tool, c.url, _digest_cell(c.sha256), c.collected_at_utc] for c in block.custody
    ]
    table = _table(["Receipt ID", "Tool", "URL", "Receipt digest (SHA-256)", "Collected (UTC)"], rows)
    return table + ["", DIGEST_CAVEAT]


def _notices_section(block: PIBlock) -> List[str]:
    notices = list(block.notices) or list(NOTICES)
    lines = [f"- {_inline(n)}" for n in notices]
    lines.append(
        "- Generated deterministically from the recorded data: no model scored, labelled or wrote any finding."
    )
    return lines


# --------------------------------------------------------------------------- entry point


def build_pi_report(result: Dict[str, Any]) -> str:
    """Render ``result["pi"]`` as a Markdown PI report; a short note when the PI block is missing or invalid."""
    data: Mapping[str, Any] = result if isinstance(result, Mapping) else {}
    try:
        block = PIBlock.model_validate(data.get("pi"))
    except ValidationError:
        return (
            "# Bunnyhole PI report\n\n"
            "No PI block was present in this result, or it was invalid, so no PI report can be built. "
            "Run the investigation with `--pi` (case type and purpose required).\n"
        )

    names = _node_names(data)
    ranked = _ranked_findings(block.findings)
    seed = _inline(data.get("seed") or data.get("seed_query")) or _inline(block.engagement.engagement_id)
    sections: List[Tuple[str, List[str]]] = [
        ("Bottom line", bottom_line_lines(block, ranked, names)),
        ("Engagement & scope", _engagement_section(block, data)),
        ("Entity profile", _entity_profile_section(block)),
        ("Client theory vs. evidence", _theory_section(data, block)),
        ("Findings", _findings_section(ranked, block, names)),
        ("Sanctions screening", _sanctions_section(block)),
        ("Identity resolution", _identity_section(block)),
        ("Ownership chain", _ownership_section(block, names)),
        ("What is NOT a link", _false_link_section(block, names)),
        ("Contradictions and gaps", _contradictions_section(block, names)),
        ("What would change this conclusion", _falsifiers_section(block)),
        ("Coverage and negatives", _coverage_section(block)),
        ("Playbook progress", _playbook_section(block)),
        ("Custodians and next steps", _custodians_section(block)),
        ("Chain of custody", _custody_section(block)),
        ("Limitations & legal notices", _notices_section(block)),
    ]
    lines = [f"# Bunnyhole PI report: {seed}", ""]
    for heading, body in sections:
        lines += [f"## {heading}", "", *body, ""]
    return "\n".join(lines).rstrip() + "\n"
