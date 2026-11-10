"""Turn a finished investigation result into the plain answer printed (and optionally saved) by ``bunnyhole ask``.

Pure functions over the result dict; no model, no network. A chain is only reported when the existing link analysis
(``interconnections.targeted_paths``) produced it, each hop carries the relation, confidence and receipt ids of the
graph edge it rests on, and the label is the repo's own ``label_finding`` (never upgraded). The answer never says two
entities are "not connected": an empty result is "no connection found in the sources searched; absence is not proof".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence, Tuple

from bunnyhole.engine.ask import AskPlan, Intent
from bunnyhole.engine.ask_checklist import (
    CLOSING_LINE,
    CheckRow,
    build_risk_checklist,
    risk_headline,
)
from bunnyhole.engine.pi import FindingLabel, count_independent_sources, label_finding

NO_CONNECTION_LINE = "No connection found in the sources searched; absence is not proof."
CONNECTION_CAVEAT = "A chain is a lead to verify against its receipts, not proof of a relationship."
_LABEL_ORDER = {FindingLabel.LEAD.value: 0, FindingLabel.PROBABLE.value: 1, FindingLabel.CONFIRMED.value: 2}
_MAX_CHAINS = 5
_MAX_SOURCES = 25


@dataclass(frozen=True)
class Hop:
    from_label: str
    to_label: str
    relation: str
    confidence: Optional[float]
    receipt_ids: Tuple[str, ...]
    finding_label: str


@dataclass(frozen=True)
class Chain:
    hops: Tuple[Hop, ...]
    finding_label: str  # the weakest hop decides


@dataclass(frozen=True)
class Answer:
    headline: str
    body: str

    def markdown(self) -> str:
        return f"# {self.headline}\n\n{self.body}\n"


def _val(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _md(text: Any) -> str:
    """One line of untrusted text for Markdown (node labels come from the web)."""
    return " ".join(str(text).split()).replace("|", "\\|").replace("`", "'")[:160]


def _edge_between(edges: Sequence[Mapping[str, Any]], a: str, b: str) -> Optional[Mapping[str, Any]]:
    for edge in edges:
        if {str(edge.get("source_id")), str(edge.get("target_id"))} == {a, b}:
            return edge
    return None


def connection_chains(result: Mapping[str, Any]) -> List[Chain]:
    """Chains from the link analysis, hop by hop, each hop tied to its graph edge and receipts."""
    labels = {str(n.get("id")): str(n.get("label") or n.get("id")) for n in (result.get("nodes") or [])}
    edges = [e for e in (result.get("edges") or []) if isinstance(e, Mapping)]
    paths = (result.get("interconnections") or {}).get("targeted_paths") or []
    chains: List[Chain] = []
    for path in paths[:_MAX_CHAINS]:
        ids = [str(i) for i in (path.get("node_ids") or [])]
        hops: List[Hop] = []
        for i in range(len(ids) - 1):
            edge = _edge_between(edges, ids[i], ids[i + 1])
            receipts = [dict(r) for r in ((edge or {}).get("receipts") or []) if isinstance(r, Mapping)]
            hops.append(
                Hop(
                    from_label=labels.get(ids[i], ids[i]),
                    to_label=labels.get(ids[i + 1], ids[i + 1]),
                    relation=_val((edge or {}).get("relation")) or "LINKED (no edge record)",
                    confidence=(edge or {}).get("confidence"),
                    receipt_ids=tuple(str(r["receipt_id"]) for r in receipts if r.get("receipt_id")),
                    finding_label=label_finding(count_independent_sources(receipts)).value,
                )
            )
        if hops:
            weakest = min((h.finding_label for h in hops), key=_LABEL_ORDER.__getitem__)
            chains.append(Chain(tuple(hops), weakest))
    return chains


def sources_searched(result: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    """``(searched, unavailable)`` from the PI coverage table when present, the run log and the receipt tools."""
    searched: List[str] = []
    unavailable: List[str] = []
    pi = result.get("pi")
    for row in (pi.get("coverage") or []) if isinstance(pi, Mapping) else []:
        (searched if row.get("searched") else unavailable).append(str(row.get("source_class")))
    for entry in result.get("logs") or []:
        action = str(entry.get("action") or "")
        if action.endswith("_SKIP") or action == "SSRF_BLOCKED":
            unavailable.append(f"{action}: {str(entry.get('detail') or '')[:120]}")
        elif action.endswith(("_SCAN", "_SWEEP")) or action.endswith("_SEARCH"):
            searched.append(action)
    searched += sorted({str(r.get("tool")) for n in (result.get("nodes") or []) for r in (n.get("receipts") or []) if r.get("tool")})
    dedupe = lambda items: list(dict.fromkeys(items))[:_MAX_SOURCES]  # noqa: E731 - tiny local helper
    return dedupe(searched), dedupe(unavailable)


def _sources_block(result: Mapping[str, Any]) -> List[str]:
    searched, unavailable = sources_searched(result)
    lines = ["## Sources", ""]
    lines.append("- Searched: " + (_md(", ".join(searched)) if searched else "none recorded in this run."))
    lines.append("- Not searched or unavailable: " + (_md("; ".join(unavailable)) if unavailable else "none recorded."))
    return lines


def _run_notes(result: Mapping[str, Any]) -> List[str]:
    stages = result.get("stage_errors") or {}
    return [f"Run note: stage failed and fell back to a default: {_md(', '.join(stages))}."] if stages else []


def build_connection_answer(plan: AskPlan, result: Mapping[str, Any]) -> Answer:
    a, b = plan.entities[0].text, plan.entities[1].text
    chains = connection_chains(result)
    lines: List[str] = []
    if chains:
        headline = f"Connection found between {_md(a)} and {_md(b)}: {len(chains)} chain(s)."
        lines.append(CONNECTION_CAVEAT)
        for n, chain in enumerate(chains, 1):
            lines += ["", f"## Chain {n}: {len(chain.hops)} hop(s), weakest hop is a {chain.finding_label}", ""]
            for hop in chain.hops:
                conf = f"{hop.confidence:.2f}" if isinstance(hop.confidence, (int, float)) else "n/a"
                receipts = ", ".join(hop.receipt_ids) or "none recorded"
                lines.append(
                    f"- {_md(hop.from_label)} -> {_md(hop.to_label)}: {_md(hop.relation)}; confidence {conf}; "
                    f"{hop.finding_label}; receipts: {_md(receipts)}"
                )
    else:
        headline = f"No connection found between {_md(a)} and {_md(b)} in the sources searched; absence is not proof."
        lines.append(NO_CONNECTION_LINE)
    note = (result.get("interconnections") or {}).get("targeted_path_note")
    if note:
        lines += ["", f"Note: {_md(note)}"]
    lines += ["", *_sources_block(result), *_run_notes(result)]
    return Answer(headline, "\n".join(lines))


def _check_lines(row: CheckRow) -> List[str]:
    lines = [f"## {row.title}: {row.status}", ""]
    for sig in row.signals:
        receipts = ", ".join(sig.receipt_ids) or "none recorded"
        lines.append(f"- {sig.finding_label}: {_md(sig.label)} [{_md(', '.join(sig.flags))}]; receipts: {_md(receipts)}")
    lines += [f"- {_md(note)}" for note in row.notes]
    return lines + [""]


def build_risk_answer(plan: AskPlan, result: Mapping[str, Any], chains_too: bool = False) -> Answer:
    company = next((e for e in plan.entities if e.kind.value != "person"), plan.entities[0])
    rows = build_risk_checklist(result)
    lines: List[str] = []
    for row in rows:
        lines += _check_lines(row)
    if chains_too and len(plan.entities) > 1:
        linked = build_connection_answer(AskPlan(Intent.CONNECTION, plan.entities[:2], plan.question), result)
        lines += [f"## Connection between {_md(plan.entities[0].text)} and {_md(plan.entities[1].text)}", "", linked.headline, ""]
        lines += [ln for ln in linked.body.splitlines() if ln.startswith(("- ", "## Chain"))] + [""]
    lines += [*_sources_block(result), *_run_notes(result), "", CLOSING_LINE]
    return Answer(risk_headline(_md(company.text), rows), "\n".join(lines))
