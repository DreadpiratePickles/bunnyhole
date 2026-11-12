"""Pure casework over a PI block: hypotheses, follow-up tasks, and stop decisions.

No I/O, no clock, no network. Every function returns a new model and leaves its inputs unchanged.
Signals are derived only from the fields already on :class:`PIBlock`.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Dict, Iterable, List, Literal, Optional, Sequence, Set, Tuple

from bunnyhole.engine.pi import (
    CaseBoard,
    CaseHypothesis,
    CaseTask,
    CaseType,
    EscalationTrigger,
    EvidenceLink,
    Finding,
    FindingLabel,
    HypothesisStatus,
    PIBlock,
    PIEngagement,
    StopReason,
)
from bunnyhole.engine.pi_analysis import expected_source_classes
from bunnyhole.engine.pi_notes import PLAYBOOK_SOURCE_MAP
from bunnyhole.engine.pi_reference import Playbook, PlaybookStep, playbook_for
from bunnyhole.engine.pi_runtime import SECRECY_JURISDICTION_CODES
from bunnyhole.engine.pi_ubo import unresolved_node_id

Direction = Literal["supports", "refutes"]
SignalResult = Optional[Tuple[str, List[str]]]
SignalFn = Callable[[PIBlock], SignalResult]
TaskOrigin = Literal["playbook", "corroborate_lead", "extend_ownership", "resolve_contradiction"]

# Verbatim Playbook.typical_hypotheses -> stable keys. Anything else is slugified.
_HYPOTHESIS_KEYS: Dict[CaseType, Dict[str, str]] = {
    CaseType.DUE_DILIGENCE: {
        "The counterparty is a legitimate operating business.": "dd_operating_business",
        "The counterparty is a shell or pass-through with nominee owners.": "dd_shell_nominee",
        "The counterparty is clean but carries sanctions or reputational exposure through an owner or affiliate.": (
            "dd_exposed_affiliate"
        ),
    },
    CaseType.ASSET_SEARCH: {
        "Assets are held through nominee entities in other jurisdictions.": "as_nominee_abroad",
        "Assets were dissipated or transferred before judgment.": "as_dissipated",
        "The subject is genuinely judgment-proof.": "as_judgment_proof",
    },
    CaseType.FRAUD_SCREEN: {
        "A fraudulent operation (complaint pattern plus shell indicators).": "fs_fraudulent",
        "A poorly run but legitimate business.": "fs_poorly_run",
        "A cloned or impersonated entity (lookalike domain, borrowed identity).": "fs_cloned",
    },
}

HYPOTHESIS_SIGNALS: Dict[CaseType, Dict[str, List[Tuple[str, Direction, float]]]] = {
    CaseType.DUE_DILIGENCE: {
        "dd_operating_business": [
            ("registry_active", "supports", 0.4),
            ("lei_issued", "supports", 0.3),
            ("filings_recent", "supports", 0.3),
            ("registry_dissolved", "refutes", 0.6),
            ("registered_agent_only_address", "refutes", 0.3),
        ],
        "dd_shell_nominee": [
            ("ownership_unresolved_at_nominee", "supports", 0.5),
            ("nominee_officer_flag", "supports", 0.4),
            ("registered_agent_only_address", "supports", 0.3),
            ("ubo_natural_person_reached", "refutes", 0.5),
            ("filings_recent", "refutes", 0.2),
        ],
        "dd_exposed_affiliate": [
            ("sanctions_soft_hit_on_related", "supports", 0.6),
            ("pep_flag_on_related", "supports", 0.5),
            ("adverse_media_on_principal", "supports", 0.3),
            ("sanctions_lists_run_no_hit", "refutes", 0.3),
        ],
    },
    CaseType.ASSET_SEARCH: {
        "as_nominee_abroad": [
            ("ownership_unresolved_at_nominee", "supports", 0.5),
            ("secrecy_jurisdiction_node", "supports", 0.4),
            ("offshore_leaks_hit", "supports", 0.4),
            ("ubo_natural_person_reached", "refutes", 0.5),
        ],
        "as_dissipated": [
            ("officer_or_owner_change_near_judgment", "supports", 0.5),
            ("entity_dissolved_after_claim", "supports", 0.5),
            ("contradiction_dates", "supports", 0.4),
            ("stable_ownership_window", "refutes", 0.5),
        ],
        "as_judgment_proof": [
            ("no_asset_hits_after_all_classes_searched", "supports", 0.8),
            ("asset_with_custodian", "refutes", 0.6),
        ],
    },
    CaseType.FRAUD_SCREEN: {
        "fs_fraudulent": [
            ("cfpb_pattern", "supports", 0.4),
            ("enforcement_action", "supports", 0.5),
            ("shell_indicators", "supports", 0.4),
            ("registry_active", "refutes", 0.3),
        ],
        "fs_poorly_run": [
            ("registry_active", "supports", 0.4),
            ("filings_recent", "supports", 0.3),
            ("cfpb_pattern", "supports", 0.3),
            ("enforcement_action", "refutes", 0.5),
            ("shell_indicators", "refutes", 0.4),
            ("registry_dissolved", "refutes", 0.6),
        ],
        "fs_cloned": [
            ("lookalike_domain", "supports", 0.6),
            ("registry_mismatch", "supports", 0.5),
            ("registry_active", "refutes", 0.3),
        ],
    },
}

# A clear sanctions screen is a small refute only. It is never in this map.
DECISIVE_REFUTES: Dict[str, frozenset[str]] = {
    "dd_operating_business": frozenset({"registry_dissolved"}),
    "fs_poorly_run": frozenset({"registry_dissolved"}),
    "as_nominee_abroad": frozenset({"ubo_natural_person_reached"}),
    "as_judgment_proof": frozenset({"asset_with_custodian"}),
}

CASE_ENDING_STOP_KEYS: frozenset[str] = frozenset({"sanctions_counsel"})

_ACTIVE_MARKERS = ("active", "live", "registered", "good standing")
_ACTIVE_BLOCKERS = ("dissolved", "struck", "inactive", "liquidat")
_DISSOLVED_MARKERS = ("dissolved", "struck off", "struck-off", "liquidation")
_ASSET_NODE_PREFIXES = ("wallet:", "btc:", "bitcoin:", "aircraft:")
_ORG_NODE_PREFIXES = ("company:", "org:", "lei:", "psc:", "organization:")
_ORG_LABEL_MARKERS = ("Ltd", "Inc", "LLC", "Limited", "PLC", "GmbH", "Corp")
_CORROBORATE_SKIP_PREFIXES = ("person:", "sanction:", "article:", "seed:", "profile:")
_CORROBORATE_SOURCES = ("gleif", "uk_psc", "sec_edgar", "news_narrative")
_EXTEND_SOURCES = ("uk_psc", "gleif")
_DUE_DILIGENCE_DONE_CLASSES = (
    "corporate_registry",
    "beneficial_ownership",
    "sanctions_pep",
    "court_dockets",
    "regulatory_enforcement",
    "news_adverse_media",
)
_LEADING_DECORATION = re.compile(r"^[^\w]+")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_")
    return slug or "hypothesis"


def _plain_label(label: str) -> str:
    return _LEADING_DECORATION.sub("", label or "").strip()


def _unique(node_ids: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(node_id for node_id in node_ids if node_id))


def _flag_reason(flag: dict) -> str:
    return str(flag.get("reason") or "")


def _flag_node_id(flag: dict) -> str:
    return str(flag.get("node_id") or "")


def _status_text(block: PIBlock) -> str:
    profile = block.entity_profile
    return profile.status if profile is not None else ""


def _graph_match(hit: dict) -> bool:
    value = hit.get("graph_match")
    if value is True:
        return True
    return isinstance(value, str) and value.strip().casefold() == "true"


def _hit_node_id(hit: dict) -> str:
    return str(hit.get("node_id") or "")


def _hit_detail(hit: dict) -> str:
    listed = str(hit.get("list") or "").strip()
    name = str(hit.get("name") or "").strip()
    return " ".join(part for part in (listed, name) if part)


def _finding_detail(findings: Sequence[Finding]) -> Tuple[str, List[str]]:
    return "; ".join(finding.label for finding in findings), [finding.node_id for finding in findings]


def open_case_board(engagement: PIEngagement, playbook: Playbook, *, budget: int) -> CaseBoard:
    """Hypotheses copied from the playbook, all open, with a fresh call budget."""
    known = _HYPOTHESIS_KEYS.get(playbook.case_type, _HYPOTHESIS_KEYS.get(engagement.case_type, {}))
    hypotheses = [
        CaseHypothesis(key=known.get(text) or _slugify(text), text=text)
        for text in playbook.typical_hypotheses
    ]
    return CaseBoard(hypotheses=hypotheses, calls_used=0, budget=budget, guide_name="playbook")


# ----------------------------------------------------------------------------------------------
# Signals. Each returns (detail, node_ids) or None when it did not fire.
# ----------------------------------------------------------------------------------------------


def registry_active(block: PIBlock) -> SignalResult:
    status = _status_text(block)
    lowered = status.casefold()
    if not status or any(marker in lowered for marker in _ACTIVE_BLOCKERS):
        return None
    if any(marker in lowered for marker in _ACTIVE_MARKERS):
        return (f"registry status {status!r}", [])
    return None


def registry_dissolved(block: PIBlock) -> SignalResult:
    status = _status_text(block)
    lowered = status.casefold()
    if status and any(marker in lowered for marker in _DISSOLVED_MARKERS):
        return (f"registry status {status!r}", [])
    return None


def lei_issued(block: PIBlock) -> SignalResult:
    profile = block.entity_profile
    if profile is None:
        return None
    lei = profile.lei.strip()
    if not lei:
        return None
    return (f"LEI {lei!r}", [])


def filings_recent(block: PIBlock) -> SignalResult:
    matched = [
        finding
        for finding in block.findings
        if finding.freshness == "fresh"
        and finding.relevance in ("subject", "related")
        and ("filing" in finding.label.casefold() or finding.node_id.startswith("sec:"))
    ]
    if not matched:
        return None
    return _finding_detail(matched)


def registered_agent_only_address(block: PIBlock) -> SignalResult:
    matched = [
        flag
        for flag in block.false_link_flags
        if "registered-agent" in _flag_reason(flag).casefold() or "registered agent" in _flag_reason(flag).casefold()
    ]
    if not matched:
        return None
    return "; ".join(_flag_reason(flag) for flag in matched), _unique(_flag_node_id(flag) for flag in matched)


def nominee_officer_flag(block: PIBlock) -> SignalResult:
    matched = [flag for flag in block.false_link_flags if "nominee" in _flag_reason(flag).casefold()]
    if not matched:
        return None
    return "; ".join(_flag_reason(flag) for flag in matched), _unique(_flag_node_id(flag) for flag in matched)


def ownership_unresolved_at_nominee(block: PIBlock) -> SignalResult:
    unresolved = block.ownership.unresolved
    if not unresolved:
        return None
    texts = [entry.casefold() for entry in unresolved]
    texts.extend(_flag_reason(flag).casefold() for flag in block.false_link_flags)
    marker = any("nominee" in text or "secrecy" in text for text in texts)
    if nominee_officer_flag(block) is None and not marker:
        return None
    ids = [unresolved_node_id(entry) for entry in unresolved]
    return (f"unresolved at nominee or secrecy: {', '.join(ids)}", ids)


def ubo_natural_person_reached(block: PIBlock) -> SignalResult:
    ownership = block.ownership
    if ownership.edges and not ownership.unresolved and ownership.levels_walked >= 1:
        return (f"ownership walked {ownership.levels_walked} level(s) to a natural person", [])
    return None


def sanctions_soft_hit_on_related(block: PIBlock) -> SignalResult:
    matched = [
        hit
        for hit in block.sanctions.hits
        if isinstance(hit, dict) and (str(hit.get("relevance") or "").casefold() == "related" or _graph_match(hit))
    ]
    if not matched:
        return None
    return "; ".join(_hit_detail(hit) for hit in matched), _unique(_hit_node_id(hit) for hit in matched)


def pep_flag_on_related(block: PIBlock) -> SignalResult:
    matched = []
    for hit in block.sanctions.hits:
        if not isinstance(hit, dict):
            continue
        blob = f"{hit.get('list') or ''} {hit.get('match') or ''}"
        if "pep" not in blob.casefold():
            continue
        related = str(hit.get("relevance") or "").casefold() == "related" or _graph_match(hit)
        if related:
            matched.append(hit)
    notes = [note for note in block.identity_notes if "pep" in note.casefold() and "related" in note.casefold()]
    if not matched and not notes:
        return None
    detail = "; ".join([*(_hit_detail(hit) for hit in matched), *notes])
    return detail, _unique(_hit_node_id(hit) for hit in matched)


def adverse_media_on_principal(block: PIBlock) -> SignalResult:
    matched = [
        finding
        for finding in block.findings
        if finding.relevance in ("subject", "related")
        and (finding.node_id.startswith("article:") or "adverse" in finding.label.casefold())
    ]
    if not matched:
        return None
    return _finding_detail(matched)


def sanctions_lists_run_no_hit(block: PIBlock) -> SignalResult:
    if block.sanctions.status == "lists_run" and not block.sanctions.hits:
        return ("sanctions lists ran with no hits", [])
    return None


def _secrecy_code(jurisdiction: str) -> str:
    stripped = jurisdiction.strip()
    if not stripped:
        return ""
    head = stripped.split(None, 1)[0].split("-", 1)[0]
    if len(head) == 2 and head.isalpha():
        return head.upper()
    return ""


def secrecy_jurisdiction_node(block: PIBlock) -> SignalResult:
    details: List[str] = []
    node_ids: List[str] = []
    profile = block.entity_profile
    if profile is not None and _secrecy_code(profile.jurisdiction) in SECRECY_JURISDICTION_CODES:
        details.append(f"jurisdiction {profile.jurisdiction!r}")
    for flag in block.false_link_flags:
        reason = _flag_reason(flag)
        if "secrecy" in reason.casefold():
            details.append(reason)
            node_ids.append(_flag_node_id(flag))
    for entry in block.ownership.unresolved:
        if "secrecy" in entry.casefold():
            details.append(entry)
            node_ids.append(unresolved_node_id(entry))
    if not details:
        return None
    return "; ".join(details), _unique(node_ids)


def offshore_leaks_hit(block: PIBlock) -> SignalResult:
    matched = []
    for finding in block.findings:
        if finding.relevance == "unrelated":
            continue
        blob = f"{finding.label} {finding.node_id}".casefold()
        if any(token in blob for token in ("offshore", "icij", "leaks")):
            matched.append(finding)
    if not matched:
        return None
    return _finding_detail(matched)


def officer_or_owner_change_near_judgment(block: PIBlock) -> SignalResult:
    matched = []
    for contradiction in block.contradictions:
        text = contradiction.description.casefold()
        role = any(word in text for word in ("officer", "owner", "director"))
        near_claim = any(word in text for word in ("judgment", "claim"))
        if role and near_claim:
            matched.append(contradiction)
    if not matched:
        return None
    detail = "; ".join(item.description for item in matched)
    return detail, _unique(node_id for item in matched for node_id in item.node_ids)


def entity_dissolved_after_claim(block: PIBlock) -> SignalResult:
    dissolved = registry_dissolved(block)
    if dissolved is None:
        return None
    mentions: List[str] = []
    node_ids: List[str] = []
    for contradiction in block.contradictions:
        blob = f"{contradiction.kind} {contradiction.description}".casefold()
        if "judgment" in blob or "claim" in blob:
            mentions.append(contradiction.description or contradiction.kind)
            node_ids.extend(contradiction.node_ids)
    for gap in block.evidence_gaps:
        if "judgment" in gap.casefold() or "claim" in gap.casefold():
            mentions.append(gap)
    if not mentions:
        return None
    return f"{dissolved[0]}; " + "; ".join(mentions), _unique(node_ids)


def contradiction_dates(block: PIBlock) -> SignalResult:
    matched = [
        item for item in block.contradictions if "date" in f"{item.kind} {item.description}".casefold()
    ]
    if not matched:
        return None
    detail = "; ".join(item.description or item.kind for item in matched)
    return detail, _unique(node_id for item in matched for node_id in item.node_ids)


def stable_ownership_window(block: PIBlock) -> SignalResult:
    ownership = block.ownership
    if ownership.edges and not ownership.unresolved and not block.contradictions:
        return ("ownership edges present, none unresolved, no contradictions", [])
    return None


def no_asset_hits_after_all_classes_searched(block: PIBlock) -> SignalResult:
    expected = expected_source_classes(CaseType.ASSET_SEARCH, subject_is_person=False)
    searched = {row.source_class for row in block.coverage if row.searched}
    if any(source_class not in searched for source_class in expected):
        return None
    if block.custodians:
        return None
    if any(finding.node_id.startswith(_ASSET_NODE_PREFIXES) for finding in block.findings):
        return None
    return ("every expected asset class searched with no custodian or asset hit", [])


def asset_with_custodian(block: PIBlock) -> SignalResult:
    if not block.custodians:
        return None
    detail = "; ".join(f"{item.custodian} ({item.finding})" for item in block.custodians)
    return (detail, [])


def cfpb_pattern(block: PIBlock) -> SignalResult:
    matched = [
        finding
        for finding in block.findings
        if finding.relevance != "unrelated" and any(word in finding.label.casefold() for word in ("cfpb", "complaint"))
    ]
    if not matched:
        return None
    return _finding_detail(matched)


def enforcement_action(block: PIBlock) -> SignalResult:
    matched = []
    for finding in block.findings:
        if finding.relevance == "unrelated":
            continue
        label = finding.label.casefold()
        if "enforcement" in label or "consent order" in label or finding.node_id.startswith("sec:"):
            matched.append(finding)
    if not matched:
        return None
    return _finding_detail(matched)


def lookalike_domain(block: PIBlock) -> SignalResult:
    matched = []
    for finding in block.findings:
        label = finding.label.casefold()
        lookalike = "lookalike" in label or "typosquat" in label
        similar_domain = finding.node_id.startswith("domain:") and "similar" in label
        if lookalike or similar_domain:
            matched.append(finding)
    if not matched:
        return None
    return _finding_detail(matched)


def shell_indicators(block: PIBlock) -> SignalResult:
    details: List[str] = []
    node_ids: List[str] = []
    for signal in (nominee_officer_flag, registered_agent_only_address, ownership_unresolved_at_nominee):
        fired = signal(block)
        if fired is None:
            continue
        detail, ids = fired
        details.append(detail)
        node_ids.extend(ids)
    if not details:
        return None
    return "; ".join(details), _unique(node_ids)


def registry_mismatch(block: PIBlock) -> SignalResult:
    matched = [
        item
        for item in block.contradictions
        if any(word in f"{item.kind} {item.description}".casefold() for word in ("registry", "mismatch"))
    ]
    if not matched:
        return None
    detail = "; ".join(item.description or item.kind for item in matched)
    return detail, _unique(node_id for item in matched for node_id in item.node_ids)


SIGNAL_FUNCTIONS: Dict[str, SignalFn] = {
    "registry_active": registry_active,
    "registry_dissolved": registry_dissolved,
    "lei_issued": lei_issued,
    "filings_recent": filings_recent,
    "registered_agent_only_address": registered_agent_only_address,
    "nominee_officer_flag": nominee_officer_flag,
    "ownership_unresolved_at_nominee": ownership_unresolved_at_nominee,
    "ubo_natural_person_reached": ubo_natural_person_reached,
    "sanctions_soft_hit_on_related": sanctions_soft_hit_on_related,
    "pep_flag_on_related": pep_flag_on_related,
    "adverse_media_on_principal": adverse_media_on_principal,
    "sanctions_lists_run_no_hit": sanctions_lists_run_no_hit,
    "secrecy_jurisdiction_node": secrecy_jurisdiction_node,
    "offshore_leaks_hit": offshore_leaks_hit,
    "officer_or_owner_change_near_judgment": officer_or_owner_change_near_judgment,
    "entity_dissolved_after_claim": entity_dissolved_after_claim,
    "contradiction_dates": contradiction_dates,
    "stable_ownership_window": stable_ownership_window,
    "no_asset_hits_after_all_classes_searched": no_asset_hits_after_all_classes_searched,
    "asset_with_custodian": asset_with_custodian,
    "cfpb_pattern": cfpb_pattern,
    "enforcement_action": enforcement_action,
    "lookalike_domain": lookalike_domain,
    "shell_indicators": shell_indicators,
    "registry_mismatch": registry_mismatch,
}


def _evidence_for(rows: Sequence[Tuple[str, Direction, float]], block: PIBlock) -> List[EvidenceLink]:
    """Replace, never append. Dedup key is (signal, sorted node ids)."""
    seen: Set[Tuple[str, Tuple[str, ...]]] = set()
    links: List[EvidenceLink] = []
    for signal, direction, weight in rows:
        function = SIGNAL_FUNCTIONS.get(signal)
        if function is None:
            continue
        fired = function(block)
        if fired is None:
            continue
        detail, node_ids = fired
        dedup = (signal, tuple(sorted(node_ids)))
        if dedup in seen:
            continue
        seen.add(dedup)
        links.append(
            EvidenceLink(signal=signal, direction=direction, weight=weight, detail=detail, node_ids=list(node_ids))
        )
    return links


def _status_for(key: str, evidence: Sequence[EvidenceLink], score: float) -> HypothesisStatus:
    refutes = {link.signal for link in evidence if link.direction == "refutes"}
    if refutes & DECISIVE_REFUTES.get(key, frozenset()):
        return HypothesisStatus.RULED_OUT
    supports = {link.signal for link in evidence if link.direction == "supports"}
    if score >= 0.8 and len(supports) >= 2:
        return HypothesisStatus.SUPPORTED
    if score <= -0.6:
        return HypothesisStatus.WEAKENED
    return HypothesisStatus.OPEN


def score_hypotheses(
    board: CaseBoard, block: PIBlock, case_type: CaseType
) -> Tuple[CaseBoard, List[str]]:
    """Recompute every hypothesis from ``block``. Scoring the same block twice is idempotent."""
    specs = HYPOTHESIS_SIGNALS.get(case_type)
    changed: List[str] = []
    hypotheses: List[CaseHypothesis] = []
    for hypothesis in board.hypotheses:
        rows = specs.get(hypothesis.key, []) if specs is not None else []
        evidence = _evidence_for(rows, block)
        score = sum(link.weight if link.direction == "supports" else -link.weight for link in evidence)
        status = _status_for(hypothesis.key, evidence, score)
        if status != hypothesis.status:
            changed.append(hypothesis.key)
        hypotheses.append(hypothesis.model_copy(update={"evidence": evidence, "score": score, "status": status}))
    return board.model_copy(update={"hypotheses": hypotheses}), changed


# ----------------------------------------------------------------------------------------------
# Tasks
# ----------------------------------------------------------------------------------------------


def task_id(origin: str, source: str, target: str) -> str:
    digest = hashlib.sha1(target.encode()).hexdigest()[:8]
    return f"{origin}:{source}:{digest}"


def _task(origin: TaskOrigin, source: str, target: str, why: str, *, step_order: Optional[int] = None) -> CaseTask:
    return CaseTask(
        task_id=task_id(origin, source, target),
        origin=origin,
        step_order=step_order,
        source=source,
        target=target,
        why=why,
    )


def playbook_tasks(step: PlaybookStep, subject_values: Sequence[str]) -> List[CaseTask]:
    """One task per mapped recorder name. Unmapped playbook sources produce nothing."""
    tasks: List[CaseTask] = []
    seen: Set[str] = set()
    for raw in subject_values:
        target = raw.strip()
        if not target:
            continue
        recorders_for_target: Set[str] = set()
        for source_name in step.sources:
            recorders = PLAYBOOK_SOURCE_MAP.get(source_name)
            if not recorders:
                continue
            for recorder in recorders:
                if recorder in recorders_for_target:
                    continue
                recorders_for_target.add(recorder)
                identifier = task_id("playbook", recorder, target)
                if identifier in seen:
                    continue
                seen.add(identifier)
                tasks.append(_task("playbook", recorder, target, step.action, step_order=step.order))
    return tasks


def _label_for(block: PIBlock, node_id: str) -> str:
    for finding in block.findings:
        if finding.node_id == node_id:
            return _plain_label(finding.label) or node_id
    return node_id


def _org_like(finding: Finding) -> bool:
    if finding.node_id.startswith(_CORROBORATE_SKIP_PREFIXES):
        return False
    if finding.node_id.startswith(_ORG_NODE_PREFIXES):
        return True
    return any(marker in finding.label for marker in _ORG_LABEL_MARKERS)


def _corroborate_leads(block: PIBlock) -> List[Finding]:
    leads = [
        finding
        for finding in block.findings
        if finding.finding_label == FindingLabel.LEAD
        and finding.relevance in ("subject", "related")
        and _org_like(finding)
    ]
    ranked = list(enumerate(leads))
    ranked.sort(key=lambda item: (0 if item[1].relevance == "subject" else 1, item[1].label, item[0]))
    return [finding for _index, finding in ranked]


def _contradiction_source(node_ids: Sequence[str]) -> str:
    if any(node_id.startswith("lei:") for node_id in node_ids):
        return "gleif"
    if any(node_id.startswith(("company:", "psc:")) for node_id in node_ids):
        return "uk_psc"
    return "sec_edgar"


def follow_up_tasks(block: PIBlock, done: Set[str], *, limit: int) -> List[CaseTask]:
    """Extend ownership, then corroborate leads, then resolve contradictions. ``done`` ids are skipped."""
    if limit <= 0:
        return []
    chosen: List[CaseTask] = []
    seen: Set[str] = set(done)

    def add(task: CaseTask) -> None:
        if len(chosen) >= limit or task.task_id in seen:
            return
        seen.add(task.task_id)
        chosen.append(task)

    for entry in block.ownership.unresolved:
        node_id = unresolved_node_id(entry)
        target = _label_for(block, node_id)
        why = f"extend the ownership walk for unresolved node {node_id}"
        for source in _EXTEND_SOURCES:
            add(_task("extend_ownership", source, target, why))

    for finding in _corroborate_leads(block):
        target = _plain_label(finding.label) or finding.node_id
        why = f"corroborate single-source lead '{finding.label}' ({finding.node_id})"
        for source in _CORROBORATE_SOURCES:
            add(_task("corroborate_lead", source, target, why))

    for contradiction in block.contradictions:
        if not contradiction.node_ids:
            continue
        target = contradiction.node_ids[0]
        source = _contradiction_source(contradiction.node_ids)
        add(_task("resolve_contradiction", source, target, f"resolve contradiction {contradiction.kind}"))
    return chosen


# ----------------------------------------------------------------------------------------------
# Done and stop
# ----------------------------------------------------------------------------------------------


def _searched_classes(block: PIBlock) -> Set[str]:
    return {row.source_class for row in block.coverage if row.searched}


def _due_diligence_done(block: PIBlock) -> bool:
    searched = _searched_classes(block)
    return all(source_class in searched for source_class in _DUE_DILIGENCE_DONE_CLASSES)


def _is_org_or_asset(finding: Finding) -> bool:
    if finding.node_id.startswith(_ORG_NODE_PREFIXES + _ASSET_NODE_PREFIXES):
        return True
    return any(marker in finding.label for marker in _ORG_LABEL_MARKERS)


def _accounted_for(finding: Finding, block: PIBlock) -> bool:
    unresolved_ids = {unresolved_node_id(entry) for entry in block.ownership.unresolved}
    if finding.node_id in unresolved_ids:
        return True
    plain = _plain_label(finding.label)
    for custodian in block.custodians:
        if finding.node_id and finding.node_id in custodian.finding:
            return True
        if plain and plain in custodian.finding:
            return True
    return False


def _asset_search_done(block: PIBlock) -> bool:
    expected = expected_source_classes(block.engagement.case_type, block.engagement.subject_is_person)
    searched = _searched_classes(block)
    if expected and all(source_class in searched for source_class in expected):
        return True
    # The OR is exact: findings must exist, and every org/asset finding is unresolved or with a custodian.
    if not block.findings:
        return False
    return all(_accounted_for(finding, block) for finding in block.findings if _is_org_or_asset(finding))


def _fraud_screen_done(block: PIBlock) -> bool:
    if any(not finding.finding_label for finding in block.findings):
        return False
    complaints = [
        finding
        for finding in block.findings
        if "cfpb" in finding.label.casefold() or "complaint" in finding.label.casefold()
    ]
    if complaints:
        notice_unverified = any("unverified" in note.casefold() for note in block.notices)
        if not notice_unverified and any("unverified" not in finding.relevance_reason.casefold() for finding in complaints):
            return False
    crypto = any(finding.node_id.startswith(("wallet:", "btc:")) for finding in block.findings)
    crypto = crypto or any(row.source_class == "crypto_onchain" and row.outcome == "hit" for row in block.coverage)
    return not crypto or bool(block.custodians)


DONE_EVALUATORS: Dict[CaseType, Callable[[PIBlock], bool]] = {
    CaseType.DUE_DILIGENCE: _due_diligence_done,
    CaseType.ASSET_SEARCH: _asset_search_done,
    CaseType.FRAUD_SCREEN: _fraud_screen_done,
}


def done_status_for(block: PIBlock) -> Literal["met", "not_met", "not_evaluated"]:
    evaluator = DONE_EVALUATORS.get(block.engagement.case_type)
    if evaluator is None:
        return "not_evaluated"
    return "met" if evaluator(block) else "not_met"


def _sanctions_counsel(block: PIBlock) -> Tuple[bool, str]:
    hits = [hit for hit in block.sanctions.hits if isinstance(hit, dict)]
    blocked = list(block.ownership.blocked_by_50_rule)
    if hits or blocked:
        which: List[str] = []
        if hits:
            which.append("sanctions hits")
        if blocked:
            which.append("50% rule block")
        return True, "refer to compliance counsel: " + ", ".join(which)
    return False, "no sanctions hit and no 50% rule block found"


def _cash_out_found(block: PIBlock) -> Tuple[bool, str]:
    for custodian in block.custodians:
        blob = f"{custodian.finding} {custodian.custodian} {custodian.note}".casefold()
        if "exchange" in blob or "cash-out" in blob or "cash out" in blob:
            return True, f"cash-out custodian {custodian.custodian}"
    return False, "no exchange or cash-out custodian found"


STOP_EVALUATORS: Dict[str, Callable[[PIBlock], Tuple[bool, str]]] = {
    "sanctions_counsel": _sanctions_counsel,
    "cash_out_found": _cash_out_found,
}


def stop_check(
    board: CaseBoard,
    step: Optional[PlaybookStep],
    block: PIBlock,
    triggers: Sequence[EscalationTrigger],
    *,
    done_eval: Callable[[PIBlock], bool],
    no_progress: bool = False,
) -> Optional[Tuple[StopReason, str]]:
    """First matching stop wins. ``cash_out_found`` is a step decision, not a case stop."""
    playbook = playbook_for(block.engagement.case_type)
    for trigger in triggers:
        if not trigger.fired:
            continue
        if playbook.escalate_keys.get(trigger.trigger) == "sanctions_or_50_rule":
            return StopReason.ESCALATED, "refer to compliance counsel: " + trigger.why
    if step is not None and step.stop_key in CASE_ENDING_STOP_KEYS:
        evaluator = STOP_EVALUATORS.get(step.stop_key)
        if evaluator is not None:
            fired, detail = evaluator(block)
            if fired:
                return StopReason.ESCALATED, detail
    if done_eval(block):
        return StopReason.DONE, "done-when check met"
    if board.calls_used >= board.budget:
        return StopReason.BUDGET, f"calls {board.calls_used}/{board.budget}"
    if no_progress:
        return StopReason.NO_PROGRESS, "no new findings and no hypothesis change"
    return None


def step_stop_decision(step: PlaybookStep, block: PIBlock) -> str:
    """``cash_out_found`` pauses the step. It does not end the case."""
    if step.stop_key == "cash_out_found":
        fired, _detail = STOP_EVALUATORS["cash_out_found"](block)
        if fired:
            return "stop:cash_out_found"
    return "continue"
