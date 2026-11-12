"""PI stream core: engagement, confidence labels and the ``result["pi"]`` schema.

The data models below are final (other PI modules import them). The purpose gates live in ``pi_gates`` (vocabulary
in ``pi_gate_terms``), the name and email heuristics in ``pi_identifiers`` and the base types in ``pi_types``; every
public name is re-exported here, so ``from bunnyhole.engine.pi import X`` keeps working. Do not change the models
without updating docs/superpowers/specs/2026-11-09-pi-stream-design.md.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Literal, Optional, Sequence
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from bunnyhole.engine.pi_gate_terms import (
    FORBIDDEN_ELIGIBILITY_PATTERNS,
    FORBIDDEN_ELIGIBILITY_TERMS,
    MIN_PURPOSE_CHARS,
    MOTIVE_PATTERNS,
    MOTIVE_RED_FLAGS,
    PURSUIT_EVASION_FLAGS,
)
from bunnyhole.engine.pi_gates import (
    is_valid_matter_ref,
    motive_screen,
    pursuit_screen,
    require_matter_ref,
    validate_purpose,
)
from bunnyhole.engine.pi_identifiers import (
    CORPORATE_MARKERS,
    identifier_warnings,
    is_free_mail_address,
    looks_like_natural_person_name,
    looks_like_person_email,
)
from bunnyhole.engine.pi_purpose import (
    require_no_credentials,
    require_person_basis,
    require_purpose_category,
    screen_free_texts,
)
from bunnyhole.engine.pi_types import (
    PERSON_PURPOSE_CATEGORIES,
    RELATIONSHIP_TERM_CATEGORIES,
    CaseType,
    FindingLabel,
    PIEligibilityError,
    PIPurposeError,
    PurposeCategory,
    purpose_category_values,
)

__all__ = [
    "CORPORATE_MARKERS",
    "FORBIDDEN_ELIGIBILITY_PATTERNS",
    "FORBIDDEN_ELIGIBILITY_TERMS",
    "MIN_PURPOSE_CHARS",
    "MOTIVE_PATTERNS",
    "MOTIVE_RED_FLAGS",
    "NOTICES",
    "PURSUIT_EVASION_FLAGS",
    "CaseBoard",
    "CaseHypothesis",
    "CaseStepRecord",
    "CaseTask",
    "CaseType",
    "Contradiction",
    "CoverageRow",
    "CustodyEntry",
    "Custodian",
    "EntityProfile",
    "EscalationTrigger",
    "EvidenceLink",
    "Finding",
    "FindingLabel",
    "HypothesisStatus",
    "OwnershipBlock",
    "OwnershipEdge",
    "PIBlock",
    "PIEngagement",
    "PIEligibilityError",
    "PIPurposeError",
    "PERSON_PURPOSE_CATEGORIES",
    "PlaybookProgress",
    "PurposeCategory",
    "RELATIONSHIP_TERM_CATEGORIES",
    "SanctionsScreening",
    "StopReason",
    "SourceLogEntry",
    "count_independent_sources",
    "identifier_warnings",
    "is_free_mail_address",
    "is_valid_matter_ref",
    "label_finding",
    "looks_like_natural_person_name",
    "looks_like_person_email",
    "motive_screen",
    "purpose_category_values",
    "pursuit_screen",
    "require_matter_ref",
    "require_person_basis",
    "require_purpose_category",
    "validate_purpose",
]


class PIEngagement(BaseModel):
    engagement_id: str
    case_type: CaseType
    purpose: str
    purpose_category: str = ""  # attested permissible-purpose category (allowlist; see pi_gates)
    objective: str = ""
    client: str = ""
    matter_ref: str = ""
    jurisdiction: str = ""
    subject_is_person: bool = True
    passive_only: bool = True
    created_at_utc: str

    @classmethod
    def build(
        cls,
        case_type: CaseType,
        purpose: str,
        *,
        client: str = "",
        matter_ref: str = "",
        jurisdiction: str = "",
        subject_is_person: bool = True,
        purpose_category: "str | PurposeCategory" = "",
        extra_texts: Sequence[str] = (),
    ) -> "PIEngagement":
        """Run every gate, then return the engagement. Raises :class:`PIPurposeError` on any refusal.

        ``purpose_category`` is the attested permissible purpose (see :class:`PurposeCategory`); it is required, and
        a natural-person subject also needs a person-eligible category and a valid ``matter_ref``. ``extra_texts``
        are the other free-text fields of the run (hypothesis, pasted notes, selectors): the eligibility, motive and
        pursuit screens run over their concatenation with the purpose, client and matter reference. Credential-shaped
        text in the purpose, client or matter reference is refused (the secret is never echoed): those fields are
        stored verbatim in the engagement and the report.
        """
        declared = str(getattr(purpose_category, "value", purpose_category) or "").strip()
        require_no_credentials({"--purpose": purpose, "--client": client, "--matter-ref": matter_ref})
        try:
            clean_purpose = validate_purpose(purpose, declared)
            screen_free_texts(
                [clean_purpose, client, matter_ref, *extra_texts], case_type, subject_is_person, matter_ref, declared
            )
        except PIEligibilityError as exc:
            if declared:
                raise PIEligibilityError(
                    f"The declared purpose contradicts the described use: category {declared!r} was attested, but "
                    f"the text describes an eligibility decision. {exc}"
                ) from exc
            raise
        category = require_purpose_category(declared)
        require_person_basis(category, subject_is_person, matter_ref)
        require_matter_ref(case_type, subject_is_person, matter_ref)
        created_at_utc = datetime.now(timezone.utc).isoformat()
        digest = hashlib.sha256(f"{created_at_utc}|{case_type.value}|{clean_purpose}".encode()).hexdigest()
        return cls(
            engagement_id="pi_" + digest[:10],
            case_type=case_type,
            purpose=clean_purpose,
            purpose_category=category.value,
            client=client.strip(),
            matter_ref=matter_ref.strip(),
            jurisdiction=jurisdiction.strip(),
            subject_is_person=subject_is_person,
            created_at_utc=created_at_utc,
        )


class SourceLogEntry(BaseModel):
    source: str
    target: str
    status: Literal["hit", "negative", "skipped", "error"]
    detail: str = ""
    at_utc: str


class Finding(BaseModel):
    node_id: str
    label: str
    finding_label: FindingLabel
    source_count: int
    freshness: str = "unknown"  # fresh | aging | stale | unknown
    relevance: Literal["subject", "related", "unrelated", "unknown"] = "unknown"
    relevance_reason: str = ""  # why the node is (or is not) about the subject


class OwnershipEdge(BaseModel):
    child: str
    parent: str
    pct: Optional[float] = None
    source: str = ""
    as_of: str = ""


class OwnershipBlock(BaseModel):
    levels_walked: int = 0
    edges: List[OwnershipEdge] = Field(default_factory=list)
    blocked_by_50_rule: List[str] = Field(default_factory=list)
    unresolved: List[str] = Field(default_factory=list)  # walk ended before reaching a natural person


class CustodyEntry(BaseModel):
    receipt_id: str
    tool: str
    url: str
    sha256: str
    collected_at_utc: str


class Contradiction(BaseModel):
    kind: str
    description: str
    node_ids: List[str] = Field(default_factory=list)


class CoverageRow(BaseModel):
    source_class: str
    searched: bool
    sources: List[str] = Field(default_factory=list)  # sources that actually ran (hit or negative)
    skipped: List[str] = Field(default_factory=list)  # sources tried but unreachable/blocked/skipped: NOT coverage
    outcome: str = ""  # hit | negative | not_searched


class Custodian(BaseModel):
    finding: str
    custodian: str
    instrument: str
    jurisdiction: str
    note: str = ""


class EntityProfile(BaseModel):
    """Registry-first profile of the subject entity, from registry sources only (GLEIF, Companies House ...)."""

    legal_name: str = ""
    lei: str = ""
    status: str = ""
    jurisdiction: str = ""
    registered_address: str = ""
    parents: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)


class SanctionsScreening(BaseModel):
    """What sanctions/PEP screening actually ran. A listing is a SOFT name match until verified on the list."""

    status: Literal["not_run", "partial", "lists_run"] = "not_run"
    screened: List[str] = Field(default_factory=list)  # lists that ran, e.g. "Canada SEMA", "OFAC SDN"
    not_screened: List[str] = Field(default_factory=list)  # lists tried but not reached, or never run
    hits: List[dict] = Field(default_factory=list)  # {"list","name","match","url","node_id"}
    # list entries that matched on a name only and were NOT linked to a person subject: {"name","reason","url"}
    weak_matches: List[dict] = Field(default_factory=list)


class PlaybookProgress(BaseModel):
    """One playbook step and what the run actually did about it."""

    order: int
    action: str
    sources: List[str] = Field(default_factory=list)
    status: Literal["done", "partial", "not_run", "handoff"]  # handoff = needs the licensed layer / counsel
    evidence: str = ""


class EscalationTrigger(BaseModel):
    trigger: str  # playbook escalate_when text
    fired: bool
    why: str = ""


class HypothesisStatus(str, Enum):
    OPEN = "open"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    RULED_OUT = "ruled_out"


class EvidenceLink(BaseModel):
    signal: str
    direction: Literal["supports", "refutes"]
    weight: float
    detail: str
    node_ids: List[str] = Field(default_factory=list)


class CaseHypothesis(BaseModel):
    key: str
    text: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    score: float = 0.0
    evidence: List[EvidenceLink] = Field(default_factory=list)


class CaseTask(BaseModel):
    task_id: str
    origin: Literal["playbook", "corroborate_lead", "extend_ownership", "resolve_contradiction"]
    step_order: Optional[int] = None
    source: str
    target: str
    why: str


class CaseStepRecord(BaseModel):
    order: int
    label: str
    tasks: List[str] = Field(default_factory=list)
    new_findings: int = 0
    hypotheses_changed: List[str] = Field(default_factory=list)
    decision: str = "continue"
    counsel: str = ""
    elapsed_s: float = 0.0


class StopReason(str, Enum):
    DONE = "done"
    ESCALATED = "escalated"
    DEAD_END = "dead_end"
    BUDGET = "budget_spent"
    NO_PROGRESS = "no_progress"


class CaseBoard(BaseModel):
    hypotheses: List[CaseHypothesis]
    log: List[CaseStepRecord] = Field(default_factory=list)
    stop_reason: Optional[StopReason] = None
    stop_detail: str = ""
    calls_used: int = 0
    budget: int
    guide_name: str = "playbook"


class PIBlock(BaseModel):
    """What goes in ``result["pi"]`` (``model_dump(mode="json")``)."""

    engagement: PIEngagement
    identifier_warnings: List[str] = Field(default_factory=list)
    prior_cases: List[dict] = Field(default_factory=list)  # {"case_id","seed","at"}
    source_log: List[SourceLogEntry] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    ownership: OwnershipBlock = Field(default_factory=OwnershipBlock)
    false_link_flags: List[dict] = Field(default_factory=list)  # {"node_id","reason","severity"}
    contradictions: List[Contradiction] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    coverage: List[CoverageRow] = Field(default_factory=list)
    falsifiers: List[str] = Field(default_factory=list)
    custodians: List[Custodian] = Field(default_factory=list)
    handoff_sheet: List[str] = Field(default_factory=list)
    custody: List[CustodyEntry] = Field(default_factory=list)
    notices: List[str] = Field(default_factory=list)
    identity_notes: List[str] = Field(default_factory=list)  # name collisions / records NOT established as one person
    done_when: str = ""  # the playbook's "done" definition (a human judges it; the run does not claim it is met)
    playbook_progress: List[PlaybookProgress] = Field(default_factory=list)
    escalation_triggers: List[EscalationTrigger] = Field(default_factory=list)
    entity_profile: Optional[EntityProfile] = None
    sanctions: SanctionsScreening = Field(default_factory=SanctionsScreening)
    loop_mode: Literal["sweep", "casework"] = "sweep"
    case_board: Optional[CaseBoard] = None
    done_status: Literal["met", "not_met", "not_evaluated"] = "not_evaluated"


# --------------------------------------------------------------------------- labels and corroboration


def label_finding(independent_source_count: int) -> FindingLabel:
    """3+ independent sources confirmed, 2 probable, otherwise a lead."""
    if independent_source_count >= 3:
        return FindingLabel.CONFIRMED
    if independent_source_count == 2:
        return FindingLabel.PROBABLE
    return FindingLabel.LEAD


def _url_key(source_url: object) -> str:
    """Host plus path of a URL, lowercase, ignoring scheme-less/query/fragment/trailing slash. Empty if unusable."""
    text = str(source_url or "").strip()
    if not text:
        return ""
    parts = urlsplit(text)
    return f"{parts.netloc}{parts.path}".lower().rstrip("/")


def count_independent_sources(receipts: List[dict]) -> int:
    """Count independent sources among receipts (dicts with ``tool`` and ``source_url``).

    Each distinct tool counts once, but receipts whose URLs resolve to the same host+path are one source
    even when the tool differs (transitively). Receipts without a tool are ignored; an empty URL falls
    back to the tool alone.
    """
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    first_tool_for_url: Dict[str, str] = {}
    for receipt in receipts:
        tool = str(receipt.get("tool") or "").strip()
        if not tool:
            continue
        parent.setdefault(tool, tool)
        key = _url_key(receipt.get("source_url"))
        if not key:
            continue
        if key in first_tool_for_url:
            union(tool, first_tool_for_url[key])
        else:
            first_tool_for_url[key] = tool
    return len({find(t) for t in parent})


# --------------------------------------------------------------------------- standing notices

NOTICES: tuple[str, ...] = (
    "This report is not a consumer report and must not be used for eligibility decisions about employment, "
    "tenancy, credit, loans or insurance (FCRA-regulated); use an FCRA-compliant screening provider for those.",
    "Findings are leads, not verdicts: each is labelled by how many independent sources support it, and "
    "records can be stale, mismatched or wrong.",
    "Absence from the sources searched is not proof of absence: the coverage matrix shows what was and was "
    "not searched.",
    "Bunnyhole is a research tool. It does not hold or imply a private investigator licence, grants no police "
    "powers, and does not replace a licensed investigator or counsel.",
    "Bunnyhole uses free, lawful, passive sources only: no pretexting, tracking, recording, account access or "
    "contact with the subject.",
    "In Ontario, verify with the Ministry of the Solicitor General whether the Private Security and "
    "Investigative Services Act, 2005 (PSISA) licensing applies if this work supports paid third-party "
    "investigation.",
)
