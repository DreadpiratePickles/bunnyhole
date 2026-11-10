"""Deterministic validator of the AI analysis. A pure function: it decides, the model does not.

``validate_analysis`` checks the model's text against the evidence it was given and the output contract in
``pi_report_rules.md``. Any violation means the text is not written to the report. Order of work: the length cap
first (nothing else runs on an oversized text), then the character screen, then layout, then one pass over sentences.

Structural rules (allowlists) come first, blocklists are the second layer:

- layout: exactly the four sections, in order, nothing before the first; no invisible, bidi or control characters;
  no links, images, HTML, code or square brackets that are not citations;
- citations: every sentence ends in tags such as ``[F3]`` / ``[F2,F5]`` and every id was supplied;
- specifics: every digit-bearing token, month name, URL, email, hash, receipt id, non-Latin word and capitalised
  word (names, acronyms, the first word of a sentence unless it is an allow-listed starter) must occur in the
  evidence, or be on a short allowlist of legal frames and generic institutional words;
- Timeline: each bullet carries a date from the evidence; next steps: each sentence starts with an allow-listed lawful
  verb, and a verb that reaches a person needs an honest-identification phrase;
- labels: wording may not exceed the label of any cited finding; a sentence citing a lead must hedge; a set-aside
  weak match must read as set aside and never as the subject;
- sanctions: a sentence about sanctions may restate the evidence but may not conclude clearance, risk level,
  compliance or safety, and absence-of-hit wording needs a same-sentence not-screened or not-clearance qualifier;
- second layer (keyword screens, run on every sentence, negated mentions rejected too): forbidden or deceptive
  methods, accusation words that the cited evidence does not itself contain.

Limits, stated honestly: this is a token and keyword screen, not understanding. It cannot tell that a fluent, correctly
cited sentence misreads a record, or that a cited statement is defamatory in context. A lowercase or uncased invented
name ("robert smith"), a spelled-out number ("five") and a paraphrase of a forbidden method pass. The capitalised-name
check compares tokens, so a real name in the evidence can be attached to the wrong record. Rejecting a sentence that
only says "do not hack" is deliberate. A false rejection costs one retry; a false acceptance costs credibility.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from bunnyhole.engine.pi_narrative_checks import (
    ACCUSATION,
    CLEARANCE,
    FORBIDDEN,
    INVENTED,
    LABEL,
    NEXT_STEP,
    TIMELINE,
    EvidenceIndex,
    accusation,
    build_index,
    clearance,
    forbidden_method,
    has_dated_token,
    invented_specifics,
    label_violation,
    next_step_problem,
    screen_text,
)
from bunnyhole.engine.pi_narrative_input import NarrativeEvidence

SECTION_HEADINGS: Tuple[str, ...] = (
    "Connections",
    "Timeline",
    "What is not established",
    "Suggested next steps (lawful)",
)
TIMELINE_SECTION = SECTION_HEADINGS[1]
NEXT_STEPS_SECTION = SECTION_HEADINGS[3]
#: The only sentences allowed without a citation (an empty section).
EXEMPT_SENTENCES: FrozenSet[str] = frozenset({"None.", "No dated facts were supplied."})
MAX_CHARS = 8000
_MAX_VIOLATIONS = 40

#: Note-level reasons (fixed wording; never quotes model text).
REASON_TEXT: Dict[str, str] = {
    "structure": "the sections were not exactly the four required, in order",
    "too_long": "it was too long",
    "invisible": "it contained invisible or control characters",
    "markup": "it used disallowed markup or square brackets that are not citations",
    "unknown_id": "a citation used an id that was not supplied",
    "uncited": "a sentence did not end with a citation",
    INVENTED: "it named a URL, email, number, date, hash, name or word that is not in the evidence",
    FORBIDDEN: "it mentioned an unlawful or deceptive method or a contact without honest identification",
    ACCUSATION: "it used an accusation word the evidence does not contain",
    CLEARANCE: "it used clearance, risk-level or safety wording about sanctions",
    LABEL: "it described a finding more strongly than its label allows",
    TIMELINE: "a Timeline bullet had no date from the evidence",
    NEXT_STEP: "a next step did not start with an allowed lawful verb",
    "no_content": "the model produced no analysis",
}
#: Per-sentence feedback for the retry prompt (fixed wording; ``{n}`` is the sentence number).
_FEEDBACK: Dict[str, str] = {
    "uncited": "sentence {n} has no citation",
    INVENTED: "sentence {n} names a URL, email, number, date, hash, name or word that is not in the evidence",
    FORBIDDEN: "sentence {n} names an unlawful or deceptive method, or contacts a person without honest identification",
    ACCUSATION: "sentence {n} uses an accusation word that the evidence does not contain",
    CLEARANCE: "sentence {n} uses clearance, risk-level or safety wording, or states an absence of hits without a qualifier",
    LABEL: "sentence {n} says more than the label allows, or states a lead or set-aside match without a hedge",
    TIMELINE: "sentence {n} has no date that is in the evidence",
    NEXT_STEP: "sentence {n} does not start with an allowed lawful verb",
    "markup": "sentence {n} uses disallowed markup or brackets",
}
_UNSAFE_ID_TEXT = "an unknown citation id"


@dataclass(frozen=True)
class Violation:
    """One failed check. ``detail`` is for logs and tests only: it is never put into a prompt, note or report."""

    code: str
    detail: str = ""
    sentence: int = 0


def reasons(violations: Sequence[Violation]) -> List[str]:
    """The distinct note-level reasons for ``violations``, in first-seen order. Never quotes model text."""
    return list(dict.fromkeys(REASON_TEXT[v.code] for v in violations))


def feedback_lines(violations: Sequence[Violation]) -> List[str]:
    """Fixed-wording, per-sentence lines for the retry prompt. Only ids of the shape ``F9`` are ever echoed."""
    lines: List[str] = []
    for v in violations:
        if v.code == "unknown_id":
            text = f"unknown id {v.detail}" if re.fullmatch(r"[A-Za-z]\d{1,6}", v.detail) else _UNSAFE_ID_TEXT
        elif v.code in _FEEDBACK and v.sentence:
            text = _FEEDBACK[v.code].format(n=v.sentence)
        else:
            text = REASON_TEXT[v.code]
        if text not in lines:
            lines.append(text)
    return lines


def _clip(text: str, limit: int = 40) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 1] + "…"


# --------------------------------------------------------------------------------------- parsing

_TAG_RE = re.compile(r"\[\s*[A-Za-z]\d+(?:\s*,\s*[A-Za-z]\d+)*\s*\]")
_BRACKET_RE = re.compile(r"\[[^\[\]]*+\]")
_BULLET_RE = re.compile(r"^\s*+(?:[-*•]|\d{1,2}[.)])\s++")
_BOUNDARY_RE = re.compile(
    r"(?<![.!?])[.!?]++(?:\s*+\[[^\[\]]*+\])*+(?=\s++[A-Z0-9\[(\"'“]|\s*+$)"
)
_ABBREVIATIONS = frozenset({"ltd", "inc", "corp", "co", "llc", "plc", "gmbh", "mr", "mrs", "ms", "dr", "vs", "no",
                            "st", "jr", "sr", "etc", "approx", "ref", "cf"})
_ALLOWED_CONTROL = frozenset({"\n", "\r", "\t"})
_BAD_CATEGORIES = frozenset({"Cf", "Cc", "Co", "Cs", "Cn", "Zl", "Zp"})


def cited_ids(text: str) -> List[str]:
    """Every id inside citation-shaped tags, in order of appearance (not de-duplicated)."""
    ids: List[str] = []
    for tag in _TAG_RE.finditer(text):
        ids.extend(part.strip() for part in tag.group(0).strip("[] ").split(","))
    return ids


def _has_invisible(text: str) -> bool:
    return any(ch not in _ALLOWED_CONTROL and unicodedata.category(ch) in _BAD_CATEGORIES for ch in text)


def _heading(line: str) -> Optional[str]:
    if not line.lstrip(" ").startswith("#") or len(line) - len(line.lstrip(" ")) > 3:
        return None
    return line.strip().lstrip("#").strip().rstrip("#").strip()


def _section_title(raw: str) -> Optional[str]:
    cleaned = raw.strip().rstrip(":").strip()
    return next((title for title in SECTION_HEADINGS if cleaned.lower() == title.lower()), None)


def _parse(text: str) -> Tuple[List[str], List[Tuple[str, List[str]]], List[str]]:
    """(preamble lines, [(canonical or raw heading, body lines)], raw headings)."""
    preamble: List[str] = []
    sections: List[Tuple[str, List[str]]] = []
    headings: List[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        raw = _heading(line)
        if raw is not None:
            headings.append(raw)
            sections.append((_section_title(raw) or raw, []))
        elif sections:
            sections[-1][1].append(line)
        else:
            preamble.append(line)
    return preamble, sections, headings


def split_sentences(line: str) -> List[str]:
    """Sentences of one line. A full stop after a legal-form abbreviation or an initial is not a boundary."""
    sentences: List[str] = []
    start = 0
    stripped_end = len(line.rstrip())
    for match in _BOUNDARY_RE.finditer(line):
        before = re.search(r"([A-Za-z]++)$", line[max(0, start):match.start()])
        single_dot = line[match.start():match.start() + 1] == "." and not match.group(0).startswith("..")
        abbreviated = before is not None and (before.group(1).lower() in _ABBREVIATIONS or len(before.group(1)) == 1)
        if abbreviated and single_dot and match.end() < stripped_end:
            continue
        sentences.append(line[start:match.end()].strip())
        start = match.end()
    tail = line[start:].strip()
    if tail:
        sentences.append(tail)
    return [s for s in sentences if s]


def _sentences_of(body: Sequence[str]) -> List[str]:
    out: List[str] = []
    for line in body:
        content = _BULLET_RE.sub("", line).strip()
        if content:
            out.extend(split_sentences(content))
    return out


def _is_exempt(sentence: str) -> bool:
    return sentence.rstrip(" ") in EXEMPT_SENTENCES


def has_content(text: str) -> bool:
    """True when ``text`` has at least one sentence that is not an exempt empty-section line."""
    preamble, sections, _headings = _parse(text)
    lines = list(preamble) + [line for _title, body in sections for line in body]
    return any(not _is_exempt(s) for s in _sentences_of(lines))


def canonical_markdown(text: str) -> str:
    """The analysis with canonical ``###`` headings and no blank lines inside a section. Call only after validation."""
    _preamble, sections, _headings = _parse(text)
    blocks = []
    for title, body in sections:
        lines = [line.rstrip() for line in body if line.strip()]
        blocks.append("\n".join([f"### {title}", *lines]))
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------------------- validation


def _structure(preamble: Sequence[str], sections: Sequence[Tuple[str, List[str]]], headings: Sequence[str]) -> List[Violation]:
    if [title for title, _body in sections] != list(SECTION_HEADINGS) or any(line.strip() for line in preamble):
        return [Violation("structure", _clip(", ".join(headings) or "no headings"))]
    return []


def _markup(text: str) -> List[Violation]:
    problems = []
    if ("`" in text or "](" in text or "![" in text or re.search(r"<\s*/?\s*[A-Za-z!]", text)
            or re.search(r"(?i)\b(?:javascript|vbscript|data|file):", text)):
        problems.append(Violation("markup", "link, image, code or HTML"))
    problems += [Violation("markup", "bracket") for b in _BRACKET_RE.findall(text) if not _TAG_RE.fullmatch(b)][:3]
    return problems


def _ends_with_tag(sentence: str) -> bool:
    body = sentence.rstrip(" \t.!?")
    start = body.rfind("[")
    return start >= 0 and body.endswith("]") and _TAG_RE.fullmatch(body[start:]) is not None


def _check_sentence(
    raw: str, number: int, section: Optional[str], idx: EvidenceIndex
) -> List[Violation]:
    sentence = screen_text(raw)
    found: List[Violation] = []

    def flag(code: str, detail: str = "") -> None:
        found.append(Violation(code, _clip(detail), number))

    if not _ends_with_tag(sentence):
        flag("uncited")
    ids = cited_ids(sentence)
    for item_id in dict.fromkeys(ids):
        if item_id not in idx.known_ids:
            found.append(Violation("unknown_id", item_id, number))
    for item in invented_specifics(sentence, idx):
        flag(INVENTED, item)
    method = forbidden_method(sentence)
    if method:
        flag(FORBIDDEN, method)
    word = accusation(sentence, ids, idx)
    if word:
        flag(ACCUSATION, word)
    word = clearance(sentence, ids)
    if word:
        flag(CLEARANCE, word)
    word = label_violation(sentence, ids, idx, hedge_required=section != NEXT_STEPS_SECTION)
    if word:
        flag(LABEL, word)
    if section == TIMELINE_SECTION and not has_dated_token(sentence, idx):
        flag(TIMELINE)
    if section == NEXT_STEPS_SECTION:
        problem = next_step_problem(sentence)
        if problem:
            flag(problem)
    return found


def validate_analysis(text: str, evidence: NarrativeEvidence) -> List[Violation]:
    """Every violation of the output contract in ``text`` (empty list means the text may be written)."""
    if len(text) > MAX_CHARS:  # first, before any regex: an oversized text is never scanned
        return [Violation("too_long", f"{len(text)} characters")]
    if _has_invisible(text):
        return [Violation("invisible")]
    violations: List[Violation] = []
    preamble, sections, headings = _parse(text)
    violations += _structure(preamble, sections, headings)
    violations += _markup(text)
    if not violations and not has_content(text):
        return [Violation("no_content")]
    idx = build_index(evidence)
    number = 0
    for title, body in [("", list(preamble))] + [(t, b) for t, b in sections]:
        section: Optional[str] = title if title in SECTION_HEADINGS else None
        for sentence in _sentences_of(body):
            number += 1
            if _is_exempt(sentence):
                continue
            violations += _check_sentence(sentence, number, section, idx)
            if len(violations) >= _MAX_VIOLATIONS:
                return violations
    return violations
