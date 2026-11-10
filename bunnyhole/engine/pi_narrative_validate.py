"""Deterministic validator of the AI analysis. A pure function: it decides, the model does not.

The model writes ONE section, ``### Connections``: at most six bullets of the exact shape
``- [F1,O1] one or two plain sentences``, tags first. Everything risky is code-built instead (the "What is not
established" and "Suggested next steps" sections, the label next to every tag, the Bottom line, the sanctions text),
so whole classes of misstatement cannot be written at all. ``validate_analysis`` checks the model's text; any
violation means the text is not written to the report. Order of work: length cap first (nothing else runs on an
oversized text), then the character allowlist, then the layout, then one pass over the bullets.

What is enforced, allowlists first:

- characters: ASCII letters, accented Latin letters, ASCII digits, the ASCII space and ``. , ; : ' " ( ) - / & % @ _``
  only; square brackets only in the leading tag. Invisible, bidi and format characters, other scripts, fullwidth
  forms (NOT ligatures or small capitals: a known gap, see docs/PI_STREAM.md), backticks, ``#`` ``>`` ``*`` ``|`` ``<`` ``~`` and tabs are refused (typographic quotes and dashes
  are first turned into ASCII);
- layout: the heading line, then bullets only (or the single line ``None.``); at most 6 bullets of at most 400
  characters and two sentences; each bullet starts with a tag of 1 to 4 ids, all of kind F or O that were in the
  prompt; no other brackets;
- specifics: every digit-bearing token, number word, month, hex string, IPv4/IPv6 address, URL, email, domain, @handle
  and capitalised word (the first word of a sentence included; closed-class function words are the only exception)
  must occur in the evidence the model was shown; a run of two or more evidence words must occur in that order;
- English gate: a quarter of the words outside the evidence must be English function words;
- second layer (word screens, no negation exceptions): sanctions, screening, list, hit, match, risk, clear, absence and
  similar topics; label and certainty words; accusation words unless the cited evidence contains them.

Limits, stated honestly: this is a token and word screen, not understanding. A fluent bullet that cites the wrong
finding, misreads what a record means, or is defamatory without using a screened word passes. A lowercase invented
name written as ordinary words ("robert smith"), a paraphrase of a screened topic, and a real name from the evidence
attached to the wrong record are not caught. Language is not enforced beyond the Latin allowlist and the function-word
gate. The validator has never run against a live model. A false rejection costs one retry; a false acceptance costs
credibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Sequence, Tuple

from bunnyhole.engine.pi_narrative_checks import (
    EvidenceIndex,
    accusation,
    advice_or_method,
    build_index,
    certainty_word,
    disallowed_character,
    excluded_topic,
    invented_specifics,
    language_ok,
    normalise_typography,
    obfuscation,
    too_short,
)
from bunnyhole.engine.pi_narrative_feedback import echoable_word, invented_class
from bunnyhole.engine.pi_narrative_input import NarrativeEvidence
from bunnyhole.engine.pi_narrative_screens import content_free, duplicate_ids, identity_or_ownership

SECTION_HEADING = "Connections"
HEADING_LINE = f"### {SECTION_HEADING}"
#: The single line that means "no connections between the findings".
NO_CONNECTIONS = "None."
MAX_CHARS = 3000
MAX_BULLETS = 6
MAX_BULLET_CHARS = 400
MAX_SENTENCES = 2
MAX_TAG_IDS = 4
_MAX_VIOLATIONS = 30

#: Note-level reasons (fixed wording; never quotes model text).
REASON_TEXT: Dict[str, str] = {
    "too_long": "it was too long",
    "characters": "it used characters outside the allowed set",
    "structure": "it was not the Connections heading followed by tagged bullets",
    "bullets": "it had too many bullets, a bullet that was too long or too short, or more than two sentences in a bullet",
    "citation": "a bullet cited an id that is not allowed in Connections",
    "unknown_id": "a citation used an id that was not supplied",
    "markup": "it used square brackets outside the leading citation tag",
    "topic": "it discussed sanctions, screening, lists, hits, risk or absence, which the code-built report covers",
    "certainty": "it used a label or certainty word",
    "advice": "it gave advice, named a method or started with an instruction, which the code builds instead",
    "accusation": "it used an accusation word the evidence does not contain",
    "duplicate_id": "a tag repeated an id",
    "repetitive": "a bullet had too little content (repeated words or mostly punctuation)",
    "identity": "it asserted an identity, an ownership, a relation or a probability in its own words",
    "invented": "it named a number, month, address, handle or name that is not in the evidence",
    "language": "it was not in English",
    "no_connections": "the model found no connections between findings",
}
#: Per-bullet feedback for the retry prompt (fixed wording; ``{n}`` is the bullet number).
_FEEDBACK: Dict[str, str] = {
    "bullets": "bullet {n} is too long, too short or has more than two sentences",
    "citation": "bullet {n} cites an id that is not an F or O id from the prompt",
    "markup": "bullet {n} uses square brackets outside its leading tag",
    "topic": "bullet {n} discusses sanctions, screening, lists, hits, risk or absence",
    "certainty": "bullet {n} uses a label or certainty word",
    "advice": "bullet {n} gives advice, names a method or starts with an instruction",
    "accusation": "bullet {n} uses an accusation word that the evidence does not contain",
    "duplicate_id": "bullet {n} repeats an id inside its tag",
    "repetitive": "bullet {n} has too little content: use at least three distinct words of three letters or more",
    "identity": (
        "bullet {n} states an identity, ownership, relation or probability in its own words; state an ownership "
        "edge only as the exact phrase of its O line"
    ),
    "invented": "bullet {n} names a number, month, address, handle or capitalised word that is not in the evidence",
    "language": "bullet {n} is not in English",
}
_UNSAFE_ID_TEXT = "an unknown citation id"


@dataclass(frozen=True)
class Violation:
    """One failed check. ``detail`` is for logs and tests only: it is never put into a prompt, note or report.

    ``word`` is the offending word only when it is in the validator's own fixed vocabulary (so a retry prompt may
    echo it); ``word_class`` is a fixed description of what kind of item was offending. Both are safe to print.
    """

    code: str
    detail: str = ""
    bullet: int = 0
    word: str = ""
    word_class: str = ""


class Bullet(NamedTuple):
    ids: Tuple[str, ...]
    text: str


def reasons(violations: Sequence[Violation]) -> List[str]:
    """The distinct note-level reasons for ``violations``, in first-seen order. Never quotes model text."""
    return list(dict.fromkeys(REASON_TEXT[v.code] for v in violations))


def feedback_lines(violations: Sequence[Violation]) -> List[str]:
    """Fixed-wording lines for the retry prompt. Only ids of the shape ``F9`` are ever echoed."""
    lines: List[str] = []
    for v in violations:
        if v.code == "unknown_id":
            text = f"unknown id {v.detail}" if _SAFE_ID_RE.match(v.detail) else _UNSAFE_ID_TEXT
        elif v.code in _FEEDBACK and v.bullet:
            text = _FEEDBACK[v.code].format(n=v.bullet)
            if v.word_class:
                text += f"; first offending item: {v.word_class}"
            if v.word:
                text += f" ('{v.word}')"
        else:
            text = REASON_TEXT[v.code]
        if text not in lines:
            lines.append(text)
    return lines


def _clip(text: str, limit: int = 40) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 1] + "…"


# --------------------------------------------------------------------------------------- parsing

_TAG_RE = re.compile(r"^- \[([A-Z]\d{1,3}(?:, ?[A-Z]\d{1,3}){0,3})\] (\S.*)$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z]\d{1,6}$")
_ABBREVIATION_RE = re.compile(r"\b(?:Ltd|Inc|Corp|Co|Jr|Sr|St|vs|Mr|Mrs|Dr)\.")
_SENTENCE_END_RE = re.compile(r"\.(?=\s|$)")


def _normalise(text: str) -> str:
    return normalise_typography(text).replace("\r\n", "\n").replace("\r", "\n")


def parse_bullets(text: str) -> Optional[List[Bullet]]:
    """The bullets of a well-formed Connections section, ``[]`` for ``None.``, ``None`` when the layout is wrong."""
    lines = [line.rstrip() for line in _normalise(text).split("\n") if line.strip()]
    if not lines or lines[0] != HEADING_LINE:
        return None
    body = lines[1:]
    if body == [NO_CONNECTIONS]:
        return []
    bullets: List[Bullet] = []
    for line in body:
        match = _TAG_RE.match(line)
        if match is None:
            return None
        bullets.append(Bullet(tuple(part.strip() for part in match.group(1).split(",")), match.group(2)))
    return bullets or None


def _sentence_count(text: str) -> int:
    return len(_SENTENCE_END_RE.findall(_ABBREVIATION_RE.sub("Abbr", text))) or 1


# --------------------------------------------------------------------------------------- rendering

_MARKDOWN_SPECIALS = "\\*_`[]()<>#|!~&"


def escape_markdown(text: str) -> str:
    """Backslash-escape every Markdown-special character of ``text`` (belt and braces: the allowlist already
    refuses most of them)."""
    return "".join("\\" + ch if ch in _MARKDOWN_SPECIALS else ch for ch in text)


def render_connections(text: str, labels: Dict[str, str]) -> str:
    """The Connections section as plain list items, each tag showing the label the CODE holds for its finding.

    ``[F1,O1]`` is written ``[F1 · confirmed, O1]``. Call only on text that passed :func:`validate_analysis`.
    """
    bullets = parse_bullets(text) or []
    lines = []
    for bullet in bullets:
        tags = ", ".join(f"{i} · {labels[i]}" if i in labels else i for i in bullet.ids)
        lines.append(f"- [{tags}] {escape_markdown(bullet.text)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------- validation


def _check_bullet(
    number: int, bullet: Bullet, line_length: int, idx: EvidenceIndex, known: FrozenSet[str]
) -> List[Violation]:
    found: List[Violation] = []

    def flag(code: str, detail: str = "") -> None:
        found.append(Violation(code, _clip(detail), number, echoable_word(detail)))

    def flag_invented(item: str) -> None:
        word_class, word = invented_class(item)
        found.append(Violation("invented", _clip(item), number, word, word_class))

    text = bullet.text
    if line_length > MAX_BULLET_CHARS or _sentence_count(text) > MAX_SENTENCES or too_short(text):
        flag("bullets")
    elif content_free(text):
        flag("repetitive")
    if duplicate_ids(bullet.ids):
        flag("duplicate_id")
    for item_id in dict.fromkeys(bullet.ids):
        if item_id in idx.model_ids:
            continue
        found.append(Violation("citation" if item_id in known else "unknown_id", item_id, number))
    if "[" in text or "]" in text:
        flag("markup")
    word = obfuscation(text)
    if word:
        flag_invented(word)
    word = excluded_topic(text)
    if word:
        flag("topic", word)
    word = certainty_word(text)
    if word:
        flag("certainty", word)
    word = advice_or_method(text)
    if word:
        flag("advice", word)
    word = accusation(text, list(bullet.ids), idx)
    if word:
        flag("accusation", word)
    word = identity_or_ownership(text, idx.names)
    if word:
        flag("identity", word)
    if not language_ok(text, idx):
        flag("language")
    for item in invented_specifics(text, idx):
        flag_invented(item)
    return found


def validate_analysis(text: str, evidence: NarrativeEvidence) -> List[Violation]:
    """Every violation of the output contract in ``text`` (empty list means the text may be written)."""
    if len(text) > MAX_CHARS:  # first, before any regex: an oversized text is never scanned
        return [Violation("too_long", f"{len(text)} characters")]
    normalised = _normalise(text)
    character = disallowed_character(normalised.replace(HEADING_LINE, "", 1))
    if character is not None:
        return [Violation("characters", repr(character))]
    bullets = parse_bullets(normalised)
    if bullets is None:
        return [Violation("structure")]
    if not bullets:
        return [Violation("no_connections")]
    violations: List[Violation] = []
    if len(bullets) > MAX_BULLETS:
        violations.append(Violation("bullets", f"{len(bullets)} bullets"))
    idx = build_index(evidence)
    raw_lines = [line.rstrip() for line in normalised.split("\n") if line.strip()][1:]
    for number, (bullet, line) in enumerate(zip(bullets, raw_lines), start=1):
        violations += _check_bullet(number, bullet, len(line), idx, evidence.known_ids)
        if len(violations) >= _MAX_VIOLATIONS:
            break
    return violations
