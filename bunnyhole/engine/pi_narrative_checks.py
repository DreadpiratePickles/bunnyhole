"""Per-sentence checks of the AI-analysis validator. Pure functions over one already length-capped sentence.

Four families: invented specifics (URLs, emails, hashes, numbers, months, names, scripts), language screens (forbidden
methods, accusation words, clearance, label upgrades), and the structural rules of the two sections that have one
(Timeline needs a date; next steps need a lawful verb). Allowlists decide first; blocklists are the second layer.
Linear time: every regex is possessive or bounded (see ``pi_narrative_lexicon``).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import FrozenSet, List, Mapping, Optional, Sequence, Set

from bunnyhole.engine.pi_narrative_input import NarrativeEvidence
from bunnyhole.engine.pi_narrative_lexicon import (
    ACCUSATION_RE,
    ALLOWED_NUMBER_TOKENS,
    ALLOWED_WORDS,
    CLEARANCE_ALWAYS_RE,
    CLEARANCE_NEGATABLE_RE,
    CONTACT_VERBS,
    FORBIDDEN_METHOD_RE,
    HEDGE_RE,
    HONEST_IDENTIFICATION_RE,
    IDENTITY_CLAIM_RE,
    LAWFUL_VERBS,
    LEGAL_PROCESS_RE,
    MONTHS,
    NEGATED_HIT_RE,
    NEGATION_BRIDGES,
    NEGATORS,
    PROBABLE_RE,
    PROCESS_ONLY_RE,
    PUBLIC_PLACE_RE,
    SANCTIONS_CONTEXT_RE,
    SANCTIONS_NEGATABLE_RE,
    SANCTIONS_QUALIFIER_RE,
    SENTENCE_STARTERS,
    SET_ASIDE_WORDING_RE,
    SURVEIL_RE,
    UPGRADE_RE,
)

_TAG_RE = re.compile(r"\[\s*[A-Za-z]\d+(?:\s*,\s*[A-Za-z]\d+)*\s*\]")
_URL_RE = re.compile(r"(?i)(?<![\w])(?:https?://|www\.)[^\s<>\"')\]]++")
_EMAIL_RE = re.compile(r"(?<![\w.+\-])[\w.+\-]++@[\w\-]++(?:\.[\w\-]++)+")
_RCPT_RE = re.compile(r"(?i)(?<!\w)rcpt_\w++")
_HASH_RE = re.compile(r"(?<!\w)[0-9A-Fa-f]{6,64}(?!\w)")
_DOMAIN_RE = re.compile(r"(?<![\w\-.])[\w\-]++(?:\.[\w\-]++)+(?![\w\-])")
_CHUNK_RE = re.compile(r"[\w$€£¥%][\w.,:/\-%$€£¥]*+")
_WORD_RE = re.compile(r"[^\W\d_][\w'’\-]*+", re.UNICODE)
_DATE_TOKEN_RE = re.compile(r"(?<![\w\-])\d{4}(?:-\d{2}(?:-\d{2})?)?(?![\w\-])")
_ISO_DATE_RE = re.compile(r"(?<!\d)(\d{4})-(\d{2})(?:-(\d{2}))?(?!\d)")
_MONTH_RE = re.compile(r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\b")
_MAY_AS_DATE_RE = re.compile(r"\bMay\s+\d|\d\s+May\b")
_FIRST_WORD_RE = re.compile(r"[A-Za-z][A-Za-z\-]*")

#: Violation codes raised here; the orchestrator wraps them with the sentence number.
INVENTED = "invented"
FORBIDDEN = "forbidden_method"
ACCUSATION = "accusation"
CLEARANCE = "clearance"
LABEL = "label_upgrade"
TIMELINE = "timeline"
NEXT_STEP = "next_step"


def fold(word: str) -> str:
    """Casefolded, accent-stripped, apostrophe-normalised form used to compare tokens with the evidence."""
    decomposed = unicodedata.normalize("NFKD", word.replace("’", "'"))
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()


def screen_text(text: str) -> str:
    """NFKC-normalised, format characters dropped, every Unicode digit turned into its ASCII digit."""
    normalised = unicodedata.normalize("NFKC", text)
    out = []
    for ch in normalised:
        category = unicodedata.category(ch)
        if category == "Cf":
            continue
        out.append(str(unicodedata.digit(ch)) if category == "Nd" and not ch.isascii() else ch)
    return "".join(out)


def _tokens(text: str) -> Set[str]:
    found: Set[str] = set()
    for word in _WORD_RE.findall(text):
        folded = fold(word).removesuffix("'s")
        found.add(folded)
        found.update(part for part in re.split(r"[\-'_]", folded) if part)
    return found


def _number_tokens(text: str) -> Set[str]:
    found: Set[str] = set()
    for chunk in _CHUNK_RE.findall(text):
        token = chunk.strip(".,:;/-").lower()
        if not any(ch.isdigit() for ch in token):
            continue
        found.add(token)
        if token.endswith("%"):
            found.add(token[:-1])
        iso = _ISO_DATE_RE.fullmatch(token)
        if iso:
            year, month = iso.group(1), iso.group(2)
            found.update({year, f"{year}-{month}"})
    return found


@dataclass(frozen=True)
class EvidenceIndex:
    """The evidence as the checks read it, built once per validation."""

    raw: str
    lower: str
    tokens: FrozenSet[str]
    numbers: FrozenSet[str]
    hex_runs: FrozenSet[str]
    months: FrozenSet[str]
    known_ids: FrozenSet[str]
    labels: Mapping[str, str]
    lines: Mapping[str, str]


def build_index(evidence: NarrativeEvidence) -> EvidenceIndex:
    text = screen_text(evidence.text)
    months = {MONTHS[int(m.group(2)) - 1] for m in _ISO_DATE_RE.finditer(text) if 1 <= int(m.group(2)) <= 12}
    return EvidenceIndex(
        raw=text,
        lower=text.lower(),
        tokens=frozenset(_tokens(text) | {fold(w) for w in evidence.extra_words}),
        numbers=frozenset(_number_tokens(text)),
        hex_runs=frozenset(m.group(0).lower() for m in _HASH_RE.finditer(text)),
        months=frozenset(months),
        known_ids=evidence.known_ids,
        labels=dict(evidence.finding_labels),
        lines={key: value.lower() for key, value in evidence.lines.items()},
    )


# --------------------------------------------------------------------------------------- negation


def negated(text: str, start: int) -> bool:
    """True when a negator sits directly before ``start`` (optionally through one bridge such as "been")."""
    words = re.findall(r"[a-z']+", text[max(0, start - 60):start].lower())[-2:]
    if not words:
        return False
    if words[-1] in NEGATORS:
        return True
    return len(words) == 2 and words[-1] in NEGATION_BRIDGES and words[0] in NEGATORS


def _first_unnegated(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    for match in pattern.finditer(text):
        if not negated(text, match.start()):
            return match.group(0)
    return None


# --------------------------------------------------------------------------------------- invented specifics


def _strip(pattern: "re.Pattern[str]", text: str) -> "tuple[List[str], str]":
    return [m.group(0) for m in pattern.finditer(text)], pattern.sub(" ", text)


def _is_domain(candidate: str) -> bool:
    last = candidate.rsplit(".", 1)[-1]
    return 2 <= len(last) <= 24 and (last.isalpha() or last.startswith("xn--"))


def _unknown_names(text: str, idx: EvidenceIndex) -> List[str]:
    """Capitalised words that are not in the evidence nor allow-listed (the first word may be a starter)."""
    unknown: List[str] = []
    for position, match in enumerate(_WORD_RE.finditer(text)):
        word = match.group(0)
        core = word.rstrip("'’-")
        core = core[:-2] if core.lower().endswith(("'s", "’s")) else core
        if len(core) < 2 or not core[0].isupper():
            continue
        folded = fold(core)
        parts = [p for p in re.split(r"[\-']", folded) if p]
        known = folded in ALLOWED_WORDS or folded in MONTHS or folded in idx.tokens or bool(parts and all(p in idx.tokens for p in parts))
        if not known and position == 0 and folded in SENTENCE_STARTERS:
            known = True
        if not known:
            unknown.append(core)
    return unknown


def _non_latin_words(text: str, idx: EvidenceIndex) -> List[str]:
    bad: List[str] = []
    for word in _WORD_RE.findall(text):
        scripts = {unicodedata.name(ch, "").split(" ")[0] for ch in word if ch.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            bad.append(word)  # a homoglyph trick: Latin mixed with look-alike letters
        elif scripts - {"LATIN", ""} and word not in idx.raw:
            bad.append(word)
    return bad


def _months(text: str, idx: EvidenceIndex) -> List[str]:
    bad = []
    for match in _MONTH_RE.finditer(text):
        month = match.group(1)
        if month == "May" and not _MAY_AS_DATE_RE.search(text[max(0, match.start() - 4):match.end() + 4]):
            continue  # the modal verb
        if month.lower() not in idx.months:
            bad.append(month)
    return bad


def invented_specifics(sentence: str, idx: EvidenceIndex) -> List[str]:
    """Specifics in ``sentence`` that are not in the evidence (each a short quote, for the log only)."""
    bad: List[str] = []
    text = _TAG_RE.sub(" ", sentence)
    urls, text = _strip(_URL_RE, text)
    bad += [u for u in urls if u.rstrip(".,;:!?").rstrip("/").lower() not in idx.lower]
    emails, text = _strip(_EMAIL_RE, text)
    bad += [e for e in emails if e.lower() not in idx.lower]
    rcpts, text = _strip(_RCPT_RE, text)
    bad += [r for r in rcpts if r.lower() not in idx.lower]
    hashes, text = _strip(_HASH_RE, text)
    for candidate in hashes:
        has_digit, has_letter = any(c.isdigit() for c in candidate), any(c.isalpha() for c in candidate)
        if not has_letter:
            text += f" {candidate}"  # a plain number: the number rule below decides
        elif (has_digit or len(candidate) >= 8) and not any(run.startswith(candidate.lower()) for run in idx.hex_runs):
            bad.append(candidate)
    domains, text = _strip(_DOMAIN_RE, text)
    bad += [d for d in domains if _is_domain(d) and d.lower() not in idx.lower]
    text += " " + " ".join(d for d in domains if not _is_domain(d))
    bad += _non_latin_words(text, idx) + _months(text, idx)
    for chunk in _CHUNK_RE.findall(text):
        token = chunk.strip(".,:;/-").lower()
        if (any(ch.isdigit() for ch in token) and token not in idx.numbers and token not in ALLOWED_NUMBER_TOKENS
                and chunk.strip(".,:;/-") not in idx.known_ids):
            bad.append(token)
    bad += _unknown_names(text, idx)
    return bad


# --------------------------------------------------------------------------------------- language screens


def forbidden_method(sentence: str) -> Optional[str]:
    """A forbidden or deceptive method named in ``sentence`` (negated mentions count too: documented)."""
    match = FORBIDDEN_METHOD_RE.search(sentence)
    if match:
        return match.group(0)
    if PROCESS_ONLY_RE.search(sentence) and not LEGAL_PROCESS_RE.search(sentence):
        return "records that need legal process"
    if SURVEIL_RE.search(sentence) and not PUBLIC_PLACE_RE.search(sentence):
        return "surveillance without public-place wording"
    return None


def accusation(sentence: str, ids: Sequence[str], idx: EvidenceIndex) -> Optional[str]:
    """An accusation word that the evidence for every cited id does not itself contain."""
    for match in ACCUSATION_RE.finditer(sentence):
        word = match.group(0).lower()
        if not ids or not all(word in idx.lines.get(item_id, "") for item_id in ids):
            return word
    return None


def clearance(sentence: str, ids: Sequence[str]) -> Optional[str]:
    """Clearance, risk level, compliance or safety wording; absence-of-hit wording needs a qualifier."""
    match = CLEARANCE_ALWAYS_RE.search(sentence)
    if match:
        return match.group(0)
    word = _first_unnegated(CLEARANCE_NEGATABLE_RE, sentence)
    if word:
        return word
    if SANCTIONS_CONTEXT_RE.search(sentence) or any(i[:1] in ("S", "W") for i in ids):
        word = _first_unnegated(SANCTIONS_NEGATABLE_RE, sentence)
        if word:
            return word
        hit = NEGATED_HIT_RE.search(sentence)
        if hit and not SANCTIONS_QUALIFIER_RE.search(sentence):
            return hit.group(0)
    return None


def label_violation(sentence: str, ids: Sequence[str], idx: EvidenceIndex, hedge_required: bool) -> Optional[str]:
    """The reason ``sentence`` says more than the labels of the cited ids allow, or ``None``."""
    labels = [idx.labels.get(i) for i in ids]
    all_confirmed = bool(labels) and all(label == "confirmed" for label in labels)
    all_probable_up = bool(labels) and all(label in ("probable", "confirmed") for label in labels)
    for match in UPGRADE_RE.finditer(sentence):
        word = match.group(0)
        if re.search(r"doubt|question", word, re.IGNORECASE) or not negated(sentence, match.start()):
            if not all_confirmed:
                return word
    probable = _first_unnegated(PROBABLE_RE, sentence)
    if probable and not all_probable_up:
        return probable
    if any(i[:1] == "W" for i in ids):
        claim = _first_unnegated(IDENTITY_CLAIM_RE, sentence)
        if claim:
            return claim
        if not SET_ASIDE_WORDING_RE.search(sentence):
            return "a set-aside match without set-aside wording"
    if hedge_required and any(label == "lead" for label in labels) and not HEDGE_RE.search(sentence):
        return "a lead stated without a hedge"
    return None


# --------------------------------------------------------------------------------------- section structure


def has_dated_token(sentence: str, idx: EvidenceIndex) -> bool:
    """True when ``sentence`` carries an ISO date or a year that the evidence also carries."""
    return any(token.group(0) in idx.numbers for token in _DATE_TOKEN_RE.finditer(sentence))


def next_step_problem(sentence: str) -> Optional[str]:
    """``None`` for a lawful next step; else why not (verb allowlist, honest identification for contact verbs)."""
    match = _FIRST_WORD_RE.match(sentence.lstrip(" *_"))
    verb = fold(match.group(0)) if match else ""
    if verb not in LAWFUL_VERBS:
        return NEXT_STEP
    if verb in CONTACT_VERBS and not HONEST_IDENTIFICATION_RE.search(sentence):
        return FORBIDDEN
    return None
