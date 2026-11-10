"""Per-bullet checks of the AI-analysis validator. Pure functions over one already length-capped bullet text.

Three families. The character allowlist decides what may be written at all. The evidence rules decide which specifics
(digits, number words, months, hex strings, addresses, handles, capitalised words) may appear: only those that are in
the evidence the model was shown. The word screens reject topics that belong to code-built sections (sanctions,
screening, absence), certainty and label words, and accusation words. Allowlists decide first; blocklists are the
second layer. Linear time: every regex is possessive or bounded.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import FrozenSet, List, Mapping, Optional, Set

from bunnyhole.engine.pi_narrative_input import NarrativeEvidence
from bunnyhole.engine.pi_narrative_lexicon import (
    ACCUSATION_RE,
    ADVICE_OR_METHOD_RE,
    ALLOWED_WORDS,
    CERTAINTY_RE,
    EXCLUDED_TOPIC_RE,
    FUNCTION_WORDS,
    IMPERATIVE_STARTS,
    MIN_FUNCTION_WORD_SHARE,
    MIN_WORDS_FOR_LANGUAGE_GATE,
    MONTHS,
    NUMBER_WORDS_RE,
    OBFUSCATION_RE,
    SEASONS_RE,
)

#: ASCII punctuation a bullet may contain. Square brackets are only legal inside the leading citation tag.
ALLOWED_PUNCTUATION = frozenset(".,;:'\"()-/&%@_[]")
#: Typographic characters turned into their ASCII form before the character check (and in the written text).
_TYPOGRAPHY = {"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", " ": " "}

_URL_RE = re.compile(r"(?i)(?<![\w])(?:https?://|www\.)[^\s<>\"')\]]++")
_EMAIL_RE = re.compile(r"(?<![\w.+\-])[\w.+\-]++@[\w\-]++(?:\.[\w\-]++)+")
_HANDLE_RE = re.compile(r"(?<![\w@])@[\w.]{1,40}")
_RCPT_RE = re.compile(r"(?i)(?<!\w)rcpt_\w++")
_HASH_RE = re.compile(r"(?<!\w)[0-9A-Fa-f]{6,64}(?!\w)")
_DOMAIN_RE = re.compile(r"(?<![\w\-.])[\w\-]++(?:\.[\w\-]++)+(?![\w\-])")
_CHUNK_RE = re.compile(r"[\w%][\w.,:/\-%]*+")
_WORD_RE = re.compile(r"[^\W_]+(?:'[^\W_]+)*", re.UNICODE)
_ISO_DATE_RE = re.compile(r"(?<!\d)(\d{4})-(\d{2})(?:-(\d{2}))?(?!\d)")
_MONTH_RE = re.compile(r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\b")
_MAY_AS_DATE_RE = re.compile(r"\bMay\s+\d|\d\s+May\b")
_SCHEME_RE = re.compile(r"[A-Za-z]:(?=\S)")
_IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?![\w:])")


def normalise_typography(text: str) -> str:
    """NFC-normalised text with typographic quotes, dashes and the no-break space turned into ASCII."""
    return "".join(_TYPOGRAPHY.get(ch, ch) for ch in unicodedata.normalize("NFC", text))


def fold(word: str) -> str:
    """Casefolded, accent-stripped form used to compare a token with the evidence."""
    decomposed = unicodedata.normalize("NFKD", word)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()


def disallowed_character(text: str) -> Optional[str]:
    """The first character outside the allowlist, or ``None``.

    Allowed: ASCII letters and accented Latin letters, ASCII digits, the ASCII space, the line feed, and
    :data:`ALLOWED_PUNCTUATION`. Everything else is refused: invisible, bidi and format characters, other scripts and
    look-alike letters, fullwidth forms, backticks, ``#``, ``>``, ``*``, ``|``, ``<``, ``~``, tabs, emoji.
    """
    for ch in text:
        if ch in (" ", "\n") or ch in ALLOWED_PUNCTUATION:
            continue
        if ch.isascii():
            if ch.isalnum():
                continue
        elif unicodedata.category(ch) == "Ll" or unicodedata.category(ch) == "Lu":
            if unicodedata.name(ch, "").startswith("LATIN"):
                continue
        return ch
    return None


def _words(text: str) -> List[str]:
    return _WORD_RE.findall(text)


def _word_tokens(text: str) -> Set[str]:
    found: Set[str] = set()
    for word in _words(text):
        folded = fold(word)
        found.add(folded)
        if folded.endswith("'s"):
            found.add(folded[:-2])
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
            found.update({iso.group(1), f"{iso.group(1)}-{iso.group(2)}"})
    return found


@dataclass(frozen=True)
class EvidenceIndex:
    """The evidence as the checks read it, built once per validation."""

    lower: str
    tokens: FrozenSet[str]
    numbers: FrozenSet[str]
    hex_runs: FrozenSet[str]
    months: FrozenSet[str]
    run_text: str
    model_ids: FrozenSet[str]
    lines: Mapping[str, str]


def build_index(evidence: NarrativeEvidence) -> EvidenceIndex:
    text = evidence.text
    months = {MONTHS[int(m.group(2)) - 1] for m in _ISO_DATE_RE.finditer(text) if 1 <= int(m.group(2)) <= 12}
    extra = {fold(w) for w in evidence.extra_words}
    run_words = [fold(w).removesuffix("'s") for w in _words(text)]
    return EvidenceIndex(
        lower=text.lower(),
        tokens=frozenset(_word_tokens(text) | extra),
        numbers=frozenset(_number_tokens(text)),
        hex_runs=frozenset(m.group(0).lower() for m in _HASH_RE.finditer(text)),
        months=frozenset(months),
        run_text=" " + " ".join(run_words) + " ",
        model_ids=evidence.model_ids,
        lines={key: value.lower() for key, value in evidence.lines.items()},
    )


# --------------------------------------------------------------------------------------- evidence rules


def _strip(pattern: "re.Pattern[str]", text: str) -> "tuple[List[str], str]":
    return [m.group(0) for m in pattern.finditer(text)], pattern.sub(" ", text)


def _is_domain(candidate: str) -> bool:
    last = candidate.rsplit(".", 1)[-1]
    return 2 <= len(last) <= 24 and (last.isalpha() or last.startswith("xn--"))


def _ipv6_candidates(text: str) -> List[str]:
    """Colon-hex runs such as ``::1`` or ``fe80::1`` (an IPv6 address, with or without a digit in its groups)."""
    return [m.group(0) for m in _IPV6_RE.finditer(text) if "::" in m.group(0) or m.group(0).count(":") >= 3]


def _unknown_capitalised(text: str, idx: EvidenceIndex) -> List[str]:
    """Capitalised words that the evidence does not contain, and runs of two or more that are not contiguous in it.

    Every capitalised word counts, including the first word of a sentence: only closed-class function words and a short
    list of generic institution words are allowed without support. Allowed words split a run, so "Acme Ltd" is checked
    as "Acme". A run of two or more evidence words ("Jane Q Example") must appear in the evidence in that order.
    """
    unknown: List[str] = []
    run: List[str] = []
    previous_end = -1

    def flush() -> None:
        if len(run) >= 2 and f" {' '.join(run)} " not in idx.run_text:
            unknown.append(" ".join(run))
        run.clear()

    for match in _WORD_RE.finditer(text):
        word = match.group(0)
        if not word[0].isalpha() or not word[0].isupper():
            flush()
            previous_end = match.end()
            continue
        folded = fold(word)
        core = folded[:-2] if folded.endswith("'s") else folded
        if core in FUNCTION_WORDS or core in ALLOWED_WORDS or core in MONTHS:
            flush()
        elif core not in idx.tokens:
            flush()
            unknown.append(word)
        else:
            if run and text[previous_end:match.start()].strip():
                flush()
            run.append(core)
        previous_end = match.end()
    flush()
    return unknown


def _months(text: str, idx: EvidenceIndex) -> List[str]:
    bad = []
    for match in _MONTH_RE.finditer(text):
        month = match.group(1)
        if month == "May" and not _MAY_AS_DATE_RE.search(text[max(0, match.start() - 4):match.end() + 4]):
            continue  # the modal verb
        if month.lower() not in idx.months:
            bad.append(month)
    return bad


def invented_specifics(text: str, idx: EvidenceIndex) -> List[str]:
    """Specifics in the bullet text that are not in the evidence (each a short quote, for the log only)."""
    bad: List[str] = []
    urls, text = _strip(_URL_RE, text)
    bad += [u for u in urls if u.rstrip(".,;:").rstrip("/").lower() not in idx.lower]
    emails, text = _strip(_EMAIL_RE, text)
    bad += [e for e in emails if e.lower() not in idx.lower]
    handles, text = _strip(_HANDLE_RE, text)
    bad += [h for h in handles if h.rstrip(".").lower() not in idx.lower]
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
    bad += [a for a in _ipv6_candidates(text) if a.lower() not in idx.lower]
    for chunk in _CHUNK_RE.findall(text):
        token = chunk.strip(".,:;/-").lower()
        if any(ch.isdigit() for ch in token) and token not in idx.numbers and chunk.strip(".,:;/-") not in idx.model_ids:
            bad.append(token)
    bad += [m.group(0) for m in NUMBER_WORDS_RE.finditer(text) if fold(m.group(0)) not in idx.tokens]
    bad += _months(text, idx)
    bad += [m.group(0) for m in SEASONS_RE.finditer(text)]
    bad += [m.group(0) for m in _SCHEME_RE.finditer(text)]  # "javascript:alert", "mailto:x": a scheme, not prose
    bad += _unknown_capitalised(text, idx)
    return bad


# --------------------------------------------------------------------------------------- word screens


def obfuscation(text: str) -> Optional[str]:
    match = OBFUSCATION_RE.search(text)
    return match.group(0) if match else None


def excluded_topic(text: str) -> Optional[str]:
    """A word of a topic that belongs to the code-built sections (sanctions, screening, absence, risk)."""
    match = EXCLUDED_TOPIC_RE.search(text)
    return match.group(0) if match else None


def certainty_word(text: str) -> Optional[str]:
    """A label or certainty word (the code renders the label next to the tag; the model never states one)."""
    match = CERTAINTY_RE.search(text)
    return match.group(0) if match else None


def advice_or_method(text: str) -> Optional[str]:
    """Advice, a method, or an imperative: the code builds every next step, so a bullet may contain none."""
    match = ADVICE_OR_METHOD_RE.search(text)
    if match:
        return match.group(0)
    first = _words(text)[:1]
    return first[0] if first and fold(first[0]) in IMPERATIVE_STARTS else None


def too_short(text: str) -> bool:
    """A bullet needs at least three alphabetic words (punctuation-only and one-word bullets are not statements)."""
    return sum(1 for w in _words(text) if w[0].isalpha()) < 3


def accusation(text: str, ids: List[str], idx: EvidenceIndex) -> Optional[str]:
    """An accusation word that the evidence for every cited id does not itself contain."""
    for match in ACCUSATION_RE.finditer(text):
        word = match.group(0).lower()
        if not ids or not all(word in idx.lines.get(item_id, "") for item_id in ids):
            return word
    return None


def language_ok(text: str, idx: EvidenceIndex) -> bool:
    """Cheap English gate: of the words the evidence does not contain, a quarter must be English function words."""
    words = [fold(w) for w in _words(text) if w[0].isalpha()]
    outside = [w for w in words if w in FUNCTION_WORDS or w not in idx.tokens]
    if len(outside) < MIN_WORDS_FOR_LANGUAGE_GATE:
        return True
    return sum(1 for w in outside if w in FUNCTION_WORDS) / len(outside) >= MIN_FUNCTION_WORD_SHARE
