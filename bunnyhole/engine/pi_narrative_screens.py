"""Text views and the identity, ownership and shape screens of the AI-analysis validator. Pure, linear time.

Three jobs, all on one already length-capped, already character-checked bullet text:

- **Views.** A word screen looks at the text as written, at an accent-folded copy (``sánctions`` is ``sanctions``)
  and at a squashed copy where punctuation that splits a word is removed (``sanc/tions``, ``con-firmed``,
  ``s.a.n.c.t.i.o.n.s``). Ordinary hyphenated words such as ``cross-border`` are not screened words once squashed, so
  they pass. Whitespace between two multi-letter fragments (``sanc tions``) is not joined: that is a paraphrase
  class the validator does not catch.
- **Identity and ownership.** The code owns every relation, so a bullet may not assert one in its own words:
  ``owns``, ``owner``, ``controls``, ``same``, ``corroborated``, ``probable``, ``likely``, ``confidence``,
  possessive identity (``is Jane's``) and copular identity (``is Jane Q Example``) are rejected. Other relation
  words (family, ``owned by``) and a cited-but-misread claim are not caught: documented limits.
- **Shape.** Three distinct words of three letters or more, not mostly punctuation, no repeated id in one tag.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import FrozenSet, Iterable, Optional, Sequence, Tuple

# Letters with no Unicode decomposition that still look like a plain letter (folded for the screens only).
_TRANSLIT = str.maketrans(
    {"ø": "o", "đ": "d", "ð": "d", "ħ": "h", "ł": "l", "ŧ": "t", "ƀ": "b", "ƈ": "c", "ƒ": "f", "ƙ": "k", "ƚ": "l",
     "ƥ": "p", "ƭ": "t", "ƴ": "y", "ƶ": "z", "ǥ": "g", "ȼ": "c", "ɇ": "e", "ɍ": "r", "ɏ": "y", "ȥ": "z",
     "æ": "ae", "œ": "oe", "þ": "th"}
)
_SINGLE_LETTER_RUN_RE = re.compile(r"(?<![^\W_])(?:[^\W\d_][\s.\-/_']+){2,}[^\W\d_](?![^\W_])")
_SPLIT_RE = re.compile(r"(?<=[^\W_])[.\-/_']+(?=[^\W_])")
_SEPARATORS_RE = re.compile(r"[\s.\-/_']+")


def fold(word: str) -> str:
    """Casefolded, accent-stripped form: used to compare a token with the evidence and to run the word screens."""
    decomposed = unicodedata.normalize("NFKD", word)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return stripped.casefold().translate(_TRANSLIT)


def squash(text: str) -> str:
    """``text`` with the punctuation that splits words removed: letter-by-letter runs and dot, hyphen, slash,
    underscore or apostrophe between two word characters are joined."""
    joined = _SINGLE_LETTER_RUN_RE.sub(lambda match: _SEPARATORS_RE.sub("", match.group(0)), text)
    return _SPLIT_RE.sub("", joined)


@lru_cache(maxsize=256)
def views(text: str) -> Tuple[str, ...]:
    """The distinct views of ``text`` a word screen runs on: as written, folded, and folded then squashed."""
    folded = fold(text)
    return tuple(dict.fromkeys((text, folded, squash(folded))))


def first_match(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    """The first match of ``pattern`` in any view of ``text`` (matched in the view where it was found)."""
    for view in views(text):
        match = pattern.search(view)
        if match:
            return match.group(0)
    return None


# --------------------------------------------------------------------------------------- identity and ownership

#: Assertions about who or what something is, who owns, runs or controls it, and how sure the claim is. The code owns
#: relations and the label owns strength, so the model states none of them in its own words.
IDENTITY_RE = re.compile(
    r"\bowns\b|\bowners?\b|\bcontrol(?:s|led|ling)?\b"
    r"|\bsame\b|\bidentical\b|\bcorroborat\w*|\bconfidence\b|\bhighly\s+likely\b|\bprobabl[ey]\b"
    r"|\blikel(?:y|ihood)\b",
    re.IGNORECASE,
)
_POSSESSIVE_IDENTITY_RE = re.compile(r"\b(?:is|are|was|were)\s+(?:the\s+)?[A-Z]\w*(?:\s+[A-Z]\w*)*'s\b")


def _eligible_name(name: str) -> bool:
    """A person or organisation style name (several words, or any capital letter), not a bare lowercase handle."""
    return len(name.split()) > 1 or any(ch.isupper() for ch in name)


def _copular_pattern(names: Iterable[str]) -> Optional["re.Pattern[str]"]:
    folded = sorted({fold(n).strip() for n in names if n.strip() and _eligible_name(n)}, key=len, reverse=True)
    if not folded:
        return None
    alternatives = "|".join(re.escape(n) for n in folded)
    return re.compile(
        r"\b(?:is|was)\s+(?:(?:actually|also|really|in\s+fact)\s+)?(?:the\s+)?(?:" + alternatives + r")(?!\w)"
    )


def identity_or_ownership(text: str, names: Iterable[str]) -> Optional[str]:
    """An unhedged identity, ownership or probability assertion, or ``None``."""
    word = first_match(IDENTITY_RE, text)
    if word:
        return word
    match = _POSSESSIVE_IDENTITY_RE.search(text)
    if match:
        return match.group(0)
    folded = fold(text)
    copular = _copular_pattern(names)
    if copular is not None:
        match = copular.search(folded)
        if match:
            return match.group(0)
    return None


# --------------------------------------------------------------------------------------- shape

MIN_DISTINCT_WORDS = 3
MIN_WORD_CHARS = 3
MAX_PUNCTUATION_SHARE = 0.5
_ALPHA_WORD_RE = re.compile(r"[^\W\d_]+")


def content_free(text: str) -> bool:
    """Too few distinct words of three letters or more, or more than half of the characters are not alphanumeric."""
    words = {fold(w) for w in _ALPHA_WORD_RE.findall(text) if len(w) >= MIN_WORD_CHARS}
    if len(words) < MIN_DISTINCT_WORDS:
        return True
    visible = [ch for ch in text if not ch.isspace()]
    return not visible or sum(1 for ch in visible if not ch.isalnum()) / len(visible) > MAX_PUNCTUATION_SHARE


def duplicate_ids(ids: Sequence[str]) -> FrozenSet[str]:
    return frozenset(i for i in ids if ids.count(i) > 1)
