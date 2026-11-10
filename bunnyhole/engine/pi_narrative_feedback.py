"""Fixed vocabulary for the retry feedback of the AI-analysis validator.

The retry prompt names the offending word class and the first offending word, but it must never echo arbitrary model
text (that text may be an injection). So a word is echoed only when it is in :data:`FIXED_WORDS`, the validator's own
list of words it screens, or in one of the closed lexicon regexes (number words, months, seasons). Anything else, such
as an out-of-evidence capitalised word, is described by class only ("an unlisted capitalised word"). Pure data and
two pure functions.
"""

from __future__ import annotations

from typing import FrozenSet, Tuple

from bunnyhole.engine.pi_narrative_lexicon import IMPERATIVE_STARTS, MONTHS, NUMBER_WORDS_RE, SEASONS_RE

_TOPIC = (
    "sanction sanctions sanctioned sanctioning screen screens screened screening ofac sema sdn watchlist blocklist pep peps "
    "list lists listed listing hit hits match matches matched matching flag flags flagged unflagged clear cleared "
    "clearance clean safe safety risk risks risky compliant compliance concern concerns worry negative empty nothing "
    "none absent absence fine ok okay pass passed passes passing adverse priority issue issues problem problems exposure "
    "eligible approve approved acceptable proceed innocent exonerated"
)
_CERTAINTY = (
    "confirm confirms confirmed confirmation verify verifies verified verification establish established prove proved "
    "proven proves definite definitely certain certainly undoubted undoubtedly authentic conclusive definitive "
    "unquestionably indisputable surely valid validated solid settled genuine indeed obviously clearly factual belong "
    "belongs belonged belonging"
)
_ACCUSATION = (
    "fraud fraudulent criminal crime crimes launder laundering illegal unlawful corrupt corruption bribe bribery scam "
    "terror terrorist guilty dangerous shady suspicious suspect suspected evade evasion sham embezzle theft steal stole "
    "illicit wrongdoing misconduct dishonest malicious extortion blackmail mafia crook felon convicted shell"
)
_ADVICE = (
    "should must ought recommend recommends advise advice suggest suggests suggested suggestion pretext hack hacking "
    "bypass impersonate phishing spoof credentials password login stalk surveil surveillance track tracking tail covert "
    "covertly leak breach deceive deceptive unlock tap trash insider"
)
_IDENTITY = (
    "owns owner owners owning owned beneficial control controls controlled same identical corroborate corroborated "
    "confidence probable probably likely unlikely shareholder shareholders runs ran manages managed operates operated "
    "husband wife spouse married brother sister son daughter mother father cousin family"
)

#: Words the validator screens: the only model-derived words a retry prompt may echo.
FIXED_WORDS: FrozenSet[str] = frozenset(
    f"{_TOPIC} {_CERTAINTY} {_ACCUSATION} {_ADVICE} {_IDENTITY}".split()
) | IMPERATIVE_STARTS


def echoable_word(word: str) -> str:
    """``word`` lower-cased when it is in the fixed vocabulary, else an empty string (never arbitrary text)."""
    lowered = " ".join(word.lower().split())
    if lowered in FIXED_WORDS or lowered in MONTHS:
        return lowered
    if NUMBER_WORDS_RE.fullmatch(lowered) or SEASONS_RE.fullmatch(lowered):
        return lowered
    return ""


def invented_class(item: str) -> Tuple[str, str]:
    """(class text, echoable word) of one out-of-evidence specific. The class never quotes the item."""
    word = echoable_word(item)
    if word in MONTHS:
        return "a month with no date in the evidence", word
    if word:
        return "a number word or relative-time word", word
    if any(ch.isdigit() for ch in item):
        return "a number or code that is not in the evidence", ""
    if item[:1].isupper():
        return "an unlisted capitalised word", ""
    return "an address, URL, handle or other specific that is not in the evidence", ""
