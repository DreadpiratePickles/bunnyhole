"""PI purpose gates: eligibility, motive and pursuit screens, the skeleton pass and the matter reference check.

Split out of ``pi.py`` unchanged. The vocabulary lives in ``pi_gate_terms``; the base types in ``pi_types``.
"""

from __future__ import annotations

import html
import re
import unicodedata
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from bunnyhole.engine.pi_gate_terms import (
    _EX_NOT_PARTNER,
    _FAMILY_LEGAL_SENSE,
    _LOCATE_WORDS,
    _MY_PARTNER,
    _NON_HIRING_APPLICANT,
    _NON_HIRING_CANDIDATE,
    _PARTNER_WORDS,
    _PURSUIT_PATTERN_STRINGS,
    FORBIDDEN_ELIGIBILITY_PATTERNS,
    FORBIDDEN_ELIGIBILITY_TERMS,
    MIN_PURPOSE_CHARS,
    MOTIVE_PATTERNS,
    MOTIVE_RED_FLAGS,
    ONBOARDING_CUE,
    ONBOARDING_PERSON_ROLE,
    PURSUIT_EVASION_FLAGS,
)
from bunnyhole.engine.pi_types import (
    RELATIONSHIP_TERM_CATEGORIES,
    CaseType,
    PIEligibilityError,
    PIPurposeError,
    PurposeCategory,
    coerce_purpose_category,
)

#: Hard cap on the text one screen call will read. Above it the call REFUSES (fail closed) instead of skipping part
#: of the text or spending unbounded time: the screens cost a few microseconds per character, so this keeps every
#: call well under a second even on adversarial input. Per-field text beyond it should be trimmed or split.
MAX_SCREEN_CHARS = 150_000

_PERSON_MOTIVE_CASE_TYPES = frozenset({CaseType.LOCATE, CaseType.BACKGROUND, CaseType.MISSING_PERSON})

_ZERO_WIDTH_OR_FORMAT = "Cf"
_APOSTROPHES = "‘’ʼʹ′`´"


def _normalize_text(text: str) -> str:
    """Normalise text so phrase matching survives trivial obfuscation.

    NFKC (folds full-width and compatibility forms), drop format characters (category ``Cf``: zero-width space,
    joiners, soft hyphen), straighten apostrophes, lowercase, turn every other punctuation mark (hyphens of any
    width, underscores, slashes, periods, commas...) into a space and collapse whitespace. Vocabulary is passed
    through the same function, so a hyphenated entry matches any spelling.
    """
    folded = unicodedata.normalize("NFKC", text or "")
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != _ZERO_WIDTH_OR_FORMAT)
    for apostrophe in _APOSTROPHES:
        folded = folded.replace(apostrophe, "'")
    folded = folded.lower().replace("_", " ")
    folded = re.sub(r"[^\w']+", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


def _phrase_regex(phrase: str, *, plural: bool = False) -> "re.Pattern[str]":
    """Whole-phrase matcher over normalised text; ``plural`` also accepts a trailing ``s`` ("job seekers")."""
    return re.compile(r"(?<!\w)" + re.escape(_normalize_text(phrase)) + (r"s?" if plural else r"") + r"(?!\w)")


_ELIGIBILITY_RES: tuple["re.Pattern[str]", ...] = tuple(
    [_phrase_regex(term, plural=True) for term in FORBIDDEN_ELIGIBILITY_TERMS]
    + [re.compile(pattern) for pattern in FORBIDDEN_ELIGIBILITY_PATTERNS]
)
_NON_HIRING_CANDIDATE_RE = re.compile(_NON_HIRING_CANDIDATE)
_NON_HIRING_APPLICANT_RE = re.compile(_NON_HIRING_APPLICANT)
_ONBOARDING_CUE_RE = re.compile(ONBOARDING_CUE)
_ONBOARDING_ROLE_RE = re.compile(ONBOARDING_PERSON_ROLE)
# "stalk" also covers stalker/stalking, so the red-flag literals match as prefixes of a word only for that one.
_MOTIVE_LITERAL_RES: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (
        flag,
        re.compile(r"(?<!\w)" + re.escape(_normalize_text(flag)) + (r"" if flag == "stalk" else r"(?!\w)")),
    )
    for flag in MOTIVE_RED_FLAGS
)
_MOTIVE_PATTERN_RES: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (label, re.compile(pattern)) for label, pattern in MOTIVE_PATTERNS
)
_MY_PARTNER_RE = re.compile(_MY_PARTNER)
_LOCATE_WORDS_RE = re.compile(_LOCATE_WORDS)
_FAMILY_LEGAL_SENSE_RE = re.compile(_FAMILY_LEGAL_SENSE)
# "the girl from my gym": an acquaintance the client met socially, only a red flag next to locate-style words.
_ACQUAINTANCE_RE = re.compile(
    r"\b(?:girl|woman|guy|man|lady|boy|stranger)\s+(?:from|at|in|on)\s+my\s+"
    r"(?:gym|work|class|building|bar|church|school|neighbou?rhood|street|office|train|bus|app|yoga|club|campus)\b"
)


def require_screenable(text: str) -> None:
    """Raise :class:`PIPurposeError` when ``text`` exceeds :data:`MAX_SCREEN_CHARS` (never skip text silently)."""
    if len(text or "") > MAX_SCREEN_CHARS:
        raise PIPurposeError(
            f"This text is too long to screen safely ({len(text):,} characters; the limit is {MAX_SCREEN_CHARS:,}). "
            "Bunnyhole screens every free-text field and will not skip any part of it: shorten the text or split it "
            "into separate runs."
        )


class _Prepared:
    """One text with its normalised form and skeleton hits, each computed at most once and only when first needed."""

    __slots__ = ("text", "_lowered", "_hits")

    def __init__(self, text: str) -> None:
        self.text = text or ""
        self._lowered: Optional[str] = None
        self._hits: Optional[Dict[str, str]] = None

    @property
    def lowered(self) -> str:
        if self._lowered is None:
            self._lowered = _normalize_text(self.text)
        return self._lowered

    @property
    def hits(self) -> Dict[str, str]:
        if self._hits is None:
            self._hits = _skeleton_hits(self.text)
        return self._hits


def validate_purpose(purpose: str, purpose_category: Optional[str] = None) -> str:
    """Return the stripped purpose, or raise :class:`PIPurposeError` if it is too thin or an eligibility use.

    This is a keyword safety net, not a guarantee: it normalises the text (case, punctuation, zero-width
    characters, full-width forms) and matches specific eligibility phrases, so a determined user can still
    phrase an eligibility purpose it does not know. A second "skeleton" pass (see :func:`_skeleton_hits`) catches
    common disguises of a few high-risk compact phrases (homoglyphs, leetspeak, spaced letters, HTML or percent
    encoding, one-character typos); it is equally a net, not a guarantee. Legal responsibility for the purpose
    stays with the user. ``purpose_category`` is the declared category (see :func:`screen_eligibility`).
    """
    clean = (purpose or "").strip()
    if len(clean) < MIN_PURPOSE_CHARS:
        raise PIPurposeError(
            f"Describe the purpose in at least {MIN_PURPOSE_CHARS} characters: what decision or legal matter "
            "this investigation serves (for example a judgment to enforce or a counterparty to vet)."
        )
    screen_eligibility(clean, purpose_category)
    return clean


def screen_eligibility(text: str, purpose_category: Optional[str] = None) -> None:
    """Raise :class:`PIEligibilityError` when ``text`` reads like an employment, tenancy, credit or insurance decision.

    The eligibility half of :func:`validate_purpose` without the length rule, so it can screen every free-text
    field of an engagement (client, hypothesis, pasted notes). ``purpose_category`` is the declared category: under
    ``regulatory_compliance_kyc`` the bare "before onboarding" cue is exempt (a know-your-customer refresh of a
    corporate client), while every employment, tenancy and credit pattern still applies. A keyword safety net, not
    a guarantee. Text over :data:`MAX_SCREEN_CHARS` is refused.
    """
    require_screenable(text)
    _check_eligibility(_Prepared(text), purpose_category)


def _is_kyc(purpose_category: Optional[str]) -> bool:
    return coerce_purpose_category(purpose_category) is PurposeCategory.REGULATORY_COMPLIANCE_KYC


def _eligibility_error(matched: str) -> PIEligibilityError:
    return PIEligibilityError(
        f"This purpose mentions '{matched}'. Decisions about employment, tenancy, credit, "
        "loans or insurance are FCRA-regulated; use an FCRA-compliant screening provider. Bunnyhole is "
        "not a consumer reporting agency and will not be used for eligibility decisions. If this is not "
        "an eligibility decision (for example fraud, litigation or counterparty work), reword the "
        "purpose to say what the matter actually is."
    )


def _check_eligibility(prepared: _Prepared, purpose_category: Optional[str]) -> None:
    lowered = _NON_HIRING_APPLICANT_RE.sub(" ", _NON_HIRING_CANDIDATE_RE.sub(" ", prepared.lowered))
    for rule in _ELIGIBILITY_RES:
        found = rule.search(lowered)
        if found:
            raise _eligibility_error(found.group(0).strip())
    if not _is_kyc(purpose_category):
        cue = _ONBOARDING_CUE_RE.search(lowered)
        if cue and _ONBOARDING_ROLE_RE.search(lowered):
            raise _eligibility_error(cue.group(0).strip())
    skeleton = prepared.hits.get(_CAT_ELIGIBILITY)
    if skeleton:
        raise PIEligibilityError(
            f"This purpose reads like '{skeleton}' (matched after folding spelling tricks). Decisions about "
            "employment, tenancy, credit, loans or insurance are FCRA-regulated; use an FCRA-compliant screening "
            "provider. Bunnyhole is not a consumer reporting agency and will not be used for eligibility decisions. "
            "If this is not an eligibility decision, reword the purpose to say what the matter actually is."
        )


def _motive_match(lowered: str) -> str:
    """The first red-flag wording found in normalised ``lowered``, or ``""``."""
    for flag, rule in _MOTIVE_LITERAL_RES:
        if rule.search(lowered):
            return flag
    family_free = _FAMILY_LEGAL_SENSE_RE.sub(" ", lowered)
    for label, rule in _MOTIVE_PATTERN_RES:
        found = rule.search(family_free if label == "family relocation" else lowered)
        if found:
            return found.group(0).strip() or label
    partner = _MY_PARTNER_RE.search(lowered)
    if partner and _LOCATE_WORDS_RE.search(lowered):
        return partner.group(0).strip()
    acquaintance = _ACQUAINTANCE_RE.search(lowered)
    if acquaintance and _LOCATE_WORDS_RE.search(lowered):
        return acquaintance.group(0).strip()
    return ""


def motive_screen(purpose: str, case_type: CaseType, subject_is_person: bool) -> None:
    """Refuse locate-style work on a private person when the stated purpose reads like pursuit of a former partner.

    A keyword safety net, not a guarantee: it matches normalised former-partner and evasion wordings (plus
    the compact-phrase skeleton pass for disguised spellings) and cannot see intent it was not told. It only
    applies to person subjects on locate, background and missing-person engagements; :func:`pursuit_screen`
    covers the remaining case types and entity subjects. Text over :data:`MAX_SCREEN_CHARS` is refused.
    """
    if not subject_is_person or case_type not in _PERSON_MOTIVE_CASE_TYPES:
        return
    require_screenable(purpose)
    _check_motive(_Prepared(purpose))


def _check_motive(prepared: _Prepared) -> None:
    matched = _motive_match(prepared.lowered)
    if not matched:
        hits = prepared.hits
        matched = hits.get(_CAT_RELATIONSHIP) or hits.get(_CAT_PURSUIT) or hits.get(_CAT_MOTIVE) or ""
    if matched:
        raise PIPurposeError(
            f"This reads like a locate or surveillance of a former partner or someone avoiding you "
            f"(matched '{matched}'). Bunnyhole will not run it. If there is a protective order or safety "
            "concern, take it to law enforcement or your counsel; they can act on it lawfully."
        )


_PURSUIT_LITERAL_RES: tuple[tuple[str, "re.Pattern[str]"], ...] = tuple(
    (flag, re.compile(r"(?<!\w)" + re.escape(_normalize_text(flag)) + r"(?!\w)")) for flag in PURSUIT_EVASION_FLAGS
)
_PURSUIT_PATTERN_RES: tuple["re.Pattern[str]", ...] = tuple(re.compile(p) for p in _PURSUIT_PATTERN_STRINGS)

# A former-partner relationship named in the purpose. For person subjects on non-locate case types this is allowed
# only with a valid matter reference (a divorce or support proceeding is a legitimate asset search).
_RELATIONSHIP_RES: tuple["re.Pattern[str]", ...] = (
    re.compile(r"\b(?:former|estranged|ex|previous|prior)\s+" + _PARTNER_WORDS + r"\b"),
    re.compile(r"\bmy\s+ex\b" + _EX_NOT_PARTNER),
    re.compile(r"\bestranged\b"),
)


def _pursuit_match(lowered: str) -> str:
    for flag, rule in _PURSUIT_LITERAL_RES:
        if rule.search(lowered):
            return flag
    for rule in _PURSUIT_PATTERN_RES:
        found = rule.search(lowered)
        if found:
            return found.group(0).strip()
    return ""


def _relationship_match(lowered: str) -> str:
    for rule in _RELATIONSHIP_RES:
        found = rule.search(lowered)
        if found:
            return found.group(0).strip()
    return ""


def _relationship_term_allowed(matter_ref: str, purpose_category: Optional[str]) -> bool:
    """May a former-partner relationship term stand on a non-locate person case?

    With a declared category (the engagement path) only ``asset_recovery`` or ``litigation_support`` qualifies, and
    only together with a valid matter reference: a reference alone no longer lifts the screen. Without a category
    (a direct call of :func:`pursuit_screen`, kept for compatibility) a valid reference is the whole test.
    """
    if not is_valid_matter_ref(matter_ref):
        return False
    if purpose_category is None:
        return True
    return coerce_purpose_category(purpose_category) in RELATIONSHIP_TERM_CATEGORIES


def pursuit_screen(
    purpose: str,
    case_type: CaseType,
    subject_is_person: bool,
    matter_ref: str = "",
    purpose_category: Optional[str] = None,
) -> None:
    """Refuse pursuit of someone avoiding the client in EVERY case type, and gate relationship terms.

    1. Pursuit and evasion wordings ("blocked me", "won't talk to me", "deleted her accounts", "where she lives",
       "current address of my ex", "changed her number", doxxing, "old flame", "where they work") are refused
       whatever the case type and whatever the declared subject type: an entity subject is self-declared and can be
       a lie. No matter reference lifts this screen.
    2. For a person subject on a non-locate case type (asset search, due diligence, fraud screen) a former-partner
       relationship term ("ex-wife", "estranged husband", "former spouse") is allowed only with a valid
       ``matter_ref`` (see :func:`is_valid_matter_ref`) and, when ``purpose_category`` is passed, only under
       ``asset_recovery`` or ``litigation_support``: a divorce or support proceeding is a legitimate asset search.
       Locate, background and missing-person engagements are handled by :func:`motive_screen`.

    A keyword safety net, not a guarantee: it matches normalised wordings (plus the compact-phrase skeleton pass for
    disguised spellings) and cannot see intent it was not told. Text over :data:`MAX_SCREEN_CHARS` is refused.
    """
    require_screenable(purpose)
    _check_pursuit(_Prepared(purpose), case_type, subject_is_person, matter_ref, purpose_category)


def _check_pursuit(
    prepared: _Prepared,
    case_type: CaseType,
    subject_is_person: bool,
    matter_ref: str,
    purpose_category: Optional[str],
) -> None:
    lowered = prepared.lowered
    pursuit = _pursuit_match(lowered) or prepared.hits.get(_CAT_PURSUIT, "")
    if pursuit:
        raise PIPurposeError(
            f"This reads like pursuit of someone who is avoiding you or a former partner (matched '{pursuit}'). "
            "Bunnyhole will not run it for any case type or subject type. If there is a protective order or "
            "safety concern, take it to law enforcement or your counsel; they can act on it lawfully."
        )
    if not subject_is_person or case_type in _PERSON_MOTIVE_CASE_TYPES:
        return
    relationship = _relationship_match(lowered) or prepared.hits.get(_CAT_RELATIONSHIP, "")
    if relationship and not _relationship_term_allowed(matter_ref, purpose_category):
        raise PIPurposeError(
            f"The purpose names a former-partner relationship (matched '{relationship}') and the subject is a "
            "private person. That is allowed only for a legal proceeding such as a divorce, support or custody "
            "matter: add --matter-ref with the real case or order number (for example '23-FC-0188') and declare "
            "--purpose-category asset_recovery or litigation_support. Otherwise take the question to counsel; "
            "Bunnyhole will not run it."
        )


# --------------------------------------------------------------------------- skeleton pass (disguised spellings)

_CAT_ELIGIBILITY = "eligibility"
_CAT_RELATIONSHIP = "relationship"
_CAT_PURSUIT = "pursuit"
_CAT_MOTIVE = "motive"

# Curated compact phrases (letters only, lowercase). A candidate must equal one of them, or, for phrases of 8+
# letters, be within one edit (insert, delete, substitute, transpose). Never short words: "shire" is not "hire".
_COMPACT_PHRASES: Dict[str, str] = {}
for _category, _phrases in (
    (
        _CAT_ELIGIBILITY,
        (
            "preemployment", "employmentscreening", "employmentbackground", "employmentcheck", "employmenteligibility",
            "tenantscreening", "tenantbackground", "rentalscreening", "rentalapplication", "rentalapplicant",
            "jobapplicant", "jobcandidate", "newhire", "prospectiveemployee", "prospectivetenant", "creditworthiness",
            "creditworthy", "creditscreening", "loanapplication", "creditapplication", "hiringdecision",
            "insuranceunderwriting", "mortgageunderwriting", "safehire", "offerletter",
        ),
    ),
    (
        _CAT_RELATIONSHIP,
        (
            "exwife", "exhusband", "exgirlfriend", "exboyfriend", "expartner", "exfiance", "exfiancee", "exspouse",
            "exlover", "xwife", "xhusband", "xgirlfriend", "xboyfriend", "xpartner", "formerwife", "formerhusband",
            "formergirlfriend", "formerboyfriend", "formerpartner", "formerspouse", "formerfiance", "previouswife",
            "previoushusband", "previousgirlfriend", "previousboyfriend", "previouspartner", "previousspouse",
            "estranged", "estrangedwife", "estrangedhusband", "estrangedspouse", "estrangedpartner",
        ),
    ),
    (
        _CAT_PURSUIT,
        (
            "blockedme", "wonttalktome", "changedhernumber", "changedhisnumber", "deletedheraccounts",
            "deletedhisaccounts", "wheresheslives", "whereshegoes", "wherehegoes",
        ),
    ),
    (_CAT_MOTIVE, ("stalking", "stalker", "restrainingorder", "protectiveorder", "ghosted")),
):
    for _phrase in _phrases:
        _COMPACT_PHRASES[_phrase] = _category

# Near neighbours of a compact phrase that are ordinary words and must not be treated as a typo of it.
_COMPACT_ALLOWED_NEIGHBOURS = frozenset({"reemployment", "reemployments", "estrange", "estranges", "unemployment"})
_FUZZY_MIN_LETTERS = 8
_MAX_SKELETON_CHARS = 4000
_MAX_CONCAT_TOKENS = 3

# Cyrillic and Greek lookalikes folded to Latin (applied after lowercasing). Not exhaustive.
_CONFUSABLES: Dict[str, str] = {
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h",
    "і": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o",
    "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ѡ": "w", "ѵ": "v",
    "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    "ϲ": "c", "ı": "i",
}
# Leetspeak un-mapping, applied only to the skeleton (never to the readable normalised text).
_LEET: Dict[str, str] = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}


def _skeleton_tokens(text: str) -> List[str]:
    """Letter-only tokens of ``text`` with HTML/percent encoding, accents, homoglyphs and leetspeak folded.

    Single-letter runs ("p r e - e m p l o y m e n t") are joined into one token. Word breaks are kept, so only
    whole tokens (and joins of up to three adjacent tokens) are ever compared with the curated phrases.
    """
    decoded = (text or "")[:_MAX_SKELETON_CHARS]
    for _ in range(2):
        decoded = unquote(html.unescape(decoded))
    decomposed = unicodedata.normalize("NFKD", decoded)
    kept = "".join(ch for ch in decomposed if unicodedata.category(ch) not in ("Mn", "Cf"))
    folded = "".join(_LEET.get(c, c) for c in (_CONFUSABLES.get(ch, ch) for ch in kept.lower()))
    tokens: List[str] = []
    run: List[str] = []
    for raw in folded.split():
        word = "".join(ch for ch in raw if ch.isalpha())
        if not word:
            continue
        if len(word) == 1:
            run.append(word)
            continue
        if run:
            tokens.append("".join(run))
            run = []
        tokens.append(word)
    if run:
        tokens.append("".join(run))
    return tokens


def _within_one_edit(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by at most one insertion, deletion, substitution or adjacent transposition."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = 0
    shorter = min(len(a), len(b))
    while i < shorter and a[i] == b[i]:
        i += 1
    if len(a) == len(b):
        if a[i + 1:] == b[i + 1:]:
            return True
        return i + 1 < len(a) and a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2:] == b[i + 2:]
    if len(a) > len(b):
        return a[i + 1:] == b[i:]
    return b[i + 1:] == a[i:]


# "xhusband" is one edit from the ordinary word "husband": x-prefixed phrases are matched exactly only.
_FUZZY_PHRASES: tuple[tuple[str, str], ...] = tuple(
    (phrase, category)
    for phrase, category in _COMPACT_PHRASES.items()
    if len(phrase) >= _FUZZY_MIN_LETTERS and not phrase.startswith("x")
)


_FUZZY_BY_LENGTH: Dict[int, List[Tuple[int, str, str]]] = {}
for _index, (_phrase, _category) in enumerate(_FUZZY_PHRASES):
    _FUZZY_BY_LENGTH.setdefault(len(_phrase), []).append((_index, _phrase, _category))


@lru_cache(maxsize=16384)
def _fuzzy_categories(candidate: str) -> Tuple[Tuple[str, str], ...]:
    """``(category, phrase)`` for each category whose first curated phrase is within one edit of ``candidate``.

    Only phrases whose length differs by at most one can be within one edit, so the length buckets avoid comparing
    every token with every phrase. The first phrase per category (in list order) wins, as before.
    """
    near = sorted(
        entry
        for length in (len(candidate) - 1, len(candidate), len(candidate) + 1)
        for entry in _FUZZY_BY_LENGTH.get(length, ())
    )
    found: Dict[str, str] = {}
    for _idx, phrase, category in near:
        if category not in found and _within_one_edit(candidate, phrase):
            found[category] = phrase
    return tuple(found.items())


def _skeleton_hits(text: str) -> Dict[str, str]:
    """Map category -> the compact phrase matched in the skeleton form of ``text`` (empty when nothing matched).

    The second normalisation pass: decode HTML entities and percent-encoding, strip combining marks, fold common
    Cyrillic/Greek homoglyphs and leetspeak, drop non-letters inside each word, join single-letter runs, then
    compare every token, and every join of two or three adjacent tokens, with a short curated list of compact
    high-risk phrases (exact, or within one edit for phrases of 8+ letters). Substrings are never matched, so
    "Shire" does not match "hire". This is a safety net against casual disguise, not a guarantee: a spelling it
    does not fold, a second edit, or a phrase not on the list still passes.
    """
    tokens = _skeleton_tokens(text)
    hits: Dict[str, str] = {}
    for start in range(len(tokens)):
        candidate = ""
        for span in range(_MAX_CONCAT_TOKENS):
            if start + span >= len(tokens):
                break
            candidate += tokens[start + span]
            if len(candidate) < 5 or candidate in _COMPACT_ALLOWED_NEIGHBOURS:
                continue
            exact = _COMPACT_PHRASES.get(candidate)
            if exact:
                hits.setdefault(exact, candidate)
                continue
            for category, phrase in _fuzzy_categories(candidate):
                hits.setdefault(category, phrase)
    return hits


def screen_text(
    text: str,
    case_type: CaseType,
    subject_is_person: bool,
    matter_ref: str = "",
    purpose_category: Optional[str] = None,
) -> None:
    """The eligibility, motive and pursuit screens over ``text`` in that order, normalising and folding it only once.

    Same refusals as calling :func:`screen_eligibility`, :func:`motive_screen` and :func:`pursuit_screen` one after
    the other, at a third of the cost. Text over :data:`MAX_SCREEN_CHARS` is refused.
    """
    require_screenable(text)
    prepared = _Prepared(text)
    _check_eligibility(prepared, purpose_category)
    if subject_is_person and case_type in _PERSON_MOTIVE_CASE_TYPES:
        _check_motive(prepared)
    _check_pursuit(prepared, case_type, subject_is_person, matter_ref, purpose_category)


# --------------------------------------------------------------------------- matter reference

_MATTER_REF_PLACEHOLDERS = frozenset(
    {"test", "tbd", "n/a", "na", "none", "xxx", "asdf", "12345", "abc", "unknown", "pending", "later"}
)
_MATTER_REF_MIN_CHARS = 5
_MATTER_REF_VERSUS_RE = re.compile(r"\bvs?\.|\s(?:v|vs)\s")
_MATTER_REF_EXAMPLE = "'23-CV-1182', 'MSA-2026-114' or 'Smith v. Jones'"


def is_valid_matter_ref(matter_ref: str) -> bool:
    """True when ``matter_ref`` looks like a real case, contract or judgment reference.

    At least 5 characters; not a placeholder (test, tbd, n/a, none, xxx, asdf, 12345, abc, unknown, pending, later,
    alone or as the only words); not a run of one digit or a counting sequence; and at least one digit or a party
    pair written ``v.``, ``v`` or ``vs``. A format check only: nothing is looked up in any court or contract system.
    """
    ref = (matter_ref or "").strip()
    if len(ref) < _MATTER_REF_MIN_CHARS:
        return False
    lowered = ref.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if compact in _MATTER_REF_PLACEHOLDERS:
        return False
    words = re.findall(r"[a-z]+", lowered)
    if words and all(word in _MATTER_REF_PLACEHOLDERS for word in words):
        return False
    digits = re.sub(r"\D", "", ref)
    if digits and compact == digits and (
        len(set(digits)) == 1 or digits in "01234567890123456789" or digits in "98765432109876543210"
    ):
        return False
    return bool(digits) or bool(_MATTER_REF_VERSUS_RE.search(lowered))


def require_matter_ref(case_type: CaseType, subject_is_person: bool, matter_ref: str) -> None:
    """A locate of a natural person needs a matter reference; any reference that is supplied must look real.

    A supplied reference is format-checked for every case type and subject type (see :func:`is_valid_matter_ref`),
    because it is free text and also unlocks the former-partner exception in :func:`pursuit_screen`.
    """
    ref = (matter_ref or "").strip()
    if ref:
        if not is_valid_matter_ref(ref):
            raise PIPurposeError(
                f"The matter reference {ref!r} does not look like a real case, contract or judgment reference. It "
                "needs at least 5 characters, must not be a placeholder such as 'TBD', 'test' or '12345', and "
                f"must contain a digit or a 'v.'/'vs' party pair. Use something like {_MATTER_REF_EXAMPLE}."
            )
        return
    if case_type is CaseType.LOCATE and subject_is_person:
        raise PIPurposeError(
            "Locating a private person needs a matter reference: a case number, contract or judgment "
            "reference that shows a legitimate legal matter. Add --matter-ref, or run an entity trace instead."
        )
