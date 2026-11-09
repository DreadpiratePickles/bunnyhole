"""PI stream: is a graph node about the subject, or is it noise?

A free-text search ("Rosneft", "Bombardier Inc") returns whatever the sources match on: another company's 10-K, a
forum post, a crypto token, a lookalike nonprofit. The graph keeps all of it (nothing here mutates the graph or
drops data); this module only labels each node so the report can put what concerns the subject first and show the
rest as noise. Pure, deterministic and offline: token comparison only, no model calls.

Labels:

* ``subject``: the node's name matches the subject's after removing legal forms, case, accents and punctuation
  (spelling tolerance of one or two edits on longer words, acronyms, aliases the node itself carries).
* ``related``: the name extends or shortens the subject's (a division, a geography), an article or token carries
  the subject's name, or a node is linked to a subject node by an ownership or officer edge. Related is not
  established affiliation: it says "worth reading", never "verified".
* ``unrelated``: no name match, only a weak overlap, or a namesake with distinct extra words (flagged as a possible
  name collision so the report can show it instead of dropping it silently).
* ``unknown``: nothing to compare (no subject name, no node name, or an identifier such as an IP or wallet).

Names are compared after removing legal forms (including their long and Cyrillic spellings), source prefixes such
as ``Wikidata Q123:`` and accents, and after transliterating Cyrillic to Latin. Financial-line words (bank, trust,
fund, insurance ...) are NOT identity-neutral: "Apple Bank" is never "Apple Inc". A name that contains the whole
subject name plus extra words is a probable affiliate (``related``) unless an extra word marks a different business
(a collision, shown as a note, never as the subject's). News, forum and token nodes must carry every subject word
as a whole word (no spelling tolerance).

Known limits are listed in :func:`score_subject_relevance`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple

Relevance = Literal["subject", "related", "unrelated", "unknown"]

#: Legal-form words, removed before comparing names (Inc, PJSC, GmbH ...).
LEGAL_FORMS = frozenset(
    {
        "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc", "llp", "lp", "plc",
        "pjsc", "ojsc", "jsc", "oao", "pao", "zao", "ooo", "gmbh", "ag", "sa", "sas", "sarl", "srl", "spa", "nv",
        "bv", "ab", "oy", "as", "asa", "pty", "pte", "kk", "ulc", "ltee", "sae", "sdn", "bhd", "cv", "kg", "se",
        "na", "kompaniya",
    }
)
#: Long and foreign legal-form phrases (accent-folded, lowercase) removed before tokenising.
_LEGAL_PHRASES: Tuple[str, ...] = (
    "gesellschaft mit beschrankter haftung", "societe a responsabilite limitee", "sociedad de responsabilidad limitada",
    "public limited company", "private limited company", "limited liability company", "open joint stock company",
    "public joint stock company", "joint stock company", "naamloze vennootschap", "besloten vennootschap",
    "societa per azioni", "societe anonyme", "sociedad anonima", "sociedade anonima", "aktiengesellschaft",
    "kommanditgesellschaft", "aktieselskab", "aktiebolag",
)
_LEGAL_PHRASE_RE = re.compile(r"\b(?:" + "|".join(re.escape(p) for p in _LEGAL_PHRASES) + r")\b")
#: Cyrillic legal forms, removed before transliteration (the letter "i kratkoe" would otherwise lose its breve).
_CYRILLIC_LEGAL_RE = re.compile(
    r"публичное акционерное общество|открытое акционерное общество|закрытое акционерное общество|"
    r"общество с ограниченной ответственностью|акционерное общество|(?<!\w)(?:пао|оао|ооо|зао|ао)(?!\w)"
)
_CYRILLIC_TO_LATIN: Dict[str, str] = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh", "з": "z", "и": "i", "й": "y",
    "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f",
    "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
    "я": "ya", "і": "i", "ї": "yi", "є": "ye", "ґ": "g",
}
_CYRILLIC = re.compile(r"[\u0400-\u04ff]")
_STOP_WORDS = frozenset({"the", "of", "and", "de", "du", "des", "la", "le", "les", "et", "der", "die", "das", "von", "van"})
#: Words that do not change which company a name denotes ("Rosneft Oil Company" is "Rosneft"). Financial-line words
#: (bank, trust, fund, insurance ...) and energy/mining are deliberately NOT here: "Rosneft Bank" is another entity.
NEUTRAL_TOKENS = frozenset(
    {
        "enterprise", "enterprises", "industries", "industrial", "oil", "gas", "petroleum", "airlines", "airline",
        "airways", "air", "management", "development", "construction", "realty", "properties", "media", "network",
        "networks", "software", "consulting", "pharma", "pharmaceuticals", "public", "joint", "stock", "neftyanaya",
    }
)
#: Division, function and geography words: a name that adds only these is a plausible affiliate, not a namesake.
AFFILIATE_TOKENS = frozenset(
    {
        "group", "holding", "holdings", "transport", "transportation", "aerospace", "aviation", "aircraft", "services",
        "service", "technologies", "technology", "tech", "systems", "solutions", "trading", "logistics", "leasing",
        "finance", "financial", "international", "global", "worldwide", "americas", "america", "american", "canada",
        "canadian", "usa", "us", "uk", "europe", "european", "asia", "asian", "africa", "pacific", "latin", "china",
        "russia", "russian", "india", "germany", "deutschland", "france", "mexico", "brazil", "japan", "australia",
        "ontario", "quebec",
    }
)
#: Words that mark a different line of business or a different kind of body (a bank, a pension trust, a recreational
#: products maker): a name that adds one is a possible name collision or a different-line affiliate, never the subject.
DIFFERENT_BUSINESS_TOKENS = frozenset(
    {
        "bank", "banking", "trust", "fund", "funds", "insurance", "assurance", "investment", "investments",
        "foundation", "charitable", "charity", "association", "society", "institute", "veba", "pension", "retirement",
        "savings", "plans", "plan", "employee", "employees", "community", "church", "school", "university", "club",
        "hospital", "restaurant", "restaurants", "produits", "produit", "recreatifs", "recreational", "recreation",
        "products", "consumer",
    }
)
_COMPOUND_SUFFIXES: Tuple[str, ...] = tuple(sorted(
    {"group", "bank", "banking", "trust", "holding", "holdings", "insurance", "capital", "finance", "financial", "fund"},
    key=len, reverse=True,
))
_MAX_UNLISTED_EXTRA_WORDS = 3  # a longer tail of unfamiliar words is a different, longer-named body
#: Filing / document words and numbers that appear in node labels but are not part of a name.
_DOC_NOISE = frozenset({"filing", "filings", "form", "annual", "report", "10k", "10q", "8k", "20f", "13d", "13g", "sec"})

#: Source families (substrings of the receipt tool name).
_NEWS_MARKERS = ("news", "wayback", "gdelt", "narrative", "hackernews", "reddit", "forum", "blog", "medium",
                 "mediawiki", "wikipedia", "ahmia", "openalex")
_TOKEN_MARKERS = ("dexscreener", "goplus", "coingecko", "token")
_IDENTIFIER_TYPES = frozenset({"account", "email", "phone", "cryptowallet", "iphost", "domain", "username", "location"})

#: Attribute keys that carry another name for the node (never ``match_query``: that is our own query).
_NAME_ATTRIBUTES = (
    "legal_name", "caption", "name", "matched_name", "aliases", "alias", "aka", "also_known_as", "names",
    "other_names", "previous_names",
)

_MAX_TOLERATED_EDITS_SHORT = 1  # words of 5..8 letters
_MAX_TOLERATED_EDITS_LONG = 2  # words of 9+ letters
_MIN_JACCARD_FOR_PARTIAL = 0.5

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX_WALLET = re.compile(r"^(?:0x)?[0-9a-fA-F]{26,64}$")
_DOMAIN_LIKE = re.compile(r"^[\w-]+(?:\.[\w-]+)+$")
_EMAIL_LIKE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ----------------------------------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Name:
    """A name reduced to comparable tokens."""

    core: Tuple[str, ...]  # legal forms, stop words, initials and document noise removed
    distinctive: Tuple[str, ...]  # core without identity-neutral words (falls back to core)


#: A source prefix on a node label ("Wikidata Q123: X", "501(c)(3): X", "Paper (2012): X", "HN (@user): X",
#: "SEC Form 10-K: X"): registry noise, not part of the name.
_SOURCE_PREFIX = re.compile(
    r"^\s*(?:wikidata\s+q?\d+|wikipedia|\d{3}\s*\(\s*[a-z]\s*\)\s*\(\s*\d+\s*\)|paper\s*\(\s*\d{4}\s*\)"
    r"|hn\s*\(\s*@[^)]*\)|sec\s+form\s+[\w\-/.]+|news\s*\([^)]*\))\s*:\s*",
    re.IGNORECASE,
)
_QID = re.compile(r"^q\d+$")


def _transliterate(text: str) -> str:
    """Cyrillic to Latin (legal forms removed first). Text without Cyrillic is returned unchanged."""
    if not _CYRILLIC.search(text):
        return text
    lowered = _CYRILLIC_LEGAL_RE.sub(" ", text.lower())
    return "".join(_CYRILLIC_TO_LATIN.get(ch, ch) for ch in lowered)


def _fold(text: str) -> str:
    text = re.sub(r"^[^\w]+", "", text or "")
    text = _SOURCE_PREFIX.sub("", text)
    folded = unicodedata.normalize("NFKD", _transliterate(text))
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch)).lower()
    folded = re.sub(r"\([^)]*\)", " ", folded)  # "(CA)": a jurisdiction suffix, not part of the name
    folded = folded.replace("&", " and ")
    folded = re.sub(r"['’`´]s\b", "", folded)
    while re.search(r"\b(\w)\.(\w)\b", folded):  # S.A. -> SA, N.V. -> NV
        folded = re.sub(r"\b(\w)\.(\w)\b", r"\1\2", folded)
    folded = re.sub(r"[\W_]+", " ", folded).strip()
    return _LEGAL_PHRASE_RE.sub(" ", folded)


def _split_compound(token: str) -> List[str]:
    """``citigroup`` -> ``citi group`` (a stem plus a business word); other tokens are returned as they are."""
    for suffix in _COMPOUND_SUFFIXES:
        if token.endswith(suffix) and len(token) - len(suffix) >= 3:
            return [token[: -len(suffix)], suffix]
    return [token]


def _name(text: str) -> _Name:
    tokens = _fold(text).split()
    kept = [
        t for t in tokens
        if t not in LEGAL_FORMS and t not in _STOP_WORDS and t not in _DOC_NOISE and not t.isdigit() and len(t) > 1
        and not _QID.match(t)
    ]
    core = tuple(part for t in kept for part in _split_compound(t))
    distinctive = tuple(t for t in core if t not in NEUTRAL_TOKENS) or core
    return _Name(core=core, distinctive=distinctive)


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Levenshtein distance, giving up (returning ``limit + 1``) once it must exceed ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def _tolerance(a: str, b: str) -> int:
    shortest = min(len(a), len(b))
    if shortest < 5 or any(ch.isdigit() for ch in a + b):
        return 0
    return _MAX_TOLERATED_EDITS_SHORT if shortest < 9 else _MAX_TOLERATED_EDITS_LONG


def _tokens_equal(a: str, b: str) -> bool:
    """Same word, within spelling tolerance (transliteration, plural) for words of five or more letters."""
    if a == b:
        return True
    tolerance = _tolerance(a, b)
    if tolerance == 0:
        return False
    short, long_ = sorted((a, b), key=len)
    if long_.startswith(short) and len(long_) - len(short) <= 3:
        return True
    return _edit_distance(a, b, tolerance) <= tolerance


def _lookalike(a: str, b: str) -> bool:
    """Different words that are only one or two edits apart (a lookalike, not a transliteration)."""
    if a == b or min(len(a), len(b)) < 5 or _tokens_equal(a, b):
        return False
    return _edit_distance(a, b, 2) <= 2


def _matched(left: Sequence[str], right: Sequence[str]) -> Tuple[List[str], List[str]]:
    """``(left tokens that have a counterpart in right, left tokens that do not)``."""
    hit = [t for t in left if any(_tokens_equal(t, r) for r in right)]
    miss = [t for t in left if t not in hit]
    return hit, miss


def _initials(tokens: Sequence[str]) -> str:
    return "".join(t[0] for t in tokens)


# ----------------------------------------------------------------------------------------------
# One name against another
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    rank: int  # higher is a stronger match
    relevance: Relevance
    reason: str
    covers_subject: bool = False  # every distinctive subject token appears in the candidate
    notes: List[str] = field(default_factory=list)


_NONE = _Match(0, "unrelated", "no name match")


def _extension_match(s_hit: Sequence[str], c_miss: Sequence[str], shown: str, subject_text: str) -> _Match:
    """The candidate contains the whole subject name and adds ``c_miss`` words."""
    extras = ", ".join(c_miss)
    different = [t for t in c_miss if t in DIFFERENT_BUSINESS_TOKENS]
    if different:
        return _Match(
            1, "unrelated",
            f"possible name collision (or an affiliate in a different line of business): '{shown}' shares "
            f"'{' '.join(s_hit)}' with '{subject_text}' but adds {extras}; not shown as the subject's, check manually",
            covers_subject=True,
        )
    if all(t in AFFILIATE_TOKENS for t in c_miss):
        return _Match(
            3, "related",
            f"'{shown}' extends the subject name with {extras}: possible affiliate or division, not established",
            covers_subject=True,
        )
    if len(c_miss) <= _MAX_UNLISTED_EXTRA_WORDS:
        return _Match(
            3, "related",
            f"'{shown}' contains the whole subject name '{subject_text}' plus {extras}: probable affiliate or "
            "subsidiary, not established",
            covers_subject=True,
        )
    return _Match(
        1, "unrelated",
        f"possible name collision: '{shown}' shares '{' '.join(s_hit)}' with '{subject_text}' but adds "
        f"{extras}; not shown as the subject's, check manually",
        covers_subject=True,
    )


def _compare(subject: _Name, candidate: _Name, shown: str, subject_text: str) -> _Match:
    cand_core, cand_key = candidate.core, candidate.distinctive
    if not cand_core:
        return _NONE
    s_key = subject.distinctive
    s_hit, s_miss = _matched(s_key, cand_key)
    c_hit, c_miss = _matched(cand_key, s_key)

    joined_equal = len(s_key) != len(cand_key) and _tokens_equal("".join(s_key), "".join(cand_key))
    acronym = (len(cand_key) == 1 and 2 <= len(cand_key[0]) <= 6 and cand_key[0] == _initials(subject.core)) or (
        len(s_key) == 1 and 2 <= len(s_key[0]) <= 6 and len(cand_core) >= 2 and s_key[0] == _initials(cand_core)
    )

    if (not s_miss and not c_miss) or joined_equal or acronym:
        exact = sorted(s_key) == sorted(cand_key)
        if acronym:
            how = "acronym of the subject name"
        elif exact:
            how = "same name after removing legal forms"
        else:
            how = "same name within spelling tolerance"
        return _Match(5 if exact else 4, "subject", f"'{shown}' is the {how} '{subject_text}'", covers_subject=True)

    if not s_miss:  # the candidate adds words to the subject's name
        return _extension_match(s_hit, c_miss, shown, subject_text)

    business = AFFILIATE_TOKENS | DIFFERENT_BUSINESS_TOKENS | frozenset(_COMPOUND_SUFFIXES)
    if s_hit and c_miss and all(t in business for t in s_miss) and all(t in business for t in c_miss):
        return _Match(
            2, "related",
            f"'{shown}' shares the name stem '{' '.join(s_hit)}' with '{subject_text}' but differs in "
            f"{', '.join(c_miss)} instead of {', '.join(s_miss)}: possible affiliate or name collision, not established",
            notes=["stem"],
        )

    if s_hit:
        union = len(set(s_key) | set(cand_key))
        jaccard = len(s_hit) / union if union else 0.0
        if not c_miss and len(cand_key) >= 2 and jaccard >= _MIN_JACCARD_FOR_PARTIAL:
            return _Match(
                2, "related",
                f"'{shown}' is a shortened form of '{subject_text}' (token overlap {jaccard:.2f}): possible same "
                "group, not established",
            )
        return _Match(1, "unrelated", f"weak name overlap: '{shown}' shares only '{' '.join(s_hit)}' with the subject")

    if set(subject.core) & set(cand_core):  # only identity-neutral words in common (airlines, group ...)
        shared = " ".join(sorted(set(subject.core) & set(cand_core)))
        return _Match(1, "unrelated", f"weak name overlap: '{shown}' shares only the generic word '{shared}'")

    for s_token in s_key:
        for c_token in cand_key:
            if _lookalike(s_token, c_token):
                return _Match(
                    1, "unrelated",
                    f"no name match: '{shown}' is a lookalike name ('{c_token}' vs '{s_token}'), not a spelling variant",
                )
    return _Match(0, "unrelated", f"no name match: '{shown}' shares no word with '{subject_text}'")


def _candidate_names(label: str, attributes: Optional[Mapping[str, Any]]) -> List[Tuple[str, str]]:
    """``(name text, where it came from)``: the label first, then names the node carries about itself."""
    names: List[Tuple[str, str]] = [(label, "label")]
    for key in _NAME_ATTRIBUTES:
        value = (attributes or {}).get(key)
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for item in values:
            text = str(item).strip() if item is not None else ""
            if text and text != label and (text, key) not in names:
                names.append((text, key))
    return names


# ----------------------------------------------------------------------------------------------
# Identifier nodes
# ----------------------------------------------------------------------------------------------


def _identifier_like(label: str, entity_type: str) -> bool:
    text = (label or "").strip()
    return (
        entity_type.lower() in _IDENTIFIER_TYPES
        or bool(_IPV4.match(text) or _HEX_WALLET.match(text) or _EMAIL_LIKE.match(text))
        or (bool(_DOMAIN_LIKE.match(text)) and not text.replace(".", "").isdigit())
    )


def _score_identifier(subject: _Name, label: str) -> Tuple[Relevance, str]:
    text = (label or "").strip().lower()
    parts = re.split(r"[\W_]+", text)
    if _DOMAIN_LIKE.match(text) and len(parts) > 1:
        parts = parts[:-1]  # drop the TLD
    tokens = tuple(p for p in parts if len(p) > 1 and not p.isdigit() and p not in {"www", "mail", "info"})
    hit, miss = _matched(subject.distinctive, tokens)
    joined = "".join(tokens)
    if (hit and not miss) or (joined and _tokens_equal(joined, "".join(subject.distinctive))):
        return "related", f"identifier '{label}' embeds the subject name (not evidence it belongs to the subject)"
    return "unknown", f"identifier or address node '{label}': no name to compare with the subject"


# ----------------------------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------------------------


def score_subject_relevance(
    subject: str,
    label: str,
    *,
    tool: str = "",
    attributes: Optional[Mapping[str, Any]] = None,
    linked_by_edge: bool = False,
    entity_type: str = "",
) -> Tuple[Relevance, str]:
    """Is the node ``label`` about ``subject``? Returns ``(relevance, reason)``; the reason is never empty.

    ``tool`` is the node's receipt tool (it decides whether a news/forum item or a crypto token that merely carries
    the name is evidence). ``attributes`` may carry other names for the node (``legal_name``, ``aliases``, ``aka``,
    ``matched_name`` ...); ``match_query`` is deliberately ignored. ``linked_by_edge`` says an ownership or
    officer edge joins the node to a subject node, which makes an otherwise unmatched node ``related``.
    ``entity_type`` (``Domain``, ``IPHost``, ``CryptoWallet`` ...) marks identifier nodes, which are compared only
    by whether they embed the name and are otherwise ``unknown``.

    Where it can still be wrong: Cyrillic is transliterated with a simple scheme, other scripts (Arabic, Chinese)
    are not; a different company that shares the whole name ("Delta" the airline and "Delta" the faucet maker)
    scores ``subject``; the affiliate and different-business word lists are finite, so an unlisted extra word is
    called a probable affiliate and a real affiliate in a listed line (a bank) is flagged a possible collision; oil,
    gas and petroleum are still identity-neutral ("Rosneft Oil Company" is "Rosneft"); the legal-form phrase list
    covers common European forms only; and an article, filing or token is judged by its title alone.
    """
    subject_name = _name(subject)
    if not subject_name.core:
        return "unknown", "no usable subject name to compare with"
    if not (label or "").strip():
        return "unknown", "the node has no name to compare"

    if _identifier_like(label, entity_type):
        relevance, reason = _score_identifier(subject_name, label)
    else:
        best = _best_match(subject_name, subject, label, attributes)
        relevance, reason = best.relevance, best.reason
        lowered_tool = tool.lower()
        if any(m in lowered_tool for m in _NEWS_MARKERS + _TOKEN_MARKERS):
            relevance, reason = _score_mention(subject_name, label, token=not any(m in lowered_tool for m in _NEWS_MARKERS))

    if linked_by_edge and relevance in ("unrelated", "unknown"):
        return "related", f"{reason}; linked to the subject by an ownership or officer edge"
    return relevance, reason


def _best_match(subject_name: _Name, subject: str, label: str, attributes: Optional[Mapping[str, Any]]) -> _Match:
    """The strongest match of the node's label, or of another name the node carries, against the subject."""
    best: Optional[_Match] = None
    for text, origin in _candidate_names(label, attributes):
        match = _compare(subject_name, _name(text), text, subject)
        if origin != "label" and match.relevance == "subject":
            match = _Match(
                match.rank, "subject",
                f"'{label}' lists the {origin} name '{text}', which is the same as '{subject}'", True,
            )
        elif origin != "label":
            match = _Match(0, "unrelated", _NONE.reason)  # another name only counts when it matches the subject
        if best is None or match.rank > best.rank:
            best = match
    return best or _NONE


def _score_mention(subject_name: _Name, label: str, *, token: bool) -> Tuple[Relevance, str]:
    """A news, forum or token node: related only when it carries EVERY subject word as a whole word (no fuzzy).

    "Bombarding gamblers" is not about "Bombardier": spelling tolerance is for registry names, not for headlines.
    """
    words = set(_fold(label).split())
    missing = [t for t in subject_name.distinctive if t not in words]
    if not missing:
        if token:
            return "related", f"token '{label}' carries the subject name (association not established)"
        return "related", f"article or post '{label}' mentions the subject name"
    kind = "crypto token" if token else "news, forum or reference item"
    return "unrelated", f"{kind} with no name match ('{label}'): no whole-word match for {', '.join(missing)}"


MatchLevel = Literal["exact", "strong", "affiliate", "none"]


def name_match_level(reference: str, label: str, *, attributes: Optional[Mapping[str, Any]] = None) -> MatchLevel:
    """How strongly ``label`` (and any other name the node carries) matches the name ``reference``.

    ``exact``: the same name after removing legal forms, case, accents and transliteration (spelling tolerance and
    acronyms included). ``strong``: a shortened form of a longer ``reference``. ``affiliate``: the label contains the
    whole ``reference`` plus other words (a probable subsidiary). ``none`` otherwise, including a different line of
    business ("Rosneft Bank" for "Rosneft"). Used to match sanctions-list names against graph entities.
    """
    reference_name = _name(reference)
    if not reference_name.core or not (label or "").strip() or _identifier_like(label, ""):
        return "none"
    match = _best_match(reference_name, reference, label, attributes)
    if match.rank >= 4:
        return "exact"
    if match.rank == 3:
        return "affiliate"
    if match.rank == 2:
        return "affiliate" if "stem" in match.notes else "strong"
    return "none"


__all__ = [
    "AFFILIATE_TOKENS", "DIFFERENT_BUSINESS_TOKENS", "LEGAL_FORMS", "MatchLevel", "NEUTRAL_TOKENS", "Relevance",
    "name_match_level", "score_subject_relevance",
]
