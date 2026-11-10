"""Plain-English question parser for ``bunnyhole ask``.

Deterministic on purpose: regular expressions only, no model call and no network. A question becomes an
:class:`AskPlan` (an intent plus typed entities) or ``Intent.UNKNOWN``, and the CLI then runs an existing
investigation. Entity typing reuses the engine's own detectors (``classify_seed_type``, ``has_legal_form``,
``looks_like_natural_person_name``); nothing here decides whether a person gate applies, it only reports that a
person is named (``AskPlan.needs_pi``) so the caller routes through the PI gates.

Supported shapes (see ``docs/ASK.md``):

* connection: "see if A is connected to B", "any ties between A and B", "does A have anything to do with B" ...
* company risk: "see if X has anything shady going on", "is X legit", "any red flags on X", "check X for fraud" ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from bunnyhole.engine.orchestrator import classify_seed_type
from bunnyhole.engine.pi_anchoring import has_legal_form
from bunnyhole.engine.pi_identifiers import looks_like_natural_person_name


class Intent(str, Enum):
    CONNECTION = "connection"
    COMPANY_RISK = "company_risk"
    UNKNOWN = "unknown"


class EntityKind(str, Enum):
    PERSON = "person"
    ORGANISATION = "organisation"
    DOMAIN = "domain"
    OTHER = "other"


@dataclass(frozen=True)
class AskEntity:
    text: str
    kind: EntityKind


@dataclass(frozen=True)
class AskPlan:
    intent: Intent
    entities: Tuple[AskEntity, ...] = ()
    question: str = ""

    @property
    def person(self) -> Optional[AskEntity]:
        """The first entity typed as a person (or a personal identifier), else ``None``."""
        return next((e for e in self.entities if e.kind is EntityKind.PERSON), None)

    @property
    def needs_pi(self) -> bool:
        """True when a person is named: the PI gates apply and are never bypassed."""
        return self.person is not None

    def help_text(self) -> str:
        return HELP_TEXT


HELP_TEXT = (
    "I did not understand that question. `bunnyhole ask` understands two shapes:\n"
    '  1. a connection:   bunnyhole ask "see if <person or company> is connected to <company>"\n'
    "                     (also: is X connected to Y, is X linked to Y, any ties between X and Y, does X have anything to do with Y)\n"
    '  2. company risk:   bunnyhole ask "see if <company> has anything shady going on"\n'
    "                     (also: is X legit, any red flags on X, check X for fraud)\n"
    'Put names in quotes if they contain "and" or other filler words.\n'
    "For anything else use the full commands: `bunnyhole trace <seed>`, `bunnyhole link <a> <b>` or "
    "`bunnyhole intake ...` (see `bunnyhole --help`)."
)

# ------------------------------------------------------------------------------------------------ text cleanup

_MAX_ENTITY_CHARS = 120
_QUOTE = re.compile(r"\"([^\"]+)\"|“([^”]+)”|(?<!\w)'([^']+)'(?!\w)|‘([^’]+)’")
_PLACEHOLDER = re.compile(r"\x01(\d+)\x01")
_TRAILING_PUNCT = re.compile(r"[\s?!.,;:]+$")
_FILLERS = [
    re.compile(p, re.I)
    for p in (
        r"^(?:hey|hi|hello|ok|okay|so|bunnyhole)\b[,\s]*",
        r"^please\b[,\s]*",
        r"^(?:can|could|would|will)\s+you\s+(?:please\s+)?",
        r"^i\s+(?:want|need|would like|'d like)\s+(?:you\s+)?to\s+",
        r"^(?:let'?s|let me)\s+",
        r"^(?:see|check|find out|find|figure out|tell me|let me know|investigate|look into|look up|verify|determine|"
        r"establish|work out|confirm|ask|research|know)\s+(?:for me\s+)?(?:if|whether|out if)\b\s*",
        r"^(?:if|whether)\s+",
    )
]
_ENTITY_PREFIX = re.compile(
    r"^(?:the\s+)?(?:(?:company|firm|business|organi[sz]ation|person|guy|man|woman|outfit)\s+)?"
    r"(?:(?:called|named)\s+)?",
    re.I,
)
_ENTITY_STOPWORDS = frozenset(
    ["is", "are", "was", "were", "it", "its", "this", "that", "these", "those", "he", "she", "they", "them", "who", "what", "which", "anything", "something", "someone", "one", "there", "here", "and", "or", "to", "with", "of", "the", "a", "an", "if", "whether", "do", "does", "did"]
)


def _extract_quotes(text: str) -> Tuple[str, List[str]]:
    quoted: List[str] = []

    def _swap(match: re.Match[str]) -> str:
        quoted.append(next(g for g in match.groups() if g is not None))
        return f"\x01{len(quoted) - 1}\x01"

    return _QUOTE.sub(_swap, text), quoted


def _restore(text: str, quoted: List[str]) -> str:
    return _PLACEHOLDER.sub(lambda m: quoted[int(m.group(1))], text)


def _normalize(question: str) -> Tuple[str, List[str]]:
    text, quoted = _extract_quotes(question or "")
    text = re.sub(r"\s+", " ", text).strip()
    text = _TRAILING_PUNCT.sub("", text)
    changed = True
    while changed:
        changed = False
        for pattern in _FILLERS:
            stripped = pattern.sub("", text, count=1)
            if stripped != text:
                text, changed = stripped.strip(), True
    return text, quoted


def _clean_entity(raw: str, quoted: List[str]) -> Optional[str]:
    text = raw.strip()
    if _PLACEHOLDER.fullmatch(text):
        value = _restore(text, quoted)
    else:
        text = _ENTITY_PREFIX.sub("", _restore(text, quoted).strip(), count=1)
        value = re.sub(r"(?:'s|’s)$", "", _TRAILING_PUNCT.sub("", text)).strip(" \"'“”")
    value = re.sub(r"\s+", " ", value).strip()
    if not value or len(value) > _MAX_ENTITY_CHARS or value.lower() in _ENTITY_STOPWORDS:
        return None
    if classify_seed_type(value)[0] == "document":  # a local file path is never read from a sentence
        return None
    return value


def classify_entity(text: str) -> EntityKind:
    """Type one entity with the engine's own detectors. A personal identifier (email, phone, handle) counts as a person."""
    value = text.strip()
    seed_type = classify_seed_type(value)[0]
    if seed_type == "domain":
        return EntityKind.DOMAIN
    if seed_type in ("email", "phone", "username", "credential"):
        return EntityKind.PERSON
    if seed_type in ("wallet", "bitcoin", "ip", "aircraft", "document"):
        return EntityKind.OTHER
    if has_legal_form(value):
        return EntityKind.ORGANISATION
    if looks_like_natural_person_name(value):
        return EntityKind.PERSON
    return EntityKind.ORGANISATION


# ------------------------------------------------------------------------------------------------ patterns

_CONN = r"(?:connected|linked|tied|related|associated|affiliated|involved)"
_ADV = r"(?:(?:in any way|in some way|somehow|directly|indirectly|at all)\s+)?"
_NOUN = r"(?:connections?|links?|ties|relationships?|relations?|associations?)"

_CONNECTION_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        rf"^how\s+(?:is|are|was)\s+(?P<a>.+?)\s+{_ADV}{_CONN}\s+(?:to|with)\s+(?P<b>.+)$",
        rf"^(?:is|are|was|were)\s+(?P<a>.+?)\s+{_ADV}{_CONN}\s+{_ADV}(?:to|with)\s+(?P<b>.+)$",
        rf"^(?:are|is)\s+(?P<a>.+?)\s+(?:and|&)\s+(?P<b>.+?)\s+{_CONN}(?:\s+(?:in any way|somehow|to each other|at all))?$",
        rf"^(?P<a>.+?)\s+(?:is|are|was|were)\s+{_ADV}{_CONN}\s+{_ADV}(?:to|with)\s+(?P<b>.+)$",
        rf"^(?:(?:is there|are there|what(?:'s| is| are)|find|show(?: me)?|trace|map|any|get)\s+)*"
        rf"(?:(?:a|an|any|the|some)\s+)*{_NOUN}\s+(?:between|among|from)\s+(?P<a>.+?)\s+(?:and|&|to)\s+(?P<b>.+)$",
        r"^(?:does|did|do)\s+(?P<a>.+?)\s+(?:have|has)\s+(?:anything to do with|something to do with|"
        r"something in common with|(?:(?:a|an|any|some)\s+)?(?:connections?|links?|ties|relationships?|dealings?)\s+(?:to|with))"
        r"\s+(?P<b>.+)$",
        r"^(?:does|did)\s+(?P<a>.+?)\s+(?:know|work for|work with|own|run|control)\s+(?P<b>.+)$",
        rf"^(?P<a>.+?)\s+{_CONN}\s+(?:to|with)\s+(?P<b>.+)$",
    )
]

_RISK_WORDS = (
    r"(?:legit(?:imate)?|reputable|trustworthy|(?:a\s+)?scam(?:mers?)?|(?:a\s+)?fraud(?:ulent)?|dodgy|shady|sketchy|"
    r"suspicious|suspect|risky|fishy|iffy|(?:a\s+)?ponzi(?:\s+scheme)?|(?:a\s+)?front|(?:a\s+)?shell(?:\s+company)?|"
    r"safe|up to (?:no good|something|anything))"
)
_BAD = r"(?:shady|dodgy|fishy|suspicious|wrong|bad|sketchy|illegal|iffy|odd)"
_RISK_NOUN = (
    r"(?:red[\s-]*flags?|warning signs?|risks?|risk flags?|fraud signals?|fraud indicators?|concerns|problems|issues)"
)
_RISK_TAIL = r"(?:\s+(?:to|or|for|and|really|at all|company|business|firm|outfit|operation)\b.*)?"
_RISK_PATTERNS = [
    re.compile(p, re.I)
    for p in (
        rf"^(?:is|are|was)\s+(?P<e>.+?)\s+(?:a\s+|an\s+)?{_RISK_WORDS}{_RISK_TAIL}$",
        rf"^(?P<e>.+?)\s+(?:is|are|was)\s+(?:a\s+|an\s+)?{_RISK_WORDS}{_RISK_TAIL}$",
        rf"^(?:does|did|do)\s+(?P<e>.+?)\s+have\s+(?:anything|something|any|some)\s+{_BAD}(?:\s+going on)?(?:\s+.*)?$",
        rf"^(?P<e>.+?)\s+(?:has|have|got|is hiding|is up to|is involved in)\s+(?:got\s+)?"
        rf"(?:anything|something|any|some)\s+(?:(?:really|too|a bit)\s+)?{_BAD}(?:\s+going on)?(?:\s+.*)?$",
        rf"^(?:is\s+)?(?:there\s+)?(?:anything|something)\s+{_BAD}\s+(?:going on\s+)?"
        r"(?:with|at|about|in|around|regarding)\s+(?P<e>.+)$",
        r"^what(?:'s| is)\s+wrong\s+with\s+(?P<e>.+)$",
        rf"^(?:(?:any|are there any|are there|what are|what|show(?: me)?|list|find|get|the)\s+)*{_RISK_NOUN}\s+"
        r"(?:on|for|about|with|at|around|regarding|against|re)\s+(?P<e>.+)$",
        r"^(?:can|should)\s+i\s+trust\s+(?P<e>.+)$",
        r"^is\s+it\s+(?:safe|ok|okay|wise|a good idea)\s+to\s+(?:deal with|do business with|trade with|buy from|"
        r"invest in|work with|use)\s+(?P<e>.+)$",
        r"^(?:(?:check|screen|vet|investigate|research|look into|look at|run|do|perform|get|give me)\s+"
        r"(?:a\s+|an\s+|the\s+)?)?(?:fraud|scam|risk|red[\s-]*flag|due diligence|compliance|kyc|sanctions?|aml)"
        r"(?:\s+(?:check|screen(?:ing)?|review|assessment|report|scan|search))?\s+(?:on|for|of|about|into)\s+(?P<e>.+)$",
        r"^(?:check|screen|vet|investigate|look into|research)\s+(?P<e>.+?)\s+(?:for|re)\s+"
        r"(?:fraud|scams?|risk|red\s*flags?|shady|sanctions?|dodgy|wrongdoing|adverse media)(?:\s+.*)?$",
        r"^(?P<e>.+?)\s+(?:red\s*flags?|fraud check|scam check|risk check)$",
    )
]
_PERSON_SPLIT = re.compile(r"\s+(?:involving|run by|owned by|headed by|directed by|managed by)\s+", re.I)


def _entities(texts: List[str]) -> Tuple[AskEntity, ...]:
    return tuple(AskEntity(text=t, kind=classify_entity(t)) for t in texts)


def parse_question(question: str) -> AskPlan:
    """Turn a plain-English question into an :class:`AskPlan`; ``Intent.UNKNOWN`` when no supported shape matches."""
    text, quoted = _normalize(question)
    unknown = AskPlan(Intent.UNKNOWN, (), question or "")
    if not text:
        return unknown
    for pattern in _CONNECTION_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        a, b = _clean_entity(match.group("a"), quoted), _clean_entity(match.group("b"), quoted)
        if a and b and a.lower() != b.lower():
            return AskPlan(Intent.CONNECTION, _entities([a, b]), question)
        return unknown  # the first matching shape is decisive: a looser pattern must not re-read a broken match
    for pattern in _RISK_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        parts = _PERSON_SPLIT.split(match.group("e"), maxsplit=1)
        cleaned = [_clean_entity(part, quoted) for part in parts]
        if all(cleaned):
            return AskPlan(Intent.COMPANY_RISK, _entities([c for c in cleaned if c]), question)
    return unknown
