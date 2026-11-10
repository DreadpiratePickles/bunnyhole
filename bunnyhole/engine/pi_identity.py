"""PI stream identity resolution: name variants, same-person scoring and candidate clustering.

Pure and deterministic (no network, no model calls). The central rule is the one an elite
investigator lives by: **a name is never an identity**. Scoring awards points for a name match but
a verdict above POSSIBLE requires non-name *anchors* (birth year, address, phone, email, relatives),
SAME requires two of them, and a handful of hard disqualifiers (birth years/ages far apart, one
record deceased, conflicting middle initials, Jr vs Sr) force DIFFERENT no matter what else matches.
See docs/superpowers/specs/2026-11-09-pi-stream-design.md section 3.2.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

# ----------------------------------------------------------------------------------------------
# Reference tables
# ----------------------------------------------------------------------------------------------

# Very common given names and surnames (lowercase). A person whose first AND last name are both in
# this set is treated as a "common name": a name match is then weak evidence on its own.
COMMON_NAMES: FrozenSet[str] = frozenset(
    {
        # surnames (US/UK/Hispanic/South Asian/East Asian very-high-frequency)
        "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez",
        "hernandez", "lopez", "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
        "lee", "perez", "thompson", "white", "harris", "sanchez", "clark", "ramirez", "lewis", "robinson",
        "walker", "young", "allen", "king", "wright", "scott", "torres", "nguyen", "hill", "flores",
        "green", "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell", "carter", "roberts",
        "evans", "turner", "patel", "singh", "kumar", "sharma", "khan", "ali", "wang", "li",
        "zhang", "chen", "kim", "park", "silva", "santos", "wood", "edwards", "murphy", "kelly",
        # given names
        "john", "james", "robert", "michael", "william", "david", "richard", "joseph", "charles",
        "christopher", "daniel", "matthew", "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
        "kenneth", "kevin", "brian", "george", "edward", "ronald", "timothy", "jason", "jeffrey", "ryan",
        "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah", "karen",
        "lisa", "nancy", "betty", "margaret", "sandra", "ashley", "kimberly", "emily", "donna", "michelle",
        "maria", "jose", "juan", "carlos", "luis", "ana", "mohammed", "muhammad", "ahmed", "wei",
    }
)

# Nickname groups. A name may sit in several groups (pat: patrick/patricia); two given names are
# nickname-compatible when they share at least one group.
_NICKNAME_GROUPS: Tuple[FrozenSet[str], ...] = tuple(
    frozenset(g.split())
    for g in (
        "william bill billy will willy liam",
        "robert bob bobby rob robbie bert",
        "elizabeth liz lizzie beth betty eliza liza",
        "richard rick ricky rich dick richie",
        "james jim jimmy jamie",
        "john jack johnny jon",
        "joseph joe joey",
        "thomas tom tommy",
        "charles charlie chuck chas",
        "edward ed eddie ted teddy ned",
        "michael mike mikey mick",
        "christopher chris kit",
        "daniel dan danny",
        "david dave davey",
        "matthew matt",
        "anthony tony",
        "andrew andy drew",
        "stephen steven steve",
        "patrick pat paddy",
        "patricia pat patty trish",
        "margaret maggie meg peggy marge",
        "katherine catherine kathryn kate katie kathy cathy kat katy",
        "jennifer jen jenny jenn",
        "susan sue susie suzy",
        "deborah debra deb debbie",
        "barbara barb barbie",
        "nicholas nick nicky",
        "alexander alex sandy xander",
        "benjamin ben benny",
        "samuel sam sammy",
        "samantha sam sammy",
        "jonathan jon jonny",
        "timothy tim timmy",
        "gregory greg",
        "raymond ray",
        "ronald ron ronnie",
        "donald don donnie",
        "kenneth ken kenny",
        "lawrence larry",
        "francis frank frankie",
        "frederick fred freddie",
        "theodore ted theo",
        "walter walt wally",
        "henry hank harry",
        "harold hal harry",
        "abigail abby",
        "victoria vicky vicki",
        "rebecca becky becca",
        "jessica jess jessie",
        "stephanie steph",
        "christine christina chrissy tina chris",
        "dorothy dot dottie dolly",
        "eleanor ellie nell",
        "josephine jo josie",
        "mary molly polly mae",
        "sarah sally sadie",
        "vincent vince vinny",
        "leonard leo len lenny",
        "gerald jerry gerry",
        "jeffrey jeff",
        "geoffrey geoff",
        "douglas doug",
        "peter pete",
        "philip phillip phil",
        "russell russ",
        "zachary zach zack",
        "nathaniel nathan nate",
        "mohammed muhammad mohamed mohammad",
        "alexei alexey alex",
    )
)

_NAME_PARTICLES: FrozenSet[str] = frozenset(
    {"van", "von", "de", "del", "della", "di", "da", "la", "le", "bin", "ibn", "al", "el", "der", "den", "du", "dos"}
)
_SUFFIXES: FrozenSet[str] = frozenset({"jr", "sr", "ii", "iii", "iv"})
_TITLES: FrozenSet[str] = frozenset({"mr", "mrs", "ms", "miss", "dr", "prof"})
_GENERATION_GROUP: Dict[str, str] = {"jr": "junior", "ii": "junior", "sr": "senior", "iii": "third", "iv": "fourth"}

_ADDRESS_WORDS: Dict[str, str] = {
    "street": "st", "avenue": "ave", "road": "rd", "drive": "dr", "boulevard": "blvd", "lane": "ln",
    "court": "ct", "place": "pl", "terrace": "ter", "highway": "hwy", "parkway": "pkwy", "circle": "cir",
    "apartment": "apt", "suite": "ste", "north": "n", "south": "s", "east": "e", "west": "w",
}  # fmt: skip

# Score weights (spec section 3.2).
_W_NAME_EXACT = 0.2
_W_NAME_VARIANT = 0.12
_W_DOB_EQUAL = 0.25
_W_DOB_NEAR = 0.15
_W_ADDRESS = 0.25
_W_PHONE = 0.3
_W_EMAIL = 0.3
_W_RELATIVE = 0.15
_W_AGE_EQUAL = 0.1  # spec is silent on ages; weaker than a birth year and never an anchor
_W_AGE_NEAR = 0.05
_COMMON_NAME_PENALTY = 0.15
_MAX_BIRTH_GAP_YEARS = 5

_SAME_MIN_SCORE = 0.8
_SAME_MIN_ANCHORS = 2
_PROBABLE_MIN_SCORE = 0.55
_POSSIBLE_MIN_SCORE = 0.3


def _build_nickname_index() -> Dict[str, FrozenSet[int]]:
    index: Dict[str, Set[int]] = {}
    for gid, group in enumerate(_NICKNAME_GROUPS):
        for name in group:
            index.setdefault(name, set()).add(gid)
    return {name: frozenset(gids) for name, gids in index.items()}


_NICKNAME_INDEX: Dict[str, FrozenSet[int]] = _build_nickname_index()


# ----------------------------------------------------------------------------------------------
# Name parsing
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _ParsedName:
    first: str
    middles: Tuple[str, ...]
    last: str  # "" for single-token names
    suffix: str  # normalised generation suffix ("jr", "sr", ...) or ""

    @property
    def middle_initial(self) -> Optional[str]:
        return self.middles[0][0] if self.middles else None

    @property
    def key(self) -> str:
        return " ".join([self.first, *self.middles, self.last]).strip()

    def first_options(self) -> Set[str]:
        opts = {self.first, self.first.replace("-", " "), self.first.replace("-", "")}
        opts.add(self.first.split("-")[0])
        return {o for o in opts if o}

    def last_options(self) -> Set[str]:
        opts = {self.last, self.last.replace("-", " ")}
        if "-" in self.last:
            opts.update(p for p in self.last.split("-") if p)
        elif " " in self.last:
            opts.add(self.last.split(" ")[-1])
        return {o for o in opts if o}


def _normalise_raw(full_name: str) -> str:
    """Lowercase, collapse whitespace, and turn ``"smith, john"`` into ``"john smith"``."""
    text = " ".join(full_name.lower().split())
    if "," in text:
        left, _, right = text.partition(",")
        left, right = left.strip(), right.strip()
        is_last_first = bool(left and right) and right.strip(".") not in _SUFFIXES
        text = f"{right} {left}" if is_last_first else f"{left} {right}".strip()
    return " ".join(text.replace(",", " ").split())


def _parse_name(full_name: str) -> Optional[_ParsedName]:
    text = _normalise_raw(full_name)
    tokens = [t for t in text.split(" ") if t.strip(".")]
    while tokens and tokens[0].strip(".") in _TITLES:
        tokens.pop(0)
    suffix = ""
    if len(tokens) > 1 and tokens[-1].strip(".") in _SUFFIXES:
        suffix = tokens.pop().strip(".")
    cleaned = [t.strip(".") for t in tokens]
    if not cleaned:
        return None
    if len(cleaned) == 1:
        return _ParsedName(first=cleaned[0], middles=(), last="", suffix=suffix)
    last_tokens = [cleaned[-1]]
    idx = len(cleaned) - 2
    while idx >= 1 and cleaned[idx] in _NAME_PARTICLES:
        last_tokens.insert(0, cleaned[idx])
        idx -= 1
    middles = tuple(cleaned[1 : idx + 1])
    return _ParsedName(first=cleaned[0], middles=middles, last=" ".join(last_tokens), suffix=suffix)


def _nickname_pool(first: str) -> List[str]:
    """Every given name sharing a nickname group with ``first`` (stable order, ``first`` excluded)."""
    pool: List[str] = []
    for gid in sorted(_NICKNAME_INDEX.get(first, frozenset())):
        for name in sorted(_NICKNAME_GROUPS[gid]):
            if name != first and name not in pool:
                pool.append(name)
    return pool


def name_variants(full_name: str) -> List[str]:
    """Lowercase, de-duplicated spellings an investigator should search for ``full_name``.

    Includes the name as given, ``first last``, initials (``j smith`` / ``j. smith``), first plus
    middle initial, hyphen/space splits, and a common-nickname expansion. Never guesses maiden names.
    """
    raw = _normalise_raw(full_name)
    parsed = _parse_name(full_name)
    if parsed is None:
        return []
    out: List[str] = []

    def add(value: str) -> None:
        value = " ".join(value.split())
        if value and value not in out:
            out.append(value)

    add(raw)
    add(raw.replace(".", ""))
    if not parsed.last:
        add(parsed.first)
        return out

    firsts = sorted(parsed.first_options(), key=lambda o: (o != parsed.first, o))
    for part in list(firsts):
        firsts.extend(n for n in _nickname_pool(part) if n not in firsts)
    lasts = sorted(parsed.last_options(), key=lambda o: (o != parsed.last, o))
    mi = parsed.middle_initial

    for last in lasts:
        for first in firsts:
            add(f"{first} {last}")
            if mi:
                add(f"{first} {mi} {last}")
                add(f"{first} {mi}. {last}")
    for last in lasts:
        initial = parsed.first[0]
        add(f"{initial} {last}")
        add(f"{initial}. {last}")
        if mi:
            add(f"{initial} {mi} {last}")
            add(f"{initial}. {mi}. {last}")
    if parsed.middles:
        full_middle = " ".join(parsed.middles)
        for last in lasts:
            add(f"{parsed.first} {full_middle} {last}")
    return out


def _first_compatible(a: _ParsedName, b: _ParsedName) -> bool:
    fa, fb = a.first_options(), b.first_options()
    if fa & fb:
        return True
    groups_a = frozenset().union(*(_NICKNAME_INDEX.get(o, frozenset()) for o in fa))
    groups_b = frozenset().union(*(_NICKNAME_INDEX.get(o, frozenset()) for o in fb))
    if groups_a & groups_b:
        return True
    pairs = ((a.first, b.first), (b.first, a.first))
    return any(len(short) == 1 and long_.startswith(short) for short, long_ in pairs)


def _compare_names(a: _ParsedName, b: _ParsedName) -> str:
    """Return ``"exact"``, ``"variant"`` or ``"none"``."""
    if not a.last or not b.last:
        return "exact" if (not a.last and not b.last and a.first == b.first) else "none"
    if a.key == b.key:
        return "exact"
    if a.last_options() & b.last_options() and _first_compatible(a, b):
        return "variant"
    return "none"


def is_common_name(full_name: str) -> bool:
    """True when the name is built from very common given name + surname (weak evidence alone)."""
    parsed = _parse_name(full_name)
    if parsed is None or not parsed.last:
        return False
    if parsed.last.replace("-", " ").split()[-1] not in COMMON_NAMES:
        return False
    return len(parsed.first) == 1 or parsed.first in COMMON_NAMES


def full_names_compatible(a: str, b: str) -> bool:
    """True when two names carry a surname each, the surnames agree and the given names are compatible.

    Compatible given names are equal, a nickname of each other, a hyphen split, or an initial of the other
    (``J. Roe`` for ``Jane Roe``). A name with no surname (``Jane``), a different surname or a different
    spelling of it (``Roe`` and ``Rowe``) is not compatible. This is the "full name" half of the two-anchor rule:
    it never says two records are the same person, only that the names do not rule it out.
    """
    a, b = fold_name(a), fold_name(b)
    tokens_a, tokens_b = name_tokens(a), name_tokens(b)
    if len(tokens_a) >= 2 and sorted(tokens_a) == sorted(tokens_b):
        return True  # same words in any order ("Roe Jane" and "Jane Roe"), hyphen and space alike
    parsed_a, parsed_b = _parse_name(a), _parse_name(b)
    if parsed_a is None or parsed_b is None or not parsed_a.last or not parsed_b.last:
        return False  # two lone given names ("Jane" and "Jane") are not a full-name match
    return _compare_names(parsed_a, parsed_b) != "none"


def fold_name(text: str) -> str:
    """``text`` with diacritics removed and case folded (``Zoë`` -> ``zoe``); nothing else is changed."""
    decomposed = unicodedata.normalize("NFKD", text or "")
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()


def name_tokens(folded: str) -> List[str]:
    """Words of an already folded name; hyphens, spaces, commas and periods all separate them."""
    return re.findall(r"[^\W_]+(?:'[^\W_]+)*", folded)


def surname_of(full_name: str) -> str:
    """The surname of ``full_name`` as the scorer reads it (lowercase), or ``""`` for a single-word name."""
    parsed = _parse_name(full_name)
    return parsed.last if parsed is not None else ""


# ----------------------------------------------------------------------------------------------
# Records and scoring
# ----------------------------------------------------------------------------------------------


class PersonRecord(BaseModel):
    """One source's claim about a person. All fields optional except the name."""

    name: str
    dob_year: Optional[int] = None
    age: Optional[int] = None
    addresses: List[str] = Field(default_factory=list)
    phones: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    relatives: List[str] = Field(default_factory=list)
    deceased: bool = False
    source: str = ""


class MatchVerdict(str, Enum):
    SAME = "same"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    DIFFERENT = "different"


class IdentityMatch(BaseModel):
    verdict: MatchVerdict
    score: float
    anchors: List[str] = Field(default_factory=list)
    disqualifiers: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)


def _norm_address(address: str) -> str:
    text = re.sub(r"[^a-z0-9#]+", " ", address.lower().replace("&", " and "))
    return " ".join(_ADDRESS_WORDS.get(tok, tok) for tok in text.split())


def _norm_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7:
        return ""
    return digits[-10:]


def _norm_email(email: str) -> str:
    return email.strip().lower()


def _overlap(left: List[str], right: List[str], norm: Callable[[str], str]) -> bool:
    a = {n for n in (norm(x) for x in left) if n}
    b = {n for n in (norm(x) for x in right) if n}
    return bool(a & b)


def _relatives_overlap(left: List[str], right: List[str]) -> bool:
    for x in left:
        px = _parse_name(x)
        if px is None or not px.last:
            continue
        for y in right:
            py = _parse_name(y)
            if py is None or not py.last:
                continue
            if _compare_names(px, py) == "exact" or (
                _compare_names(px, py) == "variant" and len(px.first) > 1 and len(py.first) > 1
            ):
                return True
    return False


def score_same_person(a: PersonRecord, b: PersonRecord, *, common_name: Optional[bool] = None) -> IdentityMatch:
    """Score whether two records describe the same person. Deterministic; never SAME on a name alone."""
    score = 0.0
    anchors: List[str] = []
    disqualifiers: List[str] = []
    reasons: List[str] = []

    pa, pb = _parse_name(a.name), _parse_name(b.name)
    name_match = "none" if pa is None or pb is None else _compare_names(pa, pb)
    if name_match == "exact":
        score += _W_NAME_EXACT
        reasons.append(f"name: exact match (+{_W_NAME_EXACT:.2f})")
    elif name_match == "variant":
        score += _W_NAME_VARIANT
        reasons.append(f"name: variant/nickname/initial match (+{_W_NAME_VARIANT:.2f})")
    else:
        reasons.append("name: no match")

    # Birth year (anchor) or, failing that, age (weak, never an anchor).
    if a.dob_year is not None and b.dob_year is not None:
        gap = abs(a.dob_year - b.dob_year)
        if gap == 0:
            score += _W_DOB_EQUAL
            anchors.append("dob_year")
            reasons.append(f"dob_year: equal (+{_W_DOB_EQUAL:.2f})")
        elif gap == 1:
            score += _W_DOB_NEAR
            anchors.append("dob_year")
            reasons.append(f"dob_year: within one year (+{_W_DOB_NEAR:.2f})")
        if gap > _MAX_BIRTH_GAP_YEARS:
            disqualifiers.append(f"birth years differ by {gap} years ({a.dob_year} vs {b.dob_year})")
    elif a.age is not None and b.age is not None:
        gap = abs(a.age - b.age)
        if gap == 0:
            score += _W_AGE_EQUAL
            reasons.append(f"age: equal (+{_W_AGE_EQUAL:.2f}, not an anchor)")
        elif gap == 1:
            score += _W_AGE_NEAR
            reasons.append(f"age: within one year (+{_W_AGE_NEAR:.2f}, not an anchor)")
        if gap > _MAX_BIRTH_GAP_YEARS:
            disqualifiers.append(f"ages differ by {gap} years ({a.age} vs {b.age})")

    for label, weight, matched in (
        ("address", _W_ADDRESS, _overlap(a.addresses, b.addresses, _norm_address)),
        ("phone", _W_PHONE, _overlap(a.phones, b.phones, _norm_phone)),
        ("email", _W_EMAIL, _overlap(a.emails, b.emails, _norm_email)),
        ("relative", _W_RELATIVE, _relatives_overlap(a.relatives, b.relatives)),
    ):
        if matched:
            score += weight
            anchors.append(label)
            reasons.append(f"{label}: overlap (+{weight:.2f})")

    # Common-name penalty: only when nothing but the name matched.
    if common_name is None:
        common_name = is_common_name(a.name) or is_common_name(b.name)
    if common_name and not anchors and score > 0:
        score = max(0.0, score - _COMMON_NAME_PENALTY)
        reasons.append(f"common name with no corroborating anchor (-{_COMMON_NAME_PENALTY:.2f})")

    if a.deceased != b.deceased:
        disqualifiers.append("deceased: one record is deceased and the other is not; resolve before merging")
    if pa is not None and pb is not None:
        if pa.middle_initial and pb.middle_initial and pa.middle_initial != pb.middle_initial:
            disqualifiers.append(f"middle initials conflict ({pa.middle_initial} vs {pb.middle_initial})")
        ga, gb = _GENERATION_GROUP.get(pa.suffix), _GENERATION_GROUP.get(pb.suffix)
        if ga and gb and ga != gb:
            disqualifiers.append(f"generation suffix conflicts ({pa.suffix} vs {pb.suffix}): different people")

    score = round(min(1.0, max(0.0, score)), 4)

    if disqualifiers:
        verdict = MatchVerdict.DIFFERENT
        reasons.append("forced DIFFERENT by disqualifier(s)")
    elif score >= _SAME_MIN_SCORE and len(anchors) >= _SAME_MIN_ANCHORS:
        verdict = MatchVerdict.SAME
    elif score >= _PROBABLE_MIN_SCORE and len(anchors) >= 1:
        verdict = MatchVerdict.PROBABLE
    elif score >= _POSSIBLE_MIN_SCORE:
        verdict = MatchVerdict.POSSIBLE
    else:
        verdict = MatchVerdict.DIFFERENT

    if name_match == "none" and verdict in (MatchVerdict.SAME, MatchVerdict.PROBABLE):
        verdict = MatchVerdict.POSSIBLE
        reasons.append("names do not match: capped at POSSIBLE (shared contact details also occur between relatives)")

    return IdentityMatch(verdict=verdict, score=score, anchors=anchors, disqualifiers=disqualifiers, reasons=reasons)


def cluster_candidates(records: List[PersonRecord]) -> List[List[int]]:
    """Group record indices by transitive SAME-or-PROBABLE matches. Singletons are included.

    Because a name-only match can never reach PROBABLE, records are never merged on a name alone.
    Clusters are returned sorted by their lowest index; indices inside a cluster are ascending.
    """
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            if score_same_person(records[i], records[j]).verdict in (MatchVerdict.SAME, MatchVerdict.PROBABLE):
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    groups: Dict[int, List[int]] = {}
    for i in range(len(records)):
        groups.setdefault(find(i), []).append(i)
    return [groups[root] for root in sorted(groups)]
