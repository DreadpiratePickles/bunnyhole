"""PI identifier heuristics: person-vs-organisation name and email shape checks and thin-identifier warnings.

Split out of ``pi.py`` unchanged.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, List

from bunnyhole.engine.pi_gates import _ZERO_WIDTH_OR_FORMAT, _normalize_text

# Words that mark a seed as an organisation (legal forms and common organisation nouns), lowercase.
CORPORATE_MARKERS: frozenset[str] = frozenset(
    {
        "inc", "incorporated", "ltd", "limited", "llc", "llp", "lp", "plc", "corp", "corporation", "co", "company",
        "gmbh", "ag", "sa", "nv", "bv", "oy", "ab", "as", "spa", "srl", "sarl", "pty", "pte", "kk", "ulc", "lt",
        "bank", "group", "holdings", "holding", "technologies", "technology", "tech", "partners", "partnership",
        "foundation", "university", "college", "school", "institute", "trust", "fund", "capital", "ventures",
        "labs", "lab", "systems", "solutions", "services", "industries", "international", "enterprises",
        "associates", "association", "society", "church", "hospital", "ministry", "department", "council",
        "authority", "agency", "bureau", "club", "cooperative", "motors", "airlines", "airways", "energy",
        "pharma", "pharmaceuticals", "media", "networks", "network", "software", "consulting", "logistics",
        "realty", "properties", "exchange", "mining", "resources", "global", "worldwide", "stores", "store",
        "restaurant", "studios", "studio", "entertainment", "insurance", "assurance", "securities", "financial",
        "investments", "investment", "management", "development", "construction", "trading", "electric",
    }
)


_HONORIFIC_PREFIXES = frozenset(
    {"mr", "mrs", "ms", "miss", "mx", "dr", "prof", "professor", "sir", "dame", "hon", "rev", "capt", "sgt"}
)
_NAME_SUFFIXES = frozenset(
    {"jr", "sr", "ii", "iii", "iv", "esq", "esquire", "phd", "md", "dds", "dvm", "cpa", "qc", "kc", "mba", "rn", "jd",
     "llm", "pe", "obe", "mbe"}
)
# Common given names. A FOUR-word seed is read as a person only when one of its words is here, so that a
# four-word organisation ("Alpha Beta Gamma Delta") is not mistaken for a person.
_COMMON_GIVEN_NAMES = frozenset(
    """
    james john robert michael william david richard joseph thomas charles christopher daniel matthew anthony mark
    donald steven paul andrew joshua kenneth kevin brian george edward ronald timothy jason jeffrey ryan jacob gary
    nicholas eric jonathan stephen larry justin scott brandon benjamin samuel gregory alexander patrick frank
    raymond jack dennis jerry tyler aaron jose adam nathan henry peter zachary douglas harold kyle noah carl gerald
    keith roger arthur terry lawrence sean christian albert joe ethan austin jesse willie billy bryan bruce jordan
    ralph roy eugene wayne louis philip bobby johnny juan luis carlos miguel pedro ahmed mohammed muhammad ali omar
    wei li jin raj amit vijay sanjay rahul ravi arjun ivan dmitri sergei vladimir pierre hans klaus giovanni marco
    luca mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa nancy betty margaret sandra
    ashley kimberly emily donna michelle dorothy carol amanda melissa deborah stephanie rebecca sharon laura
    cynthia kathleen amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra
    rachel carolyn janet catherine maria heather diane ruth julie olivia joyce virginia victoria kelly lauren
    christina joan evelyn judith megan andrea cheryl hannah jacqueline martha gloria teresa ann sara madison
    frances kathryn janice jean abigail alice julia judy sophia grace denise amber doris marilyn danielle beverly
    isabella theresa diana natalie brittany charlotte marie kayla alexis lori fatima aisha mei yuki anita sunita
    priya elena olga natasha jane john
    """.split()  # noqa: SIM905
)
_PERSON_NAME_MIN_WORDS = 2
_MAX_NAME_CHARS = 500  # no real name is longer; longer text is never read as a person name
_PERSON_NAME_MAX_WORDS = 3
_PERSON_NAME_MAX_WORDS_WITH_GIVEN_NAME = 4


def _name_words(text: str) -> List[str]:
    """Words of ``text`` reduced to the name itself: format characters, parentheticals, honorifics, suffixes and
    trailing numbers (a year, a house number) removed; ``Last, First`` reads as two words like ``First Last``."""
    folded = unicodedata.normalize("NFKC", text or "")
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != _ZERO_WIDTH_OR_FORMAT)
    folded = re.sub(r"[(\[{][^)\]}]{0,80}[)\]}]", " ", folded)
    words = [w for w in (raw.strip(",;:") for raw in re.split(r"[\s,]+", folded)) if w]
    while words and words[-1].isdigit():
        words.pop()
    while words and words[-1].strip(".").lower() in _NAME_SUFFIXES:
        words.pop()
    while words and words[0].strip(".").lower() in _HONORIFIC_PREFIXES:
        words.pop(0)
    return words


def looks_like_natural_person_name(text: str) -> bool:
    """True when ``text`` reads like a person's name and not an organisation.

    Normalises first (zero-width characters, parentheticals such as "(Toronto)", trailing years, honorifics such as
    Dr and Mr, suffixes such as Esq, Jr, PhD and MD), accepts ``Last, First`` order, then requires 2 or 3 alphabetic
    words with no organisation marker (Inc, Ltd, Bank, Holdings ...). A four-word seed counts only when one word is a
    common given name ("Jane Marie Smith Jones"). Words may carry apostrophes, hyphens and periods (O'Brien,
    Smith-Jones, "Q."). A deterministic heuristic for the self-declared ``--subject-type``: callers must offer an
    explicit override, and it is conservative on purpose (a single word such as "Tesla" or "Rosneft" is never a
    person here).
    """
    if len(text or "") > _MAX_NAME_CHARS:
        return False  # a pasted dump or blob is not a name; skip the work
    words = _name_words(text)
    if not _PERSON_NAME_MIN_WORDS <= len(words) <= _PERSON_NAME_MAX_WORDS_WITH_GIVEN_NAME:
        return False
    cores: List[str] = []
    for word in words:
        core = word.replace("'", "").replace("’", "").replace("-", "").replace(".", "")
        if not core or not core.isalpha():
            return False
        cores.append(core.lower())
    if any(_normalize_text(word).replace(" ", "") in CORPORATE_MARKERS for word in words):
        return False
    if len(words) > _PERSON_NAME_MAX_WORDS:
        return any(core in _COMMON_GIVEN_NAMES for core in cores)
    return True


_ROLE_LOCAL_PARTS = frozenset(
    """
    info sales support admin contact hello team office hr press media billing careers jobs legal security service
    services help accounts accounting finance marketing enquiries inquiries noreply reply webmaster postmaster abuse
    mail general customer care compliance privacy investor relations orders order procurement partners hiring
    recruiting recruitment payroll ops dev engineering product feedback news newsletter donotreply it
    """.split()  # noqa: SIM905
)
_FREE_MAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.ca", "yahoo.co.uk", "ymail.com", "rocketmail.com",
        "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
        "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "gmx.de", "mail.com", "zoho.com",
        "yandex.com", "yandex.ru", "qq.com", "163.com", "fastmail.com", "hey.com", "tutanota.com", "comcast.net",
        "verizon.net", "att.net", "sbcglobal.net", "rogers.com", "bell.net", "shaw.ca", "telus.net", "sympatico.ca",
    }
)
_EMAIL_SHAPE_RE = re.compile(r"^([A-Za-z][A-Za-z.'_-]*)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")


def looks_like_person_email(email: str) -> bool:
    """True for a ``first.last@`` style address: a 2 or 3 part alphabetic local part, not a role mailbox.

    ``jane.smith@gmail.com`` yes; ``jane@gmail.com`` (one token), ``info@acme.com``, ``sales.team@acme.com`` and
    ``x7.q@z.io`` no. Shape only: the caller decides whether the domain makes it a person (see
    :func:`is_free_mail_address`).
    """
    match = _EMAIL_SHAPE_RE.match((email or "").strip())
    if not match:
        return False
    parts = [part for part in re.split(r"[._-]+", match.group(1).lower()) if part]
    if not 2 <= len(parts) <= 3 or not all(part.isalpha() for part in parts):
        return False
    if len(parts[0]) < 2 or len(parts[-1]) < 2:
        return False
    return not any(part in _ROLE_LOCAL_PARTS for part in parts)


def is_free_mail_address(email: str) -> bool:
    """True when the address is at a consumer mailbox provider (gmail.com, outlook.com ...)."""
    match = _EMAIL_SHAPE_RE.match((email or "").strip())
    return bool(match) and match.group(2).lower() in _FREE_MAIL_DOMAINS


_ANCHOR_KEYS = ("usernames", "emails", "phones", "wallets", "domains")
_NAME_KEYS = ("organizations", "names")


def _clean_values(selectors: Dict[str, List[str]], keys: tuple[str, ...]) -> List[str]:
    values: List[str] = []
    for key in keys:
        raw = selectors.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        values.extend(str(v).strip() for v in raw if v is not None and str(v).strip())
    return values


def identifier_warnings(selectors: Dict[str, List[str]], subject_is_person: bool) -> List[str]:
    """Advisory strings about thin identifiers. Never raises.

    A person subject needs a full name (two or more words) and at least one more anchor
    (username, email, phone, wallet or domain); a name alone is not an identity.
    """
    names = _clean_values(selectors or {}, _NAME_KEYS)
    warnings: List[str] = []
    if subject_is_person:
        if not any(len(n.split()) >= 2 for n in names):
            warnings.append(
                "No full name (first and last) was given for the person; name-only matches are unreliable. "
                "Add the full name as written on the record."
            )
        if not _clean_values(selectors or {}, _ANCHOR_KEYS):
            warnings.append(
                "No second anchor (username, email, phone, wallet or domain) was given; a name alone is not an "
                "identity and common names will produce false matches. Add one more identifier."
            )
    elif not names and not _clean_values(selectors or {}, ("domains",)):
        warnings.append(
            "No entity name or domain was given; add the legal name and, if known, the registration number."
        )
    return warnings
