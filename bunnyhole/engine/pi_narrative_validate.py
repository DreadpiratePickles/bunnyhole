"""Deterministic validator of the AI analysis. A pure function: it decides, the model does not.

``validate_analysis`` checks the model's text against the evidence it was given and the output contract in
``pi_report_rules.md``. Any violation means the text is not written to the report. What it checks:

- layout: exactly the four sections, in order, nothing before the first (``structure``); a length cap (``too_long``);
- markup: no links, images, HTML, code, square brackets that are not citations, or words that mix Latin with
  Cyrillic or Greek letters (``markup``); the language screens read the text NFKC-normalised without zero-width
  characters;
- citations: every sentence ends with tags such as ``[F3]`` / ``[F2,F5]`` (``uncited``) and every id was supplied
  (``unknown_id``);
- invented specifics: a URL, domain, email, phone number, hash, receipt id, ISO date, year or capitalised name that
  does not occur in the evidence (``invented``);
- forbidden methods: pretext, hacking, impersonation and similar words, even when negated (``forbidden_method``);
- labels: ``confirmed`` / ``probable`` wording must match the label of every cited finding; ``cleared``, ``no risk``
  and similar are rejected (``label_upgrade``, ``clearance``).

Limits, stated honestly (a keyword and token screen, not understanding): a fluent sentence can still be wrong about a
cited record; a name written in lowercase, a sentence-initial name followed by a lowercase word, a number that is not
a year, phone or date, and a paraphrase of a forbidden method are not caught; the capitalised-name check
compares tokens with the evidence, so a real name the evidence also contains can be attached to the wrong record. The
checks are deliberately conservative: a false rejection costs one retry, a false acceptance costs credibility.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from bunnyhole.engine.pi_narrative_input import NarrativeEvidence

SECTION_HEADINGS: Tuple[str, ...] = (
    "Connections",
    "Timeline",
    "What is not established",
    "Suggested next steps (lawful)",
)
#: The only sentences allowed without a citation (an empty section).
EXEMPT_SENTENCES: FrozenSet[str] = frozenset({"None.", "No dated facts were supplied."})
MAX_CHARS = 8000

REASON_TEXT: Dict[str, str] = {
    "structure": "the sections were not exactly the four required, in order",
    "too_long": "it was too long",
    "markup": "it used disallowed markup or square brackets that are not citations",
    "unknown_id": "a citation used an id that was not supplied",
    "uncited": "a sentence did not end with a citation",
    "invented": "it named a URL, email, number, date, hash or name that is not in the evidence",
    "forbidden_method": "it mentioned an unlawful or deceptive method",
    "label_upgrade": "it described a finding more strongly than its label allows",
    "clearance": "it used clearance wording",
}


@dataclass(frozen=True)
class Violation:
    """One failed check. ``detail`` is a short quote of the offending fragment (for the retry prompt only)."""

    code: str
    detail: str


def reasons(violations: Sequence[Violation]) -> List[str]:
    """The distinct human reasons for ``violations``, in first-seen order. Never quotes model text."""
    return list(dict.fromkeys(REASON_TEXT[v.code] for v in violations))


def _clip(text: str, limit: int = 60) -> str:
    one_line = re.sub(r"\s+", " ", text).strip()
    return one_line if len(one_line) <= limit else one_line[: limit - 1] + "…"


# --------------------------------------------------------------------------------------- parsing

_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*(.*?)\s*#*\s*$")
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d{1,2}[.)])\s+")
_TAG_SHAPE = r"\[\s*[A-Za-z]\d+(?:\s*,\s*[A-Za-z]\d+)*\s*\]"
_TAG_RE = re.compile(_TAG_SHAPE)
_ENDS_WITH_TAG_RE = re.compile(_TAG_SHAPE + r"[\s.!?]*$")
_BRACKET_RE = re.compile(r"\[[^\[\]]*\]")
_BOUNDARY_RE = re.compile(r"[.!?]+(?:\s*\[[^\[\]]*\])*(?=\s+[A-Z0-9\[(\"'“]|\s*$)")
_ABBREVIATIONS = frozenset({"ltd", "inc", "corp", "co", "llc", "plc", "gmbh", "mr", "mrs", "ms", "dr", "vs", "no",
                            "st", "jr", "sr", "etc", "approx", "ref", "cf"})


def cited_ids(text: str) -> List[str]:
    """Every id inside citation-shaped tags, in order of appearance (not de-duplicated)."""
    ids: List[str] = []
    for tag in _TAG_RE.finditer(text):
        ids.extend(part.strip() for part in tag.group(0).strip("[] ").split(","))
    return ids


def _section_title(raw: str) -> Optional[str]:
    cleaned = raw.strip().rstrip(":").strip()
    for title in SECTION_HEADINGS:
        if cleaned.lower() == title.lower():
            return title
    return None


def _parse(text: str) -> Tuple[List[str], List[Tuple[str, List[str]]], List[str]]:
    """(preamble lines, [(canonical or raw heading, body lines)], raw headings)."""
    preamble: List[str] = []
    sections: List[Tuple[str, List[str]]] = []
    headings: List[str] = []
    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match:
            raw = match.group(1)
            headings.append(raw)
            sections.append((_section_title(raw) or raw, []))
        elif sections:
            sections[-1][1].append(line)
        else:
            preamble.append(line)
    return preamble, sections, headings


def split_sentences(line: str) -> List[str]:
    """Sentences of one line. A full stop after a legal-form abbreviation (``Ltd.``) is not a boundary."""
    sentences: List[str] = []
    start = 0
    for match in _BOUNDARY_RE.finditer(line):
        before = re.search(r"([A-Za-z]+)$", line[start:match.start()])
        single_dot = line[match.start():match.start() + 1] == "." and not match.group(0).startswith("..")
        abbreviated = before is not None and (before.group(1).lower() in _ABBREVIATIONS or len(before.group(1)) == 1)
        if abbreviated and single_dot and match.end() < len(line.rstrip()):
            continue
        sentences.append(line[start:match.end()].strip())
        start = match.end()
    tail = line[start:].strip()
    if tail:
        sentences.append(tail)
    return [s for s in sentences if s]


def _sentences_of(body: Sequence[str]) -> List[str]:
    out: List[str] = []
    for line in body:
        content = _BULLET_RE.sub("", line).strip()
        if content:
            out.extend(split_sentences(content))
    return out


def canonical_markdown(text: str) -> str:
    """The analysis with canonical ``###`` headings and no blank lines inside a section. Call only after validation."""
    _preamble, sections, _headings = _parse(text)
    blocks = []
    for title, body in sections:
        lines = [line.rstrip() for line in body if line.strip()]
        blocks.append("\n".join([f"### {title}", *lines]))
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------------------- identifiers and names

_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"')\]]+|\bwww\.[^\s<>\"')\]]+")
_EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_RCPT_RE = re.compile(r"(?i)\brcpt_[0-9a-z]+")
_HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12,64}(?![0-9A-Fa-f])")
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24}\b")
_PHONE_RE = re.compile(r"(?<![\w.])\+?\(?\d[\d\s().\-]{5,}\d(?!\w)")
_YEAR_RE = re.compile(r"(?<!\d)(?:19|20)\d{2}(?!\d)")
_WORD_RE = re.compile(r"[^\W\d_][\w'’\-]*", re.UNICODE)
_MIN_PHONE_DIGITS = 7

#: Capitalised words that may appear without being in the evidence: acronyms and legal frames the rules name.
ALLOWED_WORDS: FrozenSet[str] = frozenset(
    {"ofac", "sdn", "pipeda", "fcra", "glba", "dppa", "ubo", "kyc", "aml", "pep", "peps", "sha", "url", "ai", "llm",
     "pi", "eu", "un", "uk", "us", "usa", "lei", "id", "ids", "canada", "canadian", "ontario", "wayback", "ltd",
     "inc", "llc", "plc", "corp", "gmbh", "january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december",
     # function words that are only capitalised because they start a sentence ("The Acme ...")
     "the", "a", "an", "this", "that", "these", "those", "both", "each", "any", "all", "some", "its", "their",
     "his", "her", "our", "whether", "while", "although", "however", "if", "when", "since", "because", "after",
     "before", "as", "in", "on", "at", "by", "for", "from", "with", "without", "of", "to", "and", "or", "but",
     "not", "no", "none", "it", "there", "one", "two", "three", "four", "five"}
)


def _fold(word: str) -> str:
    decomposed = unicodedata.normalize("NFKD", word.replace("’", "'"))
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).casefold()


def _tokens(text: str) -> Set[str]:
    found: Set[str] = set()
    for word in _WORD_RE.findall(text):
        folded = _fold(word).removesuffix("'s")
        found.add(folded)
        found.update(part for part in re.split(r"[\-']", folded) if part)
    return found


def _phone_digit_runs(text: str) -> Set[str]:
    runs = {re.sub(r"\D", "", m.group(0)) for m in _PHONE_RE.finditer(text)}
    return {digits for digits in runs if len(digits) >= _MIN_PHONE_DIGITS}


def _strip(pattern: "re.Pattern[str]", text: str) -> Tuple[List[str], str]:
    return [m.group(0) for m in pattern.finditer(text)], pattern.sub(" ", text)


def _invented(sentence: str, evidence_lower: str, tokens: Set[str], phones: Set[str]) -> List[str]:
    """Specifics in ``sentence`` that do not occur in the evidence (each a short quote)."""
    bad: List[str] = []
    text = _TAG_RE.sub(" ", sentence)
    urls, text = _strip(_URL_RE, text)
    bad += [u for u in urls if u.rstrip(".,;:!?").rstrip("/").lower() not in evidence_lower]
    emails, text = _strip(_EMAIL_RE, text)
    bad += [e for e in emails if e.lower() not in evidence_lower]
    rcpts, text = _strip(_RCPT_RE, text)
    bad += [r for r in rcpts if r.lower() not in evidence_lower]
    hashes, text = _strip(_HASH_RE, text)
    bad += [h for h in hashes if re.search(r"\d", h) and re.search(r"[A-Fa-f]", h) and h.lower() not in evidence_lower]
    dates, text = _strip(_DATE_RE, text)
    bad += [d for d in dates if d not in evidence_lower]
    domains, text = _strip(_DOMAIN_RE, text)
    bad += [d for d in domains if d.lower().rstrip(".") not in evidence_lower]
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) >= _MIN_PHONE_DIGITS and digits not in phones:
            bad.append(match.group(0).strip())
    text = _PHONE_RE.sub(" ", text)
    bad += [y for y in _YEAR_RE.findall(text) if not re.search(rf"(?<!\d){y}(?!\d)", evidence_lower)]
    bad += _unknown_names(text, tokens)
    return bad


def _unknown_names(text: str, tokens: Set[str]) -> List[str]:
    """Capitalised words (names, organisations, acronyms) that are not in the evidence nor allow-listed.

    A capitalised word at the start of a sentence is only a name when another capitalised word follows it.
    """
    words = [m.group(0) for m in _WORD_RE.finditer(text)]
    unknown: List[str] = []
    for position, word in enumerate(words):
        core = word.rstrip("'’-")
        core = core[:-2] if core.lower().endswith(("'s", "’s")) else core
        if len(core) < 2 or not core[0].isupper():
            continue
        folded = _fold(core)
        parts = [p for p in re.split(r"[\-']", folded) if p]
        if folded in ALLOWED_WORDS or folded in tokens or (parts and all(p in tokens for p in parts)):
            continue
        if position == 0 and not (len(words) > 1 and words[1][0].isupper()):
            continue
        unknown.append(core)
    return unknown


# --------------------------------------------------------------------------------------- language screens

_FORBIDDEN_METHOD_RE = re.compile(
    r"\bpretext\w*|\bfalse\s+(?:pretens?es?|pretences?|name|names|identity|identities)\b"
    r"|\bhack(?:ing|ed|s|er|ers)?\b|\bbypass\w*|\bimpersonat\w+|\bsocial[- ]engineer\w*|\bphish\w*"
    r"|\bbrute[- ]?forc\w*|\bcredential[- ]stuff\w*"
    r"|\b(?:log(?:ging|s)?|sign(?:ing|s)?)\s+in(?:to)?\s+(?:to\s+)?(?:his|her|their|the|a|an|someone's)\s+(?:\w+\s+){0,2}account"
    r"|\b(?:reset|guess|crack)\w*\s+(?:his|her|their|the|a)\s+(?:\w+\s+)?password"
    r"|\b(?:gain\w*\s+access\s+to|access\w*)\s+(?:his|her|their|the\s+subject's)\s+(?:\w+\s+)?"
    r"(?:account|device|phone|email|inbox|messages)"
    r"|\btrespass\w*|\bwiretap\w*|\beavesdrop\w*"
    r"|\bgps\s+track\w*|\btracking\s+device|\btrack\w*\s+(?:his|her|their|the\s+subject's)\s+(?:phone|vehicle|car|location|movements)"
    r"|\bpos(?:e|es|ed|ing)\s+as\b|\b(?:fake|dummy|sock[- ]?puppet|burner)\s+(?:account|profile|identity|persona|email)"
    r"|\bwithout\s+(?:their|his|her|the\s+subject's)\s+(?:knowledge|consent|permission)"
    r"|\bdeceiv\w+|\bdeceptive\w*",
    re.IGNORECASE,
)
_CLEARANCE_NEGATABLE_RE = re.compile(r"\b(?:cleared|clean|clearance)\b", re.IGNORECASE)
_CLEARANCE_ALWAYS_RE = re.compile(
    r"\ball[- ]clear\b|\bno\s+(?:\w+\s+){0,2}risks?\b|\bnot\s+(?:been\s+)?sanctioned\b|\binnocen\w*|\bexonerat\w*"
    r"|\bsafe\s+to\s+(?:proceed|deal|trade|engage|contract)\b|\bfree\s+(?:of|from)\s+(?:any\s+)?sanctions?\b",
    re.IGNORECASE,
)
_CONFIRM_RE = re.compile(r"\b(?:confirmed|confirms|verified|corroborated|proven|established)\b", re.IGNORECASE)
_PROBABLE_RE = re.compile(r"\bprobabl[ey]\b", re.IGNORECASE)
_NEGATORS = frozenset({"not", "no", "never", "cannot", "can't", "isn't", "aren't", "wasn't", "hasn't", "without",
                       "neither", "nor"})


def _negated(text: str, start: int) -> bool:
    """True when one of the three words before ``start`` is a negator."""
    return any(word in _NEGATORS for word in re.findall(r"[a-z']+", text[:start].lower())[-3:])


def _screen_text(text: str) -> str:
    """``text`` as the language screens read it: NFKC-normalised, zero-width and other format characters removed."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf")


def _mixed_script_word(text: str) -> Optional[str]:
    """A word that mixes Latin with Cyrillic or Greek letters (a homoglyph trick), else ``None``."""
    for word in _WORD_RE.findall(text):
        scripts = {unicodedata.name(ch, "").split(" ")[0] for ch in word if ch.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            return word
    return None


def _first_unnegated(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    for match in pattern.finditer(text):
        if not _negated(text, match.start()):
            return match.group(0)
    return None


def _label_violation(sentence: str, ids: Sequence[str], labels: Dict[str, str]) -> Optional[str]:
    """The upgrading word when ``sentence`` says more than the labels of the cited ids allow."""
    cited_labels = [labels.get(i) for i in ids]
    word = _first_unnegated(_CONFIRM_RE, sentence)
    if word and not (cited_labels and all(label == "confirmed" for label in cited_labels)):
        return word
    word = _first_unnegated(_PROBABLE_RE, sentence)
    if word and not (cited_labels and all(label in ("probable", "confirmed") for label in cited_labels)):
        return word
    return None


def _clearance_word(sentence: str) -> Optional[str]:
    match = _CLEARANCE_ALWAYS_RE.search(sentence)
    return match.group(0) if match else _first_unnegated(_CLEARANCE_NEGATABLE_RE, sentence)


# --------------------------------------------------------------------------------------- the validator


def _structure(preamble: Sequence[str], headings: Sequence[str], sections: Sequence[Tuple[str, List[str]]]) -> List[Violation]:
    found = [title for title, _body in sections]
    if found != list(SECTION_HEADINGS) or any(line.strip() for line in preamble):
        return [Violation("structure", _clip(", ".join(headings) or "no headings"))]
    return []


def _markup(text: str) -> List[Violation]:
    problems = []
    if "`" in text or "](" in text or "![" in text or re.search(r"<\s*/?\s*[A-Za-z!]", text):
        problems.append(Violation("markup", "link, image, code or HTML"))
    for bracket in _BRACKET_RE.findall(text):
        if not _TAG_RE.fullmatch(bracket):
            problems.append(Violation("markup", _clip(bracket)))
    return problems


def validate_analysis(text: str, evidence: NarrativeEvidence) -> List[Violation]:
    """Every violation of the output contract in ``text`` (empty list means the text may be written)."""
    violations: List[Violation] = []
    if len(text) > MAX_CHARS:
        violations.append(Violation("too_long", f"{len(text)} characters"))
    preamble, sections, headings = _parse(text)
    violations += _structure(preamble, headings, sections)
    violations += _markup(text)

    known = evidence.known_ids
    labels = dict(evidence.finding_labels)
    evidence_lower = evidence.text.lower()
    tokens = _tokens(evidence.text)
    phones = _phone_digit_runs(evidence.text)
    body_lines = list(preamble) + [line for _title, body in sections for line in body]
    for raw_sentence in _sentences_of(body_lines):
        if raw_sentence.rstrip(" ") in EXEMPT_SENTENCES:
            continue
        sentence = _screen_text(raw_sentence)
        mixed = _mixed_script_word(sentence)
        if mixed:
            violations.append(Violation("markup", _clip(f"mixed-script word {mixed}")))
        if not _ENDS_WITH_TAG_RE.search(sentence):
            violations.append(Violation("uncited", _clip(sentence)))
        ids = cited_ids(sentence)
        violations += [Violation("unknown_id", i) for i in dict.fromkeys(ids) if i not in known]
        violations += [Violation("invented", _clip(item)) for item in _invented(sentence, evidence_lower, tokens, phones)]
        method = _FORBIDDEN_METHOD_RE.search(sentence)
        if method:
            violations.append(Violation("forbidden_method", _clip(method.group(0))))
        upgrade = _label_violation(sentence, ids, labels)
        if upgrade:
            violations.append(Violation("label_upgrade", _clip(upgrade)))
        clearance = _clearance_word(sentence)
        if clearance:
            violations.append(Violation("clearance", _clip(clearance)))
    return violations
