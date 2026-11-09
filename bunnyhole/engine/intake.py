"""Dual-Mode Case Intake & Multi-Selector Input Engine for Bunnyhole.

Supports:
1. Omni-Bar Raw Dump Auto-Tagging (`SmartIntakeParser.parse_omni_text`): paste messy notes,
   OSINT dumps, combo-lists, or natural-language questions and deterministically extract
   usernames, emails, phones, leaked credentials, wallets, domains, IPs, tail numbers,
   local .pdf/.docx files, exclusions, and the working hypothesis.
2. Structured Known Credentials & Selectors Locker (`CaseIntakePacket`): explicit slots
   for all selector types + AnchorMode ('convergence' vs 'locked_profile') + negative scope exclusions.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Callable, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from bunnyhole.engine.models import GearMode


class AnchorMode(str, Enum):
    """How Bunnyhole links multiple input selectors at Hop 0."""

    CONVERGENCE = "convergence"  # Default when >1 clue: treat as separate unverified islands & prove IF/HOW they connect
    LOCKED_PROFILE = "locked_profile"  # Confirmed same person/entity: link all known selectors to a single Target Profile root


class CaseIntakePacket(BaseModel):
    """Structured multi-selector & hypothesis intake packet for launching an investigation."""

    title: str = ""
    raw_omni_input: str = ""
    raw_omni_text: str = ""
    hypothesis: str = ""
    anchor_mode: AnchorMode = AnchorMode.CONVERGENCE
    usernames: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    phones: List[str] = Field(default_factory=list)
    credentials: List[str] = Field(default_factory=list)  # email:pass, user:pass, or hash
    wallets: List[str] = Field(default_factory=list)  # 0x..., *.eth, bc1..., 1..., 3...
    domains_or_ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    orgs_or_names: List[str] = Field(default_factory=list)  # companies, people, or N-numbers
    organizations: List[str] = Field(default_factory=list)
    aircraft_tails: List[str] = Field(default_factory=list)
    evidence_files: List[str] = Field(default_factory=list)  # local .pdf / .docx paths
    exclusions: List[str] = Field(default_factory=list)  # negative scope terms/domains/wallets
    gear: GearMode = GearMode.FAST
    depth: int = 2
    breadth: int = 4

    def summary_seed_label(self) -> str:
        if self.title:
            return self.title
        seeds = [v for _, v in self.all_seed_tuples()]
        if len(seeds) == 1:
            return seeds[0]
        if len(seeds) > 1:
            return f"{seeds[0]} + {len(seeds) - 1} selectors ({self.anchor_mode.value})"
        return (self.raw_omni_input or self.raw_omni_text or self.hypothesis or "Multi-Selector Case")[:48]

    def total_selectors(self) -> int:
        return (
            len(self.usernames)
            + len(self.emails)
            + len(self.phones)
            + len(self.credentials)
            + len(self.wallets)
            + len(self.domains_or_ips)
            + len(self.domains)
            + len(self.orgs_or_names)
            + len(self.organizations)
            + len(self.aircraft_tails)
            + len(self.evidence_files)
        )

    def all_seed_tuples(self) -> List[tuple[str, str]]:
        """Return ordered list of (lead_type, value) across all populated selector slots."""
        items: List[tuple[str, str]] = []
        for w in self.wallets:
            if re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}$", w.strip()):
                items.append(("bitcoin", w.strip()))
            else:
                items.append(("wallet", w.strip()))
        for em in self.emails:
            items.append(("email", em.strip()))
        for cr in self.credentials:
            items.append(("credential", cr.strip()))
        for ph in self.phones:
            items.append(("phone", ph.strip()))
        for u in self.usernames:
            items.append(("username", u.strip().lstrip("@")))
        for d in _dedup_list(self.domains_or_ips + self.domains):
            val = d.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                items.append(("ip", val))
            else:
                items.append(("domain", val))
        for o in _dedup_list(self.orgs_or_names + self.organizations + self.aircraft_tails):
            val = o.strip()
            if re.match(r"^N[1-9][0-9A-HJ-NP-Z]{0,4}$", val.upper()) and len(val) <= 6 and any(c.isdigit() for c in val):
                items.append(("aircraft", val.upper()))
            else:
                items.append(("company", val))
        for doc in self.evidence_files:
            items.append(("document", doc.strip()))
        return items


def _dedup_list(seq: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in seq:
        clean = item.strip()
        if not clean:
            continue
        k = clean.lower()
        if k not in seen:
            seen.add(k)
            out.append(clean)
    return out


# -------------------------------------------------------------------------------------------------
# Omni-text selector patterns. Every quantifier is bounded (RFC limits where one exists: 64-char email
# local part, 63-char DNS label) and the path pattern only starts at a token boundary, so the parser
# stays linear on adversarial input (long runs of 'ab.', digits, dots, unicode letters, ...).
# -------------------------------------------------------------------------------------------------
_EXCLUSION_VALUE = r"[a-zA-Z0-9_.\-@]{3,64}(?![a-zA-Z0-9_.\-@])"
# The keyword forms are tried before the bare '-' form, so '-exclude:x' excludes 'x' (not the word 'exclude').
_RE_EXCLUSION = re.compile(r"(?<!\S)(?:-?(?i:exclude|ignore):|-)(" + _EXCLUSION_VALUE + ")")
_RE_EVIDENCE_FILE = re.compile(r"(?<![/\w.\-~])([/\w.\-~]{1,1024}\.(?:pdf|docx))\b", re.IGNORECASE)
_EMAIL_CORE = r"[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63}){1,8}"
_RE_CREDENTIAL = re.compile(r"\b(" + _EMAIL_CORE + r":[^\s,;\"']{4,64})(?=\s|$|[,;])")
_RE_EMAIL = re.compile(r"\b(" + _EMAIL_CORE + r")\b")
_RE_EVM_WALLET = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
_RE_ENS = re.compile(r"\b([a-zA-Z0-9_-]{3,40}\.eth)\b", re.IGNORECASE)
_RE_BTC_WALLET = re.compile(r"\b((?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59})\b")
_RE_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RE_URL = re.compile(r"\b(https?://[^\s,;\"')]{1,2048})\b")
_RE_DOMAIN = re.compile(
    r"\b([a-zA-Z0-9-]{2,63}\.(?:com|org|io|net|co|ai|xyz|fi|gg|app|dev|me|info|biz|ch|uk|de|ky|vg|pa))\b",
    re.IGNORECASE,
)
_RE_TAIL = re.compile(r"\b(N[1-9][0-9A-HJ-NP-Z]{1,4})\b")
_RE_PHONE = re.compile(r"(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}\b")
_RE_HANDLE = re.compile(r"(?:^|\s)@([a-zA-Z0-9_.-]{3,30})\b")


def _extract(pattern: "re.Pattern[str]", text: str, take: "Callable[[re.Match[str]], Optional[bool]]") -> str:
    """Remove every match of ``pattern`` from ``text`` (replaced by a space), calling ``take`` on each.

    ``take`` returning ``False`` keeps that match in the text (it was not accepted as a selector).
    """

    def _replace(m: "re.Match[str]") -> str:
        return m.group(0) if take(m) is False else " "

    return pattern.sub(_replace, text)


class SmartIntakeParser:
    """
    Deterministic multi-selector parser that turns messy clipboard dumps, OSINT notes,
    or mixed structured + unstructured inputs into a clean `CaseIntakePacket`.
    """

    @staticmethod
    def split_multi_values(items: List[str]) -> List[str]:
        """Split comma/newline/semicolon-separated strings inside a list of form inputs."""
        expanded: List[str] = []
        for raw in items:
            for part in re.split(r"[\n,;]+", raw):
                p = part.strip()
                if p:
                    expanded.append(p)
        return _dedup_list(expanded)

    @classmethod
    def parse_omni_text(cls, raw_text: str) -> CaseIntakePacket:
        """
        Extract and classify all selectors, exclusions, and natural-language hypothesis
        from a raw free-text string or clipboard dump.
        """
        text = (raw_text or "").strip()
        if not text:
            return CaseIntakePacket()

        working = text
        exclusions: List[str] = []
        credentials: List[str] = []
        emails: List[str] = []
        wallets: List[str] = []
        phones: List[str] = []
        domains_or_ips: List[str] = []
        usernames: List[str] = []
        orgs_or_names: List[str] = []
        aircraft_tails: List[str] = []
        evidence_files: List[str] = []

        # Every extractor removes exactly the span it matched (re.sub with a collecting callback), in one
        # linear pass per pattern. All patterns are bounded (see the _RE_* constants) so adversarial input
        # cannot trigger catastrophic backtracking.

        # 1. Exclusions: -domain.com, exclude:xyz, ignore:xyz, -exclude:xyz, -ignore:xyz
        working = _extract(_RE_EXCLUSION, working, lambda m: exclusions.append(m.group(1).strip()))

        # 2. Local evidence files (.pdf / .docx)
        working = _extract(_RE_EVIDENCE_FILE, working, lambda m: evidence_files.append(m.group(1).strip()))

        # 3. Leaked Credentials / Combo-list entries (email:password, excluding http:// or https://)
        def _take_credential(m: "re.Match[str]") -> None:
            cred = m.group(1)
            credentials.append(cred)
            emails.append(cred.split(":", 1)[0])

        working = _extract(_RE_CREDENTIAL, working, _take_credential)

        # 4. Standalone Emails
        working = _extract(_RE_EMAIL, working, lambda m: emails.append(m.group(1)))

        # 5. EVM Wallets (0x...), ENS names (*.eth), and Bitcoin Wallets (bc1...)
        working = _extract(_RE_EVM_WALLET, working, lambda m: wallets.append(m.group(1)))
        working = _extract(_RE_ENS, working, lambda m: wallets.append(m.group(1).lower()))
        working = _extract(_RE_BTC_WALLET, working, lambda m: wallets.append(m.group(1)))

        # 6. IPv4 Addresses
        working = _extract(_RE_IPV4, working, lambda m: domains_or_ips.append(m.group(1)))

        # 7. URLs & Domains. A malformed URL (``http://a]b[c``) makes urlparse raise ValueError; it is dropped
        # from the text (it is not a usable selector) and parsing carries on.
        def _take_url(m: "re.Match[str]") -> None:
            try:
                netloc = urlparse(m.group(1)).netloc
            except ValueError:
                return
            if netloc:
                domains_or_ips.append(netloc.lower())

        working = _extract(_RE_URL, working, _take_url)
        working = _extract(_RE_DOMAIN, working, lambda m: domains_or_ips.append(m.group(1).lower()))

        # 8. FAA Aircraft Tail Numbers (e.g. N628TS)
        def _take_tail(m: "re.Match[str]") -> None:
            tail = m.group(1).upper()
            aircraft_tails.append(tail)
            orgs_or_names.append(tail)

        working = _extract(_RE_TAIL, working, _take_tail)

        # 9. Phone Numbers (e.g., +1-415-555-0199, +44 20 7946 0921, (415) 555-0199). A match whose digit count
        # is not a plausible phone number is left in the text.
        def _take_phone(m: "re.Match[str]") -> bool:
            raw_ph = m.group(0).strip()
            digits = re.sub(r"\D", "", raw_ph)
            if not 10 <= len(digits) <= 15:
                return False
            phones.append(f"+{digits}" if raw_ph.startswith("+") or len(digits) > 10 else f"+1{digits}")
            return True

        working = _extract(_RE_PHONE, working, _take_phone)

        # 10. Explicit @Handles
        working = _extract(_RE_HANDLE, working, lambda m: usernames.append(f"@{m.group(1)}"))

        # 11. Determine if remaining text is a single handle/company seed or a natural-language hypothesis
        rem = re.sub(r"\s+", " ", working).strip(" ,;:-")
        hypothesis = ""
        total_extracted = (
            len(emails)
            + len(credentials)
            + len(wallets)
            + len(phones)
            + len(domains_or_ips)
            + len(usernames)
            + len(orgs_or_names)
            + len(evidence_files)
        )

        if rem:
            words = rem.split()
            # If no other selectors were extracted and remaining text is short (<= 4 words), treat as company/username seed
            if total_extracted == 0 and len(words) <= 4 and "?" not in rem:
                if len(words) == 1 and any(c.isdigit() or c in "_-" for c in rem):
                    usernames.append(rem)
                else:
                    orgs_or_names.append(rem)
            elif len(words) >= 4 or "?" in rem or any(
                kw in rem.lower()
                for kw in ("prove", "whether", "connected", "link", "linked", "behind", "controls", "funded", "hypothesis", "investigate", "who", "how")
            ):
                hypothesis = raw_text.strip()
            elif total_extracted > 0 and len(words) <= 3:
                orgs_or_names.append(rem)

        dedup_domains = _dedup_list(domains_or_ips)
        dedup_orgs = _dedup_list(orgs_or_names)
        return CaseIntakePacket(
            raw_omni_input=text,
            raw_omni_text=text,
            hypothesis=hypothesis,
            usernames=_dedup_list(usernames),
            emails=_dedup_list(emails),
            phones=_dedup_list(phones),
            credentials=_dedup_list(credentials),
            wallets=_dedup_list(wallets),
            domains_or_ips=dedup_domains,
            domains=dedup_domains,
            orgs_or_names=dedup_orgs,
            organizations=dedup_orgs,
            aircraft_tails=_dedup_list(aircraft_tails),
            evidence_files=_dedup_list(evidence_files),
            exclusions=_dedup_list(exclusions),
        )

    # -- natural-language command interpretation -------------------------------------------------
    @classmethod
    def interpret(cls, text: str) -> "InterpretedCommand":
        """See module-level :func:`interpret_command`."""
        return interpret_command(text)

    @classmethod
    def normalize_packet(cls, packet: CaseIntakePacket) -> CaseIntakePacket:
        """Merge raw_omni_input / raw_omni_text (if any) with explicit structured fields and normalize lists."""
        raw_txt = (packet.raw_omni_input or packet.raw_omni_text).strip()
        parsed = cls.parse_omni_text(raw_txt) if raw_txt else CaseIntakePacket()

        merged_hypothesis = packet.hypothesis.strip() or parsed.hypothesis
        usernames = _dedup_list(cls.split_multi_values(packet.usernames) + parsed.usernames)
        emails = _dedup_list(cls.split_multi_values(packet.emails) + parsed.emails)
        phones = _dedup_list(cls.split_multi_values(packet.phones) + parsed.phones)
        credentials = _dedup_list(cls.split_multi_values(packet.credentials) + parsed.credentials)
        wallets = _dedup_list(cls.split_multi_values(packet.wallets) + parsed.wallets)
        domains_or_ips = _dedup_list(
            cls.split_multi_values(packet.domains_or_ips + packet.domains) + parsed.domains_or_ips
        )
        orgs_or_names = _dedup_list(
            cls.split_multi_values(packet.orgs_or_names + packet.organizations + packet.aircraft_tails)
            + parsed.orgs_or_names
        )
        aircraft_tails = _dedup_list(cls.split_multi_values(packet.aircraft_tails) + parsed.aircraft_tails)
        evidence_files = _dedup_list(cls.split_multi_values(packet.evidence_files) + parsed.evidence_files)
        exclusions = _dedup_list(cls.split_multi_values(packet.exclusions) + parsed.exclusions)

        # Ensure any email or username inside credentials is also in emails / usernames
        for cred in credentials:
            if ":" in cred:
                ident = cred.split(":", 1)[0].strip()
                if "@" in ident and ident not in emails:
                    emails.append(ident)
                elif ident and "@" not in ident and ident not in usernames:
                    usernames.append(ident)

        norm = CaseIntakePacket(
            title=packet.title.strip(),
            raw_omni_input=raw_txt,
            raw_omni_text=raw_txt,
            hypothesis=merged_hypothesis,
            anchor_mode=packet.anchor_mode,
            usernames=_dedup_list(usernames),
            emails=_dedup_list(emails),
            phones=_dedup_list(phones),
            credentials=_dedup_list(credentials),
            wallets=_dedup_list(wallets),
            domains_or_ips=_dedup_list(domains_or_ips),
            domains=_dedup_list(domains_or_ips),
            orgs_or_names=_dedup_list(orgs_or_names),
            organizations=_dedup_list(orgs_or_names),
            aircraft_tails=_dedup_list(aircraft_tails),
            evidence_files=_dedup_list(evidence_files),
            exclusions=_dedup_list(exclusions),
            gear=packet.gear,
            depth=packet.depth,
            breadth=packet.breadth,
        )
        if not norm.title:
            norm.title = norm.summary_seed_label()
        return norm


# =================================================================================================
# Natural-language command interpretation
# -------------------------------------------------------------------------------------------------
# Lets a user type a plain-English instruction ("take a quick look at acme.io", "dig 3 levels into
# example.com, same operator?") instead of flags. We reuse SmartIntakeParser for selector/hypothesis
# extraction and add a thin layer that infers run parameters (gear / depth / breadth / anchor mode)
# from the language, then scrubs the leftover command words so they don't become bogus selectors.
# =================================================================================================

_NUM_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4}

_DEEP_CUE = re.compile(
    r"\b(deep(?:er)?|deep[\s-]?dive|thorough(?:ly)?|exhaustive|in[\s-]?depth|heavy|dig\s+in|"
    r"full\s+send|leave\s+no\s+stone|no\s+stone\s+unturned|everything\s+you(?:'ve|\s+have)\s+got)\b",
    re.IGNORECASE,
)
_FAST_CUE = re.compile(
    r"\b(quick(?:ly)?|fast|rapid(?:ly)?|light(?:weight)?|brief(?:ly)?|glance|skim|triage|"
    r"first\s+look|quick\s+scan|just\s+a\s+(?:quick\s+)?look)\b",
    re.IGNORECASE,
)
_WIDE_CUE = re.compile(
    r"\b(wider?|widen|broad(?:ly)?|broaden|wide\s+net|cast\s+a\s+wide\s+net|as\s+many\s+as\s+possible)\b",
    re.IGNORECASE,
)
_NARROW_CUE = re.compile(r"\b(narrow(?:ly)?|focused|tight(?:ly)?|minimal|just\s+the\s+main)\b", re.IGNORECASE)

_DEPTH_PATTERNS = [
    re.compile(r"\bdepth\s*(?:of\s*)?(\d)\b", re.IGNORECASE),
    re.compile(r"\b(\d)\s*hops?\b", re.IGNORECASE),
    re.compile(r"\b(\d)\s*(?:levels?|layers?)\b", re.IGNORECASE),
    re.compile(r"\bdig\s*(\d)\b", re.IGNORECASE),
    re.compile(r"\bgo\s*(\d)\s*(?:deep|hops?|levels?|layers?)?\b", re.IGNORECASE),
]
_DEPTH_WORD = re.compile(r"\b(one|two|three|four)\s+(?:hops?|levels?|layers?|deep)\b", re.IGNORECASE)

_BREADTH_PATTERNS = [
    re.compile(r"\bbreadth\s*(?:of\s*)?(\d)\b", re.IGNORECASE),
    re.compile(r"\b(\d)\s*(?:leads?|branches?)(?:\s*per(?:\s*hop)?)?\b", re.IGNORECASE),
]

_LOCKED_CUE = re.compile(
    r"\b(same\s+(?:person|operator|entity|individual|guy|owner|actor)|one\s+and\s+the\s+same|"
    r"all\s+the\s+same|confirmed\s+same|known\s+to\s+be\s+the\s+same|these\s+are\s+all|"
    r"all\s+belong\s+to|belongs?\s+to\s+the\s+same|locked\s+profile|known\s+alias(?:es)?)\b",
    re.IGNORECASE,
)
_QUESTION_START = re.compile(
    r"^\s*(is|are|was|were|does|do|did|who|whose|whether|could|can|how|which|what|should|has|have)\b",
    re.IGNORECASE,
)

# Words that are pure run-control / phrasing noise: an extracted "company/username" made only of
# these (plus stopwords/numbers) is a parser artifact of the command phrasing, not a real selector.
_CONTROL_WORDS = {
    "go", "run", "dig", "dive", "deep", "deeper", "thorough", "thoroughly", "exhaustive", "indepth",
    "heavy", "full", "send", "stone", "unturned", "leave", "everything", "quick", "quickly", "fast",
    "rapid", "rapidly", "light", "lightweight", "brief", "briefly", "glance", "skim", "triage",
    "scan", "look", "first", "wide", "wider", "widen", "broad", "broaden", "narrow", "focused",
    "tight", "net", "cast", "minimal", "main", "many", "possible", "hops", "hop", "levels", "level",
    "layers", "layer", "depth", "breadth", "leads", "branches", "branch", "per", "map", "footprint",
    "take", "please", "check", "investigate", "trace", "find", "show", "me", "pull", "search",
    "just", "one", "two", "three", "four",
}
_STOP_FOR_HYP = {
    "a", "an", "the", "of", "on", "for", "into", "this", "that", "it", "please", "me", "my", "to",
    "at", "in", "and", "with", "about", "as", "by", "from", "up", "out", "its",
}


class InterpretedCommand(BaseModel):
    """Result of turning a plain-language instruction into a runnable investigation request."""

    packet: CaseIntakePacket
    understanding: str = ""  # one-line, human-readable "here's what I'll do"
    notes: List[str] = Field(default_factory=list)  # inferences/assumptions worth surfacing
    is_actionable: bool = False  # False when no selector or hypothesis could be extracted
    # Whether each run parameter was driven by the language (vs. left at default). Lets a UI treat
    # its gear/depth/breadth controls as overrides that apply only when the text didn't specify.
    gear_from_language: bool = False
    depth_from_language: bool = False
    breadth_from_language: bool = False


def _tokens(entry: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", entry.lower())


def _is_pure_control(entry: str) -> bool:
    toks = _tokens(entry)
    if not toks:
        return True
    return all(t in _CONTROL_WORDS or t in _STOP_FOR_HYP or t.isdigit() for t in toks)


def _clean_hypothesis(hyp: str, selector_values: Optional[set] = None) -> str:
    """Trim leading/trailing command words and blank out hypotheses that are only phrasing + seeds.

    ``selector_values`` are the already-extracted selectors; they're removed before judging whether
    anything meaningful remains, so "take a quick look at acme.io" leaves no hypothesis while
    "is acme.io the same operator as its token?" keeps one.
    """
    words = hyp.split()
    drop = _CONTROL_WORDS | _STOP_FOR_HYP
    while words and re.sub(r"[^a-z0-9]", "", words[0].lower()) in drop:
        words.pop(0)
    while words and re.sub(r"[^a-z0-9]", "", words[-1].lower()) in drop:
        words.pop()
    cleaned = " ".join(words).strip(" ,.;:?-")

    probe = cleaned.lower()
    for val in sorted(selector_values or set(), key=len, reverse=True):
        if val:
            probe = probe.replace(val.lower(), " ")
    meaningful = [
        w for w in re.findall(r"[a-zA-Z]{3,}", probe)
        if w.lower() not in _CONTROL_WORDS and w.lower() not in _STOP_FOR_HYP
    ]
    return cleaned if len(meaningful) >= 2 else ""


def interpret_command(text: str) -> InterpretedCommand:
    """Turn a free-text instruction into an :class:`InterpretedCommand`.

    Extracts selectors + hypothesis via :meth:`SmartIntakeParser.parse_omni_text`, then infers the
    run profile (gear / depth / breadth / anchor mode) from natural-language cues like "go deep",
    "quick look", "3 hops", "wide net", or "the same operator". Leftover command words are scrubbed
    so phrases like "go deep" never leak in as a bogus company/username seed.
    """
    raw = (text or "").strip()
    if not raw:
        packet = CaseIntakePacket()
        return InterpretedCommand(
            packet=packet,
            understanding="Nothing entered — give me a domain, wallet, @handle, company, email, or a question.",
            notes=[],
            is_actionable=False,
        )

    packet = SmartIntakeParser.parse_omni_text(raw)
    notes: List[str] = []

    # -- infer depth ---------------------------------------------------------------------------
    explicit_depth: Optional[int] = None
    for pat in _DEPTH_PATTERNS:
        m = pat.search(raw)
        if m:
            explicit_depth = int(m.group(1))
            break
    if explicit_depth is None:
        m = _DEPTH_WORD.search(raw)
        if m:
            explicit_depth = _NUM_WORDS[m.group(1).lower()]
    if explicit_depth is not None:
        explicit_depth = max(1, min(4, explicit_depth))

    deep = bool(_DEEP_CUE.search(raw))
    fast = bool(_FAST_CUE.search(raw))

    if explicit_depth is not None:
        depth = explicit_depth
    elif deep and not fast:
        depth = 3
        notes.append("“deep” with no explicit number → depth 3")
    elif fast and not deep:
        depth = 1
        notes.append("“quick/fast” → shallow depth 1")
    else:
        depth = 2

    # -- infer gear ----------------------------------------------------------------------------
    if deep and fast:
        gear = GearMode.DEEP
        notes.append("conflicting speed cues — defaulted to deep gear")
    elif deep:
        gear = GearMode.DEEP
    elif fast:
        gear = GearMode.FAST
    elif depth >= 3:
        gear = GearMode.DEEP
        notes.append(f"depth {depth} → deep gear")
    else:
        gear = GearMode.FAST

    # -- infer breadth -------------------------------------------------------------------------
    explicit_breadth: Optional[int] = None
    for pat in _BREADTH_PATTERNS:
        m = pat.search(raw)
        if m:
            explicit_breadth = int(m.group(1))
            break
    if explicit_breadth is not None:
        breadth = max(2, min(8, explicit_breadth))
    elif _WIDE_CUE.search(raw):
        breadth = 6
        notes.append("“wide net” → breadth 6")
    elif _NARROW_CUE.search(raw):
        breadth = 2
        notes.append("“narrow/focused” → breadth 2")
    else:
        breadth = 4

    # -- infer anchor mode ---------------------------------------------------------------------
    is_question = ("?" in raw) or bool(_QUESTION_START.match(raw))
    if _LOCKED_CUE.search(raw) and not is_question:
        anchor = AnchorMode.LOCKED_PROFILE
        notes.append("asserted same entity → locked-profile mode (link all selectors to one target)")
    else:
        anchor = AnchorMode.CONVERGENCE
        if _LOCKED_CUE.search(raw) and is_question:
            notes.append("phrased as a question → convergence mode (prove IF/HOW the clues connect)")

    # -- scrub command-only selectors & hypothesis ---------------------------------------------
    packet.orgs_or_names = [o for o in packet.orgs_or_names if not _is_pure_control(o)]
    packet.organizations = [o for o in packet.organizations if not _is_pure_control(o)]
    packet.usernames = [u for u in packet.usernames if not _is_pure_control(u.lstrip("@"))]
    if packet.hypothesis:
        selector_values = {
            v.lower()
            for v in (
                packet.domains_or_ips
                + packet.wallets
                + packet.emails
                + packet.phones
                + packet.aircraft_tails
                + packet.orgs_or_names
                + [u.lstrip("@") for u in packet.usernames]
            )
        }
        packet.hypothesis = _clean_hypothesis(packet.hypothesis, selector_values)

    packet.gear = gear
    packet.depth = depth
    packet.breadth = breadth
    packet.anchor_mode = anchor
    if not packet.title:
        packet.title = packet.summary_seed_label()

    is_actionable = packet.total_selectors() > 0 or bool(packet.hypothesis.strip())

    # -- build the human-readable "understanding" line -----------------------------------------
    seeds = packet.all_seed_tuples()
    if is_actionable:
        if seeds:
            shown = "; ".join(f"{lt}:{val}" for lt, val in seeds[:6])
            if len(seeds) > 6:
                shown += f"; +{len(seeds) - 6} more"
            lead = f"Investigate {len(seeds)} selector(s) — {shown}"
        else:
            lead = "Investigate the stated question"
        understanding = (
            f"{lead}  ·  gear={gear.value} depth={depth} breadth={breadth} mode={anchor.value}"
        )
        if packet.hypothesis.strip():
            understanding += f'  ·  hypothesis: "{packet.hypothesis.strip()}"'
        if packet.exclusions:
            understanding += f"  ·  excluding: {', '.join(packet.exclusions)}"
    else:
        understanding = (
            "I couldn't find anything to investigate in that — give me a domain, wallet, @handle, "
            "company, email, aircraft tail (N-number), a local .pdf/.docx, or a question to chase."
        )
        notes.append("no selector or hypothesis detected")

    return InterpretedCommand(
        packet=packet,
        understanding=understanding,
        notes=notes,
        is_actionable=is_actionable,
        gear_from_language=bool(deep or fast or explicit_depth is not None),
        depth_from_language=bool(explicit_depth is not None or deep or fast),
        breadth_from_language=bool(explicit_breadth is not None or _WIDE_CUE.search(raw) or _NARROW_CUE.search(raw)),
    )
