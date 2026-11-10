"""PI stream, person subject: the two-anchor rule for candidates a name search produced.

A name-derived pivot (a Keybase or GitHub user found by a name token, a sanctions-list entry or a PEP record that
matched on a name) is a *candidate*, not a finding. The PI stream's rule (docs/PI_STREAM.md, identity resolution)
is that a name is never an identity, so a candidate is linked to a person subject only when

1. its name is a compatible FULL name (a surname each, the surnames agree, the given names are compatible: see
   :func:`bunnyhole.engine.pi_identity.full_names_compatible`), and
2. for an account, at least one more anchor agrees: a shared domain, email, username or company.

Anything else is a *weak name match, not linked*: it is recorded on the graph as a set-aside candidate (kept in the
JSON result and named in the identity notes), never as a node or an edge, so no path, broker or predicted-link
table can run through it. Pure and deterministic: no network, no model calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

from bunnyhole.engine.pi_identifiers import is_free_mail_address, looks_like_natural_person_name
from bunnyhole.engine.pi_identity import full_names_compatible, surname_of
from bunnyhole.engine.pi_relevance import name_match_level

WEAK_MATCH_PREFIX = "weak name match, not linked"
_STRONG_COMPANY_LEVELS = ("exact", "strong")
_MIN_DOMAIN_LABEL_CHARS = 4
_SECOND_LEVEL_LABELS = frozenset({"co", "com", "org", "net", "gov", "ac", "edu"})
_HANDLE_IN_LABEL = re.compile(r"@([\w.\-]+)")

#: Platform-owned accounts (the company's own page). They are hubs every profile touches, never evidence about a
#: person, so they are not an endpoint, a broker or a shared intermediary of any analytics table.
GENERIC_PLATFORM_HANDLES = frozenset(
    {
        "github", "gitlab", "bitbucket", "twitter", "x", "facebook", "meta", "instagram", "linkedin", "youtube",
        "google", "microsoft", "apple", "amazon", "reddit", "medium", "wordpress", "wikipedia", "telegram",
        "discord", "tiktok", "pinterest", "keybase", "npm", "docker", "stackoverflow", "slack", "paypal",
        "cloudflare", "gravatar", "wikimedia", "mastodon", "bluesky",
    }
)


def normalize_host(value: str) -> str:
    """Lowercase host of a URL, bare domain or ``www.`` form; ``""`` when there is none."""
    text = (value or "").strip().lower()
    if not text:
        return ""
    host = urlsplit(text if "//" in text else f"//{text}").hostname or ""
    return host.removeprefix("www.")


def _domain_label(host: str) -> str:
    """The registrable label of a host (``roecorp`` for ``www.roecorp.co.uk``), or ``""``."""
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return ""
    label = parts[-2]
    if label in _SECOND_LEVEL_LABELS and len(parts) >= 3:
        label = parts[-3]
    return label


@dataclass(frozen=True)
class SubjectAnchors:
    """What the investigator supplied about a person subject: the full names and every non-name anchor."""

    names: Tuple[str, ...] = ()  # person-looking full names
    companies: Tuple[str, ...] = ()  # organisation-looking names given next to the person
    domains: Tuple[str, ...] = ()
    emails: Tuple[str, ...] = ()
    usernames: Tuple[str, ...] = ()
    phones: Tuple[str, ...] = ()

    @classmethod
    def from_selectors(cls, selectors: Mapping[str, Sequence[str]]) -> "SubjectAnchors":
        """Build from the PI selector dict (``names``, ``organizations``, ``domains``, ``emails``, ``usernames``...)."""

        def clean(key: str) -> List[str]:
            raw = selectors.get(key) or []
            values = [raw] if isinstance(raw, str) else list(raw)
            return [str(v).strip() for v in values if v is not None and str(v).strip()]

        names: List[str] = []
        companies: List[str] = []
        for text in clean("names") + clean("organizations"):
            (names if looks_like_natural_person_name(text) else companies).append(text)
        emails = [e.lower() for e in clean("emails")]
        domains = [h for h in (normalize_host(d) for d in clean("domains")) if h]
        domains += [
            e.rsplit("@", 1)[1] for e in emails if "@" in e and not is_free_mail_address(e)
        ]  # a work address's domain is the subject's domain
        return cls(
            names=tuple(dict.fromkeys(names)),
            companies=tuple(dict.fromkeys(companies)),
            domains=tuple(dict.fromkeys(domains)),
            emails=tuple(dict.fromkeys(emails)),
            usernames=tuple(dict.fromkeys(u.lstrip("@").lower() for u in clean("usernames"))),
            phones=tuple(dict.fromkeys(clean("phones"))),
        )

    def is_explicit_username(self, handle: str) -> bool:
        """True when the investigator supplied this handle: it is an anchor in its own right, not a name guess."""
        return (handle or "").strip().lstrip("@").lower() in self.usernames


@dataclass(frozen=True)
class AccountFacts:
    """What a platform profile says about itself (only public profile fields)."""

    platform: str
    handle: str
    display_name: str = ""
    company: str = ""
    websites: Tuple[str, ...] = ()  # profile URL, blog, signed DNS or web-site proofs
    emails: Tuple[str, ...] = ()
    linked_handles: Tuple[str, ...] = ()  # usernames the profile proves or names on other platforms


@dataclass(frozen=True)
class AnchorVerdict:
    attach: bool
    anchors: Tuple[str, ...] = ()  # what agreed, for the receipt text
    detail: str = ""  # why it was not linked ("" when it was)

    @property
    def reason(self) -> str:
        return f"{WEAK_MATCH_PREFIX}: {self.detail}" if self.detail else ""


def account_anchors(subject: SubjectAnchors, facts: AccountFacts) -> List[str]:
    """The non-name anchors (shared domain, email, username, company) a profile has in common with the subject."""
    found: List[str] = []
    hosts = {h for h in (normalize_host(w) for w in facts.websites) if h}
    hosts |= {e.rsplit("@", 1)[1].lower() for e in facts.emails if "@" in e and not is_free_mail_address(e)}
    for domain in subject.domains:
        if any(h == domain or h.endswith(f".{domain}") for h in hosts):
            found.append(f"domain {domain}")
    shared_emails = {e.lower() for e in facts.emails} & set(subject.emails)
    found += [f"email {e}" for e in sorted(shared_emails)]
    handles = {h.strip().lstrip("@").lower() for h in (facts.handle, *facts.linked_handles) if h}
    found += [f"username {u}" for u in sorted(handles & set(subject.usernames))]
    company = (facts.company or "").strip().lstrip("@").strip()
    if company:
        references = list(subject.companies) + [
            label for label in (_domain_label(d) for d in subject.domains) if len(label) >= _MIN_DOMAIN_LABEL_CHARS
        ]
        if any(name_match_level(ref, company) in _STRONG_COMPANY_LEVELS for ref in references):
            found.append(f"company {company}")
    return found


def judge_account(subject: SubjectAnchors, facts: AccountFacts) -> AnchorVerdict:
    """Attach a name-derived account only on a compatible full name plus one more anchor."""
    who = f"{facts.platform} @{facts.handle}"
    name = (facts.display_name or "").strip()
    name_ok = bool(name) and any(full_names_compatible(subject_name, name) for subject_name in subject.names)
    anchors = tuple(account_anchors(subject, facts))
    if name_ok and anchors:
        return AnchorVerdict(attach=True, anchors=anchors)
    if not name:
        detail = f"{who} shows no name, so the handle (guessed from a name token) is not an anchor"
    elif not name_ok and len(name.split()) < 2:
        detail = f"{who} is named '{name}' (given-name match only, no surname)"
    elif not name_ok:
        detail = f"{who} is named '{name}', which is not the subject's full name"
    else:
        detail = (
            f"{who} has the subject's full name but no second anchor (shared domain, email, username or company) agrees"
        )
    return AnchorVerdict(attach=False, detail=detail)


def judge_listing(subject: SubjectAnchors, listed_names: Iterable[str], *, list_name: str = "") -> AnchorVerdict:
    """A sanctions or PEP entry counts for the subject only when one listed name is a compatible full name.

    A match on given-name tokens only, or a different spelling of the surname, is a weak name match: it is reported
    (with the existing "verify identifiers on the primary list" wording on the receipt) but never linked.
    """
    names = [n for n in dict.fromkeys(str(n).strip() for n in listed_names) if n]
    if any(full_names_compatible(s, n) for s in subject.names for n in names):
        return AnchorVerdict(attach=True, anchors=("full name",))
    surnames = {part for s in subject.names for part in surname_of(s).replace("-", " ").split() if part}
    shown = f"'{names[0]}'" if names else "the entry"
    where = f" on {list_name}" if list_name else ""
    if not surnames:
        detail = f"{shown}{where}: no full person name to compare with"
    elif any(set(re.findall(r"\w+", n.lower())) & surnames for n in names):
        detail = f"{shown}{where}: the surname agrees but no listed name is a compatible full name"
    else:
        detail = (
            f"{shown}{where} lacks the subject's surname (given-name tokens or a different spelling only); "
            "name match only, verify identifiers on the primary list if the subject may be listed"
        )
    return AnchorVerdict(attach=False, detail=detail)


def is_generic_platform_account(entity_type: str, node_id: str, label: str, attributes: Mapping[str, Any]) -> bool:
    """A platform's own account (``@github``): never an endpoint, broker or intermediary of an analytics table."""
    if str(entity_type).lower() != "account":
        return False
    candidates = [str((attributes or {}).get("handle") or "")]
    if node_id.startswith("account:"):
        candidates.append(node_id.rsplit(":", 1)[-1])
    candidates += _HANDLE_IN_LABEL.findall(label or "")
    return any(c.strip().lstrip("@").lower() in GENERIC_PLATFORM_HANDLES for c in candidates if c.strip())


def set_aside_notes(candidates: Sequence[Mapping[str, Any]], limit: int = 3) -> List[str]:
    """Identity-note lines for the set-aside candidates (the rest are counted), so none is dropped silently."""
    notes: List[str] = []
    for candidate in candidates[:limit]:
        reason = str(candidate.get("reason") or WEAK_MATCH_PREFIX)
        notes.append(
            f"{reason[:1].upper()}{reason[1:]} [{candidate.get('tool') or 'source'}]; kept in the JSON result "
            "(set_aside_candidates), not in the graph"
        )
    if len(candidates) > limit:
        notes.append(f"+{len(candidates) - limit} more weak name match(es), not linked (see set_aside_candidates)")
    return notes


def candidate_record(
    kind: str, label: str, tool: str, source_url: str, verdict: AnchorVerdict, receipts: Sequence[Any] = ()
) -> Dict[str, Any]:
    """The JSON row for a set-aside candidate (receipts are dumped so the evidence hash is kept)."""
    return {
        "kind": kind,
        "label": label,
        "tool": tool,
        "source_url": source_url,
        "reason": verdict.reason,
        "receipts": [r.model_dump(mode="json") if hasattr(r, "model_dump") else dict(r) for r in receipts],
    }


__all__ = [
    "GENERIC_PLATFORM_HANDLES", "WEAK_MATCH_PREFIX", "AccountFacts", "AnchorVerdict", "SubjectAnchors",
    "account_anchors", "candidate_record", "is_generic_platform_account", "judge_account", "judge_listing",
    "normalize_host", "set_aside_notes",
]
