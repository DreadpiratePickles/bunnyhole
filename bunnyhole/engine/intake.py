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
from typing import List
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

        # 1. Exclusions: -domain.com or exclude:xyz or ignore:xyz
        for m in re.finditer(r"(?:^|\s)(?:-|(?:exclude|ignore):)([a-zA-Z0-9_.\-@]{3,64})", working):
            exclusions.append(m.group(1).strip())
            working = working.replace(m.group(0), " ")

        # 2. Local evidence files (.pdf / .docx)
        for m in re.finditer(r"([/\w.\-~]+\.(?:pdf|docx))\b", working, flags=re.IGNORECASE):
            evidence_files.append(m.group(1).strip())
            working = working.replace(m.group(0), " ")

        # 3. Leaked Credentials / Combo-list entries (email:password or user:password, excluding http:// or https://)
        for m in re.finditer(
            r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+:[^\s,;\"']{4,64})(?=\s|$|[,;])",
            working,
        ):
            cred = m.group(1)
            credentials.append(cred)
            email_part = cred.split(":", 1)[0]
            emails.append(email_part)
            working = working.replace(m.group(0), " ")

        # 4. Standalone Emails
        for m in re.finditer(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", working):
            emails.append(m.group(1))
            working = working.replace(m.group(0), " ")

        # 5. EVM Wallets (0x...), ENS names (*.eth), and Bitcoin Wallets (bc1...)
        for m in re.finditer(r"\b(0x[a-fA-F0-9]{40})\b", working):
            wallets.append(m.group(1))
            working = working.replace(m.group(0), " ")

        for m in re.finditer(r"\b([a-zA-Z0-9_-]{3,40}\.eth)\b", working, flags=re.IGNORECASE):
            wallets.append(m.group(1).lower())
            working = working.replace(m.group(0), " ")

        for m in re.finditer(r"\b((?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59})\b", working):
            wallets.append(m.group(1))
            working = working.replace(m.group(0), " ")

        # 6. IPv4 Addresses
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", working):
            domains_or_ips.append(m.group(1))
            working = working.replace(m.group(0), " ")

        # 7. URLs & Domains
        for m in re.finditer(r"\b(https?://[^\s,;\"')]+)\b", working):
            parsed = urlparse(m.group(1))
            if parsed.netloc:
                domains_or_ips.append(parsed.netloc.lower())
            working = working.replace(m.group(0), " ")

        for m in re.finditer(
            r"\b([a-zA-Z0-9-]{2,63}\.(?:com|org|io|net|co|ai|xyz|fi|gg|app|dev|me|info|biz|ch|uk|de|ky|vg|pa))\b",
            working,
            flags=re.IGNORECASE,
        ):
            domains_or_ips.append(m.group(1).lower())
            working = working.replace(m.group(0), " ")

        # 8. FAA Aircraft Tail Numbers (e.g. N628TS)
        for m in re.finditer(r"\b(N[1-9][0-9A-HJ-NP-Z]{1,4})\b", working):
            tail = m.group(1).upper()
            aircraft_tails.append(tail)
            orgs_or_names.append(tail)
            working = working.replace(m.group(0), " ")

        # 9. Phone Numbers (e.g., +1-415-555-0199, +44 20 7946 0921, (415) 555-0199)
        for m in re.finditer(r"(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}\b", working):
            raw_ph = m.group(0).strip()
            digits = re.sub(r"\D", "", raw_ph)
            if 10 <= len(digits) <= 15:
                norm_ph = f"+{digits}" if raw_ph.startswith("+") or len(digits) > 10 else f"+1{digits}"
                phones.append(norm_ph)
                working = working.replace(m.group(0), " ")

        # 10. Explicit @Handles
        for m in re.finditer(r"(?:^|\s)@([a-zA-Z0-9_.-]{3,30})\b", working):
            usernames.append(f"@{m.group(1)}")
            working = working.replace(m.group(0), " ")

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
