"""Investigator personas: reusable lenses that tune a Bunnyhole run to a line of work.

A persona bundles sensible run defaults (gear / depth / breadth), the domains it cares about
most, whether it leans on sanctions/PEP screening, and a one-line *analyst framing* that rides
along in every result so the output reads in the right register. Personas never change what the
engine is *capable* of — they only set defaults the caller can still override. They pair with
:mod:`bunnyhole.engine.profile`, which remembers the chosen persona plus the operator's watchlist,
jurisdictions and overrides across cases.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List

from pydantic import BaseModel, Field

from bunnyhole.engine.models import DomainCategory, GearMode


class Persona(str, Enum):
    """The investigator lens a run is conducted through."""

    GENERALIST = "generalist"
    JOURNALIST = "journalist"
    COMPLIANCE = "compliance"  # KYC / AML / due-diligence
    THREAT_INTEL = "threat_intel"
    CRYPTO_TRACER = "crypto_tracer"
    PRIVATE_INVESTIGATOR = "pi"  # elite-PI method on the free, lawful, passive layer (see `--pi`)


class PersonaProfile(BaseModel):
    """The tunables a :class:`Persona` carries."""

    key: Persona
    display_name: str
    description: str
    default_gear: GearMode
    default_depth: int
    default_breadth: int
    priority_domains: List[DomainCategory] = Field(default_factory=list)
    emphasize_sanctions: bool = False
    analyst_framing: str = ""


_PERSONAS: Dict[Persona, PersonaProfile] = {
    Persona.GENERALIST: PersonaProfile(
        key=Persona.GENERALIST,
        display_name="Generalist",
        description="Balanced multi-domain investigation with no particular bias.",
        default_gear=GearMode.FAST,
        default_depth=2,
        default_breadth=4,
        priority_domains=[
            DomainCategory.OSINT,
            DomainCategory.FIAT,
            DomainCategory.ONCHAIN,
            DomainCategory.JOURNALISM,
        ],
        emphasize_sanctions=False,
        analyst_framing="Balanced multi-domain lead development; follow the strongest selectors first.",
    ),
    Persona.JOURNALIST: PersonaProfile(
        key=Persona.JOURNALIST,
        display_name="Investigative Journalist",
        description="Public-interest accountability: sourcing, narrative laundering, scrubbed-page provenance.",
        default_gear=GearMode.FAST,
        default_depth=2,
        default_breadth=5,
        priority_domains=[DomainCategory.JOURNALISM, DomainCategory.OSINT, DomainCategory.FIAT],
        emphasize_sanctions=False,
        analyst_framing=(
            "Public-interest accountability: establish sourcing and provenance, watch for narrative "
            "laundering and scrubbed claims, and keep every assertion receipt-backed and publishable."
        ),
    ),
    Persona.COMPLIANCE: PersonaProfile(
        key=Persona.COMPLIANCE,
        display_name="KYC / AML Due Diligence",
        description="Onboarding & EDD: beneficial ownership, sanctions/PEP exposure, adverse media.",
        default_gear=GearMode.DEEP,
        default_depth=3,
        default_breadth=4,
        priority_domains=[DomainCategory.FIAT, DomainCategory.ONCHAIN, DomainCategory.JOURNALISM],
        emphasize_sanctions=True,
        analyst_framing=(
            "KYC/AML due diligence: resolve beneficial ownership, screen for sanctions/PEP exposure and "
            "adverse media, and record a defensible, auditable trail. Leads, not an onboarding decision."
        ),
    ),
    Persona.THREAT_INTEL: PersonaProfile(
        key=Persona.THREAT_INTEL,
        display_name="Threat Intelligence / CTI",
        description="Infrastructure pivoting, breach exposure, and actor attribution.",
        default_gear=GearMode.FAST,
        default_depth=2,
        default_breadth=6,
        priority_domains=[DomainCategory.OSINT, DomainCategory.JOURNALISM],
        emphasize_sanctions=False,
        analyst_framing=(
            "Infrastructure & attribution: pivot across DNS/CT/certs, breach and infostealer exposure, "
            "and pattern-of-life signals; separate shared-infrastructure coincidence from real overlap."
        ),
    ),
    Persona.CRYPTO_TRACER: PersonaProfile(
        key=Persona.CRYPTO_TRACER,
        display_name="On-Chain Fund Tracer",
        description="Follow the money on-chain: clustering, bridges, mixers, and CEX off-ramps.",
        default_gear=GearMode.DEEP,
        default_depth=3,
        default_breadth=5,
        priority_domains=[DomainCategory.ONCHAIN, DomainCategory.OSINT, DomainCategory.FIAT],
        emphasize_sanctions=True,
        analyst_framing=(
            "On-chain fund-flow tracing: cluster first-funder and deposit-sweep addresses, follow bridges "
            "and mixers to re-convergence, and flag sanctioned addresses and CEX off-ramps for referral."
        ),
    ),
    Persona.PRIVATE_INVESTIGATOR: PersonaProfile(
        key=Persona.PRIVATE_INVESTIGATOR,
        display_name="Private Investigator (PI)",
        description="Elite-PI method on the free, lawful, passive layer: vetted purpose, identity first, custodians named.",
        default_gear=GearMode.DEEP,
        default_depth=3,
        default_breadth=4,
        priority_domains=[DomainCategory.FIAT, DomainCategory.OSINT, DomainCategory.JOURNALISM],
        emphasize_sanctions=True,
        analyst_framing=(
            "Elite-PI method: scope the decision, vet purpose, resolve identity before inferring links, "
            "corroborate across independent sources, log negatives, name the custodian for what public data "
            "cannot reach. Leads, not verdicts."
        ),
    ),
}


class UnknownPersonaError(ValueError):
    """A persona key that is not one of :func:`persona_keys`. ``str()`` lists the valid keys."""

    def __init__(self, value: object) -> None:
        self.value = value
        super().__init__(f"Unknown persona {str(value)!r}. Valid personas: {', '.join(persona_keys())}")


def parse_persona(value: "Persona | str") -> Persona:
    """Strict: the :class:`Persona` for ``value`` (case-insensitive, surrounding spaces ignored).

    Raises :class:`UnknownPersonaError` for anything else. Use this at user-facing boundaries (CLI flags, API
    input); :func:`coerce_persona` stays lenient for stored/internal values.
    """
    if isinstance(value, Persona):
        return value
    try:
        return Persona(str(value).strip().lower())
    except ValueError:
        raise UnknownPersonaError(value) from None


def coerce_persona(value: "Persona | str | None") -> Persona:
    """Best-effort: turn a string/enum/None into a :class:`Persona`, defaulting to GENERALIST.

    Lenient by design (stored profiles, internal callers). User input should go through :func:`parse_persona`.
    """
    if value is None:
        return Persona.GENERALIST
    if isinstance(value, Persona):
        return value
    try:
        return Persona(str(value).strip().lower())
    except ValueError:
        return Persona.GENERALIST


def get_persona(value: "Persona | str | None") -> PersonaProfile:
    """Return the :class:`PersonaProfile` for a persona key (string or enum), defaulting to GENERALIST."""
    return _PERSONAS[coerce_persona(value)]


def list_personas() -> List[PersonaProfile]:
    """All personas in a stable, display-friendly order (generalist first)."""
    return [_PERSONAS[p] for p in Persona]


def persona_keys() -> List[str]:
    """The valid persona key strings (for CLI choices / validation)."""
    return [p.value for p in Persona]
