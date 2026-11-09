"""Base types shared by the PI core models and the purpose gates (kept separate to avoid a circular import)."""

from __future__ import annotations

from enum import Enum


class CaseType(str, Enum):
    """The kind of engagement; selects the playbook, expected source classes and stop rule."""

    LOCATE = "locate"
    BACKGROUND = "background"
    ASSET_SEARCH = "asset_search"
    DUE_DILIGENCE = "due_diligence"
    FRAUD_SCREEN = "fraud_screen"
    MISSING_PERSON = "missing_person"


class PurposeCategory(str, Enum):
    """The permissible-purpose allowlist: the only reasons an engagement may be opened.

    There is deliberately no employment, tenancy, credit or insurance category: eligibility decisions are refused by
    construction. The category is attested by the operator (Bunnyhole cannot verify it); the phrase screens remain
    as a cross-check against the purpose text.
    """

    JUDGMENT_ENFORCEMENT = "judgment_enforcement"
    LITIGATION_SUPPORT = "litigation_support"
    SERVICE_OF_PROCESS = "service_of_process"
    ASSET_RECOVERY = "asset_recovery"
    FRAUD_INVESTIGATION = "fraud_investigation"
    COUNTERPARTY_DUE_DILIGENCE = "counterparty_due_diligence"
    REGULATORY_COMPLIANCE_KYC = "regulatory_compliance_kyc"
    JOURNALISM_PUBLIC_INTEREST = "journalism_public_interest"
    AUTHORITIES_REFERRAL = "authorities_referral"


#: Categories open to a natural-person subject. Each one also needs a valid matter reference.
PERSON_PURPOSE_CATEGORIES: frozenset[PurposeCategory] = frozenset(
    {
        PurposeCategory.JUDGMENT_ENFORCEMENT,
        PurposeCategory.LITIGATION_SUPPORT,
        PurposeCategory.SERVICE_OF_PROCESS,
        PurposeCategory.ASSET_RECOVERY,
        PurposeCategory.FRAUD_INVESTIGATION,
        PurposeCategory.AUTHORITIES_REFERRAL,
        PurposeCategory.COUNTERPARTY_DUE_DILIGENCE,
    }
)

#: The only categories under which a former-partner relationship term is tolerated (non-locate person cases).
RELATIONSHIP_TERM_CATEGORIES: frozenset[PurposeCategory] = frozenset(
    {PurposeCategory.ASSET_RECOVERY, PurposeCategory.LITIGATION_SUPPORT}
)


def coerce_purpose_category(value: object) -> "PurposeCategory | None":
    """The category named by ``value`` (a member, or text in any case with spaces or hyphens), else ``None``."""
    if isinstance(value, PurposeCategory):
        return value
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return PurposeCategory(text)
    except ValueError:
        return None


def purpose_category_values() -> str:
    """Comma-separated valid category values, in declaration order (for error messages and help text)."""
    return ", ".join(category.value for category in PurposeCategory)


class PIPurposeError(ValueError):
    """Raised by every PI gate. The message is actionable and shown to the user as-is."""


class PIEligibilityError(PIPurposeError):
    """The purpose reads like an eligibility decision (employment, tenancy, credit, insurance): FCRA territory."""


class FindingLabel(str, Enum):
    CONFIRMED = "confirmed"  # 3+ independent sources
    PROBABLE = "probable"  # 2 independent sources
    LEAD = "lead"  # 1 source
