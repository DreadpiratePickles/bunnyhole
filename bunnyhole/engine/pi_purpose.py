"""PI permissible-purpose allowlist and whole-engagement free-text screening.

A phrase blocklist can never reach full recall, so an engagement needs an attested category from a short allowlist
(:class:`PurposeCategory`) before any search runs. Person subjects get a narrower list and always need a valid matter
reference. There is deliberately no employment, tenancy, credit or insurance category: eligibility decisions are
refused by construction. The phrase screens stay as a cross-check, now over EVERY free-text field of the engagement.

The category is attested by the operator. Bunnyhole cannot verify it; a false declaration passes the allowlist and
only the phrase screens remain. A safety net, not a guarantee.
"""

from __future__ import annotations

from typing import List, Mapping, Sequence

from bunnyhole.engine.pi_credentials import scrub_credential_text_full
from bunnyhole.engine.pi_gates import (
    MAX_SCREEN_CHARS,
    is_valid_matter_ref,
    require_screenable,
    screen_text,
)
from bunnyhole.engine.pi_types import (
    PERSON_PURPOSE_CATEGORIES,
    CaseType,
    PIPurposeError,
    PurposeCategory,
    coerce_purpose_category,
    purpose_category_values,
)

_CHUNK_CHARS = 3500
_CHUNK_OVERLAP_CHARS = 300
_FIELD_SEPARATOR = " ; "


def require_purpose_category(value: object) -> PurposeCategory:
    """The attested :class:`PurposeCategory`, or a :class:`PIPurposeError` that lists every valid value."""
    category = coerce_purpose_category(value)
    if category is not None:
        return category
    given = str(value or "").strip()
    problem = f"{given!r} is not a permissible purpose category" if given else "A purpose category is required"
    raise PIPurposeError(
        f"{problem}. Declare what the engagement is for with --purpose-category, one of: "
        f"{purpose_category_values()}. There is no category for employment, tenancy, credit or insurance "
        "decisions: those are FCRA-regulated and Bunnyhole will not run them."
    )


def require_person_basis(category: PurposeCategory, subject_is_person: bool, matter_ref: str) -> None:
    """A natural-person subject needs a person-eligible category AND a valid matter reference.

    Entity subjects may use any category and need no reference here (a supplied reference is still format-checked
    by ``require_matter_ref``).
    """
    if not subject_is_person:
        return
    if category not in PERSON_PURPOSE_CATEGORIES:
        allowed = ", ".join(c.value for c in PurposeCategory if c in PERSON_PURPOSE_CATEGORIES)
        raise PIPurposeError(
            f"The category {category.value!r} is not available when the subject is a private person. A person may "
            f"be investigated only under: {allowed}. For a company, use --subject-type entity."
        )
    if not (matter_ref or "").strip():
        raise PIPurposeError(
            f"Investigating a private person under {category.value!r} needs a matter reference: a case number, "
            "contract or judgment reference that shows the legitimate matter. Add --matter-ref."
        )
    if not is_valid_matter_ref(matter_ref):
        raise PIPurposeError(
            f"The matter reference {matter_ref.strip()!r} does not look like a real case, contract or judgment "
            "reference (at least 5 characters, not a placeholder, with a digit or a 'v.'/'vs' party pair)."
        )


def _chunks(text: str) -> List[str]:
    if len(text) <= _CHUNK_CHARS:
        return [text]
    step = _CHUNK_CHARS - _CHUNK_OVERLAP_CHARS
    return [text[start:start + _CHUNK_CHARS] for start in range(0, len(text), step)]


def screen_free_texts(
    texts: Sequence[str],
    case_type: CaseType,
    subject_is_person: bool,
    matter_ref: str,
    purpose_category: str,
) -> None:
    """Run the eligibility, motive and pursuit screens over the concatenation of every free-text field.

    ``texts`` is the purpose, client, hypothesis, pasted notes, matter reference and every selector value, so moving
    a wording into another field no longer bypasses a screen. The fields are joined (a phrase split across two
    fields is still caught, at the cost of an occasional cross-field false positive) and long input is screened in
    overlapping chunks, because the disguised-spelling pass reads only the first few thousand characters of a text.
    A keyword safety net, not a guarantee.
    """
    seen: List[str] = []
    for text in texts:
        clean = (text or "").strip()
        if clean and clean not in seen:
            seen.append(clean)
    if not seen:
        return
    joined = _FIELD_SEPARATOR.join(seen)
    require_screenable(joined)  # refuses over MAX_SCREEN_CHARS: bounded work, and no part of the text is skipped
    screened: set[str] = set()
    for chunk in _chunks(joined):
        if chunk in screened:
            continue  # an identical chunk already passed every screen
        screen_text(chunk, case_type, subject_is_person, matter_ref, purpose_category)
        screened.add(chunk)


def require_no_credentials(fields: Mapping[str, str]) -> None:
    """Refuse credential-shaped text in the engagement record's own fields (purpose, client, matter reference).

    ``fields`` maps the flag name (``--client``) to its text. The secret is never echoed in the message. Credentials
    in the intake dump or packet are dropped and scrubbed elsewhere; these three fields are stored verbatim in the
    engagement and the report, so they must not carry one.
    """
    for flag, text in fields.items():
        if not (text or "").strip():
            continue
        if len(text) > MAX_SCREEN_CHARS:
            continue  # the length gate refuses it with its own message
        _clean, found, _secrets = scrub_credential_text_full(text)
        if found:
            raise PIPurposeError(
                f"credential-shaped text found in {flag}: remove it; credentials are not used in PI mode."
            )
