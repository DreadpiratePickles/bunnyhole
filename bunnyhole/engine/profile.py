"""Remembered investigator context: a persisted profile that follows the operator across cases.

The profile stores the chosen :class:`~bunnyhole.engine.personas.Persona`, a display name, a
**watchlist** of recurring selectors (so a case that surfaces a known target is flagged), standing
**jurisdictions** of interest, **default exclusions**, and optional run-parameter overrides. It
lives at ``~/.bunnyhole/profile.json`` (same secured config dir as the keys vault and case DB).

Nothing here reaches out to the network and nothing runs automatically — the profile only supplies
*defaults* the caller may override, plus the watchlist cross-reference applied to a finished graph.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from bunnyhole.arsenal.manager import BUNNYHOLE_CONFIG_DIR
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.personas import Persona, PersonaProfile, coerce_persona, get_persona

PROFILE_PATH: Path = BUNNYHOLE_CONFIG_DIR / "profile.json"


class InvestigatorProfile(BaseModel):
    """The operator's remembered context. Persona defaults are overridden by any *_override set."""

    persona: Persona = Persona.GENERALIST
    display_name: str = ""
    watchlist: List[str] = Field(default_factory=list)  # recurring selectors (domains/wallets/handles/orgs)
    jurisdictions: List[str] = Field(default_factory=list)  # ISO-ish country codes of standing interest
    default_exclusions: List[str] = Field(default_factory=list)  # negative scope folded into every case
    gear_override: Optional[GearMode] = None
    depth_override: Optional[int] = None
    breadth_override: Optional[int] = None
    notes: str = ""

    def persona_profile(self) -> PersonaProfile:
        return get_persona(self.persona)

    def analyst_framing(self) -> str:
        return self.persona_profile().analyst_framing

    def effective_run_params(self) -> Tuple[GearMode, int, int]:
        """The run defaults this profile implies: persona defaults, with any explicit override winning."""
        pp = self.persona_profile()
        gear = self.gear_override or pp.default_gear
        depth = self.depth_override if self.depth_override is not None else pp.default_depth
        breadth = self.breadth_override if self.breadth_override is not None else pp.default_breadth
        return gear, max(1, min(4, depth)), max(2, min(8, breadth))


def resolve_run_params(
    profile: InvestigatorProfile,
    gear: Optional[GearMode] = None,
    depth: Optional[int] = None,
    breadth: Optional[int] = None,
) -> Tuple[GearMode, int, int]:
    """Fill in gear/depth/breadth from the profile wherever the caller left them unset (None)."""
    eg, ed, eb = profile.effective_run_params()
    return (
        gear or eg,
        ed if depth is None else max(1, min(4, depth)),
        eb if breadth is None else max(2, min(8, breadth)),
    )


def match_watchlist(nodes: List[Dict[str, Any]], watchlist: List[str]) -> List[Dict[str, Any]]:
    """Cross-reference finished-graph nodes against the watchlist.

    A node hits when a watchlist term appears (case-insensitively) in its id or label — enough to
    say "a recurring target of yours showed up here" without re-running anything. Returns one record
    per (term, node) hit.
    """
    terms = [t.strip().lower() for t in (watchlist or []) if t and t.strip()]
    if not terms:
        return []
    hits: List[Dict[str, Any]] = []
    for node in nodes or []:
        hay = f"{node.get('id', '')} {node.get('label', '')}".lower()
        for term in terms:
            if term in hay:
                hits.append(
                    {
                        "term": term,
                        "node_id": node.get("id", ""),
                        "label": node.get("label", ""),
                        "domain": node.get("domain", ""),
                        "smoke": node.get("smoke_score", 0),
                    }
                )
    return hits


def load_profile(path: Path = PROFILE_PATH) -> InvestigatorProfile:
    """Load the operator's profile, returning a fresh default if it is missing or unreadable."""
    try:
        if not path.exists():
            return InvestigatorProfile()
        data = json.loads(path.read_text(encoding="utf-8"))
        return InvestigatorProfile.model_validate(data)
    except Exception:
        # A corrupt profile must never break an investigation — fall back to defaults.
        return InvestigatorProfile()


def save_profile(profile: InvestigatorProfile, path: Path = PROFILE_PATH) -> None:
    """Persist the profile to disk (creating the secured config dir if needed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:  # pragma: no cover - best-effort on platforms without chmod semantics
        pass
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover
        pass


def add_watch(profile: InvestigatorProfile, selectors: List[str]) -> InvestigatorProfile:
    """Return the profile with ``selectors`` added to the watchlist (de-duplicated, order-preserving)."""
    seen = {w.lower() for w in profile.watchlist}
    for s in selectors:
        s = (s or "").strip()
        if s and s.lower() not in seen:
            profile.watchlist.append(s)
            seen.add(s.lower())
    return profile


def remove_watch(profile: InvestigatorProfile, selectors: List[str]) -> InvestigatorProfile:
    """Return the profile with ``selectors`` removed from the watchlist (case-insensitive)."""
    drop = {s.strip().lower() for s in selectors if s and s.strip()}
    profile.watchlist = [w for w in profile.watchlist if w.lower() not in drop]
    return profile


def set_persona(profile: InvestigatorProfile, persona: "Persona | str") -> InvestigatorProfile:
    """Return the profile with its persona set (coerced; unknown values fall back to generalist)."""
    profile.persona = coerce_persona(persona)
    return profile
