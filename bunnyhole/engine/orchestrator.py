"""Chief Case Director & Recursive Deep-Research Orchestrator (fusing dzhng/deep-research breadth x depth + learnings accumulation with Bunnyhole's 6 Specialist Agents & Link Sleuth)."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from bunnyhole.agents.accountant import AccountantAgent
from bunnyhole.agents.journalist import JournalistAgent
from bunnyhole.agents.link_sleuth import LinkSleuthAgent, extract_entity_stem
from bunnyhole.agents.onchain import OnChainAgent
from bunnyhole.agents.osint import OSINTAgent
from bunnyhole.agents.pi_sources import PISourcesAgent
from bunnyhole.engine.council import InvestigativeCouncil
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.ids import canonical_wallet_id
from bunnyhole.engine.intake import AnchorMode, CaseIntakePacket, SmartIntakeParser
from bunnyhole.engine.models import (
    ConfidenceTier,
    DomainCategory,
    EntityType,
    EvidenceReceipt,
    GearMode,
    GraphEdge,
    GraphNode,
    RelationType,
    SelectorStrength,
)
from bunnyhole.engine.pi import PIEngagement, looks_like_natural_person_name
from bunnyhole.engine.pi_anchoring import SubjectAnchors
from bunnyhole.engine.pi_runtime import (
    BREACH_SKIP_REASON,
    CREDENTIAL_SKIP_REASON,
    PIRunRecorder,
    analytics_exclusions,
    assemble_pi_block,
    make_breach_blocker,
    make_holehe_blocker,
    redact_value,
    run_conflict_check,
    scrub_credential_text,
    selectors_from_seeds,
    strip_packet_credentials,
    with_objective,
)
from bunnyhole.engine.profile import InvestigatorProfile, load_profile, match_watchlist
from bunnyhole.engine.storage import build_case_store
from bunnyhole.engine.synthesizer import InvestigativeSynthesizer

# Compact IANA TLD allowlist: ISO 3166-1 alpha-2 ccTLDs + the common generic TLDs that
# actually appear in investigative data. A label is accepted as a domain only when its final
# label is one of these (or a punycode `xn--` label). This keeps 'node.js' and 'john.smith'
# out of the domain bucket ('js'/'smith' are not real TLDs) with a documented, compact trade-off:
# a genuine but obscure new-gTLD not in this set is read as a general term, not a domain.
_CCTLDS = (
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz "
    "ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk "
    "fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir "
    "is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk "
    "ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl "
    "pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st sv sx sy sz tc td "
    "tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"
)
_GTLDS = (
    "com org net int edu gov mil info biz name pro xyz app dev io ai co me tv cc online site tech store blog "
    "shop live cloud digital network media news agency ventures capital finance fund group global world "
    "foundation llc ltd inc gmbh crypto eth finance exchange wtf gg sh "
)
_IANA_TLDS = frozenset((_CCTLDS + " " + _GTLDS).split())

_EMAIL_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
#: A handle is letter-led and carries at least one of _ . - or a digit, so plain words ('note',
#: 'admin') are not mistaken for credential identifiers.
_HANDLE_RE = re.compile(r"^@?[A-Za-z][A-Za-z0-9_.-]{2,29}$")
_BASE58_CHARS = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
_AIRCRAFT_RE = re.compile(r"^N[1-9][0-9A-HJ-NP-Z]{0,4}$")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_handle_like(ident: str) -> bool:
    return bool(_HANDLE_RE.match(ident)) and (
        ident.startswith("@") or any(c.isdigit() or c in "_.-" for c in ident)
    )


def _is_credential(s: str) -> bool:
    """A credential is ``identifier:secret`` where identifier is a real email or handle and the
    secret is a single non-space, non-trivial token (not a label, port, or ``host:8080``)."""
    if "://" in s or ":" not in s:
        return False
    ident, secret = s.split(":", 1)
    ident = ident.strip()
    if not secret or any(ch.isspace() for ch in secret):
        return False
    if not (_EMAIL_RE.match(ident) or _is_handle_like(ident)):
        return False
    return len(secret) >= 4 and not secret.isdigit()


def _is_bitcoin_address(s: str) -> bool:
    """Real Bitcoin address: bech32 (``bc1``) or base58 (26-35 chars, valid charset, has a letter)."""
    low = s.lower()
    if low.startswith("bc1"):
        return 14 <= len(s) <= 90 and all(c in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" for c in low[3:])
    if s[:1] in ("1", "3"):
        return 26 <= len(s) <= 35 and all(c in _BASE58_CHARS for c in s) and any(c.isalpha() for c in s)
    return False


def _is_aircraft_tail(s: str) -> bool:
    """FAA N-number: reject bare ``N`` + two digits ('N26') that collide with brand names; a real
    tail either carries a letter in its suffix or is at least 4 characters long."""
    u = s.upper()
    if not _AIRCRAFT_RE.match(u):
        return False
    suffix = u[1:]
    return len(u) >= 4 or any(c.isalpha() for c in suffix)


def mask_credential(value: str) -> str:
    """Return a display-safe form of a credential seed: the identifier kept, the secret masked.

    ``ceo@acme.com:hunter2`` -> ``ceo@acme.com:****``. A value without a secret is fully masked.
    """
    v = (value or "").strip()
    if ":" in v:
        ident, _secret = v.split(":", 1)
        if ident:
            return f"{ident}:****"
    return "****"


def _valid_public_suffix(host: str) -> bool:
    labels = host.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1].lower()
    return tld in _IANA_TLDS or tld.startswith("xn--")


def classify_seed_type(seed: str) -> Tuple[str, EntityType, DomainCategory]:
    """Deterministically classify any input seed trace into its primary type and domain."""
    s = seed.strip()
    if s.lower().endswith((".pdf", ".docx")):
        return ("document", EntityType.DOCUMENT, DomainCategory.JOURNALISM)
    # IP (v4 or v6) before credential, so IPv6 literals like '2001:db8::1' are not read as creds.
    if _is_ip_address(s):
        return ("ip", EntityType.IP_HOST, DomainCategory.OSINT)
    if _is_credential(s):
        return ("credential", EntityType.TRACKER_ID, DomainCategory.OSINT)
    if re.match(r"^0x[a-fA-F0-9]{40}$", s) or s.lower().endswith(".eth"):
        return ("wallet", EntityType.CRYPTO_WALLET, DomainCategory.ONCHAIN)
    if _is_bitcoin_address(s):
        return ("bitcoin", EntityType.CRYPTO_WALLET, DomainCategory.ONCHAIN)
    if _is_aircraft_tail(s):
        return ("aircraft", EntityType.AIRCRAFT, DomainCategory.PHYSICAL)
    digits_only = re.sub(r"\D", "", s)
    if (
        (s.startswith("+") or re.match(r"^[\d\s().+-]{10,18}$", s))
        and 10 <= len(digits_only) <= 15
        and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s)  # a dotted-quad (e.g. invalid IP) is not a phone
    ):
        return ("phone", EntityType.PHONE, DomainCategory.OSINT)
    if "@" in s and "." in s.split("@")[-1] and not s.startswith("@") and _EMAIL_RE.match(s):
        return ("email", EntityType.EMAIL, DomainCategory.OSINT)
    if s.startswith(("http://", "https://")):
        host = s.split("//", 1)[1].split("/")[0].split(":")[0]
        if _valid_public_suffix(host):
            return ("domain", EntityType.DOMAIN, DomainCategory.OSINT)
    if " " not in s and re.match(r"^[a-zA-Z0-9.-]+$", s) and _valid_public_suffix(s):
        return ("domain", EntityType.DOMAIN, DomainCategory.OSINT)
    if s.startswith("@") or (
        re.match(r"^[a-zA-Z0-9_.-]{3,30}$", s)
        and not re.match(r"^[\d.]+$", s)
        and any(c.isdigit() or c in "_-" for c in s)
    ):
        return ("username", EntityType.ACCOUNT, DomainCategory.OSINT)
    return ("company", EntityType.ORGANIZATION, DomainCategory.FIAT)


# DexScreener token-name search matches company/person/handle strings against crypto tickers (a "$ROBINCAT" hit for a
# person called Robin Cat is noise, not evidence), so PI mode does not run it for name-driven leads.
_DEX_PI_SKIP = "token-name search is noise for company/person/handle leads; not run in PI mode"


class BunnyholeOrchestrator:
    """
    Executes the recursive dzhng/deep-research Breadth x Depth loop across all 6 investigative agents,
    accumulating structured learnings[], followUpQuestions[], Link Sleuth interconnection paths,
    SQLite Cross-Case Entity Memory hits, Citation-Backed Investigative Synthesis, and Karpathy's
    3-Stage Adversarial LLM Council deliberation.
    """

    def __init__(
        self,
        seed_query: str,
        gear: GearMode = GearMode.FAST,
        max_depth: int = 2,
        initial_breadth: int = 4,
        hypothesis: str = "",
        exclusions: Optional[List[str]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        intake_packet: Optional[CaseIntakePacket] = None,
        profile: Optional[InvestigatorProfile] = None,
        engagement: Optional[PIEngagement] = None,
    ) -> None:
        case_id = f"bh_{uuid.uuid4().hex[:8]}"
        self.seed_query = seed_query.strip()
        # PI mode never uses credential/breach contents: drop them before ANY run logic can see them.
        self._pi_redactions: List[str] = []
        self._pi_credentials_dropped = 0
        # Non-PI runs: the plaintext secret of any `email:secret` seed is kept ONLY here, in memory,
        # for the credential-combo agent. It is masked in every receipt/label and scrubbed from the
        # compiled result and persisted case (see mask_credential / _scrub_result_credentials).
        self._credential_secrets: List[str] = []
        if engagement is not None:
            self.seed_query, seed_tokens = scrub_credential_text(self.seed_query)
            self._pi_redactions += seed_tokens
            self._pi_credentials_dropped += len(seed_tokens)
            if seed_tokens and (not self.seed_query.replace("[credential removed]", "").strip()):
                raise ValueError(
                    "PI mode does not use credential or breach contents, and the seed is only a credential. "
                    "Give the subject's name, entity, domain or another selector instead."
                )
            if intake_packet is not None:
                intake_packet, dropped, tokens = strip_packet_credentials(intake_packet)
                self._pi_redactions += tokens
                self._pi_credentials_dropped += dropped
        self.gear = gear
        self.max_depth = max(1, min(4, max_depth))
        self.initial_breadth = max(2, min(8, initial_breadth))
        if intake_packet and not hypothesis:
            hypothesis = intake_packet.hypothesis
        if intake_packet and not exclusions:
            exclusions = intake_packet.exclusions
        self.graph = InvestigationGraph(
            case_id=case_id,
            seed_query=self.seed_query,
            hypothesis=hypothesis,
            exclusions=exclusions,
        )
        if event_callback:
            self.graph.subscribe(event_callback)

        self.journalist = JournalistAgent(self.graph, gear=self.gear)
        self.accountant = AccountantAgent(self.graph, gear=self.gear)
        self.osint = OSINTAgent(self.graph, gear=self.gear)
        self.onchain = OnChainAgent(self.graph, gear=self.gear)
        self.link_sleuth = LinkSleuthAgent(self.graph, gear=self.gear)
        # Persistence is optional: a corrupt or read-only case DB must not break an investigation.
        # build_case_store recovers (move-aside) or returns a no-op store carrying the reason.
        self.case_store: Any = build_case_store()
        self._persist_error: Optional[str] = getattr(self.case_store, "persist_error", None)
        self.synthesizer = InvestigativeSynthesizer(self.graph)
        self.council = InvestigativeCouncil(self.graph)

        # dzhng/deep-research state accumulators
        self.learnings: List[str] = []
        self.follow_up_questions: List[str] = []
        self.cross_case_hits: List[Dict[str, Any]] = []
        self.synthesis: Dict[str, Any] = {}
        self.council_deliberation: Dict[str, Any] = {}
        self.intake_packet: Optional[Dict[str, Any]] = intake_packet.model_dump() if intake_packet else None
        # Remembered investigator context (persona lens + watchlist). Loads the persisted profile when
        # not supplied; a missing profile yields harmless generalist defaults with no disk writes.
        self.profile: InvestigatorProfile = profile if profile is not None else load_profile()
        self._emphasize_sanctions: bool = self.profile.persona_profile().emphasize_sanctions
        self._sem = asyncio.Semaphore(5)
        # Count of agent-task exceptions swallowed by a gather (non-PI). PI mode records its own via
        # PIRunRecorder, whose wrapper never re-raises, so this stays 0 there (no double counting).
        self._agent_errors: int = 0

        # PI stream (optional). With no engagement none of this exists and behaviour is unchanged.
        self.engagement: Optional[PIEngagement] = with_objective(engagement) if engagement is not None else None
        self.pi_sources: Optional[PISourcesAgent] = None
        self.pi_recorder: Optional[PIRunRecorder] = None
        self._pi_prior_cases: List[Dict[str, Any]] = []
        self._pi_selectors: Dict[str, List[str]] = {}
        self._pi_ownership_links: List[Dict[str, Any]] = []
        self._pi_conflict_checked = False
        self._pi_deep_run: bool = self.gear == GearMode.DEEP  # gates the "no corroborated finding" escalation trigger
        if self.engagement is not None:
            self.pi_sources = PISourcesAgent(self.graph, gear=self.gear)
            self.pi_recorder = PIRunRecorder()
            self._pi_credential_entry: Optional[Any] = None
            self._pi_note_dropped_credentials(0)
            # Breach/infostealer lookups also run inside other OSINT methods (email pivots, domain recon, handle
            # sweeps): shadow them on this instance so nothing in PI mode ever collects breach contents.
            for method, source, target_arg in (
                ("investigate_hudsonrock_infostealer", "hudsonrock", 0),
                ("_scan_leakcheck", "leakcheck", 0),
                ("_lookup_emailrep", "emailrep", 0),
                ("investigate_credential_combo", "credential_combo", 1),
            ):
                setattr(self.osint, method, make_breach_blocker(self.pi_recorder, source, target_arg=target_arg))
            if self.engagement.passive_only:
                # Holehe probes account-recovery flows with the target's email: not passive, so blocked and logged.
                # Shadowed on the instance like the breach blockers above (setattr: mypy rejects assigning a plain
                # function to a method attribute; the blocker's signature mirrors _run_local_arsenal_holehe).
                setattr(self.osint, "_run_local_arsenal_holehe", make_holehe_blocker(self.pi_recorder))  # noqa: B010

    def _pi_note_dropped_credentials(self, dropped: int) -> None:
        """Keep exactly ONE source-log entry for dropped credentials (the value is never echoed)."""
        if self.pi_recorder is None:
            return
        self._pi_credentials_dropped += dropped
        if not self._pi_credentials_dropped:
            return
        detail = (
            f"{self._pi_credentials_dropped} credential entr(y/ies) dropped before the run; "
            f"{CREDENTIAL_SKIP_REASON} (nothing was derived from them, not even the email half)"
        )
        if self._pi_credential_entry is None:
            self.pi_recorder.skip("credentials", "intake", detail)
            self._pi_credential_entry = self.pi_recorder.entries[-1]
        else:
            self._pi_credential_entry.detail = detail

    def _pi_strip_credentials(self, packet: CaseIntakePacket) -> CaseIntakePacket:
        """PI mode: return the packet without credentials/``email:secret`` tokens and log the drop once."""
        if self.engagement is None:
            return packet
        clean, dropped, tokens = strip_packet_credentials(packet)
        self._pi_redactions += tokens
        self._pi_note_dropped_credentials(dropped)
        return clean

    def _pi_skip(self, source: str, target: str, detail: str) -> None:
        if self.pi_recorder is not None:
            self.pi_recorder.skip(source, target, detail)

    def _pi_task(self, source: str, target: str, coro: Any) -> Any:
        """In PI mode wrap a source call so its outcome (hit/negative/skipped/error) is logged; else pass through."""
        if self.pi_recorder is None:
            return coro
        return self.pi_recorder.run(source, target, self.graph, coro)

    async def _pi_collect_psc(self, company_name: str, origin_node_id: str, hop_depth: int) -> None:
        """Companies House PSC lookup; keeps the returned ownership links for the PI ownership walk."""
        assert self.pi_sources is not None
        owners = await self.pi_sources.investigate_companies_house_psc(company_name, origin_node_id, hop_depth)
        self._pi_ownership_links.extend(owners or [])

    def _pi_start_case(self, seed_tuples: List[Tuple[str, str]]) -> None:
        """PI mode: derive selectors and run the conflict check once per case (failures are non-fatal)."""
        if self.engagement is None or self.pi_recorder is None or self._pi_conflict_checked:
            return
        self._pi_conflict_checked = True
        self._pi_selectors = selectors_from_seeds(seed_tuples, self.engagement.subject_is_person)
        if self.engagement.subject_is_person:  # the two-anchor rule for name-derived pivots (pi_anchoring.py)
            self.graph.pi_subject = SubjectAnchors.from_selectors(self._pi_selectors)
        values = [self.seed_query] + [v for lt, v in seed_tuples if lt not in ("credential", "document")]
        self._pi_prior_cases = run_conflict_check(self.case_store, values, self.graph.case_id, self.pi_recorder)

    def _pi_refresh_analytics_exclusions(self) -> None:
        """PI mode: tell the graph which nodes the paths, brokers and predicted-link tables must not run through.

        Uses the relevance scorer the PI report already uses (``pi_relevance``); see ``analytics_exclusions``.
        Safe to repeat: it recomputes from the current graph.
        """
        if self.engagement is None:
            return
        self.graph.analytics_excluded_ids = analytics_exclusions(
            [n.model_dump() for n in self.graph.nodes.values()],
            [e.model_dump() for e in self.graph.edges.values()],
            self._pi_ownership_links,
            self._pi_selectors,
            self.seed_query,
            subject_is_person=self.engagement.subject_is_person,
        )

    def _create_seed_node(self, seed_str: str, hop_depth: int = 0, forced_type: Optional[str] = None) -> Tuple[str, GraphNode]:
        lead_type, ent_type, dom_cat = classify_seed_type(seed_str)
        if forced_type:
            lead_type = forced_type
        clean_val = seed_str.strip()
        # A free-text name classifies as a company (that lead type keeps routing the name to the registry, sanctions
        # and news sources). Under a PI engagement whose subject is a person, a person-shaped name is a Person node:
        # an Organization seed would also make the identity notes and relevance scorer treat the subject as a company.
        node_kind = lead_type
        if (
            lead_type == "company"
            and ent_type == EntityType.ORGANIZATION
            and self.engagement is not None
            and self.engagement.subject_is_person
            and looks_like_natural_person_name(clean_val)
        ):
            ent_type, node_kind = EntityType.PERSON, "person"
        if lead_type == "domain":
            clean_val = clean_val.replace("https://", "").replace("http://", "").split("/")[0].lower()
        if lead_type == "credential" and ":" in clean_val:
            masked_lbl = clean_val.split(":", 1)[0] + ":***"
            # Keep the plaintext secret in memory (only) for the credential-combo agent, and record it
            # for the result/persistence scrub. The engagement==None guard keeps PI mode untouched.
            if self.engagement is None:
                self._credential_secrets.append(clean_val)
                secret = clean_val.split(":", 1)[1].strip()
                if len(secret) >= 6:
                    self._credential_secrets.append(secret)
        else:
            masked_lbl = clean_val
        if lead_type in ("wallet", "bitcoin") and clean_val:
            # the one id the on-chain agent also uses for this wallet (engine/ids.py), so its findings land here
            node_id = canonical_wallet_id("btc" if lead_type == "bitcoin" else "eth", clean_val)
        else:
            node_id = f"{node_kind}:{masked_lbl.lower().replace(' ', '_')[:48]}"
        rcpt = EvidenceReceipt(
            tool="bunnyhole_case_director",
            domain=dom_cat,
            admiralty_code="A1",
            selector_strength=SelectorStrength.STRONG,
            source_url=f"seed://{masked_lbl}",
            extracted_fact=f"Initial investigative anchor '{masked_lbl}' classified as {node_kind.upper()} ({ent_type.value})",
            raw_snippet=f"seed={masked_lbl} | classified_type={node_kind}",
        )
        node = self.graph.upsert_node(
            GraphNode(
                id=node_id,
                label=f"🎯 {masked_lbl}",
                entity_type=ent_type,
                domain=dom_cat,
                selector_strength=SelectorStrength.STRONG,
                smoke_score=50.0,
                risk_flags=["PRIMARY_INVESTIGATION_ANCHOR"] if hop_depth == 0 else ["SECONDARY_ANCHOR"],
                attributes={"raw_seed": masked_lbl, "seed_type": node_kind},
                receipts=[rcpt],
                hop_depth=hop_depth,
            )
        )
        return lead_type, node

    async def _execute_lead(self, lead_type: str, value: str, origin_node_id: str, hop_depth: int) -> None:
        """Dispatch a single lead across the relevant specialist agents with concurrency control."""
        if self.graph.is_excluded(value):
            return
        async with self._sem:
            tasks = []
            pi = self._pi_task  # identity in normal mode; in PI mode logs every source call incl. negatives
            if lead_type == "domain":
                tasks.append(pi("osint_domain", value, self.osint.investigate_domain_infrastructure(value, origin_node_id, hop_depth)))
                tasks.append(pi("wayback", value, self.journalist.investigate_wayback_ghost_edits(value, origin_node_id, hop_depth)))
                tasks.append(pi("news_narrative", value, self.journalist.investigate_news_and_narrative(value, origin_node_id, hop_depth)))
                stem = extract_entity_stem(value)
                if len(stem) >= 4:
                    tasks.append(pi("gleif", stem, self.accountant.investigate_gleif_corporate_hierarchy(stem, origin_node_id, hop_depth)))
                    if self.engagement is None:
                        tasks.append(pi("dexscreener", stem, self.onchain.investigate_dexscreener_tokens(stem, origin_node_id, hop_depth)))
                    else:
                        self._pi_skip("dexscreener", stem, _DEX_PI_SKIP)
                    if self._emphasize_sanctions:
                        tasks.append(pi("opensanctions", stem, self.accountant.investigate_opensanctions(stem, origin_node_id, hop_depth)))

            elif lead_type == "wallet":
                tasks.append(pi("onchain_evm", value, self.onchain.investigate_evm_address(value, origin_node_id, hop_depth)))
                if value.lower().endswith(".eth"):
                    stem = value.lower().removesuffix(".eth")
                    if len(stem) >= 3:
                        tasks.append(pi("osint_identity", stem, self.osint.investigate_identity_and_handle(stem, origin_node_id, hop_depth)))

            elif lead_type == "bitcoin":
                tasks.append(pi("onchain_bitcoin", value, self.onchain.investigate_bitcoin_utxo(value, origin_node_id, hop_depth)))

            elif lead_type == "aircraft":
                tasks.append(pi("aircraft_adsb", value, self.accountant.investigate_aircraft_adsb(value, origin_node_id, hop_depth)))
                tasks.append(pi("news_narrative", value, self.journalist.investigate_news_and_narrative(value, origin_node_id, hop_depth)))

            elif lead_type == "ip":
                tasks.append(pi("ip_shodan_ripestat", value, self.osint.investigate_ip_shodan_and_ripestat(value, origin_node_id, hop_depth)))
                if self.engagement is None:
                    tasks.append(pi("hudsonrock", value, self.osint.investigate_hudsonrock_infostealer(value, "ip", origin_node_id, hop_depth)))
                else:
                    self._pi_skip("hudsonrock", value, BREACH_SKIP_REASON)

            elif lead_type == "email":
                tasks.append(pi("email_pivots", value, self.osint.investigate_email_pivots(value, origin_node_id, hop_depth)))
                handle_part = value.split("@")[0]
                if len(handle_part) >= 3:
                    tasks.append(pi("osint_identity", handle_part, self.osint.investigate_identity_and_handle(handle_part, origin_node_id, hop_depth)))

            elif lead_type == "phone":
                tasks.append(pi("phone_lookup", value, self.osint.investigate_phone_number(value, origin_node_id, hop_depth)))

            elif lead_type == "credential":
                if self.pi_recorder is not None:
                    # The target is the (masked) origin node: the secret never reaches the source log.
                    self.pi_recorder.skip("credential_combo", origin_node_id, CREDENTIAL_SKIP_REASON)
                else:
                    tasks.append(self.osint.investigate_credential_combo(value, origin_node_id, hop_depth))

            elif lead_type == "document":
                self.journalist.inspect_document_binary_forensics(value, origin_node_id=origin_node_id)

            elif lead_type == "username":
                tasks.append(pi("osint_identity", value, self.osint.investigate_identity_and_handle(value, origin_node_id, hop_depth)))
                tasks.append(pi("hackernews", value, self.journalist.investigate_hackernews_archive(value, origin_node_id, hop_depth)))
                if self.engagement is None:
                    tasks.append(pi("dexscreener", value, self.onchain.investigate_dexscreener_tokens(value, origin_node_id, hop_depth)))
                else:
                    self._pi_skip("dexscreener", value, _DEX_PI_SKIP)

            else:  # company / person / general topic
                tasks.append(pi("gleif", value, self.accountant.investigate_gleif_corporate_hierarchy(value, origin_node_id, hop_depth)))
                tasks.append(pi("opensanctions", value, self.accountant.investigate_opensanctions(value, origin_node_id, hop_depth)))
                tasks.append(pi("sec_edgar", value, self.accountant.investigate_sec_edgar(value, origin_node_id, hop_depth)))
                tasks.append(pi("nonprofit_990s", value, self.accountant.investigate_nonprofit_990s_and_usaspending(value, origin_node_id, hop_depth)))
                tasks.append(pi("news_narrative", value, self.journalist.investigate_news_and_narrative(value, origin_node_id, hop_depth)))
                tasks.append(pi("court_dockets", value, self.journalist.investigate_court_dockets(value, origin_node_id, hop_depth)))
                tasks.append(pi("wikipedia", value, self.journalist.investigate_wikipedia_revisions(value, origin_node_id, hop_depth)))
                tasks.append(pi("openalex", value, self.journalist.investigate_openalex_academic_and_grants(value, origin_node_id, hop_depth)))
                tasks.append(pi("hackernews", value, self.journalist.investigate_hackernews_archive(value, origin_node_id, hop_depth)))
                if self.engagement is None:
                    tasks.append(pi("dexscreener", value, self.onchain.investigate_dexscreener_tokens(value, origin_node_id, hop_depth)))
                else:
                    self._pi_skip("dexscreener", value, _DEX_PI_SKIP)
                if self.gear == GearMode.DEEP:
                    stem = extract_entity_stem(value)
                    if len(stem) >= 4:
                        tasks.append(pi("osint_identity", stem, self.osint.investigate_identity_and_handle(stem, origin_node_id, hop_depth)))
                if self.pi_sources is not None:  # PI-only free sources (Companies House PSC, GAC sanctions, CFPB, Wikidata)
                    tasks.append(pi("uk_psc", value, self._pi_collect_psc(value, origin_node_id, hop_depth)))
                    tasks.append(pi("ca_sanctions", value, self.pi_sources.screen_canadian_sanctions(value, origin_node_id, hop_depth)))
                    # Official keyless lists (OFAC SDN, UN, UK): the keyless replacement for an OpenSanctions key.
                    tasks.append(pi("ofac_sdn", value, self.pi_sources.screen_ofac_sdn(value, origin_node_id, hop_depth)))
                    tasks.append(pi("un_consolidated", value, self.pi_sources.screen_un_consolidated(value, origin_node_id, hop_depth)))
                    tasks.append(pi("uk_sanctions_list", value, self.pi_sources.screen_uk_sanctions_list(value, origin_node_id, hop_depth)))
                    tasks.append(pi("cfpb_complaints", value, self.pi_sources.investigate_cfpb_complaints(value, origin_node_id, hop_depth)))
                    tasks.append(pi("wikidata", value, self.pi_sources.investigate_wikidata_entity(value, origin_node_id, hop_depth)))

            if tasks:
                await self._gather_logged(tasks, f"lead:{lead_type}")

    async def _gather_logged(self, tasks: List[Any], stage: str) -> List[Any]:
        """Await gathered agent tasks, turning every swallowed exception into a logged agent event and
        a count in ``deep_research.agent_errors`` — so a bug in one agent is visible, not silent.

        Behaviour is otherwise identical to ``gather(..., return_exceptions=True)``: results (and the
        exception objects) are returned in order. In PI mode the PIRunRecorder wrapper catches inside
        each task and returns None, so no exception reaches here and nothing is double counted.
        """
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, BaseException):
                self._agent_errors += 1
                self.graph.log(
                    DomainCategory.SKEPTIC,
                    "AGENT_TASK_ERROR",
                    stage,
                    f"{type(res).__name__}: {res}",  # type + message only; agents never put secrets here
                    level="warning",
                )
        return results

    def _harvest_step_learnings_and_followups(self, current_hop: int) -> None:
        """
        dzhng/deep-research style distillation: extract new verified facts (learnings[])
        and generate targeted follow-up hypotheses from the current depth's discoveries.
        """
        for edge in self.graph.edges.values():
            for rcpt in edge.receipts:
                fact = f"[{rcpt.admiralty_code} | {rcpt.tool}] {rcpt.extracted_fact}"
                if fact not in self.learnings:
                    self.learnings.append(fact)

        # Generate follow-up investigative questions based on high-smoke discoveries
        for node in self.graph.nodes.values():
            if node.hop_depth == current_hop and node.smoke_score >= 60.0:
                q = f"How does high-smoke entity '{node.label}' ({', '.join(node.risk_flags[:2])}) connect to the primary anchor's financial or infrastructure footprint?"
                if q not in self.follow_up_questions:
                    self.follow_up_questions.append(q)

    async def run_intake_investigation(self, packet: CaseIntakePacket) -> Dict[str, Any]:
        """
        Execute a Multi-Selector & Hypothesis-Driven Case Intake Investigation:
        - Normalizes unstructured Omni-Bar dumps + structured Credential/Selector slots.
        - Supports both `AnchorMode.CONVERGENCE` (separate root islands -> prove IF/HOW they connect)
          and `AnchorMode.LOCKED_PROFILE` (confirmed same entity -> link all selectors to a single Target Profile root).
        """
        packet = self._pi_strip_credentials(packet)  # PI mode: before the parser or any lead can see a secret
        norm = self._pi_strip_credentials(SmartIntakeParser.normalize_packet(packet))
        packet_dump = norm.model_dump()
        # Never persist or return raw credentials. PI mode already emptied them; non-PI masks the secret.
        if packet_dump.get("credentials"):
            packet_dump["credentials"] = [mask_credential(c) for c in packet_dump["credentials"]]
        self.intake_packet = packet_dump
        self.seed_query = norm.title
        self.graph.seed_query = norm.title
        if norm.hypothesis:
            self.graph.hypothesis = norm.hypothesis
            self.graph.hypothesis_keywords = {
                w for w in re.findall(r"[a-z0-9]{4,}", norm.hypothesis.lower())
                if w not in {"prove", "whether", "that", "this", "with", "from", "into", "through", "connected", "linked", "between", "does", "have"}
            }
        if norm.exclusions:
            self.graph.exclusions.update(x.lower().strip() for x in norm.exclusions if x.strip())

        seed_tuples = norm.all_seed_tuples()
        if not seed_tuples and norm.raw_omni_input:
            ltype, _, _ = classify_seed_type(norm.raw_omni_input)
            seed_tuples = [(ltype, norm.raw_omni_input)]
        self._pi_start_case(seed_tuples)

        self.graph.log(
            DomainCategory.SKEPTIC,
            "CASE_INTAKE_START",
            norm.title,
            f"Launching Case Intake ({norm.anchor_mode.value.upper()}) with {len(seed_tuples)} selectors, "
            f"Hypothesis='{norm.hypothesis[:60]}', Exclusions={norm.exclusions}",
            level="discovery",
        )

        root_nodes: List[Tuple[str, str, GraphNode]] = []
        locked_hub_node: Optional[GraphNode] = None

        if norm.anchor_mode == AnchorMode.LOCKED_PROFILE and len(seed_tuples) > 1:
            rcpt_hub = EvidenceReceipt(
                tool="bunnyhole_intake_locked_profile",
                domain=DomainCategory.SKEPTIC,
                admiralty_code="A1",
                selector_strength=SelectorStrength.STRONG,
                source_url="intake://locked_target_profile",
                extracted_fact=f"User-confirmed Target Profile bundling {len(seed_tuples)} known credentials/selectors",
                raw_snippet=str([mask_credential(v) if lt == "credential" else v for lt, v in seed_tuples])[:300],
            )
            locked_hub_node = self.graph.upsert_node(
                GraphNode(
                    id="profile:locked_target_root",
                    label=f"🔒 Target Profile: {norm.title[:36]}",
                    entity_type=EntityType.PERSON,
                    domain=DomainCategory.SKEPTIC,
                    selector_strength=SelectorStrength.STRONG,
                    smoke_score=65.0,
                    risk_flags=["USER_CONFIRMED_TARGET_BUNDLE"],
                    attributes={"anchor_mode": "locked_profile", "selector_count": len(seed_tuples)},
                    receipts=[rcpt_hub],
                    hop_depth=0,
                )
            )

        for ltype, val in seed_tuples:
            _, s_node = self._create_seed_node(val, hop_depth=0, forced_type=ltype)
            self.graph.explored_seeds.add(f"{ltype}:{val.lower().strip()}")
            root_nodes.append((ltype, val, s_node))
            if locked_hub_node and s_node.id != locked_hub_node.id:
                self.graph.upsert_edge(
                    GraphEdge(
                        source_id=locked_hub_node.id,
                        target_id=s_node.id,
                        relation=RelationType.LINKED_IDENTITY,
                        domain=DomainCategory.SKEPTIC,
                        admiralty_code="A1",
                        confidence=1.0,
                        tier=ConfidenceTier.VERIFIED,
                        summary="User-Confirmed Selector",
                        receipts=locked_hub_node.receipts,
                    )
                )

        # Hop 1: Parallel expansion of all intake selectors
        await self._gather_logged(
            [self._execute_lead(lt, v, n.id, hop_depth=1) for lt, v, n in root_nodes],
            "intake_hop1",
        )
        self._harvest_step_learnings_and_followups(current_hop=1)

        # If in CONVERGENCE mode with >= 2 root selectors, also run direct co-occurrence checks between top root pairs!
        # Credential roots are excluded from co-occurrence: their raw value is a secret and must never
        # be built into an outbound search query (Google News / CourtListener).
        co_roots = [rn for rn in root_nodes if rn[0] != "credential"]
        if norm.anchor_mode == AnchorMode.CONVERGENCE and len(co_roots) >= 2:
            co_pairs = []
            for i in range(min(3, len(co_roots))):
                for j in range(i + 1, min(4, len(co_roots))):
                    co_pairs.append(
                        self.link_sleuth.verify_interconnection_cooccurrence(
                            co_roots[i][1],
                            co_roots[i][2].id,
                            co_roots[j][1],
                            co_roots[j][2].id,
                            hop_depth=1,
                        )
                    )
            if co_pairs:
                await self._gather_logged(co_pairs, "intake_cooccurrence")

        self.link_sleuth.break_dead_ends(current_hop=1)

        # Recursive Depth Loop
        current_breadth = self.initial_breadth
        for hop in range(2, self.max_depth + 1):
            next_leads = self.graph.pop_next_leads(max_hop=hop, batch_size=current_breadth)
            if not next_leads:
                break
            self.graph.log(
                DomainCategory.SKEPTIC,
                f"RECURSIVE_HOP_{hop}",
                f"{len(next_leads)} leads (breadth={current_breadth})",
                f"Chasing top {len(next_leads)} scored leads down the rabbit hole: {[l.seed_value for l in next_leads]}",
                level="discovery",
            )
            await self._gather_logged(
                [
                    self._execute_lead(l.lead_type, l.seed_value, l.origin_node_id, hop_depth=hop)
                    for l in next_leads
                ],
                f"intake_hop{hop}",
            )
            self._harvest_step_learnings_and_followups(current_hop=hop)
            self.link_sleuth.break_dead_ends(current_hop=hop)
            current_breadth = max(2, math.ceil(current_breadth / 2))

        return await self._finalize_and_persist_investigation()

    async def run_investigation(self) -> Dict[str, Any]:
        """
        Execute the full recursive Breadth x Depth investigation loop (automatically parses multi-selector strings if provided).
        """
        packet = SmartIntakeParser.normalize_packet(
            CaseIntakePacket(
                raw_omni_input=self.seed_query,
                hypothesis=self.graph.hypothesis,
                exclusions=list(self.graph.exclusions),
                gear=self.gear,
                depth=self.max_depth,
                breadth=self.initial_breadth,
            )
        )
        if packet.total_selectors() > 1 or packet.hypothesis or packet.exclusions:
            return await self.run_intake_investigation(packet)

        lead_type, root_node = self._create_seed_node(self.seed_query, hop_depth=0)
        self.graph.explored_seeds.add(f"{lead_type}:{self.seed_query.lower().strip()}")
        self._pi_start_case([(lead_type, self.seed_query)])

        self.graph.log(
            DomainCategory.SKEPTIC,
            "DEEP_RESEARCH_START",
            self.seed_query,
            f"Launching recursive Breadth={self.initial_breadth} x Depth={self.max_depth} loop in {self.gear.value.upper()} gear",
            level="discovery",
        )

        # Hop 1: Initial Anchor Sweep
        await self._execute_lead(lead_type, self.seed_query, root_node.id, hop_depth=1)
        self._harvest_step_learnings_and_followups(current_hop=1)

        # Link Sleuth Pass 1: Diagnose dead-end leaf nodes & inject orthogonal lateral bypass leads!
        self.link_sleuth.break_dead_ends(current_hop=1)

        # Recursive Depth Loop (dzhng/deep-research dynamic breadth tapering: new_breadth = ceil(breadth / 2))
        current_breadth = self.initial_breadth
        for hop in range(2, self.max_depth + 1):
            next_leads = self.graph.pop_next_leads(max_hop=hop, batch_size=current_breadth)
            if not next_leads:
                break
            self.graph.log(
                DomainCategory.SKEPTIC,
                f"RECURSIVE_HOP_{hop}",
                f"{len(next_leads)} leads (breadth={current_breadth})",
                f"Chasing top {len(next_leads)} scored leads down the rabbit hole: {[l.seed_value for l in next_leads]}",
                level="discovery",
            )
            await self._gather_logged(
                [
                    self._execute_lead(l.lead_type, l.seed_value, l.origin_node_id, hop_depth=hop)
                    for l in next_leads
                ],
                f"hop{hop}",
            )
            self._harvest_step_learnings_and_followups(current_hop=hop)
            self.link_sleuth.break_dead_ends(current_hop=hop)
            current_breadth = max(2, math.ceil(current_breadth / 2))

        # Final Link Sleuth Pass: Verify top Adamic-Adar predicted missing links via live Joint Co-Occurrence probes!
        predicted = self.link_sleuth.predict_missing_links_adamic_adar()
        co_tasks = []
        for pred in predicted[:2]:
            if pred["is_cross_domain"]:
                co_tasks.append(
                    self.link_sleuth.verify_interconnection_cooccurrence(
                        pred["node_a_label"],
                        pred["node_a_id"],
                        pred["node_b_label"],
                        pred["node_b_id"],
                        hop_depth=self.max_depth,
                    )
                )
        if co_tasks:
            await self._gather_logged(co_tasks, "predicted_cooccurrence")

        return await self._finalize_and_persist_investigation()

    async def run_bidirectional_link_investigation(self, entity_a: str, entity_b: str) -> Dict[str, Any]:
        """
        Meet-in-the-Middle Link Sleuth Mode:
        Simultaneously expands Entity A and Entity B across all domains, tests direct co-occurrence,
        and computes all connecting paths and shared intermediaries between them!
        """
        type_a, node_a = self._create_seed_node(entity_a, hop_depth=0)
        type_b, node_b = self._create_seed_node(entity_b, hop_depth=0)

        self.graph.log(
            DomainCategory.SKEPTIC,
            "BIDIRECTIONAL_LINK_HUNT",
            f"{entity_a} <-> {entity_b}",
            f"Running bidirectional Meet-in-the-Middle sweep between '{entity_a}' and '{entity_b}'",
            level="discovery",
        )

        await self._gather_logged(
            [
                self._execute_lead(type_a, entity_a, node_a.id, hop_depth=1),
                self._execute_lead(type_b, entity_b, node_b.id, hop_depth=1),
                self.link_sleuth.verify_interconnection_cooccurrence(entity_a, node_a.id, entity_b, node_b.id, hop_depth=1),
            ],
            "bidirectional_hop1",
        )

        # Expand converged leads or top leads from both sides
        next_leads = self.graph.pop_next_leads(max_hop=2, batch_size=self.initial_breadth)
        if next_leads:
            await self._gather_logged(
                [self._execute_lead(l.lead_type, l.seed_value, l.origin_node_id, hop_depth=2) for l in next_leads],
                "bidirectional_hop2",
            )

        self._harvest_step_learnings_and_followups(current_hop=2)
        return await self._finalize_and_persist_investigation(source_query=entity_a, target_query=entity_b)

    async def _finalize_and_persist_investigation(
        self,
        source_query: Optional[str] = None,
        target_query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Correlate against SQLite Cross-Case Entity Memory, run Karpathy 3-Stage LLM Council + Synthesis, and save case to ~/.bunnyhole/cases.db.

        No single stage failure loses the finished work: cross-case correlation, synthesis and the
        council each fall back to a deterministic default (recorded in ``result['stage_errors']``),
        and a failed persist is reported in ``result['persist_error']`` — never silently swallowed.
        """
        stage_errors: Dict[str, str] = {}

        try:
            # Under a PI engagement another case's seed query is a different client's subject, so the
            # cross-case receipts must not carry prior seed text (only `case <id>`).
            self.cross_case_hits = self.case_store.correlate_cross_case_entities(
                self.graph, include_seed_text=self.engagement is None
            )
        except Exception as exc:  # noqa: BLE001 - optional enrichment; recorded, not fatal
            self.cross_case_hits = []
            stage_errors["cross_case"] = f"{type(exc).__name__}: {exc}"
            self.graph.log(
                DomainCategory.SKEPTIC, "STAGE_ERROR", "correlate_cross_case_entities",
                stage_errors["cross_case"], level="warning",
            )

        self._pi_refresh_analytics_exclusions()
        interconnections = self.link_sleuth.analyze_interconnected_web()
        if source_query and target_query:
            interconnections["targeted_paths"] = self.link_sleuth.find_interconnection_paths(source_query, target_query)

        synth_res: Dict[str, Any] | BaseException
        council_res: Dict[str, Any] | BaseException
        synth_res, council_res = await asyncio.gather(
            self.synthesizer.synthesize_investigation(self.learnings, interconnections, self.cross_case_hits),
            self.council.run_full_council(interconnections, self.cross_case_hits),
            return_exceptions=True,
        )
        if isinstance(synth_res, BaseException):
            stage_errors["synthesis"] = f"{type(synth_res).__name__}: {synth_res}"
            self.synthesis = {}  # compile_full_result falls back to the deterministic brief
            self.graph.log(
                DomainCategory.SKEPTIC, "STAGE_ERROR", "synthesize_investigation",
                stage_errors["synthesis"], level="warning",
            )
        else:
            self.synthesis = synth_res
        if isinstance(council_res, BaseException):
            stage_errors["council"] = f"{type(council_res).__name__}: {council_res}"
            self.council_deliberation = {}
            self.graph.log(
                DomainCategory.SKEPTIC, "STAGE_ERROR", "run_full_council",
                stage_errors["council"], level="warning",
            )
        else:
            self.council_deliberation = council_res

        res = self.compile_full_result(source_query=source_query, target_query=target_query)
        if stage_errors:
            res["stage_errors"] = stage_errors

        persist_error = self._persist_error
        try:
            self.case_store.save_case(self.graph, res)
            persist_error = persist_error or getattr(self.case_store, "persist_error", None)
        except Exception as exc:  # noqa: BLE001 - persistence is optional; report, never silently pass
            persist_error = f"{type(exc).__name__}: {exc}"
            self.graph.log(
                DomainCategory.SKEPTIC, "STAGE_ERROR", "save_case", persist_error, level="warning",
            )
        if persist_error:
            res["persist_error"] = persist_error
        return res

    def compile_full_result(
        self,
        source_query: Optional[str] = None,
        target_query: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._pi_refresh_analytics_exclusions()
        base = self.graph.to_dict()
        interconnections = self.link_sleuth.analyze_interconnected_web()
        if source_query and target_query:
            interconnections["targeted_paths"] = self.link_sleuth.find_interconnection_paths(source_query, target_query)
        base["interconnections"] = interconnections
        base["cross_case_hits"] = self.cross_case_hits
        if not self.synthesis:
            self.synthesis = self.synthesizer.build_deterministic_brief(
                self.learnings, interconnections, self.cross_case_hits
            )
        base["synthesis"] = self.synthesis
        base["council"] = self.council_deliberation
        if self.intake_packet:
            base["intake_packet"] = self.intake_packet
        base["deep_research"] = {
            "gear": self.gear.value,
            "max_depth": self.max_depth,
            "initial_breadth": self.initial_breadth,
            "hypothesis": self.graph.hypothesis,
            "exclusions": list(self.graph.exclusions),
            "total_learnings": len(self.learnings),
            "learnings": self.learnings[:40],
            "follow_up_questions": self.follow_up_questions[:15],
            "agent_errors": self._agent_errors,
        }
        # Personalization: the persona lens this case ran through + any watchlist targets it surfaced.
        base["persona"] = self.profile.persona.value
        base["analyst_framing"] = self.profile.analyst_framing()
        base["watchlist_hits"] = match_watchlist(base.get("nodes", []), self.profile.watchlist)
        if self.engagement is not None and self.pi_recorder is not None:
            # Nodes the analytics tables left out (unanchored name-only records, platform accounts): the JSON keeps
            # them, and the CLI tables use this list to skip them.
            base["set_aside_node_ids"] = sorted(self.graph.analytics_excluded_ids)
            base["pi"] = assemble_pi_block(
                self.engagement,
                base,
                self.pi_recorder.entries,
                cross_case_prior=self._pi_prior_cases,
                selectors=self._pi_selectors,
                ownership_links=self._pi_ownership_links,
                deep_run=self._pi_deep_run,
            ).model_dump(mode="json")
            if self._pi_redactions:  # safety net: no credential string survives anywhere in the PI result
                base = redact_value(base, self._pi_redactions)
        elif self._credential_secrets:
            # Non-PI safety net: replace any plaintext credential that reached the compiled result with
            # its masked form (`ident:****`), keeping the non-secret identifier readable.
            base = self._scrub_credential_result(base)
        return base

    def _scrub_credential_result(self, value: Any) -> Any:
        """Deep copy of ``value`` with every tracked plaintext credential replaced by its masked form.

        Unlike the PI redactor (which blanks to ``[credential removed]``), this keeps the identifier:
        ``ceo@acme.com:hunter2`` -> ``ceo@acme.com:****`` and a bare secret -> ``****``. Longest tokens
        first, so a full ``email:secret`` is masked before its bare secret is.
        """
        pairs = [(tok, mask_credential(tok)) for tok in sorted(set(self._credential_secrets), key=len, reverse=True)]

        def clean(text: str) -> str:
            for needle, repl in pairs:
                if needle and needle in text:
                    text = text.replace(needle, repl)
            return text

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                return clean(node)
            if isinstance(node, dict):
                return {(clean(k) if isinstance(k, str) else k): walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            if isinstance(node, tuple):
                return tuple(walk(v) for v in node)
            return node

        return walk(value)
