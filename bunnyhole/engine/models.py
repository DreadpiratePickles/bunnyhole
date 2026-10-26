"""Universal Investigation Graph Models with NATO Admiralty Grading, CIA ACH Matrix, Selector Taxonomy, and Mandatory Evidence Receipts."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class GearMode(str, Enum):
    """2-Gear Execution Profile."""
    FAST = "fast"   # Gear 1: Rapid API, DNS/CT, Scrapling HTTP Fetcher, Blockscout, GLEIF, EDGAR, Cavalier
    DEEP = "deep"   # Gear 2: Adds Scrapling StealthyFetcher headless, Wayback diffing, PDF/DOCX RSID forensics, Holehe email sweep, 2-hop burner expansion


class DomainCategory(str, Enum):
    """The investigative pillars of Bunnyhole."""
    JOURNALISM = "journalism"      # News, Wayback CDX ghost-edits, PDF/DOCX RSID forensics, CourtListener, Pink-Slime detection
    FIAT = "fiat"                  # SEC EDGAR, Beneish M-Score, GLEIF parent/child, FEC, IRS 990s, Sanctions, Offshore, UCC-1
    OSINT = "osint"                # CT logs, DNS SOA RNAME, Scrapling, Favicon mmh3, .js.map, GitHub .patch & PoL, HudsonRock, Holehe
    ONCHAIN = "onchain"            # Multi-chain EVM/BTC/SOL, First-Funder Mother Wallet, CEX Deposit Sweep, THORChain memo, Jito Bundlers
    PHYSICAL = "physical"          # ADS-B Corporate Jets (adsb.lol + ICAO hex), Maritime AIS Shadow Fleet (IMO/MMSI), Supply Chain
    SKEPTIC = "skeptic"            # Red-Cell verifier, NATO Admiralty A1-F6, CIA ACH Matrix, Betweenness Centrality cut-out detector


class SelectorStrength(str, Enum):
    """NSA Contact Chaining Selector Taxonomy."""
    STRONG = "STRONG"  # Deterministic, near-zero collision (Wallet, CIK, LEI, Email, GitHub UID, GA ID, Word RSID, ICAO Hex, IMO)
    SOFT = "SOFT"      # Probabilistic, prone to false-positive collision (Person Name, Shared CDN IP, Registered Agent, Timezone)


class AdmiraltySourceReliability(str, Enum):
    """NATO STANAG 2511 Source Reliability (A-F)."""
    A = "A"  # Completely reliable (Cryptographic blockchain state, SEC EDGAR, GLEIF, DNS Root, ADS-B transponder)
    B = "B"  # Usually reliable (Wayback CDX, Certificate Transparency crt.sh, FEC, IRS 990, CourtListener)
    C = "C"  # Fairly reliable (Mainstream journalism, GitHub API, HudsonRock Cavalier, DexScreener)
    D = "D"  # Not usually reliable (Unverified forum posts, partisan/pink-slime blogs, self-reported social bios)
    E = "E"  # Unreliable (Known spoofed or unverified commit header / false-flag memo)
    F = "F"  # Reliability cannot be judged (Newly discovered raw web page)


class AdmiraltyInfoCredibility(str, Enum):
    """NATO STANAG 2511 Information Credibility (1-6)."""
    ONE = "1"    # Confirmed by other independent sources
    TWO = "2"    # Probably true (logical, consistent with other facts)
    THREE = "3"  # Possibly true (reasonably conceived, not corroborated)
    FOUR = "4"   # Doubtful
    FIVE = "5"   # Improbable (matches known false-positive trap like shared Registered Agent)
    SIX = "6"    # Truth cannot be judged


class EntityType(str, Enum):
    """Universal entity types aligned with OCCRP FollowTheMoney."""
    PERSON = "Person"
    ORGANIZATION = "Organization"
    SHELL_COMPANY = "ShellCompany"
    DOMAIN = "Domain"
    IP_HOST = "IPHost"
    ACCOUNT = "Account"
    EMAIL = "Email"
    CRYPTO_WALLET = "CryptoWallet"
    SMART_CONTRACT = "SmartContract"
    TOKEN = "Token"
    TRANSACTION = "Transaction"
    FILING = "Filing"
    LEGAL_CASE = "LegalCase"
    NEWS_ARTICLE = "NewsArticle"
    DOCUMENT = "Document"
    EVENT = "Event"
    LOCATION = "Location"
    TRACKER_ID = "TrackerID"       # Google Analytics, AdSense, Favicon mmh3 hash, TLS cert fingerprint, Word RSID
    AIRCRAFT = "Aircraft"          # Corporate jet (N-Number / ICAO 24-bit hex)
    VESSEL = "Vessel"              # Maritime vessel (IMO / MMSI)
    BREACH_RECORD = "BreachRecord" # Infostealer compromise or Ransomware leak record


class RelationType(str, Enum):
    """Directed relationship types across all domains."""
    OWNS = "OWNS"
    DIRECT_PARENT_OF = "DIRECT_PARENT_OF"
    ULTIMATE_PARENT_OF = "ULTIMATE_PARENT_OF"
    DIRECTOR_OF = "DIRECTOR_OF"
    OFFICER_OF = "OFFICER_OF"
    NOMINEE_FOR = "NOMINEE_FOR"
    SUBSIDIARY_OF = "SUBSIDIARY_OF"
    REGISTERED_AT = "REGISTERED_AT"
    DONATED_TO = "DONATED_TO"
    EMPLOYED_BY = "EMPLOYED_BY"
    FILED = "FILED"
    AUDITED_BY = "AUDITED_BY"
    LITIGATED_IN = "LITIGATED_IN"
    MENTIONED_IN = "MENTIONED_IN"
    CONTRADICTS = "CONTRADICTS"
    SCRUBBED_FROM = "SCRUBBED_FROM"
    ARCHIVED_AT = "ARCHIVED_AT"
    SHARES_RSID_WITH = "SHARES_RSID_WITH"
    RESOLVES_TO = "RESOLVES_TO"
    SHARES_CERT_WITH = "SHARES_CERT_WITH"
    SHARES_FINGERPRINT_WITH = "SHARES_FINGERPRINT_WITH"
    COMMITTED_TO = "COMMITTED_TO"
    LINKED_IDENTITY = "LINKED_IDENTITY"
    COMPROMISED_IN = "COMPROMISED_IN"
    FIRST_FUNDED_BY = "FIRST_FUNDED_BY"
    TRANSFERRED_TO = "TRANSFERRED_TO"
    SWAPPED_IN = "SWAPPED_IN"
    BRIDGED_TO = "BRIDGED_TO"
    DEPLOYED_BY = "DEPLOYED_BY"
    BUNDLED_WITH = "BUNDLED_WITH"
    SHARED_CEX_DEPOSIT = "SHARED_CEX_DEPOSIT"
    OPERATES_AIRCRAFT = "OPERATES_AIRCRAFT"
    OPERATES_VESSEL = "OPERATES_VESSEL"
    SANCTIONED_MATCH = "SANCTIONED_MATCH"


class ConfidenceTier(str, Enum):
    """Adversarial confidence rating assigned by the Red-Cell Skeptic."""
    VERIFIED = "VERIFIED"               # 0.90 - 1.00 (Admiralty A1, A2, B1)
    CORROBORATED = "CORROBORATED"       # 0.65 - 0.89 (Admiralty B2, C1, C2)
    CIRCUMSTANTIAL = "CIRCUMSTANTIAL"   # 0.35 - 0.64 (Admiralty C3, D2, D3)
    HYPOTHESIS = "HYPOTHESIS"           # < 0.35 (Admiralty D4, E5, F6)


class EvidenceReceipt(BaseModel):
    """Immutable proof attached to every discovered node or edge."""
    receipt_id: str = Field(default_factory=lambda: "")
    tool: str = Field(..., description="Tool/library used (e.g. scrapling, edgartools, gleif, crt.sh, blockscout, adsb.lol)")
    domain: DomainCategory
    admiralty_code: str = Field("B2", description="NATO STANAG 2511 code, e.g. A1, B2, C3")
    selector_strength: SelectorStrength = SelectorStrength.STRONG
    source_url: str = Field(..., description="Verifiable URL, API endpoint, or block explorer link")
    archive_url: Optional[str] = Field(None, description="Wayback Machine snapshot URL if archived")
    extracted_fact: str = Field(..., description="Human-readable statement of what this receipt proves")
    raw_snippet: str = Field("", description="Raw excerpt, JSON snippet, commit header, or tx log")
    sha256_proof: str = Field("", description="SHA-256 hash of raw evidence payload")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.sha256_proof:
            payload = f"{self.tool}|{self.source_url}|{self.extracted_fact}|{self.raw_snippet}"
            self.sha256_proof = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if not self.receipt_id:
            self.receipt_id = f"rcpt_{self.sha256_proof[:10]}"


class GraphNode(BaseModel):
    """A node in the Universal Investigation Graph."""
    id: str = Field(..., description="Canonical node ID, e.g. wallet:eth:0x123..., domain:example.com")
    label: str = Field(..., description="Display name")
    entity_type: EntityType
    domain: DomainCategory
    selector_strength: SelectorStrength = SelectorStrength.STRONG
    ftm_schema: str = Field("LegalEntity", description="OCCRP FollowTheMoney schema equivalent")
    smoke_score: float = Field(0.0, ge=0.0, le=100.0, description="0-100 risk/anomaly index ('Smoke Index')")
    betweenness_centrality: float = Field(0.0, description="Graph bridge centrality for spotting cut-outs/strawmen")
    is_cutout_broker: bool = Field(False, description="True if node acts as an articulation bridge between domains")
    risk_flags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    receipts: List[EvidenceReceipt] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hop_depth: int = Field(0, description="Distance in hops from the initial seed")


class GraphEdge(BaseModel):
    """A directed, provenance-backed edge between two GraphNodes."""
    id: str = Field(default_factory=lambda: "")
    source_id: str
    target_id: str
    relation: RelationType
    domain: DomainCategory
    admiralty_code: str = Field("B2", description="NATO STANAG 2511 code (A1 to F6)")
    confidence: float = Field(0.85, ge=0.0, le=1.0)
    tier: ConfidenceTier = ConfidenceTier.CORROBORATED
    summary: str = Field("", description="Short label explaining the connection")
    event_date: Optional[str] = Field(None, description="ISO date/timestamp if temporal (tx, filing, article)")
    amount_usd: Optional[float] = Field(None, description="Monetary value if financial/crypto flow")
    skeptic_notes: Optional[str] = Field(None, description="Red-Cell Skeptic verification or false-positive warning")
    receipts: List[EvidenceReceipt] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            raw = f"{self.source_id}--{self.relation.value}-->{self.target_id}"
            self.id = f"edge_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:10]}"
        if self.confidence >= 0.90:
            self.tier = ConfidenceTier.VERIFIED
        elif self.confidence >= 0.65:
            self.tier = ConfidenceTier.CORROBORATED
        elif self.confidence >= 0.35:
            self.tier = ConfidenceTier.CIRCUMSTANTIAL
        else:
            self.tier = ConfidenceTier.HYPOTHESIS


class ACHHypothesisRow(BaseModel):
    """CIA Analysis of Competing Hypotheses (ACH) evaluation row."""
    evidence_id: str
    evidence_summary: str
    admiralty_code: str
    diagnosticity: str = Field("HIGH", description="EXTREME, HIGH, MEDIUM, LOW")
    h1_coordinated_control: str = Field("+", description="++, +, 0, -, -- (Consistent vs Inconsistent)")
    h2_coincidence_shared_vendor: str = Field("-", description="++, +, 0, -, --")
    h3_false_flag_spoofing: str = Field("-", description="++, +, 0, -, --")


class ACHAssessment(BaseModel):
    """Complete CIA Analysis of Competing Hypotheses Matrix for the investigation."""
    primary_question: str
    winning_hypothesis: str
    h1_score: float = Field(0.0, description="Support score for H1: Direct Attribution / Coordinated Action")
    h2_score: float = Field(0.0, description="Support score for H2: Innocent Coincidence / Shared Service Provider")
    h3_score: float = Field(0.0, description="Support score for H3: Spoofing / False Flag")
    inconsistency_count_h1: int = 0
    inconsistency_count_h2: int = 0
    inconsistency_count_h3: int = 0
    matrix_rows: List[ACHHypothesisRow] = Field(default_factory=list)
    narrative_verdict: str = ""


class Lead(BaseModel):
    """An unexplored investigative lead queued in the rabbit-hole frontier."""
    lead_id: str = Field(default_factory=lambda: "")
    seed_value: str = Field(..., description="The exact value to pivot on (address, domain, name, handle, CIK, LEI, email, N-Number)")
    lead_type: str = Field(..., description="domain, wallet, bitcoin, solana, person, company, username, email, url, aircraft, vessel")
    selector_strength: SelectorStrength = SelectorStrength.STRONG
    target_agent: DomainCategory
    priority_score: float = Field(50.0, ge=0.0, le=100.0)
    convergence_count: int = Field(1, description="Number of independent branches that discovered this selector (ABI Path Convergence)")
    reason: str = Field(..., description="Why this lead is worth chasing down the rabbit hole")
    origin_node_id: str
    hop_depth: int = 1
    explored: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.lead_id:
            raw = f"{self.lead_type}:{self.seed_value.lower().strip()}"
            self.lead_id = f"lead_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:10]}"


class TimelineItem(BaseModel):
    """Chronological event across news, SEC/FEC filings, OSINT infra, flight/vessel tracks, and on-chain transfers."""
    timestamp: str
    domain: DomainCategory
    title: str
    description: str
    node_ids: List[str] = Field(default_factory=list)
    source_url: Optional[str] = None
    admiralty_code: str = "B2"
    anomaly_flag: Optional[str] = None


class AgentLogEvent(BaseModel):
    """Real-time streaming telemetry event from an active Bunnyhole agent."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent: DomainCategory
    action: str
    target: str
    detail: str
    receipt_count: int = 0
    level: str = "info"  # info, discovery, warning, anomaly
