"""Karpathy llm-council 3-Stage Adversarial Investigative Council for Bunnyhole.

Adapts https://github.com/karpathy/llm-council (Stage 1 Parallel Independent Opinions ->
Stage 2 Forced Ranking -> Stage 3 Chairman Verdict) to multi-domain intelligence analysis with strict SHA-256
receipt verification.

Honesty note: Stage 2 here is a deterministic evidence-rubric ranking (see :func:`deterministic_rubric_score`), not
an LLM peer review; it is labelled that way in the result (``stage2_method``/``stage2_label``) and in the report.
Stage 1 seats and the Stage 3 chairman may add LLM text when a provider key is set (llm_providers); failures are
logged and reported in ``llm_status`` and the deterministic text is kept.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.llm_providers import PROVIDER_ORDER, complete_with_fallback, configured_providers
from bunnyhole.engine.models import ConfidenceTier, DomainCategory, SelectorStrength

STAGE2_METHOD = "deterministic_evidence_rubric"
STAGE2_LABEL = "Deterministic evidence ranking (not peer review)"


def deterministic_rubric_score(stage1_result: Dict[str, Any]) -> float:
    """Stage 2 rule: evidentiary rigor score + 3 points per ``[R#]`` citation in the response, capped at +15.

    The same rule applies whichever seat "casts" the ballot, so all ballots are identical by construction; ties
    keep seat order (stable sort). There is no per-reviewer perspective term.
    """
    citation_cnt = len(re.findall(r"\[R\d+\]", stage1_result["response"]))
    return float(stage1_result["evidentiary_rigor_score"]) + min(15.0, citation_cnt * 3.0)

# 5 Specialized Investigative Council Seats (can be backed by distinct OpenRouter / API models or deterministic engines)
COUNCIL_SEATS: List[Dict[str, str]] = [
    {
        "id": "bellingcat_archival_lead",
        "name": "Seat 1: Bellingcat Archival & Legal Lead",
        "default_model": "google/gemini-2.5-pro",
        "domain": DomainCategory.JOURNALISM.value,
        "role_prompt": (
            "You are Seat 1 (Bellingcat Archival & Legal Lead). Focus on Wayback CDX ghost edits, "
            "CourtListener federal litigation dockets, Wikipedia anonymous IP revisions, document RSIDs, "
            "and narrative syndication. Cite exact [R#] receipt IDs."
        ),
    },
    {
        "id": "hindenburg_forensic_accountant",
        "name": "Seat 2: Hindenburg Forensic Short-Seller",
        "default_model": "anthropic/claude-3.5-sonnet",
        "domain": DomainCategory.FIAT.value,
        "role_prompt": (
            "You are Seat 2 (Hindenburg Forensic Short-Seller). Focus on SEC EDGAR filings (Form D, 8-K Items 4.01/4.02), "
            "SEC XBRL Beneish M-Score earnings manipulation flags, GLEIF Level-2 ultimate parents, offshore tax havens, "
            "IRS Form 990s, and FAA/ICAO ADS-B corporate jet telemetry. Cite exact [R#] receipt IDs."
        ),
    },
    {
        "id": "nsa_sigint_infra_analyst",
        "name": "Seat 3: NSA SIGINT & Infrastructure Analyst",
        "default_model": "openai/gpt-4o",
        "domain": DomainCategory.OSINT.value,
        "role_prompt": (
            "You are Seat 3 (NSA SIGINT & Infrastructure Analyst). Focus on Strong vs Soft selectors, "
            "DNS/ASN origin servers, crt.sh TLS certificates, Shodan CVEs, HudsonRock infostealer infections, "
            "GitHub .patch commit emails, and Sherlock/Holehe identity pivots. Cite exact [R#] receipt IDs."
        ),
    },
    {
        "id": "zachxbt_onchain_sleuth",
        "name": "Seat 4: ZachXBT On-Chain & DeFi Sleuth",
        "default_model": "x-ai/grok-3",
        "domain": DomainCategory.ONCHAIN.value,
        "role_prompt": (
            "You are Seat 4 (ZachXBT On-Chain & DeFi Sleuth). Focus on ENS identity links, chronological First-Funder "
            "Mother Wallet gas lineage (sort=asc), THORChain cross-chain swap memos, Bitcoin CIOH co-inputs & peel chains, "
            "and GoPlus security flags. Cite exact [R#] receipt IDs."
        ),
    },
    {
        "id": "red_cell_defense_skeptic",
        "name": "Seat 5: Red-Cell Defense Counsel & Skeptic",
        "default_model": "deepseek/deepseek-r1",
        "domain": DomainCategory.SKEPTIC.value,
        "role_prompt": (
            "You are Seat 5 (Red-Cell Defense Counsel & Principal Skeptic). Your job is to attack apophenia, "
            "expose false positives (mass Registered Agent addresses, shared Cloudflare Anycast IPs, uncorroborated "
            "DEX ticker matches, generic stem collisions), and defend Hypothesis H2 (innocent coincidence) wherever "
            "A1/B1 Strong-selector proof is missing. Cite exact [R#] receipt IDs."
        ),
    },
]


def parse_ranking_from_text(ranking_text: str) -> List[str]:
    """
    Parse the 'FINAL RANKING:' section from a Council Member's Stage 2 peer evaluation.
    Adapted directly from karpathy/llm-council (backend/council.py).
    """
    if "FINAL RANKING:" in ranking_text:
        parts = ranking_text.split("FINAL RANKING:")
        if len(parts) >= 2:
            ranking_section = parts[1]
            numbered_matches = re.findall(r"\d+\.\s*Response [A-Z]", ranking_section)
            if numbered_matches:
                return [re.search(r"Response [A-Z]", m).group() for m in numbered_matches]  # type: ignore[union-attr]
            matches = re.findall(r"Response [A-Z]", ranking_section)
            return matches
    return re.findall(r"Response [A-Z]", ranking_text)


def calculate_aggregate_rankings(
    stage2_results: List[Dict[str, Any]],
    label_to_member: Dict[str, Dict[str, str]],
) -> List[Dict[str, Any]]:
    """
    Calculate average rank position across all Council Members' anonymized Stage 2 ballots.
    Adapted directly from karpathy/llm-council (backend/council.py).
    """
    member_positions: Dict[str, List[int]] = defaultdict(list)

    for ranking in stage2_results:
        parsed_ranking = ranking.get("parsed_ranking") or parse_ranking_from_text(ranking.get("ranking", ""))
        seen: set[str] = set()
        for position, label in enumerate(parsed_ranking, start=1):
            if label in label_to_member and label not in seen:
                seen.add(label)
                member_id = label_to_member[label]["id"]
                member_positions[member_id].append(position)

    aggregate: List[Dict[str, Any]] = []
    for label, member_info in label_to_member.items():
        mid = member_info["id"]
        positions = member_positions.get(mid, [])
        if positions:
            avg_rank = sum(positions) / len(positions)
            aggregate.append({
                "member_id": mid,
                "member_name": member_info["name"],
                "anonymous_label": label,
                "model": member_info["default_model"],
                "average_rank": round(avg_rank, 2),
                "rankings_count": len(positions),
            })

    aggregate.sort(key=lambda x: x["average_rank"])
    return aggregate


class InvestigativeCouncil:
    """
    Executes a Karpathy-style 3-stage council over Bunnyhole's Universal Investigation Graph:
    - Stage 1: 5 Specialized Investigative Personas produce independent citation-backed assessments.
    - Stage 2: Responses are anonymized as Response A..E and ranked by a deterministic evidence rubric
      (not peer review; see deterministic_rubric_score).
    - Stage 3: The Chairman synthesizes the top-ranked thesis into the final Council Verdict.
    """

    def __init__(self, graph: InvestigationGraph) -> None:
        self.graph = graph
        self._llm_failures: List[Dict[str, Any]] = []

    def _build_receipt_catalog(self) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        """Assign sequential citation tags [R1], [R2], ... to every unique SHA-256 EvidenceReceipt."""
        catalog: List[Dict[str, Any]] = []
        id_to_tag: Dict[str, str] = {}

        all_receipts = []
        for n in self.graph.nodes.values():
            all_receipts.extend(n.receipts)
        for e in self.graph.edges.values():
            all_receipts.extend(e.receipts)

        for r in all_receipts:
            if r.receipt_id in id_to_tag:
                continue
            tag = f"R{len(catalog) + 1}"
            id_to_tag[r.receipt_id] = tag
            catalog.append({
                "tag": tag,
                "receipt_id": r.receipt_id,
                "tool": r.tool,
                "domain": r.domain.value,
                "admiralty_code": r.admiralty_code,
                "selector_strength": r.selector_strength.value,
                "extracted_fact": r.extracted_fact,
                "source_url": r.source_url,
                "sha256_proof": r.sha256_proof,
            })
        return catalog, id_to_tag

    def _generate_deterministic_seat_opinion(
        self,
        seat: Dict[str, str],
        catalog: List[Dict[str, Any]],
        interconnections: Dict[str, Any],
    ) -> Tuple[str, float]:
        """
        Generate a rigorous, domain-specific Stage 1 assessment for a Council Seat,
        plus an evidentiary rigor score used for deterministic peer-review evaluation.
        """
        seat_id = seat["id"]
        target_domain = seat["domain"]
        domain_rcpts = [r for r in catalog if r["domain"] == target_domain]
        strong_rcpts = [r for r in domain_rcpts if r["selector_strength"] == SelectorStrength.STRONG.value]
        all_strong = [r for r in catalog if r["selector_strength"] == SelectorStrength.STRONG.value]

        verified_edges = [e for e in self.graph.edges.values() if e.tier == ConfidenceTier.VERIFIED]
        hyp_edges = [e for e in self.graph.edges.values() if e.tier in (ConfidenceTier.HYPOTHESIS, ConfidenceTier.CIRCUMSTANTIAL)]

        if seat_id == "red_cell_defense_skeptic":
            # Seat 5 actively audits false positives & quarantined hypotheses
            quarantined_notes = [
                f"- `{e.summary}` ({e.admiralty_code}, conf={e.confidence:.2f}): {e.skeptic_notes or 'Soft/Circumstantial selector'}"
                for e in hyp_edges[:5]
            ]
            cite_tags = ", ".join(f"[{r['tag']}]" for r in (all_strong[:3] or catalog[:2]))
            lines = [
                f"### {seat['name']} — Adversarial Red-Cell Audit",
                f"- **Evidentiary Baseline:** Reviewed `{len(catalog)}` total SHA-256 receipts (`{len(all_strong)}` Strong `A1`/`B1` selectors vs `{len(catalog) - len(all_strong)}` Soft/Circumstantial selectors) {cite_tags}.",
                f"- **Quarantined Hypotheses & Potential False Positives (`{len(hyp_edges)}` edges downgraded):**",
            ]
            if quarantined_notes:
                lines.extend(quarantined_notes)
            else:
                lines.append("- Zero uncorroborated Soft-to-Soft or mass Registered Agent links survived into the verified tier.")
            lines.append(
                f"- **Defense Counsel Thesis:** Only the `{len(verified_edges)}` verified edges backed by hard registry, cryptographic, or network selectors may be treated as proven attribution. Any keyword-only DEX ticker or news mention must remain quarantined in `HYPOTHESIS` tier until corroborated by a second orthogonal domain."
            )
            rigor = 92.0 + min(7.0, len(hyp_edges) * 1.5)
            return "\n".join(lines), rigor

        # Domain specialist seats (Seats 1..4)
        if not domain_rcpts:
            fallback_cite = f"[{catalog[0]['tag']}]" if catalog else "[R1]"
            text = (
                f"### {seat['name']}\n"
                f"- **Domain Coverage:** Zero direct `{target_domain.upper()}` receipts were triggered for `{self.graph.seed_query}` {fallback_cite}.\n"
                f"- **Assessment:** No primary `{target_domain}` anomalies detected at current hop depth; deferring primary attribution to seats with `A1`/`B1` Strong-selector hits."
            )
            return text, 55.0

        bullet_lines = [
            f"### {seat['name']}",
            f"- **Domain Evidence Collected:** `{len(domain_rcpts)}` receipts in `{target_domain.upper()}` (`{len(strong_rcpts)}` Strong `A1`/`B1` selectors).",
        ]
        for r in (strong_rcpts + [x for x in domain_rcpts if x not in strong_rcpts])[:4]:
            bullet_lines.append(
                f"- **[{r['tag']}] (`{r['admiralty_code']}` | `{r['tool']}`):** {r['extracted_fact']} (`SHA-256: {r['sha256_proof'][:12]}...`)"
            )

        # Highlight cross-domain bridges involving this seat's domain
        paths = [
            p for p in interconnections.get("cross_domain_paths", [])
            if target_domain in p.get("domains_crossed", [])
        ]
        if paths:
            top_p = paths[0]
            bullet_lines.append(
                f"- **Cross-Domain Pivot:** `{target_domain.upper()}` bridges directly into `{', '.join(top_p['domains_crossed'])}` via path: {' ──► '.join(top_p['step_labels'][:4])} (score `{top_p['path_score']}`)."
            )

        rigor = 70.0 + min(28.0, len(strong_rcpts) * 7.5 + len(domain_rcpts) * 2.0 + (6.0 if paths else 0.0))
        return "\n".join(bullet_lines), rigor

    async def _query_llm_if_configured(
        self,
        system_prompt: str,
        user_prompt: str,
        preferred_model: str,
        *,
        fast: bool = False,
        purpose: str = "council",
    ) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """Query OpenRouter (``preferred_model``) then Gemini / Anthropic / OpenAI, whichever keys are set.

        Returns ``(text or None, failures)``. No key: no request at all. Every failure is logged as an agent event
        by llm_providers and kept for the result's ``llm_status``.
        """
        outcome = await complete_with_fallback(
            system_prompt,
            user_prompt,
            providers=PROVIDER_ORDER,
            openrouter_model=preferred_model,
            fast=fast,
            max_tokens=900,
            timeout=20.0,
            graph=self.graph,
            purpose=purpose,
        )
        failures = outcome.failures()
        self._llm_failures.extend(failures)
        return outcome.text, failures

    async def stage1_collect_responses(
        self,
        catalog: List[Dict[str, Any]],
        interconnections: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Stage 1 (karpathy/llm-council): Collect independent first-opinion briefs from all 5 Council Seats in parallel.
        """
        evidence_digest = "\n".join(
            f"[{r['tag']}] ({r['admiralty_code']} | {r['domain']} | {r['selector_strength']} | {r['tool']}): {r['extracted_fact']}"
            for r in catalog[:35]
        )

        async def _eval_seat(seat: Dict[str, str]) -> Dict[str, Any]:
            det_text, det_rigor = self._generate_deterministic_seat_opinion(seat, catalog, interconnections)
            llm_resp, failures = await self._query_llm_if_configured(
                seat["role_prompt"],
                f"Target Seed: {self.graph.seed_query}\n\nEvidence Receipts:\n{evidence_digest}\n\nProvide a concise 4-bullet forensic assessment citing [R#] tags.",
                seat["default_model"],
                fast=True,
                purpose=f"council stage 1 ({seat['id']})",
            )
            return {
                "member_id": seat["id"],
                "member_name": seat["name"],
                "model": seat["default_model"],
                "domain": seat["domain"],
                "response": llm_resp or det_text,
                "evidentiary_rigor_score": round(det_rigor, 1),
                "mode": "llm_council_api" if llm_resp else "deterministic_specialist_seat",
                "llm_failures": failures,
            }

        return list(await asyncio.gather(*[_eval_seat(s) for s in COUNCIL_SEATS]))

    async def stage2_collect_rankings(
        self,
        stage1_results: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, str]]]:
        """
        Stage 2: anonymize Stage 1 responses as Response A..E and rank them with the deterministic evidence rubric
        (:func:`deterministic_rubric_score`). No LLM is consulted, so this is NOT a peer review: every seat's
        ballot is the same ranking, kept one-per-seat only for result-schema compatibility.
        """
        labels = [chr(65 + i) for i in range(len(stage1_results))]  # A, B, C, D, E
        label_to_member: Dict[str, Dict[str, str]] = {}
        labeled_items: List[Tuple[str, Dict[str, Any]]] = []

        for label, s1 in zip(labels, stage1_results):
            label_to_member[f"Response {label}"] = {
                "id": s1["member_id"],
                "name": s1["member_name"],
                "default_model": s1["model"],
            }
            labeled_items.append((f"Response {label}", s1))

        scored: List[Tuple[float, str, str]] = []
        for resp_label, candidate in labeled_items:
            score = deterministic_rubric_score(candidate)
            citation_cnt = len(re.findall(r"\[R\d+\]", candidate["response"]))
            note = (
                f"{resp_label}: cites {citation_cnt} receipts, rigor {candidate['evidentiary_rigor_score']:.0f}/100, "
                f"rubric score {score:.1f}."
            )
            scored.append((score, resp_label, note))
        scored.sort(key=lambda x: x[0], reverse=True)  # stable: ties keep label order
        ranking_text = (
            "DETERMINISTIC EVIDENCE-RUBRIC RANKING (not an LLM peer review; score = rigor + min(15, 3 x [R#] cites)):\n"
            + "\n".join(f"- {note}" for _, _, note in scored)
            + "\n\nFINAL RANKING:\n"
            + "\n".join(f"{pos}. {r_lbl}" for pos, (_, r_lbl, _) in enumerate(scored, start=1))
        )
        parsed = parse_ranking_from_text(ranking_text)

        stage2_results: List[Dict[str, Any]] = [
            {
                "reviewer_id": reviewer["member_id"],
                "reviewer_name": reviewer["member_name"],
                "model": reviewer["model"],
                "method": STAGE2_METHOD,
                "ranking": ranking_text,
                "parsed_ranking": list(parsed),
            }
            for reviewer in stage1_results
        ]

        return stage2_results, label_to_member

    async def stage3_synthesize_final(
        self,
        catalog: List[Dict[str, Any]],
        stage1_results: List[Dict[str, Any]],
        stage2_results: List[Dict[str, Any]],
        aggregate_rankings: List[Dict[str, Any]],
        interconnections: Dict[str, Any],
        cross_case_hits: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Stage 3 (karpathy/llm-council): The Chairman synthesizes all 5 Stage 1 specialist briefs +
        the Stage 2 deterministic ranking into the final Council Verdict.
        """
        ach = self.graph.run_skeptic_network_analytics()
        top_ranked = aggregate_rankings[0] if aggregate_rankings else {"member_name": "Council Consensus", "average_rank": 1.0}

        verified_edges = [e for e in self.graph.edges.values() if e.tier == ConfidenceTier.VERIFIED and e.receipts]
        circumstantial_edges = [e for e in self.graph.edges.values() if e.tier == ConfidenceTier.CIRCUMSTANTIAL and e.receipts]
        hypothesis_edges = [e for e in self.graph.edges.values() if e.tier == ConfidenceTier.HYPOTHESIS]

        id_to_tag = {r["receipt_id"]: r["tag"] for r in catalog}

        md_lines = [
            f"## 🏛️ KARPATHY LLM-COUNCIL DELIBERATION VERDICT: `{self.graph.seed_query}`",
            f"**Top-Ranked Council Seat (deterministic rubric):** **{top_ranked['member_name']}** (Avg Rank: `{top_ranked['average_rank']}`) | **CIA ACH Winner:** **{ach.winning_hypothesis}**",
            "",
            f"### 1. Stage 2 {STAGE2_LABEL}",
            "*Ranked by a fixed rule (rigor score + 3 per [R#] citation, max +15); no model reviewed the briefs.*",
            "| Rank | Council Seat | Anonymized Label | Avg Rank | Ballots |",
            "| :---: | :--- | :---: | :---: | :---: |",
        ]
        for idx, item in enumerate(aggregate_rankings, start=1):
            md_lines.append(
                f"| **#{idx}** | {item['member_name']} | `{item['anonymous_label']}` | **{item['average_rank']:.2f}** | `{item['rankings_count']}/5` |"
            )

        md_lines.extend([
            "",
            "### 2. Tier 1: Proven Multi-Domain Facts (`VERIFIED` — NATO `A1`/`B1` Strong Selectors)",
        ])
        if verified_edges:
            for e in verified_edges[:8]:
                rcpt = e.receipts[0]
                tag = id_to_tag.get(rcpt.receipt_id, "R1")
                md_lines.append(
                    f"- **[{tag}] (`{e.admiralty_code}` | `{e.relation.value}`):** {rcpt.extracted_fact} *(Confidence: `{e.confidence:.2f}`, SHA-256: `{rcpt.sha256_proof[:12]}...`)*"
                )
        else:
            md_lines.append("- No `VERIFIED` (`A1`/`B1`) edges recorded at current depth.")

        md_lines.extend([
            "",
            "### 3. Tier 2 & 3: Quarantined Hypotheses & Red-Cell Skeptic Filter (`CIRCUMSTANTIAL` / `HYPOTHESIS`)",
        ])
        quarantined = hypothesis_edges + circumstantial_edges
        if quarantined:
            for e in quarantined[:6]:
                first_receipt = e.receipts[0] if e.receipts else None
                tag = id_to_tag.get(first_receipt.receipt_id, "R?") if first_receipt else "R?"
                note = e.skeptic_notes or "Soft selector match; requires orthogonal Strong-selector corroboration."
                md_lines.append(
                    f"- **[QUARANTINED `{e.tier.value.upper()}`] [{tag}] (`{e.admiralty_code}`):** {e.summary} — *{note}*"
                )
        else:
            md_lines.append("- Zero uncorroborated links required quarantine in this run.")

        if cross_case_hits:
            md_lines.extend([
                "",
                "### 4. Persistent Cross-Case Entity Memory Hits (`~/.bunnyhole/cases.db`)",
            ])
            for h in cross_case_hits[:5]:
                priors = ", ".join(f"`{c['case_id']}` ({c['seed_query']})" for c in h.get("prior_cases", [])[:3])
                md_lines.append(f"- **`{h['label']}` (`{h['entity_id']}`):** Previously sighted in {priors}.")

        chairman_markdown = "\n".join(md_lines)

        # Optionally augment Chairman Verdict via LLM if configured
        s1_summary = "\n\n".join(f"{r['member_name']}:\n{r['response']}" for r in stage1_results)
        s2_summary = "\n".join(
            f"#{i+1} {a['member_name']} ({a['anonymous_label']}) - Avg Rank {a['average_rank']}"
            for i, a in enumerate(aggregate_rankings)
        )
        llm_chairman, chairman_failures = await self._query_llm_if_configured(
            "You are the Chairman of the Bunnyhole Investigative Council (modeled on karpathy/llm-council). "
            "Synthesize the 5 Stage-1 specialist briefs and the Stage-2 deterministic evidence ranking into a rigorous "
            "executive conclusion. Always cite [R#] receipt tags and strictly distinguish VERIFIED A1/B1 facts from "
            "quarantined HYPOTHESIS leads.",
            f"Target: {self.graph.seed_query}\n\nStage 1 Briefs:\n{s1_summary}\n\nStage 2 Deterministic Ranking:\n{s2_summary}",
            "google/gemini-2.5-pro",
            purpose="council chairman",
        )
        if llm_chairman:
            chairman_markdown = llm_chairman.strip() + "\n\n---\n\n" + chairman_markdown

        return {
            "chairman_model": "llm_council_chairman" if llm_chairman else "deterministic_council_chairman",
            "top_ranked_seat": top_ranked,
            "verified_facts_count": len(verified_edges),
            "quarantined_hypotheses_count": len(quarantined),
            "verdict_markdown": chairman_markdown,
            "llm_failures": chairman_failures,
        }

    async def run_full_council(
        self,
        interconnections: Dict[str, Any],
        cross_case_hits: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run all 3 stages of the Karpathy Investigative Council and return full structured telemetry."""
        catalog, _ = self._build_receipt_catalog()
        self._llm_failures = []
        stage1 = await self.stage1_collect_responses(catalog, interconnections)
        stage2, label_to_member = await self.stage2_collect_rankings(stage1)
        aggregate_rankings = calculate_aggregate_rankings(stage2, label_to_member)
        stage3 = await self.stage3_synthesize_final(
            catalog,
            stage1,
            stage2,
            aggregate_rankings,
            interconnections,
            cross_case_hits or [],
        )
        self.graph.log(
            DomainCategory.SKEPTIC,
            "LLM_COUNCIL_VERDICT",
            self.graph.seed_query,
            f"3-Stage Council complete: Top Seat='{stage3['top_ranked_seat']['member_name']}' (Avg Rank {stage3['top_ranked_seat']['average_rank']}), "
            f"Verified Edges={stage3['verified_facts_count']}, Quarantined Hypotheses={stage3['quarantined_hypotheses_count']}",
            receipt_count=len(catalog),
            level="discovery",
        )
        return {
            "stage1_opinions": stage1,
            "stage2_peer_rankings": stage2,
            "label_to_member": label_to_member,
            "aggregate_rankings": aggregate_rankings,
            "stage3_chairman_verdict": stage3,
            "stage2_method": STAGE2_METHOD,
            "stage2_label": STAGE2_LABEL,
            "llm_status": {
                "configured_providers": configured_providers(PROVIDER_ORDER),
                "failures": list(self._llm_failures),
            },
        }
