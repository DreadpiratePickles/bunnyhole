"""LLM & Deterministic Investigative Synthesizer: Produces citation-backed Bellingcat/Hindenburg-style intelligence briefs and next-hop hypotheses."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.llm_providers import complete_with_fallback, configured_providers, llm_max_tokens

#: Direct providers tried in order for the narrative synthesis (OpenRouter is the council's per-seat route).
SYNTHESIS_PROVIDERS: Tuple[str, ...] = ("gemini", "anthropic", "openai")

#: Per-provider-attempt HTTP timeout. A thinking model with the shared token budget can legitimately take a while.
SYNTHESIS_TIMEOUT_S = 120.0


class InvestigativeSynthesizer:
    """
    Synthesizes accumulated `learnings[]`, SHA-256 `EvidenceReceipts`, Keystone Brokers,
    Adamic-Adar Triadic Closures, and CIA ACH scores into a citation-backed Investigative Brief.
    Supports Gemini, Anthropic Claude, OpenAI (explicit fallback chain) and a zero-key deterministic narrative engine.
    """

    def __init__(self, graph: InvestigationGraph) -> None:
        self.graph = graph

    def _collect_indexed_receipts(self) -> List[Dict[str, Any]]:
        """Collect all unique SHA-256 EvidenceReceipts across nodes AND edges with 1-based citation numbers.

        Relationship evidence lives on edges (e.g. OWNS, FIRST_FUNDED_BY, SHARES_RSID_WITH), so both
        node and edge receipts must be indexed or the brief would silently drop most of the proof.
        """
        seen_hashes: set[str] = set()
        indexed: List[Dict[str, Any]] = []

        def _add(label: str, r: Any) -> None:
            if r.sha256_proof in seen_hashes:
                return
            seen_hashes.add(r.sha256_proof)
            indexed.append(
                {
                    "cite_id": f"R{len(indexed) + 1}",
                    "entity_label": label,
                    "tool": r.tool,
                    "domain": r.domain.value,
                    "admiralty_code": r.admiralty_code,
                    "source_class": (r.source_class.value if r.source_class else "PAI"),
                    "extracted_fact": r.extracted_fact,
                    "source_url": r.source_url,
                    "sha256_short": r.sha256_proof[:12],
                }
            )

        for n in self.graph.nodes.values():
            for r in n.receipts:
                _add(n.label, r)
        for e in self.graph.edges.values():
            for r in e.receipts:
                _add(e.summary or f"{e.source_id} → {e.target_id}", r)
        return indexed

    def build_deterministic_brief(
        self,
        learnings: List[str],
        interconnections: Dict[str, Any],
        cross_case_hits: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate a rigorous citation-backed investigative brief without requiring any external LLM API key."""
        receipts = self._collect_indexed_receipts()
        ach = self.graph.run_skeptic_network_analytics()

        # Unique indexed receipts (the [R#] citations) vs. attachments: one receipt can sit on several nodes and
        # edges, so the attachment count is larger. Same formula as graph.to_dict()["stats"]["total_receipts"].
        attachment_count = sum(len(n.receipts) for n in self.graph.nodes.values()) + sum(
            len(e.receipts) for e in self.graph.edges.values()
        )

        pai_count = sum(1 for r in receipts if r["source_class"] == "PAI")
        cai_count = sum(1 for r in receipts if r["source_class"] == "CAI")
        cai_tools = sorted({r["tool"] for r in receipts if r["source_class"] == "CAI"})

        high_smoke_nodes = sorted(
            self.graph.nodes.values(),
            key=lambda x: (x.is_cutout_broker, x.smoke_score),
            reverse=True,
        )[:6]

        keystones = interconnections.get("keystone_brokers", [])
        paths = interconnections.get("targeted_paths") or interconnections.get("cross_domain_paths", [])
        preds = interconnections.get("predicted_missing_links", [])

        sections: List[str] = []

        # 1. Executive Intelligence Lead
        sections.append(
            f"### 1. Executive Intelligence Lead\n"
            f"Investigation **`{self.graph.case_id}`** into seed **`{self.graph.seed_query}`** mapped "
            f"**{len(self.graph.nodes)} entities**, **{len(self.graph.edges)} edges**, and "
            f"**{len(receipts)} unique SHA-256 receipts ({attachment_count} receipt attachments across nodes and edges)** across "
            f"**{len({n.domain.value for n in self.graph.nodes.values()})} intelligence domains**.\n\n"
            f"- **CIA ACH Verdict:** `{ach.winning_hypothesis}` — {ach.narrative_verdict}\n"
            f"- **Source Provenance (ODNI):** {pai_count} PAI (publicly available) · {cai_count} CAI (commercially acquired)."
        )

        # 2. High-Smoke Entities & Keystone Cut-Out Brokers
        broker_lines = []
        if keystones:
            for k in keystones[:4]:
                broker_lines.append(
                    f"- **Keystone Broker `{k['label']}`** (`{k['entity_type']}`): Bridges `{', '.join(k['domains_bridged'])}` "
                    f"(Betweenness Centrality $C_B = {k['betweenness_centrality']}$, Domain Entropy $H = {k['domain_entropy']}$, Smoke = `{k['smoke_score']}/100`)."
                )
        else:
            for n in high_smoke_nodes[:4]:
                flags = ", ".join(n.risk_flags[:3]) or "STANDARD_NODE"
                broker_lines.append(
                    f"- **`{n.label}`** (`{n.domain.value}` | Smoke `{n.smoke_score:.0f}/100`): Flags: `{flags}`."
                )
        sections.append("### 2. Keystone Cut-Out Brokers & High-Smoke Entities\n" + "\n".join(broker_lines))

        # 3. Cross-Domain Interconnection Chains & Triadic Closure
        chain_lines = []
        for p in paths[:4]:
            chain_lines.append(
                f"- **[{p['hop_count']}-Hop Chain | Score `{p['path_score']}` | Domains: `{', '.join(p['domains_crossed'])}`]:** "
                + " $\\longrightarrow$ ".join(f"`{lbl}`" for lbl in p.get("step_labels", []))
            )
        for pr in preds[:3]:
            chain_lines.append(
                f"- **[Adamic-Adar Triadic Closure `AA={pr['adamic_adar_score']}`]:** Predicted hidden link between "
                f"**`{pr['node_a_label']}`** and **`{pr['node_b_label']}`** via rare shared intermediary `{', '.join(pr['shared_intermediaries'][:2])}`."
            )
        if chain_lines:
            sections.append("### 3. Multi-Domain Interconnection & Money/Identity Trails\n" + "\n".join(chain_lines))

        # 4. Cross-Case Memory Overlaps
        if cross_case_hits:
            cc_lines = [
                f"- **`{h['label']}` (`{h['entity_id']}`)** previously appeared in "
                + ", ".join(f"Case `{c['case_id']}` (seed: `{c['seed_query']}`)" for c in h["prior_cases"][:3])
                for h in cross_case_hits
            ]
            sections.append("### 4. Cross-Case Entity Memory Hits (`~/.bunnyhole/cases.db`)\n" + "\n".join(cc_lines))

        # 5. Primary Citation-Backed Findings
        cite_lines = []
        for r in receipts[:12]:
            cite_lines.append(
                f"- **[{r['cite_id']} | NATO `{r['admiralty_code']}` | `{r['tool']}` | SHA256 `{r['sha256_short']}`]:** "
                f"{r['extracted_fact']} ([Source]({r['source_url']}))"
            )
        sections.append("### 5. Primary Cryptographic Evidence Receipts\n" + ("\n".join(cite_lines) or "- No receipts collected."))

        # 6. Source Provenance — ODNI IC OSINT Strategy PAI/CAI catalog
        total_cls = pai_count + cai_count
        pai_pct = (pai_count / total_cls * 100) if total_cls else 0.0
        prov_lines = [
            f"- **Publicly Available Information (PAI):** `{pai_count}` receipts ({pai_pct:.0f}% of graded evidence) — free/public endpoints, keyless by default.",
            f"- **Commercially Available Information (CAI):** `{cai_count}` receipts"
            + (f" via `{', '.join(cai_tools)}`." if cai_tools else " — none; this investigation stands entirely on public data."),
        ]
        sections.append(
            "### 6. Source Provenance — PAI vs CAI (ODNI IC OSINT Strategy)\n" + "\n".join(prov_lines)
        )

        # 7. Key Assumptions Check — CIA Structured Analytic Technique
        if ach.key_assumptions:
            _frag_icon = {"FRAGILE": "🔴", "SUPPORTED": "🟡", "SOLID": "🟢"}
            ka_lines = []
            for ka in ach.key_assumptions:
                icon = _frag_icon.get(ka.fragility.value, "🟡")
                ka_lines.append(
                    f"- {icon} **[{ka.fragility.value}]** {ka.assumption}\n"
                    f"  - *If wrong:* {ka.if_wrong}\n"
                    f"  - *Signal:* {ka.supporting_signal}"
                )
            fragile_n = sum(1 for ka in ach.key_assumptions if ka.fragility.value == "FRAGILE")
            header = (
                f"### 7. Key Assumptions Check (CIA SAT)\n"
                f"These assumptions underpin the verdict above — **findings are leads, not verdicts**. "
                f"{fragile_n} flagged 🔴 FRAGILE.\n"
            )
            sections.append(header + "\n".join(ka_lines))

        markdown_brief = "\n\n".join(sections)
        return {
            "engine": "deterministic_evidence_synthesizer",
            "llm_provider": None,
            "markdown_brief": markdown_brief,
            "citation_count": len(receipts),
            "receipt_index": receipts[:25],
        }

    async def synthesize_investigation(
        self,
        learnings: List[str],
        interconnections: Dict[str, Any],
        cross_case_hits: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Produce the deterministic citation-backed brief first, and if an LLM API key
        (GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY) is configured, augment it with an AI narrative.

        Providers are tried in order (Gemini, Anthropic, OpenAI) until one answers; each failure is logged and
        listed in ``llm_fallback`` (``reason`` + ``failures``). With no key nothing is sent anywhere.
        """
        base_report = self.build_deterministic_brief(learnings, interconnections, cross_case_hits)
        receipts = base_report["receipt_index"]

        base_report["llm_fallback"] = {"reason": "no_provider_configured", "failures": []}
        if not configured_providers(SYNTHESIS_PROVIDERS):
            return base_report
        if not receipts:
            base_report["llm_fallback"] = {"reason": "no_receipts", "failures": []}
            return base_report

        prompt_facts = "\n".join(
            f"[{r['cite_id']} | NATO {r['admiralty_code']} | {r['tool']} | SHA256:{r['sha256_short']}] {r['extracted_fact']}"
            for r in receipts[:20]
        )
        system_prompt = (
            "You are a senior investigative journalist (Bellingcat/ICIJ), forensic short-seller (Hindenburg Research), "
            "and on-chain sleuth (ZachXBT). Write a concise, hard-hitting 3-paragraph investigative synthesis of the "
            "provided verified evidence receipts. Every factual claim MUST cite its exact receipt tag like [R1] or [R2]. "
            "Highlight cross-domain bridges, financial/on-chain anomalies, and what the investigator should subpoena or pivot on next. "
            "Never invent facts outside the provided receipts."
        )
        outcome = await complete_with_fallback(
            system_prompt,
            f"Seed: {self.graph.seed_query}\n\nReceipts:\n{prompt_facts}",
            providers=SYNTHESIS_PROVIDERS,
            max_tokens=llm_max_tokens(),
            timeout=SYNTHESIS_TIMEOUT_S,
            graph=self.graph,
            purpose="investigative synthesis",
        )
        base_report["llm_fallback"] = {"reason": outcome.reason, "failures": outcome.failures()}

        if outcome.text:
            base_report["engine"] = "hybrid_llm_and_deterministic_synthesizer"
            base_report["llm_provider"] = outcome.model
            base_report["llm_provider_name"] = outcome.provider
            base_report["markdown_brief"] = (
                f"### 🤖 AI Investigative Analyst Synthesis (`{outcome.model}`)\n{outcome.text.strip()}\n\n---\n\n"
                + base_report["markdown_brief"]
            )
        elif outcome.attempts:
            failed = "; ".join(a.describe() for a in outcome.attempts)
            base_report["markdown_brief"] = (
                f"> **LLM synthesis unavailable** ({failed}). Showing the deterministic evidence brief only.\n\n"
                + base_report["markdown_brief"]
            )

        return base_report
