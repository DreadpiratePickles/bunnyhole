"""Bunnyhole Rich CLI: Autonomous Multi-Domain Investigation, Bidirectional Link Sleuth, Corporate Jet Tracker, Document Forensics, and War-Room Server."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, List, Optional, TypedDict

import typer
import uvicorn
from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.panel import Panel
from rich.table import Table

from bunnyhole.agents.accountant import AccountantAgent, n_number_to_icao_hex
from bunnyhole.agents.journalist import JournalistAgent
from bunnyhole.agents.osint import OSINTAgent
from bunnyhole.cli import pi_commands
from bunnyhole.cli.ask_command import register_ask
from bunnyhole.cli.pi_commands import SubjectType
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.intake import AnchorMode, CaseIntakePacket, SmartIntakeParser
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator
from bunnyhole.engine.pi import CaseType, PIEngagement
from bunnyhole.engine.pi_credentials import REDACTED_CREDENTIAL, strip_packet_credentials

if TYPE_CHECKING:
    from bunnyhole.arsenal.manager import ArsenalManager

app = typer.Typer(
    name="bunnyhole",
    help="🐇🕳️ Bunnyhole: Autonomous Multi-Domain Investigative AI (Journalism, Forensic Accounting, Red Team OSINT, Link Sleuth & On-Chain Crypto)",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
app.add_typer(pi_commands.pi_app, name="pi")
register_ask(app)  # `bunnyhole ask "<question>"`: bunnyhole/cli/ask_command.py


class _EngagementKwargs(TypedDict, total=False):
    engagement: PIEngagement
    pi_loop: str
    pi_budget: int


def _engagement_kwargs(
    engagement: Optional[PIEngagement],
    *,
    pi_loop: Optional[str] = None,
    pi_budget: Optional[int] = None,
) -> _EngagementKwargs:
    """``engagement=`` only in PI mode. Loop and budget are passed only when the caller set those flags."""
    if engagement is None:
        return {}
    kwargs: _EngagementKwargs = {"engagement": engagement}
    if pi_loop is not None:
        kwargs["pi_loop"] = pi_loop
    if pi_budget is not None:
        kwargs["pi_budget"] = pi_budget
    return kwargs


def _version_callback(value: bool) -> None:
    if value:
        import bunnyhole

        console.print(f"bunnyhole {bunnyhole.__version__}")
        raise typer.Exit()


PERSONA_HELP = "Run through an investigator persona lens for this case (see `bunnyhole personas`)."


def _persona_option(value: Optional[str]) -> Optional[str]:
    """Typer callback for every ``--persona``: case-insensitive, and an unknown key is a usage error (exit 2)."""
    if value is None:
        return None
    from bunnyhole.engine.personas import UnknownPersonaError, parse_persona

    try:
        return parse_persona(value).value
    except UnknownPersonaError as exc:
        raise typer.BadParameter(str(exc)) from None


DEPTH_MIN, DEPTH_MAX = 1, 4
BREADTH_MIN, BREADTH_MAX = 2, 8


@app.callback()
def _global_options(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Print the Bunnyhole version and exit."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Route all outbound HTTP through this proxy (e.g. http://host:8080 or socks5h://127.0.0.1:9050)."
    ),
    tor: bool = typer.Option(
        False, "--tor", help="Shortcut for --proxy socks5h://127.0.0.1:9050 (route everything via a local Tor SOCKS listener)."
    ),
) -> None:
    """🐇🕳️ Bunnyhole global options (apply to every command)."""
    from bunnyhole.engine import netutil

    # An operator can also set BUNNYHOLE_TOR_PROXY to point --tor / onion fetches at a non-default
    # Tor SOCKS listener, and BUNNYHOLE_PROXY as a standing default proxy when no flag is given.
    tor_override = os.environ.get("BUNNYHOLE_TOR_PROXY", "").strip()
    if tor_override:
        try:
            netutil.set_tor_proxy(tor_override)
        except netutil.InvalidProxyError as exc:
            console.print(f"[bold yellow]⚠ Ignoring invalid BUNNYHOLE_TOR_PROXY:[/bold yellow] {exc}")

    chosen = proxy or (netutil.get_tor_proxy() if tor else None) or os.environ.get("BUNNYHOLE_PROXY", "").strip() or None
    if not chosen:
        return
    try:
        netutil.set_default_proxy(chosen)
    except netutil.InvalidProxyError as exc:
        console.print(f"[bold red]Invalid --proxy:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    console.print(f"[dim]🧅 Routing outbound traffic through proxy:[/dim] [cyan]{chosen}[/cyan]")


def _render_investigation_results(result: dict) -> None:
    stats = result.get("stats", {})
    ach = result.get("ach_assessment", {})
    deep = result.get("deep_research", {})
    inter = result.get("interconnections", {})

    console.print()
    console.print(
        Panel(
            f"[bold cyan]Case ID:[/bold cyan] {result['case_id']}  |  "
            f"[bold yellow]Seed:[/bold yellow] {result['seed_query']}  |  "
            f"[bold magenta]Gear:[/bold magenta] {deep.get('gear', 'fast').upper()} "
            f"(Breadth={deep.get('initial_breadth')}, Depth={deep.get('max_depth')})\n"
            f"[bold green]Entities:[/bold green] {stats.get('total_nodes', 0)}  |  "
            f"[bold green]Edges:[/bold green] {stats.get('total_edges', 0)}  |  "
            f"[bold green]SHA-256 Receipts:[/bold green] {stats.get('total_receipts', 0)}  |  "
            f"[bold red]Cut-Out Brokers:[/bold red] {stats.get('cutout_brokers', 0)}\n"
            f"[bold white]CIA ACH Verdict:[/bold white] {ach.get('winning_hypothesis')}\n"
            f"[dim]{ach.get('narrative_verdict')}[/dim]",
            title="🐇🕳️ [bold white]BUNNYHOLE INTELLIGENCE SUMMARY[/bold white]",
            border_style="bright_magenta",
        )
    )

    # 1. Top High-Smoke Entities Table
    nodes_table = Table(title="🔥 Top Entities & Cross-Domain Cut-Out Brokers", show_lines=False)
    nodes_table.add_column("Entity", style="bold white")
    nodes_table.add_column("Type", style="cyan")
    nodes_table.add_column("Domain", style="magenta")
    nodes_table.add_column("Smoke", justify="right", style="bold red")
    nodes_table.add_column("Centrality", justify="right", style="yellow")
    nodes_table.add_column("Flags", style="dim")

    # PI run: nodes the identity rules set aside (name-only records, platform accounts) stay in the JSON but are
    # not ranked here, so the summary does not contradict the report's "never link on a name alone" rule.
    set_aside_ids = set(result.get("set_aside_node_ids") or [])
    nodes = sorted(
        (n for n in result.get("nodes", []) if n.get("id") not in set_aside_ids),
        key=lambda x: (x.get("is_cutout_broker", False), x.get("smoke_score", 0)),
        reverse=True,
    )
    for n in nodes[:15]:
        broker_badge = " 🔗[CUT-OUT]" if n.get("is_cutout_broker") else ""
        flags_str = ", ".join(n.get("risk_flags", [])[:3]) or "—"
        nodes_table.add_row(
            f"{n['label'][:52]}{broker_badge}",
            n["entity_type"],
            n["domain"],
            f"{n['smoke_score']:.0f}",
            f"{n.get('betweenness_centrality', 0.0):.3f}",
            flags_str[:48],
        )
    console.print(nodes_table)
    weak = result.get("set_aside_candidates") or []
    if weak or set_aside_ids:
        console.print(
            f"[dim]Set aside, not linked (weak name matches, see the JSON result): {len(weak)} candidate(s), "
            f"{len(set_aside_ids)} unanchored record(s).[/dim]"
        )

    # 2. Link Sleuth: Cross-Domain Paths & Adamic-Adar Predicted Missing Links
    if inter.get("targeted_path_note"):
        console.print(f"[yellow]{inter['targeted_path_note']}[/yellow]")
    paths = inter.get("targeted_paths") or inter.get("cross_domain_paths", [])
    if paths:
        path_table = Table(title="🔗 Link Sleuth: Multi-Domain Interconnection Chains", show_lines=True)
        path_table.add_column("Hops", justify="center", style="cyan")
        path_table.add_column("Score", justify="right", style="green")
        path_table.add_column("Domains Crossed", style="magenta")
        path_table.add_column("Interconnection Path", style="white")
        for p in paths[:6]:
            chain_str = " ──► ".join(p.get("step_labels", []))
            path_table.add_row(
                str(p["hop_count"]),
                f"{p['path_score']:.2f}",
                ", ".join(p["domains_crossed"]),
                chain_str,
            )
        console.print(path_table)

    preds = inter.get("predicted_missing_links", [])
    if preds:
        pred_table = Table(title="🧠 Link Sleuth: Adamic-Adar Predicted Hidden Connections (Triadic Closure)", show_lines=False)
        pred_table.add_column("Entity A", style="bold white")
        pred_table.add_column("Entity B", style="bold white")
        pred_table.add_column("AA Score", justify="right", style="bold yellow")
        pred_table.add_column("Shared Rare Intermediary", style="cyan")
        for pr in preds[:6]:
            pred_table.add_row(
                f"{pr['node_a_label'][:38]} ({pr['node_a_domain']})",
                f"{pr['node_b_label'][:38]} ({pr['node_b_domain']})",
                f"{pr['adamic_adar_score']:.2f}",
                ", ".join(pr["shared_intermediaries"][:2]),
            )
        console.print(pred_table)

    # 3. Cross-Case Entity Memory Hits (~/.bunnyhole/cases.db)
    cc_hits = result.get("cross_case_hits", [])
    if cc_hits:
        cc_table = Table(title="🗄️ SQLite Cross-Case Entity Memory Hits (~/.bunnyhole/cases.db)", show_lines=False)
        cc_table.add_column("Entity", style="bold yellow")
        cc_table.add_column("ID", style="cyan")
        cc_table.add_column("Previously Seen In Cases", style="white")
        for h in cc_hits[:8]:
            priors = ", ".join(f"{c['case_id']} ('{c['seed_query']}')" for c in h.get("prior_cases", [])[:3])
            cc_table.add_row(h["label"][:44], h["entity_id"][:36], priors)
        console.print(cc_table)

    # 4. Accumulated Deep-Research Learnings
    learnings = deep.get("learnings", [])
    if learnings:
        console.print("\n[bold bright_cyan]📚 Accumulated Deep-Research Learnings (with NATO Admiralty Grades):[/bold bright_cyan]")
        for item in learnings[:10]:
            console.print(f"  • {item}")

    # 5. Citation-Backed Investigative Synthesis Brief
    synthesis = result.get("synthesis", {})
    if synthesis and synthesis.get("markdown_brief"):
        from rich.markdown import Markdown

        engine_lbl = synthesis.get("llm_provider") or synthesis.get("engine", "synthesizer")
        console.print()
        console.print(
            Panel(
                Markdown(synthesis["markdown_brief"]),
                title=f"🧠 [bold white]INVESTIGATIVE SYNTHESIS BRIEF ({engine_lbl})[/bold white]",
                border_style="green",
            )
        )

    # 6. Karpathy 3-Stage LLM Council Deliberation & Chairman Verdict
    council = result.get("council", {})
    stage3 = council.get("stage3_chairman_verdict", {})
    if stage3 and stage3.get("verdict_markdown"):
        from rich.markdown import Markdown

        console.print()
        console.print(
            Panel(
                Markdown(stage3["verdict_markdown"]),
                title="🏛️ [bold bright_yellow]KARPATHY 3-STAGE LLM-COUNCIL VERDICT (STAGE 1 OPINIONS → STAGE 2 DETERMINISTIC EVIDENCE RANKING (NOT PEER REVIEW) → STAGE 3 CHAIRMAN)[/bold bright_yellow]",
                border_style="bright_yellow",
            )
        )


@app.command("council")
def council_command(
    seed: str = typer.Argument(..., help="Seed trace to investigate and deliberate before the 5-Seat Karpathy LLM Council"),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast or deep"),
    depth: int = typer.Option(1, "--depth", "-d", min=DEPTH_MIN, max=DEPTH_MAX, help="Recursive rabbit-hole depth (1-4)"),
) -> None:
    """Convene the 5-Seat Karpathy LLM Council (Stage 1 Specialist Briefs -> Stage 2 Deterministic evidence ranking (not peer review) -> Stage 3 Chairman Verdict)."""
    from rich.markdown import Markdown

    orch = BunnyholeOrchestrator(seed_query=seed, gear=gear, max_depth=depth, initial_breadth=4)
    result = asyncio.run(orch.run_investigation())
    council = result.get("council", {})
    for s1 in council.get("stage1_opinions", []):
        console.print(
            Panel(
                Markdown(s1["response"]),
                title=f"🪑 [bold cyan]STAGE 1 — {s1['member_name']}[/bold cyan] ({s1['model']} | Rigor: {s1['evidentiary_rigor_score']})",
                border_style="cyan",
            )
        )
    s3 = council.get("stage3_chairman_verdict", {})
    if s3.get("verdict_markdown"):
        console.print(
            Panel(
                Markdown(s3["verdict_markdown"]),
                title="🏛️ [bold bright_yellow]STAGE 2 & STAGE 3 — DETERMINISTIC EVIDENCE RANKING (NOT PEER REVIEW) & CHAIRMAN VERDICT[/bold bright_yellow]",
                border_style="bright_yellow",
            )
        )


@app.command("intake")
def intake_command(
    ctx: typer.Context,
    dump: Optional[str] = typer.Option(None, "--dump", help="Paste raw clipboard dump / free-text notes to auto-extract hypothesis & selectors"),
    persona: Optional[str] = typer.Option(None, "--persona", callback=_persona_option, help=PERSONA_HELP),
    hypothesis: Optional[str] = typer.Option(None, "--hypothesis", "-H", help="Working hypothesis or investigative question"),
    username: Optional[List[str]] = typer.Option(None, "--username", "-u", help="Known @username / handle (can pass multiple)"),
    email: Optional[List[str]] = typer.Option(None, "--email", "-e", help="Known email address (can pass multiple)"),
    phone: Optional[List[str]] = typer.Option(None, "--phone", "-p", help="Known phone number in E.164 or international format (here -p is --phone; on `serve`, -p is --port)"),
    cred: Optional[List[str]] = typer.Option(None, "--cred", "-c", help="Known leaked credential combo email:password or hash"),
    wallet: Optional[List[str]] = typer.Option(None, "--wallet", "-w", help="Known crypto wallet, ENS (.eth), or BTC address"),
    domain: Optional[List[str]] = typer.Option(None, "--domain", help="Known domain or IPv4 address"),
    org: Optional[List[str]] = typer.Option(None, "--org", help="Known company, person name, or aircraft tail number"),
    doc: Optional[List[str]] = typer.Option(None, "--doc", help="Local .pdf or .docx evidence file path"),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", "-x", help="Negative scope exclusion (domain, wallet, term to ignore)"),
    anchor_mode: AnchorMode = typer.Option(
        AnchorMode.CONVERGENCE,
        "--anchor-mode",
        help="convergence (prove IF/HOW clues connect) or locked_profile (confirmed same target entity)",
    ),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast or deep"),
    depth: int = typer.Option(2, "--depth", "-d", min=DEPTH_MIN, max=DEPTH_MAX, help="Recursive rabbit-hole depth (1-4)"),
    breadth: int = typer.Option(4, "--breadth", "-b", min=BREADTH_MIN, max=BREADTH_MAX, help="Parallel search breadth per depth level (2-8)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Export full Markdown Dossier to file path"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export full Universal Graph JSON to file path"),
    pi: bool = typer.Option(False, "--pi", help="Private-investigator engagement: vets --purpose, uses the PI persona, adds a PI block (labels, coverage, custodians)."),
    case_type: Optional[CaseType] = typer.Option(None, "--case-type", help="PI case type (default due_diligence): locate, background, asset_search, due_diligence, fraud_screen, missing_person. Needs --pi."),
    purpose: Optional[str] = typer.Option(None, "--purpose", help="PI: the client's written purpose / the decision this serves (required with --pi). Employment, tenancy, credit and insurance decisions are refused."),
    purpose_category: Optional[str] = typer.Option(None, "--purpose-category", help=pi_commands.PURPOSE_CATEGORY_HELP),
    client: Optional[str] = typer.Option(None, "--client", help="PI: client name for the engagement record. Needs --pi."),
    matter_ref: Optional[str] = typer.Option(None, "--matter-ref", help="PI: case no., contract or judgment reference. REQUIRED for every person subject (any category); optional for an entity, but checked if given. Format check only. Needs --pi."),
    subject_type: Optional[SubjectType] = typer.Option(None, "--subject-type", help="PI: person or entity (default person). Needs --pi."),
    pi_jurisdiction: Optional[str] = typer.Option(None, "--pi-jurisdiction", help="PI: jurisdiction for custodians and legal notes, e.g. us, ca-on, uk. Needs --pi."),
    pi_report: Optional[Path] = typer.Option(None, "--pi-report", help="PI: write the bottom-line-up-front PI report (Markdown) to this path. Needs --pi."),
    no_ai_analysis: bool = typer.Option(False, "--no-ai-analysis", help="PI: no AI-written text in --pi-report (no LLM call is made for the report); the account is written by code from the case file instead. Needs --pi-report."),
    confirm_entity: bool = typer.Option(False, "--confirm-entity", help="PI: confirm a person-like seed really is an organisation when --subject-type entity. Needs --pi."),
    pi_loop: Optional[str] = typer.Option(None, "--pi-loop", help="PI: casework (the default) works the case like an investigator: a lead sheet, pivots off what each lead returns, questions answered one by one, run by an AI case officer when a provider key is set. sweep is the old single pass. Needs --pi."),
    pi_budget: Optional[int] = typer.Option(None, "--pi-budget", help="PI: source-call cap for casework, an integer from 10 to 400 (default 120, not a measured percentile). Needs --pi."),
    chase: bool = typer.Option(False, "--chase", help="PI: when the case stops, show the leads left on the sheet and ask which to chase (interactive; each round adds 40 source calls). Needs --pi."),
) -> None:
    """Run a Dual-Mode Case Intake investigation combining a Working Hypothesis with multiple known credentials/selectors."""
    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            console.print(f"[dim][{d['agent'].upper()}][/dim] [bold]{_rich_escape(str(d['action']))}[/bold] ({_rich_escape(str(d['target']))}): {_rich_escape(str(d['detail']))}")

    pi_commands.require_report_for_ai_flag(no_ai_analysis, pi_report)
    engagement, persona = pi_commands.resolve_pi_flags(
        pi=pi, case_type=case_type, purpose=purpose, client=client, matter_ref=matter_ref,
        subject_type=subject_type, pi_jurisdiction=pi_jurisdiction, pi_report=pi_report, persona=persona,
        cred=cred, confirm_entity=confirm_entity, seed=((org[0] if org else None) or dump),
        orgs=list(org or []), emails=list(email or []), domains=list(domain or []),
        purpose_category=purpose_category,
        extra_texts=[
            hypothesis or "", dump or "", *(username or []), *(phone or []), *(wallet or []),
            *(exclude or []), *(doc or []),
        ],
        pi_loop=pi_loop, pi_budget=pi_budget, chase=chase,
    )
    report_builder = pi_commands.load_report_builder(pi_report)
    prof, gear, depth, breadth, exclusions = _personalize(ctx, gear, depth, breadth, list(exclude or []), persona)

    packet = CaseIntakePacket(
        hypothesis=hypothesis or "",
        anchor_mode=anchor_mode,
        usernames=list(username or []),
        emails=list(email or []),
        phones=list(phone or []),
        credentials=list(cred or []),
        wallets=list(wallet or []),
        domains=list(domain or []),
        organizations=list(org or []),
        evidence_files=list(doc or []),
        exclusions=exclusions,
        raw_omni_text=dump or "",
        gear=gear,
        depth=depth,
        breadth=breadth,
    )
    if engagement is not None:
        # PI mode: scrub credential shapes BEFORE the parser derives selectors from the raw text (a URL with userinfo
        # would otherwise yield an "email" such as SECRET@acme.com); a marker keeps the dropped count visible.
        packet, dropped_credentials, _ = strip_packet_credentials(packet)
        if dropped_credentials:
            packet = packet.model_copy(update={"credentials": [REDACTED_CREDENTIAL]})
    normalized = SmartIntakeParser.normalize_packet(packet)
    if not normalized.all_seed_tuples() and not normalized.raw_omni_input.strip():
        # Nothing to investigate: the orchestrator would run (and save) an empty case. A hypothesis or exclusions
        # alone are not seeds.
        console.print(
            "[bold red]Error:[/bold red] intake needs at least one selector: --dump, --username, --email, --phone, "
            "--cred, --wallet, --domain, --org or --doc (a --hypothesis or --exclude alone is not a seed)."
        )
        raise typer.Exit(2)
    orch = BunnyholeOrchestrator(
        seed_query=normalized.summary_seed_label(),
        gear=gear,
        max_depth=depth,
        initial_breadth=breadth,
        event_callback=_on_event,
        intake_packet=normalized,
        profile=prof,
        **_engagement_kwargs(engagement, pi_loop=pi_loop, pi_budget=pi_budget),
    )
    result = asyncio.run(orch.run_intake_investigation(normalized))
    _render_investigation_results(result)
    if engagement is not None:
        pi_commands.render_pi_summary(result)
        if chase:
            result = pi_commands.chase_leads_interactively(orch, result)
        pi_commands.write_pi_report(report_builder, result, pi_report, ai_analysis=not no_ai_analysis)

    if out:
        md = orch.graph.export_markdown_dossier()
        out.write_text(md, encoding="utf-8")
        console.print(f"\n[bold green]✔ Saved Markdown Dossier to:[/bold green] {out}")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[bold green]✔ Saved Universal Graph JSON to:[/bold green] {json_out}")


@app.command("trace")
def trace_command(
    ctx: typer.Context,
    seed: str = typer.Argument(..., help="Any seed trace: company, domain, EVM/BTC wallet, ENS (.eth), @handle, email, or tail number"),
    persona: Optional[str] = typer.Option(None, "--persona", callback=_persona_option, help=PERSONA_HELP),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast (Gear 1) or deep (Gear 2)"),
    depth: int = typer.Option(2, "--depth", "-d", min=DEPTH_MIN, max=DEPTH_MAX, help="Recursive rabbit-hole depth (1-4)"),
    breadth: int = typer.Option(4, "--breadth", "-b", min=BREADTH_MIN, max=BREADTH_MAX, help="Parallel search breadth per depth level (2-8)"),
    hypothesis: Optional[str] = typer.Option(None, "--hypothesis", "-H", help="Optional working hypothesis to steer ACH and lead priority"),
    username: Optional[List[str]] = typer.Option(None, "--username", "-u", help="Additional known @username (repeatable)"),
    email: Optional[List[str]] = typer.Option(None, "--email", "-e", help="Additional known email (repeatable)"),
    phone: Optional[List[str]] = typer.Option(None, "--phone", "-p", help="Additional known phone number (here -p is --phone; on `serve`, -p is --port)"),
    cred: Optional[List[str]] = typer.Option(None, "--cred", "-c", help="Additional known leaked credential (email:pass) (repeatable)"),
    wallet: Optional[List[str]] = typer.Option(None, "--wallet", "-w", help="Additional known wallet/ENS (repeatable)"),
    domain: Optional[List[str]] = typer.Option(None, "--domain", help="Additional known domain (repeatable)"),
    doc: Optional[List[str]] = typer.Option(None, "--doc", help="Additional local .pdf/.docx evidence file"),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", "-x", help="Negative scope exclusion"),
    anchor_mode: AnchorMode = typer.Option(AnchorMode.CONVERGENCE, "--anchor-mode", help="convergence or locked_profile"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Export full Markdown Dossier to file path"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export full Universal Graph JSON to file path"),
    pi: bool = typer.Option(False, "--pi", help="Private-investigator engagement: vets --purpose, uses the PI persona, adds a PI block (labels, coverage, custodians)."),
    case_type: Optional[CaseType] = typer.Option(None, "--case-type", help="PI case type (default due_diligence): locate, background, asset_search, due_diligence, fraud_screen, missing_person. Needs --pi."),
    purpose: Optional[str] = typer.Option(None, "--purpose", help="PI: the client's written purpose / the decision this serves (required with --pi). Employment, tenancy, credit and insurance decisions are refused."),
    purpose_category: Optional[str] = typer.Option(None, "--purpose-category", help=pi_commands.PURPOSE_CATEGORY_HELP),
    client: Optional[str] = typer.Option(None, "--client", help="PI: client name for the engagement record. Needs --pi."),
    matter_ref: Optional[str] = typer.Option(None, "--matter-ref", help="PI: case no., contract or judgment reference. REQUIRED for every person subject (any category); optional for an entity, but checked if given. Format check only. Needs --pi."),
    subject_type: Optional[SubjectType] = typer.Option(None, "--subject-type", help="PI: person or entity (default person). Needs --pi."),
    pi_jurisdiction: Optional[str] = typer.Option(None, "--pi-jurisdiction", help="PI: jurisdiction for custodians and legal notes, e.g. us, ca-on, uk. Needs --pi."),
    pi_report: Optional[Path] = typer.Option(None, "--pi-report", help="PI: write the bottom-line-up-front PI report (Markdown) to this path. Needs --pi."),
    no_ai_analysis: bool = typer.Option(False, "--no-ai-analysis", help="PI: no AI-written text in --pi-report (no LLM call is made for the report); the account is written by code from the case file instead. Needs --pi-report."),
    confirm_entity: bool = typer.Option(False, "--confirm-entity", help="PI: confirm a person-like seed really is an organisation when --subject-type entity. Needs --pi."),
    pi_loop: Optional[str] = typer.Option(None, "--pi-loop", help="PI: casework (the default) works the case like an investigator: a lead sheet, pivots off what each lead returns, questions answered one by one, run by an AI case officer when a provider key is set. sweep is the old single pass. Needs --pi."),
    pi_budget: Optional[int] = typer.Option(None, "--pi-budget", help="PI: source-call cap for casework, an integer from 10 to 400 (default 120, not a measured percentile). Needs --pi."),
    chase: bool = typer.Option(False, "--chase", help="PI: when the case stops, show the leads left on the sheet and ask which to chase (interactive; each round adds 40 source calls). Needs --pi."),
) -> None:
    """Run an autonomous multi-domain Bunnyhole investigation down the rabbit hole.

    Note: giving extra selectors (-u/-e/-p/-w/--domain/--doc/-x) or --hypothesis routes the run through `intake`,
    with SEED treated as free text; for company work with several identifiers prefer `intake --org`.
    """
    has_extra_intake = any([hypothesis, username, email, phone, cred, wallet, domain, doc, exclude])
    if has_extra_intake:
        intake_command(
            ctx=ctx,
            dump=seed,
            persona=persona,
            hypothesis=hypothesis,
            username=username,
            email=email,
            phone=phone,
            cred=cred,
            wallet=wallet,
            domain=domain,
            org=None,
            doc=doc,
            exclude=exclude,
            anchor_mode=anchor_mode,
            gear=gear,
            depth=depth,
            breadth=breadth,
            out=out,
            json_out=json_out,
            pi=pi,
            case_type=case_type,
            purpose=purpose,
            purpose_category=purpose_category,
            client=client,
            matter_ref=matter_ref,
            subject_type=subject_type,
            pi_jurisdiction=pi_jurisdiction,
            pi_report=pi_report,
            no_ai_analysis=no_ai_analysis,
            confirm_entity=confirm_entity,
            pi_loop=pi_loop,
            pi_budget=pi_budget,
        )
        return

    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            console.print(f"[dim][{d['agent'].upper()}][/dim] [bold]{_rich_escape(str(d['action']))}[/bold] ({_rich_escape(str(d['target']))}): {_rich_escape(str(d['detail']))}")

    pi_commands.require_report_for_ai_flag(no_ai_analysis, pi_report)
    engagement, persona = pi_commands.resolve_pi_flags(
        pi=pi, case_type=case_type, purpose=purpose, client=client, matter_ref=matter_ref,
        subject_type=subject_type, pi_jurisdiction=pi_jurisdiction, pi_report=pi_report, persona=persona,
        cred=cred, confirm_entity=confirm_entity, seed=seed, purpose_category=purpose_category,
        pi_loop=pi_loop, pi_budget=pi_budget, chase=chase,
    )
    report_builder = pi_commands.load_report_builder(pi_report)
    prof, gear, depth, breadth, _exclusions = _personalize(ctx, gear, depth, breadth, list(exclude or []), persona)
    orch = BunnyholeOrchestrator(
        seed_query=seed,
        gear=gear,
        max_depth=depth,
        initial_breadth=breadth,
        event_callback=_on_event,
        profile=prof,
        **_engagement_kwargs(engagement, pi_loop=pi_loop, pi_budget=pi_budget),
    )
    result = asyncio.run(orch.run_investigation())
    _render_investigation_results(result)
    if engagement is not None:
        pi_commands.render_pi_summary(result)
        if chase:
            result = pi_commands.chase_leads_interactively(orch, result)
        pi_commands.write_pi_report(report_builder, result, pi_report, ai_analysis=not no_ai_analysis)

    if out:
        md = orch.graph.export_markdown_dossier()
        out.write_text(md, encoding="utf-8")
        console.print(f"\n[bold green]✔ Saved Markdown Dossier to:[/bold green] {out}")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[bold green]✔ Saved Universal Graph JSON to:[/bold green] {json_out}")


@app.command("link")
def link_command(
    entity_a: str = typer.Argument(..., help="First entity (person, company, domain, wallet, handle)"),
    entity_b: str = typer.Argument(..., help="Second entity to connect with Entity A"),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="fast or deep gear"),
) -> None:
    """Run the Link Sleuth in Bidirectional Meet-in-the-Middle mode to discover how two entities connect."""
    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            console.print(f"[dim][{d['agent'].upper()}][/dim] [bold]{_rich_escape(str(d['action']))}[/bold] ({_rich_escape(str(d['target']))}): {_rich_escape(str(d['detail']))}")

    orch = BunnyholeOrchestrator(
        seed_query=f"{entity_a} <-> {entity_b}",
        gear=gear,
        max_depth=2,
        initial_breadth=4,
        event_callback=_on_event,
    )
    result = asyncio.run(orch.run_bidirectional_link_investigation(entity_a, entity_b))
    _render_investigation_results(result)


@app.command("jet")
def jet_command(
    tail_or_hex: str = typer.Argument(..., help="US Tail Number (e.g., N628TS) or 24-bit ICAO Mode-S Hex (6 hex digits, e.g. a835af)"),
) -> None:
    """Convert FAA N-Number <-> 24-bit ICAO Hex and query unfiltered ADS-B telemetry (adsb.lol)."""
    parsed = parse_aircraft_selector(tail_or_hex)
    if parsed is None:
        console.print(
            f"[bold red]Error:[/bold red] {_rich_escape(repr(tail_or_hex))} is neither a US N-number (e.g. N628TS) "
            "nor a 6-hex-digit ICAO Mode-S address (e.g. a835af)."
        )
        raise typer.Exit(2)
    query, icao_hex = parsed
    g = InvestigationGraph("jet_lookup", query)
    acct = AccountantAgent(g)
    info = asyncio.run(acct.investigate_aircraft_adsb(query, "seed:jet", hop_depth=1))
    console.print(
        Panel(
            _rich_escape(json.dumps(info, indent=2)),
            title=f"✈️ ADS-B Forensics: {_rich_escape(query)} (ICAO Hex: {icao_hex})",
        )
    )


_ICAO_HEX = re.compile(r"[0-9A-F]{6}")


def parse_aircraft_selector(value: str) -> Optional[tuple[str, str]]:
    """``(query, icao_hex)`` for a valid US N-number or 6-hex-digit ICAO address, else None.

    ``query`` is the normalized (upper-case) input passed to the ADS-B lookup; ``icao_hex`` is lower-case.
    """
    q = (value or "").strip().upper()
    if _ICAO_HEX.fullmatch(q):
        return q, q.lower()
    if q.startswith("N"):
        icao = n_number_to_icao_hex(q)
        if icao:
            return q, icao.lower()
    return None


@app.command("darkweb")
def darkweb_command(
    query: str = typer.Argument(..., help="Selector to search the Tor dark-web index for (domain, company, email, @handle)"),
    fetch_onion: bool = typer.Option(
        False, "--fetch-onion", help="Also fetch each .onion hit through Tor to capture its page title (requires a running Tor SOCKS proxy; pair with --tor)."
    ),
) -> None:
    """Search the Tor dark-web via Ahmia (keyless, clearnet-indexed) for public mentions of a selector."""
    g = InvestigationGraph("darkweb_search", query)
    agent = OSINTAgent(g)
    urls = asyncio.run(agent.search_darkweb_ahmia(query, "seed:darkweb", hop_depth=1, fetch_pages=fetch_onion))

    if not urls:
        console.print(f"[yellow]No dark-web (.onion) results indexed by Ahmia for[/yellow] [bold]{_rich_escape(query)}[/bold].")
        return

    d_table = Table(title=f"🧅 Ahmia Dark-Web Results for '{query}'", show_lines=False)
    d_table.add_column("Onion Service", style="bold white")
    d_table.add_column("Title", style="cyan")
    d_table.add_column("Flags", style="dim")
    for node in g.nodes.values():
        if node.entity_type.value == "OnionService":
            d_table.add_row(
                node.attributes.get("onion_host", node.label)[:48],
                (node.attributes.get("title") or "—")[:40],
                ", ".join(node.risk_flags[:2]) or "—",
            )
    console.print(d_table)
    console.print(
        "[dim]Dark-web hits are SOFT, low-confidence leads (Admiralty C3): an indexed mention is not "
        "proof of a link. Corroborate before acting.[/dim]"
    )


@app.command("anonsurf")
def anonsurf_command(
    action: str = typer.Argument(
        "status", help="status | start | stop | restart | change (new Tor identity) | install"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt for start/stop (system-wide network change)."),
) -> None:
    """Install and control anonsurf — Parrot/Kali's system-wide Tor transparent proxy (Linux, root).

    anonsurf reroutes ALL of this host's traffic through Tor via iptables to anonymize your own
    OSINT traffic. It is Linux-only and needs root (sudo will prompt). On macOS/Windows, use the
    portable `--tor` flag instead. Nothing here runs automatically — every action is explicit.
    """
    from bunnyhole.arsenal.manager import AnonsurfController

    ctl = AnonsurfController()
    act = action.strip().lower()
    valid = {"status", "start", "stop", "restart", "change", "install"}
    if act not in valid:
        console.print(f"[bold red]Unknown action '{action}'.[/bold red] Use one of: {', '.join(sorted(valid))}.")
        raise typer.Exit(2)

    if act in ("start", "stop") and not yes:
        verb = "route ALL of this machine's traffic through Tor" if act == "start" else "restore normal (clearnet) networking"
        if not typer.confirm(f"anonsurf {act} will {verb} (needs root). Continue?"):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)

    dispatch = {
        "status": ctl.status,
        "start": ctl.start,
        "stop": ctl.stop,
        "restart": ctl.restart,
        "change": ctl.change_identity,
        "install": ctl.install,
    }
    console.print(f"[bold cyan]🧅 anonsurf {act}...[/bold cyan]")
    res = dispatch[act]()
    if res.get("success"):
        detail = res.get("output") or res.get("note") or res.get("command") or res.get("method") or "done"
        console.print(f"[bold green]✔ anonsurf {act}:[/bold green] {detail}")
    else:
        console.print(f"[bold yellow]⚠ anonsurf {act} failed:[/bold yellow] {res.get('error', 'unknown error')}")
        raise typer.Exit(1)


@app.command("doc-forensics")
def doc_forensics_command(
    file_path: str = typer.Argument(..., help="Path to .docx or .pdf file to inspect for Word RSIDs or PDF XMP timezone leaks"),
) -> None:
    """Extract binary Word RSID revision fingerprints (.docx) or PDF /Info & XMP timezone metadata (.pdf).

    Exits 1 with a one-line message for a missing, unreadable, non-regular, unsupported or corrupt file.
    """

    def _fail(message: str) -> "typer.Exit":
        console.print(f"[bold red]Error:[/bold red] {_rich_escape(message)}")
        return typer.Exit(1)

    raw = (file_path or "").strip()
    if not raw:
        raise _fail("doc-forensics needs the path of a .docx or .pdf file.")
    path = Path(raw).expanduser()
    if not path.exists():
        raise _fail(f"File not found: {raw}")
    if not path.is_file():
        raise _fail(f"Not a regular file: {raw}")
    kind = DOC_FORENSICS_TYPES.get(path.suffix.lower())
    if kind is None:
        raise _fail(f"Unsupported file type '{path.suffix or '(none)'}' for {raw}: doc-forensics reads .docx and .pdf.")
    if not os.access(path, os.R_OK):
        raise _fail(f"Permission denied: cannot read {raw}")

    g = InvestigationGraph("doc_forensics", str(path))
    journo = JournalistAgent(g)
    with _quiet_document_libraries():
        res = journo.inspect_document_binary_forensics(str(path))
    if res.get("error"):
        raise _fail(f"Could not parse {raw} as {kind}: {res['error']}")
    console.print(Panel(_rich_escape(json.dumps(res, indent=2)), title=f"📄 Binary Document Forensics: {_rich_escape(raw)}"))


DOC_FORENSICS_TYPES = {".docx": "a Word .docx (zip) file", ".pdf": "a PDF"}


@contextlib.contextmanager
def _quiet_document_libraries() -> Iterator[None]:
    """Silence pypdf's logger and library warnings (e.g. 'incorrect startxref pointer') for one parse."""
    loggers = [logging.getLogger(name) for name in ("pypdf", "PyPDF2")]
    previous = [lg.level for lg in loggers]
    try:
        for lg in loggers:
            lg.setLevel(logging.CRITICAL + 1)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        for lg, level in zip(loggers, previous):
            lg.setLevel(level)


@app.command("doctor")
@app.command("arsenal")
def doctor_command(
    install: Optional[str] = typer.Option(None, "--install", "-i", help="Install a missing tool by name (e.g. sherlock, maigret, subfinder) or 'all'"),
) -> None:
    """Cross-Platform Arsenal Health Doctor & Tool Installer (Kali, Parrot OS, Debian, Arch, Fedora, macOS).

    `--install all` installs every missing catalog tool (Python libraries go into the active environment via
    `uv pip install`). Exits 1 when any requested install fails or the tool name is unknown.
    """
    from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager

    mgr = ArsenalManager()
    pinfo = mgr.platform_info
    shown_platform = _rich_escape(pinfo["display_name"])  # e.g. "[arm64]" must not be read as Rich markup

    failures = 0
    if install:
        tools_to_install = (
            [t["name"] for t in mgr.check_arsenal_status() if not t["installed"]]
            if install.strip().lower() == "all"
            else [install.strip()]
        )
        for tname in tools_to_install:
            console.print(f"[bold cyan]⚙ Installing '{_rich_escape(tname)}' on {shown_platform}...[/bold cyan]")
            res = mgr.install_tool(tname)
            if res.get("success"):
                console.print(f"[bold green]✔ Installed {_rich_escape(str(res.get('tool')))} via:[/bold green] {_rich_escape(str(res.get('command')))}")
            else:
                failures += 1
                console.print(f"[bold yellow]⚠ Could not auto-install {_rich_escape(tname)}:[/bold yellow] {_rich_escape(str(res.get('error')))}")

    tools = mgr.check_arsenal_status()
    keys = mgr.get_api_keys_status()
    installed_cnt = sum(1 for t in tools if t["installed"])
    configured_keys_cnt = sum(1 for k in keys if k["configured"])

    console.print(
        Panel(
            f"[bold cyan]Detected OS:[/bold cyan] {shown_platform}  |  "
            f"[bold magenta]Distro Profile:[/bold magenta] {_rich_escape(pinfo['distro'].upper())}  |  "
            f"[bold yellow]Package Manager:[/bold yellow] {_rich_escape(pinfo['pkg_manager'])}\n"
            f"[bold green]Tools Installed:[/bold green] {installed_cnt}/{len(tools)}  |  "
            f"[bold green]API Keys Configured:[/bold green] {configured_keys_cnt}/{len(keys)}\n"
            f"[dim]Key vault: {_rich_escape(str(BUNNYHOLE_ENV_FILE))}  (legacy, read-only: "
            f"{_rich_escape(str(LEGACY_OSINT_ENV_FILE))})[/dim]",
            title="🛠️ [bold white]BUNNYHOLE CROSS-PLATFORM ARSENAL DOCTOR[/bold white]",
            border_style="cyan",
        )
    )

    t_table = Table(title="🧰 OSINT, Forensics & Red-Team Arsenal Status", show_lines=False)
    t_table.add_column("Status", justify="center")
    t_table.add_column("Tool", style="bold white")
    t_table.add_column("Type", style="cyan")
    t_table.add_column("Location / Install hint", style="green", overflow="fold")
    t_table.add_column("Description", style="dim", overflow="fold")

    for t in tools:
        badge = "[bold green]✔ READY[/bold green]" if t["installed"] else "[yellow]○ MISSING[/yellow]"
        loc = t["location"] if t["installed"] else t["install_hint"]
        t_table.add_row(badge, t["name"], t["type"], _rich_escape(loc), _rich_escape(t["description"]))
    console.print(t_table)
    if failures:
        raise typer.Exit(1)


def _personalize(
    ctx: typer.Context,
    gear: GearMode,
    depth: int,
    breadth: int,
    exclusions: List[str],
    persona: Optional[str],
):
    """Resolve the investigator profile + run parameters for a CLI run.

    The saved profile (or a one-off ``--persona`` override) supplies the persona lens that the
    orchestrator uses for watchlist/framing/sanctions emphasis. Persona run-param *defaults* fill in
    only the gear/depth/breadth flags the user did not pass on the command line; explicit flags win.
    Standing profile exclusions are folded into the case's negative scope.
    """
    from bunnyhole.engine.personas import coerce_persona
    from bunnyhole.engine.profile import load_profile, resolve_run_params

    prof = load_profile()
    if persona:
        prof.persona = coerce_persona(persona)

    def _explicit(name: str) -> bool:
        try:
            return ctx.get_parameter_source(name).name == "COMMANDLINE"  # type: ignore[union-attr]
        except Exception:
            return True  # when we can't tell, treat the passed value as intentional

    g = gear if _explicit("gear") else None
    d = depth if _explicit("depth") else None
    b = breadth if _explicit("breadth") else None
    rg, rd, rb = resolve_run_params(prof, gear=g, depth=d, breadth=b)

    merged_exclusions = list(dict.fromkeys([*(exclusions or []), *prof.default_exclusions]))
    return prof, rg, rd, rb, merged_exclusions


@app.command("personas")
def personas_command() -> None:
    """List the investigator personas (lenses that tune gear/depth/breadth, sources & framing)."""
    from bunnyhole.engine.personas import list_personas
    from bunnyhole.engine.profile import load_profile

    active = load_profile().persona
    table = Table(title="🎭 Investigator Personas", show_lines=False)
    table.add_column("", justify="center")
    table.add_column("Key", style="bold cyan")
    table.add_column("Persona", style="bold white")
    table.add_column("Defaults", style="magenta")
    table.add_column("Sanctions", justify="center")
    table.add_column("Lens", style="dim")
    for p in list_personas():
        mark = "[bold green]●[/bold green]" if p.key == active else " "
        table.add_row(
            mark,
            p.key.value,
            p.display_name,
            f"{p.default_gear.value}/d{p.default_depth}/b{p.default_breadth}",
            "✔" if p.emphasize_sanctions else "—",
            p.description,
        )
    console.print(table)
    console.print("[dim]Set yours with:[/dim] [bold]bunnyhole profile --persona <key>[/bold]")


@app.command("profile")
def profile_command(
    persona: Optional[str] = typer.Option(None, "--persona", callback=_persona_option, help="Set the active investigator persona (see `bunnyhole personas`)."),
    name: Optional[str] = typer.Option(None, "--name", help="Set your display name (attribution on dossiers)."),
    add_watch: Optional[List[str]] = typer.Option(None, "--watch", help="Add a recurring selector to your watchlist (repeatable)."),
    remove_watch: Optional[List[str]] = typer.Option(None, "--unwatch", help="Remove a selector from your watchlist (repeatable)."),
    clear_watch: bool = typer.Option(False, "--clear-watch", help="Empty the watchlist."),
    jurisdiction: Optional[List[str]] = typer.Option(None, "--jurisdiction", help="Set standing jurisdictions of interest (replaces; repeatable)."),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", "-x", help="Set standing default exclusions folded into every case (replaces; repeatable)."),
    gear: Optional[GearMode] = typer.Option(None, "--gear", "-g", help="Override the persona's default gear."),
    depth: Optional[int] = typer.Option(None, "--depth", "-d", min=DEPTH_MIN, max=DEPTH_MAX, help="Override the persona's default depth (1-4)."),
    breadth: Optional[int] = typer.Option(None, "--breadth", "-b", min=BREADTH_MIN, max=BREADTH_MAX, help="Override the persona's default breadth (2-8)."),
    note: Optional[str] = typer.Option(None, "--note", help="Set a free-text note on your profile."),
) -> None:
    """View or edit your remembered investigator context (persona, watchlist, jurisdictions, defaults)."""
    from bunnyhole.engine.personas import coerce_persona, get_persona
    from bunnyhole.engine.profile import PROFILE_PATH, load_profile, save_profile
    from bunnyhole.engine.profile import add_watch as _add
    from bunnyhole.engine.profile import remove_watch as _rm

    prof = load_profile()
    mutated = False
    if persona is not None:
        prof.persona = coerce_persona(persona)
        mutated = True
    if name is not None:
        prof.display_name = name
        mutated = True
    if clear_watch:
        prof.watchlist = []
        mutated = True
    if add_watch:
        _add(prof, list(add_watch))
        mutated = True
    if remove_watch:
        _rm(prof, list(remove_watch))
        mutated = True
    if jurisdiction is not None:
        prof.jurisdictions = [j.strip().upper() for j in jurisdiction if j.strip()]
        mutated = True
    if exclude is not None:
        prof.default_exclusions = [e.strip() for e in exclude if e.strip()]
        mutated = True
    if gear is not None:
        prof.gear_override = gear
        mutated = True
    if depth is not None:
        prof.depth_override = depth
        mutated = True
    if breadth is not None:
        prof.breadth_override = breadth
        mutated = True
    if note is not None:
        prof.notes = note
        mutated = True

    if mutated:
        save_profile(prof)
        console.print(f"[bold green]✔ Saved profile to[/bold green] {PROFILE_PATH}")

    pp = get_persona(prof.persona)
    eg, ed, eb = prof.effective_run_params()
    console.print(
        Panel(
            f"[bold cyan]Persona:[/bold cyan] {pp.display_name} ([bold]{prof.persona.value}[/bold])  |  "
            f"[bold magenta]Name:[/bold magenta] {prof.display_name or '—'}\n"
            f"[bold yellow]Effective run defaults:[/bold yellow] gear={eg.value}, depth={ed}, breadth={eb}  "
            f"[dim](sanctions emphasis: {'on' if pp.emphasize_sanctions else 'off'})[/dim]\n"
            f"[bold green]Watchlist:[/bold green] {', '.join(prof.watchlist) or '—'}\n"
            f"[bold green]Jurisdictions:[/bold green] {', '.join(prof.jurisdictions) or '—'}  |  "
            f"[bold green]Default exclusions:[/bold green] {', '.join(prof.default_exclusions) or '—'}\n"
            f"[dim]Lens: {pp.analyst_framing}[/dim]"
            + (f"\n[dim]Note: {prof.notes}[/dim]" if prof.notes else ""),
            title="🧭 [bold white]YOUR BUNNYHOLE INVESTIGATOR PROFILE[/bold white]",
            border_style="cyan",
        )
    )
    if not mutated:
        console.print("[dim]Edit with e.g.:[/dim] [bold]bunnyhole profile --persona compliance --watch acme.io[/bold]")


@app.command("keys")
def keys_command(
    set_key: Optional[str] = typer.Option(None, "--set", "-s", help="Set an API key in KEY=VALUE format (e.g. SHODAN_API_KEY=xxx)"),
) -> None:
    """View and configure API keys in the Bunnyhole vault ($BUNNYHOLE_HOME/api_keys.env, default ~/.bunnyhole).

    Exported shell variables always win over the vault. The legacy ~/.osint-apis/api_keys.env is read (merged
    under the vault) but never written. Clear a key with --set NAME= (empty value).
    """
    from bunnyhole.arsenal import manager as arsenal

    mgr = arsenal.ArsenalManager()
    if set_key is not None:
        if not _apply_key_assignment(mgr, set_key):
            raise typer.Exit(2)

    keys = mgr.get_api_keys_status()
    k_table = Table(title=f"🔑 API Keys Vault ({arsenal.BUNNYHOLE_ENV_FILE})", show_lines=False)
    k_table.add_column("State", justify="center")
    k_table.add_column("Environment Variable", style="bold white")
    k_table.add_column("Category", style="magenta")
    k_table.add_column("Value", style="cyan")
    k_table.add_column("Free Tier / Registration URL", style="dim")

    for item in keys:
        if item["configured"]:
            badge = f"[bold green]● SET ({item.get('source') or 'vault'})[/bold green]"
        else:
            badge = "[dim]○ EMPTY[/dim]"
        val = item["masked_value"] or "—"
        info = f"{item['url']} ({item['note']})"
        if item.get("reserved"):
            info = f"({arsenal.RESERVED_LABEL}) {info}"
        k_table.add_row(badge, item["key"], item["category"], val, _rich_escape(info))
    console.print(k_table)
    console.print(
        f"[dim]Shell exports win over the vault. Legacy file {_rich_escape(str(arsenal.LEGACY_OSINT_ENV_FILE))} "
        "is read-only (merged under the vault, never written).[/dim]"
    )


def _print_allowed_key_names() -> None:
    from bunnyhole.arsenal.manager import accepted_key_names

    console.print("[bold]Allowed key names:[/bold]")
    # One soft-wrapped line: Rich wraps it at the terminal width instead of truncating.
    console.print(", ".join(accepted_key_names()), soft_wrap=False, overflow="fold")


def _store_key(mgr: "ArsenalManager", name: str, value: str) -> bool:
    """Save/clear one key through ``mgr.set_api_key`` and report it. Returns False (error printed) on bad input."""
    from bunnyhole.arsenal.manager import UnknownKeyError

    try:
        result = mgr.set_api_key(name, value)
    except UnknownKeyError:
        console.print(f"[bold red]Error:[/bold red] unknown API key name {_rich_escape(repr(name.strip()))}.")
        _print_allowed_key_names()
        return False
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {_rich_escape(str(exc))}")
        return False
    path = _rich_escape(str(result["path"]))
    if result["action"] == "cleared":
        console.print(f"[bold green]✔ Cleared {result['key']} in {path}[/bold green]")
    else:
        console.print(f"[bold green]✔ Saved {result['key']} to {path}[/bold green]")
    if result.get("shadowed_by_shell"):
        console.print(
            f"[bold yellow]⚠ {result['key']} is also exported in your shell; the shell value stays in effect "
            "until you unset it.[/bold yellow]"
        )
    return True


def _apply_key_assignment(mgr: "ArsenalManager", assignment: str) -> bool:
    """Handle ``--set NAME=VALUE``. Returns False (error printed) on malformed input or an unknown name."""
    if "=" not in assignment:
        console.print("[bold red]Error:[/bold red] Use --set KEY_NAME=VALUE (an empty VALUE clears the key).")
        _print_allowed_key_names()
        return False
    name, value = assignment.split("=", 1)
    return _store_key(mgr, name, value)


@app.command("cases")
def cases_command(
    search: Optional[str] = typer.Option(None, "--search", "-q", help="Search across all historical entity sightings in ~/.bunnyhole/cases.db"),
    load: Optional[str] = typer.Option(None, "--load", "-l", help="Reload and display a saved case by Case ID"),
) -> None:
    """Browse persistent SQLite investigations and search Cross-Case Entity Memory ($BUNNYHOLE_HOME/cases.db, default ~/.bunnyhole)."""
    from bunnyhole.engine.storage import CASES_DB_PATH, CaseStore

    if load is not None and not load.strip():
        console.print("[bold red]Error:[/bold red] --load needs a case ID (see `bunnyhole cases`).")
        raise typer.Exit(2)
    if search is not None and not search.strip():
        console.print("[bold red]Error:[/bold red] --search needs a non-empty entity substring.")
        raise typer.Exit(2)
    store = CaseStore()
    if load:
        data = store.get_case(load.strip())
        if not data:
            console.print(f"[bold red]Case '{load}' not found in {CASES_DB_PATH}[/bold red]")
            raise typer.Exit(1)
        _render_investigation_results(data)
        return

    if search:
        hits = store.search_entity_memory(search)
        s_table = Table(title=f"🔍 Cross-Case Entity Memory Search: '{search}' ({CASES_DB_PATH})", show_lines=False)
        s_table.add_column("Entity ID", style="cyan")
        s_table.add_column("Label", style="bold white")
        s_table.add_column("Domain", style="magenta")
        s_table.add_column("Smoke", justify="right", style="red")
        s_table.add_column("Case ID (Seed)", style="yellow")
        s_table.add_column("Sighted At", style="dim")
        for h in hits:
            s_table.add_row(
                h["entity_id"][:36],
                h["label"][:42],
                h["domain"],
                f"{h['smoke_score']:.0f}",
                f"{h['case_id']} ({h['seed_query']})",
                h["sighted_at"][:19],
            )
        console.print(s_table)
        return

    cases = store.list_cases(limit=25)
    c_table = Table(title=f"🗄️ Saved Investigations in SQLite Vault ({CASES_DB_PATH})", show_lines=False)
    c_table.add_column("Case ID", style="bold cyan")
    c_table.add_column("Seed Query", style="bold white")
    c_table.add_column("Gear", style="magenta")
    c_table.add_column("Nodes", justify="right", style="green")
    c_table.add_column("Edges", justify="right", style="green")
    c_table.add_column("Receipts", justify="right", style="yellow")
    c_table.add_column("Created At (UTC)", style="dim")
    for c in cases:
        c_table.add_row(
            c["case_id"],
            c["seed_query"],
            c["gear"].upper(),
            str(c["total_nodes"]),
            str(c["total_edges"]),
            str(c["total_receipts"]),
            c["created_at"][:19],
        )
    console.print(c_table)


@app.command("ui")
def ui_command(seed: str = typer.Argument("", help="Optional seed to prefill the War-Room")) -> None:
    """Launch the full-screen War-Room TUI (Textual)."""
    from bunnyhole.tui.app import launch

    launch(seed=seed or None)


@app.command("tui")
def tui_command(seed: str = typer.Argument("", help="Optional seed to prefill the War-Room")) -> None:
    """Alias for `ui` — the full-screen War-Room TUI."""
    ui_command(seed=seed)


@app.command("menu")
def menu_command(ctx: typer.Context) -> None:
    """Classic prompt-driven terminal command center (Traces, Link Sleuth, Arsenal, Keys, Cases)."""
    from rich.prompt import Prompt

    from bunnyhole.arsenal.manager import ArsenalManager

    mgr = ArsenalManager()
    while True:
        console.print()
        console.print(
            Panel(
                f"[bold white]Platform:[/bold white] {_rich_escape(mgr.platform_info['display_name'])} ({_rich_escape(mgr.platform_info['distro'].upper())})\n\n"
                "[bold cyan][1][/bold cyan] 🎯 Run Rabbit-Hole Trace (Journalism + Accounting + OSINT + On-Chain + Link Sleuth)\n"
                "[bold cyan][2][/bold cyan] 🔗 Run Bidirectional Link Sleuth (Connect Entity A ↔ Entity B)\n"
                "[bold cyan][3][/bold cyan] 🛠️  Arsenal Health Doctor & Tool Installer (Kali / Parrot / Debian / Arch / macOS)\n"
                "[bold cyan][4][/bold cyan] 🔑 Configure API Keys Vault (~/.bunnyhole/api_keys.env)\n"
                "[bold cyan][5][/bold cyan] ✈️  Track Corporate Jet (FAA Tail N-Number <-> ICAO Hex & ADS-B)\n"
                "[bold cyan][6][/bold cyan] 🗄️  Browse SQLite Case Store & Cross-Case Entity Memory (~/.bunnyhole/cases.db)\n"
                "[bold cyan][7][/bold cyan] 🌐 Launch Interactive Web War-Room UI (http://127.0.0.1:8000)\n"
                "[bold cyan][0][/bold cyan] 🚪 Exit",
                title="🐇🕳️ [bold bright_magenta]BUNNYHOLE INTERACTIVE TERMINAL COMMAND CENTER[/bold bright_magenta]",
                border_style="bright_magenta",
            )
        )
        choice = Prompt.ask("Select an operation", choices=["1", "2", "3", "4", "5", "6", "7", "0"], default="1")
        if choice == "0":
            break
        elif choice == "1":
            seed = Prompt.ask("Enter seed trace (company, domain, wallet/ENS, @handle, email, or tail number)", default="vitalik.eth")
            gear_str = Prompt.ask("Select gear", choices=["fast", "deep"], default="fast")
            depth = int(Prompt.ask("Select recursive depth", choices=[str(d) for d in range(DEPTH_MIN, DEPTH_MAX + 1)], default="2"))
            # Pass EVERY parameter explicitly: omitted Typer options would stay as truthy OptionInfo
            # objects and wrongly trigger the multi-selector intake path (TypeError on list(OptionInfo)).
            trace_command(
                ctx=ctx, seed=seed, persona=None, gear=GearMode(gear_str), depth=depth, breadth=4,
                hypothesis=None, username=None, email=None, phone=None, cred=None,
                wallet=None, domain=None, doc=None, exclude=None,
                anchor_mode=AnchorMode.CONVERGENCE, out=None, json_out=None,
                pi=False, case_type=None, purpose=None, purpose_category=None, client=None, matter_ref=None,
                subject_type=None, pi_jurisdiction=None, pi_report=None, no_ai_analysis=False, confirm_entity=False,
                pi_loop=None, pi_budget=None, chase=False,
            )
        elif choice == "2":
            ea = Prompt.ask("Enter Entity A", default="vitalik.eth")
            eb = Prompt.ask("Enter Entity B", default="ethereum.org")
            gear_str = Prompt.ask("Select gear", choices=["fast", "deep"], default="fast")
            link_command(entity_a=ea, entity_b=eb, gear=GearMode(gear_str))
        elif choice == "3":
            doctor_command(install=None)
            to_inst = Prompt.ask("Enter tool name to install (or 'all', or press Enter to skip)", default="")
            if to_inst.strip():
                try:
                    doctor_command(install=to_inst.strip())
                except typer.Exit:
                    pass  # the failure was already printed; stay in the menu
        elif choice == "4":
            keys_command(set_key=None)
            kname = Prompt.ask("Enter API Key variable name to set (or press Enter to return)", default="")
            if kname.strip():
                from bunnyhole.arsenal.manager import UnknownKeyError, canonical_key_name

                try:
                    canonical = canonical_key_name(kname)
                except UnknownKeyError:
                    console.print(f"[bold red]Error:[/bold red] unknown API key name {_rich_escape(repr(kname.strip()))}.")
                    _print_allowed_key_names()
                    continue
                kval = Prompt.ask(f"Enter value for {canonical} (empty clears it)", password=True)
                _store_key(mgr, canonical, kval)
        elif choice == "5":
            tail = Prompt.ask("Enter FAA Tail Number or ICAO Hex", default="N628TS")
            try:
                jet_command(tail_or_hex=tail)
            except typer.Exit:
                pass  # the validation error was printed; back to the menu
        elif choice == "6":
            cases_command(search=None, load=None)
            q = Prompt.ask("Enter entity substring to search across cases (or press Enter to skip)", default="")
            if q.strip():
                cases_command(search=q.strip(), load=None)
        elif choice == "7":
            serve_command(host="127.0.0.1", port=8000)


@app.command("mcp")
def mcp_command(
    print_config: bool = typer.Option(
        False,
        "--print-config",
        "-c",
        help="Print an mcpServers config snippet for registering THIS instance with an MCP client (Claude Desktop, IDE copilots), then exit.",
    ),
    no_uv: bool = typer.Option(
        False,
        "--no-uv",
        help="With --print-config, emit a plain `bunnyhole mcp` invocation instead of `uv run` (requires the bunnyhole entrypoint on PATH).",
    ),
) -> None:
    """Run this Bunnyhole instance as a Model-Context-Protocol (MCP) server over stdio.

    Exposes the investigation engine (trace / intake / link / jet / darkweb / interpret / cases /
    arsenal) to any MCP client. Use --print-config to get the JSON snippet to paste into your
    client, then run `bunnyhole mcp` as that client's configured command.
    """
    from bunnyhole.mcp.server import client_config, run_stdio

    if print_config:
        cfg = client_config(use_uv=not no_uv)
        console.print_json(json.dumps(cfg))
        console.print(
            "\n[dim]Add this to your MCP client (e.g. Claude Desktop's claude_desktop_config.json), "
            "then restart the client. See docs/MCP_SERVER.md.[/dim]"
        )
        return

    # stdio transport talks MCP on stdin/stdout; keep the banner on stderr so it never corrupts the
    # protocol stream.
    Console(stderr=True).print(
        "[bold bright_magenta]🐇🕳️ Bunnyhole MCP server[/bold bright_magenta] "
        "[dim]running on stdio — connect an MCP client; Ctrl-C to stop.[/dim]"
    )
    run_stdio()


@app.command("serve")
def serve_command(
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Bind host. A non-loopback host requires BUNNYHOLE_API_TOKEN in the environment."
    ),
    port: int = typer.Option(8000, "--port", "-p", min=1, max=65535, help="Bind port (here -p is --port; on trace/intake, -p is --phone)"),
) -> None:
    """Launch the Bunnyhole Interactive Web War-Room & FastAPI Server.

    Loopback hosts (127.0.0.1, localhost, ::1) start without a token. Any other host is refused (exit 2)
    unless BUNNYHOLE_API_TOKEN is set, because the server stores API keys and case data.
    """
    if not is_loopback_host(host):
        if not os.environ.get("BUNNYHOLE_API_TOKEN", "").strip():
            console.print(
                f"[bold red]Refusing to bind to non-loopback host {_rich_escape(host)}:[/bold red] set "
                "[bold]BUNNYHOLE_API_TOKEN[/bold] in the environment first (every client must then send it), or bind to "
                "127.0.0.1. The server stores API keys and case data; never expose it to an untrusted network."
            )
            raise typer.Exit(2)
        console.print(
            f"[bold yellow]⚠ WARNING:[/bold yellow] binding to a non-loopback host ([bold]{_rich_escape(host)}[/bold]) "
            "exposes the War-Room API to your network (BUNNYHOLE_API_TOKEN is set)."
        )
    console.print(f"[bold bright_magenta]🐇🕳️ Launching Bunnyhole War-Room UI at http://{_rich_escape(host)}:{port}[/bold bright_magenta]")
    uvicorn.run("bunnyhole.api.server:app", host=host, port=port, reload=False)


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and any loopback IP literal (127.0.0.0/8, ::1), with or without IPv6 brackets."""
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    app()
