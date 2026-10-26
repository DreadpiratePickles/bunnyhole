"""Bunnyhole Rich CLI: Autonomous Multi-Domain Investigation, Bidirectional Link Sleuth, Corporate Jet Tracker, Document Forensics, and War-Room Server."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import List, Optional

import typer
import uvicorn
from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.panel import Panel
from rich.table import Table

from bunnyhole.agents.accountant import AccountantAgent, n_number_to_icao_hex
from bunnyhole.agents.journalist import JournalistAgent
from bunnyhole.agents.osint import OSINTAgent
from bunnyhole.engine.graph import InvestigationGraph
from bunnyhole.engine.intake import AnchorMode, CaseIntakePacket, SmartIntakeParser
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator

app = typer.Typer(
    name="bunnyhole",
    help="🐇🕳️ Bunnyhole: Autonomous Multi-Domain Investigative AI (Journalism, Forensic Accounting, Red Team OSINT, Link Sleuth & On-Chain Crypto)",
    add_completion=False,
)
console = Console()


@app.callback()
def _global_options(
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

    nodes = sorted(
        result.get("nodes", []),
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

    # 2. Link Sleuth: Cross-Domain Paths & Adamic-Adar Predicted Missing Links
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
                title="🏛️ [bold bright_yellow]KARPATHY 3-STAGE LLM-COUNCIL VERDICT (STAGE 1 OPINIONS → STAGE 2 ANONYMIZED PEER RANKING → STAGE 3 CHAIRMAN)[/bold bright_yellow]",
                border_style="bright_yellow",
            )
        )


@app.command("council")
def council_command(
    seed: str = typer.Argument(..., help="Seed trace to investigate and deliberate before the 5-Seat Karpathy LLM Council"),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast or deep"),
    depth: int = typer.Option(1, "--depth", "-d", help="Recursive rabbit-hole depth (1-4)"),
) -> None:
    """Convene the 5-Seat Karpathy LLM Council (Stage 1 Specialist Briefs -> Stage 2 Anonymized Peer Review -> Stage 3 Chairman Verdict)."""
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
                title="🏛️ [bold bright_yellow]STAGE 2 & STAGE 3 — ANONYMIZED PEER RANKINGS & CHAIRMAN VERDICT[/bold bright_yellow]",
                border_style="bright_yellow",
            )
        )


@app.command("intake")
def intake_command(
    dump: Optional[str] = typer.Option(None, "--dump", help="Paste raw clipboard dump / free-text notes to auto-extract hypothesis & selectors"),
    hypothesis: Optional[str] = typer.Option(None, "--hypothesis", "-H", help="Working hypothesis or investigative question"),
    username: Optional[List[str]] = typer.Option(None, "--username", "-u", help="Known @username / handle (can pass multiple)"),
    email: Optional[List[str]] = typer.Option(None, "--email", "-e", help="Known email address (can pass multiple)"),
    phone: Optional[List[str]] = typer.Option(None, "--phone", "-p", help="Known phone number in E.164 or international format"),
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
    depth: int = typer.Option(2, "--depth", "-d", help="Recursive rabbit-hole depth (1-4)"),
    breadth: int = typer.Option(4, "--breadth", "-b", help="Parallel search breadth per depth level"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Export full Markdown Dossier to file path"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export full Universal Graph JSON to file path"),
) -> None:
    """Run a Dual-Mode Case Intake investigation combining a Working Hypothesis with multiple known credentials/selectors."""
    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            console.print(f"[dim][{d['agent'].upper()}][/dim] [bold]{_rich_escape(str(d['action']))}[/bold] ({_rich_escape(str(d['target']))}): {_rich_escape(str(d['detail']))}")

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
        exclusions=list(exclude or []),
        raw_omni_text=dump or "",
        gear=gear,
        depth=depth,
        breadth=breadth,
    )
    normalized = SmartIntakeParser.normalize_packet(packet)
    orch = BunnyholeOrchestrator(
        seed_query=normalized.summary_seed_label(),
        gear=gear,
        max_depth=depth,
        initial_breadth=breadth,
        event_callback=_on_event,
        intake_packet=normalized,
    )
    result = asyncio.run(orch.run_intake_investigation(normalized))
    _render_investigation_results(result)

    if out:
        md = orch.graph.export_markdown_dossier()
        out.write_text(md, encoding="utf-8")
        console.print(f"\n[bold green]✔ Saved Markdown Dossier to:[/bold green] {out}")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[bold green]✔ Saved Universal Graph JSON to:[/bold green] {json_out}")


@app.command("trace")
def trace_command(
    seed: str = typer.Argument(..., help="Any seed trace: company, domain, EVM/BTC wallet, ENS (.eth), @handle, email, or tail number"),
    gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast (Gear 1) or deep (Gear 2)"),
    depth: int = typer.Option(2, "--depth", "-d", help="Recursive rabbit-hole depth (1-4)"),
    breadth: int = typer.Option(4, "--breadth", "-b", help="Parallel search breadth per depth level (2-8)"),
    hypothesis: Optional[str] = typer.Option(None, "--hypothesis", "-H", help="Optional working hypothesis to steer ACH and lead priority"),
    username: Optional[List[str]] = typer.Option(None, "--username", "-u", help="Additional known @username"),
    email: Optional[List[str]] = typer.Option(None, "--email", "-e", help="Additional known email"),
    phone: Optional[List[str]] = typer.Option(None, "--phone", "-p", help="Additional known phone number"),
    cred: Optional[List[str]] = typer.Option(None, "--cred", "-c", help="Additional known leaked credential (email:pass)"),
    wallet: Optional[List[str]] = typer.Option(None, "--wallet", "-w", help="Additional known wallet/ENS"),
    domain: Optional[List[str]] = typer.Option(None, "--domain", help="Additional known domain"),
    doc: Optional[List[str]] = typer.Option(None, "--doc", help="Additional local .pdf/.docx evidence file"),
    exclude: Optional[List[str]] = typer.Option(None, "--exclude", "-x", help="Negative scope exclusion"),
    anchor_mode: AnchorMode = typer.Option(AnchorMode.CONVERGENCE, "--anchor-mode", help="convergence or locked_profile"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Export full Markdown Dossier to file path"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export full Universal Graph JSON to file path"),
) -> None:
    """Run an autonomous multi-domain Bunnyhole investigation down the rabbit hole."""
    has_extra_intake = any([hypothesis, username, email, phone, cred, wallet, domain, doc, exclude])
    if has_extra_intake:
        intake_command(
            dump=seed,
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
        )
        return

    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            console.print(f"[dim][{d['agent'].upper()}][/dim] [bold]{_rich_escape(str(d['action']))}[/bold] ({_rich_escape(str(d['target']))}): {_rich_escape(str(d['detail']))}")

    orch = BunnyholeOrchestrator(
        seed_query=seed,
        gear=gear,
        max_depth=depth,
        initial_breadth=breadth,
        event_callback=_on_event,
    )
    result = asyncio.run(orch.run_investigation())
    _render_investigation_results(result)

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
    tail_or_hex: str = typer.Argument(..., help="US Tail Number (e.g., N628TS) or 24-bit ICAO Mode-S Hex"),
) -> None:
    """Convert FAA N-Number <-> 24-bit ICAO Hex and query unfiltered ADS-B telemetry (adsb.lol)."""
    g = InvestigationGraph("jet_lookup", tail_or_hex)
    acct = AccountantAgent(g)
    info = asyncio.run(acct.investigate_aircraft_adsb(tail_or_hex, "seed:jet", hop_depth=1))
    console.print(Panel(json.dumps(info, indent=2), title=f"✈️ ADS-B Forensics: {tail_or_hex} (ICAO Hex: {n_number_to_icao_hex(tail_or_hex)})"))


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
    """Extract binary Word RSID revision fingerprints (.docx) or PDF /Info & XMP timezone metadata (.pdf)."""
    g = InvestigationGraph("doc_forensics", file_path)
    journo = JournalistAgent(g)
    res = journo.inspect_document_binary_forensics(file_path)
    console.print(Panel(json.dumps(res, indent=2), title=f"📄 Binary Document Forensics: {file_path}"))


@app.command("doctor")
@app.command("arsenal")
def doctor_command(
    install: Optional[str] = typer.Option(None, "--install", "-i", help="Install a missing tool by name (e.g. sherlock, maigret, subfinder) or 'all'"),
) -> None:
    """Cross-Platform Arsenal Health Doctor & Tool Installer (Kali, Parrot OS, Debian, Arch, Fedora, macOS)."""
    from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager

    mgr = ArsenalManager()
    pinfo = mgr.platform_info

    if install:
        tools_to_install = (
            [t["name"] for t in mgr.check_arsenal_status() if not t["installed"]]
            if install.lower() == "all"
            else [install]
        )
        for tname in tools_to_install:
            console.print(f"[bold cyan]⚙ Installing '{tname}' on {pinfo['display_name']}...[/bold cyan]")
            res = mgr.install_tool(tname)
            if res.get("success"):
                console.print(f"[bold green]✔ Installed {tname} via:[/bold green] {res.get('command')}")
            else:
                console.print(f"[bold yellow]⚠ Could not auto-install {tname}:[/bold yellow] {res.get('error')}")

    tools = mgr.check_arsenal_status()
    keys = mgr.get_api_keys_status()
    installed_cnt = sum(1 for t in tools if t["installed"])
    configured_keys_cnt = sum(1 for k in keys if k["configured"])

    console.print(
        Panel(
            f"[bold cyan]Detected OS:[/bold cyan] {pinfo['display_name']}  |  "
            f"[bold magenta]Distro Profile:[/bold magenta] {pinfo['distro'].upper()}  |  "
            f"[bold yellow]Package Manager:[/bold yellow] {pinfo['pkg_manager']}\n"
            f"[bold green]Tools Installed:[/bold green] {installed_cnt}/{len(tools)}  |  "
            f"[bold green]API Keys Configured:[/bold green] {configured_keys_cnt}/{len(keys)}\n"
            f"[dim]Unified Vaults: {BUNNYHOLE_ENV_FILE}  <->  {LEGACY_OSINT_ENV_FILE}[/dim]",
            title="🛠️ [bold white]BUNNYHOLE CROSS-PLATFORM ARSENAL DOCTOR[/bold white]",
            border_style="cyan",
        )
    )

    t_table = Table(title="🧰 OSINT, Forensics & Red-Team Arsenal Status", show_lines=False)
    t_table.add_column("Status", justify="center")
    t_table.add_column("Tool", style="bold white")
    t_table.add_column("Type", style="cyan")
    t_table.add_column("Location / Binary", style="green")
    t_table.add_column("Description / Install Hint", style="dim")

    for t in tools:
        badge = "[bold green]✔ READY[/bold green]" if t["installed"] else "[yellow]○ MISSING[/yellow]"
        loc = t["location"] if t["installed"] else f"Hint: {t['install_hint']}"
        t_table.add_row(badge, t["name"], t["type"], loc[:48], t["description"])
    console.print(t_table)


@app.command("keys")
def keys_command(
    set_key: Optional[str] = typer.Option(None, "--set", "-s", help="Set an API key in KEY=VALUE format (e.g. SHODAN_API_KEY=xxx)"),
) -> None:
    """View and configure API keys in the Unified Bunnyhole & OSINT Vault (~/.bunnyhole/api_keys.env)."""
    from bunnyhole.arsenal.manager import BUNNYHOLE_ENV_FILE, LEGACY_OSINT_ENV_FILE, ArsenalManager

    mgr = ArsenalManager()
    if set_key:
        if "=" not in set_key:
            console.print("[bold red]Error:[/bold red] Use --set KEY_NAME=VALUE")
            raise typer.Exit(1)
        k, v = set_key.split("=", 1)
        mgr.set_api_key(k, v)
        console.print(f"[bold green]✔ Saved {k.strip().upper()} to {BUNNYHOLE_ENV_FILE} and {LEGACY_OSINT_ENV_FILE}[/bold green]")

    keys = mgr.get_api_keys_status()
    k_table = Table(title="🔑 Unified API Keys Vault (~/.bunnyhole/api_keys.env)", show_lines=False)
    k_table.add_column("State", justify="center")
    k_table.add_column("Environment Variable", style="bold white")
    k_table.add_column("Category", style="magenta")
    k_table.add_column("Value", style="cyan")
    k_table.add_column("Free Tier / Registration URL", style="dim")

    for item in keys:
        badge = "[bold green]● SET[/bold green]" if item["configured"] else "[dim]○ EMPTY[/dim]"
        val = item["masked_value"] or "—"
        k_table.add_row(badge, item["key"], item["category"], val, f"{item['url']} ({item['note']})")
    console.print(k_table)


@app.command("cases")
def cases_command(
    search: Optional[str] = typer.Option(None, "--search", "-q", help="Search across all historical entity sightings in ~/.bunnyhole/cases.db"),
    load: Optional[str] = typer.Option(None, "--load", "-l", help="Reload and display a saved case by Case ID"),
) -> None:
    """Browse persistent SQLite investigations and search Cross-Case Entity Memory (~/.bunnyhole/cases.db)."""
    from bunnyhole.engine.storage import CASES_DB_PATH, CaseStore

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
    """Launch the full-screen War-Room TUI (Textual). Also runs in a browser via `textual serve \"bunnyhole ui\"`."""
    from bunnyhole.tui.app import launch

    launch(seed=seed or None)


@app.command("tui")
def tui_command(seed: str = typer.Argument("", help="Optional seed to prefill the War-Room")) -> None:
    """Alias for `ui` — the full-screen War-Room TUI."""
    ui_command(seed=seed)


@app.command("menu")
def menu_command() -> None:
    """Classic prompt-driven terminal command center (Traces, Link Sleuth, Arsenal, Keys, Cases)."""
    from rich.prompt import Prompt

    from bunnyhole.arsenal.manager import ArsenalManager

    mgr = ArsenalManager()
    while True:
        console.print()
        console.print(
            Panel(
                f"[bold white]Platform:[/bold white] {mgr.platform_info['display_name']} ({mgr.platform_info['distro'].upper()})\n\n"
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
            depth = int(Prompt.ask("Select recursive depth", choices=["1", "2", "3"], default="2"))
            # Pass EVERY parameter explicitly: omitted Typer options would stay as truthy OptionInfo
            # objects and wrongly trigger the multi-selector intake path (TypeError on list(OptionInfo)).
            trace_command(
                seed=seed, gear=GearMode(gear_str), depth=depth, breadth=4,
                hypothesis=None, username=None, email=None, phone=None, cred=None,
                wallet=None, domain=None, doc=None, exclude=None,
                anchor_mode=AnchorMode.CONVERGENCE, out=None, json_out=None,
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
                doctor_command(install=to_inst.strip())
        elif choice == "4":
            keys_command(set_key=None)
            kname = Prompt.ask("Enter API Key variable name to set (or press Enter to return)", default="")
            if kname.strip():
                kval = Prompt.ask(f"Enter value for {kname.strip().upper()}", password=True)
                mgr.set_api_key(kname.strip(), kval.strip())
                console.print(f"[bold green]✔ Updated {kname.strip().upper()}[/bold green]")
        elif choice == "5":
            tail = Prompt.ask("Enter FAA Tail Number or ICAO Hex", default="N628TS")
            jet_command(tail_or_hex=tail)
        elif choice == "6":
            cases_command(search=None, load=None)
            q = Prompt.ask("Enter entity substring to search across cases (or press Enter to skip)", default="")
            if q.strip():
                cases_command(search=q.strip(), load=None)
        elif choice == "7":
            serve_command(host="127.0.0.1", port=8000)


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
) -> None:
    """Launch the Bunnyhole Interactive Web War-Room & FastAPI Server."""
    console.print(f"[bold bright_magenta]🐇🕳️ Launching Bunnyhole War-Room UI at http://{host}:{port}[/bold bright_magenta]")
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[bold yellow]⚠ WARNING:[/bold yellow] binding to a non-loopback host ([bold]{host}[/bold]) exposes the "
            "War-Room API to your network. Set [bold]BUNNYHOLE_API_TOKEN[/bold] before doing so, and never expose it "
            "to an untrusted network — the server stores API keys and case data."
        )
        if not os.environ.get("BUNNYHOLE_API_TOKEN", "").strip():
            console.print("[bold red]  No BUNNYHOLE_API_TOKEN set: mutating endpoints will be unauthenticated.[/bold red]")
    uvicorn.run("bunnyhole.api.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
