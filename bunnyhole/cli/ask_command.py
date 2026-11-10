"""``bunnyhole ask "<plain English question>"``: parse the question, run an existing investigation, answer honestly.

The parser (``bunnyhole.engine.ask``) is deterministic. This module only routes: a connection question runs the same
bidirectional link investigation as ``bunnyhole link``; a company-risk question runs the same organisation trace as
``bunnyhole trace`` through the compliance persona (sanctions emphasis). The PI gates are the existing ones
(``pi_commands.resolve_pi_flags``): naming a person makes the run a PI engagement, so a missing purpose, category or
matter reference is refused exactly as ``trace --pi`` refuses it, before anything is investigated. No LLM is called
here beyond what the existing investigation already does.

``bunnyhole.cli.main`` is imported lazily (it registers this command), so the command uses the same orchestrator
class, console and persona resolution as ``trace``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Optional

import typer
from rich.markdown import Markdown
from rich.markup import escape as _rich_escape
from rich.panel import Panel
from rich.text import Text

from bunnyhole.cli import pi_commands
from bunnyhole.cli.pi_commands import SubjectType
from bunnyhole.engine.ask import AskPlan, Intent, parse_question
from bunnyhole.engine.ask_answer import Answer, build_connection_answer, build_risk_answer
from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import classify_seed_type

_LINK_DEPTH = 2
_LINK_BREADTH = 4
_RISK_PERSONA = "compliance"


def _runs_link_investigation(plan: AskPlan) -> bool:
    """A connection question, or a risk question that also names a second entity, runs the link investigation."""
    return plan.intent is Intent.CONNECTION or len(plan.entities) > 1


def _investigate(cli_main: Any, plan: AskPlan, gear: GearMode, depth: int, breadth: int, prof: Any, engagement: Any, status: Any) -> Dict[str, Any]:
    def _on_event(evt: dict) -> None:
        if evt.get("type") == "agent_log":
            d = evt["data"]
            status.update(f"[dim]{_rich_escape(str(d['agent']).upper())}[/dim] {_rich_escape(str(d['action']))}")

    link = _runs_link_investigation(plan)
    first = plan.entities[0].text
    seed = f"{first} <-> {plan.entities[1].text}" if link else first
    orch = cli_main.BunnyholeOrchestrator(
        seed_query=seed,
        gear=gear,
        max_depth=depth,
        initial_breadth=breadth,
        event_callback=_on_event,
        profile=prof,
        **cli_main._engagement_kwargs(engagement),
    )
    if not link:
        return asyncio.run(orch.run_investigation())
    if engagement is not None:
        # The link run does not open the PI case itself (trace/intake do). Open it on the PI subject so the conflict
        # check and the two-anchor rule for name-derived pivots apply, as they do for `trace --pi`.
        subject = plan.person.text if plan.person else first
        orch._pi_start_case([(classify_seed_type(subject)[0], subject)])
    return asyncio.run(orch.run_bidirectional_link_investigation(first, plan.entities[1].text))


def _build_answer(plan: AskPlan, result: Dict[str, Any]) -> Answer:
    if plan.intent is Intent.CONNECTION:
        return build_connection_answer(plan, result)
    return build_risk_answer(plan, result, chains_too=len(plan.entities) > 1)


def run_ask(
    ctx: typer.Context,
    question: str,
    gear: GearMode,
    out: Optional[Path],
    json_out: Optional[Path],
    pi: bool,
    purpose: Optional[str],
    purpose_category: Optional[str],
    matter_ref: Optional[str],
    pi_jurisdiction: Optional[str],
    pi_report: Optional[Path],
    no_ai_analysis: bool,
) -> None:
    from bunnyhole.cli import main as cli_main

    console = cli_main.console
    plan = parse_question(question)
    if plan.intent is Intent.UNKNOWN:
        console.print(Panel(Text(plan.help_text()), title="bunnyhole ask", border_style="yellow"))
        raise typer.Exit(2)
    pi_commands.require_report_for_ai_flag(no_ai_analysis, pi_report)
    if plan.needs_pi and not pi:
        console.print(
            Text("A person is named, so this runs as a private-investigator engagement; the PI gates apply.", style="yellow")
        )
    use_pi = pi or plan.needs_pi
    subject = plan.person.text if plan.person else plan.entities[0].text
    engagement, persona = pi_commands.resolve_pi_flags(
        pi=use_pi, case_type=None, purpose=purpose, client=None, matter_ref=matter_ref,
        subject_type=(SubjectType.PERSON if plan.needs_pi else SubjectType.ENTITY) if use_pi else None,
        pi_jurisdiction=pi_jurisdiction, pi_report=pi_report,
        persona=_RISK_PERSONA if plan.intent is Intent.COMPANY_RISK and not use_pi else None,
        seed=subject, purpose_category=purpose_category,
        extra_texts=[e.text for e in plan.entities if e.text != subject],
    )
    report_builder = pi_commands.load_report_builder(pi_report)
    prof, gear, depth, breadth, _exclusions = cli_main._personalize(ctx, gear, _LINK_DEPTH, _LINK_BREADTH, [], persona)
    with console.status("Investigating...") as status:
        result = _investigate(cli_main, plan, gear, depth, breadth, prof, engagement, status)
    answer = _build_answer(plan, result)
    console.print()
    console.print(Panel(Text(answer.headline), title="bunnyhole ask", border_style="cyan"))
    console.print(Markdown(answer.body))
    if engagement is not None:
        pi_commands.render_pi_summary(result)
        pi_commands.write_pi_report(report_builder, result, pi_report, ai_analysis=not no_ai_analysis)
    if out:
        out.write_text(answer.markdown(), encoding="utf-8")
        console.print(f"\n[bold green]✔ Saved Markdown answer to:[/bold green] {_rich_escape(str(out))}")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        console.print(f"[bold green]✔ Saved Universal Graph JSON to:[/bold green] {_rich_escape(str(json_out))}")


def register_ask(app: typer.Typer) -> None:
    """Add the ``ask`` command to ``app`` (called once from ``bunnyhole.cli.main``)."""

    @app.command("ask")
    def ask_command(
        ctx: typer.Context,
        question: str = typer.Argument(..., help='A plain-English question, e.g. "see if Jane Smith is connected to Acme Ltd" or "see if Acme Ltd has anything shady going on"'),
        gear: GearMode = typer.Option(GearMode.FAST, "--gear", "-g", help="Execution profile: fast (Gear 1) or deep (Gear 2)"),
        out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the answer (Markdown) to this path"),
        json_out: Optional[Path] = typer.Option(None, "--json", help="Export the full Universal Graph JSON to this path"),
        pi: bool = typer.Option(False, "--pi", help="Private-investigator engagement (implied when a person is named): vets --purpose and applies the PI gates."),
        purpose: Optional[str] = typer.Option(None, "--purpose", help="PI: the client's written purpose / the decision this serves (required in PI mode)."),
        purpose_category: Optional[str] = typer.Option(None, "--purpose-category", help=pi_commands.PURPOSE_CATEGORY_HELP),
        matter_ref: Optional[str] = typer.Option(None, "--matter-ref", help="PI: case no., contract or judgment reference. REQUIRED when a person is named."),
        pi_jurisdiction: Optional[str] = typer.Option(None, "--pi-jurisdiction", help="PI: jurisdiction for custodians and legal notes, e.g. us, ca-on, uk."),
        pi_report: Optional[Path] = typer.Option(None, "--pi-report", help="PI: write the bottom-line-up-front PI report (Markdown) to this path."),
        no_ai_analysis: bool = typer.Option(False, "--no-ai-analysis", help="PI: leave the AI-written analysis out of --pi-report (no LLM call is made). Needs --pi-report."),
    ) -> None:
        """Ask in plain English: "see if X is connected to Y" or "see if X has anything shady going on"."""
        run_ask(ctx, question, gear, out, json_out, pi, purpose, purpose_category, matter_ref, pi_jurisdiction, pi_report, no_ai_analysis)

