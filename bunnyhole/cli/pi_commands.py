"""CLI side of the PI stream: the ``bunnyhole pi`` reference sub-app and the ``--pi`` engagement helpers.

``trace`` and ``intake`` share :func:`resolve_pi_flags` (validates the PI-only flags, runs every purpose
gate and builds the engagement) and :func:`render_pi_summary` / :func:`write_pi_report` (post-run output).
Nothing here touches the network: the ``pi`` commands only render the static tables in
:mod:`bunnyhole.engine.pi_reference`.
"""

from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bunnyhole.engine import pi_reference
from bunnyhole.engine.pi import (
    PERSON_PURPOSE_CATEGORIES,
    CaseType,
    PIEngagement,
    PIPurposeError,
    PurposeCategory,
    is_free_mail_address,
    looks_like_natural_person_name,
    looks_like_person_email,
)
from bunnyhole.engine.pi_purpose import require_no_credentials

console = Console()

PI_PERSONA_KEY = "pi"


class SubjectType(str, Enum):
    PERSON = "person"
    ENTITY = "entity"


def _valid_case_types() -> str:
    return ", ".join(c.value for c in CaseType)


def purpose_category_help() -> str:
    """Help text for ``--purpose-category``; both value lists are derived from the code constants, never hand-typed."""
    every = ", ".join(c.value for c in PurposeCategory)
    person = ", ".join(c.value for c in PurposeCategory if c in PERSON_PURPOSE_CATEGORIES)
    return (
        f"PI: attested permissible purpose (required with --pi): {every}. "
        f"A person subject is limited to {person}. Needs --pi."
    )


PURPOSE_CATEGORY_HELP = purpose_category_help()


def _jurisdiction_hint() -> str:
    """One jurisdiction hint for `pi sources` and `pi legal`, derived from the reference data (never hand-typed)."""
    codes = sorted({s.jurisdiction for s in pi_reference.SOURCES} - {"intl"})
    with_rules = [k for k in pi_reference.LEGAL_RULES if k != "general"]
    return (
        f"Jurisdiction code: {', '.join(codes)} (us-<state> and uk-/gb-<region> are accepted). "
        f"Legal rule sets exist for {', '.join(with_rules)}; general rules and global sources always apply."
    )


PI_JURISDICTION_HINT = _jurisdiction_hint()


def _person_like_selector(
    seed: Optional[str], orgs: List[str], emails: List[str], domains: List[str]
) -> Optional[str]:
    """The first selector that clearly reads as a natural person, or ``None``.

    Checks the seed and EVERY ``--org`` as a name (an email-shaped value is checked as an address), and every
    ``--email``: a ``first.last@`` address at a consumer mail provider always counts, and at any other domain it
    counts only for an email-only intake (no seed, org or domain), so ``--org "Acme Ltd" --email
    jane.smith@acme.com`` stays an entity. Conservative by design: only a clearly person-shaped value is returned.
    """
    for value in [seed or "", *orgs]:
        text = value.strip()
        if not text:
            continue
        if "@" in text and " " not in text:
            if looks_like_person_email(text):
                return text
        elif looks_like_natural_person_name(text):
            return text
    email_only = not (seed or "").strip() and not any(o.strip() for o in orgs) and not any(d.strip() for d in domains)
    for email in emails:
        if looks_like_person_email(email) and (is_free_mail_address(email) or email_only):
            return email.strip()
    return None


def _refuse(message: str, title: str = "PI engagement refused") -> "typer.Exit":
    """Print ``message`` in a red panel (no markup interpretation) and return the exit-2 exception to raise."""
    console.print(Panel(Text(message), title=title, border_style="red"))
    return typer.Exit(code=2)


# --------------------------------------------------------------------------------------------- run flags


def resolve_pi_flags(
    *,
    pi: bool,
    case_type: Optional[CaseType],
    purpose: Optional[str],
    client: Optional[str],
    matter_ref: Optional[str],
    subject_type: Optional[SubjectType],
    pi_jurisdiction: Optional[str],
    pi_report: Optional[Path],
    persona: Optional[str],
    cred: Optional[List[str]] = None,
    confirm_entity: bool = False,
    seed: Optional[str] = None,
    orgs: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
    domains: Optional[List[str]] = None,
    purpose_category: Optional[str] = None,
    extra_texts: Optional[Sequence[str]] = None,
) -> Tuple[Optional[PIEngagement], Optional[str]]:
    """Validate the PI flags of ``trace``/``intake`` and return ``(engagement, effective_persona)``.

    Without ``--pi`` every PI-only option is an error (exit 2), never silently ignored. With ``--pi`` the
    persona becomes ``pi`` unless ``--persona`` was given, a purpose is mandatory, and the engagement gates
    (eligibility purposes, motive and pursuit screens, the permissible-purpose category, matter reference) run
    before anything is investigated.

    ``purpose_category`` (``--purpose-category``) is the attested permissible purpose and is required with ``--pi``
    (a missing or unknown value exits 2 with the list of valid values). ``extra_texts`` are the remaining free-text
    fields of the run (hypothesis, pasted notes, usernames, phones, wallets, exclusions, evidence file names): the
    screens run over them together with the purpose, client, matter reference, seed and selectors, so a wording
    moved into another field is still screened.

    ``cred`` (``--cred``) is refused in PI mode: breach and credential contents are not used there. So is
    credential-shaped text in ``--purpose``, ``--client`` and ``--matter-ref`` (the secret is never echoed); these are
    stored verbatim in the engagement and the report.
    ``seed`` is the trace seed, or the first org/name selector (else the dump) of an intake; ``orgs``, ``emails``
    and ``domains`` are the intake's selector lists. With ``--subject-type entity`` the seed, EVERY org and the
    email selectors are checked, and a clearly person-shaped one (a name, ``Last, First``, a ``first.last@``
    address) is refused unless ``confirm_entity`` (``--confirm-entity``) is set, because the subject type is
    self-declared. A heuristic, not a guarantee.
    """
    pi_only = {
        "--case-type": case_type,
        "--purpose": purpose,
        "--purpose-category": purpose_category,
        "--client": client,
        "--matter-ref": matter_ref,
        "--subject-type": subject_type,
        "--pi-jurisdiction": pi_jurisdiction,
        "--pi-report": pi_report,
    }
    if not pi:
        given = [flag for flag, value in pi_only.items() if value is not None]
        if confirm_entity:
            given.append("--confirm-entity")
        if given:
            verb = "only applies" if len(given) == 1 else "only apply"
            raise _refuse(
                f"{', '.join(given)} {verb} to a private-investigator engagement. Add --pi to run one, "
                "or drop the option.",
                title="PI option without --pi",
            )
        return None, persona

    if cred:
        raise _refuse(
            "--cred is not accepted with --pi: credential and breach contents are not used in PI mode "
            "(passive, lawful sources only). Drop the --cred flag, or run without --pi.",
            title="PI credential option refused",
        )

    if purpose is None or not purpose.strip():
        raise _refuse(
            "--pi needs --purpose: state in a sentence what decision or legal matter this investigation serves "
            "(for example 'vet a counterparty before signing a supply contract').",
            title="PI purpose required",
        )
    try:
        require_no_credentials({"--purpose": purpose, "--client": client or "", "--matter-ref": matter_ref or ""})
    except PIPurposeError as exc:
        raise _refuse(str(exc), title="PI credential text refused") from exc
    chosen_case = case_type or CaseType.DUE_DILIGENCE
    person_like = (
        _person_like_selector(seed, list(orgs or []), list(emails or []), list(domains or []))
        if subject_type is SubjectType.ENTITY and not confirm_entity
        else None
    )
    if person_like:
        raise _refuse(
            f"--subject-type entity was declared, but {person_like!r} reads like a natural person's name, and "
            "person subjects get stricter gates (narrower purpose categories, matter reference). "
            "Use --subject-type person, "
            "give the legal form of the entity (for example 'Inc', 'Ltd', 'LLC'), or, if this really is an "
            "organisation, confirm it with --confirm-entity.",
            title="PI subject type looks wrong",
        )
    try:
        engagement = PIEngagement.build(
            chosen_case,
            purpose,
            client=client or "",
            matter_ref=matter_ref or "",
            jurisdiction=pi_jurisdiction or "",
            subject_is_person=(subject_type or SubjectType.PERSON) is SubjectType.PERSON,
            purpose_category=purpose_category or "",
            extra_texts=[seed or "", *(orgs or []), *(emails or []), *(domains or []), *(extra_texts or [])],
        )
    except PIPurposeError as exc:
        raise _refuse(str(exc)) from exc
    engagement = engagement.model_copy(update={"objective": pi_reference.playbook_for(chosen_case).objective})
    return engagement, persona or PI_PERSONA_KEY


def load_report_builder(pi_report: Optional[Path]) -> Optional[Callable[[Dict[str, Any]], str]]:
    """Return ``build_pi_report`` when ``--pi-report`` was given, failing clearly (exit 1) if it is unavailable."""
    if pi_report is None:
        return None
    try:
        from bunnyhole.engine.pi_report import build_pi_report
    except ImportError as exc:
        console.print(
            Panel(
                Text(f"--pi-report needs bunnyhole.engine.pi_report, which could not be imported: {exc}"),
                title="PI report unavailable",
                border_style="red",
            )
        )
        raise typer.Exit(code=1) from exc
    return build_pi_report


def require_report_for_ai_flag(no_ai_analysis: bool, pi_report: Optional[Path]) -> None:
    """``--no-ai-analysis`` only means something together with ``--pi-report`` (exit 2 otherwise, like every PI option)."""
    if no_ai_analysis and pi_report is None:
        raise _refuse(
            "--no-ai-analysis only applies together with --pi-report (it leaves the AI-written analysis section out "
            "of that report). Add --pi and --pi-report, or drop the option.",
            title="PI option without --pi-report",
        )


def _report_with_ai_analysis(report: str, result: Dict[str, Any]) -> str:
    """``report`` plus the AI analysis section or the one-line note. Prints what happened; never raises."""
    from bunnyhole.engine.pi_narrative import append_ai_analysis, generate_ai_analysis

    analysis = asyncio.run(generate_ai_analysis(result))
    if analysis.status == "included":
        console.print(Text(f"✔ AI analysis added to the report ({analysis.model}, {analysis.provider}).", style="green"))
    elif analysis.status == "omitted":
        console.print(Text(f"⚠ AI analysis not included: {analysis.reason}", style="yellow"))
    else:
        console.print(Text(f"AI analysis skipped: {analysis.reason}.", style="dim"))
    return append_ai_analysis(report, analysis)


def write_pi_report(
    builder: Optional[Callable[[Dict[str, Any]], str]],
    result: Dict[str, Any],
    pi_report: Optional[Path],
    *,
    ai_analysis: bool = True,
) -> None:
    """Write the BOTTOM-LINE-UP-FRONT PI report for ``result`` to ``pi_report`` (no-op when not requested).

    The code-built report is always written. With ``ai_analysis`` (the default) and a configured LLM provider, a
    validated, clearly labelled AI-written section is appended after it, or a one-line note when the analysis failed
    (see :mod:`bunnyhole.engine.pi_narrative`); ``--no-ai-analysis`` turns it off and nothing is sent to a provider.
    """
    if builder is None or pi_report is None:
        return
    report = builder(result)
    if ai_analysis:
        pi_report.write_text(report, encoding="utf-8")  # the code-built report is on disk before any model call
        report = _report_with_ai_analysis(report, result)
    else:
        console.print(Text("AI analysis skipped: switched off with --no-ai-analysis.", style="dim"))
    pi_report.write_text(report, encoding="utf-8")
    console.print(f"[bold green]✔ Saved PI Report to:[/bold green] {pi_report}")


def render_pi_summary(result: Dict[str, Any]) -> None:
    """Compact PI block summary: labels, coverage gaps, custodians. Prints a notice when the block is absent."""
    block = result.get("pi")
    if not isinstance(block, dict):
        console.print("[bold yellow]⚠ No PI block in this result (the engine returned none).[/bold yellow]")
        return
    labels = {"confirmed": 0, "probable": 0, "lead": 0}
    for finding in block.get("findings", []) or []:
        key = str(finding.get("finding_label", "lead"))
        labels[key] = labels.get(key, 0) + 1
    not_searched = [
        row.get("source_class", "?") for row in (block.get("coverage", []) or []) if not row.get("searched")
    ]
    engagement = block.get("engagement", {}) or {}
    lines = [
        f"[bold cyan]Engagement:[/bold cyan] {_esc(engagement.get('engagement_id', '—'))}  |  "
        f"[bold magenta]Case type:[/bold magenta] {_esc(engagement.get('case_type', '—'))}  |  "
        f"[bold yellow]Matter ref:[/bold yellow] {_esc(engagement.get('matter_ref') or '—')}  |  "
        f"[bold blue]Purpose category:[/bold blue] {_esc(engagement.get('purpose_category') or '—')}",
        f"[bold green]Findings:[/bold green] {labels.get('confirmed', 0)} confirmed, "
        f"{labels.get('probable', 0)} probable, {labels.get('lead', 0)} lead "
        "[dim](confirmed = 3+ independent sources)[/dim]",
        f"[bold red]Not searched:[/bold red] {_esc(', '.join(not_searched) or 'none')}",
        f"[bold green]Custodians named:[/bold green] {len(block.get('custodians', []) or [])}  |  "
        f"[bold green]Contradictions:[/bold green] {len(block.get('contradictions', []) or [])}  |  "
        f"[bold green]Prior cases:[/bold green] {len(block.get('prior_cases', []) or [])}",
    ]
    for warning in (block.get("identifier_warnings", []) or [])[:3]:
        lines.append(f"[yellow]⚠ {_esc(warning)}[/yellow]")
    console.print(Panel("\n".join(lines), title="🕵️ [bold white]PI SUMMARY[/bold white]", border_style="bright_blue"))


def _esc(value: Any) -> str:
    from rich.markup import escape

    return escape(str(value))


# ---------------------------------------------------------------------------------------- `bunnyhole pi`

pi_app = typer.Typer(
    name="pi",
    help="Private-investigator reference: method guide, free sources, legal frame, case playbooks, out-of-scope.",
    no_args_is_help=True,
    add_completion=False,
)


def _parse_case_type(value: str) -> CaseType:
    try:
        return CaseType(value.strip().lower())
    except ValueError:
        raise _refuse(
            f"Unknown case type {value!r}. Valid case types: {_valid_case_types()}.", title="Unknown case type"
        ) from None


@pi_app.command("guide")
def pi_guide_command() -> None:
    """The elite-PI method: investigation cycle, the thirteen behaviours and the case types."""
    console.print(Markdown(pi_reference.render_guide()))


@pi_app.command("sources")
def pi_sources_command(
    case_type: Optional[CaseType] = typer.Option(None, "--case-type", help=f"Only sources useful for: {_valid_case_types()}."),
    jurisdiction: Optional[str] = typer.Option(None, "--jurisdiction", help=PI_JURISDICTION_HINT),
    implemented: bool = typer.Option(False, "--implemented", help="Only sources Bunnyhole already queries."),
) -> None:
    """Free, lawful source catalog (what each gives a PI, access tier, and whether Bunnyhole queries it)."""
    if jurisdiction and jurisdiction.strip():
        # Known iff the jurisdiction filter keeps any non-global source (same scope rules as the filter itself).
        if not any(s.jurisdiction != "intl" for s in pi_reference.sources_for(None, jurisdiction)):
            console.print(
                f"[yellow]No jurisdiction-specific sources for {_esc(jurisdiction.strip())}; showing global sources only.[/yellow]"
            )
    rows = pi_reference.sources_for(case_type, jurisdiction, implemented_only=implemented)
    table = Table(title=f"🗂️ Free PI Sources ({len(rows)})", show_lines=False)
    table.add_column("Source", style="bold white")
    table.add_column("Access", style="cyan")
    table.add_column("Where", style="magenta")
    table.add_column("Queried", justify="center")
    table.add_column("Gives a PI", style="white")
    table.add_column("Caveats", style="dim")
    for s in rows:
        table.add_row(
            _esc(s.name),
            s.access,
            s.jurisdiction,
            "[bold green]✔[/bold green]" if s.implemented else "—",
            _esc(s.what),
            _esc(s.caveats or "—"),
        )
    console.print(table)
    console.print("[dim]Unverified rows (research marked U) need checking before you rely on them. `✔` = Bunnyhole queries it.[/dim]")


@pi_app.command("legal")
def pi_legal_command(
    jurisdiction: str = typer.Option("general", "--jurisdiction", help=PI_JURISDICTION_HINT),
) -> None:
    """The legal frame for PI work in a jurisdiction (information, not legal advice)."""
    key = jurisdiction.strip().lower()
    if key not in pi_reference.LEGAL_RULES and not key.startswith("us-"):
        console.print(f"[yellow]No jurisdiction-specific rules for {_esc(jurisdiction)}; showing the general rules.[/yellow]")
    rules = pi_reference.legal_for(jurisdiction)
    table = Table(title=f"⚖️ Legal Frame: {jurisdiction.strip() or 'general'}", show_lines=True)
    table.add_column("Rule", style="bold white")
    table.add_column("Applies", style="cyan")
    table.add_column("In practice", style="white")
    table.add_column("Verify", style="dim")
    for r in rules:
        table.add_row(_esc(r["rule"]), _esc(r["applies"]), _esc(r["practical"]), _esc(r["verify"]))
    console.print(table)
    console.print("[bold yellow]Not legal advice: verify current law with counsel before relying on any rule here.[/bold yellow]")


@pi_app.command("playbook")
def pi_playbook_command(
    case_type: str = typer.Argument(..., help=f"One of: {_valid_case_types()}"),
) -> None:
    """How an elite PI sequences a case type: objective, done-when, ordered steps, escalation, pitfalls."""
    pb = pi_reference.playbook_for(_parse_case_type(case_type))
    console.print(
        Panel(
            f"[bold cyan]Objective:[/bold cyan] {_esc(pb.objective)}\n[bold green]Done when:[/bold green] {_esc(pb.done_when)}",
            title=f"📋 [bold white]PLAYBOOK: {pb.case_type.value}[/bold white]",
            border_style="cyan",
        )
    )
    steps = Table(title="Order of work (cheapest, highest-yield first)", show_lines=True)
    steps.add_column("#", justify="right", style="cyan")
    steps.add_column("Action", style="bold white")
    steps.add_column("Sources", style="magenta")
    steps.add_column("Yield", justify="center")
    steps.add_column("Cost", justify="center")
    steps.add_column("Legal gate", style="yellow")
    steps.add_column("Stop if", style="dim")
    for st in pb.steps:
        steps.add_row(
            str(st.order), _esc(st.action), _esc(", ".join(st.sources) or "—"), st.yield_level, st.cost,
            _esc(st.legal_gate or "—"), _esc(st.stop_if or "—"),
        )
    console.print(steps)
    _print_list("Escalate when", pb.escalate_when)
    _print_list("Pitfalls", pb.pitfalls)
    _print_list("Competing hypotheses to keep open", pb.typical_hypotheses)


def _print_list(title: str, items: List[str]) -> None:
    console.print(f"\n[bold bright_cyan]{title}:[/bold bright_cyan]")
    for item in items:
        console.print(f"  • {_esc(item)}")


@pi_app.command("out-of-scope")
def pi_out_of_scope_command() -> None:
    """What Bunnyhole refuses to do or use (licensed databases, unlawful methods) and why."""
    table = Table(title="🚫 Out of Scope: hand off to a licensed investigator or counsel", show_lines=True)
    table.add_column("What", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Why", style="white")
    for entry in pi_reference.OUT_OF_SCOPE:
        table.add_row(_esc(entry["name"]), _esc(entry["category"]), _esc(entry["why"]))
    console.print(table)
    _print_list("Unlawful methods (never)", list(pi_reference.UNLAWFUL_METHODS))
