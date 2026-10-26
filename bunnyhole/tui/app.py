"""The Bunnyhole War-Room Textual application.

A full-screen TUI that mirrors the web War-Room: a seed/intake sidebar, a live entity table
("graph"), a tabbed inspector (Node / Links / Council / ACH / Dossier), a timeline strip, and a
streaming agent-telemetry log. Investigations run as a Textual worker; the engine's event callback
is relayed into the UI as thread-safe messages so the log and stats update in real time.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    Markdown,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from bunnyhole.engine.models import GearMode
from bunnyhole.engine.orchestrator import BunnyholeOrchestrator, classify_seed_type

PRESETS = ["vitalik.eth", "uniswap.org", "N628TS", "ethereum.org"]

_LEVEL_STYLE = {
    "discovery": "bold cyan",
    "anomaly": "bold magenta",
    "warning": "bold yellow",
    "info": "dim",
}
_DOMAIN_STYLE = {
    "journalism": "bright_blue",
    "fiat": "green",
    "osint": "cyan",
    "onchain": "yellow",
    "physical": "bright_magenta",
    "skeptic": "magenta",
}


class EngineEvent(Message):
    """A single telemetry event relayed from the investigation engine to the UI."""

    def __init__(self, payload: Dict[str, Any]) -> None:
        self.payload = payload
        super().__init__()


class RunFinished(Message):
    """Signals that an investigation worker completed, carrying the full result dict."""

    def __init__(self, result: Dict[str, Any], orchestrator: BunnyholeOrchestrator) -> None:
        self.result = result
        self.orchestrator = orchestrator
        super().__init__()


class RunFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class BunnyholeTUI(App):
    """Bunnyhole War-Room."""

    TITLE = "BUNNYHOLE // War-Room"
    SUB_TITLE = "Autonomous Multi-Domain Investigative Intelligence"

    CSS = """
    Screen { layers: base; background: #0a0d14; }
    #statsbar { height: 1; background: #0d1119; color: #7f8ea3; padding: 0 1; }
    #body { height: 1fr; }
    #sidebar { width: 30; border-right: solid #1f2735; padding: 0 1; }
    #sidebar Label { color: #38bdf8; margin-top: 1; }
    #sidebar .hint { color: #5f6f85; }
    #center { width: 1fr; }
    #inspector { width: 52; border-left: solid #1f2735; }
    #entities { height: 1fr; }
    #timeline { height: 3; border-top: solid #1f2735; background: #0d1119; padding: 0 1; color: #8aa0bd; }
    #log { height: 9; border-top: solid #1f2735; background: #0b0e16; }
    #runbtn { width: 100%; margin-top: 1; }
    .preset { width: 100%; margin-top: 1; }
    Select { margin-top: 1; }
    DataTable { background: #0a0d14; }
    #nodedetail, #linksbody, #achbody, #arsenalbody { padding: 0 1; }
    """

    BINDINGS = [
        ("enter", "run", "Run"),
        ("r", "run", "Run"),
        ("/", "focus_seed", "Seed"),
        ("d", "show_dossier", "Dossier"),
        ("p", "pivot", "Pivot"),
        ("ctrl+l", "clear_log", "Clear log"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, initial_seed: Optional[str] = None) -> None:
        super().__init__()
        self._initial_seed = initial_seed or ""
        self._result: Dict[str, Any] = {}
        self._nodes_by_id: Dict[str, Dict[str, Any]] = {}
        self._orchestrator: Optional[BunnyholeOrchestrator] = None
        self._running = False

    # ---- layout -------------------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static(self._stats_text(), id="statsbar")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Label("SEED")
                yield Input(value=self._initial_seed, placeholder="domain / wallet / @handle / company", id="seed")
                yield Select(
                    [("FAST gear", "fast"), ("DEEP gear", "deep")],
                    value="fast",
                    allow_blank=False,
                    id="gear",
                )
                yield Select(
                    [(f"depth {d}", d) for d in (1, 2, 3, 4)],
                    value=2,
                    allow_blank=False,
                    id="depth",
                )
                yield Button("▶ Run investigation", id="runbtn", variant="primary")
                yield Label("PRESETS")
                for preset in PRESETS:
                    yield Button(preset, classes="preset")
                yield Label("KEYS")
                yield Static("enter run · tab panes\n/ seed · d dossier\np pivot · q quit", classes="hint")
            with Vertical(id="center"):
                table: DataTable = DataTable(id="entities", cursor_type="row", zebra_stripes=True)
                table.add_columns("Entity", "Type", "Domain", "Smoke", "Flags")
                yield table
            with VerticalScroll(id="inspector"), TabbedContent(id="tabs"):
                with TabPane("Node", id="tab-node"):
                    yield Static("Select an entity to inspect its receipts.", id="nodedetail")
                with TabPane("Links", id="tab-links"):
                    yield Static("Run an investigation to map interconnections.", id="linksbody")
                with TabPane("Council", id="tab-council"):
                    yield Markdown("", id="councilbody")
                with TabPane("ACH", id="tab-ach"):
                    yield Static("", id="achbody")
                with TabPane("Dossier", id="tab-dossier"):
                    yield Markdown("", id="dossierbody")
                with TabPane("Arsenal", id="tab-arsenal"):
                    yield Static("Loading…", id="arsenalbody")
        yield Static("TIMELINE  —  run an investigation to build the chronology", id="timeline")
        log: RichLog = RichLog(id="log", highlight=False, markup=True, wrap=False, max_lines=2000)
        yield log
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log", RichLog).write("[dim]Ready. Enter a seed and press Run (or Enter).[/dim]")
        self._load_arsenal()
        if self._initial_seed:
            self.query_one("#seed", Input).cursor_position = len(self._initial_seed)

    # ---- actions & events ---------------------------------------------------------------------
    def action_focus_seed(self) -> None:
        self.query_one("#seed", Input).focus()

    def action_clear_log(self) -> None:
        self.query_one("#log", RichLog).clear()

    def action_show_dossier(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-dossier"

    def action_pivot(self) -> None:
        self._pivot_selected()

    def action_run(self) -> None:
        self._start_run()

    @on(Button.Pressed, "#runbtn")
    def _on_run_button(self) -> None:
        self._start_run()

    @on(Button.Pressed, ".preset")
    def _on_preset(self, event: Button.Pressed) -> None:
        label = str(event.button.label)
        self.query_one("#seed", Input).value = label
        self._start_run()

    @on(Input.Submitted, "#seed")
    def _on_seed_submit(self) -> None:
        self._start_run()

    @on(DataTable.RowHighlighted, "#entities")
    def _on_row(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        node = self._nodes_by_id.get(str(event.row_key.value))
        if node:
            self.query_one("#nodedetail", Static).update(self._format_node(node))

    # ---- the investigation worker -------------------------------------------------------------
    def _start_run(self) -> None:
        if self._running:
            self.notify("An investigation is already running.", severity="warning")
            return
        seed = self.query_one("#seed", Input).value.strip()
        if not seed:
            self.notify("Enter a seed first.", severity="error")
            self.query_one("#seed", Input).focus()
            return
        gear = GearMode(self.query_one("#gear", Select).value)
        depth = int(self.query_one("#depth", Select).value)
        self._running = True
        log = self.query_one("#log", RichLog)
        log.write(f"[bold cyan]▶ Launching[/bold cyan] seed=[bold]{seed}[/bold] gear={gear.value} depth={depth}")
        self.query_one("#statsbar", Static).update(self._stats_text(status="running"))
        self._run_worker(seed, gear, depth)

    @work(exclusive=True)
    async def _run_worker(self, seed: str, gear: GearMode, depth: int) -> None:
        def callback(evt: Dict[str, Any]) -> None:
            self.post_message(EngineEvent(evt))

        try:
            orch = BunnyholeOrchestrator(
                seed_query=seed, gear=gear, max_depth=depth, initial_breadth=4, event_callback=callback
            )
            result = await orch.run_investigation()
            self.post_message(RunFinished(result, orch))
        except Exception as exc:  # surface failure in the UI rather than crashing the app
            self.post_message(RunFailed(f"{type(exc).__name__}: {exc}"))

    def on_engine_event(self, message: EngineEvent) -> None:
        evt = message.payload
        if evt.get("type") != "agent_log":
            return
        d = evt.get("data", {})
        domain = str(d.get("agent", "")).lower()
        level = str(d.get("level", "info"))
        dstyle = _DOMAIN_STYLE.get(domain, "white")
        lstyle = _LEVEL_STYLE.get(level, "white")
        line = Text.assemble(
            (f"[{domain.upper()}] ", dstyle),
            (f"{d.get('action', '')} ", lstyle),
            (f"({d.get('target', '')}) ", "dim"),
            (str(d.get("detail", "")), "default"),
        )
        self.query_one("#log", RichLog).write(line)

    def on_run_finished(self, message: RunFinished) -> None:
        self._running = False
        self._result = message.result
        self._orchestrator = message.orchestrator
        self._populate(message.result)
        self.query_one("#log", RichLog).write("[bold green]✔ Investigation complete.[/bold green]")

    def on_run_failed(self, message: RunFailed) -> None:
        self._running = False
        self.query_one("#statsbar", Static).update(self._stats_text(status="error"))
        self.query_one("#log", RichLog).write(f"[bold red]✖ {message.error}[/bold red]")
        self.notify(message.error, severity="error", title="Investigation failed")

    # ---- rendering ----------------------------------------------------------------------------
    def _stats_text(self, status: str = "idle") -> str:
        stats = (self._result or {}).get("stats", {})
        badge = {"idle": "[dim]idle[/dim]", "running": "[bold yellow]running…[/bold yellow]",
                 "error": "[bold red]error[/bold red]", "done": "[bold green]done[/bold green]"}.get(status, status)
        return (
            f"[b magenta]BUNNYHOLE[/b magenta]  {badge}   "
            f"nodes [b green]{stats.get('total_nodes', 0)}[/b green]  "
            f"edges [b green]{stats.get('total_edges', 0)}[/b green]  "
            f"receipts [b green]{stats.get('total_receipts', 0)}[/b green]  "
            f"brokers [b #f0997b]{stats.get('cutout_brokers', 0)}[/b #f0997b]"
        )

    def _populate(self, result: Dict[str, Any]) -> None:
        nodes: List[Dict[str, Any]] = result.get("nodes", [])
        self._nodes_by_id = {n["id"]: n for n in nodes}
        table = self.query_one("#entities", DataTable)
        table.clear()
        for n in sorted(nodes, key=lambda x: (x.get("is_cutout_broker", False), x.get("smoke_score", 0)), reverse=True):
            flags = ", ".join(n.get("risk_flags", [])[:2]) or "—"
            smoke = f"{n.get('smoke_score', 0):.0f}"
            label = n.get("label", n["id"])
            if n.get("is_cutout_broker"):
                label = f"◆ {label}"
            table.add_row(label, n.get("entity_type", ""), n.get("domain", ""), smoke, flags, key=n["id"])

        self.query_one("#statsbar", Static).update(self._stats_text(status="done"))
        self._render_links(result.get("interconnections", {}))
        self._render_council(result.get("council", {}))
        self._render_ach(result.get("ach_assessment", {}))
        self.query_one("#dossierbody", Markdown).update(result.get("markdown_dossier", "") or "_No dossier._")
        self._render_timeline(result.get("timeline", []))
        if nodes:
            table.move_cursor(row=0)
            self.query_one("#nodedetail", Static).update(self._format_node(nodes[0]))

    def _format_node(self, n: Dict[str, Any]) -> Text:
        t = Text()
        t.append(f"{n.get('label', n['id'])}\n", style="bold white")
        t.append(f"{n.get('entity_type', '')} · {n.get('domain', '')}\n", style="dim")
        t.append(f"smoke {n.get('smoke_score', 0):.0f}/100   centrality {n.get('betweenness_centrality', 0):.3f}\n",
                 style="bold #f0997b")
        flags = n.get("risk_flags", [])
        if flags:
            t.append("flags: ", style="dim")
            t.append(", ".join(flags) + "\n", style="yellow")
        t.append(f"id: {n['id']}  hop {n.get('hop_depth', 0)}\n\n", style="dim")
        receipts = n.get("receipts", [])
        t.append(f"RECEIPTS ({len(receipts)})\n", style="bold green")
        for r in receipts[:8]:
            t.append(f"  [{r.get('admiralty_code', '?')}] ", style="bold cyan")
            t.append(f"{r.get('tool', '')}\n", style="green")
            t.append(f"    {r.get('extracted_fact', '')}\n", style="default")
            t.append(f"    {r.get('source_url', '')}\n", style="dim")
        return t

    def _render_links(self, inter: Dict[str, Any]) -> None:
        t = Text()
        keystones = inter.get("keystone_brokers", [])
        t.append("KEYSTONE / CUT-OUT BROKERS\n", style="bold yellow")
        for k in keystones[:5]:
            t.append(f"  ◆ {k.get('label', '')} ", style="yellow")
            t.append(f"bridges {', '.join(k.get('domains_bridged', []))} (CB {k.get('betweenness_centrality', 0)})\n", style="dim")
        if not keystones:
            t.append("  none detected\n", style="dim")
        paths = inter.get("targeted_paths") or inter.get("cross_domain_paths", [])
        t.append("\nCROSS-DOMAIN PATHS\n", style="bold cyan")
        for p in paths[:5]:
            t.append(f"  {p.get('hop_count', '?')}-hop ", style="cyan")
            t.append(" → ".join(p.get("step_labels", [])[:5]) + "\n", style="default")
        preds = inter.get("predicted_missing_links", [])
        if preds:
            t.append("\nPREDICTED (Adamic-Adar)\n", style="bold magenta")
            for pr in preds[:4]:
                t.append(f"  {pr.get('node_a_label', '')} ↔ {pr.get('node_b_label', '')} (AA {pr.get('adamic_adar_score', 0)})\n", style="default")
        self.query_one("#linksbody", Static).update(t)

    def _render_council(self, council: Dict[str, Any]) -> None:
        verdict = (council.get("stage3_chairman_verdict", {}) or {}).get("verdict_markdown", "")
        self.query_one("#councilbody", Markdown).update(verdict or "_Council verdict appears after a run._")

    def _render_ach(self, ach: Dict[str, Any]) -> None:
        t = Text()
        t.append(f"{ach.get('primary_question', '')}\n\n", style="bold cyan")
        t.append(f"WINNER: {ach.get('winning_hypothesis', '')}\n", style="bold green")
        t.append(f"{ach.get('narrative_verdict', '')}\n\n", style="default")
        t.append(f"H1 {ach.get('h1_score', 0)}  H2 {ach.get('h2_score', 0)}  H3 {ach.get('h3_score', 0)}\n", style="dim")
        for row in ach.get("matrix_rows", [])[:12]:
            t.append(f"  [{row.get('admiralty_code', '?')}] ", style="bold cyan")
            t.append(f"{row.get('diagnosticity', '')} ", style="yellow")
            t.append(f"{row.get('evidence_summary', '')}\n", style="default")
        self.query_one("#achbody", Static).update(t)

    def _render_timeline(self, items: List[Dict[str, Any]]) -> None:
        if not items:
            self.query_one("#timeline", Static).update("TIMELINE  —  no dated events")
            return
        parts = []
        for it in items[:8]:
            flag = " ⚠" if it.get("anomaly_flag") else ""
            parts.append(f"[cyan]{str(it.get('timestamp', ''))[:10]}[/cyan] {it.get('title', '')[:22]}{flag}")
        self.query_one("#timeline", Static).update("TIMELINE  " + "   ".join(parts))

    def _pivot_selected(self) -> None:
        if not self._orchestrator:
            self.notify("Run an investigation first.", severity="warning")
            return
        table = self.query_one("#entities", DataTable)
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            self.notify("Highlight an entity to pivot.", severity="warning")
            return
        node = self._nodes_by_id.get(str(row_key.value))
        if not node or self._running:
            return
        seed = node.get("attributes", {}).get("raw_seed") or str(node.get("label", "")).lstrip("🎯🔐🌐👤🖥️ ").strip()
        self.query_one("#log", RichLog).write(f"[bold cyan]⚡ Pivot[/bold cyan] on [bold]{seed}[/bold]")
        self._running = True
        self._pivot_worker(node["id"], seed, int(node.get("hop_depth", 1)) + 1)

    @work(exclusive=False)
    async def _pivot_worker(self, node_id: str, seed: str, hop: int) -> None:
        def callback(evt: Dict[str, Any]) -> None:
            self.post_message(EngineEvent(evt))

        try:
            orch = self._orchestrator
            orch.graph.subscribe(callback)
            ltype, _, _ = classify_seed_type(seed)
            await orch._execute_lead(ltype, seed, node_id, hop_depth=hop)
            orch._harvest_step_learnings_and_followups(current_hop=hop)
            orch.link_sleuth.break_dead_ends(current_hop=hop)
            result = orch.compile_full_result()
            result["markdown_dossier"] = orch.graph.export_markdown_dossier()
            self.post_message(RunFinished(result, orch))
        except Exception as exc:
            self.post_message(RunFailed(f"{type(exc).__name__}: {exc}"))

    @work(exclusive=False, thread=True)
    def _load_arsenal(self) -> None:
        try:
            from bunnyhole.arsenal.manager import ArsenalManager

            mgr = ArsenalManager()
            tools = mgr.check_arsenal_status()
            keys = mgr.get_api_keys_status()
        except Exception as exc:
            self.call_from_thread(self.query_one("#arsenalbody", Static).update, f"Arsenal unavailable: {exc}")
            return
        t = Text()
        installed = sum(1 for x in tools if x["installed"])
        t.append(f"TOOLS ({installed}/{len(tools)} installed)\n", style="bold cyan")
        for tool in tools:
            mark = "✔" if tool["installed"] else "○"
            style = "green" if tool["installed"] else "dim"
            t.append(f"  {mark} {tool['name']}\n", style=style)
        configured = sum(1 for k in keys if k["configured"])
        t.append(f"\nAPI KEYS ({configured}/{len(keys)} set)\n", style="bold yellow")
        for k in keys:
            mark = "●" if k["configured"] else "○"
            style = "green" if k["configured"] else "dim"
            t.append(f"  {mark} {k['key']}\n", style=style)
        self.call_from_thread(self.query_one("#arsenalbody", Static).update, t)


def launch(seed: Optional[str] = None) -> None:
    """Entry point used by the CLI and by ``textual serve``."""
    BunnyholeTUI(initial_seed=seed).run()


if __name__ == "__main__":
    launch()
