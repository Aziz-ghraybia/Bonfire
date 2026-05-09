import threading
import time
import sys
import tty
import termios
import pathlib

from datetime import datetime, timezone
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from rules_query import (
    fetch_rules_with_hits,
    is_sequence_rule,
    format_conditions,
)

console = Console()


# ── Viewer state ─────────────────────────────────────────────────

class RulesViewerState:
    def __init__(self):
        self.rules    = []
        self.selected = 0
        self.expanded = None    # expanded rule dict or None
        self.stop     = threading.Event()

    def refresh(self):
        self.rules = fetch_rules_with_hits()
        if self.selected >= len(self.rules):
            self.selected = max(0, len(self.rules) - 1)

    def move_up(self):
        if self.selected > 0:
            self.selected -= 1

    def move_down(self):
        if self.selected < len(self.rules) - 1:
            self.selected += 1

    def expand_selected(self):
        if self.rules:
            self.expanded = self.rules[self.selected]

    def collapse(self):
        self.expanded = None


# ── Panel builders ───────────────────────────────────────────────

def build_header() -> Panel:
    now     = datetime.now(timezone.utc)
    content = Text()
    content.append("🔥 BONFIRE", style="bold orange1")
    content.append("  │  ", style="dim")
    content.append("Rules Viewer", style="bold white")
    content.append("  │  ", style="dim")
    content.append("default.yaml", style="dim cyan")
    content.append("  │  ", style="dim")
    content.append(now.strftime("%Y-%m-%d  %H:%M:%S UTC"), style="bold white")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_rules_table(state: RulesViewerState) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("ID",       width=7)
    table.add_column("NAME",     ratio=1)
    table.add_column("TYPE",     width=10)
    table.add_column("EVENT",    width=10)
    table.add_column("SEVERITY", width=10)
    table.add_column("HITS",     width=6)

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "bold orange1",
        "MEDIUM":   "bold yellow",
        "LOW":      "dim white",
    }

    if not state.rules:
        table.add_row("", "No rules loaded.", "", "", "", "")
    else:
        for i, rule in enumerate(state.rules):
            is_selected  = (i == state.selected)
            is_sequence  = is_sequence_rule(rule)
            sev_style    = sev_styles.get(rule.get("severity", ""), "white")
            row_style    = "on grey19" if is_selected else ""
            prefix       = "▶ " if is_selected else "  "
            hits         = rule.get("hits", 0)
            hits_style   = "bold red" if hits > 0 else "dim"
            rule_type    = "SEQUENCE" if is_sequence else "SINGLE"
            type_style   = "bold magenta" if is_sequence else "dim cyan"
            event_type   = "MULTI" if is_sequence else rule.get("event_type", "").upper()

            table.add_row(
                f"{prefix}{rule['id']}",
                Text(rule.get("name", ""), style="bold white" if is_selected else "white"),
                Text(rule_type,  style=type_style),
                Text(event_type, style="dim"),
                Text(rule.get("severity", ""), style=sev_style),
                Text(str(hits), style=hits_style),
                style=row_style,
            )

    subtitle = f"[dim]{len(state.rules)} rules loaded[/dim]"

    return Panel(
        table,
        title="[bold white]Detection Rules[/bold white]",
        subtitle=subtitle,
        border_style="dim orange1",
        box=box.ROUNDED,
    )


def build_expanded(rule: dict) -> Panel:
    content  = Text()
    is_seq   = is_sequence_rule(rule)
    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "bold orange1",
        "MEDIUM":   "bold yellow",
        "LOW":      "dim white",
    }

    def row(label, value, style="white"):
        content.append(f"  {label:<16}", style="dim")
        content.append(f"{value}\n", style=style)

    content.append("── Rule Details ─────────────────────────\n", style="dim")
    row("ID",       rule["id"])
    row("Name",     rule.get("name", ""),     "bold white")
    row("Severity", rule.get("severity", ""),
        sev_styles.get(rule.get("severity", ""), "white"))
    row("Type",     "SEQUENCE" if is_seq else "SINGLE EVENT",
        "bold magenta" if is_seq else "cyan")
    row("Hits",     str(rule.get("hits", 0)),
        "bold red" if rule.get("hits", 0) > 0 else "dim")

    content.append("\n── Conditions ───────────────────────────\n", style="dim")
    for line in format_conditions(rule):
        if line.startswith("Step"):
            content.append(f"  {line}\n", style="bold cyan")
        elif line.startswith("  "):
            content.append(f"  {line}\n", style="white")
        elif line == "":
            content.append("\n")
        else:
            content.append(f"  {line}\n", style="dim")

    return Panel(
        content,
        title=f"[bold white]{rule['id']} — {rule.get('name', '')}[/bold white]"
              "  [dim](ESC to close)[/dim]",
        border_style="orange1",
        box=box.ROUNDED,
    )


def build_footer(state: RulesViewerState) -> Panel:
    content = Text()

    if state.expanded:
        content.append(" [ESC]", style="bold cyan")
        content.append(" close  ", style="dim")
    else:
        content.append(" [↑↓]",   style="bold cyan")
        content.append(" navigate  ", style="dim")
        content.append("[ENTER]", style="bold cyan")
        content.append(" expand  ", style="dim")
        content.append("[R]",     style="bold cyan")
        content.append(" refresh  ", style="dim")
        content.append("[Q]",     style="bold cyan")
        content.append(" quit", style="dim")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_layout(state: RulesViewerState) -> Layout:
    layout = Layout()

    if state.expanded:
        layout.split_column(
            Layout(name="header",   size=3),
            Layout(name="expanded"),
            Layout(name="footer",   size=3),
        )
        layout["header"].update(build_header())
        layout["expanded"].update(build_expanded(state.expanded))
        layout["footer"].update(build_footer(state))
    else:
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="table"),
            Layout(name="footer", size=3),
        )
        layout["header"].update(build_header())
        layout["table"].update(build_rules_table(state))
        layout["footer"].update(build_footer(state))

    return layout


# ── Keyboard handling ────────────────────────────────────────────

def handle_key(ch: str, state: RulesViewerState):
    if state.expanded:
        if ch in ('\x1b', 'q', 'Q'):
            state.collapse()
        return

    if ch == '\x1b[A':                 # up arrow
        state.move_up()
    elif ch == '\x1b[B':               # down arrow
        state.move_down()
    elif ch in ('\r', '\n'):           # enter — expand
        state.expand_selected()
    elif ch.lower() == 'r':            # refresh
        state.refresh()
    elif ch.lower() == 'q':            # quit
        state.stop.set()


def keyboard_listener(state: RulesViewerState):
    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not state.stop.is_set():
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                try:
                    ch2 = sys.stdin.read(1)
                    if ch2 == '[':
                        ch3 = sys.stdin.read(1)
                        ch  = f'\x1b[{ch3}'
                    else:
                        ch = '\x1b'
                except Exception:
                    ch = '\x1b'
            handle_key(ch, state)
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ── Main entry point ─────────────────────────────────────────────

def run_rules_viewer():
    state = RulesViewerState()
    state.refresh()

    threading.Thread(
        target=keyboard_listener,
        args=(state,),
        daemon=True
    ).start()

    with Live(
        build_layout(state),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        try:
            while not state.stop.is_set():
                live.update(build_layout(state))
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass

    console.print("\n[orange1]🔥 Bonfire rules viewer closed.[/orange1]")


if __name__ == "__main__":
    run_rules_viewer()
