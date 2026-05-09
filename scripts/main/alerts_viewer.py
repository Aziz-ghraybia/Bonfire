import threading
import time
import sys
import tty
import termios
import json
import pathlib

from datetime import datetime, timezone
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from alerts_query import (
    Filters, fetch_page, fetch_count,
    fetch_rule_ids, fetch_years, total_pages, parse_detail,
    PAGE_SIZE
)

console = Console()


# ── Viewer state ─────────────────────────────────────────────────

class ViewerState:
    def __init__(self):
        self.filters      = Filters()
        self.page         = 1
        self.selected     = 0
        self.total        = 0
        self.rows         = []
        self.expanded     = None
        self.filter_focus = False
        self.filter_field = 0
        self.rule_ids     = []
        self.rule_idx     = 0
        self.sev_idx      = 0
        self.time_idx     = 0
        self.year_idx  = 0    # index into available years list
        self.month_idx = 0    # 0 = ALL, 1-12 = Jan-Dec
        self.years     = []   # populated on refresh
        self.stop         = threading.Event()

    @property
    def total_pages(self) -> int:
        return total_pages(self.filters)

    def refresh(self):
        self.rule_ids = fetch_rule_ids()
        self.years = fetch_years()   # we'll add this to alerts_query.py
        self.total    = fetch_count(self.filters)
        self.rows     = fetch_page(self.filters, self.page)
        if self.selected >= len(self.rows):
            self.selected = max(0, len(self.rows) - 1)

    def next_page(self):
        if self.page < self.total_pages:
            self.page    += 1
            self.selected = 0
            self.refresh()

    def prev_page(self):
        if self.page > 1:
            self.page    -= 1
            self.selected = 0
            self.refresh()

    def move_down(self):
        if self.selected < len(self.rows) - 1:
            self.selected += 1

    def move_up(self):
        if self.selected > 0:
            self.selected -= 1

    def expand_selected(self):
        if self.rows:
            self.expanded = self.rows[self.selected]

    def collapse(self):
        self.expanded = None


# ── Panel builders ───────────────────────────────────────────────

def build_header() -> Panel:
    now     = datetime.now(timezone.utc)
    content = Text()
    content.append("🔥 BONFIRE", style="bold orange1")
    content.append("  │  ", style="dim")
    content.append("Alert Inspector", style="bold white")
    content.append("  │  ", style="dim")
    content.append(now.strftime("%Y-%m-%d  %H:%M:%S UTC"), style="bold white")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_filters(state: ViewerState) -> Panel:
    content = Text()
    f       = state.filters

    # severity row
    content.append("Severity : ", style="dim")
    for i, sev in enumerate(Filters.SEVERITIES):
        is_active = (sev == f.severity)
        is_focus  = (state.filter_focus and state.filter_field == 0
                     and i == state.sev_idx)
        if is_active:
            style = "bold white on red" if sev != "ALL" else "bold white on blue"
        elif is_focus:
            style = "bold cyan on grey23"
        else:
            style = "dim"
        content.append(f" {sev} ", style=style)
        content.append(" ")
    content.append("\n")

    # rule row
    content.append("Rule     : ", style="dim")
    visible_rules = state.rule_ids[:10] if state.rule_ids else ["ALL"]
    for i, rid in enumerate(visible_rules):
        is_active = (rid == f.rule_id)
        is_focus  = (state.filter_focus and state.filter_field == 1
                     and i == state.rule_idx)
        if is_active:
            style = "bold white on dark_orange"
        elif is_focus:
            style = "bold cyan on grey23"
        else:
            style = "dim"
        content.append(f" {rid} ", style=style)
        content.append(" ")
    content.append("\n")

    # time row
    content.append("Time     : ", style="dim")
    for i, opt in enumerate(Filters.TIME_OPTS.keys()):
        is_active = (opt == f.time)
        is_focus  = (state.filter_focus and state.filter_field == 2
                     and i == state.time_idx)
        if is_active:
            style = "bold white on green4"
        elif is_focus:
            style = "bold cyan on grey23"
        else:
            style = "dim"
        content.append(f" {opt} ", style=style)
        content.append(" ")
    content.append("\n")


    # date row
    months = ["ALL","01","02","03","04","05","06","07","08","09","10","11","12"]
    month_names = ["ALL","Jan","Feb","Mar","Apr","May","Jun",
               "Jul","Aug","Sep","Oct","Nov","Dec"]

    content.append("Year     : ", style="dim")
    year_val  = state.years[state.year_idx] if state.years else "ALL"
    is_focus  = (state.filter_focus and state.filter_field == 3)
    year_style = "bold cyan on grey23" if is_focus else ("bold white on green4" if year_val != "ALL" else "dim")
    content.append(" ◀ ", style="dim")
    content.append(f" {year_val} ", style=year_style)
    content.append(" ▶ ", style="dim")
    content.append("   Month : ", style="dim")
    for i, (m, mn) in enumerate(zip(months, month_names)):
    	is_active = (m == state.filters.month)
    	is_focus  = (state.filter_focus and state.filter_field == 4 and i == state.month_idx)
    	if is_active:
        	style = "bold white on green4"
    	elif is_focus:
        	style = "bold cyan on grey23"
    	else:
        	style = "dim"
    	content.append(f" {mn} ", style=style)
    	content.append(" ")
    content.append("\n")

    # process + search text inputs
    proc_style   = "bold cyan" if (state.filter_focus
                                   and state.filter_field == 5) else "dim"
    search_style = "bold cyan" if (state.filter_focus
                                   and state.filter_field == 6) else "dim"
    content.append("Process  : ", style="dim")
    content.append(f"[{f.process or '...'}]", style=proc_style)
    content.append("    Search : ", style="dim")
    content.append(f"[{f.search or '...'}]", style=search_style)

    border = "cyan" if state.filter_focus else "dim"
    return Panel(
        content,
        title="[bold white]Filters[/bold white]  [dim](F to toggle)[/dim]",
        border_style=border,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def build_table(state: ViewerState) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("ID",      width=5,  style="dim")
    table.add_column("TIME",    width=19, style="dim")
    table.add_column("SEV",     width=10)
    table.add_column("RULE",    width=6)
    table.add_column("PROCESS", width=12)
    table.add_column("MESSAGE", ratio=1)

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "bold orange1",
        "MEDIUM":   "bold yellow",
        "LOW":      "dim white",
    }

    if not state.rows:
        table.add_row(
            "", "", "", "", "",
            Text("No alerts match current filters.", style="dim italic")
        )
    else:
        for i, row in enumerate(state.rows):
            is_selected = (i == state.selected)
            sev_style   = sev_styles.get(row["severity"], "white")
            ts          = row["timestamp"][:19].replace("T", " ")
            row_style   = "on grey19" if is_selected else ""
            prefix      = "▶ " if is_selected else "  "
            message     = row.get("message", "")
            if len(message) > 80:
                message = message[:80] + "..."

            table.add_row(
                f"{prefix}{row['id']}",
                ts,
                Text(row["severity"], style=sev_style),
                row["rule_id"],
                row["comm"] or "",
                message,
                style=row_style,
            )

    start    = (state.page - 1) * PAGE_SIZE + 1
    end      = min(state.page * PAGE_SIZE, state.total)
    subtitle = (
        f"[dim]page {state.page} of {state.total_pages}"
        f"  │  {start}-{end} of {state.total} alerts[/dim]"
    )

    return Panel(
        table,
        title="[bold white]Alerts[/bold white]",
        subtitle=subtitle,
        border_style="dim red",
        box=box.ROUNDED,
    )


def build_expanded(alert: dict) -> Panel:
    content = Text()

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "bold orange1",
        "MEDIUM":   "bold yellow",
        "LOW":      "dim white",
    }

    def row(label, value, style="white"):
        content.append(f"  {label:<16}", style="dim")
        content.append(f"{value}\n", style=style)

    content.append("── Alert Details ────────────────────────\n", style="dim")
    row("ID",         str(alert["id"]))
    row("Timestamp",  alert["timestamp"][:19].replace("T", " "), "cyan")
    row("Rule",       f"{alert['rule_id']} — {alert['rule_name']}", "bold white")
    row("Severity",   alert["severity"],
        sev_styles.get(alert["severity"], "white"))
    row("Message",    alert["message"])

    content.append("\n── Process ──────────────────────────────\n", style="dim")
    row("PID",        str(alert["pid"]))
    row("UID",        str(alert["uid"]))
    row("Process",    alert["comm"] or "")
    row("Event Type", alert["event_type"])

    detail = parse_detail(alert)
    if detail:
        content.append("\n── Event Detail ─────────────────────────\n",
                       style="dim")
        for k, v in detail.items():
            row(k, str(v), "cyan")

    return Panel(
        content,
        title="[bold white]Expanded Alert[/bold white]"
              "  [dim](ESC to close)[/dim]",
        border_style="red",
        box=box.ROUNDED,
    )


def build_footer(state: ViewerState) -> Panel:
    content = Text()

    if state.filter_focus:
        content.append(" [TAB]",  style="bold cyan")
        content.append(" next field  ", style="dim")
        content.append("[←→]",   style="bold cyan")
        content.append(" cycle option  ", style="dim")
        content.append("[ESC]",   style="bold cyan")
        content.append(" exit filters", style="dim")
    elif state.expanded:
        content.append(" [ESC]",  style="bold cyan")
        content.append(" close expanded alert", style="dim")
    else:
        content.append(" [↑↓]",   style="bold cyan")
        content.append(" navigate  ", style="dim")
        content.append("[←→]",   style="bold cyan")
        content.append(" page  ", style="dim")
        content.append("[ENTER]", style="bold cyan")
        content.append(" expand  ", style="dim")
        content.append("[F]",     style="bold cyan")
        content.append(" filters  ", style="dim")
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


def build_layout(state: ViewerState) -> Layout:
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
            Layout(name="header",  size=3),
            Layout(name="filters", size=7),
            Layout(name="table"),
            Layout(name="footer",  size=3),
        )
        layout["header"].update(build_header())
        layout["filters"].update(build_filters(state))
        layout["table"].update(build_table(state))
        layout["footer"].update(build_footer(state))

    return layout


# ── Keyboard handling ────────────────────────────────────────────

def handle_key(ch: str, state: ViewerState):
    if state.expanded:
        if ch in ('\x1b', 'q', 'Q'):
            state.collapse()
        return

    if state.filter_focus:
        _handle_filter_key(ch, state)
        return

    if ch == '\x1b[A':                 # up arrow
        state.move_up()
    elif ch == '\x1b[B':               # down arrow
        state.move_down()
    elif ch == '\x1b[C':               # right arrow — next page
        state.next_page()
    elif ch == '\x1b[D':               # left arrow — prev page
        state.prev_page()
    elif ch in ('\r', '\n'):           # enter — expand
        state.expand_selected()
    elif ch.lower() == 'f':            # toggle filters
        state.filter_focus = True
    elif ch.lower() == 'r':            # refresh
        state.refresh()
    elif ch.lower() == 'q':            # quit
        state.stop.set()


def _handle_filter_key(ch: str, state: ViewerState):
    f = state.filters

    if ch == '\x1b':                   # ESC — exit filter mode
        state.filter_focus = False
        state.refresh()
        return

    if ch == '\t':                     # TAB — next field
        state.filter_field = (state.filter_field + 1) % 7
        return

    field = state.filter_field

    if field == 0:                     # severity
        if ch == '\x1b[C':
            state.sev_idx = (state.sev_idx + 1) % len(Filters.SEVERITIES)
        elif ch == '\x1b[D':
            state.sev_idx = (state.sev_idx - 1) % len(Filters.SEVERITIES)
        f.severity = Filters.SEVERITIES[state.sev_idx]

    elif field == 1:                   # rule
        if state.rule_ids:
            if ch == '\x1b[C':
                state.rule_idx = (state.rule_idx + 1) % len(state.rule_ids)
            elif ch == '\x1b[D':
                state.rule_idx = (state.rule_idx - 1) % len(state.rule_ids)
            f.rule_id = state.rule_ids[state.rule_idx]

    elif field == 2:                   # time
        time_keys = list(Filters.TIME_OPTS.keys())
        if ch == '\x1b[C':
            state.time_idx = (state.time_idx + 1) % len(time_keys)
        elif ch == '\x1b[D':
            state.time_idx = (state.time_idx - 1) % len(time_keys)
        f.time = time_keys[state.time_idx]
    elif field == 3:    # year
    	if state.years:
        	if ch == '\x1b[C':
            		state.year_idx = (state.year_idx + 1) % len(state.years)
        	elif ch == '\x1b[D':
           		 state.year_idx = (state.year_idx - 1) % len(state.years)
        	state.filters.year = state.years[state.year_idx]

    elif field == 4:    # month
    	months = ["ALL","01","02","03","04","05","06",
              "07","08","09","10","11","12"]
    	if ch == '\x1b[C':
        	state.month_idx = (state.month_idx + 1) % len(months)
    	elif ch == '\x1b[D':
        	state.month_idx = (state.month_idx - 1) % len(months)
    	state.filters.month = months[state.month_idx]

    elif field == 5:                   # process text input
        if ch in ('\x7f', '\x08'):
            f.process = f.process[:-1]
        elif ch.isprintable():
            f.process += ch

    elif field == 6:                   # search text input
        if ch in ('\x7f', '\x08'):
            f.search = f.search[:-1]
        elif ch.isprintable():
            f.search += ch

    state.page     = 1
    state.selected = 0
    state.refresh()


# ── Keyboard listener thread ─────────────────────────────────────

def keyboard_listener(state: ViewerState):
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

def run_alerts_viewer():
    state = ViewerState()
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

    console.print("\n[orange1]🔥 Bonfire alerts viewer closed.[/orange1]")


if __name__ == "__main__":
    run_alerts_viewer()
