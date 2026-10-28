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

from archive_query import (
    fetch_archives, fetch_hot_days,
    fetch_days_from_archive, fetch_events_from_archive,
    fetch_events_from_hot,
)

console = Console()

HOT_DIR  = pathlib.Path(__file__).parent.parent / "storage" / "hot"
WARM_DIR = pathlib.Path(__file__).parent.parent / "storage" / "warm"


# ── Viewer state ─────────────────────────────────────────────────

class ArchiveState:

    # view levels
    LEVEL_MONTHS = "months"
    LEVEL_DAYS   = "days"
    LEVEL_EVENTS = "events"

    def __init__(self):
        self.level         = self.LEVEL_MONTHS
        self.selected      = 0
        self.stop          = threading.Event()

        # months level
        self.archives      = []     # warm zips
        self.hot_days      = []     # current hot logs
        self.all_months    = []     # combined: hot current + warm archives

        # days level
        self.selected_month = None  # dict from all_months
        self.days           = []    # list of day dicts

        # events level
        self.selected_day   = None  # dict from days
        self.events         = []    # list of event dicts
        self.event_offset   = 0     # scroll position
        self.filter_type    = "ALL" # ALL / EXECVE / CONNECT
        self.search         = ""
        self.search_active  = False
        self.search_buffer  = ""

    def refresh_months(self):
        self.archives   = fetch_archives()
        self.hot_days   = fetch_hot_days()

        # build combined list — hot current month first then warm archives
        self.all_months = []

        # group hot days into current month entry
        if self.hot_days:
            first      = self.hot_days[0]
            ym         = first["date"][:7]
            from archive_query import _ym_to_label
            label      = _ym_to_label(ym) + "  (current)"
            total_lines = sum(d["line_count"] for d in self.hot_days)
            self.all_months.append({
                "type":        "hot",
                "ym":          ym,
                "label":       label,
                "line_count":  total_lines,
                "days":        self.hot_days,
            })

        # add warm archives
        for arch in self.archives:
            self.all_months.append({
                "type":     "warm",
                "ym":       arch["ym"],
                "label":    arch["label"],
                "size_mb":  arch["size_mb"],
                "path":     arch["path"],
            })

        # clamp selection
        if self.selected >= len(self.all_months):
            self.selected = max(0, len(self.all_months) - 1)

    def open_month(self):
        if not self.all_months:
            return
        month = self.all_months[self.selected]
        self.selected_month = month

        if month["type"] == "hot":
            self.days = month["days"]
        else:
            self.days = fetch_days_from_archive(month["path"])

        self.level    = self.LEVEL_DAYS
        self.selected = 0

    def open_day(self):
        if not self.days:
            return
        day = self.days[self.selected]
        self.selected_day = day

        if self.selected_month["type"] == "hot":
            self.events = fetch_events_from_hot(day["path"])
        else:
            self.events = fetch_events_from_archive(
                self.selected_month["path"],
                day["filename"],
            )

        self.level        = self.LEVEL_EVENTS
        self.selected     = 0
        self.event_offset = 0
        self.filter_type  = "ALL"
        self.search       = ""

    def filtered_events(self) -> list[dict]:
        evs = self.events
        if self.filter_type != "ALL":
            evs = [e for e in evs if e.get("type") == self.filter_type]
        if self.search.strip():
            term = self.search.strip().lower()
            evs  = [e for e in evs if
                    term in e.get("comm",     "").lower() or
                    term in e.get("filename", "").lower() or
                    term in e.get("daddr",    "").lower() or
                    term in str(e.get("dport","")).lower()]
        return evs

    def go_back(self):
        if self.level == self.LEVEL_EVENTS:
            self.level    = self.LEVEL_DAYS
            self.selected = 0
        elif self.level == self.LEVEL_DAYS:
            self.level    = self.LEVEL_MONTHS
            self.selected = 0

    def move_up(self):
        if self.level == self.LEVEL_EVENTS:
            if self.event_offset > 0:
                self.event_offset -= 1
        else:
            if self.selected > 0:
                self.selected -= 1

    def move_down(self):
        if self.level == self.LEVEL_EVENTS:
            evs = self.filtered_events()
            if self.event_offset < max(0, len(evs) - 20):
                self.event_offset += 1
        else:
            items = self.all_months if self.level == self.LEVEL_MONTHS else self.days
            if self.selected < len(items) - 1:
                self.selected += 1

    def cycle_filter(self):
        types = ["ALL", "EXECVE", "CONNECT"]
        idx   = types.index(self.filter_type)
        self.filter_type  = types[(idx + 1) % len(types)]
        self.event_offset = 0


# ── Panel builders ───────────────────────────────────────────────

def build_header(state: ArchiveState) -> Panel:
    now     = datetime.now(timezone.utc)
    content = Text()
    content.append("🔥 BONFIRE", style="bold orange1")
    content.append("  │  ", style="dim")
    content.append("Archive Viewer", style="bold white")
    content.append("  │  ", style="dim")

    # breadcrumb
    if state.level == ArchiveState.LEVEL_MONTHS:
        content.append("All Archives", style="dim cyan")
    elif state.level == ArchiveState.LEVEL_DAYS:
        content.append("All Archives", style="dim")
        content.append(" › ", style="dim")
        content.append(state.selected_month["label"], style="dim cyan")
    elif state.level == ArchiveState.LEVEL_EVENTS:
        content.append("All Archives", style="dim")
        content.append(" › ", style="dim")
        content.append(state.selected_month["label"], style="dim")
        content.append(" › ", style="dim")
        content.append(state.selected_day["label"], style="dim cyan")

    content.append("  │  ", style="dim")
    content.append(now.strftime("%Y-%m-%d  %H:%M:%S UTC"), style="bold white")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_months_panel(state: ArchiveState) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("",       width=3)
    table.add_column("Month",  ratio=1)
    table.add_column("Type",   width=10)
    table.add_column("Size",   width=12)

    if not state.all_months:
        table.add_row("", "No archives found.", "", "")
    else:
        for i, m in enumerate(state.all_months):
            is_sel     = (i == state.selected)
            row_style  = "on grey19" if is_sel else ""
            prefix     = "▶ " if is_sel else "  "
            type_label = Text("CURRENT", style="bold green") \
                         if m["type"] == "hot" \
                         else Text("ARCHIVE", style="dim cyan")

            if m["type"] == "hot":
                size_str = Text(f"{m['line_count']} events", style="dim")
            else:
                size_str = Text(f"{m['size_mb']} MB", style="dim")

            table.add_row(
                prefix,
                Text(m["label"], style="bold white" if is_sel else "white"),
                type_label,
                size_str,
                style=row_style,
            )

    return Panel(
        table,
        title="[bold white]Archives[/bold white]",
        subtitle=f"[dim]{len(state.all_months)} available[/dim]",
        border_style="dim orange1",
        box=box.ROUNDED,
    )


def build_days_panel(state: ArchiveState) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("",      width=3)
    table.add_column("Date",  ratio=1)
    table.add_column("Events", width=10)

    if not state.days:
        table.add_row("", "No daily logs found.", "")
    else:
        for i, day in enumerate(state.days):
            is_sel    = (i == state.selected)
            row_style = "on grey19" if is_sel else ""
            prefix    = "▶ " if is_sel else "  "
            table.add_row(
                prefix,
                Text(day["label"], style="bold white" if is_sel else "white"),
                Text(str(day["line_count"]), style="dim cyan"),
                style=row_style,
            )

    month_label = state.selected_month["label"] if state.selected_month else ""
    return Panel(
        table,
        title=f"[bold white]{month_label}[/bold white]",
        subtitle=f"[dim]{len(state.days)} daily logs[/dim]",
        border_style="dim orange1",
        box=box.ROUNDED,
    )


def build_events_panel(state: ArchiveState) -> Panel:
    evs      = state.filtered_events()
    visible  = evs[state.event_offset: state.event_offset + 25]

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("TIME",   width=10, style="dim")
    table.add_column("TYPE",   width=9)
    table.add_column("PID",    width=7,  style="dim")
    table.add_column("PROC",   width=14)
    table.add_column("DETAIL", ratio=1)

    if not visible:
        table.add_row("", "", "", "",
            Text("No events match current filter.", style="dim italic"))
    else:
        for ev in visible:
            ts   = ev.get("timestamp", "")[:19].replace("T", " ")[11:]
            etype = ev.get("type", "")

            if etype == "EXECVE":
                type_text  = Text("EXECVE",  style="cyan")
                detail     = Text()
                detail.append(ev.get("filename", ""), style="green")
                detail.append(f"  parent={ev.get('pcomm','')}", style="dim")
                detail.append(f"  argc={ev.get('argc','')}", style="dim")
            elif etype == "CONNECT":
                type_text  = Text("CONNECT", style="yellow")
                detail     = Text()
                detail.append(ev.get("daddr", ""), style="yellow")
                detail.append(f":{ev.get('dport','')}", style="bold yellow")
            else:
                type_text = Text(etype, style="dim")
                detail    = Text(ev.get("message", ""), style="dim")

            table.add_row(
                ts,
                type_text,
                str(ev.get("pid", "")),
                ev.get("comm", ""),
                detail,
            )

    # filter + search status
    filter_str  = f"type={state.filter_type}"
    search_str  = f"  search=[{state.search or '...'}]"
    total       = len(evs)
    subtitle    = f"[dim]{total} events  │  {filter_str}{search_str}[/dim]"

    day_label = state.selected_day["label"] if state.selected_day else ""
    return Panel(
        table,
        title=f"[bold white]{day_label}[/bold white]",
        subtitle=subtitle,
        border_style="dim orange1",
        box=box.ROUNDED,
    )


def build_footer(state: ArchiveState) -> Panel:
    content = Text()

    if state.search_active:
        content.append(" Search: ", style="dim")
        content.append(f"[{state.search_buffer}]", style="bold cyan")
        content.append("  [ENTER]", style="bold cyan")
        content.append(" apply  ", style="dim")
        content.append("[ESC]", style="bold cyan")
        content.append(" cancel", style="dim")
    elif state.level == ArchiveState.LEVEL_EVENTS:
        content.append(" [↑↓]",   style="bold cyan")
        content.append(" scroll  ", style="dim")
        content.append("[T]",     style="bold cyan")
        content.append(" type filter  ", style="dim")
        content.append("[S]",     style="bold cyan")
        content.append(" search  ", style="dim")
        content.append("[ESC]",   style="bold cyan")
        content.append(" back  ", style="dim")
        content.append("[Q]",     style="bold cyan")
        content.append(" quit", style="dim")
    else:
        content.append(" [↑↓]",   style="bold cyan")
        content.append(" navigate  ", style="dim")
        content.append("[ENTER]", style="bold cyan")
        content.append(" open  ", style="dim")
        content.append("[ESC]",   style="bold cyan")
        content.append(" back  ", style="dim")
        content.append("[Q]",     style="bold cyan")
        content.append(" quit", style="dim")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_layout(state: ArchiveState) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    layout["header"].update(build_header(state))
    layout["footer"].update(build_footer(state))

    if state.level == ArchiveState.LEVEL_MONTHS:
        layout["body"].update(build_months_panel(state))
    elif state.level == ArchiveState.LEVEL_DAYS:
        layout["body"].update(build_days_panel(state))
    elif state.level == ArchiveState.LEVEL_EVENTS:
        layout["body"].update(build_events_panel(state))

    return layout


# ── Keyboard handling ────────────────────────────────────────────

def handle_key(ch: str, state: ArchiveState):

    # search input mode
    if state.search_active:
        if ch == '\x1b':
            state.search_active = False
            state.search_buffer = ""
        elif ch in ('\r', '\n'):
            state.search        = state.search_buffer
            state.search_active = False
            state.event_offset  = 0
        elif ch in ('\x7f', '\x08'):
            state.search_buffer = state.search_buffer[:-1]
        elif ch.isprintable():
            state.search_buffer += ch
        return

    # normal navigation
    if ch == '\x1b[A':      # up
        state.move_up()
    elif ch == '\x1b[B':    # down
        state.move_down()
    elif ch in ('\r', '\n'):
        if state.level == ArchiveState.LEVEL_MONTHS:
            state.open_month()
        elif state.level == ArchiveState.LEVEL_DAYS:
            state.open_day()
    elif ch == '\x1b':      # ESC — back
        state.go_back()
    elif ch.lower() == 'q':
        state.stop.set()
    elif ch.lower() == 't' and state.level == ArchiveState.LEVEL_EVENTS:
        state.cycle_filter()
    elif ch.lower() == 's' and state.level == ArchiveState.LEVEL_EVENTS:
        state.search_active = True
        state.search_buffer = state.search


def keyboard_listener(state: ArchiveState):
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


# ── Entry point ──────────────────────────────────────────────────

def run_archive_viewer():
    state = ArchiveState()
    state.refresh_months()

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

    console.print("\n[orange1]🔥 Bonfire archive viewer closed.[/orange1]")


if __name__ == "__main__":
    run_archive_viewer()
