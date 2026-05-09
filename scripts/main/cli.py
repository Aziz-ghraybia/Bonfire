import threading
import time
from datetime import datetime, timezone
from collections import deque

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from monitor import build_monitor
from metrics import Metrics
from rules import RuleEngine
from correlator import Correlator
from logger import Logger
from events import ExecveEvent, ConnectEvent


# ── constants ────────────────────────────────────────────────────
MAX_EVENTS = 100
MAX_ALERTS = 50
REFRESH_HZ = 4

console = Console()


# ── shared state ─────────────────────────────────────────────────

class SharedState:
    def __init__(self):
        self._lock        = threading.Lock()
        self.events       = deque(maxlen=MAX_EVENTS)
        self.alerts       = deque(maxlen=MAX_ALERTS)
        self.metrics_snap = {}
        self.paused       = False
        self.alert_pids   = set()

    def add_event(self, event):
        with self._lock:
            if not self.paused:
                self.events.appendleft(event)

    def add_alert(self, alert):
        with self._lock:
            self.alerts.appendleft(alert)
            self.alert_pids.add(alert.event.pid)

    def update_metrics(self, snap: dict):
        with self._lock:
            self.metrics_snap = snap

    def toggle_pause(self):
        with self._lock:
            self.paused = not self.paused

    def clear_events(self):
        with self._lock:
            self.events.clear()
            self.alert_pids.clear()

    def get_events(self):
        with self._lock:
            return list(self.events)

    def get_alerts(self):
        with self._lock:
            return list(self.alerts)

    def get_metrics(self):
        with self._lock:
            return dict(self.metrics_snap)

    def is_paused(self):
        with self._lock:
            return self.paused

    def is_alert_pid(self, pid):
        with self._lock:
            return pid in self.alert_pids


# ── layout builders ──────────────────────────────────────────────

def build_header(snap: dict) -> Panel:
    now      = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S UTC")
    uptime   = snap.get("uptime", "00:00:00")

    row1 = Text()
    row1.append("🔥 BONFIRE", style="bold orange1")
    row1.append("  │  ", style="dim")
    row1.append("uptime: ", style="dim")
    row1.append(uptime, style="bold cyan")
    row1.append("  │  ", style="dim")
    row1.append(date_str, style="dim white")
    row1.append("  ")
    row1.append(time_str, style="bold white")

    cpu = snap.get("cpu_percent", 0.0)
    mem = snap.get("mem_percent", 0.0)
    thr = snap.get("cpu_per_thread", [])
    dr  = snap.get("disk_read_bps",  0.0)
    dw  = snap.get("disk_write_bps", 0.0)
    ns  = snap.get("net_sent_bps",   0.0)
    nr  = snap.get("net_recv_bps",   0.0)

    cpu_color   = "green" if cpu < 50 else "yellow" if cpu < 80 else "red"
    mem_color   = "green" if mem < 50 else "yellow" if mem < 80 else "red"
    threads_str = " ".join(f"{t:.0f}%" for t in thr)

    row2 = Text()
    row2.append("CPU: ", style="dim")
    row2.append(f"{cpu:.1f}%", style=cpu_color)
    row2.append(f"  Threads: [{threads_str}]", style="dim")
    row2.append("  MEM: ", style="dim")
    row2.append(f"{mem:.1f}%", style=mem_color)
    row2.append("  DISK ", style="dim")
    row2.append(f"R:{_fmt_bytes(dr)}/s", style="cyan")
    row2.append(f" W:{_fmt_bytes(dw)}/s", style="cyan")
    row2.append("  NET ", style="dim")
    row2.append(f"↑{_fmt_bytes(ns)}/s", style="green")
    row2.append(f" ↓{_fmt_bytes(nr)}/s", style="yellow")

    content = Text()
    content.append_text(row1)
    content.append("\n")
    content.append_text(row2)

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )

def build_footer(paused: bool) -> Panel:
    content = Text()
    content.append(" [P]", style="bold cyan")
    content.append(" pause/resume", style="dim")
    content.append("   [C]", style="bold cyan")
    content.append(" clear feed", style="dim")
    content.append("   [Q]", style="bold cyan")
    content.append(" quit", style="dim")
    content.append("   │   ", style="dim")
    content.append("observe-only mode", style="dim green")
    content.append("   │   ", style="dim")
    content.append("eBPF · bonfire v0.1.0", style="dim")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )

def build_events_panel(events: list, state: SharedState) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("TIME",   width=12, style="dim")
    table.add_column("TYPE",   width=8)
    table.add_column("PID",    width=7,  style="dim")
    table.add_column("PROC",   width=14)
    table.add_column("DETAIL", ratio=1)

    if not events:
        table.add_row(
            "", "", "", "",
            Text("Waiting for events...", style="dim italic")
        )
    else:
        for ev in events[:40]:
            ts       = ev.timestamp.strftime("%H:%M:%S")
            is_alert = state.is_alert_pid(ev.pid)

            if isinstance(ev, ExecveEvent):
                type_style = "bold red" if is_alert else "cyan"
                detail     = Text()
                detail.append(ev.filename,
                    style="bold red" if is_alert else "green")
                detail.append(f"  parent={ev.pcomm}", style="dim")
                detail.append(f"  argc={ev.argc}",    style="dim")
                ev_type = "EXECVE"
            else:
                type_style = "bold red" if is_alert else "yellow"
                detail     = Text()
                detail.append(f"{ev.daddr}",
                    style="bold red" if is_alert else "yellow")
                detail.append(f":{ev.dport}",
                    style="bold red" if is_alert else "bold yellow")
                ev_type = "CONNECT"

            row_style = "on grey15" if is_alert else ""

            table.add_row(
                ts,
                Text(ev_type, style=type_style),
                str(ev.pid),
                Text(ev.comm, style="bold white" if is_alert else "white"),
                detail,
                style=row_style,
            )

    paused = state.is_paused()
    title  = "[bold white]Syscall Feed[/bold white]"
    if paused:
        title += " [yellow](paused)[/yellow]"

    return Panel(
        table,
        title=title,
        border_style="dim blue",
        box=box.ROUNDED,
    )


def build_alerts_panel(alerts: list) -> Panel:
    content = Text()

    if not alerts:
        content.append("No alerts fired.\n", style="dim italic")
        content.append("\nSystem is clean.", style="dim green")
    else:
        for alert in alerts[:20]:
            ts        = alert.timestamp.strftime("%H:%M:%S")
            sev_colors = {
                "CRITICAL": "bold red",
                "HIGH":     "bold orange1",
                "MEDIUM":   "bold yellow",
                "LOW":      "dim white",
            }
            sev_style = sev_colors.get(alert.severity, "white")
            icon      = "🔴" if alert.rule_id.startswith("R1") else "⚠️ "

            content.append(f"{icon} ")
            content.append(f"[{alert.severity}]", style=sev_style)
            content.append(f" {alert.rule_id}\n",     style="bold white")
            content.append(f"   {alert.rule_name}\n", style="dim white")
            content.append(f"   pid={alert.event.pid} ", style="dim")
            content.append(f"proc={alert.event.comm}\n", style="dim")
            content.append(f"   {ts}\n",               style="dim cyan")
            content.append("─" * 28 + "\n",            style="dim")

    return Panel(
        content,
        title="[bold red]Alerts & Threats[/bold red]",
        subtitle=f"[dim]{len(alerts)} total[/dim]",
        border_style="red" if alerts else "dim red",
        box=box.ROUNDED,
    )


def build_metrics_panel(snap: dict) -> Panel:
    content = Text()

    def row(label: str, value: str, style: str = "white"):
        content.append(f"{label:<18}", style="dim")
        content.append(f"{value}\n", style=style)

    content.append("── Event Rates ──────────\n", style="dim")
    row("execve/min",   str(snap.get("execve_min",  0)), "cyan")
    row("connect/min",  str(snap.get("connect_min", 0)), "yellow")
    row("alerts/min",   str(snap.get("alerts_min",  0)),
        "red" if snap.get("alerts_min", 0) > 0 else "dim")

    content.append("\n── Peak Rates ───────────\n", style="dim")
    row("peak execve",  str(snap.get("peak_execve_min",  0)), "cyan")
    row("peak connect", str(snap.get("peak_connect_min", 0)), "yellow")
    row("peak alerts",  str(snap.get("peak_alerts_min",  0)),
        "red" if snap.get("peak_alerts_min", 0) > 0 else "dim")

    content.append("\n── Totals ───────────────\n", style="dim")
    row("total execve",  str(snap.get("total_execve",  0)), "cyan")
    row("total connect", str(snap.get("total_connect", 0)), "yellow")
    row("total alerts",  str(snap.get("total_alerts",  0)),
        "red" if snap.get("total_alerts", 0) > 0 else "dim")

    rule_counts = snap.get("rule_counts", {})
    if rule_counts:
        content.append("\n── Rule Hits ────────────\n", style="dim")
        for rule_id, count in sorted(rule_counts.items()):
            row(rule_id, str(count), "orange1")

    return Panel(
        content,
        title="[bold green]Metrics[/bold green]",
        subtitle="[dim]60s snapshot[/dim]",
        border_style="dim green",
        box=box.ROUNDED,
    )


# ── layout assembly ──────────────────────────────────────────────

def build_layout(state: SharedState) -> Layout:
    snap   = state.get_metrics()
    events = state.get_events()
    alerts = state.get_alerts()
    paused = state.is_paused()

    layout = Layout()

    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    layout["body"].split_row(
        Layout(name="left",   ratio=20),
        Layout(name="middle", ratio=55),
        Layout(name="right",  ratio=25),
    )

    layout["header"].update(build_header(snap))
    layout["left"].update(build_alerts_panel(alerts))
    layout["middle"].update(build_events_panel(events, state))
    layout["right"].update(build_metrics_panel(snap))
    layout["footer"].update(build_footer(paused))

    return layout


# ── keyboard listener ────────────────────────────────────────────

def keyboard_listener(state: SharedState, stop_event: threading.Event):
    import sys
    import termios
    import tty

    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)    # ← setcbreak instead of setraw
                             # reads char by char but doesn't
                             # interfere with terminal size reporting
        while not stop_event.is_set():
            ch = sys.stdin.read(1)
            if ch.lower() == 'q':
                stop_event.set()
            elif ch.lower() == 'p':
                state.toggle_pause()
            elif ch.lower() == 'c':
                state.clear_events()
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ── main CLI entry point ─────────────────────────────────────────

def run_dashboard():
    state      = SharedState()
    logger     = Logger()
    metrics    = Metrics()
    engine     = RuleEngine()
    correlator = Correlator()
    stop_event = threading.Event()

    logger.start()
    metrics.start()

    def metrics_loop():
        while not stop_event.is_set():
            state.update_metrics(metrics.snapshot())
            time.sleep(1)

    threading.Thread(target=metrics_loop, daemon=True).start()

    def on_event(event):
        state.add_event(event)

        if isinstance(event, ExecveEvent):
            metrics.record_execve()
        else:
            metrics.record_connect()

        for alert in engine.evaluate(event):
            metrics.record_alert(alert.rule_id)
            logger.ingest_alert(alert)
            state.add_alert(alert)

        for alert in correlator.process(event):
            metrics.record_alert(alert.rule_id)
            logger.ingest_alert(alert)
            state.add_alert(alert)

        logger.ingest(event)

    threading.Thread(
        target=build_monitor,
        args=(on_event,),
        daemon=True
    ).start()

    threading.Thread(
        target=keyboard_listener,
        args=(state, stop_event),
        daemon=True
    ).start()

    with Live(
        build_layout(state),
        console=console,
        refresh_per_second=REFRESH_HZ,
        screen=True,
    ) as live:
        try:
            while not stop_event.is_set():
                live.update(build_layout(state))
                time.sleep(1 / REFRESH_HZ)
        except KeyboardInterrupt:
            pass
        finally:
            logger.stop()
            metrics.stop()
            console.print("\n[orange1]🔥 Bonfire stopped.[/orange1]")


# ── helpers ──────────────────────────────────────────────────────

def _fmt_bytes(b: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}GB"


if __name__ == "__main__":
    run_dashboard()
