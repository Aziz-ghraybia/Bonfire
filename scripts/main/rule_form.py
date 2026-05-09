import sys
import tty
import termios
import threading
import time

from rich.text import Text
from rich.panel import Panel
from rich import box

from rule_builder import RuleFormState, save_rule


# ── Panel builders ───────────────────────────────────────────────

def build_form_header() -> Panel:
    from datetime import datetime, timezone
    now     = datetime.now(timezone.utc)
    content = Text()
    content.append("🔥 BONFIRE", style="bold orange1")
    content.append("  │  ", style="dim")
    content.append("Rule Builder", style="bold white")
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


def build_form_footer(form: RuleFormState) -> Panel:
    content = Text()

    if form.step == "basic":
        content.append(" [TAB]",   style="bold cyan")
        content.append(" next field  ", style="dim")
        content.append("[←→]",    style="bold cyan")
        content.append(" cycle options  ", style="dim")
        content.append("[ENTER]",  style="bold cyan")
        content.append(" next step  ", style="dim")
        content.append("[ESC]",    style="bold cyan")
        content.append(" cancel", style="dim")

    elif form.step == "conditions":
        content.append(" [TAB]",   style="bold cyan")
        content.append(" next field  ", style="dim")
        content.append("[ENTER]",  style="bold cyan")
        content.append(" next step  ", style="dim")
        content.append("[ESC]",    style="bold cyan")
        content.append(" back", style="dim")

    elif form.step == "confirm":
        content.append(" [ENTER]", style="bold cyan")
        content.append(" save rule  ", style="dim")
        content.append("[ESC]",    style="bold cyan")
        content.append(" back", style="dim")

    return Panel(
        content,
        style="on grey7",
        box=box.HORIZONTALS,
        padding=(0, 1),
    )


def build_form_basic(form: RuleFormState) -> Panel:
    content = Text()

    # id field
    content.append("\n")
    is_focus = (form.field_idx == 0)
    style    = "bold cyan" if is_focus else "dim"
    cursor   = "█" if is_focus else " "
    content.append(f"  {'ID':<18}", style="dim")
    content.append(f"[{form.id}{cursor}]", style=style)
    content.append("  e.g. R013\n", style="dim")

    # name field
    is_focus = (form.field_idx == 1)
    style    = "bold cyan" if is_focus else "dim"
    cursor   = "█" if is_focus else " "
    content.append(f"  {'Name':<18}", style="dim")
    content.append(f"[{form.name}{cursor}]", style=style)
    content.append("  e.g. Suspicious curl execution\n", style="dim")

    content.append("\n")

    # severity
    content.append(f"  {'Severity':<18}", style="dim")
    for i, sev in enumerate(RuleFormState.SEVERITIES):
        is_active = (i == form.sev_idx)
        is_focus  = (form.field_idx == 2)
        if is_active:
            style = "bold white on red" if sev == "CRITICAL" else \
                    "bold white on dark_orange" if sev == "HIGH" else \
                    "bold white on yellow" if sev == "MEDIUM" else \
                    "bold white on grey50"
        elif is_focus:
            style = "bold cyan on grey23"
        else:
            style = "dim"
        content.append(f" {sev} ", style=style)
        content.append(" ")
    content.append("\n\n")

    # event type
    content.append(f"  {'Event Type':<18}", style="dim")
    for i, et in enumerate(RuleFormState.EVENT_TYPES):
        is_active = (i == form.event_idx)
        is_focus  = (form.field_idx == 3)
        if is_active:
            style = "bold white on blue"
        elif is_focus:
            style = "bold cyan on grey23"
        else:
            style = "dim"
        content.append(f" {et.upper()} ", style=style)
        content.append(" ")
    content.append("\n")

    if form.error:
        content.append(f"\n  ⚠  {form.error}\n", style="bold red")

    return Panel(
        content,
        title="[bold white]Step 1 — Basic Info[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def build_form_conditions(form: RuleFormState) -> Panel:
    content = Text()
    content.append("\n")
    content.append(f"  Event type: ", style="dim")
    content.append(f"{form.event_type.upper()}\n\n", style="bold cyan")

    for i, (cond_name, cond_type, hint) in enumerate(form.conditions):
        is_focus = (form.field_idx == i)
        style    = "bold cyan" if is_focus else "dim"
        cursor   = "█" if is_focus else " "
        value    = form.cond_values.get(cond_name, "")
        type_tag = "[int] " if cond_type == "int" else "[list]"

        content.append(
            f"  {cond_name:<20}",
            style="bold white" if is_focus else "white"
        )
        content.append(f"{type_tag}  ", style="dim")
        content.append(f"[{value}{cursor}]", style=style)
        content.append(f"  {hint}\n", style="dim")

    content.append("\n")
    content.append(
        "  Leave empty to skip. Lists are comma separated: "
        "/bin/bash, /bin/sh\n",
        style="dim italic"
    )

    return Panel(
        content,
        title="[bold white]Step 2 — Conditions[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def build_form_confirm(form: RuleFormState) -> Panel:
    content = Text()
    content.append("\n  Preview:\n\n", style="dim")

    for line in form.format_preview():
        if line.startswith("    "):
            content.append(f"  {line}\n", style="white")
        elif ":" in line:
            key, _, val = line.partition(":")
            content.append(f"  {key}:", style="dim")
            content.append(f"{val}\n",  style="bold white")
        else:
            content.append(f"  {line}\n", style="dim")

    if form.error:
        content.append(f"\n  ⚠  {form.error}\n", style="bold red")

    if form.saved:
        content.append("\n  ✓  Rule saved successfully!\n", style="bold green")

    return Panel(
        content,
        title="[bold white]Step 3 — Confirm & Save[/bold white]",
        border_style="green" if form.saved else "cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


# ── Keyboard handling ────────────────────────────────────────────

def handle_form_key(ch: str, form: RuleFormState, stop_event: threading.Event):
    if form.step in ("basic", "conditions"):

        if ch == '\x1b':
            if form.step == "basic":
                stop_event.set()
            else:
                form.prev_step()
            return

        if ch == '\t':
            form.next_field()
            return

        if ch in ('\r', '\n'):
            form.next_step()
            return

        if form.step == "basic":
            if form.field_idx == 0:
                if ch in ('\x7f', '\x08'):
                    form.id = form.id[:-1]
                elif ch.isprintable():
                    form.id += ch

            elif form.field_idx == 1:
                if ch in ('\x7f', '\x08'):
                    form.name = form.name[:-1]
                elif ch.isprintable():
                    form.name += ch

            elif form.field_idx == 2:
                if ch == '\x1b[C':
                    form.sev_idx = (form.sev_idx + 1) % len(RuleFormState.SEVERITIES)
                elif ch == '\x1b[D':
                    form.sev_idx = (form.sev_idx - 1) % len(RuleFormState.SEVERITIES)

            elif form.field_idx == 3:
                if ch in ('\x1b[C', '\x1b[D'):
                    form.event_idx = (form.event_idx + 1) % len(RuleFormState.EVENT_TYPES)

        elif form.step == "conditions":
            cond_name = form.conditions[form.field_idx][0]
            current   = form.cond_values.get(cond_name, "")
            if ch in ('\x7f', '\x08'):
                form.cond_values[cond_name] = current[:-1]
            elif ch.isprintable():
                form.cond_values[cond_name] = current + ch

    elif form.step == "confirm":
        if ch == '\x1b':
            form.prev_step()

        elif ch in ('\r', '\n'):
            if form.saved:
                stop_event.set()
                return
            rule    = form.build_rule()
            success = save_rule(rule)
            if success:
                form.saved = True
                form.error = ""
            else:
                form.error = "Failed to save — check file permissions"


def keyboard_listener(form: RuleFormState, stop_event: threading.Event):
    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop_event.is_set():
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
            handle_form_key(ch, form, stop_event)
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
