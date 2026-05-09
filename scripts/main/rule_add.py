import os
import sys
import time
import threading

from rich.console import Console
from rich.layout import Layout
from rich.live import Live

from rule_builder import RuleFormState
from rule_form import (
    build_form_header,
    build_form_footer,
    build_form_basic,
    build_form_conditions,
    build_form_confirm,
    keyboard_listener,
)

console = Console()


def build_layout(form: RuleFormState) -> Layout:
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="form"),
        Layout(name="footer", size=3),
    )

    layout["header"].update(build_form_header())
    layout["footer"].update(build_form_footer(form))

    if form.step == "basic":
        layout["form"].update(build_form_basic(form))
    elif form.step == "conditions":
        layout["form"].update(build_form_conditions(form))
    elif form.step == "confirm":
        layout["form"].update(build_form_confirm(form))

    return layout


def run_rule_add():
    # root check
    if os.geteuid() != 0:
        print("⚠  bonfire rules --add requires root privileges.")
        print("   Run with: sudo bonfire rules --add")
        sys.exit(1)

    form       = RuleFormState()
    stop_event = threading.Event()

    threading.Thread(
        target=keyboard_listener,
        args=(form, stop_event),
        daemon=True
    ).start()

    with Live(
        build_layout(form),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        try:
            while not stop_event.is_set():
                live.update(build_layout(form))
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass

    console.print("\n[orange1]🔥 Bonfire rule builder closed.[/orange1]")


if __name__ == "__main__":
    run_rule_add()
