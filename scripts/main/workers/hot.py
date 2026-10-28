import json
import gzip
import os
import pathlib
import queue
import shutil
import threading
from datetime import datetime, timezone

HOT_DIR  = pathlib.Path(__file__).parent.parent.parent / "storage" / "hot"
WARM_DIR = pathlib.Path(__file__).parent.parent.parent / "storage" / "warm"


class HotWorker:

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self._stop       = threading.Event()

        HOT_DIR.mkdir(parents=True, exist_ok=True)
        WARM_DIR.mkdir(parents=True, exist_ok=True)

        # run startup checks before anything else
        self._startup_check()

    # ── public ──────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="hot-worker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ── startup logic ────────────────────────────────────────────

    def _startup_check(self):
        """
        On every startup:
        1. Check if any logs belong to a previous month → zip and move to warm
        2. Get or create today's log file
        3. Write the startup entry
        """
        self._archive_old_months()
        self._write_startup_entry()

    def _today_log_path(self) -> pathlib.Path:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return HOT_DIR / f"bonfire_{today}.log"

    def _archive_old_months(self):
        """
        Find any .log files in hot/ that belong to a previous month.
        Group them by month, zip each group, move to warm/, delete originals.
        """
        now          = datetime.now(timezone.utc)
        current_ym   = now.strftime("%Y-%m")
        log_files    = sorted(HOT_DIR.glob("bonfire_*.log"))

        # group files by year-month
        months: dict[str, list[pathlib.Path]] = {}
        for f in log_files:
            # filename: bonfire_2025-01-15.log → extract 2025-01
            parts = f.stem.split("_")   # ['bonfire', '2025-01-15']
            if len(parts) != 2:
                continue
            ym = parts[1][:7]           # '2025-01'
            if ym == current_ym:
                continue                # skip current month
            months.setdefault(ym, []).append(f)

        for ym, files in months.items():
            self._zip_month(ym, files)

    def _zip_month(self, ym: str, files: list[pathlib.Path]):
        """Zip all log files for a month into warm/bonfire_YYYY-MM.zip"""
        zip_path = WARM_DIR / f"bonfire_{ym}.zip"

        import zipfile
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.write(f, arcname=f.name)

        # delete originals after successful zip
        for f in files:
            f.unlink()

        print(f"[hot] archived {len(files)} log files → {zip_path.name}")

    def _write_startup_entry(self):
        """Write 'Bonfire lit' marker to today's log."""
        now = datetime.now(timezone.utc)
        ts  = now.strftime("%d/%m/%Y %H:%M:%S")

        entry = {
            "type":      "SYSTEM",
            "timestamp": now.isoformat(),
            "message":   f"Bonfire lit — {ts}",
        }

        log_path = self._today_log_path()
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"[hot] logging to {log_path.name}")

    # ── internal loop ────────────────────────────────────────────

    def _run(self):
        print("[hot] worker started")
        while not self._stop.is_set():
            try:
                event = self.event_queue.get(timeout=1)
                self._write(event)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[hot] error: {e}")

    def _write(self, event):
        # always write to today's log — path recalculated each time
        # handles midnight rollover automatically
        log_path = self._today_log_path()
        line     = json.dumps(self._serialize(event)) + "\n"

        with open(log_path, "a") as f:
            f.write(line)

    # ── serialization ────────────────────────────────────────────

    def _serialize(self, event) -> dict:
        from events import ExecveEvent, ConnectEvent

        base = {
            "timestamp": event.timestamp.isoformat(),
            "pid":       event.pid,
            "uid":       event.uid,
            "comm":      event.comm,
        }

        if isinstance(event, ExecveEvent):
            base.update({
                "type":     "EXECVE",
                "ppid":     event.ppid,
                "pcomm":    event.pcomm,
                "filename": event.filename,
                "argc":     event.argc,
            })
        elif isinstance(event, ConnectEvent):
            base.update({
                "type":  "CONNECT",
                "daddr": event.daddr,
                "dport": event.dport,
            })

        return base 
