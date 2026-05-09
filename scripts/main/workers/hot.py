import json
import os
import pathlib
import queue
import threading
from datetime import datetime
from events import ExecveEvent, ConnectEvent

HOT_DIR      = pathlib.Path(__file__).parent.parent.parent / "storage" / "hot"
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50MB per file before rotation
MAX_ROTATIONS = 3                   # keep last 3 rotated files


class HotWorker:

    def __init__(self, event_queue: queue.Queue):
        self.event_queue  = event_queue
        self.log_path     = HOT_DIR / "bonfire.log"
        self._stop        = threading.Event()

        # create storage dir if it doesn't exist
        HOT_DIR.mkdir(parents=True, exist_ok=True)

    # ── public ──────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="hot-worker",
            daemon=True             # dies automatically when main exits
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ── internal loop ───────────────────────────────────────────

    def _run(self):
        print("[hot] worker started")
        while not self._stop.is_set():
            try:
                # block for up to 1s waiting for an event
                # timeout lets us check _stop regularly
                event = self.event_queue.get(timeout=1)
                self._write(event)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[hot] error: {e}")

    def _write(self, event):
        # check if we need to rotate before writing
        if self._should_rotate():
            self._rotate()

        line = json.dumps(self._serialize(event)) + "\n"

        with open(self.log_path, "a") as f:
            f.write(line)

    # ── rotation ────────────────────────────────────────────────

    def _should_rotate(self) -> bool:
        if not self.log_path.exists():
            return False
        return self.log_path.stat().st_size >= MAX_FILE_SIZE

    def _rotate(self):
        # shift existing rotations: .2 → .3, .1 → .2, base → .1
        for i in range(MAX_ROTATIONS - 1, 0, -1):
            src  = HOT_DIR / f"bonfire.log.{i}"
            dest = HOT_DIR / f"bonfire.log.{i + 1}"
            if src.exists():
                src.rename(dest)

        # move active log to .1
        if self.log_path.exists():
            self.log_path.rename(HOT_DIR / "bonfire.log.1")

        print(f"[hot] rotated log at {datetime.utcnow().isoformat()}")

    # ── serialization ───────────────────────────────────────────

    def _serialize(self, event) -> dict:
        base = {
            "timestamp": event.timestamp.isoformat(),
            "pid":       event.pid,
            "uid":       event.uid,
            "comm":      event.comm,
        }

        if isinstance(event, ExecveEvent):
            base.update({
                "type":     "execve",
                "ppid":     event.ppid,
                "pcomm":    event.pcomm,
                "filename": event.filename,
                "argc":     event.argc,
            })

        elif isinstance(event, ConnectEvent):
            base.update({
                "type":  "connect",
                "daddr": event.daddr,
                "dport": event.dport,
            })

        return base
