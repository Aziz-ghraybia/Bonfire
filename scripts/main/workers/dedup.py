import json
import os
import pathlib
import threading
import time
from collections import defaultdict

HOT_DIR         = pathlib.Path(__file__).parent.parent.parent / "storage" / "hot"
DEDUP_THRESHOLD = 1000    # run dedup after this many events in hot log
DEDUP_WINDOW    = 2.0     # seconds — events within this window are candidates


class DedupWorker:

    def __init__(self):
        self._stop          = threading.Event()
        self._event_count   = 0
        self._count_lock    = threading.Lock()

    # ── public ──────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="dedup-worker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def notify(self):
        """Called by hot worker every time an event is written."""
        with self._count_lock:
            self._event_count += 1

    # ── internal loop ───────────────────────────────────────────

    def _run(self):
        print("[dedup] worker started")
        while not self._stop.is_set():
            # sleep and periodically check threshold
            time.sleep(5)

            with self._count_lock:
                count = self._event_count

            if count >= DEDUP_THRESHOLD:
                print(f"[dedup] threshold reached ({count} events), running dedup")
                self._run_dedup()
                with self._count_lock:
                    self._event_count = 0

    def _run_dedup(self):
        log_path = HOT_DIR / "bonfire.log"
        if not log_path.exists():
            return

        lines = log_path.read_text().splitlines()
        if not lines:
            return

        # group events by (type, comm, key_field) within time windows
        # key_field = filename for execve, daddr:dport for connect
        buckets  = defaultdict(list)

        for line in lines:
            try:
                ev = json.loads(line)
                key = self._make_key(ev)
                buckets[key].append(ev)
            except json.JSONDecodeError:
                continue

        # write back deduplicated lines
        output = []
        for key, events in buckets.items():
            if len(events) == 1:
                output.append(events[0])
            else:
                # collapse into one entry with count
                merged = events[0].copy()
                merged["count"]      = len(events)
                merged["first_seen"] = events[0]["timestamp"]
                merged["last_seen"]  = events[-1]["timestamp"]
                merged.pop("timestamp", None)
                output.append(merged)

        # sort by first_seen
        output.sort(key=lambda e: e.get("first_seen") or e.get("timestamp", ""))

        with open(log_path, "w") as f:
            for entry in output:
                f.write(json.dumps(entry) + "\n")

        saved = len(lines) - len(output)
        print(f"[dedup] reduced {len(lines)} → {len(output)} entries (saved {saved})")

    def _make_key(self, ev: dict) -> str:
        if ev.get("type") == "execve":
            return f"execve:{ev.get('comm')}:{ev.get('filename')}"
        if ev.get("type") == "connect":
            return f"connect:{ev.get('comm')}:{ev.get('daddr')}:{ev.get('dport')}"
        return str(ev)
