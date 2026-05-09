import json
import pathlib
import queue
import sqlite3
import threading
from datetime import datetime

COLD_DIR = pathlib.Path(__file__).parent.parent.parent / "storage" / "cold"
DB_PATH  = COLD_DIR / "alerts.db"


class ColdWorker:

    def __init__(self, alert_queue: queue.Queue):
        self.alert_queue = alert_queue
        self._stop       = threading.Event()

        COLD_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── public ──────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="cold-worker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ── db setup ────────────────────────────────────────────────

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    rule_id     TEXT    NOT NULL,
                    rule_name   TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    message     TEXT    NOT NULL,
                    event_type  TEXT    NOT NULL,
                    pid         INTEGER,
                    uid         INTEGER,
                    comm        TEXT,
                    detail      TEXT    -- JSON snapshot of relevant fields
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON alerts(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rule_id
                ON alerts(rule_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity
                ON alerts(severity)
            """)
            conn.commit()
        print(f"[cold] database ready at {DB_PATH}")

    # ── internal loop ───────────────────────────────────────────

    def _run(self):
        print("[cold] worker started")
        while not self._stop.is_set():
            try:
                alert = self.alert_queue.get(timeout=1)
                self._write(alert)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[cold] error: {e}")

    def _write(self, alert):
        event  = alert.event
        detail = self._snapshot(event)

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO alerts
                    (timestamp, rule_id, rule_name, severity,
                     message, event_type, pid, uid, comm, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp.isoformat(),
                alert.rule_id,
                alert.rule_name,
                alert.severity,
                alert.message,
                type(event).__name__,
                event.pid,
                event.uid,
                event.comm,
                json.dumps(detail),
            ))
            conn.commit()

    def _snapshot(self, event) -> dict:
        """Minimal event context stored alongside the alert."""
        from events import ExecveEvent, ConnectEvent

        if isinstance(event, ExecveEvent):
            return {
                "filename": event.filename,
                "ppid":     event.ppid,
                "pcomm":    event.pcomm,
                "argc":     event.argc,
            }
        if isinstance(event, ConnectEvent):
            return {
                "daddr": event.daddr,
                "dport": event.dport,
            }
        return {}
