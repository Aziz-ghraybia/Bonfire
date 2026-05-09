import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
from events import ExecveEvent, ConnectEvent
from rules  import Alert


# ── Sequence definitions ─────────────────────────────────────────
# These mirror R100, R101, R102 from your yaml
# but sequences need state so they live in code not yaml

SEQUENCES = [
    {
        "id":       "R100",
        "name":     "Reverse Shell Detected",
        "severity": "CRITICAL",
        "within":   5,       # seconds
        "steps": [
            {
                "event_type": "execve",
                "conditions": {
                    "filename_in": ["/bin/bash", "/bin/sh", "/bin/dash"]
                }
            },
            {
                "event_type": "connect",
                "conditions": {
                    "dport_not_in": [80, 443, 53, 22]
                }
            },
        ]
    },
    {
        "id":       "R101",
        "name":     "Webshell Activity",
        "severity": "CRITICAL",
        "within":   3,
        "steps": [
            {
                "event_type": "execve",
                "conditions": {
                    "parent_comm_in": ["nginx", "apache2", "httpd", "php-fpm"],
                    "filename_in":    ["/bin/bash", "/bin/sh", "/bin/dash"]
                }
            },
            {
                "event_type": "connect",
                "conditions": {}   # any outbound connection after webshell exec
            },
        ]
    },
    {
        "id":       "R102",
        "name":     "Suspicious Execution Followed by Network",
        "severity": "CRITICAL",
        "within":   10,
        "steps": [
            {
                "event_type": "execve",
                "conditions": {
                    "path_contains": ["/tmp", "/dev/shm", "/var/tmp"]
                }
            },
            {
                "event_type": "connect",
                "conditions": {}   # any outbound after tmp execution
            },
        ]
    },
]


# ── Pending sequence tracker ─────────────────────────────────────

class PendingSequence:
    """Tracks a partially matched sequence for a specific PID."""

    def __init__(self, sequence: dict, first_event):
        self.sequence    = sequence
        self.step        = 1               # we already matched step 0
        self.first_event = first_event
        self.started_at  = datetime.utcnow()
        self.root_pid    = first_event.pid
        self.seen_pids   = {first_event.pid} 
    def is_expired(self) -> bool:
        window = timedelta(seconds=self.sequence["within"])
        return datetime.utcnow() - self.started_at > window

    def is_complete(self) -> bool:
        return self.step >= len(self.sequence["steps"])


# ── Correlator ───────────────────────────────────────────────────

class Correlator:

    def __init__(self):
        # pid → list of PendingSequence
        self._pending = defaultdict(list)
        self._lock    = threading.Lock()

        # start expiry cleanup thread
        self._stop    = threading.Event()
        self._thread  = threading.Thread(
            target=self._expiry_loop,
            name="correlator-expiry",
            daemon=True
        )
        self._thread.start()
        print("[correlator] started")

    def stop(self):
        self._stop.set()

    # ── public ──────────────────────────────────────────────────

    def process(self, event) -> list[Alert]:
        """
        Feed an event into the correlator.
        Returns a list of alerts if any sequences were completed.
        """
        alerts = []

        with self._lock:
            # 1. check if this event advances any pending sequences for this pid
            alerts += self._advance_pending(event)

            # 2. check if this event starts any new sequences
            self._start_new(event)

        return alerts

    # ── sequence matching ────────────────────────────────────────

    def _start_new(self, event):
        """Check if event matches step 0 of any sequence."""
        for seq in SEQUENCES:
            step0 = seq["steps"][0]
            if self._matches_step(step0, event):
                print(f"[correlator] sequence {seq['id']} started — pid={event.pid}")
                pending = PendingSequence(seq, event)
                self._pending[event.pid].append(pending)

    def _advance_pending(self, event) -> list[Alert]:
        """Try to advance any pending sequences for this pid."""
        alerts   = []
        survived = []   # sequences that didn't complete or expire
        all_pending = []

        for pid_list in self._pending.values():
            all_pending.extend(pid_list)

        for pending in all_pending:
            if pending.is_expired():
                continue    # drop expired sequences silently
            pid_match = (
                event.pid in pending.seen_pids or
                (hasattr(event, 'ppid') and event.ppid in pending.seen_pids)
            )
            if not pid_match:
                survived.append(pending)
                continue

            current_step = pending.sequence["steps"][pending.step]

            if self._matches_step(current_step, event):
                pending.seen_pids.add(event.pid)
                pending.step += 1
                print(f"[correlator] {pending.sequence['id']} advanced to step {pending.step} — pid={event.pid}")

                if pending.is_complete():
                    # sequence fully matched — fire alert
                    alert = self._build_alert(pending, event)
                    alerts.append(alert)
                    # don't add to survived — sequence is done
                else:
                    survived.append(pending)
            else:
                survived.append(pending)

        from collections import defaultdict  # ADDED (only if not already imported)
        new_pending = defaultdict(list)
        for p in survived:
            new_pending[p.root_pid].append(p)

        self._pending = new_pending  # ADDED

        return alerts

    def _matches_step(self, step: dict, event) -> bool:
        """Check if an event satisfies a sequence step."""
        event_type  = step.get("event_type")
        conditions  = step.get("conditions", {})

        # check event type
        if event_type == "execve" and not isinstance(event, ExecveEvent):
            return False
        if event_type == "connect" and not isinstance(event, ConnectEvent):
            return False

        # check conditions — same logic as RuleEngine
        for condition, value in conditions.items():

            if condition == "filename_in":
                if not any(v in event.filename for v in value):
                    return False

            elif condition == "path_contains":
                if not any(v in event.filename for v in value):
                    return False

            elif condition == "parent_comm_in":
                if not hasattr(event, "pcomm"):
                    return False
                if not any(event.pcomm == v for v in value):
                    return False

            elif condition == "dport_not_in":
                if not hasattr(event, "dport"):
                    return False
                if event.dport in value:
                    return False

            elif condition == "dport_in":
                if not hasattr(event, "dport"):
                    return False
                if event.dport not in value:
                    return False

            elif condition == "comm_in":
                if not any(event.comm == v for v in value):
                    return False

        return True

    # ── alert builder ────────────────────────────────────────────

    def _build_alert(self, pending: PendingSequence, final_event) -> Alert:
        seq     = pending.sequence
        elapsed = (datetime.utcnow() - pending.started_at).total_seconds()

        return Alert(
            rule_id   = seq["id"],
            rule_name = seq["name"],
            severity  = seq["severity"],
            message   = (
                f"sequence completed in {elapsed:.1f}s — "
                f"pid={final_event.pid} proc={final_event.comm} "
                f"started_with={pending.first_event.comm}"
            ),
            event     = final_event,
        )

    # ── expiry cleanup ───────────────────────────────────────────

    def _expiry_loop(self):
        """Periodically remove expired pending sequences to free memory."""
        while not self._stop.is_set():
            time.sleep(5)
            with self._lock:
                for pid in list(self._pending.keys()):
                    self._pending[pid] = [
                        p for p in self._pending[pid]
                        if not p.is_expired()
                    ]
                    if not self._pending[pid]:
                        del self._pending[pid]
