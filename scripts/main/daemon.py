#!/usr/bin/env python3
"""
Bonfire Daemon
Runs Bonfire silently in the background.
Managed via: bonfire start / bonfire stop / bonfire status
"""

import os
import sys
import json
import time
import signal
import pathlib
import threading
from datetime import datetime, timezone

# ── Paths ─────────────────────────────────────────────────────────
SCRIPT_DIR  = pathlib.Path(__file__).parent
PID_FILE    = pathlib.Path("/tmp/bonfire.pid")
STATE_FILE  = pathlib.Path("/tmp/bonfire.state")


# ── State writer ──────────────────────────────────────────────────

class DaemonState:
    """Tracks runtime stats and writes them to STATE_FILE periodically."""

    def __init__(self):
        self._lock       = threading.Lock()
        self._start_time = datetime.now(timezone.utc)
        self._events     = 0
        self._alerts     = 0
        self._stop       = threading.Event()

    def record_event(self):
        with self._lock:
            self._events += 1

    def record_alert(self):
        with self._lock:
            self._alerts += 1

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="daemon-state",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        STATE_FILE.unlink(missing_ok=True)

    def _run(self):
        while not self._stop.is_set():
            self._write()
            time.sleep(5)

    def _write(self):
        with self._lock:
            uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
            state  = {
                "pid":        os.getpid(),
                "started_at": self._start_time.isoformat(),
                "uptime_sec": int(uptime),
                "events":     self._events,
                "alerts":     self._alerts,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        try:
            STATE_FILE.write_text(json.dumps(state))
        except Exception:
            pass


# ── Daemon process ────────────────────────────────────────────────

def _run_daemon():
    """
    Main daemon loop — runs inside the forked background process.
    Starts all Bonfire workers and monitor silently.
    """
    sys.path.insert(0, str(SCRIPT_DIR))

    from monitor  import build_monitor
    from logger   import Logger
    from metrics  import Metrics
    from rules    import RuleEngine
    from correlator import Correlator
    from events   import ExecveEvent, ConnectEvent

    state      = DaemonState()
    logger     = Logger()
    metrics    = Metrics()
    engine     = RuleEngine()
    correlator = Correlator()

    logger.start()
    metrics.start()
    state.start()

    def on_event(event):
        state.record_event()

        if isinstance(event, ExecveEvent):
            metrics.record_execve()
        else:
            metrics.record_connect()

        for alert in engine.evaluate(event):
            metrics.record_alert(alert.rule_id)
            logger.ingest_alert(alert)
            state.record_alert()

        for alert in correlator.process(event):
            metrics.record_alert(alert.rule_id)
            logger.ingest_alert(alert)
            state.record_alert()

        logger.ingest(event)

    # handle shutdown signals cleanly
    def shutdown(signum, frame):
        logger.stop()
        metrics.stop()
        state.stop()
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT,  shutdown)

    # blocking monitor loop
    build_monitor(on_event)


def _fork_daemon():
    """
    Double-fork to properly daemonize the process.
    Detaches completely from the terminal.
    """
    # first fork
    pid = os.fork()
    if pid > 0:
        # parent — wait briefly then return
        time.sleep(0.5)
        return pid

    # first child — create new session
    os.setsid()

    # second fork — detach from session leader
    pid = os.fork()
    if pid > 0:
        os._exit(0)

    # grandchild — this is the actual daemon
    # redirect stdin/stdout/stderr to /dev/null
    devnull = os.open("/dev/null", os.O_RDWR)
    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(devnull, sys.stdout.fileno())
    os.dup2(devnull, sys.stderr.fileno())

    # write PID file
    PID_FILE.write_text(str(os.getpid()))

    # run the actual daemon
    _run_daemon()
    sys.exit(0)


# ── Commands ──────────────────────────────────────────────────────

def cmd_start():
    # check if already running
    if PID_FILE.exists():
        pid = PID_FILE.read_text().strip()
        # verify process is actually alive
        try:
            os.kill(int(pid), 0)
            print(f"🔥 Bonfire is already running  (pid: {pid})")
            sys.exit(0)
        except ProcessLookupError:
            # stale PID file — process is gone
            PID_FILE.unlink(missing_ok=True)

    print("🔥 Starting Bonfire in background...")

    pid = _fork_daemon()
    if pid:
        # we are the original parent — wait for PID file
        for _ in range(20):
            if PID_FILE.exists():
                daemon_pid = PID_FILE.read_text().strip()
                print(f"🔥 Bonfire started  (pid: {daemon_pid})")
                print(f"   Monitoring: execve + connect")
                print(f"   Storage:    {SCRIPT_DIR.parent / 'storage' / 'hot'}")
                print(f"   Alerts DB:  {SCRIPT_DIR.parent / 'storage' / 'cold' / 'alerts.db'}")
                print(f"\n   Run 'bonfire status' to check  ·  'bonfire stop' to stop")
                sys.exit(0)
            time.sleep(0.2)

        print("⚠  Bonfire started but PID file not written yet.")
        print("   Run 'bonfire status' in a moment to confirm.")
        sys.exit(0)


def cmd_stop():
    if not PID_FILE.exists():
        print("🔥 Bonfire is not running.")
        sys.exit(0)

    pid_str = PID_FILE.read_text().strip()

    try:
        pid = int(pid_str)
        os.kill(pid, 0)   # check if alive
    except (ValueError, ProcessLookupError):
        print("🔥 Bonfire is not running  (stale PID file removed)")
        PID_FILE.unlink(missing_ok=True)
        STATE_FILE.unlink(missing_ok=True)
        sys.exit(0)

    print(f"🔥 Stopping Bonfire  (pid: {pid})...")

    # send SIGTERM — daemon handles cleanup
    os.kill(pid, signal.SIGTERM)

    # wait for process to exit
    for _ in range(30):
        try:
            os.kill(pid, 0)
            time.sleep(0.3)
        except ProcessLookupError:
            break

    # verify it stopped
    try:
        os.kill(pid, 0)
        print("⚠  Bonfire did not stop cleanly — sending SIGKILL")
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    PID_FILE.unlink(missing_ok=True)
    STATE_FILE.unlink(missing_ok=True)
    print("🔥 Bonfire stopped.")


def cmd_status():
    if not PID_FILE.exists():
        print("🔥 Bonfire is not running.")
        sys.exit(0)

    pid_str = PID_FILE.read_text().strip()

    try:
        pid = int(pid_str)
        os.kill(pid, 0)
    except (ValueError, ProcessLookupError):
        print("🔥 Bonfire is not running  (stale PID file)")
        PID_FILE.unlink(missing_ok=True)
        STATE_FILE.unlink(missing_ok=True)
        sys.exit(0)

    print(f"🔥 Bonfire is running\n")

    # read state file if available
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())

            uptime_sec = state.get("uptime_sec", 0)
            hours      = uptime_sec // 3600
            minutes    = (uptime_sec % 3600) // 60
            seconds    = uptime_sec % 60

            started    = state.get("started_at", "")[:19].replace("T", " ")

            print(f"   PID        : {pid}")
            print(f"   Started    : {started} UTC")
            print(f"   Uptime     : {hours:02d}:{minutes:02d}:{seconds:02d}")
            print(f"   Events     : {state.get('events', 0)}")
            print(f"   Alerts     : {state.get('alerts', 0)}")

            # storage usage
            hot_dir  = SCRIPT_DIR.parent / "storage" / "hot"
            warm_dir = SCRIPT_DIR.parent / "storage" / "warm"
            cold_db  = SCRIPT_DIR.parent / "storage" / "cold" / "alerts.db"

            hot_size  = _dir_size_mb(hot_dir)
            warm_size = _dir_size_mb(warm_dir)
            cold_size = round(cold_db.stat().st_size / (1024*1024), 2) \
                        if cold_db.exists() else 0.0

            print(f"\n   Storage")
            print(f"   ├ hot      : {hot_size} MB")
            print(f"   ├ warm     : {warm_size} MB")
            print(f"   └ cold     : {cold_size} MB")
            print(f"\n   Mode       : observe-only  (eBPF passive)")
            print(f"   Hooks      : execve  ·  connect")

        except Exception:
            print(f"   PID    : {pid}")
            print(f"   Status : running (state file not yet available)")
    else:
        print(f"   PID    : {pid}")
        print(f"   Status : starting up...")

    print(f"\n   Run 'bonfire stop' to stop  ·  'bonfire dashboard' for live view")


# ── Helpers ───────────────────────────────────────────────────────

def _dir_size_mb(path: pathlib.Path) -> float:
    if not path.exists():
        return 0.0
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return round(total / (1024 * 1024), 2)


# ── Entry point ───────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("⚠  Bonfire requires root privileges.")
        print("   Run with: sudo bonfire start")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: bonfire start | stop | status")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "start":
        cmd_start()
    elif cmd == "stop":
        cmd_stop()
    elif cmd == "status":
        cmd_status()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: bonfire start | stop | status")
        sys.exit(1)


if __name__ == "__main__":
    main()
