import threading
import time
import psutil
from collections import deque
from datetime import datetime


class Metrics:

    def __init__(self):
        self._lock      = threading.Lock()
        self._stop      = threading.Event()
        self._start_time = datetime.utcnow()

        # ── event counters ───────────────────────────────────────
        self.total_execve   = 0
        self.total_connect  = 0
        self.total_alerts   = 0
        self.rule_counts    = {}   # {rule_id: count}

        # ── rolling windows (timestamps of events) ───────────────
        # we store the timestamp of each event in a deque
        # to calculate per-minute rates we count entries
        # within the last 60 seconds
        self._execve_times  = deque()
        self._connect_times = deque()
        self._alert_times   = deque()

        # ── peak rates ───────────────────────────────────────────
        self.peak_execve_min  = 0
        self.peak_connect_min = 0
        self.peak_alerts_min  = 0

        # ── hardware snapshot (updated by fast sampler) ──────────
        self.cpu_percent        = 0.0
        self.cpu_per_thread     = []
        self.mem_used           = 0
        self.mem_total          = 0
        self.mem_percent        = 0.0
        self.disk_read_bps      = 0
        self.disk_write_bps     = 0
        self.net_sent_bps       = 0
        self.net_recv_bps       = 0

        # ── previous I/O counters for delta calculation ──────────
        io                      = psutil.disk_io_counters()
        net                     = psutil.net_io_counters()
        self._prev_disk_read    = io.read_bytes  if io  else 0
        self._prev_disk_write   = io.write_bytes if io  else 0
        self._prev_net_sent     = net.bytes_sent if net else 0
        self._prev_net_recv     = net.bytes_recv if net else 0
        self._prev_io_time      = time.time()

    # ── public recording API ─────────────────────────────────────
    # these are called by monitor.py on every event

    def record_execve(self):
        with self._lock:
            self.total_execve += 1
            self._execve_times.append(time.time())

    def record_connect(self):
        with self._lock:
            self.total_connect += 1
            self._connect_times.append(time.time())

    def record_alert(self, rule_id: str):
        with self._lock:
            self.total_alerts += 1
            self._alert_times.append(time.time())
            self.rule_counts[rule_id] = self.rule_counts.get(rule_id, 0) + 1

    # ── public snapshot API ──────────────────────────────────────
    # CLI reads this — always returns a clean dict, never blocks

    def snapshot(self) -> dict:
        with self._lock:
            now = time.time()
            execve_min  = self._rate_per_min(self._execve_times,  now)
            connect_min = self._rate_per_min(self._connect_times, now)
            alerts_min  = self._rate_per_min(self._alert_times,   now)

            return {
                # uptime
                "uptime": self._uptime(),

                # event rates
                "execve_min":        execve_min,
                "connect_min":       connect_min,
                "alerts_min":        alerts_min,

                # peak rates
                "peak_execve_min":   self.peak_execve_min,
                "peak_connect_min":  self.peak_connect_min,
                "peak_alerts_min":   self.peak_alerts_min,

                # totals
                "total_execve":      self.total_execve,
                "total_connect":     self.total_connect,
                "total_alerts":      self.total_alerts,

                # per rule
                "rule_counts":       dict(self.rule_counts),

                # hardware
                "cpu_percent":       self.cpu_percent,
                "cpu_per_thread":    list(self.cpu_per_thread),
                "mem_used":          self.mem_used,
                "mem_total":         self.mem_total,
                "mem_percent":       self.mem_percent,
                "disk_read_bps":     self.disk_read_bps,
                "disk_write_bps":    self.disk_write_bps,
                "net_sent_bps":      self.net_sent_bps,
                "net_recv_bps":      self.net_recv_bps,
            }

    # ── start / stop ─────────────────────────────────────────────

    def start(self):
        # fast sampler — every 1s, updates hardware + peaks
        self._fast_thread = threading.Thread(
            target=self._fast_sampler,
            name="metrics-fast",
            daemon=True
        )

        # slow sampler — every 60s, logs snapshot to disk
        self._slow_thread = threading.Thread(
            target=self._slow_sampler,
            name="metrics-slow",
            daemon=True
        )

        self._fast_thread.start()
        self._slow_thread.start()
        print("[metrics] started")

    def stop(self):
        self._stop.set()

    # ── fast sampler (every 1s) ──────────────────────────────────

    def _fast_sampler(self):
        while not self._stop.is_set():
            self._sample_hardware()
            self._update_peaks()
            self._expire_old_events()
            time.sleep(1)

    def _sample_hardware(self):
        # CPU
        cpu_total   = psutil.cpu_percent(interval=None)
        cpu_threads = psutil.cpu_percent(interval=None, percpu=True)

        # Memory
        mem = psutil.virtual_memory()

        # Disk I/O delta
        io      = psutil.disk_io_counters()
        net     = psutil.net_io_counters()
        now     = time.time()
        elapsed = max(now - self._prev_io_time, 0.001)  # avoid div by zero

        disk_read_bps  = (io.read_bytes  - self._prev_disk_read)  / elapsed if io  else 0
        disk_write_bps = (io.write_bytes - self._prev_disk_write) / elapsed if io  else 0
        net_sent_bps   = (net.bytes_sent - self._prev_net_sent)   / elapsed if net else 0
        net_recv_bps   = (net.bytes_recv - self._prev_net_recv)   / elapsed if net else 0

        # update previous counters
        if io:
            self._prev_disk_read  = io.read_bytes
            self._prev_disk_write = io.write_bytes
        if net:
            self._prev_net_sent = net.bytes_sent
            self._prev_net_recv = net.bytes_recv
        self._prev_io_time = now

        with self._lock:
            self.cpu_percent    = cpu_total
            self.cpu_per_thread = cpu_threads
            self.mem_used       = mem.used
            self.mem_total      = mem.total
            self.mem_percent    = mem.percent
            self.disk_read_bps  = disk_read_bps
            self.disk_write_bps = disk_write_bps
            self.net_sent_bps   = net_sent_bps
            self.net_recv_bps   = net_recv_bps

    def _update_peaks(self):
        now = time.time()
        with self._lock:
            em = self._rate_per_min(self._execve_times,  now)
            cm = self._rate_per_min(self._connect_times, now)
            am = self._rate_per_min(self._alert_times,   now)

            if em > self.peak_execve_min:
                self.peak_execve_min = em
            if cm > self.peak_connect_min:
                self.peak_connect_min = cm
            if am > self.peak_alerts_min:
                self.peak_alerts_min = am

    def _expire_old_events(self):
        """Remove timestamps older than 60s from rolling windows."""
        cutoff = time.time() - 60
        with self._lock:
            for dq in (self._execve_times, self._connect_times, self._alert_times):
                while dq and dq[0] < cutoff:
                    dq.popleft()

    # ── slow sampler (every 60s) ─────────────────────────────────

    def _slow_sampler(self):
        while not self._stop.is_set():
            for _ in range(60):
                if self._stop.is_set():
                    return
                time.sleep(1)
            self._log_snapshot()

    def _log_snapshot(self):
        import json
        import pathlib

        snap     = self.snapshot()
        log_path = pathlib.Path(__file__).parent.parent.parent / \
                   "scripts" / "storage" / "hot" / "metrics.log"

        snap["logged_at"] = datetime.utcnow().isoformat()
        with open(log_path, "a") as f:
            f.write(json.dumps(snap) + "\n")

    # ── helpers ──────────────────────────────────────────────────

    def _rate_per_min(self, dq: deque, now: float) -> int:
        """Count events in the last 60 seconds."""
        cutoff = now - 60
        return sum(1 for t in dq if t >= cutoff)

    def _uptime(self) -> str:
        delta   = datetime.utcnow() - self._start_time
        hours   = int(delta.total_seconds() // 3600)
        minutes = int((delta.total_seconds() % 3600) // 60)
        seconds = int(delta.total_seconds() % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _fmt_bytes(self, b: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"
