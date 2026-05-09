import gzip
import pathlib
import shutil
import threading
import time
from datetime import datetime

HOT_DIR          = pathlib.Path(__file__).parent.parent.parent / "storage" / "hot"
WARM_DIR         = pathlib.Path(__file__).parent.parent.parent / "storage" / "warm"
ARCHIVE_INTERVAL = 60 * 60 * 24    # run once every 24 hours
WARM_RETENTION   = 30              # keep warm files for 30 days


class WarmWorker:

    def __init__(self):
        self._stop = threading.Event()
        WARM_DIR.mkdir(parents=True, exist_ok=True)

    # ── public ──────────────────────────────────────────────────

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="warm-worker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ── internal loop ───────────────────────────────────────────

    def _run(self):
        print("[warm] worker started")
        while not self._stop.is_set():
            self._archive_rotated_files()
            self._purge_old_archives()

            # sleep in small increments so stop() is responsive
            for _ in range(ARCHIVE_INTERVAL):
                if self._stop.is_set():
                    break
                time.sleep(1)

    # ── archiving ───────────────────────────────────────────────

    def _archive_rotated_files(self):
        """Compress any rotated hot files (bonfire.log.1, .2, .3)."""
        for i in range(1, 4):
            src = HOT_DIR / f"bonfire.log.{i}"
            if not src.exists():
                continue

            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            dest      = WARM_DIR / f"bonfire-{timestamp}-{i}.log.gz"

            self._compress(src, dest)
            src.unlink()    # remove original after compressing
            print(f"[warm] archived {src.name} → {dest.name}")

    def _compress(self, src: pathlib.Path, dest: pathlib.Path):
        with open(src, "rb") as f_in:
            with gzip.open(dest, "wb", compresslevel=6) as f_out:
                shutil.copyfileobj(f_in, f_out)

    # ── retention ───────────────────────────────────────────────

    def _purge_old_archives(self):
        """Delete warm files older than WARM_RETENTION days."""
        now     = time.time()
        cutoff  = now - (WARM_RETENTION * 86400)

        for f in WARM_DIR.glob("*.log.gz"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                print(f"[warm] purged expired archive {f.name}")
