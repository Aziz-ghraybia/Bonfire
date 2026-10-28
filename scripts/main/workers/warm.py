import pathlib
import threading
import time

WARM_DIR        = pathlib.Path(__file__).parent.parent.parent / "storage" / "warm"
WARM_RETENTION  = 30    # days to keep archives


class WarmWorker:

    def __init__(self):
        self._stop = threading.Event()
        WARM_DIR.mkdir(parents=True, exist_ok=True)

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name="warm-worker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        print("[warm] worker started")
        while not self._stop.is_set():
            self._purge_old_archives()
            # check once per day
            for _ in range(86400):
                if self._stop.is_set():
                    return
                time.sleep(1)

    def _purge_old_archives(self):
        """Delete zip archives older than WARM_RETENTION days."""
        cutoff = time.time() - (WARM_RETENTION * 86400)
        for f in WARM_DIR.glob("bonfire_*.zip"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                print(f"[warm] purged expired archive {f.name}") 
