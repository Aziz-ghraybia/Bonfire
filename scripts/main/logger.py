import queue
import workers.hot  as hot_mod
import workers.cold as cold_mod
import workers.dedup as dedup_mod
import workers.warm as warm_mod


class Logger:

    def __init__(self):
        self._event_queue = queue.Queue()
        self._alert_queue = queue.Queue()

        self._hot   = hot_mod.HotWorker(self._event_queue)
        self._cold  = cold_mod.ColdWorker(self._alert_queue)
        self._dedup = dedup_mod.DedupWorker()
        self._warm  = warm_mod.WarmWorker()

    def start(self):
        self._hot.start()
        self._cold.start()
        self._dedup.start()
        self._warm.start()
        print("[logger] all workers started")

    def stop(self):
        self._hot.stop()
        self._cold.stop()
        self._dedup.stop()
        self._warm.stop()
        print("[logger] all workers stopped")

    def ingest(self, event):
        """Called by monitor.py for every event."""
        self._event_queue.put(event)
        self._dedup.notify()        # dedup tracks event count

    def ingest_alert(self, alert):
        """Called by monitor.py when a rule fires."""
        self._alert_queue.put(alert)
