import queue
import threading


class Worker:
    def __init__(self):
        self._queue = queue.Queue(maxsize=1000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def submit(self, item):
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            return False
        return True

    def _run(self):
        while not self._stop.is_set():
            self._queue.get()
