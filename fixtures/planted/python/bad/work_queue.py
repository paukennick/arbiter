import queue
import threading


class Worker:
    def __init__(self):
        self._queue = queue.Queue()  # expect: arbiter/python.unbounded-queue
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            self._queue.get()
