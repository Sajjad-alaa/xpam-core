"""XPAM: a cap on the WebSockets one user keeps open in this process. Each of these sockets holds a Redis
subscription and a listening thread for as long as it is open, so a signed-in user opening sockets without end
could exhaust the server; a browser needs one per open tab."""
import threading
from collections import Counter

__all__ = ['UserSocketLimit']


class UserSocketLimit:
    def __init__(self, limit):
        self.limit = limit
        self._lock = threading.Lock()
        self._open = Counter()

    def acquire(self, user_id):
        key = str(user_id)
        with self._lock:
            if self._open[key] >= self.limit:
                return False
            self._open[key] += 1
            return True

    def release(self, user_id):
        key = str(user_id)
        with self._lock:
            if self._open[key] <= 1:
                self._open.pop(key, None)
            else:
                self._open[key] -= 1
