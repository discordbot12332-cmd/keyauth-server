import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, client_key: str) -> bool:
        with self._lock:
            now = time.time()
            self._requests[client_key] = [
                t for t in self._requests[client_key] if now - t < self.window
            ]
            if len(self._requests[client_key]) >= self.max_requests:
                return False
            self._requests[client_key].append(now)
            return True

    def remaining(self, client_key: str) -> int:
        with self._lock:
            now = time.time()
            self._requests[client_key] = [
                t for t in self._requests[client_key] if now - t < self.window
            ]
            return max(0, self.max_requests - len(self._requests[client_key]))


rate_limiter = RateLimiter(max_requests=120)
