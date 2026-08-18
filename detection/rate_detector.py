"""Bounded in-memory behavioural detection for a single-process lab deployment."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic


@dataclass(frozen=True)
class RateCheck:
    exceeded: bool
    first_exceedance: bool
    count: int


class RateDetector:
    """Tracks request and login-failure timestamps per IP address in memory."""

    def __init__(self) -> None:
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    @staticmethod
    def _trim(items: deque[float], window: int, now: float) -> None:
        while items and now - items[0] > window:
            items.popleft()

    def check_request(self, ip_address: str, limit: int, window: int = 60) -> RateCheck:
        now = monotonic()
        with self._lock:
            items = self._requests[ip_address]
            self._trim(items, window, now)
            items.append(now)
            count = len(items)
            return RateCheck(count > limit, count == limit + 1, count)

    def record_login_failure(self, ip_address: str, threshold: int, window: int) -> RateCheck:
        now = monotonic()
        with self._lock:
            items = self._failures[ip_address]
            self._trim(items, window, now)
            items.append(now)
            count = len(items)
            return RateCheck(count >= threshold, count == threshold, count)

    def clear_login_failures(self, ip_address: str) -> None:
        with self._lock:
            self._failures.pop(ip_address, None)

    def clear_ip(self, ip_address: str) -> None:
        """Remove local state for an IP (useful after a successful test/login)."""
        with self._lock:
            self._requests.pop(ip_address, None)
            self._failures.pop(ip_address, None)
