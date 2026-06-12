from __future__ import annotations

import asyncio
import time
from collections import deque


class TokenBucket:
    """Token bucket rate limiter for per-source EPS control."""

    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = rate
        self.capacity = capacity or max(rate, 1.0)
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def set_rate(self, rate: float) -> None:
        self.rate = rate
        self.capacity = max(rate, 1.0)

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)

    @property
    def current_tokens(self) -> float:
        return self._tokens


class SlidingWindowCounter:
    """Counts events in per-second buckets over a fixed window, for actual-EPS stats."""

    def __init__(self, window_seconds: int = 60):
        self._window = window_seconds
        self._buckets: deque[tuple[int, int]] = deque()
        self._started: float | None = None

    def increment(self) -> None:
        now = time.monotonic()
        if self._started is None:
            self._started = now
        sec = int(now)
        if self._buckets and self._buckets[-1][0] == sec:
            self._buckets[-1] = (sec, self._buckets[-1][1] + 1)
        else:
            self._buckets.append((sec, 1))
            self._trim(sec)

    def rate(self) -> float:
        now = time.monotonic()
        self._trim(int(now))
        if self._started is None:
            return 0.0
        # Recently-started counters divide by actual elapsed time, not the
        # full window, so they don't underreport.
        elapsed = max(min(self._window, now - self._started), 1.0)
        return sum(count for _, count in self._buckets) / elapsed

    def _trim(self, now_sec: int) -> None:
        cutoff = now_sec - self._window
        while self._buckets and self._buckets[0][0] <= cutoff:
            self._buckets.popleft()
