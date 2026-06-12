from __future__ import annotations

import asyncio
import time


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
