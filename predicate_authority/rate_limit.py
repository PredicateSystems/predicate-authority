from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock


@dataclass(frozen=True)
class TokenBucketDecision:
    allowed: bool
    retry_after_s: float


@dataclass
class _TokenBucketState:
    tokens: float
    last_refill_s: float


@dataclass(frozen=True)
class PrincipalRateLimiterConfig:
    enabled: bool = True
    requests_per_second: float = 100.0
    burst_size: int = 100


@dataclass
class PrincipalRateLimiter:
    config: PrincipalRateLimiterConfig
    clock: Callable[[], float] = time.monotonic
    _lock: Lock = field(default_factory=Lock, init=False)
    _buckets: dict[str, _TokenBucketState] = field(default_factory=dict, init=False)

    def allow(self, principal_id: str) -> TokenBucketDecision:
        if not self.config.enabled:
            return TokenBucketDecision(allowed=True, retry_after_s=0.0)

        now = self.clock()
        with self._lock:
            state = self._buckets.get(principal_id)
            if state is None:
                state = _TokenBucketState(
                    tokens=float(max(1, self.config.burst_size) - 1),
                    last_refill_s=now,
                )
                self._buckets[principal_id] = state
                return TokenBucketDecision(allowed=True, retry_after_s=0.0)

            self._refill(state, now)
            if state.tokens >= 1.0:
                state.tokens -= 1.0
                return TokenBucketDecision(allowed=True, retry_after_s=0.0)

            retry_after = self._retry_after_s(state.tokens)
            return TokenBucketDecision(allowed=False, retry_after_s=retry_after)

    def _refill(self, state: _TokenBucketState, now: float) -> None:
        refill_rate = max(0.0, self.config.requests_per_second)
        if refill_rate <= 0.0:
            state.last_refill_s = now
            return
        elapsed = max(0.0, now - state.last_refill_s)
        if elapsed <= 0.0:
            return
        state.tokens = min(
            float(max(1, self.config.burst_size)),
            state.tokens + (elapsed * refill_rate),
        )
        state.last_refill_s = now

    def _retry_after_s(self, current_tokens: float) -> float:
        refill_rate = max(0.0, self.config.requests_per_second)
        if refill_rate <= 0.0:
            return 1.0
        missing_tokens = max(0.0, 1.0 - current_tokens)
        return missing_tokens / refill_rate
