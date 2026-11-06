"""Attempt limiters shared across processes. ``pip install "generateapikey[redis]"``.

:class:`~generateapikey.mfa.AttemptLimiter` lives in one process. With several
workers or servers, use Redis so every process sees the same counters::

    import redis
    from generateapikey.limiters import RedisAttemptLimiter

    limiter = RedisAttemptLimiter(redis.Redis(), max_attempts=5, window=900)
    if not limiter.hit(user_id):
        return "Too many attempts"
    if verify_totp(secret, code):
        limiter.reset(user_id)

``AsyncRedisAttemptLimiter`` takes a ``redis.asyncio.Redis`` and has the same
methods as coroutines. Both plug into ``APIKeyAuth(limiter=...)``.

Every operation is a single atomic Lua script, so counts are exact under
concurrency. Counters expire on their own (fixed window from the first attempt).
"""

from __future__ import annotations

import hashlib
from typing import Any

__all__ = ["AsyncRedisAttemptLimiter", "RedisAttemptLimiter"]

# KEYS[1] = counter key, ARGV[1] = window ms, ARGV[2] = max attempts, ARGV[3] = mode
#   mode "hit":  if count >= max -> return -1 (blocked, not incremented); else INCR
#   mode "fail": INCR unconditionally
# Returns the new count (or -1).
_SCRIPT = """
local c = tonumber(redis.call('GET', KEYS[1]) or '0')
if ARGV[3] == 'hit' and c >= tonumber(ARGV[2]) then
  return -1
end
c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
"""


class _Base:
    def __init__(self, client: Any, max_attempts: int = 5, window: float = 900, prefix: str = "gak:attempts:"):
        if max_attempts < 1 or window <= 0:
            raise ValueError("max_attempts and window must be positive.")
        self.client = client
        self.max_attempts = max_attempts
        self.window = window
        self.prefix = prefix
        self._script = client.register_script(_SCRIPT)

    def _key(self, key: str) -> str:
        # Hash so arbitrary user input (emails, IPs) can't create odd Redis keys.
        return self.prefix + hashlib.sha256(str(key).encode("utf-8", "surrogatepass")).hexdigest()

    def _args(self, mode: str) -> list[Any]:
        return [int(self.window * 1000), self.max_attempts, mode]


class RedisAttemptLimiter(_Base):
    """Redis-backed limiter with the same interface as ``AttemptLimiter``."""

    def hit(self, key: str) -> bool:
        """Atomically record an attempt. False if the key is over the limit."""
        return int(self._script(keys=[self._key(key)], args=self._args("hit"))) != -1

    def fail(self, key: str) -> int:
        """Record a failed attempt. Returns attempts left."""
        count = int(self._script(keys=[self._key(key)], args=self._args("fail")))
        return max(0, self.max_attempts - count)

    def is_blocked(self, key: str) -> bool:
        return self._count(key) >= self.max_attempts

    def remaining(self, key: str) -> int:
        return max(0, self.max_attempts - self._count(key))

    def reset(self, key: str) -> None:
        self.client.delete(self._key(key))

    def _count(self, key: str) -> int:
        return int(self.client.get(self._key(key)) or 0)


class AsyncRedisAttemptLimiter(_Base):
    """``redis.asyncio`` version; every method is a coroutine."""

    async def hit(self, key: str) -> bool:
        return int(await self._script(keys=[self._key(key)], args=self._args("hit"))) != -1

    async def fail(self, key: str) -> int:
        count = int(await self._script(keys=[self._key(key)], args=self._args("fail")))
        return max(0, self.max_attempts - count)

    async def is_blocked(self, key: str) -> bool:
        return await self._count(key) >= self.max_attempts

    async def remaining(self, key: str) -> int:
        return max(0, self.max_attempts - await self._count(key))

    async def reset(self, key: str) -> None:
        await self.client.delete(self._key(key))

    async def _count(self, key: str) -> int:
        return int(await self.client.get(self._key(key)) or 0)
