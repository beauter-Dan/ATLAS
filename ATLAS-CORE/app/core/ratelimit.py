"""Distributed sliding-window rate limiting.

Redis backend: one atomic Lua script (uses Redis TIME so all workers share one clock) over a sorted set per key.
If Redis is unreachable behavior follows ATLAS_RATE_LIMIT_FAIL_MODE: memory (per-process fallback, default),
closed (reject with 503) or open (allow). Fallback events are logged."""
import hashlib, logging, time, uuid
from collections import defaultdict, deque
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import get_settings
from app.core.deps import client_ip
from app.core.errors import error_body

log = logging.getLogger("atlas.ratelimit")

LUA = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local win, limit = tonumber(ARGV[1]), tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - win)
local n = redis.call('ZCARD', KEYS[1])
if n >= limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return {0, n, math.max(1, math.ceil((tonumber(oldest[2]) + win - now) / 1000))}
end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], win)
return {1, n + 1, 0}
"""


class MemoryLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)

    async def hit(self, key: str, limit: int, window: int = 60):
        t, q = time.monotonic(), self.hits[key]
        while q and t - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False, len(q), max(1, int(window - (t - q[0])))
        q.append(t)
        return True, len(q), 0


class RedisLimiter:
    def __init__(self, url: str):
        import redis.asyncio as aioredis
        self.client = aioredis.from_url(url, socket_timeout=1.0, socket_connect_timeout=1.0)
        self.script = self.client.register_script(LUA)

    async def hit(self, key: str, limit: int, window: int = 60):
        ok, n, retry = await self.script(keys=[key], args=[window * 1000, limit, uuid.uuid4().hex])
        return bool(ok), int(n), int(retry)


_memory = MemoryLimiter()
_redis: dict[str, RedisLimiter] = {}


async def hit(key: str, limit: int, window: int = 60):
    s = get_settings()
    if s.rate_limit_backend == "memory":
        return await _memory.hit(key, limit, window)
    try:
        lim = _redis.get(s.redis_url) or _redis.setdefault(s.redis_url, RedisLimiter(s.redis_url))
        return await lim.hit(f"atlas:{s.env}:rl:{key}", limit, window)
    except Exception as e:  # Redis down / misconfigured
        log.warning("rate limiter backend unavailable (%s); fail mode=%s", type(e).__name__, s.rate_limit_fail_mode)
        if s.rate_limit_fail_mode == "closed":
            return None, 0, 5
        if s.rate_limit_fail_mode == "open":
            return True, 0, 0
        return await _memory.hit(key, limit, window)


async def close() -> None:
    """Release pooled Redis connections (called on application shutdown)."""
    for lim in list(_redis.values()):
        try:
            await lim.client.aclose()
        except Exception:
            pass
    _redis.clear()


AUTH_PATHS = ("/auth/login", "/auth/refresh", "/auth/password-reset")


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        s = get_settings()
        ip = client_ip(request) or "unknown"
        auth = request.headers.get("authorization")
        principal = hashlib.sha256(auth.encode()).hexdigest()[:32] if auth else f"ip:{ip}"
        checks = [(f"g:{principal}", s.rate_limit_per_minute)]
        if request.method == "POST" and any(request.url.path.endswith(p) or f"{p}/" in request.url.path for p in AUTH_PATHS):
            checks.append((f"auth:{ip}", s.auth_rate_limit_per_minute))  # brute-force bucket, per client IP
        for key, limit in checks:
            ok, _, retry = await hit(key, limit)
            if ok is None:
                return JSONResponse(error_body("rate_limiter_unavailable", "Rate limiter unavailable"), status_code=503, headers={"Retry-After": str(retry)})
            if not ok:
                return JSONResponse(error_body("rate_limited", "Too many requests", {"retry_after_seconds": retry}), status_code=429,
                                    headers={"Retry-After": str(retry), "X-RateLimit-Limit": str(limit)})
        return await call_next(request)
