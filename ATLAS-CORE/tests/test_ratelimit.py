import asyncio, os, pathlib, subprocess, sys, time, uuid
import httpx
import pytest
from fastapi.testclient import TestClient
from app.core import ratelimit
from app.core.config import get_settings
from app.main import app
from tests.conftest import REDIS_URL, DB_URL, ROOT


def flush():
    import redis
    redis.Redis.from_url(REDIS_URL).flushdb()


# ---------------- memory backend + middleware behaviour
def test_general_limit_per_principal(client):
    get_settings().rate_limit_per_minute = 3
    a, b = {"Authorization": "Bearer aaa"}, {"Authorization": "Bearer bbb"}
    assert [client.get("/api/v1/health", headers=a).status_code for _ in range(4)] == [200, 200, 200, 429]
    r = client.get("/api/v1/health", headers=a)
    assert r.json()["error"]["code"] == "rate_limited" and int(r.headers["Retry-After"]) >= 1 and r.headers["X-RateLimit-Limit"] == "3"
    assert client.get("/api/v1/health", headers=b).status_code == 200            # another principal is unaffected


def test_login_bruteforce_bucket_is_per_ip_and_separate(client, users):
    get_settings().auth_rate_limit_per_minute = 3
    codes = [client.post("/api/v1/auth/login", json={"username": f"u{i}", "password": "x" * 14}).status_code for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]                                    # rotating usernames does not evade it
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": "x"}).status_code == 429
    assert client.get("/api/v1/health").status_code == 200                       # general traffic unaffected


def test_proxy_headers_ignored_unless_trusted(client):
    get_settings().auth_rate_limit_per_minute = 2
    spoof = lambda i: {"X-Forwarded-For": f"10.9.9.{i}"}  # noqa: E731
    codes = [client.post("/api/v1/auth/login", headers=spoof(i), json={"username": "x", "password": "y" * 14}).status_code for i in range(4)]
    assert codes[-1] == 429                                                      # spoofed XFF does not reset the bucket
    get_settings().trust_proxy_headers = True
    assert client.post("/api/v1/auth/login", headers=spoof(99), json={"username": "x", "password": "y" * 14}).status_code == 401


# ---------------- Redis backend
@pytest.mark.redis
def test_redis_limiter_is_shared_between_instances_and_atomic():
    flush()
    key, A, B = f"t:{uuid.uuid4().hex}", ratelimit.RedisLimiter(REDIS_URL), ratelimit.RedisLimiter(REDIS_URL)

    async def go():
        r = [await A.hit(key, 3, 60), await B.hit(key, 3, 60), await A.hit(key, 3, 60), await B.hit(key, 3, 60)]
        assert [x[0] for x in r] == [True, True, True, False] and r[3][2] >= 1
        # atomicity under concurrency across two clients: exactly `limit` winners
        k2 = f"t:{uuid.uuid4().hex}"
        res = await asyncio.gather(*[(A if i % 2 else B).hit(k2, 20, 60) for i in range(100)])
        assert sum(1 for x in res if x[0]) == 20
        await A.client.aclose(); await B.client.aclose()
    asyncio.run(go())


@pytest.mark.redis
def test_redis_sliding_window_expires():
    flush()
    L, key = ratelimit.RedisLimiter(REDIS_URL), f"t:{uuid.uuid4().hex}"

    async def go():
        assert (await L.hit(key, 2, 1))[0] and (await L.hit(key, 2, 1))[0] and not (await L.hit(key, 2, 1))[0]
        await asyncio.sleep(1.2)
        assert (await L.hit(key, 2, 1))[0]
        await L.client.aclose()
    asyncio.run(go())


@pytest.mark.redis
def test_middleware_uses_redis_backend():
    flush()
    s = get_settings(); s.rate_limit_backend, s.rate_limit_per_minute = "redis", 3
    with TestClient(app) as c:
        h = {"Authorization": f"Bearer {uuid.uuid4().hex}"}
        assert [c.get("/api/v1/health", headers=h).status_code for _ in range(4)] == [200, 200, 200, 429]
    import redis
    keys = redis.Redis.from_url(REDIS_URL).keys("atlas:test:rl:*")
    assert keys and all(b"Bearer" not in k and h["Authorization"].encode() not in k for k in keys)   # tokens are hashed in keys


def test_fail_modes_when_redis_unreachable():
    s = get_settings()
    s.rate_limit_backend, s.redis_url, s.rate_limit_per_minute = "redis", "redis://127.0.0.1:1/0", 2
    h = {"Authorization": "Bearer failmode"}
    with TestClient(app) as c:
        s.rate_limit_fail_mode = "memory"                                         # degrade to per-process limiting
        assert [c.get("/api/v1/health", headers=h).status_code for _ in range(3)] == [200, 200, 429]
        ratelimit._memory.hits.clear()
        s.rate_limit_fail_mode = "closed"
        r = c.get("/api/v1/health", headers=h)
        assert r.status_code == 503 and r.json()["error"]["code"] == "rate_limiter_unavailable"
        s.rate_limit_fail_mode = "open"
        assert all(c.get("/api/v1/health", headers=h).status_code == 200 for _ in range(5))


# ---------------- REAL multi-process: two separate backend servers sharing only Redis
def _serve(port, backend, limit):
    env = {**os.environ, "ATLAS_RATE_LIMIT_BACKEND": backend, "ATLAS_RATE_LIMIT_PER_MINUTE": str(limit),
           "ATLAS_REDIS_URL": REDIS_URL, "ATLAS_DATABASE_URL": DB_URL}
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
                         cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(60):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/api/v1/health", timeout=1).status_code == 200:
                return p
        except Exception:
            time.sleep(0.25)
    p.kill()
    raise RuntimeError("server did not start: " + p.stderr.read().decode()[:500])


def _stop(procs):
    for p in procs:
        p.terminate(); p.wait(5); p.stderr.close()


def _alternate(ports, n, token):
    codes = []
    for i in range(n):
        codes.append(httpx.get(f"http://127.0.0.1:{ports[i % 2]}/api/v1/health", headers={"Authorization": f"Bearer {token}"}).status_code)
    return codes


@pytest.mark.redis
def test_limit_is_enforced_across_two_backend_processes():
    flush()
    procs = [_serve(8781, "redis", 20), _serve(8782, "redis", 20)]
    try:
        codes = _alternate((8781, 8782), 30, "shared-principal")
        assert codes.count(200) == 20 and codes.count(429) == 10, codes          # ONE shared budget of 20 over both processes
        assert codes[:20] == [200] * 20
    finally:
        _stop(procs)


@pytest.mark.redis
def test_control_in_memory_limits_are_per_process_only():
    """Control experiment: proves the Redis result above is due to shared state, not coincidence."""
    procs = [_serve(8783, "memory", 20), _serve(8784, "memory", 20)]
    try:
        codes = _alternate((8783, 8784), 30, "control-principal")
        assert codes.count(200) == 30                                             # each process only saw 15 requests
    finally:
        _stop(procs)
