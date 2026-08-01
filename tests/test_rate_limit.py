import httpx
import pytest

from chancery.app import create_app
from chancery.config import Settings


def _settings(tmp_path, **overrides) -> Settings:
    base = {
        "db_path": tmp_path / "test.db",
        "db_key": "ab" * 32,
        "base_url": "http://testserver",
        "paste_max_size": 1024,
        "max_ttl_seconds": 86400,
        "paste_id_length": 10,
        "tcp_enabled": False,
        "kdf_opslimit": 1,
        "kdf_memlimit": 1 << 20,
        "rate_limit_enabled": False,
    }
    base.update(overrides)
    return Settings(**base)


async def _client(settings: Settings, ip: str = "127.0.0.1"):
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app, client=(ip, 123))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as c,
    ):
        yield c


@pytest.fixture
async def limited_client(tmp_path):
    settings = _settings(tmp_path, rate_limit_enabled=True, rate_limit="3/minute")
    async for c in _client(settings):
        yield c


async def test_rate_limit_429_after_budget_exhausted(limited_client):
    for _ in range(3):
        assert (await limited_client.get("/health")).status_code == 200
    r = await limited_client.get("/health")
    assert r.status_code == 429
    assert "rate limit exceeded" in r.text.lower()
    assert r.headers["x-ratelimit-limit"] == "3"
    assert r.headers["x-ratelimit-remaining"] == "0"


async def test_rate_limit_headers_reported(limited_client):
    await limited_client.get("/health")
    r = await limited_client.get("/health")
    assert r.headers["x-ratelimit-limit"] == "3"
    assert r.headers["x-ratelimit-remaining"] == "1"
    assert r.headers["x-ratelimit-reset"]


async def test_rate_limit_disabled(tmp_path):
    settings = _settings(tmp_path)
    async for c in _client(settings):
        for _ in range(10):
            assert (await c.get("/health")).status_code == 200


async def test_rate_limit_keys_by_remote_address(tmp_path):
    settings = _settings(tmp_path, rate_limit_enabled=True, rate_limit="3/minute")
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        c1 = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("203.0.113.1", 123)),
            base_url="http://testserver",
        )
        c2 = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("203.0.113.2", 123)),
            base_url="http://testserver",
        )
        async with c1, c2:
            for _ in range(3):
                assert (await c1.get("/health")).status_code == 200
            assert (await c1.get("/health")).status_code == 429
            for _ in range(3):
                assert (await c2.get("/health")).status_code == 200
            assert (await c2.get("/health")).status_code == 429


async def test_rate_limit_honors_forwarded_client_ip(tmp_path):
    settings = _settings(
        tmp_path,
        rate_limit_enabled=True,
        rate_limit="3/minute",
        forwarded_allow_ips="127.0.0.1",
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as c,
    ):
        for _ in range(3):
            assert (
                await c.get("/health", headers={"X-Forwarded-For": "203.0.113.9"})
            ).status_code == 200
        assert (
            await c.get("/health", headers={"X-Forwarded-For": "203.0.113.9"})
        ).status_code == 429
        assert (
            await c.get("/health", headers={"X-Forwarded-For": "203.0.113.8"})
        ).status_code == 200
