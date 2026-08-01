import httpx
import pytest

from chancery.app import create_app
from chancery.config import Settings


def _make_app(tmp_path, *, expected_host=None, forwarded_allow_ips=""):
    settings = Settings(
        db_path=tmp_path / "proxy.db",
        db_key="ab" * 32,
        base_url="http://chancery.example.com",
        paste_max_size=1024,
        max_ttl_seconds=86400,
        tcp_enabled=False,
        expected_host=expected_host,
        forwarded_allow_ips=forwarded_allow_ips,
    )
    return create_app(settings)


async def _probe(app, base_url="http://chancery.example.com", headers=None):
    from fastapi import Request

    @app.get("/api/probe")
    def probe(request: Request):
        return {
            "client": request.client.host if request.client else None,
            "scheme": request.url.scheme,
            "host": request.headers.get("host"),
        }

    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url=base_url) as client,
    ):
        return await client.get("/api/probe", headers=headers or {})


@pytest.mark.anyio
async def test_unexpected_host_rejected(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com")
    r = await _probe(app, base_url="http://evil.example.com")
    assert r.status_code == 400


@pytest.mark.anyio
async def test_expected_host_allowed(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com")
    r = await _probe(app)
    assert r.status_code == 200
    assert r.json()["client"] == "127.0.0.1"


@pytest.mark.anyio
async def test_forwarded_headers_honored_when_trusted(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com", forwarded_allow_ips="127.0.0.1")
    r = await _probe(
        app,
        headers={"x-forwarded-for": "203.0.113.9", "x-forwarded-proto": "https"},
    )
    body = r.json()
    assert body["client"] == "203.0.113.9"
    assert body["scheme"] == "https"


@pytest.mark.anyio
async def test_forwarded_headers_ignored_when_untrusted(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com")
    r = await _probe(
        app,
        headers={"x-forwarded-for": "203.0.113.9", "x-forwarded-proto": "https"},
    )
    body = r.json()
    assert body["client"] == "127.0.0.1"
    assert body["scheme"] == "http"


@pytest.mark.anyio
async def test_forwarded_host_used_when_trusted(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com", forwarded_allow_ips="127.0.0.1")
    r = await _probe(
        app,
        headers={"x-forwarded-host": "chancery.example.com", "x-forwarded-proto": "https"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["host"] == "chancery.example.com"
    assert body["scheme"] == "https"


@pytest.mark.anyio
async def test_forwarded_host_mismatch_rejected(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com", forwarded_allow_ips="127.0.0.1")
    r = await _probe(app, headers={"x-forwarded-host": "evil.example.com"})
    assert r.status_code == 400


@pytest.mark.anyio
async def test_expected_host_comma_separated(tmp_path):
    app = _make_app(tmp_path, expected_host="chancery.example.com, paste.example.com")
    assert (await _probe(app, base_url="http://paste.example.com")).status_code == 200
    assert (await _probe(app, base_url="http://evil.example.com")).status_code == 400
