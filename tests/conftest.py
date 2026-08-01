import httpx
import pytest

from chancery.app import create_app
from chancery.config import Settings
from chancery.db import init_schema, open_database
from chancery.service import PasteService


@pytest.fixture
def settings(tmp_path):
    return Settings(
        db_path=tmp_path / "test.db",
        db_key="ab" * 32,
        base_url="http://testserver",
        paste_max_size=1024,
        max_ttl_seconds=86400,
        paste_id_length=10,
        tcp_enabled=False,
        kdf_opslimit=1,
        kdf_memlimit=1 << 20,
    )


@pytest.fixture
def service(settings):
    conn = open_database(settings.db_path, settings.require_key())
    init_schema(conn)
    svc = PasteService(
        conn,
        base_url=settings.base_url,
        paste_max_size=settings.paste_max_size,
        max_ttl_seconds=settings.max_ttl_seconds,
        paste_id_length=settings.paste_id_length,
        kdf_opslimit=settings.kdf_opslimit,
        kdf_memlimit=settings.kdf_memlimit,
    )
    yield svc
    svc.close()


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as c,
    ):
        yield c
