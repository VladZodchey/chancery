import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Settings
from .db import init_schema, open_database
from .logging import setup_logging
from .service import PasteService
from .tcp import run_tcp_server
from .web import api, errors, pages
from .web.middleware import ProxySecurityMiddleware

app_logger = logging.getLogger("chancery.app")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory.

    The database is opened and the TCP listener started in the lifespan, so
    constructing the app is cheap and side-effect free (safe to import).
    """
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Respect --log-level from `chancery serve`; only fall back to
        # CHANCERY_LOG_LEVEL when nothing configured the logger (e.g. running
        # `uvicorn chancery.app:app` directly).
        if not logging.getLogger("chancery").handlers:
            setup_logging(settings.log_level)
        key = settings.require_key()
        conn = open_database(settings.db_path, key)
        init_schema(conn)
        service = PasteService(
            conn,
            base_url=settings.base_url,
            paste_max_size=settings.paste_max_size,
            max_ttl_seconds=settings.max_ttl_seconds,
            paste_id_length=settings.paste_id_length,
            kdf_opslimit=settings.kdf_opslimit,
            kdf_memlimit=settings.kdf_memlimit,
        )
        app.state.settings = settings
        app.state.service = service

        tcp_task = None
        if settings.tcp_enabled:
            tcp_task = asyncio.create_task(run_tcp_server(settings, service))

        app_logger.info(
            "startup db_path=%s tcp_enabled=%s expected_host=%s",
            settings.db_path,
            settings.tcp_enabled,
            settings.expected_host,
        )

        try:
            yield
        finally:
            app_logger.info("shutdown")
            if tcp_task is not None:
                tcp_task.cancel()
            service.close()

    app = FastAPI(title="Chancery", version=__version__, lifespan=lifespan)

    if settings.expected_host or settings.forwarded_allow_ips:
        app.add_middleware(
            ProxySecurityMiddleware,
            expected_host=settings.expected_host,
            forwarded_allow_ips=settings.forwarded_allow_ips,
        )

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(pages.router)
    app.include_router(api.router)
    errors.register_exception_handlers(app)

    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    return app


app = create_app()
