from datetime import UTC, datetime

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, select_autoescape

from ..service import PasteService


def _datetime(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


_env = Environment(
    loader=PackageLoader("chancery.web", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
_env.filters["datetime"] = _datetime

templates = Jinja2Templates(env=_env)


def get_service(request: Request) -> PasteService:
    return request.app.state.service
