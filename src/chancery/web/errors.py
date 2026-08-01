from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..service import (
    InvalidContent,
    InvalidPassword,
    InvalidTTL,
    PasteNeedsPassword,
    PasteNotFound,
    PasteTooLarge,
)
from .deps import templates

_HTML_ERRORS = {
    PasteNotFound: (404, "Paste not found"),
    PasteNeedsPassword: (401, "Password required"),
    InvalidPassword: (403, "Wrong password"),
    PasteTooLarge: (413, "Paste too large"),
    InvalidContent: (400, "Invalid content"),
    InvalidTTL: (400, "Invalid expiry"),
}


def _handler_for(status: int, detail: str):
    def handler(request: Request, exc: Exception):
        if request.url.path.startswith("/api/"):
            return JSONResponse(status_code=status, content={"detail": detail})
        return templates.TemplateResponse(
            request,
            "error.html",
            {"status_code": status, "detail": detail},
            status_code=status,
        )

    return handler


def register_exception_handlers(app: FastAPI) -> None:
    for exc, (status, detail) in _HTML_ERRORS.items():
        app.add_exception_handler(exc, _handler_for(status, detail))
    app.add_exception_handler(Exception, _handler_for(500, "Internal server error"))
