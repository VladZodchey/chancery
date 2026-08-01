from fastapi import APIRouter, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from ..service import (
    InvalidPassword,
    InvalidTTL,
    PasteNeedsPassword,
    PasteService,
)
from .deps import get_service, templates

router = APIRouter()


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@router.post("/")
def create_paste(
    request: Request,
    content: str = Form(...),
    password: str | None = Form(default=None),
    burn_after_read: bool = Form(default=False),
    ttl_seconds: str | None = Form(default=None),
):
    service: PasteService = get_service(request)
    ttl = _parse_ttl(ttl_seconds)
    result = service.create(
        content,
        password=password or None,
        burn_after_read=burn_after_read,
        ttl_seconds=ttl,
    )
    if burn_after_read:
        return templates.TemplateResponse(
            request,
            "created.html",
            {"url": result.url},
        )
    return RedirectResponse(url=f"/{result.id}", status_code=303)


@router.get("/raw/{paste_id}")
def raw_paste(request: Request, paste_id: str):
    """Curl-friendly plain-text view. Encrypted pastes are never served raw."""
    service: PasteService = get_service(request)
    try:
        paste = service.get(paste_id)
    except PasteNeedsPassword:
        return PlainTextResponse("password required\n", status_code=401)
    return PlainTextResponse(paste.text)


@router.get("/{paste_id}")
def view_paste(request: Request, paste_id: str):
    service: PasteService = get_service(request)
    try:
        paste = service.get(paste_id)
    except PasteNeedsPassword:
        return templates.TemplateResponse(
            request,
            "view.html",
            {"paste_id": paste_id, "locked": True, "error": None},
        )
    return templates.TemplateResponse(
        request,
        "view.html",
        {"paste": paste, "content": paste.text, "locked": False},
    )


@router.post("/{paste_id}/unlock")
def unlock_paste(
    request: Request,
    paste_id: str,
    password: str = Form(...),
):
    service: PasteService = get_service(request)
    try:
        paste = service.get(paste_id, password=password)
    except PasteNeedsPassword:
        return templates.TemplateResponse(
            request,
            "view.html",
            {"paste_id": paste_id, "locked": True, "error": None},
        )
    except InvalidPassword:
        return templates.TemplateResponse(
            request,
            "view.html",
            {
                "paste_id": paste_id,
                "locked": True,
                "error": "Wrong password",
            },
            status_code=403,
        )
    return templates.TemplateResponse(
        request,
        "view.html",
        {"paste": paste, "content": paste.text, "locked": False},
    )


def _parse_ttl(raw: str | None) -> int | None:
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise InvalidTTL("expiry must be an integer number of seconds") from None
