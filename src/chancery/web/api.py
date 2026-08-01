from fastapi import APIRouter, Query, Request

from ..models import CreatedPaste, NewPaste, PasteOut
from ..service import PasteService
from .deps import get_service

router = APIRouter(prefix="/api/pastes")


@router.post("", status_code=201, response_model=CreatedPaste)
def create_paste(payload: NewPaste, request: Request) -> CreatedPaste:
    service: PasteService = get_service(request)
    return service.create(
        payload.content,
        password=payload.password,
        burn_after_read=payload.burn_after_read,
        ttl_seconds=payload.ttl_seconds,
    )


@router.get("/{paste_id}", response_model=PasteOut)
def get_paste(
    paste_id: str,
    request: Request,
    password: str | None = Query(default=None),
) -> PasteOut:
    service: PasteService = get_service(request)
    paste = service.get(paste_id, password=password)
    return PasteOut(
        id=paste.id,
        url=service.resolve_url(paste.id),
        content=paste.text,
        size_bytes=paste.size_bytes,
        encrypted=paste.encrypted,
        burn_after_read=paste.burn_after_read,
        created_at=paste.created_at,
        expires_at=paste.expires_at,
    )
