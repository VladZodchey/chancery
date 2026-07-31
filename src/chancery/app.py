from fastapi import FastAPI

from . import __version__

app = FastAPI(title="Chancery", version=__version__)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
