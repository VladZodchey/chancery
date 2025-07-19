FROM python:3.12-alpine AS builder

WORKDIR /app

RUN pip install uv

COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen

RUN uv pip install gunicorn


FROM python:3.12-alpine

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY api.py /app/

ENV PATH="/app/.venv/bin:$PATH"

ENV PORT=8888

EXPOSE $PORT

CMD ["/bin/sh", "-c", "gunicorn -w 4 --bind 0.0.0.0:$PORT api:app"]