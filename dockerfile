FROM python:3.12-alpine AS builder

WORKDIR /app

RUN pip install uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen


FROM python:3.12-alpine

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir -p ./logs ./pastes ./protected && chown -R appuser:appgroup .

COPY --from=builder --chown=appuser:appgroup /app/.venv ./.venv
COPY --chown=appuser:appgroup app ./app/
COPY --chown=appuser:appgroup run.py ./run.py

USER appuser

ENV PATH="/app/.venv/bin:$PATH"
ENV PORT=8888
EXPOSE $PORT

CMD ["/bin/sh", "-c", "gunicorn -w 4 -b 0.0.0.0:$PORT --access-logfile - --disable-redirect-access-to-syslog run:app"]