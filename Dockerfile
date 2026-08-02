FROM python:3.13-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/chancery/.venv/bin:$PATH"

RUN groupadd --system chancery \
    && useradd --system --gid chancery --home /var/lib/chancery chancery \
    && install -d -o chancery -g chancery -m 0750 /var/lib/chancery

WORKDIR /opt/chancery

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/chancery/.venv \
    && /opt/chancery/.venv/bin/pip install .

ENV CHANCERY_DB_PATH=/var/lib/chancery/chancery.db

USER chancery

EXPOSE 8000 9999

VOLUME /var/lib/chancery

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["chancery", "healthcheck", "--url", "http://127.0.0.1:8000/health"]

ENTRYPOINT ["chancery"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
