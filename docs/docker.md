# Running with Docker

Chancery is available on [Docker Hub](https://hub.docker.com/vladzodchey/chancery)

Example docker-compose config:

```yml
services:
  chancery:
    build: .
    image: docker.io/vladzodchey/chancery:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      CHANCERY_DB_KEY: change-me-64-char-hex-key-or-passphrase
      CHANCERY_BASE_URL: https://paste.example.com
      CHANCERY_EXPECTED_HOST: paste.example.com
      CHANCERY_LOG_LEVEL: INFO
    volumes:
      - chancery-data:/var/lib/chancery
    healthcheck:
      test:
        [
          "CMD",
          "chancery",
          "healthcheck",
          "--url",
          "http://127.0.0.1:8000/health",
        ]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  chancery-data:
```
