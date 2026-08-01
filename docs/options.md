# Configuration options

All settings come from `CHANCERY_*` environment variables (a `.env` file in
the working directory is also honored).

| Variable                       | Default                 | Meaning                                    |
| -------------------------------| ----------------------- | ------------------------------------------ |
| `CHANCERY_DB_PATH`             | `chancery.db`           | Path to the encrypted SQLCipher database.  |
| `CHANCERY_DB_KEY`              | (none, required)        | 64-char hex key or passphrase.             |
| `CHANCERY_BASE_URL`            | `http://127.0.0.1:8000` | Base URL used in generated paste URLs.     |
| `CHANCERY_EXPECTED_HOST`       | (none)                  | Comma-separated Host names to accept.      |
|                                |                         | Requests with any other Host get `400`.    |
| `CHANCERY_FORWARDED_ALLOW_IPS` | (none)                  | Comma-separated IPs/CIDRs of trusted       |
|                                |                         | proxies; X-Forwarded-* honored only from   |
|                                |                         | these. Otherwise such headers are stripped.|
| `CHANCERY_LOG_LEVEL`           | `INFO`                  | Log level (DEBUG/INFO/WARNING/ERROR).      |
| `CHANCERY_PASTE_MAX_SIZE`      | `1000000`               | Maximum paste size in bytes.               |
| `CHANCERY_MAX_TTL_SECONDS`     | `2592000`               | Upper bound for TTL (30 days).             |
| `CHANCERY_PASTE_ID_LENGTH`     | `10`                    | Paste ID length in characters.             |
| `CHANCERY_TCP_ENABLED`         | `false`                 | Start the raw TCP listener on `serve`.     |
| `CHANCERY_TCP_HOST`            | `127.0.0.1`             | TCP bind address.                          |
| `CHANCERY_TCP_PORT`            | `9999`                  | TCP port.                                  |
| `CHANCERY_TCP_CONNECT_TIMEOUT` | `60.0`                  | Seconds to allow a client to send a paste. |
| `CHANCERY_KDF_OPSLIMIT`        | Argon2id MODERATE       | KDF operations limit.                      |
| `CHANCERY_KDF_MEMLIMIT`        | Argon2id MODERATE       | KDF memory limit in bytes.                 |
