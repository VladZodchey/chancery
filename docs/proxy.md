## Running behind a reverse proxy (Nginx / Caddy)

Chancery is meant to sit behind a reverse proxy. Two settings make that safe:

- `CHANCERY_EXPECTED_HOST` -- set it to your public hostname (comma-separated
  if you serve several). Requests arriving with any other `Host` header are
  rejected with `400`, which blocks Host-header poisoning and DNS-rebinding
  style attacks. For example `CHANCERY_EXPECTED_HOST=paste.example.com`.
- `CHANCERY_FORWARDED_ALLOW_IPS` -- the IPs (or CIDRs) of your proxy, e.g.
  `CHANCERY_FORWARDED_ALLOW_IPS=10.0.0.5`. Only then are
  `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` trusted: the
  real client IP shows up in logs, the scheme becomes `https`, and the
  forwarded Host is honored. If the direct peer is not trusted, those headers
  are stripped so nobody can spoof them by hitting chancery directly.

Also set `CHANCERY_BASE_URL` to your public URL so generated paste links are
correct, and make sure the proxy forwards the `Host` header (`proxy_set_header
Host $host;` in Nginx; Caddy does this by default).

Example Nginx server block:

```nginx
server {
    listen 443 ssl;
    server_name paste.example.com;
    # ... TLS setup ...

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```
