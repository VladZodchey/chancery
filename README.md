# Chancery

Selfhosted, security-focused paste store.
The project sacrifices some UX in favor of simplicity and security.

Built on FastAPI, Typer, Jinja2 and sqlcipher3.
Build with uv, ruff and ty.

## Security features:
- Mandatory DB encryption
- Password-protected pastes (Content encrypted with XSalsa20-Poly1305 under a key derived via Argon2id)
- One-time-read pastes (like 1ty.me)
- TTL (pastes can be set to be deleted automatically after N seconds)
- Configurably long cryptographically secure random IDs for pastes

## Quickstart

### Docker

Docker coming soon.

### NixOS

See [NixOS options](docs/nixos.md)

### Proxy

See [Running behind a reverse proxy](docs/proxy.md)

## Development | Building from source

With `nix`:
```sh
git clone https://codeberg.org/vladzodchey/chancery.git chancery && cd chancery
nix develop
chancery
```

Without `nix`:
```sh
git clone https://codeberg.org/vladzodchey/chancery.git chancery && cd chancery
uv venv && uv sync
chancery
```

## AI

I used LLMs to help scout dependency documentation and usage examples. 
Chancery's code is hand-written and held up to the security standards I'm aware of.
No-slop PRs welcome.
