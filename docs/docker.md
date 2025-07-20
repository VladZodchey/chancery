## note: this doc is in progress, information may be inaccurate

# Running Chancery via docker

```commandline
docker run vladzodchey/chancery:latest
```

## Environment variables

- `PORT` The port to run on. Default: `8888`
- `AUTH_SECRET` The secret to generate access tokens with. On default generates a one-time random secret.
- `DB_PATH` The path to an SQLite3 DB. On default opens a one-time in-RAM DB.
- `PASTES_PATH` The path to save and retrieve read-unprotected pastes. Default: `./pastes`
- `PROTECTED_PATH` The path to save and retrieve read-protected pastes. Default: `./protected`
- ~~`ENCRYPT` If `true`, will encrypt read-protected pastes. If `false`, will save them in plaintext.~~ (*planned*)
- `AUTHORIZED` If `true`, will require authorization and sufficient permissions to perform actions, if `false`, disables all security and auth related internal checks and read-protected pasting gets disabled. Default: `true`
- `LAN` If `true`, will disable CORS
- `ANONYMOUS` If `true`, will not require authorization to post public pastes, if `AUTHORIZED` is `false`, will allow putting anything in paste's `author` property. If `false`, will. Default: `false`