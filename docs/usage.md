# Chancery usage

## Admin CLI

Chancery provides `chancery` command, which acts both as a service starter and an admin CLI.
Admin CLI does not communicate with the service. It manipulates the database directly.

To use the admin CLI you have to set `CHANCERY_DP_KEY` env variable, example:
```sh
export CHANCERY_DP_KEY=super-secret-password
sudo -u chancery chancery admin list
```
or pass it directly:
```sh
CHANCERY_DP_KEY=super-secret-password sudo -u chancery chancery admin list
```

Available `chancery` commands:

```
chancery serve [--reload] [--port N] [--host H] [--log-level L]  # Start the server
chancery healthcheck [--url U]
chancery admin ...
```

Available `chancery admin` commands:

```
chancery admin init-db
chancery admin rekey
chancery admin list
chancery admin show <id>
chancery admin create [--password pw] [--burn] [--ttl N] [file|-]
chancery admin delete <id>
chancery admin stats
chancery admin purge-expired
```

## HTTP API

Create form:

```sh
curl -X POST https://paste.example.com/api/pastes \
  -H 'content-type: application/json' \
  -d '{"content": "hello", "password": "pw", "burn_after_read": false, "ttl_seconds": 3600}'
# {"id":"Abc123XyZ9","url":"https://paste.example.com/Abc123XyZ9"}
```

Read form (JSON):

```sh
curl https://paste.example.com/api/pastes/Abc123XyZ9                   # plain
curl 'https://paste.example.com/api/pastes/Abc123XyZ9?password=pw'     # encrypted
```

Read form (raw):

```sh
wget https://paste.example.com/raw/Abc123XyZ9
```
*note: password-protected pastes deliberately can't be fetched raw*

The API exposes only create and read. There is no remote delete or listing.

## TCP

If `CHANCERY_TCP_ENABLED` is true, Chancery starts up a raw TCP listener at `CHANCERY_TCP_HOST:CHANCERY_TCP_PORT`.

It acts like Termbin, you pipe in text via something like `nc`, and get a link back.

```sh
cat .ssh/id_ed25519.pub | nc paste.example.com 9999
# https://paste.example.com/Abc123XyZ9
```
