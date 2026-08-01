# NixOS installation

## Flake

### 1. add Chancery as a flake:

```nix
inputs.chancery = {
  url = "git+https://codeberg.org/vladzodchey/chancery";
  inputs.nixpkgs.follows = "nixpkgs";
}
```

### 2. import the module

```nix
imports = [
  inputs.chancery.nixosModules.default
];
```

### 3. enable the service

```nix
{
  imports = [ chancery.nixosModules.default ];

  services.chancery = {
    enable = true;
    host = "127.0.0.1";
    port = 2914;

    dataDir = "/var/lib/chancery"; # DB will be at ${dataDir}/chancery.db

    dbKey = "64-character-hex-key-or-passphrase";
    # or: dbKeyFile = config.age.secrets.chancery-dbkey.path;  # file with plaintext secret

    settings = {
      baseUrl = "https://paste.example.com";
      expectedHost = [ "paste.example.com" ];
      forwardedAllowIps = [ "10.0.0.0/8" ];  # trusted reverse proxies
      logLevel = "INFO";
      tcpEnabled = false;
    };
  };
}
```

### Options

See [Options](options.md) for details on each option.
All `services.chancery.settings` options with Env prototypes and defaults:

- `baseUrl` - `CHANCERY_BASE_URL` - `http://127.0.0.1:8000`
- `expectedHost` - `CHANCERY_EXPECTED_HOST` - `[]`  (no host checking)
- `forwardedAllowIps` - `CHANCERY_FORWARDED_ALLOW_IPS` - `[]`
- `logLevel` - `CHANCERY_LOG_LEVEL` - `INFO`
- `pasteMaxSize` - `CHANCERY_PASTE_MAX_SIZE` - `1000000`
- `maxTtlSeconds` - `CHANCERY_MAX_TTL_SECONDS` - `2592000`
- `pasteIdLength` - `CHANCERY_PASTE_ID_LENGTH` - `10`
- `tcpEnabled` - `CHANCERY_TCP_ENABLED` - `false`
- `tcpHost` - `CHANCERY_TCP_HOST` - `127.0.0.1`
- `tcpPort` - `CHANCERY_TCP_PORT` - `9999`
- `tcpConnectTimeout` - `CHANCERY_TCP_CONNECT_TIMEOUT` - `60.0`
- `kdfOpslimit` - `CHANCERY_KDF_OPSLIMIT` - `Argon2id MODERATE`
- `kdfMemlimit` - `CHANCERY_KDF_MEMLIMIT` - `Argon2id MODERATE`
- `rateLimitEnabled` - `CHANCERY_RATE_LIMIT_ENABLED` - `true`
- `rateLimit` - `CHANCERY_RATE_LIMIT` - `60/minute`
