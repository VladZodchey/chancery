{
  description = "Security-focused selfhosted Pastebin/Termbin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      uv2nix,
      pyproject-nix,
      pyproject-build-systems,
    }:
    let
      inherit (nixpkgs) lib;
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      pyprojectOverrides = _final: _prev: { };
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python314;

        pythonBase = pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        };

        pythonSet = pythonBase.overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            overlay
            pyprojectOverrides
          ]
        );

        inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;

        app = mkApplication {
          venv = pythonSet.mkVirtualEnv "chancery-env" workspace.deps.default;
          package = pythonSet.chancery;
        };

        editableOverlay = workspace.mkEditablePyprojectOverlay {
          root = "$REPO_ROOT";
        };

        editablePythonSet = pythonSet.overrideScope editableOverlay;

        virtualenv = editablePythonSet.mkVirtualEnv "chancery-dev-env" workspace.deps.all;
      in
      {
        packages.default = app;

        apps.default = {
          type = "app";
          program = "${app}/bin/chancery";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            virtualenv
            pkgs.uv
          ];

          env = {
            UV_NO_SYNC = "1";
            UV_PYTHON = editablePythonSet.python.interpreter;
            UV_PYTHON_DOWNLOADS = "never";
          };

          shellHook = ''
            unset PYTHONPATH
            export REPO_ROOT=$(git rev-parse --show-toplevel)
            ln -sfnT "$(dirname "$(dirname "$(command -v python)")")" "$REPO_ROOT/.venv"
          '';
        };
      }
    )

    // {
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.chancery;
        in
        {
          options.services.chancery = {
            enable = lib.mkEnableOption "Chancery, a security-focused selfhosted paste store";

            host = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1";
              description = "Address the HTTP server binds to.";
            };

            port = lib.mkOption {
              type = lib.types.port;
              default = 2914;
              description = "TCP port the HTTP server listens on.";
            };

            dataDir = lib.mkOption {
              type = lib.types.path;
              default = "/var/lib/chancery";
              description = ''
                Directory where chancery stores its encrypted database, as
                ''${dataDir}/chancery.db. The directory is created if missing.
              '';
            };

            dbKey = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Database encryption key (`CHANCERY_DB_KEY`). Set exactly one of
                `dbKey` or `dbKeyFile`. Prefer `dbKeyFile` over this!
              '';
            };

            dbKeyFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Path to a file containing the raw database encryption key.
                The service reads this file as user `chancery` at startup.
                Set exactly one of `dbKey` or `dbKeyFile`. Prefer this over `dbKey`!
              '';
            };

            settings = lib.mkOption {
              type = lib.types.submodule {
                options = {
                  baseUrl = lib.mkOption {
                    type = lib.types.str;
                    default = "http://127.0.0.1:8000";
                    description = "Public base URL used in generated paste links.";
                  };

                  expectedHost = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [ ];
                    description = ''
                      Hosts allowed in the Host header (empty list = no host
                      checking). Requests with any other Host are rejected.
                    '';
                  };

                  forwardedAllowIps = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [ ];
                    description = ''
                      Reverse proxies trusted to set X-Forwarded-For/Proto/Host
                      (IPs or CIDR ranges). Empty list = no forwarded headers
                      are honored.
                    '';
                  };

                  rateLimitEnabled = lib.mkOption {
                    type = lib.types.bool;
                    default = true;
                    description = ''
                      Enable per-client-IP rate limiting on all HTTP endpoints
                      as a spam defense. Requires trusted reverse proxies to be
                      configured via `forwardedAllowIps` so real client IPs are
                      seen.
                    '';
                  };

                  rateLimit = lib.mkOption {
                    type = lib.types.str;
                    default = "60/minute";
                    description = ''
                      Global request rate limit per client IP, in limits-syntax
                      (e.g. "60/minute", "1000/hour").
                    '';
                  };

                  logLevel = lib.mkOption {
                    type = lib.types.enum [
                      "TRACE"
                      "DEBUG"
                      "INFO"
                      "WARNING"
                      "ERROR"
                      "CRITICAL"
                    ];
                    default = "INFO";
                    description = ''
                      Log verbosity. INFO records events without revealing which
                      paste (no ids, sizes, or flags); DEBUG adds full detail.
                    '';
                  };

                  pasteMaxSize = lib.mkOption {
                    type = lib.types.ints.positive;
                    default = 1000000;
                    description = "Maximum paste size in bytes.";
                  };

                  maxTtlSeconds = lib.mkOption {
                    type = lib.types.ints.positive;
                    default = 30 * 24 * 60 * 60;
                    description = "Longest allowed time-to-live in seconds.";
                  };

                  pasteIdLength = lib.mkOption {
                    type = lib.types.ints.positive;
                    default = 10;
                    description = "Length of generated paste ids.";
                  };

                  tcpEnabled = lib.mkOption {
                    type = lib.types.bool;
                    default = false;
                    description = "Enable the termbin-style TCP listener.";
                  };

                  tcpHost = lib.mkOption {
                    type = lib.types.str;
                    default = "127.0.0.1";
                    description = "Address the TCP listener binds to.";
                  };

                  tcpPort = lib.mkOption {
                    type = lib.types.port;
                    default = 9999;
                    description = "Port the TCP listener listens on.";
                  };

                  tcpConnectTimeout = lib.mkOption {
                    type = lib.types.number;
                    default = 60.0;
                    description = "TCP connection timeout in seconds.";
                  };

                  kdfOpslimit = lib.mkOption {
                    type = lib.types.ints.positive;
                    default = 3;
                    description = ''
                      Argon2id opslimit for password-derived keys. Defaults match
                      PyNaCl's MODERATE profile.
                    '';
                  };

                  kdfMemlimit = lib.mkOption {
                    type = lib.types.ints.positive;
                    default = 268435456;
                    description = ''
                      Argon2id memory limit in bytes for password-derived keys.
                      Defaults match PyNaCl's MODERATE profile.
                    '';
                  };
                };
              };
              default = { };
              description = ''
                Runtime settings, exported to the service as `CHANCERY_*`
                environment variables.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ self.packages.${pkgs.system}.default ];

            users.users.chancery = {
              isSystemUser = true;
              group = "chancery";
              home = cfg.dataDir;
              createHome = true;
            };
            users.groups.chancery = { };

            systemd.tmpfiles.rules = [
              "d ${cfg.dataDir} 0750 chancery chancery -"
            ];

            systemd.services.chancery = {
              description = "Chancery, a security-focused selfhosted paste store";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              environment = {
                CHANCERY_DB_PATH = "${cfg.dataDir}/chancery.db";
                CHANCERY_BASE_URL = cfg.settings.baseUrl;
                CHANCERY_EXPECTED_HOST = lib.concatStringsSep "," cfg.settings.expectedHost;
                CHANCERY_FORWARDED_ALLOW_IPS = lib.concatStringsSep "," cfg.settings.forwardedAllowIps;
                CHANCERY_RATE_LIMIT_ENABLED = lib.boolToString cfg.settings.rateLimitEnabled;
                CHANCERY_RATE_LIMIT = cfg.settings.rateLimit;
                CHANCERY_LOG_LEVEL = cfg.settings.logLevel;
                CHANCERY_PASTE_MAX_SIZE = toString cfg.settings.pasteMaxSize;
                CHANCERY_MAX_TTL_SECONDS = toString cfg.settings.maxTtlSeconds;
                CHANCERY_PASTE_ID_LENGTH = toString cfg.settings.pasteIdLength;
                CHANCERY_TCP_ENABLED = lib.boolToString cfg.settings.tcpEnabled;
                CHANCERY_TCP_HOST = cfg.settings.tcpHost;
                CHANCERY_TCP_PORT = toString cfg.settings.tcpPort;
                CHANCERY_TCP_CONNECT_TIMEOUT = toString cfg.settings.tcpConnectTimeout;
                CHANCERY_KDF_OPSLIMIT = toString cfg.settings.kdfOpslimit;
                CHANCERY_KDF_MEMLIMIT = toString cfg.settings.kdfMemlimit;
              }
              // lib.optionalAttrs (cfg.dbKey != null) {
                CHANCERY_DB_KEY = cfg.dbKey;
              }
              // lib.optionalAttrs (cfg.dbKeyFile != null) {
                CHANCERY_DB_KEY_FILE = cfg.dbKeyFile;
              };

              serviceConfig = {
                ExecStart = "${
                  self.packages.${pkgs.system}.default
                }/bin/chancery serve --host ${cfg.host} --port ${toString cfg.port}";
                Restart = "on-failure";
                User = "chancery";
                Group = "chancery";
                WorkingDirectory = cfg.dataDir;
                ProtectSystem = "strict";
                ReadWritePaths = [ cfg.dataDir ];
                PrivateTmp = true;
                NoNewPrivileges = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictSUIDSGID = true;
                RestrictRealtime = true;
                RestrictAddressFamilies = [
                  "AF_INET"
                  "AF_INET6"
                  "AF_UNIX"
                ];
              };
            };

            assertions = [
              {
                assertion = (cfg.dbKey != null) != (cfg.dbKeyFile != null);
                message = "services.chancery: set exactly one of `dbKey` or `dbKeyFile`.";
              }
            ];
          };
        };
    };
}
