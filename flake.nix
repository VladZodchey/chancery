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
            enable = lib.mkEnableOption "Chancery, selfhosted paste store";
            host = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1";
            };
            port = lib.mkOption {
              type = lib.types.port;
              default = 2914;
            };
          };

          config = lib.mkIf cfg.enable {
            users.users.chancery = {
              isSystemUser = true;
              group = "chancery";
              home = "/var/lib/chancery";
              createHome = true;
            };
            users.groups.chancery = { };

            systemd.services.chancery = {
              description = "Chancery, selfhosted paste store";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              serviceConfig = {
                ExecStart = "${
                  self.packages.${pkgs.system}.default
                }/bin/chancery serve --host ${cfg.host} --port ${toString cfg.port}";
                Restart = "on-failure";
                User = "chancery";
                Group = "chancery";
                WorkingDirectory = "/var/lib/chancery";
              };
            };
          };
        };
    };
}
