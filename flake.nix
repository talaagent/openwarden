{
  description = "warden-client: an async Rust client for the Bitwarden and Vaultwarden API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        # The library, built and tested (cargo test runs in checkPhase).
        warden-client = pkgs.rustPlatform.buildRustPackage {
          pname = "warden-client";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
              # crates/warden-client links its README and LICENSE here.
              ./README.md
              ./LICENSE
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          # The tests build real HTTP clients (against a local mock
          # server); rustls' platform verifier wants a CA store to exist.
          SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          meta = {
            description = "Async client for the Bitwarden and Vaultwarden API";
            license = pkgs.lib.licenses.asl20;
          };
        };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.warden-client;
      });

      checks = forAllSystems (pkgs: {
        warden-client = self.packages.${pkgs.stdenv.hostPlatform.system}.warden-client;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "warden-client";
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
            pkgs.cargo-deny
            # scripts/gen-fixtures.sh: the reference implementation the
            # known-answer fixtures are built with.
            pkgs.openssl
            pkgs.xxd
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
