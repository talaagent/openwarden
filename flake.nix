{
  description = "wardwire: an async Rust client for the Bitwarden and Vaultwarden API";

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
        wardwire = pkgs.rustPlatform.buildRustPackage {
          pname = "wardwire";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
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
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.wardwire;
      });

      checks = forAllSystems (pkgs: {
        wardwire = self.packages.${pkgs.stdenv.hostPlatform.system}.wardwire;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "wardwire";
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
