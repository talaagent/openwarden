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
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
