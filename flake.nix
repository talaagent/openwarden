{
  description = "openwarden: an async Rust client for the Bitwarden and Vaultwarden API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ (import rust-overlay) ];
            }
          )
        );
      # The toolchain pinned in rust-toolchain.toml, from rust-overlay.
      rustToolchainFor = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatformFor =
        pkgs:
        pkgs.makeRustPlatform {
          cargo = rustToolchainFor pkgs;
          rustc = rustToolchainFor pkgs;
        };
    in
    {
      packages = forAllSystems (pkgs: {
        # The library, built and tested (cargo test runs in checkPhase).
        openwarden = (rustPlatformFor pkgs).buildRustPackage {
          pname = "openwarden";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
              # crates/openwarden links its README and LICENSE here.
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
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.openwarden;
      });

      checks = forAllSystems (pkgs: {
        openwarden = self.packages.${pkgs.stdenv.hostPlatform.system}.openwarden;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "openwarden";
          packages = [
            (rustToolchainFor pkgs)
            pkgs.cargo-deny
            pkgs.cargo-nextest
            # scripts/gen-fixtures.sh: the reference implementation the
            # known-answer fixtures are built with.
            pkgs.openssl
            pkgs.xxd
          ];
          RUST_SRC_PATH = "${rustToolchainFor pkgs}/lib/rustlib/src/rust/library";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
