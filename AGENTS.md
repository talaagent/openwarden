# warden-client: contributor and agent guide

An async Rust client library for the Bitwarden and Vaultwarden
personal-vault API: API-key login, KDFs and unlock, sync, field-by-field
decryption, URI matching, and creating and updating logins. It handles
master passwords, keys and decrypted vault data, so most of the rules below
are about not leaking them. CONTRIBUTING.md covers the pull request flow
and releases.

## Commands

Use the nix dev shell. It provides the Rust toolchain, cargo-nextest,
cargo-deny and the OpenSSL used for the fixtures:

```sh
nix develop -c cargo fmt --all --check
nix develop -c cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
nix develop -c cargo nextest run --workspace --all-targets --all-features --locked
nix develop -c cargo test --workspace --all-features --doc --locked
RUSTDOCFLAGS="-D warnings" nix develop -c cargo doc --workspace --no-deps --all-features --locked
nix develop -c cargo deny check
nix develop -c cargo publish --workspace --dry-run --locked
nix flake check -L
```

The MSRV is the workspace `rust-version` (1.88); CI checks and tests on it.

## Layout

- `crates/warden-client/src/client.rs`: `Client`, `ServerUrls`, `Device`,
  `ApiKey`, `Session`, `SyncData`; HTTP, the body cap, error mapping.
- `src/kdf.rs`: `Kdf`, `KdfPolicy`, `MasterKey` (derive, stretch, unlock).
- `src/crypto.rs`: `SymmetricKey` and `EncString` (type 2 only).
- `src/vault.rs`: `Vault`, `UserKey`, `KeyState`, lazy decryption, key-change
  detection, and login writes (`ConfirmedItem`, password history,
  round-tripping fields the crate doesn't model).
- `src/uri.rs`: URI matching; the rules are in its module docs.
- `src/totp.rs`: TOTP codes.
- `tests/kat.rs`: known-answer tests against `tests/fixtures/kat.json`,
  which `scripts/gen-fixtures.sh` computes with OpenSSL from synthetic
  inputs (deterministic; CI regenerates it and diffs).
- `tests/flow.rs`: the HTTP flows against a wiremock server.
- `tests/uri_match.rs`: URI matching tables.

## Conventions

- No secret in `Debug`, `Display` or errors. A type that holds a key, a
  token, a password, a decrypted field or the protected key gets a manual
  `Debug` that redacts it, and a test that checks the output.
- Keys and plaintext live in `secrecy` types or `Zeroizing`/`ZeroizeOnDrop`
  buffers; don't copy them into plain `String`s or `Vec`s.
- Errors carry no server body text or serde messages (they can quote the
  input): endpoint names, status codes, OAuth error codes, item ids and
  positions only.
- `tracing` events carry item ids only, never names, usernames, URIs or
  secrets.
- Verify a MAC before decrypting; refuse unauthenticated `EncString` types.
- Anything the server chooses (KDF parameters, body sizes, regexes in
  login URIs) is bounded.
- Matching changes need a row in `tests/uri_match.rs` and, if a rule
  changes, the `uri` module docs and the README.
- Test data is synthetic: `example.com`-style hosts, made-up accounts, and
  fixtures from `scripts/gen-fixtures.sh`. Never commit a real API key,
  token, sync response or server URL.
- Don't port code from Bitwarden's clients or SDK (GPL-3.0 or the Bitwarden
  license). Implement from the documented protocol and test vectors.
- `unsafe` is forbidden; no `unwrap` outside tests; `core`/`alloc` paths
  over `std` where they exist (the workspace lints enforce these).
- The README is the crate docs (`include_str!`), so its example is a
  doctest. Keep its links absolute so they work on crates.io.
- Changelog entries come from commit messages (release-plz), so write
  commit subjects that read well in CHANGELOG.md.
