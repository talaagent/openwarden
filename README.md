# openwarden

[![CI](https://github.com/talaagent/openwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/talaagent/openwarden/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/openwarden.svg)](https://crates.io/crates/openwarden)
[![downloads](https://img.shields.io/crates/d/openwarden.svg)](https://crates.io/crates/openwarden)
[![docs.rs](https://docs.rs/openwarden/badge.svg)](https://docs.rs/openwarden)
[![lib.rs](https://img.shields.io/badge/lib.rs-openwarden-blue.svg)](https://lib.rs/crates/openwarden)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://github.com/talaagent/openwarden/blob/main/Cargo.toml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/talaagent/openwarden/blob/main/LICENSE)

An async Rust client library for the [Bitwarden](https://bitwarden.com) and
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) API, for the
personal vault. It logs in with a personal API key, derives the master key
and unlocks the vault, syncs, decrypts login items one field at a time,
matches them to a page URL, and creates and updates logins.

This project is not affiliated with or endorsed by Bitwarden, Inc.
"Bitwarden" is a trademark of Bitwarden, Inc.

## Install

```toml
[dependencies]
openwarden = "0.1"
```

Rust 1.88 or newer. HTTP goes through reqwest on rustls (aws-lc-rs); the
calls are plain `async fn`s and the tests run them on Tokio.

## Example

```rust,no_run
use openwarden::{
    ApiKey, Client, Device, ExposeSecret as _, KdfPolicy, MasterKey, MatchOptions, SecretString,
    ServerUrls, Vault,
};

async fn run() -> openwarden::Result<()> {
    let client = Client::new(
        ServerUrls::self_hosted("https://vault.example.com")?,
        Device {
            identifier: "6d3c2f0e-0000-4000-8000-000000000001".into(),
            name: "my-tool".into(),
            device_type: Device::LINUX_CLI,
        },
    )?;
    let session = client
        .login_api_key(&ApiKey {
            client_id: "user.<uuid>".into(),
            client_secret: SecretString::from("..."),
        })
        .await?;
    let sync = client.sync(&session).await?;

    let email = "me@example.com";
    let kdf = match session.kdf() {
        Some(kdf) => kdf,
        None => client.prelogin(email).await?,
    };
    // CPU- and memory-heavy: in async code, run it on a blocking thread.
    let password = SecretString::from("master password");
    let master = MasterKey::derive(&password, email, &kdf, &KdfPolicy::default())?;
    let protected = sync.protected_key().unwrap_or_default().to_owned();
    let mut vault = Vault::unlock(&master, &protected, Some(kdf))?;
    vault.apply_sync(sync)?;

    // Keep the user key sealed (your own way) instead of the master password:
    let _sealed_later = vault.export_user_key()?;
    let _beside_it = vault.key_state().clone();

    for login in vault.find_logins("https://login.example.com/", &MatchOptions::default())? {
        if let Some(password) = vault.password(&login.id)? {
            let _use_it = password.expose_secret();
        }
    }
    Ok(())
}
```

Later runs reopen with `Vault::open(UserKey::from_bytes(..)?, key_state)`.
`apply_sync` and `check_session` lock the vault and return
`Error::KeyChanged` when the server shows the key is no longer valid (a new
protected key, a new KDF, or a rotated user key): unlock again with the
master password.

## What it does

- **Prelogin and KDFs**: PBKDF2-SHA256 and Argon2id with the server's
  parameters, checked against a `KdfPolicy`; HKDF stretching.
- **Login**: the `client_credentials` grant with a personal API key and
  device identifiers. Bitwarden's US and EU clouds, or a self-hosted base
  URL.
- **Unlock**: from the protected symmetric key (`EncString` type 2), or from
  a user key the caller kept; the user key can be exported for sealing.
- **Sync**: `/api/sync`, personal items and folders. Logins keep their
  `EncString`s: names, usernames, URIs and TOTP secrets are decrypted on
  request, and a password only by `Vault::password`. Per-item keys are
  supported.
- **URI matching**: Bitwarden's match types (base domain by the public
  suffix list, host, starts with, exact, regular expression, never), with
  caller-supplied equivalent domains, and stricter defaults (see below).
- **TOTP**: `otpauth://` (SHA-1/256/512, digits, period), `steam://` and
  bare base32.
- **Writes**: create a login; update one. Every update (name, username,
  password, TOTP, URIs) needs a `ConfirmedItem` from `Vault::confirm_item`,
  bound to the item and its revision; a replaced password goes to the
  item's history, and fields openwarden doesn't model are sent back
  unchanged.

## Why another client

The other Rust crates around Bitwarden do different jobs:

- [`bitwarden`](https://crates.io/crates/bitwarden) is Bitwarden's Secrets
  Manager SDK. It works with Secrets Manager projects and secrets, not the
  personal vault, and is published under Bitwarden's own SDK license.
- [`bitwarden-core`](https://crates.io/crates/bitwarden-core) and
  [`bitwarden-vault`](https://crates.io/crates/bitwarden-vault) are
  internal crates of Bitwarden's SDK, described on crates.io as "Internal
  crate for the bitwarden crate. Do not use.", and licensed GPL-3.0-only or
  under the Bitwarden SDK License.
- [`bitwarden-api-api`](https://crates.io/crates/bitwarden-api-api) is
  generated bindings for the HTTP API, without the key derivation or
  decryption.
- [`rbw`](https://crates.io/crates/rbw) is an unofficial command-line client
  with a background agent, not a library.

openwarden is an Apache-2.0 library for the whole personal-vault flow:
login, key derivation, unlock, sync, decryption, URI matching and writes.

## Status and roadmap

Early (0.1); the API may change between minor versions.

- [x] API-key login, prelogin, PBKDF2 and Argon2id, unlock, sync
- [x] Login items: lazy decryption, per-item keys, URI matching, TOTP
- [x] Creating and updating logins, with confirmation and password history
- [ ] Organizations and collections (organization keys, `EncString` RSA
      types): next
- [ ] Other item types (secure notes, cards, identities, SSH keys): synced,
      but not decrypted yet
- [ ] Master-password login (the `password` grant) and two-factor
- [ ] A CLI (planned, no code yet): the `openwarden-cli` crate, installing
      the `ow` command, a fast `bw`-style CLI with an encrypted local cache
      and the unlocked key held in the OS keyring

### Servers

The HTTP flows are tested against a mock server that answers with the
request and response shapes of the Bitwarden and Vaultwarden APIs,
including both the `camelCase` and the `PascalCase` field names the two use.
The crypto is checked against known-answer vectors computed independently
with OpenSSL. It has not yet been tested against a live Bitwarden or
Vaultwarden server in CI, so no server versions are claimed as supported;
reports from real servers are welcome.

## Security model

- Every key and decrypted value is zeroized on drop or held in a `secrecy`
  type, and no `Debug` impl prints one (keys, tokens, API keys, decrypted
  fields, the protected key). The crate's own copy of a response body is
  wiped on drop; copies made inside reqwest, hyper and rustls are outside
  its control, so this is best effort.
- `EncString` MACs are verified, in constant time, before decryption; the
  unauthenticated types 0 and 1 are refused.
- The server picks the KDF parameters, so `KdfPolicy` bounds them. By
  default: PBKDF2 at least 100,000 and at most 10,000,000 iterations;
  Argon2id 2 to 20 iterations, 16 to 1024 MiB and 1 to 16 lanes. A hostile
  server can't make an offline guess cheap or exhaust memory.
- HTTPS (rustls) only, except to loopback addresses; no redirects, so the
  bearer token never follows one; a 30-second timeout. Response bodies are
  capped (32 MiB by default, `Client::with_max_body_size`).
- Nothing is written to disk. Logging (`tracing`, debug level) carries item
  ids only, never names, usernames, URIs or secrets. Errors carry no server
  body text, only endpoint names, status codes, OAuth error codes and
  positions.
- URI matching is stricter than Bitwarden's: with `strict_scheme` (the
  default) an `https` login doesn't match an `http` page; starts-with needs
  a boundary (`https://bank.com` matches `https://bank.com/login` but not
  `https://bank.com.evil.net`); a page URL with userinfo never matches; and
  regular-expression URIs never match unless `allow_regex` is set (their
  compiled size is capped).
- The crate forbids `unsafe` code.

What the server is trusted with: it can't read the vault, but it is trusted
to keep each field with its item. Bitwarden's encrypted fields aren't bound
to the item or field they belong to: every field of a personal item is
encrypted under the same key, so a hostile server could move one item's
password into another item that carries the server's own URI, and it would
decrypt and match there. openwarden can't detect that. A caller that
fills passwords into pages should use a server it trusts, over a trusted
transport, and confirm with the user before any `Vault::update_login`.

Report vulnerabilities privately: see
[SECURITY.md](https://github.com/talaagent/openwarden/blob/main/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/talaagent/openwarden/blob/main/CONTRIBUTING.md).
All test data is synthetic: known-answer fixtures from
`scripts/gen-fixtures.sh` (OpenSSL), a mock server for the HTTP flows, and
URI matching tables.

## License

Apache-2.0. See [LICENSE](https://github.com/talaagent/openwarden/blob/main/LICENSE).
