# wardwire

An async Rust client for the [Bitwarden](https://bitwarden.com) and
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) API, for the
personal vault.

Status: early (0.1). It logs in with a personal API key, unlocks the vault,
syncs, decrypts login items one field at a time, matches them to a URL, and
can create and update logins. Organization items and collections are not
supported yet.

## Install

Until the first crates.io release, use the git repository:

```toml
[dependencies]
wardwire = { git = "https://github.com/talaagent/wardwire" }
```

## Example

```rust,no_run
use wardwire::{
    ApiKey, Client, Device, ExposeSecret as _, KdfPolicy, MasterKey, MatchOptions, SecretString, ServerUrls,
    Vault,
};

async fn run() -> wardwire::Result<()> {
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
    let master = MasterKey::derive(&SecretString::from("master password"), email, &kdf, &KdfPolicy::default())?;
    let protected = sync.protected_key().unwrap_or_default().to_owned();
    let mut vault = Vault::unlock(&master, &protected, Some(kdf))?;
    vault.apply_sync(sync)?;

    // Keep the user key sealed (your own way) instead of the master password:
    let _sealed_later = vault.export_user_key()?;
    let _beside_it = vault.key_state().clone();

    for login in vault.find_logins("https://login.example.com/", &MatchOptions::default())? {
        if let Some(password) = vault.password(&login.id)? {
            let _ = password.expose_secret();
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
  parameters, checked against a `KdfPolicy` (a floor against downgrades, a
  ceiling against absurd costs); HKDF stretching.
- **Login**: the `client_credentials` grant with a personal API key and
  device identifiers.
- **Unlock**: from the protected symmetric key (EncString type 2), or from
  a user key the caller kept; the user key can be exported for sealing.
- **Sync**: `/api/sync`, personal items and folders. Logins keep their
  EncStrings: names, usernames, URIs and TOTP secrets are decrypted on
  request, and a password only by `Vault::password`. Per-item keys are
  supported.
- **URI matching**: Bitwarden's base domain (public suffix list), host,
  starts with, exact, regular expression (off unless `allow_regex`) and
  never, with caller-supplied equivalent domains. Stricter than Bitwarden
  by default: an `https` login doesn't match an `http` page
  (`strict_scheme`), and starts-with needs a boundary (`https://bank.com`
  doesn't match `https://bank.com.evil.net`).
- **TOTP**: `otpauth://` (SHA-1/256/512, digits, period), `steam://` and
  bare base32.
- **Writes**: create a login; update one. Every update (name, username,
  password, TOTP, URIs) needs a `ConfirmedItem` from `Vault::confirm_item`,
  bound to the item and its revision; a replaced password goes to the
  item's history, and fields wardwire doesn't model are sent back
  unchanged.

## Security

- Every key and decrypted value is `zeroize`d on drop or held in `secrecy`
  types; no `Debug` impl prints one.
- EncString MACs are verified (in constant time) before decryption; the
  unauthenticated types 0 and 1 are refused.
- Nothing is cached on disk.
- Logging (`tracing`, debug level) carries item ids only, never names,
  usernames, URIs or secrets. Errors carry no server body text.
- HTTPS (rustls) only, except to loopback addresses; no redirects.
  Response bodies are capped (32 MiB by default,
  `Client::with_max_body_size`).
- The server is trusted to keep each field with its item: Bitwarden's
  encrypted fields aren't bound to their item, so a hostile server could
  move one item's password into another item with its own URI. Use a
  server you trust.

## Tests

Known-answer tests against fixtures computed independently with OpenSSL
(`scripts/gen-fixtures.sh`, run in `nix develop`), a mock server for the
HTTP flows, and URI matching tables. All test data is synthetic.

## License

Apache-2.0
