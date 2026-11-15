//! warden-client: an async client for the Bitwarden and Vaultwarden API.
//!
//! It logs in with a personal API key, unlocks the personal vault (with the
//! master password, or a user key the caller kept sealed), syncs, and
//! decrypts items one field at a time: a password only on an explicit
//! [`Vault::password`] call. Nothing is cached on disk; every key and
//! plaintext is zeroized on drop and none has a `Debug` that prints it.
//!
//! ```no_run
//! use warden_client::{ApiKey, Client, Device, KdfPolicy, MasterKey, MatchOptions, SecretString, ServerUrls, Vault};
//! use warden_client::ExposeSecret as _;
//!
//! # async fn run() -> warden_client::Result<()> {
//! let client = Client::new(
//!     ServerUrls::self_hosted("https://vault.example.com")?,
//!     Device {
//!         identifier: "6d3c2f0e-0000-4000-8000-000000000001".into(),
//!         name: "my-tool".into(),
//!         device_type: Device::LINUX_CLI,
//!     },
//! )?;
//! let key = ApiKey {
//!     client_id: "user.<uuid>".into(),
//!     client_secret: SecretString::from("..."),
//! };
//! let session = client.login_api_key(&key).await?;
//! let sync = client.sync(&session).await?;
//!
//! let email = "me@example.com";
//! let kdf = match session.kdf() {
//!     Some(kdf) => kdf,
//!     None => client.prelogin(email).await?,
//! };
//! let password = SecretString::from("master password");
//! let master = MasterKey::derive(&password, email, &kdf, &KdfPolicy::default())?;
//! let protected = sync.protected_key().unwrap_or_default().to_owned();
//! let mut vault = Vault::unlock(&master, &protected, Some(kdf))?;
//! vault.apply_sync(sync)?;
//!
//! for login in vault.find_logins("https://login.example.com/", &MatchOptions::default())? {
//!     if let Some(pw) = vault.password(&login.id)? {
//!         let _use_it = pw.expose_secret();
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What the server is trusted with
//!
//! The server can't read the vault, but it is trusted to keep each field
//! with its item. Bitwarden's encrypted fields are not bound to the item or
//! field they belong to: every field of a personal item is encrypted under
//! the same key, so a hostile server can move one item's password into
//! another item that carries the server's own URI, and it will decrypt and
//! match there. warden-client can't detect that. A caller that fills passwords
//! into pages should treat the server as trusted for item binding (run your
//! own, over a trusted transport), and confirm with the user before any
//! [`Vault::update_login`] (every one needs a [`ConfirmedItem`]).

extern crate alloc;

mod client;
mod crypto;
mod error;
mod kdf;
pub mod totp;
pub mod uri;
mod vault;

pub use client::{ApiKey, Client, Device, ServerUrls, Session, SyncData};
pub use crypto::{EncString, SymmetricKey};
pub use error::{Error, KeyChange, Result};
pub use kdf::{Kdf, KdfPolicy, MasterKey};
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
pub use totp::TotpCode;
pub use uri::{MatchOptions, UriMatch, uri_matches};
pub use vault::{
    CipherId, ConfirmedItem, FolderId, KeyState, LoginDraft, LoginInfo, LoginUpdate, LoginUri,
    UserKey, Vault,
};
