//! The README follows; its example is compiled as a doctest.
//!
// The README's example uses the client, so without `std` the crate docs
// are a pointer to it instead.
#![cfg_attr(feature = "std", doc = include_str!("../README.md"))]
#![cfg_attr(
    not(feature = "std"),
    doc = "Built without the `std` feature: no HTTP client. See the README on \
           [docs.rs](https://docs.rs/openwarden)."
)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
mod client;
mod crypto;
mod error;
mod kdf;
mod sync;
pub mod totp;
pub mod uri;
mod vault;

#[cfg(feature = "std")]
pub use client::{ApiKey, Client, Device, ServerUrls, Session};
pub use crypto::{EncString, SymmetricKey};
pub use error::{Error, KeyChange, Result};
pub use kdf::{Kdf, KdfPolicy, MasterKey};
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
pub use sync::SyncData;
pub use totp::TotpCode;
pub use uri::{MatchOptions, UriMatch, uri_matches};
pub use vault::{
    CipherId, ConfirmedItem, FolderId, KeyState, LoginDraft, LoginInfo, LoginUpdate, LoginUri,
    UserKey, Vault,
};
