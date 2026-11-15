//! The README follows; its example is compiled as a doctest.
//!
#![doc = include_str!("../README.md")]

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
