//! A sync response, parsed but still encrypted (no I/O: also without
//! `std`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::Deserialize;

use crate::crypto::EncString;
use crate::error::{Error, Result};
use crate::vault::FolderId;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileWire {
    id: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    organizations: Vec<crate::crypto::OrganizationKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderWire {
    id: String,
    name: String,
}

/// Collection membership and effective permissions from the account's sync.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Collection {
    pub id: String,
    pub organization_id: String,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub hide_passwords: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncWire {
    profile: ProfileWire,
    #[serde(default)]
    collections: Vec<Collection>,
    #[serde(default)]
    folders: Vec<FolderWire>,
    #[serde(default)]
    ciphers: Vec<serde_json::Value>,
}

/// A `/api/sync` response, still encrypted: what
/// [`Vault::apply_sync`](crate::Vault::apply_sync) takes.
pub struct SyncData {
    pub(crate) collections: Vec<Collection>,
    pub(crate) user_id: String,
    pub(crate) protected_key: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) organizations: Vec<crate::crypto::OrganizationKey>,
    pub(crate) folders: Vec<(FolderId, Option<EncString>)>,
    pub(crate) ciphers: Vec<serde_json::Value>,
}

impl fmt::Debug for SyncData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncData")
            .field("folders", &self.folders.len())
            .field("ciphers", &self.ciphers.len())
            .finish_non_exhaustive()
    }
}

impl SyncData {
    /// The account's user id.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The protected symmetric key (`profile.key`): with the master key,
    /// it gives the user key.
    pub fn protected_key(&self) -> Option<&str> {
        self.protected_key.as_deref()
    }

    /// Parses a sync response body (what the client fetches; also for
    /// tests).
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] if it doesn't parse.
    pub fn from_json(body: &[u8]) -> Result<Self> {
        let wire: SyncWire = serde_json::from_slice(body).map_err(|e| Error::decode("sync", &e))?;
        Ok(Self {
            collections: wire.collections,
            user_id: wire.profile.id,
            protected_key: wire.profile.key,
            private_key: wire.profile.private_key,
            organizations: wire.profile.organizations,
            folders: wire
                .folders
                .into_iter()
                .map(|f| (FolderId::new(f.id), f.name.parse().ok()))
                .collect(),
            ciphers: wire.ciphers,
        })
    }
}
