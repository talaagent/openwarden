//! The vault: the user key, and the synced items, still encrypted.
//!
//! Items are kept as the server sent them (`EncStrings` and the raw JSON);
//! a field is decrypted only when asked for, and a password only by
//! [`Vault::password`].

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
#[cfg(any(feature = "std", test))]
use alloc::format;
use alloc::string::String;
#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "std")]
use base64::Engine as _;
#[cfg(feature = "std")]
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use serde_json::Map;
use serde_json::Value;
#[cfg(feature = "std")]
use serde_json::json;
#[cfg(feature = "std")]
use sha2::{Digest, Sha256};

#[cfg(feature = "std")]
use crate::client::{Client, Session};
use crate::crypto::{EncString, SymmetricKey};
use crate::error::{Error, KeyChange, Result};
use crate::kdf::{Kdf, MasterKey};
use crate::sync::SyncData;
use crate::totp::{self, TotpCode};
use crate::uri::{MatchOptions, UriMatch, uri_matches};

/// An item (cipher) id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CipherId(String);

impl CipherId {
    /// From the server's id string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id as a URL path segment: ids are UUIDs, so anything outside
    /// `[0-9A-Za-z-]` is refused rather than escaped.
    #[cfg(feature = "std")]
    pub(crate) fn as_url_segment(&self) -> Result<&str> {
        if !self.0.is_empty()
            && self
                .0
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            Ok(&self.0)
        } else {
            Err(Error::NotFound(self.clone()))
        }
    }
}

impl fmt::Display for CipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A folder id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FolderId(String);

impl FolderId {
    /// From the server's id string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The unlocked user key: it decrypts every personal item. Zeroized on
/// drop; `Debug` prints nothing of it.
#[derive(Clone)]
pub struct UserKey(SymmetricKey);

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserKey([redacted])")
    }
}

impl UserKey {
    pub(crate) fn from_symmetric(key: SymmetricKey) -> Self {
        Self(key)
    }

    /// From its 64 bytes (`enc || mac`), as [`export`](Self::export) gave
    /// them.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] unless 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SymmetricKey::from_bytes(bytes).map(Self)
    }

    /// Its 64 bytes, for the caller to seal (never store them in clear).
    pub fn export(&self) -> SecretBox<[u8; 64]> {
        let mut out = Box::new([0u8; 64]);
        out.copy_from_slice(self.0.to_bytes().as_ref());
        SecretBox::new(out)
    }

    pub(crate) fn symmetric(&self) -> &SymmetricKey {
        &self.0
    }
}

/// What the user key was unlocked from: kept beside a sealed user key so a
/// later sync can tell whether it is still valid.
///
/// Its `Debug` leaves out the protected key: with it, the master password
/// can be guessed offline.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyState {
    /// The protected symmetric key (`profile.key`), an `EncString`.
    pub protected_key: String,
    /// The account's KDF when unlocked, if known.
    pub kdf: Option<Kdf>,
}

impl fmt::Debug for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyState")
            .field("protected_key", &"[redacted]")
            .field("kdf", &self.kdf)
            .finish()
    }
}

/// A login's metadata: nothing encrypted, nothing secret.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoginInfo {
    /// The item's id.
    pub id: CipherId,
    /// Its folder.
    pub folder_id: Option<FolderId>,
    /// The server's revision date (RFC 3339).
    pub revision_date: Option<String>,
    /// Whether it has a password.
    pub has_password: bool,
    /// Whether it has a TOTP secret.
    pub has_totp: bool,
}

/// A login URI, decrypted.
#[non_exhaustive]
pub struct LoginUri {
    /// The URI.
    pub uri: SecretString,
    /// Its match type; `None` means the caller's default.
    pub match_type: Option<UriMatch>,
}

impl fmt::Debug for LoginUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginUri")
            .field("uri", &"[redacted]")
            .field("match_type", &self.match_type)
            .finish()
    }
}

/// Proof that the caller had an item confirmed (by the user) for a
/// change: from [`Vault::confirm_item`], bound to the item's id and
/// revision, and used up by [`Vault::update_login`].
#[derive(Debug)]
pub struct ConfirmedItem {
    id: CipherId,
    // Read by `update_login` (behind `std`).
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    revision: Option<String>,
}

impl ConfirmedItem {
    /// The item it confirms.
    pub fn id(&self) -> &CipherId {
        &self.id
    }
}

/// A new login.
pub struct LoginDraft {
    /// The item name.
    pub name: SecretString,
    /// The username.
    pub username: Option<SecretString>,
    /// The password.
    pub password: Option<SecretString>,
    /// A TOTP secret (`otpauth://`, `steam://` or base32).
    pub totp: Option<SecretString>,
    /// URIs, with their match types.
    pub uris: Vec<(SecretString, Option<UriMatch>)>,
    /// The folder.
    pub folder_id: Option<FolderId>,
}

impl fmt::Debug for LoginDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginDraft")
            .field("uris", &self.uris.len())
            .field("folder_id", &self.folder_id)
            .finish_non_exhaustive()
    }
}

/// Changes to a login: each `Some` field replaces the item's. Any update
/// needs a [`ConfirmedItem`].
#[derive(Default)]
pub struct LoginUpdate {
    /// A new name.
    pub name: Option<SecretString>,
    /// A new username.
    pub username: Option<SecretString>,
    /// A new password; a replaced one goes to the password history.
    pub password: Option<SecretString>,
    /// A new TOTP secret.
    pub totp: Option<SecretString>,
    /// URIs to add (existing ones are kept).
    pub add_uris: Vec<(SecretString, Option<UriMatch>)>,
}

impl fmt::Debug for LoginUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginUpdate")
            .field("name", &self.name.is_some())
            .field("username", &self.username.is_some())
            .field("password", &self.password.is_some())
            .field("totp", &self.totp.is_some())
            .field("add_uris", &self.add_uris.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UriWire {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default, rename = "match")]
    match_type: Option<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginWire {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<UriWire>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherWire {
    id: String,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    login: Option<LoginWire>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    revision_date: Option<String>,
    #[serde(default)]
    deleted_date: Option<String>,
}

const LOGIN: u8 = 1;

struct StoredUri {
    uri: Option<String>,
    match_type: Option<UriMatch>,
}

struct StoredLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Vec<StoredUri>,
}

struct StoredCipher {
    id: CipherId,
    folder_id: Option<FolderId>,
    revision: Option<String>,
    kind: u8,
    key: Option<String>,
    name: Option<String>,
    login: Option<StoredLogin>,
    // Read by `update_login` (behind `std`).
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    raw: Value,
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.is_empty())
}

impl StoredCipher {
    /// `None` for items that aren't personal and live.
    fn parse(raw: Value) -> Option<Self> {
        let w: CipherWire = serde_json::from_value(raw.clone()).ok()?;
        if w.organization_id.is_some() || w.deleted_date.is_some() {
            return None;
        }
        let login = w.login.map(|l| StoredLogin {
            username: nonempty(l.username),
            password: nonempty(l.password),
            totp: nonempty(l.totp),
            uris: l
                .uris
                .unwrap_or_default()
                .into_iter()
                .map(|u| StoredUri {
                    uri: nonempty(u.uri),
                    match_type: u.match_type.and_then(UriMatch::from_wire),
                })
                .collect(),
        });
        Some(Self {
            id: CipherId(w.id),
            folder_id: w.folder_id.map(FolderId),
            revision: w.revision_date,
            kind: w.kind,
            key: nonempty(w.key),
            name: w.name,
            login,
            raw,
        })
    }

    fn info(&self) -> Option<LoginInfo> {
        let login = self.login.as_ref().filter(|_| self.kind == LOGIN)?;
        Some(LoginInfo {
            id: self.id.clone(),
            folder_id: self.folder_id.clone(),
            revision_date: self.revision.clone(),
            has_password: login.password.is_some(),
            has_totp: login.totp.is_some(),
        })
    }

    /// The key this item's fields are encrypted with: its own item key,
    /// or the user key.
    fn item_key(&self, user: &UserKey) -> Result<SymmetricKey> {
        match &self.key {
            Some(k) => k.parse::<EncString>()?.decrypt_key(user.symmetric()),
            None => Ok(user.symmetric().clone()),
        }
    }

    fn login(&self) -> Result<&StoredLogin> {
        match &self.login {
            Some(l) if self.kind == LOGIN => Ok(l),
            _ => Err(Error::NotALogin(self.id.clone())),
        }
    }
}

fn decrypt_opt(s: Option<&String>, key: &SymmetricKey) -> Result<Option<SecretString>> {
    s.map(|s| s.parse::<EncString>()?.decrypt_string(key))
        .transpose()
}

#[cfg(feature = "std")]
fn encrypt_str(s: &SecretString, key: &SymmetricKey) -> Result<String> {
    Ok(EncString::encrypt(key, s.expose_secret().as_bytes())?.to_string())
}

#[cfg(feature = "std")]
fn uri_json(uri: &SecretString, m: Option<UriMatch>, key: &SymmetricKey) -> Result<Value> {
    let checksum = B64.encode(Sha256::digest(uri.expose_secret().as_bytes()));
    Ok(json!({
        "uri": encrypt_str(uri, key)?,
        "match": m.map(UriMatch::to_wire),
        "uriChecksum": EncString::encrypt(key, checksum.as_bytes())?.to_string(),
    }))
}

/// The fields of a cipher response that a cipher request takes back.
#[cfg(feature = "std")]
const REQUEST_FIELDS: &[&str] = &[
    "type",
    "folderId",
    "organizationId",
    "name",
    "notes",
    "favorite",
    "login",
    "card",
    "identity",
    "secureNote",
    "sshKey",
    "fields",
    "passwordHistory",
    "reprompt",
    "key",
    "attachments2",
];

/// The personal vault: the user key (while unlocked), the key state, and
/// the synced folders and items.
pub struct Vault {
    key: Option<UserKey>,
    state: KeyState,
    folders: Vec<(FolderId, Option<EncString>)>,
    ciphers: Vec<StoredCipher>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("locked", &self.key.is_none())
            .field("folders", &self.folders.len())
            .field("items", &self.ciphers.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// An unlocked, empty vault from a user key the caller kept (unsealed)
    /// and the [`KeyState`] it was kept with. Call
    /// [`apply_sync`](Self::apply_sync) next: it checks the key is still
    /// valid.
    pub fn open(key: UserKey, state: KeyState) -> Self {
        Self {
            key: Some(key),
            state,
            folders: Vec::new(),
            ciphers: Vec::new(),
        }
    }

    /// Unlocks with the master key: decrypts the protected symmetric key
    /// (`profile.key` from a sync, or [`Session::protected_key`]).
    ///
    /// # Errors
    ///
    /// [`Error::MacMismatch`] for a wrong master password, and the
    /// `EncString` errors.
    pub fn unlock(master_key: &MasterKey, protected_key: &str, kdf: Option<Kdf>) -> Result<Self> {
        let key = master_key.unlock(&protected_key.parse()?)?;
        Ok(Self::open(
            key,
            KeyState {
                protected_key: protected_key.to_owned(),
                kdf,
            },
        ))
    }

    /// Whether the user key is gone.
    pub fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    /// Drops the user key (zeroizing it). Items stay, encrypted.
    pub fn lock(&mut self) {
        self.key = None;
    }

    /// What the key was unlocked from, to keep beside the sealed key.
    pub fn key_state(&self) -> &KeyState {
        &self.state
    }

    /// The user key's bytes, for the caller to seal.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`].
    pub fn export_user_key(&self) -> Result<SecretBox<[u8; 64]>> {
        Ok(self.user_key()?.export())
    }

    fn user_key(&self) -> Result<&UserKey> {
        self.key.as_ref().ok_or(Error::Locked)
    }

    fn key_changed(&mut self, change: KeyChange) -> Error {
        tracing::debug!(
            ?change,
            "openwarden: vault key changed on the server; locking"
        );
        self.lock();
        Error::KeyChanged(change)
    }

    /// Checks the account's current KDF (from [`Session::kdf`] or a
    /// prelogin) against the one the key was unlocked under; on a change,
    /// locks.
    ///
    /// # Errors
    ///
    /// [`Error::KeyChanged`] with [`KeyChange::Kdf`].
    pub fn check_kdf(&mut self, kdf: &Kdf) -> Result<()> {
        match self.state.kdf {
            Some(known) if known != *kdf => Err(self.key_changed(KeyChange::Kdf)),
            Some(_) => Ok(()),
            None => {
                self.state.kdf = Some(*kdf);
                Ok(())
            }
        }
    }

    /// Checks a fresh session's view of the keys (protected key and KDF);
    /// on a change, locks.
    ///
    /// # Errors
    ///
    /// [`Error::KeyChanged`].
    #[cfg(feature = "std")]
    pub fn check_session(&mut self, session: &Session) -> Result<()> {
        if session
            .protected_key()
            .is_some_and(|k| k != self.state.protected_key)
        {
            return Err(self.key_changed(KeyChange::ProtectedKey));
        }
        match session.kdf() {
            Some(kdf) => self.check_kdf(&kdf),
            None => Ok(()),
        }
    }

    /// Takes a sync: checks the keys are unchanged, then replaces the
    /// folders and items (personal, not deleted; organization items are
    /// skipped in v1).
    ///
    /// # Errors
    ///
    /// [`Error::Locked`], and [`Error::KeyChanged`] (the vault locks) when
    /// the protected key differs or the user key no longer decrypts the
    /// account's private key.
    pub fn apply_sync(&mut self, data: SyncData) -> Result<()> {
        let key = self.user_key()?;
        if data
            .protected_key
            .as_deref()
            .is_some_and(|k| k != self.state.protected_key)
        {
            return Err(self.key_changed(KeyChange::ProtectedKey));
        }
        if let Some(pk) = data.private_key.as_deref() {
            // The private key's MAC is a check that the user key is the
            // account's current one. Only type 2 can be checked.
            if let Ok(enc) = pk.parse::<EncString>()
                && enc.decrypt(key.symmetric()).is_err()
            {
                return Err(self.key_changed(KeyChange::UserKey));
            }
        }
        self.folders = data.folders;
        self.ciphers = data
            .ciphers
            .into_iter()
            .filter_map(StoredCipher::parse)
            .collect();
        tracing::debug!(items = self.ciphers.len(), "openwarden: sync applied");
        Ok(())
    }

    fn cipher(&self, id: &CipherId) -> Result<&StoredCipher> {
        self.ciphers
            .iter()
            .find(|c| c.id == *id)
            .ok_or_else(|| Error::NotFound(id.clone()))
    }

    /// Every login's metadata.
    pub fn logins(&self) -> Vec<LoginInfo> {
        self.ciphers.iter().filter_map(StoredCipher::info).collect()
    }

    /// The logins with a URI matching `page`. Decrypts URIs (not
    /// passwords); an item whose URIs don't decrypt is skipped.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`].
    pub fn find_logins(&self, page: &str, opts: &MatchOptions) -> Result<Vec<LoginInfo>> {
        let user = self.user_key()?;
        let mut out = Vec::new();
        for c in &self.ciphers {
            let Some(info) = c.info() else { continue };
            match Self::cipher_matches(c, user, page, opts) {
                Ok(true) => out.push(info),
                Ok(false) => {}
                Err(_) => {
                    tracing::debug!(item = %c.id, "openwarden: item URIs did not decrypt; skipped");
                }
            }
        }
        Ok(out)
    }

    fn cipher_matches(
        c: &StoredCipher,
        user: &UserKey,
        page: &str,
        opts: &MatchOptions,
    ) -> Result<bool> {
        let key = c.item_key(user)?;
        for u in &c.login()?.uris {
            if let Some(uri) = decrypt_opt(u.uri.as_ref(), &key)?
                && uri_matches(uri.expose_secret(), u.match_type, page, opts)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// An item's name.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`], [`Error::NotFound`], and decryption errors.
    pub fn name(&self, id: &CipherId) -> Result<SecretString> {
        let c = self.cipher(id)?;
        let key = c.item_key(self.user_key()?)?;
        Ok(decrypt_opt(c.name.as_ref(), &key)?.unwrap_or_else(|| SecretString::from("")))
    }

    fn login_field(
        &self,
        id: &CipherId,
        f: impl FnOnce(&StoredLogin) -> Option<&String>,
    ) -> Result<Option<SecretString>> {
        let c = self.cipher(id)?;
        let key = c.item_key(self.user_key()?)?;
        decrypt_opt(f(c.login()?), &key)
    }

    /// A login's username.
    ///
    /// # Errors
    ///
    /// As [`name`](Self::name), and [`Error::NotALogin`].
    pub fn username(&self, id: &CipherId) -> Result<Option<SecretString>> {
        self.login_field(id, |l| l.username.as_ref())
    }

    /// A login's password: decrypted only here.
    ///
    /// # Errors
    ///
    /// As [`username`](Self::username).
    pub fn password(&self, id: &CipherId) -> Result<Option<SecretString>> {
        tracing::debug!(item = %id, "openwarden: password decrypted");
        self.login_field(id, |l| l.password.as_ref())
    }

    /// A login's TOTP secret, as stored.
    ///
    /// # Errors
    ///
    /// As [`username`](Self::username).
    pub fn totp_secret(&self, id: &CipherId) -> Result<Option<SecretString>> {
        self.login_field(id, |l| l.totp.as_ref())
    }

    /// A login's current TOTP code, at `unix_time` (seconds).
    ///
    /// # Errors
    ///
    /// As [`username`](Self::username), and [`Error::InvalidTotp`].
    pub fn totp(&self, id: &CipherId, unix_time: u64) -> Result<Option<TotpCode>> {
        self.totp_secret(id)?
            .map(|s| totp::generate(&s, unix_time))
            .transpose()
    }

    /// A login's URIs.
    ///
    /// # Errors
    ///
    /// As [`username`](Self::username).
    pub fn uris(&self, id: &CipherId) -> Result<Vec<LoginUri>> {
        let c = self.cipher(id)?;
        let key = c.item_key(self.user_key()?)?;
        let mut out = Vec::new();
        for u in &c.login()?.uris {
            if let Some(uri) = decrypt_opt(u.uri.as_ref(), &key)? {
                out.push(LoginUri {
                    uri,
                    match_type: u.match_type,
                });
            }
        }
        Ok(out)
    }

    /// The folder ids.
    pub fn folders(&self) -> Vec<FolderId> {
        self.folders.iter().map(|(id, _)| id.clone()).collect()
    }

    /// A folder's name; `None` for an unknown folder.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`], and decryption errors.
    pub fn folder_name(&self, id: &FolderId) -> Result<Option<SecretString>> {
        let key = self.user_key()?;
        match self.folders.iter().find(|(f, _)| f == id) {
            None => Ok(None),
            Some((_, None)) => Err(Error::MalformedEncString),
            Some((_, Some(name))) => name.decrypt_string(key.symmetric()).map(Some),
        }
    }

    /// Marks an item as confirmed (by the user, out of band) for one
    /// [`update_login`](Self::update_login). The token holds the item's current
    /// revision: if the item changes before the update, it no longer
    /// matches.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn confirm_item(&self, id: &CipherId) -> Result<ConfirmedItem> {
        let c = self.cipher(id)?;
        Ok(ConfirmedItem {
            id: c.id.clone(),
            revision: c.revision.clone(),
        })
    }

    /// Creates a login (encrypted with the user key) and adds it to the
    /// vault.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`], the client's errors, and [`Error::Decode`] if
    /// the server's answer isn't a personal item.
    #[cfg(feature = "std")]
    pub async fn create_login(
        &mut self,
        client: &Client,
        session: &Session,
        draft: LoginDraft,
    ) -> Result<CipherId> {
        let key = self.user_key()?.symmetric().clone();
        let enc = |s: &Option<SecretString>| s.as_ref().map(|s| encrypt_str(s, &key)).transpose();
        let uris = draft
            .uris
            .iter()
            .map(|(u, m)| uri_json(u, *m, &key))
            .collect::<Result<Vec<_>>>()?;
        let body = json!({
            "type": LOGIN,
            "folderId": draft.folder_id,
            "organizationId": null,
            "name": encrypt_str(&draft.name, &key)?,
            "notes": null,
            "favorite": false,
            "reprompt": 0,
            "fields": [],
            "passwordHistory": null,
            "login": {
                "username": enc(&draft.username)?,
                "password": enc(&draft.password)?,
                "totp": enc(&draft.totp)?,
                "uris": uris,
            },
        });
        let resp = client.post_cipher(session, &body).await?;
        let stored = StoredCipher::parse(resp).ok_or(Error::Decode {
            endpoint: "cipher create",
            line: 0,
            column: 0,
        })?;
        let id = stored.id.clone();
        tracing::debug!(item = %id, "openwarden: login created");
        self.ciphers.push(stored);
        Ok(id)
    }

    /// Updates a login. Every update needs `confirmed`, from
    /// [`confirm_item`](Self::confirm_item) for this item at its current
    /// revision, whatever it changes (name, username, password, TOTP or
    /// URIs); without one nothing is sent. A replaced password goes to the
    /// item's password history. Fields openwarden doesn't model are sent back
    /// as they came.
    ///
    /// # Errors
    ///
    /// [`Error::UpdateRefused`] without a confirmation,
    /// [`Error::ConfirmationMismatch`] with one for another item or
    /// revision, [`Error::Locked`], [`Error::NotFound`],
    /// [`Error::NotALogin`], and the client's errors.
    #[cfg(feature = "std")]
    pub async fn update_login(
        &mut self,
        client: &Client,
        session: &Session,
        id: &CipherId,
        update: LoginUpdate,
        confirmed: Option<ConfirmedItem>,
    ) -> Result<()> {
        let body = self.update_body(id, &update, confirmed)?;
        let resp = client.put_cipher(session, id, &body).await?;
        let stored = StoredCipher::parse(resp)
            .filter(|c| c.id == *id)
            .ok_or(Error::Decode {
                endpoint: "cipher update",
                line: 0,
                column: 0,
            })?;
        tracing::debug!(item = %id, "openwarden: login updated");
        if let Some(slot) = self.ciphers.iter_mut().find(|c| c.id == *id) {
            *slot = stored;
        }
        Ok(())
    }

    /// Deletes an item: to the trash, or for good with `permanent`. Like
    /// an update, it needs `confirmed` for this item at its current
    /// revision.
    ///
    /// # Errors
    ///
    /// [`Error::UpdateRefused`] without a confirmation,
    /// [`Error::ConfirmationMismatch`] with one for another item or
    /// revision, [`Error::NotFound`], and the client's errors.
    #[cfg(feature = "std")]
    pub async fn delete_item(
        &mut self,
        client: &Client,
        session: &Session,
        id: &CipherId,
        permanent: bool,
        confirmed: Option<ConfirmedItem>,
    ) -> Result<()> {
        let c = self.cipher(id)?;
        match confirmed {
            None => return Err(Error::UpdateRefused(id.clone())),
            Some(t) if t.id != *id || t.revision != c.revision => {
                return Err(Error::ConfirmationMismatch(id.clone()));
            }
            Some(_) => {}
        }
        client.delete_cipher(session, id, permanent).await?;
        tracing::debug!(item = %id, permanent, "openwarden: item deleted");
        self.ciphers.retain(|c| c.id != *id);
        Ok(())
    }

    #[cfg(feature = "std")]
    fn update_body(
        &self,
        id: &CipherId,
        update: &LoginUpdate,
        confirmed: Option<ConfirmedItem>,
    ) -> Result<Value> {
        let c = self.cipher(id)?;
        let login = c.login()?;
        let key = c.item_key(self.user_key()?)?;
        // Every change to an existing item needs the user's confirmation:
        // a new URI or TOTP secret is as dangerous as a new password (an
        // added URI makes the item match, and fill, another site).
        match confirmed {
            None => return Err(Error::UpdateRefused(id.clone())),
            Some(t) if t.id != *id || t.revision != c.revision => {
                return Err(Error::ConfirmationMismatch(id.clone()));
            }
            Some(_) => {}
        }
        let old_password =
            decrypt_opt(login.password.as_ref(), &key)?.filter(|p| !p.expose_secret().is_empty());
        let mut history_entry = None;
        if let (Some(new), Some(old)) = (&update.password, &old_password)
            && new.expose_secret() != old.expose_secret()
        {
            history_entry = Some(json!({
                "password": encrypt_str(old, &key)?,
                "lastUsedDate": rfc3339_now(),
            }));
        }

        let raw = c.raw.as_object().ok_or(Error::NotALogin(id.clone()))?;
        let mut body = Map::new();
        for f in REQUEST_FIELDS {
            if let Some(v) = raw.get(*f) {
                body.insert((*f).to_owned(), v.clone());
            }
        }
        body.insert("lastKnownRevisionDate".to_owned(), json!(c.revision));
        if let Some(name) = &update.name {
            body.insert("name".to_owned(), json!(encrypt_str(name, &key)?));
        }
        if let Some(entry) = history_entry {
            let history = body.entry("passwordHistory").or_insert(Value::Null);
            match history {
                Value::Array(a) => a.insert(0, entry),
                _ => *history = json!([entry]),
            }
        }
        let login_v = body.entry("login").or_insert_with(|| json!({}));
        let Value::Object(lobj) = login_v else {
            return Err(Error::NotALogin(id.clone()));
        };
        for (field, value) in [
            ("username", &update.username),
            ("password", &update.password),
            ("totp", &update.totp),
        ] {
            if let Some(v) = value {
                lobj.insert(field.to_owned(), json!(encrypt_str(v, &key)?));
            }
        }
        if update.password.is_some() {
            lobj.insert("passwordRevisionDate".to_owned(), json!(rfc3339_now()));
        }
        if !update.add_uris.is_empty() {
            let uris = lobj.entry("uris").or_insert(Value::Null);
            if !uris.is_array() {
                *uris = json!([]);
            }
            if let Value::Array(a) = uris {
                for (u, m) in &update.add_uris {
                    a.push(uri_json(u, *m, &key)?);
                }
            }
        }
        Ok(Value::Object(body))
    }
}

/// Now, as RFC 3339 UTC with milliseconds.
#[cfg(feature = "std")]
fn rfc3339_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs(), d.subsec_millis())
}

/// Seconds since the epoch as RFC 3339 UTC (civil-from-days, Howard
/// Hinnant's algorithm).
#[cfg(any(feature = "std", test))]
fn rfc3339(secs: u64, millis: u32) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(rfc3339(1_798_761_599, 999), "2026-12-31T23:59:59.999Z");
    }

    #[test]
    #[cfg(feature = "std")]
    fn cipher_id_segment() {
        assert!(CipherId::new("0b5c-AF12").as_url_segment().is_ok());
        assert!(CipherId::new("../x").as_url_segment().is_err());
        assert!(CipherId::new("").as_url_segment().is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let k = UserKey(SymmetricKey::zeroed());
        assert_eq!(format!("{k:?}"), "UserKey([redacted])");
    }
}
