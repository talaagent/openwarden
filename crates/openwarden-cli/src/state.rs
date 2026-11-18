//! The state directory: `openwarden.json` (settings, the account, and
//! sealed keys and tokens) and `openwarden-vault.enc` (the last sync
//! response, encrypted).
//!
//! What is in clear: the server URL, the device id, the email, user id,
//! KDF, the protected key (an `EncString` under the master key, as `bw`
//! keeps it), the API key's client id and the last revision and sync
//! times. Everything else is sealed:
//!
//! - the user key, under the session key (`BW_SESSION`); dropped by `lock`;
//! - a random state key, under the user key;
//! - the tokens and the vault cache, under the state key, so they outlive a
//!   `lock` and a fresh session key.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use openwarden::{EncString, ExposeSecret as _, Kdf, SecretString, Session, SymmetricKey, UserKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CliError, Result};

const STATE_FILE: &str = "openwarden.json";
const CACHE_FILE: &str = "openwarden-vault.enc";

/// Where state lives: `$OPENWARDEN_APPDATA_DIR`, else
/// `$BITWARDENCLI_APPDATA_DIR` (beside bw's own `data.json`, which `ow`
/// never touches), else `$XDG_CONFIG_HOME/openwarden` or
/// `~/.config/openwarden`.
pub fn app_dir() -> PathBuf {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    if let Some(dir) = var("OPENWARDEN_APPDATA_DIR").or_else(|| var("BITWARDENCLI_APPDATA_DIR")) {
        return PathBuf::from(dir);
    }
    let config = var("XDG_CONFIG_HOME").map_or_else(
        || PathBuf::from(var("HOME").unwrap_or_default()).join(".config"),
        PathBuf::from,
    );
    config.join("openwarden")
}

/// `openwarden.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    /// The server's base URL; Bitwarden's US cloud when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// This install's device identifier (a random UUID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// The logged-in account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
}

/// The logged-in account.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub email: String,
    #[serde(default)]
    pub user_id: Option<String>,
    pub kdf: Kdf,
    /// The protected symmetric key: an `EncString` under the master key.
    pub protected_key: String,
    /// For an API-key login: the client id (the secret is never stored).
    #[serde(default)]
    pub api_client_id: Option<String>,
    /// The state key, under the user key.
    #[serde(default)]
    pub sealed_state_key: Option<EncString>,
    /// The tokens, under the state key.
    #[serde(default)]
    pub sealed_tokens: Option<EncString>,
    /// The user key, under the session key: `None` when locked.
    #[serde(default)]
    pub sealed_user_key: Option<EncString>,
    /// The account's revision date at the last sync (ms since the epoch).
    #[serde(default)]
    pub last_revision_ms: Option<i64>,
    /// When the last sync ran (ms since the epoch).
    #[serde(default)]
    pub last_sync_ms: Option<i64>,
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sealed = |s: &Option<EncString>| s.as_ref().map(|_| "[sealed]");
        f.debug_struct("Account")
            .field("email", &self.email)
            .field("user_id", &self.user_id)
            .field("kdf", &self.kdf)
            .field("protected_key", &"[redacted]")
            .field("api_client_id", &self.api_client_id)
            .field("sealed_state_key", &sealed(&self.sealed_state_key))
            .field("sealed_tokens", &sealed(&self.sealed_tokens))
            .field("sealed_user_key", &sealed(&self.sealed_user_key))
            .field("last_revision_ms", &self.last_revision_ms)
            .field("last_sync_ms", &self.last_sync_ms)
            .finish()
    }
}

/// The state directory and its files.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    fn cache_path(&self) -> PathBuf {
        self.dir.join(CACHE_FILE)
    }

    /// The state, or the default when there is none yet.
    pub fn load(&self) -> Result<State> {
        let path = self.state_path();
        match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| CliError::json("the state file", &e))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(CliError::io(path, e)),
        }
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(state).map_err(|e| CliError::json("the state", &e))?;
        self.write(&self.state_path(), &bytes)
    }

    /// The sealed vault cache, if there is one.
    pub fn load_cache(&self) -> Result<Option<EncString>> {
        let path = self.cache_path();
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text.trim().parse()?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CliError::io(path, e)),
        }
    }

    pub fn save_cache(&self, sealed: &EncString) -> Result<()> {
        self.write(&self.cache_path(), sealed.to_string().as_bytes())
    }

    pub fn remove_cache(&self) -> Result<()> {
        let path = self.cache_path();
        match fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(CliError::io(path, e)),
            _ => Ok(()),
        }
    }

    /// Writes `path` whole: a private temporary file, then a rename.
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        create_private_dir(&self.dir)?;
        let tmp = path.with_extension("tmp");
        let mut file = private_file(&tmp).map_err(|e| CliError::io(&tmp, e))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| CliError::io(&tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| CliError::io(path, e))
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CliError::io(dir, e))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| CliError::io(dir, e))
}

#[cfg(unix)]
fn private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// A new random device identifier (a version 4 UUID).
pub fn new_device_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| CliError::Usage("no system randomness"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().fold(String::with_capacity(32), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    });
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// A session key: printed once (base64), sealing the user key.
pub struct SessionKey(SymmetricKey);

impl SessionKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SymmetricKey::generate()?))
    }

    /// From `BW_SESSION`'s base64.
    pub fn from_base64(text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(B64.decode(text.trim()).map_err(|_| CliError::BadSession)?);
        Ok(Self(
            SymmetricKey::from_bytes(&bytes).map_err(|_| CliError::BadSession)?,
        ))
    }

    /// The base64 text to hand to the user.
    pub fn to_base64(&self) -> SecretString {
        SecretString::from(B64.encode(self.0.to_bytes().as_slice()))
    }

    pub fn seal(&self, user: &UserKey) -> Result<EncString> {
        Ok(EncString::encrypt(&self.0, user.export().expose_secret())?)
    }

    /// The user key, or [`CliError::BadSession`].
    pub fn open(&self, sealed: &EncString) -> Result<UserKey> {
        let bytes = sealed.decrypt(&self.0).map_err(|_| CliError::BadSession)?;
        Ok(UserKey::from_bytes(&bytes)?)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey([redacted])")
    }
}

/// The unlocked keys: the user key (items) and the state key (tokens and
/// the cache).
pub struct Keys {
    pub user: SymmetricKey,
    pub state: SymmetricKey,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys([redacted])")
    }
}

impl Keys {
    /// The user key's symmetric key.
    pub fn user_symmetric(user: &UserKey) -> Result<SymmetricKey> {
        Ok(SymmetricKey::from_bytes(user.export().expose_secret())?)
    }

    /// Opens the state key sealed under `user`.
    pub fn open(user: &UserKey, sealed_state_key: &EncString) -> Result<Self> {
        let user = Self::user_symmetric(user)?;
        let state = sealed_state_key.decrypt_key(&user)?;
        Ok(Self { user, state })
    }

    /// A new state key, and its seal under `user`.
    pub fn generate(user: &UserKey) -> Result<(Self, EncString)> {
        let user = Self::user_symmetric(user)?;
        let state = SymmetricKey::generate()?;
        let sealed = EncString::encrypt(&user, state.to_bytes().as_slice())?;
        Ok((Self { user, state }, sealed))
    }

    pub fn seal_cache(&self, body: &[u8]) -> Result<EncString> {
        Ok(EncString::encrypt(&self.state, body)?)
    }

    pub fn open_cache(&self, sealed: &EncString) -> Result<Zeroizing<Vec<u8>>> {
        Ok(sealed.decrypt(&self.state)?)
    }

    pub fn seal_tokens(&self, session: &Session, now_secs: u64) -> Result<EncString> {
        let wire = TokensWire {
            access_token: Cow::Borrowed(session.access_token().expose_secret()),
            refresh_token: session
                .refresh_token()
                .map(|t| Cow::Borrowed(t.expose_secret())),
            expires_at: now_secs.saturating_add(session.expires_in().as_secs()),
        };
        let json = Zeroizing::new(
            serde_json::to_vec(&wire).map_err(|e| CliError::json("the tokens", &e))?,
        );
        Ok(EncString::encrypt(&self.state, &json)?)
    }

    /// The session the tokens make; it may have expired.
    pub fn open_tokens(&self, sealed: &EncString, now_secs: u64) -> Result<Session> {
        let json = sealed.decrypt(&self.state)?;
        let wire: TokensWire<'_> =
            serde_json::from_slice(&json).map_err(|e| CliError::json("the sealed tokens", &e))?;
        let left = core::time::Duration::from_secs(wire.expires_at.saturating_sub(now_secs));
        let session = Session::from_token(SecretString::from(wire.access_token.as_ref()), left)?;
        Ok(match wire.refresh_token {
            Some(rt) => session.with_refresh_token(SecretString::from(rt.as_ref())),
            None => session,
        })
    }
}

/// The tokens, as sealed: borrowed from the session or the decrypted
/// (zeroized) buffer.
#[derive(Serialize, Deserialize)]
struct TokensWire<'a> {
    #[serde(borrow)]
    access_token: Cow<'a, str>,
    #[serde(borrow, default)]
    refresh_token: Option<Cow<'a, str>>,
    expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            email: "alice@example.org".into(),
            user_id: Some("u1".into()),
            kdf: Kdf::Pbkdf2 {
                iterations: 600_000,
            },
            protected_key: "2.secret-looking".into(),
            api_client_id: None,
            sealed_state_key: None,
            sealed_tokens: None,
            sealed_user_key: None,
            last_revision_ms: None,
            last_sync_ms: None,
        }
    }

    #[test]
    fn debug_redacts_the_protected_key() {
        let out = format!("{:?}", account());
        assert!(!out.contains("secret-looking"), "{out}");
        assert!(out.contains("alice@example.org"));
    }

    #[test]
    fn keys_debug_is_redacted() {
        let user = UserKey::from_bytes(&[7u8; 64]).unwrap();
        let (keys, _) = Keys::generate(&user).unwrap();
        assert_eq!(format!("{keys:?}"), "Keys([redacted])");
        let session = SessionKey::generate().unwrap();
        assert_eq!(format!("{session:?}"), "SessionKey([redacted])");
    }

    #[test]
    fn session_key_round_trip() {
        let user = UserKey::from_bytes(&[7u8; 64]).unwrap();
        let session = SessionKey::generate().unwrap();
        let sealed = session.seal(&user).unwrap();
        let again = SessionKey::from_base64(session.to_base64().expose_secret()).unwrap();
        let opened = again.open(&sealed).unwrap();
        assert_eq!(
            opened.export().expose_secret(),
            user.export().expose_secret()
        );
        let other = SessionKey::generate().unwrap();
        assert!(matches!(other.open(&sealed), Err(CliError::BadSession)));
    }

    #[test]
    fn tokens_round_trip() {
        let user = UserKey::from_bytes(&[7u8; 64]).unwrap();
        let (_, sealed_key) = Keys::generate(&user).unwrap();
        let keys = Keys::open(&user, &sealed_key).unwrap();
        let session = Session::from_token(
            SecretString::from("at"),
            core::time::Duration::from_secs(3600),
        )
        .unwrap()
        .with_refresh_token(SecretString::from("rt"));
        let sealed = keys.seal_tokens(&session, 1000).unwrap();
        let back = keys.open_tokens(&sealed, 1000).unwrap();
        assert_eq!(back.access_token().expose_secret(), "at");
        assert_eq!(back.refresh_token().unwrap().expose_secret(), "rt");
        assert!(!back.is_expired());
        assert!(keys.open_tokens(&sealed, 1000 + 3600).unwrap().is_expired());
    }

    #[test]
    fn device_ids_are_uuid_v4() {
        let id = new_device_id().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
    }
}
