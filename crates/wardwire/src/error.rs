//! The crate's error type.
//!
//! No variant carries a secret, a name, a username or a URI: only item ids,
//! endpoint names, status codes and positions. Server bodies and serde
//! messages (which can quote the input) are never kept.

use crate::vault::CipherId;

/// A `Result` with [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// What changed on the server that invalidates the unlocked key.
///
/// On any of these the [`Vault`](crate::Vault) locks itself: the caller
/// should drop whatever sealed copy of the user key it holds and unlock
/// again (with the master password).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyChange {
    /// The protected symmetric key (`profile.key`) differs: the master
    /// password changed or the user key was rotated.
    ProtectedKey,
    /// The account's KDF or its parameters differ.
    Kdf,
    /// The user key no longer authenticates the account's data (a
    /// rotation the protected key alone didn't show).
    UserKey,
}

/// An error from wardwire.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A transport error (connect, TLS, timeout, body read).
    #[error("http error on {endpoint}")]
    Http {
        /// Which call failed.
        endpoint: &'static str,
        /// The underlying error, without its URL.
        #[source]
        source: reqwest::Error,
    },
    /// The server answered with an error status.
    #[error("{endpoint} returned HTTP {status}{}", oauth_error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default())]
    Status {
        /// Which call failed.
        endpoint: &'static str,
        /// The HTTP status code.
        status: u16,
        /// The OAuth `error` code (`invalid_client`, `invalid_grant`, ...),
        /// when the body had a well-formed one.
        oauth_error: Option<String>,
    },
    /// A response body was larger than the client's limit
    /// ([`Client::with_max_body_size`](crate::Client::with_max_body_size)).
    #[error("{endpoint} response larger than {limit} bytes")]
    BodyTooLarge {
        /// Which call's body.
        endpoint: &'static str,
        /// The limit, in bytes.
        limit: usize,
    },
    /// A token lifetime too large to represent as a point in time.
    #[error("token lifetime out of range")]
    InvalidExpiry,
    /// A response body didn't parse. Only its position is kept: serde's
    /// own message can quote the body.
    #[error("malformed {endpoint} response at line {line}, column {column}")]
    Decode {
        /// Which call's body.
        endpoint: &'static str,
        /// The line of the error.
        line: usize,
        /// The column of the error.
        column: usize,
    },
    /// The server's KDF parameters are outside the [`KdfPolicy`](crate::KdfPolicy):
    /// too weak (a downgrade) or too expensive.
    #[error("KDF parameters rejected: {0}")]
    KdfRejected(&'static str),
    /// The server named a KDF this crate doesn't know.
    #[error("unknown KDF type {0}")]
    UnknownKdf(u8),
    /// An `EncString` didn't parse.
    #[error("malformed EncString")]
    MalformedEncString,
    /// An `EncString` of a type this crate refuses or doesn't support
    /// (0 and 1 are unauthenticated; RSA and COSE are not in v1).
    #[error("unsupported EncString type {0}")]
    UnsupportedEncType(u8),
    /// The MAC didn't verify: wrong key, or tampered data.
    #[error("MAC verification failed")]
    MacMismatch,
    /// The plaintext had bad padding (after a good MAC: a buggy writer).
    #[error("bad padding")]
    Padding,
    /// A decrypted value that should be text isn't UTF-8.
    #[error("decrypted value is not UTF-8")]
    NotUtf8,
    /// A key had the wrong length.
    #[error("invalid key length")]
    InvalidKey,
    /// The vault is locked: no user key.
    #[error("vault is locked")]
    Locked,
    /// The server shows the key is no longer valid; the vault locked.
    #[error("vault key changed on the server ({0:?}); vault locked")]
    KeyChanged(KeyChange),
    /// No (personal, live) item with that id.
    #[error("no item {0}")]
    NotFound(CipherId),
    /// The item is not a login.
    #[error("item {0} is not a login")]
    NotALogin(CipherId),
    /// An update to an existing item came without a
    /// [`ConfirmedItem`](crate::ConfirmedItem).
    #[error("refusing to change item {0} without a confirmation")]
    UpdateRefused(CipherId),
    /// The [`ConfirmedItem`](crate::ConfirmedItem) is for another item, or the
    /// item changed since it was confirmed.
    #[error("confirmation does not match item {0} (another item, or it changed)")]
    ConfirmationMismatch(CipherId),
    /// A TOTP secret didn't parse.
    #[error("invalid TOTP secret")]
    InvalidTotp,
    /// A URL given to the client didn't parse.
    #[error("invalid server URL")]
    InvalidUrl,
}

impl Error {
    pub(crate) fn http(endpoint: &'static str, source: reqwest::Error) -> Self {
        Self::Http {
            endpoint,
            source: source.without_url(),
        }
    }

    pub(crate) fn decode(endpoint: &'static str, e: &serde_json::Error) -> Self {
        Self::Decode {
            endpoint,
            line: e.line(),
            column: e.column(),
        }
    }
}
