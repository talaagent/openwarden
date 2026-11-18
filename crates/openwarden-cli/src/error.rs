//! The command's errors. Like the library's, they carry no secrets and no
//! server or serde text: item ids, file paths, positions and fixed
//! messages only.

use std::io;
use std::path::PathBuf;

use bpaf_kit::report::Coded;

/// Everything `ow` can fail with.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// From the library: its messages are already free of secrets.
    #[error(transparent)]
    Vault(#[from] openwarden::Error),
    #[error("you are not logged in")]
    NotLoggedIn,
    #[error("you are already logged in as {0}")]
    AlreadyLoggedIn(String),
    #[error("logout required before changing the server")]
    LogoutRequired,
    #[error("vault is locked: unlock it and set BW_SESSION to the session key it prints")]
    Locked,
    #[error("the session key in BW_SESSION doesn't open this vault")]
    BadSession,
    #[error("invalid master password")]
    BadPassword,
    #[error("{0}")]
    Usage(&'static str),
    #[error("not found")]
    NotFound,
    #[error("more than one result was found: {}", .0.join(", "))]
    Ambiguous(Vec<String>),
    #[error("{0} is not supported yet")]
    Unsupported(&'static str),
    #[error(
        "login refused: wrong email or master password, or the account uses two-step login (not supported yet)"
    )]
    LoginRefused,
    #[error("the login has expired: log in again")]
    LoginExpired,
    #[error("the account's keys changed on the server: log in again")]
    KeyChanged,
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("writing the output: {0}")]
    Output(#[source] io::Error),
    #[error("reading stdin: {0}")]
    Stdin(#[source] io::Error),
    #[error("{0} is not valid (line {1}, column {2})")]
    Json(&'static str, usize, usize),
    #[error("the encoded input is not valid base64")]
    Base64,
    #[error("item {0} could not be decrypted")]
    Decrypt(String),
}

impl CliError {
    /// A JSON error, by position only: serde's message can quote the input.
    pub fn json(what: &'static str, e: &serde_json::Error) -> Self {
        Self::Json(what, e.line(), e.column())
    }

    /// An I/O error on `path`.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Coded for CliError {
    fn code(&self) -> &str {
        match self {
            Self::Vault(e) => match e {
                openwarden::Error::Http { .. } => "http",
                openwarden::Error::Status { .. } => "status",
                openwarden::Error::MacMismatch => "mac_mismatch",
                openwarden::Error::KdfRejected(_) => "kdf_rejected",
                _ => "vault",
            },
            Self::NotLoggedIn => "not_logged_in",
            Self::AlreadyLoggedIn(_) => "already_logged_in",
            Self::LogoutRequired => "logout_required",
            Self::Locked => "locked",
            Self::BadSession => "bad_session",
            Self::BadPassword => "bad_password",
            Self::Usage(_) => "usage",
            Self::NotFound => "not_found",
            Self::Ambiguous(_) => "ambiguous",
            Self::Unsupported(_) => "unsupported",
            Self::LoginRefused => "login_refused",
            Self::LoginExpired => "login_expired",
            Self::KeyChanged => "key_changed",
            Self::Io { .. } => "io",
            Self::Output(_) => "output",
            Self::Stdin(_) => "stdin",
            Self::Json(..) => "json",
            Self::Base64 => "base64",
            Self::Decrypt(_) => "decrypt",
        }
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            _ => 1,
        }
    }
}

/// The command's result.
pub type Result<T, E = CliError> = core::result::Result<T, E>;
