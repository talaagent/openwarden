//! `config`, `login`, `unlock`, `lock`, `logout`, `sync` and `status`.

use openwarden::{
    EncString, ExposeSecret as _, Kdf, KdfPolicy, MasterKey, SecretString, ServerUrls, UserKey,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{Ctx, api_key, expired, iso8601, now_secs, parse_sync, read_password};
use crate::error::{CliError, Result};
use crate::output;
use crate::state::{Account, Keys, SessionKey};
use crate::{Common, PasswordSource};

/// Bitwarden's US cloud, used when no server is set.
const DEFAULT_SERVER: &str = "https://vault.bitwarden.com";

/// `config server [URL]`.
pub fn config(ctx: &mut Ctx, setting: &str, value: Option<&str>, common: &Common) -> Result<()> {
    if setting != "server" {
        return Err(CliError::Unsupported("settings other than `server`"));
    }
    let Some(url) = value else {
        let url = ctx.state.server_url.as_deref().unwrap_or(DEFAULT_SERVER);
        return output::message(url, common);
    };
    if ctx.state.account.is_some() {
        return Err(CliError::LogoutRequired);
    }
    let url = url.trim().trim_end_matches('/');
    ctx.state.server_url = if url.is_empty() || url == "null" {
        None
    } else {
        ServerUrls::self_hosted(url)?;
        Some(url.to_owned())
    };
    ctx.save()?;
    output::message("Saved setting `config`.", common)
}

/// Stretches the master password (seconds, by design).
fn derive(password: &SecretString, email: &str, kdf: &Kdf) -> Result<MasterKey> {
    Ok(MasterKey::derive(
        password,
        email,
        kdf,
        &KdfPolicy::default(),
    )?)
}

/// The user key, or [`CliError::BadPassword`].
fn open_user_key(master: &MasterKey, protected_key: &str) -> Result<UserKey> {
    let protected: EncString = protected_key.parse()?;
    master.unlock(&protected).map_err(|err| match err {
        openwarden::Error::MacMismatch => CliError::BadPassword,
        other => other.into(),
    })
}

/// A wrong password (or two-step login) is a refused grant.
fn refused(err: openwarden::Error) -> CliError {
    match err {
        openwarden::Error::Status { status: 400, .. } => CliError::LoginRefused,
        other => other.into(),
    }
}

/// `login EMAIL`: logs in with the master password, syncs, and unlocks.
pub async fn login(
    ctx: &mut Ctx,
    email: Option<&str>,
    src: &PasswordSource,
    common: &Common,
) -> Result<()> {
    if let Some(account) = &ctx.state.account {
        return Err(CliError::AlreadyLoggedIn(account.email.clone()));
    }
    let email = email
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or(CliError::Usage("login needs the account's email"))?
        .to_owned();
    let password = read_password(src)?;
    let client = ctx.client()?;
    let kdf = client.prelogin(&email).await?;
    let master = derive(&password, &email, &kdf)?;
    let session = client
        .login_password(&email, &master, &password)
        .await
        .map_err(refused)?;
    drop(password);
    let revision = client.revision_date(&session).await?;
    let body = client.sync_body(&session).await?;
    let sync = parse_sync(&body)?;
    let protected_key = sync
        .profile
        .key
        .clone()
        .or_else(|| session.protected_key().map(str::to_owned))
        .ok_or(CliError::Usage("the server sent no account key"))?;
    let user = open_user_key(&master, &protected_key)?;
    let (keys, sealed_state_key) = Keys::generate(&user)?;
    ctx.state.account = Some(Account {
        email: sync.profile.email.clone(),
        user_id: Some(sync.profile.id.clone()),
        kdf: session.kdf().unwrap_or(kdf),
        protected_key,
        api_client_id: None,
        sealed_state_key: Some(sealed_state_key),
        sealed_tokens: Some(keys.seal_tokens(&session, now_secs())?),
        sealed_user_key: None,
        last_revision_ms: Some(revision),
        last_sync_ms: Some(super::now_ms()),
    });
    ctx.store.save_cache(&keys.seal_cache(&body)?)?;
    start_session(ctx, &user, "You are logged in!", common)
}

/// `login --apikey`: logs in with the personal API key; `unlock` next.
pub async fn login_api_key(ctx: &mut Ctx, common: &Common) -> Result<()> {
    if let Some(account) = &ctx.state.account {
        return Err(CliError::AlreadyLoggedIn(account.email.clone()));
    }
    let key = api_key(None)?;
    let client = ctx.client()?;
    let session = client.login_api_key(&key).await.map_err(refused)?;
    let body = client.sync_body(&session).await?;
    let sync = parse_sync(&body)?;
    let kdf = match session.kdf() {
        Some(kdf) => kdf,
        None => client.prelogin(&sync.profile.email).await?,
    };
    let protected_key = sync
        .profile
        .key
        .clone()
        .or_else(|| session.protected_key().map(str::to_owned))
        .ok_or(CliError::Usage("the server sent no account key"))?;
    // Nothing to seal the tokens or the vault with until `unlock`.
    ctx.state.account = Some(Account {
        email: sync.profile.email.clone(),
        user_id: Some(sync.profile.id.clone()),
        kdf,
        protected_key,
        api_client_id: Some(key.client_id),
        sealed_state_key: None,
        sealed_tokens: None,
        sealed_user_key: None,
        last_revision_ms: None,
        last_sync_ms: None,
    });
    ctx.save()?;
    output::message(
        "You are logged in!\n\nTo unlock your vault, use the `unlock` command. ex:\n$ ow unlock --passwordenv BW_PASSWORD",
        common,
    )
}

/// `unlock`: the master password opens the user key; offline unless the
/// vault was never synced.
pub async fn unlock(ctx: &mut Ctx, src: &PasswordSource, common: &Common) -> Result<()> {
    let account = ctx.account()?;
    let password = read_password(src)?;
    let master = derive(&password, &account.email, &account.kdf)?;
    drop(password);
    let user = open_user_key(&master, &account.protected_key)?;
    drop(master);
    if let Some(sealed) = &account.sealed_state_key {
        Keys::open(&user, sealed)?;
    } else {
        // After `login --apikey`: the first unlock syncs, with the API key
        // from the environment again.
        let client_id = account.api_client_id.clone();
        let client = ctx.client()?;
        let session = client
            .login_api_key(&api_key(client_id.as_ref())?)
            .await
            .map_err(expired)?;
        let (keys, sealed) = Keys::generate(&user)?;
        let tokens = keys.seal_tokens(&session, now_secs())?;
        let account = ctx.account_mut()?;
        account.sealed_state_key = Some(sealed);
        account.sealed_tokens = Some(tokens);
        ctx.sync(&client, &keys, &session, true).await?;
    }
    start_session(ctx, &user, "Your vault is now unlocked!", common)
}

/// Seals the user key under a new session key, saves, and prints the key.
fn start_session(ctx: &mut Ctx, user: &UserKey, headline: &str, common: &Common) -> Result<()> {
    let session_key = SessionKey::generate()?;
    ctx.account_mut()?.sealed_user_key = Some(session_key.seal(user)?);
    ctx.save()?;
    let key = session_key.to_base64();
    if common.raw {
        return output::value(&key);
    }
    let text = Zeroizing::new(format!(
        "{headline}\n\nTo unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n$ export BW_SESSION=\"{}\"\n\now never takes the session key on the command line.",
        key.expose_secret()
    ));
    output::message(&text, common)
}

/// `lock`: drops the sealed user key; every session key stops working.
pub fn lock(ctx: &mut Ctx, common: &Common) -> Result<()> {
    ctx.account_mut()?.sealed_user_key = None;
    ctx.save()?;
    output::message("Your vault is locked.", common)
}

/// `logout`: forgets the account and the cache (the server and the
/// device id stay).
pub fn logout(ctx: &mut Ctx, common: &Common) -> Result<()> {
    ctx.account()?;
    ctx.state.account = None;
    ctx.store.remove_cache()?;
    ctx.save()?;
    output::message("You have logged out.", common)
}

/// `sync`: fetches the vault if its revision date moved (or `--force`).
pub async fn sync(ctx: &mut Ctx, force: bool, last: bool, common: &Common) -> Result<()> {
    if last {
        return match ctx.account()?.last_sync_ms {
            Some(ms) => output::message(&iso8601(ms), common),
            None => Ok(()),
        };
    }
    let keys = ctx.keys()?;
    let client = ctx.client()?;
    let session = ctx.session(&client, &keys).await?;
    ctx.sync(&client, &keys, &session, force).await?;
    output::message("Syncing complete.", common)
}

/// `bw status`'s JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusOut<'a> {
    server_url: Option<&'a str>,
    last_sync: Option<String>,
    user_email: Option<&'a str>,
    user_id: Option<&'a str>,
    status: &'static str,
}

/// `status`.
pub fn status(ctx: &Ctx, common: &Common) -> Result<()> {
    let account = ctx.state.account.as_ref();
    let status = match account {
        None => "unauthenticated",
        Some(_) if ctx.keys().is_ok() => "unlocked",
        Some(_) => "locked",
    };
    output::json(
        &StatusOut {
            server_url: ctx.state.server_url.as_deref(),
            last_sync: account
                .and_then(|account| account.last_sync_ms)
                .map(iso8601),
            user_email: account.map(|account| account.email.as_str()),
            user_id: account.and_then(|account| account.user_id.as_deref()),
            status,
        },
        common,
    )
}
