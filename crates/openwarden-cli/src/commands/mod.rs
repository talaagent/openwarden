//! The commands, and what they share: the state, the keys, the client.

mod account;
mod read;
mod write;

use std::io::{IsTerminal as _, Read as _};
use std::time::{SystemTime, UNIX_EPOCH};

use jiff::Timestamp;
use openwarden::{ApiKey, Client, Device, SecretString, ServerUrls, Session};
use zeroize::Zeroizing;

use crate::error::{CliError, Result};
use crate::state::{self, Account, Keys, SessionKey, State, Store};
use crate::wire::SyncResponse;
use crate::{Command, Common, PasswordSource, WriteObject};

/// Runs a command.
pub async fn run(command: Command) -> Result<()> {
    let mut ctx = Ctx::load()?;
    match command {
        Command::Config {
            setting,
            value,
            common,
        } => account::config(&mut ctx, &setting, value.as_deref(), &check(common)?),
        Command::Login {
            apikey,
            password,
            common,
            email,
            password_arg,
        } => {
            refuse_password_arg(password_arg.as_ref())?;
            let common = check(common)?;
            if apikey {
                account::login_api_key(&mut ctx, &common).await
            } else {
                account::login(&mut ctx, email.as_deref(), &password, &common).await
            }
        }
        Command::Unlock {
            password,
            common,
            password_arg,
        } => {
            refuse_password_arg(password_arg.as_ref())?;
            account::unlock(&mut ctx, &password, &check(common)?).await
        }
        Command::Lock { common } => account::lock(&mut ctx, &check(common)?),
        Command::Logout { common } => account::logout(&mut ctx, &check(common)?),
        Command::Sync {
            force,
            last,
            common,
        } => account::sync(&mut ctx, force, last, &check(common)?).await,
        Command::Status { common } => account::status(&ctx, &check(common)?),
        Command::List {
            search,
            folderid,
            collectionid,
            organizationid,
            trash,
            common,
            object,
        } => {
            let filter = crate::items::Filter {
                search,
                folder_id: folderid,
                collection_id: collectionid,
                organization_id: organizationid,
                trash,
            };
            read::list(&ctx, object, &filter, &check(common)?)
        }
        Command::Get { common, object, id } => read::get(&ctx, object, &id, &check(common)?),
        Command::Create {
            common,
            object: WriteObject::Item,
            encoded,
        } => {
            refuse_encoded_arg(encoded.as_ref())?;
            write::create(&mut ctx, &check(common)?).await
        }
        Command::Edit {
            common,
            object: WriteObject::Item,
            id,
            encoded,
        } => {
            refuse_encoded_arg(encoded.as_ref())?;
            write::edit(&mut ctx, &id, &check(common)?).await
        }
        Command::Delete {
            permanent,
            common,
            object: WriteObject::Item,
            id,
        } => write::delete(&mut ctx, &id, permanent, &check(common)?).await,
        Command::Encode { common } => write::encode(&check(common)?),
    }
}

/// Refuses `--session`: a key on the command line is visible to other
/// processes.
fn check(common: Common) -> Result<Common> {
    if common.session.is_some() {
        return Err(CliError::Usage(
            "--session is refused (other processes can read the command line): set BW_SESSION",
        ));
    }
    Ok(common)
}

fn refuse_password_arg(arg: Option<&String>) -> Result<()> {
    match arg {
        Some(_) => Err(CliError::Usage(
            "a password on the command line is refused: use --passwordenv, --passwordfile or stdin",
        )),
        None => Ok(()),
    }
}

fn refuse_encoded_arg(arg: Option<&String>) -> Result<()> {
    match arg {
        Some(_) => Err(CliError::Usage(
            "item JSON on the command line is refused (it can hold secrets): pipe it on stdin",
        )),
        None => Ok(()),
    }
}

/// The state, loaded once per run.
pub struct Ctx {
    store: Store,
    state: State,
}

impl Ctx {
    fn load() -> Result<Self> {
        let store = Store::new(state::app_dir());
        let state = store.load()?;
        Ok(Self { store, state })
    }

    fn save(&self) -> Result<()> {
        self.store.save(&self.state)
    }

    fn account(&self) -> Result<&Account> {
        self.state.account.as_ref().ok_or(CliError::NotLoggedIn)
    }

    fn account_mut(&mut self) -> Result<&mut Account> {
        self.state.account.as_mut().ok_or(CliError::NotLoggedIn)
    }

    /// An HTTP client for the configured server (and a device id, made
    /// the first time).
    fn client(&mut self) -> Result<Client> {
        let urls = match self.state.server_url.as_deref() {
            Some(url) => ServerUrls::self_hosted(url)?,
            None => ServerUrls::bitwarden_us(),
        };
        let identifier = if let Some(id) = &self.state.device_id {
            id.clone()
        } else {
            let id = state::new_device_id()?;
            self.state.device_id = Some(id.clone());
            id
        };
        Ok(Client::new(
            urls,
            Device {
                identifier,
                name: "ow".into(),
                device_type: Device::LINUX_CLI,
            },
        )?)
    }

    /// The unlocked keys, from the session key in `BW_SESSION`.
    fn keys(&self) -> Result<Keys> {
        let account = self.account()?;
        let sealed_user = account.sealed_user_key.as_ref().ok_or(CliError::Locked)?;
        let env = std::env::var("BW_SESSION").map_err(|_| CliError::Locked)?;
        let env = Zeroizing::new(env);
        let user = SessionKey::from_base64(&env)?.open(sealed_user)?;
        let sealed_state = account.sealed_state_key.as_ref().ok_or(CliError::Locked)?;
        Keys::open(&user, sealed_state)
    }

    /// The cached sync response, decrypted.
    fn vault_body(&self, keys: &Keys) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = self.store.load_cache()?.ok_or(CliError::Usage(
            "the vault hasn't been synced: run `ow sync`",
        ))?;
        keys.open_cache(&sealed)
    }

    /// A session that hasn't expired: the sealed one, refreshed, or a new
    /// API-key login. New tokens are sealed and saved.
    async fn session(&mut self, client: &Client, keys: &Keys) -> Result<Session> {
        let now = now_secs();
        let account = self.account()?;
        let current = account
            .sealed_tokens
            .as_ref()
            .map(|sealed| keys.open_tokens(sealed, now))
            .transpose()?;
        let fresh = match current {
            Some(session) if !session.is_expired() => return Ok(session),
            Some(session) if session.refresh_token().is_some() => {
                let refresh_token = session.refresh_token().ok_or(CliError::LoginExpired)?;
                client.refresh(refresh_token).await.map_err(expired)?
            }
            _ => match &account.api_client_id {
                Some(id) => client
                    .login_api_key(&api_key(Some(id))?)
                    .await
                    .map_err(expired)?,
                None => return Err(CliError::LoginExpired),
            },
        };
        let sealed = keys.seal_tokens(&fresh, now)?;
        self.account_mut()?.sealed_tokens = Some(sealed);
        // Saved now: a rotated refresh token replaces the old one.
        self.save()?;
        Ok(fresh)
    }

    /// Fetches the vault (`force`, or the revision date moved) and caches
    /// it; returns whether it fetched. The state is saved.
    async fn sync(
        &mut self,
        client: &Client,
        keys: &Keys,
        session: &Session,
        force: bool,
    ) -> Result<bool> {
        let revision = client.revision_date(session).await?;
        let account = self.account()?;
        let unchanged = account.last_revision_ms == Some(revision);
        let fetch = force || !unchanged || self.store.load_cache()?.is_none();
        if fetch {
            let body = client.sync_body(session).await?;
            let sync = parse_sync(&body)?;
            if sync.profile.key.as_deref() != Some(account.protected_key.as_str()) {
                self.account_mut()?.sealed_user_key = None;
                self.save()?;
                return Err(CliError::KeyChanged);
            }
            self.store.save_cache(&keys.seal_cache(&body)?)?;
        }
        let account = self.account_mut()?;
        account.last_revision_ms = Some(revision);
        account.last_sync_ms = Some(now_ms());
        self.save()?;
        Ok(fetch)
    }
}

/// A login that no longer works means logging in again.
fn expired(err: openwarden::Error) -> CliError {
    match err {
        openwarden::Error::Status {
            status: 400 | 401, ..
        } => CliError::LoginExpired,
        other => other.into(),
    }
}

/// The personal API key, from `BW_CLIENTID` and `BW_CLIENTSECRET`; it must
/// be `expected`'s, if given.
fn api_key(expected: Option<&String>) -> Result<ApiKey> {
    let client_id = std::env::var("BW_CLIENTID").map_err(|_| {
        CliError::Usage("set BW_CLIENTID and BW_CLIENTSECRET to the personal API key")
    })?;
    if expected.is_some_and(|expected_id| *expected_id != client_id) {
        return Err(CliError::Usage(
            "BW_CLIENTID is not the API key this account logged in with",
        ));
    }
    let secret = std::env::var("BW_CLIENTSECRET").map_err(|_| {
        CliError::Usage("set BW_CLIENTID and BW_CLIENTSECRET to the personal API key")
    })?;
    Ok(ApiKey {
        client_id,
        client_secret: SecretString::from(secret),
    })
}

/// The master password: from `--passwordenv`, `--passwordfile` or stdin;
/// never the command line.
fn read_password(src: &PasswordSource) -> Result<SecretString> {
    let text = if let Some(var) = &src.env {
        Zeroizing::new(
            std::env::var(var)
                .map_err(|_| CliError::Usage("the --passwordenv variable is not set"))?,
        )
    } else if let Some(path) = &src.file {
        Zeroizing::new(std::fs::read_to_string(path).map_err(|err| CliError::io(path, err))?)
    } else if std::io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "pass the master password with --passwordenv, --passwordfile or stdin",
        ));
    } else {
        let mut input = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(CliError::Stdin)?;
        input
    };
    let line = text.lines().next().unwrap_or_default();
    if line.is_empty() {
        return Err(CliError::Usage("the master password is empty"));
    }
    Ok(SecretString::from(line))
}

fn parse_sync(body: &[u8]) -> Result<SyncResponse> {
    serde_json::from_slice(body).map_err(|err| CliError::json("the sync response", &err))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `2024-05-01T12:00:00.000Z` for ms since the epoch, as `bw` prints
/// dates (RFC 3339, UTC, milliseconds). Out of range clamps to jiff's
/// bounds; the times come from `ow`'s own clock.
fn iso8601(ms: i64) -> String {
    let timestamp = Timestamp::from_millisecond(ms).unwrap_or(if ms < 0 {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    });
    format!("{timestamp:.3}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(iso8601(1_779_105_600_000), "2026-05-18T12:00:00.000Z");
        assert_eq!(iso8601(946_684_799_999), "1999-12-31T23:59:59.999Z");
        assert_eq!(iso8601(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(iso8601(i64::MAX), "9999-12-30T22:00:00.999Z");
    }
}
