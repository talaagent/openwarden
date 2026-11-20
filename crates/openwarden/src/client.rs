//! The HTTP client: prelogin, the API key and password logins, token
//! refresh, sync and cipher writes.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::{Kdf, MasterKey};
use crate::sync::SyncData;
use crate::vault::CipherId;

/// Where the server's two APIs live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerUrls {
    api: String,
    identity: String,
}

fn checked_base(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url).map_err(|_| Error::InvalidUrl)?;
    let loopback = match parsed.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(Error::InvalidUrl),
    };
    match parsed.scheme() {
        "https" => {}
        // Plain HTTP only to this machine (a local server, or a test's).
        "http" if loopback => {}
        _ => return Err(Error::InvalidUrl),
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::InvalidUrl);
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

impl ServerUrls {
    /// A self-hosted server (Vaultwarden, or a self-hosted Bitwarden) at
    /// `base`: the API at `<base>/api`, the identity server at
    /// `<base>/identity`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] unless `base` is an `https` URL (or `http` to
    /// a loopback address) with no query or fragment.
    pub fn self_hosted(base: &str) -> Result<Self> {
        let base = checked_base(base)?;
        Ok(Self {
            api: format!("{base}/api"),
            identity: format!("{base}/identity"),
        })
    }

    /// Separate API and identity base URLs.
    ///
    /// # Errors
    ///
    /// As [`self_hosted`](Self::self_hosted), for each.
    pub fn new(api: &str, identity: &str) -> Result<Self> {
        Ok(Self {
            api: checked_base(api)?,
            identity: checked_base(identity)?,
        })
    }

    /// Bitwarden's US cloud.
    pub fn bitwarden_us() -> Self {
        Self {
            api: "https://api.bitwarden.com".to_owned(),
            identity: "https://identity.bitwarden.com".to_owned(),
        }
    }

    /// Bitwarden's EU cloud.
    pub fn bitwarden_eu() -> Self {
        Self {
            api: "https://api.bitwarden.eu".to_owned(),
            identity: "https://identity.bitwarden.eu".to_owned(),
        }
    }
}

/// The device the client logs in as. The server lists it in the account's
/// devices; keep `identifier` stable per installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// A stable UUID for this installation.
    pub identifier: String,
    /// A human-readable name.
    pub name: String,
    /// Bitwarden's device type number (see [`Device::LINUX_CLI`]).
    pub device_type: u8,
}

impl Device {
    /// Bitwarden's device type for the Linux CLI.
    pub const LINUX_CLI: u8 = 25;
    /// Bitwarden's device type for the SDK.
    pub const SDK: u8 = 21;
}

/// A personal API key (account settings, Security, Keys, View API key).
pub struct ApiKey {
    /// `client_id`, `user.<uuid>`.
    pub client_id: String,
    /// `client_secret`.
    pub client_secret: SecretString,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .finish()
    }
}

/// A logged-in session: the bearer token, and what the token response said
/// about the account's keys.
pub struct Session {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    expires_at: Instant,
    protected_key: Option<String>,
    kdf: Option<Kdf>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_at", &self.expires_at)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether the token has expired, or will within a minute: log in
    /// again.
    pub fn is_expired(&self) -> bool {
        Instant::now()
            .checked_add(Duration::from_secs(60))
            .is_none_or(|soon| soon >= self.expires_at)
    }

    /// The account's KDF, if the token response gave it.
    pub fn kdf(&self) -> Option<Kdf> {
        self.kdf
    }

    /// The protected symmetric key, if the token response gave it.
    pub fn protected_key(&self) -> Option<&str> {
        self.protected_key.as_deref()
    }

    /// The bearer token, for a caller that keeps the session between runs
    /// (seal it; never store it in clear).
    pub fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// The refresh token, from a password login: with
    /// [`Client::refresh`], a new session without the password. Seal it
    /// like the access token.
    pub fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    /// How long until the token expires (zero once it has).
    pub fn expires_in(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Adds a refresh token (one kept from an earlier session).
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: SecretString) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// A session from a token directly (tests, or a token obtained
    /// elsewhere).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidExpiry`] if `expires_in` is too large.
    pub fn from_token(access_token: SecretString, expires_in: Duration) -> Result<Self> {
        Ok(Self {
            access_token,
            refresh_token: None,
            expires_at: expires_at(expires_in)?,
            protected_key: None,
            kdf: None,
        })
    }
}

/// Now plus `expires_in`; an error, never a panic, past what `Instant`
/// can hold.
fn expires_at(expires_in: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(expires_in)
        .ok_or(Error::InvalidExpiry)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreloginWire {
    #[serde(alias = "Kdf")]
    kdf: u8,
    #[serde(alias = "KdfIterations")]
    kdf_iterations: u32,
    #[serde(default, alias = "KdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(default, alias = "KdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: SecretString,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<SecretString>,
    #[serde(default, rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(default, rename = "Kdf", alias = "kdf")]
    kdf: Option<u8>,
    #[serde(default, rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: Option<u32>,
    #[serde(default, rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(default, rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(Deserialize)]
struct OauthErrorWire {
    error: String,
}

/// The client: one server, one device.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    urls: ServerUrls,
    device: Device,
    max_body: usize,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("urls", &self.urls)
            .field("device", &self.device)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// The default cap on a response body: 32 MiB.
    pub const DEFAULT_MAX_BODY_SIZE: usize = 32 * 1024 * 1024;

    /// A client with its own HTTP client: rustls, a 30-second timeout, no
    /// redirects, and response bodies capped at
    /// [`DEFAULT_MAX_BODY_SIZE`](Self::DEFAULT_MAX_BODY_SIZE).
    ///
    /// # Errors
    ///
    /// [`Error::Http`] if the HTTP client can't be built (no TLS roots).
    pub fn new(urls: ServerUrls, device: Device) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("openwarden/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::http("client", e))?;
        Ok(Self::with_http(http, urls, device))
    }

    /// A client over a caller-built HTTP client. Turn redirects off on it:
    /// the bearer token goes with every API call.
    pub fn with_http(http: reqwest::Client, urls: ServerUrls, device: Device) -> Self {
        Self {
            http,
            urls,
            device,
            max_body: Self::DEFAULT_MAX_BODY_SIZE,
        }
    }

    /// Caps response bodies at `bytes`: a larger one is an
    /// [`Error::BodyTooLarge`]. A big vault's sync needs room.
    #[must_use]
    pub fn with_max_body_size(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// The account's KDF, from `/identity/accounts/prelogin`. Check it
    /// against a [`KdfPolicy`](crate::KdfPolicy) before deriving (as
    /// [`MasterKey::derive`](crate::MasterKey::derive) does).
    ///
    /// # Errors
    ///
    /// [`Error::Http`], [`Error::Status`], [`Error::Decode`], and
    /// [`Error::UnknownKdf`].
    pub async fn prelogin(&self, email: &str) -> Result<Kdf> {
        let url = format!("{}/accounts/prelogin", self.urls.identity);
        let req = self
            .http
            .post(url)
            .json(&serde_json::json!({ "email": email.trim() }));
        let w: PreloginWire = self.send("prelogin", req).await?;
        Kdf::from_wire(w.kdf, w.kdf_iterations, w.kdf_memory, w.kdf_parallelism)
    }

    /// Logs in with a personal API key (the `client_credentials` grant).
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `invalid_client` for a wrong key, and
    /// [`Error::Http`], [`Error::Decode`].
    pub async fn login_api_key(&self, key: &ApiKey) -> Result<Session> {
        let url = format!("{}/connect/token", self.urls.identity);
        let device_type = self.device.device_type.to_string();
        let form = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", key.client_id.as_str()),
            ("client_secret", key.client_secret.expose_secret()),
            ("deviceType", device_type.as_str()),
            ("deviceIdentifier", self.device.identifier.as_str()),
            ("deviceName", self.device.name.as_str()),
        ];
        let req = self.http.post(url).form(&form);
        let session = self.token(req).await?;
        tracing::debug!("openwarden: logged in with an API key");
        Ok(session)
    }

    /// Logs in with the master password (the `password` grant): `master`
    /// is [`MasterKey::derive`] of `password` under the account's KDF
    /// (from [`prelogin`](Self::prelogin)). Only the master password hash
    /// is sent. The session has a refresh token.
    ///
    /// Two-step login isn't supported: an account that has it gets
    /// [`Error::Status`] (400, `invalid_grant`), as for a wrong password.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `invalid_grant` for a wrong password, and
    /// [`Error::Http`], [`Error::Decode`].
    pub async fn login_password(
        &self,
        email: &str,
        master: &MasterKey,
        password: &SecretString,
    ) -> Result<Session> {
        let url = format!("{}/connect/token", self.urls.identity);
        let email = email.trim();
        let hash = master.password_hash(password);
        let device_type = self.device.device_type.to_string();
        let form = [
            ("grant_type", "password"),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("username", email),
            ("password", hash.expose_secret()),
            ("deviceType", device_type.as_str()),
            ("deviceIdentifier", self.device.identifier.as_str()),
            ("deviceName", self.device.name.as_str()),
        ];
        // Bitwarden's cloud wants the email again, base64url, in a header.
        let req = self
            .http
            .post(url)
            .header("Auth-Email", B64_URL.encode(email))
            .form(&form);
        let session = self.token(req).await?;
        tracing::debug!("openwarden: logged in with the master password");
        Ok(session)
    }

    /// A new session from a refresh token (the `refresh_token` grant). The
    /// server may rotate the refresh token: keep the new session's.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `invalid_grant` for an expired or revoked
    /// refresh token, and [`Error::Http`], [`Error::Decode`].
    pub async fn refresh(&self, refresh_token: &SecretString) -> Result<Session> {
        let url = format!("{}/connect/token", self.urls.identity);
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", "cli"),
            ("refresh_token", refresh_token.expose_secret()),
        ];
        let req = self.http.post(url).form(&form);
        let mut session = self.token(req).await?;
        if session.refresh_token.is_none() {
            session.refresh_token = Some(refresh_token.clone());
        }
        tracing::debug!("openwarden: session refreshed");
        Ok(session)
    }

    async fn token(&self, req: reqwest::RequestBuilder) -> Result<Session> {
        let w: TokenWire = self.send("token", req).await?;
        let kdf = match (w.kdf, w.kdf_iterations) {
            (Some(k), Some(i)) => Some(Kdf::from_wire(k, i, w.kdf_memory, w.kdf_parallelism)?),
            _ => None,
        };
        Ok(Session {
            access_token: w.access_token,
            refresh_token: w.refresh_token,
            expires_at: expires_at(Duration::from_secs(w.expires_in))?,
            protected_key: w.key,
            kdf,
        })
    }

    /// `GET /api/accounts/revision-date`: when the account's vault last
    /// changed, in milliseconds since the epoch. Unchanged since the last
    /// sync means the sync can be skipped.
    ///
    /// # Errors
    ///
    /// [`Error::Http`], [`Error::Status`] (401 for an expired session),
    /// [`Error::Decode`].
    pub async fn revision_date(&self, session: &Session) -> Result<i64> {
        let url = format!("{}/accounts/revision-date", self.urls.api);
        let req = self
            .http
            .get(url)
            .bearer_auth(session.access_token.expose_secret());
        self.send("revision date", req).await
    }

    /// `GET /api/sync`: the account's keys, folders and items, encrypted.
    ///
    /// # Errors
    ///
    /// [`Error::Http`], [`Error::Status`] (401 for an expired session),
    /// [`Error::Decode`].
    pub async fn sync(&self, session: &Session) -> Result<SyncData> {
        SyncData::from_json(&self.sync_body(session).await?)
    }

    /// As [`sync`](Self::sync), but the response body itself (for a caller
    /// that caches it, sealed; [`SyncData::from_json`] parses it).
    ///
    /// # Errors
    ///
    /// As [`sync`](Self::sync), but no [`Error::Decode`].
    pub async fn sync_body(&self, session: &Session) -> Result<Zeroizing<Vec<u8>>> {
        let url = format!("{}/sync", self.urls.api);
        let req = self
            .http
            .get(url)
            .query(&[("excludeDomains", "true")])
            .bearer_auth(session.access_token.expose_secret());
        self.send_raw("sync", req).await
    }

    pub(crate) async fn delete_cipher(
        &self,
        session: &Session,
        id: &CipherId,
        permanent: bool,
    ) -> Result<()> {
        let segment = id.as_url_segment()?;
        let req = if permanent {
            self.http
                .delete(format!("{}/ciphers/{segment}", self.urls.api))
        } else {
            self.http
                .put(format!("{}/ciphers/{segment}/delete", self.urls.api))
        };
        let req = req.bearer_auth(session.access_token.expose_secret());
        self.send_raw("cipher delete", req).await?;
        Ok(())
    }

    pub(crate) async fn post_cipher(
        &self,
        session: &Session,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let organization = body
            .get("organizationId")
            .is_some_and(serde_json::Value::is_string);
        let (endpoint, payload) = if organization {
            (
                "ciphers/create",
                serde_json::json!({
                    "cipher": body,
                    "collectionIds": body["collectionIds"],
                }),
            )
        } else {
            ("ciphers", body.clone())
        };
        let url = format!("{}/{endpoint}", self.urls.api);
        let req = self
            .http
            .post(url)
            .bearer_auth(session.access_token.expose_secret())
            .json(&payload);
        self.send("cipher create", req).await
    }

    pub(crate) async fn put_cipher(
        &self,
        session: &Session,
        id: &CipherId,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/ciphers/{}", self.urls.api, id.as_url_segment()?);
        let req = self
            .http
            .put(url)
            .bearer_auth(session.access_token.expose_secret())
            .json(body);
        self.send("cipher update", req).await
    }

    async fn send_raw(
        &self,
        endpoint: &'static str,
        req: reqwest::RequestBuilder,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut resp = req
            .header("Device-Type", self.device.device_type.to_string())
            .send()
            .await
            .map_err(|e| Error::http(endpoint, e))?;
        let status = resp.status();
        let too_large = Error::BodyTooLarge {
            endpoint,
            limit: self.max_body,
        };
        if resp
            .content_length()
            .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > self.max_body))
        {
            return Err(too_large);
        }
        // Read chunk by chunk into a buffer that is wiped on drop (`Bytes`
        // can't be), stopping at the cap.
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = resp.chunk().await.map_err(|e| Error::http(endpoint, e))? {
            if chunk.len() > self.max_body - body.len() {
                return Err(too_large);
            }
            if body.capacity() - body.len() < chunk.len() {
                // Grow by hand so no unwiped copy is left behind.
                let mut bigger = Zeroizing::new(Vec::with_capacity(
                    (body.len() + chunk.len())
                        .max(body.capacity() * 2)
                        .min(self.max_body),
                ));
                bigger.extend_from_slice(&body);
                body = bigger;
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let oauth_error = serde_json::from_slice::<OauthErrorWire>(&body)
                .ok()
                .map(|w| w.error)
                .filter(|e| {
                    e.len() <= 64 && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                });
            return Err(Error::Status {
                endpoint,
                status: status.as_u16(),
                oauth_error,
            });
        }
        Ok(body)
    }

    async fn send<T: DeserializeOwned>(
        &self,
        endpoint: &'static str,
        req: reqwest::RequestBuilder,
    ) -> Result<T> {
        let body = self.send_raw(endpoint, req).await?;
        serde_json::from_slice(&body).map_err(|e| Error::decode(endpoint, &e))
    }
}
