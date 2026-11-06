//! The HTTP client: prelogin, the API key login, sync and cipher writes.

use core::fmt;
use core::time::Duration;
use std::time::Instant;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::crypto::EncString;
use crate::error::{Error, Result};
use crate::kdf::Kdf;
use crate::vault::{CipherId, FolderId};

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
    expires_at: Instant,
    protected_key: Option<String>,
    kdf: Option<Kdf>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether the token has expired, or will within a minute: log in
    /// again.
    pub fn is_expired(&self) -> bool {
        Instant::now() + Duration::from_secs(60) >= self.expires_at
    }

    /// The account's KDF, if the token response gave it.
    pub fn kdf(&self) -> Option<Kdf> {
        self.kdf
    }

    /// The protected symmetric key, if the token response gave it.
    pub fn protected_key(&self) -> Option<&str> {
        self.protected_key.as_deref()
    }

    /// A session from a token directly (tests, or a token obtained
    /// elsewhere).
    pub fn from_token(access_token: SecretString, expires_in: Duration) -> Self {
        Self {
            access_token,
            expires_at: Instant::now() + expires_in,
            protected_key: None,
            kdf: None,
        }
    }
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileWire {
    id: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderWire {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncWire {
    profile: ProfileWire,
    #[serde(default)]
    folders: Vec<FolderWire>,
    #[serde(default)]
    ciphers: Vec<serde_json::Value>,
}

/// A `/api/sync` response, still encrypted: what
/// [`Vault::apply_sync`](crate::Vault::apply_sync) takes.
pub struct SyncData {
    pub(crate) user_id: String,
    pub(crate) protected_key: Option<String>,
    pub(crate) private_key: Option<String>,
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
            user_id: wire.profile.id,
            protected_key: wire.profile.key,
            private_key: wire.profile.private_key,
            folders: wire
                .folders
                .into_iter()
                .map(|f| (FolderId::new(f.id), f.name.parse().ok()))
                .collect(),
            ciphers: wire.ciphers,
        })
    }
}

/// The client: one server, one device.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    urls: ServerUrls,
    device: Device,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("urls", &self.urls)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with its own HTTP client: rustls, a 30-second timeout and
    /// no redirects.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] if the HTTP client can't be built (no TLS roots).
    pub fn new(urls: ServerUrls, device: Device) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("wardwire/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::http("client", e))?;
        Ok(Self::with_http(http, urls, device))
    }

    /// A client over a caller-built HTTP client. Turn redirects off on it:
    /// the bearer token goes with every API call.
    pub fn with_http(http: reqwest::Client, urls: ServerUrls, device: Device) -> Self {
        Self { http, urls, device }
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
        let w: TokenWire = self.send("token", req).await?;
        let kdf = match (w.kdf, w.kdf_iterations) {
            (Some(k), Some(i)) => Some(Kdf::from_wire(k, i, w.kdf_memory, w.kdf_parallelism)?),
            _ => None,
        };
        tracing::debug!("wardwire: logged in with an API key");
        Ok(Session {
            access_token: w.access_token,
            expires_at: Instant::now() + Duration::from_secs(w.expires_in),
            protected_key: w.key,
            kdf,
        })
    }

    /// `GET /api/sync`: the account's keys, folders and items, encrypted.
    ///
    /// # Errors
    ///
    /// [`Error::Http`], [`Error::Status`] (401 for an expired session),
    /// [`Error::Decode`].
    pub async fn sync(&self, session: &Session) -> Result<SyncData> {
        let url = format!("{}/sync", self.urls.api);
        let req = self
            .http
            .get(url)
            .query(&[("excludeDomains", "true")])
            .bearer_auth(session.access_token.expose_secret());
        let body = self.send_raw("sync", req).await?;
        SyncData::from_json(&body)
    }

    pub(crate) async fn post_cipher(
        &self,
        session: &Session,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/ciphers", self.urls.api);
        let req = self
            .http
            .post(url)
            .bearer_auth(session.access_token.expose_secret())
            .json(body);
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
        let resp = req
            .header("Device-Type", self.device.device_type.to_string())
            .send()
            .await
            .map_err(|e| Error::http(endpoint, e))?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| Error::http(endpoint, e))?;
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
        // `Bytes` can't be wiped in place: copy into a buffer that is.
        Ok(Zeroizing::new(body.to_vec()))
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
