//! `create`, `edit` and `delete` (logins, through the library's write
//! calls), and `encode`.

use std::io::{IsTerminal as _, Read as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use openwarden::{
    CipherId, ExposeSecret as _, FolderId, KeyState, LoginDraft, LoginUpdate, SecretString,
    SyncData, UriMatch, UserKey, Vault,
};
use serde::Deserialize;
use serde::de::IgnoredAny;
use zeroize::Zeroizing;

use super::Ctx;
use super::read::print_item;
use crate::error::{CliError, Result};
use crate::items::{Decryptor, ItemOut, Plain};
use crate::state::Keys;
use crate::{Common, GetObject, output};

/// The login type.
const LOGIN: u8 = 1;

/// The item JSON `create` and `edit` read (`bw get item`'s shape).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemIn {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<SecretString>,
    #[serde(default)]
    notes: Option<SecretString>,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    login: Option<LoginIn>,
    #[serde(default)]
    fields: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
struct LoginIn {
    #[serde(default)]
    username: Option<SecretString>,
    #[serde(default)]
    password: Option<SecretString>,
    #[serde(default)]
    totp: Option<SecretString>,
    #[serde(default)]
    uris: Option<Vec<UriIn>>,
}

#[derive(Deserialize)]
struct UriIn {
    #[serde(default)]
    uri: Option<SecretString>,
    #[serde(default, rename = "match")]
    match_type: Option<u8>,
}

/// Base64 item JSON from stdin (`ow encode`'s output, as `bw` takes it).
fn read_item() -> Result<ItemIn> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "pipe the item's base64 JSON (`ow encode`) on stdin",
        ));
    }
    let mut text = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(CliError::Stdin)?;
    let compact: Zeroizing<String> = Zeroizing::new(text.split_whitespace().collect());
    let json = Zeroizing::new(
        B64.decode(compact.as_bytes())
            .map_err(|_| CliError::Base64)?,
    );
    let item: ItemIn =
        serde_json::from_slice(&json).map_err(|e| CliError::json("the item JSON", &e))?;
    if item.kind != LOGIN {
        return Err(CliError::Unsupported("items other than logins"));
    }
    if item.organization_id.is_some() {
        return Err(CliError::Unsupported("organization items"));
    }
    Ok(item)
}

fn non_empty(s: Option<&SecretString>) -> Option<&str> {
    s.map(openwarden::ExposeSecret::expose_secret)
        .filter(|s| !s.is_empty())
}

fn uris(input: Option<&LoginIn>) -> Vec<(SecretString, Option<UriMatch>)> {
    input
        .and_then(|l| l.uris.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|u| {
            let uri = non_empty(u.uri.as_ref())?;
            Some((
                SecretString::from(uri),
                u.match_type.and_then(UriMatch::from_wire),
            ))
        })
        .collect()
}

/// The library's vault, from the unlocked keys and the cache.
fn open_vault(ctx: &Ctx, keys: &Keys) -> Result<Vault> {
    let account = ctx.account()?;
    let user = UserKey::from_bytes(keys.user.to_bytes().as_slice())?;
    let mut vault = Vault::open(
        user,
        KeyState {
            protected_key: account.protected_key.clone(),
            kdf: Some(account.kdf),
        },
    );
    vault.apply_sync(SyncData::from_json(&ctx.vault_body(keys)?)?)?;
    Ok(vault)
}

/// `create item`: a login, from base64 JSON on stdin.
pub async fn create(ctx: &mut Ctx, common: &Common) -> Result<()> {
    let keys = ctx.keys()?;
    let item = read_item()?;
    if non_empty(item.notes.as_ref()).is_some() {
        return Err(CliError::Unsupported("notes in `create`"));
    }
    if item.fields.as_ref().is_some_and(|f| !f.is_empty()) {
        return Err(CliError::Unsupported("custom fields in `create`"));
    }
    if item.favorite {
        return Err(CliError::Unsupported("favorites in `create`"));
    }
    let login = item.login.as_ref();
    let secret = |f: fn(&LoginIn) -> Option<&SecretString>| {
        login.and_then(|l| non_empty(f(l))).map(SecretString::from)
    };
    let draft = LoginDraft {
        name: SecretString::from(
            non_empty(item.name.as_ref()).ok_or(CliError::Usage("the item needs a name"))?,
        ),
        username: secret(|l| l.username.as_ref()),
        password: secret(|l| l.password.as_ref()),
        totp: secret(|l| l.totp.as_ref()),
        uris: uris(login),
        folder_id: item.folder_id.clone().map(FolderId::new),
    };
    let client = ctx.client()?;
    let session = ctx.session(&client, &keys).await?;
    let mut vault = open_vault(ctx, &keys)?;
    let id = vault.create_login(&client, &session, draft).await?;
    ctx.sync(&client, &keys, &session, true).await?;
    print_item(ctx, &keys, GetObject::Item, id.as_str(), common)
}

fn same(a: Option<&SecretString>, b: Option<&Plain>) -> bool {
    non_empty(a) == non_empty(b.map(|p| &p.0))
}

/// What `edit` can change: the name, username, password and TOTP, and new
/// URIs. Anything else that differs is refused rather than dropped.
fn diff(item: &ItemIn, current: &ItemOut<'_>) -> Result<LoginUpdate> {
    if item.kind != current.kind {
        return Err(CliError::Unsupported("changing an item's type"));
    }
    if !same(item.notes.as_ref(), current.notes.as_ref()) {
        return Err(CliError::Unsupported("changing notes in `edit`"));
    }
    if item.folder_id.as_deref() != current.folder_id || item.favorite != current.favorite {
        return Err(CliError::Unsupported(
            "changing the folder or favorite in `edit`",
        ));
    }
    if item.fields.as_ref().map_or(0, Vec::len) != current.fields.len() {
        return Err(CliError::Unsupported("changing custom fields in `edit`"));
    }
    let login = item.login.as_ref();
    let cur = current.login.as_ref();
    let changed =
        |new: Option<&SecretString>, old: Option<&Plain>| -> Result<Option<SecretString>> {
            match (non_empty(new), non_empty(old.map(|p| &p.0))) {
                (a, b) if a == b => Ok(None),
                (None, Some(_)) => Err(CliError::Unsupported("clearing a field in `edit`")),
                (Some(a), _) => Ok(Some(SecretString::from(a))),
                (None, None) => Ok(None),
            }
        };
    let new_uris = uris(login);
    let old_uris: Vec<&str> = cur
        .map(|l| {
            l.uris
                .iter()
                .filter_map(|u| non_empty(u.uri.as_ref().map(|p| &p.0)))
                .collect()
        })
        .unwrap_or_default();
    if old_uris
        .iter()
        .any(|o| !new_uris.iter().any(|(n, _)| n.expose_secret() == *o))
    {
        return Err(CliError::Unsupported("removing URIs in `edit`"));
    }
    Ok(LoginUpdate {
        name: changed(item.name.as_ref(), current.name.as_ref())?,
        username: changed(
            login.and_then(|l| l.username.as_ref()),
            cur.and_then(|l| l.username.as_ref()),
        )?,
        password: changed(
            login.and_then(|l| l.password.as_ref()),
            cur.and_then(|l| l.password.as_ref()),
        )?,
        totp: changed(
            login.and_then(|l| l.totp.as_ref()),
            cur.and_then(|l| l.totp.as_ref()),
        )?,
        add_uris: new_uris
            .into_iter()
            .filter(|(n, _)| !old_uris.contains(&n.expose_secret()))
            .collect(),
    })
}

fn is_empty(u: &LoginUpdate) -> bool {
    u.name.is_none()
        && u.username.is_none()
        && u.password.is_none()
        && u.totp.is_none()
        && u.add_uris.is_empty()
}

/// `edit item ID`: from base64 JSON on stdin.
pub async fn edit(ctx: &mut Ctx, id: &str, common: &Common) -> Result<()> {
    let keys = ctx.keys()?;
    let item = read_item()?;
    let update = {
        let body = ctx.vault_body(&keys)?;
        let sync = super::parse_sync(&body)?;
        let cipher = crate::items::readable(&sync)
            .0
            .into_iter()
            .find(|c| c.id.eq_ignore_ascii_case(id))
            .ok_or(CliError::NotFound)?;
        let current = Decryptor::new(&keys.user).item(cipher)?;
        diff(&item, &current)?
    };
    if !is_empty(&update) {
        let client = ctx.client()?;
        let session = ctx.session(&client, &keys).await?;
        let mut vault = open_vault(ctx, &keys)?;
        let cid = CipherId::new(id);
        let confirmed = vault.confirm_item(&cid)?;
        vault
            .update_login(&client, &session, &cid, update, Some(confirmed))
            .await?;
        ctx.sync(&client, &keys, &session, true).await?;
    }
    print_item(ctx, &keys, GetObject::Item, id, common)
}

/// `delete item ID`: to the trash, or for good with `--permanent`.
pub async fn delete(ctx: &mut Ctx, id: &str, permanent: bool, _common: &Common) -> Result<()> {
    let keys = ctx.keys()?;
    let client = ctx.client()?;
    let session = ctx.session(&client, &keys).await?;
    let mut vault = open_vault(ctx, &keys)?;
    let cid = CipherId::new(id);
    let confirmed = vault.confirm_item(&cid)?;
    vault
        .delete_item(&client, &session, &cid, permanent, Some(confirmed))
        .await?;
    ctx.sync(&client, &keys, &session, true).await?;
    Ok(())
}

/// `encode`: base64 of stdin.
pub fn encode(_common: &Common) -> Result<()> {
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(CliError::Stdin)?;
    output::value(&SecretString::from(B64.encode(input.as_slice())))
}
