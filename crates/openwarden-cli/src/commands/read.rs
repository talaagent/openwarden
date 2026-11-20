//! `list` and `get`: offline, from the encrypted cache.

use openwarden::{ExposeSecret as _, SecretString};

use super::{Ctx, now_secs, parse_sync};
use crate::error::{CliError, Result};
use crate::items::{self, Decryptor, Filter, FolderOut, Plain};
use crate::output;
use crate::state::Keys;
use crate::{Common, GetObject, ListObject};

/// `list items|folders`.
pub fn list(ctx: &Ctx, object: ListObject, filter: &Filter, common: &Common) -> Result<()> {
    let keys = ctx.keys()?;
    let body = ctx.vault_body(&keys)?;
    let sync = parse_sync(&body)?;
    let dec = Decryptor::with_sync(&keys.user, &sync)?;
    match object {
        ListObject::Items => {
            let (readable, skipped) = items::readable(&sync);
            let (found, mut failed) = items::select(&dec, &readable, filter);
            let mut out = Vec::with_capacity(found.len());
            for cipher in found {
                match dec.item(cipher) {
                    Ok(mut item) => {
                        if common.redact {
                            item.redact();
                        }
                        out.push(item);
                    }
                    Err(_) => failed.push(cipher.id.clone()),
                }
            }
            report_skipped(skipped, &failed, common);
            output::json(&out, common)
        }
        ListObject::Folders => {
            let needle = filter.search.as_deref().map(str::to_lowercase);
            let mut out: Vec<FolderOut<'_>> = Vec::new();
            for encrypted in sync.folders.as_deref().unwrap_or_default() {
                match dec.folder(encrypted) {
                    Ok(folder) => out.push(folder),
                    Err(_) => {
                        output::note(
                            &format!("folder {} could not be decrypted", encrypted.id),
                            common,
                        );
                    }
                }
            }
            out.push(FolderOut {
                object: "folder",
                id: None,
                name: Plain(SecretString::from("No Folder")),
            });
            if let Some(needle) = needle {
                out.retain(|folder| {
                    folder
                        .name
                        .0
                        .expose_secret()
                        .to_lowercase()
                        .contains(&needle)
                });
            }
            output::json(&out, common)
        }
    }
}

fn report_skipped(_org_items: usize, failed: &[String], common: &Common) {
    for id in failed {
        output::note(&format!("item {id} could not be decrypted"), common);
    }
}

/// `get item|password|username|totp|notes|uri ID`.
pub fn get(ctx: &Ctx, object: GetObject, query: &str, common: &Common) -> Result<()> {
    let keys = ctx.keys()?;
    print_item(ctx, &keys, object, query, common)
}

/// Prints an item (or one of its fields) from the cache.
pub fn print_item(
    ctx: &Ctx,
    keys: &Keys,
    object: GetObject,
    query: &str,
    common: &Common,
) -> Result<()> {
    let body = ctx.vault_body(keys)?;
    let sync = parse_sync(&body)?;
    let dec = Decryptor::with_sync(&keys.user, &sync)?;
    let (readable, _) = items::readable(&sync);
    let cipher = items::find_one(&dec, &readable, query)?;
    if common.redact
        && matches!(
            object,
            GetObject::Password | GetObject::Totp | GetObject::Notes
        )
    {
        return Err(CliError::Usage(
            "--redact refuses `get password`, `get totp` and `get notes`",
        ));
    }
    let mut item = dec.item(cipher)?;
    if object == GetObject::Item {
        if common.redact {
            item.redact();
        }
        return output::json(&item, common);
    }
    let login = item.login;
    let field = match object {
        GetObject::Password => login.and_then(|login| login.password),
        GetObject::Username => login.and_then(|login| login.username),
        GetObject::Notes => item.notes,
        GetObject::Uri => login.and_then(|login| login.uris.into_iter().find_map(|uri| uri.uri)),
        GetObject::Totp => {
            let secret = login
                .and_then(|login| login.totp)
                .ok_or(CliError::NotFound)?;
            let code = openwarden::totp::generate(&secret.0, now_secs())?;
            Some(Plain(code.code))
        }
        GetObject::Item => None,
    };
    output::value(&field.ok_or(CliError::NotFound)?.0)
}
