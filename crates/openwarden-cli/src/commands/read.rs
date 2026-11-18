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
    let dec = Decryptor::new(&keys.user);
    match object {
        ListObject::Items => {
            let (readable, skipped) = items::readable(&sync);
            let (found, mut failed) = items::select(&dec, &readable, filter);
            let mut out = Vec::with_capacity(found.len());
            for c in found {
                match dec.item(c) {
                    Ok(item) => out.push(item),
                    Err(_) => failed.push(c.id.clone()),
                }
            }
            report_skipped(skipped, &failed, common);
            output::json(&out, common)
        }
        ListObject::Folders => {
            let needle = filter.search.as_deref().map(str::to_lowercase);
            let mut out: Vec<FolderOut<'_>> = Vec::new();
            for f in sync.folders.as_deref().unwrap_or_default() {
                match dec.folder(f) {
                    Ok(folder) => out.push(folder),
                    Err(_) => {
                        output::note(&format!("folder {} could not be decrypted", f.id), common);
                    }
                }
            }
            out.push(FolderOut {
                object: "folder",
                id: None,
                name: Plain(SecretString::from("No Folder")),
            });
            if let Some(n) = needle {
                out.retain(|f| f.name.0.expose_secret().to_lowercase().contains(&n));
            }
            output::json(&out, common)
        }
    }
}

fn report_skipped(org_items: usize, failed: &[String], common: &Common) {
    if org_items > 0 {
        output::note(
            &format!("{org_items} organization items left out (not supported yet)"),
            common,
        );
    }
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
    let dec = Decryptor::new(&keys.user);
    let (readable, _) = items::readable(&sync);
    let cipher = items::find_one(&dec, &readable, query)?;
    let item = dec.item(cipher)?;
    if object == GetObject::Item {
        return output::json(&item, common);
    }
    let login = item.login;
    let field = match object {
        GetObject::Password => login.and_then(|l| l.password),
        GetObject::Username => login.and_then(|l| l.username),
        GetObject::Notes => item.notes,
        GetObject::Uri => login.and_then(|l| l.uris.into_iter().find_map(|u| u.uri)),
        GetObject::Totp => {
            let secret = login.and_then(|l| l.totp).ok_or(CliError::NotFound)?;
            let code = openwarden::totp::generate(&secret.0, now_secs())?;
            Some(Plain(code.code))
        }
        GetObject::Item => None,
    };
    output::value(&field.ok_or(CliError::NotFound)?.0)
}
