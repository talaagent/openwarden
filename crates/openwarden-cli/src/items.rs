//! Decrypting the cached sync into `bw`'s JSON shapes, and finding items
//! the way `bw` does.

use std::borrow::Cow;
use std::collections::BTreeMap;

use openwarden::{EncString, ExposeSecret as _, SecretString, SymmetricKey};
use serde::{Serialize, Serializer};

use crate::error::{CliError, Result};
use crate::wire::{Cipher, EncValue, Folder, SyncResponse};

/// A decrypted value, written into the JSON output (and nowhere else).
pub struct Plain(pub SecretString);

impl Serialize for Plain {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose_secret())
    }
}

impl core::fmt::Debug for Plain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// `bw`'s item JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemOut<'a> {
    pub password_history: Option<Vec<HistoryOut<'a>>>,
    pub revision_date: Option<&'a str>,
    pub creation_date: Option<&'a str>,
    pub deleted_date: Option<&'a str>,
    pub object: &'static str,
    pub id: &'a str,
    pub organization_id: Option<&'a str>,
    pub folder_id: Option<&'a str>,
    #[serde(rename = "type")]
    pub kind: u8,
    pub reprompt: u8,
    pub name: Option<Plain>,
    pub notes: Option<Plain>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<SecureNoteOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<BTreeMap<String, Option<Plain>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<BTreeMap<String, Option<Plain>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<BTreeMap<String, Option<Plain>>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldOut>,
    pub collection_ids: &'a [String],
}

/// `bw`'s login JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginOut<'a> {
    pub fido2_credentials: [(); 0],
    pub uris: Vec<UriOut>,
    pub username: Option<Plain>,
    pub password: Option<Plain>,
    pub totp: Option<Plain>,
    pub password_revision_date: Option<&'a str>,
}

/// A login URI.
#[derive(Serialize)]
pub struct UriOut {
    #[serde(rename = "match")]
    pub match_type: Option<u8>,
    pub uri: Option<Plain>,
}

/// A secure note's type.
#[derive(Serialize)]
pub struct SecureNoteOut {
    #[serde(rename = "type")]
    pub kind: u8,
}

/// A custom field.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldOut {
    pub name: Option<Plain>,
    pub value: Option<Plain>,
    #[serde(rename = "type")]
    pub kind: u8,
    pub linked_id: Option<u32>,
}

/// A former password.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryOut<'a> {
    pub last_used_date: Option<&'a str>,
    pub password: Plain,
}

/// `bw`'s folder JSON.
#[derive(Serialize)]
pub struct FolderOut<'a> {
    pub object: &'static str,
    pub id: Option<&'a str>,
    pub name: Plain,
}

/// Decrypts with the user key (and each item's own key).
pub struct Decryptor<'k> {
    user: &'k SymmetricKey,
}

/// What a search looks at: the name, the username and the URIs.
pub struct Summary {
    pub name: Option<SecretString>,
    pub username: Option<SecretString>,
    pub uris: Vec<SecretString>,
}

fn text(key: &SymmetricKey, field: Option<&str>) -> openwarden::Result<Option<SecretString>> {
    field
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<EncString>()?.decrypt_string(key))
        .transpose()
}

fn plain(key: &SymmetricKey, field: Option<&str>) -> openwarden::Result<Option<Plain>> {
    Ok(text(key, field)?.map(Plain))
}

/// `brandName` for `BrandName`, so both casings come out as `bw` prints.
fn camel(key: &str) -> String {
    let mut chars = key.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_lowercase().chain(chars).collect())
}

impl<'k> Decryptor<'k> {
    pub fn new(user: &'k SymmetricKey) -> Self {
        Self { user }
    }

    /// The key an item's fields are under: its own, or the user key.
    fn item_key(&self, c: &Cipher) -> openwarden::Result<Cow<'k, SymmetricKey>> {
        match c.key.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => Ok(Cow::Owned(k.parse::<EncString>()?.decrypt_key(self.user)?)),
            None => Ok(Cow::Borrowed(self.user)),
        }
    }

    /// The fields a search looks at.
    pub fn summary(&self, c: &Cipher) -> Result<Summary> {
        self.try_summary(c)
            .map_err(|_| CliError::Decrypt(c.id.clone()))
    }

    fn try_summary(&self, c: &Cipher) -> openwarden::Result<Summary> {
        let key = self.item_key(c)?;
        let login = c.login.as_ref();
        let uris = login
            .and_then(|l| l.uris.as_deref())
            .unwrap_or_default()
            .iter()
            .filter_map(|u| text(&key, u.uri.as_deref()).transpose())
            .collect::<openwarden::Result<_>>()?;
        Ok(Summary {
            name: text(&key, c.name.as_deref())?,
            username: text(&key, login.and_then(|l| l.username.as_deref()))?,
            uris,
        })
    }

    /// The whole item, as `bw get item` prints it.
    pub fn item<'a>(&self, c: &'a Cipher) -> Result<ItemOut<'a>> {
        self.try_item(c)
            .map_err(|_| CliError::Decrypt(c.id.clone()))
    }

    fn try_item<'a>(&self, c: &'a Cipher) -> openwarden::Result<ItemOut<'a>> {
        let key = self.item_key(c)?;
        let key = key.as_ref();
        let login = c
            .login
            .as_ref()
            .map(|l| -> openwarden::Result<_> {
                let uris = l
                    .uris
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|u| {
                        Ok(UriOut {
                            match_type: u.match_type,
                            uri: plain(key, u.uri.as_deref())?,
                        })
                    })
                    .collect::<openwarden::Result<_>>()?;
                Ok(LoginOut {
                    fido2_credentials: [],
                    uris,
                    username: plain(key, l.username.as_deref())?,
                    password: plain(key, l.password.as_deref())?,
                    totp: plain(key, l.totp.as_deref())?,
                    password_revision_date: l.password_revision_date.as_deref(),
                })
            })
            .transpose()?;
        let map = |m: &Option<BTreeMap<String, EncValue>>| {
            m.as_ref()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| {
                            let v = match v {
                                EncValue::Text(t) => plain(key, Some(t))?,
                                EncValue::Other(_) => None,
                            };
                            Ok((camel(k), v))
                        })
                        .collect::<openwarden::Result<BTreeMap<_, _>>>()
                })
                .transpose()
        };
        let fields = c
            .fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|f| {
                Ok(FieldOut {
                    name: plain(key, f.name.as_deref())?,
                    value: plain(key, f.value.as_deref())?,
                    kind: f.kind,
                    linked_id: f.linked_id,
                })
            })
            .collect::<openwarden::Result<_>>()?;
        let history = c
            .password_history
            .as_ref()
            .map(|h| {
                h.iter()
                    .filter_map(|p| {
                        text(key, Some(&p.password)).transpose().map(|pw| {
                            Ok(HistoryOut {
                                last_used_date: p.last_used_date.as_deref(),
                                password: Plain(pw?),
                            })
                        })
                    })
                    .collect::<openwarden::Result<_>>()
            })
            .transpose()?;
        Ok(ItemOut {
            password_history: history,
            revision_date: c.revision_date.as_deref(),
            creation_date: c.creation_date.as_deref(),
            deleted_date: c.deleted_date.as_deref(),
            object: "item",
            id: &c.id,
            organization_id: c.organization_id.as_deref(),
            folder_id: c.folder_id.as_deref(),
            kind: c.kind,
            reprompt: c.reprompt.unwrap_or(0),
            name: plain(key, c.name.as_deref())?,
            notes: plain(key, c.notes.as_deref())?,
            favorite: c.favorite,
            login,
            secure_note: c.secure_note.as_ref().map(|n| SecureNoteOut {
                kind: n.kind.unwrap_or(0),
            }),
            card: map(&c.card)?,
            identity: map(&c.identity)?,
            ssh_key: map(&c.ssh_key)?,
            fields,
            collection_ids: c.collection_ids.as_deref().unwrap_or_default(),
        })
    }

    /// A folder, as `bw list folders` prints it.
    pub fn folder<'a>(&self, f: &'a Folder) -> Result<FolderOut<'a>> {
        let name = text(self.user, Some(&f.name))
            .ok()
            .flatten()
            .ok_or_else(|| CliError::Decrypt(f.id.clone()))?;
        Ok(FolderOut {
            object: "folder",
            id: Some(&f.id),
            name: Plain(name),
        })
    }
}

/// `list items`' filters.
#[derive(Debug, Default)]
pub struct Filter {
    pub search: Option<String>,
    pub folder_id: Option<String>,
    pub collection_id: Option<String>,
    pub organization_id: Option<String>,
    pub trash: bool,
}

/// `bw`'s id filters: an id, `null` (none) or `notnull` (any).
fn id_matches(filter: Option<&str>, value: Option<&str>) -> bool {
    match filter {
        None => true,
        Some("null") => value.is_none(),
        Some("notnull") => value.is_some(),
        Some(id) => value == Some(id),
    }
}

fn contains(haystack: Option<&SecretString>, needle: &str) -> bool {
    haystack.is_some_and(|h| h.expose_secret().to_lowercase().contains(needle))
}

impl Summary {
    /// `bw`'s basic search: the name, the username or a URI contains the
    /// text (case-insensitively).
    pub fn matches(&self, needle_lower: &str) -> bool {
        contains(self.name.as_ref(), needle_lower)
            || contains(self.username.as_ref(), needle_lower)
            || self.uris.iter().any(|u| contains(Some(u), needle_lower))
    }
}

/// The items `ow` can read: personal ones (organization items need the
/// organization keys, not supported yet). Returns them and how many were
/// left out.
pub fn readable(sync: &SyncResponse) -> (Vec<&Cipher>, usize) {
    let all = sync.ciphers.as_deref().unwrap_or_default();
    let personal: Vec<&Cipher> = all.iter().filter(|c| c.organization_id.is_none()).collect();
    let skipped = all.len() - personal.len();
    (personal, skipped)
}

/// The items passing `filter` (the search decrypts names, usernames and
/// URIs). Items that don't decrypt are left out and their ids returned.
pub fn select<'a>(
    dec: &Decryptor<'_>,
    items: &[&'a Cipher],
    filter: &Filter,
) -> (Vec<&'a Cipher>, Vec<String>) {
    let needle = filter.search.as_deref().map(str::to_lowercase);
    let mut failed = Vec::new();
    let found = items
        .iter()
        .copied()
        .filter(|c| c.deleted_date.is_some() == filter.trash)
        .filter(|c| id_matches(filter.folder_id.as_deref(), c.folder_id.as_deref()))
        .filter(|c| {
            id_matches(
                filter.organization_id.as_deref(),
                c.organization_id.as_deref(),
            )
        })
        .filter(|c| {
            let first = c.collection_ids.as_deref().and_then(<[String]>::first);
            match filter.collection_id.as_deref() {
                Some(id) if id != "null" && id != "notnull" => c
                    .collection_ids
                    .as_deref()
                    .is_some_and(|ids| ids.iter().any(|i| i == id)),
                f => id_matches(f, first.map(String::as_str)),
            }
        })
        .filter(|c| match needle.as_deref() {
            None | Some("") => true,
            Some(n) => {
                if let Ok(s) = dec.summary(c) {
                    c.id == n || s.matches(n)
                } else {
                    failed.push(c.id.clone());
                    false
                }
            }
        })
        .collect();
    (found, failed)
}

/// `bw get`'s lookup: an exact id, else the one item the search finds
/// (trash left out).
pub fn find_one<'a>(dec: &Decryptor<'_>, items: &[&'a Cipher], query: &str) -> Result<&'a Cipher> {
    if let Some(c) = items.iter().find(|c| c.id.eq_ignore_ascii_case(query)) {
        return Ok(c);
    }
    let filter = Filter {
        search: Some(query.to_owned()),
        ..Filter::default()
    };
    let (found, _) = select(dec, items, &filter);
    match found.as_slice() {
        [] => Err(CliError::NotFound),
        [one] => Ok(one),
        many => Err(CliError::Ambiguous(
            many.iter().map(|c| c.id.clone()).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_case_keys() {
        assert_eq!(camel("CardholderName"), "cardholderName");
        assert_eq!(camel("brand"), "brand");
        assert_eq!(camel(""), "");
    }

    #[test]
    fn id_filters() {
        assert!(id_matches(None, Some("a")));
        assert!(id_matches(Some("null"), None));
        assert!(!id_matches(Some("null"), Some("a")));
        assert!(id_matches(Some("notnull"), Some("a")));
        assert!(id_matches(Some("a"), Some("a")));
        assert!(!id_matches(Some("a"), Some("b")));
    }

    #[test]
    fn plain_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", Plain(SecretString::from("hunter2"))),
            "[redacted]"
        );
    }
}
