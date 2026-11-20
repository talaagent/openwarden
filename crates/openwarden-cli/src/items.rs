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
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.expose_secret())
    }
}

impl core::fmt::Debug for Plain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

/// `bw`'s item JSON.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemOut<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<AttachmentOut<'a>>>,
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

impl ItemOut<'_> {
    /// Drops the secrets (`--redact`): notes, the login's password and TOTP
    /// seed, password history, field values, and every card, identity and
    /// SSH key value (their keys stay, as nulls). Names, usernames, URIs,
    /// ids and dates stay.
    pub fn redact(&mut self) {
        self.notes = None;
        if let Some(attachments) = &mut self.attachments {
            for attachment in attachments {
                attachment.key = None;
            }
        }
        self.password_history = None;
        if let Some(login) = &mut self.login {
            login.password = None;
            login.totp = None;
        }
        for map in [&mut self.card, &mut self.identity, &mut self.ssh_key]
            .into_iter()
            .flatten()
        {
            for value in map.values_mut() {
                *value = None;
            }
        }
        for field in &mut self.fields {
            field.value = None;
        }
    }
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
    organizations: std::collections::BTreeMap<String, SymmetricKey>,
}

/// What a search looks at: the name, the username and the URIs.
pub struct Summary {
    pub name: Option<SecretString>,
    pub username: Option<SecretString>,
    pub uris: Vec<SecretString>,
}

fn text(key: &SymmetricKey, field: Option<&str>) -> openwarden::Result<Option<SecretString>> {
    field
        .filter(|enc| !enc.is_empty())
        .map(|enc| enc.parse::<EncString>()?.decrypt_string(key))
        .transpose()
}

fn plain(key: &SymmetricKey, field: Option<&str>) -> openwarden::Result<Option<Plain>> {
    Ok(text(key, field)?.map(Plain))
}

/// `brandName` for `BrandName`, so both casings come out as `bw` prints.
fn camel(key: &str) -> String {
    let mut chars = key.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

impl<'k> Decryptor<'k> {
    pub fn new(user: &'k SymmetricKey) -> Self {
        Self {
            user,
            organizations: std::collections::BTreeMap::new(),
        }
    }

    pub fn with_sync(user: &'k SymmetricKey, sync: &SyncResponse) -> Result<Self> {
        Ok(Self {
            user,
            organizations: openwarden::organization_keys(
                user,
                sync.profile.private_key.as_deref(),
                &sync.profile.organizations,
            )?,
        })
    }

    /// The key an item's fields are under: its own, or the user key.
    fn item_key(&self, cipher: &Cipher) -> openwarden::Result<Cow<'_, SymmetricKey>> {
        let parent = match &cipher.organization_id {
            Some(id) => self
                .organizations
                .get(id)
                .ok_or(openwarden::Error::InvalidKey)?,
            None => self.user,
        };
        match cipher
            .key
            .as_deref()
            .filter(|item_key| !item_key.is_empty())
        {
            Some(item_key) => Ok(Cow::Owned(
                item_key.parse::<EncString>()?.decrypt_key(parent)?,
            )),
            None => Ok(Cow::Borrowed(parent)),
        }
    }

    /// The fields a search looks at.
    pub fn summary(&self, cipher: &Cipher) -> Result<Summary> {
        self.try_summary(cipher)
            .map_err(|_| CliError::Decrypt(cipher.id.clone()))
    }

    fn try_summary(&self, cipher: &Cipher) -> openwarden::Result<Summary> {
        let key = self.item_key(cipher)?;
        let login = cipher.login.as_ref();
        let uris = login
            .and_then(|login| login.uris.as_deref())
            .unwrap_or_default()
            .iter()
            .filter_map(|uri| text(&key, uri.uri.as_deref()).transpose())
            .collect::<openwarden::Result<_>>()?;
        Ok(Summary {
            name: text(&key, cipher.name.as_deref())?,
            username: text(&key, login.and_then(|login| login.username.as_deref()))?,
            uris,
        })
    }

    /// The whole item, as `bw get item` prints it.
    pub fn item<'a>(&self, cipher: &'a Cipher) -> Result<ItemOut<'a>> {
        self.try_item(cipher)
            .map_err(|_| CliError::Decrypt(cipher.id.clone()))
    }

    fn try_item<'a>(&self, cipher: &'a Cipher) -> openwarden::Result<ItemOut<'a>> {
        let key = self.item_key(cipher)?;
        let key = key.as_ref();
        let login = cipher
            .login
            .as_ref()
            .map(|login| -> openwarden::Result<_> {
                let uris = login
                    .uris
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|uri| {
                        Ok(UriOut {
                            match_type: uri.match_type,
                            uri: plain(key, uri.uri.as_deref())?,
                        })
                    })
                    .collect::<openwarden::Result<_>>()?;
                Ok(LoginOut {
                    fido2_credentials: [],
                    uris,
                    username: plain(key, login.username.as_deref())?,
                    password: plain(key, login.password.as_deref())?,
                    totp: plain(key, login.totp.as_deref())?,
                    password_revision_date: login.password_revision_date.as_deref(),
                })
            })
            .transpose()?;
        let map = |object: &Option<BTreeMap<String, EncValue>>| {
            object
                .as_ref()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|(name, value)| {
                            let value = match value {
                                EncValue::Text(text_value) => plain(key, Some(text_value))?,
                                EncValue::Other(_) => None,
                            };
                            Ok((camel(name), value))
                        })
                        .collect::<openwarden::Result<BTreeMap<_, _>>>()
                })
                .transpose()
        };
        let fields = cipher
            .fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| {
                Ok(FieldOut {
                    name: plain(key, field.name.as_deref())?,
                    value: plain(key, field.value.as_deref())?,
                    kind: field.kind,
                    linked_id: field.linked_id,
                })
            })
            .collect::<openwarden::Result<_>>()?;
        Ok(ItemOut {
            attachments: Self::attachments(cipher, key)?,
            password_history: Self::history(cipher, key)?,
            revision_date: cipher.revision_date.as_deref(),
            creation_date: cipher.creation_date.as_deref(),
            deleted_date: cipher.deleted_date.as_deref(),
            object: "item",
            id: &cipher.id,
            organization_id: cipher.organization_id.as_deref(),
            folder_id: cipher.folder_id.as_deref(),
            kind: cipher.kind,
            reprompt: cipher.reprompt.unwrap_or(0),
            name: plain(key, cipher.name.as_deref())?,
            notes: plain(key, cipher.notes.as_deref())?,
            favorite: cipher.favorite,
            login,
            secure_note: cipher.secure_note.as_ref().map(|note| SecureNoteOut {
                kind: note.kind.unwrap_or(0),
            }),
            card: map(&cipher.card)?,
            identity: map(&cipher.identity)?,
            ssh_key: map(&cipher.ssh_key)?,
            fields,
            collection_ids: cipher.collection_ids.as_deref().unwrap_or_default(),
        })
    }

    fn history<'a>(
        cipher: &'a Cipher,
        key: &SymmetricKey,
    ) -> openwarden::Result<Option<Vec<HistoryOut<'a>>>> {
        cipher
            .password_history
            .as_ref()
            .map(|history| {
                history
                    .iter()
                    .filter_map(|entry| {
                        text(key, Some(&entry.password)).transpose().map(|pw| {
                            Ok(HistoryOut {
                                last_used_date: entry.last_used_date.as_deref(),
                                password: Plain(pw?),
                            })
                        })
                    })
                    .collect::<openwarden::Result<_>>()
            })
            .transpose()
    }

    fn attachments<'a>(
        cipher: &'a Cipher,
        key: &SymmetricKey,
    ) -> openwarden::Result<Option<Vec<AttachmentOut<'a>>>> {
        cipher
            .attachments
            .as_ref()
            .map(|attachments| {
                use base64::Engine as _;
                attachments
                    .iter()
                    .map(|attachment| {
                        let attachment_key = attachment
                            .key
                            .as_deref()
                            .map(|encrypted| {
                                let decrypted = encrypted.parse::<EncString>()?.decrypt_key(key)?;
                                Ok::<_, openwarden::Error>(Plain(SecretString::from(
                                    base64::engine::general_purpose::STANDARD
                                        .encode(decrypted.to_bytes().as_ref()),
                                )))
                            })
                            .transpose()?;
                        Ok::<_, openwarden::Error>(AttachmentOut {
                            id: &attachment.id,
                            file_name: plain(key, attachment.file_name.as_deref())?,
                            key: attachment_key,
                            size: attachment.size.as_deref(),
                            url: attachment.url.as_deref(),
                        })
                    })
                    .collect::<openwarden::Result<Vec<_>>>()
            })
            .transpose()
    }

    /// A folder, as `bw list folders` prints it.
    pub fn folder<'a>(&self, folder: &'a Folder) -> Result<FolderOut<'a>> {
        let name = text(self.user, Some(&folder.name))
            .ok()
            .flatten()
            .ok_or_else(|| CliError::Decrypt(folder.id.clone()))?;
        Ok(FolderOut {
            object: "folder",
            id: Some(&folder.id),
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
    haystack.is_some_and(|text| text.expose_secret().to_lowercase().contains(needle))
}

impl Summary {
    /// `bw`'s basic search: the name, the username or a URI contains the
    /// text (case-insensitively).
    pub fn matches(&self, needle_lower: &str) -> bool {
        contains(self.name.as_ref(), needle_lower)
            || contains(self.username.as_ref(), needle_lower)
            || self
                .uris
                .iter()
                .any(|uri| contains(Some(uri), needle_lower))
    }
}

/// All synced personal and organization items.
pub fn readable(sync: &SyncResponse) -> (Vec<&Cipher>, usize) {
    let all = sync.ciphers.as_deref().unwrap_or_default();
    let personal: Vec<&Cipher> = all.iter().collect();
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
        .filter(|cipher| cipher.deleted_date.is_some() == filter.trash)
        .filter(|cipher| id_matches(filter.folder_id.as_deref(), cipher.folder_id.as_deref()))
        .filter(|cipher| {
            id_matches(
                filter.organization_id.as_deref(),
                cipher.organization_id.as_deref(),
            )
        })
        .filter(|cipher| {
            let first = cipher.collection_ids.as_deref().and_then(<[String]>::first);
            match filter.collection_id.as_deref() {
                Some(id) if id != "null" && id != "notnull" => cipher
                    .collection_ids
                    .as_deref()
                    .is_some_and(|ids| ids.iter().any(|candidate| candidate == id)),
                other => id_matches(other, first.map(String::as_str)),
            }
        })
        .filter(|cipher| match needle.as_deref() {
            None | Some("") => true,
            Some(needle) => {
                if let Ok(summary) = dec.summary(cipher) {
                    cipher.id == needle || summary.matches(needle)
                } else {
                    failed.push(cipher.id.clone());
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
    if let Some(cipher) = items
        .iter()
        .find(|cipher| cipher.id.eq_ignore_ascii_case(query))
    {
        return Ok(cipher);
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
            many.iter().map(|cipher| cipher.id.clone()).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_items_search_and_get() {
        let user = SymmetricKey::generate().unwrap();
        let organization = SymmetricKey::generate().unwrap();
        let item_key = SymmetricKey::generate().unwrap();
        let attachment_key = SymmetricKey::generate().unwrap();
        let cipher: Cipher = serde_json::from_slice(&serde_json::to_vec(&serde_json::json!({
            "id": "shared", "type": 1, "organizationId": "synthetic-org",
            "collectionIds": ["synthetic-collection"],
            "name": EncString::encrypt(&item_key, b"shared example").unwrap(),
            "key": EncString::encrypt(&organization, item_key.to_bytes().as_ref()).unwrap(),
            "attachments": [{
                "id": "attachment", "fileName": EncString::encrypt(&item_key, b"example.txt").unwrap(),
                "key": EncString::encrypt(&item_key, attachment_key.to_bytes().as_ref()).unwrap()
            }]
        })).unwrap()).unwrap();
        let mut decryptor = Decryptor::new(&user);
        decryptor
            .organizations
            .insert("synthetic-org".into(), organization);
        let summary = decryptor.summary(&cipher).unwrap();
        assert_eq!(summary.name.unwrap().expose_secret(), "shared example");
        let mut item = decryptor.item(&cipher).unwrap();
        assert_eq!(item.organization_id, Some("synthetic-org"));
        assert_eq!(item.collection_ids, ["synthetic-collection"]);
        let attachment = &item.attachments.as_ref().unwrap()[0];
        assert_eq!(
            attachment.file_name.as_ref().unwrap().0.expose_secret(),
            "example.txt"
        );
        assert!(attachment.key.is_some());
        item.redact();
        assert!(item.attachments.as_ref().unwrap()[0].key.is_none());
    }

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentOut<'a> {
    pub id: &'a str,
    pub file_name: Option<Plain>,
    pub key: Option<Plain>,
    pub size: Option<&'a str>,
    pub url: Option<&'a str>,
}
