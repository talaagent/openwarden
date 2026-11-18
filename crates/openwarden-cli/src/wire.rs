//! The sync response, typed: the fields `ow` reads. Bitwarden and newer
//! Vaultwarden send `camelCase`, older Vaultwarden `PascalCase`, so each
//! field takes both. Encrypted fields stay strings until they are used.

use std::collections::BTreeMap;

use serde::Deserialize;

/// `/api/sync`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    #[serde(alias = "Profile")]
    pub profile: Profile,
    #[serde(default, alias = "Folders")]
    pub folders: Option<Vec<Folder>>,
    #[serde(default, alias = "Ciphers")]
    pub ciphers: Option<Vec<Cipher>>,
}

/// The account.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "Email")]
    pub email: String,
    /// The protected symmetric key.
    #[serde(default, alias = "Key")]
    pub key: Option<String>,
}

/// A folder.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "Name")]
    pub name: String,
}

/// An item ("cipher").
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(default, alias = "OrganizationId")]
    pub organization_id: Option<String>,
    #[serde(default, alias = "FolderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "type", alias = "Type")]
    pub kind: u8,
    #[serde(default, alias = "Reprompt")]
    pub reprompt: Option<u8>,
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    #[serde(default, alias = "Notes")]
    pub notes: Option<String>,
    #[serde(default, alias = "Favorite")]
    pub favorite: bool,
    /// The item key, under the user key.
    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "Login")]
    pub login: Option<Login>,
    #[serde(default, alias = "SecureNote")]
    pub secure_note: Option<SecureNote>,
    #[serde(default, alias = "Card")]
    pub card: Option<BTreeMap<String, EncValue>>,
    #[serde(default, alias = "Identity")]
    pub identity: Option<BTreeMap<String, EncValue>>,
    #[serde(default, alias = "SshKey")]
    pub ssh_key: Option<BTreeMap<String, EncValue>>,
    #[serde(default, alias = "Fields")]
    pub fields: Option<Vec<Field>>,
    #[serde(default, alias = "PasswordHistory")]
    pub password_history: Option<Vec<PasswordHistory>>,
    #[serde(default, alias = "CollectionIds")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(default, alias = "RevisionDate")]
    pub revision_date: Option<String>,
    #[serde(default, alias = "CreationDate")]
    pub creation_date: Option<String>,
    #[serde(default, alias = "DeletedDate")]
    pub deleted_date: Option<String>,
}

/// One value of a card, identity or SSH key: an `EncString`, or anything
/// else (ignored).
#[derive(Deserialize)]
#[serde(untagged)]
pub enum EncValue {
    Text(String),
    Other(serde::de::IgnoredAny),
}

/// A login's fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default, alias = "Username")]
    pub username: Option<String>,
    #[serde(default, alias = "Password")]
    pub password: Option<String>,
    #[serde(default, alias = "Totp")]
    pub totp: Option<String>,
    #[serde(default, alias = "Uris")]
    pub uris: Option<Vec<LoginUri>>,
    #[serde(default, alias = "PasswordRevisionDate")]
    pub password_revision_date: Option<String>,
}

/// A login URI.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    #[serde(default, alias = "Uri")]
    pub uri: Option<String>,
    #[serde(default, rename = "match", alias = "Match")]
    pub match_type: Option<u8>,
}

/// A secure note's type (always 0, generic).
#[derive(Deserialize)]
pub struct SecureNote {
    #[serde(default, rename = "type", alias = "Type")]
    pub kind: Option<u8>,
}

/// A custom field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    #[serde(default, alias = "Value")]
    pub value: Option<String>,
    #[serde(rename = "type", alias = "Type")]
    pub kind: u8,
    #[serde(default, alias = "LinkedId")]
    pub linked_id: Option<u32>,
}

/// A former password.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    #[serde(alias = "Password")]
    pub password: String,
    #[serde(default, alias = "LastUsedDate")]
    pub last_used_date: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_casings_parse() {
        let camel = br#"{"profile":{"id":"u","email":"alice@example.org","key":"2.k"},
            "ciphers":[{"id":"c","type":1,"name":"2.n","login":{"uris":[{"uri":"2.u","match":null}]},
            "card":null,"fields":null}],"folders":[]}"#;
        let pascal = br#"{"Profile":{"Id":"u","Email":"alice@example.org","Key":"2.k"},
            "Ciphers":[{"Id":"c","Type":1,"Name":"2.n","Login":{"Uris":[{"Uri":"2.u","Match":3}]},
            "Card":{"Brand":"2.b","ExpYear":null}}],"Folders":null}"#;
        for body in [&camel[..], &pascal[..]] {
            let sync: SyncResponse = serde_json::from_slice(body).unwrap();
            assert_eq!(sync.profile.email, "alice@example.org");
            let cipher = &sync.ciphers.unwrap()[0];
            assert_eq!(cipher.kind, 1);
            assert_eq!(
                cipher.login.as_ref().unwrap().uris.as_ref().unwrap()[0]
                    .uri
                    .as_deref(),
                Some("2.u")
            );
        }
    }
}
