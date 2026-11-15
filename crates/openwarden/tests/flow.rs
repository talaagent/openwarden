//! End-to-end flows against a mock server: prelogin, the API key login,
//! sync, lazy decryption, key-change detection, and cipher create/update.
//! All data is synthetic (the known-answer fixtures).

// `#[tokio::test]` expands to `block_on`, which is fine in tests.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::disallowed_methods
)]

mod common;

use common::{bytes, kat, s, string};
use openwarden::{
    ApiKey, CipherId, Client, Device, EncString, Error, ExposeSecret, FolderId, Kdf, KeyChange,
    LoginDraft, LoginUpdate, MasterKey, MatchOptions, SecretString, ServerUrls, Session,
    SymmetricKey, SyncData, UriMatch, UserKey, Vault,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PLAIN_ID: &str = "11111111-1111-4111-8111-111111111111";
const KEYED_ID: &str = "22222222-2222-4222-8222-222222222222";
const ORG_ID: &str = "33333333-3333-4333-8333-333333333333";
const DELETED_ID: &str = "44444444-4444-4444-8444-444444444444";
const NOTE_ID: &str = "55555555-5555-4555-8555-555555555555";
const FOLDER: &str = "66666666-6666-4666-8666-666666666666";
const REV1: &str = "2026-01-02T03:04:05.000Z";
const REV2: &str = "2026-02-03T04:05:06.000Z";

fn device() -> Device {
    Device {
        identifier: "00000000-0000-4000-8000-00000000d001".into(),
        name: "openwarden-test".into(),
        device_type: Device::LINUX_CLI,
    }
}

fn client(server: &MockServer) -> Client {
    Client::new(ServerUrls::self_hosted(&server.uri()).unwrap(), device()).unwrap()
}

fn user_key(kat: &Value) -> SymmetricKey {
    SymmetricKey::from_bytes(&bytes(kat, "user_key")).unwrap()
}

fn plain_cipher(kat: &Value, rev: &str) -> Value {
    json!({
        "id": PLAIN_ID,
        "organizationId": null,
        "folderId": FOLDER,
        "type": 1,
        "name": string(kat, "name").1,
        "notes": null,
        "favorite": true,
        "reprompt": 0,
        "key": null,
        "login": {
            "username": string(kat, "username").1,
            "password": string(kat, "password").1,
            "totp": string(kat, "totp").1,
            "uris": [
                { "uri": string(kat, "uri").1, "match": null },
                { "uri": string(kat, "uri2").1, "match": 1 },
            ],
        },
        "fields": [{ "name": string(kat, "empty").1, "value": null, "type": 0 }],
        "passwordHistory": null,
        "revisionDate": rev,
        "deletedDate": null,
        "object": "cipherDetails",
    })
}

fn sync_json(kat: &Value, rev: &str, protected_key: &str, private_key: &str) -> Value {
    json!({
        "object": "sync",
        "profile": {
            "id": "77777777-7777-4777-8777-777777777777",
            "email": s(kat, "email"),
            "key": protected_key,
            "privateKey": private_key,
        },
        "folders": [{ "id": FOLDER, "name": string(kat, "folder_name").1, "revisionDate": REV1 }],
        "ciphers": [
            plain_cipher(kat, rev),
            {
                "id": KEYED_ID, "organizationId": null, "folderId": null, "type": 1,
                "name": string(kat, "item_name").1, "key": s(kat, "item_key"),
                "login": {
                    "username": null,
                    "password": string(kat, "item_password").1,
                    "totp": null,
                    "uris": [{ "uri": string(kat, "item_uri").1, "match": 2 }],
                },
                "revisionDate": REV1, "deletedDate": null,
            },
            {
                "id": ORG_ID, "organizationId": "88888888-8888-4888-8888-888888888888", "type": 1,
                "name": "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "login": { "uris": [] }, "revisionDate": REV1,
            },
            {
                "id": DELETED_ID, "organizationId": null, "type": 1,
                "name": string(kat, "name").1,
                "login": { "uris": [{ "uri": string(kat, "uri").1, "match": null }] },
                "revisionDate": REV1, "deletedDate": REV1,
            },
            {
                "id": NOTE_ID, "organizationId": null, "type": 2,
                "name": string(kat, "name").1, "secureNote": { "type": 0 },
                "revisionDate": REV1, "deletedDate": null,
            },
        ],
    })
}

fn sync_data(kat: &Value, rev: &str) -> SyncData {
    let body = sync_json(kat, rev, s(kat, "protected_key"), string(kat, "empty").1);
    SyncData::from_json(&serde_json::to_vec(&body).unwrap()).unwrap()
}

fn unlocked(kat: &Value) -> Vault {
    let master = MasterKey::from_bytes(bytes(kat, "master_key_pbkdf2").try_into().unwrap());
    let mut vault = Vault::unlock(
        &master,
        s(kat, "protected_key"),
        Some(Kdf::Pbkdf2 { iterations: 5000 }),
    )
    .unwrap();
    vault.apply_sync(sync_data(kat, REV1)).unwrap();
    vault
}

fn session() -> Session {
    Session::from_token(
        SecretString::from("test-token"),
        core::time::Duration::from_secs(3600),
    )
    .unwrap()
}

fn reveal(s: Option<SecretString>) -> Option<String> {
    s.map(|s| s.expose_secret().to_owned())
}

#[tokio::test]
async fn prelogin_login_sync_unlock() {
    let kat = kat();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .and(body_string_contains(s(&kat, "email")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=api"))
        .and(body_string_contains("client_id=user.abc"))
        .and(body_string_contains("client_secret=s3cret"))
        .and(body_string_contains(
            "deviceIdentifier=00000000-0000-4000-8000-00000000d001",
        ))
        .and(body_string_contains("deviceType=25"))
        .and(header("Device-Type", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-123", "expires_in": 3600, "token_type": "Bearer",
            "Key": s(&kat, "protected_key"), "PrivateKey": null,
            "Kdf": 0, "KdfIterations": 5000, "KdfMemory": null, "KdfParallelism": null,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(query_param("excludeDomains", "true"))
        .and(header("Authorization", "Bearer tok-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sync_json(
            &kat,
            REV1,
            s(&kat, "protected_key"),
            string(&kat, "empty").1,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    assert_eq!(
        client.prelogin(s(&kat, "email")).await.unwrap(),
        Kdf::Argon2id {
            iterations: 3,
            memory_mib: 64,
            parallelism: 4
        }
    );
    let session = client
        .login_api_key(&ApiKey {
            client_id: "user.abc".into(),
            client_secret: SecretString::from("s3cret"),
        })
        .await
        .unwrap();
    assert!(!session.is_expired());
    assert_eq!(session.kdf(), Some(Kdf::Pbkdf2 { iterations: 5000 }));
    assert_eq!(session.protected_key(), Some(s(&kat, "protected_key")));
    assert!(!format!("{session:?}").contains("tok-123"));

    let sync = client.sync(&session).await.unwrap();
    assert_eq!(sync.protected_key(), Some(s(&kat, "protected_key")));
    let master = MasterKey::from_bytes(bytes(&kat, "master_key_pbkdf2").try_into().unwrap());
    let mut vault = Vault::unlock(&master, sync.protected_key().unwrap(), session.kdf()).unwrap();
    vault.check_session(&session).unwrap();
    vault.apply_sync(sync).unwrap();
    assert_eq!(vault.logins().len(), 2);
}

#[tokio::test]
async fn bad_api_key_gives_oauth_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client", "error_description": "echoes user.abc",
        })))
        .mount(&server)
        .await;
    let err = client(&server)
        .login_api_key(&ApiKey {
            client_id: "user.abc".into(),
            client_secret: SecretString::from("wrong"),
        })
        .await
        .unwrap_err();
    match &err {
        Error::Status {
            endpoint,
            status,
            oauth_error,
        } => {
            assert_eq!(*endpoint, "token");
            assert_eq!(*status, 400);
            assert_eq!(oauth_error.as_deref(), Some("invalid_client"));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!err.to_string().contains("user.abc"));
}

#[tokio::test]
async fn malformed_sync_keeps_no_body_text() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"profile\": \"secret-ish\"}"))
        .mount(&server)
        .await;
    let err = client(&server).sync(&session()).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Decode {
            endpoint: "sync",
            ..
        }
    ));
    assert!(!format!("{err} {err:?}").contains("secret-ish"));
}

#[test]
fn lazy_decryption() {
    let kat = kat();
    let vault = unlocked(&kat);
    let plain = CipherId::new(PLAIN_ID);
    let keyed = CipherId::new(KEYED_ID);

    let mut ids: Vec<_> = vault.logins().into_iter().map(|l| l.id).collect();
    ids.sort();
    assert_eq!(ids, vec![plain.clone(), keyed.clone()]);
    let info = vault.logins().into_iter().find(|l| l.id == plain).unwrap();
    assert!(info.has_password && info.has_totp);
    assert_eq!(info.folder_id, Some(FolderId::new(FOLDER)));
    assert_eq!(info.revision_date.as_deref(), Some(REV1));

    assert_eq!(
        vault.name(&plain).unwrap().expose_secret(),
        string(&kat, "name").0
    );
    assert_eq!(
        reveal(vault.username(&plain).unwrap()).as_deref(),
        Some(string(&kat, "username").0)
    );
    assert_eq!(
        reveal(vault.password(&plain).unwrap()).as_deref(),
        Some(string(&kat, "password").0)
    );
    assert_eq!(
        reveal(vault.totp_secret(&plain).unwrap()).as_deref(),
        Some(string(&kat, "totp").0)
    );
    let code = vault.totp(&plain, 59).unwrap().unwrap();
    assert_eq!(code.code.expose_secret().len(), 6);
    assert_eq!(code.remaining, 1);
    let uris = vault.uris(&plain).unwrap();
    assert_eq!(uris.len(), 2);
    assert_eq!(uris[0].uri.expose_secret(), string(&kat, "uri").0);
    assert_eq!(uris[0].match_type, None);
    assert_eq!(uris[1].match_type, Some(UriMatch::Host));

    // The item-keyed login.
    assert_eq!(
        vault.name(&keyed).unwrap().expose_secret(),
        string(&kat, "item_name").0
    );
    assert_eq!(
        reveal(vault.password(&keyed).unwrap()).as_deref(),
        Some(string(&kat, "item_password").0)
    );
    assert_eq!(vault.username(&keyed).unwrap().map(|_| ()), None);

    // Folders.
    assert_eq!(vault.folders(), vec![FolderId::new(FOLDER)]);
    assert_eq!(
        reveal(vault.folder_name(&FolderId::new(FOLDER)).unwrap()).as_deref(),
        Some(string(&kat, "folder_name").0)
    );

    // Org, deleted and unknown items are not there; notes are not logins.
    for id in [ORG_ID, DELETED_ID, "99999999-9999-4999-8999-999999999999"] {
        assert!(matches!(
            vault.name(&CipherId::new(id)),
            Err(Error::NotFound(_))
        ));
    }
    assert!(matches!(
        vault.password(&CipherId::new(NOTE_ID)),
        Err(Error::NotALogin(_))
    ));
    assert!(!format!("{vault:?}").contains(string(&kat, "name").0));
    // The protected key would allow offline guessing of the master password.
    let protected = &vault.key_state().protected_key;
    assert_eq!(protected, s(&kat, "protected_key"));
    assert!(!format!("{:?}", vault.key_state()).contains(protected.as_str()));
}

#[test]
fn find_logins_by_url() {
    let kat = kat();
    let vault = unlocked(&kat);
    let opts = MatchOptions::default();
    let find = |url: &str| -> Vec<String> {
        let mut v: Vec<_> = vault
            .find_logins(url, &opts)
            .unwrap()
            .into_iter()
            .map(|l| l.id.as_str().to_owned())
            .collect();
        v.sort();
        v
    };
    // uri: https://login.example.com/signin (domain); uri2: https://app.example.org (host).
    assert_eq!(find("https://www.example.com/"), vec![PLAIN_ID]);
    assert_eq!(find("https://app.example.org/x"), vec![PLAIN_ID]);
    assert_eq!(find("https://other.example.org/"), Vec::<String>::new());
    // item_uri: https://shop.example.net (starts with).
    assert_eq!(find("https://shop.example.net/cart"), vec![KEYED_ID]);
    assert_eq!(find("https://example.net/"), Vec::<String>::new());
}

#[test]
fn locked_vault_refuses() {
    let kat = kat();
    let mut vault = unlocked(&kat);
    vault.lock();
    assert!(vault.is_locked());
    let id = CipherId::new(PLAIN_ID);
    assert!(matches!(vault.password(&id), Err(Error::Locked)));
    assert!(matches!(vault.export_user_key(), Err(Error::Locked)));
    assert!(matches!(
        vault.find_logins("https://example.com", &MatchOptions::default()),
        Err(Error::Locked)
    ));
    // Metadata stays.
    assert_eq!(vault.logins().len(), 2);
}

#[test]
fn export_and_reopen() {
    let kat = kat();
    let vault = unlocked(&kat);
    let exported = vault.export_user_key().unwrap();
    assert_eq!(hex::encode(exported.expose_secret()), s(&kat, "user_key"));
    let state = vault.key_state().clone();
    let json = serde_json::to_string(&state).unwrap();
    let state = serde_json::from_str(&json).unwrap();
    let mut reopened = Vault::open(
        UserKey::from_bytes(exported.expose_secret()).unwrap(),
        state,
    );
    reopened.apply_sync(sync_data(&kat, REV1)).unwrap();
    assert_eq!(
        reveal(reopened.password(&CipherId::new(PLAIN_ID)).unwrap()).as_deref(),
        Some(string(&kat, "password").0)
    );
    assert_eq!(
        format!(
            "{:?}",
            UserKey::from_bytes(exported.expose_secret()).unwrap()
        ),
        "UserKey([redacted])"
    );
}

#[test]
fn key_changes_lock_the_vault() {
    let kat = kat();
    let empty = string(&kat, "empty").1;

    // A new protected key (master password changed, or the key rotated).
    let mut vault = unlocked(&kat);
    let body = sync_json(&kat, REV1, s(&kat, "protected_key_argon2id"), empty);
    let data = SyncData::from_json(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert!(matches!(
        vault.apply_sync(data),
        Err(Error::KeyChanged(KeyChange::ProtectedKey))
    ));
    assert!(vault.is_locked());

    // Same protected key string but the user key no longer fits the data.
    let other = SymmetricKey::generate().unwrap();
    let foreign = EncString::encrypt(&other, b"private key")
        .unwrap()
        .to_string();
    let mut vault = unlocked(&kat);
    let body = sync_json(&kat, REV1, s(&kat, "protected_key"), &foreign);
    let data = SyncData::from_json(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert!(matches!(
        vault.apply_sync(data),
        Err(Error::KeyChanged(KeyChange::UserKey))
    ));
    assert!(vault.is_locked());

    // A changed KDF.
    let mut vault = unlocked(&kat);
    vault.check_kdf(&Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
    assert!(matches!(
        vault.check_kdf(&Kdf::Pbkdf2 {
            iterations: 600_000
        }),
        Err(Error::KeyChanged(KeyChange::Kdf))
    ));
    assert!(vault.is_locked());
}

async fn mount_put(server: &MockServer, response: Value) {
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{PLAIN_ID}")))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(server)
        .await;
}

async fn last_body(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    serde_json::from_slice(&reqs.last().unwrap().body).unwrap()
}

fn dec(v: &Value, key: &SymmetricKey) -> String {
    let enc: EncString = v.as_str().unwrap().parse().unwrap();
    enc.decrypt_string(key).unwrap().expose_secret().to_owned()
}

#[tokio::test]
async fn password_overwrite_needs_confirmation() {
    let kat = kat();
    let key = user_key(&kat);
    let server = MockServer::start().await;
    let mut updated = plain_cipher(&kat, REV2);
    updated["login"]["password"] =
        json!(EncString::encrypt(&key, b"new-pass").unwrap().to_string());
    mount_put(&server, updated).await;
    let client = client(&server);
    let session = session();
    let mut vault = unlocked(&kat);
    let id = CipherId::new(PLAIN_ID);
    let new_password = || LoginUpdate {
        password: Some(SecretString::from("new-pass")),
        ..LoginUpdate::default()
    };

    // No token: refused, nothing sent.
    let err = vault
        .update_login(&client, &session, &id, new_password(), None)
        .await;
    assert!(matches!(err, Err(Error::UpdateRefused(_))));
    // A token for another item: refused.
    let other = vault.confirm_item(&CipherId::new(KEYED_ID)).unwrap();
    let err = vault
        .update_login(&client, &session, &id, new_password(), Some(other))
        .await;
    assert!(matches!(err, Err(Error::ConfirmationMismatch(_))));
    // A token from before the item changed: refused.
    let stale = vault.confirm_item(&id).unwrap();
    vault.apply_sync(sync_data(&kat, REV2)).unwrap();
    let err = vault
        .update_login(&client, &session, &id, new_password(), Some(stale))
        .await;
    assert!(matches!(err, Err(Error::ConfirmationMismatch(_))));
    assert!(server.received_requests().await.unwrap().is_empty());

    // Even the same password again needs a token.
    let same = LoginUpdate {
        password: Some(SecretString::from(string(&kat, "password").0)),
        ..LoginUpdate::default()
    };
    let err = vault.update_login(&client, &session, &id, same, None).await;
    assert!(matches!(err, Err(Error::UpdateRefused(_))));
    assert!(server.received_requests().await.unwrap().is_empty());

    // Confirmed: sent, with the old password in the history.
    vault.apply_sync(sync_data(&kat, REV2)).unwrap();
    let token = vault.confirm_item(&id).unwrap();
    assert_eq!(token.id(), &id);
    vault
        .update_login(&client, &session, &id, new_password(), Some(token))
        .await
        .unwrap();
    let body = last_body(&server).await;
    assert_eq!(dec(&body["login"]["password"], &key), "new-pass");
    assert_eq!(
        dec(&body["passwordHistory"][0]["password"], &key),
        string(&kat, "password").0
    );
    assert!(
        body["passwordHistory"][0]["lastUsedDate"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert_eq!(body["lastKnownRevisionDate"], REV2);
    // Fields openwarden doesn't model go back as they came; response-only ones don't.
    assert_eq!(body["favorite"], true);
    assert_eq!(body["fields"], plain_cipher(&kat, REV1)["fields"]);
    assert_eq!(body["login"]["username"], string(&kat, "username").1);
    assert_eq!(body["login"]["uris"].as_array().unwrap().len(), 2);
    assert!(
        body.get("id").is_none()
            && body.get("object").is_none()
            && body.get("revisionDate").is_none()
    );

    // The vault took the server's answer.
    assert_eq!(
        reveal(vault.password(&id).unwrap()).as_deref(),
        Some("new-pass")
    );
    assert_eq!(
        vault
            .logins()
            .into_iter()
            .find(|l| l.id == id)
            .unwrap()
            .revision_date
            .as_deref(),
        Some(REV2)
    );
}

#[tokio::test]
async fn update_without_password_and_add_uri() {
    let kat = kat();
    let key = user_key(&kat);
    let server = MockServer::start().await;
    mount_put(&server, plain_cipher(&kat, REV2)).await;
    let client = client(&server);
    let session = session();
    let mut vault = unlocked(&kat);
    let id = CipherId::new(PLAIN_ID);
    let update = || LoginUpdate {
        username: Some(SecretString::from("new-user")),
        add_uris: vec![(
            SecretString::from("https://new.example.com"),
            Some(UriMatch::Exact),
        )],
        ..LoginUpdate::default()
    };

    // No token: refused, nothing sent.
    let err = vault
        .update_login(&client, &session, &id, update(), None)
        .await;
    assert!(matches!(err, Err(Error::UpdateRefused(_))));
    assert!(server.received_requests().await.unwrap().is_empty());

    // Confirmed: sent.
    let token = vault.confirm_item(&id).unwrap();
    vault
        .update_login(&client, &session, &id, update(), Some(token))
        .await
        .unwrap();
    let body = last_body(&server).await;
    assert_eq!(dec(&body["login"]["username"], &key), "new-user");
    assert_eq!(body["login"]["password"], string(&kat, "password").1);
    let uris = body["login"]["uris"].as_array().unwrap();
    assert_eq!(uris.len(), 3);
    assert_eq!(dec(&uris[2]["uri"], &key), "https://new.example.com");
    assert_eq!(uris[2]["match"], 3);
    assert_eq!(
        dec(&uris[2]["uriChecksum"], &key),
        "q3twREOdFEdlkMD6uWPpxUPTaiAqmRKcR36KRuJ/XDA="
    );
    assert!(body["passwordHistory"].is_null());
}

#[tokio::test]
async fn every_change_needs_confirmation() {
    let kat = kat();
    let server = MockServer::start().await;
    mount_put(&server, plain_cipher(&kat, REV2)).await;
    let client = client(&server);
    let session = session();
    let mut vault = unlocked(&kat);
    let id = CipherId::new(PLAIN_ID);
    let secret = |v: &str| Some(SecretString::from(v.to_owned()));
    let changes = [
        (
            "uri",
            LoginUpdate {
                add_uris: vec![(SecretString::from("https://evil.example"), None)],
                ..LoginUpdate::default()
            },
        ),
        (
            "totp",
            LoginUpdate {
                totp: secret("GEZDGNBVGY3TQOJQ"),
                ..LoginUpdate::default()
            },
        ),
        (
            "username",
            LoginUpdate {
                username: secret("someone-else"),
                ..LoginUpdate::default()
            },
        ),
        (
            "name",
            LoginUpdate {
                name: secret("renamed"),
                ..LoginUpdate::default()
            },
        ),
        ("nothing", LoginUpdate::default()),
    ];
    for (what, update) in changes {
        let err = vault
            .update_login(&client, &session, &id, update, None)
            .await;
        assert!(matches!(err, Err(Error::UpdateRefused(_))), "{what}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    // The refused URI didn't make the item match the attacker's page.
    assert_eq!(
        vault
            .find_logins("https://evil.example/", &MatchOptions::default())
            .unwrap()
            .len(),
        0
    );
    assert_ne!(
        reveal(vault.totp_secret(&id).unwrap()).as_deref(),
        Some("GEZDGNBVGY3TQOJQ")
    );

    // A TOTP change, confirmed, goes through.
    let token = vault.confirm_item(&id).unwrap();
    vault
        .update_login(
            &client,
            &session,
            &id,
            LoginUpdate {
                totp: secret("GEZDGNBVGY3TQOJQ"),
                ..LoginUpdate::default()
            },
            Some(token),
        )
        .await
        .unwrap();
    let body = last_body(&server).await;
    assert_eq!(
        dec(&body["login"]["totp"], &user_key(&kat)),
        "GEZDGNBVGY3TQOJQ"
    );
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096)))
        .mount(&server)
        .await;
    let err = client(&server)
        .with_max_body_size(1024)
        .sync(&session())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::BodyTooLarge {
            endpoint: "sync",
            limit: 1024
        }
    ));
}

#[tokio::test]
async fn oversized_chunked_body_is_refused() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    // No Content-Length: the cap applies while reading.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        let chunk = "x".repeat(1024);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n{chunk}\r\n400\r\n{chunk}\r\n0\r\n\r\n"
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
    });
    let client = Client::new(
        ServerUrls::self_hosted(&format!("http://{addr}")).unwrap(),
        device(),
    )
    .unwrap()
    .with_max_body_size(1500);
    let err = client.sync(&session()).await.unwrap_err();
    assert!(matches!(
        err,
        Error::BodyTooLarge {
            endpoint: "sync",
            limit: 1500
        }
    ));
}

#[tokio::test]
async fn huge_expires_in_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok", "expires_in": u64::MAX, "token_type": "Bearer",
        })))
        .mount(&server)
        .await;
    let err = client(&server)
        .login_api_key(&ApiKey {
            client_id: "user.abc".into(),
            client_secret: SecretString::from("s3cret"),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidExpiry));
    assert!(matches!(
        Session::from_token(SecretString::from("t"), core::time::Duration::MAX),
        Err(Error::InvalidExpiry)
    ));
}

#[tokio::test]
async fn create_login() {
    let kat = kat();
    let key = user_key(&kat);
    let server = MockServer::start().await;
    let created = json!({
        "id": "abababab-abab-4bab-8bab-abababababab", "organizationId": null, "folderId": null, "type": 1,
        "name": EncString::encrypt(&key, b"New item").unwrap().to_string(),
        "login": {
            "username": null,
            "password": EncString::encrypt(&key, b"pw").unwrap().to_string(),
            "uris": [],
        },
        "revisionDate": REV1, "deletedDate": null,
    });
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(created))
        .expect(1)
        .mount(&server)
        .await;
    let mut vault = unlocked(&kat);
    let id = vault
        .create_login(
            &client(&server),
            &session(),
            LoginDraft {
                name: SecretString::from("New item"),
                username: None,
                password: Some(SecretString::from("pw")),
                totp: None,
                uris: vec![(SecretString::from("https://new.example.com"), None)],
                folder_id: Some(FolderId::new(FOLDER)),
            },
        )
        .await
        .unwrap();
    assert_eq!(id.as_str(), "abababab-abab-4bab-8bab-abababababab");
    let body = last_body(&server).await;
    assert_eq!(body["type"], 1);
    assert_eq!(body["folderId"], FOLDER);
    assert_eq!(dec(&body["name"], &key), "New item");
    assert_eq!(dec(&body["login"]["password"], &key), "pw");
    assert!(body["login"]["username"].is_null());
    assert!(body["login"]["uris"][0]["match"].is_null());
    assert_eq!(reveal(vault.password(&id).unwrap()).as_deref(), Some("pw"));
    assert_eq!(vault.logins().len(), 3);
}

#[test]
fn server_urls() {
    assert!(ServerUrls::self_hosted("https://vault.example.com/").is_ok());
    assert!(ServerUrls::self_hosted("http://127.0.0.1:8080").is_ok());
    assert!(ServerUrls::self_hosted("http://vault.example.com").is_err());
    assert!(ServerUrls::self_hosted("https://vault.example.com/?x=1").is_err());
    assert!(ServerUrls::self_hosted("not a url").is_err());
    assert!(ServerUrls::new("https://api.example.com", "https://id.example.com").is_ok());
}
