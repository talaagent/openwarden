//! `ow` end to end against a mock server: login, status, list, get, an
//! unchanged sync, lock, unlock, logout, and what never reaches the disk.
//! All data is synthetic (the library's known-answer fixtures).

// `#[tokio::test]` expands to `block_on`, which is fine in tests.
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PLAIN_ID: &str = "11111111-1111-4111-8111-111111111111";
const ORG_ID: &str = "33333333-3333-4333-8333-333333333333";
const DELETED_ID: &str = "44444444-4444-4444-8444-444444444444";
const FOLDER: &str = "66666666-6666-4666-8666-666666666666";
const USER_ID: &str = "77777777-7777-4777-8777-777777777777";
const REV: &str = "2026-01-02T03:04:05.000Z";
const REVISION_MS: i64 = 1_767_225_600_000;
const ACCESS: &str = "access-token-not-real";
const REFRESH: &str = "refresh-token-not-real";

fn kat() -> Value {
    serde_json::from_str(include_str!("../../openwarden/tests/fixtures/kat.json")).unwrap()
}

fn s<'a>(kat: &'a Value, key: &str) -> &'a str {
    kat[key].as_str().unwrap()
}

/// `(plaintext, encstring)` of a fixture string.
fn string<'a>(kat: &'a Value, name: &str) -> (&'a str, &'a str) {
    let pair = &kat["strings"][name];
    (pair[0].as_str().unwrap(), pair[1].as_str().unwrap())
}

fn sync_json(kat: &Value) -> Value {
    json!({
        "object": "sync",
        "profile": { "id": USER_ID, "email": s(kat, "email"), "key": s(kat, "protected_key_argon2id") },
        "folders": [{ "id": FOLDER, "name": string(kat, "folder_name").1, "revisionDate": REV }],
        "ciphers": [
            {
                "id": PLAIN_ID, "organizationId": null, "folderId": FOLDER, "type": 1,
                "name": string(kat, "name").1, "notes": null, "favorite": true, "reprompt": 0,
                "login": {
                    "username": string(kat, "username").1,
                    "password": string(kat, "password").1,
                    "totp": string(kat, "totp").1,
                    "uris": [{ "uri": string(kat, "uri").1, "match": null }],
                },
                "revisionDate": REV, "deletedDate": null,
            },
            {
                "id": ORG_ID, "organizationId": "88888888-8888-4888-8888-888888888888", "type": 1,
                "name": "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "login": { "uris": [] }, "revisionDate": REV,
            },
            {
                "id": DELETED_ID, "organizationId": null, "type": 1,
                "name": string(kat, "name").1,
                "login": { "uris": [] },
                "revisionDate": REV, "deletedDate": REV,
            },
        ],
    })
}

/// A mock server with the account, and `sync_calls` expected `/api/sync`
/// calls.
async fn server(kat: &Value, sync_calls: u64) -> MockServer {
    let server = MockServer::start().await;
    // Argon2id: the fixture's PBKDF2 count is below the default policy.
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kdf": 1, "kdfIterations": 3, "kdfMemory": 16, "kdfParallelism": 4,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600,
            "token_type": "Bearer", "Key": s(kat, "protected_key_argon2id"),
            "Kdf": 1, "KdfIterations": 3, "KdfMemory": 16, "KdfParallelism": 4,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/accounts/revision-date"))
        .and(header("Authorization", format!("Bearer {ACCESS}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(REVISION_MS)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("Authorization", format!("Bearer {ACCESS}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(sync_json(kat)))
        .expect(sync_calls)
        .mount(&server)
        .await;
    server
}

/// A fresh state directory.
fn app_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ow-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ow(dir: &Path, session: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ow"));
    cmd.args(args)
        .env_clear()
        .env("OPENWARDEN_APPDATA_DIR", dir)
        .env("OW_TEST_PASSWORD", s(&kat(), "password"))
        .stdin(std::process::Stdio::null());
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }
    cmd.output().unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "status {:?}, stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn json_out(out: &Output) -> Value {
    serde_json::from_str(&ok(out)).unwrap()
}

/// Every file in the state directory, as bytes.
fn state_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            all.extend(std::fs::read(path).unwrap());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// `config server` and `login`; returns the session key.
fn login(dir: &Path, server: &MockServer) -> String {
    ok(&ow(dir, None, &["config", "server", &server.uri()]));
    let kat = kat();
    let key = ok(&ow(
        dir,
        None,
        &[
            "login",
            s(&kat, "email"),
            "--passwordenv",
            "OW_TEST_PASSWORD",
            "--raw",
        ],
    ));
    assert_ne!(key, "");
    key
}

#[tokio::test(flavor = "multi_thread")]
async fn login_read_sync_lock_unlock_logout() {
    let kat = kat();
    // Login syncs once; the later `sync` finds the revision unchanged.
    let server = server(&kat, 1).await;
    let dir = app_dir("flow");
    let key = login(&dir, &server);
    let session = Some(key.as_str());

    let status = json_out(&ow(&dir, session, &["status"]));
    assert_eq!(status["status"], "unlocked");
    assert_eq!(status["userEmail"], s(&kat, "email"));
    assert_eq!(status["userId"], USER_ID);
    assert_eq!(status["serverUrl"], server.uri());

    // The org item is left out (with a note), the deleted one too.
    let out = ow(&dir, session, &["list", "items"]);
    let items = json_out(&out);
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["id"], PLAIN_ID);
    assert_eq!(items[0]["name"], string(&kat, "name").0);
    assert_eq!(items[0]["folderId"], FOLDER);
    assert_eq!(items[0]["login"]["username"], string(&kat, "username").0);
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 organization items left out"));

    let searched = json_out(&ow(
        &dir,
        session,
        &["list", "items", "--search", "nothing-like-it"],
    ));
    assert_eq!(searched.as_array().unwrap().len(), 0);

    let folders = json_out(&ow(&dir, session, &["list", "folders"]));
    assert_eq!(folders[0]["name"], string(&kat, "folder_name").0);
    assert_eq!(folders[1]["id"], Value::Null);

    assert_eq!(
        ok(&ow(&dir, session, &["get", "password", PLAIN_ID])),
        string(&kat, "password").0
    );
    assert_eq!(
        ok(&ow(
            &dir,
            session,
            &["get", "username", string(&kat, "name").0]
        )),
        string(&kat, "username").0
    );
    let totp = ok(&ow(&dir, session, &["get", "totp", PLAIN_ID]));
    assert_eq!(totp.len(), 6);
    assert!(totp.bytes().all(|b| b.is_ascii_digit()));
    let item = json_out(&ow(&dir, session, &["get", "item", PLAIN_ID]));
    assert_eq!(item["login"]["uris"][0]["uri"], string(&kat, "uri").0);
    assert!(
        !ow(&dir, session, &["get", "password", ORG_ID])
            .status
            .success()
    );

    // Unchanged revision date: no second `/api/sync` (the mock expects one).
    assert_eq!(ok(&ow(&dir, session, &["sync"])), "Syncing complete.\n");
    assert!(ok(&ow(&dir, session, &["sync", "--last"])).starts_with("20"));

    // Nothing in the state directory is plaintext.
    let disk = state_bytes(&dir);
    for secret in [
        string(&kat, "password").0,
        string(&kat, "username").0,
        string(&kat, "totp").0,
        string(&kat, "name").0,
        s(&kat, "password"),
        ACCESS,
        REFRESH,
        key.as_str(),
    ] {
        assert!(!contains(&disk, secret), "{secret} is on disk");
    }

    // A wrong session key, no session key, then lock.
    assert!(!ow(&dir, Some("AAAA"), &["list", "items"]).status.success());
    let locked = ow(&dir, None, &["get", "password", PLAIN_ID]);
    assert!(!locked.status.success());
    assert_eq!(locked.stdout, b"");
    ok(&ow(&dir, session, &["lock"]));
    assert!(!ow(&dir, session, &["list", "items"]).status.success());
    assert_eq!(json_out(&ow(&dir, None, &["status"]))["status"], "locked");

    // Unlock is offline (no new token, no sync) and gives a new key.
    let key2 = ok(&ow(
        &dir,
        None,
        &["unlock", "--passwordenv", "OW_TEST_PASSWORD", "--raw"],
    ));
    assert_ne!(key2, key);
    assert_eq!(
        ok(&ow(&dir, Some(&key2), &["get", "password", PLAIN_ID])),
        string(&kat, "password").0
    );

    ok(&ow(&dir, Some(&key2), &["logout"]));
    assert_eq!(
        json_out(&ow(&dir, None, &["status"]))["status"],
        "unauthenticated"
    );
    assert!(!dir.join("cache").exists() || state_bytes(&dir.join("cache")).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_refused_offline() {
    let kat = kat();
    let server = server(&kat, 1).await;
    let dir = app_dir("wrong");
    login(&dir, &server);
    let out = Command::new(env!("CARGO_BIN_EXE_ow"))
        .args(["unlock", "--passwordenv", "OW_TEST_PASSWORD", "--raw"])
        .env_clear()
        .env("OPENWARDEN_APPDATA_DIR", &dir)
        .env("OW_TEST_PASSWORD", "not the password")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.stdout, b"");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secrets_on_argv_are_refused() {
    let dir = app_dir("argv");
    let refused = |args: &[&str]| {
        let out = ow(&dir, None, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!err.contains("hunter2"), "{err}");
        err
    };
    assert!(refused(&["login", "alice@example.org", "hunter2"]).contains("refused"));
    assert!(refused(&["unlock", "hunter2"]).contains("refused"));
    assert!(refused(&["list", "items", "--session", "hunter2"]).contains("BW_SESSION"));
    assert!(refused(&["create", "item", "aHVudGVyMg=="]).contains("stdin"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn ow_stdin(dir: &Path, session: &str, args: &[&str], input: &[u8]) -> Output {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_ow"))
        .args(args)
        .env_clear()
        .env("OPENWARDEN_APPDATA_DIR", dir)
        .env("BW_SESSION", session)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn edit_round_trips_and_delete_trashes() {
    let kat = kat();
    // Login, then the sync after the delete.
    let server = server(&kat, 2).await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{PLAIN_ID}/delete")))
        .and(header("Authorization", format!("Bearer {ACCESS}").as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let dir = app_dir("write");
    let key = login(&dir, &server);

    // `get item | encode | edit` with nothing changed: no request.
    let item = ok(&ow(&dir, Some(&key), &["get", "item", PLAIN_ID]));
    let encoded = ok(&ow_stdin(&dir, &key, &["encode"], item.as_bytes()));
    let edited = json_out(&ow_stdin(
        &dir,
        &key,
        &["edit", "item", PLAIN_ID],
        encoded.as_bytes(),
    ));
    assert_eq!(edited["id"], PLAIN_ID);

    // Changes ow can't make yet are refused, not dropped.
    let mut with_notes: Value = serde_json::from_str(&item).unwrap();
    with_notes["notes"] = json!("a note");
    let encoded = ok(&ow_stdin(
        &dir,
        &key,
        &["encode"],
        with_notes.to_string().as_bytes(),
    ));
    let out = ow_stdin(&dir, &key, &["edit", "item", PLAIN_ID], encoded.as_bytes());
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("notes"));

    ok(&ow(&dir, Some(&key), &["delete", "item", PLAIN_ID]));
    let _ = std::fs::remove_dir_all(&dir);
}
