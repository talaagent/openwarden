//! Known-answer tests: KDFs, stretching and `EncString` decryption against
//! values computed independently with OpenSSL (`scripts/gen-fixtures.sh`).

#![allow(clippy::unwrap_used)]

mod common;

use common::{bytes, kat, s, string};
use warden_client::{
    EncString, Error, ExposeSecret, Kdf, KdfPolicy, MasterKey, SecretString, SymmetricKey,
};

fn lenient() -> KdfPolicy {
    // The fixtures use 5,000 PBKDF2 iterations, below the default floor,
    // to keep the tests fast.
    KdfPolicy {
        pbkdf2_min_iterations: 1_000,
        ..KdfPolicy::default()
    }
}

fn password(kat: &serde_json::Value) -> SecretString {
    SecretString::from(s(kat, "password"))
}

fn pbkdf2(kat: &serde_json::Value) -> Kdf {
    Kdf::Pbkdf2 {
        iterations: u32::try_from(kat["pbkdf2_iterations"].as_u64().unwrap()).unwrap(),
    }
}

fn master(kat: &serde_json::Value) -> MasterKey {
    MasterKey::from_bytes(bytes(kat, "master_key_pbkdf2").try_into().unwrap())
}

#[test]
fn pbkdf2_master_key() {
    let kat = kat();
    let derived =
        MasterKey::derive(&password(&kat), s(&kat, "email"), &pbkdf2(&kat), &lenient()).unwrap();
    // Same key: it unlocks the protected key the fixture's key wrapped.
    let user = derived
        .unlock(&s(&kat, "protected_key").parse().unwrap())
        .unwrap();
    assert_eq!(
        hex::encode(user.export().expose_secret()),
        s(&kat, "user_key")
    );
    assert_eq!(
        derived.password_hash(&password(&kat)).expose_secret(),
        s(&kat, "master_password_hash")
    );
}

#[test]
fn pbkdf2_email_is_normalized() {
    let kat = kat();
    let email = format!("  {}  ", s(&kat, "email").to_uppercase());
    let derived = MasterKey::derive(&password(&kat), &email, &pbkdf2(&kat), &lenient()).unwrap();
    assert!(
        derived
            .unlock(&s(&kat, "protected_key").parse().unwrap())
            .is_ok()
    );
}

#[test]
fn default_policy_refuses_weak_pbkdf2() {
    let kat = kat();
    let err = MasterKey::derive(
        &password(&kat),
        s(&kat, "email"),
        &pbkdf2(&kat),
        &KdfPolicy::default(),
    );
    assert!(matches!(err, Err(Error::KdfRejected(_))));
}

#[test]
fn argon2id_master_key() {
    let kat = kat();
    let a = &kat["argon2"];
    let kdf = Kdf::Argon2id {
        iterations: u32::try_from(a["iterations"].as_u64().unwrap()).unwrap(),
        memory_mib: u32::try_from(a["memory_mib"].as_u64().unwrap()).unwrap(),
        parallelism: u32::try_from(a["parallelism"].as_u64().unwrap()).unwrap(),
    };
    let derived = MasterKey::derive(&password(&kat), s(&kat, "email"), &kdf, &lenient()).unwrap();
    let expected = MasterKey::from_bytes(bytes(&kat, "master_key_argon2id").try_into().unwrap());
    assert_eq!(derived.stretch().to_bytes(), expected.stretch().to_bytes());
    let user = derived
        .unlock(&s(&kat, "protected_key_argon2id").parse().unwrap())
        .unwrap();
    assert_eq!(
        hex::encode(user.export().expose_secret()),
        s(&kat, "user_key")
    );
}

#[test]
fn stretch_matches_hkdf_expand() {
    let kat = kat();
    let stretched = master(&kat).stretch().to_bytes();
    assert_eq!(hex::encode(&stretched[..32]), s(&kat, "stretched_enc"));
    assert_eq!(hex::encode(&stretched[32..]), s(&kat, "stretched_mac"));
}

#[test]
fn wrong_password_fails_mac() {
    let kat = kat();
    let wrong = MasterKey::derive(
        &SecretString::from("not the password"),
        s(&kat, "email"),
        &pbkdf2(&kat),
        &lenient(),
    )
    .unwrap();
    let err = wrong.unlock(&s(&kat, "protected_key").parse().unwrap());
    assert!(matches!(err, Err(Error::MacMismatch)));
}

#[test]
fn decrypts_user_key_strings() {
    let kat = kat();
    let user = SymmetricKey::from_bytes(&bytes(&kat, "user_key")).unwrap();
    for name in [
        "folder_name",
        "name",
        "username",
        "password",
        "totp",
        "uri",
        "uri2",
        "empty",
    ] {
        let (plain, enc) = string(&kat, name);
        let enc: EncString = enc.parse().unwrap();
        assert_eq!(
            enc.decrypt_string(&user).unwrap().expose_secret(),
            plain,
            "{name}"
        );
        // Display gives the wire form back.
        assert_eq!(enc.to_string(), string(&kat, name).1);
    }
}

#[test]
fn decrypts_item_key_and_its_strings() {
    let kat = kat();
    let user = SymmetricKey::from_bytes(&bytes(&kat, "user_key")).unwrap();
    let item: EncString = s(&kat, "item_key").parse().unwrap();
    let item = item.decrypt_key(&user).unwrap();
    assert_eq!(hex::encode(&item.to_bytes()[..]), s(&kat, "item_key_plain"));
    for name in ["item_name", "item_password", "item_uri"] {
        let (plain, enc) = string(&kat, name);
        let enc: EncString = enc.parse().unwrap();
        assert_eq!(
            enc.decrypt_string(&item).unwrap().expose_secret(),
            plain,
            "{name}"
        );
        // Not under the user key.
        assert!(matches!(enc.decrypt_string(&user), Err(Error::MacMismatch)));
    }
}

#[test]
fn encrypt_roundtrips_through_the_wire_form() {
    let kat = kat();
    let user = SymmetricKey::from_bytes(&bytes(&kat, "user_key")).unwrap();
    let enc = EncString::encrypt(&user, b"hunter2").unwrap();
    let back: EncString = enc.to_string().parse().unwrap();
    assert_eq!(back.decrypt(&user).unwrap().as_slice(), b"hunter2");
}
