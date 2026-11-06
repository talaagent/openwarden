//! Shared test helpers: the known-answer fixtures (synthetic data only).

#![allow(dead_code, clippy::unwrap_used)]

use serde_json::Value;

pub fn kat() -> Value {
    serde_json::from_str(include_str!("../fixtures/kat.json")).unwrap()
}

pub fn s<'a>(kat: &'a Value, key: &str) -> &'a str {
    kat[key].as_str().unwrap()
}

/// `(plaintext, encstring)` of a fixture string.
pub fn string<'a>(kat: &'a Value, name: &str) -> (&'a str, &'a str) {
    let pair = &kat["strings"][name];
    (pair[0].as_str().unwrap(), pair[1].as_str().unwrap())
}

pub fn bytes(kat: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(kat, key)).unwrap()
}
