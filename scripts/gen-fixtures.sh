#!/usr/bin/env bash
# Builds crates/warden-client/tests/fixtures/kat.json: known-answer vectors for
# the KDFs, the key stretching and EncString (type 2) decryption, computed
# with OpenSSL (an implementation independent of the crate's RustCrypto
# one), following Bitwarden's published key derivation.
#
# Every input is made up here: a throwaway email, password, user key and
# item contents. No real vault data. IVs and keys come from SHA-256 of fixed
# labels, so the output is deterministic: rerun it and diff.
#
# Usage: scripts/gen-fixtures.sh > crates/warden-client/tests/fixtures/kat.json
# (inside `nix develop`, for OpenSSL 3.2+ with Argon2).
set -euo pipefail

email="kat-user@example.invalid"
password="correct horse battery staple"
pbkdf2_iter=5000
argon_iter=3
argon_mem_mib=16
argon_par=4

hex() { od -An -v -tx1 | tr -d ' \n'; }
b64hex() { xxd -r -p | base64 -w0; }
sha256hex() { printf '%s' "$1" | openssl dgst -sha256 -binary | hex; }
label_key() { sha256hex "warden-client-fixture-$1"; }
label_iv() { sha256hex "warden-client-fixture-iv-$1" | cut -c1-32; }

hkdf_expand() { # prk_hex info -> 32 bytes hex
  openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "hexkey:$1" \
    -kdfopt "info:$2" -kdfopt mode:EXPAND_ONLY HKDF | tr -d ':' | tr 'A-F' 'a-f'
}

# encstring enc_hex mac_hex iv_label < plaintext -> "2.iv|ct|mac"
encstring() {
  local enc=$1 mac=$2 iv
  iv=$(label_iv "$3")
  local ct
  ct=$(openssl enc -aes-256-cbc -K "$enc" -iv "$iv" | hex)
  local tag
  tag=$(printf '%s%s' "$iv" "$ct" | xxd -r -p |
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac" -binary | hex)
  printf '2.%s|%s|%s' "$(printf '%s' "$iv" | b64hex)" "$(printf '%s' "$ct" | b64hex)" \
    "$(printf '%s' "$tag" | b64hex)"
}

# Master keys.
mk_pbkdf2=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "pass:$password" \
  -kdfopt "salt:$email" -kdfopt "iter:$pbkdf2_iter" PBKDF2 | tr -d ':' | tr 'A-F' 'a-f')
argon_salt=$(sha256hex "$email")
mk_argon=$(openssl kdf -keylen 32 -kdfopt "pass:$password" -kdfopt "hexsalt:$argon_salt" \
  -kdfopt "iter:$argon_iter" -kdfopt "memcost:$((argon_mem_mib * 1024))" \
  -kdfopt "lanes:$argon_par" ARGON2ID | tr -d ':' | tr 'A-F' 'a-f')

# The master password hash the password grant sends: PBKDF2(master key,
# password, 1).
mph=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "hexpass:$mk_pbkdf2" \
    -kdfopt "salt:$password" -kdfopt iter:1 PBKDF2 | tr -d ':' | tr 'A-F' 'a-f')

# Stretched master key (PBKDF2 account).
s_enc=$(hkdf_expand "$mk_pbkdf2" enc)
s_mac=$(hkdf_expand "$mk_pbkdf2" mac)
a_enc=$(hkdf_expand "$mk_argon" enc)
a_mac=$(hkdf_expand "$mk_argon" mac)

# The user key: 64 bytes, enc || mac.
uk_enc=$(label_key user-enc)
uk_mac=$(label_key user-mac)
protected_key=$(printf '%s%s' "$uk_enc" "$uk_mac" | xxd -r -p | encstring "$s_enc" "$s_mac" protected)
protected_key_argon=$(printf '%s%s' "$uk_enc" "$uk_mac" | xxd -r -p | encstring "$a_enc" "$a_mac" protected-argon)

u() { printf '%s' "$1" | encstring "$uk_enc" "$uk_mac" "$2"; }

# A per-item key, under the user key, and a field under it.
ik_enc=$(label_key item-enc)
ik_mac=$(label_key item-mac)
item_key=$(printf '%s%s' "$ik_enc" "$ik_mac" | xxd -r -p | encstring "$uk_enc" "$uk_mac" item-key)
i() { printf '%s' "$1" | encstring "$ik_enc" "$ik_mac" "$2"; }

cat <<JSON
{
  "email": "$email",
  "password": "$password",
  "pbkdf2_iterations": $pbkdf2_iter,
  "argon2": { "iterations": $argon_iter, "memory_mib": $argon_mem_mib, "parallelism": $argon_par },
  "master_key_pbkdf2": "$mk_pbkdf2",
  "master_key_argon2id": "$mk_argon",
  "master_password_hash": "$(printf '%s' "$mph" | b64hex)",
  "stretched_enc": "$s_enc",
  "stretched_mac": "$s_mac",
  "user_key": "$uk_enc$uk_mac",
  "protected_key": "$protected_key",
  "protected_key_argon2id": "$protected_key_argon",
  "item_key_plain": "$ik_enc$ik_mac",
  "item_key": "$item_key",
  "strings": {
    "folder_name": ["Work", "$(u Work folder)"],
    "name": ["Example Login", "$(u 'Example Login' name)"],
    "username": ["alice@example.invalid", "$(u alice@example.invalid username)"],
    "password": ["hunter2-not-real", "$(u hunter2-not-real password)"],
    "totp": ["JBSWY3DPEHPK3PXP", "$(u JBSWY3DPEHPK3PXP totp)"],
    "uri": ["https://login.example.com/signin", "$(u https://login.example.com/signin uri)"],
    "uri2": ["https://app.example.org", "$(u https://app.example.org uri2)"],
    "empty": ["", "$(u '' empty)"],
    "item_name": ["Item Key Login", "$(i 'Item Key Login' item-name)"],
    "item_password": ["item-key-secret", "$(i item-key-secret item-password)"],
    "item_uri": ["https://shop.example.net", "$(i https://shop.example.net item-uri)"]
  }
}
JSON
