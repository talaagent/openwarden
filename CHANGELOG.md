# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/talaagent/openwarden/compare/v0.1.0...v0.1.1) - 2026-11-18

### Added

- support no_std + alloc behind a default std feature ([#3](https://github.com/talaagent/openwarden/pull/3))

### Other

- Add ow, a fast bw-compatible CLI (openwarden-cli) ([#7](https://github.com/talaagent/openwarden/pull/7))
- Add password login, refresh tokens, the revision date, raw sync bodies and item deletion ([#6](https://github.com/talaagent/openwarden/pull/6))

## [0.1.0](https://github.com/talaagent/openwarden/releases/tag/v0.1.0) - 2026-11-15

First release.

### Added

- `Client`: prelogin, login with a personal API key (`client_credentials`),
  `/api/sync`, and creating and updating ciphers, over rustls with no
  redirects and capped response bodies. Bitwarden's US and EU clouds or a
  self-hosted server (Vaultwarden or Bitwarden).
- `MasterKey`: PBKDF2-SHA256 and Argon2id, bounded by a `KdfPolicy`; HKDF
  stretching and the master password hash.
- `EncString` (type 2) and `SymmetricKey`: MAC-verified AES-256-CBC
  decryption and encryption.
- `Vault`: unlock from the master key or a kept user key, key-change
  detection (`Error::KeyChanged`), personal logins and folders decrypted
  one field at a time, per-item keys, URI matching (`find_logins`), TOTP
  codes, and creating and updating logins (every update needs a
  `ConfirmedItem`; replaced passwords go to the password history).
- `uri`: Bitwarden's match types with stricter defaults (`strict_scheme`,
  starts-with boundaries, no userinfo pages, regex off unless allowed).
- `totp`: `otpauth://`, `steam://` and bare base32 secrets.
