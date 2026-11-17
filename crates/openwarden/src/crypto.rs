//! Symmetric keys and `EncStrings`.
//!
//! Bitwarden's `EncString` type 2: `2.<iv>|<ciphertext>|<mac>`, each part
//! base64, AES-256-CBC with PKCS#7 padding, and HMAC-SHA256 over
//! `iv || ciphertext`. The MAC is checked (in constant time) before any
//! decryption. Types 0 and 1 (no MAC, or a 128-bit key) are refused; the
//! RSA types (3 to 6) and COSE (7) are not supported in v1.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{KeyInit, Mac};
use secrecy::SecretString;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

type HmacSha256 = hmac::Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// A 512-bit symmetric key: a 256-bit AES key and a 256-bit HMAC key.
///
/// The user key, a stretched master key and a per-item key all have this
/// shape. Zeroized on drop; its `Debug` prints nothing of the key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    pub(crate) enc: [u8; 32],
    pub(crate) mac: [u8; 32],
}

impl SymmetricKey {
    /// From its 64 bytes, `enc || mac`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] unless `bytes` is 64 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidKey);
        }
        let mut key = Self::zeroed();
        key.enc.copy_from_slice(&bytes[..32]);
        key.mac.copy_from_slice(&bytes[32..]);
        Ok(key)
    }

    pub(crate) fn zeroed() -> Self {
        Self {
            enc: [0; 32],
            mac: [0; 32],
        }
    }

    /// A fresh random key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the OS has no randomness to give.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::InvalidKey)?;
        Self::from_bytes(bytes.as_ref())
    }

    /// Its 64 bytes, `enc || mac`, zeroized when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.enc);
        out[32..].copy_from_slice(&self.mac);
        out
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey([redacted])")
    }
}

/// An encrypted value, as Bitwarden stores it (type 2 only).
///
/// Ciphertext isn't secret, but its `Debug` prints only the type and length:
/// nothing that would let a log line be matched to an item.
#[derive(Clone, PartialEq, Eq)]
pub struct EncString {
    iv: [u8; 16],
    ct: Vec<u8>,
    mac: [u8; 32],
}

impl EncString {
    /// Decrypts to bytes, zeroized when dropped.
    ///
    /// # Errors
    ///
    /// [`Error::MacMismatch`] for the wrong key or tampered data,
    /// [`Error::Padding`] for bad padding.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>> {
        let mut hmac =
            <HmacSha256 as KeyInit>::new_from_slice(&key.mac).map_err(|_| Error::InvalidKey)?;
        hmac.update(&self.iv);
        hmac.update(&self.ct);
        // verify_slice compares in constant time.
        hmac.verify_slice(&self.mac)
            .map_err(|_| Error::MacMismatch)?;
        let mut buf = Zeroizing::new(self.ct.clone());
        let len = Aes256CbcDec::new(&key.enc.into(), &self.iv.into())
            .decrypt_padded::<Pkcs7>(buf.as_mut_slice())
            .map_err(|_| Error::Padding)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypts to a UTF-8 string.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), and [`Error::NotUtf8`].
    pub fn decrypt_string(&self, key: &SymmetricKey) -> Result<SecretString> {
        let bytes = self.decrypt(key)?;
        let s = core::str::from_utf8(&bytes).map_err(|_| Error::NotUtf8)?;
        Ok(SecretString::from(s))
    }

    /// Decrypts a 64-byte key (a user key or an item key).
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), and [`Error::InvalidKey`] if the
    /// plaintext isn't 64 bytes.
    pub fn decrypt_key(&self, key: &SymmetricKey) -> Result<SymmetricKey> {
        SymmetricKey::from_bytes(&self.decrypt(key)?)
    }

    /// Encrypts `plaintext` under `key` with a fresh random IV.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKey`] if the OS has no randomness to give.
    pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Result<Self> {
        let mut iv = [0u8; 16];
        getrandom::fill(&mut iv).map_err(|_| Error::InvalidKey)?;
        Ok(Self::encrypt_with_iv(key, iv, plaintext))
    }

    pub(crate) fn encrypt_with_iv(key: &SymmetricKey, iv: [u8; 16], plaintext: &[u8]) -> Self {
        let ct =
            Aes256CbcEnc::new(&key.enc.into(), &iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext);
        let mut hmac =
            <HmacSha256 as KeyInit>::new_from_slice(&key.mac).expect("HMAC takes any key length");
        hmac.update(&iv);
        hmac.update(&ct);
        let mac = hmac.finalize().into_bytes().into();
        Self { iv, ct, mac }
    }
}

impl FromStr for EncString {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (ty, rest) = s.split_once('.').ok_or(Error::MalformedEncString)?;
        let ty: u8 = ty.parse().map_err(|_| Error::MalformedEncString)?;
        if ty != 2 {
            return Err(Error::UnsupportedEncType(ty));
        }
        let mut parts = rest.split('|');
        let (Some(iv), Some(ct), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::MalformedEncString);
        };
        let iv: [u8; 16] = B64
            .decode(iv)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::MalformedEncString)?;
        let ct = B64.decode(ct).map_err(|_| Error::MalformedEncString)?;
        if ct.is_empty() || ct.len() % 16 != 0 {
            return Err(Error::MalformedEncString);
        }
        let mac: [u8; 32] = B64
            .decode(mac)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::MalformedEncString)?;
        Ok(Self { iv, ct, mac })
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "2.{}|{}|{}",
            B64.encode(self.iv),
            B64.encode(&self.ct),
            B64.encode(self.mac)
        )
    }
}

impl fmt::Debug for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncString(type 2, {} bytes)", self.ct.len())
    }
}

impl serde::Serialize for EncString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for EncString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let s = <alloc::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse()
            .map_err(|_| serde::de::Error::custom("invalid or unsupported EncString"))
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let e = EncString::encrypt(&key, b"hello").unwrap();
        let parsed: EncString = e.to_string().parse().unwrap();
        assert_eq!(parsed, e);
        assert_eq!(
            parsed.decrypt_string(&key).unwrap().expose_secret(),
            "hello"
        );
    }

    #[test]
    fn wrong_key_fails_mac() {
        let a = SymmetricKey::generate().unwrap();
        let b = SymmetricKey::generate().unwrap();
        let e = EncString::encrypt(&a, b"x").unwrap();
        assert!(matches!(e.decrypt(&b), Err(Error::MacMismatch)));
    }

    #[test]
    fn tampered_ciphertext_fails_mac() {
        let key = SymmetricKey::generate().unwrap();
        let mut e = EncString::encrypt(&key, b"some text").unwrap();
        e.ct[0] ^= 1;
        assert!(matches!(e.decrypt(&key), Err(Error::MacMismatch)));
    }

    #[test]
    fn refuses_other_types() {
        for s in ["0.aaaa|bbbb", "1.a|b|c", "4.abcd", "6.abcd|x", "7.abcd"] {
            assert!(
                matches!(s.parse::<EncString>(), Err(Error::UnsupportedEncType(_))),
                "{s}"
            );
        }
        for s in ["", "2", "2.a|b", "x.a|b|c", "2.AAAA|AAAA|AAAA|AAAA"] {
            assert!(
                matches!(s.parse::<EncString>(), Err(Error::MalformedEncString)),
                "{s}"
            );
        }
    }

    #[test]
    fn debug_is_redacted() {
        let key = SymmetricKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "SymmetricKey([redacted])");
        let e = EncString::encrypt(&key, b"secret").unwrap();
        assert_eq!(format!("{e:?}"), "EncString(type 2, 16 bytes)");
    }
}
