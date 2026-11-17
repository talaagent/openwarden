//! TOTP codes (RFC 6238) from a login's `totp` field.
//!
//! The field takes three forms, as Bitwarden reads it:
//! - an `otpauth://totp/...` URI with `secret`, and optionally `digits`
//!   (1 to 10), `period` and `algorithm` (`SHA1`, `SHA256`, `SHA512`);
//! - `steam://<secret>`: Steam Guard's 5-character codes;
//! - a bare base32 secret (spaces and padding ignored): SHA-1, 6 digits,
//!   30 seconds.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use hmac::{KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A TOTP code and how long it stays valid.
pub struct TotpCode {
    /// The code.
    pub code: SecretString,
    /// The period, in seconds.
    pub period: u64,
    /// Seconds left in this period.
    pub remaining: u64,
}

impl core::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"[redacted]")
            .field("period", &self.period)
            .field("remaining", &self.remaining)
            .finish()
    }
}

struct Params {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    steam: bool,
}

fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'=' | b'-' => continue,
            _ => return None,
        };
        buf = (buf << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
        }
        buf &= (1 << bits) - 1;
    }
    (!out.is_empty()).then_some(out)
}

fn parse(secret: &str) -> Result<Params> {
    let secret = secret.trim();
    if let Some(rest) = secret.strip_prefix("steam://") {
        return Ok(Params {
            key: base32_decode(rest).ok_or(Error::InvalidTotp)?,
            algorithm: Algorithm::Sha1,
            digits: 5,
            period: 30,
            steam: true,
        });
    }
    if secret.len() > 10 && secret[..10].eq_ignore_ascii_case("otpauth://") {
        let url = url::Url::parse(secret).map_err(|_| Error::InvalidTotp)?;
        let mut p = Params {
            key: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            steam: false,
        };
        for (k, v) in url.query_pairs() {
            match &*k.to_ascii_lowercase() {
                "secret" => p.key = base32_decode(&v).ok_or(Error::InvalidTotp)?,
                "digits" => {
                    p.digits = v
                        .parse()
                        .ok()
                        .filter(|d| (1..=10).contains(d))
                        .ok_or(Error::InvalidTotp)?;
                }
                "period" => {
                    p.period = v
                        .parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or(Error::InvalidTotp)?;
                }
                "algorithm" => {
                    p.algorithm = match &*v.to_ascii_uppercase() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(Error::InvalidTotp),
                    }
                }
                _ => {}
            }
        }
        if p.key.is_empty() {
            return Err(Error::InvalidTotp);
        }
        return Ok(p);
    }
    Ok(Params {
        key: base32_decode(secret).ok_or(Error::InvalidTotp)?,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        steam: false,
    })
}

fn hmac_of<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg);
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

/// The TOTP code for `secret` (a login's `totp` field) at `unix_time`
/// (seconds).
///
/// # Errors
///
/// [`Error::InvalidTotp`] if the field doesn't parse.
///
/// # Panics
///
/// Never: HMAC outputs are at least 20 bytes, so the dynamic-truncation
/// window is always in bounds.
pub fn generate(secret: &SecretString, unix_time: u64) -> Result<TotpCode> {
    let p = parse(secret.expose_secret())?;
    let counter = (unix_time / p.period).to_be_bytes();
    let mac = match p.algorithm {
        Algorithm::Sha1 => hmac_of::<hmac::Hmac<sha1::Sha1>>(&p.key, &counter),
        Algorithm::Sha256 => hmac_of::<hmac::Hmac<sha2::Sha256>>(&p.key, &counter),
        Algorithm::Sha512 => hmac_of::<hmac::Hmac<sha2::Sha512>>(&p.key, &counter),
    };
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let mut word = [0u8; 4];
    word.copy_from_slice(&mac[offset..offset + 4]);
    let mut bin = u32::from_be_bytes(word) & 0x7fff_ffff;
    let code = if p.steam {
        let mut s = String::with_capacity(5);
        let n = u32::try_from(STEAM_ALPHABET.len()).expect("26 fits");
        for _ in 0..5 {
            s.push(char::from(
                STEAM_ALPHABET[usize::try_from(bin % n).expect("< 26")],
            ));
            bin /= n;
        }
        s
    } else {
        let modulus = 10u64.pow(p.digits);
        format!(
            "{:0width$}",
            u64::from(bin) % modulus,
            width = p.digits as usize
        )
    };
    Ok(TotpCode {
        code: SecretString::from(code),
        period: p.period,
        remaining: p.period - unix_time % p.period,
    })
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;

    use super::*;

    fn code(secret: &str, t: u64) -> String {
        generate(&SecretString::from(secret), t)
            .unwrap()
            .code
            .expose_secret()
            .to_owned()
    }

    // RFC 6238 appendix B: the ASCII seeds "12345678901234567890" (SHA-1),
    // its 32-byte and 64-byte extensions (SHA-256, SHA-512), 8 digits.
    const SHA1_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn rfc6238_vectors() {
        let table: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for &(t, s1, s256, s512) in table {
            assert_eq!(
                code(&format!("otpauth://totp/x?secret={SHA1_B32}&digits=8"), t),
                s1
            );
            assert_eq!(
                code(
                    &format!("otpauth://totp/x?secret={SHA256_B32}&digits=8&algorithm=SHA256"),
                    t
                ),
                s256
            );
            assert_eq!(
                code(
                    &format!("otpauth://totp/x?secret={SHA512_B32}&digits=8&algorithm=SHA512"),
                    t
                ),
                s512
            );
        }
    }

    #[test]
    fn bare_base32_is_six_digit_sha1() {
        // The 6-digit truncation of the RFC's SHA-1 code at t=59.
        assert_eq!(code(SHA1_B32, 59), "287082");
        assert_eq!(code(&SHA1_B32.to_lowercase(), 59), "287082");
        assert_eq!(
            code("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", 59),
            "287082"
        );
    }

    #[test]
    fn steam_codes() {
        let c = code(&format!("steam://{SHA1_B32}"), 59);
        assert_eq!(c.len(), 5);
        assert!(c.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
    }

    #[test]
    fn remaining() {
        let c = generate(&SecretString::from(SHA1_B32), 59).unwrap();
        assert_eq!((c.period, c.remaining), (30, 1));
        assert!(!format!("{c:?}").contains("287082"));
    }

    #[test]
    fn bad_secrets() {
        for s in [
            "",
            "not base32!",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=GEZD&digits=99",
            "steam://",
        ] {
            assert!(generate(&SecretString::from(s), 0).is_err(), "{s}");
        }
    }
}
