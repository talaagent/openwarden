//! The master key: prelogin's KDF, its policy, and key stretching.
//!
//! - PBKDF2-SHA256 over the password, salted with the email (trimmed,
//!   lowercased), with the server's iteration count.
//! - Argon2id (v0x13) over the password, salted with SHA-256 of the email,
//!   with the server's iterations, memory (MiB) and parallelism.
//! - The 256-bit master key is stretched with HKDF-Expand-SHA256 (`enc`
//!   and `mac` infos) into the key that decrypts the protected symmetric
//!   key (the user key).
//!
//! The server picks the parameters, so a [`KdfPolicy`] bounds them: a
//! hostile server can't downgrade the KDF to make an offline guess cheap,
//! or inflate it to exhaust memory.

use alloc::string::String;
use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{EncString, SymmetricKey};
use crate::error::{Error, Result};
use crate::vault::UserKey;

/// An account's KDF and its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256 (Bitwarden KDF type 0).
    Pbkdf2 {
        /// Iterations.
        iterations: u32,
    },
    /// Argon2id (Bitwarden KDF type 1).
    Argon2id {
        /// Passes over memory.
        iterations: u32,
        /// Memory, in MiB.
        memory_mib: u32,
        /// Lanes.
        parallelism: u32,
    },
}

impl Kdf {
    /// From the wire's `kdf`, `kdfIterations`, `kdfMemory` and
    /// `kdfParallelism`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKdf`] for a type other than 0 or 1, and
    /// [`Error::KdfRejected`] for Argon2id without its memory or
    /// parallelism.
    pub fn from_wire(
        kdf: u8,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        match kdf {
            0 => Ok(Self::Pbkdf2 { iterations }),
            1 => Ok(Self::Argon2id {
                iterations,
                memory_mib: memory.ok_or(Error::KdfRejected("argon2id without memory"))?,
                parallelism: parallelism
                    .ok_or(Error::KdfRejected("argon2id without parallelism"))?,
            }),
            other => Err(Error::UnknownKdf(other)),
        }
    }
}

/// Bounds on the server's KDF parameters.
///
/// The defaults accept every account Bitwarden or Vaultwarden would create
/// today (and PBKDF2 accounts from the 100,000-iteration era), and refuse
/// anything weaker or absurdly expensive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfPolicy {
    /// PBKDF2 iterations, at least (default 100,000).
    pub pbkdf2_min_iterations: u32,
    /// PBKDF2 iterations, at most (default 10,000,000).
    pub pbkdf2_max_iterations: u32,
    /// Argon2id iterations, at least (default 2).
    pub argon2_min_iterations: u32,
    /// Argon2id iterations, at most (default 20).
    pub argon2_max_iterations: u32,
    /// Argon2id memory in MiB, at least (default 16).
    pub argon2_min_memory_mib: u32,
    /// Argon2id memory in MiB, at most (default 1024).
    pub argon2_max_memory_mib: u32,
    /// Argon2id parallelism, at most (default 16; at least 1 always).
    pub argon2_max_parallelism: u32,
}

impl Default for KdfPolicy {
    fn default() -> Self {
        Self {
            pbkdf2_min_iterations: 100_000,
            pbkdf2_max_iterations: 10_000_000,
            argon2_min_iterations: 2,
            argon2_max_iterations: 20,
            argon2_min_memory_mib: 16,
            argon2_max_memory_mib: 1024,
            argon2_max_parallelism: 16,
        }
    }
}

impl KdfPolicy {
    /// Checks `kdf` against the bounds.
    ///
    /// # Errors
    ///
    /// [`Error::KdfRejected`], naming the bound.
    pub fn check(&self, kdf: &Kdf) -> Result<()> {
        match *kdf {
            Kdf::Pbkdf2 { iterations } => {
                if iterations < self.pbkdf2_min_iterations {
                    return Err(Error::KdfRejected("pbkdf2 iterations below the minimum"));
                }
                if iterations > self.pbkdf2_max_iterations {
                    return Err(Error::KdfRejected("pbkdf2 iterations above the maximum"));
                }
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                if iterations < self.argon2_min_iterations {
                    return Err(Error::KdfRejected("argon2id iterations below the minimum"));
                }
                if iterations > self.argon2_max_iterations {
                    return Err(Error::KdfRejected("argon2id iterations above the maximum"));
                }
                if memory_mib < self.argon2_min_memory_mib {
                    return Err(Error::KdfRejected("argon2id memory below the minimum"));
                }
                if memory_mib > self.argon2_max_memory_mib {
                    return Err(Error::KdfRejected("argon2id memory above the maximum"));
                }
                if parallelism == 0 {
                    return Err(Error::KdfRejected("argon2id parallelism is zero"));
                }
                if parallelism > self.argon2_max_parallelism {
                    return Err(Error::KdfRejected("argon2id parallelism above the maximum"));
                }
            }
        }
        Ok(())
    }
}

/// The master key, derived from the master password. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}

/// Bitwarden's salt form of the email: trimmed and lowercased.
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

impl MasterKey {
    /// Derives the master key, after checking `kdf` against `policy`.
    ///
    /// CPU- and memory-heavy by design (seconds, and up to the policy's
    /// memory bound): call it from a blocking thread in async code.
    ///
    /// # Errors
    ///
    /// [`Error::KdfRejected`] if the policy refuses `kdf`.
    pub fn derive(
        password: &SecretString,
        email: &str,
        kdf: &Kdf,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        policy.check(kdf)?;
        let email = normalize_email(email);
        let pw = password.expose_secret().as_bytes();
        let mut key = Self([0; 32]);
        match *kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(pw, email.as_bytes(), iterations, &mut key.0);
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let salt = Sha256::digest(email.as_bytes());
                let memory_kib = memory_mib
                    .checked_mul(1024)
                    .ok_or(Error::KdfRejected("argon2id memory overflows"))?;
                let params = argon2::Params::new(memory_kib, iterations, parallelism, Some(32))
                    .map_err(|_| Error::KdfRejected("argon2id parameters invalid"))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(pw, &salt, &mut key.0)
                    .map_err(|_| Error::KdfRejected("argon2id parameters invalid"))?;
            }
        }
        Ok(key)
    }

    /// From raw bytes (tests and callers that derived it elsewhere).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The master password hash the `password` grant sends:
    /// PBKDF2-SHA256(master key, password, 1 iteration), base64.
    pub fn password_hash(&self, password: &SecretString) -> SecretString {
        let mut out = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            &self.0,
            password.expose_secret().as_bytes(),
            1,
            out.as_mut(),
        );
        SecretString::from(B64.encode(out.as_ref()))
    }

    /// The stretched master key: HKDF-Expand(SHA-256) with infos `enc` and
    /// `mac`.
    ///
    /// # Panics
    ///
    /// Never: a 32-byte PRK and 32-byte outputs are always valid.
    pub fn stretch(&self) -> SymmetricKey {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(&self.0).expect("a 32-byte PRK is valid");
        let mut key = SymmetricKey::zeroed();
        hk.expand(b"enc", &mut key.enc)
            .expect("32 bytes is a valid HKDF length");
        hk.expand(b"mac", &mut key.mac)
            .expect("32 bytes is a valid HKDF length");
        key
    }

    /// Decrypts the protected symmetric key (`profile.key`, or `Key` in the
    /// token response) into the user key.
    ///
    /// # Errors
    ///
    /// [`Error::MacMismatch`] for a wrong password (or tampered key), and
    /// [`Error::InvalidKey`] if it isn't a 64-byte key.
    pub fn unlock(&self, protected_key: &EncString) -> Result<UserKey> {
        Ok(UserKey::from_symmetric(
            protected_key.decrypt_key(&self.stretch())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_refuses_downgrade_and_inflation() {
        let p = KdfPolicy::default();
        assert!(
            p.check(&Kdf::Pbkdf2 {
                iterations: 600_000
            })
            .is_ok()
        );
        assert!(
            p.check(&Kdf::Pbkdf2 {
                iterations: 100_000
            })
            .is_ok()
        );
        assert!(p.check(&Kdf::Pbkdf2 { iterations: 5_000 }).is_err());
        assert!(p.check(&Kdf::Pbkdf2 { iterations: 1 }).is_err());
        assert!(
            p.check(&Kdf::Pbkdf2 {
                iterations: u32::MAX
            })
            .is_err()
        );
        let ok = Kdf::Argon2id {
            iterations: 3,
            memory_mib: 64,
            parallelism: 4,
        };
        assert!(p.check(&ok).is_ok());
        for bad in [
            Kdf::Argon2id {
                iterations: 1,
                memory_mib: 64,
                parallelism: 4,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 1,
                parallelism: 4,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 1 << 20,
                parallelism: 4,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 0,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 64,
            },
        ] {
            assert!(p.check(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn from_wire() {
        assert_eq!(
            Kdf::from_wire(0, 600_000, None, None).unwrap(),
            Kdf::Pbkdf2 {
                iterations: 600_000
            }
        );
        assert!(matches!(
            Kdf::from_wire(1, 3, None, Some(4)),
            Err(Error::KdfRejected(_))
        ));
        assert!(matches!(
            Kdf::from_wire(9, 3, None, None),
            Err(Error::UnknownKdf(9))
        ));
    }

    #[test]
    fn email_is_normalized() {
        assert_eq!(
            normalize_email("  Kat@Example.Invalid "),
            "kat@example.invalid"
        );
    }
}
