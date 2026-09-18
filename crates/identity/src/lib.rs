//! Identities and their identifiers.
//!
//! An identity is a root key pair and the devices it has certified. The root
//! key signs certificates and revocations, takes part in no handshake and
//! signs no message, which is what lets it be kept out of daily reach and
//! rebuilt from a seed.
//!
//! Spec: `spec/40-identity.md`.

#![forbid(unsafe_code)]

use onestein_crypto::{HASH_LEN, hash};

/// Identity format version. Inside the identifier, so an identity of another
/// version is another identity even with the same keys.
pub const IDENTITY_VERSION: u8 = 1;

/// Length of an Ed25519 public key.
pub const ROOT_ED25519_LEN: usize = 32;

/// Length of an ML-DSA-65 public key.
pub const ROOT_MLDSA_LEN: usize = 1952;

const IDENTITY_ID_LABEL: &[u8] = b"org.onestein.identity/IDENTITY_ID";

/// Why an identity could not be named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A root public key had the wrong length for its algorithm.
    WrongKeyLength {
        /// Bytes the algorithm requires.
        expected: usize,
        /// Bytes given.
        given: usize,
    },
}

/// An identity identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityId([u8; HASH_LEN]);

impl IdentityId {
    /// Derives the identifier of an identity from both its root public keys.
    ///
    /// Both keys are required. An identity that carried only one of them
    /// would be an identity whose certificates a quantum adversary could
    /// forge, and it must not be expressible.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKeyLength`] if either key is not the length its
    /// algorithm defines.
    pub fn derive(root_ed25519: &[u8], root_mldsa: &[u8]) -> Result<Self, Error> {
        if root_ed25519.len() != ROOT_ED25519_LEN {
            return Err(Error::WrongKeyLength {
                expected: ROOT_ED25519_LEN,
                given: root_ed25519.len(),
            });
        }
        if root_mldsa.len() != ROOT_MLDSA_LEN {
            return Err(Error::WrongKeyLength {
                expected: ROOT_MLDSA_LEN,
                given: root_mldsa.len(),
            });
        }
        Ok(Self(hash(&[
            IDENTITY_ID_LABEL,
            &[IDENTITY_VERSION],
            root_ed25519,
            root_mldsa,
        ])))
    }

    /// The identifier as bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}
