//! Identities and their identifiers.
//!
//! An identity is a root key pair and the devices it has certified. The root
//! key signs certificates and revocations, takes part in no handshake and
//! signs no message, which is what lets it be kept out of daily reach and
//! rebuilt from a seed.
//!
//! Spec: `spec/40-identity.md`.

#![forbid(unsafe_code)]

mod certificate;
mod revocation;

pub use revocation::{Revocation, accept_epoch, verify_revocation};

pub use certificate::{
    DeviceCertificate, ED25519_SIGNATURE_LEN, KEM_ENCAPSULATION_KEY_LEN, MLDSA_SIGNATURE_LEN,
    RootKeys, X25519_LEN, verify_certificate,
};

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
    /// A number does not fit the signed integer BDF uses.
    OutOfRange,
    /// The container or the certificate is not the structure it should be.
    Malformed,
    /// The certificate names an identity other than the one whose root keys
    /// are verifying it.
    WrongIdentity,
    /// One of the two signatures did not verify. Which one is not reported:
    /// both are required, so one failing is the same answer.
    BadSignature,
    /// The signing algorithm refused.
    Signing,
    /// The epoch is below the highest one this contact has recorded for that
    /// identity, so accepting it could resurrect a revoked device.
    EpochInThePast {
        /// The highest epoch recorded.
        recorded: u64,
        /// The epoch offered.
        given: u64,
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

    /// Takes an identifier that came off a wire.
    ///
    /// Nothing is checked here. An identity identifier is a hash of two root
    /// keys, and it is checked where those keys are: when a certificate is
    /// verified (`spec/40-identity.md` §4).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }
}
