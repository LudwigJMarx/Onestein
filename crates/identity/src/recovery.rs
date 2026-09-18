//! Recovery: one seed, and the identity comes back.
//!
//! The root key pair and the contact key are derived from a 32-byte seed, so
//! the same seed yields the same identity on any device, forever, with no
//! server and no backup file.
//!
//! What that does **not** restore is written in the specification and worth
//! repeating where someone might rely on it: the contact list, the message
//! history, and the pairwise keys of existing contacts are all gone. The
//! pairwise keys deliberately so, because a seed that could re-derive them
//! would be a seed that undoes forward secrecy.
//!
//! Spec: `spec/40-identity.md` §6.

use onestein_crypto::{HASH_LEN, kdf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, IdentityId, RootKeys};

/// Length of a recovery seed.
pub const RECOVERY_SEED_LEN: usize = 32;

const ROOT_ED25519_LABEL: &[u8] = b"org.onestein.identity/ROOT_ED25519";
const ROOT_MLDSA_LABEL: &[u8] = b"org.onestein.identity/ROOT_MLDSA";
const CONTACT_KEY_LABEL: &[u8] = b"org.onestein.identity/CONTACT_KEY";

/// The one secret a person keeps.
///
/// This type gathers no randomness and generates nothing: the seed is handed
/// in. Where it came from, how it is shown to a person, and whether it is
/// written down are the application's problem, and the last one is the
/// difference between a backup and a story about a backup.
#[derive(Clone, Copy)]
pub struct RecoverySeed([u8; RECOVERY_SEED_LEN]);

impl RecoverySeed {
    /// Takes a seed.
    #[must_use]
    pub const fn from_bytes(seed: [u8; RECOVERY_SEED_LEN]) -> Self {
        Self(seed)
    }

    /// The seed for the Ed25519 root key.
    #[must_use]
    pub fn root_ed25519_seed(&self) -> [u8; HASH_LEN] {
        kdf(&self.0, &[ROOT_ED25519_LABEL])
    }

    /// The seed for the ML-DSA root key.
    #[must_use]
    pub fn root_mldsa_seed(&self) -> [u8; HASH_LEN] {
        kdf(&self.0, &[ROOT_MLDSA_LABEL])
    }

    /// The X25519 contact secret key.
    ///
    /// The one identity-level key that is not a signing key. It has no
    /// forward secrecy and protects only the handshake that has not happened
    /// yet (`spec/20-transport.md` §3).
    #[must_use]
    pub fn contact_secret(&self) -> [u8; HASH_LEN] {
        kdf(&self.0, &[CONTACT_KEY_LABEL])
    }

    /// The X25519 contact public key, as it travels in a contact bundle.
    #[must_use]
    pub fn contact_public(&self) -> [u8; HASH_LEN] {
        PublicKey::from(&StaticSecret::from(self.contact_secret())).to_bytes()
    }

    /// The root key pair.
    #[must_use]
    pub fn root_keys(&self) -> RootKeys {
        RootKeys::from_seeds(&self.root_ed25519_seed(), &self.root_mldsa_seed())
    }

    /// The identity this seed is.
    ///
    /// # Errors
    ///
    /// As [`IdentityId::derive`].
    pub fn identity_id(&self) -> Result<IdentityId, Error> {
        self.root_keys().identity_id()
    }
}
