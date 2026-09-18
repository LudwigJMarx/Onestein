//! Queues at a relay: names, keys and proofs.
//!
//! A relay is a transport, not a layer of trust. It holds ciphertext it
//! cannot read, under names that change every period, and it decides nothing
//! except whether a proof verifies.
//!
//! The relay is assumed hostile. Nothing here protects against what it can
//! see, which is queue identifiers, sizes and times; the defence is that a
//! relay can be swapped, self-hosted, or left out.
//!
//! Spec: `spec/60-relay.md`.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use onestein_crypto::{HASH_LEN, kdf};

/// Length of a queue identifier.
pub const QUEUE_ID_LEN: usize = HASH_LEN;

/// Length of a proof.
pub const PROOF_LEN: usize = 64;

/// The shortest challenge a relay may hand out.
pub const MIN_CHALLENGE_LEN: usize = 16;

/// The largest blob a queue accepts, in bytes.
pub const MAX_BLOB_LEN: usize = 64 * 1024;

/// The largest a queue may grow, in bytes.
pub const MAX_QUEUE_LEN: usize = 16 * 1024 * 1024;

/// How long a blob is kept, collected or not, in days.
pub const BLOB_EXPIRY_DAYS: u64 = 30;

/// How long a queue outlives its last write, in days.
pub const QUEUE_EXPIRY_DAYS: u64 = 60;

const QUEUE_A_LABEL: &[u8] = b"org.onestein.relay/QUEUE_A";
const QUEUE_B_LABEL: &[u8] = b"org.onestein.relay/QUEUE_B";
const WRITE_LABEL: &[u8] = b"org.onestein.relay/WRITE";
const READ_LABEL: &[u8] = b"org.onestein.relay/READ";
const WRITE_PROOF_LABEL: &[u8] = b"org.onestein.relay/WRITE_PROOF";
const READ_PROOF_LABEL: &[u8] = b"org.onestein.relay/READ_PROOF";

/// Which of a pair's two queues at a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the device whose identity identifier sorts earlier to the other.
    AToB,
    /// The other way.
    BToA,
}

/// Which of a queue's two rights a proof is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Right {
    /// Putting a blob in.
    Write,
    /// Taking a blob out, and deleting it.
    Read,
}

/// Why a proof was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The signature does not match the challenge and the stored key.
    BadProof,
    /// The challenge is shorter than [`MIN_CHALLENGE_LEN`], so the relay is
    /// inviting a replay.
    ChallengeTooShort {
        /// Bytes given.
        given: usize,
    },
    /// A stored public key is not an Ed25519 key.
    MalformedKey,
}

/// The name of one queue in one period.
#[must_use]
pub fn queue_id(
    root_key: &[u8; HASH_LEN],
    direction: Direction,
    relay_id: &str,
    period: u64,
) -> [u8; QUEUE_ID_LEN] {
    let label = match direction {
        Direction::AToB => QUEUE_A_LABEL,
        Direction::BToA => QUEUE_B_LABEL,
    };
    derive(root_key, label, relay_id, period)
}

fn derive(root_key: &[u8; HASH_LEN], label: &[u8], relay_id: &str, period: u64) -> [u8; HASH_LEN] {
    kdf(
        root_key,
        &[label, relay_id.as_bytes(), &period.to_be_bytes()],
    )
}

/// The message a proof signs: the label for the right, then the challenge.
///
/// The label is in there so that a proof of one right is not a proof of the
/// other. Without it the two key pairs would be the only separation, and a
/// single implementation slip that reused one pair would go unnoticed.
fn proof_message(right: Right, challenge: &[u8]) -> Vec<u8> {
    let label = match right {
        Right::Write => WRITE_PROOF_LABEL,
        Right::Read => READ_PROOF_LABEL,
    };
    let mut message = Vec::with_capacity(label.len().saturating_add(challenge.len()));
    message.extend_from_slice(label);
    message.extend_from_slice(challenge);
    message
}

fn long_enough(challenge: &[u8]) -> Result<(), Error> {
    if challenge.len() < MIN_CHALLENGE_LEN {
        return Err(Error::ChallengeTooShort {
            given: challenge.len(),
        });
    }
    Ok(())
}

/// A peer's keys for one queue in one period.
pub struct QueueKeys {
    write: SigningKey,
    read: SigningKey,
}

impl QueueKeys {
    /// Derives both key pairs from the pairwise root key.
    #[must_use]
    pub fn derive(
        root_key: &[u8; HASH_LEN],
        direction: Direction,
        relay_id: &str,
        period: u64,
    ) -> Self {
        // The direction is in the relay identifier's place in the derivation
        // so that the two directions of one relationship never share a key.
        let scope = match direction {
            Direction::AToB => format!("{relay_id}/a"),
            Direction::BToA => format!("{relay_id}/b"),
        };
        Self {
            write: SigningKey::from_bytes(&derive(root_key, WRITE_LABEL, &scope, period)),
            read: SigningKey::from_bytes(&derive(root_key, READ_LABEL, &scope, period)),
        }
    }

    /// The public keys a relay is handed on first use.
    #[must_use]
    pub fn registration(&self) -> Registration {
        Registration {
            write_public: self.write.verifying_key().to_bytes(),
            read_public: self.read.verifying_key().to_bytes(),
        }
    }

    /// Signs a challenge for one of the two rights.
    ///
    /// # Errors
    ///
    /// [`Error::ChallengeTooShort`].
    pub fn prove(&self, right: Right, challenge: &[u8]) -> Result<[u8; PROOF_LEN], Error> {
        long_enough(challenge)?;
        let key = match right {
            Right::Write => &self.write,
            Right::Read => &self.read,
        };
        Ok(key.sign(&proof_message(right, challenge)).to_bytes())
    }
}

/// What a relay stores for a queue: two public keys and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Verifies proofs of the right to write.
    pub write_public: [u8; 32],
    /// Verifies proofs of the right to read.
    pub read_public: [u8; 32],
}

impl Registration {
    /// Checks a proof, as a relay does.
    ///
    /// # Errors
    ///
    /// [`Error::BadProof`], [`Error::ChallengeTooShort`],
    /// [`Error::MalformedKey`].
    pub fn check(
        &self,
        right: Right,
        challenge: &[u8],
        proof: &[u8; PROOF_LEN],
    ) -> Result<(), Error> {
        long_enough(challenge)?;
        let public = match right {
            Right::Write => self.write_public,
            Right::Read => self.read_public,
        };
        let key = VerifyingKey::from_bytes(&public).map_err(|_| Error::MalformedKey)?;
        key.verify(
            &proof_message(right, challenge),
            &Signature::from_bytes(proof),
        )
        .map_err(|_| Error::BadProof)
    }
}
