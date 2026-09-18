//! Hybrid key agreement between two devices.
//!
//! X25519 and ML-KEM-768 side by side: if either falls, the handshake is as
//! strong as the other alone. Authentication is by decapsulation against
//! certified static keys rather than by signature, so nothing here signs
//! anything.
//!
//! This crate gathers no randomness. Every key and every encapsulation takes
//! its randomness as an argument, because a library that reaches for the
//! system generator cannot be tested against known vectors and cannot be used
//! on a platform whose generator the caller distrusts
//! (`spec/05-primitives.md` §7).
//!
//! Spec: `spec/30-handshake.md`.

#![forbid(unsafe_code)]

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use onestein_crypto::{HASH_LEN, hash, kdf};
use x25519_dalek::{PublicKey, StaticSecret};

/// Handshake layer version, bound into the root key.
pub const HANDSHAKE_VERSION: u8 = 1;

/// Identity layer version, bound into the root key.
pub const IDENTITY_VERSION: u8 = 1;

/// Primitives version, bound into the root key.
pub const PRIMITIVES_VERSION: u8 = 1;

/// Transport layer version, bound into the root key although the transport
/// runs afterwards, so that the key cannot be carried into a weaker one.
pub const TRANSPORT_VERSION: u8 = 1;

/// Length of an X25519 public key or shared secret.
pub const X25519_LEN: usize = 32;

/// Length of an ML-KEM-768 encapsulation key.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1184;

/// Length of an ML-KEM-768 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;

/// Length of the seed an ML-KEM key pair is generated from.
pub const KEM_SEED_LEN: usize = 64;

const ROOT_KEY_LABEL: &[u8] = b"org.onestein.handshake/ROOT_KEY";
const CONFIRMATION_A_LABEL: &[u8] = b"org.onestein.handshake/CONFIRMATION_A";
const CONFIRMATION_B_LABEL: &[u8] = b"org.onestein.handshake/CONFIRMATION_B";

/// Which side of the handshake a device is, decided by the order of the two
/// identity identifiers as byte strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The device whose identity identifier sorts earlier.
    A,
    /// The other one.
    B,
}

/// Why a handshake step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An X25519 agreement came out all zeroes, which means the peer sent a
    /// point of small order. The handshake stops rather than continuing with
    /// a secret both the peer and anyone watching can predict.
    DegenerateSharedSecret,
    /// An encapsulation key or ciphertext was not the length its algorithm
    /// defines.
    WrongLength {
        /// Bytes the algorithm requires.
        expected: usize,
        /// Bytes given.
        given: usize,
    },
}

/// One device's key pair for this handshake: X25519 and ML-KEM side by side.
///
/// Used for both the ephemeral pair, generated per handshake, and the static
/// pair, which lives in the device certificate. The difference is how long
/// they are kept, and that is the caller's business.
pub struct KeyPair {
    x25519: StaticSecret,
    kem: DecapsulationKey,
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (slot, byte) in out.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    out
}

impl KeyPair {
    /// Builds a key pair from caller-supplied randomness.
    #[must_use]
    pub fn from_seeds(x25519_seed: &[u8; X25519_LEN], kem_seed: &[u8; KEM_SEED_LEN]) -> Self {
        Self {
            x25519: StaticSecret::from(*x25519_seed),
            kem: DecapsulationKey::from_seed(Array(*kem_seed)),
        }
    }

    /// The X25519 public key.
    #[must_use]
    pub fn x25519_public(&self) -> [u8; X25519_LEN] {
        PublicKey::from(&self.x25519).to_bytes()
    }

    /// The ML-KEM encapsulation key.
    #[must_use]
    pub fn kem_encapsulation_key(&self) -> [u8; KEM_ENCAPSULATION_KEY_LEN] {
        fixed(&self.kem.encapsulation_key().to_bytes())
    }

    /// Agrees with a peer's X25519 public key.
    ///
    /// # Errors
    ///
    /// [`Error::DegenerateSharedSecret`] if the result is all zeroes.
    pub fn agree(&self, peer_public: &[u8; X25519_LEN]) -> Result<[u8; HASH_LEN], Error> {
        let shared = self.x25519.diffie_hellman(&PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(Error::DegenerateSharedSecret);
        }
        Ok(*shared.as_bytes())
    }

    /// Recovers the secret from a ciphertext encapsulated to this key.
    ///
    /// ML-KEM rejects implicitly: a ciphertext that was tampered with does
    /// not fail here, it yields a different secret, and the handshake finds
    /// out at the confirmation.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &[u8; KEM_CIPHERTEXT_LEN]) -> [u8; HASH_LEN] {
        let ciphertext = Ciphertext::from(*ciphertext);
        fixed(&self.kem.decapsulate(&ciphertext))
    }
}

/// Encapsulates to a peer's ML-KEM key with caller-supplied randomness.
///
/// The randomness must be 32 uniform bytes, fresh for every call. Reusing it
/// against the same key reproduces the ciphertext and the secret, which is
/// what makes this function testable and what makes it dangerous: the caller
/// owns that decision, because this crate does not gather randomness
/// (`spec/05-primitives.md` §7).
///
/// # Errors
///
/// [`Error::WrongLength`] if the key is not an ML-KEM-768 encapsulation key.
pub fn encapsulate(
    encapsulation_key: &[u8; KEM_ENCAPSULATION_KEY_LEN],
    randomness: &[u8; 32],
) -> Result<([u8; KEM_CIPHERTEXT_LEN], [u8; HASH_LEN]), Error> {
    let key = EncapsulationKey::new(&Array(*encapsulation_key)).map_err(|_| Error::WrongLength {
        expected: KEM_ENCAPSULATION_KEY_LEN,
        given: encapsulation_key.len(),
    })?;
    let (ciphertext, secret) = key.encapsulate_deterministic(&Array(*randomness));
    Ok((fixed(&ciphertext), fixed(&secret)))
}

/// The seven shared secrets, named as `spec/30-handshake.md` §2 names them:
/// the X25519 ones for whose key is whose, A's first, and the encapsulated
/// ones for whoever encapsulated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secrets {
    /// DH(ephemeral_a, ephemeral_b)
    pub dh_ephemeral: [u8; HASH_LEN],
    /// DH(ephemeral_a, static_b)
    pub dh_ephemeral_static: [u8; HASH_LEN],
    /// DH(static_a, ephemeral_b)
    pub dh_static_ephemeral: [u8; HASH_LEN],
    /// A's encapsulation to B's ephemeral key.
    pub kem_ephemeral_a: [u8; HASH_LEN],
    /// B's encapsulation to A's ephemeral key.
    pub kem_ephemeral_b: [u8; HASH_LEN],
    /// A's encapsulation to B's static key.
    pub kem_static_a: [u8; HASH_LEN],
    /// B's encapsulation to A's static key.
    pub kem_static_b: [u8; HASH_LEN],
}

/// Every public value the handshake touched, in the order the root key hashes
/// them.
///
/// Named fields rather than a list of arguments: the order is the security
/// property, and a caller who swaps two thirty-two byte arrays by accident
/// should not be able to.
pub struct Transcript<'a> {
    /// A's identity identifier.
    pub identity_id_a: &'a [u8; HASH_LEN],
    /// B's identity identifier.
    pub identity_id_b: &'a [u8; HASH_LEN],
    /// A's device signing public key.
    pub device_signing_pub_a: &'a [u8; HASH_LEN],
    /// B's device signing public key.
    pub device_signing_pub_b: &'a [u8; HASH_LEN],
    /// A's static X25519 public key.
    pub dh_static_pub_a: &'a [u8; X25519_LEN],
    /// B's static X25519 public key.
    pub dh_static_pub_b: &'a [u8; X25519_LEN],
    /// A's static ML-KEM encapsulation key.
    pub kem_static_pub_a: &'a [u8; KEM_ENCAPSULATION_KEY_LEN],
    /// B's static ML-KEM encapsulation key.
    pub kem_static_pub_b: &'a [u8; KEM_ENCAPSULATION_KEY_LEN],
    /// A's ephemeral X25519 public key.
    pub dh_ephemeral_pub_a: &'a [u8; X25519_LEN],
    /// B's ephemeral X25519 public key.
    pub dh_ephemeral_pub_b: &'a [u8; X25519_LEN],
    /// A's ephemeral ML-KEM encapsulation key.
    pub kem_ephemeral_pub_a: &'a [u8; KEM_ENCAPSULATION_KEY_LEN],
    /// B's ephemeral ML-KEM encapsulation key.
    pub kem_ephemeral_pub_b: &'a [u8; KEM_ENCAPSULATION_KEY_LEN],
    /// A's ciphertext to B's ephemeral key.
    pub ct_ephemeral_a: &'a [u8; KEM_CIPHERTEXT_LEN],
    /// B's ciphertext to A's ephemeral key.
    pub ct_ephemeral_b: &'a [u8; KEM_CIPHERTEXT_LEN],
    /// A's ciphertext to B's static key.
    pub ct_static_a: &'a [u8; KEM_CIPHERTEXT_LEN],
    /// B's ciphertext to A's static key.
    pub ct_static_b: &'a [u8; KEM_CIPHERTEXT_LEN],
}

/// Derives the root key the transport layer starts from.
#[must_use]
pub fn root_key(secrets: &Secrets, transcript: &Transcript) -> [u8; HASH_LEN] {
    hash(&[
        ROOT_KEY_LABEL,
        &[HANDSHAKE_VERSION],
        &[IDENTITY_VERSION],
        &[PRIMITIVES_VERSION],
        &[TRANSPORT_VERSION],
        &secrets.dh_ephemeral,
        &secrets.dh_ephemeral_static,
        &secrets.dh_static_ephemeral,
        &secrets.kem_ephemeral_a,
        &secrets.kem_ephemeral_b,
        &secrets.kem_static_a,
        &secrets.kem_static_b,
        transcript.identity_id_a,
        transcript.identity_id_b,
        transcript.device_signing_pub_a,
        transcript.device_signing_pub_b,
        transcript.dh_static_pub_a,
        transcript.dh_static_pub_b,
        transcript.kem_static_pub_a,
        transcript.kem_static_pub_b,
        transcript.dh_ephemeral_pub_a,
        transcript.dh_ephemeral_pub_b,
        transcript.kem_ephemeral_pub_a,
        transcript.kem_ephemeral_pub_b,
        transcript.ct_ephemeral_a,
        transcript.ct_ephemeral_b,
        transcript.ct_static_a,
        transcript.ct_static_b,
    ])
}

/// The proof that a peer derived the same root key.
#[must_use]
pub fn confirmation(root_key: &[u8; HASH_LEN], role: Role) -> [u8; HASH_LEN] {
    let label = match role {
        Role::A => CONFIRMATION_A_LABEL,
        Role::B => CONFIRMATION_B_LABEL,
    };
    kdf(root_key, &[label])
}
