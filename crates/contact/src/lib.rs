//! Contact establishment: how two identities first learn each other's root
//! keys.
//!
//! Spec: `spec/35-contact.md`.

#![forbid(unsafe_code)]

pub mod base32;

use onestein_bdf::{Value, from_bytes_canonical, to_bytes};
use onestein_crypto::{HASH_LEN, hash, kdf};
use x25519_dalek::{PublicKey, StaticSecret};

/// Contact layer version.
pub const CONTACT_VERSION: u8 = 1;

/// Identity layer version, inside the bundle.
pub const IDENTITY_VERSION: u8 = 1;

/// Length of an Ed25519 root public key.
pub const ROOT_ED25519_LEN: usize = 32;

/// Length of an ML-DSA-65 root public key.
pub const ROOT_MLDSA_LEN: usize = 1952;

/// Length of an X25519 contact public key.
pub const CONTACT_KEY_LEN: usize = 32;

/// The prefix of a contact link.
pub const LINK_PREFIX: &str = "onestein:1:";

const BUNDLE_LABEL: &[u8] = b"org.onestein.contact/BUNDLE";
const RENDEZVOUS_LABEL: &[u8] = b"org.onestein.contact/RENDEZVOUS";
const ADDRESS_A_LABEL: &[u8] = b"org.onestein.contact/ADDRESS_A";
const ADDRESS_B_LABEL: &[u8] = b"org.onestein.contact/ADDRESS_B";

/// Why a bundle or a link could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bundle is not the structure it should be, or is not canonical.
    Malformed,
    /// A key was not the length its algorithm defines.
    WrongKeyLength {
        /// Bytes the algorithm requires.
        expected: usize,
        /// Bytes given.
        given: usize,
    },
    /// The link does not start with `onestein:1:`.
    NotALink,
    /// The link's payload is not base32.
    NotBase32(base32::Error),
    /// The bundle does not hash to the commitment that came over the other
    /// channel. This is the pairing being attacked, or the wrong code being
    /// scanned.
    CommitmentMismatch,
    /// An X25519 agreement came out all zeroes.
    DegenerateSharedSecret,
}

/// What crosses between two people when they meet or exchange a link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactBundle {
    /// Ed25519 root public key.
    pub root_ed25519: [u8; ROOT_ED25519_LEN],
    /// ML-DSA-65 root public key.
    pub root_mldsa: Vec<u8>,
    /// X25519 contact public key.
    pub contact_key: [u8; CONTACT_KEY_LEN],
}

impl ContactBundle {
    /// Encodes the bundle as canonical BDF.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKeyLength`] if the ML-DSA key is not its size.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.root_mldsa.len() != ROOT_MLDSA_LEN {
            return Err(Error::WrongKeyLength {
                expected: ROOT_MLDSA_LEN,
                given: self.root_mldsa.len(),
            });
        }
        let fields = Value::Dict(vec![
            ("ed".to_owned(), Value::Raw(self.root_ed25519.to_vec())),
            ("pq".to_owned(), Value::Raw(self.root_mldsa.clone())),
            ("v".to_owned(), Value::Int(i64::from(IDENTITY_VERSION))),
            ("x".to_owned(), Value::Raw(self.contact_key.to_vec())),
        ]);
        debug_assert!(
            fields.is_canonical(),
            "the field order above is the canonical one"
        );
        Ok(to_bytes(&fields))
    }

    /// Reads a bundle.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::WrongKeyLength`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Ok(Value::Dict(fields)) = from_bytes_canonical(bytes) else {
            return Err(Error::Malformed);
        };
        let raw = |key: &str| match fields.iter().find(|(name, _)| name == key) {
            Some((_, Value::Raw(value))) => Ok(value.clone()),
            _ => Err(Error::Malformed),
        };
        match fields.iter().find(|(name, _)| name == "v") {
            Some((_, Value::Int(version))) if *version == i64::from(IDENTITY_VERSION) => {}
            _ => return Err(Error::Malformed),
        }

        let root_mldsa = raw("pq")?;
        if root_mldsa.len() != ROOT_MLDSA_LEN {
            return Err(Error::WrongKeyLength {
                expected: ROOT_MLDSA_LEN,
                given: root_mldsa.len(),
            });
        }
        Ok(Self {
            root_ed25519: sized(&raw("ed")?, ROOT_ED25519_LEN)?,
            root_mldsa,
            contact_key: sized(&raw("x")?, CONTACT_KEY_LEN)?,
        })
    }

    /// The 32 bytes that travel over the channel an adversary can watch but
    /// not alter.
    ///
    /// # Errors
    ///
    /// As [`ContactBundle::encode`].
    pub fn commitment(&self) -> Result<[u8; HASH_LEN], Error> {
        Ok(hash(&[BUNDLE_LABEL, &[CONTACT_VERSION], &self.encode()?]))
    }

    /// Checks a received bundle against a commitment from the other channel.
    ///
    /// # Errors
    ///
    /// [`Error::CommitmentMismatch`] if they disagree, which aborts the
    /// pairing rather than retrying it.
    pub fn check(&self, commitment: &[u8; HASH_LEN]) -> Result<(), Error> {
        if self.commitment()? == *commitment {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }
}

/// A contact link, as it is pasted into some other channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactLink {
    /// The peer's X25519 contact public key, in the clear on purpose: without
    /// it there is no shared secret and no way for two devices that never met
    /// to find each other.
    pub contact_key: [u8; CONTACT_KEY_LEN],
    /// The commitment to everything else.
    pub commitment: [u8; HASH_LEN],
}

impl ContactLink {
    /// Renders the link.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut payload = Vec::with_capacity(CONTACT_KEY_LEN + HASH_LEN);
        payload.extend_from_slice(&self.contact_key);
        payload.extend_from_slice(&self.commitment);
        format!("{LINK_PREFIX}{}", base32::encode(&payload))
    }

    /// Reads a link, accepting lower case and whitespace.
    ///
    /// # Errors
    ///
    /// [`Error::NotALink`], [`Error::NotBase32`], [`Error::Malformed`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let payload = text
            .trim()
            .strip_prefix(LINK_PREFIX)
            .ok_or(Error::NotALink)?;
        let bytes = base32::decode(payload).map_err(Error::NotBase32)?;
        if bytes.len() != CONTACT_KEY_LEN + HASH_LEN {
            return Err(Error::Malformed);
        }
        let key: Vec<u8> = bytes.iter().take(CONTACT_KEY_LEN).copied().collect();
        let commitment: Vec<u8> = bytes.iter().skip(CONTACT_KEY_LEN).copied().collect();
        Ok(Self {
            contact_key: sized(&key, CONTACT_KEY_LEN)?,
            commitment: sized(&commitment, HASH_LEN)?,
        })
    }
}

/// The key both sides derive once they hold each other's links.
///
/// # Errors
///
/// [`Error::DegenerateSharedSecret`] if the agreement is all zeroes.
pub fn rendezvous_key(
    own_contact_secret: &[u8; CONTACT_KEY_LEN],
    peer_contact_key: &[u8; CONTACT_KEY_LEN],
    commitment_a: &[u8; HASH_LEN],
    commitment_b: &[u8; HASH_LEN],
) -> Result<[u8; HASH_LEN], Error> {
    let secret = StaticSecret::from(*own_contact_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_contact_key));
    if !shared.was_contributory() {
        return Err(Error::DegenerateSharedSecret);
    }
    Ok(hash(&[
        RENDEZVOUS_LABEL,
        &[CONTACT_VERSION],
        shared.as_bytes(),
        commitment_a,
        commitment_b,
    ]))
}

/// Which side of the pair an address belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The identity that sorts earlier.
    A,
    /// The other one.
    B,
}

/// The seed for one side's address on one transport in one time period.
#[must_use]
pub fn address_seed(
    rendezvous_key: &[u8; HASH_LEN],
    side: Side,
    transport_id: &str,
    period: u64,
) -> [u8; HASH_LEN] {
    let label = match side {
        Side::A => ADDRESS_A_LABEL,
        Side::B => ADDRESS_B_LABEL,
    };
    kdf(
        rendezvous_key,
        &[label, transport_id.as_bytes(), &period.to_be_bytes()],
    )
}

/// Formats an identity identifier for a person to read out: 13 groups of
/// four base32 characters.
#[must_use]
pub fn fingerprint(identity_id: &[u8; HASH_LEN]) -> String {
    let characters: Vec<char> = base32::encode(identity_id).chars().collect();
    characters
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(" ")
}

/// Copies a slice into a fixed-size array, or says how long it should have
/// been.
fn sized<const N: usize>(bytes: &[u8], expected: usize) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::WrongKeyLength {
        expected,
        given: bytes.len(),
    })
}
