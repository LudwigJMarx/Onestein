//! The six records a handshake exchanges.
//!
//! Framing comes from `onestein-record`; what this module adds is which type
//! byte means what, and how long each payload has to be.
//!
//! Spec: `spec/30-handshake.md` §3.

use onestein_crypto::HASH_LEN;
use onestein_record::{Reader, encode};

use crate::{Error, HANDSHAKE_VERSION, KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN, X25519_LEN};

/// Type byte 0.
pub const TYPE_EPHEMERAL_KEYS: u8 = 0;
/// Type byte 1.
pub const TYPE_DEVICE_CERTIFICATE: u8 = 1;
/// Type byte 2.
pub const TYPE_CERTIFICATE_ID: u8 = 2;
/// Type byte 3.
pub const TYPE_CERTIFICATE_REQUEST: u8 = 3;
/// Type byte 4.
pub const TYPE_ENCAPSULATIONS: u8 = 4;
/// Type byte 5.
pub const TYPE_CONFIRMATION: u8 = 5;

/// One record of a handshake.
///
/// Fixed-size fields are borrowed from the buffer they were read out of.
/// Copying them into the type would make one variant a kilobyte wide and the
/// rest a few bytes, so every record in a queue would cost as much as the
/// largest, and decoding would copy what the caller already holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeRecord<'a> {
    /// The sender's ephemeral public keys.
    EphemeralKeys {
        /// X25519 public key.
        x25519: &'a [u8; X25519_LEN],
        /// ML-KEM encapsulation key.
        kem: &'a [u8; KEM_ENCAPSULATION_KEY_LEN],
    },
    /// The sender's device certificate, as canonical BDF.
    DeviceCertificate(&'a [u8]),
    /// The hash of a certificate the sender believes the peer already holds.
    CertificateId(&'a [u8; HASH_LEN]),
    /// Sent when a certificate identifier names one the peer does not hold.
    CertificateRequest,
    /// The sender's two ciphertexts.
    Encapsulations {
        /// To the peer's ephemeral key.
        to_ephemeral: &'a [u8; KEM_CIPHERTEXT_LEN],
        /// To the peer's static key.
        to_static: &'a [u8; KEM_CIPHERTEXT_LEN],
    },
    /// Proof that the sender derived the same root key.
    Confirmation(&'a [u8; HASH_LEN]),
    /// A type this version does not know.
    ///
    /// Handed over rather than refused: `05-primitives.md` §4 has a peer
    /// ignore an unknown type so that a later addition passes through an
    /// older peer. Ignoring it is the caller's move, and it can only ignore
    /// what it has been told about.
    Unknown {
        /// The type byte on the wire.
        record_type: u8,
    },
}

/// Writes one record.
///
/// # Errors
///
/// [`Error::Record`] if the payload does not fit a record.
pub fn encode_record(record: &HandshakeRecord) -> Result<Vec<u8>, Error> {
    let (record_type, payload) = match record {
        HandshakeRecord::EphemeralKeys { x25519, kem } => {
            let mut payload = Vec::with_capacity(X25519_LEN + KEM_ENCAPSULATION_KEY_LEN);
            payload.extend_from_slice(*x25519);
            payload.extend_from_slice(*kem);
            (TYPE_EPHEMERAL_KEYS, payload)
        }
        HandshakeRecord::DeviceCertificate(bytes) => (TYPE_DEVICE_CERTIFICATE, bytes.to_vec()),
        HandshakeRecord::CertificateId(id) => (TYPE_CERTIFICATE_ID, id.to_vec()),
        HandshakeRecord::CertificateRequest => (TYPE_CERTIFICATE_REQUEST, Vec::new()),
        HandshakeRecord::Encapsulations {
            to_ephemeral,
            to_static,
        } => {
            let mut payload = Vec::with_capacity(2 * KEM_CIPHERTEXT_LEN);
            payload.extend_from_slice(*to_ephemeral);
            payload.extend_from_slice(*to_static);
            (TYPE_ENCAPSULATIONS, payload)
        }
        HandshakeRecord::Confirmation(mac) => (TYPE_CONFIRMATION, mac.to_vec()),
        // Nothing here knows what an unknown record meant, so nothing here
        // can write one back.
        HandshakeRecord::Unknown { record_type } => {
            return Err(Error::WrongLength {
                expected: 0,
                given: usize::from(*record_type),
            });
        }
    };
    encode(HANDSHAKE_VERSION, record_type, &payload).map_err(Error::Record)
}

/// Borrows a fixed-size field out of a payload, or says what it expected.
fn field<const N: usize>(
    payload: &[u8],
    offset: usize,
    expected: usize,
) -> Result<&[u8; N], Error> {
    let end = offset.saturating_add(N);
    payload
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::WrongLength {
            expected,
            given: payload.len(),
        })
}

fn exactly(payload: &[u8], expected: usize) -> Result<(), Error> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(Error::WrongLength {
            expected,
            given: payload.len(),
        })
    }
}

/// Reads the records of one handshake message.
///
/// # Errors
///
/// [`Error::Record`] for framing, [`Error::WrongLength`] for a known type
/// whose payload is the wrong size.
pub fn decode_records(input: &[u8]) -> Result<Vec<HandshakeRecord<'_>>, Error> {
    let mut out = Vec::new();
    for framed in Reader::new(input, HANDSHAKE_VERSION) {
        let record = framed.map_err(Error::Record)?;
        let payload = record.payload;
        out.push(match record.record_type {
            TYPE_EPHEMERAL_KEYS => {
                let expected = X25519_LEN + KEM_ENCAPSULATION_KEY_LEN;
                exactly(payload, expected)?;
                HandshakeRecord::EphemeralKeys {
                    x25519: field(payload, 0, expected)?,
                    kem: field(payload, X25519_LEN, expected)?,
                }
            }
            TYPE_DEVICE_CERTIFICATE => HandshakeRecord::DeviceCertificate(payload),
            TYPE_CERTIFICATE_ID => {
                exactly(payload, HASH_LEN)?;
                HandshakeRecord::CertificateId(field(payload, 0, HASH_LEN)?)
            }
            TYPE_CERTIFICATE_REQUEST => {
                exactly(payload, 0)?;
                HandshakeRecord::CertificateRequest
            }
            TYPE_ENCAPSULATIONS => {
                let expected = 2 * KEM_CIPHERTEXT_LEN;
                exactly(payload, expected)?;
                HandshakeRecord::Encapsulations {
                    to_ephemeral: field(payload, 0, expected)?,
                    to_static: field(payload, KEM_CIPHERTEXT_LEN, expected)?,
                }
            }
            TYPE_CONFIRMATION => {
                exactly(payload, HASH_LEN)?;
                HandshakeRecord::Confirmation(field(payload, 0, HASH_LEN)?)
            }
            record_type => HandshakeRecord::Unknown { record_type },
        });
    }
    Ok(out)
}
