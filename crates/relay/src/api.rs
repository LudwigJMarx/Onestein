//! What a relay and its users say to each other.
//!
//! The records of `spec/60-relay.md` §4a, and the handler that answers them.
//! The handler is here rather than in the daemon because it is the part that
//! decides, and a decision behind a socket is a decision nobody can test.

use std::collections::BTreeMap;

use onestein_crypto::HASH_LEN;
use onestein_record::{Reader, encode};

use crate::{PROOF_LEN, QUEUE_ID_LEN, RELAY_VERSION, Refusal, Registration, Right, Store};

/// Type bytes, in the order of the table in §4a.
pub const TYPE_REGISTER: u8 = 0;
/// Ask for a challenge.
pub const TYPE_CHALLENGE_REQUEST: u8 = 1;
/// A challenge.
pub const TYPE_CHALLENGE: u8 = 2;
/// Put a blob in.
pub const TYPE_WRITE: u8 = 3;
/// Take a blob out.
pub const TYPE_READ: u8 = 4;
/// A blob.
pub const TYPE_BLOB: u8 = 5;
/// Remove a blob.
pub const TYPE_DELETE: u8 = 6;
/// Done.
pub const TYPE_OK: u8 = 7;
/// Nothing there.
pub const TYPE_EMPTY: u8 = 8;
/// No.
pub const TYPE_REFUSED: u8 = 9;

/// What a user of a relay says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// First use of a queue.
    Register {
        /// The queue.
        queue_id: [u8; QUEUE_ID_LEN],
        /// Verifies write proofs.
        write_public: [u8; 32],
        /// Verifies read proofs.
        read_public: [u8; 32],
    },
    /// Ask for something to sign.
    ChallengeRequest {
        /// The queue.
        queue_id: [u8; QUEUE_ID_LEN],
        /// Which right the challenge is for.
        right: Right,
    },
    /// Put a blob in.
    Write {
        /// The queue.
        queue_id: [u8; QUEUE_ID_LEN],
        /// Proof of the right to write.
        proof: [u8; PROOF_LEN],
        /// The blob.
        blob: &'a [u8],
    },
    /// Take the oldest blob.
    Read {
        /// The queue.
        queue_id: [u8; QUEUE_ID_LEN],
        /// Proof of the right to read.
        proof: [u8; PROOF_LEN],
    },
    /// Remove a blob that has been collected.
    Delete {
        /// The queue.
        queue_id: [u8; QUEUE_ID_LEN],
        /// Proof of the right to read.
        proof: [u8; PROOF_LEN],
        /// Which blob.
        blob_id: [u8; HASH_LEN],
    },
}

/// What a relay says back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response<'a> {
    /// Sign this.
    Challenge([u8; 32]),
    /// Here it is.
    Blob {
        /// Its name.
        blob_id: [u8; HASH_LEN],
        /// Its bytes.
        blob: &'a [u8],
    },
    /// Done.
    Ok,
    /// Nothing in that queue.
    Empty,
    /// No, and why in one byte.
    Refused(Refusal),
}

/// Why a record could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Framing, version, or a payload that is not what its type requires.
    Malformed,
}

/// Writes a request.
///
/// # Errors
///
/// [`WireError::Malformed`] if the blob does not fit a record.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, WireError> {
    let (record_type, payload) = match request {
        Request::Register {
            queue_id,
            write_public,
            read_public,
        } => (
            TYPE_REGISTER,
            [queue_id.as_slice(), write_public, read_public].concat(),
        ),
        Request::ChallengeRequest { queue_id, right } => (
            TYPE_CHALLENGE_REQUEST,
            [queue_id.as_slice(), &[right_byte(*right)]].concat(),
        ),
        Request::Write {
            queue_id,
            proof,
            blob,
        } => (TYPE_WRITE, [queue_id.as_slice(), proof, blob].concat()),
        Request::Read { queue_id, proof } => (TYPE_READ, [queue_id.as_slice(), proof].concat()),
        Request::Delete {
            queue_id,
            proof,
            blob_id,
        } => (TYPE_DELETE, [queue_id.as_slice(), proof, blob_id].concat()),
    };
    encode(RELAY_VERSION, record_type, &payload).map_err(|_| WireError::Malformed)
}

const fn right_byte(right: Right) -> u8 {
    match right {
        Right::Write => 0,
        Right::Read => 1,
    }
}

/// One record, or nothing. A stream that carries a second record where one
/// was expected is refused rather than half read.
fn single(bytes: &[u8]) -> Result<(u8, &[u8]), WireError> {
    let mut reader = Reader::new(bytes, RELAY_VERSION);
    let record = reader.next().ok_or(WireError::Malformed)?;
    let record = record.map_err(|_| WireError::Malformed)?;
    if reader.next().is_some() {
        return Err(WireError::Malformed);
    }
    Ok((record.record_type, record.payload))
}

fn field<const N: usize>(payload: &[u8], offset: usize) -> Result<[u8; N], WireError> {
    payload
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(WireError::Malformed)
}

fn exactly(payload: &[u8], length: usize) -> Result<(), WireError> {
    if payload.len() == length {
        Ok(())
    } else {
        Err(WireError::Malformed)
    }
}

/// Reads a request.
///
/// # Errors
///
/// [`WireError::Malformed`].
pub fn decode_request(bytes: &[u8]) -> Result<Request<'_>, WireError> {
    let (record_type, payload) = single(bytes)?;
    match record_type {
        TYPE_REGISTER => {
            exactly(payload, QUEUE_ID_LEN + 64)?;
            Ok(Request::Register {
                queue_id: field(payload, 0)?,
                write_public: field(payload, QUEUE_ID_LEN)?,
                read_public: field(payload, QUEUE_ID_LEN + 32)?,
            })
        }
        TYPE_CHALLENGE_REQUEST => {
            exactly(payload, QUEUE_ID_LEN + 1)?;
            let right = match payload.get(QUEUE_ID_LEN) {
                Some(0) => Right::Write,
                Some(1) => Right::Read,
                _ => return Err(WireError::Malformed),
            };
            Ok(Request::ChallengeRequest {
                queue_id: field(payload, 0)?,
                right,
            })
        }
        TYPE_WRITE => {
            let blob = payload
                .get(QUEUE_ID_LEN + PROOF_LEN..)
                .ok_or(WireError::Malformed)?;
            Ok(Request::Write {
                queue_id: field(payload, 0)?,
                proof: field(payload, QUEUE_ID_LEN)?,
                blob,
            })
        }
        TYPE_READ => {
            exactly(payload, QUEUE_ID_LEN + PROOF_LEN)?;
            Ok(Request::Read {
                queue_id: field(payload, 0)?,
                proof: field(payload, QUEUE_ID_LEN)?,
            })
        }
        TYPE_DELETE => {
            exactly(payload, QUEUE_ID_LEN + PROOF_LEN + HASH_LEN)?;
            Ok(Request::Delete {
                queue_id: field(payload, 0)?,
                proof: field(payload, QUEUE_ID_LEN)?,
                blob_id: field(payload, QUEUE_ID_LEN + PROOF_LEN)?,
            })
        }
        _ => Err(WireError::Malformed),
    }
}

/// Writes a response.
///
/// # Errors
///
/// [`WireError::Malformed`] if the blob does not fit a record.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, WireError> {
    let (record_type, payload) = match response {
        Response::Challenge(challenge) => (TYPE_CHALLENGE, challenge.to_vec()),
        Response::Blob { blob_id, blob } => (TYPE_BLOB, [blob_id.as_slice(), blob].concat()),
        Response::Ok => (TYPE_OK, Vec::new()),
        Response::Empty => (TYPE_EMPTY, Vec::new()),
        Response::Refused(refusal) => (TYPE_REFUSED, vec![*refusal as u8]),
    };
    encode(RELAY_VERSION, record_type, &payload).map_err(|_| WireError::Malformed)
}

/// Reads a response.
///
/// # Errors
///
/// [`WireError::Malformed`].
pub fn decode_response(bytes: &[u8]) -> Result<Response<'_>, WireError> {
    let (record_type, payload) = single(bytes)?;
    match record_type {
        TYPE_CHALLENGE => {
            exactly(payload, 32)?;
            Ok(Response::Challenge(field(payload, 0)?))
        }
        TYPE_BLOB => {
            let blob = payload.get(HASH_LEN..).ok_or(WireError::Malformed)?;
            Ok(Response::Blob {
                blob_id: field(payload, 0)?,
                blob,
            })
        }
        TYPE_OK => {
            exactly(payload, 0)?;
            Ok(Response::Ok)
        }
        TYPE_EMPTY => {
            exactly(payload, 0)?;
            Ok(Response::Empty)
        }
        TYPE_REFUSED => {
            exactly(payload, 1)?;
            let refusal = match payload.first() {
                Some(0) => Refusal::UnknownQueue,
                Some(1) => Refusal::BadProof,
                Some(2) => Refusal::TooLarge,
                Some(3) => Refusal::QueueFull,
                Some(4) => Refusal::UnknownChallenge,
                _ => return Err(WireError::Malformed),
            };
            Ok(Response::Refused(refusal))
        }
        _ => Err(WireError::Malformed),
    }
}

/// The challenges a relay is waiting on, keyed by queue and right.
pub type Challenges = BTreeMap<([u8; QUEUE_ID_LEN], u8), [u8; 32]>;

/// Answers one request.
///
/// `fresh_challenge` is randomness the caller brings, because this crate does
/// not gather any. A challenge is good once: it is taken out of the map the
/// moment it is used, whether the proof was good or not, or an attacker could
/// grind against the same challenge until it verified.
pub fn handle<'a>(
    store: &'a mut Store,
    challenges: &mut Challenges,
    request: &Request,
    now_ms: u64,
    fresh_challenge: [u8; 32],
) -> Response<'a> {
    match request {
        Request::Register {
            queue_id,
            write_public,
            read_public,
        } => {
            store.register(
                *queue_id,
                Registration {
                    write_public: *write_public,
                    read_public: *read_public,
                },
                now_ms,
            );
            Response::Ok
        }
        Request::ChallengeRequest { queue_id, right } => {
            if store.registration(queue_id).is_none() {
                return Response::Refused(Refusal::UnknownQueue);
            }
            challenges.insert((*queue_id, right_byte(*right)), fresh_challenge);
            Response::Challenge(fresh_challenge)
        }
        Request::Write {
            queue_id,
            proof,
            blob,
        } => match spend(store, challenges, queue_id, Right::Write, proof) {
            Err(refusal) => Response::Refused(refusal),
            Ok(()) => match store.write(queue_id, blob.to_vec(), now_ms) {
                Ok(_) => Response::Ok,
                Err(refusal) => Response::Refused(refusal),
            },
        },
        Request::Read { queue_id, proof } => {
            match spend(store, challenges, queue_id, Right::Read, proof) {
                Err(refusal) => Response::Refused(refusal),
                Ok(()) => match store.read(queue_id) {
                    Some((blob_id, blob)) => Response::Blob { blob_id, blob },
                    None => Response::Empty,
                },
            }
        }
        Request::Delete {
            queue_id,
            proof,
            blob_id,
        } => match spend(store, challenges, queue_id, Right::Read, proof) {
            Err(refusal) => Response::Refused(refusal),
            Ok(()) => match store.delete(queue_id, blob_id) {
                Ok(()) => Response::Ok,
                Err(refusal) => Response::Refused(refusal),
            },
        },
    }
}

/// Takes the outstanding challenge and checks the proof against it.
///
/// The challenge is removed before the proof is checked, so a bad proof
/// spends it too. Leaving it in place would let an attacker grind against one
/// challenge until something verified.
fn spend(
    store: &Store,
    challenges: &mut Challenges,
    queue_id: &[u8; QUEUE_ID_LEN],
    right: Right,
    proof: &[u8; PROOF_LEN],
) -> Result<(), Refusal> {
    let registration = store.registration(queue_id).ok_or(Refusal::UnknownQueue)?;
    let challenge = challenges
        .remove(&(*queue_id, right_byte(right)))
        .ok_or(Refusal::UnknownChallenge)?;
    registration
        .check(right, &challenge, proof)
        .map_err(|_| Refusal::BadProof)
}
